"""Graph analytics with NetworkX on the neighbourhood of an incident.

* **Pivot entity** - the node with the highest betweenness centrality inside the
  incident subgraph: the entity that connects the attack's pieces together
  (usually the compromised identity).
* **Attack paths** - shortest paths from external / hosting-provider IPs to
  critical assets: "how did the attacker get from the internet to production?"
* **Blast radius** - everything the compromised principal created, modified or
  accessed: what needs to be reviewed / rotated / rebuilt.
"""

from __future__ import annotations

import networkx as nx

from aegis.graph.builder import STRONG_EDGES
from aegis.schema import Incident
from aegis.storage.db import Repository

IMPACT_EDGES = {"created", "modified", "accessed", "exec_into", "called", "assumed", "has_ip"}


def expand_strong(repo: Repository, entity_ids: list[str], hops: int = 1) -> set[str]:
    """Entities reachable over causal/ownership edges (used by the correlator)."""
    frontier, seen = set(entity_ids), set(entity_ids)
    for _ in range(hops):
        edges = repo.edges_touching(list(frontier), types=sorted(STRONG_EDGES), limit=500)
        nxt = {e["dst"] for e in edges} | {e["src"] for e in edges}
        frontier = nxt - seen
        seen |= nxt
        if not frontier:
            break
    return seen


def incident_subgraph(repo: Repository, incident: Incident, max_edges: int = 400) -> nx.MultiDiGraph:
    core = [e.id for e in incident.entities]
    edges = repo.edges_touching(core, limit=max_edges)
    # Restrict to the incident's time span (+/- 1h) so years of history don't swamp the picture -
    # but always keep strong (causal) edges.
    lo = incident.first_seen.timestamp() - 3600
    hi = incident.last_seen.timestamp() + 3600
    # Busy shared nodes (production-api, a country) touch hundreds of unrelated identities.
    # For those "weak" incident entities only keep edges that lead to another incident entity.
    weak = {i for i in core if i.split(":", 1)[0] in ("resource", "country", "role")}
    core_set = set(core)
    g = nx.MultiDiGraph()
    for e in edges:
        recent = e["last_seen"] and lo <= e["last_seen"].timestamp() and e["first_seen"].timestamp() <= hi
        touches_strong = (e["src"] in core_set and e["src"] not in weak) or (e["dst"] in core_set and e["dst"] not in weak)
        if not touches_strong and not (e["src"] in core_set and e["dst"] in core_set):
            continue
        if recent or e["type"] in STRONG_EDGES:
            g.add_edge(e["src"], e["dst"], type=e["type"], count=e["count"])
    for node_id in core:
        g.add_node(node_id)
    meta = {n["id"]: n for n in repo.get_entities(list(g.nodes))}
    for node_id in g.nodes:
        m = meta.get(node_id, {})
        t, _, v = node_id.partition(":")
        g.nodes[node_id].update(type=m.get("type", t), value=m.get("value", v), in_incident=node_id in core,
                                **(m.get("attributes") or {}))
    return g


def analyze(g: nx.MultiDiGraph) -> dict:
    if g.number_of_nodes() == 0:
        return {"pivot": None, "attack_paths": [], "blast_radius": [], "centrality": {}}
    ug = nx.Graph(g)
    centrality = nx.betweenness_centrality(ug) if ug.number_of_nodes() > 2 else {n: 0.0 for n in ug}
    degree = dict(ug.degree())
    principals = [n for n in g.nodes if g.nodes[n].get("type") in ("user", "service_account", "host")
                  and g.nodes[n].get("in_incident")]
    candidates = principals or [n for n in g.nodes if g.nodes[n].get("in_incident")] or list(g.nodes)
    pivot = max(candidates, key=lambda n: (centrality.get(n, 0), degree.get(n, 0)))

    external = [n for n in g.nodes if g.nodes[n].get("type") == "ip" and g.nodes[n].get("internal") is False
                and g.nodes[n].get("in_incident")]
    critical = [n for n in g.nodes if g.nodes[n].get("criticality") in ("critical", "high")]
    paths = []
    for src in external:
        for dst in critical:
            try:
                p = nx.shortest_path(ug, src, dst)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            if 1 < len(p) <= 6:
                paths.append(p)
    paths.sort(key=len)

    blast = []
    if pivot:
        for _, dst, data in g.out_edges(pivot, data=True):
            if data.get("type") in IMPACT_EDGES:
                blast.append({"entity": dst, "relation": data["type"], "criticality": g.nodes[dst].get("criticality")})
                # second hop: e.g. created instance -> has_ip
                for _, dst2, d2 in g.out_edges(dst, data=True):
                    if d2.get("type") in {"has_ip", "belongs_to"}:
                        blast.append({"entity": dst2, "relation": f"{data['type']}->{d2['type']}",
                                      "criticality": g.nodes[dst2].get("criticality")})
    seen, uniq = set(), []
    for b in blast:
        if b["entity"] not in seen:
            seen.add(b["entity"])
            uniq.append(b)
    return {
        "pivot": pivot,
        "attack_paths": paths[:5],
        "blast_radius": uniq[:30],
        "centrality": {n: round(c, 3) for n, c in sorted(centrality.items(), key=lambda x: -x[1])[:10]},
    }


def to_json(g: nx.MultiDiGraph) -> dict:
    nodes = [{"id": n, **{k: v for k, v in d.items() if isinstance(v, str | int | float | bool) or v is None}}
             for n, d in g.nodes(data=True)]
    agg: dict[tuple, int] = {}
    for s, d, data in g.edges(data=True):
        k = (s, d, data.get("type"))
        agg[k] = agg.get(k, 0) + int(data.get("count", 1))
    edges = [{"source": s, "target": d, "type": t, "count": c} for (s, d, t), c in agg.items()]
    return {"nodes": nodes, "edges": edges}


def graph_context(repo: Repository, incident: Incident) -> dict:
    g = incident_subgraph(repo, incident)
    return {**analyze(g), **to_json(g)}


def export_cypher(repo: Repository) -> str:
    """Neo4j import script for the whole entity graph (`aegis graph export-cypher > graph.cypher`)."""

    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace("'", "\\'")

    lines = ["// Generated by Aegis. Load with: cypher-shell -f graph.cypher",
             "CREATE CONSTRAINT entity_id IF NOT EXISTS FOR (e:Entity) REQUIRE e.id IS UNIQUE;"]
    for n in repo.all_entities():
        label = "".join(w.capitalize() for w in n["type"].split("_"))
        lines.append(f"MERGE (e:Entity:{label} {{id: '{esc(n['id'])}'}}) SET e.value = '{esc(n['value'])}';")
    for e in repo.all_edges():
        rel = e["type"].upper()
        lines.append(f"MATCH (a:Entity {{id: '{esc(e['src'])}'}}), (b:Entity {{id: '{esc(e['dst'])}'}}) "
                     f"MERGE (a)-[r:{rel}]->(b) SET r.count = {e['count']};")
    return "\n".join(lines) + "\n"
