from __future__ import annotations

from aegis.enrichment import asset_criticality, geoip
from aegis.entities import principal_entity
from aegis.schema import EntityRef, Event

# Edges that represent *causation / ownership* rather than mere co-occurrence.
# The correlator may follow these to link alerts that share no entity directly
# (e.g. the user who created instance i-123 and the exfiltration flow FROM i-123's IP).
STRONG_EDGES = {"created", "has_ip", "assumed", "belongs_to", "modified"}


def _node(ref: EntityRef, evt: Event, **attrs) -> dict:
    a = dict(attrs)
    crit = asset_criticality(ref.value) if ref.type in ("resource", "role") else None
    if crit:
        a["criticality"] = crit
    if ref.type == "ip":
        g = geoip(ref.value)
        a.update({"internal": g.is_internal, "country": g.country, "asn_org": g.asn_org, "hosting": g.is_hosting})
    return {"id": ref.id, "type": ref.type, "value": ref.value[:260], "first_seen": evt.timestamp,
            "last_seen": evt.timestamp, "attributes": a}


def _edge(src: EntityRef, dst: EntityRef, etype: str, evt: Event) -> dict:
    return {"src": src.id, "dst": dst.id, "type": etype, "first_seen": evt.timestamp, "last_seen": evt.timestamp,
            "last_event_id": evt.event_id}


def graph_elements(evt: Event) -> tuple[list[dict], list[dict]]:
    nodes: list[dict] = []
    edges: list[dict] = []

    def add(ref: EntityRef | None, **attrs) -> EntityRef | None:
        if ref is not None:
            nodes.append(_node(ref, evt, **attrs))
        return ref

    def link(a: EntityRef | None, b: EntityRef | None, etype: str) -> None:
        if a is not None and b is not None and a.id != b.id:
            edges.append(_edge(a, b, etype, evt))

    who = add(principal_entity(evt))
    ip = add(EntityRef(type="ip", value=evt.src_ip)) if evt.src_ip else None
    if ip and evt.geo_country:
        link(ip, add(EntityRef(type="country", value=evt.geo_country)), "located_in")

    attrs = evt.attributes
    req = attrs.get("request") or {}

    if evt.category == "authentication":
        link(who, ip, "authenticated_from" if evt.outcome == "success" else "failed_auth_from")
        if attrs.get("role"):
            link(who, add(EntityRef(type="role", value=attrs["role"])), "assumed")
        return nodes, edges

    if evt.category == "network":
        dst = add(EntityRef(type="ip", value=evt.dst_ip)) if evt.dst_ip else None
        link(ip, dst, "connected_to")
        return nodes, edges

    link(who, ip, "connected_from")

    if evt.category == "iam":
        if "roleName" in req:
            link(who, add(EntityRef(type="role", value=req["roleName"])), "modified")
        if "userName" in req:
            target_user = add(EntityRef(type="user", value=req["userName"]))
            link(who, target_user, "created" if evt.action == "CreateUser" else "modified")
            if attrs.get("created_access_key"):
                key = add(EntityRef(type="access_key", value=attrs["created_access_key"]))
                link(who, key, "created")
                link(key, target_user, "belongs_to")
        return nodes, edges

    if evt.action == "RunInstances" and attrs.get("instance_id"):
        inst = add(EntityRef(type="resource", value=attrs["instance_id"]), instance_type=attrs.get("instance_type"))
        link(who, inst, "created")
        if attrs.get("private_ip"):
            link(inst, add(EntityRef(type="ip", value=attrs["private_ip"])), "has_ip")
        return nodes, edges

    if evt.target_resource:
        res = add(EntityRef(type="resource", value=evt.target_resource), resource_type=evt.resource_type)
        if evt.category == "kubernetes" and evt.action.startswith("create"):
            etype = "exec_into" if "exec" in evt.action else "created"
        elif evt.category == "application":
            etype = "called"
        else:
            etype = "accessed" if attrs.get("read_only", True) else "modified"
        link(who, res, etype)
    return nodes, edges
