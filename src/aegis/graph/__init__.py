"""Entity graph: who authenticated from where, assumed what, created what, talked to whom.

    user ──authenticated_from──▶ ip ──located_in──▶ country
     │
     ├──assumed──▶ role
     ├──created──▶ instance ──has_ip──▶ ip ──connected_to──▶ external ip
     └──accessed──▶ resource

`builder` turns events into nodes and edges (written to PostgreSQL by the
indexer service); `analysis` loads a neighbourhood into NetworkX for path,
centrality and blast-radius analysis used by the correlator and investigator.
"""
