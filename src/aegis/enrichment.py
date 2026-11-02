"""Event enrichment: GeoIP and asset inventory.

Real SIEMs enrich raw logs with context that the log itself does not contain:
which country an IP belongs to (MaxMind GeoIP), whether it belongs to a hosting
provider / VPN / Tor, and how critical the target asset is (a CMDB). In the lab
we use a small static table built around the RFC 5737 documentation ranges, so
no real-world IP address is ever involved.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class GeoInfo:
    country: str | None
    city: str | None
    asn_org: str
    is_hosting: bool = False
    is_internal: bool = False


_GEO_TABLE: list[tuple[str, GeoInfo]] = [
    ("10.0.0.0/8", GeoInfo(None, None, "internal", is_internal=True)),
    ("198.51.100.0/28", GeoInfo("US", "Seattle", "Example Residential ISP")),
    ("198.51.100.16/28", GeoInfo("US", "Austin", "Example Residential ISP")),
    ("198.51.100.32/28", GeoInfo("US", "New York", "Example Residential ISP")),
    ("198.51.100.48/28", GeoInfo("GB", "London", "Example UK Broadband")),
    ("198.51.100.64/28", GeoInfo("DE", "Berlin", "Example DE Telekom")),
    ("198.51.100.80/28", GeoInfo("IN", "Bengaluru", "Example IN Broadband")),
    ("198.51.100.96/28", GeoInfo("US", "Chicago", "Example Residential ISP")),
    ("198.51.100.112/28", GeoInfo("CA", "Toronto", "Example CA Cable")),
    ("198.51.100.128/28", GeoInfo("FR", "Paris", "Example FR Mobile")),
    ("198.51.100.144/28", GeoInfo("US", "Ashburn", "Corp VPN")),
    ("192.0.2.0/24", GeoInfo("US", "San Francisco", "Example SaaS Provider")),
    ("203.0.113.0/26", GeoInfo("NL", "Amsterdam", "Example Bulletproof VPS", is_hosting=True)),
    ("203.0.113.64/26", GeoInfo("SG", "Singapore", "Example Cloud VPS", is_hosting=True)),
    ("203.0.113.128/25", GeoInfo("BR", "Sao Paulo", "Example Hosting BR", is_hosting=True)),
]
_NETWORKS = [(ipaddress.ip_network(cidr), info) for cidr, info in _GEO_TABLE]

UNKNOWN = GeoInfo(None, None, "unknown")


@lru_cache(maxsize=4096)
def geoip(ip: str | None) -> GeoInfo:
    if not ip:
        return UNKNOWN
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return UNKNOWN  # e.g. "cloudtrail.amazonaws.com" as sourceIPAddress
    # Longest-prefix match, like a routing table.
    best: tuple[int, GeoInfo] | None = None
    for net, info in _NETWORKS:
        if addr in net and (best is None or net.prefixlen > best[0]):
            best = (net.prefixlen, info)
    return best[1] if best else UNKNOWN


def is_internal(ip: str | None) -> bool:
    return geoip(ip).is_internal


# A tiny CMDB: how bad is it if this asset is compromised?
ASSET_CRITICALITY: dict[str, str] = {
    "production-api": "critical",
    "payments-db": "critical",
    "aegis-customer-data": "critical",
    "prod-cluster": "critical",
    "cloudtrail-main": "critical",
    "staging-web": "low",
    "aegis-dev-artifacts": "low",
    "data-lake": "high",
}


def asset_criticality(resource: str | None) -> str | None:
    if not resource:
        return None
    for name, level in ASSET_CRITICALITY.items():
        if name in resource:
            return level
    return None
