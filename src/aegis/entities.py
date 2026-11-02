"""Turning events into *entities* - the nouns of security analysis.

Entities (users, IPs, resources, roles, keys...) are what lets us connect
otherwise unrelated log lines: an IdP login and an S3 download are linked
because they share the entity `service_account:service-account-17`.
"""

from __future__ import annotations

from aegis.enrichment import is_internal
from aegis.schema import EntityRef, Event


def principal_entity(evt: Event) -> EntityRef | None:
    if not evt.principal:
        return None
    etype = {"service_account": "service_account", "host": "host"}.get(evt.principal_type or "", "user")
    return EntityRef(type=etype, value=evt.principal)


def _get(evt: Event, path: str):
    obj = evt
    for part in path.split("."):
        if obj is None:
            return None
        obj = obj.get(part) if isinstance(obj, dict) else getattr(obj, part, None)
    return obj


# event field -> entity type
FIELD_ENTITY_TYPES = {
    "src_ip": "ip",
    "dst_ip": "ip",
    "target_resource": "resource",
    "attributes.role": "role",
    "attributes.created_access_key": "access_key",
    "attributes.instance_id": "resource",
    "attributes.private_ip": "ip",
    "geo_country": "country",
}


def entities_from_event(evt: Event, fields: list[str] | None = None) -> list[EntityRef]:
    fields = fields or ["principal", "src_ip", "target_resource"]
    out: list[EntityRef] = []
    for f in fields:
        if f == "principal":
            ref = principal_entity(evt)
            if ref:
                out.append(ref)
            continue
        value = _get(evt, f)
        if value in (None, "", "account"):
            continue
        out.append(EntityRef(type=FIELD_ENTITY_TYPES.get(f, "resource"), value=str(value)))
    # de-duplicate, keep order
    seen, uniq = set(), []
    for e in out:
        if e.id not in seen:
            seen.add(e.id)
            uniq.append(e)
    return uniq


# Entities that are good *correlation keys*. A shared country or a popular
# resource ("production-api") links far too many unrelated things, so those are
# "weak" and never merge incidents on their own.
STRONG_TYPES = {"user", "service_account", "access_key", "host"}


def is_strong(ref: EntityRef) -> bool:
    if ref.type in STRONG_TYPES:
        return True
    if ref.type == "ip":
        # An external attacker IP is a great key; internal IPs are hosts and only
        # strong when they are not shared infrastructure (DNS, DB).
        return not is_internal(ref.value) or ref.value not in {"10.0.0.2", "10.0.4.5"}
    return ref.type == "resource" and ref.value.startswith("i-")
