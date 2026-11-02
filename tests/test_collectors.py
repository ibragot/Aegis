from aegis.collectors import normalize
from aegis.simulator import build_dataset, run_scenario
from tests.conftest import START


def _events(name):
    return [normalize(e) for e in run_scenario(name, START, seed=1)]


def test_all_sources_normalize_and_ids_are_deterministic():
    envs = build_dataset(0.25, seed=3)
    a = [normalize(e) for e in envs]
    b = [normalize(e) for e in envs]
    assert {e.source for e in a} == {"cloudtrail", "auth", "k8s_audit", "network", "app"}
    assert [e.event_id for e in a] == [e.event_id for e in b]  # idempotent re-processing
    assert len({e.event_id for e in a}) == len(a)


def test_cloudtrail_assumed_role_principal_and_iam_category():
    evs = _events("credential_compromise")
    attach = next(e for e in evs if e.action == "AttachRolePolicy")
    assert attach.category == "iam"
    assert attach.privileged
    assert "AdministratorAccess" in attach.attributes["policy_arn"]
    run = next(e for e in evs if e.action == "RunInstances")
    assert run.attributes["instance_id"].startswith("i-")
    assert run.attributes["private_ip"].startswith("10.0.9.")


def test_idp_and_geo_enrichment():
    evs = _events("credential_compromise")
    first = evs[0]
    assert first.source == "auth" and first.principal == "service-account-17"
    assert first.principal_type == "service_account"
    assert first.geo_country == "NL"
    assert first.attributes["src_hosting"] is True


def test_k8s_privileged_pod_flags():
    evs = _events("k8s_compromise")
    pod = next(e for e in evs if e.action == "create pods" and e.outcome == "success")
    assert pod.attributes["privileged_pod"] and pod.attributes["host_path"] and pod.privileged
    binding = next(e for e in evs if e.attributes.get("resource") == "clusterrolebindings")
    assert binding.attributes["role_ref"] == "cluster-admin"
    assert binding.principal == "k8s-sa:staging/web"


def test_vpc_flow_parsing():
    evs = _events("internal_recon")
    flow = evs[0]
    assert flow.category == "network" and flow.principal is None and flow.entity_key == flow.src_ip
    assert flow.outcome == "failure"  # REJECT
    assert flow.attributes["dst_internal"] is True
