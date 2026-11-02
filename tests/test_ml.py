import copy

import numpy as np

from aegis.collectors import normalize
from aegis.ml.features import FEATURE_NAMES, FeatureExtractor
from aegis.ml.inference import MLEngine
from aegis.simulator import build_dataset, run_scenario
from tests.conftest import START


def test_feature_vector_shape_and_new_country():
    fx = FeatureExtractor()
    for env in build_dataset(1, seed=4, start=START.replace(day=10)):
        fx.transform(normalize(env))
    evs = [normalize(e) for e in run_scenario("password_spray", START, seed=1)]
    victim_login = next(e for e in evs if e.principal == "frank" and e.outcome == "success")
    vec = fx.transform(victim_login)
    assert vec.shape == (len(FEATURE_NAMES),)
    assert vec[FEATURE_NAMES.index("new_country")] == 1.0
    assert vec[FEATURE_NAMES.index("src_hosting")] == 1.0


def test_training_report_has_required_metrics(ml_artifact):
    r = ml_artifact["report"]
    for name in ("isolation_forest", "autoencoder", "xgboost", "markov_sequence", "ensemble", "rules_engine"):
        m = r["results"][name]
        for k in ("precision", "recall", "f1", "false_positive_rate"):
            assert 0.0 <= m[k] <= 1.0
    assert r["latency_ms"]["isolation_forest"]["batched_per_event"] > 0
    # the unsupervised models are calibrated to a low false-positive rate
    assert r["results"]["isolation_forest"]["false_positive_rate"] < 0.03
    # the ensemble must be clearly better than chance on the held-out test split
    assert r["results"]["ensemble"]["roc_auc"] > 0.9
    assert "novel_attack_recall" in r


def test_ml_engine_flags_attack_but_not_much_benign(ml_artifact):
    engine = MLEngine(artifact=copy.deepcopy(ml_artifact["artifact"]), model="ensemble", suppression_seconds=0)
    benign = [normalize(e) for e in build_dataset(0.5, seed=99, start=START.replace(hour=0))]
    benign_alerts = engine.process_batch(benign)
    attack = [normalize(e) for e in run_scenario("credential_compromise", START, seed=5)]
    attack_alerts = engine.process_batch(attack)
    assert len(attack_alerts) / len(attack) > 0.3
    assert len(benign_alerts) / len(benign) < 0.03
    a = attack_alerts[0]
    assert a.detector == "ml" and "model_scores" in a.evidence and isinstance(a.evidence["top_features"], list)


def test_models_are_picklable_and_scores_are_finite(ml_artifact):
    art = ml_artifact["artifact"]
    X = np.zeros((3, len(FEATURE_NAMES)), dtype=np.float32)
    for name in ("isolation_forest", "autoencoder", "xgboost"):
        assert np.isfinite(art["models"][name].score(X)).all()
