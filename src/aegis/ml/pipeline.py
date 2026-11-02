"""Train, threshold and evaluate every model on synthetic data with known labels.

    aegis train            # -> models/aegis_models.joblib + ml/reports/{metrics.json,REPORT.md}

Data splits are separated *in time* (train: days 1-14, validation: 15-17,
test: 18-21) and generated with different random seeds, so the test set has
attack instances the models have never seen. Thresholds are chosen on the
validation split only; the test split is touched exactly once, for the
final numbers.
"""

from __future__ import annotations

import copy
import json
import logging
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

from aegis.collectors import normalize
from aegis.config import REPO_ROOT, get_settings
from aegis.ml.features import FEATURE_NAMES, FeatureExtractor
from aegis.ml.models import (
    AutoencoderDetector,
    IsolationForestDetector,
    MarkovSequenceDetector,
    XGBoostDetector,
    threshold_for_f1,
    threshold_for_fpr,
)
from aegis.rules import RulesEngine, load_rules
from aegis.schema import Event
from aegis.simulator import build_dataset

log = logging.getLogger(__name__)

ARTIFACT_NAME = "aegis_models.joblib"
UNSUPERVISED = ["isolation_forest", "autoencoder", "markov_sequence"]
TARGET_FPR = 0.005  # alert budget for unsupervised models: 0.5% of benign events


def ensemble_score(norm: dict[str, np.ndarray]) -> np.ndarray:
    """Combine normalized scores (1.0 == that model's own threshold).

    The supervised model is trusted on its own; the unsupervised models must
    agree (mean), which cancels out a lot of their individual false positives.
    """
    unsup = np.mean([norm[m] for m in UNSUPERVISED if m in norm], axis=0)
    return np.maximum(norm["xgboost"], unsup) if "xgboost" in norm else unsup


def _stream(envs: list[dict], fx: FeatureExtractor) -> tuple[np.ndarray, np.ndarray, list[Event]]:
    events = [normalize(e) for e in envs]
    X = np.vstack([fx.transform(e) for e in events])
    y = np.asarray([1 if (e.truth and e.truth.malicious) else 0 for e in events])
    return X, y, events


def _metrics(y: np.ndarray, pred: np.ndarray, scores: np.ndarray | None = None) -> dict:
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    out = {
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        "false_positive_rate": round(fp / (fp + tn), 5) if fp + tn else 0.0,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }
    if scores is not None and len(set(y)) > 1:
        out["roc_auc"] = round(float(roc_auc_score(y, scores)), 4)
        out["pr_auc"] = round(float(average_precision_score(y, scores)), 4)
    return out


def _scenario_detection(events: list[Event], pred: np.ndarray) -> dict:
    """Did we catch each attack *instance* at all? (what an analyst cares about)"""
    by_scenario: dict[str, list[bool]] = {}
    # instances are contiguous runs of the same scenario in time order
    instances: dict[tuple[str, int], bool] = {}
    counter: dict[str, int] = {}
    last: str | None = None
    for e, p in zip(events, pred, strict=True):
        if not (e.truth and e.truth.malicious):
            continue
        s = e.truth.scenario or "?"
        if s != last:
            counter[s] = counter.get(s, 0) + 1
            last = s
        key = (s, counter[s])
        instances[key] = instances.get(key, False) or bool(p)
    for (s, _), hit in instances.items():
        by_scenario.setdefault(s, []).append(hit)
    return {s: f"{sum(h)}/{len(h)}" for s, h in sorted(by_scenario.items())}


def _rules_predictions(events: list[Event], warmup: list[Event]) -> np.ndarray:
    engine = RulesEngine(load_rules(get_settings().rules_dir))
    for e in warmup:
        engine.process(e)
    flagged: set[str] = set()
    for e in events:
        for alert in engine.process(e):
            flagged.update(alert.event_ids)
    return np.asarray([1 if e.event_id in flagged else 0 for e in events])


def train_and_evaluate(
    model_dir: Path | None = None,
    report_dir: Path | None = None,
    seed: int = 7,
    train_days: float = 14,
    val_days: float = 3,
    test_days: float = 4,
) -> dict:
    settings = get_settings()
    model_dir = model_dir or settings.model_dir
    report_dir = report_dir or (REPO_ROOT / "ml" / "reports")
    t0 = time.time()
    d0 = datetime(2026, 9, 7, tzinfo=UTC)

    log.info("generating synthetic data ...")
    train_envs = build_dataset(train_days, seed, start=d0, attacks_per_day=1.0)
    val_envs = build_dataset(val_days, seed + 1, start=d0 + timedelta(days=train_days), attacks_per_day=3)
    test_envs = build_dataset(test_days, seed + 2, start=d0 + timedelta(days=train_days + val_days),
                              attacks_per_day=3)

    log.info("extracting features ...")
    fx = FeatureExtractor()
    X_tr, y_tr, ev_tr = _stream(train_envs, fx)
    serving_fx = copy.deepcopy(fx)  # the profiles learned from training = the deployed baseline
    X_va, y_va, ev_va = _stream(val_envs, fx)
    X_te, y_te, ev_te = _stream(test_envs, fx)
    benign = y_tr == 0

    log.info("training models on %d events (%d malicious) ...", len(y_tr), int(y_tr.sum()))
    models = {
        "isolation_forest": IsolationForestDetector(seed).fit(X_tr[benign]),
        "autoencoder": AutoencoderDetector(seed).fit(X_tr[benign]),
        "xgboost": XGBoostDetector(seed).fit(X_tr, y_tr),
    }
    seq = MarkovSequenceDetector().fit_events([e for e, b in zip(ev_tr, benign, strict=True) if b])

    # --- thresholds on validation ------------------------------------------
    val_scores = {name: m.score(X_va) for name, m in models.items()}
    seq.reset_state()
    seq.score_events(ev_tr[-5000:])  # warm the per-identity history
    val_scores["markov_sequence"] = seq.score_events(ev_va)
    for name in UNSUPERVISED:
        model = models.get(name, seq)
        model.threshold = threshold_for_fpr(val_scores[name][y_va == 0], TARGET_FPR)
    models["xgboost"].threshold = threshold_for_f1(val_scores["xgboost"], y_va)
    models["markov_sequence"] = seq

    # --- test -------------------------------------------------------------
    test_scores = {name: m.score(X_te) for name, m in models.items() if name != "markov_sequence"}
    test_scores["markov_sequence"] = seq.score_events(ev_te)
    norm = {name: test_scores[name] / models[name].threshold for name in models}
    norm["ensemble"] = ensemble_score(norm)

    results: dict[str, dict] = {}
    for name, s in norm.items():
        pred = (s >= 1.0).astype(int)
        results[name] = {**_metrics(y_te, pred, s), "scenario_detection": _scenario_detection(ev_te, pred)}

    rules_pred = _rules_predictions(ev_te, ev_tr + ev_va)
    results["rules_engine"] = {**_metrics(y_te, rules_pred), "scenario_detection": _scenario_detection(ev_te, rules_pred)}
    combined = np.maximum(rules_pred, (norm["ensemble"] >= 1.0).astype(int))
    results["rules_plus_ml"] = {**_metrics(y_te, combined), "scenario_detection": _scenario_detection(ev_te, combined)}

    # --- generalization: can XGBoost catch an attack type it never saw? ------
    novel = _novel_attack_experiment(X_tr, y_tr, ev_tr, X_te, y_te, ev_te, models, norm, seed)

    # --- latency ----------------------------------------------------------
    latency = _measure_latency(serving_fx, models, ev_te[:1000])

    mean = X_tr[benign].mean(axis=0)
    std = X_tr[benign].std(axis=0)
    artifact = {
        "version": 1,
        "trained_at": datetime.now(UTC).isoformat(),
        "feature_names": FEATURE_NAMES,
        "extractor": serving_fx,
        "models": models,
        "baseline_mean": mean,
        "baseline_std": std,
        "thresholds": {n: float(m.threshold) for n, m in models.items()},
    }
    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, model_dir / ARTIFACT_NAME, compress=3)

    report = {
        "generated_at": artifact["trained_at"],
        "seed": seed,
        "data": {
            "train_events": len(y_tr), "train_malicious": int(y_tr.sum()),
            "validation_events": len(y_va), "validation_malicious": int(y_va.sum()),
            "test_events": len(y_te), "test_malicious": int(y_te.sum()),
            "features": len(FEATURE_NAMES),
        },
        "thresholds": artifact["thresholds"],
        "target_fpr_unsupervised": TARGET_FPR,
        "results": results,
        "latency_ms": latency,
        "novel_attack_recall": novel,
        "xgboost_top_features": models["xgboost"].feature_importance(FEATURE_NAMES),
        "training_seconds": round(time.time() - t0, 1),
    }
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "metrics.json").write_text(json.dumps(report, indent=2))
    (report_dir / "REPORT.md").write_text(render_report(report))
    log.info("done in %.1fs", time.time() - t0)
    return report


def _novel_attack_experiment(X_tr, y_tr, ev_tr, X_te, y_te, ev_te, models, norm, seed) -> dict:
    """Leave-one-scenario-out: retrain XGBoost *without* one attack type and see if it still finds it.

    This is the honest test of a supervised detector - real attackers do not
    repeat the exact attacks you have labels for.
    """
    out = {}
    scen_tr = np.asarray([e.truth.scenario if e.truth else "" for e in ev_tr])
    scen_te = np.asarray([e.truth.scenario if e.truth else "" for e in ev_te])
    for scenario in sorted(set(scen_te) - {""}):
        keep = scen_tr != scenario
        xgb = XGBoostDetector(seed).fit(X_tr[keep], y_tr[keep])
        mask = scen_te == scenario
        unseen = (xgb.score(X_te[mask]) >= models["xgboost"].threshold).mean()
        out[scenario] = {
            "xgboost_seen": round(float((norm["xgboost"][mask] >= 1).mean()), 3),
            "xgboost_unseen": round(float(unseen), 3),
            "autoencoder": round(float((norm["autoencoder"][mask] >= 1).mean()), 3),
            "isolation_forest": round(float((norm["isolation_forest"][mask] >= 1).mean()), 3),
            "ensemble": round(float((norm["ensemble"][mask] >= 1).mean()), 3),
        }
    return out


def _measure_latency(fx: FeatureExtractor, models: dict, events: list[Event]) -> dict:
    fx = copy.deepcopy(fx)
    out: dict[str, dict] = {}
    t = time.perf_counter()
    X = np.vstack([fx.transform(e) for e in events])
    feat_ms = (time.perf_counter() - t) * 1000 / len(events)
    out["feature_extraction"] = {"per_event": round(feat_ms, 4)}
    for name, m in models.items():
        if name == "markov_sequence":
            m.reset_state()
            t = time.perf_counter()
            m.score_events(events)
            per = (time.perf_counter() - t) * 1000 / len(events)
            out[name] = {"batched_per_event": round(per, 4), "single_event": round(per, 4)}
            continue
        t = time.perf_counter()
        m.score(X)
        batched = (time.perf_counter() - t) * 1000 / len(events)
        singles = []
        for i in range(50):
            t = time.perf_counter()
            m.score(X[i : i + 1])
            singles.append((time.perf_counter() - t) * 1000)
        out[name] = {"batched_per_event": round(batched, 4), "single_event": round(float(np.median(singles)), 3),
                     "single_event_p99": round(float(np.quantile(singles, 0.99)), 3)}
    return out


def render_report(r: dict) -> str:
    lines = [
        "# Aegis ML evaluation report",
        "",
        f"Generated {r['generated_at']} by `aegis train` (seed {r['seed']}). "
        "All numbers are on the held-out **test** split (different days and random seed than training).",
        "",
        "## Data",
        "",
        "| split | events | malicious |",
        "|---|---:|---:|",
        f"| train | {r['data']['train_events']:,} | {r['data']['train_malicious']:,} |",
        f"| validation | {r['data']['validation_events']:,} | {r['data']['validation_malicious']:,} |",
        f"| test | {r['data']['test_events']:,} | {r['data']['test_malicious']:,} |",
        "",
        f"Features per event: {r['data']['features']}. Unsupervised thresholds target a "
        f"{r['target_fpr_unsupervised']:.1%} false-positive rate on benign validation events; "
        "XGBoost's threshold maximizes F1 on validation.",
        "",
        "## Event-level detection quality",
        "",
        "| detector | precision | recall | F1 | FPR | ROC-AUC | PR-AUC | TP | FP | FN |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, m in r["results"].items():
        lines.append(
            f"| {name} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['false_positive_rate']:.4f} | "
            f"{m.get('roc_auc', '-')} | {m.get('pr_auc', '-')} | {m['tp']} | {m['fp']} | {m['fn']} |"
        )
    scen = sorted({s for m in r["results"].values() for s in m["scenario_detection"]})
    lines += ["", "## Attack-instance detection (caught at least one event of the attack)", "",
              "| detector | " + " | ".join(scen) + " |", "|---|" + "---:|" * len(scen)]
    for name, m in r["results"].items():
        lines.append(f"| {name} | " + " | ".join(m["scenario_detection"].get(s, "-") for s in scen) + " |")
    lines += ["", "## Inference latency (milliseconds per event, CPU)", "",
              "| stage / model | batched (500-1000 events) | single event (median) |", "|---|---:|---:|"]
    for name, m in r["latency_ms"].items():
        lines.append(f"| {name} | {m.get('batched_per_event', m.get('per_event'))} | {m.get('single_event', '-')} |")
    lines += ["", "## Novel-attack test (event recall per scenario)", "",
              "`xgboost_unseen` = XGBoost retrained with that scenario removed from its training data.", "",
              "| scenario | xgboost (seen) | xgboost (unseen) | autoencoder | isolation_forest | ensemble |",
              "|---|---:|---:|---:|---:|---:|"]
    for s, m in r["novel_attack_recall"].items():
        lines.append(f"| {s} | {m['xgboost_seen']} | {m['xgboost_unseen']} | {m['autoencoder']} | "
                     f"{m['isolation_forest']} | {m['ensemble']} |")
    lines += ["", "## Most important XGBoost features", ""]
    lines += [f"- `{f}` ({w})" for f, w in r["xgboost_top_features"]]
    lines += ["", "## How to read this", "",
              "- **Precision**: of the events we flagged, how many were really malicious (analyst time well spent).",
              "- **Recall**: of the malicious events, how many we flagged.",
              "- **FPR**: share of benign events flagged. At SIEM volumes even 0.5% is a lot - this is why the "
              "correlator groups alerts into incidents instead of paging on every alert.",
              "- Event-level recall is naturally below 100%: many attacker actions (e.g. a `DescribeInstances`) "
              "look exactly like normal work. Attack-instance detection is the number that matters for response.",
              "- XGBoost scores well because it is trained on labels from the *same simulator* - in the real world "
              "labels are scarce and attacks evolve, which is why unsupervised models are kept alongside it.",
              ""]
    return "\n".join(lines)
