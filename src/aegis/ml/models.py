"""The anomaly detectors.

All detectors share one convention: `score()` returns a number where *higher
means more suspicious*, and each detector has a `threshold` chosen on a
validation set. `score / threshold >= 1.0` means "raise an alert", which lets
us compare and combine models with very different raw score scales.

| Model              | Learns from          | Idea                                                   |
|--------------------|----------------------|--------------------------------------------------------|
| Isolation Forest   | unlabeled benign     | anomalies are easy to isolate with random splits       |
| Autoencoder        | unlabeled benign     | a net trained to copy normal data copies anomalies badly|
| XGBoost            | labeled benign+attack| gradient-boosted trees, supervised classification      |
| Markov sequence    | benign action orders | rare *transitions* between actions are suspicious      |
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict, deque

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from aegis.schema import Event


class IsolationForestDetector:
    name = "isolation_forest"

    def __init__(self, seed: int = 0):
        # Isolation Forest builds random trees; points that get isolated after
        # very few splits (short path length) are anomalies.
        self.model = IsolationForest(n_estimators=200, max_samples=512, random_state=seed, n_jobs=1)
        self.threshold = 1.0

    def fit(self, X: np.ndarray, y: np.ndarray | None = None) -> IsolationForestDetector:
        self.model.fit(X)
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        # score_samples is "higher = more normal" in sklearn, so flip the sign.
        return -self.model.score_samples(X)


class AutoencoderDetector:
    name = "autoencoder"

    def __init__(self, seed: int = 0):
        # A bottleneck MLP (input -> 16 -> 6 -> 16 -> input). Trained to reproduce
        # benign feature vectors, it fails to reproduce unusual ones: the
        # reconstruction error is the anomaly score.
        self.scaler = StandardScaler()
        self.model = MLPRegressor(hidden_layer_sizes=(16, 6, 16), activation="relu", max_iter=80,
                                  early_stopping=True, random_state=seed, learning_rate_init=0.003)
        self.threshold = 1.0

    def fit(self, X: np.ndarray, y: np.ndarray | None = None) -> AutoencoderDetector:
        Z = self.scaler.fit_transform(X)
        self.model.fit(Z, Z)
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        Z = self.scaler.transform(X)
        Z = np.clip(Z, -20, 20)
        return np.mean((self.model.predict(Z) - Z) ** 2, axis=1)


class XGBoostDetector:
    name = "xgboost"

    def __init__(self, seed: int = 0):
        from xgboost import XGBClassifier

        self.model = XGBClassifier(n_estimators=250, max_depth=4, learning_rate=0.08, subsample=0.9,
                                   colsample_bytree=0.9, random_state=seed, n_jobs=2, eval_metric="aucpr")
        self.threshold = 0.5

    def fit(self, X: np.ndarray, y: np.ndarray | None = None) -> XGBoostDetector:
        assert y is not None, "XGBoost is supervised"
        pos = max(int(y.sum()), 1)
        self.model.set_params(scale_pos_weight=(len(y) - pos) / pos)  # handle class imbalance
        self.model.fit(X, y)
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)[:, 1]

    def feature_importance(self, names: list[str], top: int = 10) -> list[tuple[str, float]]:
        imp = self.model.feature_importances_
        order = np.argsort(-imp)[:top]
        return [(names[i], round(float(imp[i]), 4)) for i in order]


class MarkovSequenceDetector:
    """First-order Markov chain over each identity's sequence of actions.

    P(action_t | action_{t-1}) is estimated from benign data (global counts,
    with a per-persona back-off). The score of an event is the average
    surprise (-log p) over the identity's last 3 transitions, so one odd call
    does little but a *run* of odd calls (an attacker's playbook) scores high.
    """

    name = "markov_sequence"

    def __init__(self, window: int = 3):
        self.window = window
        self.bigrams: Counter = Counter()
        self.unigrams: Counter = Counter()
        self.vocab: set[str] = set()
        self.threshold = 1.0
        # plain dicts (not defaultdict(lambda)) so the model can be pickled by joblib
        self._last: dict[str, str | None] = {}
        self._hist: dict[str, deque] = {}

    @staticmethod
    def _tok(evt: Event) -> str:
        # include outcome so "failure -> failure -> success" is a distinct pattern
        return f"{evt.category}:{evt.action}:{evt.outcome}"

    def fit_events(self, events: list[Event]) -> MarkovSequenceDetector:
        last: dict[str, str | None] = defaultdict(lambda: None)
        for e in events:
            tok = self._tok(e)
            prev = last[e.entity_key]
            self.bigrams[(prev, tok)] += 1
            self.unigrams[prev] += 1
            self.vocab.add(tok)
            last[e.entity_key] = tok
        return self

    def _surprise(self, prev: str | None, tok: str) -> float:
        v = len(self.vocab) + 1
        p = (self.bigrams[(prev, tok)] + 0.1) / (self.unigrams[prev] + 0.1 * v)
        return -math.log(p)

    def reset_state(self) -> None:
        self._last.clear()
        self._hist.clear()

    def score_event(self, evt: Event) -> float:
        tok = self._tok(evt)
        key = evt.entity_key
        s = self._surprise(self._last.get(key), tok)
        self._last[key] = tok
        h = self._hist.setdefault(key, deque(maxlen=self.window))
        h.append(s)
        return sum(h) / len(h)

    def score_events(self, events: list[Event]) -> np.ndarray:
        return np.asarray([self.score_event(e) for e in events])


def threshold_for_fpr(benign_scores: np.ndarray, target_fpr: float) -> float:
    """Pick the threshold that flags `target_fpr` of benign validation events."""
    return float(np.quantile(benign_scores, 1 - target_fpr))


def threshold_for_f1(scores: np.ndarray, y: np.ndarray) -> float:
    from sklearn.metrics import precision_recall_curve

    prec, rec, thr = precision_recall_curve(y, scores)
    f1 = 2 * prec * rec / np.maximum(prec + rec, 1e-9)
    best = int(np.argmax(f1[:-1])) if len(thr) else 0
    return float(thr[best]) if len(thr) else 0.5
