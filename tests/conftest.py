from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

# Tests never call a real LLM and never touch infrastructure.
os.environ["AEGIS_LLM_ENABLED"] = "false"
os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ["AEGIS_BUS"] = "memory"

from aegis.config import Settings  # noqa: E402

START = datetime(2026, 9, 14, 14, 3, tzinfo=UTC)


@pytest.fixture(scope="session")
def ml_artifact(tmp_path_factory):
    """A small but real trained model (a few seconds) shared by the whole test session."""
    from aegis.ml.pipeline import ARTIFACT_NAME, train_and_evaluate

    model_dir: Path = tmp_path_factory.mktemp("models")
    report = train_and_evaluate(model_dir=model_dir, report_dir=model_dir / "reports", train_days=5, val_days=2,
                                test_days=2)
    import joblib

    return {"artifact": joblib.load(model_dir / ARTIFACT_NAME), "report": report, "dir": model_dir}


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(database_url="sqlite://", archive_dir=tmp_path / "archive", llm_enabled=False)


@pytest.fixture
def pipeline(settings, ml_artifact):
    from aegis.ml.inference import MLEngine
    from aegis.pipeline import LocalPipeline

    engine = MLEngine(artifact=_fresh(ml_artifact["artifact"]), model="ensemble")
    p = LocalPipeline(settings, ml_engine=engine)
    p.warm_up(days=1, end=START - timedelta(minutes=10))
    return p


def _fresh(artifact: dict) -> dict:
    import copy

    return copy.deepcopy(artifact)
