"""Central configuration.

Every setting comes from an environment variable (12-factor style) so the same
container image can run locally under docker compose or on EKS, where the values
come from a ConfigMap / Secret. Defaults are chosen so `aegis demo` works with
no infrastructure at all (in-memory bus, SQLite, no Redis, no S3).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _env_bool(name: str, default: bool) -> bool:
    value = _env(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _resolve_dir(env_name: str, default_relative: str) -> Path:
    value = _env(env_name)
    if value:
        return Path(value)
    # Inside the Docker image the package is installed but the data folders are
    # copied to /app; locally they live at the repo root.
    for base in (REPO_ROOT, Path("/app"), Path.cwd()):
        candidate = base / default_relative
        if candidate.exists():
            return candidate
    return REPO_ROOT / default_relative


@dataclass(frozen=True)
class Settings:
    # --- Event bus --------------------------------------------------------
    bus: str = field(default_factory=lambda: _env("AEGIS_BUS", "memory"))  # memory | kafka
    kafka_bootstrap: str = field(default_factory=lambda: _env("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"))
    kafka_partitions: int = field(default_factory=lambda: int(_env("KAFKA_PARTITIONS", "6")))
    kafka_replication: int = field(default_factory=lambda: int(_env("KAFKA_REPLICATION_FACTOR", "1")))
    kafka_security_protocol: str = field(default_factory=lambda: _env("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT"))

    # --- Storage ----------------------------------------------------------
    database_url: str = field(default_factory=lambda: _env("DATABASE_URL", "sqlite:///data/aegis.db"))
    redis_url: str | None = field(default_factory=lambda: _env("REDIS_URL"))
    s3_bucket: str | None = field(default_factory=lambda: _env("AEGIS_ARCHIVE_BUCKET"))
    s3_endpoint_url: str | None = field(default_factory=lambda: _env("S3_ENDPOINT_URL"))
    archive_dir: Path = field(default_factory=lambda: Path(_env("AEGIS_ARCHIVE_DIR", "data/archive")))

    # --- Paths ------------------------------------------------------------
    rules_dir: Path = field(default_factory=lambda: _resolve_dir("AEGIS_RULES_DIR", "config/rules"))
    knowledge_dir: Path = field(default_factory=lambda: _resolve_dir("AEGIS_KNOWLEDGE_DIR", "knowledge"))
    model_dir: Path = field(default_factory=lambda: Path(_env("AEGIS_MODEL_DIR", str(REPO_ROOT / "models"))))

    # --- Detection --------------------------------------------------------
    ml_model: str = field(default_factory=lambda: _env("AEGIS_ML_MODEL", "ensemble"))
    correlation_window_minutes: int = field(default_factory=lambda: int(_env("AEGIS_CORRELATION_WINDOW_MIN", "60")))
    investigate_min_level: str = field(default_factory=lambda: _env("AEGIS_INVESTIGATE_MIN_LEVEL", "MEDIUM"))

    # --- AI investigator --------------------------------------------------
    llm_enabled: bool = field(default_factory=lambda: _env_bool("AEGIS_LLM_ENABLED", True))
    llm_model: str = field(default_factory=lambda: _env("AEGIS_LLM_MODEL", "claude-opus-5-5"))
    llm_effort: str = field(default_factory=lambda: _env("AEGIS_LLM_EFFORT", "high"))
    llm_fallbacks: bool = field(default_factory=lambda: _env_bool("AEGIS_LLM_FALLBACKS", True))

    # --- Simulator --------------------------------------------------------
    generator_rate: float = field(default_factory=lambda: float(_env("AEGIS_GENERATOR_EPS", "5")))
    attack_interval_seconds: int = field(default_factory=lambda: int(_env("AEGIS_ATTACK_INTERVAL_S", "300")))
    seed: int = field(default_factory=lambda: int(_env("AEGIS_SEED", "7")))

    # --- Observability ----------------------------------------------------
    metrics_port: int = field(default_factory=lambda: int(_env("AEGIS_METRICS_PORT", "9100")))
    otel_endpoint: str | None = field(default_factory=lambda: _env("OTEL_EXPORTER_OTLP_ENDPOINT"))
    service_name: str = field(default_factory=lambda: _env("AEGIS_SERVICE_NAME", "aegis"))
    log_level: str = field(default_factory=lambda: _env("AEGIS_LOG_LEVEL", "INFO"))


def get_settings() -> Settings:
    return Settings()
