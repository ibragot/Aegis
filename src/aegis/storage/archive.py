"""Raw-log archive ("data lake") on S3.

SIEMs keep hot data (recent events) in a fast database and cold data (all raw
logs, months/years for compliance and forensics) in cheap object storage.
Records are written as gzip-compressed JSON Lines under Hive-style partitions:

    s3://<bucket>/raw/source=cloudtrail/dt=2026-09-14/hour=14/<uuid>.jsonl.gz

That layout can be queried directly with Amazon Athena / Spark
(`WHERE source='cloudtrail' AND dt='2026-09-14'`) without loading it anywhere.
Locally (no bucket configured) the same files go to `data/archive/`. Under
docker compose, MinIO provides an S3-compatible API.
"""

from __future__ import annotations

import gzip
import json
import logging
import time
import uuid
from collections import defaultdict
from pathlib import Path

from aegis.collectors import parse_timestamp_from_envelope
from aegis.config import Settings, get_settings
from aegis.observability import metrics

log = logging.getLogger(__name__)


class Archiver:
    def __init__(self, settings: Settings | None = None, max_records: int = 2000, max_age_s: float = 30):
        self.settings = settings or get_settings()
        self.max_records, self.max_age_s = max_records, max_age_s
        self._buf: dict[str, list[dict]] = defaultdict(list)
        self._since = time.monotonic()
        self._s3 = None
        if self.settings.s3_bucket:
            import boto3

            self._s3 = boto3.client("s3", endpoint_url=self.settings.s3_endpoint_url)
            self._ensure_bucket()

    def _ensure_bucket(self) -> None:
        try:
            self._s3.head_bucket(Bucket=self.settings.s3_bucket)
        except Exception:
            try:
                self._s3.create_bucket(Bucket=self.settings.s3_bucket)
            except Exception as exc:  # bucket is normally created by Terraform
                log.warning("could not create bucket: %s", exc)

    def add(self, env: dict) -> None:
        ts = parse_timestamp_from_envelope(env)
        key = f"raw/source={env['source']}/dt={ts:%Y-%m-%d}/hour={ts:%H}"
        self._buf[key].append(env)
        if sum(len(v) for v in self._buf.values()) >= self.max_records or time.monotonic() - self._since > self.max_age_s:
            self.flush()

    def flush(self) -> None:
        for prefix, records in self._buf.items():
            if not records:
                continue
            body = gzip.compress("\n".join(json.dumps(r, default=str) for r in records).encode())
            name = f"{prefix}/{uuid.uuid4().hex}.jsonl.gz"
            try:
                if self._s3:
                    self._s3.put_object(Bucket=self.settings.s3_bucket, Key=name, Body=body,
                                        ContentEncoding="gzip", ContentType="application/x-ndjson")
                else:
                    path = Path(self.settings.archive_dir) / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(body)
                metrics.RAW_ARCHIVED.inc(len(records))
            except Exception:
                log.exception("archive write failed for %s", name)
        self._buf.clear()
        self._since = time.monotonic()
