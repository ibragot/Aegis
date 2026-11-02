"""Persistence: PostgreSQL (production) or SQLite (local / tests) via SQLAlchemy 2.0,
plus the S3 data-lake archiver for raw logs."""

from aegis.storage.db import Repository, create_repository

__all__ = ["Repository", "create_repository"]
