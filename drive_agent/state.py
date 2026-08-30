from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from pathlib import Path

from drive_agent.google_drive import DriveUnit, validate_hash_list_bytes


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS units (
    unit_ref TEXT PRIMARY KEY,
    drive_unit_id TEXT NOT NULL UNIQUE,
    root_mime_type TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL,
    stable_since INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    last_submitted_snapshot TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
    job_id INTEGER PRIMARY KEY AUTOINCREMENT,
    unit_ref TEXT NOT NULL REFERENCES units(unit_ref) ON DELETE RESTRICT,
    snapshot_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('pending_approval', 'approved', 'published', 'error')
    ),
    hash_list BLOB NOT NULL,
    subject_digest TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    seal_id TEXT NOT NULL UNIQUE,
    bearer_token TEXT NOT NULL,
    approval_url TEXT NOT NULL,
    bundle_json BLOB,
    genesis_json BLOB,
    identity_activation BLOB,
    ots_proof BLOB,
    identity_ots_proof BLOB,
    publication_prefix TEXT,
    github_status TEXT NOT NULL DEFAULT 'pending',
    github_error TEXT,
    error_code TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(unit_ref, snapshot_digest)
);

CREATE INDEX IF NOT EXISTS jobs_status_created
ON jobs(status, created_at);
"""


def unit_reference(drive_unit_id: str) -> str:
    return hashlib.sha256(("SkySeal Drive Unit v1\0" + drive_unit_id).encode("utf-8")).hexdigest()


class AgentStore:
    def __init__(self, database_path: Path):
        self.database_path = database_path

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        previous_umask = os.umask(0o077)
        try:
            with self.connect() as connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.executescript(SCHEMA)
                job_columns = {
                    row["name"] for row in connection.execute("PRAGMA table_info(jobs)")
                }
                if "identity_activation" not in job_columns:
                    connection.execute("ALTER TABLE jobs ADD COLUMN identity_activation BLOB")
                if "identity_ots_proof" not in job_columns:
                    connection.execute("ALTER TABLE jobs ADD COLUMN identity_ots_proof BLOB")
                if "github_status" not in job_columns:
                    connection.execute(
                        "ALTER TABLE jobs ADD COLUMN github_status TEXT NOT NULL DEFAULT 'pending'"
                    )
                    connection.execute(
                        "UPDATE jobs SET github_status = 'synced' WHERE status = 'published'"
                    )
                if "github_error" not in job_columns:
                    connection.execute("ALTER TABLE jobs ADD COLUMN github_error TEXT")
        finally:
            os.umask(previous_umask)
        for candidate in (
            self.database_path,
            Path(str(self.database_path) + "-wal"),
            Path(str(self.database_path) + "-shm"),
        ):
            if candidate.exists():
                os.chmod(candidate, 0o600)

    def observe(self, unit: DriveUnit, now: int | None = None) -> str:
        observed_at = int(time.time()) if now is None else now
        reference = unit_reference(unit.root.file_id)
        with self.connect() as connection:
            current = connection.execute(
                "SELECT * FROM units WHERE unit_ref = ?", (reference,)
            ).fetchone()
            if current is None:
                connection.execute(
                    """
                    INSERT INTO units
                    (unit_ref, drive_unit_id, root_mime_type, snapshot_digest,
                     stable_since, last_seen, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        reference,
                        unit.root.file_id,
                        unit.root.mime_type,
                        unit.snapshot_digest,
                        observed_at,
                        observed_at,
                        observed_at,
                        observed_at,
                    ),
                )
            else:
                stable_since = (
                    current["stable_since"]
                    if current["snapshot_digest"] == unit.snapshot_digest
                    else observed_at
                )
                connection.execute(
                    """
                    UPDATE units
                    SET root_mime_type = ?, snapshot_digest = ?, stable_since = ?,
                        last_seen = ?, updated_at = ?
                    WHERE unit_ref = ?
                    """,
                    (
                        unit.root.mime_type,
                        unit.snapshot_digest,
                        stable_since,
                        observed_at,
                        observed_at,
                        reference,
                    ),
                )
        return reference

    def ready_units(self, settle_seconds: int, now: int | None = None) -> list[sqlite3.Row]:
        observed_at = int(time.time()) if now is None else now
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM units
                WHERE stable_since <= ?
                  AND (last_submitted_snapshot IS NULL OR last_submitted_snapshot != snapshot_digest)
                ORDER BY stable_since, unit_ref
                """,
                (observed_at - settle_seconds,),
            ).fetchall()
        return list(rows)

    def add_job(
        self,
        *,
        unit_ref: str,
        snapshot_digest: str,
        hash_list: bytes,
        seal_id: str,
        bearer_token: str,
        approval_url: str,
        now: int | None = None,
    ) -> sqlite3.Row:
        created_at = int(time.time()) if now is None else now
        records = validate_hash_list_bytes(hash_list)
        subject_digest = hashlib.sha256(hash_list).hexdigest()
        with self.connect() as connection:
            current = connection.execute(
                "SELECT snapshot_digest FROM units WHERE unit_ref = ?", (unit_ref,)
            ).fetchone()
            if current is None or current["snapshot_digest"] != snapshot_digest:
                raise ValueError("unit changed before the job could be recorded")
            connection.execute(
                """
                INSERT INTO jobs
                (unit_ref, snapshot_digest, status, hash_list, subject_digest,
                 entry_count, seal_id, bearer_token, approval_url, created_at, updated_at)
                VALUES (?, ?, 'pending_approval', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    unit_ref,
                    snapshot_digest,
                    hash_list,
                    subject_digest,
                    len(records),
                    seal_id,
                    bearer_token,
                    approval_url,
                    created_at,
                    created_at,
                ),
            )
            connection.execute(
                "UPDATE units SET last_submitted_snapshot = ?, updated_at = ? WHERE unit_ref = ?",
                (snapshot_digest, created_at, unit_ref),
            )
            return connection.execute(
                "SELECT * FROM jobs WHERE seal_id = ?", (seal_id,)
            ).fetchone()

    def jobs_with_status(self, *statuses: str) -> list[sqlite3.Row]:
        if not statuses:
            return []
        placeholders = ",".join("?" for _ in statuses)
        with self.connect() as connection:
            return list(
                connection.execute(
                    f"SELECT * FROM jobs WHERE status IN ({placeholders}) ORDER BY created_at, job_id",
                    statuses,
                ).fetchall()
            )

    def jobs_needing_github_mirror(self) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return list(
                connection.execute(
                    """
                    SELECT * FROM jobs
                    WHERE status = 'published' AND github_status != 'synced'
                    ORDER BY created_at, job_id
                    """
                ).fetchall()
            )

    def store_approved_artifacts(
        self,
        seal_id: str,
        *,
        bundle_json: bytes,
        genesis_json: bytes,
        identity_activation: bytes,
    ) -> None:
        now = int(time.time())
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE jobs
                SET status = 'approved', bundle_json = ?, genesis_json = ?,
                    identity_activation = ?, updated_at = ?, error_code = NULL
                WHERE seal_id = ? AND status IN ('pending_approval', 'approved')
                """,
                (bundle_json, genesis_json, identity_activation, now, seal_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("job is not available for artifact storage")

    def get_job(self, seal_id: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM jobs WHERE seal_id = ?", (seal_id,)
            ).fetchone()

    def store_timestamp_proofs(
        self, seal_id: str, ots_proof: bytes, identity_ots_proof: bytes
    ) -> None:
        now = int(time.time())
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE jobs
                SET ots_proof = ?, identity_ots_proof = ?, updated_at = ?
                WHERE seal_id = ? AND status = 'approved'
                """,
                (ots_proof, identity_ots_proof, now, seal_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("approved job not found")

    def mark_published(
        self,
        seal_id: str,
        ots_proof: bytes,
        identity_ots_proof: bytes,
        publication_prefix: str,
    ) -> None:
        now = int(time.time())
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE jobs
                SET status = 'published', ots_proof = ?, identity_ots_proof = ?, publication_prefix = ?,
                    github_status = 'pending', github_error = NULL,
                    updated_at = ?, error_code = NULL
                WHERE seal_id = ? AND status IN ('approved', 'published')
                """,
                (ots_proof, identity_ots_proof, publication_prefix, now, seal_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("job is not available for publication")

    def update_ots_proofs(
        self, seal_id: str, ots_proof: bytes, identity_ots_proof: bytes
    ) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE jobs
                SET ots_proof = ?, identity_ots_proof = ?, github_status = 'pending',
                    github_error = NULL, updated_at = ?
                WHERE seal_id = ? AND status = 'published'
                """,
                (ots_proof, identity_ots_proof, int(time.time()), seal_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("published job not found")

    def mark_github_synced(self, seal_id: str) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE jobs
                SET github_status = 'synced', github_error = NULL, updated_at = ?
                WHERE seal_id = ? AND status = 'published'
                """,
                (int(time.time()), seal_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("published job not found for GitHub mirror state")

    def mark_github_pending(self, seal_id: str, error: str) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE jobs
                SET github_status = 'pending', github_error = ?, updated_at = ?
                WHERE seal_id = ? AND status = 'published'
                """,
                (error[:120], int(time.time()), seal_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("published job not found for GitHub retry state")

    def mark_error(self, seal_id: str, error_code: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE jobs SET status = 'error', error_code = ?, updated_at = ? WHERE seal_id = ?",
                (error_code[:120], int(time.time()), seal_id),
            )
