from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

from verifier.skyseal_verify import encode_base64url


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    orcid TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    user_handle BLOB NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    orcid TEXT NOT NULL REFERENCES users(orcid) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_states (
    state_hash TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS registration_challenges (
    registration_hash TEXT PRIMARY KEY,
    orcid TEXT NOT NULL REFERENCES users(orcid) ON DELETE CASCADE,
    challenge BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    credential_id_hash TEXT PRIMARY KEY,
    raw_id BLOB NOT NULL UNIQUE,
    orcid TEXT NOT NULL REFERENCES users(orcid) ON DELETE CASCADE,
    algorithm INTEGER NOT NULL,
    jwk_json TEXT NOT NULL,
    transports_json TEXT NOT NULL,
    sign_count INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS credentials_orcid_status
ON credentials(orcid, status);

CREATE TABLE IF NOT EXISTS identities (
    orcid TEXT PRIMARY KEY REFERENCES users(orcid) ON DELETE CASCADE,
    genesis_json BLOB NOT NULL,
    genesis_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending_openpgp', 'active')),
    openpgp_signature BLOB,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_tokens (
    token_hash TEXT PRIMARY KEY,
    orcid TEXT NOT NULL REFERENCES users(orcid) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);

CREATE INDEX IF NOT EXISTS agent_tokens_orcid_status
ON agent_tokens(orcid, status);

CREATE TABLE IF NOT EXISTS seals (
    seal_id TEXT PRIMARY KEY,
    bearer_hash TEXT NOT NULL UNIQUE,
    commitment_format TEXT NOT NULL,
    subject_digest TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    source TEXT NOT NULL DEFAULT 'interactive' CHECK (source IN ('interactive', 'drive_agent')),
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'awaiting_assertion', 'approved', 'expired', 'rejected', 'invalidated')
    ),
    identity_id TEXT,
    payload_json BLOB,
    challenge BLOB,
    challenge_expires_at INTEGER,
    assertion_hash TEXT,
    bundle_json BLOB,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
"""


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


class Store:
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
                seal_columns = {
                    row["name"] for row in connection.execute("PRAGMA table_info(seals)")
                }
                if "source" not in seal_columns:
                    connection.execute(
                        "ALTER TABLE seals ADD COLUMN source TEXT NOT NULL DEFAULT 'interactive'"
                    )
        finally:
            os.umask(previous_umask)
        for candidate in (
            self.database_path,
            Path(str(self.database_path) + "-wal"),
            Path(str(self.database_path) + "-shm"),
        ):
            if candidate.exists():
                os.chmod(candidate, 0o600)

    def create_oauth_state(self, lifetime_seconds: int = 600) -> str:
        state = encode_base64url(secrets.token_bytes(32))
        now = int(time.time())
        with self.connect() as connection:
            connection.execute("DELETE FROM oauth_states WHERE expires_at < ?", (now,))
            connection.execute(
                "INSERT INTO oauth_states VALUES (?, ?, ?)",
                (token_hash(state), now, now + lifetime_seconds),
            )
        return state

    def consume_oauth_state(self, state: str) -> bool:
        now = int(time.time())
        hashed = token_hash(state)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT expires_at FROM oauth_states WHERE state_hash = ?", (hashed,)
            ).fetchone()
            connection.execute("DELETE FROM oauth_states WHERE state_hash = ?", (hashed,))
        return row is not None and row["expires_at"] >= now

    def upsert_user(self, orcid: str, display_name: str) -> sqlite3.Row:
        now = int(time.time())
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM users WHERE orcid = ?", (orcid,)).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO users VALUES (?, ?, ?, ?, ?)",
                    (orcid, display_name, secrets.token_bytes(32), now, now),
                )
            else:
                connection.execute(
                    "UPDATE users SET display_name = ?, updated_at = ? WHERE orcid = ?",
                    (display_name, now, orcid),
                )
            return connection.execute("SELECT * FROM users WHERE orcid = ?", (orcid,)).fetchone()

    def get_user(self, orcid: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute("SELECT * FROM users WHERE orcid = ?", (orcid,)).fetchone()

    def create_session(self, orcid: str, lifetime_seconds: int) -> tuple[str, str]:
        raw_token = encode_base64url(secrets.token_bytes(32))
        csrf = encode_base64url(secrets.token_bytes(32))
        now = int(time.time())
        with self.connect() as connection:
            connection.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            connection.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
                (token_hash(raw_token), orcid, csrf, now, now + lifetime_seconds),
            )
        return raw_token, csrf

    def get_session(self, raw_token: str | None) -> sqlite3.Row | None:
        if not raw_token:
            return None
        now = int(time.time())
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT sessions.*, users.display_name, users.user_handle
                FROM sessions JOIN users USING(orcid)
                WHERE token_hash = ? AND expires_at >= ?
                """,
                (token_hash(raw_token), now),
            ).fetchone()
        return row

    def delete_session(self, raw_token: str | None) -> None:
        if not raw_token:
            return
        with self.connect() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(raw_token),))

    def create_registration_challenge(self, orcid: str, lifetime_seconds: int = 300) -> tuple[str, bytes]:
        registration_id = encode_base64url(secrets.token_bytes(32))
        challenge = secrets.token_bytes(32)
        now = int(time.time())
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM registration_challenges WHERE expires_at < ?", (now,)
            )
            connection.execute(
                "INSERT INTO registration_challenges VALUES (?, ?, ?, ?, ?)",
                (
                    token_hash(registration_id),
                    orcid,
                    challenge,
                    now,
                    now + lifetime_seconds,
                ),
            )
        return registration_id, challenge

    def consume_registration_challenge(self, registration_id: str, orcid: str) -> bytes | None:
        now = int(time.time())
        hashed = token_hash(registration_id)
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT challenge, expires_at FROM registration_challenges
                WHERE registration_hash = ? AND orcid = ?
                """,
                (hashed, orcid),
            ).fetchone()
            connection.execute(
                "DELETE FROM registration_challenges WHERE registration_hash = ?", (hashed,)
            )
        if row is None or row["expires_at"] < now:
            return None
        return bytes(row["challenge"])

    def add_credential(
        self,
        *,
        orcid: str,
        raw_id: bytes,
        algorithm: int,
        jwk: dict[str, str],
        transports: list[str],
        sign_count: int,
    ) -> str:
        credential_hash = hashlib.sha256(raw_id).hexdigest()
        now = int(time.time())
        try:
            with self.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO credentials VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
                    """,
                    (
                        credential_hash,
                        raw_id,
                        orcid,
                        algorithm,
                        json.dumps(jwk, sort_keys=True, separators=(",", ":")),
                        json.dumps(transports, sort_keys=True, separators=(",", ":")),
                        sign_count,
                        now,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("credential ID is already registered") from exc
        return "sha256:" + credential_hash

    def list_active_credentials(self, orcid: str) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return list(
                connection.execute(
                    "SELECT * FROM credentials WHERE orcid = ? AND status = 'active' ORDER BY created_at",
                    (orcid,),
                ).fetchall()
            )

    def get_credential(self, raw_id: bytes) -> sqlite3.Row | None:
        credential_hash = hashlib.sha256(raw_id).hexdigest()
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM credentials WHERE credential_id_hash = ?", (credential_hash,)
            ).fetchone()
        if row is None or bytes(row["raw_id"]) != raw_id:
            return None
        return row

    def update_sign_count(self, credential_hash: str, sign_count: int) -> None:
        now = int(time.time())
        with self.connect() as connection:
            connection.execute(
                "UPDATE credentials SET sign_count = ?, updated_at = ? WHERE credential_id_hash = ?",
                (sign_count, now, credential_hash),
            )

    def create_identity(
        self, orcid: str, genesis_json: bytes, genesis_digest: str
    ) -> sqlite3.Row:
        now = int(time.time())
        with self.connect() as connection:
            existing = connection.execute(
                "SELECT * FROM identities WHERE orcid = ?", (orcid,)
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO identities
                    (orcid, genesis_json, genesis_digest, status, created_at, updated_at)
                    VALUES (?, ?, ?, 'pending_openpgp', ?, ?)
                    """,
                    (orcid, genesis_json, genesis_digest, now, now),
                )
            return connection.execute(
                "SELECT * FROM identities WHERE orcid = ?", (orcid,)
            ).fetchone()

    def get_identity(self, orcid: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM identities WHERE orcid = ?", (orcid,)
            ).fetchone()

    def activate_identity(self, orcid: str, signature: bytes) -> None:
        now = int(time.time())
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE identities
                SET status = 'active', openpgp_signature = ?, updated_at = ?
                WHERE orcid = ?
                """,
                (signature, now, orcid),
            )
            if cursor.rowcount != 1:
                raise ValueError("identity not found")

    def create_agent_token(self, orcid: str) -> str:
        raw_token = encode_base64url(secrets.token_bytes(32))
        now = int(time.time())
        with self.connect() as connection:
            identity = connection.execute(
                "SELECT status FROM identities WHERE orcid = ?", (orcid,)
            ).fetchone()
            if identity is None or identity["status"] != "active":
                raise ValueError("an active OpenPGP-verified identity is required")
            connection.execute(
                "INSERT INTO agent_tokens VALUES (?, ?, 'active', ?, NULL)",
                (token_hash(raw_token), orcid, now),
            )
        return raw_token

    def get_agent(self, raw_token: str | None) -> sqlite3.Row | None:
        if not raw_token:
            return None
        now = int(time.time())
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT agent_tokens.*, users.display_name
                FROM agent_tokens JOIN users USING(orcid)
                WHERE token_hash = ? AND status = 'active'
                """,
                (token_hash(raw_token),),
            ).fetchone()
            if row is not None:
                connection.execute(
                    "UPDATE agent_tokens SET last_used_at = ? WHERE token_hash = ?",
                    (now, token_hash(raw_token)),
                )
        return row

    def create_seal(
        self,
        *,
        seal_id: str,
        commitment_format: str,
        subject_digest: str,
        entry_count: int,
        lifetime_seconds: int,
        identity_id: str | None = None,
        source: str = "interactive",
    ) -> tuple[str, sqlite3.Row]:
        bearer = encode_base64url(secrets.token_bytes(32))
        now = int(time.time())
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO seals
                (seal_id, bearer_hash, commitment_format, subject_digest, entry_count,
                 source, status, identity_id, created_at, expires_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)
                """,
                (
                    seal_id,
                    token_hash(bearer),
                    commitment_format,
                    subject_digest,
                    entry_count,
                    source,
                    identity_id,
                    now,
                    now + lifetime_seconds,
                    now,
                ),
            )
            row = connection.execute("SELECT * FROM seals WHERE seal_id = ?", (seal_id,)).fetchone()
        return bearer, row

    def list_pending_seals(self, orcid: str) -> list[sqlite3.Row]:
        now = int(time.time())
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE seals SET status = 'expired', updated_at = ?
                WHERE expires_at < ? AND status IN ('pending', 'awaiting_assertion')
                """,
                (now, now),
            )
            return list(
                connection.execute(
                    """
                    SELECT seal_id, entry_count, status, created_at, expires_at
                    FROM seals
                    WHERE identity_id = ? AND source = 'drive_agent'
                      AND status IN ('pending', 'awaiting_assertion')
                    ORDER BY created_at, seal_id
                    """,
                    (orcid,),
                ).fetchall()
            )

    def get_seal_for_identity(self, seal_id: str, orcid: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM seals WHERE seal_id = ? AND identity_id = ?",
                (seal_id, orcid),
            ).fetchone()

    def get_seal(self, seal_id: str, bearer: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM seals WHERE seal_id = ? AND bearer_hash = ?",
                (seal_id, token_hash(bearer)),
            ).fetchone()
        if row is None:
            return None
        if row["expires_at"] < int(time.time()) and row["status"] not in {"approved", "expired"}:
            with self.connect() as connection:
                connection.execute(
                    "UPDATE seals SET status = 'expired', updated_at = ? WHERE seal_id = ?",
                    (int(time.time()), seal_id),
                )
            return self.get_seal(seal_id, bearer)
        return row

    def set_seal_options(
        self,
        *,
        seal_id: str,
        identity_id: str,
        payload_json: bytes,
        challenge: bytes,
        challenge_lifetime_seconds: int,
    ) -> sqlite3.Row:
        now = int(time.time())
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE seals
                SET identity_id = ?, payload_json = ?, challenge = ?,
                    challenge_expires_at = ?, status = 'awaiting_assertion', updated_at = ?
                WHERE seal_id = ? AND status IN ('pending', 'awaiting_assertion')
                """,
                (
                    identity_id,
                    payload_json,
                    challenge,
                    now + challenge_lifetime_seconds,
                    now,
                    seal_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("seal is not available for approval")
            return connection.execute("SELECT * FROM seals WHERE seal_id = ?", (seal_id,)).fetchone()

    def approve_seal(
        self,
        *,
        seal_id: str,
        assertion_hash: str,
        bundle_json: bytes,
    ) -> sqlite3.Row:
        now = int(time.time())
        with self.connect() as connection:
            current = connection.execute(
                "SELECT * FROM seals WHERE seal_id = ?", (seal_id,)
            ).fetchone()
            if current is None:
                raise ValueError("seal not found")
            if current["status"] == "approved":
                if current["assertion_hash"] == assertion_hash:
                    return current
                raise ValueError("seal already approved by a different assertion")
            if current["status"] != "awaiting_assertion":
                raise ValueError("seal is not awaiting an assertion")
            if current["challenge_expires_at"] < now:
                connection.execute(
                    "UPDATE seals SET status = 'expired', updated_at = ? WHERE seal_id = ?",
                    (now, seal_id),
                )
                raise ValueError("assertion challenge expired")
            connection.execute(
                """
                UPDATE seals
                SET assertion_hash = ?, bundle_json = ?, status = 'approved',
                    challenge = NULL, updated_at = ?
                WHERE seal_id = ?
                """,
                (assertion_hash, bundle_json, now, seal_id),
            )
            return connection.execute("SELECT * FROM seals WHERE seal_id = ?", (seal_id,)).fetchone()
