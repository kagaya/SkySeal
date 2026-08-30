#!/usr/bin/env python3
"""Fail-closed deployment configuration checks without printing secrets."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit

REPOSITORY = Path(__file__).resolve().parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from drive_agent.config import AgentConfig, ConfigurationError  # noqa: E402
from service.config import Config  # noqa: E402


PLACEHOLDER_FRAGMENTS = ("REPLACE", "EXAMPLE", "CHANGEME")
PRODUCTION_PROFILE = json.loads(
    (Path(__file__).with_name("production-profile.json")).read_text(encoding="utf-8")
)
if PRODUCTION_PROFILE.get("schema") != "urn:skyseal:deployment-profile:v1":
    raise RuntimeError("invalid SkySeal production deployment profile")
PRODUCTION_ORIGIN = str(PRODUCTION_PROFILE["service_origin"])
PRODUCTION_RP_ID = str(PRODUCTION_PROFILE["rp_id"])
PRODUCTION_ORCID_REDIRECT = str(PRODUCTION_PROFILE["orcid_redirect_uri"])
if PRODUCTION_ORCID_REDIRECT != f"{PRODUCTION_ORIGIN}/api/v1/orcid/callback":
    raise RuntimeError("production profile ORCID callback does not match its origin")


class Checks:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.notes: list[str] = []

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            self.failures.append(message)

    def note(self, message: str) -> None:
        self.notes.append(message)

    def finish(self) -> int:
        for message in self.notes:
            print(f"NOTE: {message}")
        for message in self.failures:
            print(f"ERROR: {message}", file=sys.stderr)
        if self.failures:
            print(f"Configuration check failed ({len(self.failures)} error(s)).", file=sys.stderr)
            return 1
        print("Configuration check passed.")
        return 0


def configured_secret(name: str) -> bool:
    value = os.getenv(name, "").strip()
    upper = value.upper()
    return bool(value) and not any(fragment in upper for fragment in PLACEHOLDER_FRAGMENTS)


def private_mode(path: Path) -> bool:
    mode = path.stat().st_mode
    return stat.S_ISREG(mode) and not bool(mode & 0o077)


def private_directory(path: Path) -> bool:
    mode = path.stat().st_mode
    return stat.S_ISDIR(mode) and not bool(mode & 0o077)


def public_directory(path: Path) -> bool:
    mode = path.stat().st_mode
    return stat.S_ISDIR(mode) and mode & 0o777 == 0o755


def check_state_path(checks: Checks, path: Path, label: str) -> None:
    parent = path.parent
    checks.require(parent.is_dir(), f"{label} parent directory does not exist: {parent}")
    if parent.is_dir():
        checks.require(private_directory(parent), f"{label} parent must have mode 700: {parent}")
        checks.require(os.access(parent, os.W_OK), f"{label} parent is not writable: {parent}")
    if path.exists():
        checks.require(private_mode(path), f"{label} must be a mode-600 regular file: {path}")


def check_service() -> int:
    checks = Checks()
    try:
        config = Config.from_environment()
    except Exception as exc:
        checks.require(False, f"service configuration is invalid: {exc}")
        return checks.finish()

    parsed = urlsplit(config.origin)
    checks.require(parsed.scheme == "https", "SKYSEAL_ORIGIN must use HTTPS")
    checks.require(
        config.origin == PRODUCTION_ORIGIN,
        f"SKYSEAL_ORIGIN must be the fixed production origin {PRODUCTION_ORIGIN}",
    )
    checks.require(
        config.rp_id == PRODUCTION_RP_ID,
        f"SKYSEAL_RP_ID must be the fixed production RP ID {PRODUCTION_RP_ID}",
    )
    checks.require(
        config.orcid_redirect_uri == PRODUCTION_ORCID_REDIRECT,
        "ORCID redirect URI must match the fixed production callback",
    )
    checks.require(
        config.bind_host in {"127.0.0.1", "::1", "localhost"},
        "the Python service must bind only to loopback behind the HTTPS proxy",
    )
    checks.require(not config.allow_http_localhost, "development HTTP mode must be disabled")
    checks.require(not config.allow_mock_orcid, "mock ORCID mode must be disabled")
    checks.require(
        not config.allow_unsealed_identity,
        "the unsealed-identity bypass must be disabled",
    )
    checks.require(
        config.orcid_base_url == "https://orcid.org",
        "production must use the ORCID production authorization service",
    )
    checks.require(
        configured_secret("SKYSEAL_ORCID_CLIENT_ID"),
        "SKYSEAL_ORCID_CLIENT_ID is missing or still a placeholder",
    )
    checks.require(
        configured_secret("SKYSEAL_ORCID_CLIENT_SECRET"),
        "SKYSEAL_ORCID_CLIENT_SECRET is missing or still a placeholder",
    )
    check_state_path(checks, config.database_path, "service database")
    checks.require(
        config.public_root is not None and config.public_root.is_dir(),
        f"public evidence root does not exist: {config.public_root}",
    )
    if config.public_root is not None and config.public_root.is_dir():
        checks.require(
            public_directory(config.public_root),
            f"public evidence root must have mode 755: {config.public_root}",
        )
        checks.require(
            os.access(config.public_root, os.R_OK),
            f"public evidence root is not readable: {config.public_root}",
        )
    return checks.finish()


def check_service_account(checks: Checks, path: Path) -> None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        checks.require(False, "Google service-account file is not valid JSON")
        return
    checks.require(document.get("type") == "service_account", "Google credential is not a service account")
    checks.require(
        isinstance(document.get("client_email"), str)
        and document["client_email"].endswith(".gserviceaccount.com"),
        "Google service-account client_email is invalid",
    )
    checks.require(
        isinstance(document.get("private_key"), str)
        and document["private_key"].startswith("-----BEGIN PRIVATE KEY-----"),
        "Google service-account private key is missing",
    )


def check_agent() -> int:
    checks = Checks()
    try:
        config = AgentConfig.from_environment()
    except (ConfigurationError, OSError, ValueError) as exc:
        checks.require(False, f"Drive agent configuration is invalid: {exc}")
        return checks.finish()

    checks.require(
        config.skyseal_server == PRODUCTION_ORIGIN,
        f"agent server must be the fixed production origin {PRODUCTION_ORIGIN}",
    )
    checks.require(
        config.skyseal_rp_id == PRODUCTION_RP_ID,
        f"agent RP ID must be the fixed production RP ID {PRODUCTION_RP_ID}",
    )
    check_state_path(checks, config.database_path, "agent database")
    checks.require(
        config.work_directory.parent.is_dir(),
        f"agent work parent directory does not exist: {config.work_directory.parent}",
    )
    if config.work_directory.parent.is_dir():
        checks.require(
            private_directory(config.work_directory.parent),
            f"agent work parent must have mode 700: {config.work_directory.parent}",
        )
    checks.require(
        config.public_root.is_dir(),
        f"public evidence root does not exist: {config.public_root}",
    )
    if config.public_root.is_dir():
        checks.require(
            public_directory(config.public_root),
            f"public evidence root must have mode 755: {config.public_root}",
        )
        checks.require(
            os.access(config.public_root, os.W_OK),
            f"public evidence root is not writable: {config.public_root}",
        )
    checks.require(private_mode(config.google_service_account_file), "Google credential file must have mode 600")
    checks.require(private_mode(config.skyseal_agent_token_file), "SkySeal agent token must have mode 600")
    checks.require(private_mode(config.github_token_file), "GitHub token must have mode 600")
    check_service_account(checks, config.google_service_account_file)

    for executable in ("ots", "flock"):
        checks.require(shutil.which(executable) is not None, f"required command is missing: {executable}")
    if (config.github_owner, config.github_repository) != ("kagaya", "SkySeal"):
        checks.note("GitHub publication target differs from kagaya/SkySeal; verify this is intentional")
    return checks.finish()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("service", "agent"))
    return parser


def main(argv: list[str] | None = None) -> int:
    role = build_parser().parse_args(argv).role
    return check_service() if role == "service" else check_agent()


if __name__ == "__main__":
    raise SystemExit(main())
