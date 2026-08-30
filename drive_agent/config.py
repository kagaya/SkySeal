from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


class ConfigurationError(ValueError):
    pass


DRIVE_ID_RE = re.compile(r"[A-Za-z0-9_-]+")


def private_file(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    try:
        mode = resolved.stat().st_mode
    except OSError as exc:
        raise ConfigurationError(f"cannot read {label}: {resolved}") from exc
    if not stat.S_ISREG(mode):
        raise ConfigurationError(f"{label} is not a regular file")
    if os.name == "posix" and mode & 0o077:
        raise ConfigurationError(f"{label} must not be accessible by group or others")
    return resolved


def read_secret(path: Path, label: str) -> str:
    value = private_file(path, label).read_text(encoding="utf-8").strip()
    if not value or "\n" in value or "\r" in value:
        raise ConfigurationError(f"{label} must contain exactly one non-empty line")
    return value


def exact_https_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigurationError("SKYSEAL_AGENT_SERVER must be an exact HTTPS origin")
    port = f":{parsed.port}" if parsed.port is not None else ""
    canonical = f"https://{parsed.hostname.lower()}{port}"
    if canonical != value:
        raise ConfigurationError("SKYSEAL_AGENT_SERVER is not canonical")
    return value


@dataclass(frozen=True)
class AgentConfig:
    database_path: Path
    work_directory: Path
    public_root: Path
    google_service_account_file: Path
    drive_folder_id: str
    skyseal_server: str
    skyseal_rp_id: str
    skyseal_agent_token_file: Path
    github_owner: str
    github_repository: str
    github_token_file: Path
    private_ledger_spreadsheet_id: str | None = None
    private_ledger_sheet: str = "Ledger"
    github_branch: str = "main"
    github_prefix: str = "evidence"
    settle_seconds: int = 120
    poll_seconds: int = 30

    def __post_init__(self) -> None:
        exact_https_origin(self.skyseal_server)
        origin_host = urlsplit(self.skyseal_server).hostname
        if (
            not self.skyseal_rp_id
            or origin_host is None
            or (
                origin_host != self.skyseal_rp_id
                and not origin_host.endswith("." + self.skyseal_rp_id)
            )
        ):
            raise ConfigurationError("SKYSEAL_AGENT_RP_ID does not cover the service origin")
        for value, label in (
            (self.drive_folder_id, "Drive folder ID"),
            (self.github_owner, "GitHub owner"),
            (self.github_repository, "GitHub repository"),
            (self.github_branch, "GitHub branch"),
        ):
            if not value or any(character.isspace() for character in value):
                raise ConfigurationError(f"invalid {label}")
        if DRIVE_ID_RE.fullmatch(self.drive_folder_id) is None:
            raise ConfigurationError("invalid Drive folder ID")
        if (
            self.private_ledger_spreadsheet_id is not None
            and DRIVE_ID_RE.fullmatch(self.private_ledger_spreadsheet_id) is None
        ):
            raise ConfigurationError("invalid private-ledger spreadsheet ID")
        if re.fullmatch(r"[A-Za-z0-9 _-]{1,50}", self.private_ledger_sheet) is None:
            raise ConfigurationError("invalid private-ledger sheet name")
        if self.github_prefix.startswith("/") or ".." in self.github_prefix.split("/"):
            raise ConfigurationError("invalid GitHub evidence prefix")
        if self.settle_seconds < 0 or self.poll_seconds < 1:
            raise ConfigurationError("invalid polling interval")

    @classmethod
    def from_environment(cls) -> "AgentConfig":
        root = Path(__file__).resolve().parents[1]

        def required(name: str) -> str:
            value = os.getenv(name, "").strip()
            if not value:
                raise ConfigurationError(f"{name} is required")
            return value

        return cls(
            database_path=Path(
                os.getenv("SKYSEAL_AGENT_DATABASE", str(root / "var" / "drive-agent.sqlite3"))
            ).expanduser().resolve(),
            work_directory=Path(
                os.getenv("SKYSEAL_AGENT_WORK", str(root / "var" / "drive-agent-work"))
            ).expanduser().resolve(),
            public_root=Path(
                os.getenv("SKYSEAL_PUBLIC_ROOT", "/var/lib/skyseal-public")
            ).expanduser().resolve(),
            google_service_account_file=private_file(
                Path(required("SKYSEAL_GOOGLE_SERVICE_ACCOUNT")),
                "Google service-account key",
            ),
            drive_folder_id=required("SKYSEAL_DRIVE_FOLDER_ID"),
            skyseal_server=required("SKYSEAL_AGENT_SERVER"),
            skyseal_rp_id=required("SKYSEAL_AGENT_RP_ID"),
            skyseal_agent_token_file=private_file(
                Path(required("SKYSEAL_AGENT_TOKEN_FILE")), "SkySeal agent token"
            ),
            github_owner=required("SKYSEAL_GITHUB_OWNER"),
            github_repository=required("SKYSEAL_GITHUB_REPOSITORY"),
            github_token_file=private_file(
                Path(required("SKYSEAL_GITHUB_TOKEN_FILE")), "GitHub token"
            ),
            private_ledger_spreadsheet_id=(
                os.getenv("SKYSEAL_PRIVATE_LEDGER_SPREADSHEET_ID", "").strip() or None
            ),
            private_ledger_sheet=os.getenv("SKYSEAL_PRIVATE_LEDGER_SHEET", "Ledger").strip(),
            github_branch=os.getenv("SKYSEAL_GITHUB_BRANCH", "main"),
            github_prefix=os.getenv("SKYSEAL_GITHUB_PREFIX", "evidence").strip("/"),
            settle_seconds=int(os.getenv("SKYSEAL_DRIVE_SETTLE_SECONDS", "120")),
            poll_seconds=int(os.getenv("SKYSEAL_DRIVE_POLL_SECONDS", "30")),
        )
