from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


PINNED_OPENPGP_FINGERPRINT = "85F79058BD83EB3889DEF766B065C54586067E2E"


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid boolean value: {value}")


def validate_service_origin(origin: str, allow_http_localhost: bool) -> str:
    parsed = urlsplit(origin)
    host = parsed.hostname
    is_local = host in {"localhost", "127.0.0.1", "::1"}
    allowed_scheme = parsed.scheme == "https" or (
        parsed.scheme == "http" and allow_http_localhost and is_local
    )
    if (
        not allowed_scheme
        or host is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("SKYSEAL_ORIGIN must be an exact HTTPS origin")
    port = f":{parsed.port}" if parsed.port is not None else ""
    canonical_host = f"[{host}]" if ":" in host else host.lower()
    canonical = f"{parsed.scheme}://{canonical_host}{port}"
    if canonical != origin:
        raise ValueError("SKYSEAL_ORIGIN is not canonical")
    return origin


@dataclass(frozen=True)
class Config:
    origin: str
    rp_id: str
    database_path: Path
    bind_host: str = "127.0.0.1"
    bind_port: int = 8787
    orcid_base_url: str = "https://orcid.org"
    orcid_client_id: str = ""
    orcid_client_secret: str = ""
    orcid_redirect_uri: str = ""
    openpgp_fingerprint: str = PINNED_OPENPGP_FINGERPRINT
    allow_mock_orcid: bool = False
    allow_unsealed_identity: bool = False
    allow_http_localhost: bool = False
    session_lifetime_seconds: int = 8 * 60 * 60
    transaction_lifetime_seconds: int = 24 * 60 * 60
    assertion_lifetime_seconds: int = 5 * 60
    public_root: Path | None = None

    def __post_init__(self) -> None:
        validate_service_origin(self.origin, self.allow_http_localhost)
        if not self.rp_id or "/" in self.rp_id or "://" in self.rp_id:
            raise ValueError("SKYSEAL_RP_ID must be a relying-party DNS identifier")
        origin_host = urlsplit(self.origin).hostname
        if origin_host != self.rp_id and not origin_host.endswith("." + self.rp_id):
            raise ValueError("SKYSEAL_RP_ID must equal or be a registrable suffix of the origin host")
        expected_redirect = f"{self.origin}/api/v1/orcid/callback"
        if self.orcid_redirect_uri and self.orcid_redirect_uri != expected_redirect:
            raise ValueError("SKYSEAL_ORCID_REDIRECT_URI must be the exact configured callback URL")
        if len(self.openpgp_fingerprint) != 40 or not all(
            character in "0123456789ABCDEF" for character in self.openpgp_fingerprint
        ):
            raise ValueError("SKYSEAL_OPENPGP_FINGERPRINT must be 40 uppercase hex characters")
        if not 1 <= self.bind_port <= 65535:
            raise ValueError("SKYSEAL_PORT is out of range")
        if not 15 * 60 <= self.transaction_lifetime_seconds <= 7 * 24 * 60 * 60:
            raise ValueError("transaction lifetime must be between 15 minutes and 7 days")
        if self.allow_mock_orcid and self.bind_host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("mock ORCID mode may bind only to loopback")
        if self.allow_unsealed_identity and self.bind_host not in {
            "127.0.0.1",
            "::1",
            "localhost",
        }:
            raise ValueError("unsealed identity bypass may bind only to loopback")

    @property
    def secure_cookie(self) -> bool:
        return self.origin.startswith("https://")

    @classmethod
    def from_environment(cls) -> "Config":
        root = Path(__file__).resolve().parents[1]
        allow_http = parse_bool(os.getenv("SKYSEAL_DEV_ALLOW_HTTP_LOCALHOST"))
        origin = os.getenv("SKYSEAL_ORIGIN", "http://localhost:8787")
        redirect = os.getenv("SKYSEAL_ORCID_REDIRECT_URI", f"{origin}/api/v1/orcid/callback")
        return cls(
            origin=origin,
            rp_id=os.getenv("SKYSEAL_RP_ID", "localhost"),
            database_path=Path(
                os.getenv("SKYSEAL_DATABASE", str(root / "var" / "skyseal.sqlite3"))
            ).resolve(),
            bind_host=os.getenv("SKYSEAL_HOST", "127.0.0.1"),
            bind_port=int(os.getenv("SKYSEAL_PORT", "8787")),
            orcid_base_url=os.getenv("SKYSEAL_ORCID_BASE_URL", "https://orcid.org").rstrip("/"),
            orcid_client_id=os.getenv("SKYSEAL_ORCID_CLIENT_ID", ""),
            orcid_client_secret=os.getenv("SKYSEAL_ORCID_CLIENT_SECRET", ""),
            orcid_redirect_uri=redirect,
            openpgp_fingerprint=os.getenv(
                "SKYSEAL_OPENPGP_FINGERPRINT", PINNED_OPENPGP_FINGERPRINT
            ),
            allow_mock_orcid=parse_bool(os.getenv("SKYSEAL_DEV_MOCK_ORCID")),
            allow_unsealed_identity=parse_bool(
                os.getenv("SKYSEAL_DEV_ALLOW_UNSEALED_IDENTITY")
            ),
            allow_http_localhost=allow_http,
            transaction_lifetime_seconds=int(
                os.getenv("SKYSEAL_TRANSACTION_LIFETIME_SECONDS", "86400")
            ),
            public_root=Path(
                os.getenv("SKYSEAL_PUBLIC_ROOT", "/var/lib/skyseal-public")
            ).resolve(),
        )
