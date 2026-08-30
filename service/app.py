#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import html
import json
import mimetypes
import re
import secrets
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, quote, urlsplit

REPOSITORY = Path(__file__).resolve().parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from service.config import Config  # noqa: E402
from service.orcid import (
    AuthenticatedORCID,
    ORCIDError,
    authorization_url,
    exchange_authorization_code,
)  # noqa: E402
from service.storage import Store  # noqa: E402
from service.webauthn import verify_assertion, verify_registration  # noqa: E402
from verifier.skyseal_verify import (
    BUNDLE_SCHEMA,
    DIGEST_RE,
    GENESIS_SCHEMA,
    HASH_LIST_FORMAT,
    HEX64_RE,
    IDENTITY_ACTIVATION_PAYLOAD_SCHEMA,
    IDENTITY_ACTIVATION_SCHEMA,
    PAYLOAD_SCHEMA,
    VerificationError,
    canonical_json,
    compute_challenge,
    compute_identity_activation_challenge,
    decode_base64url,
    encode_base64url,
    parse_json_bytes,
    validate_orcid,
    validate_sky_witness,
)  # noqa: E402


MAX_BODY_BYTES = 1024 * 1024
ORCID_COMPACT_RE = re.compile(r"[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{3}[0-9X]")
SEAL_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
STATIC_FILES = {
    "/": "index.html",
    "/app.js": "app.js",
    "/styles.css": "styles.css",
    "/manifest.webmanifest": "manifest.webmanifest",
    "/sw.js": "sw.js",
}
PUBLIC_INDEX_SCHEMA = "urn:skyseal:public-evidence-index:v1"
PUBLIC_PATH_COMPONENT_RE = re.compile(r"[A-Za-z0-9._-]+")
PUBLIC_ARTIFACTS = (
    "manifest.json",
    "hashes.txt",
    "seal.skyseal.json",
    "seal.skyseal.json.ots",
    "identity-genesis.json",
    "identity-activation.json",
    "identity-activation.json.ots",
)


@dataclass
class Response:
    status: int
    body: bytes = b""
    headers: list[tuple[str, str]] | None = None


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    ) + b"\n"


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def uuid7() -> str:
    timestamp_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    random_a = secrets.randbits(12)
    random_b = secrets.randbits(62)
    value = (
        (timestamp_ms << 80)
        | (0x7 << 76)
        | (random_a << 64)
        | (0b10 << 62)
        | random_b
    )
    return str(uuid.UUID(int=value))


def exact_object(
    value: Any,
    required: set[str],
    context: str,
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{context}: expected a JSON object")
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - required - (optional or set()))
    if missing:
        raise VerificationError(f"{context}: missing members: {', '.join(missing)}")
    if unknown:
        raise VerificationError(f"{context}: unknown members: {', '.join(unknown)}")
    return value


class Application:
    def __init__(
        self,
        config: Config,
        store: Store | None = None,
        orcid_exchange: Callable[..., AuthenticatedORCID] = exchange_authorization_code,
    ):
        self.config = config
        self.store = store or Store(config.database_path)
        self.store.initialize()
        self.orcid_exchange = orcid_exchange
        self.static_root = Path(__file__).resolve().parent / "pwa"
        self.public_root = (
            config.public_root or config.database_path.parent / "public"
        ).resolve()

    def _response(
        self,
        status: int,
        body: bytes = b"",
        headers: list[tuple[str, str]] | None = None,
    ) -> Response:
        base = [
            ("Referrer-Policy", "no-referrer"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            (
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'; form-action 'self' https://orcid.org https://sandbox.orcid.org",
            ),
        ]
        return Response(status, body, base + (headers or []))

    def _json(self, status: int, value: Any, headers: list[tuple[str, str]] | None = None) -> Response:
        return self._response(
            status,
            json_bytes(value),
            [("Content-Type", "application/json; charset=utf-8"), ("Cache-Control", "no-store")]
            + (headers or []),
        )

    def _error(self, status: int, code: str, message: str) -> Response:
        return self._json(status, {"ok": False, "error": code, "message": message})

    def _redirect(self, location: str, cookies: list[str] | None = None) -> Response:
        headers = [("Location", location), ("Cache-Control", "no-store")]
        headers.extend(("Set-Cookie", cookie) for cookie in (cookies or []))
        return self._response(HTTPStatus.FOUND, b"", headers)

    def _cookie_value(self, headers: dict[str, str], name: str) -> str | None:
        raw = headers.get("cookie", "")
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            return None
        morsel = cookie.get(name)
        return morsel.value if morsel else None

    def _session(self, headers: dict[str, str]):
        return self.store.get_session(self._cookie_value(headers, "skyseal_session"))

    def _require_session(self, headers: dict[str, str]):
        session = self._session(headers)
        if session is None:
            raise PermissionError("ORCID session required")
        return session

    def _require_csrf(self, headers: dict[str, str], session) -> None:
        supplied = headers.get("x-skyseal-csrf")
        if not supplied or not secrets.compare_digest(supplied, session["csrf_token"]):
            raise PermissionError("CSRF token mismatch")

    def _bearer(self, headers: dict[str, str]) -> str:
        authorization = headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            raise PermissionError("transaction bearer token required")
        bearer = authorization[7:]
        decode_base64url(bearer, "transaction bearer", expected_length=32)
        return bearer

    def _agent(self, headers: dict[str, str]):
        authorization = headers.get("authorization", "")
        if not authorization.startswith("SkySeal-Agent "):
            return None
        raw_token = authorization[len("SkySeal-Agent ") :]
        decode_base64url(raw_token, "Drive agent token", expected_length=32)
        agent = self.store.get_agent(raw_token)
        if agent is None:
            raise PermissionError("Drive agent token is invalid or revoked")
        return agent

    def _parse_json(self, body: bytes, context: str) -> Any:
        if len(body) > MAX_BODY_BYTES:
            raise VerificationError(f"{context}: request body is too large")
        return parse_json_bytes(body, context)

    def _session_cookie(self, token: str, max_age: int) -> str:
        secure = "; Secure" if self.config.secure_cookie else ""
        return (
            f"skyseal_session={token}; Path=/; HttpOnly; SameSite=Lax; "
            f"Max-Age={max_age}{secure}"
        )

    def _oauth_cookie(self, state: str, max_age: int) -> str:
        secure = "; Secure" if self.config.secure_cookie else ""
        return (
            f"skyseal_oauth_state={state}; Path=/api/v1/orcid/callback; HttpOnly; "
            f"SameSite=Lax; Max-Age={max_age}{secure}"
        )

    def _clear_cookie(self, name: str, path: str = "/") -> str:
        secure = "; Secure" if self.config.secure_cookie else ""
        return f"{name}=; Path={path}; HttpOnly; SameSite=Lax; Max-Age=0{secure}"

    def _static(self, path: str) -> Response:
        filename = STATIC_FILES[path]
        target = self.static_root / filename
        try:
            data = target.read_bytes()
        except OSError:
            return self._error(HTTPStatus.NOT_FOUND, "not_found", "static resource not found")
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        # The service worker supplies offline copies. Online requests must
        # revalidate every shell asset so a security or workflow fix is not
        # hidden behind an hour-long browser cache.
        cache_control = "no-cache"
        response = self._response(
            HTTPStatus.OK,
            data,
            [("Content-Type", content_type), ("Cache-Control", cache_control)],
        )
        return response

    def _html(self, status: int, body: str) -> Response:
        return self._response(
            status,
            body.encode("utf-8"),
            [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Cache-Control", "no-cache"),
                ("Referrer-Policy", "no-referrer"),
                (
                    "Content-Security-Policy",
                    "default-src 'none'; style-src 'self'; img-src 'self'; "
                    "base-uri 'none'; frame-ancestors 'none'",
                ),
            ],
        )

    def _public_records(self) -> list[dict[str, object]]:
        index_path = self.public_root / "index.json"
        if not index_path.exists():
            return []
        try:
            if index_path.stat().st_size > 4 * 1024 * 1024:
                raise VerificationError("public evidence index is too large")
            document = json.loads(index_path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            raise VerificationError("public evidence index is unreadable") from exc
        if (
            not isinstance(document, dict)
            or set(document) != {"schema", "publications"}
            or document.get("schema") != PUBLIC_INDEX_SCHEMA
            or not isinstance(document.get("publications"), list)
        ):
            raise VerificationError("public evidence index is invalid")
        records: list[dict[str, object]] = []
        required = {
            "seal_id",
            "created_at",
            "entry_count",
            "identity_id",
            "relative_path",
            "github_mirror",
        }
        for raw in document["publications"]:
            if not isinstance(raw, dict) or set(raw) != required:
                raise VerificationError("public evidence index record is invalid")
            seal_id = raw["seal_id"]
            created_at = raw["created_at"]
            entry_count = raw["entry_count"]
            identity_id = raw["identity_id"]
            relative_path = raw["relative_path"]
            mirror = raw["github_mirror"]
            if not isinstance(seal_id, str) or SEAL_ID_RE.fullmatch(seal_id) is None:
                raise VerificationError("public evidence index has an invalid seal ID")
            if not isinstance(created_at, str) or not 1 <= len(created_at) <= 40:
                raise VerificationError("public evidence index has an invalid timestamp")
            if isinstance(entry_count, bool) or not isinstance(entry_count, int) or entry_count < 1:
                raise VerificationError("public evidence index has an invalid entry count")
            if not isinstance(identity_id, str):
                raise VerificationError("public evidence index has an invalid identity")
            validate_orcid(identity_id, "public evidence identity")
            if not isinstance(relative_path, str):
                raise VerificationError("public evidence index has an invalid path")
            components = relative_path.split("/")
            if (
                len(components) < 2
                or components[0] != "evidence"
                or components[-1] != seal_id
                or any(PUBLIC_PATH_COMPONENT_RE.fullmatch(item) is None for item in components)
            ):
                raise VerificationError("public evidence index has an unsafe path")
            if mirror not in {"pending", "synced"}:
                raise VerificationError("public evidence index has an invalid mirror state")
            records.append(dict(raw))
        return records

    @staticmethod
    def _page(title: str, content: str) -> str:
        escaped_title = html.escape(title)
        return f"""<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="theme-color" content="#12372a">
  <title>{escaped_title}</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body><main>
  <header><p class="eyebrow">Research provenance</p><h1>SkySeal</h1></header>
  {content}
</main></body>
</html>"""

    def _public_index(self) -> Response:
        records = self._public_records()
        if records:
            items = []
            for record in records:
                seal_id = html.escape(str(record["seal_id"]))
                created_at = html.escape(str(record["created_at"]))
                entry_count = int(record["entry_count"])
                mirror = "GitHub同期済み" if record["github_mirror"] == "synced" else "GitHub再試行中"
                items.append(
                    f'<li><a href="/proofs/{seal_id}"><code>{seal_id}</code></a>'
                    f'<span>{created_at} · {entry_count}件 · {mirror}</span></li>'
                )
            listing = '<ul class="proof-list">' + "".join(items) + "</ul>"
        else:
            listing = "<p>VPSに保存された公開証拠はまだありません。</p>"
        content = f"""
<section class="card">
  <h2>公開証拠</h2>
  <p>この一覧はVPSに保存された証拠です。GitHubの状態にかかわらず閲覧できます。</p>
  <p>一覧は案内用です。検証時は各パッケージの <code>manifest.json</code> と署名を確認してください。</p>
  {listing}
</section>
<p><a class="button secondary" href="/">承認画面へ戻る</a></p>"""
        return self._html(HTTPStatus.OK, self._page("SkySeal 公開証拠", content))

    def _public_detail(self, seal_id: str) -> Response:
        record = next(
            (item for item in self._public_records() if item["seal_id"] == seal_id), None
        )
        if record is None:
            return self._html(
                HTTPStatus.NOT_FOUND,
                self._page(
                    "SkySeal 証拠が見つかりません",
                    '<section class="card"><h2>証拠が見つかりません</h2>'
                    '<p><a href="/proofs/">公開証拠一覧へ戻る</a></p></section>',
                ),
            )
        relative_path = str(record["relative_path"])
        base_url = "/" + quote(relative_path, safe="/")
        package_path = (self.public_root / relative_path).resolve()
        if self.public_root not in package_path.parents:
            raise VerificationError("public evidence path escapes its root")
        manifest_path = package_path / "manifest.json"
        if manifest_path.exists():
            try:
                if manifest_path.stat().st_size > 1024 * 1024:
                    raise VerificationError("public evidence manifest is too large")
                manifest = parse_json_bytes(
                    manifest_path.read_bytes(), "public evidence manifest"
                )
            except OSError as exc:
                raise VerificationError("public evidence manifest is unreadable") from exc
            if (
                not isinstance(manifest, dict)
                or not isinstance(manifest.get("artifacts"), dict)
                or any(
                    not isinstance(name, str)
                    or name in {".", ".."}
                    or PUBLIC_PATH_COMPONENT_RE.fullmatch(name) is None
                    for name in manifest["artifacts"]
                )
            ):
                raise VerificationError("public evidence manifest is invalid")
            artifact_names = ["manifest.json", *sorted(manifest["artifacts"])]
        else:
            manifest = {"artifacts": {name: {} for name in PUBLIC_ARTIFACTS[1:]}}
            artifact_names = list(PUBLIC_ARTIFACTS)
        links = "".join(
            f'<li><a href="{base_url}/{quote(name, safe="")}">{html.escape(name)}</a></li>'
            for name in artifact_names
        )
        sky_section = ""
        if {"sky-witness.json", "sky-witness.jpg"} <= set(manifest["artifacts"]):
            try:
                witness = validate_sky_witness(
                    parse_json_bytes(
                        (package_path / "sky-witness.json").read_bytes(),
                        "published sky witness",
                    )
                )
            except OSError as exc:
                raise VerificationError("published sky witness is unreadable") from exc
            sky_section = f"""
<section class="card">
  <h2>Sky witness</h2>
  <img class="sky-witness" src="{base_url}/sky-witness.jpg"
       alt="{html.escape(str(witness['observation_time']))} のひまわり赤外全球画像">
  <dl>
    <div><dt>観測時刻</dt><dd>{html.escape(str(witness['observation_time']))}</dd></div>
    <div><dt>観測</dt><dd>{html.escape(str(witness['provider']))}</dd></div>
    <div><dt>プロダクト</dt><dd>{html.escape(str(witness['product']))}</dd></div>
  </dl>
  <p class="hint">この画像とハッシュはパスキー署名対象です。地球の物理的文脈を与えますが、画像単独を信頼不要な時刻証明とは扱いません。</p>
</section>"""
        identity_id = str(record["identity_id"])
        mirror_label = (
            "同期済み" if record["github_mirror"] == "synced" else "未同期・自動再試行中"
        )
        github_link = ""
        if record["github_mirror"] == "synced":
            github_url = "https://github.com/kagaya/SkySeal/tree/main/" + quote(
                relative_path, safe="/"
            )
            github_link = (
                f'<p><a class="button secondary" href="{html.escape(github_url)}">'
                "GitHubミラーを開く</a></p>"
            )
        content = f"""
<section class="card">
  <h2>公開証拠</h2>
  <dl>
    <div><dt>Seal ID</dt><dd>{html.escape(seal_id)}</dd></div>
    <div><dt>作成日時</dt><dd>{html.escape(str(record["created_at"]))}</dd></div>
    <div><dt>ハッシュ件数</dt><dd>{int(record["entry_count"])}</dd></div>
    <div><dt>本人性</dt><dd><a href="{html.escape(identity_id)}">{html.escape(identity_id)}</a></dd></div>
    <div><dt>VPS保存</dt><dd>保存済み</dd></div>
    <div><dt>GitHub</dt><dd>{mirror_label}</dd></div>
  </dl>
</section>
{sky_section}
<section class="card">
  <h2>証拠ファイル</h2>
  <p>原ファイル、ファイル名、Drive上のパスは含まれていません。</p>
  <ul class="artifact-list">{links}</ul>
  {github_link}
</section>
<p><a class="button secondary" href="/proofs/">公開証拠一覧へ戻る</a></p>"""
        return self._html(HTTPStatus.OK, self._page(f"SkySeal {seal_id}", content))

    def handle(
        self,
        method: str,
        target: str,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> Response:
        headers = {key.lower(): value for key, value in (headers or {}).items()}
        parsed = urlsplit(target)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)
        try:
            if method == "GET" and path in STATIC_FILES:
                return self._static(path)
            if method == "GET" and path in {"/proofs", "/proofs/"}:
                return self._public_index()
            public_match = re.fullmatch(r"/proofs/([0-9a-f-]{36})", path)
            if method == "GET" and public_match and SEAL_ID_RE.fullmatch(public_match.group(1)):
                return self._public_detail(public_match.group(1))
            if method == "GET" and path == "/api/v1/orcid/start":
                return self._orcid_start()
            if method == "GET" and path == "/api/v1/orcid/callback":
                return self._orcid_callback(headers, query)
            if method == "GET" and path == "/api/v1/orcid/mock":
                return self._orcid_mock(query)
            if method == "GET" and path == "/api/v1/me":
                return self._me(headers)
            if method == "POST" and path == "/api/v1/logout":
                return self._logout(headers)
            if method == "POST" and path == "/api/v1/webauthn/registration/options":
                return self._registration_options(headers)
            if method == "POST" and path == "/api/v1/webauthn/registration/complete":
                return self._registration_complete(headers, body)
            if method == "POST" and path == "/api/v1/identity/activation/options":
                return self._identity_activation_options(headers)
            if method == "POST" and path == "/api/v1/identity/activation/assertion":
                return self._identity_activation_assertion(headers, body)
            identity_match = re.fullmatch(
                r"/api/v1/identity/([0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{3}[0-9X])/(genesis|genesis\.asc|activation)",
                path,
            )
            if method == "GET" and identity_match:
                if identity_match.group(2) == "genesis":
                    return self._identity_genesis(identity_match.group(1))
                if identity_match.group(2) == "activation":
                    return self._identity_activation(identity_match.group(1))
                return self._identity_genesis_signature(identity_match.group(1))
            if method == "GET" and path == "/api/v1/seals/pending":
                return self._pending_seals(headers)
            if method == "POST" and path == "/api/v1/seals":
                return self._create_seal(headers, body)
            seal_match = re.fullmatch(
                r"/api/v1/seals/([0-9a-f-]{36})(?:/(webauthn/options|webauthn/assertion|bundle))?",
                path,
            )
            if seal_match and SEAL_ID_RE.fullmatch(seal_match.group(1)):
                seal_id, action = seal_match.groups()
                if method == "GET" and action is None:
                    return self._seal_status(headers, seal_id)
                if method == "GET" and action == "bundle":
                    return self._seal_bundle(headers, seal_id)
                if method == "POST" and action == "webauthn/options":
                    return self._seal_options(headers, seal_id)
                if method == "POST" and action == "webauthn/assertion":
                    return self._seal_assertion(headers, seal_id, body)
            return self._error(HTTPStatus.NOT_FOUND, "not_found", "route not found")
        except PermissionError as exc:
            return self._error(HTTPStatus.UNAUTHORIZED, "unauthorized", str(exc))
        except (VerificationError, ValueError) as exc:
            return self._error(HTTPStatus.BAD_REQUEST, "invalid_request", str(exc))
        except ORCIDError as exc:
            return self._error(HTTPStatus.BAD_GATEWAY, "orcid_error", str(exc))
        except Exception as exc:  # avoid returning private exception details to clients
            print(f"SkySeal internal error: {type(exc).__name__}", file=sys.stderr, flush=True)
            return self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "internal_error",
                "internal service error",
            )

    def _orcid_start(self) -> Response:
        state = self.store.create_oauth_state()
        location = authorization_url(
            base_url=self.config.orcid_base_url,
            client_id=self.config.orcid_client_id,
            redirect_uri=self.config.orcid_redirect_uri,
            state=state,
        )
        return self._redirect(location, [self._oauth_cookie(state, 600)])

    def _orcid_callback(self, headers: dict[str, str], query: dict[str, list[str]]) -> Response:
        state = query.get("state", [""])[0]
        code = query.get("code", [""])[0]
        cookie_state = self._cookie_value(headers, "skyseal_oauth_state")
        if not state or not code or not cookie_state or not secrets.compare_digest(state, cookie_state):
            raise VerificationError("ORCID OAuth state mismatch")
        if not self.store.consume_oauth_state(state):
            raise VerificationError("ORCID OAuth state is expired or already used")
        authenticated = self.orcid_exchange(
            base_url=self.config.orcid_base_url,
            client_id=self.config.orcid_client_id,
            client_secret=self.config.orcid_client_secret,
            redirect_uri=self.config.orcid_redirect_uri,
            code=code,
        )
        self.store.upsert_user(authenticated.identity_url, authenticated.display_name)
        token, _ = self.store.create_session(
            authenticated.identity_url, self.config.session_lifetime_seconds
        )
        return self._redirect(
            "/",
            [
                self._session_cookie(token, self.config.session_lifetime_seconds),
                self._clear_cookie("skyseal_oauth_state", "/api/v1/orcid/callback"),
            ],
        )

    def _orcid_mock(self, query: dict[str, list[str]]) -> Response:
        if not self.config.allow_mock_orcid:
            return self._error(HTTPStatus.NOT_FOUND, "not_found", "route not found")
        compact = query.get("orcid", ["0000-0000-0000-0001"])[0]
        name = query.get("name", ["SkySeal Development Researcher"])[0][:200]
        identity_url = f"https://orcid.org/{compact}"
        validate_orcid(identity_url, "mock ORCID")
        self.store.upsert_user(identity_url, name)
        token, _ = self.store.create_session(identity_url, self.config.session_lifetime_seconds)
        return self._redirect("/", [self._session_cookie(token, self.config.session_lifetime_seconds)])

    def _me(self, headers: dict[str, str]) -> Response:
        session = self._session(headers)
        if session is None:
            return self._json(
                HTTPStatus.OK,
                {
                    "authenticated": False,
                    "mock_orcid_available": self.config.allow_mock_orcid,
                },
            )
        credentials = self.store.list_active_credentials(session["orcid"])
        identity = self.store.get_identity(session["orcid"])
        passkey_active = bool(
            identity
            and identity["status"] == "active"
            and identity["activation_method"] == "webauthn_v1"
            and identity["activation_proof"] is not None
            and identity["activation_digest"] is not None
        )
        public_status = (
            "active" if passkey_active else "pending_activation" if identity else "not_enrolled"
        )
        return self._json(
            HTTPStatus.OK,
            {
                "authenticated": True,
                "orcid": session["orcid"],
                "display_name": session["display_name"],
                "csrf_token": session["csrf_token"],
                "credential_count": len(credentials),
                "identity_status": public_status,
                "identity_activation_method": identity["activation_method"] if identity else None,
                "can_activate_identity": bool(
                    identity
                    and not passkey_active
                    and credentials
                ),
                "can_register_initial_passkey": not credentials and identity is None,
                "development_unsealed_identity_bypass": self.config.allow_unsealed_identity,
            },
        )

    def _logout(self, headers: dict[str, str]) -> Response:
        session = self._require_session(headers)
        self._require_csrf(headers, session)
        self.store.delete_session(self._cookie_value(headers, "skyseal_session"))
        return self._json(
            HTTPStatus.OK,
            {"ok": True},
            [("Set-Cookie", self._clear_cookie("skyseal_session"))],
        )

    def _registration_options(self, headers: dict[str, str]) -> Response:
        session = self._require_session(headers)
        self._require_csrf(headers, session)
        if self.store.list_active_credentials(session["orcid"]):
            return self._error(
                HTTPStatus.CONFLICT,
                "already_enrolled",
                "additional credential events are not implemented in Phase 1",
            )
        registration_id, challenge = self.store.create_registration_challenge(session["orcid"])
        return self._json(
            HTTPStatus.OK,
            {
                "registration_id": registration_id,
                "publicKey": {
                    "challenge": encode_base64url(challenge),
                    "rp": {"id": self.config.rp_id, "name": "SkySeal"},
                    "user": {
                        "id": encode_base64url(bytes(session["user_handle"])),
                        "name": session["orcid"],
                        "displayName": session["display_name"],
                    },
                    "pubKeyCredParams": [
                        {"type": "public-key", "alg": -7},
                        {"type": "public-key", "alg": -8},
                    ],
                    "timeout": 300000,
                    "attestation": "none",
                    "authenticatorSelection": {
                        "residentKey": "preferred",
                        "userVerification": "required",
                    },
                    "excludeCredentials": [],
                },
            },
        )

    def _registration_complete(self, headers: dict[str, str], body: bytes) -> Response:
        session = self._require_session(headers)
        self._require_csrf(headers, session)
        request = exact_object(
            self._parse_json(body, "registration completion"),
            {"registration_id", "credential"},
            "registration completion",
        )
        registration_id = request["registration_id"]
        if not isinstance(registration_id, str):
            raise VerificationError("registration_id must be a string")
        challenge = self.store.consume_registration_challenge(
            registration_id, session["orcid"]
        )
        if challenge is None:
            raise VerificationError("registration challenge is expired or already used")
        credential_request = request["credential"]
        credential_object = exact_object(
            credential_request,
            {"id", "raw_id", "type", "response", "transports", "recovery_code_commitment"},
            "credential",
        )
        recovery_commitment = credential_object["recovery_code_commitment"]
        if not isinstance(recovery_commitment, str) or DIGEST_RE.fullmatch(recovery_commitment) is None:
            raise VerificationError("invalid recovery-code commitment")
        credential = verify_registration(
            credential_object,
            expected_challenge=challenge,
            rp_id=self.config.rp_id,
            origin=self.config.origin,
        )
        credential_ref = self.store.add_credential(
            orcid=session["orcid"],
            raw_id=credential.raw_id,
            algorithm=credential.algorithm,
            jwk=credential.jwk,
            transports=credential.transports,
            sign_count=credential.sign_count,
        )
        created_at = utc_timestamp()
        genesis = {
            "schema": GENESIS_SCHEMA,
            "identity_id": session["orcid"],
            "identity_version": 1,
            "display_name": session["display_name"],
            "rp_id": self.config.rp_id,
            "initial_credential_public_key": {
                "algorithm": credential.algorithm,
                "jwk": credential.jwk,
            },
            "recovery_code_commitment": recovery_commitment,
            "openpgp_primary_fingerprint": self.config.openpgp_fingerprint,
            "orcid_authenticated_at": created_at,
            "created_at": created_at,
        }
        genesis_canonical = canonical_json(genesis)
        genesis_digest = "sha256:" + hashlib.sha256(genesis_canonical).hexdigest()
        identity = self.store.create_identity(
            session["orcid"], genesis_canonical + b"\n", genesis_digest
        )
        compact = session["orcid"].rsplit("/", 1)[-1]
        return self._json(
            HTTPStatus.CREATED,
            {
                "ok": True,
                "credential_ref": credential_ref,
                "identity_status": "pending_activation",
                "identity_genesis_digest": identity["genesis_digest"],
                "genesis_url": f"/api/v1/identity/{compact}/genesis",
            },
        )

    def _identity_genesis(self, compact_orcid: str) -> Response:
        identity_url = f"https://orcid.org/{compact_orcid}"
        validate_orcid(identity_url, "identity path")
        identity = self.store.get_identity(identity_url)
        if identity is None:
            return self._error(HTTPStatus.NOT_FOUND, "not_found", "identity not found")
        return self._response(
            HTTPStatus.OK,
            bytes(identity["genesis_json"]),
            [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Cache-Control", "no-store"),
                ("Content-Disposition", 'attachment; filename="identity-genesis.json"'),
            ],
        )

    def _identity_genesis_signature(self, compact_orcid: str) -> Response:
        identity_url = f"https://orcid.org/{compact_orcid}"
        validate_orcid(identity_url, "identity path")
        identity = self.store.get_identity(identity_url)
        if (
            identity is None
            or identity["status"] != "active"
            or identity["openpgp_signature"] is None
        ):
            return self._error(
                HTTPStatus.NOT_FOUND,
                "not_found",
                "verified identity signature not found",
            )
        return self._response(
            HTTPStatus.OK,
            bytes(identity["openpgp_signature"]),
            [
                ("Content-Type", "application/pgp-signature"),
                ("Cache-Control", "no-store"),
                ("Content-Disposition", 'attachment; filename="identity-genesis.json.asc"'),
            ],
        )

    def _identity_activation(self, compact_orcid: str) -> Response:
        identity_url = f"https://orcid.org/{compact_orcid}"
        validate_orcid(identity_url, "identity path")
        identity = self.store.get_identity(identity_url)
        if (
            identity is None
            or identity["status"] != "active"
            or identity["activation_method"] != "webauthn_v1"
            or identity["activation_proof"] is None
        ):
            return self._error(
                HTTPStatus.NOT_FOUND, "not_found", "Passkey identity activation not found"
            )
        return self._response(
            HTTPStatus.OK,
            bytes(identity["activation_proof"]),
            [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Cache-Control", "no-store"),
                ("Content-Disposition", 'attachment; filename="identity-activation.json"'),
            ],
        )

    def _identity_activation_options(self, headers: dict[str, str]) -> Response:
        session = self._require_session(headers)
        self._require_csrf(headers, session)
        identity = self.store.get_identity(session["orcid"])
        if identity is None:
            return self._error(
                HTTPStatus.CONFLICT, "identity_missing", "register a Passkey first"
            )
        if (
            identity["status"] == "active"
            and identity["activation_method"] == "webauthn_v1"
            and identity["activation_proof"] is not None
            and identity["activation_digest"] is not None
        ):
            return self._error(
                HTTPStatus.CONFLICT, "already_active", "identity is already active"
            )
        credentials = self.store.list_active_credentials(session["orcid"])
        if not credentials:
            return self._error(
                HTTPStatus.CONFLICT, "credential_missing", "no active Passkey"
            )
        payload = {
            "schema": IDENTITY_ACTIVATION_PAYLOAD_SCHEMA,
            "identity_id": session["orcid"],
            "identity_version": 1,
            "identity_genesis_digest": identity["genesis_digest"],
            "rp_id": self.config.rp_id,
            "nonce": encode_base64url(secrets.token_bytes(32)),
            "created_at": utc_timestamp(),
        }
        payload_json = canonical_json(payload)
        challenge = compute_identity_activation_challenge(payload)
        self.store.start_identity_activation(
            session["orcid"],
            payload_json,
            challenge,
            self.config.assertion_lifetime_seconds,
        )
        allow_credentials = []
        for credential in credentials:
            transports = set(json.loads(credential["transports_json"]))
            transports.add("hybrid")
            allow_credentials.append(
                {
                    "type": "public-key",
                    "id": encode_base64url(bytes(credential["raw_id"])),
                    "transports": sorted(transports),
                }
            )
        code = hashlib.sha256(payload_json).hexdigest()[:8].upper()
        return self._json(
            HTTPStatus.OK,
            {
                "confirmation_code": f"{code[:4]}-{code[4:]}",
                "identity_id": session["orcid"],
                "identity_genesis_digest": identity["genesis_digest"],
                "publicKey": {
                    "challenge": encode_base64url(challenge),
                    "rpId": self.config.rp_id,
                    "timeout": self.config.assertion_lifetime_seconds * 1000,
                    "userVerification": "required",
                    "allowCredentials": allow_credentials,
                },
            },
        )

    def _identity_activation_assertion(
        self, headers: dict[str, str], body: bytes
    ) -> Response:
        session = self._require_session(headers)
        self._require_csrf(headers, session)
        assertion_dict = exact_object(
            self._parse_json(body, "identity activation assertion"),
            {"raw_id", "type", "response"},
            "identity activation assertion",
        )
        raw_id = decode_base64url(assertion_dict["raw_id"], "assertion.raw_id")
        credential = self.store.get_credential(raw_id)
        if (
            credential is None
            or credential["status"] != "active"
            or credential["orcid"] != session["orcid"]
        ):
            raise PermissionError("credential is not active for this identity")
        pending = self.store.consume_identity_activation(session["orcid"])
        if pending is None:
            return self._error(
                HTTPStatus.CONFLICT,
                "activation_challenge_missing",
                "identity activation challenge is expired or already used",
            )
        result = verify_assertion(
            assertion_dict,
            expected_challenge=bytes(pending["activation_challenge"]),
            rp_id=self.config.rp_id,
            origin=self.config.origin,
            algorithm=credential["algorithm"],
            jwk=json.loads(credential["jwk_json"]),
            expected_raw_id=bytes(credential["raw_id"]),
            expected_user_handle=bytes(session["user_handle"]),
        )
        self.store.update_sign_count(credential["credential_id_hash"], result.sign_count)
        payload = parse_json_bytes(
            bytes(pending["activation_payload"]), "stored identity activation payload"
        )
        proof = {
            "schema": IDENTITY_ACTIVATION_SCHEMA,
            "activation_payload": payload,
            "webauthn": {
                "client_data_json": encode_base64url(result.client_data_json),
                "authenticator_data": encode_base64url(result.authenticator_data),
                "signature": encode_base64url(result.signature),
            },
            "verification": {
                "rp_id": self.config.rp_id,
                "allowed_origin": self.config.origin,
            },
        }
        proof_json = canonical_json(proof) + b"\n"
        proof_digest = "sha256:" + hashlib.sha256(canonical_json(proof)).hexdigest()
        self.store.activate_identity_with_passkey(
            session["orcid"], proof_json, proof_digest
        )
        return self._json(
            HTTPStatus.OK,
            {
                "ok": True,
                "identity_status": "active",
                "activation_method": "orcid_oauth+webauthn",
                "identity_activation_digest": proof_digest,
                "credential_algorithm": result.algorithm_name,
            },
        )

    def _create_seal(self, headers: dict[str, str], body: bytes) -> Response:
        request = exact_object(
            self._parse_json(body, "seal creation"),
            {"commitment_format", "subject_digest", "entry_count"},
            "seal creation",
            {"private_ledger_commitment", "sky_witness"},
        )
        if request["commitment_format"] != HASH_LIST_FORMAT:
            raise VerificationError("unsupported commitment format")
        subject_digest = request["subject_digest"]
        if not isinstance(subject_digest, str) or HEX64_RE.fullmatch(subject_digest) is None:
            raise VerificationError("subject_digest must be 64 lowercase hexadecimal characters")
        entry_count = request["entry_count"]
        if isinstance(entry_count, bool) or not isinstance(entry_count, int) or not 1 <= entry_count <= 10_000_000:
            raise VerificationError("entry_count is outside the accepted range")
        authorization = headers.get("authorization", "")
        agent = self._agent(headers)
        if authorization and agent is None:
            raise PermissionError("unsupported seal-creation authorization")
        private_ledger_commitment = request.get("private_ledger_commitment")
        if private_ledger_commitment is not None:
            if agent is None:
                raise PermissionError("private ledger commitments require a Drive agent")
            if (
                not isinstance(private_ledger_commitment, str)
                or DIGEST_RE.fullmatch(private_ledger_commitment) is None
            ):
                raise VerificationError("private_ledger_commitment must be a SHA-256 digest")
        sky_witness = request.get("sky_witness")
        if sky_witness is not None:
            if agent is None:
                raise PermissionError("sky witnesses require a Drive agent")
            sky_witness = validate_sky_witness(sky_witness)
        seal_id = uuid7()
        bearer, row = self.store.create_seal(
            seal_id=seal_id,
            commitment_format=HASH_LIST_FORMAT,
            subject_digest=subject_digest,
            entry_count=entry_count,
            private_ledger_commitment=private_ledger_commitment,
            sky_witness_json=(canonical_json(sky_witness) if sky_witness is not None else None),
            lifetime_seconds=self.config.transaction_lifetime_seconds,
            identity_id=agent["orcid"] if agent is not None else None,
            source="drive_agent" if agent is not None else "interactive",
        )
        approval_url = self.config.origin + "/"
        delivery = "identity_inbox"
        if agent is None:
            approval_url = (
                f"{self.config.origin}/#seal={quote(seal_id)}&token={quote(bearer)}"
            )
            delivery = "fragment_bearer"
        return self._json(
            HTTPStatus.CREATED,
            {
                "ok": True,
                "seal_id": seal_id,
                "bearer_token": bearer,
                "approval_url": approval_url,
                "delivery": delivery,
                "expires_at": row["expires_at"],
            },
        )

    def _authorized_seal(self, headers: dict[str, str], seal_id: str, session=None):
        if headers.get("authorization"):
            bearer = self._bearer(headers)
            seal = self.store.get_seal(seal_id, bearer)
            if seal is None:
                raise PermissionError("seal or bearer token is invalid")
            return bearer, seal
        if session is not None:
            seal = self.store.get_seal_for_identity(seal_id, session["orcid"])
            if seal is not None and seal["source"] == "drive_agent":
                return None, seal
        raise PermissionError("transaction authorization required")

    def _pending_seals(self, headers: dict[str, str]) -> Response:
        session = self._require_session(headers)
        rows = self.store.list_pending_seals(session["orcid"])
        return self._json(
            HTTPStatus.OK,
            {
                "ok": True,
                "seals": [
                    {
                        "seal_id": row["seal_id"],
                        "entry_count": row["entry_count"],
                        "status": row["status"],
                        "created_at": row["created_at"],
                        "expires_at": row["expires_at"],
                        "sky_witness": (
                            parse_json_bytes(bytes(row["sky_witness_json"]), "stored sky witness")
                            if row["sky_witness_json"] is not None
                            else None
                        ),
                    }
                    for row in rows
                ],
            },
        )

    def _seal_status(self, headers: dict[str, str], seal_id: str) -> Response:
        _, seal = self._authorized_seal(headers, seal_id)
        return self._json(
            HTTPStatus.OK,
            {
                "ok": True,
                "seal_id": seal_id,
                "status": seal["status"],
                "entry_count": seal["entry_count"],
                "identity_id": seal["identity_id"],
                "expires_at": seal["expires_at"],
                "bundle_available": seal["bundle_json"] is not None,
            },
        )

    def _seal_options(self, headers: dict[str, str], seal_id: str) -> Response:
        session = self._require_session(headers)
        self._require_csrf(headers, session)
        _, seal = self._authorized_seal(headers, seal_id, session)
        if seal["status"] in {"expired", "rejected", "invalidated", "approved"}:
            return self._error(HTTPStatus.CONFLICT, "wrong_state", f"seal is {seal['status']}")
        if seal["identity_id"] and seal["identity_id"] != session["orcid"]:
            raise PermissionError("seal is already bound to another identity")
        identity = self.store.get_identity(session["orcid"])
        if identity is None:
            return self._error(HTTPStatus.CONFLICT, "identity_missing", "register a passkey first")
        passkey_active = bool(
            identity["status"] == "active"
            and identity["activation_method"] == "webauthn_v1"
            and identity["activation_proof"] is not None
            and identity["activation_digest"] is not None
        )
        if not passkey_active and not self.config.allow_unsealed_identity:
            return self._error(
                HTTPStatus.CONFLICT,
                "identity_pending_activation",
                "activate the ORCID identity with the registered Passkey before approving seals",
            )
        credentials = self.store.list_active_credentials(session["orcid"])
        if not credentials:
            return self._error(HTTPStatus.CONFLICT, "credential_missing", "no active passkey")
        created_at = utc_timestamp()
        payload = {
            "schema": PAYLOAD_SCHEMA,
            "seal_id": seal_id,
            "commitment_format": HASH_LIST_FORMAT,
            "subject_digest": {"algorithm": "sha256", "value": seal["subject_digest"]},
            "identity_id": session["orcid"],
            "identity_version": 1,
            "identity_state_digest": identity["activation_digest"] or identity["genesis_digest"],
            "nonce": encode_base64url(secrets.token_bytes(32)),
            "created_at": created_at,
        }
        if seal["private_ledger_commitment"] is not None:
            payload["private_ledger_commitment"] = seal["private_ledger_commitment"]
        if seal["sky_witness_json"] is not None:
            payload["sky_witness"] = validate_sky_witness(
                parse_json_bytes(bytes(seal["sky_witness_json"]), "stored sky witness")
            )
        payload_json = canonical_json(payload)
        challenge = compute_challenge(payload)
        self.store.set_seal_options(
            seal_id=seal_id,
            identity_id=session["orcid"],
            payload_json=payload_json,
            challenge=challenge,
            challenge_lifetime_seconds=self.config.assertion_lifetime_seconds,
        )
        allow_credentials = []
        for credential in credentials:
            transports = set(json.loads(credential["transports_json"]))
            transports.add("hybrid")
            allow_credentials.append(
                {
                    "type": "public-key",
                    "id": encode_base64url(bytes(credential["raw_id"])),
                    "transports": sorted(transports),
                }
            )
        code = hashlib.sha256(payload_json).hexdigest()[:8].upper()
        return self._json(
            HTTPStatus.OK,
            {
                "confirmation_code": f"{code[:4]}-{code[4:]}",
                "entry_count": seal["entry_count"],
                "identity_id": session["orcid"],
                "sky_witness": payload.get("sky_witness"),
                "development_unsealed_identity_bypass": (
                    identity["status"] != "active" and self.config.allow_unsealed_identity
                ),
                "publicKey": {
                    "challenge": encode_base64url(challenge),
                    "rpId": self.config.rp_id,
                    "timeout": self.config.assertion_lifetime_seconds * 1000,
                    "userVerification": "required",
                    "allowCredentials": allow_credentials,
                },
            },
        )

    def _seal_assertion(
        self, headers: dict[str, str], seal_id: str, body: bytes
    ) -> Response:
        session = self._require_session(headers)
        self._require_csrf(headers, session)
        _, seal = self._authorized_seal(headers, seal_id, session)
        if seal["status"] == "approved":
            assertion_hash = hashlib.sha256(body).hexdigest()
            if assertion_hash == seal["assertion_hash"]:
                return self._json(HTTPStatus.OK, {"ok": True, "status": "approved"})
            return self._error(
                HTTPStatus.CONFLICT, "already_approved", "a different assertion already approved this seal"
            )
        if seal["status"] != "awaiting_assertion" or seal["challenge"] is None:
            return self._error(
                HTTPStatus.CONFLICT, "wrong_state", "seal is not awaiting an assertion"
            )
        if seal["identity_id"] != session["orcid"]:
            raise PermissionError("seal identity does not match the session")
        assertion_object = self._parse_json(body, "assertion")
        assertion_dict = exact_object(
            assertion_object, {"raw_id", "type", "response"}, "assertion"
        )
        raw_id = decode_base64url(assertion_dict["raw_id"], "assertion.raw_id")
        credential = self.store.get_credential(raw_id)
        if (
            credential is None
            or credential["status"] != "active"
            or credential["orcid"] != session["orcid"]
        ):
            raise PermissionError("credential is not active for this identity")
        result = verify_assertion(
            assertion_dict,
            expected_challenge=bytes(seal["challenge"]),
            rp_id=self.config.rp_id,
            origin=self.config.origin,
            algorithm=credential["algorithm"],
            jwk=json.loads(credential["jwk_json"]),
            expected_raw_id=bytes(credential["raw_id"]),
            expected_user_handle=bytes(session["user_handle"]),
        )
        self.store.update_sign_count(credential["credential_id_hash"], result.sign_count)
        identity = self.store.get_identity(session["orcid"])
        payload = parse_json_bytes(bytes(seal["payload_json"]), "stored seal payload")
        bundle = {
            "schema": BUNDLE_SCHEMA,
            "seal_payload": payload,
            "webauthn": {
                "client_data_json": encode_base64url(result.client_data_json),
                "authenticator_data": encode_base64url(result.authenticator_data),
                "signature": encode_base64url(result.signature),
            },
            "identity": {
                "orcid": session["orcid"],
                "identity_genesis_digest": identity["genesis_digest"],
                "identity_state_digest": identity["activation_digest"] or identity["genesis_digest"],
                "credential_event_digest": identity["genesis_digest"],
            },
            "verification": {
                "rp_id": self.config.rp_id,
                "allowed_origin": self.config.origin,
            },
        }
        bundle_json = canonical_json(bundle) + b"\n"
        assertion_hash = hashlib.sha256(body).hexdigest()
        self.store.approve_seal(
            seal_id=seal_id,
            assertion_hash=assertion_hash,
            bundle_json=bundle_json,
        )
        return self._json(
            HTTPStatus.OK,
            {
                "ok": True,
                "status": "approved",
                "credential_algorithm": result.algorithm_name,
                "bundle_url": f"/api/v1/seals/{seal_id}/bundle",
            },
        )

    def _seal_bundle(self, headers: dict[str, str], seal_id: str) -> Response:
        _, seal = self._authorized_seal(headers, seal_id)
        if seal["status"] != "approved" or seal["bundle_json"] is None:
            return self._error(HTTPStatus.CONFLICT, "not_approved", "bundle is not available")
        return self._response(
            HTTPStatus.OK,
            bytes(seal["bundle_json"]),
            [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Cache-Control", "no-store"),
                ("Content-Disposition", f'attachment; filename="{seal_id}.skyseal.json"'),
            ],
        )


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "SkySeal/1.1"

    @property
    def application(self) -> Application:
        return self.server.application  # type: ignore[attr-defined]

    def _handle(self) -> None:
        content_length = self.headers.get("Content-Length", "0")
        try:
            length = int(content_length)
        except ValueError:
            length = MAX_BODY_BYTES + 1
        if length < 0 or length > MAX_BODY_BYTES:
            response = self.application._error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body_too_large", "request body is too large"
            )
        else:
            body = self.rfile.read(length) if length else b""
            response = self.application.handle(
                "GET" if self.command == "HEAD" else self.command,
                self.path,
                {key: value for key, value in self.headers.items()},
                body,
            )
        self.send_response(response.status)
        for key, value in response.headers or []:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(response.body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.body)

    do_GET = _handle
    do_HEAD = _handle
    do_POST = _handle

    def log_message(self, format_string: str, *args: object) -> None:
        # Never log query strings because an OAuth code can occur there.
        path = urlsplit(self.path).path
        print(f"{self.address_string()} {self.command} {path}", flush=True)


def run(config: Config | None = None) -> None:
    config = config or Config.from_environment()
    application = Application(config)
    server = ThreadingHTTPServer((config.bind_host, config.bind_port), RequestHandler)
    server.application = application  # type: ignore[attr-defined]
    print(
        f"SkySeal Phase 1 listening on {config.bind_host}:{config.bind_port} "
        f"for origin {config.origin}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    run()
