"""Direct ORCID OIDC authentication through a temporary local HTTPS receiver.

No SkySeal service, shared client secret, access-token persistence, or token-supplied
key URL is used. Production ORCID registration must include CALLBACK_URI exactly.
The local certificate is trusted only by an explicit ``trust_certificate`` call.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import secrets
import shlex
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener
import webbrowser

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from verifier.skyseal_verify import (
    VerificationError,
    decode_base64url,
    encode_base64url,
    parse_json_bytes,
    validate_orcid,
)


ISSUER = "https://orcid.org"
JWKS_URI = ISSUER + "/oauth/jwks"
CALLBACK_PORT = 24731
CALLBACK_ORIGIN = f"https://localhost:{CALLBACK_PORT}"
CALLBACK_URI = CALLBACK_ORIGIN + "/callback"
MAX_TOKEN_BYTES = 32 * 1024
MAX_CALLBACK_BYTES = 64 * 1024
MAX_JWKS_BYTES = 256 * 1024
CLOCK_SKEW = 60


class ORCIDAuthError(ValueError):
    """An ORCID authentication, configuration, or evidence check failed."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ORCIDAuthError("ORCID key endpoint redirected unexpectedly")


def fetch_jwks() -> dict:
    """Fetch keys from the fixed issuer endpoint with normal system TLS checks."""
    request = Request(JWKS_URI, headers={"Accept": "application/json", "User-Agent": "SkySeal-Desktop/0.1"})
    try:
        with build_opener(_NoRedirect).open(request, timeout=20) as response:
            if response.status != 200:
                raise ORCIDAuthError("ORCID key endpoint returned an unexpected status")
            raw = response.read(MAX_JWKS_BYTES + 1)
        if len(raw) > MAX_JWKS_BYTES:
            raise ORCIDAuthError("ORCID key response exceeds the size limit")
        result = parse_json_bytes(raw, "ORCID JWKS")
    except ORCIDAuthError:
        raise
    except Exception as exc:
        raise ORCIDAuthError("Could not retrieve trusted ORCID signing keys") from exc
    if not isinstance(result, dict) or not isinstance(result.get("keys"), list):
        raise ORCIDAuthError("ORCID key response is not a JWKS")
    return result


def _integer_claim(claims: dict, name: str, *, required: bool = True) -> int | None:
    value = claims.get(name)
    if value is None and not required:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ORCIDAuthError(f"ORCID {name} claim must be a nonnegative integer")
    return value


def verify_id_token(
    token: str,
    client_id: str,
    nonce: str,
    *,
    jwks: dict | None = None,
    now: int | float | None = None,
    historical: bool = False,
) -> dict:
    """Verify an ORCID ID token; ``jwks`` must be trusted by the calling verifier.

    The default fetches current keys from ORCID, never from the evidence package.
    Historical mode checks the signed historical assertion, not permission to log
    in now. It permits an expired token but still requires internally valid times
    and no future issue time. It cannot recover keys removed from ORCID's JWKS or
    independently prove when a verifier first received the token.
    """
    if not isinstance(token, str) or len(token) > MAX_TOKEN_BYTES or token.count(".") != 2:
        raise ORCIDAuthError("Invalid ORCID ID token")
    if not isinstance(client_id, str) or not client_id or len(client_id) > 256:
        raise ORCIDAuthError("An ORCID client ID is required")
    if not isinstance(nonce, str) or not nonce or len(nonce) > 1024:
        raise ORCIDAuthError("An expected ORCID nonce is required")
    try:
        head_text, body_text, signature_text = token.split(".")
        header = parse_json_bytes(decode_base64url(head_text, "JWT header"), "JWT header")
        claims = parse_json_bytes(decode_base64url(body_text, "JWT claims"), "JWT claims")
        signature = decode_base64url(signature_text, "JWT signature")
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise ORCIDAuthError("ORCID token header and claims must be objects")
        if header.get("alg") != "RS256":
            raise ORCIDAuthError("Only ORCID RS256 tokens are accepted")
        if set(header) - {"alg", "kid", "typ"}:
            raise ORCIDAuthError("Unsupported ORCID token header")
        if header.get("typ", "JWT") != "JWT":
            raise ORCIDAuthError("Unexpected ORCID token type")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > 256:
            raise ORCIDAuthError("ORCID token has no valid signing-key ID")
        trusted_keys = fetch_jwks() if jwks is None else jwks
        if not isinstance(trusted_keys, dict) or not isinstance(trusted_keys.get("keys"), list):
            raise ORCIDAuthError("Invalid trusted ORCID key set")
        keys = [key for key in trusted_keys["keys"] if isinstance(key, dict) and key.get("kid") == kid]
        if len(keys) != 1:
            raise ORCIDAuthError("ORCID signing key is unknown or ambiguous")
        key = keys[0]
        if key.get("kty") != "RSA" or key.get("alg", "RS256") != "RS256" or key.get("use", "sig") != "sig":
            raise ORCIDAuthError("ORCID signing key is not an RS256 signature key")
        if "key_ops" in key and (not isinstance(key["key_ops"], list) or "verify" not in key["key_ops"]):
            raise ORCIDAuthError("ORCID signing key does not permit verification")
        modulus_bytes = decode_base64url(key.get("n"), "RSA modulus")
        exponent_bytes = decode_base64url(key.get("e"), "RSA exponent")
        if not 256 <= len(modulus_bytes) <= 1024 or not 1 <= len(exponent_bytes) <= 4:
            raise ORCIDAuthError("ORCID RSA key size is outside the accepted range")
        n, e = int.from_bytes(modulus_bytes, "big"), int.from_bytes(exponent_bytes, "big")
        if n.bit_length() < 2048 or e < 3 or e % 2 == 0:
            raise ORCIDAuthError("Invalid ORCID RSA key")
        rsa.RSAPublicNumbers(e, n).public_key().verify(
            signature, (head_text + "." + body_text).encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
        )
        if claims.get("iss") != ISSUER:
            raise ORCIDAuthError("ORCID token issuer mismatch")
        audience = claims.get("aud")
        if isinstance(audience, str):
            valid_audience = audience == client_id
        elif isinstance(audience, list):
            valid_audience = bool(audience) and all(isinstance(x, str) for x in audience) and len(set(audience)) == len(audience) and client_id in audience
            if len(audience) > 1 and claims.get("azp") != client_id:
                valid_audience = False
        else:
            valid_audience = False
        if not valid_audience or ("azp" in claims and claims["azp"] != client_id):
            raise ORCIDAuthError("ORCID token audience mismatch")
        if not isinstance(claims.get("nonce"), str) or not hmac.compare_digest(claims["nonce"], nonce):
            raise ORCIDAuthError("ORCID token nonce mismatch")
        subject = claims.get("sub")
        if not isinstance(subject, str):
            raise ORCIDAuthError("ORCID token has no subject")
        validate_orcid(ISSUER + "/" + subject, "ORCID token subject")
        issued = _integer_claim(claims, "iat")
        expires = _integer_claim(claims, "exp")
        auth_time = _integer_claim(claims, "auth_time", required=False)
        not_before = _integer_claim(claims, "nbf", required=False)
        current_time = time.time() if now is None else now
        if issued > current_time + CLOCK_SKEW or expires <= issued:
            raise ORCIDAuthError("ORCID token has invalid issue/expiry times")
        if auth_time is not None and auth_time > issued + CLOCK_SKEW:
            raise ORCIDAuthError("ORCID authentication time is later than token issue time")
        if not_before is not None and (not_before > expires or not_before > current_time + CLOCK_SKEW):
            raise ORCIDAuthError("ORCID token is not yet valid")
        if not historical and current_time >= expires + CLOCK_SKEW:
            raise ORCIDAuthError("ORCID token has expired")
        return claims
    except ORCIDAuthError:
        raise
    except InvalidSignature as exc:
        raise ORCIDAuthError("ORCID token signature is invalid") from exc
    except (VerificationError, ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise ORCIDAuthError("Malformed ORCID ID token or signing key") from exc


def _private_write(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def ensure_certificate(data_dir: Path | str) -> dict:
    """Create or inspect the per-installation localhost certificate; do not trust it."""
    directory = Path(data_dir).resolve() / "local-tls"
    if directory.is_symlink():
        raise ORCIDAuthError("Local TLS directory must not be a symbolic link")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    certificate_path, key_path = directory / "localhost.pem", directory / "localhost-key.pem"
    if certificate_path.is_symlink() or key_path.is_symlink():
        raise ORCIDAuthError("Local TLS files must not be symbolic links")
    if certificate_path.exists() != key_path.exists():
        raise ORCIDAuthError("Local TLS setup is incomplete; restore or remove the incomplete TLS files")
    now = datetime.now(timezone.utc)
    if not certificate_path.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SkySeal local callback")])
        cert = (
            x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                x509.IPAddress(ipaddress.ip_address("::1")),
            ]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        _private_write(key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        _private_write(certificate_path, cert.public_bytes(serialization.Encoding.PEM))
    try:
        cert = x509.load_pem_x509_certificate(certificate_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ORCIDAuthError("Invalid local TLS private key")
        if cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
            raise ORCIDAuthError("Local TLS certificate and private key do not match")
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ORCIDAuthError("Local TLS certificate must be a leaf certificate")
        if cert.subject != cert.issuer:
            raise ORCIDAuthError("Local TLS certificate must be installation-specific and self-signed")
        cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        expected_names = {x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.IPAddress(ipaddress.ip_address("::1"))}
        if set(names) != expected_names:
            raise ORCIDAuthError("Local TLS certificate must cover only loopback names")
        if list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) != [ExtendedKeyUsageOID.SERVER_AUTH]:
            raise ORCIDAuthError("Local TLS certificate must be limited to server authentication")
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if usage.key_cert_sign or usage.crl_sign:
            raise ORCIDAuthError("Local TLS certificate must not sign certificates")
        if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            raise ORCIDAuthError("Local TLS certificate has expired or is not yet valid; renew it before login")
    except ORCIDAuthError:
        raise
    except Exception as exc:
        raise ORCIDAuthError("Could not validate the local TLS certificate") from exc
    # DER is accepted directly by Windows Import-Certificate; PEM serves Python TLS.
    der_path = directory / "localhost.cer"
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    if der_path.is_symlink():
        raise ORCIDAuthError("Local TLS certificate must not be a symbolic link")
    if der_path.exists():
        if der_path.read_bytes() != der_bytes:
            raise ORCIDAuthError("Local TLS import certificate does not match the HTTPS certificate")
    else:
        _private_write(der_path, der_bytes)
    return {
        "certificate_path": str(certificate_path), "key_path": str(key_path),
        "certificate_der_path": str(der_path),
        "thumbprint": cert.fingerprint(hashes.SHA1()).hex().upper(),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "expires_at": cert.not_valid_after_utc.isoformat(), "callback_uri": CALLBACK_URI,
        "trust_scope": ("user Keychain / SSL / localhost" if sys.platform == "darwin"
                        else "CurrentUser/Root" if sys.platform == "win32" else "unsupported platform"),
        "trust_installation_is_explicit": True,
    }


def trust_certificate(data_dir: Path | str) -> dict:
    """Explicit UI action; never elevate or silently install machine-wide trust.

    macOS requires its own authentication dialog even for per-user trust
    settings. Its trust rule is limited to SSL for localhost. The callback's
    exact certificate is checked using system trust after the change; passing
    a custom root to the verifier would incorrectly bypass that check.
    """
    if sys.platform not in {"win32", "darwin"}:
        raise ORCIDAuthError("Certificate trust installation is available only on Windows and macOS")
    info = ensure_certificate(data_dir)
    if sys.platform == "darwin":
        return _trust_certificate_macos(info)
    env = dict(os.environ)
    env["SKYSEAL_LOCAL_CERTIFICATE"] = info["certificate_der_path"]
    env["SKYSEAL_LOCAL_THUMBPRINT"] = info["thumbprint"]
    script = (
        "$ErrorActionPreference='Stop'; "
        "$cert=Import-Certificate -FilePath $env:SKYSEAL_LOCAL_CERTIFICATE -CertStoreLocation Cert:\\CurrentUser\\Root; "
        "if ($cert.Thumbprint -ne $env:SKYSEAL_LOCAL_THUMBPRINT) { throw 'Certificate thumbprint mismatch' }"
    )
    try:
        subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            env=env, capture_output=True, check=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError) as exc:
        raise ORCIDAuthError("Could not trust the local certificate in the Windows current-user certificate store") from exc
    return {**info, "trusted": True}


def _trust_certificate_macos(info: dict) -> dict:
    security = "/usr/bin/security"
    try:
        current = subprocess.run([security, "default-keychain", "-d", "user"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True, timeout=10)
        paths = shlex.split(current.stdout.strip())
        if len(paths) != 1 or not Path(paths[0]).is_absolute():
            raise ORCIDAuthError("Could not identify the current user's default Keychain")
        keychain = Path(paths[0]).resolve()
        # A system/admin Keychain is never selected even if made the user's
        # default externally. User trust settings must stay in the user domain.
        user_keychains = (Path.home() / "Library" / "Keychains").resolve()
        if not keychain.is_relative_to(user_keychains) or keychain == user_keychains:
            raise ORCIDAuthError("Select a default Keychain in your Library/Keychains folder before registering the local certificate")
        subprocess.run([security, "add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-s", "localhost",
            "-k", str(keychain), info["certificate_der_path"]],
            stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=180)
        subprocess.run([security, "verify-cert", "-p", "ssl", "-n", "localhost", "-L",
            "-c", info["certificate_der_path"]],
            stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=15)
    except ORCIDAuthError:
        raise
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise ORCIDAuthError("Could not confirm localhost certificate trust in your macOS Keychain; complete the macOS authentication dialog or retry") from exc
    return {**info, "trust_scope": "user Keychain / SSL / localhost", "keychain_path": str(keychain), "trusted": True}


def authorization_url(client_id: str, nonce: str, state: str) -> str:
    if not isinstance(client_id, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,256}", client_id) is None:
        raise ORCIDAuthError("Configure the registered ORCID public client ID first")
    if not isinstance(nonce, str) or not nonce or len(nonce) > 1024:
        raise ORCIDAuthError("Invalid ORCID nonce")
    return ISSUER + "/oauth/authorize?" + urlencode({
        "client_id": client_id, "response_type": "id_token token", "scope": "openid",
        "redirect_uri": CALLBACK_URI, "state": state, "nonce": nonce, "prompt": "login",
    })


def _callback_page(script_nonce: str) -> bytes:
    # Never interpolate an OAuth token or error description into HTML or JavaScript.
    return ("""<!doctype html><html lang="ja"><meta charset="utf-8"><title>SkySeal ORCID</title>
<body><h1>SkySeal</h1><p id="status">ORCIDの認証結果を確認しています。</p>
<script nonce=""" + '"' + script_nonce + '"' + """>
(async () => {
  const fragment = new URLSearchParams(location.hash.slice(1));
  history.replaceState(null, '', '/callback');
  const status = document.getElementById('status');
  try {
    const payload = {};
    for (const key of ['state', 'id_token', 'access_token', 'error']) {
      if (fragment.getAll(key).length > 1) throw new Error('duplicate');
      if (fragment.has(key)) payload[key] = fragment.get(key);
    }
    const response = await fetch('/complete', {method: 'POST', credentials: 'omit',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
    const result = await response.json();
    status.textContent = result.ok ? '認証結果をSkySealに渡しました。アプリに戻ってください。' : '認証結果を受け付けられませんでした。アプリからやり直してください。';
  } catch (_) { status.textContent = '認証結果を受け付けられませんでした。アプリからやり直してください。'; }
})();
</script></body></html>""").encode("utf-8")


def _handler_type(expected_state: str, result_queue: queue.Queue):
    lock = threading.Lock()
    consumed = False

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format, *args):
            pass  # Callback URLs and bearer values must never enter a request log.

        def _send(self, status: int, body: bytes, content_type: str, *, script_nonce: str | None = None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            scripts = f"'nonce-{script_nonce}'" if script_nonce else "'none'"
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src " + scripts + "; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def _host_valid(self):
            return self.headers.get_all("Host", []) == [f"localhost:{CALLBACK_PORT}"]

        def do_GET(self):
            if not self._host_valid() or self.path != "/callback":
                self._send(404, b"Not found", "text/plain; charset=utf-8")
                return
            script_nonce = secrets.token_urlsafe(24)
            self._send(200, _callback_page(script_nonce), "text/html; charset=utf-8", script_nonce=script_nonce)

        def do_POST(self):
            nonlocal consumed
            if (not self._host_valid() or self.path != "/complete"
                or self.headers.get_all("Origin", []) != [CALLBACK_ORIGIN]
                or self.headers.get("Sec-Fetch-Site", "same-origin") != "same-origin"
                or self.headers.get("Content-Type") != "application/json"
                or self.headers.get("Transfer-Encoding") is not None):
                self._send(403, b'{"ok":false}', "application/json")
                return
            try:
                lengths = self.headers.get_all("Content-Length", [])
                if len(lengths) != 1 or not lengths[0].isdigit():
                    raise ValueError("Invalid length")
                length = int(lengths[0])
                if not 1 <= length <= MAX_CALLBACK_BYTES:
                    raise ValueError("Invalid length")
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("Incomplete body")
                payload = parse_json_bytes(raw, "ORCID callback")
                if not isinstance(payload, dict) or set(payload) - {"state", "id_token", "access_token", "error"}:
                    raise ValueError("Invalid payload")
                state = payload.get("state")
                if not isinstance(state, str) or not hmac.compare_digest(state, expected_state):
                    raise ValueError("State mismatch")
                if "error" not in payload and (not isinstance(payload.get("id_token"), str) or not isinstance(payload.get("access_token"), str)):
                    raise ValueError("Missing tokens")
                with lock:
                    if consumed:
                        raise ValueError("Callback already consumed")
                    result_queue.put_nowait(payload)
                    consumed = True
            except (ValueError, TypeError, queue.Full):
                self._send(400, b'{"ok":false}', "application/json")
                return
            self._send(200, b'{"ok":true}', "application/json")

    return Handler


class _TLSReceiver(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        try:
            return self.tls_context.wrap_socket(connection, server_side=True), address
        except Exception:
            connection.close()
            raise

    def handle_error(self, request, client_address):
        pass  # No request details, tracebacks, or bearer data in background logs.


def login(client_id: str, nonce: str, data_dir: Path | str, timeout: int = 180) -> dict:
    """Run one ORCID login in the default browser and verify its signed response."""
    if not isinstance(timeout, (int, float)) or not 1 <= timeout <= 600:
        raise ORCIDAuthError("ORCID login timeout must be between 1 and 600 seconds")
    state = secrets.token_urlsafe(32)
    url = authorization_url(client_id, nonce, state)
    certificate = ensure_certificate(data_dir)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate["certificate_path"], certificate["key_path"])
    result_queue: queue.Queue = queue.Queue(maxsize=1)
    try:
        server = _TLSReceiver(("127.0.0.1", CALLBACK_PORT), _handler_type(state, result_queue))
    except OSError as exc:
        raise ORCIDAuthError("The local ORCID callback port is unavailable; close another SkySeal login and retry") from exc
    server.tls_context = context
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    worker.start()
    try:
        if not webbrowser.open(url, new=1, autoraise=True):
            raise ORCIDAuthError("Could not open the default browser for ORCID authentication")
        try:
            result = result_queue.get(timeout=timeout)
        except queue.Empty as exc:
            raise ORCIDAuthError("ORCID authentication timed out; check the registered HTTPS callback and local certificate trust") from exc
        if "error" in result:
            raise ORCIDAuthError("ORCID authentication was declined or did not complete")
        token = result["id_token"]
        access_token = result.pop("access_token")
        claims = verify_id_token(token, client_id, nonce)
        # OIDC implicit responses bind the bearer token through the signed at_hash.
        expected_hash = encode_base64url(hashlib.sha256(access_token.encode("ascii")).digest()[:16])
        if not isinstance(claims.get("at_hash"), str) or not hmac.compare_digest(claims["at_hash"], expected_hash):
            raise ORCIDAuthError("ORCID access-token binding is missing or invalid")
        return {"id_token": token, "claims": claims}
    except UnicodeError as exc:
        raise ORCIDAuthError("Invalid ORCID access-token encoding") from exc
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=6)
