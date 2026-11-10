"""macOS login-Keychain signer; private keys never enter this Python process.

The signed evidence has an explicit Keychain profile, not a synthetic WebAuthn
assertion. A fresh native helper uses an OS-protected key for each signature and
checks its signing ACL before and after use. This development build uses the
Keychain password, including on Intel Macs without Touch ID. It does not claim
Secure Enclave protection or independently attested user verification.
"""
from __future__ import annotations

import json
from pathlib import Path
import platform
import re
import subprocess
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from verifier.skyseal_verify import (
    VerificationError, decode_base64url, encode_base64url,
    parse_json_bytes, validate_public_key,
)

PROFILE = "skyseal-local-macos-keychain-v0.1-draft"
METHOD = "macos-keychain-p256-v0.1"
KEY_NAMESPACE = "net.excyberlab.skyseal.desktop.macos"
RP_ID = "skyseal.localhost"
ORIGIN = "https://skyseal.localhost"
MAX_RESPONSE = 64 * 1024


class MacOSAuthError(RuntimeError):
    def __init__(self, message: str, code: str = "macos_auth_error"):
        super().__init__(message)
        self.code = code


def _helper_path() -> Path:
    if sys.platform != "darwin":
        raise MacOSAuthError("macOS Keychain signing is available only on macOS", "unsupported_platform")
    if getattr(sys, "frozen", False):
        candidate = Path(sys.executable).resolve().parent / "macos-signer"
    else:
        architecture = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64"}.get(platform.machine())
        if architecture is None:
            raise MacOSAuthError("Unsupported Mac architecture", "unsupported_architecture")
        candidate = Path(__file__).resolve().parents[1] / "src-tauri" / "binaries" / ("macos-signer-" + architecture + "-apple-darwin")
    if not candidate.is_file() or candidate.is_symlink():
        raise MacOSAuthError("The bundled macOS signing helper is missing. Reinstall SkySeal.", "signer_missing")
    return candidate


def _invoke(request: dict, *, timeout: int = 180) -> dict:
    helper = _helper_path()
    try:
        completed = subprocess.run([str(helper)], input=json.dumps(request).encode("utf-8") + b"\n",
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=False,
            cwd=str(helper.parent))
    except subprocess.TimeoutExpired as exc:
        raise MacOSAuthError("The Keychain approval timed out", "approval_timeout") from exc
    except OSError as exc:
        raise MacOSAuthError("Cannot start the macOS signing helper", "signer_unavailable") from exc
    if len(completed.stdout) > MAX_RESPONSE:
        raise MacOSAuthError("The signing helper returned an oversized response", "invalid_native_response")
    try:
        response = parse_json_bytes(completed.stdout, "macOS signing response")
    except (VerificationError, ValueError, TypeError) as exc:
        raise MacOSAuthError("The signing helper did not return a valid response", "invalid_native_response") from exc
    if not isinstance(response, dict):
        raise MacOSAuthError("Invalid macOS signing response", "invalid_native_response")
    if response.get("ok") is not True:
        detail = response.get("error")
        if not isinstance(detail, dict):
            raise MacOSAuthError("macOS did not approve this signing operation", "approval_failed")
        code = detail.get("code")
        message = detail.get("message")
        if not isinstance(code, str) or not re.fullmatch(r"[a-z_]{1,80}", code) or not isinstance(message, str) or len(message) > 1000:
            raise MacOSAuthError("Invalid macOS signing error", "invalid_native_response")
        raise MacOSAuthError(message, code)
    if completed.returncode != 0 or not isinstance(response.get("result"), dict):
        raise MacOSAuthError("macOS signing did not complete successfully", "invalid_native_response")
    return response["result"]


def _context(rp_id: str, origin: str) -> None:
    if rp_id != RP_ID or origin != ORIGIN:
        raise MacOSAuthError("The macOS signer requires the fixed SkySeal local context", "invalid_local_context")


def availability() -> dict:
    try:
        result = _invoke({"op": "status"}, timeout=10)
        if result.get("backend") != "macos-keychain" or result.get("approval_method") != METHOD or not isinstance(result.get("available"), bool):
            raise MacOSAuthError("Invalid signing helper status", "invalid_native_response")
        return {**result, "platform": "macos", "profile": PROFILE,
                "authentication_assurance": "local_user_presence_not_attested"}
    except MacOSAuthError as exc:
        return {"available": False, "platform": "macos", "backend": "macos-keychain",
                "profile": PROFILE, "approval_method": METHOD,
                "reason": str(exc), "error_code": exc.code,
                "authentication_assurance": "local_user_presence_not_attested"}


def _credential(value: dict) -> dict:
    if not isinstance(value, dict) or value.get("method") != METHOD or value.get("algorithm") != -7:
        raise MacOSAuthError("Unsupported macOS signing credential", "invalid_credential")
    key_id = value.get("key_id")
    if not isinstance(key_id, str) or re.fullmatch(r"skyseal-key-[0-9a-f]{32}", key_id) is None:
        raise MacOSAuthError("Invalid macOS key identifier", "invalid_credential")
    if value.get("key_storage") != "login-keychain-nonextractable" or value.get("approval_policy") != "password-per-signature" or value.get("hardware_attested") is not False:
        raise MacOSAuthError("The native key does not have the required protected signing policy", "invalid_credential")
    try:
        validate_public_key({"algorithm": -7, "jwk": value["public_key"]})
    except (VerificationError, KeyError, ValueError, TypeError) as exc:
        raise MacOSAuthError("Invalid macOS signing public key", "invalid_credential") from exc
    return value


def register(rp_id: str, origin: str, user_id: bytes, user_name: str) -> dict:
    _context(rp_id, origin)
    if not isinstance(user_id, bytes) or not 1 <= len(user_id) <= 64 or not isinstance(user_name, str) or not user_name:
        raise MacOSAuthError("Invalid local researcher registration", "invalid_registration")
    result = _credential(_invoke({"op": "register"}))
    # Only the opaque Keychain reference and public fields are retained. Avoid
    # carrying unexpected helper data or user handles into private metadata.
    return {name: result[name] for name in ("key_id", "algorithm", "public_key", "method",
        "key_storage", "approval_policy", "hardware_attested")}


def sign(credential: dict, challenge: bytes, rp_id: str, origin: str) -> dict:
    _context(rp_id, origin)
    credential = _credential(credential)
    if not isinstance(challenge, bytes) or len(challenge) != 32:
        raise MacOSAuthError("A 32-byte SkySeal signing challenge is required", "invalid_challenge")
    response = _invoke({"op": "sign", "key_id": credential["key_id"], "challenge": encode_base64url(challenge)})
    if set(response) != {"method", "signature"} or response.get("method") != METHOD:
        raise MacOSAuthError("Invalid native signature fields", "invalid_native_response")
    try:
        signature = decode_base64url(response["signature"], "macOS signature")
        if not 8 <= len(signature) <= 80:
            raise ValueError("invalid DER signature size")
        jwk = credential["public_key"]
        key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(decode_base64url(jwk["x"], "key x", 32), "big"),
            int.from_bytes(decode_base64url(jwk["y"], "key y", 32), "big"),
            ec.SECP256R1()).public_key()
        key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
    except (VerificationError, ValueError, TypeError, KeyError, InvalidSignature) as exc:
        raise MacOSAuthError("The native signature does not match the registered key and exact challenge", "invalid_native_signature") from exc
    return {"method": METHOD, "signature": response["signature"]}
