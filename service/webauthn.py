from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

from service.cbor import CBORDecodeError, decode_one
from verifier.skyseal_verify import (
    VerificationError,
    decode_base64url,
    encode_base64url,
    parse_json_bytes,
    verify_webauthn_signature,
)


ALLOWED_TRANSPORTS = {"ble", "hybrid", "internal", "nfc", "usb"}


@dataclass(frozen=True)
class RegisteredCredential:
    raw_id: bytes
    algorithm: int
    jwk: dict[str, str]
    transports: list[str]
    sign_count: int


@dataclass(frozen=True)
class AssertionResult:
    raw_id: bytes
    client_data_json: bytes
    authenticator_data: bytes
    signature: bytes
    sign_count: int
    algorithm_name: str


def _require_dict(value: Any, context: str) -> dict[Any, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{context}: expected an object")
    return value


def _exact_keys(value: dict[Any, Any], required: set[str], optional: set[str], context: str) -> None:
    keys = set(value)
    if not all(isinstance(key, str) for key in keys):
        raise VerificationError(f"{context}: member names must be strings")
    missing = sorted(required - keys)
    unknown = sorted(keys - required - optional)
    if missing:
        raise VerificationError(f"{context}: missing members: {', '.join(missing)}")
    if unknown:
        raise VerificationError(f"{context}: unknown members: {', '.join(unknown)}")


def _verify_client_data(
    encoded: Any,
    expected_type: str,
    expected_challenge: bytes,
    expected_origin: str,
) -> bytes:
    raw = decode_base64url(encoded, "clientDataJSON")
    client = _require_dict(parse_json_bytes(raw, "clientDataJSON"), "clientDataJSON")
    if client.get("type") != expected_type:
        raise VerificationError(f"clientDataJSON.type must be {expected_type}")
    if client.get("challenge") != encode_base64url(expected_challenge):
        raise VerificationError("clientDataJSON challenge mismatch")
    if client.get("origin") != expected_origin:
        raise VerificationError("clientDataJSON origin mismatch")
    if "crossOrigin" in client and client["crossOrigin"] is not False:
        raise VerificationError("cross-origin WebAuthn ceremonies are forbidden")
    return raw


def _verify_rp_and_flags(
    authenticator_data: bytes,
    rp_id: str,
    *,
    require_attested_data: bool,
) -> tuple[int, int]:
    if len(authenticator_data) < 37:
        raise VerificationError("authenticator data is shorter than 37 bytes")
    if not hmac.compare_digest(
        authenticator_data[:32], hashlib.sha256(rp_id.encode("utf-8")).digest()
    ):
        raise VerificationError("authenticator rpIdHash mismatch")
    flags = authenticator_data[32]
    if flags & 0x01 == 0:
        raise VerificationError("WebAuthn User Present flag is absent")
    if flags & 0x04 == 0:
        raise VerificationError("WebAuthn User Verified flag is absent")
    has_attested_data = flags & 0x40 != 0
    if has_attested_data != require_attested_data:
        expectation = "required" if require_attested_data else "forbidden"
        raise VerificationError(f"attested credential data flag is {expectation}")
    return flags, int.from_bytes(authenticator_data[33:37], "big")


def _cose_to_jwk(cose: Any) -> tuple[int, dict[str, str]]:
    key = _require_dict(cose, "COSE credential public key")
    if key.get(1) == 2 and key.get(3) == -7 and key.get(-1) == 1:
        x = key.get(-2)
        y = key.get(-3)
        if not isinstance(x, bytes) or len(x) != 32 or not isinstance(y, bytes) or len(y) != 32:
            raise VerificationError("invalid ES256 COSE coordinates")
        return -7, {
            "kty": "EC",
            "crv": "P-256",
            "x": encode_base64url(x),
            "y": encode_base64url(y),
        }
    if key.get(1) == 1 and key.get(3) == -8 and key.get(-1) == 6:
        x = key.get(-2)
        if not isinstance(x, bytes) or len(x) != 32:
            raise VerificationError("invalid Ed25519 COSE public key")
        return -8, {"kty": "OKP", "crv": "Ed25519", "x": encode_base64url(x)}
    raise VerificationError("unsupported COSE credential public key; expected ES256 or Ed25519")


def verify_registration(
    value: Any,
    *,
    expected_challenge: bytes,
    rp_id: str,
    origin: str,
) -> RegisteredCredential:
    registration = _require_dict(value, "registration")
    _exact_keys(
        registration,
        {"id", "raw_id", "type", "response", "transports", "recovery_code_commitment"},
        set(),
        "registration",
    )
    if registration["type"] != "public-key":
        raise VerificationError("registration.type must be public-key")
    raw_id = decode_base64url(registration["raw_id"], "registration.raw_id")
    if not 1 <= len(raw_id) <= 1024:
        raise VerificationError("credential ID length is outside the accepted range")
    if registration["id"] != encode_base64url(raw_id):
        raise VerificationError("registration.id and raw_id differ")
    transports_value = registration["transports"]
    if not isinstance(transports_value, list) or not all(
        isinstance(item, str) and item in ALLOWED_TRANSPORTS for item in transports_value
    ):
        raise VerificationError("registration.transports contains an unsupported value")
    transports = sorted(set(transports_value))

    response = _require_dict(registration["response"], "registration.response")
    _exact_keys(
        response,
        {"client_data_json", "attestation_object"},
        set(),
        "registration.response",
    )
    _verify_client_data(response["client_data_json"], "webauthn.create", expected_challenge, origin)
    attestation_bytes = decode_base64url(response["attestation_object"], "attestationObject")
    try:
        attestation, _ = decode_one(attestation_bytes)
    except CBORDecodeError as exc:
        raise VerificationError(f"invalid attestation CBOR: {exc}") from exc
    attestation = _require_dict(attestation, "attestation object")
    if attestation.get("fmt") != "none":
        raise VerificationError("registration attestation format must be none")
    if attestation.get("attStmt") != {}:
        raise VerificationError("none attestation statement must be empty")
    authenticator_data = attestation.get("authData")
    if not isinstance(authenticator_data, bytes):
        raise VerificationError("attestation authData must be bytes")
    flags, sign_count = _verify_rp_and_flags(
        authenticator_data, rp_id, require_attested_data=True
    )
    if len(authenticator_data) < 55:
        raise VerificationError("attested credential data is truncated")
    credential_id_length = int.from_bytes(authenticator_data[53:55], "big")
    credential_start = 55
    credential_end = credential_start + credential_id_length
    if credential_end > len(authenticator_data):
        raise VerificationError("attested credential ID is truncated")
    if not hmac.compare_digest(authenticator_data[credential_start:credential_end], raw_id):
        raise VerificationError("attested credential ID does not match raw_id")
    try:
        cose_key, consumed = decode_one(
            authenticator_data[credential_end:], require_eof=flags & 0x80 == 0
        )
    except CBORDecodeError as exc:
        raise VerificationError(f"invalid credential public key CBOR: {exc}") from exc
    if flags & 0x80:
        extension_start = credential_end + consumed
        try:
            decode_one(authenticator_data[extension_start:])
        except CBORDecodeError as exc:
            raise VerificationError(f"invalid authenticator extension CBOR: {exc}") from exc
    algorithm, jwk = _cose_to_jwk(cose_key)
    return RegisteredCredential(raw_id, algorithm, jwk, transports, sign_count)


def verify_assertion(
    value: Any,
    *,
    expected_challenge: bytes,
    rp_id: str,
    origin: str,
    algorithm: int,
    jwk: dict[str, str],
    expected_raw_id: bytes,
    expected_user_handle: bytes | None,
) -> AssertionResult:
    assertion = _require_dict(value, "assertion")
    _exact_keys(assertion, {"raw_id", "type", "response"}, set(), "assertion")
    if assertion["type"] != "public-key":
        raise VerificationError("assertion.type must be public-key")
    raw_id = decode_base64url(assertion["raw_id"], "assertion.raw_id")
    if not hmac.compare_digest(raw_id, expected_raw_id):
        raise VerificationError("assertion credential ID mismatch")
    response = _require_dict(assertion["response"], "assertion.response")
    _exact_keys(
        response,
        {"client_data_json", "authenticator_data", "signature", "user_handle"},
        set(),
        "assertion.response",
    )
    client_data_json = _verify_client_data(
        response["client_data_json"], "webauthn.get", expected_challenge, origin
    )
    authenticator_data = decode_base64url(
        response["authenticator_data"], "assertion.authenticator_data"
    )
    flags, sign_count = _verify_rp_and_flags(
        authenticator_data, rp_id, require_attested_data=False
    )
    if flags & 0x80:
        try:
            decode_one(authenticator_data[37:])
        except CBORDecodeError as exc:
            raise VerificationError(f"invalid assertion extension CBOR: {exc}") from exc
    elif len(authenticator_data) != 37:
        raise VerificationError("unexpected trailing assertion authenticator data")
    user_handle_value = response["user_handle"]
    if user_handle_value is not None:
        user_handle = decode_base64url(user_handle_value, "assertion.user_handle")
        if expected_user_handle is None or not hmac.compare_digest(user_handle, expected_user_handle):
            raise VerificationError("assertion user handle mismatch")
    signature = decode_base64url(response["signature"], "assertion.signature")
    signed_bytes = authenticator_data + hashlib.sha256(client_data_json).digest()
    algorithm_name = verify_webauthn_signature(algorithm, jwk, signature, signed_bytes)
    return AssertionResult(
        raw_id=raw_id,
        client_data_json=client_data_json,
        authenticator_data=authenticator_data,
        signature=signature,
        sign_count=sign_count,
        algorithm_name=algorithm_name,
    )
