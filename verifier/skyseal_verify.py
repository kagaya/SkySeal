#!/usr/bin/env python3
"""Strict, offline verifier for SkySeal v1.2 public evidence."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urlsplit

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
except ImportError as exc:  # pragma: no cover - exercised by deployment, not tests
    raise SystemExit(
        "cryptography is required; install verifier/requirements.txt"
    ) from exc


VERSION = "1.2.0-draft.1"
HASH_LIST_FORMAT = "skyseal-sha256-set-v1"
PAYLOAD_SCHEMA = "urn:skyseal:seal-payload:v1"
BUNDLE_SCHEMA = "urn:skyseal:webauthn-bundle:v1"
GENESIS_SCHEMA = "urn:skyseal:identity-genesis:v1"
IDENTITY_ACTIVATION_PAYLOAD_SCHEMA = "urn:skyseal:identity-activation-payload:v1"
IDENTITY_ACTIVATION_SCHEMA = "urn:skyseal:identity-activation:v1"
SKY_WITNESS_SCHEMA = "urn:skyseal:sky-witness:v1"
DOMAIN_SEPARATOR = b"SkySeal WebAuthn Challenge v1\x00"
IDENTITY_ACTIVATION_DOMAIN_SEPARATOR = b"SkySeal Identity Activation Challenge v1\x00"
MAX_SAFE_INTEGER = 9_007_199_254_740_991

HEX64_RE = re.compile(r"[0-9a-f]{64}")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
FINGERPRINT_RE = re.compile(r"[0-9A-F]{40}")
UUID7_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
ORCID_RE = re.compile(
    r"https://orcid\.org/([0-9]{4})-([0-9]{4})-([0-9]{4})-([0-9]{3}[0-9X])"
)
BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+")
TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
RP_ID_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
JMA_SKY_WITNESS_URL_RE = re.compile(
    r"https://www\.data\.jma\.go\.jp/mscweb/data/himawari/img/fd_/fd__b13_([0-9]{4})\.jpg"
)


class VerificationError(ValueError):
    """Raised when an input fails a normative verification rule."""


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


def _reject_float(value: str) -> NoReturn:
    fail(f"floating-point JSON number is forbidden in v1: {value}")


def _reject_constant(value: str) -> NoReturn:
    fail(f"non-finite JSON value is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member name: {key}")
        result[key] = value
    return result


def parse_json_bytes(data: bytes, context: str) -> Any:
    if data.startswith(b"\xef\xbb\xbf"):
        fail(f"{context}: UTF-8 BOM is forbidden")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        fail(f"{context}: not valid UTF-8: {exc}")
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_int=int,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        fail(f"{context}: invalid JSON: {exc.msg} at byte/character {exc.pos}")


def load_json(path: Path, context: str) -> Any:
    try:
        return parse_json_bytes(path.read_bytes(), context)
    except OSError as exc:
        fail(f"{context}: cannot read {path}: {exc}")


def _jcs_string(value: str) -> str:
    output = ['"']
    short_escapes = {
        0x08: "\\b",
        0x09: "\\t",
        0x0A: "\\n",
        0x0C: "\\f",
        0x0D: "\\r",
        0x22: '\\"',
        0x5C: "\\\\",
    }
    for char in value:
        codepoint = ord(char)
        if 0xD800 <= codepoint <= 0xDFFF:
            fail("lone Unicode surrogate is forbidden by JCS")
        if codepoint in short_escapes:
            output.append(short_escapes[codepoint])
        elif codepoint <= 0x1F:
            output.append(f"\\u{codepoint:04x}")
        else:
            output.append(char)
    output.append('"')
    return "".join(output)


def _utf16_sort_key(value: str) -> bytes:
    try:
        return value.encode("utf-16-be", errors="strict")
    except UnicodeEncodeError:
        fail("lone Unicode surrogate is forbidden in an object member name")


def canonical_json(value: Any) -> bytes:
    """Return RFC 8785 bytes for the restricted, integer-only SkySeal subset."""

    def encode(item: Any) -> str:
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, int):
            if not -MAX_SAFE_INTEGER <= item <= MAX_SAFE_INTEGER:
                fail("JSON integer is outside the interoperable IEEE-754 safe range")
            return str(item)
        if isinstance(item, float):
            fail("floating-point JSON values are forbidden in SkySeal v1")
        if isinstance(item, str):
            return _jcs_string(item)
        if isinstance(item, list):
            return "[" + ",".join(encode(element) for element in item) + "]"
        if isinstance(item, dict):
            for key in item:
                if not isinstance(key, str):
                    fail("JSON object member names must be strings")
            members = []
            for key in sorted(item, key=_utf16_sort_key):
                members.append(_jcs_string(key) + ":" + encode(item[key]))
            return "{" + ",".join(members) + "}"
        fail(f"unsupported JSON value type: {type(item).__name__}")

    return encode(value).encode("utf-8")


def _require_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{context}: expected a JSON object")
    return value


def _require_exact_keys(
    value: dict[str, Any],
    required: set[str],
    optional: set[str],
    context: str,
) -> None:
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - required - optional)
    if missing:
        fail(f"{context}: missing members: {', '.join(missing)}")
    if unknown:
        fail(f"{context}: unknown members: {', '.join(unknown)}")


def _require_string(value: Any, context: str) -> str:
    if not isinstance(value, str):
        fail(f"{context}: expected a string")
    return value


def _require_fullmatch(pattern: re.Pattern[str], value: Any, context: str) -> str:
    text = _require_string(value, context)
    if pattern.fullmatch(text) is None:
        fail(f"{context}: invalid value")
    return text


def validate_timestamp(value: Any, context: str) -> str:
    text = _require_fullmatch(TIMESTAMP_RE, value, context)
    try:
        datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        fail(f"{context}: invalid UTC calendar timestamp")
    return text


def validate_orcid(value: Any, context: str) -> str:
    text = _require_string(value, context)
    match = ORCID_RE.fullmatch(text)
    if match is None:
        fail(f"{context}: expected canonical https://orcid.org/... form")
    compact = "".join(match.groups())
    total = 0
    for digit in compact[:15]:
        total = (total + int(digit)) * 2
    result = (12 - (total % 11)) % 11
    expected = "X" if result == 10 else str(result)
    if compact[-1] != expected:
        fail(f"{context}: invalid ORCID ISO 7064 check digit")
    return text


def validate_rp_id(value: Any, context: str) -> str:
    text = _require_string(value, context)
    if text != text.lower() or RP_ID_RE.fullmatch(text) is None:
        fail(f"{context}: expected a lowercase DNS relying-party ID")
    return text


def validate_origin(value: Any, context: str) -> str:
    text = _require_string(value, context)
    parsed = urlsplit(text)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != ""
        or parsed.query
        or parsed.fragment
    ):
        fail(f"{context}: expected an exact HTTPS origin without path/query/fragment")
    canonical_host = parsed.hostname.lower()
    port = f":{parsed.port}" if parsed.port is not None else ""
    canonical = f"https://{canonical_host}{port}"
    if text != canonical:
        fail(f"{context}: origin is not in canonical form")
    return text


def decode_base64url(value: Any, context: str, expected_length: int | None = None) -> bytes:
    text = _require_string(value, context)
    if not text or BASE64URL_RE.fullmatch(text) is None or "=" in text:
        fail(f"{context}: expected canonical unpadded base64url")
    padding = "=" * ((4 - len(text) % 4) % 4)
    try:
        decoded = base64.b64decode(text + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        fail(f"{context}: invalid base64url")
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != text:
        fail(f"{context}: non-canonical base64url encoding")
    if expected_length is not None and len(decoded) != expected_length:
        fail(f"{context}: expected {expected_length} decoded bytes, got {len(decoded)}")
    return decoded


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def parse_hash_list(path: Path) -> tuple[list[str], str]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        fail(f"hash list: cannot read {path}: {exc}")
    if not data:
        fail("hash list: empty commitments are forbidden")
    if data.startswith(b"\xef\xbb\xbf"):
        fail("hash list: UTF-8 BOM is forbidden")
    if not data.endswith(b"\n"):
        fail("hash list: final LF is required")
    records = data[:-1].split(b"\n")
    previous: bytes | None = None
    hashes_out: list[str] = []
    for index, record in enumerate(records, start=1):
        if len(record) != 64 or re.fullmatch(rb"[0-9a-f]{64}", record) is None:
            fail(f"hash list: line {index} is not 64 lowercase hexadecimal characters")
        if previous is not None and record <= previous:
            relation = "duplicate" if record == previous else "not strictly sorted"
            fail(f"hash list: line {index} is {relation}")
        previous = record
        hashes_out.append(record.decode("ascii"))
    digest = hashlib.sha256(data).hexdigest()
    return hashes_out, digest


def validate_sky_witness(value: Any) -> dict[str, Any]:
    witness = _require_object(value, "sky_witness")
    required = {
        "schema",
        "provider",
        "platform",
        "product",
        "observation_time",
        "retrieved_at",
        "source_url",
        "media_type",
        "image_digest",
        "attribution",
    }
    _require_exact_keys(witness, required, set(), "sky_witness")
    constants = {
        "schema": SKY_WITNESS_SCHEMA,
        "provider": "Japan Meteorological Agency (JMA)",
        "platform": "Himawari-8/9",
        "product": "Full Disk Band 13 infrared",
        "media_type": "image/jpeg",
        "attribution": "Japan Meteorological Agency (JMA)",
    }
    for member, expected in constants.items():
        if witness[member] != expected:
            fail(f"sky_witness.{member}: unsupported value")
    validate_timestamp(witness["observation_time"], "sky_witness.observation_time")
    validate_timestamp(witness["retrieved_at"], "sky_witness.retrieved_at")
    observation = datetime.strptime(witness["observation_time"], "%Y-%m-%dT%H:%M:%SZ")
    retrieved = datetime.strptime(witness["retrieved_at"], "%Y-%m-%dT%H:%M:%SZ")
    if observation.second != 0 or observation.minute % 10 != 0:
        fail("sky_witness.observation_time: expected a ten-minute observation slot")
    if retrieved < observation:
        fail("sky_witness.retrieved_at: precedes the observation")
    source_url = _require_fullmatch(
        JMA_SKY_WITNESS_URL_RE,
        witness["source_url"],
        "sky_witness.source_url",
    )
    source_match = JMA_SKY_WITNESS_URL_RE.fullmatch(source_url)
    assert source_match is not None
    if source_match.group(1) != observation.strftime("%H%M"):
        fail("sky_witness.source_url: time slot does not match observation_time")
    _require_fullmatch(DIGEST_RE, witness["image_digest"], "sky_witness.image_digest")
    return witness


def validate_payload(value: Any) -> dict[str, Any]:
    payload = _require_object(value, "seal_payload")
    required = {
        "schema",
        "seal_id",
        "commitment_format",
        "subject_digest",
        "identity_id",
        "identity_version",
        "identity_state_digest",
        "nonce",
        "created_at",
    }
    _require_exact_keys(
        payload,
        required,
        {"private_ledger_commitment", "sky_witness"},
        "seal_payload",
    )
    if payload["schema"] != PAYLOAD_SCHEMA:
        fail("seal_payload.schema: unsupported schema")
    _require_fullmatch(UUID7_RE, payload["seal_id"], "seal_payload.seal_id")
    if payload["commitment_format"] != HASH_LIST_FORMAT:
        fail("seal_payload.commitment_format: unsupported format")

    subject = _require_object(payload["subject_digest"], "seal_payload.subject_digest")
    _require_exact_keys(subject, {"algorithm", "value"}, set(), "seal_payload.subject_digest")
    if subject["algorithm"] != "sha256":
        fail("seal_payload.subject_digest.algorithm: must be sha256")
    _require_fullmatch(HEX64_RE, subject["value"], "seal_payload.subject_digest.value")

    validate_orcid(payload["identity_id"], "seal_payload.identity_id")
    version = payload["identity_version"]
    if isinstance(version, bool) or not isinstance(version, int) or not 1 <= version <= MAX_SAFE_INTEGER:
        fail("seal_payload.identity_version: expected a positive safe integer")
    _require_fullmatch(DIGEST_RE, payload["identity_state_digest"], "seal_payload.identity_state_digest")
    decode_base64url(payload["nonce"], "seal_payload.nonce", expected_length=32)
    validate_timestamp(payload["created_at"], "seal_payload.created_at")
    if "private_ledger_commitment" in payload:
        _require_fullmatch(
            DIGEST_RE,
            payload["private_ledger_commitment"],
            "seal_payload.private_ledger_commitment",
        )
    if "sky_witness" in payload:
        validate_sky_witness(payload["sky_witness"])
    return payload


def validate_bundle(value: Any) -> dict[str, Any]:
    bundle = _require_object(value, "bundle")
    _require_exact_keys(
        bundle,
        {"schema", "seal_payload", "webauthn", "identity", "verification"},
        set(),
        "bundle",
    )
    if bundle["schema"] != BUNDLE_SCHEMA:
        fail("bundle.schema: unsupported schema")
    payload = validate_payload(bundle["seal_payload"])

    assertion = _require_object(bundle["webauthn"], "bundle.webauthn")
    _require_exact_keys(
        assertion,
        {"client_data_json", "authenticator_data", "signature"},
        set(),
        "bundle.webauthn",
    )
    for member in ("client_data_json", "authenticator_data", "signature"):
        decode_base64url(assertion[member], f"bundle.webauthn.{member}")

    identity = _require_object(bundle["identity"], "bundle.identity")
    _require_exact_keys(
        identity,
        {
            "orcid",
            "identity_genesis_digest",
            "identity_state_digest",
            "credential_event_digest",
        },
        set(),
        "bundle.identity",
    )
    validate_orcid(identity["orcid"], "bundle.identity.orcid")
    for member in (
        "identity_genesis_digest",
        "identity_state_digest",
        "credential_event_digest",
    ):
        _require_fullmatch(DIGEST_RE, identity[member], f"bundle.identity.{member}")

    hints = _require_object(bundle["verification"], "bundle.verification")
    _require_exact_keys(hints, {"rp_id", "allowed_origin"}, set(), "bundle.verification")
    validate_rp_id(hints["rp_id"], "bundle.verification.rp_id")
    validate_origin(hints["allowed_origin"], "bundle.verification.allowed_origin")

    if identity["orcid"] != payload["identity_id"]:
        fail("bundle identity ORCID does not match the signed payload")
    if identity["identity_state_digest"] != payload["identity_state_digest"]:
        fail("bundle identity state does not match the signed payload")
    return bundle


def validate_genesis(value: Any) -> dict[str, Any]:
    genesis = _require_object(value, "identity genesis")
    required = {
        "schema",
        "identity_id",
        "identity_version",
        "display_name",
        "rp_id",
        "initial_credential_public_key",
        "recovery_code_commitment",
        "openpgp_primary_fingerprint",
        "orcid_authenticated_at",
        "created_at",
    }
    optional = {"affiliation", "institutional_email"}
    _require_exact_keys(genesis, required, optional, "identity genesis")
    if genesis["schema"] != GENESIS_SCHEMA:
        fail("identity genesis.schema: unsupported schema")
    validate_orcid(genesis["identity_id"], "identity genesis.identity_id")
    if genesis["identity_version"] != 1 or isinstance(genesis["identity_version"], bool):
        fail("identity genesis.identity_version: must be integer 1")
    display_name = _require_string(genesis["display_name"], "identity genesis.display_name")
    if not 1 <= len(display_name) <= 200:
        fail("identity genesis.display_name: invalid length")
    for member, limit in (("affiliation", 300), ("institutional_email", 254)):
        if member in genesis:
            text = _require_string(genesis[member], f"identity genesis.{member}")
            if len(text) > limit:
                fail(f"identity genesis.{member}: too long")
    validate_rp_id(genesis["rp_id"], "identity genesis.rp_id")
    validate_public_key(genesis["initial_credential_public_key"])
    _require_fullmatch(
        DIGEST_RE, genesis["recovery_code_commitment"], "identity genesis.recovery_code_commitment"
    )
    _require_fullmatch(
        FINGERPRINT_RE,
        genesis["openpgp_primary_fingerprint"],
        "identity genesis.openpgp_primary_fingerprint",
    )
    validate_timestamp(genesis["orcid_authenticated_at"], "identity genesis.orcid_authenticated_at")
    validate_timestamp(genesis["created_at"], "identity genesis.created_at")
    return genesis


def validate_public_key(value: Any) -> tuple[int, dict[str, str]]:
    key = _require_object(value, "identity genesis.initial_credential_public_key")
    _require_exact_keys(
        key, {"algorithm", "jwk"}, set(), "identity genesis.initial_credential_public_key"
    )
    algorithm = key["algorithm"]
    if isinstance(algorithm, bool) or not isinstance(algorithm, int) or algorithm not in (-7, -8):
        fail("initial credential algorithm must be ES256 (-7) or Ed25519 (-8)")
    jwk = _require_object(key["jwk"], "initial credential JWK")
    if algorithm == -7:
        _require_exact_keys(jwk, {"kty", "crv", "x", "y"}, set(), "ES256 JWK")
        if jwk["kty"] != "EC" or jwk["crv"] != "P-256":
            fail("ES256 JWK must use EC/P-256")
        decode_base64url(jwk["x"], "ES256 JWK.x", expected_length=32)
        decode_base64url(jwk["y"], "ES256 JWK.y", expected_length=32)
    else:
        _require_exact_keys(jwk, {"kty", "crv", "x"}, set(), "Ed25519 JWK")
        if jwk["kty"] != "OKP" or jwk["crv"] != "Ed25519":
            fail("Ed25519 JWK must use OKP/Ed25519")
        decode_base64url(jwk["x"], "Ed25519 JWK.x", expected_length=32)
    return algorithm, jwk


def compute_challenge(payload: dict[str, Any]) -> bytes:
    return hashlib.sha256(DOMAIN_SEPARATOR + canonical_json(payload)).digest()


def compute_identity_activation_challenge(payload: dict[str, Any]) -> bytes:
    return hashlib.sha256(
        IDENTITY_ACTIVATION_DOMAIN_SEPARATOR + canonical_json(payload)
    ).digest()


def validate_identity_activation(value: Any) -> dict[str, Any]:
    activation = _require_object(value, "identity activation")
    _require_exact_keys(
        activation,
        {"schema", "activation_payload", "webauthn", "verification"},
        set(),
        "identity activation",
    )
    if activation["schema"] != IDENTITY_ACTIVATION_SCHEMA:
        fail("identity activation.schema: unsupported schema")

    payload = _require_object(
        activation["activation_payload"], "identity activation.activation_payload"
    )
    _require_exact_keys(
        payload,
        {
            "schema",
            "identity_id",
            "identity_version",
            "identity_genesis_digest",
            "rp_id",
            "nonce",
            "created_at",
        },
        set(),
        "identity activation.activation_payload",
    )
    if payload["schema"] != IDENTITY_ACTIVATION_PAYLOAD_SCHEMA:
        fail("identity activation payload.schema: unsupported schema")
    validate_orcid(payload["identity_id"], "identity activation payload.identity_id")
    if payload["identity_version"] != 1 or isinstance(payload["identity_version"], bool):
        fail("identity activation payload.identity_version: must be integer 1")
    _require_fullmatch(
        DIGEST_RE,
        payload["identity_genesis_digest"],
        "identity activation payload.identity_genesis_digest",
    )
    validate_rp_id(payload["rp_id"], "identity activation payload.rp_id")
    decode_base64url(payload["nonce"], "identity activation payload.nonce", 32)
    validate_timestamp(payload["created_at"], "identity activation payload.created_at")

    assertion = _require_object(activation["webauthn"], "identity activation.webauthn")
    _require_exact_keys(
        assertion,
        {"client_data_json", "authenticator_data", "signature"},
        set(),
        "identity activation.webauthn",
    )
    for member in ("client_data_json", "authenticator_data", "signature"):
        decode_base64url(assertion[member], f"identity activation.webauthn.{member}")

    hints = _require_object(
        activation["verification"], "identity activation.verification"
    )
    _require_exact_keys(
        hints, {"rp_id", "allowed_origin"}, set(), "identity activation.verification"
    )
    validate_rp_id(hints["rp_id"], "identity activation.verification.rp_id")
    validate_origin(
        hints["allowed_origin"], "identity activation.verification.allowed_origin"
    )
    return activation


def verify_webauthn_signature(
    algorithm: int,
    jwk: dict[str, str],
    signature: bytes,
    signed_bytes: bytes,
) -> str:
    try:
        if algorithm == -7:
            x = int.from_bytes(decode_base64url(jwk["x"], "ES256 JWK.x", 32), "big")
            y = int.from_bytes(decode_base64url(jwk["y"], "ES256 JWK.y", 32), "big")
            public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
            public_key.verify(signature, signed_bytes, ec.ECDSA(hashes.SHA256()))
            return "ES256"
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            decode_base64url(jwk["x"], "Ed25519 JWK.x", 32)
        )
        public_key.verify(signature, signed_bytes)
        return "Ed25519"
    except (InvalidSignature, ValueError) as exc:
        fail(f"WebAuthn signature verification failed: {type(exc).__name__}")


def _verify_webauthn_artifact(
    assertion: dict[str, Any],
    *,
    expected_challenge: bytes,
    algorithm: int,
    jwk: dict[str, str],
    trusted_rp_id: str,
    trusted_origin: str,
    context: str,
) -> tuple[str, int]:
    client_data_bytes = decode_base64url(
        assertion["client_data_json"], f"{context}.client_data_json"
    )
    client_data = _require_object(
        parse_json_bytes(client_data_bytes, f"{context}.clientDataJSON"),
        f"{context}.clientDataJSON",
    )
    if client_data.get("type") != "webauthn.get":
        fail(f"{context}.clientDataJSON.type must be webauthn.get")
    client_challenge = _require_string(
        client_data.get("challenge"), f"{context}.clientDataJSON.challenge"
    )
    if not hmac.compare_digest(client_challenge, encode_base64url(expected_challenge)):
        fail(f"{context}.clientDataJSON challenge does not match")
    if client_data.get("origin") != trusted_origin:
        fail(f"{context}.clientDataJSON origin does not match the trusted origin")
    if "crossOrigin" in client_data and client_data["crossOrigin"] is not False:
        fail(f"{context}: cross-origin WebAuthn assertions are forbidden")

    authenticator_data = decode_base64url(
        assertion["authenticator_data"], f"{context}.authenticator_data"
    )
    if len(authenticator_data) < 37:
        fail(f"{context}.authenticator_data is shorter than 37 bytes")
    expected_rp_hash = hashlib.sha256(trusted_rp_id.encode("utf-8")).digest()
    if not hmac.compare_digest(authenticator_data[:32], expected_rp_hash):
        fail(f"{context}.authenticator_data rpIdHash does not match the trusted RP ID")
    flags = authenticator_data[32]
    if flags & 0x01 == 0:
        fail(f"{context}: WebAuthn User Present flag is not set")
    if flags & 0x04 == 0:
        fail(f"{context}: WebAuthn User Verified flag is not set")
    if flags & 0x40:
        fail(f"{context}: unexpected attested-credential-data flag in an assertion")
    sign_count = int.from_bytes(authenticator_data[33:37], "big")

    signature = decode_base64url(assertion["signature"], f"{context}.signature")
    signed_bytes = authenticator_data + hashlib.sha256(client_data_bytes).digest()
    return verify_webauthn_signature(algorithm, jwk, signature, signed_bytes), sign_count


def verify_identity_activation(
    genesis_path: Path,
    activation_path: Path,
    trusted_rp_id: str,
    trusted_origin: str,
) -> dict[str, Any]:
    trusted_rp_id = validate_rp_id(trusted_rp_id, "trusted RP ID")
    trusted_origin = validate_origin(trusted_origin, "trusted origin")
    genesis = validate_genesis(load_json(genesis_path, "identity genesis"))
    activation = validate_identity_activation(
        load_json(activation_path, "identity activation")
    )
    payload = activation["activation_payload"]
    hints = activation["verification"]
    if hints["rp_id"] != trusted_rp_id or payload["rp_id"] != trusted_rp_id:
        fail("identity activation RP ID does not match the trusted RP ID")
    if hints["allowed_origin"] != trusted_origin:
        fail("identity activation origin does not match the trusted origin")
    if genesis["rp_id"] != trusted_rp_id:
        fail("identity genesis RP ID does not match the trusted RP ID")
    if payload["identity_id"] != genesis["identity_id"]:
        fail("identity activation ORCID does not match the genesis")
    if payload["identity_version"] != genesis["identity_version"]:
        fail("identity activation version does not match the genesis")
    genesis_digest = "sha256:" + hashlib.sha256(canonical_json(genesis)).hexdigest()
    if not hmac.compare_digest(payload["identity_genesis_digest"], genesis_digest):
        fail("identity activation does not match the canonical genesis digest")
    algorithm, jwk = validate_public_key(genesis["initial_credential_public_key"])
    algorithm_name, sign_count = _verify_webauthn_artifact(
        activation["webauthn"],
        expected_challenge=compute_identity_activation_challenge(payload),
        algorithm=algorithm,
        jwk=jwk,
        trusted_rp_id=trusted_rp_id,
        trusted_origin=trusted_origin,
        context="identity activation",
    )
    activation_digest = "sha256:" + hashlib.sha256(canonical_json(activation)).hexdigest()
    return {
        "ok": True,
        "identity_id": genesis["identity_id"],
        "identity_genesis_digest": genesis_digest,
        "identity_activation_digest": activation_digest,
        "credential_algorithm": algorithm_name,
        "sign_count": sign_count,
        "user_present": True,
        "user_verified": True,
    }


def verify_bundle(
    hash_list_path: Path,
    bundle_path: Path,
    genesis_path: Path,
    trusted_rp_id: str,
    trusted_origin: str,
    identity_activation_path: Path | None = None,
    sky_witness_path: Path | None = None,
    sky_witness_image_path: Path | None = None,
) -> dict[str, Any]:
    trusted_rp_id = validate_rp_id(trusted_rp_id, "trusted RP ID")
    trusted_origin = validate_origin(trusted_origin, "trusted origin")
    records, subject_digest = parse_hash_list(hash_list_path)
    bundle = validate_bundle(load_json(bundle_path, "bundle"))
    genesis = validate_genesis(load_json(genesis_path, "identity genesis"))
    payload = bundle["seal_payload"]
    identity = bundle["identity"]
    assertion = bundle["webauthn"]
    hints = bundle["verification"]

    if not hmac.compare_digest(payload["subject_digest"]["value"], subject_digest):
        fail("hash-list digest does not match the signed subject_digest")
    if hints["rp_id"] != trusted_rp_id:
        fail("bundle RP ID hint does not match the trusted RP ID")
    if hints["allowed_origin"] != trusted_origin:
        fail("bundle origin hint does not match the trusted origin")
    if genesis["rp_id"] != trusted_rp_id:
        fail("identity genesis RP ID does not match the trusted RP ID")
    if genesis["identity_id"] != payload["identity_id"]:
        fail("identity genesis ORCID does not match the signed payload")
    if genesis["identity_version"] != payload["identity_version"]:
        fail("identity genesis version does not match the signed payload")

    genesis_digest = "sha256:" + hashlib.sha256(canonical_json(genesis)).hexdigest()
    for member in ("identity_genesis_digest", "credential_event_digest"):
        if not hmac.compare_digest(identity[member], genesis_digest):
            fail(f"bundle.identity.{member} does not match the canonical genesis digest")

    activation_report = None
    if identity_activation_path is not None:
        activation_report = verify_identity_activation(
            genesis_path,
            identity_activation_path,
            trusted_rp_id,
            trusted_origin,
        )
        if not hmac.compare_digest(
            identity["identity_state_digest"],
            activation_report["identity_activation_digest"],
        ):
            fail("bundle identity state does not match the Passkey activation proof")
    elif not hmac.compare_digest(identity["identity_state_digest"], genesis_digest):
        fail("bundle identity state requires an identity activation proof")

    expected_challenge = compute_challenge(payload)
    algorithm, jwk = validate_public_key(genesis["initial_credential_public_key"])
    algorithm_name, sign_count = _verify_webauthn_artifact(
        assertion,
        expected_challenge=expected_challenge,
        algorithm=algorithm,
        jwk=jwk,
        trusted_rp_id=trusted_rp_id,
        trusted_origin=trusted_origin,
        context="seal assertion",
    )

    sky_witness_report = None
    sky_witness_checked = False
    if "sky_witness" in payload:
        signed_witness = payload["sky_witness"]
        if (sky_witness_path is None) != (sky_witness_image_path is None):
            fail("both sky witness metadata and image are required together")
        if sky_witness_path is not None and sky_witness_image_path is not None:
            artifact_witness = validate_sky_witness(
                load_json(sky_witness_path, "sky witness metadata")
            )
            if not hmac.compare_digest(
                canonical_json(signed_witness), canonical_json(artifact_witness)
            ):
                fail("sky witness metadata does not match the signed payload")
            try:
                size = sky_witness_image_path.stat().st_size
                with sky_witness_image_path.open("rb") as handle:
                    start = handle.read(2)
                    handle.seek(-2, 2)
                    end = handle.read(2)
            except OSError as exc:
                fail(f"sky witness image cannot be read: {exc}")
            if not 1024 <= size <= 2 * 1024 * 1024 or start != b"\xff\xd8" or end != b"\xff\xd9":
                fail("sky witness image is not an accepted complete JPEG")
            image_digest = "sha256:" + _hash_file(sky_witness_image_path)
            if not hmac.compare_digest(image_digest, signed_witness["image_digest"]):
                fail("sky witness image digest does not match the signed payload")
            sky_witness_checked = True
        sky_witness_report = {
            "provider": signed_witness["provider"],
            "product": signed_witness["product"],
            "observation_time": signed_witness["observation_time"],
            "retrieved_at": signed_witness["retrieved_at"],
            "source_url": signed_witness["source_url"],
            "image_digest": signed_witness["image_digest"],
            "artifacts_checked": sky_witness_checked,
        }

    return {
        "ok": True,
        "verifier_version": VERSION,
        "commitment_format": HASH_LIST_FORMAT,
        "entry_count": len(records),
        "subject_digest": f"sha256:{subject_digest}",
        "seal_id": payload["seal_id"],
        "identity_id": payload["identity_id"],
        "identity_state_digest": payload["identity_state_digest"],
        "credential_algorithm": algorithm_name,
        "sign_count": sign_count,
        "user_present": True,
        "user_verified": True,
        "sky_witness": sky_witness_report,
        "checked": [
            "strict hash-list format",
            "hash-list subject digest",
            "canonical identity-genesis digest",
            "trusted RP ID and exact origin",
            "WebAuthn challenge binding",
            "User Present and User Verified flags",
            f"{algorithm_name} assertion signature",
        ]
        + (["ORCID-bound Passkey identity activation"] if activation_report else [])
        + (["signed JMA Himawari image digest"] if sky_witness_checked else []),
        "not_checked": ([] if activation_report else ["Passkey identity activation proof"])
        + (["sky witness image artifact"] if sky_witness_report and not sky_witness_checked else [])
        + [
            "optional detached OpenPGP identity link",
            "credential events after genesis",
            "OpenTimestamps proof",
        ],
    }


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        fail(f"candidate file: cannot read {path}: {exc}")
    return digest.hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    hash_parser = subparsers.add_parser("hash-list", help="strictly validate a v1 hash list")
    hash_parser.add_argument("hash_list", type=Path)

    contains_parser = subparsers.add_parser(
        "contains", help="strictly validate a v1 list and test candidate-byte membership"
    )
    contains_parser.add_argument("hash_list", type=Path)
    contains_parser.add_argument("candidate", type=Path)

    bundle_parser = subparsers.add_parser(
        "bundle", help="verify a WebAuthn seal and optional identity activation"
    )
    bundle_parser.add_argument("--hash-list", type=Path, required=True)
    bundle_parser.add_argument("--bundle", type=Path, required=True)
    bundle_parser.add_argument("--identity-genesis", type=Path, required=True)
    bundle_parser.add_argument("--identity-activation", type=Path)
    bundle_parser.add_argument("--rp-id", required=True)
    bundle_parser.add_argument("--origin", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "hash-list":
            records, digest = parse_hash_list(args.hash_list)
            result = {
                "ok": True,
                "commitment_format": HASH_LIST_FORMAT,
                "entry_count": len(records),
                "subject_digest": f"sha256:{digest}",
            }
        elif args.command == "contains":
            records, digest = parse_hash_list(args.hash_list)
            candidate_digest = _hash_file(args.candidate)
            result = {
                "ok": True,
                "commitment_format": HASH_LIST_FORMAT,
                "entry_count": len(records),
                "subject_digest": f"sha256:{digest}",
                "candidate_digest": f"sha256:{candidate_digest}",
                "member": candidate_digest in set(records),
            }
        else:
            result = verify_bundle(
                args.hash_list,
                args.bundle,
                args.identity_genesis,
                args.rp_id,
                args.origin,
                args.identity_activation,
            )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        if args.command == "contains" and not result["member"]:
            return 1
        return 0
    except VerificationError as exc:
        print(
            json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, sort_keys=True),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
