"""Independent verification for the explicitly versioned local desktop draft.

The fixed RP/origin are a native-client namespace, not proof that a particular
application binary was used. ORCID trust comes from independently supplied
configuration and the issuer's signing keys, never keys carried by a bundle.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import ec

from verifier.skyseal_verify import (
    VerificationError, canonical_json, decode_base64url, encode_base64url,
    parse_hash_list, parse_json_bytes, validate_orcid, validate_public_key,
    validate_sky_witness, validate_timestamp, _verify_webauthn_artifact,
)

PROFILE = "skyseal-local-desktop-v0.1-draft"
MAC_PROFILE = "skyseal-local-macos-keychain-v0.1-draft"
MAC_METHOD = "macos-keychain-p256-v0.1"
MAC_NAMESPACE = "net.excyberlab.skyseal.desktop.macos"
SUPPORTED_PROFILES = frozenset({PROFILE, MAC_PROFILE})
RP_ID = "skyseal.localhost"
ORIGIN = "https://skyseal.localhost"
GENESIS_SCHEMA = "urn:skyseal:local:identity-genesis:v0.1"
ACTIVATION_SCHEMA = "urn:skyseal:local:identity-activation:v0.1"
SEAL_SCHEMA = "urn:skyseal:local:seal:v0.1"
MANIFEST_SCHEMA = "urn:skyseal:local:manifest:v0.1"
_SCHEMAS = {
    PROFILE: {"genesis": GENESIS_SCHEMA, "activation": ACTIVATION_SCHEMA,
              "seal": SEAL_SCHEMA, "manifest": MANIFEST_SCHEMA},
    MAC_PROFILE: {kind: "urn:skyseal:local:macos-keychain:" + name + ":v0.1"
                  for kind, name in (("genesis", "identity-genesis"),
                                     ("activation", "identity-activation"),
                                     ("seal", "seal"), ("manifest", "manifest"))},
}
MANIFEST_SCHEMAS = frozenset(item["manifest"] for item in _SCHEMAS.values())
BASE_ARTIFACTS = frozenset({"hashes.txt", "seal.skyseal.json", "identity-genesis.json",
    "identity-activation.json", "sky-witness.json", "sky-witness.jpg"})
OTS_TARGETS = ("identity-activation.json", "seal.skyseal.json")
PUBLIC_ARTIFACTS = BASE_ARTIFACTS | {name + ".ots" for name in OTS_TARGETS} | {"manifest.json"}
MAX_PUBLIC_FILE = 8 * 1024 * 1024


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return canonical_json(value) + b"\n"


def object_digest(value: object) -> str:
    return digest(canonical_json(value))


def schema(profile: str, kind: str) -> str:
    if not isinstance(profile, str) or profile not in SUPPORTED_PROFILES:
        raise VerificationError("unsupported local evidence profile")
    return _SCHEMAS[profile][kind]


def challenge(kind: str, payload: dict) -> bytes:
    if kind not in {"identity", "seal"}:
        raise ValueError("unsupported challenge kind")
    profile = payload.get("profile")
    schema(profile, "seal")
    # Preserve every byte of the Windows v0.1 challenge. macOS uses a separate
    # domain and binds its fixed signing method through the linked genesis.
    prefix = "SkySeal Local Desktop " if profile == PROFILE else "SkySeal Local macOS Keychain "
    return hashlib.sha256((prefix + kind + " v0.1\0").encode() + canonical_json(payload)).digest()


def enrollment_nonce(public_key: dict, algorithm: int, seed: str, profile: str = PROFILE) -> str:
    decode_base64url(seed, "enrollment seed", 32)
    schema(profile, "genesis")
    if profile == PROFILE:
        binding = {"schema": "urn:skyseal:local:orcid-key-binding:v0.1", "public_key": public_key,
            "algorithm": algorithm, "rp_id": RP_ID, "origin": ORIGIN, "seed": seed}
    else:
        binding = {"schema": "urn:skyseal:local:macos-keychain:orcid-key-binding:v0.1",
            "profile": profile, "approval_method": MAC_METHOD, "key_namespace": MAC_NAMESPACE,
            "public_key": public_key, "algorithm": algorithm, "seed": seed}
    return encode_base64url(hashlib.sha256(canonical_json(binding)).digest())


def public_assertion(value: dict, profile: str = PROFILE) -> dict:
    schema(profile, "genesis")
    fields = ("client_data_json", "authenticator_data", "signature") if profile == PROFILE else ("method", "signature")
    return {name: value[name] for name in fields}


def _keys(value: object, expected: set[str], context: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise VerificationError(context + ": invalid members")
    return value


def read_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400 or path.stat().st_size > MAX_PUBLIC_FILE:
        raise VerificationError("invalid or oversized public artifact: " + path.name)
    value = parse_json_bytes(path.read_bytes(), path.name)
    if not isinstance(value, dict):
        raise VerificationError(path.name + ": expected object")
    return value


def verify_assertion(assertion: dict, expected_challenge: bytes, genesis: dict) -> None:
    profile = genesis.get("profile")
    schema(profile, "genesis")
    algorithm, key = validate_public_key({"algorithm": genesis["algorithm"], "jwk": genesis["public_key"]})
    if profile == PROFILE:
        _keys(assertion, {"client_data_json", "authenticator_data", "signature"}, "assertion")
        _verify_webauthn_artifact(assertion, expected_challenge=expected_challenge,
            algorithm=algorithm, jwk=key, trusted_rp_id=RP_ID, trusted_origin=ORIGIN, context="local approval")
        return
    _keys(assertion, {"method", "signature"}, "macOS assertion")
    if assertion["method"] != MAC_METHOD or genesis.get("approval_method") != MAC_METHOD or genesis.get("key_namespace") != MAC_NAMESPACE:
        raise VerificationError("unsupported macOS approval method or key namespace")
    if algorithm != -7 or not isinstance(expected_challenge, bytes) or len(expected_challenge) != 32:
        raise VerificationError("macOS approval requires ES256 and a 32-byte challenge")
    signature = decode_base64url(assertion["signature"], "macOS signature")
    if not 8 <= len(signature) <= 80:
        raise VerificationError("invalid macOS signature length")
    try:
        public_key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(decode_base64url(key["x"], "public key x", 32), "big"),
            int.from_bytes(decode_base64url(key["y"], "public key y", 32), "big"),
            ec.SECP256R1()).public_key()
        public_key.verify(signature, expected_challenge, ec.ECDSA(crypto_hashes.SHA256()))
    except (InvalidSignature, ValueError) as exc:
        raise VerificationError("macOS approval signature verification failed") from exc


def verify_identity(genesis: dict, activation: dict, client_id: str,
                    token_verifier: Callable | None = None) -> dict:
    if not isinstance(genesis, dict):
        raise VerificationError("genesis: expected object")
    profile = genesis.get("profile")
    expected_schema = schema(profile, "genesis")
    context_fields = {"rp_id", "origin"} if profile == PROFILE else {"approval_method", "key_namespace"}
    _keys(genesis, {"schema", "profile", "identity_id", "display_name", "created_at",
        "algorithm", "public_key", "enrollment_seed", "orcid_client_id", "orcid_id_token"} | context_fields, "genesis")
    if genesis["schema"] != expected_schema:
        raise VerificationError("unsupported local identity profile")
    if profile == PROFILE and (genesis["rp_id"] != RP_ID or genesis["origin"] != ORIGIN):
        raise VerificationError("local identity RP/origin mismatch")
    if profile == MAC_PROFILE and (genesis["approval_method"] != MAC_METHOD or genesis["key_namespace"] != MAC_NAMESPACE or genesis["algorithm"] != -7):
        raise VerificationError("unsupported macOS approval method, key namespace, or algorithm")
    if not client_id or genesis["orcid_client_id"] != client_id:
        raise VerificationError("ORCID client ID must match independent verifier configuration")
    validate_orcid(genesis["identity_id"], "local ORCID")
    validate_timestamp(genesis["created_at"], "identity creation time")
    validate_public_key({"algorithm": genesis["algorithm"], "jwk": genesis["public_key"]})
    if token_verifier is None:
        from .orcid_auth import verify_id_token
        token_verifier = verify_id_token
    claims = token_verifier(genesis["orcid_id_token"], client_id,
        enrollment_nonce(genesis["public_key"], genesis["algorithm"], genesis["enrollment_seed"], profile), historical=True)
    if genesis["identity_id"] != "https://orcid.org/" + claims["sub"]:
        raise VerificationError("ORCID token subject does not match the identity")
    _keys(activation, {"schema", "payload", "assertion"}, "activation")
    if activation["schema"] != schema(profile, "activation"):
        raise VerificationError("unsupported local activation")
    payload = _keys(activation["payload"], {"profile", "genesis_digest", "created_at", "nonce"}, "activation payload")
    if payload["profile"] != profile or payload["genesis_digest"] != object_digest(genesis):
        raise VerificationError("identity activation digest mismatch")
    validate_timestamp(payload["created_at"], "activation creation time")
    decode_base64url(payload["nonce"], "activation nonce", 32)
    verify_assertion(activation["assertion"], challenge("identity", payload), genesis)
    return claims


def create_manifest(directory: Path, seal_id: str, profile: str = PROFILE) -> dict:
    return {"schema": schema(profile, "manifest"), "profile": profile, "seal_id": seal_id,
        "artifacts": {name: digest((directory / name).read_bytes())
                      for name in sorted(PUBLIC_ARTIFACTS - {"manifest.json"}) if (directory / name).is_file()}}


def verify_directory(directory: Path, *, client_id: str, token_verifier: Callable | None = None,
                     ots_verify: Callable | None = None, candidate: Path | None = None) -> dict:
    directory = Path(directory)
    manifest = read_json(directory / "manifest.json")
    _keys(manifest, {"schema", "profile", "seal_id", "artifacts"}, "manifest")
    profile = manifest["profile"]
    if manifest["schema"] != schema(profile, "manifest"):
        raise VerificationError("unsupported local evidence profile")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, dict) or not BASE_ARTIFACTS <= set(artifacts) or set(artifacts) - (PUBLIC_ARTIFACTS - {"manifest.json"}):
        raise VerificationError("invalid public artifact set")
    for name, expected in artifacts.items():
        path = directory / name
        if path.is_symlink() or not path.is_file() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400 or path.stat().st_size > MAX_PUBLIC_FILE:
            raise VerificationError("invalid public artifact: " + name)
        if digest(path.read_bytes()) != expected:
            raise VerificationError("artifact digest mismatch: " + name)
    hashes, subject = parse_hash_list(directory / "hashes.txt")
    genesis = read_json(directory / "identity-genesis.json")
    activation = read_json(directory / "identity-activation.json")
    if genesis.get("profile") != profile:
        raise VerificationError("manifest and identity profiles do not match")
    verify_identity(genesis, activation, client_id, token_verifier)
    seal = read_json(directory / "seal.skyseal.json")
    _keys(seal, {"schema", "payload", "assertion"}, "seal")
    if seal["schema"] != schema(profile, "seal"):
        raise VerificationError("unsupported local seal")
    payload = _keys(seal["payload"], {"profile", "seal_id", "subject_digest", "identity_id",
        "identity_digest", "created_at", "nonce", "sky_witness"}, "seal payload")
    if payload["profile"] != profile or payload["seal_id"] != manifest["seal_id"]:
        raise VerificationError("local profile/seal ID mismatch")
    if payload["subject_digest"] != "sha256:" + subject:
        raise VerificationError("hash list subject mismatch")
    if payload["identity_id"] != genesis["identity_id"] or payload["identity_digest"] != object_digest(activation):
        raise VerificationError("seal identity binding mismatch")
    validate_timestamp(payload["created_at"], "seal creation time")
    decode_base64url(payload["nonce"], "seal nonce", 32)
    witness = validate_sky_witness(payload["sky_witness"])
    if witness != read_json(directory / "sky-witness.json") or witness["image_digest"] != digest((directory / "sky-witness.jpg").read_bytes()):
        raise VerificationError("signed sky witness does not match image/metadata")
    verify_assertion(seal["assertion"], challenge("seal", payload), genesis)
    timestamp_status = {}
    timestamp_details = {}
    for target in OTS_TARGETS:
        proof = directory / (target + ".ots")
        detail = ots_verify(directory / target, proof) if proof.name in artifacts and proof.is_file() and ots_verify else {"status": "pending"}
        confirmed = detail.get("status") == "confirmed" if isinstance(detail, dict) else detail is True
        timestamp_details[target] = detail
        timestamp_status[target] = "confirmed" if confirmed else "pending_or_unverified"
    candidate_match = None
    if candidate is not None:
        sha = hashlib.sha256()
        with Path(candidate).open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                sha.update(chunk)
        candidate_match = sha.hexdigest() in hashes
        if not candidate_match:
            raise VerificationError("candidate file is not a member of this seal")
    windows = profile == PROFILE
    warnings = [
        "Experimental local desktop profile; native RP/origin does not attest application binary identity."
        if windows else "Experimental macOS Keychain profile; this signature does not attest application identity or independently prove a password prompt.",
        "Historical ORCID token signature is checked against independently trusted issuer keys; expiry is not a new login.",
        "ORCID identity association and image-provider trust do not establish authorship or exact creation time."]
    result = {"ok": True, "profile": profile, "seal_id": payload["seal_id"],
        "identity_id": genesis["identity_id"], "entry_count": len(hashes),
        "signature_valid": True, "user_verified": True if windows else None, "user_present": True if windows else None,
        "sky_witness": {"artifacts_checked": True}, "opentimestamps": timestamp_status,
        "timestamp_details": timestamp_details,
        "time_confirmed": all(value == "confirmed" for value in timestamp_status.values()),
        "candidate_match": candidate_match, "warnings": warnings}
    if not windows:
        result.update(approval_method=MAC_METHOD,
                      authentication_assurance="local_user_presence_not_attested")
    return result
