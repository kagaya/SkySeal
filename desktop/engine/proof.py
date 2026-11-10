"""Independent verification for the explicitly versioned local desktop draft.

The fixed RP/origin are a native-client namespace, not proof that a particular
application binary was used. ORCID trust comes from independently supplied
configuration and the issuer's signing keys, never keys carried by a bundle.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable

from verifier.skyseal_verify import (
    VerificationError, canonical_json, decode_base64url, encode_base64url,
    parse_hash_list, parse_json_bytes, validate_orcid, validate_public_key,
    validate_sky_witness, validate_timestamp, _verify_webauthn_artifact,
)

PROFILE = "skyseal-local-desktop-v0.1-draft"
RP_ID = "skyseal.localhost"
ORIGIN = "https://skyseal.localhost"
GENESIS_SCHEMA = "urn:skyseal:local:identity-genesis:v0.1"
ACTIVATION_SCHEMA = "urn:skyseal:local:identity-activation:v0.1"
SEAL_SCHEMA = "urn:skyseal:local:seal:v0.1"
MANIFEST_SCHEMA = "urn:skyseal:local:manifest:v0.1"
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


def challenge(kind: str, payload: dict) -> bytes:
    if kind not in {"identity", "seal"}:
        raise ValueError("unsupported challenge kind")
    return hashlib.sha256(("SkySeal Local Desktop " + kind + " v0.1\0").encode() + canonical_json(payload)).digest()


def enrollment_nonce(public_key: dict, algorithm: int, seed: str) -> str:
    decode_base64url(seed, "enrollment seed", 32)
    return encode_base64url(hashlib.sha256(canonical_json({
        "schema": "urn:skyseal:local:orcid-key-binding:v0.1", "public_key": public_key,
        "algorithm": algorithm, "rp_id": RP_ID, "origin": ORIGIN, "seed": seed,
    })).digest())


def public_assertion(value: dict) -> dict:
    return {name: value[name] for name in ("client_data_json", "authenticator_data", "signature")}


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
    _keys(assertion, {"client_data_json", "authenticator_data", "signature"}, "assertion")
    algorithm, key = validate_public_key({"algorithm": genesis["algorithm"], "jwk": genesis["public_key"]})
    _verify_webauthn_artifact(assertion, expected_challenge=expected_challenge,
        algorithm=algorithm, jwk=key, trusted_rp_id=RP_ID, trusted_origin=ORIGIN, context="local approval")


def verify_identity(genesis: dict, activation: dict, client_id: str,
                    token_verifier: Callable | None = None) -> dict:
    _keys(genesis, {"schema", "profile", "identity_id", "display_name", "created_at",
        "rp_id", "origin", "algorithm", "public_key", "enrollment_seed", "orcid_client_id", "orcid_id_token"}, "genesis")
    if genesis["schema"] != GENESIS_SCHEMA or genesis["profile"] != PROFILE:
        raise VerificationError("unsupported local identity profile")
    if genesis["rp_id"] != RP_ID or genesis["origin"] != ORIGIN:
        raise VerificationError("local identity RP/origin mismatch")
    if not client_id or genesis["orcid_client_id"] != client_id:
        raise VerificationError("ORCID client ID must match independent verifier configuration")
    validate_orcid(genesis["identity_id"], "local ORCID")
    validate_timestamp(genesis["created_at"], "identity creation time")
    validate_public_key({"algorithm": genesis["algorithm"], "jwk": genesis["public_key"]})
    if token_verifier is None:
        from .orcid_auth import verify_id_token
        token_verifier = verify_id_token
    claims = token_verifier(genesis["orcid_id_token"], client_id,
        enrollment_nonce(genesis["public_key"], genesis["algorithm"], genesis["enrollment_seed"]), historical=True)
    if genesis["identity_id"] != "https://orcid.org/" + claims["sub"]:
        raise VerificationError("ORCID token subject does not match the identity")
    _keys(activation, {"schema", "payload", "assertion"}, "activation")
    if activation["schema"] != ACTIVATION_SCHEMA:
        raise VerificationError("unsupported local activation")
    payload = _keys(activation["payload"], {"profile", "genesis_digest", "created_at", "nonce"}, "activation payload")
    if payload["profile"] != PROFILE or payload["genesis_digest"] != object_digest(genesis):
        raise VerificationError("identity activation digest mismatch")
    validate_timestamp(payload["created_at"], "activation creation time")
    decode_base64url(payload["nonce"], "activation nonce", 32)
    verify_assertion(activation["assertion"], challenge("identity", payload), genesis)
    return claims


def create_manifest(directory: Path, seal_id: str) -> dict:
    return {"schema": MANIFEST_SCHEMA, "profile": PROFILE, "seal_id": seal_id,
        "artifacts": {name: digest((directory / name).read_bytes())
                      for name in sorted(PUBLIC_ARTIFACTS - {"manifest.json"}) if (directory / name).is_file()}}


def verify_directory(directory: Path, *, client_id: str, token_verifier: Callable | None = None,
                     ots_verify: Callable | None = None, candidate: Path | None = None) -> dict:
    directory = Path(directory)
    manifest = read_json(directory / "manifest.json")
    _keys(manifest, {"schema", "profile", "seal_id", "artifacts"}, "manifest")
    if manifest["schema"] != MANIFEST_SCHEMA or manifest["profile"] != PROFILE:
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
    verify_identity(genesis, activation, client_id, token_verifier)
    seal = read_json(directory / "seal.skyseal.json")
    _keys(seal, {"schema", "payload", "assertion"}, "seal")
    if seal["schema"] != SEAL_SCHEMA:
        raise VerificationError("unsupported local seal")
    payload = _keys(seal["payload"], {"profile", "seal_id", "subject_digest", "identity_id",
        "identity_digest", "created_at", "nonce", "sky_witness"}, "seal payload")
    if payload["profile"] != PROFILE or payload["seal_id"] != manifest["seal_id"]:
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
    return {"ok": True, "profile": PROFILE, "seal_id": payload["seal_id"],
        "identity_id": genesis["identity_id"], "entry_count": len(hashes),
        "signature_valid": True, "user_verified": True, "user_present": True,
        "sky_witness": {"artifacts_checked": True}, "opentimestamps": timestamp_status,
        "timestamp_details": timestamp_details,
        "time_confirmed": all(value == "confirmed" for value in timestamp_status.values()),
        "candidate_match": candidate_match, "warnings": [
            "Experimental local desktop profile; native RP/origin does not attest application binary identity.",
            "Historical ORCID token signature is checked against independently trusted issuer keys; expiry is not a new login.",
            "ORCID identity association and image-provider trust do not establish authorship or exact creation time."]}
