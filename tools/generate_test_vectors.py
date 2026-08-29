#!/usr/bin/env python3
"""Generate deterministic, non-secret SkySeal v1 conformance vectors."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY))

from verifier.skyseal_verify import (  # noqa: E402
    BUNDLE_SCHEMA,
    GENESIS_SCHEMA,
    HASH_LIST_FORMAT,
    PAYLOAD_SCHEMA,
    canonical_json,
    compute_challenge,
    decode_base64url,
    encode_base64url,
)

OUTPUT = REPOSITORY / "spec" / "test-vectors" / "v1"
RP_ID = "seal.example.org"
ORIGIN = "https://seal.example.org"
ORCID = "https://orcid.org/0000-0000-0000-0001"
OPENPGP_FINGERPRINT = "85F79058BD83EB3889DEF766B065C54586067E2E"
CREATED_AT = "2026-08-29T03:00:00Z"

MEMBER_BYTES = b"SkySeal v1 deterministic test member\n"
SECOND_MEMBER_BYTES = b"SkySeal v1 second deterministic test member\n"
NON_MEMBER_BYTES = b"SkySeal v1 deterministic non-member\n"
NONCE = bytes(range(32))
RECOVERY_CODE = bytes(range(255, 223, -1))


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def public_key_and_signer(algorithm: int):
    if algorithm == -7:
        private_key = ec.derive_private_key(1, ec.SECP256R1())
        numbers = private_key.public_key().public_numbers()
        public_record = {
            "algorithm": -7,
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": encode_base64url(numbers.x.to_bytes(32, "big")),
                "y": encode_base64url(numbers.y.to_bytes(32, "big")),
            },
        }

        def sign(data: bytes) -> bytes:
            return private_key.sign(
                data,
                ec.ECDSA(hashes.SHA256(), deterministic_signing=True),
            )

        return public_record, sign

    seed = hashlib.sha256(b"SkySeal v1 public Ed25519 test seed").digest()
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    public_record = {
        "algorithm": -8,
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": encode_base64url(public_bytes),
        },
    }
    return public_record, private_key.sign


def create_valid_vector(directory: Path, algorithm: int, seal_id: str) -> dict[str, object]:
    directory.mkdir(parents=True, exist_ok=True)
    public_key, sign = public_key_and_signer(algorithm)
    recovery_commitment = "sha256:" + hashlib.sha256(
        b"SkySeal Recovery Code v1\x00" + RECOVERY_CODE
    ).hexdigest()
    genesis = {
        "schema": GENESIS_SCHEMA,
        "identity_id": ORCID,
        "identity_version": 1,
        "display_name": "SkySeal Test Researcher",
        "rp_id": RP_ID,
        "initial_credential_public_key": public_key,
        "recovery_code_commitment": recovery_commitment,
        "openpgp_primary_fingerprint": OPENPGP_FINGERPRINT,
        "orcid_authenticated_at": CREATED_AT,
        "created_at": CREATED_AT,
    }
    genesis_digest = "sha256:" + hashlib.sha256(canonical_json(genesis)).hexdigest()

    member_hashes = sorted(
        {
            hashlib.sha256(MEMBER_BYTES).hexdigest(),
            hashlib.sha256(SECOND_MEMBER_BYTES).hexdigest(),
        }
    )
    hash_list_bytes = ("\n".join(member_hashes) + "\n").encode("ascii")
    subject_digest = hashlib.sha256(hash_list_bytes).hexdigest()
    payload = {
        "schema": PAYLOAD_SCHEMA,
        "seal_id": seal_id,
        "commitment_format": HASH_LIST_FORMAT,
        "subject_digest": {"algorithm": "sha256", "value": subject_digest},
        "identity_id": ORCID,
        "identity_version": 1,
        "identity_state_digest": genesis_digest,
        "nonce": encode_base64url(NONCE),
        "created_at": CREATED_AT,
    }
    challenge = compute_challenge(payload)
    client_data = {
        "type": "webauthn.get",
        "challenge": encode_base64url(challenge),
        "origin": ORIGIN,
        "crossOrigin": False,
    }
    client_data_bytes = json.dumps(
        client_data, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    authenticator_data = (
        hashlib.sha256(RP_ID.encode("utf-8")).digest()
        + bytes([0x05])
        + (0).to_bytes(4, "big")
    )
    signed_bytes = authenticator_data + hashlib.sha256(client_data_bytes).digest()
    signature = sign(signed_bytes)
    bundle = {
        "schema": BUNDLE_SCHEMA,
        "seal_payload": payload,
        "webauthn": {
            "client_data_json": encode_base64url(client_data_bytes),
            "authenticator_data": encode_base64url(authenticator_data),
            "signature": encode_base64url(signature),
        },
        "identity": {
            "orcid": ORCID,
            "identity_genesis_digest": genesis_digest,
            "identity_state_digest": genesis_digest,
            "credential_event_digest": genesis_digest,
        },
        "verification": {"rp_id": RP_ID, "allowed_origin": ORIGIN},
    }

    (directory / "public.txt").write_bytes(hash_list_bytes)
    (directory / "candidate-member.bin").write_bytes(MEMBER_BYTES)
    (directory / "candidate-nonmember.bin").write_bytes(NON_MEMBER_BYTES)
    write_json(directory / "identity-genesis.json", genesis)
    write_json(directory / "public.txt.skyseal.json", bundle)
    manifest = {
        "algorithm": "ES256" if algorithm == -7 else "Ed25519",
        "challenge_base64url": encode_base64url(challenge),
        "genesis_digest": genesis_digest,
        "hash_list_sha256": subject_digest,
        "member_sha256": hashlib.sha256(MEMBER_BYTES).hexdigest(),
        "nonmember_sha256": hashlib.sha256(NON_MEMBER_BYTES).hexdigest(),
        "signed_bytes_sha256": hashlib.sha256(signed_bytes).hexdigest(),
    }
    write_json(directory / "manifest.json", manifest)
    return bundle


def create_invalid_vectors(valid_es256: dict[str, object]) -> None:
    invalid = OUTPUT / "invalid"
    invalid.mkdir(parents=True, exist_ok=True)
    hashes_list = sorted(
        [
            hashlib.sha256(MEMBER_BYTES).hexdigest(),
            hashlib.sha256(SECOND_MEMBER_BYTES).hexdigest(),
        ]
    )
    (invalid / "uppercase.txt").write_bytes((hashes_list[0].upper() + "\n").encode("ascii"))
    (invalid / "unsorted.txt").write_bytes(("\n".join(reversed(hashes_list)) + "\n").encode("ascii"))
    (invalid / "duplicate.txt").write_bytes(
        (hashes_list[0] + "\n" + hashes_list[0] + "\n").encode("ascii")
    )
    (invalid / "missing-final-lf.txt").write_bytes(hashes_list[0].encode("ascii"))
    (invalid / "blank-line.txt").write_bytes((hashes_list[0] + "\n\n").encode("ascii"))

    tampered_signature = copy.deepcopy(valid_es256)
    signature_text = tampered_signature["webauthn"]["signature"]
    signature = bytearray(decode_base64url(signature_text, "test signature"))
    signature[-1] ^= 0x01
    tampered_signature["webauthn"]["signature"] = encode_base64url(bytes(signature))
    write_json(invalid / "tampered-signature.skyseal.json", tampered_signature)

    wrong_origin = copy.deepcopy(valid_es256)
    client = json.loads(
        decode_base64url(wrong_origin["webauthn"]["client_data_json"], "test client data")
    )
    client["origin"] = "https://attacker.example"
    wrong_origin["webauthn"]["client_data_json"] = encode_base64url(
        json.dumps(client, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )
    write_json(invalid / "wrong-origin.skyseal.json", wrong_origin)

    missing_uv = copy.deepcopy(valid_es256)
    auth_data = bytearray(
        decode_base64url(missing_uv["webauthn"]["authenticator_data"], "test auth data")
    )
    auth_data[32] = 0x01
    missing_uv["webauthn"]["authenticator_data"] = encode_base64url(bytes(auth_data))
    write_json(invalid / "missing-uv.skyseal.json", missing_uv)

    wrong_subject = copy.deepcopy(valid_es256)
    digest = wrong_subject["seal_payload"]["subject_digest"]["value"]
    wrong_subject["seal_payload"]["subject_digest"]["value"] = (
        ("0" if digest[0] != "0" else "1") + digest[1:]
    )
    write_json(invalid / "wrong-subject.skyseal.json", wrong_subject)

    raw_identifier = copy.deepcopy(valid_es256)
    raw_identifier["webauthn"]["credential_id"] = "forbidden-public-identifier"
    write_json(invalid / "raw-credential-id.skyseal.json", raw_identifier)


def main() -> None:
    if OUTPUT.exists():
        shutil.rmtree(OUTPUT)
    valid_es256 = create_valid_vector(
        OUTPUT / "valid-es256",
        -7,
        "0198f6d0-1234-7abc-8def-0123456789ab",
    )
    create_valid_vector(
        OUTPUT / "valid-ed25519",
        -8,
        "0198f6d0-1234-7abc-8def-0123456789ac",
    )
    create_invalid_vectors(valid_es256)
    print(f"Generated deterministic test vectors in {OUTPUT}")


if __name__ == "__main__":
    main()
