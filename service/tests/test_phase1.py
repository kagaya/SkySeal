from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from service.app import Application
from service.bootstrap_identity import valid_signature_fingerprints, verify_signature
from service.cbor import CBORDecodeError, decode_one
from service.config import Config
from service.orcid import AuthenticatedORCID
from service.storage import Store
from verifier.skyseal_verify import (
    VerificationError,
    canonical_json,
    decode_base64url,
    encode_base64url,
    verify_bundle,
    verify_identity_activation,
)


ORCID = "https://orcid.org/0000-0000-0000-0001"
RP_ID = "seal.example.org"
ORIGIN = "https://seal.example.org"


def cbor_argument(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 256:
        return bytes([(major << 5) | 24, value])
    if value < 65536:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 2**32:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def cbor_encode(value) -> bytes:
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int):
        return cbor_argument(0, value) if value >= 0 else cbor_argument(1, -1 - value)
    if isinstance(value, bytes):
        return cbor_argument(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return cbor_argument(3, len(encoded)) + encoded
    if isinstance(value, list):
        return cbor_argument(4, len(value)) + b"".join(cbor_encode(item) for item in value)
    if isinstance(value, dict):
        return cbor_argument(5, len(value)) + b"".join(
            cbor_encode(key) + cbor_encode(item) for key, item in value.items()
        )
    raise TypeError(type(value))


def response_json(response) -> dict:
    return json.loads(response.body)


class Phase1FlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = Config(
            origin=ORIGIN,
            rp_id=RP_ID,
            database_path=self.root / "skyseal.sqlite3",
            orcid_client_id="APP-TEST",
            orcid_client_secret="test-secret",
            orcid_redirect_uri=f"{ORIGIN}/api/v1/orcid/callback",
            allow_unsealed_identity=True,
        )
        self.app = Application(self.config)
        user = self.app.store.upsert_user(ORCID, "SkySeal Test Researcher")
        self.user_handle = bytes(user["user_handle"])
        token, csrf = self.app.store.create_session(ORCID, 3600)
        self.session_token = token
        self.csrf = csrf
        self.session_headers = {
            "Cookie": f"skyseal_session={token}",
            "X-SkySeal-CSRF": csrf,
        }
        self.private_key = ec.derive_private_key(1, ec.SECP256R1())
        self.raw_id = hashlib.sha256(b"SkySeal Phase 1 test credential ID").digest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def registration_body(self, options: dict, challenge_override: bytes | None = None) -> bytes:
        public = self.private_key.public_key().public_numbers()
        cose = {
            1: 2,
            3: -7,
            -1: 1,
            -2: public.x.to_bytes(32, "big"),
            -3: public.y.to_bytes(32, "big"),
        }
        challenge = challenge_override or decode_base64url(
            options["publicKey"]["challenge"], "challenge"
        )
        client_data = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": encode_base64url(challenge),
                "origin": ORIGIN,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()
        auth_data = (
            hashlib.sha256(RP_ID.encode()).digest()
            + bytes([0x45])
            + (0).to_bytes(4, "big")
            + bytes(16)
            + len(self.raw_id).to_bytes(2, "big")
            + self.raw_id
            + cbor_encode(cose)
        )
        attestation = cbor_encode({"fmt": "none", "authData": auth_data, "attStmt": {}})
        return json.dumps(
            {
                "registration_id": options["registration_id"],
                "credential": {
                    "id": encode_base64url(self.raw_id),
                    "raw_id": encode_base64url(self.raw_id),
                    "type": "public-key",
                    "response": {
                        "client_data_json": encode_base64url(client_data),
                        "attestation_object": encode_base64url(attestation),
                    },
                    "transports": ["internal"],
                    "recovery_code_commitment": "sha256:"
                    + hashlib.sha256(b"public test recovery commitment").hexdigest(),
                },
            },
            separators=(",", ":"),
        ).encode()

    def enroll(self) -> dict:
        options_response = self.app.handle(
            "POST", "/api/v1/webauthn/registration/options", self.session_headers
        )
        self.assertEqual(options_response.status, 200, options_response.body)
        options = response_json(options_response)
        completed = self.app.handle(
            "POST",
            "/api/v1/webauthn/registration/complete",
            {**self.session_headers, "Content-Type": "application/json"},
            self.registration_body(options),
        )
        self.assertEqual(completed.status, 201, completed.body)
        return response_json(completed)

    def assertion_body(self, challenge: bytes) -> bytes:
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": encode_base64url(challenge),
                "origin": ORIGIN,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()
        authenticator_data = (
            hashlib.sha256(RP_ID.encode()).digest()
            + bytes([0x05])
            + (0).to_bytes(4, "big")
        )
        signature = self.private_key.sign(
            authenticator_data + hashlib.sha256(client_data).digest(),
            ec.ECDSA(hashes.SHA256(), deterministic_signing=True),
        )
        return json.dumps(
            {
                "raw_id": encode_base64url(self.raw_id),
                "type": "public-key",
                "response": {
                    "client_data_json": encode_base64url(client_data),
                    "authenticator_data": encode_base64url(authenticator_data),
                    "signature": encode_base64url(signature),
                    "user_handle": None,
                },
            },
            separators=(",", ":"),
        ).encode()

    def activate_with_passkey(self) -> dict:
        options = response_json(
            self.app.handle(
                "POST", "/api/v1/identity/activation/options", self.session_headers
            )
        )
        challenge = decode_base64url(
            options["publicKey"]["challenge"], "activation challenge"
        )
        completed = self.app.handle(
            "POST",
            "/api/v1/identity/activation/assertion",
            {**self.session_headers, "Content-Type": "application/json"},
            self.assertion_body(challenge),
        )
        self.assertEqual(completed.status, 200, completed.body)
        return response_json(completed)

    def test_complete_enrollment_approval_and_offline_verification(self) -> None:
        enrollment = self.enroll()
        self.assertEqual(enrollment["identity_status"], "pending_activation")
        identity = self.app.store.get_identity(ORCID)
        self.assertNotIn(encode_base64url(self.raw_id).encode(), bytes(identity["genesis_json"]))
        self.activate_with_passkey()
        identity = self.app.store.get_identity(ORCID)
        self.assertEqual(identity["activation_method"], "webauthn_v1")

        member_bytes = b"private research bytes remain on the PC\n"
        file_hash = hashlib.sha256(member_bytes).hexdigest()
        hash_list_bytes = (file_hash + "\n").encode()
        hash_list = self.root / "public.txt"
        hash_list.write_bytes(hash_list_bytes)
        subject_digest = hashlib.sha256(hash_list_bytes).hexdigest()
        created = self.app.handle(
            "POST",
            "/api/v1/seals",
            {"Content-Type": "application/json"},
            json.dumps(
                {
                    "commitment_format": "skyseal-sha256-set-v1",
                    "subject_digest": subject_digest,
                    "entry_count": 1,
                },
                separators=(",", ":"),
            ).encode(),
        )
        self.assertEqual(created.status, 201, created.body)
        transaction = response_json(created)
        self.assertIn("#seal=", transaction["approval_url"])
        self.assertNotIn("token=", urlsplit(transaction["approval_url"]).query)
        authorization = {"Authorization": f"Bearer {transaction['bearer_token']}"}

        options_response = self.app.handle(
            "POST",
            f"/api/v1/seals/{transaction['seal_id']}/webauthn/options",
            {**self.session_headers, **authorization},
        )
        self.assertEqual(options_response.status, 200, options_response.body)
        assertion_options = response_json(options_response)
        transports = assertion_options["publicKey"]["allowCredentials"][0]["transports"]
        self.assertIn("hybrid", transports)
        challenge = decode_base64url(assertion_options["publicKey"]["challenge"], "challenge")
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": encode_base64url(challenge),
                "origin": ORIGIN,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()
        authenticator_data = (
            hashlib.sha256(RP_ID.encode()).digest() + bytes([0x05]) + (0).to_bytes(4, "big")
        )
        signed = authenticator_data + hashlib.sha256(client_data).digest()
        signature = self.private_key.sign(
            signed, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
        )
        assertion_body = json.dumps(
            {
                "raw_id": encode_base64url(self.raw_id),
                "type": "public-key",
                "response": {
                    "client_data_json": encode_base64url(client_data),
                    "authenticator_data": encode_base64url(authenticator_data),
                    "signature": encode_base64url(signature),
                    "user_handle": None,
                },
            },
            separators=(",", ":"),
        ).encode()
        approved = self.app.handle(
            "POST",
            f"/api/v1/seals/{transaction['seal_id']}/webauthn/assertion",
            {**self.session_headers, **authorization, "Content-Type": "application/json"},
            assertion_body,
        )
        self.assertEqual(approved.status, 200, approved.body)

        bundle_response = self.app.handle(
            "GET",
            f"/api/v1/seals/{transaction['seal_id']}/bundle",
            authorization,
        )
        self.assertEqual(bundle_response.status, 200, bundle_response.body)
        self.assertNotIn(encode_base64url(self.raw_id).encode(), bundle_response.body)
        self.assertNotIn(b"credential_id", bundle_response.body)
        self.assertNotIn(b"user_handle", bundle_response.body)
        bundle_path = self.root / "public.txt.skyseal.json"
        bundle_path.write_bytes(bundle_response.body)
        genesis_path = self.root / "identity-genesis.json"
        genesis_path.write_bytes(bytes(identity["genesis_json"]))
        compact = ORCID.rsplit("/", 1)[-1]
        activation_response = self.app.handle(
            "GET", f"/api/v1/identity/{compact}/activation"
        )
        self.assertEqual(activation_response.status, 200)
        activation_path = self.root / "identity-activation.json"
        activation_path.write_bytes(activation_response.body)
        report = verify_bundle(
            hash_list, bundle_path, genesis_path, RP_ID, ORIGIN, activation_path
        )
        self.assertTrue(report["ok"])
        self.assertEqual(report["entry_count"], 1)
        with self.assertRaisesRegex(
            VerificationError, "requires an identity activation proof"
        ):
            verify_bundle(hash_list, bundle_path, genesis_path, RP_ID, ORIGIN)
        tampered = json.loads(activation_response.body)
        tampered["activation_payload"]["nonce"] = encode_base64url(bytes(32))
        tampered_path = self.root / "tampered-identity-activation.json"
        tampered_path.write_bytes(canonical_json(tampered) + b"\n")
        with self.assertRaisesRegex(VerificationError, "challenge does not match"):
            verify_identity_activation(
                genesis_path, tampered_path, RP_ID, ORIGIN
            )

    def test_registration_challenge_mismatch_is_rejected_and_consumed(self) -> None:
        options = response_json(
            self.app.handle(
                "POST", "/api/v1/webauthn/registration/options", self.session_headers
            )
        )
        bad = self.app.handle(
            "POST",
            "/api/v1/webauthn/registration/complete",
            self.session_headers,
            self.registration_body(options, challenge_override=bytes(32)),
        )
        self.assertEqual(bad.status, 400)
        retry = self.app.handle(
            "POST",
            "/api/v1/webauthn/registration/complete",
            self.session_headers,
            self.registration_body(options),
        )
        self.assertEqual(retry.status, 400)
        self.assertIn("already used", response_json(retry)["message"])

    def test_csrf_is_required_for_registration_options(self) -> None:
        response = self.app.handle(
            "POST",
            "/api/v1/webauthn/registration/options",
            {"Cookie": f"skyseal_session={self.session_token}"},
        )
        self.assertEqual(response.status, 401)

    def test_pwa_shell_has_security_headers_and_external_script(self) -> None:
        response = self.app.handle("GET", "/")
        self.assertEqual(response.status, 200)
        headers = dict(response.headers)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn(b'<script src="/app.js" defer></script>', response.body)
        self.assertNotIn(b"<script>", response.body)

    def test_drive_agent_creates_identity_inbox_transaction_without_public_source_metadata(self) -> None:
        self.enroll()
        self.activate_with_passkey()
        agent_token = self.app.store.create_agent_token(ORCID)
        subject_digest = hashlib.sha256(b"private strict hash list\n").hexdigest()
        created = self.app.handle(
            "POST",
            "/api/v1/seals",
            {
                "Authorization": f"SkySeal-Agent {agent_token}",
                "Content-Type": "application/json",
            },
            json.dumps(
                {
                    "commitment_format": "skyseal-sha256-set-v1",
                    "subject_digest": subject_digest,
                    "entry_count": 3,
                },
                separators=(",", ":"),
            ).encode(),
        )
        self.assertEqual(created.status, 201, created.body)
        transaction = response_json(created)
        self.assertEqual(transaction["delivery"], "identity_inbox")
        self.assertEqual(transaction["approval_url"], ORIGIN + "/")
        self.assertNotIn("#", transaction["approval_url"])

        pending = self.app.handle("GET", "/api/v1/seals/pending", self.session_headers)
        self.assertEqual(pending.status, 200, pending.body)
        pending_object = response_json(pending)
        self.assertEqual(
            pending_object["seals"],
            [
                {
                    "seal_id": transaction["seal_id"],
                    "entry_count": 3,
                    "status": "pending",
                    "created_at": pending_object["seals"][0]["created_at"],
                    "expires_at": transaction["expires_at"],
                }
            ],
        )
        other_orcid = "https://orcid.org/0000-0002-1825-0097"
        self.app.store.upsert_user(other_orcid, "Other Researcher")
        other_token, other_csrf = self.app.store.create_session(other_orcid, 3600)
        other_headers = {
            "Cookie": f"skyseal_session={other_token}",
            "X-SkySeal-CSRF": other_csrf,
        }
        other_pending = response_json(
            self.app.handle("GET", "/api/v1/seals/pending", other_headers)
        )
        self.assertEqual(other_pending["seals"], [])
        denied = self.app.handle(
            "POST",
            f"/api/v1/seals/{transaction['seal_id']}/webauthn/options",
            other_headers,
        )
        self.assertEqual(denied.status, 401)
        options = self.app.handle(
            "POST",
            f"/api/v1/seals/{transaction['seal_id']}/webauthn/options",
            self.session_headers,
        )
        self.assertEqual(options.status, 200, options.body)
        assertion_options = response_json(options)
        challenge = decode_base64url(
            assertion_options["publicKey"]["challenge"], "challenge"
        )
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": encode_base64url(challenge),
                "origin": ORIGIN,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()
        authenticator_data = (
            hashlib.sha256(RP_ID.encode()).digest()
            + bytes([0x05])
            + (0).to_bytes(4, "big")
        )
        signature_bytes = self.private_key.sign(
            authenticator_data + hashlib.sha256(client_data).digest(),
            ec.ECDSA(hashes.SHA256(), deterministic_signing=True),
        )
        assertion = json.dumps(
            {
                "raw_id": encode_base64url(self.raw_id),
                "type": "public-key",
                "response": {
                    "client_data_json": encode_base64url(client_data),
                    "authenticator_data": encode_base64url(authenticator_data),
                    "signature": encode_base64url(signature_bytes),
                    "user_handle": None,
                },
            },
            separators=(",", ":"),
        ).encode()
        approved = self.app.handle(
            "POST",
            f"/api/v1/seals/{transaction['seal_id']}/webauthn/assertion",
            {**self.session_headers, "Content-Type": "application/json"},
            assertion,
        )
        self.assertEqual(approved.status, 200, approved.body)
        finished_pending = response_json(
            self.app.handle("GET", "/api/v1/seals/pending", self.session_headers)
        )
        self.assertEqual(finished_pending["seals"], [])
        agent_bundle = self.app.handle(
            "GET",
            f"/api/v1/seals/{transaction['seal_id']}/bundle",
            {"Authorization": f"Bearer {transaction['bearer_token']}"},
        )
        self.assertEqual(agent_bundle.status, 200, agent_bundle.body)
        self.assertNotIn(b"drive", agent_bundle.body.lower())

        compact = ORCID.rsplit("/", 1)[-1]
        activation = self.app.handle(
            "GET", f"/api/v1/identity/{compact}/activation"
        )
        self.assertEqual(activation.status, 200)
        self.assertIn(b"identity-activation:v1", activation.body)

        with self.app.store.connect() as connection:
            seal = connection.execute(
                "SELECT * FROM seals WHERE seal_id = ?", (transaction["seal_id"],)
            ).fetchone()
            agent = connection.execute("SELECT * FROM agent_tokens").fetchone()
        self.assertEqual(seal["source"], "drive_agent")
        self.assertEqual(seal["identity_id"], ORCID)
        self.assertNotEqual(agent["token_hash"], agent_token)

    def test_legacy_openpgp_identity_can_migrate_but_cannot_issue_agent_token_first(
        self,
    ) -> None:
        self.enroll()
        self.app.store.activate_identity(ORCID, b"legacy draft signature")
        me = response_json(self.app.handle("GET", "/api/v1/me", self.session_headers))
        self.assertEqual(me["identity_status"], "pending_activation")
        self.assertTrue(me["can_activate_identity"])
        with self.assertRaisesRegex(ValueError, "ORCID-and-Passkey"):
            self.app.store.create_agent_token(ORCID)
        self.activate_with_passkey()
        migrated = self.app.store.get_identity(ORCID)
        self.assertEqual(migrated["activation_method"], "webauthn_v1")
        self.assertTrue(self.app.store.create_agent_token(ORCID))

    def test_production_pending_identity_cannot_approve(self) -> None:
        production_config = Config(
            origin=ORIGIN,
            rp_id=RP_ID,
            database_path=self.root / "production.sqlite3",
            orcid_client_id="APP-TEST",
            orcid_client_secret="secret",
            orcid_redirect_uri=f"{ORIGIN}/api/v1/orcid/callback",
            allow_unsealed_identity=False,
        )
        app = Application(production_config)
        user = app.store.upsert_user(ORCID, "Researcher")
        token, csrf = app.store.create_session(ORCID, 3600)
        headers = {"Cookie": f"skyseal_session={token}", "X-SkySeal-CSRF": csrf}
        # Reuse a verified enrollment by copying only through normal application flow.
        original_app = self.app
        self.app = app
        self.session_headers = headers
        self.user_handle = bytes(user["user_handle"])
        self.enroll()
        created = response_json(
            app.handle(
                "POST",
                "/api/v1/seals",
                {},
                json.dumps(
                    {
                        "commitment_format": "skyseal-sha256-set-v1",
                        "subject_digest": "0" * 64,
                        "entry_count": 1,
                    }
                ).encode(),
            )
        )
        response = app.handle(
            "POST",
            f"/api/v1/seals/{created['seal_id']}/webauthn/options",
            {**headers, "Authorization": f"Bearer {created['bearer_token']}"},
        )
        self.assertEqual(response.status, 409)
        self.assertEqual(response_json(response)["error"], "identity_pending_activation")
        activated_identity = self.activate_with_passkey()
        self.assertEqual(activated_identity["identity_status"], "active")
        compact = ORCID.rsplit("/", 1)[-1]
        activation = app.handle("GET", f"/api/v1/identity/{compact}/activation")
        self.assertEqual(activation.status, 200, activation.body)
        genesis = app.handle("GET", f"/api/v1/identity/{compact}/genesis")
        genesis_path = self.root / "activation-genesis.json"
        activation_path = self.root / "identity-activation.json"
        genesis_path.write_bytes(genesis.body)
        activation_path.write_bytes(activation.body)
        report = verify_identity_activation(
            genesis_path, activation_path, RP_ID, ORIGIN
        )
        self.assertTrue(report["user_verified"])
        activated = app.handle(
            "POST",
            f"/api/v1/seals/{created['seal_id']}/webauthn/options",
            {**headers, "Authorization": f"Bearer {created['bearer_token']}"},
        )
        self.assertEqual(activated.status, 200, activated.body)
        self.app = original_app


class ORCIDFlowTests(unittest.TestCase):
    def test_state_cookie_database_and_code_exchange_are_all_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Config(
                origin=ORIGIN,
                rp_id=RP_ID,
                database_path=Path(directory) / "oauth.sqlite3",
                orcid_client_id="APP-TEST",
                orcid_client_secret="secret",
                orcid_redirect_uri=f"{ORIGIN}/api/v1/orcid/callback",
            )
            calls = []

            def exchange(**kwargs):
                calls.append(kwargs)
                return AuthenticatedORCID(ORCID, "OAuth Researcher")

            app = Application(config, orcid_exchange=exchange)
            started = app.handle("GET", "/api/v1/orcid/start")
            self.assertEqual(started.status, 302)
            headers = dict(started.headers)
            location = headers["Location"]
            state = parse_qs(urlsplit(location).query)["state"][0]
            state_cookie = next(
                value for key, value in started.headers if key == "Set-Cookie" and value.startswith("skyseal_oauth_state=")
            )
            callback_cookie = state_cookie.split(";", 1)[0]
            completed = app.handle(
                "GET",
                f"/api/v1/orcid/callback?state={state}&code=one-use-code",
                {"Cookie": callback_cookie},
            )
            self.assertEqual(completed.status, 302, completed.body)
            self.assertEqual(len(calls), 1)
            replay = app.handle(
                "GET",
                f"/api/v1/orcid/callback?state={state}&code=replay",
                {"Cookie": callback_cookie},
            )
            self.assertEqual(replay.status, 400)


class LowLevelTests(unittest.TestCase):
    def test_cbor_rejects_indefinite_and_trailing_data(self) -> None:
        with self.assertRaises(CBORDecodeError):
            decode_one(b"\x9f\xff")
        with self.assertRaises(CBORDecodeError):
            decode_one(b"\x01\x01")

    def test_gpg_status_parser_accepts_primary_fingerprint_field(self) -> None:
        fingerprint = "85F79058BD83EB3889DEF766B065C54586067E2E"
        status = (
            "[GNUPG:] NEWSIG\n"
            "[GNUPG:] VALIDSIG 1111111111111111111111111111111111111111 "
            f"2026-08-29 0 4 0 1 10 00 {fingerprint}\n"
        ).encode()
        self.assertIn(fingerprint, valid_signature_fingerprints(status))

    def test_existing_pinned_openpgp_fixture_verifies_in_isolated_keyring(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        verify_signature(
            (repository / "20250823_0002_public.txt").read_bytes(),
            repository / "20250823_0002_public.txt.asc",
            repository / "publickey_kkagaya@mail.kitami-it.ac.jp.asc",
            "85F79058BD83EB3889DEF766B065C54586067E2E",
        )

    def test_existing_identity_table_gains_passkey_activation_columns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "legacy.sqlite3"
            with sqlite3.connect(database) as connection:
                connection.execute(
                    """
                    CREATE TABLE identities (
                        orcid TEXT PRIMARY KEY,
                        genesis_json BLOB NOT NULL,
                        genesis_digest TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (
                            status IN ('pending_openpgp', 'active')
                        ),
                        openpgp_signature BLOB,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL
                    )
                    """
                )
            store = Store(database)
            store.initialize()
            with store.connect() as connection:
                columns = {
                    row["name"]
                    for row in connection.execute("PRAGMA table_info(identities)")
                }
            self.assertTrue(
                {
                    "activation_method",
                    "activation_payload",
                    "activation_challenge",
                    "activation_expires_at",
                    "activation_proof",
                    "activation_digest",
                }.issubset(columns)
            )


if __name__ == "__main__":
    unittest.main()
