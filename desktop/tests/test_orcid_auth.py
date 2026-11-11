"""ORCID signature, callback isolation, and local TLS tests (no live login)."""

import copy
import hashlib
import http.client
import json
from pathlib import Path
import queue
import ssl
import subprocess
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from desktop.engine import orcid_auth as auth
from verifier.skyseal_verify import encode_base64url


class TokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = cls.private_key.public_key().public_numbers()
        cls.jwk = {"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig",
            "n": encode_base64url(public.n.to_bytes(256, "big")),
            "e": encode_base64url(public.e.to_bytes(3, "big"))}

    def setUp(self):
        self.now = 1_800_000_000
        self.claims = {"iss": auth.ISSUER, "sub": "0000-0003-3001-7690", "aud": "APP-TEST",
            "nonce": "key-digest-and-random-nonce", "iat": self.now - 10, "exp": self.now + 590,
            "auth_time": self.now - 12}
        self.header = {"alg": "RS256", "kid": "test-key"}

    def token(self, *, claims=None, header=None, claims_bytes=None):
        head = encode_base64url(json.dumps(self.header if header is None else header, separators=(",", ":")).encode())
        body = encode_base64url(claims_bytes if claims_bytes is not None else json.dumps(self.claims if claims is None else claims, separators=(",", ":")).encode())
        signed = (head + "." + body).encode("ascii")
        return head + "." + body + "." + encode_base64url(self.private_key.sign(signed, padding.PKCS1v15(), hashes.SHA256()))

    def verify(self, token=None, **kwargs):
        return auth.verify_id_token(self.token() if token is None else token, "APP-TEST", self.claims["nonce"],
            jwks=kwargs.pop("jwks", {"keys": [self.jwk]}), now=kwargs.pop("now", self.now), **kwargs)

    def test_valid_signature_and_orcid(self):
        self.assertEqual(self.verify(), self.claims)

    def test_payload_tampering_rejected(self):
        token = self.token().split(".")
        altered = dict(self.claims, sub="0000-0002-1825-0097")
        token[1] = encode_base64url(json.dumps(altered).encode())
        with self.assertRaisesRegex(auth.ORCIDAuthError, "signature"):
            self.verify(".".join(token))

    def test_wrong_issuer_audience_nonce_and_checksum(self):
        for field, value in [("iss", "https://attacker.invalid"), ("aud", "OTHER"),
            ("nonce", "different"), ("sub", "0000-0003-3001-7691")]:
            with self.subTest(field=field), self.assertRaises(auth.ORCIDAuthError):
                self.verify(self.token(claims=dict(self.claims, **{field: value})))

    def test_multi_audience_requires_authorized_party(self):
        claims = dict(self.claims, aud=["APP-TEST", "OTHER"])
        with self.assertRaises(auth.ORCIDAuthError):
            self.verify(self.token(claims=claims))
        claims["azp"] = "APP-TEST"
        self.assertEqual(self.verify(self.token(claims=claims))["azp"], "APP-TEST")
        claims["azp"] = "OTHER"
        with self.assertRaises(auth.ORCIDAuthError):
            self.verify(self.token(claims=claims))

    def test_current_login_rejects_expired_historical_keeps_signature_checks(self):
        token = self.token(claims=dict(self.claims, iat=self.now - 1000, exp=self.now - 400, auth_time=self.now - 1002))
        with self.assertRaisesRegex(auth.ORCIDAuthError, "expired"):
            self.verify(token)
        self.assertEqual(self.verify(token, historical=True)["exp"], self.now - 400)
        with self.assertRaisesRegex(auth.ORCIDAuthError, "unknown"):
            self.verify(token, historical=True, jwks={"keys": []})

    def test_future_bad_and_boolean_times_rejected(self):
        variants = [{"iat": self.now + 120}, {"exp": self.now - 20}, {"iat": True},
            {"auth_time": self.now + 100}, {"nbf": self.now + 120}]
        for changes in variants:
            with self.subTest(changes=changes), self.assertRaises(auth.ORCIDAuthError):
                self.verify(self.token(claims=dict(self.claims, **changes)), historical=True)

    def test_duplicate_json_member_rejected_even_if_signed(self):
        raw = json.dumps(self.claims).encode()[:-1] + b', "aud": "OTHER"}'
        with self.assertRaises(auth.ORCIDAuthError):
            self.verify(self.token(claims_bytes=raw))

    def test_alg_none_key_url_and_critical_headers_rejected(self):
        for changes in [{"alg": "none"}, {"alg": "HS256"}, {"jku": "https://attacker.invalid/jwks"}, {"crit": ["b64"]}]:
            with self.subTest(changes=changes), self.assertRaises(auth.ORCIDAuthError):
                self.verify(self.token(header=dict(self.header, **changes)))

    def test_duplicate_or_unknown_key_rejected(self):
        for keys in [[], [self.jwk, self.jwk]]:
            with self.subTest(keys=len(keys)), self.assertRaises(auth.ORCIDAuthError):
                self.verify(jwks={"keys": keys})

    def test_default_only_fetches_pinned_issuer_keys(self):
        with patch.object(auth, "fetch_jwks", return_value={"keys": [self.jwk]}) as fetch:
            claims = auth.verify_id_token(self.token(), "APP-TEST", self.claims["nonce"], now=self.now)
        self.assertEqual(claims["sub"], self.claims["sub"])
        fetch.assert_called_once_with()

    def test_authorization_url_has_exact_callback_and_no_secret(self):
        url = auth.authorization_url("APP-TEST", "nonce", "state")
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)
        self.assertEqual(parsed.netloc, "orcid.org")
        self.assertEqual(query["redirect_uri"], ["https://localhost:24731/callback"])
        self.assertEqual(query["response_type"], ["id_token token"])
        self.assertEqual(query["scope"], ["openid"])
        self.assertNotIn("client_secret", query)

    def _run_local_login(self, wrong_access_token=False):
        servers = []
        receiver_class = auth._TLSReceiver
        access_token = "transient-bearer-never-persisted"
        claims = dict(self.claims, at_hash=encode_base64url(hashlib.sha256(access_token.encode()).digest()[:16]))

        def receiver(address, handler):
            server = receiver_class(("127.0.0.1", 0), handler)
            servers.append(server)
            return server

        with tempfile.TemporaryDirectory() as directory:
            cert = auth.ensure_certificate(directory)
            def browser(url, **kwargs):
                query_values = parse_qs(urlsplit(url).query)
                self.assertEqual(query_values["nonce"], [self.claims["nonce"]])
                context = ssl.create_default_context(cafile=cert["certificate_path"])
                connection = http.client.HTTPSConnection("127.0.0.1", servers[0].server_port, context=context, timeout=3)
                body = json.dumps({"state": query_values["state"][0], "id_token": self.token(claims=claims),
                    "access_token": "injected" if wrong_access_token else access_token})
                connection.request("POST", "/complete", body=body, headers={"Host": f"localhost:{auth.CALLBACK_PORT}",
                    "Origin": auth.CALLBACK_ORIGIN, "Content-Type": "application/json"})
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                response.read()
                connection.close()
                return True

            with patch.object(auth, "_TLSReceiver", side_effect=receiver), \
                patch.object(auth.webbrowser, "open", side_effect=browser), \
                patch.object(auth, "fetch_jwks", return_value={"keys": [self.jwk]}), \
                patch.object(auth.time, "time", return_value=self.now):
                return auth.login("APP-TEST", self.claims["nonce"], directory, timeout=5)

    def test_local_https_login_checks_tokens_and_returns_no_bearer(self):
        result = self._run_local_login()
        self.assertEqual(set(result), {"id_token", "claims"})
        self.assertEqual(result["claims"]["sub"], self.claims["sub"])

    def test_implicit_access_token_substitution_rejected(self):
        with self.assertRaisesRegex(auth.ORCIDAuthError, "binding"):
            self._run_local_login(wrong_access_token=True)


class CertificateTests(unittest.TestCase):
    def test_installation_unique_leaf_and_stable_until_expiry(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            a = auth.ensure_certificate(Path(first))
            b = auth.ensure_certificate(Path(second))
            self.assertNotEqual(a["thumbprint"], b["thumbprint"])
            self.assertEqual(a["thumbprint"], auth.ensure_certificate(first)["thumbprint"])
            cert = x509.load_pem_x509_certificate(Path(a["certificate_path"]).read_bytes())
            self.assertFalse(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            self.assertEqual(list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value), [ExtendedKeyUsageOID.SERVER_AUTH])
            self.assertEqual(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName), ["localhost"])
            self.assertNotIn("trusted", a)

    def test_partial_key_is_not_silently_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "local-tls"
            directory.mkdir()
            key = directory / "localhost-key.pem"
            key.write_bytes(b"existing")
            with self.assertRaisesRegex(auth.ORCIDAuthError, "incomplete"):
                auth.ensure_certificate(temp)
            self.assertEqual(key.read_bytes(), b"existing")


class CertificateTrustTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.info = auth.ensure_certificate(self.temporary.name)
        self.keychain = str(Path.home() / "Library" / "Keychains" / "login.keychain-db")
        self.current = subprocess.CompletedProcess([], 0, stdout=json.dumps(self.keychain) + "\n")
        self.success = subprocess.CompletedProcess([], 0, stdout=b"")

    def test_macos_requires_user_ssl_localhost_trust_and_independent_verification(self):
        with patch.object(auth.sys, "platform", "darwin"), \
                patch.object(auth, "ensure_certificate", return_value=self.info), \
                patch.object(auth.subprocess, "run", side_effect=[self.current, self.success, self.success]) as run:
            result = auth.trust_certificate(self.temporary.name)
        self.assertTrue(result["trusted"])
        self.assertEqual(result["trust_scope"], "user Keychain / SSL / localhost")
        add = run.call_args_list[1].args[0]
        self.assertEqual(add[:2], ["/usr/bin/security", "add-trusted-cert"])
        self.assertNotIn("-d", add)  # No administrator trust settings.
        self.assertEqual(add[add.index("-p") + 1], "ssl")
        self.assertEqual(add[add.index("-s") + 1], "localhost")
        self.assertEqual(add[-1], self.info["certificate_der_path"])
        verify = run.call_args_list[2].args[0]
        self.assertEqual(verify[:2], ["/usr/bin/security", "verify-cert"])
        self.assertIn("-L", verify)  # Local trust evaluation, no CA downloads.
        self.assertNotIn("-r", verify)  # Never supply a root that bypasses installed trust.
        self.assertEqual(verify[verify.index("-n") + 1], "localhost")

    def test_macos_cancelled_os_authentication_does_not_report_trusted(self):
        cancelled = subprocess.CalledProcessError(128, ["security", "add-trusted-cert"])
        with patch.object(auth.sys, "platform", "darwin"), \
                patch.object(auth, "ensure_certificate", return_value=self.info), \
                patch.object(auth.subprocess, "run", side_effect=[self.current, cancelled]) as run:
            with self.assertRaises(auth.ORCIDAuthError):
                auth.trust_certificate(self.temporary.name)
        self.assertEqual(run.call_count, 2)

    def test_macos_failed_post_import_verification_does_not_report_trusted(self):
        rejected = subprocess.CalledProcessError(1, ["security", "verify-cert"])
        with patch.object(auth.sys, "platform", "darwin"), \
                patch.object(auth, "ensure_certificate", return_value=self.info), \
                patch.object(auth.subprocess, "run", side_effect=[self.current, self.success, rejected]):
            with self.assertRaises(auth.ORCIDAuthError):
                auth.trust_certificate(self.temporary.name)

    def test_macos_system_keychain_default_is_rejected_before_mutation(self):
        system = subprocess.CompletedProcess([], 0, stdout='"/Library/Keychains/System.keychain"\n')
        with patch.object(auth.sys, "platform", "darwin"), \
                patch.object(auth, "ensure_certificate", return_value=self.info), \
                patch.object(auth.subprocess, "run", return_value=system) as run:
            with self.assertRaisesRegex(auth.ORCIDAuthError, "default Keychain"):
                auth.trust_certificate(self.temporary.name)
        self.assertEqual(run.call_count, 1)

    def test_windows_still_imports_only_exact_certificate_to_current_user(self):
        with patch.object(auth.sys, "platform", "win32"), \
                patch.object(auth, "ensure_certificate", return_value=self.info), \
                patch.object(auth.subprocess, "run", return_value=self.success) as run:
            result = auth.trust_certificate(self.temporary.name)
        self.assertTrue(result["trusted"])
        call = run.call_args
        self.assertIn("CurrentUser", call.args[0][-1])
        self.assertNotIn("LocalMachine", call.args[0][-1])
        self.assertEqual(call.kwargs["env"]["SKYSEAL_LOCAL_CERTIFICATE"], self.info["certificate_der_path"])
        self.assertEqual(call.kwargs["env"]["SKYSEAL_LOCAL_THUMBPRINT"], self.info["thumbprint"])


class CallbackTests(unittest.TestCase):
    def setUp(self):
        self.results = queue.Queue(maxsize=1)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), auth._handler_type("expected-state", self.results))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, payload=None, headers=None, method="POST", path="/complete"):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        supplied = {"Host": f"localhost:{auth.CALLBACK_PORT}", "Origin": auth.CALLBACK_ORIGIN,
            "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"}
        supplied.update(headers or {})
        raw = json.dumps(payload if payload is not None else {"state": "expected-state", "id_token": "token", "access_token": "bearer"})
        connection.request(method, path, body=raw if method == "POST" else None, headers=supplied)
        response = connection.getresponse()
        data = response.read()
        result = response.status, dict(response.getheaders()), data
        connection.close()
        return result

    def test_valid_callback_is_one_shot(self):
        self.assertEqual(self.request()[0], 200)
        self.assertEqual(self.results.get_nowait()["state"], "expected-state")
        self.assertEqual(self.request()[0], 400)
        self.assertTrue(self.results.empty())

    def test_wrong_host_origin_fetchsite_and_state_rejected(self):
        for headers in [{"Host": "evil.invalid"}, {"Origin": "https://evil.invalid"}, {"Origin": "null"}, {"Sec-Fetch-Site": "cross-site"}]:
            with self.subTest(headers=headers):
                self.assertEqual(self.request(headers=headers)[0], 403)
                self.assertTrue(self.results.empty())
        self.assertEqual(self.request({"state": "wrong", "id_token": "token", "access_token": "bearer"})[0], 400)
        self.assertTrue(self.results.empty())

    def test_callback_page_cleans_fragment_and_disallows_external_scripts(self):
        status, headers, body = self.request(method="GET", path="/callback")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertIn(b"history.replaceState", body)
        self.assertNotIn(b"expected-state", body)
        self.assertEqual(self.request(method="GET", path="/callback?token=bad")[0], 404)

    def test_oversized_body_rejected(self):
        self.assertEqual(self.request({"state": "expected-state", "id_token": "x" * auth.MAX_CALLBACK_BYTES, "access_token": "bearer"})[0], 400)
        self.assertTrue(self.results.empty())


if __name__ == "__main__":
    unittest.main()
