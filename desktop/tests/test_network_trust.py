import os
from pathlib import Path
import shutil
import ssl
import sys
import tempfile
import unittest
from unittest.mock import patch

import certifi

from desktop.engine import network_trust


class FrozenUnixTrustTests(unittest.TestCase):
    def test_relocated_frozen_bundle_loads_its_own_public_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary).resolve()
            certificate = bundle / "certifi" / "cacert.pem"
            certificate.parent.mkdir()
            shutil.copyfile(certifi.where(), certificate)
            for platform in ("darwin", "linux"):
                with self.subTest(platform=platform), patch.object(sys, "platform", platform), \
                        patch.object(sys, "frozen", True, create=True), \
                        patch.object(sys, "_MEIPASS", str(bundle), create=True), \
                        patch.object(certifi, "where", return_value=str(certificate)), \
                        patch.dict(os.environ, {}, clear=True):
                    result = network_trust.self_test()
                    self.assertTrue(result["bundled_public_roots"])
                    self.assertGreater(result["ca_count"], 0)
                    self.assertFalse(result["network_used"])
                    self.assertEqual(os.environ["SSL_CERT_FILE"], str(certificate))
                    self.assertEqual(ssl.create_default_context().verify_mode, ssl.CERT_REQUIRED)

    def test_frozen_runtime_rejects_certificate_path_outside_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            for platform in ("darwin", "linux"):
                with self.subTest(platform=platform), patch.object(sys, "platform", platform), \
                        patch.object(sys, "frozen", True, create=True), \
                        patch.object(sys, "_MEIPASS", temporary, create=True), patch.dict(os.environ, {}, clear=True):
                    with self.assertRaises(network_trust.NetworkTrustError):
                        network_trust.initialize_https_trust()

    def test_explicit_ca_configuration_is_preserved(self):
        for platform in ("darwin", "linux"):
            with self.subTest(platform=platform), patch.object(sys, "platform", platform), \
                    patch.object(sys, "frozen", True, create=True), \
                    patch.dict(os.environ, {"SSL_CERT_FILE": certifi.where()}, clear=True):
                before = os.environ["SSL_CERT_FILE"]
                result = network_trust.initialize_https_trust()
                self.assertEqual(result["source"], "explicit-ca-file")
                self.assertFalse(result["bundled_public_roots"])
                self.assertEqual(os.environ["SSL_CERT_FILE"], before)

    def test_missing_explicit_ca_file_is_not_silently_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = str(Path(temporary) / "missing.pem")
            for platform in ("darwin", "linux"):
                with self.subTest(platform=platform), patch.object(sys, "platform", platform), \
                        patch.object(sys, "frozen", True, create=True), \
                        patch.dict(os.environ, {"SSL_CERT_FILE": missing}, clear=True):
                    with self.assertRaises(network_trust.NetworkTrustError):
                        network_trust.initialize_https_trust()

    def test_windows_keeps_native_default_certificate_loading(self):
        with patch.object(sys, "platform", "win32"), patch.object(sys, "frozen", True, create=True), \
                patch.dict(os.environ, {}, clear=True):
            self.assertEqual(network_trust.initialize_https_trust()["source"], "platform-default")
            self.assertNotIn("SSL_CERT_FILE", os.environ)


if __name__ == "__main__":
    unittest.main()
