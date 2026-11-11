"""Public HTTPS trust for the standalone macOS Python runtime.

CPython/OpenSSL on macOS does not read the user's Keychain trust store. A frozen
application must not depend on the build machine's CA path. Use the bundled
public CA set unless the user explicitly configured SSL_CERT_FILE. This is
separate from the browser's localhost certificate trust for ORCID callbacks.
"""
from __future__ import annotations

import os
from pathlib import Path
import ssl
import sys


class NetworkTrustError(RuntimeError):
    pass


def initialize_https_trust() -> dict:
    if sys.platform != "darwin" or not getattr(sys, "frozen", False):
        return {"source": "platform-default", "bundled_public_roots": False}
    configured = os.environ.get("SSL_CERT_FILE")
    if configured:
        path = Path(configured)
        if not path.is_file():
            raise NetworkTrustError("The configured HTTPS CA file is missing")
        # Preserve an explicit managed/local trust configuration. It remains a
        # caller-supplied trust decision and is not labelled as bundled roots.
        return {"source": "explicit-ca-file", "bundled_public_roots": False}
    import certifi
    path = Path(certifi.where()).resolve()
    bundle_root = getattr(sys, "_MEIPASS", None)
    if not bundle_root or not path.is_relative_to(Path(bundle_root).resolve()) or not path.is_file():
        raise NetworkTrustError("Bundled HTTPS certificates are missing. Reinstall SkySeal.")
    context = ssl.create_default_context(cafile=str(path))
    if context.cert_store_stats().get("x509_ca", 0) < 1:
        raise NetworkTrustError("The bundled HTTPS certificate store is empty")
    os.environ["SSL_CERT_FILE"] = str(path)
    return {"source": "bundled-public-cas", "bundled_public_roots": True}


def self_test() -> dict:
    trust = initialize_https_trust()
    context = ssl.create_default_context()
    count = context.cert_store_stats().get("x509_ca", 0)
    if count < 1:
        raise NetworkTrustError("No public HTTPS certificate authorities are available")
    return {"ok": True, **trust, "ca_count": count, "network_used": False}
