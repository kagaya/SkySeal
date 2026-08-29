from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from cli.skyseal_pc import ClientError, validate_server
from service.app import Application, RequestHandler
from service.config import Config


REPOSITORY = Path(__file__).resolve().parents[2]
CLI = REPOSITORY / "cli" / "skyseal_pc.py"


class QuietHandler(RequestHandler):
    def log_message(self, format_string: str, *args: object) -> None:
        pass


class PCClientTests(unittest.TestCase):
    def test_server_origin_rejects_paths_and_credentials(self) -> None:
        with self.assertRaises(ClientError):
            validate_server("https://seal.example.org/api")
        with self.assertRaises(ClientError):
            validate_server("https://user:secret@seal.example.org")
        self.assertEqual(validate_server("https://seal.example.org/"), "https://seal.example.org")

    def test_create_sends_only_commitment_and_writes_mode_600_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
            origin = f"http://localhost:{server.server_port}"
            config = Config(
                origin=origin,
                rp_id="localhost",
                database_path=root / "server.sqlite3",
                bind_host="127.0.0.1",
                bind_port=server.server_port,
                allow_http_localhost=True,
                allow_mock_orcid=True,
                allow_unsealed_identity=True,
            )
            application = Application(config)
            server.application = application  # type: ignore[attr-defined]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                secret_name = "revealing-research-name.bin"
                digest = hashlib.sha256(b"private fixture bytes").hexdigest()
                hash_list = root / secret_name
                hash_list.write_text(digest + "\n", encoding="ascii", newline="\n")
                state_path = root / "private.pending.json"
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(CLI),
                        "create",
                        str(hash_list),
                        "--server",
                        origin,
                        "--rp-id",
                        "localhost",
                        "--state",
                        str(state_path),
                    ],
                    cwd=REPOSITORY,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(os.stat(state_path).st_mode & 0o777, 0o600)
                state = json.loads(state_path.read_text())
                with application.store.connect() as connection:
                    seal = connection.execute(
                        "SELECT * FROM seals WHERE seal_id = ?", (state["seal_id"],)
                    ).fetchone()
                self.assertEqual(seal["subject_digest"], hashlib.sha256(hash_list.read_bytes()).hexdigest())
                self.assertNotIn(secret_name, json.dumps(dict(seal)))
                self.assertNotIn(str(hash_list), json.dumps(dict(seal)))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
