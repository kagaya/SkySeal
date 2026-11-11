"""Real ELF fixtures for staged search-path normalization (Linux build CI only)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from linux_freezer import _dynamic, _paths, stage_binaries


class StagingChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="skyseal-elf-staging-test-")
        self.root = Path(self.temporary.name).resolve()
        self.prefix = self.root / "toolcache-python"
        self.prefix.mkdir()
        self.c = self.root / "fixture.c"
        self.c.write_text("int skyseal_fixture(void) { return 42; }\n")

    def tearDown(self):
        self.temporary.cleanup()

    def binary(self, rpath, *, old_tag=False):
        path = self.prefix / "fixture.so"
        command = ["cc", "-shared", "-fPIC", str(self.c), "-o", str(path)]
        if old_tag:
            command.append("-Wl,--disable-new-dtags")
        if rpath is not None:
            command.append("-Wl,-rpath," + rpath)
        subprocess.run(command, check=True, capture_output=True)
        return path

    def stage(self, binary):
        return stage_binaries([("fixture.so", str(binary), "BINARY")],
                              self.root / "staged", (self.prefix,), self.root / "report.json")

    def test_removes_only_build_path_and_preserves_both_tag_kinds(self):
        for old_tag in (False, True):
            with self.subTest(old_tag=old_tag):
                binary = self.binary(str(self.prefix / "lib") + ":$ORIGIN/private:/usr/lib", old_tag=old_tag)
                before = hashlib.sha256(binary.read_bytes()).hexdigest()
                destination, staged, kind = self.stage(binary)[0]
                self.assertEqual((destination, kind), ("fixture.so", "BINARY"))
                self.assertNotEqual(Path(staged), binary)
                self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), before)
                self.assertEqual(_paths(_dynamic(Path(staged))),
                                 [("RPATH" if old_tag else "RUNPATH", "$ORIGIN/private:/usr/lib")])

    def test_removes_tag_entirely_when_only_build_paths_exist(self):
        binary = self.binary(str(self.prefix / "lib"))
        self.assertEqual(_paths(_dynamic(Path(self.stage(binary)[0][1]))), [])
        self.assertTrue(json.loads((self.root / "report.json").read_text())["passed"])

    def test_keeps_portable_inputs_and_symlink_toc_unchanged(self):
        binary = self.binary("$ORIGIN")
        entries = [("fixture.so", str(binary), "BINARY"), ("alias.so", "fixture.so", "SYMLINK")]
        self.assertEqual(stage_binaries(entries, self.root / "stage", (self.prefix,),
                                        self.root / "report.json"), entries)

    def test_rejects_unknown_absolute_path_and_integrity_companion(self):
        with self.assertRaisesRegex(RuntimeError, "Unrecognized"):
            self.stage(self.binary("/unknown-host/library"))
        binary = self.binary(str(self.prefix / "lib"))
        (binary.parent / (binary.name + ".hmac")).write_text("fixture")
        with self.assertRaisesRegex(RuntimeError, "integrity-protected"):
            self.stage(binary)


if __name__ == "__main__":
    unittest.main(verbosity=2)
