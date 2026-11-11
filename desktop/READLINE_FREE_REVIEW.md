# SkySeal Desktop 0.3.1 — Readline-free experimental revision

This review build derives from Desktop 0.3.0 commit
8afc7a67d1d52f7b662cbabc97f7df842e66a0f5. It excludes the optional Python
readline extension during PyInstaller analysis, and checks both the final
CArchive and PYZ membership. Original 0.3.0 archives remain unchanged.

The ordinary GUI, JSON engine API, timestamping, sealing and evidence workflow
do not offer an interactive Python command-line editor. Standard-library
optional imports may still refer to readline; their ImportError fallbacks apply.

## Licensing status

MIT is the intended policy for original code, subject to confirmation of rights
with the university. This revision does not apply an MIT license, establish a
copyright owner, or grant new rights to original code. Third-party licenses
remain applicable to their respective components. Documents, images, archived
evidence and third-party code are separate categories. Legal compliance review
and corresponding-source completeness remain pending.

## Rebuild with a modified library

Use Ubuntu 22.04 x86_64, Python 3.12, Node 22 and the native dependencies listed
in .github/workflows/desktop-linux.yml. Create desktop/.venv, install
desktop/requirements-build.txt, and save `pip freeze --all`.
Install your modified, API-compatible OpenTimestamps/python-bitcoinlib source
with `desktop/.venv/bin/python -m pip install --no-deps --force-reinstall PATH`.
Verify its source path and hash, then build with:

```
SKYSEAL_SKIP_DEPENDENCY_INSTALL=1 bash desktop/scripts/build-linux.sh
```

The flag preserves your installed libraries. The ordinary default continues to
install declared dependencies. Retain the diagnostic dependency list, source
changes, all third-party notices, and the test results alongside the rebuilt
package. This procedure needs separate validation using an actually modified
LGPL library before it is represented as a completed relinking demonstration.

CI tests use temporary test profiles and keys. Offline timestamp and workflow
tests do not establish production ORCID authentication or Bitcoin confirmation.
