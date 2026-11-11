# SkySeal Desktop 0.3.1 — Readline-free experimental revision

This review build derives from Desktop 0.3.0 commit
8afc7a67d1d52f7b662cbabc97f7df842e66a0f5. It excludes the optional Python
readline extension during PyInstaller analysis, and checks both the final
CArchive and PYZ membership. Original 0.3.0 archives remain unchanged.

The ordinary GUI, JSON engine API, timestamping, sealing and evidence workflow
do not offer an interactive Python command-line editor. Standard-library
optional imports may still refer to readline; their ImportError fallbacks apply.

## Licensing status

MIT is now applied to original SkySeal software by Katsushi Kagaya. See the
root LICENSE and LICENSE_SCOPE.md. The finishing source supplement includes
them in its compliance directory too. Third-party
libraries retain their own terms; graphics, historical reports and archived
evidence are not automatically relicensed. Native provenance, source
completeness, dependency security and acceptance review remain separate.

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
package. An engine-level mechanical replacement demonstration passed in CI run
42958783387: inert markers added to both LGPL libraries were found in the
finished frozen engine, followed by offline smoke and TLS-root checks. This was
not a rebuild from edited sdist through a complete GUI installer. Full-package
replacement and native Windows/macOS demonstrations remain pending.

CI tests use temporary test profiles and keys. Offline timestamp and workflow
tests do not establish production ORCID authentication or Bitcoin confirmation.
