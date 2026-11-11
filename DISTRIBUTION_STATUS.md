# Distribution and licensing status — 2026-11-11

## Applied

Katsushi Kagaya has applied MIT to original SkySeal software, including commercial use, modification and redistribution. LICENSE_SCOPE.md excludes third-party material, images/artwork, historical scientific documents and archived evidence. The MIT notice is a software license grant, not blanket licensing of every file or every component of an installer.

## Existing packages are development builds

Original 0.3.0 ZIPs and sealed evidence remain unchanged. The separate Linux 0.3.1 Readline-free build has static dependency-audit and Ubuntu CI evidence, but is not a final signed/security-cleared release. A license supplement does not establish that the app is secure, every third-party condition is satisfied, or real-user identity/sealing acceptance has passed.

Remaining review includes exact native/static dependency provenance, Microsoft runtime entitlement, installer plugin mapping, full corresponding-source completeness and continuing availability, complete native library-replacement/package tests, production ORCID/native approval/GUI end-to-end acceptance, and final Bitcoin attestation verification. Do not describe offline or mocked tests as those real-user acceptance tests.

## Dependency security and platform support

The audited engines pin cryptography 46.0.7. Upstream security advisories apply to parts of that dependency stack; exploit reachability in SkySeal has not been established. Repackaging notices does not update that binary dependency.

As of this review, cryptography 50.0.2 is an isolated compatibility-test candidate, not an approved release pin. Official macOS Intel support was removed in 49.0.0, so a silent universal version bump would drop an existing target. Its OpenSSL 4.0.3 also has newly announced 2026-11-10 upstream issues requiring impact review or patched/update builds. The choices are a separately maintained/tested Intel build or deferring a new Intel package; neither choice has been made by this update.

Official upstream references:
- https://github.com/pyca/cryptography/security/advisories
- https://cryptography.io/en/latest/changelog/
- https://openssl-library.org/news/secadv/20261110.txt

## License/source supplements

THIRD_PARTY_NOTICES.md identifies major components and fixed source references. Full notice/source kits are prepared separately. Their availability is not complete until publication and recipient access have been verified. Old archives are not rewritten by this licensing update. No functionality branch is merged and no new native package is promoted to a final release by adding these notices.
