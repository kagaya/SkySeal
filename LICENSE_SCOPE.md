# SkySeal software license scope

Effective licensing update: 2026-11-11. The MIT license in LICENSE is applied by Katsushi Kagaya to his original SkySeal software. This is a software license grant, not a statement that every item in this repository or every component of a binary package has the same license.

## Original software covered by MIT

To the extent they are original SkySeal software, this covers the executable source, build and test configuration, and software test data in desktop/, service/, verifier/, cli/, drive_agent/, tools/, deploy/, .github/, and spec/schemas/ and spec/test-vectors/. It also covers the original root scripts make_public_hashlist.sh, make_public_hashlist_v1.sh and sign_and_stamp.sh. Necessary original build instructions and library-replacement instructions shipped with this software source are included as associated documentation. Paths not present in a particular branch are not created by this license notice.

You may use, modify, commercially use and redistribute that original software under MIT. You may modify the LGPL libraries used by SkySeal, recombine the application with compatible modified versions, and reverse engineer the resulting work for debugging those modifications. No additional SkySeal term is imposed to prohibit those activities. Third-party component licenses still govern their own material.

## Exclusions and retained third-party terms

- Third-party source, libraries, vendored code, frozen runtimes, CA certificates, and files under compliance/licenses/, compliance/extracted_notices/ and compliance/sources/ retain their upstream licenses and notices. A root MIT file does not relicense them.
- Microsoft-derived WebAuthn declarations identified in desktop/engine/windows_auth.py retain Microsoft's own MIT copyright/permission text. SkySeal's copyright notice does not replace Microsoft's notice.
- Photos, satellite/weather images, application icons and other image/artwork assets are not licensed by this software MIT grant merely because they are stored beside code. Any separate permission or service terms remain applicable.
- Historical signed hash lists, detached signatures, timestamps, public-key material, archived evidence, scientific reports, papers and non-build manuals are outside this grant. Their existing terms and byte identity are not changed. Copies retained solely as regression fixtures are not relicensed by being placed in a test archive.
- An executable/installer contains separately licensed components. In particular LGPL/GPL obligations and proprietary Microsoft runtime terms are not replaced by MIT. See THIRD_PARTY_NOTICES.md and the distribution license/source supplement.

## Package status

The original 0.3.0 archives remain unchanged. Licensing/source supplements are separately versioned. The Linux 0.3.1 Readline-free build and later notice-only repacks are development/review builds, not a declaration of complete legal compliance, native acceptance, signing/notarization or security readiness. Source availability and notice completeness must be evaluated for the actual binary and target platform.

The application author has selected MIT for his original software. This notice does not purport to decide third-party or institutional ownership outside the rights he can grant.
