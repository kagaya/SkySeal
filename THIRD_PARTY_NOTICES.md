# SkySeal third-party software notices

Original SkySeal software is MIT-licensed by Katsushi Kagaya. The scope and exclusions are in LICENSE_SCOPE.md. Third-party copyrights and licenses remain in force; the application, frozen runtime and installer are not collectively relicensed to MIT.

This summary describes the Desktop 0.3.0 Windows/macOS/Linux distributions and the separate Linux 0.3.1 Readline-free review build. A feature-branch component is not necessarily built by this branch. Full component inventories, retained upstream notices and source-provision records must be used for the actual package; this page is not a certification of complete compliance.

- OpenTimestamps 0.4.5 and python-bitcoinlib 0.12.2: LGPL-3.0-or-later. See LICENSES/LGPL-3.0.txt and LICENSES/GPL-3.0.txt. The corresponding library source must be provided together with the required application/build material and permissions for recombination. LICENSE_SCOPE.md expressly permits compatible library modification/recombination and reverse engineering to debug those modifications.
- cryptography 46.0.7: Apache-2.0 OR BSD-3-Clause. Its wheel also contains native Rust/OpenSSL components with additional upstream notices. This pin is under security review, not a recommended current deployment version.
- certifi 2026.10.23: MPL-2.0, including Mozilla-derived CA material. Covered source and original notices must remain available.
- CFFI 2.1.1, pycparser 3.12, packaging 26.3, PyCryptodomex 3.24.2 and setuptools 84.2.1/vendored modules: component-specific MIT-0, BSD, Apache, public-domain and other retained upstream terms. Do not reduce all embedded files to a single license.
- CPython and PyInstaller: Python's full license/notice stack and PyInstaller's GPL license with its bootloader exception apply to their respective components. That exception does not waive other libraries' obligations.
- Microsoft-derived WebAuthn declarations in desktop/engine/windows_auth.py: Microsoft's MIT notice is reproduced in LICENSES/Microsoft-WebAuthn-MIT.txt and remains separate from SkySeal's copyright.
- Linux 0.3.0 only: the frozen engine contains GNU Readline 8.1.2-1 and libtinfo. GNU Readline is GPL-3.0-or-later. Linux 0.3.1 excludes the Readline extension, library and libtinfo; this later build does not retroactively alter the old archive or settle old distribution obligations.
- Linux native libraries: component-specific Ubuntu notices for libffi, bzip2, libgcc/GCC Runtime Library Exception, XZ/liblzma, SQLite, OpenSSL, libuuid and zlib remain applicable. OS-provided GTK/WebKit/Pinentry dependencies are separate from files bundled inside the frozen executable.
- Rust/Tauri GUI, Rust standard-library and statically linked dependencies: their own upstream notices apply. Cargo.lock is an overinclusive dependency candidate list, not proof that every listed crate ships.
- Windows CRT/UCRT: Microsoft's separate redistribution conditions apply; Microsoft's WebAuthn MIT notice does not cover these DLLs. Exact runtime provenance/redistribution entitlement remains to be confirmed.
- NSIS 3.13 and its plugins: their respective zlib, bzip2, CPL, MIT/Apache and other component conditions apply. Tauri's declared nsis_tauri_utils version is 0.5.3. Exact actual plugin/build mapping remains under review.

## Source and full-text locations

The existing binary distribution and original 0.3.0 repository snapshot are at:
https://drive.google.com/drive/folders/1FUuhgza6XHgoHedITdHc_YLIN8H-n-Io

The application source corresponding to original Linux 0.3.0 is commit 8afc7a67d1d52f7b662cbabc97f7df842e66a0f5; the Readline-free review engine was built from the same tree as commit e3141d12fcb3d51297c92df83ec08af9903f598f. Later license-only notices do not change those executable bytes.

Fixed LGPL library sources:
- https://files.pythonhosted.org/packages/fb/2a/5f19420091d137e5a4c49cbe3de1964a3741d3264bad5e0a528e54aaef15/opentimestamps-0.4.5.tar.gz
  SHA-256: 56726ccde97fb67f336a7f237ce36808e5593c3089d68d900b1c83d0ebf9dcfa
- https://files.pythonhosted.org/packages/90/a1/ca9d770094a0bfd0f2ce66b7180f0a7729b1b646d90f37f6debf38b28fab/python-bitcoinlib-0.12.2.tar.gz
  SHA-256: c65ab61427c77c38d397bfc431f71d86fd355b453a536496ec3fcb41bd10087d

These references aid access but do not by themselves establish complete corresponding-source delivery, native build provenance or a fulfilled written source offer. All nine retained upstream source companions have now been published and hash/permission verified in the existing source folder. PUBLIC_SOURCE_INDEX.json provides their exact URLs and hashes; the finishing application source ZIP is supplied alongside them. This publication does not resolve the remaining native-provenance/source-completeness questions. No new written source-offer commitment is made here.

See DISTRIBUTION_STATUS.md for known remaining work. Preserve upstream full copyright, permission and disclaimer texts when redistributing the actual packages.
