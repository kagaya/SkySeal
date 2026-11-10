#!/usr/bin/env bash
# Native macOS build. Intel and Apple Silicon are built/tested on separate hosts.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  printf '%s\n' 'Build this package on macOS with Xcode command-line tools.' >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/../.." && pwd -P)"
desktop_root="$repo_root/desktop"
native_arch="$(uname -m)"
case "$native_arch" in
  x86_64) rust_target=x86_64-apple-darwin; distribution_arch=Intel ;;
  arm64) rust_target=aarch64-apple-darwin; distribution_arch=AppleSilicon ;;
  *) printf 'Unsupported native architecture: %s\n' "$native_arch" >&2; exit 1 ;;
esac
if [[ -n "${SKYSEAL_EXPECTED_ARCH:-}" && "$native_arch" != "$SKYSEAL_EXPECTED_ARCH" ]]; then
  printf 'Expected native %s runner, found %s\n' "$SKYSEAL_EXPECTED_ARCH" "$native_arch" >&2
  exit 1
fi

export MACOSX_DEPLOYMENT_TARGET=12.0
export PYTHONUTF8=1
build_root="$desktop_root/.build/macos-$rust_target"
binary_root="$desktop_root/src-tauri/binaries"
diagnostic_root="$build_root/diagnostics"
distribution_root="$build_root/dist"
mkdir -p "$binary_root" "$diagnostic_root" "$distribution_root"

cd "$repo_root"
python3 -m venv "$desktop_root/.venv"
python_exe="$desktop_root/.venv/bin/python"
"$python_exe" -c 'import platform,sys; assert sys.version_info >= (3,12), "Python 3.12+ required"; assert platform.machine() == sys.argv[1], "Python and runner architectures differ"' "$native_arch"
# macOS /var is a system symlink. Keep security-sensitive source/snapshot paths
# physical without weakening the engine's rejection of user-selected links.
export TMPDIR="$("$python_exe" -c 'import pathlib,tempfile; print(pathlib.Path(tempfile.gettempdir()).resolve())')"
export SKYSEAL_TEST_PYTHON="$python_exe"
"$python_exe" -m pip install -r "$desktop_root/requirements-build.txt"

signer="$binary_root/macos-signer-$rust_target"
xcrun swiftc -O -target "$native_arch-apple-macos12.0" \
  -sdk "$(xcrun --sdk macosx --show-sdk-path)" \
  -framework Foundation -framework Security \
  "$desktop_root/native/macos/SkySealSigner.swift" -o "$signer"
codesign --force --sign - --identifier net.excyberlab.skyseal.desktop.signer "$signer"
"$signer" --self-test > "$diagnostic_root/native-signer-self-test.json"
"$python_exe" - "$diagnostic_root/native-signer-self-test.json" <<'PY'
import json,sys
result=json.load(open(sys.argv[1]))
assert all(result.get(key) is True for key in ('ok','acl_policy_checked','permissive_acl_rejected','signature_roundtrip','changed_challenge_rejected'))
assert result.get('persistent_keys_created') is False and result.get('user_approval_tested') is False
PY

# This separate executable contains test-only entry points. It is never bundled
# or distributed; its isolated temporary keychain tests enforced denial when UI
# is disabled in a fresh process, without changing the user's login keychain.
policy_probe="$build_root/macos-signer-policy-test"
xcrun swiftc -O -D SKYSEAL_NATIVE_TESTS -target "$native_arch-apple-macos12.0" \
  -sdk "$(xcrun --sdk macosx --show-sdk-path)" \
  -framework Foundation -framework Security \
  "$desktop_root/native/macos/SkySealSigner.swift" -o "$policy_probe"
codesign --force --sign - --identifier net.excyberlab.skyseal.desktop.signer-policy-test "$policy_probe"
"$python_exe" - "$policy_probe" "$diagnostic_root/keychain-policy-self-test.json" <<'PY'
import json,pathlib,subprocess,sys
result=subprocess.run([sys.argv[1],'--keychain-policy-self-test'],capture_output=True,text=True,encoding='utf-8',timeout=90,check=True)
payload=json.loads(result.stdout)
pathlib.Path(sys.argv[2]).write_text(json.dumps(payload,indent=2)+'\n',encoding='utf-8')
assert payload.get('ok') is True
PY

"$python_exe" -m unittest discover -s desktop/tests -v
"$python_exe" -m PyInstaller --clean --noconfirm --onefile --console \
  --name "desktop-engine-$rust_target" \
  --distpath "$binary_root" --workpath "$build_root/pyinstaller" \
  --specpath "$build_root" --paths "$repo_root" \
  --target-arch "$native_arch" --codesign-identity - \
  --hidden-import opentimestamps.core.timestamp \
  --hidden-import opentimestamps.core.notary \
  --hidden-import opentimestamps.core.op \
  --hidden-import opentimestamps.core.serialize \
  --hidden-import bitcoin.core \
  --exclude-module otsclient --exclude-module bitcoin.wallet \
  --exclude-module bitcoin.rpc --exclude-module bitcoin.core.key \
  --exclude-module opentimestamps.core.git \
  --copy-metadata opentimestamps --copy-metadata python-bitcoinlib \
  --copy-metadata cryptography --collect-data certifi "$script_dir/engine_entry.py"
"$python_exe" "$script_dir/smoke_engine.py" "$binary_root/desktop-engine-$rust_target"
env -u SSL_CERT_FILE "$binary_root/desktop-engine-$rust_target" --tls-self-test > "$diagnostic_root/public-tls-self-test.json"
"$python_exe" - "$diagnostic_root/public-tls-self-test.json" <<'PY'
import json,sys
result=json.load(open(sys.argv[1]))
assert result.get('ok') is True and result.get('bundled_public_roots') is True
assert result.get('ca_count',0)>0 and result.get('network_used') is False
PY

cd "$desktop_root"
npm ci
npm run check
npm test
npm run build -- --target "$rust_target" --bundles app

app="$desktop_root/src-tauri/target/$rust_target/release/bundle/macos/SkySeal.app"
test -d "$app"
test -x "$app/Contents/MacOS/desktop-engine"
test -x "$app/Contents/MacOS/macos-signer"
codesign --verify --deep --strict --verbose=2 "$app"
codesign --display --verbose=4 "$app" 2> "$diagnostic_root/app-signature.txt"
"$python_exe" "$script_dir/audit-macos-runtime.py" \
  --app "$app" --architecture "$native_arch" --minimum 12.0 \
  --output "$diagnostic_root/runtime-audit.json"
"$python_exe" "$script_dir/smoke-installed-macos.py" "$app" \
  --diagnostics "$diagnostic_root/installed-smoke"

version="$("$python_exe" -c 'import json; print(json.load(open("src-tauri/tauri.conf.json"))["version"])')"
artifact_base="SkySeal_${version}_macOS_${distribution_arch}_development"
ditto -c -k --sequesterRsrc --keepParent "$app" "$distribution_root/$artifact_base.app.zip"
# A simple native disk image avoids an AppleScript/Finder dependency in CI.
# The /Applications alias gives the usual drag-to-install interface.
image_stage="$(mktemp -d "$build_root/dmg-content.XXXXXX")"
trap 'rm -rf -- "$image_stage"' EXIT
ditto "$app" "$image_stage/SkySeal.app"
ln -sfn /Applications "$image_stage/Applications"
hdiutil create -ov -fs HFS+ -volname SkySeal -format UDZO \
  -srcfolder "$image_stage" "$distribution_root/$artifact_base.dmg"
cp "$desktop_root/README.macos.ja.md" "$distribution_root/README.macos.ja.md"
"$python_exe" - "$distribution_root" "$rust_target" "$diagnostic_root/runtime-audit.json" "$artifact_base" <<'PY'
import hashlib,json,pathlib,platform,subprocess,sys
root=pathlib.Path(sys.argv[1])
files=[root/(sys.argv[4]+'.app.zip'),root/(sys.argv[4]+'.dmg')]
assert all(path.is_file() for path in files)
(root/'SHA256SUMS.txt').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files),encoding='utf-8')
report={
 'target':sys.argv[2], 'native_architecture':platform.machine(),
 'minimum_macos':'12.0', 'tested_macos':platform.mac_ver()[0],
 'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
 'signature':'ad-hoc', 'developer_id_signed':False, 'notarized':False,
 'runtime_audit':json.loads(pathlib.Path(sys.argv[3]).read_text()),
 'local_package_smoke':'passed',
 'production_orcid_and_keychain_password_acceptance':'not_tested'
}
(root/'BUILD_INFO.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
PY
printf 'macOS %s development packages: %s\n' "$distribution_arch" "$distribution_root"
printf '%s\n' 'Ad-hoc signed; not Developer ID signed or notarized. Actual ORCID and Keychain approval acceptance remains separate.'
