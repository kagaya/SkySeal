#!/usr/bin/env bash
# Build on Ubuntu 22.04 x86_64; the packaged app needs no Python/Node/Rust.
set -euo pipefail

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  printf '%s\n' 'This development package targets Linux x86_64.' >&2
  exit 1
fi
if [[ "$(id -u)" == 0 ]]; then
  printf '%s\n' 'Build and run the desktop app as an ordinary user.' >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/../.." && pwd -P)"
desktop_root="$repo_root/desktop"
rust_target=x86_64-unknown-linux-gnu
build_root="$desktop_root/.build/linux-$rust_target"
binary_root="$desktop_root/src-tauri/binaries"
diagnostic_root="$build_root/diagnostics"
distribution_root="$build_root/dist"
mkdir -p "$binary_root" "$diagnostic_root" "$distribution_root"
export PYTHONUTF8=1

cd "$repo_root"
python3 -m venv "$desktop_root/.venv"
python_exe="$desktop_root/.venv/bin/python"
"$python_exe" - <<'PY'
import platform,sys
assert sys.version_info >= (3,12), 'Python 3.12+ required'
assert platform.machine() == 'x86_64', 'A native x86_64 Python is required'
libc,version=platform.libc_ver()
assert libc == 'glibc' and tuple(map(int,version.split('.'))) <= (2,35), 'Build on Ubuntu 22.04 (glibc <= 2.35) for the declared baseline'
PY
export TMPDIR="$("$python_exe" -c 'import pathlib,tempfile; print(pathlib.Path(tempfile.gettempdir()).resolve())')"
export SKYSEAL_TEST_PYTHON="$python_exe"
"$python_exe" -m pip install -r "$desktop_root/requirements-build.txt"
"$python_exe" -m unittest discover -s desktop/tests -v
"$python_exe" "$script_dir/test-linux-freezer.py"

# Exercise real native password dialogs only in an isolated CI X11 display.
# This harness is not shipped and cannot inject credentials into the app.
dbus-run-session -- xvfb-run -a -s '-screen 0 1280x900x24' \
  bash "$script_dir/linux-test-session.sh" \
  "$python_exe" "$script_dir/smoke-linux-signing.py" \
  --diagnostics "$diagnostic_root/native-signing"

# Freeze only the CI adapter harness as a separate worker. It is never copied
# into either package. This checks the real Pinentry child under PyInstaller's
# modified shared-library environment, without a production credential hook.
SKYSEAL_FREEZE_KIND=signing-worker \
SKYSEAL_FREEZE_REPORT="$diagnostic_root/frozen-worker-elf-staging.json" \
  "$python_exe" -m PyInstaller --clean --noconfirm \
  --distpath "$build_root/ci-worker" --workpath "$build_root/ci-worker-build" \
  "$script_dir/linux-runtime.spec"
dbus-run-session -- xvfb-run -a -s '-screen 0 1280x900x24' \
  bash "$script_dir/linux-test-session.sh" \
  "$python_exe" "$script_dir/smoke-linux-signing.py" \
  --worker-executable "$build_root/ci-worker/linux-signing-worker" \
  --diagnostics "$diagnostic_root/frozen-native-signing"

SKYSEAL_FREEZE_KIND=engine \
SKYSEAL_FREEZE_REPORT="$diagnostic_root/engine-elf-staging.json" \
  "$python_exe" -m PyInstaller --clean --noconfirm \
  --distpath "$binary_root" --workpath "$build_root/pyinstaller" \
  "$script_dir/linux-runtime.spec"
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
npm run build -- --target "$rust_target" --bundles deb

release_root="$desktop_root/src-tauri/target/$rust_target/release"
portable_root="$build_root/portable/SkySeal"
mkdir -p "$portable_root"
install -m 755 "$release_root/skyseal-desktop" "$portable_root/skyseal-desktop"
install -m 755 "$binary_root/desktop-engine-$rust_target" "$portable_root/desktop-engine"
cp "$desktop_root/README.linux.ja.md" "$portable_root/README.linux.ja.md"
cp "$desktop_root/README.ja.md" "$portable_root/README.ja.md"
"$python_exe" "$script_dir/audit-linux-runtime.py" \
  --app-dir "$portable_root" --maximum-glibc 2.35 \
  --output "$diagnostic_root/runtime-audit.json"
dbus-run-session -- xvfb-run -a -s '-screen 0 1280x900x24' \
  bash "$script_dir/linux-test-session.sh" \
  "$python_exe" "$script_dir/smoke-installed-linux.py" \
  --app-dir "$portable_root" --diagnostics "$diagnostic_root/portable-smoke"

version="$("$python_exe" -c 'import json; print(json.load(open("src-tauri/tauri.conf.json"))["version"])')"
artifact_base="SkySeal_${version}_Linux_x86_64_development"
"$python_exe" - "$release_root/bundle/deb" "$distribution_root/$artifact_base.deb" <<'PY'
import pathlib,shutil,sys
packages=list(pathlib.Path(sys.argv[1]).glob('*.deb'))
assert len(packages)==1, f'Expected exactly one .deb, found {len(packages)}'
shutil.copyfile(packages[0],sys.argv[2])
PY
dpkg-deb --info "$distribution_root/$artifact_base.deb" > "$diagnostic_root/debian-package-info.txt"
"$python_exe" "$script_dir/audit-linux-package.py" \
  "$distribution_root/$artifact_base.deb" --version "$version" \
  --portable "$portable_root" --output "$diagnostic_root/debian-package-audit.json"
tar --sort=name --owner=0 --group=0 --numeric-owner -czf \
  "$distribution_root/$artifact_base.tar.gz" -C "$build_root/portable" SkySeal
cp "$desktop_root/README.linux.ja.md" "$distribution_root/README.linux.ja.md"
cp "$desktop_root/README.ja.md" "$distribution_root/README.ja.md"
"$python_exe" - "$distribution_root" "$diagnostic_root" "$artifact_base" <<'PY'
import hashlib,json,pathlib,platform,subprocess,sys
root=pathlib.Path(sys.argv[1]);diagnostics=pathlib.Path(sys.argv[2])
files=[root/(sys.argv[3]+'.deb'),root/(sys.argv[3]+'.tar.gz')]
(root/'SHA256SUMS.txt').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files),encoding='utf-8')
report={
 'target':'x86_64-unknown-linux-gnu','native_architecture':platform.machine(),
 'minimum_ubuntu':'22.04','maximum_glibc_requirement':'2.35',
 'build_os':platform.freedesktop_os_release(),
 'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
 'distribution_signature':'unsigned-development-package',
 'runtime_audit':json.loads((diagnostics/'runtime-audit.json').read_text()),
 'runtime_elf_staging':json.loads((diagnostics/'engine-elf-staging.json').read_text()),
 'portable_application_smoke':'passed',
 'native_pinentry_adapter_test':json.loads((diagnostics/'native-signing/result.json').read_text()),
 'frozen_native_pinentry_adapter_test':json.loads((diagnostics/'frozen-native-signing/result.json').read_text()),
 'installed_debian_package_tests':'see separate Ubuntu 22.04 and 24.04 CI jobs',
 'production_orcid_acceptance':'not_tested'
}
(root/'BUILD_INFO.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
PY
printf 'Linux x86_64 development packages: %s\n' "$distribution_root"
