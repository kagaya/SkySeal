"""Inspect the actual Debian archive; no maintainer scripts are executed here."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument('package', type=Path)
    p.add_argument('--portable', required=True, type=Path)
    p.add_argument('--version', required=True)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    def field(name):
        return subprocess.check_output(['dpkg-deb', '-f', str(a.package), name], text=True).strip()
    dependencies = field('Depends')
    assert field('Architecture') == 'amd64'
    assert field('Version') == a.version
    for required in ('libwebkit2gtk-4.1-0', 'libgtk-3-0', 'pinentry-gtk2', 'xdg-utils', 'ca-certificates', 'libc6'):
        assert required in dependencies, f'Missing Debian runtime dependency: {required}'
    with tempfile.TemporaryDirectory(prefix='skyseal-deb-audit-') as temporary:
        root = Path(temporary)
        subprocess.run(['dpkg-deb', '-x', str(a.package), str(root)], check=True)
        for name in ('skyseal-desktop', 'desktop-engine'):
            binary = root / 'usr/bin' / name
            assert binary.is_file() and binary.stat().st_mode & 0o111
            assert hashlib.sha256(binary.read_bytes()).digest() == hashlib.sha256((a.portable/name).read_bytes()).digest(), name
        entries = list((root/'usr/share/applications').glob('*.desktop'))
        assert len(entries) == 1
        entry = entries[0].read_text()
        assert 'skyseal-desktop' in entry and 'Type=Application' in entry
        assert list((root/'usr/share/icons').rglob('*.png'))
    report = {'passed': True, 'package': field('Package'), 'version': a.version,
              'architecture': 'amd64', 'dependencies': dependencies,
              'desktop_entry': True, 'binaries_match_portable': True}
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
