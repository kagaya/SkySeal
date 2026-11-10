"""Check actual Mach-O deployment targets, including the frozen Python archive.

This reads the pinned PyInstaller archive; it does not execute extracted files.
It checks declared load-command floors, not behavior on every older macOS.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tempfile

from PyInstaller.archive.readers import CArchiveReader

MACHO_MAGICS = {bytes.fromhex(value) for value in (
    "feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe", "bebafeca",
    "cafebabf", "bfbafeca")}


def version(value: str) -> tuple[int, ...]:
    parts = tuple(int(item) for item in value.split("."))
    return (parts + (0, 0, 0))[:3]


def run(*command: str) -> str:
    return subprocess.check_output(command, text=True, encoding="utf-8", timeout=30)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--architecture", choices=("x86_64", "arm64"), required=True)
    parser.add_argument("--minimum", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise SystemExit("The runtime audit must run on macOS.")
    app = args.app.resolve(strict=True)
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    if info.get("LSMinimumSystemVersion") != args.minimum:
        raise RuntimeError("Bundle metadata does not match the claimed macOS minimum")
    executables = app / "Contents/MacOS"
    records = []

    def inspect(path: Path, component: str) -> None:
        architectures = run("/usr/bin/lipo", "-archs", str(path)).strip().split()
        if architectures != [args.architecture]:
            raise RuntimeError(f"{component}: expected native {args.architecture}, got {architectures}")
        output = run("/usr/bin/otool", "-l", str(path))
        floors = []
        for command in re.split(r"(?=Load command \d+)", output):
            if re.search(r"\bcmd LC_BUILD_VERSION\b", command):
                platform = re.search(r"\bplatform (\w+)", command)
                if platform is None or platform.group(1).lower() not in {"1", "macos"}:
                    raise RuntimeError(f"{component}: build-version platform is not macOS")
                match = re.search(r"\bminos (\d+(?:\.\d+)*)", command)
                if match:
                    floors.append(match.group(1))
            elif re.search(r"\bcmd LC_VERSION_MIN_MACOSX\b", command):
                match = re.search(r"\bversion (\d+(?:\.\d+)*)", command)
                if match:
                    floors.append(match.group(1))
        if not floors:
            raise RuntimeError(f"{component}: no macOS deployment load command was found")
        maximum = max(floors, key=version)
        if version(maximum) > version(args.minimum):
            raise RuntimeError(f"{component}: requires macOS {maximum}, above declared {args.minimum}")
        records.append({"component": component, "architecture": args.architecture,
                        "minimum_macos": maximum})

    for name in (info["CFBundleExecutable"], "desktop-engine", "macos-signer"):
        inspect(executables / name, name)

    archive = CArchiveReader(str(executables / "desktop-engine"))
    with tempfile.TemporaryDirectory(prefix="skyseal-runtime-audit-") as temporary:
        for number, name in enumerate(archive.toc):
            # Most entries are Python bytecode/data. Only inspect Mach-O bytes;
            # names from the archive are never used as filesystem destinations.
            content = archive.extract(name)
            if not isinstance(content, bytes) or content[:4] not in MACHO_MAGICS:
                continue
            extracted = Path(temporary) / f"component-{number}"
            extracted.write_bytes(content)
            inspect(extracted, "desktop-engine::" + name)
    if len(records) <= 3:
        raise RuntimeError("No embedded Python Mach-O runtime was audited")
    report = {
        "passed": True, "architecture": args.architecture,
        "declared_minimum_macos": args.minimum,
        "maximum_embedded_minimum": max((item["minimum_macos"] for item in records), key=version),
        "components": records,
        "limit": f"Load-command audit; application behavior on macOS {args.minimum} still requires a matching device.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Runtime audit passed: {len(records)} native {args.architecture} Mach-O components, minimum <= {args.minimum}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
