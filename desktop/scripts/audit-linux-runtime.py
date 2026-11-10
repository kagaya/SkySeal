"""Audit packaged ELF architecture and required ABI versions without running it.

The version-needs section matters: versions a bundled library *provides* must
not be mistaken for versions it requires. Only the two trusted build outputs
are passed to ldd; extracted PyInstaller entries are inspected by readelf only.
https://sourceware.org/binutils/docs/binutils/readelf.html
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import posixpath
import re
import struct
import subprocess
import sys
import tempfile


ELF_MAGIC = b"\x7fELF"
EM_X86_64 = 62


def version(value: str) -> tuple[int, ...]:
    if not re.fullmatch(r"\d+(?:\.\d+)*", value):
        raise ValueError(f"Not a numeric ABI version: {value}")
    return tuple(map(int, value.split(".")))


def run(*command: str, clean_loader: bool = False) -> str:
    environment = dict(os.environ)
    environment["LC_ALL"] = "C"
    if clean_loader:
        for key in ("LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"):
            environment.pop(key, None)
    return subprocess.check_output(command, text=True, encoding="utf-8",
                                   stderr=subprocess.STDOUT, env=environment,
                                   timeout=30)


def required_versions(output: str) -> dict[str, list[str]]:
    """Parse only VERNEED, excluding VERDEF and the version-symbols display."""
    needed: set[str] = set()
    in_needs = False
    for line in output.splitlines():
        if line.startswith("Version needs section "):
            in_needs = True
        elif re.match(r"Version (?:symbols|definition) section ", line):
            in_needs = False
        if in_needs:
            match = re.search(r"\bName:\s+(\S+)", line)
            if match:
                needed.add(match.group(1))
    return {prefix: sorted((name for name in needed if name.startswith(prefix + "_")))
            for prefix in ("GLIBC", "GLIBCXX", "CXXABI")}


def elf_architecture(header: bytes, component: str) -> None:
    if len(header) < 64 or header[:4] != ELF_MAGIC:
        raise RuntimeError(f"{component}: missing or truncated ELF header")
    if header[4:7] != bytes((2, 1, 1)):
        raise RuntimeError(f"{component}: expected ELF64, little endian, version 1")
    kind, machine, elf_version = struct.unpack_from("<HHI", header, 16)
    if machine != EM_X86_64 or kind not in (2, 3) or elf_version != 1:
        raise RuntimeError(f"{component}: expected x86_64 executable/shared ELF, got machine={machine}, type={kind}")
    if header[7] not in (0, 3):
        raise RuntimeError(f"{component}: ELF OS/ABI is neither System V nor GNU/Linux")


def dynamic_metadata(output: str, component: str) -> dict[str, list[str]]:
    needed = re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", output)
    search_paths = re.findall(r"\((?:RPATH|RUNPATH)\).*?\[([^\]]*)\]", output)
    if any("/" in name for name in needed):
        raise RuntimeError(f"{component}: a required library uses a nonportable explicit path")
    paths = [part for value in search_paths for part in value.split(":")]
    for path in paths:
        if re.match(r"^\$(?:ORIGIN|\{ORIGIN\})(?:/|$)", path):
            continue
        normalized = posixpath.normpath(path)
        if path.startswith("/") and any(normalized == root or normalized.startswith(root + "/")
                                        for root in ("/lib", "/lib64", "/usr/lib", "/usr/lib64")):
            continue
        raise RuntimeError(f"{component}: nonportable runtime search path: {path!r}")
    return {"needed_libraries": needed, "runtime_search_paths": paths}


def inspect(path: Path, component: str, maximum_glibc: str) -> dict:
    with path.open("rb") as stream:
        elf_architecture(stream.read(64), component)
    requirements = required_versions(run("/usr/bin/readelf", "--wide", "--version-info", str(path)))
    glibc_versions = []
    for name in requirements["GLIBC"]:
        match = re.fullmatch(r"GLIBC_(\d+(?:\.\d+)*)", name)
        if not match:
            # PRIVATE or new named ABI markers cannot establish the 2.35 floor.
            raise RuntimeError(f"{component}: unsupported required glibc ABI marker {name}")
        glibc_versions.append(match.group(1))
    maximum = max(glibc_versions, key=version) if glibc_versions else None
    if maximum is not None and version(maximum) > version(maximum_glibc):
        raise RuntimeError(f"{component}: requires glibc {maximum}, above declared {maximum_glibc}")
    dynamic = dynamic_metadata(run("/usr/bin/readelf", "--wide", "--dynamic", str(path)), component)
    return {"component": component, "architecture": "x86_64",
            "maximum_required_glibc": maximum, "required_symbol_versions": requirements,
            **dynamic}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-dir", type=Path, required=True)
    parser.add_argument("--maximum-glibc", default="2.35")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        raise SystemExit("The ELF runtime audit must run on Linux.")
    version(args.maximum_glibc)
    records: list[dict] = []
    report = {"passed": False, "architecture": "x86_64",
              "declared_minimum_ubuntu": "22.04", "maximum_allowed_glibc": args.maximum_glibc,
              "components": records,
              "limit": "Required ELF ABI versions and current-host dependencies are audited; GUI behavior still requires installed tests on each supported Ubuntu release."}
    failure = None
    try:
        # Imported here so parser/header checks need no installed PyInstaller.
        from PyInstaller.archive.readers import CArchiveReader

        app = args.app_dir.resolve(strict=True)
        dependencies = {}
        for name in ("skyseal-desktop", "desktop-engine"):
            executable = app / name
            if not executable.is_file() or executable.is_symlink() or not os.access(executable, os.X_OK):
                raise RuntimeError(f"{name}: expected a regular executable in the package")
            records.append(inspect(executable, name, args.maximum_glibc))
            output = run("/usr/bin/ldd", str(executable), clean_loader=True)
            if re.search(r"\bnot found\b", output):
                raise RuntimeError(f"{name}: a system runtime dependency was not found")
            dependencies[name] = output.splitlines()
        report["host_dependency_resolution"] = dependencies

        archive = CArchiveReader(str(app / "desktop-engine"))
        embedded = 0
        with tempfile.TemporaryDirectory(prefix="skyseal-elf-audit-") as temporary:
            for number, name in enumerate(archive.toc):
                content = archive.extract(name)
                if not isinstance(content, bytes) or not content.startswith(ELF_MAGIC):
                    continue
                # Never interpret archive member names as local filesystem paths.
                extracted = Path(temporary) / f"component-{number}"
                extracted.write_bytes(content)
                records.append(inspect(extracted, "desktop-engine::" + name, args.maximum_glibc))
                embedded += 1
        if not embedded:
            raise RuntimeError("No embedded Python ELF runtime was audited")
        report["embedded_elf_count"] = embedded
        floors = [item["maximum_required_glibc"] for item in records if item["maximum_required_glibc"]]
        if not floors:
            raise RuntimeError("No required glibc ABI versions were found")
        report["maximum_required_glibc"] = max(floors, key=version)
        report["passed"] = True
    except Exception as exc:
        report["error"] = str(exc)
        failure = exc
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if failure is not None:
        print(f"ELF runtime audit failed: {failure}", file=sys.stderr)
        return 1
    print(f"ELF runtime audit passed: {len(records)} native x86_64 components, required glibc <= {args.maximum_glibc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
