"""Stage portable ELF inputs for Linux PyInstaller builds; never edit the host."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import subprocess


def _dynamic(path: Path) -> str:
    environment = dict(os.environ, LC_ALL="C")
    return subprocess.check_output(["readelf", "--wide", "--dynamic", str(path)],
                                   text=True, env=environment, timeout=30)


def _paths(output: str) -> list[tuple[str, str]]:
    return re.findall(r"\((RPATH|RUNPATH)\).*?\[([^\]]*)\]", output)


def portable_paths(value: str, build_roots: tuple[Path, ...]) -> tuple[list[str], list[str]]:
    kept, removed = [], []
    for entry in value.split(":"):
        normalized = posixpath.normpath(entry)
        if re.match(r"^\$(?:ORIGIN|\{ORIGIN\})(?:/|$)", entry) or (
            entry.startswith("/") and any(normalized == root or normalized.startswith(root + "/")
                                          for root in ("/lib", "/lib64", "/usr/lib", "/usr/lib64"))
        ):
            kept.append(entry)
        elif entry.startswith("/") and any(Path(entry).resolve().is_relative_to(root)
                                           for root in build_roots):
            removed.append(entry)
        else:
            raise RuntimeError(f"Unrecognized nonportable ELF search path: {entry!r}")
    return kept, removed


def stage_binaries(binaries, stage: Path, build_roots: tuple[Path, ...], report_path: Path):
    """Replace only changed TOC source paths, preserving names and symlinks."""
    build_roots = tuple(root.resolve() for root in build_roots)
    stage.mkdir(parents=True, exist_ok=True)
    result, changes = [], []
    for index, (destination, source_name, typecode) in enumerate(binaries):
        source = Path(source_name)
        if typecode == "SYMLINK":
            result.append((destination, source_name, typecode))
            continue
        with source.open("rb") as stream:
            is_elf = stream.read(4) == b"\x7fELF"
        paths = _paths(_dynamic(source)) if is_elf else []
        if len(paths) > 1:
            raise RuntimeError(f"Multiple ELF runtime search path tags: {destination}")
        if not paths:
            result.append((destination, source_name, typecode))
            continue
        tag, original = paths[0]
        kept, removed = portable_paths(original, build_roots)
        if not removed:
            result.append((destination, source_name, typecode))
            continue
        for name in (source.name + ".hmac", "." + source.name + ".hmac",
                     source.name + ".chk", source.stem + ".chk"):
            if (source.parent / name).exists():
                raise RuntimeError(f"Refusing to rewrite integrity-protected ELF input: {destination}")
        original_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        copied = stage / f"{index}-{source.name}"
        shutil.copy2(source, copied)
        if kept:
            command = ["patchelf"] + (["--force-rpath"] if tag == "RPATH" else [])
            command += ["--set-rpath", ":".join(kept), str(copied)]
        else:
            command = ["patchelf", "--remove-rpath", str(copied)]
        subprocess.run(command, check=True, timeout=30)
        expected = [(tag, ":".join(kept))] if kept else []
        if _paths(_dynamic(copied)) != expected:
            raise RuntimeError(f"ELF search path normalization did not match: {destination}")
        if hashlib.sha256(source.read_bytes()).hexdigest() != original_hash:
            raise RuntimeError(f"The original ELF input changed during staging: {destination}")
        result.append((destination, str(copied), typecode))
        changes.append({"component": destination, "original_tag": tag,
                        "removed_build_paths": removed, "preserved_paths": kept,
                        "original_sha256": original_hash,
                        "staged_sha256": hashlib.sha256(copied.read_bytes()).hexdigest()})
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps({"passed": True, "host_inputs_modified": False,
                                     "changed_components": changes}, indent=2) + "\n", encoding="utf-8")
    return result
