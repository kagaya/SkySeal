# Linux-only one-file engine and disposable CI worker. The latter is never shipped.
import os
from pathlib import Path
import sys

from PyInstaller.utils.hooks import collect_data_files, copy_metadata

script_root = Path(SPECPATH).resolve()
repo_root = script_root.parents[1]
sys.path.insert(0, str(script_root))
from linux_freezer import stage_binaries

kind = os.environ["SKYSEAL_FREEZE_KIND"]
if kind not in {"engine", "signing-worker"}:
    raise RuntimeError("Unknown Linux freezer target")
engine = kind == "engine"
datas = collect_data_files("certifi") if engine else []
if engine:
    for distribution in ("opentimestamps", "python-bitcoinlib", "cryptography"):
        datas += copy_metadata(distribution)

a = Analysis(
    [str(script_root / ("engine_entry.py" if engine else "smoke-linux-signing.py"))],
    pathex=[str(repo_root)], binaries=[], datas=datas,
    hiddenimports=(["opentimestamps.core.timestamp", "opentimestamps.core.notary",
                    "opentimestamps.core.op", "opentimestamps.core.serialize", "bitcoin.core"]
                   if engine else []),
    excludes=(["otsclient", "bitcoin.wallet", "bitcoin.rpc", "bitcoin.core.key",
               "opentimestamps.core.git"] if engine else []),
    noarchive=False,
)
pyz = PYZ(a.pure)
# PYZ adds bootstrap extensions such as _struct and zlib after Analysis. EXE
# merges that dependency TOC too, so normalize every file TOC before packing.
binary_count, data_count = len(a.binaries), len(a.datas)
staged = stage_binaries(
    [*a.binaries, *a.datas, *pyz.dependencies], Path(workpath) / "portable-elf",
    (Path(sys.base_prefix), repo_root, Path(workpath)),
    Path(os.environ["SKYSEAL_FREEZE_REPORT"]),
)
a.binaries = staged[:binary_count]
a.datas = staged[binary_count:binary_count + data_count]
pyz.dependencies = staged[binary_count + data_count:]
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="desktop-engine-x86_64-unknown-linux-gnu" if engine else "linux-signing-worker",
    console=True, debug=False, strip=False, upx=False,
)
