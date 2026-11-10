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
a.binaries = stage_binaries(
    a.binaries, Path(workpath) / "portable-elf",
    (Path(sys.base_prefix), repo_root, Path(workpath)),
    Path(os.environ["SKYSEAL_FREEZE_REPORT"]),
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="desktop-engine-x86_64-unknown-linux-gnu" if engine else "linux-signing-worker",
    console=True, debug=False, strip=False, upx=False,
)
