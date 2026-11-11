"""CI-only mechanical replacement test. No hook is added to the application."""
import sys,json,hashlib,importlib.util
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
out=Path('license-review-output')
marker='SKYSEAL_LGPL_REPLACEMENT_TEST_20261111'
modules=('opentimestamps','bitcoin')
if sys.argv[1]=='prepare':
 records=[]
 for name in modules:
  path=Path(importlib.util.find_spec(name).origin)
  old=path.read_bytes();new=old+b'\n# CI-only compatible modification for relinking review, 2026-11-11.\n__skyseal_relink_probe__ = '+repr(marker).encode()+b'\n'
  path.write_bytes(new)
  records.append({'module':name,'before_sha256':hashlib.sha256(old).hexdigest(),'after_sha256':hashlib.sha256(new).hexdigest(),'change':'Added inert compatibility-test constant; API unchanged; CI only.'})
 (out/'modified_libraries.json').write_text(json.dumps(records,indent=2))
elif sys.argv[1]=='verify':
 engine=out/'engine/desktop-engine-x86_64-unknown-linux-gnu'
 a=CArchiveReader(str(engine));z=a.open_embedded_archive('PYZ.pyz')
 found={name:marker in z.extract(name).co_consts for name in modules}
 result={'modified_modules_embedded':found,'engine_sha256':hashlib.sha256(engine.read_bytes()).hexdigest(),'scope':'Modified LGPL libraries rebuilt into frozen engine; full GUI installer replacement remains a separate test.'}
 (out/'replacement_result.json').write_text(json.dumps(result,indent=2));assert all(found.values()),found
else:raise SystemExit('prepare or verify required')
