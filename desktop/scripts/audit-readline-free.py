"""Inspect the finished frozen engine without executing embedded Python code."""
import argparse
import hashlib
import json
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader

def main():
    p=argparse.ArgumentParser()
    p.add_argument('engine',type=Path)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    archive=CArchiveReader(str(args.engine))
    outer=list(archive.toc)
    modules=[]
    for name,entry in archive.toc.items():
        if entry[-1]=='z':
            modules.extend(archive.open_embedded_archive(name).toc)
    forbidden=[n for n in outer+modules if 'readline' in n.lower()]
    report={'passed':not forbidden,'engine_sha256':hashlib.sha256(args.engine.read_bytes()).hexdigest(),
            'outer_members':outer,'python_modules':sorted(modules),'forbidden_members':forbidden,
            'scope':'CArchive and PYZ membership. No embedded code execution.'}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    if forbidden:raise SystemExit('Readline found in finished engine: '+repr(forbidden))
    print('Readline absent from finished CArchive and PYZ')

if __name__=='__main__':main()
