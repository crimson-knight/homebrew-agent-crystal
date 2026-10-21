"""Authored metadata values for active v105 guarded source fixtures."""
from pathlib import Path
import pkgconf_provider as pkg

def descriptor(model,root):
    paths=[root/'bin/pkgconf',root/'lib/pkgconfig/bdw-gc.pc',root/'lib/libgc.1.dylib']
    raws=[b'SYNTHETIC pkgconf executable',b'Version: 8.2.12\nName: bdw-gc\nDescription: SYNTHETIC\nLibs: -lgc\n',b'SYNTHETIC GC native image']
    rows=[]
    for path,raw in zip(paths,raws):
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o755 if path==paths[0] else 0o644)
        rows.append(dict(path=str(path),bytes=len(raw),sha256=model.sha(raw),mode=path.stat().st_mode&0o777))
    lexical=[str(root/'bin/pkg-config'),str(root/'opt/bdw-gc/lib/pkgconfig/bdw-gc.pc'),str(root/'opt/bdw-gc/lib/libgc.1.dylib')]
    return pkg.descriptor(model,root,rows,[dict(declared_path=a,resolved_path=str(p),links=[]) for a,p in zip(lexical,paths)],[dict(name=n,stable_receipt=dict(source=dict(versions=dict(stable=v)))) for n,v in [('pkgconf','3.0.10'),('bdw-gc','8.2.12')]],[dict(path=str(p),imports=['/usr/lib/libSystem.B.dylib'],rpaths=[]) for p in (paths[0],paths[2])],raws[1],[])
