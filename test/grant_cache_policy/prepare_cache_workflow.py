"""Derive source-bound workflow entrypoints from the exact retained cache predecessor."""
from pathlib import Path
import re,shlex
R=Path(__file__).resolve().parent
raw=(R/'inputs/v100/grant-cache-mac.proposed.yml').read_text()
gate='''import hashlib, json, os, pathlib, stat
for folder, variable, count in (("grant_assignment_cost", "ATLAS_GRANT_PACKET_SHA256", 215), ("grant_cache_policy", "ATLAS_CACHE_PACKET_SHA256", None)):
    base = pathlib.Path("test") / folder
    pins = base / "SOURCE_PINS.json"
    def regular(path):
        for parent in (path.parent, *path.parent.parents):
            if parent == pathlib.Path('.'):
                break
            if not stat.S_ISDIR(parent.lstat().st_mode):
                raise SystemExit("Physical source directory required")
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > 8 * 2**20:
            raise SystemExit("Bounded ordinary source file required")
        with path.open('rb') as stream:
            value = stream.read(8 * 2**20 + 1)
        after = path.lstat()
        fields = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if fields(before) != fields(after) or len(value) != before.st_size:
            raise SystemExit("Stable complete source member required")
        return value
    raw_pins = regular(pins)
    if hashlib.sha256(raw_pins).hexdigest() != os.environ[variable]:
        raise SystemExit("Exact source manifest differs: " + folder)
    rows = json.loads(raw_pins)["files"]
    if (count is not None and len(rows) != count) or not 1 <= len(rows) <= 256 or len({row['path'] for row in rows}) != len(rows):
        raise SystemExit("Complete unique source roster required")
    for row in rows:
        relative = pathlib.PurePosixPath(row['path'])
        if relative.is_absolute() or '..' in relative.parts or str(relative) != row['path']:
            raise SystemExit("Contained source member required")
        value = regular(base / relative)
        if type(row['bytes']) is not int or len(value) != row['bytes'] or hashlib.sha256(value).hexdigest() != row['sha256']:
            raise SystemExit("Exact source member differs: " + folder + "/" + row['path'])
'''
# Every Python consumer that imports the inherited packet receives both full
# source checks in its own interpreter before runpy reaches the local module.
lines=raw.splitlines();out=[];i=0
while i<len(lines):
 line=lines[i]
 if "<<'PYTHON'" in line:
  end=next(j for j in range(i+1,len(lines)) if lines[j].strip()=='PYTHON')
  block='\n'.join(x[10:] for x in lines[i+1:end])+'\n'
  begin=block.index('source = root /')
  folder='grant_cache_policy' if 'test/grant_cache_policy' in block else 'grant_assignment_cost'
  tail=block[begin:]
  # The original tail's expected variable belongs to its own selected packet.
  prelude=gate+'import runpy, sys\nroot = pathlib.Path("test/'+folder+'").resolve()\nexpected = os.environ["'+('ATLAS_CACHE_PACKET_SHA256' if folder=='grant_cache_policy' else 'ATLAS_GRANT_PACKET_SHA256')+'"]\n'
  out.append(line);out.extend('          '+x for x in (prelude+tail).splitlines());out.append(lines[end]);i=end+1;continue
 match=re.fullmatch(r'          python3 (?P<flags>.*?)test/(?P<folder>grant_assignment_cost|grant_cache_policy)/(?P<script>\S+)\s*(?P<arguments>.*)',line)
 if match:
  flags=match.group('flags');script='test/'+match.group('folder')+'/'+match.group('script');args=shlex.split(match.group('arguments'))
  body=gate+'import runpy, sys\nsource = pathlib.Path('+repr(script)+').resolve()\nsys.argv = [str(source), *'+repr(args)+']\nrunpy.run_path(str(source), run_name="__main__")\n'
  out.append("          python3 "+flags+"- <<'PYTHON'");out.extend('          '+x for x in body.splitlines());out.append('          PYTHON');i+=1;continue
 out.append(line);i+=1
raw='\n'.join(out)+'\n'
raw=raw.replace('0071ce45ef66d490db3954d47b53c6d1e5b7c6018c426afd837be2231afc1ea3','CACHE_V101_MANIFEST_LITERAL')
(R.parent/'grant-cache-mac.proposed.yml').write_text(raw)
