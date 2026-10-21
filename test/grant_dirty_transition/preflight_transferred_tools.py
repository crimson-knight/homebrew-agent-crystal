"""Bootstrap the script directory before delegating the exact preserved core preflight."""
import hashlib
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
source = ROOT / 'preflight_dirty_tools.py'
if hashlib.sha256(source.read_bytes()).hexdigest() != 'b43ea82bdd52b74dfafc5033b286208caea30b2819b267910f011da0dac21a5a':
    raise RuntimeError('Exact preserved dirty preflight source required')
try:
    runpy.run_path(str(source), run_name='__main__')
except RuntimeError as error:
    if str(error) == 'Hosted Amber LSP and Ameba provider admission remains an explicit prerequisite':
        print('PENDING_PROOF_TOOLS_REFUSED: ' + str(error), file=sys.stderr)
        raise SystemExit(2)
    raise
