"""Validate exact hosted API/lint paths, source origins and executable hashes."""
import argparse
import json
from pathlib import Path
from dirty_proof import admit_tools


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proof-tools',type=Path,required=True)
    parser.add_argument('--proof-tools-sha256',required=True)
    args = parser.parse_args()
    print(json.dumps(admit_tools(args.proof_tools,args.proof_tools_sha256),indent=2,sort_keys=True))
