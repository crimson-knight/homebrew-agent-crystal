"""Call the exact ordinary SDK qualifier once and seal that same job's observation."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from same_job_policy import DRIVER_SHA256, LOCK_SHA256, digest, identity, metadata, need, protect_packet, roster


def qualify(args):
    need(platform.system() == 'Darwin' and platform.machine() == 'arm64' and os.environ.get('GITHUB_ACTIONS') == 'true', 'Actual GitHub-hosted Mac ARM64 SDK call required')
    protected = protect_packet(args.packet_sha256)
    need(digest(args.driver) == DRIVER_SHA256 and digest(args.driver.with_name('sdk_source_lock.json')) == LOCK_SHA256, 'Exact existing SDK qualifier and source lock required')
    need(digest(Path(sys.executable).resolve()) == args.python_sha256, 'Exact actually observed Python provider required')
    protected.update({args.driver: DRIVER_SHA256, args.driver.with_name('sdk_source_lock.json'): LOCK_SHA256, Path(sys.executable).resolve(): args.python_sha256})
    job = identity(os.environ)
    nonce = secrets.token_hex(32)
    os.environ['ATLAS_GRANT_JOB_NONCE'] = nonce
    with Path(os.environ['GITHUB_ENV']).open('a') as stream:
        stream.write('ATLAS_GRANT_JOB_NONCE=' + nonce + '\n')
    started = time.monotonic()
    need(not args.output.exists() and not args.output.is_symlink(), 'Fresh same-job SDK output required')
    spec = importlib.util.spec_from_file_location('grant_same_job_exact_sdk', args.driver)
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    code = driver.qualify(args.output, json.loads(args.driver.with_name('sdk_source_lock.json').read_bytes()))
    binding = dict(format='atlas-sdk-in-process-same-job-binding-v1', job_identity=job, nonce=nonce,
                   sdk_call_returned=True, sdk_return_code=code, driver_sha256=DRIVER_SHA256,
                   policy_sha256=digest(ROOT / 'same_job_policy.py'), wrapper_sha256=digest(__file__),
                   started_monotonic=started, terminal_monotonic=time.monotonic(), evidence=roster(args.output),
                   actual_native_qualification=False, whole_build_qualification=False, target_cells_accepted=0)
    (args.output / 'SAME_JOB_BINDING.json').write_text(json.dumps(binding, indent=2, sort_keys=True) + '\n')
    need(code == 0 and type(code) is int, 'Ordinary installation/SDK qualification failed; complete evidence retained')
    metadata(args.output, os.environ)
    for path, expected in protected.items():
        need(digest(path) == expected, 'Exact source packet remains unchanged through SDK call')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--packet-sha256', required=True)
    parser.add_argument('--python-sha256', required=True)
    return qualify(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
