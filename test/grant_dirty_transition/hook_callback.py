"""Admit a supplied real harness callback before application overlays or native proofs."""
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from proof_command import terminal, finite
from propose_dirty_transition import ROOT, need, sha
from run_hosted_contrast import digest
from vendor.verify_compile_acceptance import source_input_inventory

ADAPTER_SHA256 = 'cbb09db5b1d69e960dd1dc93bf0c7e21df6360ef9fd6d357d20829bf14b3fa1c'
CONFIG_SHA256 = 'ba66dadc78bfc66536ba47b1ac888d31a58ad5d701b63149a8c7b0f6822e364e'
ORIGINAL_SOURCE_SHA256 = 'edeb868d76119f67dacdd829a0113ba0b0637583f0ee2fcbd87078a6cbee9d8a'
PROBE_RELATIVE = 'performance/results/hook-prerequisite/callback_probe.cr'


def read(path, maximum):
    need(path.is_absolute() and path.resolve(strict=True) == path, 'Absolute physical callback evidence path required')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
         'Bounded ordinary callback evidence file required')
    raw = path.read_bytes()
    after = path.lstat()
    need(len(raw) == before.st_size and
         (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
         'Stable exact callback evidence bytes required')
    return raw


def admit(path, expected, grant, admission, tools, environment=None, now=None):
    environment = os.environ if environment is None else environment
    now = time.monotonic() if now is None else now
    need(isinstance(path, Path) and isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected) is not None,
         'A real supplied callback receipt and reviewed SHA-256 are prerequisites')
    raw = read(path, 64 * 2**10)
    need(sha(raw) == expected, 'Exact parent-reviewed genuine callback receipt required')
    value = json.loads(raw)
    need(value['format'] == 'atlas-grant-real-hook-callback-v1' and value['callback_verified'] is True and
         value['issuer'] == 'actual-harness-PostToolUse' and value['session_id'],
         'Successful actual harness callback evidence required')
    need(value['job_identity'] == admission['job_identity'] and value['nonce'] == environment.get('ATLAS_GRANT_JOB_NONCE') and
         re.fullmatch('[0-9a-f]{64}', value['nonce']) is not None,
         'Fresh same-job run/attempt/source/runner/nonce callback identity required')
    need(value['project'] == str(grant) and grant.is_absolute() and grant.resolve(strict=True) == grant and
         value['source_tree_sha256'] == ORIGINAL_SOURCE_SHA256 and
         source_input_inventory(grant)[1] == ORIGINAL_SOURCE_SHA256 and
         value['packet_sha256'] == digest(ROOT / 'SOURCE_PINS.json'),
         'Exact actual project and original source/packet callback binding required')
    need(value['providers'] == admission['providers'] and value['proof_tools'] == tools['tools'],
         'Exact same-job compiler/Ruby and API/lint providers required in callback evidence')
    python = Path(sys.executable).resolve()
    need(value['python'] == dict(path=str(python), sha256=digest(python)), 'Exact callback Python provider required')
    command = value['command']
    need(value['monotonic_clock'] == 'same-host-boot' and finite(value['started_monotonic'], 0, now) and
         finite(value['completed_monotonic'], value['started_monotonic'], now) and
         0 <= now - value['completed_monotonic'] <= 600 and
         value['completed_monotonic'] - value['started_monotonic'] <= command['maximum_seconds'],
         'Fresh completed real callback inside its supplied finite command horizon required')
    protected = {path: expected}
    evidence = {}
    need(set(value['evidence']) == {'adapter', 'config', 'payload', 'observation'}, 'Complete exact callback evidence roster required')
    for name, row in value['evidence'].items():
        item = Path(row['path'])
        data = read(item, 256 * 2**10)
        need(sha(data) == row['sha256'], 'Exact callback evidence bytes required: ' + name)
        protected[item] = row['sha256']
        evidence[name] = data
    need(sha(evidence['adapter']) == ADAPTER_SHA256 and sha(evidence['config']) == CONFIG_SHA256,
         'Exact reviewed adapter and registered hook configuration required')
    config = json.loads(evidence['config'])
    adapter_path = value['evidence']['adapter']['path']
    registered = [entry['command'] for row in config['hooks']['PostToolUse'] for entry in row['hooks']]
    need(any(adapter_path in entry and ADAPTER_SHA256 in entry for entry in registered),
         'Actual registered checksum-bound adapter callback required')
    payload, observed = json.loads(evidence['payload']), json.loads(evidence['observation'])
    need(payload['cwd'] == str(grant) and payload['session_id'] == value['session_id'] and
         payload['hook_event_name'] == 'PostToolUse' and payload['tool_name'] == observed['tool_name'] and
         observed['phase'] == 'posttool' and observed['cwd'] == str(grant) and
         observed['session_id'] == value['session_id'] and observed['adapter_path'] == adapter_path and
         observed['adapter_sha256'] == ADAPTER_SHA256 and observed['route_sha256'] ==
         '9ae9fa90e4971d50b3985aca1a3c6ea3b1c2bc676697a249263cb2a939c3177a',
         'Actual adapter-emitted project/session/source-bound observation required')
    probe = grant / PROBE_RELATIVE
    need(observed['files'] == [str(probe)] and read(probe, 1024) == (ROOT / 'source/hook_callback_probe.cr.txt').read_bytes(),
         'Genuine callback probe in the actual project precedes product overlays')
    need(value['dispatch']['stdin_sha256'] == value['evidence']['payload']['sha256'],
         'Exact callback payload delivered to the registered hook required')
    need(value['dispatch']['origin'] == 'actual-hook-registry' and value['dispatch']['hook_event_name'] == 'PostToolUse' and
         value['dispatch']['registered_command'] in registered and value['dispatch']['session_id'] == value['session_id'],
         'Real harness dispatch receipt required; direct adapter metadata is insufficient')
    directory = Path(value['command_output'])
    need(directory.is_absolute() and directory.resolve(strict=True) == directory and
         value['dispatch']['argv'] == ['/bin/sh','-c',value['dispatch']['registered_command']] and
         command['arguments'] == value['dispatch']['argv'] and command['label'] == 'callback' and
         command['elapsed_seconds'] >= value['completed_monotonic'] - value['started_monotonic'],
         'Exact callback dispatch/command/elapsed join required')
    terminal(command, 300, output=directory)
    need(set(value['callback_providers']) == {'registered_shell','ruby_launcher'},
         'Exact callback dispatch provider roster required')
    for name,expected_path in [('registered_shell','/bin/sh'),('ruby_launcher','/usr/bin/ruby')]:
        row = value['callback_providers'][name]
        item = Path(row['path'])
        need(str(item) == expected_path and os.access(item,os.X_OK) and sha(read(item,64*2**20)) == row['sha256'],
             'Exact reviewed actual callback dispatch provider required: '+name)
        protected[item] = row['sha256']
    protected[probe] = sha((ROOT / 'source/hook_callback_probe.cr.txt').read_bytes())
    protected[python] = digest(python)
    for stream in ('stdout', 'stderr'):
        item = directory / ('callback.' + stream + '.txt')
        protected[item] = command[stream + '_sha256']
    for name, row in admission['providers'].items():
        item = Path(row['path'])
        need(digest(item) == row['sha256'], 'Unchanged actual callback compiler/Ruby provider required: ' + name)
        protected[item] = row['sha256']
    return dict(receipt=value, protected=protected)
