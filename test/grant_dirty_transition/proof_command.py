"""Validate original Runner terminal metadata and retained raw output without retrying failures."""
import json
import math
from pathlib import Path
import re
import stat
from propose_dirty_transition import need
from run_hosted_contrast import digest


def finite(value, minimum, maximum):
    return type(value) in (int, float) and math.isfinite(value) and minimum <= value <= maximum


def raw_streams(row, output):
    values = []
    total = 0
    need(re.fullmatch(r'[a-z0-9_-]+', row['label']) is not None, 'Contained exact command label required')
    for stream in ('stdout', 'stderr'):
        path = output / (row['label'] + '.' + stream + '.txt')
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 4 * 2**20,
             'Bounded private ordinary command stream required')
        raw = path.read_bytes()
        need(len(raw) == info.st_size and digest(path) == row[stream + '_sha256'],
             'Exact qualified command stream hash required')
        after = path.lstat()
        need((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
             'Stable private command stream identity required')
        total += len(raw)
        values.append(raw.decode('utf-8'))
    need(total <= 4 * 2**20, 'Original combined four-MiB command output bound required')
    return tuple(values)


def terminal(row, maximum, *, expected=0, unknown=False, output=None, observation=None):
    """Exit4 is one bounded unknown-card result; resource refusals stay failures."""
    need(row['refusal'] is None, 'Every deadline/output/group refusal remains a failed command')
    need(type(row['exit_code']) is int and row['exit_code'] == (4 if unknown else expected) and
         type(row['expected_exit']) is int and row['expected_exit'] == expected,
         'Exact original Runner actual/expected status required')
    need(finite(row['maximum_seconds'], 0, maximum) and row['maximum_seconds'] > 0 and
         finite(row['elapsed_seconds'], 0, row['maximum_seconds']),
         'Command must retire inside its original finite requested horizon')
    group = row['terminal_group_observation']
    for value in (row['pid'], row['original_group'], group['group']):
        need(type(value) is int and value > 0, 'Positive exact integer original PID/group required')
    need(row['pid'] == row['original_group'] == group['group'] and row['writers_confirmed_retired'] is True and
         group['status'] == 'absent', 'Exact original command group absence required')
    need(group['scope'] == 'original POSIX process group' and group['phase'] == 'direct_child_returned' and
         group['bounded_drain_exhausted'] is False and finite(group['maximum_drain_seconds'], 5, 5) and
         finite(group['elapsed_seconds'], 0, 5), 'Complete original-group terminal drain required')
    need(finite(group['original_command_deadline'], 0, float('inf')) and
         finite(group['drain_deadline'], 0, group['original_command_deadline']),
         'Finite original command and capped drain deadlines required')
    samples = group['samples']
    need(isinstance(samples, list) and 1 <= len(samples) <= 128 and group['initial_sample'] == samples[0] and
         group['terminal_sample'] == samples[-1] and samples[-1]['status'] == 'absent',
         'Complete bounded original-group sample roster required')
    for sample in samples:
        need(sample['status'] in ('present', 'absent') and finite(sample['elapsed_seconds'], 0, group['elapsed_seconds']),
             'Finite exact original-group sample required')
    if observation is not None:
        need(json.dumps(group, sort_keys=True, allow_nan=False) == json.dumps(observation, sort_keys=True, allow_nan=False),
             'Exact command and final group observation join required')
    for stream in ('stdout', 'stderr'):
        need(isinstance(row[stream + '_sha256'], str) and re.fullmatch('[0-9a-f]{64}', row[stream + '_sha256']) is not None,
             'Qualified exact command stream SHA-256 required')
    return raw_streams(row, output) if output is not None else None
