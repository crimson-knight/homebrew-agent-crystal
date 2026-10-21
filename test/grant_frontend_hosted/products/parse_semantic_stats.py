"""Strict source-proposed eleven-stage no-codegen grammar; actual output qualification pending."""
import hashlib
import math
import re

STAGES = ('Parse', 'Semantic (top level)', 'Semantic (new)', 'Semantic (type declarations)',
          'Semantic (abstract def check)', 'Semantic (restrictions augmenter)', 'Semantic (ivars initializers)',
          'Semantic (cvars initializers)', 'Semantic (main)', 'Semantic (cleanup)', 'Semantic (recursive struct check)')
DURATION = r'(\d+):([0-5]\d):([0-5]\d)(?:\.(\d{1,9}))?'


def require(value, message):
    if not value:
        raise ValueError(message)


def parse(raw):
    require(type(raw) is bytes and 0 < len(raw) < 2**20, 'Finite raw semantic stats required')
    lines = raw.decode('utf-8').replace('\r', '\n').splitlines()
    require(len(lines) == 2 * len(STAGES), 'Exactly eleven complete stage start/completion pairs required')
    stages, offset = [], 0
    for number, stage in enumerate(STAGES):
        prefix = (stage + ':').ljust(34)
        require(lines[2 * number] == prefix, 'Exact semantic start order/padding differs')
        line = lines[2 * number + 1]
        match = re.fullmatch(re.escape(prefix) + r' ' + DURATION + r' \(( *)(\d+\.\d{2})MB\)', line)
        require(match is not None, 'Exact semantic completion grammar differs')
        hours, minutes, seconds, fraction, padding, heap = match.groups()
        require(padding + heap == heap.rjust(7), 'Exact compiler heap padding required')
        elapsed = int(hours) * 3600 + int(minutes) * 60 + int(seconds) + (float('0.' + fraction) if fraction else 0)
        capacity = float(heap)
        require(math.isfinite(elapsed) and elapsed >= 0 and math.isfinite(capacity) and capacity >= 0,
                'Finite nonnegative semantic endpoints required')
        position = raw.find(line.encode(), offset)
        require(position >= 0, 'Raw semantic completion byte binding differs')
        offset = position + len(line.encode()) + 1
        require(raw[offset - 1:offset] == b'\n', 'Raw completion newline required')
        stages.append({'stage': stage, 'duration_seconds': elapsed, 'compiler_gc_heap_mib_reported': capacity,
                       'completion_stdout_byte_end': offset, 'raw_completion_line': line})
    return {'stages': stages, 'raw_stdout_sha256': hashlib.sha256(raw).hexdigest(),
            'scope': 'Rounded GC heap capacity after each phase; MB is the pinned compiler label for binary MiB',
            'live_bytes_measured': False, 'compiler_peak_qualified': False, 'whole_build_provider_qualified': False,
            'canonical_cells_accepted': 0}
