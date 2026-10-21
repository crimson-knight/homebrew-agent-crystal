"""Own an exact four-path source overlay and restore bytes, kinds, modes and new directories."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat

from propose_dirty_transition import PATHS, derive, need, sha


def file_state(path):
    if not path.exists() and not path.is_symlink():
        return None
    value = path.lstat()
    need(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_size <= 256 * 2**10,
         'Bounded single-link regular overlay source required: ' + str(path))
    raw = path.read_bytes()
    return dict(raw=raw, mode=stat.S_IMODE(value.st_mode), sha256=sha(raw))


def safe_parent(root, path):
    for parent in reversed(path.parents):
        if parent == root or root in parent.parents:
            need(not parent.is_symlink() and (not parent.exists() or parent.is_dir()), 'Owned ordinary overlay directories required')


@contextmanager
def apply(root, arm, retired=lambda: True, observation=None):
    root = Path(root)
    need(root.is_absolute() and root.is_dir() and not root.is_symlink(), 'Absolute owned Grant overlay root required')
    original, requested = derive('original'), derive(arm)
    before = {}
    created = []
    state = observation if observation is not None else {}
    state.update(arm=arm, restored=False, restoration_deferred=False, paths=list(PATHS))
    # Validate every original member before the first write.
    for relative in PATHS:
        path = root / relative
        safe_parent(root, path)
        before[relative] = file_state(path)
        expected = original[relative]
        need((before[relative] is None if expected is None else before[relative] is not None and before[relative]['raw'] == expected and before[relative]['mode'] == 0o644),
             'Exact complete original overlay roster required: ' + relative)
    try:
        for relative in PATHS:
            path, raw = root / relative, requested[relative]
            if raw is None:
                continue
            if not path.parent.exists():
                path.parent.mkdir()
                created.append(path.parent)
            path.write_bytes(raw)
            path.chmod(before[relative]['mode'] if before[relative] is not None else 0o644)
            need(file_state(path)['raw'] == raw, 'Exact active multi-file overlay bytes required')
        state['active_sha256'] = {name: sha(value) if value is not None else None for name,value in requested.items()}
        yield state
    finally:
        if not retired():
            state['restoration_deferred'] = True
            raise RuntimeError('Original owned groups remain unresolved; private overlay and outputs retained for explicit recovery')
        errors = []
        for relative in PATHS:
            path, expected = root / relative, before[relative]
            try:
                safe_parent(root, path)
                current = file_state(path)
                active = requested[relative]
                expected_mode = before[relative]['mode'] if before[relative] is not None else 0o644
                if (current is None if active is None else current is not None and current['raw'] == active and current['mode'] == expected_mode) is False:
                    errors.append('Active overlay changed before restoration: ' + relative)
                if expected is None:
                    if current is not None:
                        path.unlink()
                else:
                    path.write_bytes(expected['raw'])
                    path.chmod(expected['mode'])
                need(file_state(path) == expected, 'Exact original overlay kind/mode/bytes restoration required')
            except Exception as error:
                errors.append('%s: %s' % (type(error).__name__, error))
        for directory in reversed(created):
            try:
                directory.rmdir()
            except Exception as error:
                errors.append('%s: %s' % (type(error).__name__, error))
        state['restoration_errors'] = errors
        state['restored'] = not errors
        need(not errors, 'Complete multi-file source restoration required: ' + '; '.join(errors))
