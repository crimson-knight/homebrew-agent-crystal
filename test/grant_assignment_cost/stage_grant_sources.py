"""Project the exact existing frozen Grant archive into one fresh owned directory."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import os
import stat
import sys
import tarfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'vendor'))
from verify_compile_acceptance import source_input_inventory

ARCHIVE_SHA256 = 'd2c90cc3110109337c92f567fdf533dadf475b3f468602b8fcb5e2ed21426ff5'
TREE_SHA256 = 'edeb868d76119f67dacdd829a0113ba0b0637583f0ee2fcbd87078a6cbee9d8a'


def need(value, message):
    if not value:
        raise RuntimeError(message)


def stage(archive, output):
    need(archive.is_file() and not archive.is_symlink() and archive.stat().st_size == 1626007, 'Exact frozen Grant source archive size required')
    need(hashlib.sha256(archive.read_bytes()).hexdigest() == ARCHIVE_SHA256, 'Exact frozen Grant source archive SHA required')
    need(output.is_absolute() and not output.exists() and not output.is_symlink(), 'Fresh absolute owned source directory required')
    output.mkdir(parents=True)
    links, total, names = [], 0, set()
    with tarfile.open(archive, 'r:gz') as source:
        for index, member in enumerate(source):
            name = PurePosixPath(member.name)
            need(index < 4096 and not name.is_absolute() and name.parts and name.parts[0] == 'grant' and '..' not in name.parts and str(name) == member.name and member.name not in names, 'Unique contained frozen source path required')
            names.add(member.name)
            path = output.joinpath(*name.parts)
            need(all(not parent.is_symlink() for parent in path.parents), 'Ordinary source ancestors required')
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif member.isreg():
                need(0 <= member.size <= 16 * 2**20 and total + member.size <= 128 * 2**20, 'Bounded frozen source file/content roster required')
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = source.extractfile(member).read(member.size + 1)
                need(len(raw) == member.size and not path.exists(), 'Exact ordinary source member bytes required')
                path.write_bytes(raw)
                path.chmod(stat.S_IMODE(member.mode))
                total += len(raw)
            elif member.issym():
                need(not PurePosixPath(member.linkname).is_absolute(), 'Relative frozen source alias required')
                links.append((path, member.linkname))
            else:
                raise RuntimeError('Frozen source contains an unsupported member kind')
    for path, target in links:
        resolved = (path.parent / target).resolve(strict=True)
        need(resolved.is_relative_to(output / 'grant') if hasattr(resolved, 'is_relative_to') else (output / 'grant') in resolved.parents, 'Contained frozen source alias target required')
        need(not path.exists() and not path.is_symlink(), 'Fresh frozen source alias path required')
        path.symlink_to(target)
    rows, fingerprint = source_input_inventory(output / 'grant')
    need(fingerprint == TREE_SHA256 and len(rows) == 1554 and len(links) == 5, 'Exact complete1554-source closure and five aliases required')
    return dict(passed=True, archive_sha256=ARCHIVE_SHA256, source_tree_sha256=fingerprint, source_rows=len(rows), aliases=len(links), physical_regular_bytes=total,
                actual_compiler_jobs=0, execution_admitted=False, target_cells_accepted=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = stage(args.archive, args.output)
    (args.output / 'SOURCE_PROJECTION.json').write_text(json.dumps(result, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
