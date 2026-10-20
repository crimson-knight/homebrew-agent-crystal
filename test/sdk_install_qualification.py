#!/usr/bin/env python3
"""Exercise the public SDK against this job's ordinary Alpha installation."""

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request


class QualificationError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise QualificationError(message)


def sha256(path):
    with pathlib.Path(path).open("rb") as stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        return digest.hexdigest()


def write_json(path, value):
    pathlib.Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def tree_identity(root):
    root = pathlib.Path(root)
    files, aliases = {}, {}
    for directory, list_of_directories, list_of_files in os.walk(root, followlinks=False):
        for name in list_of_directories + list_of_files:
            path = pathlib.Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                aliases[relative] = os.readlink(path)
                require(path.resolve().is_relative_to(root.resolve()), "Standard-library alias must remain inside its source tree")
            elif path.is_file():
                files[relative] = sha256(path)
    data = "".join(f"{files[path]}  {path}\n" for path in sorted(files)).encode()
    return {"sha256": hashlib.sha256(data).hexdigest(), "files": files, "directory_aliases": aliases}


def verify_stdlib(identity, expected):
    require(identity["sha256"] == expected["stdlib_sha256"], "Installed standard library differs from the pinned Alpha source archive")
    require(len(identity["files"]) == expected["stdlib_file_count"], "Installed standard-library file count differs")
    require(identity["directory_aliases"] == expected["stdlib_directory_aliases"], "Installed standard-library directory aliases differ")


def verify_formula_receipt(receipt, expected):
    require(len(receipt) == 1 and receipt[0]["versions"]["stable"] == expected["source_version"], "Alpha formula source version differs")
    require(receipt[0].get("revision") == expected["formula_revision"], "Alpha formula revision differs")
    require(receipt[0]["urls"]["stable"]["checksum"] == expected["source_archive_sha256"], "Alpha formula source checksum differs")
    installed = receipt[0]["installed"]
    require(len(installed) == 1 and installed[0]["version"] == expected["installed_package_version"], "Exact pinned Alpha package installation is required")
    require(installed[0].get("poured_from_bottle") is False, "This source-build qualification requires the actual same-job build")


def literal_runtime_path(path):
    path = pathlib.Path(path)
    require(path.is_absolute() and not any(character in str(path) for character in ('"', "\\", "$", "`", "\n", "\r", ":")), "Runtime paths require literal absolute single-component library roots")
    return path


def derive_runtime_dependencies(metadata, brew_root):
    """Resolve declared required/recommended/selected-optional metadata independently."""
    brew_root = literal_runtime_path(brew_root)
    formulae = metadata["formulae"]
    require(isinstance(formulae, list) and 1 <= len(formulae) <= 256, "Bounded installed formula metadata roster required")
    by_name = {}
    for row in formulae:
        name = row["name"]
        require(re.fullmatch(r"[a-z0-9][a-z0-9+_.@-]*", name) is not None and name not in by_name, "Unique canonical installed formula names required")
        by_name[name] = row
    require("agent-crystal" in by_name, "Installed Alpha dependency root required")
    visited, active, result = set(), set(), []
    def visit(name):
        require(name in by_name and name not in active, "Installed declared runtime dependency closure requires present acyclic metadata")
        if name in visited:
            return
        active.add(name)
        row = by_name[name]
        installed = row["installed"]
        require(isinstance(installed, list) and len(installed) == 1 and isinstance(installed[0]["version"], str), "One exact installed version per selected dependency required")
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.-]*", installed[0]["version"]) is not None, "Literal installed dependency version required")
        options = installed[0].get("used_options", [])
        require(isinstance(options, list) and all(isinstance(value, str) for value in options), "Actual selected installed dependency options required")
        dependencies = list(row["dependencies"])
        for entry in row.get("uses_from_macos", []):
            if isinstance(entry, str):
                dependencies.append(entry)
            else:
                require(isinstance(entry, dict) and len(entry) == 1, "Declared Linux uses-from-macOS dependency metadata required")
                dependency_name, tags = next(iter(entry.items()))
                tags = [tags] if isinstance(tags, str) else tags
                require(isinstance(tags, list) and all(tag in ("build", "test", "recommended", "optional") for tag in tags), "Explicit uses-from-macOS dependency tags required")
                if not set(tags).intersection(("build", "test")):
                    dependencies.append(dependency_name)
        dependencies += [value for value in row.get("recommended_dependencies", []) if "--without-" + value.rsplit("/", 1)[-1] not in options]
        dependencies += [value for value in row.get("optional_dependencies", []) if "--with-" + value.rsplit("/", 1)[-1] in options]
        require(all(isinstance(value, str) and re.fullmatch(r"(?:[a-zA-Z0-9_.@+-]+/)*[a-z0-9][a-z0-9+_.@-]*", value) is not None for value in dependencies), "Literal declared runtime dependency names required")
        for dependency in sorted(set(dependencies)):
            visit(dependency.rsplit("/", 1)[-1])
        active.remove(name)
        visited.add(name)
        if name != "agent-crystal":
            result.append({"name": name, "version": installed[0]["version"], "used_options": options,
                           "opt_library": str(brew_root / "opt" / name / "lib")})
    visit("agent-crystal")
    return sorted(result, key=lambda row: row["name"])


def runtime_directory_identity(path, contained_root):
    path, contained_root = pathlib.Path(path), pathlib.Path(contained_root)
    require(path.is_dir(), "Actual runtime library directory required")
    resolved = path.resolve(strict=True)
    require(resolved.is_relative_to(contained_root.resolve(strict=True)), "Runtime library directory escaped its admitted package/prefix root")
    lexical, physical = path.lstat(), resolved.stat()
    return {"path": str(path), "contained_root": str(contained_root), "resolved_path": str(resolved),
            "symlink_target": os.readlink(path) if path.is_symlink() else None,
            "device": lexical.st_dev, "inode": lexical.st_ino, "mode": lexical.st_mode,
            "resolved_device": physical.st_dev, "resolved_inode": physical.st_ino, "resolved_mode": physical.st_mode}


def runtime_dependency_identity(metadata, prefix, brew_root):
    prefix, brew_root = literal_runtime_path(prefix), literal_runtime_path(brew_root)
    rows = derive_runtime_dependencies(metadata, brew_root)
    roots = [row for row in metadata["formulae"] if row["name"] == "agent-crystal"]
    require(len(roots) == 1 and roots[0]["installed"][0]["version"] == prefix.name and prefix.parent.name == "agent-crystal" and prefix.parent.parent.resolve(strict=True) == (brew_root / "Cellar").resolve(strict=True), "Fresh Alpha root metadata version must match the actual installed package prefix")
    paths = [str(brew_root / "lib")]
    require((brew_root / "lib").is_dir(), "Ordinary Homebrew prefix library directory required")
    prefix_library_identity = runtime_directory_identity(brew_root / "lib", brew_root)
    for row in rows:
        opt = brew_root / "opt" / row["name"]
        require(opt.is_symlink(), "Installed dependency requires its actual opt alias")
        physical = opt.resolve(strict=True)
        expected = brew_root / "Cellar" / row["name"] / row["version"]
        require(physical == expected.resolve(strict=True) and physical.is_dir(), "Installed dependency version/opt identity join required")
        row["opt_alias_target"] = os.readlink(opt)
        row["physical_prefix"] = str(physical)
        row["identities"] = []
        for path in (physical / "INSTALL_RECEIPT.json", physical / ".brew" / (row["name"] + ".rb")):
            require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 2 * 1024**2, "Bounded actual dependency receipt/formula identity required")
            row["identities"].append({"path": str(path), "bytes": path.stat().st_size, "sha256": sha256(path)})
        library = pathlib.Path(row["opt_library"])
        row["has_library_directory"] = library.is_dir()
        if row["has_library_directory"]:
            require(library.resolve(strict=True).is_relative_to(physical), "Contained actual dependency library directory required")
            row["library_path_identity"] = runtime_directory_identity(library, physical)
            paths.append(str(library))
        else:
            require(not library.exists() and not library.is_symlink(), "Absent dependency library path requires ordinary absence")
    paths = sorted(set(paths))
    manifest = prefix / "share/agent-crystal/runtime_library_paths.txt"
    require(manifest.is_file() and not manifest.is_symlink() and manifest.stat().st_size <= 64 * 1024, "Bounded ordinary installed runtime-path manifest required")
    raw = manifest.read_bytes()
    require(raw == ("\n".join(paths) + "\n").encode(), "Emitted runtime-path manifest differs from independently derived installed dependencies")
    return {"root_installed_version": prefix.name, "root_prefix": str(prefix), "prefix_library_identity": prefix_library_identity, "library_paths": paths, "manifest": {"path": str(manifest), "bytes": len(raw), "sha256": sha256(manifest)},
            "dependencies": rows, "scope": "Declared installed dependency paths and exact receipt/formula aliases; full loader closure remains separately unqualified"}


def verify_runtime_dependency_identity(value):
    prefix_library = value["prefix_library_identity"]
    require(runtime_directory_identity(prefix_library["path"], prefix_library["contained_root"]) == prefix_library, "Homebrew prefix library directory/alias identity changed")
    manifest = value["manifest"]
    path = pathlib.Path(manifest["path"])
    require(path.is_file() and not path.is_symlink() and path.stat().st_size == manifest["bytes"] and sha256(path) == manifest["sha256"], "Installed runtime manifest changed")
    for row in value["dependencies"]:
        opt = pathlib.Path(row["opt_library"]).parent
        require(opt.is_symlink() and os.readlink(opt) == row["opt_alias_target"] and str(opt.resolve(strict=True)) == row["physical_prefix"], "Installed dependency opt alias changed")
        library = pathlib.Path(row["opt_library"])
        require(library.is_dir() is row["has_library_directory"], "Installed dependency library presence changed")
        if row["has_library_directory"]:
            identity = runtime_directory_identity(library, pathlib.Path(row["physical_prefix"]))
            require(identity == row["library_path_identity"], "Installed dependency library path/alias identity changed")
        else:
            require(not library.exists() and not library.is_symlink(), "Absent dependency library path changed")
        for identity in row["identities"]:
            path = pathlib.Path(identity["path"])
            require(path.is_file() and not path.is_symlink() and path.stat().st_size == identity["bytes"] and sha256(path) == identity["sha256"], "Installed dependency receipt/formula changed")


def collect_runtime_dependency_identity(runner, brew, prefix, brew_root, output, cwd, environment=None):
    text, errors = runner.run("runtime-dependency-metadata", [brew, "info", "--json=v2", "--installed"], cwd=cwd, environment=environment, seconds=45)
    require(not errors, "Installed dependency metadata stderr requires review")
    value = runtime_dependency_identity(json.loads(text), prefix, brew_root)
    write_json(output / "RUNTIME_LIBRARY_PATHS.json", value)
    return value


def verify_wrapper(wrapper, compiler, stdlib, homebrew_prefix, system, runtime_identity=None):
    require(system in ("Linux", "Darwin"), "Wrapper platform requires a reviewed template")
    for path in (compiler, stdlib, homebrew_prefix):
        require(path.is_absolute() and not any(character in str(path) for character in ('"', "\\", "$", "`", "\n", "\r")),
                "Wrapper source requires literal absolute Homebrew paths")
    parts = [re.escape('CRYSTAL_PATH="lib:' + str(stdlib) + '"')]
    if system == "Linux":
        if callable(runtime_identity):
            runtime_identity = runtime_identity()
        require(compiler.parent.parent.name != "1.21.0-incremental-1_2" or runtime_identity is not None, "Qualified revision2 Linux wrapper requires independently verified runtime identity")
        if runtime_identity is not None:
            verify_runtime_dependency_identity(runtime_identity)
        paths = runtime_identity["library_paths"] if runtime_identity is not None else [str(homebrew_prefix / "lib")]
        require(paths == sorted(set(paths)) and paths and str(homebrew_prefix / "lib") in paths, "Exact canonical runtime library path roster required")
        for path in paths:
            literal_runtime_path(path)
        parts.append(re.escape('LD_RUN_PATH="${LD_RUN_PATH:+${LD_RUN_PATH}:}' + ":".join(paths) + '"'))
    parts.extend(["exec", re.escape('"' + str(compiler) + '"'), re.escape('"$@"')])
    pattern = r"\A#!/bin/bash\n" + r"[ \t]+".join(parts) + r"[ \t]*\n\Z"
    require(re.fullmatch(pattern, wrapper) is not None,
            "Alpha wrapper must match the exact static Homebrew Bash environment and argv template")


def installed_alias_identity(entrypoint, physical):
    entrypoint, physical = pathlib.Path(entrypoint).absolute(), pathlib.Path(physical)
    require(entrypoint.is_file() and entrypoint.resolve(strict=True) == physical and physical.is_file() and not physical.is_symlink(), "Ordinary public alias requires the exact installed physical wrapper")
    return {"path": str(physical), "sha256": sha256(physical), "entrypoint": str(entrypoint),
            "entrypoint_resolved": str(entrypoint.resolve(strict=True)), "entrypoint_symlink_target": os.readlink(entrypoint) if entrypoint.is_symlink() else None}


def verify_installed_alias_identity(value):
    require(installed_alias_identity(value["entrypoint"], pathlib.Path(value["path"])) == value, "Ordinary public alias resolution or installed wrapper changed")


def retain_failed_spec_binaries(private, output, writers_confirmed_retired):
    observed = []
    if writers_confirmed_retired is not True:
        return {"retained": observed, "scope": "Original writers remain alive or unverifiable; private evidence preserved under existing return policy"}
    for label in ("default-specs", "without-mt-specs"):
        binary = private / label / "cache/crystal-run-spec.tmp"
        if binary.exists() or binary.is_symlink():
            require(binary.is_file() and not binary.is_symlink() and binary.stat().st_size <= 20 * 1024**2, "Bounded ordinary failed-spec ELF retention required")
            destination = output / (label + "-failed-spec.bin")
            before = sha256(binary)
            shutil.copyfile(binary, destination)
            require(sha256(binary) == before == sha256(destination), "Exact stable returned failed-spec binary snapshot required")
            observed.append({"label": label, "path": destination.name, "sha256": before, "bytes": destination.stat().st_size})
    return {"retained": observed, "scope": "Bounded failed same-job SDK spec ELF after verified original-group return; actual link-selection remains for independent metadata replay"}


CRYPTO_CONSUMER = b'require "openssl"\n\ndigest = OpenSSL::Digest.new("SHA256")\ndigest.update("atlas-runtime")\nSTDOUT << digest.hexfinal << "\\n"\n'
CRYPTO_EXPECTED = hashlib.sha256(b"atlas-runtime").hexdigest() + "\n"


def exercise_crypto_consumer(runner, wrapper, private, output, environment):
    source, binary = private / "crypto_consumer.cr", private / "crypto_consumer"
    source.write_bytes(CRYPTO_CONSUMER)
    (output / "CRYPTO_CONSUMER.cr").write_bytes(CRYPTO_CONSUMER)
    readelf = pathlib.Path(shutil.which("readelf") or "").resolve(strict=True)
    require(readelf.is_file(), "Ordinary Linux ELF metadata provider required")
    readelf_identity = {"path": str(readelf), "sha256": sha256(readelf), "bytes": readelf.stat().st_size}
    observed = {"passed": False, "source_sha256": sha256(source), "readelf": readelf_identity,
                "actual_project_api_lookup_qualified": False, "api_lookup_scope": "Exact pinned source signatures documented in the source receipt; actual-project Amber LSP provider/lookup remains a separate gate",
                "scope": "Ordinary installed wrapper builds and executes one OpenSSL SHA256 consumer; emitted ELF retained, complete loader closure remains separate"}
    original_error = None
    retention_error = None
    try:
        runner.run("crypto-consumer-format", [wrapper, "tool", "format", "--check", "--no-color", source], cwd=private, environment=environment, seconds=15)
        stdout, errors = runner.run("crypto-consumer-build", [wrapper, "build", "--no-color", "--error-on-warnings", "-Dwithout_mt", "--threads", "1", source, "-o", binary],
                                    cwd=private, environment=dict(environment, CRYSTAL_CACHE_DIR=str(private / "crypto-cache")), seconds=120)
        require(not stdout and not errors, "Cryptographic consumer compilation requires GREEN")
        require(binary.is_file() and not binary.is_symlink() and binary.stat().st_size <= 20 * 1024**2, "Bounded ordinary cryptographic consumer ELF required")
        before = sha256(binary)
        runner.run("crypto-consumer-elf", [readelf, "-W", "-d", "-l", binary], cwd=private, environment=environment, seconds=10)
        stdout, errors = runner.run("crypto-consumer-runtime", [binary], cwd=private, environment=environment, seconds=10)
        require(stdout == CRYPTO_EXPECTED and not errors, "Exact ordinary OpenSSL SHA256 behavior required")
        require(sha256(binary) == before and sha256(source) == observed["source_sha256"] and sha256(readelf) == readelf_identity["sha256"], "Cryptographic source/binary/ELF metadata provider changed")
        observed.update(passed=True, binary_sha256=before)
    except Exception as error:
        observed["error"] = f"{type(error).__name__}: {error}"
        original_error = error
    finally:
        try:
            if binary.exists() or binary.is_symlink():
                require(runner.writers_confirmed_retired is True, "Crypto binary retention requires confirmed original writer retirement")
                require(binary.is_file() and not binary.is_symlink() and binary.stat().st_size <= 20 * 1024**2, "Bounded ordinary crypto binary retention required")
                before = sha256(binary)
                shutil.copyfile(binary, output / "CRYPTO_CONSUMER.bin")
                require(sha256(binary) == before == sha256(output / "CRYPTO_CONSUMER.bin"), "Exact stable returned cryptographic binary snapshot required")
                observed["retained_binary"] = {"sha256": before, "bytes": binary.stat().st_size}
        except Exception as error:
            observed["retention_error"] = f"{type(error).__name__}: {error}"
            observed["passed"] = False
            retention_error = error
        write_json(output / "CRYPTO_CONSUMER.json", observed)
    if original_error is not None:
        raise original_error
    if retention_error is not None:
        raise retention_error


def extract_sdk(archive_path, destination, expected):
    require(sha256(archive_path) == expected["archive_sha256"], "SDK archive SHA-256 mismatch")
    require(pathlib.Path(archive_path).stat().st_size == expected["archive_bytes"], "SDK archive size mismatch")
    prefix = "memory_budget-" + expected["commit"] + "/"
    roster = {row["file"]: row for row in expected["files"]}
    require(len(roster) == len(expected["files"]), "SDK source requires unique paths")
    seen = set()
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            require(member.name.startswith(prefix) or member.name == prefix[:-1], "SDK archive prefix mismatch")
            if member.isdir():
                continue
            relative = member.name[len(prefix):]
            require(relative in roster and relative not in seen and member.isfile(), "SDK archive member roster mismatch")
            parts = pathlib.PurePosixPath(relative).parts
            require(parts and all(part not in (".", "..", "") for part in parts) and not relative.startswith("/"), "SDK member requires a relative source path")
            row = roster[relative]
            require(member.size == row["bytes"], "SDK source size mismatch")
            require(("100755" if member.mode & 0o111 else "100644") == row["mode"], "SDK source mode mismatch")
            data = archive.extractfile(member).read(row["bytes"] + 1)
            require(hashlib.sha256(data).hexdigest() == row["sha256"], "SDK source SHA-256 mismatch")
            require(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == row["git_blob"], "SDK source Git object mismatch")
            target = pathlib.Path(destination) / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o755 if row["mode"] == "100755" else 0o644)
            seen.add(relative)
    require(seen == set(roster), "SDK archive source coverage differs")


def verify_source(root, rows):
    expected = {row["file"]: row["sha256"] for row in rows}
    actual = tree_identity(root)
    require(actual["files"] == expected and actual["directory_aliases"] == {}, "SDK source changed during qualification")


def verify_bundle(root):
    manifest = json.loads((root / "PACKAGE_PINS.json").read_text())
    expected = {row["file"]: row["sha256"] for row in manifest["files"]}
    require(len(expected) == len(manifest["files"]) == 67, "SDK bundle requires its exact 67-member manifest")
    expected["PACKAGE_PINS.json"] = sha256(root / "PACKAGE_PINS.json")
    actual = tree_identity(root)
    require(actual["files"] == expected and actual["directory_aliases"] == {}, "Installed SDK bundle identity differs")
    return actual


def verify_spec_result(stdout, stderr, expected_count, expected_failures=0):
    text = re.sub(r"\x1b\[[0-9;]*m", "", stdout)
    pattern = r"(?m)^(\d+) examples?, (\d+) failures?, (\d+) errors?(?:, (\d+) pending)?\s*$"
    summaries = [tuple(int(value or 0) for value in row) for row in re.findall(pattern, text)]
    require(summaries == [(expected_count, expected_failures, 0, 0)], "Actual spec summary differs from the required behavior")
    require(not re.search(r"(?im)\bwarning(?:s)?\b", stdout + stderr), "Compiler/spec output is YELLOW: warning observed")
    require(not stderr.strip(), "Compiler/spec stderr requires review")
    if expected_failures:
        require(all(value in text for value in ("construct_record", "crystal_allocation_calls", "crystal_requested_bytes")), "Regression must fail its actual allocation expectation")


class Runner:
    GROUP_DRAIN_SECONDS = 5.0
    GROUP_POLL_SECONDS = 0.05
    MAXIMUM_GROUP_SAMPLES = 128

    def __init__(self, output):
        self.output = output
        self.records = []
        self.group_observations = []
        self.writers_confirmed_retired = True
        self.deadline = time.monotonic() + 840

    def observe_group(self, group, command_deadline, stream_paths=()):
        started = time.monotonic()
        deadline = min(command_deadline, self.deadline, started + self.GROUP_DRAIN_SECONDS)
        observation = {"group": group, "phase": "direct_child_returned", "status": "unverifiable",
            "scope": "original POSIX process group", "maximum_drain_seconds": self.GROUP_DRAIN_SECONDS,
            "original_command_deadline": command_deadline, "drain_deadline": deadline, "samples": []}
        for _ in range(self.MAXIMUM_GROUP_SAMPLES):
            sample = {"elapsed_seconds": max(0, time.monotonic() - started)}
            try:
                os.killpg(group, 0)
                sample["status"] = "present"
            except ProcessLookupError:
                sample["status"] = "absent"
            except OSError as error:
                sample.update(status="unverifiable", error=f"{type(error).__name__}: {error}")
            observation["samples"].append(sample)
            observation["status"] = sample["status"]
            if "error" in sample:
                observation["error"] = sample["error"]
            if stream_paths and sum(path.stat().st_size for path in stream_paths) > 4 * 1024 * 1024:
                observation["raw_output_budget_exceeded"] = True
                break
            if sample["status"] != "present":
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(self.GROUP_POLL_SECONDS, remaining))
        observation["elapsed_seconds"] = max(0, time.monotonic() - started)
        observation["initial_sample"] = dict(observation["samples"][0])
        observation["terminal_sample"] = dict(observation["samples"][-1])
        observation["bounded_drain_exhausted"] = observation["status"] == "present"
        return observation

    def group_diagnostics(self, group, code, observation, command_deadline):
        """Record finite identities/states; absence qualification uses signal zero."""
        result = {"group": group, "direct_child_pid": group, "direct_child_exit_code": code,
            "last_group_status": observation["status"], "member_rows": [],
            "maximum_member_rows": 64, "maximum_scanned_entries": 4096,
            "scope": "non-secret original-group metadata; original-group absence is a separate gate"}
        deadline = min(command_deadline, self.deadline, time.monotonic() + 0.15)
        if platform.system() != "Linux":
            result["member_observation"] = "Linux proc metadata applies to the Ubuntu case; aggregate group state is retained on this platform"
            return result
        if time.monotonic() >= deadline:
            result["member_observation"] = "original command deadline reached"
            return result
        scanned, vanished = 0, 0
        result["member_observation"] = "bounded Linux proc identity/state read"
        try:
            with os.scandir("/proc") as entries:
                for entry in entries:
                    scanned += 1
                    if scanned > 4096 or time.monotonic() >= deadline:
                        result["truncated"] = True
                        break
                    if not entry.name.isdecimal():
                        continue
                    try:
                        directory = pathlib.Path("/proc") / entry.name
                        with (directory / "stat").open("rb") as stream:
                            raw = stream.read(16385)
                        require(len(raw) <= 16384, "Bounded process-stat metadata required")
                        fields = raw.rsplit(b")", 1)[1].split()
                        require(len(fields) >= 20, "Complete process identity metadata required")
                        if int(fields[2]) != group:
                            continue
                        require(re.fullmatch(rb"[A-Za-z]", fields[0]) is not None, "One process-state code required")
                        result["member_rows"].append({"pid": int(entry.name), "ppid": int(fields[1]),
                            "pgid": int(fields[2]), "sid": int(fields[3]), "uid": directory.stat().st_uid,
                            "state": fields[0].decode("ascii"), "start_ticks": int(fields[19])})
                        if len(result["member_rows"]) >= 64:
                            result["truncated"] = True
                            break
                    except (OSError, ValueError, IndexError, QualificationError):
                        vanished += 1
        except OSError as error:
            result["diagnostic_error"] = f"{type(error).__name__}: {error}"
        result.update(scanned_entries=min(scanned, 4096), unavailable_or_changed_entries=vanished)
        return result

    def run(self, label, arguments, *, cwd, environment=None, expected_exit=0, seconds=300):
        stdout_path = self.output / (label + ".stdout.txt")
        stderr_path = self.output / (label + ".stderr.txt")
        started = time.monotonic()
        seconds = min(seconds, self.deadline - started)
        require(seconds >= 1, "SDK step exhausted its complete time budget")
        command_deadline = started + seconds
        process = None
        reason = None
        def refuse(message):
            nonlocal reason
            if reason and message in reason.split("; "):
                return
            reason = reason + "; " + message if reason else message
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            self.writers_confirmed_retired = False
            process = subprocess.Popen([str(arg) for arg in arguments], cwd=cwd, env=environment,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            group_observation = {"group": process.pid, "status": "unverifiable", "phase": "started"}
            self.group_observations.append(group_observation)
            while process.poll() is None:
                if time.monotonic() > command_deadline:
                    refuse("Command exceeded its time budget")
                if stdout_path.stat().st_size + stderr_path.stat().st_size > 4 * 1024 * 1024:
                    refuse("Command exceeded its raw-output budget")
                if reason:
                    os.killpg(process.pid, signal.SIGKILL)
                    break
                time.sleep(0.1)
            code = process.wait(timeout=10)
            group_observation.update(self.observe_group(process.pid, command_deadline, (stdout_path, stderr_path)))
            self.writers_confirmed_retired = group_observation["status"] == "absent"
            if not self.writers_confirmed_retired:
                refuse("Original owned process group is " + group_observation["status"])
                try:
                    group_observation["diagnostics"] = self.group_diagnostics(process.pid, code, group_observation, command_deadline)
                except Exception as diagnostic_error:
                    group_observation["diagnostics"] = {"group": process.pid,
                        "diagnostic_error": f"{type(diagnostic_error).__name__}: {diagnostic_error}"}
            if time.monotonic() > command_deadline:
                refuse("Command exceeded its time budget")
        if stdout_path.stat().st_size + stderr_path.stat().st_size > 4 * 1024 * 1024:
            refuse("Command exceeded its raw-output budget")
        record = {"label": label, "arguments": [str(arg) for arg in arguments],
                  "pid": process.pid, "exit_code": code, "expected_exit": expected_exit,
                  "elapsed_seconds": time.monotonic() - started, "refusal": reason,
                  "maximum_seconds": seconds,
                  "original_group": process.pid, "terminal_group_observation": dict(group_observation),
                  "writers_confirmed_retired": self.writers_confirmed_retired,
                  "stdout_sha256": sha256(stdout_path) if self.writers_confirmed_retired else None,
                  "stderr_sha256": sha256(stderr_path) if self.writers_confirmed_retired else None}
        self.records.append(record)
        write_json(self.output / "COMMANDS.json", self.records)
        require(reason is None, reason)
        require(code == expected_exit, f"{label} exited {code}; expected {expected_exit}")
        return stdout_path.read_text(), stderr_path.read_text()


def make_readiness_runner(output):
    """Bound this SDK roster while delegating each command to the exact reviewed Runner."""
    runner = Runner(output)
    runner.maximum_command_count = 16 if platform.system() == "Linux" else 11
    original_run = runner.run
    def bounded_run(*arguments, **settings):
        require(len(runner.records) < runner.maximum_command_count, "SDK exceeded its finite original/new command roster")
        return original_run(*arguments, **settings)
    runner.run = bounded_run
    return runner


def qualify(output, lock):
    output.mkdir(parents=True, exist_ok=False)
    runner = make_readiness_runner(output)
    result = {"passed": False, "scope": lock["scope"], "sdk_commit": lock["sdk"]["commit"],
              "full_native_provider_acceptance": False, "frozen_dependency_installation_accepted": False,
              "customer_device_accepted": False, "compiler_color": "UNEXECUTED",
              "owned_group_observation_scope": "original POSIX process group",
              "actual_group_recovery_qualified": False, "detached_session_coverage_qualified": False}
    private = None
    runtime_identity = None
    package_inputs = {}
    linux_aliases = {}
    try:
        require(platform.system() in lock["alpha"]["full_versions"], "Runner platform requires a reviewed expectation")
        require(shutil.disk_usage(output).free >= 13 * 1024**3, "SDK readiness requires 3 GiB projection plus a 10 GiB disk floor")
        private = pathlib.Path(tempfile.mkdtemp(prefix="alpha-sdk-readiness-"))
        shutil.copyfile(pathlib.Path(__file__).with_name("sdk_source_lock.json"), output / "SOURCE_LOCK.json")
        write_json(output / "RUNNER.json", {"system": platform.system(), "machine": platform.machine(),
                   "release": platform.release(), "image_os": os.environ.get("ImageOS"),
                   "image_version": os.environ.get("ImageVersion"), "run_id": os.environ.get("GITHUB_RUN_ID"),
                   "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"), "source_commit": os.environ.get("GITHUB_SHA"),
                   "python_path": sys.executable, "python_sha256": sha256(pathlib.Path(sys.executable).resolve()),
                   "qualification_script_sha256": sha256(__file__),
                   "source_lock_sha256": sha256(pathlib.Path(__file__).with_name("sdk_source_lock.json")),
                   "private_directory": str(private)})
        archive_path = output / "sdk-source.tar.gz"
        with urllib.request.urlopen(lock["sdk"]["url"], timeout=45) as response:
            data = response.read(lock["sdk"]["archive_bytes"] + 1)
        archive_path.write_bytes(data)
        source = private / "public SDK source"
        extract_sdk(archive_path, source, lock["sdk"])
        verify_source(source, lock["sdk"]["files"])
        repository = pathlib.Path(__file__).resolve().parent.parent
        require(sha256(repository / "Formula/agent-crystal.rb") == lock["alpha"]["formula_sha256"], "Alpha formula differs from its accepted source")
        brew = shutil.which("brew")
        require(brew is not None, "Ordinary Homebrew installation is required")
        prefix_text, _ = runner.run("brew-prefix", [brew, "--prefix", "agent-crystal"], cwd=source, seconds=45)
        prefix = pathlib.Path(prefix_text.strip()).resolve()
        brew_root_text, _ = runner.run("brew-root", [brew, "--prefix"], cwd=source, seconds=45)
        brew_root = pathlib.Path(brew_root_text.strip()).resolve()
        receipt_text, _ = runner.run("brew-receipt", [brew, "info", "--json=v2", "agent-crystal"], cwd=source, seconds=45)
        receipt = json.loads(receipt_text)["formulae"]
        verify_formula_receipt(receipt, lock["alpha"])
        require(sha256(prefix / ".brew/agent-crystal.rb") == lock["alpha"]["formula_sha256"], "Installed formula source differs")
        shutil.copyfile(prefix / ".brew/agent-crystal.rb", output / "INSTALLED_FORMULA.rb")
        shutil.copyfile(prefix / "INSTALL_RECEIPT.json", output / "INSTALL_RECEIPT.json")
        package_inputs = {str(path): sha256(path) for path in (repository / "Formula/agent-crystal.rb", prefix / ".brew/agent-crystal.rb", prefix / "INSTALL_RECEIPT.json", pathlib.Path(__file__), pathlib.Path(__file__).with_name("sdk_source_lock.json"))}
        write_json(output / "PACKAGE_INPUTS_BEFORE.json", package_inputs)
        compiler = prefix / "libexec/agent-crystal-bin"
        entrypoint = pathlib.Path(shutil.which("crystal-alpha") or "").resolve()
        require(entrypoint == prefix / "bin/crystal-alpha", "crystal-alpha must select this ordinary formula installation")
        wrapper = entrypoint.read_text()
        (output / "COMPILER_WRAPPER.sh").write_text(wrapper)
        stdlib = prefix / "share/agent-crystal/src"
        if platform.system() == "Linux":
            runtime_identity = collect_runtime_dependency_identity(runner, brew, prefix, brew_root, output, source)
        verify_wrapper(wrapper, compiler, stdlib, brew_root, platform.system(), runtime_identity)
        linux_aliases = {}
        if runtime_identity is not None:
            for alias in ("acrystal", "agent-crystal", "crystal-alpha"):
                alias_path = prefix / "bin" / alias
                alias_entrypoint = pathlib.Path(shutil.which(alias) or "").absolute()
                require(alias_entrypoint.resolve(strict=True) == alias_path, "Every Linux alias must select the same ordinary formula")
                verify_wrapper(alias_path.read_text(), compiler, stdlib, brew_root, "Linux", runtime_identity)
                linux_aliases[alias] = installed_alias_identity(alias_entrypoint, alias_path)
                (output / (alias + "-wrapper.sh")).write_bytes(alias_path.read_bytes())
            write_json(output / "LINUX_ALIAS_WRAPPERS.json", linux_aliases)
        stdlib_identity = tree_identity(stdlib)
        write_json(output / "STDLIB_BEFORE.json", stdlib_identity)
        verify_stdlib(stdlib_identity, lock["alpha"])
        compiler_version, compiler_errors = runner.run("alpha-version", [entrypoint, "--version"], cwd=source, seconds=30)
        require(compiler_version == lock["alpha"]["full_versions"][platform.system()] and not compiler_errors, "Actual Alpha full version differs")
        ruby_launcher = pathlib.Path(shutil.which("ruby") or "").resolve()
        require(ruby_launcher.is_file(), "Runner Ruby is required")
        ruby_text, ruby_errors = runner.run("ruby-identity", [ruby_launcher, "-rjson", "-rrbconfig", "-e",
            'puts JSON.generate({"path" => File.realpath(RbConfig.ruby), "version" => RUBY_DESCRIPTION})'], cwd=source, seconds=30)
        require(not ruby_errors, "Ruby identity stderr requires review")
        ruby_identity = json.loads(ruby_text)
        ruby_backend = pathlib.Path(ruby_identity["path"])
        profile = {"schema_version": 1, "profile": "ordinary-alpha-sdk-readiness-" + platform.system().lower(),
                   "counter_protocol": 1, "compiler_sha256": sha256(compiler), "wrapper_sha256": sha256(entrypoint),
                   "stdlib_sha256": lock["alpha"]["stdlib_sha256"], "ruby_sha256": sha256(ruby_backend),
                   "ruby_launcher_sha256": sha256(ruby_launcher)}
        profile_path = output / "REVIEWED_COMPILER_PROFILE.json"
        write_json(profile_path, profile)
        write_json(output / "PROVIDER_IDENTITIES.json", {
            key: {"path": str(path), "bytes": path.stat().st_size, "sha256": sha256(path)}
            for key, path in (("compiler_backend", compiler), ("compiler_wrapper", entrypoint),
                              ("ruby_backend", ruby_backend), ("ruby_launcher", ruby_launcher))})
        write_json(output / "PROFILE_DERIVATION.json", {
            "policy": "Exact formula source/version/checksum, same-job ordinary install, independently source-derived complete stdlib and alias expectations, static wrapper/backend binding, immutable observed backend/Ruby hashes.",
            "alpha_source_commit": lock["alpha"]["source_commit"], "ruby": ruby_identity,
            "profile_sha256": sha256(profile_path), "profile_schema": 1,
            "qualified_scope": "Compiler, standard library, package/spec/tutorial readiness",
            "native_git_and_frozen_install_scope": "Pending separate schema-3 qualification"})
        environment = {key: value for key, value in os.environ.items() if key in ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SDKROOT", "DEVELOPER_DIR")}
        environment.update({"MEMORY_BUDGET_COMPILER": str(entrypoint), "MEMORY_BUDGET_STDLIB": str(stdlib),
                            "MEMORY_BUDGET_RUBY_LAUNCHER": str(ruby_launcher),
                            "MEMORY_BUDGET_TOOLCHAIN_LOCK": str(profile_path),
                            "MEMORY_BUDGET_TOOLCHAIN_PROFILE_SHA256": sha256(profile_path),
                            "CRYSTAL_WORKERS": "1", "NO_COLOR": "1"})
        consumer = private / "ordinary consumer with spaces"
        runner.run("install-bundle", [ruby_launcher, source / "scripts/install_bundle.rb", consumer], cwd=source, environment=environment, seconds=30)
        bundle = consumer / "performance/vendor/memory_budget"
        installed = verify_bundle(bundle)
        require(sha256(bundle / "PACKAGE_PINS.json") == sha256(source / "PACKAGE_PINS.json"), "Installed manifest differs from the pinned public source")
        write_json(output / "INSTALLED_BUNDLE_BEFORE.json", installed)
        if platform.system() == "Linux":
            exercise_crypto_consumer(runner, entrypoint, private, output, environment)
        for label, flags in (("default-specs", []), ("without-mt-specs", ["-Dwithout_mt"])):
            environment["CRYSTAL_CACHE_DIR"] = str(private / label / "cache")
            stdout, stderr = runner.run(label, [ruby_launcher, bundle / "scripts/budget.rb", "spec", "-Dfiber_allocation_tally", *flags],
                                        cwd=source, environment=environment, seconds=300)
            verify_spec_result(stdout, stderr, 39)
        environment["CRYSTAL_CACHE_DIR"] = str(private / "tutorial/cache")
        binary = private / "fiber-budget-example"
        compile_output, errors = runner.run("tutorial-build", [ruby_launcher, bundle / "scripts/budget.rb", "build", "docs/0.1.1/examples/fiber_budget_spec.cr",
                                                  "-Dfiber_allocation_tally", "-o", binary], cwd=bundle, environment=environment, seconds=300)
        require(not errors.strip(), "Tutorial compile stderr requires review")
        require(not re.search(r"(?im)\bwarning(?:s)?\b", compile_output + errors), "Tutorial compiler output is YELLOW")
        binary_digest = sha256(binary)
        normal, errors = runner.run("tutorial-normal", [binary], cwd=bundle, environment=environment, seconds=30)
        verify_spec_result(normal, errors, 1)
        records = [line.split("=", 1)[1] for line in normal.splitlines() if line.startswith("MEMORY_BUDGET_OBSERVATION_JSON=")]
        require(len(records) == 1, "Tutorial requires one actual measurement verdict")
        observation = json.loads(records[0])
        require(observation["scenario_name"] == "construct_record" and observation["verdict_status"] == "passed" and observation["list_of_violations"] == [], "Tutorial actual memory verdict differs")
        write_json(output / "TUTORIAL_OBSERVATION.json", observation)
        regression, errors = runner.run("tutorial-regression", [binary], cwd=bundle,
                                       environment={**environment, "MEMORY_BUDGET_INJECT_REGRESSION": "1"}, expected_exit=1, seconds=30)
        verify_spec_result(regression, errors, 1, 1)
        require(sha256(binary) == binary_digest, "Both tutorial controls require the same executable")
        require(sha256(compiler) == profile["compiler_sha256"] and sha256(entrypoint) == profile["wrapper_sha256"], "Alpha compiler changed during execution")
        require(sha256(ruby_backend) == profile["ruby_sha256"] and sha256(ruby_launcher) == profile["ruby_launcher_sha256"], "Ruby provider changed during execution")
        for path, expected in package_inputs.items():
            require(sha256(path) == expected, "Installed package/formula/qualifier/source-lock inputs changed")
        write_json(output / "PACKAGE_INPUTS_AFTER.json", {path: sha256(path) for path in package_inputs})
        verify_source(source, lock["sdk"]["files"])
        require(verify_bundle(bundle) == installed, "SDK bundle changed during execution")
        if runtime_identity is not None:
            verify_runtime_dependency_identity(runtime_identity)
            for alias in linux_aliases.values():
                verify_installed_alias_identity(alias)
        after = tree_identity(stdlib)
        write_json(output / "STDLIB_AFTER.json", after)
        verify_stdlib(after, lock["alpha"])
        require(after == stdlib_identity, "Alpha standard library changed during execution")
        result.update({"passed": True, "compiler_color": "GREEN", "default_examples": 39,
                       "without_mt_examples": 39, "tutorial_normal_exit": 0, "tutorial_regression_exit": 1,
                       "tutorial_binary_sha256": binary_digest, "installed_bundle_files": 68})
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        result["private_directory"] = str(private) if private is not None else None
        result["owned_group_observations"] = runner.group_observations
        result["writers_confirmed_retired"] = runner.writers_confirmed_retired
        finalization_errors = []
        final_package_inputs = {}
        for path, expected in package_inputs.items():
            try:
                observed = sha256(path)
                final_package_inputs[path] = observed
                require(observed == expected, "Installed package/formula/qualifier/source-lock inputs changed")
            except Exception as error:
                finalization_errors.append(f"Package {path}: {type(error).__name__}: {error}")
        if package_inputs:
            write_json(output / "PACKAGE_INPUTS_AFTER.json", final_package_inputs)
        if runtime_identity is not None:
            try:
                verify_runtime_dependency_identity(runtime_identity)
            except Exception as error:
                finalization_errors.append(f"Runtime identity: {type(error).__name__}: {error}")
        for alias in linux_aliases.values():
            try:
                verify_installed_alias_identity(alias)
            except Exception as error:
                finalization_errors.append(f"Alias {alias['path']}: {type(error).__name__}: {error}")
        result["finalization_errors"] = finalization_errors
        if finalization_errors:
            result["passed"] = False
        try:
            if private is not None and result.get("passed") is not True:
                try:
                    result["failed_spec_binary_evidence"] = retain_failed_spec_binaries(private, output, runner.writers_confirmed_retired)
                except Exception as retention_error:
                    result["failed_spec_binary_retention_error"] = f"{type(retention_error).__name__}: {retention_error}"
            if private is not None and not runner.writers_confirmed_retired:
                result["private_cache_removed"] = False
                result["private_cache_preserved"] = True
                result["cleanup_error"] = "Private source and cache remain preserved for an alive or unverifiable command group"
            elif private is not None:
                shutil.rmtree(private)
                result["private_cache_removed"] = not private.exists()
            else:
                result["private_cache_removed"] = True
        except Exception as cleanup_error:
            result["private_cache_removed"] = False
            result["cleanup_error"] = f"{type(cleanup_error).__name__}: {cleanup_error}"
        finally:
            if result.get("private_cache_removed") is not True:
                result["passed"] = False
                result.setdefault("cleanup_error", "Private source and cache removal remains incomplete")
            result["command_count"] = len(runner.records)
            result["maximum_command_count"] = runner.maximum_command_count
            result["maximum_seconds"] = 840
            result["terminal_elapsed_seconds"] = time.monotonic() - (runner.deadline - 840)
            if result["terminal_elapsed_seconds"] > 840:
                result["passed"] = False
                result["finalization_errors"].append("Complete SDK terminal time budget exceeded")
            write_json(output / "READINESS_RESULT.json", result)
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    source_lock = pathlib.Path(__file__).with_name("sdk_source_lock.json")
    sys.exit(qualify(arguments.output.resolve(), json.loads(source_lock.read_text())))
