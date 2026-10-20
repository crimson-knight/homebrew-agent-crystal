#!/usr/bin/env python3
"""Exercise the public SDK against this job's ordinary Alpha installation."""

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shlex
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
    require(len(receipt) == 1 and receipt[0]["versions"]["stable"] == expected["version"], "Alpha formula version differs")
    require(receipt[0]["urls"]["stable"]["checksum"] == expected["source_archive_sha256"], "Alpha formula source checksum differs")
    installed = receipt[0]["installed"]
    require(len(installed) == 1 and installed[0]["version"] == expected["version"], "Exact pinned Alpha installation is required")
    require(installed[0].get("poured_from_bottle") is False, "This source-build qualification requires the actual same-job build")


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
    def __init__(self, output):
        self.output = output
        self.records = []
        self.deadline = time.monotonic() + 840

    def run(self, label, arguments, *, cwd, environment=None, expected_exit=0, seconds=300):
        stdout_path = self.output / (label + ".stdout.txt")
        stderr_path = self.output / (label + ".stderr.txt")
        started = time.monotonic()
        seconds = min(seconds, self.deadline - started)
        require(seconds >= 1, "SDK step exhausted its complete time budget")
        process = None
        reason = None
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            process = subprocess.Popen([str(arg) for arg in arguments], cwd=cwd, env=environment,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            while process.poll() is None:
                if time.monotonic() - started > seconds:
                    reason = "Command exceeded its time budget"
                if stdout_path.stat().st_size + stderr_path.stat().st_size > 4 * 1024 * 1024:
                    reason = "Command exceeded its raw-output budget"
                if reason:
                    os.killpg(process.pid, signal.SIGKILL)
                    break
                time.sleep(0.1)
            code = process.wait(timeout=10)
        if stdout_path.stat().st_size + stderr_path.stat().st_size > 4 * 1024 * 1024:
            reason = "Command exceeded its raw-output budget"
        record = {"label": label, "arguments": [str(arg) for arg in arguments],
                  "pid": process.pid, "exit_code": code, "expected_exit": expected_exit,
                  "elapsed_seconds": time.monotonic() - started, "refusal": reason,
                  "stdout_sha256": sha256(stdout_path), "stderr_sha256": sha256(stderr_path)}
        self.records.append(record)
        write_json(self.output / "COMMANDS.json", self.records)
        require(reason is None, reason)
        require(code == expected_exit, f"{label} exited {code}; expected {expected_exit}")
        return stdout_path.read_text(), stderr_path.read_text()


def qualify(output, lock):
    output.mkdir(parents=True, exist_ok=False)
    runner = Runner(output)
    result = {"passed": False, "scope": lock["scope"], "sdk_commit": lock["sdk"]["commit"],
              "full_native_provider_acceptance": False, "frozen_dependency_installation_accepted": False,
              "customer_device_accepted": False, "compiler_color": "UNEXECUTED"}
    private = None
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
        receipt_text, _ = runner.run("brew-receipt", [brew, "info", "--json=v2", "agent-crystal"], cwd=source, seconds=45)
        receipt = json.loads(receipt_text)["formulae"]
        verify_formula_receipt(receipt, lock["alpha"])
        require(sha256(prefix / ".brew/agent-crystal.rb") == lock["alpha"]["formula_sha256"], "Installed formula source differs")
        shutil.copyfile(prefix / ".brew/agent-crystal.rb", output / "INSTALLED_FORMULA.rb")
        shutil.copyfile(prefix / "INSTALL_RECEIPT.json", output / "INSTALL_RECEIPT.json")
        compiler = prefix / "libexec/agent-crystal-bin"
        entrypoint = pathlib.Path(shutil.which("crystal-alpha") or "").resolve()
        require(entrypoint == prefix / "bin/crystal-alpha", "crystal-alpha must select this ordinary formula installation")
        wrapper = entrypoint.read_text()
        (output / "COMPILER_WRAPPER.sh").write_text(wrapper)
        commands = [shlex.split(line) for line in wrapper.splitlines() if line.lstrip().startswith("exec ")]
        require(commands == [["exec", str(compiler), "$@"]], "Alpha wrapper/backend binding differs")
        stdlib = prefix / "share/agent-crystal/src"
        stdlib_identity = tree_identity(stdlib)
        verify_stdlib(stdlib_identity, lock["alpha"])
        write_json(output / "STDLIB_BEFORE.json", stdlib_identity)
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
        verify_source(source, lock["sdk"]["files"])
        require(verify_bundle(bundle) == installed, "SDK bundle changed during execution")
        after = tree_identity(stdlib)
        verify_stdlib(after, lock["alpha"])
        require(after == stdlib_identity, "Alpha standard library changed during execution")
        write_json(output / "STDLIB_AFTER.json", after)
        result.update({"passed": True, "compiler_color": "GREEN", "default_examples": 39,
                       "without_mt_examples": 39, "tutorial_normal_exit": 0, "tutorial_regression_exit": 1,
                       "tutorial_binary_sha256": binary_digest, "installed_bundle_files": 68})
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        if private is not None:
            shutil.rmtree(private)
            result["private_cache_removed"] = not private.exists()
        else:
            result["private_cache_removed"] = True
        result["command_count"] = len(runner.records)
        write_json(output / "READINESS_RESULT.json", result)
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    source_lock = pathlib.Path(__file__).with_name("sdk_source_lock.json")
    sys.exit(qualify(arguments.output.resolve(), json.loads(source_lock.read_text())))
