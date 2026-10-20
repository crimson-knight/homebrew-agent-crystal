#!/usr/bin/env python3
"""Hosted-only real POSIX controls for the SDK driver's original-group observation."""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import sys
import time

REVIEWED_DRIVER_ANCESTOR_SHA256 = "89ed2148b3e6fa6089a8dbec1ed498ffa393f583b8ff1f27e132846d365eb09d"
REVIEWED_RUNNER_SOURCE_SHA256 = "f7cc290c415ae14d6c0c4093c1361aeb78d7bbaf94ec9512dde89ff6f887f48f"
OUTPUT_LIMIT = 1024 * 1024
PRIMARY_SECONDS = 35
FINAL_SECONDS = 5
NORMAL_SECONDS = 3
LEADER_SECONDS = 4
NATURAL_SECONDS = 4
DESCENDANT_SECONDS = 6
NORMAL_SOURCE = 'import os\nprint("normal-fixture-exit", flush=True)\n'
DESCENDANT_SOURCE = r'''import json
import os
from pathlib import Path
import sys
import time

root = Path(sys.argv[1])
token = sys.argv[2]
deadline = time.monotonic() + 6
leader = os.getpid()
group = os.getpgrp()
assert group == leader
reader, writer = os.pipe()
child = os.fork()
if child == 0:
    os.close(reader)
    ready = {"token": token, "leader_pid": leader, "child_pid": os.getpid(),
             "group": os.getpgrp(), "uid": os.getuid(), "phase": "ready"}
    temporary = root / "CHILD_READY.stage"
    temporary.write_text(json.dumps(ready) + "\n")
    temporary.replace(root / "CHILD_READY.json")
    os.write(writer, b"R")
    os.close(writer)
    phase = "self_deadline"
    while time.monotonic() < deadline:
        release = root / "RELEASE_CHILD.txt"
        if release.is_file() and release.read_text().strip() == token:
            phase = "released"
            break
        time.sleep(0.02)
    intent = dict(ready, phase=phase, action="returning through os._exit")
    temporary = root / "SELF_RETIREMENT.stage"
    temporary.write_text(json.dumps(intent) + "\n")
    temporary.replace(root / "SELF_RETIREMENT_INTENT.json")
    print("descendant-self-exit", flush=True)
    os._exit(0 if phase == "released" else 3)
os.close(writer)
assert os.read(reader, 1) == b"R"
os.close(reader)
print("leader-exit-with-live-descendant", flush=True)
os._exit(0)
'''
NATURAL_SOURCE = r'''import json
import os
from pathlib import Path
import sys
import time

root = Path(sys.argv[1])
token = sys.argv[2]
leader = os.getpid()
group = os.getpgrp()
if group != leader:
    raise RuntimeError("The natural fixture requires its original leader group")
reader, writer = os.pipe()
child = os.fork()
if child == 0:
    os.close(reader)
    ready = {"token": token, "leader_pid": leader, "child_pid": os.getpid(),
             "group": os.getpgrp(), "uid": os.getuid(), "phase": "ready"}
    (root / "NATURAL_CHILD_READY.json").write_text(json.dumps(ready) + "\n")
    os.write(writer, b"R")
    os.close(writer)
    deadline = time.monotonic() + 0.6
    while time.monotonic() < deadline:
        time.sleep(0.01)
    (root / "NATURAL_RETIREMENT_INTENT.json").write_text(json.dumps(dict(ready, phase="naturally_retired")) + "\n")
    print("natural-descendant-self-exit", flush=True)
    os._exit(0)
os.close(writer)
if os.read(reader, 1) != b"R":
    raise RuntimeError("The natural child must publish its ready identity")
os.close(reader)
print("leader-exit-before-natural-retirement", flush=True)
os._exit(0)
'''


class ControlError(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise ControlError(message)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def reference(path):
    path = Path(path)
    before = path.lstat()
    require(path.resolve() == path and stat.S_ISREG(before.st_mode), "Canonical regular provider/source required")
    row = {"path": str(path), "bytes": before.st_size, "mode": stat.S_IMODE(before.st_mode), "sha256": sha256(path)}
    after = path.lstat()
    fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    require(tuple(getattr(before, key) for key in fields) == tuple(getattr(after, key) for key in fields),
            "Stable exact source/provider identity required")
    return row


def output_bytes(root):
    rows = list(root.rglob("*"))
    require(len(rows) <= 64 and all(not path.is_symlink() for path in rows), "Finite ordinary control evidence tree required")
    return sum(path.stat().st_size for path in rows if path.is_file())


def runner_source_sha256(path):
    source = path.read_text()
    classes = [node for node in ast.parse(source).body if isinstance(node, ast.ClassDef) and node.name == "Runner"]
    require(len(classes) == 1, "One exact reviewed Runner class required")
    return hashlib.sha256(ast.get_source_segment(source, classes[0]).encode()).hexdigest()


def save(path, value):
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    require(len(data) <= 64 * 1024, "Finite control receipt required")
    with path.open("xb") as target:
        target.write(data)


def observe_group(group):
    require(type(group) is int and group > 1, "One positive original fixture group required")
    try:
        os.killpg(group, 0)
        return {"group": group, "status": "present"}
    except ProcessLookupError:
        return {"group": group, "status": "absent"}
    except OSError as error:
        return {"group": group, "status": "unverifiable", "error": f"{type(error).__name__}: {error}"}


def await_absence(group, deadline):
    samples = []
    while True:
        sample = observe_group(group)
        samples.append(dict(sample, monotonic=time.monotonic()))
        if sample["status"] == "absent":
            return {"passed": True, "group": group, "samples": samples, "coverage": "original POSIX process group only"}
        require(sample["status"] == "present", "Original group observation must remain verifiable")
        require(time.monotonic() < deadline and len(samples) < 256, "Bounded original-group absence deadline reached")
        time.sleep(0.04)


def verify_record(record, expected):
    require(expected in ("absent", "present"), "Reviewed command group expectation required")
    observation = record["terminal_group_observation"]
    require(observation["phase"] == "direct_child_returned" and observation["status"] == expected,
            "Exact direct-child-return original-group state required")
    require(record["original_group"] == observation["group"] == record["pid"], "Exact original process-group identity required")
    require(record["writers_confirmed_retired"] is (expected == "absent"), "Exact original-group retirement flag required")
    samples = observation["samples"]
    require(type(samples) is list and 1 <= len(samples) <= 128
            and observation["initial_sample"] == samples[0] and observation["terminal_sample"] == samples[-1]
            and samples[-1]["status"] == expected and observation["maximum_drain_seconds"] == 5.0,
            "Bounded initial and terminal original-group samples required")
    for field in ("stdout_sha256", "stderr_sha256"):
        if expected == "absent":
            require(type(record[field]) is str and re.fullmatch(r"[0-9a-f]{64}", record[field]) is not None,
                    "Confirmed group absence must precede output qualification")
        else:
            require(record[field] is None, "Live-group output hashes must remain unqualified")


def hosted_guard(environment):
    require(environment.get("GITHUB_ACTIONS") == "true" and environment.get("RUNNER_ENVIRONMENT") == "github-hosted",
            "These real process controls require GitHub-hosted Actions execution")


def deadline_alarm(signum, frame):
    raise ControlError("Hosted control deadline reached")


def execute(arguments):
    hosted_guard(os.environ)
    require(platform.system() in ("Linux", "Darwin"), "Reviewed POSIX platform required")
    driver = arguments.driver.resolve()
    source = Path(__file__).resolve()
    python = Path(sys.executable).resolve()
    require(sha256(source) == arguments.source_sha256 and sha256(driver) == arguments.driver_sha256,
            "Exact hosted control and reviewed driver source required")
    require(runner_source_sha256(driver) == REVIEWED_RUNNER_SOURCE_SHA256,
            "Exact independently reviewed original-group Runner source required")
    require(sha256(python) == arguments.python_sha256 and platform.python_version() == arguments.python_version,
            "Exact declared hosted Python provider required")
    sys.dont_write_bytecode = True
    before = [reference(path) for path in (source, driver, python)]
    output = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    result = {"passed": False, "scope": "real hosted original POSIX process-group observation controls",
              "group_recovery_qualified": False, "detached_session_coverage_qualified": False,
              "full_native_provider_acceptance": False, "compiler_jobs": 0, "ssh_jobs": 0,
              "maximum_concurrent_fixture_processes_by_source": 2, "fixture_processes_expected": 5,
              "time_limit_seconds": 45, "output_limit_bytes": OUTPUT_LIMIT,
              "output_accounting": "evidence tree plus duplicate final JSON stdout",
              "sources_and_provider_before": before, "python_version": sys.version,
              "reviewed_runner_source_sha256": REVIEWED_RUNNER_SOURCE_SHA256,
              "reviewed_driver_ancestor_sha256": REVIEWED_DRIVER_ANCESTOR_SHA256,
              "runner": {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA",
                         "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion")}}
    private = output / "private cache"
    private.mkdir()
    sentinel = private / "cache-sentinel.txt"
    sentinel.write_text("preserved until independently observed original-group absence\n")
    token = os.urandom(16).hex()
    release = private / "RELEASE_CHILD.txt"
    runner = None
    previous_handler = signal.signal(signal.SIGALRM, deadline_alarm)
    signal.alarm(PRIMARY_SECONDS)
    try:
        fixture_root = output / "fixture sources"
        fixture_root.mkdir()
        normal = fixture_root / "normal_exit.py"
        natural = fixture_root / "natural_group_retirement.py"
        descendant = fixture_root / "same_group_descendant.py"
        normal.write_text(NORMAL_SOURCE)
        natural.write_text(NATURAL_SOURCE)
        descendant.write_text(DESCENDANT_SOURCE)
        fixture_sources = [reference(path) for path in (normal, natural, descendant)]
        save(output / "FIXTURE_SOURCE_IDENTITIES.json", fixture_sources)
        spec = importlib.util.spec_from_file_location("reviewed_sdk_original_group_driver", driver)
        sdk = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sdk)
        command_root = output / "commands"
        command_root.mkdir()
        runner = sdk.Runner(command_root)
        runner.deadline = started + 25
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
        runner.run("normal-exit", [python, "-I", "-S", "-B", normal], cwd=private,
                   environment=environment, seconds=NORMAL_SECONDS)
        verify_record(runner.records[-1], "absent")
        result["normal_exit"] = {"passed": True, "record": runner.records[-1]}
        runner.run("natural-retirement", [python, "-I", "-S", "-B", natural, private, token], cwd=private,
                   environment=environment, seconds=NATURAL_SECONDS)
        natural_record = runner.records[-1]
        verify_record(natural_record, "absent")
        natural_ready = json.loads((private / "NATURAL_CHILD_READY.json").read_text())
        natural_intent = json.loads((private / "NATURAL_RETIREMENT_INTENT.json").read_text())
        require(natural_record["terminal_group_observation"]["initial_sample"]["status"] == "present"
                and len(natural_record["terminal_group_observation"]["samples"]) >= 2
                and natural_ready["token"] == token and natural_ready["group"] == natural_ready["leader_pid"] == natural_record["pid"]
                and type(natural_ready["child_pid"]) is int and natural_ready["child_pid"] > 1
                and natural_ready["child_pid"] != natural_ready["leader_pid"]
                and natural_intent == dict(natural_ready, phase="naturally_retired"),
                "The same-group child must retire naturally during the bounded original command interval")
        save(output / "NATURAL_GROUP_RETIREMENT.json", {"passed": True, "record": natural_record,
            "child": natural_ready, "intent": natural_intent, "driver_group_recovery_performed": False})
        result["natural_retirement"] = {"passed": True, "record": natural_record,
            "child_pid": natural_ready["child_pid"], "driver_group_recovery_performed": False}
        refusal = None
        try:
            runner.run("live-descendant", [python, "-I", "-S", "-B", descendant, private, token], cwd=private,
                       environment=environment, seconds=LEADER_SECONDS)
        except sdk.QualificationError as error:
            refusal = str(error)
        require(refusal is not None and len(runner.records) == 3, "Live descendant must earn an actual refused command")
        record = runner.records[-1]
        verify_record(record, "present")
        ready = json.loads((private / "CHILD_READY.json").read_text())
        require(ready["token"] == token and ready["leader_pid"] == ready["group"] == record["original_group"]
                and type(ready["child_pid"]) is int and ready["child_pid"] > 1
                and ready["child_pid"] != ready["leader_pid"] and ready["phase"] == "ready",
                "Exact same-group fixture identity and readiness receipt required")
        require(sentinel.is_file() and runner.writers_confirmed_retired is False,
                "Private cache must remain retained at the refused live-group checkpoint")
        save(output / "LIVE_GROUP_REFUSAL.json", {"passed": True, "refusal": refusal, "record": record,
             "child": ready, "private_cache_present": True, "output_hashes_qualified": False})
        release.write_text(token + "\n")
        absence = await_absence(record["original_group"], min(started + 30, time.monotonic() + 10))
        intent = json.loads((private / "SELF_RETIREMENT_INTENT.json").read_text())
        require(intent == dict(ready, phase="released", action="returning through os._exit"),
                "Pinned descendant must take its cooperative self-retirement branch")
        save(output / "SELF_RETIREMENT_INTENT.json", intent)
        save(output / "GROUP_ABSENCE_AFTER_SELF_RETIREMENT.json", absence)
        save(output / "POST_RETIREMENT_OUTPUT_IDENTITIES.json", [reference(command_root / name)
             for name in ("live-descendant.stdout.txt", "live-descendant.stderr.txt")])
        result["live_descendant"] = {"passed": True, "original_refusal_preserved": True,
            "independently_observed_absence_after_self_retirement": True, "driver_group_recovery_performed": False,
            "group": record["original_group"], "child_pid": ready["child_pid"]}
        result["actual_fixture_pids"] = [runner.records[0]["pid"], natural_record["pid"], natural_ready["child_pid"], record["pid"], ready["child_pid"]]
        require(len(set(result["actual_fixture_pids"])) == 5, "Five distinct actual fixture process identities required")
        result["sources_and_provider_after"] = [reference(path) for path in (source, driver, python)]
        require(result["sources_and_provider_after"] == before,
                "Exact original source and Python provider must remain fixed")
        result["fixture_sources_after"] = [reference(path) for path in (normal, natural, descendant)]
        require(result["fixture_sources_after"] == fixture_sources,
                "Exact fixture source must remain fixed")
        require(time.monotonic() - started < 40 and output_bytes(output) < OUTPUT_LIMIT - 128 * 1024,
                "Complete hosted behavior evidence must retain original time and output limits")
        result["passed"] = True
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        signal.alarm(FINAL_SECONDS)
        try:
            if not release.exists():
                release.write_text(token + "\n")
            observations = runner.group_observations if runner is not None else []
            groups = sorted({row["group"] for row in observations})
            outcomes = [await_absence(group, min(started + 40, time.monotonic() + 4)) for group in groups]
            result["final_original_group_absence"] = outcomes
            require(runner is None or runner.writers_confirmed_retired or groups,
                    "Unidentified launched command remains unqualified")
            if result["passed"]:
                shutil.rmtree(private)
                result["private_cache_removed"] = not private.exists()
                require(result["private_cache_removed"], "Confirmed fixture private-cache removal required")
            else:
                result["private_cache_removed"] = False
                result["private_cache_preserved"] = private.exists()
        except Exception as cleanup_error:
            result["passed"] = False
            result["private_cache_removed"] = False
            result["private_cache_preserved"] = private.exists()
            result["cleanup_error"] = f"{type(cleanup_error).__name__}: {cleanup_error}"
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous_handler)
            result["elapsed_seconds"] = time.monotonic() - started
            try:
                result["observed_evidence_bytes_before_result"] = output_bytes(output)
                require(result["elapsed_seconds"] < 45 and result["observed_evidence_bytes_before_result"] < OUTPUT_LIMIT - 128 * 1024,
                        "Complete control resource bounds require review")
            except Exception as budget_error:
                result["passed"] = False
                result["budget_error"] = f"{type(budget_error).__name__}: {budget_error}"
            save(output / "HOSTED_GROUP_CONTROL_RESULT.json", result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--driver-sha256", required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--python-sha256", required=True)
    parser.add_argument("--python-version", required=True)
    return execute(parser.parse_args())


if __name__ == "__main__":
    sys.exit(main())
