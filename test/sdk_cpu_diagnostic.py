#!/usr/bin/env python3
"""Hosted Linux arithmetic CPU contrast; every result remains diagnostic evidence."""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import platform
import re
import resource
import shutil
import sys
import struct
import time

FIXTURE = b"puts 40 + 2\n"
DRIVER_SHA256 = "f6b709e32790ad89a160910afac03beeffa5f160d7b06af4027ceae9f98da396"
LOCK_SHA256 = "40d43a7faa200a125448b02ddeaf2b0e9bd043f54de847edd970ede48dabe79d"
MAXIMUM_SECONDS = 240
MAXIMUM_RAW_BYTES = 32 * 1024**2
MAXIMUM_BINARY_BYTES = 16 * 1024**2
MAXIMUM_DISASSEMBLY_WINDOW_BYTES = 256
HOMEBREW_CONTEXT_KEYS = ("USER", "LOGNAME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
    "HOMEBREW_XDG_CONFIG_HOME", "HOMEBREW_USER_CONFIG_HOME", "HOMEBREW_USER_CACHE_HOME",
    "HOMEBREW_CACHE", "HOMEBREW_PREFIX", "HOMEBREW_CELLAR", "HOMEBREW_REPOSITORY",
    "HOMEBREW_NO_INSTALL_FROM_API", "HOMEBREW_NO_ENV_HINTS", "HOMEBREW_REQUIRE_TAP_TRUST",
    "CI", "GITHUB_ACTIONS", "GITHUB_REPOSITORY", "ImageOS", "ImageVersion")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with pathlib.Path(path).open("rb") as stream:
        result = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def write_json(path, value):
    pathlib.Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def load_driver(path):
    require(digest(path) == DRIVER_SHA256, "Reviewed original-group runner SHA-256 required")
    spec = importlib.util.spec_from_file_location("cpu_diagnostic_reviewed_driver", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def provider(path):
    path = pathlib.Path(path).resolve(strict=True)
    require(path.is_file(), "Regular provider required")
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest(path)}


def bounded_output(output):
    total = sum(path.stat().st_size for path in output.glob("*.txt"))
    require(total <= MAXIMUM_RAW_BYTES, "Complete diagnostic raw-output budget exceeded")
    return total


def observe(runner, label, arguments, *, cwd, environment, seconds):
    """Retain actual nonzero statuses while requiring the original writer gate."""
    previous = len(runner.records)
    try:
        runner.run(label, arguments, cwd=cwd, environment=environment, seconds=seconds)
    except Exception as error:
        # A normal nonzero status is the behavior being investigated. Every other
        # runner failure propagates with its original error and retained records.
        if len(runner.records) != previous + 1:
            raise
        record = runner.records[-1]
        if (type(error).__name__ != "QualificationError" or
                str(error) != f"{label} exited {record['exit_code']}; expected 0" or
                record["label"] != label or record["refusal"] is not None or
                record["writers_confirmed_retired"] is not True or
                type(record["exit_code"]) is not int or record["exit_code"] == 0):
            raise
    require(len(runner.records) == previous + 1, "One complete command observation required")
    record = runner.records[-1]
    require(record["writers_confirmed_retired"] is True and record["refusal"] is None,
            "Observed output requires confirmed original-group absence")
    bounded_output(runner.output)
    return dict(record)


def command_passed(record, output, expected=None):
    if record["exit_code"] != 0:
        return False
    return expected is None or (output / (record["label"] + ".stdout.txt")).read_bytes() == expected


def contrast_phase(build, run, output):
    if not command_passed(build, output):
        return "build_command_failed"
    if run is None:
        return "runtime_unobserved"
    if run["exit_code"] == -4:
        return "generated_program_sigill"
    if not command_passed(run, output, b"42\n"):
        return "generated_program_failed_or_output_differs"
    return "arithmetic_build_and_runtime_passed"


def disassembly_selection(binary, debugger_text=None):
    """Select a finite ELF address window, or an explicitly unqualified entry symbol."""
    try:
        require(binary.stat().st_size <= MAXIMUM_BINARY_BYTES, "Finite generated ELF required")
        with binary.open("rb") as stream:
            raw = stream.read(MAXIMUM_BINARY_BYTES + 1)
        require(64 <= len(raw) <= MAXIMUM_BINARY_BYTES and raw[:6] == b"\x7fELF\x02\x01",
                "ELF64 little-endian metadata required for an address selection")
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
        kind, machine, entry, offset, size, count = header[1], header[2], header[4], header[5], header[9], header[10]
        require(kind in (2, 3) and machine == 62 and size == 56 and 1 <= count <= 256
                and offset + size * count <= len(raw), "Bounded x86-64 ELF program headers required")
        segments = []
        for index in range(count):
            row = struct.unpack_from("<IIQQQQQQ", raw, offset + index * size)
            require(row[2] + row[5] <= len(raw) and row[5] <= row[6], "Contained ELF load segment required")
            if row[0] == 1 and row[1] & 1:
                segments.append(row)
        center, basis, runtime_pc = entry, "ELF entry point", None
        if debugger_text is not None:
            require("SIGILL" in debugger_text, "Actual debugger SIGILL required for fault selection")
            pcs = re.findall(r"(?m)^rip\s+0x([0-9a-fA-F]+)\b", debugger_text)
            entries = re.findall(r"(?m)^\s*Entry point:\s*0x([0-9a-fA-F]+)\b", debugger_text)
            require(len(pcs) == len(entries) == 1, "One actual RIP and runtime ELF entry point required")
            runtime_pc, runtime_entry = int(pcs[0], 16), int(entries[0], 16)
            slide = runtime_entry - entry
            require((kind == 2 and slide == 0) or (kind == 3 and slide >= 0 and slide % 4096 == 0),
                    "Exact executable or page-aligned PIE relocation required")
            center, basis = runtime_pc - slide, "Actual SIGILL RIP mapped through runtime ELF entry point"
        matches = [row for row in segments if row[3] <= center < row[3] + row[5]]
        require(len(matches) == 1, "One file-backed executable segment must contain the selection")
        segment = matches[0]
        start = max(segment[3], center - (64 if debugger_text is not None else 0))
        stop = min(segment[3] + segment[5], start + MAXIMUM_DISASSEMBLY_WINDOW_BYTES)
        require(start <= center < stop and 0 < stop - start <= MAXIMUM_DISASSEMBLY_WINDOW_BYTES,
                "Finite selected instruction window required")
        result = {"kind": "address-window", "selection_qualified": True, "basis": basis,
                  "start_address": start, "stop_address": stop, "center_address": center,
                  "maximum_window_bytes": MAXIMUM_DISASSEMBLY_WINDOW_BYTES,
                  "runtime_rip": runtime_pc, "binary_sha256": hashlib.sha256(raw).hexdigest()}
        if debugger_text is not None:
            file_offset = segment[2] + center - segment[3]
            result["fault_file_offset"] = file_offset
            result["fault_file_bytes_hex"] = raw[file_offset:min(file_offset + 16, segment[2] + segment[5])].hex()
        return result
    except (RuntimeError, struct.error, ValueError) as error:
        return {"kind": "selected-symbol", "symbol": "_start", "selection_qualified": False,
                "selection_error": f"{type(error).__name__}: {error}",
                "scope": "Bounded provider output still applies; this entry-symbol fallback qualifies no fault address."}


def disassembly_arguments(tool, binary, selection):
    if selection["kind"] == "address-window":
        start, stop = selection["start_address"], selection["stop_address"]
        require(type(start) is int and type(stop) is int and 0 <= start < stop
                and stop - start <= MAXIMUM_DISASSEMBLY_WINDOW_BYTES, "Exact finite disassembly addresses required")
        return [tool, "-d", "--start-address=" + hex(start), "--stop-address=" + hex(stop), binary]
    require(selection["kind"] == "selected-symbol" and selection["symbol"] == "_start",
            "Exact entry-symbol fallback required")
    return [tool, "-d", "--disassemble=_start", binary]


def environment_for(cache):
    environment = {key: value for key, value in os.environ.items()
                   if key in ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL")}
    environment.update(CRYSTAL_CACHE_DIR=str(cache), CRYSTAL_WORKERS="1", NO_COLOR="1",
                       DEBUGINFOD_URLS="", LC_ALL="C")
    return environment


def homebrew_environment_for(cache):
    """Preserve the ordinary user's trust/config context for metadata queries."""
    require(os.environ.get("HOMEBREW_NO_REQUIRE_TAP_TRUST") in (None, ""),
            "Homebrew metadata requires ordinary tap trust enforcement")
    environment = environment_for(cache)
    environment.update({key: os.environ[key] for key in HOMEBREW_CONTEXT_KEYS if key in os.environ})
    environment.update(HOMEBREW_NO_AUTO_UPDATE="1", HOMEBREW_NO_ANALYTICS="1")
    return environment


def receipt_control(record, output, driver, lock):
    """A filtered metadata refusal stays observable without changing the contrast."""
    value = {"record": record, "receipt_valid": False}
    if record["exit_code"] == 0:
        try:
            raw = (output / (record["label"] + ".stdout.txt")).read_text()
            driver.verify_formula_receipt(json.loads(raw)["formulae"], lock)
            value["receipt_valid"] = True
        except Exception as error:
            value["receipt_error"] = f"{type(error).__name__}: {error}"
    return value


def cpu_metadata(output):
    with pathlib.Path("/proc/cpuinfo").open("rb") as stream:
        data = stream.read(512 * 1024 + 1)
    require(len(data) <= 512 * 1024, "CPU advertisement metadata exceeds its finite bound")
    # Each processor block repeats the advertised model/features. Retain the
    # first block and processor count; the bounded raw file retains all blocks.
    (output / "CPUINFO.txt").write_bytes(data)
    return {"system": platform.system(), "machine": platform.machine(),
            "kernel_release": platform.release(), "first_processor_block": data.split(b"\n\n", 1)[0].decode(),
            "processor_blocks": sum(line.startswith(b"processor\t") for line in data.splitlines()),
            "image_os": os.environ.get("ImageOS"), "image_version": os.environ.get("ImageVersion"),
            "github_run_id": os.environ.get("GITHUB_RUN_ID"), "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "github_sha": os.environ.get("GITHUB_SHA")}


def qualify(arguments):
    require(platform.system() == "Linux" and os.environ.get("GITHUB_ACTIONS") == "true",
            "Actual execution belongs to GitHub-hosted Linux")
    require(digest(__file__) == arguments.source_sha256, "Diagnostic source SHA-256 mismatch")
    require(digest(pathlib.Path(sys.executable).resolve()) == arguments.python_sha256,
            "Python provider SHA-256 mismatch")
    repository = arguments.repository.resolve(strict=True)
    lock_path = repository / "test/sdk_source_lock.json"
    require(digest(lock_path) == LOCK_SHA256, "Reviewed source lock SHA-256 mismatch")
    driver = load_driver(repository / "test/sdk_install_qualification.py")
    lock = json.loads(lock_path.read_text())["alpha"]
    output = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    runner = driver.Runner(output)
    started = time.monotonic()
    runner.deadline = started + MAXIMUM_SECONDS
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    result = {"diagnostic_complete": False, "ordinary_smoke_accepted": False,
              "sdk_accepted": False, "supported_installation_accepted": False,
              "source_sha256": digest(__file__), "driver_sha256": DRIVER_SHA256,
              "source_lock_sha256": LOCK_SHA256, "maximum_seconds": MAXIMUM_SECONDS,
              "maximum_raw_bytes": MAXIMUM_RAW_BYTES, "providers": {}, "contrasts": {},
              "scope": "same installed compiler; default and explicit generic arithmetic target contrast",
              "actual_group_recovery_qualified": False, "detached_session_coverage_qualified": False}
    protected = {str(pathlib.Path(__file__).resolve()): arguments.source_sha256,
                 str(pathlib.Path(sys.executable).resolve()): arguments.python_sha256,
                 str(repository / "test/sdk_install_qualification.py"): DRIVER_SHA256,
                 str(lock_path): LOCK_SHA256}
    stdlib = None
    before = None
    runtime_identity = {}
    runtime_aliases = {}
    try:
        write_json(output / "CPU_METADATA.json", cpu_metadata(output))
        filtered_environment = dict(environment_for(output / "metadata-cache"),
                                    HOMEBREW_NO_AUTO_UPDATE="1", HOMEBREW_NO_ANALYTICS="1")
        environment = homebrew_environment_for(output / "metadata-cache")
        result["homebrew_metadata_context"] = {key: environment[key] for key in HOMEBREW_CONTEXT_KEYS
                                               if key in environment}
        result["homebrew_metadata_context"].update(HOMEBREW_NO_AUTO_UPDATE="1", HOMEBREW_NO_ANALYTICS="1")
        result["filtered_homebrew_metadata_context"] = {key: filtered_environment[key]
            for key in HOMEBREW_CONTEXT_KEYS if key in filtered_environment}
        result["filtered_homebrew_metadata_context"].update(HOMEBREW_NO_AUTO_UPDATE="1", HOMEBREW_NO_ANALYTICS="1")
        result["homebrew_tap_trust_enforced"] = True
        brew = pathlib.Path(shutil.which("brew") or "").absolute()
        require(brew.is_file(), "Ordinary Homebrew entrypoint required")
        brew_physical = brew.resolve(strict=True)
        result["brew_entrypoint"] = str(brew)
        result["providers"]["brew"] = provider(brew)
        protected[str(brew)] = digest(brew)
        def command(label, argv, seconds=20, env=environment):
            return observe(runner, label, argv, cwd=output, environment=env, seconds=seconds)
        for label, argv in (("brew-prefix", [brew, "--prefix", "agent-crystal"]),
                            ("brew-root", [brew, "--prefix"]),
                            ("brew-receipt", [brew, "info", "--json=v2", "agent-crystal"])):
            require(command_passed(command(label, argv), output), label + " must succeed")
        prefix = pathlib.Path((output / "brew-prefix.stdout.txt").read_text().strip()).resolve(strict=True)
        brew_root = pathlib.Path((output / "brew-root.stdout.txt").read_text().strip()).resolve(strict=True)
        driver.verify_formula_receipt(json.loads((output / "brew-receipt.stdout.txt").read_text())["formulae"], lock)
        filtered = command("brew-receipt-filtered-control", [brew, "info", "--json=v2", "agent-crystal"],
                           env=filtered_environment)
        result["filtered_homebrew_metadata_control"] = receipt_control(filtered, output, driver, lock)
        result["homebrew_context_control_scope"] = "Same lexical brew entrypoint and argv; ordinary versus compiler-filtered metadata environment"
        for formula in (prefix / ".brew/agent-crystal.rb", repository / "Formula/agent-crystal.rb"):
            require(digest(formula) == lock["formula_sha256"], "Exact installed and checkout formula source required")
            protected[str(formula)] = digest(formula)
        shutil.copyfile(prefix / "INSTALL_RECEIPT.json", output / "INSTALL_RECEIPT.json")
        protected[str(prefix / "INSTALL_RECEIPT.json")] = digest(prefix / "INSTALL_RECEIPT.json")
        compiler = prefix / "libexec/agent-crystal-bin"
        stdlib = prefix / "share/agent-crystal/src"
        before = driver.tree_identity(stdlib)
        write_json(output / "STDLIB_BEFORE.json", before)
        driver.verify_stdlib(before, lock)
        protected[str(compiler)] = digest(compiler)
        result["providers"]["compiler"] = provider(compiler)
        aliases = {}
        runtime_identity = {}
        def runtime_context():
            if not runtime_identity:
                record = command("runtime-dependency-metadata", [brew, "info", "--json=v2", "--installed"], 45)
                require(command_passed(record, output), "Actual installed runtime dependency metadata required")
                value = driver.runtime_dependency_identity(json.loads((output / "runtime-dependency-metadata.stdout.txt").read_text()), prefix, brew_root)
                runtime_identity.update(value)
                write_json(output / "RUNTIME_LIBRARY_PATHS.json", value)
            runtime_aliases[alias] = driver.installed_alias_identity(alias_entrypoint, wrapper)
            return runtime_identity
        for alias in ("acrystal", "agent-crystal", "crystal-alpha"):
            alias_entrypoint = pathlib.Path(shutil.which(alias) or "").absolute()
            wrapper = alias_entrypoint.resolve(strict=True)
            require(wrapper == prefix / "bin" / alias, "Alias requires the same ordinary installation")
            driver.verify_wrapper(wrapper.read_text(), compiler, stdlib, brew_root, "Linux", runtime_context)
            protected[str(wrapper)] = digest(wrapper)
            result["providers"][alias] = provider(wrapper)
            shutil.copyfile(wrapper, output / (alias + "-wrapper.txt"))
            aliases[alias] = wrapper
            record = command(alias + "-version", [wrapper, "--version"])
            require(command_passed(record, output, lock["full_versions"]["Linux"].encode()), "Exact compiler full version required")
        tools = {}
        for name in ("lscpu", "objdump", "gdb"):
            found = shutil.which(name)
            if found:
                tools[name] = pathlib.Path(found).resolve(strict=True)
                result["providers"][name] = provider(tools[name])
                protected[str(tools[name])] = digest(tools[name])
                require(command_passed(command(name + "-version", [tools[name], "--version"]), output), name + " version required")
        require("lscpu" in tools and "objdump" in tools, "Host CPU and disassembly providers required")
        require(command_passed(command("lscpu", [tools["lscpu"], "--json"]), output), "CPU advertisement command required")
        fixture = output / "arithmetic.cr"
        fixture.write_bytes(FIXTURE)
        protected[str(fixture)] = digest(fixture)
        for target, flags in (("default", []), ("generic", ["--mcpu", "generic"])):
            case = output / target
            case.mkdir()
            env = environment_for(case / "cache")
            binary = case / "arithmetic"
            build = command(target + "-build", [aliases["acrystal"], "build", *flags,
                            "--threads", "1", fixture, "-o", binary], 60, env)
            runtime = None
            row = {"target_flags": flags, "build": build}
            result["contrasts"][target] = row
            if command_passed(build, output):
                require(binary.is_file() and not binary.is_symlink() and binary.stat().st_size <= MAXIMUM_BINARY_BYTES,
                        "Finite regular generated binary required")
                row["binary_before"] = provider(binary)
                runtime = command(target + "-runtime", [binary], 10, env)
                row["runtime"] = runtime
                debugger_text = None
                if runtime["exit_code"] == -4 and "gdb" in tools:
                    row["debugger"] = command(target + "-fault-location", [tools["gdb"], "--batch", "-nx", "-nh",
                        "-iex", "set auto-load off",
                        "-ex", "set pagination off", "-ex", "set debuginfod enabled off",
                        "-ex", "set startup-with-shell off", "-ex", "run", "-ex", "info registers",
                        "-ex", "info files", "-ex", "x/16i $pc", "-ex", "x/16xb $pc",
                        "-ex", "info symbol $pc", "--args", binary], 15, env)
                    if row["debugger"]["exit_code"] == 0:
                        debugger_text = (output / (target + "-fault-location.stdout.txt")).read_text()
                row["disassembly_selection"] = disassembly_selection(binary, debugger_text)
                row["fault_address_qualified"] = (runtime["exit_code"] == -4 and debugger_text is not None
                    and row["disassembly_selection"]["selection_qualified"] is True)
                row["fault_evidence_scope"] = ("Actual debugger RIP and retained ELF address bytes"
                    if row["fault_address_qualified"] else "Fault-address qualification pending when no valid in-binary debugger mapping is retained")
                row["disassembly"] = command(target + "-disassembly",
                    disassembly_arguments(tools["objdump"], binary, row["disassembly_selection"]), 15, env)
                require(command_passed(row["disassembly"], output), "Complete selected disassembly required")
                row["binary_after"] = provider(binary)
                require(row["binary_before"] == row["binary_after"], "Generated binary changed during runtime or disassembly")
            row["eval"] = command(target + "-eval", [aliases["acrystal"], "eval", *flags, "puts 40 + 2"], 45, env)
            row["phase"] = contrast_phase(build, runtime, output)
            row["eval_matches_42"] = command_passed(row["eval"], output, b"42\n")
            result["contrasts"][target] = row
            write_json(output / "CPU_DIAGNOSTIC.json", result)
        if runtime_identity:
            driver.verify_runtime_dependency_identity(runtime_identity)
        result["diagnostic_complete"] = True
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        try:
            require(runner.writers_confirmed_retired is True, "Private caches retained for unresolved writers")
            for path, expected in protected.items():
                require(digest(path) == expected, "Protected provider or fixture changed: " + path)
            if "brew_entrypoint" in result:
                require(brew.resolve(strict=True) == brew_physical,
                        "Ordinary Homebrew entrypoint changed its physical provider")
            if stdlib is not None:
                after = driver.tree_identity(stdlib)
                write_json(output / "STDLIB_AFTER.json", after)
                driver.verify_stdlib(after, lock)
                require(after == before, "Complete installed standard library changed")
            result["protected_identities_verified"] = True
            # All diagnostic work and binaries remain in the artifact. Private
            # compilation caches are removed only after original-group absence.
            for cache in (output / "metadata-cache", output / "default/cache", output / "generic/cache"):
                if cache.exists():
                    shutil.rmtree(cache)
            result["private_caches_removed"] = True
            require(time.monotonic() <= runner.deadline, "Complete diagnostic time budget exceeded")
            bounded_output(output)
        except Exception as cleanup_error:
            result["diagnostic_complete"] = False
            result["cleanup_error"] = f"{type(cleanup_error).__name__}: {cleanup_error}"
        finally:
            result["command_count"] = len(runner.records)
            result["owned_group_observations"] = runner.group_observations
            result["writers_confirmed_retired"] = runner.writers_confirmed_retired
            # Final provider failure is evidence, and shares the retained result
            # with the original command and cleanup errors.
            result["finalization_errors"] = []
            if runtime_identity:
                try:
                    driver.verify_runtime_dependency_identity(runtime_identity)
                except Exception as final_error:
                    result["diagnostic_complete"] = False
                    result["finalization_errors"].append(f"Runtime identity: {type(final_error).__name__}: {final_error}")
            result["ordinary_alias_identities"] = runtime_aliases
            for alias_identity in runtime_aliases.values():
                try:
                    driver.verify_installed_alias_identity(alias_identity)
                except Exception as final_error:
                    result["diagnostic_complete"] = False
                    result["finalization_errors"].append(f"Ordinary alias: {type(final_error).__name__}: {final_error}")
            result["python_provider"] = None
            try:
                result["python_provider"] = provider(pathlib.Path(sys.executable))
                require(result["python_provider"]["sha256"] == arguments.python_sha256,
                        "Final Python provider SHA-256 differs from admitted identity")
            except Exception as provider_error:
                result["diagnostic_complete"] = False
                result["finalization_errors"].append(f"Final Python provider: {type(provider_error).__name__}: {provider_error}")
            # This terminal observation covers final provider hashing as well as
            # the original command/cleanup interval. Its recorded values govern
            # completion, including a command that finishes at the deadline.
            finished = time.monotonic()
            elapsed = finished - started
            result["started_monotonic_seconds"] = started
            result["finished_monotonic_seconds"] = finished
            result["absolute_deadline_monotonic_seconds"] = runner.deadline
            result["elapsed_seconds"] = elapsed
            result["terminal_clock_verified"] = started <= finished <= runner.deadline and 0 <= elapsed <= MAXIMUM_SECONDS
            if not result["terminal_clock_verified"]:
                result["diagnostic_complete"] = False
                result["finalization_errors"].append("Complete diagnostic terminal time budget exceeded")
            write_json(output / "CPU_DIAGNOSTIC.json", result)
    print(json.dumps({key: result.get(key) for key in ("diagnostic_complete", "error", "cleanup_error", "finalization_errors", "ordinary_smoke_accepted")}, sort_keys=True))
    return 0 if result["diagnostic_complete"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--python-sha256", required=True)
    sys.exit(qualify(parser.parse_args()))
