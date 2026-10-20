"""Source-only controls for preserved Homebrew context and distro SQLite metadata."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cpu = load("successor_cpu", ROOT / "sdk_cpu_diagnostic.py")
native = load("successor_native", ROOT / "linux_native_projection.py")
reader = load("successor_reader", ROOT / "linux_projection_identity.py")


class QualificationError(RuntimeError):
    pass


class DiagnosticSuccessorControls(unittest.TestCase):
    def setUp(self):
        self.private = tempfile.TemporaryDirectory(prefix="diagnostic source control ")
        self.addCleanup(self.private.cleanup)
        self.root = Path(self.private.name).resolve()

    def test_homebrew_context_preserves_user_config_and_identity(self):
        values = {"PATH": "/usr/bin", "HOME": str(self.root), "USER": "runner", "LOGNAME": "runner",
            "XDG_CONFIG_HOME": str(self.root / "config"), "HOMEBREW_XDG_CONFIG_HOME": str(self.root / "brewconfig"),
            "HOMEBREW_USER_CONFIG_HOME": str(self.root / "config/homebrew"),
            "HOMEBREW_PREFIX": "/home/linuxbrew/.linuxbrew", "HOMEBREW_NO_INSTALL_FROM_API": "",
            "HOMEBREW_GITHUB_API_TOKEN": "PRIVATE_METADATA_FIXTURE", "CRYSTAL_OPTS": "--mcpu native"}
        with mock.patch.dict(os.environ, values, clear=True):
            environment = cpu.homebrew_environment_for(self.root / "cache")
        for key in ("USER", "LOGNAME", "XDG_CONFIG_HOME", "HOMEBREW_XDG_CONFIG_HOME",
                    "HOMEBREW_USER_CONFIG_HOME", "HOMEBREW_PREFIX", "HOMEBREW_NO_INSTALL_FROM_API"):
            self.assertEqual(environment[key], values[key])
        self.assertEqual(environment["HOMEBREW_NO_AUTO_UPDATE"], "1")
        self.assertEqual(environment["HOMEBREW_NO_ANALYTICS"], "1")
        self.assertNotIn("HOMEBREW_GITHUB_API_TOKEN", environment)
        self.assertNotIn("CRYSTAL_OPTS", environment)

    def test_compile_contrast_retains_explicit_filtered_policy(self):
        with mock.patch.dict(os.environ, {"PATH": "/usr/bin", "HOME": str(self.root), "USER": "runner",
                "XDG_CONFIG_HOME": "/config", "CRYSTAL_OPTS": "--mcpu native"}, clear=True):
            filtered = cpu.environment_for(self.root / "cache")
            preserved = cpu.homebrew_environment_for(self.root / "cache")
        self.assertNotIn("USER", filtered)
        self.assertNotIn("XDG_CONFIG_HOME", filtered)
        self.assertNotIn("CRYSTAL_OPTS", filtered)
        self.assertNotIn("CRYSTAL_OPTS", preserved)
        self.assertEqual(filtered["CRYSTAL_WORKERS"], "1")
        self.assertEqual(preserved["USER"], "runner")

    def test_homebrew_context_requires_trust_enforcement(self):
        with mock.patch.dict(os.environ, {"HOMEBREW_NO_REQUIRE_TAP_TRUST": "1"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "trust enforcement"):
                cpu.homebrew_environment_for(self.root)

    def test_filtered_receipt_failure_is_preserved_as_control(self):
        record = {"label": "filtered", "exit_code": 1}
        result = cpu.receipt_control(record, self.root, types.SimpleNamespace(), {})
        self.assertEqual(result["record"], record)
        self.assertFalse(result["receipt_valid"])

    def test_filtered_zero_status_still_requires_valid_receipt(self):
        (self.root / "filtered.stdout.txt").write_text("invalid receipt")
        driver = types.SimpleNamespace(verify_formula_receipt=lambda *arguments: None)
        result = cpu.receipt_control({"label": "filtered", "exit_code": 0}, self.root, driver, {})
        self.assertFalse(result["receipt_valid"])
        self.assertIn("JSONDecodeError", result["receipt_error"])

    def test_filtered_valid_receipt_records_its_observed_pass(self):
        (self.root / "filtered.stdout.txt").write_text('{"formulae": [{"exact": true}]}')
        driver = types.SimpleNamespace(verify_formula_receipt=lambda receipt, lock: self.assertEqual(receipt, [{"exact": True}]))
        result = cpu.receipt_control({"label": "filtered", "exit_code": 0}, self.root, driver, {})
        self.assertTrue(result["receipt_valid"])

    def test_complete_mocked_diagnostic_preserves_context_and_control_scope(self):
        original = load("original_cpu_behavior_controls", ROOT / "test_sdk_cpu_diagnostic.py")
        case = original.DiagnosticTests(methodName="runTest")
        case.setUp()
        self.addCleanup(case.tearDown)
        with mock.patch.dict(os.environ, {"USER": "runner", "LOGNAME": "runner",
                "XDG_CONFIG_HOME": str(self.root / "user config"), "CRYSTAL_OPTS": "--mcpu native"}):
            code, result = case.full_case()
        self.assertEqual(code, 0)
        self.assertEqual(result["homebrew_metadata_context"]["USER"], "runner")
        self.assertEqual(result["homebrew_metadata_context"]["XDG_CONFIG_HOME"], str(self.root / "user config"))
        self.assertTrue(result["homebrew_tap_trust_enforced"])
        self.assertEqual(result["homebrew_metadata_context"]["HOMEBREW_NO_AUTO_UPDATE"], "1")
        self.assertEqual(result["filtered_homebrew_metadata_context"]["HOMEBREW_NO_AUTO_UPDATE"], "1")
        control = result["filtered_homebrew_metadata_control"]
        self.assertEqual(control["record"]["arguments"],
            [result["brew_entrypoint"], "info", "--json=v2", "agent-crystal"])
        self.assertIn("Same lexical brew entrypoint and argv", result["homebrew_context_control_scope"])
        self.assertFalse(result["sdk_accepted"])

    def commands(self, code=1, refusal=None, wrong_argv=False):
        root = self.root
        class ObservedRunner:
            def __init__(inner):
                inner.records = []
            def run(inner, label, arguments, **options):
                stdout, stderr = b"", b"observed metadata refusal\n"
                for suffix, raw in (("stdout.txt", stdout), ("stderr.txt", stderr)):
                    (root / (label + "." + suffix)).write_bytes(raw)
                record = {"label": label, "arguments": ["altered"] if wrong_argv else [str(value) for value in arguments],
                    "exit_code": code, "pid": 101, "original_group": 101,
                    "terminal_group_observation": {"group": 101, "status": "absent"},
                    "writers_confirmed_retired": True, "refusal": refusal, "elapsed_seconds": 0.1,
                    "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest()}
                inner.records.append(record)
                if refusal:
                    raise QualificationError(refusal)
                if code != 0:
                    raise QualificationError(f"{label} exited {code}; expected 0")
                return "", stderr.decode()
        tool = self.root / "identified metadata tool"
        tool.write_bytes(b"identified source metadata provider")
        roster = native.Roster(reader.file_identity, time.monotonic() + 15)
        runner = ObservedRunner()
        return native.Commands(runner, roster, root), tool

    def test_explicit_nonzero_observation_keeps_raw_and_hashes(self):
        commands, tool = self.commands()
        stdout, stderr = commands.run("control", [str(tool), "--variable=libdir", "sqlite3"], observe_nonzero=True)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "observed metadata refusal\n")
        self.assertEqual(commands.runner.records[0]["exit_code"], 1)
        self.assertEqual(commands.runner.records[0]["stderr_sha256"], hashlib.sha256(stderr.encode()).hexdigest())

    def test_required_metadata_nonzero_remains_failure(self):
        commands, tool = self.commands()
        with self.assertRaisesRegex(QualificationError, "exited 1"):
            commands.run("required", [str(tool)])
        self.assertEqual(commands.runner.records[-1]["exit_code"], 1)
        self.assertTrue((self.root / "required.stderr.txt").exists())

    def test_observed_control_preserves_original_runner_refusal(self):
        commands, tool = self.commands(refusal="Original owned process group is present")
        with self.assertRaisesRegex(QualificationError, "process group is present"):
            commands.run("control", [str(tool)], observe_nonzero=True)

    def test_observed_control_requires_exact_command_identity(self):
        commands, tool = self.commands(wrong_argv=True)
        with self.assertRaisesRegex(RuntimeError, "label/argv"):
            commands.run("control", [str(tool)], observe_nonzero=True)

    def test_distro_sqlite_context_replaces_ambient_pkg_config_paths(self):
        with mock.patch.dict(os.environ, {"PKG_CONFIG_PATH": "/unrelated",
                "PKG_CONFIG_LIBDIR": "/unrelated/lib", "PKG_CONFIG_SYSROOT_DIR": "/unrelated/root"}):
            environment = native.sqlite_metadata_environment()
        self.assertEqual(environment["PKG_CONFIG_LIBDIR"],
            "/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig")
        self.assertEqual(environment["PKG_CONFIG_PATH"], "")
        self.assertEqual(environment["PKG_CONFIG_SYSROOT_DIR"], "")
        self.assertEqual(native.SYSTEM_PKG_CONFIG, "/usr/bin/pkg-config")

    def test_distro_provider_alias_and_failed_homebrew_control_stay_separate(self):
        binary = self.root / "usr/bin/pkgconf"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"identified distro metadata fixture")
        alias = binary.with_name("pkg-config")
        alias.symlink_to("pkgconf")
        directories = (str(self.root / "usr/lib/pkgconfig"), str(self.root / "usr/share/pkgconfig"))
        for directory in directories:
            Path(directory).mkdir(parents=True)
        calls = []
        class MetadataCommands:
            runner = types.SimpleNamespace(records=[])
            def run(inner, label, arguments, **options):
                calls.append((label, arguments, options))
                inner.runner.records.append({"label": label, "arguments": arguments,
                    "exit_code": 1 if label.endswith("homebrew-libdir-control") else 0})
                return "", ""
        roster = native.Roster(reader.file_identity, time.monotonic() + 15)
        with mock.patch.object(native, "SYSTEM_PKG_CONFIG", str(alias)), mock.patch.object(native, "SYSTEM_PKG_CONFIG_DIRECTORIES", directories):
            physical, environment, control = native.sqlite_metadata_provider(MetadataCommands(), roster, "/brew/pkgconf")
        self.assertEqual(physical, str(binary))
        self.assertEqual(roster.entries[str(alias)]["target"], "pkgconf")
        self.assertEqual(roster.entries[str(binary)]["sha256"], hashlib.sha256(binary.read_bytes()).hexdigest())
        self.assertEqual(control["exit_code"], 1)
        self.assertTrue(calls[0][2]["observe_nonzero"])
        self.assertEqual(calls[0][1], ["/brew/pkgconf", "--variable=libdir", "sqlite3"])
        self.assertEqual(calls[1][1], [str(binary), "--version"])
        self.assertEqual(calls[2][1], [str(binary), "--variable=pc_path", "pkg-config"])
        self.assertEqual(environment["PKG_CONFIG_LIBDIR"], ":".join(directories))

    def test_absent_distro_provider_preserves_prior_control_record(self):
        records = []
        class MetadataCommands:
            runner = types.SimpleNamespace(records=records)
            def run(inner, label, arguments, **options):
                records.append({"label": label, "exit_code": 1})
                return "", ""
        roster = native.Roster(reader.file_identity, time.monotonic() + 15)
        with mock.patch.object(native, "SYSTEM_PKG_CONFIG", str(self.root / "absent")):
            with self.assertRaisesRegex(RuntimeError, "Required native path is absent"):
                native.sqlite_metadata_provider(MetadataCommands(), roster, "/brew/pkgconf")
        self.assertEqual(records[0]["label"], "sqlite3-homebrew-libdir-control")
        self.assertEqual(records[0]["exit_code"], 1)


if __name__ == "__main__":
    unittest.main()
