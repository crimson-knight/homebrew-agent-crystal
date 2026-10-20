import importlib.util
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock

SOURCE = pathlib.Path(__file__).with_name("sdk_cpu_diagnostic.py")
SPEC = importlib.util.spec_from_file_location("cpu_diagnostic_under_test", SOURCE)
diagnostic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostic)


class QualificationError(RuntimeError):
    pass


class FakeRunner:
    def __init__(self, output):
        self.output = output
        self.records = []
        self.group_observations = []
        self.writers_confirmed_retired = True
        self.deadline = 0
        self.code = 0
        self.refusal = None
        self.version = "Crystal exact test version\n"
        self.prefix = output / "installed"
        self.exception = None

    def run(self, label, arguments, **options):
        code = self.code
        text = b""
        if label == "brew-prefix":
            text = (str(self.prefix) + "\n").encode()
        elif label == "brew-root":
            text = (str(self.output) + "\n").encode()
        elif label == "brew-receipt":
            text = b'{"formulae": []}'
        elif label in ("acrystal-version", "agent-crystal-version", "crystal-alpha-version"):
            text = self.version.encode()
        elif label.endswith("-build"):
            pathlib.Path(arguments[-1]).write_bytes(b"fake ELF metadata")
        elif label == "default-runtime":
            code = -4
        elif label in ("generic-runtime", "generic-eval"):
            text = b"42\n"
        elif label == "default-eval":
            code = 1
            text = b""
        (self.output / (label + ".stdout.txt")).write_bytes(text)
        (self.output / (label + ".stderr.txt")).write_bytes(b"")
        record = {"label": label, "exit_code": code, "refusal": self.refusal,
                  "arguments": [str(value) for value in arguments],
                  "cache": options["environment"].get("CRYSTAL_CACHE_DIR"),
                  "writers_confirmed_retired": self.writers_confirmed_retired}
        self.records.append(record)
        self.group_observations.append({"status": "absent"})
        if self.exception:
            raise self.exception
        if self.refusal:
            raise QualificationError(self.refusal)
        if code != 0:
            raise QualificationError(f"{label} exited {code}; expected 0")
        return text.decode(), ""


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cpu source controls ")
        self.root = pathlib.Path(self.temporary.name)
        self.runner = FakeRunner(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def observe(self):
        return diagnostic.observe(self.runner, "case", ["mocked"], cwd=self.root, environment={}, seconds=2)

    def test_zero_command_observation(self):
        self.assertEqual(self.observe()["exit_code"], 0)

    def test_actual_negative_signal_is_diagnostic(self):
        self.runner.code = -4
        self.assertEqual(self.observe()["exit_code"], -4)

    def test_nonzero_normal_exit_is_diagnostic(self):
        self.runner.code = 1
        self.assertEqual(self.observe()["exit_code"], 1)

    def test_original_refusal_survives(self):
        self.runner.refusal = "Command exceeded its time budget"
        with self.assertRaisesRegex(QualificationError, "time budget"):
            self.observe()

    def test_original_group_absence_required(self):
        self.runner.writers_confirmed_retired = False
        with self.assertRaisesRegex(RuntimeError, "confirmed original-group absence"):
            self.observe()

    def test_unexpected_exception_survives_nonzero_record(self):
        self.runner.code = -4
        self.runner.exception = OSError("original failure")
        with self.assertRaisesRegex(OSError, "original failure"):
            self.observe()

    def test_missing_record_refuses(self):
        with mock.patch.object(self.runner, "run", side_effect=RuntimeError("before record")):
            with self.assertRaisesRegex(RuntimeError, "before record"):
                self.observe()

    def test_boolean_nonzero_status_refuses(self):
        self.runner.code = True
        with self.assertRaises(QualificationError):
            self.observe()

    def test_complete_raw_budget_refuses(self):
        (self.root / "large.txt").write_bytes(b"1234")
        with mock.patch.object(diagnostic, "MAXIMUM_RAW_BYTES", 3):
            with self.assertRaisesRegex(RuntimeError, "raw-output budget"):
                self.observe()

    def test_build_failure_phase(self):
        self.assertEqual(diagnostic.contrast_phase({"exit_code": -4}, None, self.root), "build_command_failed")

    def test_generated_sigill_phase(self):
        self.assertEqual(diagnostic.contrast_phase({"exit_code": 0}, {"exit_code": -4}, self.root), "generated_program_sigill")

    def test_unobserved_runtime_phase(self):
        self.assertEqual(diagnostic.contrast_phase({"exit_code": 0}, None, self.root), "runtime_unobserved")

    def test_output_mismatch_is_recorded(self):
        (self.root / "runtime.stdout.txt").write_bytes(b"43\n")
        self.assertEqual(diagnostic.contrast_phase({"exit_code": 0}, {"exit_code": 0, "label": "runtime"}, self.root),
                         "generated_program_failed_or_output_differs")

    def test_exact_arithmetic_runtime_passes(self):
        (self.root / "runtime.stdout.txt").write_bytes(b"42\n")
        self.assertEqual(diagnostic.contrast_phase({"exit_code": 0}, {"exit_code": 0, "label": "runtime"}, self.root),
                         "arithmetic_build_and_runtime_passed")

    def test_target_environment_is_explicit(self):
        with mock.patch.dict(diagnostic.os.environ, {"CRYSTAL_OPTS": "--mcpu native", "SECRET_TEST_VALUE": "private"}):
            environment = diagnostic.environment_for(self.root)
        self.assertNotIn("CRYSTAL_OPTS", environment)
        self.assertNotIn("SECRET_TEST_VALUE", environment)
        self.assertEqual(environment["CRYSTAL_WORKERS"], "1")

    def test_local_actual_execution_requires_hosted_linux(self):
        with mock.patch.object(diagnostic.platform, "system", return_value="Darwin"):
            with self.assertRaisesRegex(RuntimeError, "GitHub-hosted Linux"):
                diagnostic.qualify(types.SimpleNamespace())

    def full_case(self, *, cleanup_error=False, mutation=False, command_failure=False):
        repository = self.root / "repository"
        (repository / "test").mkdir(parents=True)
        (repository / "Formula").mkdir()
        formula = repository / "Formula/agent-crystal.rb"
        formula.write_bytes(b"formula fixture")
        lock = {"formula_sha256": diagnostic.digest(formula), "full_versions": {"Linux": self.runner.version}}
        lock_path = repository / "test/sdk_source_lock.json"
        lock_path.write_text(json.dumps({"alpha": lock}))
        driver_path = repository / "test/sdk_install_qualification.py"
        driver_path.write_bytes(b"mocked reviewed driver")
        output = self.root / "fresh diagnostic output"
        prefix = output / "installed"
        def create_runner(output):
            runner = FakeRunner(output)
            if command_failure:
                runner.code = 1
            for path in (prefix / "bin", prefix / "libexec", prefix / ".brew", prefix / "share/agent-crystal/src"):
                path.mkdir(parents=True)
            (prefix / ".brew/agent-crystal.rb").write_bytes(formula.read_bytes())
            (prefix / "INSTALL_RECEIPT.json").write_text("{}")
            (prefix / "libexec/agent-crystal-bin").write_bytes(b"compiler identity fixture")
            for alias in ("acrystal", "agent-crystal", "crystal-alpha"):
                (prefix / "bin" / alias).write_bytes(b"wrapper identity fixture")
            return runner
        tool = self.root / "tool"
        tool.write_bytes(b"metadata fixture tool")
        def which(name):
            return str(prefix / "bin" / name) if name in ("acrystal", "agent-crystal", "crystal-alpha") else str(tool)
        calls = 0
        def tree_identity(path):
            nonlocal calls
            calls += 1
            if mutation and calls > 1:
                return {"changed": True}
            return {"exact": True}
        fake_driver = types.SimpleNamespace(Runner=create_runner, verify_formula_receipt=lambda *args: None,
            tree_identity=tree_identity, verify_stdlib=lambda *args: None, verify_wrapper=lambda *args: None)
        arguments = types.SimpleNamespace(repository=repository, output=output,
            source_sha256=diagnostic.digest(SOURCE), python_sha256=diagnostic.digest(pathlib.Path(diagnostic.sys.executable).resolve()))
        cleanup = mock.Mock(side_effect=OSError("retained cleanup failure")) if cleanup_error else lambda path: None
        with mock.patch.dict(diagnostic.os.environ, {"GITHUB_ACTIONS": "true"}), \
             mock.patch.object(diagnostic.platform, "system", return_value="Linux"), \
             mock.patch.object(diagnostic, "LOCK_SHA256", diagnostic.digest(lock_path)), \
             mock.patch.object(diagnostic, "DRIVER_SHA256", diagnostic.digest(driver_path)), \
             mock.patch.object(diagnostic, "load_driver", return_value=fake_driver), \
             mock.patch.object(diagnostic, "cpu_metadata", return_value={"mocked": True}), \
             mock.patch.object(diagnostic.shutil, "which", side_effect=which), \
             mock.patch.object(diagnostic.resource, "setrlimit"), \
             mock.patch.object(diagnostic.shutil, "rmtree", side_effect=cleanup), \
             mock.patch.object(diagnostic.pathlib.Path, "exists", autospec=True, side_effect=lambda path: True):
            code = diagnostic.qualify(arguments)
        return code, json.loads((output / "CPU_DIAGNOSTIC.json").read_text())

    def test_complete_mocked_sigill_generic_contrast_keeps_acceptance_separate(self):
        code, result = self.full_case()
        self.assertEqual(code, 0)
        self.assertEqual(result["contrasts"]["default"]["phase"], "generated_program_sigill")
        self.assertEqual(result["contrasts"]["generic"]["phase"], "arithmetic_build_and_runtime_passed")
        self.assertFalse(result["ordinary_smoke_accepted"])
        self.assertFalse(result["sdk_accepted"])
        self.assertTrue(result["protected_identities_verified"])
        default = result["contrasts"]["default"]
        generic = result["contrasts"]["generic"]
        self.assertNotIn("--mcpu", default["build"]["arguments"])
        self.assertEqual(generic["build"]["arguments"][2:4], ["--mcpu", "generic"])
        self.assertEqual(default["eval"]["arguments"][-1], "puts 40 + 2")
        self.assertEqual(generic["eval"]["arguments"][-1], "puts 40 + 2")
        self.assertNotEqual(default["build"]["cache"], generic["build"]["cache"])

    def test_cleanup_error_survives_result_write(self):
        code, result = self.full_case(cleanup_error=True)
        self.assertEqual(code, 1)
        self.assertIn("retained cleanup failure", result["cleanup_error"])

    def test_stdlib_mutation_refuses_complete_diagnostic(self):
        code, result = self.full_case(mutation=True)
        self.assertEqual(code, 1)
        self.assertIn("standard library changed", result["cleanup_error"])

    def test_recorded_terminal_elapsed_over_budget_refuses_completion(self):
        with mock.patch.object(diagnostic.time, "monotonic", side_effect=[0.0, 239.0, 241.0]):
            code, result = self.full_case()
        self.assertEqual(code, 1)
        self.assertFalse(result["diagnostic_complete"])
        self.assertEqual(result["elapsed_seconds"], 241.0)
        self.assertEqual(result["absolute_deadline_monotonic_seconds"], 240.0)
        self.assertFalse(result["terminal_clock_verified"])
        self.assertIn("terminal time budget", result["finalization_errors"][0])
        self.assertFalse(result["ordinary_smoke_accepted"])
        self.assertFalse(result["sdk_accepted"])
        self.assertFalse(result["supported_installation_accepted"])

    def test_final_provider_failure_retains_original_and_cleanup_errors(self):
        real_provider = diagnostic.provider
        python = pathlib.Path(diagnostic.sys.executable).resolve()
        def unavailable(path):
            if pathlib.Path(path).resolve() == python:
                raise OSError("MODELED final Python provider read became unavailable")
            return real_provider(path)
        with mock.patch.object(diagnostic, "provider", side_effect=unavailable):
            code, result = self.full_case(command_failure=True, cleanup_error=True)
        self.assertEqual(code, 1)
        self.assertFalse(result["diagnostic_complete"])
        self.assertIn("brew-prefix must succeed", result["error"])
        self.assertIn("retained cleanup failure", result["cleanup_error"])
        self.assertIn("final Python provider read became unavailable", result["finalization_errors"][0])
        self.assertIsNone(result["python_provider"])

    def test_final_provider_observation_is_included_in_terminal_time(self):
        real_provider = diagnostic.provider
        python = pathlib.Path(diagnostic.sys.executable).resolve()
        clock = [0.0]
        def advance_after_provider(path):
            result = real_provider(path)
            if pathlib.Path(path).resolve() == python:
                clock[0] = 241.0
            return result
        with mock.patch.object(diagnostic, "provider", side_effect=advance_after_provider), \
                mock.patch.object(diagnostic.time, "monotonic", side_effect=lambda: clock[0]):
            code, result = self.full_case()
        self.assertEqual(code, 1)
        self.assertEqual(result["finished_monotonic_seconds"], 241.0)
        self.assertFalse(result["diagnostic_complete"])
        self.assertFalse(result["terminal_clock_verified"])

    def test_exact_terminal_deadline_preserves_diagnostic_completion(self):
        with mock.patch.object(diagnostic.time, "monotonic", side_effect=[0.0, 239.0, 240.0]):
            code, result = self.full_case()
        self.assertEqual(code, 0)
        self.assertTrue(result["diagnostic_complete"])
        self.assertTrue(result["terminal_clock_verified"])
        self.assertEqual(result["elapsed_seconds"], 240.0)
        self.assertEqual(result["finalization_errors"], [])
        self.assertFalse(result["ordinary_smoke_accepted"])

    def test_changed_final_python_identity_refuses_completion(self):
        real_provider = diagnostic.provider
        python = pathlib.Path(diagnostic.sys.executable).resolve()
        def changed(path):
            result = real_provider(path)
            if pathlib.Path(path).resolve() == python:
                result["sha256"] = "0" * 64
            return result
        with mock.patch.object(diagnostic, "provider", side_effect=changed):
            code, result = self.full_case()
        self.assertEqual(code, 1)
        self.assertFalse(result["diagnostic_complete"])
        self.assertEqual(result["python_provider"]["sha256"], "0" * 64)
        self.assertIn("SHA-256 differs from admitted identity", result["finalization_errors"][0])
        self.assertFalse(result["ordinary_smoke_accepted"])
        self.assertFalse(result["sdk_accepted"])
        self.assertFalse(result["supported_installation_accepted"])

    def test_restored_final_python_identity_completes_normally(self):
        real_provider = diagnostic.provider
        python = pathlib.Path(diagnostic.sys.executable).resolve()
        def changed(path):
            result = real_provider(path)
            if pathlib.Path(path).resolve() == python:
                result["sha256"] = "0" * 64
            return result
        with mock.patch.object(diagnostic, "provider", side_effect=changed):
            refused_code, refused = self.full_case()
        self.assertEqual(refused_code, 1)
        self.assertFalse(refused["diagnostic_complete"])
        self.root = self.root / "restored provider control"
        self.root.mkdir()
        code, result = self.full_case()
        self.assertEqual(code, 0)
        self.assertTrue(result["diagnostic_complete"])
        self.assertTrue(result["terminal_clock_verified"])
        self.assertEqual(result["python_provider"]["sha256"], diagnostic.digest(python))
        self.assertEqual(result["finalization_errors"], [])
        self.assertFalse(result["ordinary_smoke_accepted"])
        self.assertFalse(result["sdk_accepted"])
        self.assertFalse(result["supported_installation_accepted"])

    def test_original_and_cleanup_errors_both_survive(self):
        code, result = self.full_case(command_failure=True, cleanup_error=True)
        self.assertEqual(code, 1)
        self.assertIn("brew-prefix must succeed", result["error"])
        self.assertIn("retained cleanup failure", result["cleanup_error"])


if __name__ == "__main__":
    unittest.main()
