"""Source and metadata controls; real POSIX execution belongs to hosted CI."""
import ast
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

PATH = Path(__file__).with_name("sdk_owned_group_controls.py")
SPEC = importlib.util.spec_from_file_location("hosted_group_controls_source", PATH)
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


def command_record(status):
    return {"pid": 765432, "original_group": 765432,
            "terminal_group_observation": {"group": 765432, "phase": "direct_child_returned", "status": status},
            "writers_confirmed_retired": status == "absent",
            "stdout_sha256": "a" * 64 if status == "absent" else None,
            "stderr_sha256": "b" * 64 if status == "absent" else None}


class HostedSourceTest(unittest.TestCase):
    def test_compiles_controller_and_both_fixture_sources(self):
        for label, text in [(str(PATH), PATH.read_text()), ("normal", CONTROL.NORMAL_SOURCE),
                            ("descendant", CONTROL.DESCENDANT_SOURCE)]:
            compile(text, label, "exec")

    def test_fixture_processes_have_one_fork_and_cooperative_deadline(self):
        normal = ast.parse(CONTROL.NORMAL_SOURCE)
        tree = ast.parse(CONTROL.DESCENDANT_SOURCE)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertEqual(sum(isinstance(node.func, ast.Attribute) and node.func.attr == "fork" for node in calls), 1)
        self.assertFalse(any(isinstance(node.func, ast.Attribute) and node.func.attr in ("Popen", "setsid", "setpgid") for node in calls))
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                             and node.func.attr == "fork" for node in ast.walk(normal)))
        self.assertIn("time.monotonic() + 6", CONTROL.DESCENDANT_SOURCE)
        self.assertIn('phase = "self_deadline"', CONTROL.DESCENDANT_SOURCE)
        self.assertIn('phase = "released"', CONTROL.DESCENDANT_SOURCE)
        self.assertEqual(CONTROL.DESCENDANT_SECONDS, 6)

    def test_local_and_self_hosted_environments_refuse_before_real_controls(self):
        for environment in ({}, {"GITHUB_ACTIONS": "true"},
                            {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}):
            with self.subTest(environment=environment), self.assertRaises(CONTROL.ControlError):
                CONTROL.hosted_guard(environment)
        CONTROL.hosted_guard({"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"})

    def test_execute_refuses_locally_before_sdk_loading_or_signals(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(CONTROL.importlib.util, "spec_from_file_location") as load, \
                mock.patch.object(CONTROL.os, "killpg") as signal_group:
            with self.assertRaises(CONTROL.ControlError):
                CONTROL.execute(SimpleNamespace())
            load.assert_not_called()
            signal_group.assert_not_called()

    def test_static_process_and_time_contract(self):
        tree = ast.parse(PATH.read_text())
        execute = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "execute")
        run_calls = [node for node in ast.walk(execute) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Attribute) and node.func.attr == "run"]
        self.assertEqual(len(run_calls), 2)
        self.assertEqual((CONTROL.PRIMARY_SECONDS, CONTROL.FINAL_SECONDS), (35, 5))
        self.assertEqual((CONTROL.NORMAL_SECONDS, CONTROL.LEADER_SECONDS), (3, 4))
        self.assertEqual(CONTROL.OUTPUT_LIMIT, 1024 * 1024)

    def test_reviewed_driver_hash_matches_retained_complete_proposal(self):
        path = PATH.parents[1] / "proposed-complete-v102/sdk_install_qualification.py"
        if path.exists():
            self.assertEqual(CONTROL.sha256(path), CONTROL.REVIEWED_DRIVER_ANCESTOR_SHA256)
            self.assertEqual(CONTROL.runner_source_sha256(path), CONTROL.REVIEWED_RUNNER_SOURCE_SHA256)
        installed_driver = PATH.with_name("sdk_install_qualification.py")
        if installed_driver.exists():
            self.assertEqual(CONTROL.runner_source_sha256(installed_driver), CONTROL.REVIEWED_RUNNER_SOURCE_SHA256)
        self.assertEqual(len(CONTROL.REVIEWED_DRIVER_ANCESTOR_SHA256), 64)

    def test_changed_runner_source_has_a_distinct_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "driver.py"
            path.write_text("class Runner:\n    def run(self):\n        return 1\n")
            self.assertNotEqual(CONTROL.runner_source_sha256(path), CONTROL.REVIEWED_RUNNER_SOURCE_SHA256)


class GroupMetadataTest(unittest.TestCase):
    def test_accepts_exact_absent_and_present_record_metadata(self):
        CONTROL.verify_record(command_record("absent"), "absent")
        CONTROL.verify_record(command_record("present"), "present")

    def test_refuses_conflicting_output_retirement_group_and_phase(self):
        changes = [("stdout_sha256", "a" * 64), ("writers_confirmed_retired", True),
                   ("original_group", 765433)]
        for field, value in changes:
            damaged = command_record("present")
            damaged[field] = value
            with self.subTest(field=field), self.assertRaises(CONTROL.ControlError):
                CONTROL.verify_record(damaged, "present")
        damaged = command_record("present")
        damaged["terminal_group_observation"]["phase"] = "started"
        with self.assertRaises(CONTROL.ControlError):
            CONTROL.verify_record(damaged, "present")

    def test_original_group_observer_has_only_mocked_signal_zero_cases(self):
        for failure, status in [(ProcessLookupError("metadata absent"), "absent"),
                                (None, "present"), (PermissionError("metadata refusal"), "unverifiable")]:
            with self.subTest(status=status), mock.patch.object(CONTROL.os, "killpg", side_effect=failure) as observe:
                self.assertEqual(CONTROL.observe_group(765432)["status"], status)
                observe.assert_called_once_with(765432, 0)

    def test_wait_records_present_then_absent_with_mocked_time(self):
        values = [{"group": 765432, "status": "present"}, {"group": 765432, "status": "absent"}]
        with mock.patch.object(CONTROL, "observe_group", side_effect=values), \
                mock.patch.object(CONTROL.time, "monotonic", return_value=0), \
                mock.patch.object(CONTROL.time, "sleep") as wait:
            result = CONTROL.await_absence(765432, 1)
            self.assertTrue(result["passed"])
            self.assertEqual(len(result["samples"]), 2)
            wait.assert_called_once_with(0.04)

    def test_wait_refuses_expired_or_unverifiable_metadata(self):
        for status in ("present", "unverifiable"):
            with self.subTest(status=status), \
                    mock.patch.object(CONTROL, "observe_group", return_value={"group": 765432, "status": status}), \
                    mock.patch.object(CONTROL.time, "monotonic", return_value=1), \
                    self.assertRaises(CONTROL.ControlError):
                CONTROL.await_absence(765432, 0)

    def test_receipt_size_and_exclusive_write_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "receipt.json"
            CONTROL.save(target, {"passed": True})
            with self.assertRaises(FileExistsError):
                CONTROL.save(target, {"passed": True})
            with self.assertRaises(CONTROL.ControlError):
                CONTROL.save(Path(temporary) / "large.json", {"value": "x" * 65536})


if __name__ == "__main__":
    unittest.main()
