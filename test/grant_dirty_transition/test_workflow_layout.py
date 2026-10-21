"""Exercise the actual repository workflow path and explicit packet-only fixture boundary."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import test_timing_profile as controls

WORKFLOW_FIXTURE = None


class WorkflowLayoutControls(unittest.TestCase):
    def setUp(self):
        self.raw = controls.workflow_bytes(ROOT, WORKFLOW_FIXTURE)
        self.temporary = tempfile.TemporaryDirectory(prefix='atlas workflow physical layouts ')
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name) / 'integrated public checkout'
        self.packet = self.repository / 'test/grant_assignment_cost'
        self.packet.mkdir(parents=True)
        self.installed = self.repository / '.github/workflows/grant-installed-mac.yml'
        self.fixture = Path(self.temporary.name) / 'explicit local proposal.yml'

    def write_installed(self, raw=None):
        self.installed.parent.mkdir(parents=True, exist_ok=True)
        self.installed.write_text(self.raw if raw is None else raw)

    def exercise_contract(self, fixture=None):
        case = controls.CausalCalibrationControls('test_active_workflow_opt_in_and_exact_original_deadlines_remain_explicit')
        with mock.patch.object(controls, 'ROOT', self.packet), mock.patch.object(controls, 'WORKFLOW_FIXTURE', fixture):
            case.test_active_workflow_opt_in_and_exact_original_deadlines_remain_explicit()

    def test_actual_integrated_repository_layout_passes_original_workflow_assertions(self):
        self.write_installed()
        self.assertFalse((self.packet / 'grant-causal-mac.proposed.yml').exists())
        self.exercise_contract()

    def test_packet_only_layout_uses_explicit_local_proposal_fixture(self):
        self.fixture.write_text(self.raw)
        self.assertFalse(self.installed.exists())
        self.exercise_contract(self.fixture)

    def test_missing_installed_workflow_refuses_with_an_unselected_packet_proposal_present(self):
        (self.packet / 'grant-causal-mac.proposed.yml').write_text(self.raw)
        with self.assertRaisesRegex(RuntimeError, 'Bounded regular workflow source required'):
            self.exercise_contract()

    def test_changed_installed_timing_probe_assertion_refuses(self):
        self.write_installed(self.raw.replace('"--timing-true-sha256"', '"--changed-timing-argument"'))
        with self.assertRaises(AssertionError):
            self.exercise_contract()

    def test_changed_installed_outer_step_limit_refuses(self):
        self.write_installed(self.raw.replace('timeout-minutes: 82', 'timeout-minutes: 83'))
        with self.assertRaises(AssertionError):
            self.exercise_contract()

    def test_changed_installed_optimized_suite_assertion_refuses(self):
        self.write_installed(self.raw.replace('python3 -O -I -S -B test/grant_assignment_cost/test_timing_profile.py',
                                              'python3 -I -S -B test/grant_assignment_cost/test_timing_profile.py'))
        with self.assertRaises(AssertionError):
            self.exercise_contract()

    def test_missing_explicit_fixture_refuses_without_a_layout_fallback(self):
        self.write_installed()
        with self.assertRaisesRegex(RuntimeError, 'Bounded regular workflow source required'):
            self.exercise_contract(self.fixture)

    def test_selected_workflow_alias_refuses(self):
        self.fixture.write_text(self.raw)
        self.installed.parent.mkdir(parents=True)
        self.installed.symlink_to(self.fixture)
        with self.assertRaisesRegex(RuntimeError, 'Bounded regular workflow source required'):
            self.exercise_contract()

    def test_selected_workflow_retains_a_finite_source_byte_limit(self):
        self.write_installed(self.raw + ' ' * (64 * 2**10))
        with self.assertRaisesRegex(RuntimeError, 'Bounded regular workflow source required'):
            self.exercise_contract()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--workflow-fixture', type=Path)
    options, remaining = parser.parse_known_args()
    WORKFLOW_FIXTURE = options.workflow_fixture
    sys.argv = [sys.argv[0], *remaining]
    with mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('Source-only tests intercept workload creation')), \
         mock.patch.object(os, 'kill', side_effect=AssertionError('Source-only tests intercept process signals')), \
         mock.patch.object(os, 'killpg', side_effect=AssertionError('Source-only tests intercept group signals')):
        unittest.main(verbosity=2)
