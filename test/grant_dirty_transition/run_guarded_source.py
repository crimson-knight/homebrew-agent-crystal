"""Run complete inherited and fresh prerequisite source cases under process and signal guards."""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--workflow-fixture',type=Path)
parser.add_argument('--dirty-workflow-fixture',type=Path)
args=parser.parse_args()
sys.path.insert(0,str(ROOT))
started=time.monotonic();external=[]

def guarded(*a,**k):
    external.append('external workload entrypoint')
    raise AssertionError('Guarded source/mock scope')

names=('test_assignment_cost','test_same_job_policy','test_causal_only','test_timing_profile','test_workflow_layout','test_dirty_transition','test_dirty_prerequisites')
suite=unittest.TestSuite();cohorts=[]
with mock.patch.object(subprocess,'Popen',side_effect=guarded),mock.patch.object(os,'kill',side_effect=guarded), \
     mock.patch.object(os,'killpg',side_effect=guarded),mock.patch.object(os,'system',side_effect=guarded), \
     mock.patch.object(os,'fork',side_effect=guarded),mock.patch.object(os,'posix_spawn',side_effect=guarded),mock.patch.object(os,'posix_spawnp',side_effect=guarded):
    for name in names:
        module=importlib.import_module(name)
        if name in ('test_timing_profile','test_workflow_layout','test_dirty_transition'):
            module.WORKFLOW_FIXTURE=args.workflow_fixture
        if name=='test_dirty_transition':module.DIRTY_WORKFLOW_FIXTURE=args.dirty_workflow_fixture
        tests=unittest.defaultTestLoader.loadTestsFromModule(module)
        cohorts.append(dict(module=name,tests=tests.countTestCases(),sha256=hashlib.sha256((ROOT/(name+'.py')).read_bytes()).hexdigest()))
        suite.addTests(tests)
    if [row['tests'] for row in cohorts] != [23,14,23,38,9,28,24]:
        raise RuntimeError('Complete original135 and fresh24 source cases required')
    result=unittest.TextTestRunner(verbosity=2).run(suite)
print(json.dumps(dict(format='atlas-grant-dirty-guarded-source-v101',passed=result.wasSuccessful(),tests=result.testsRun,
    errors=len(result.errors),failures=len(result.failures),skipped=len(result.skipped),cohorts=cohorts,
    optimization=sys.flags.optimize,elapsed_seconds=time.monotonic()-started,actual_external_guard_calls=len(external),
    actual_local_compiler_native_container_ssh_workload_jobs=0,actual_target_cells_accepted=0,
    python_path=str(Path(sys.executable).resolve()),python_sha256=hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()),sort_keys=True,allow_nan=False))
raise SystemExit(0 if result.wasSuccessful() else 2)
