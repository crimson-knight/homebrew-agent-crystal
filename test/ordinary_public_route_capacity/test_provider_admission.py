"""Model finite source/provider byte admission with exact boundary read observations."""
from contextlib import ExitStack
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parent))
import run_capacity_controls as driver
GUARD_CALLS=[]

class ModeledBytes:
    def __init__(self,size):self.size=size
    def __len__(self):return self.size

class ModeledFile:
    """Expose only file facts/read observations for boundary admission controls."""
    def __init__(self,size):self.size=size;self.reads=0
    def lstat(self):
        return SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o755,st_size=self.size,st_mtime_ns=3,st_ctime_ns=4)
    def read_bytes(self):self.reads+=1;return ModeledBytes(self.size)

class ProviderAdmissionControls(unittest.TestCase):
    def setUp(self):
        self.assertEqual(driver.MAX_SOURCE_BYTES,1048576);self.assertEqual(driver.MAX_PROVIDER_BYTES,67108864)
        self.guards=ExitStack();self.addCleanup(self.guards.close)
        def guard(*args,**settings):GUARD_CALLS.append('external');raise AssertionError('Authored metadata fixture provider required')
        for target in ('subprocess.Popen','os.system','os.fork','os.posix_spawn','os.posix_spawnp','os.kill','os.killpg'):
            self.guards.enter_context(mock.patch(target,side_effect=guard))
        self.addCleanup(lambda:self.assertEqual(GUARD_CALLS,[]))
    def accept(self,size,maximum):
        path=ModeledFile(size)
        def modeled_digest(raw):
            self.assertIsInstance(raw,ModeledBytes);self.assertEqual(len(raw),size)
            return SimpleNamespace(hexdigest=lambda:'e'*64)
        with mock.patch.object(driver.hashlib,'sha256',side_effect=modeled_digest):value=driver.identity(path,maximum)
        self.assertEqual(value,{'bytes':size,'sha256':'e'*64});self.assertEqual(path.reads,1)
    def refuse(self,size,maximum):
        path=ModeledFile(size)
        with self.assertRaisesRegex(RuntimeError,'required before reading'):driver.identity(path,maximum)
        self.assertEqual(path.reads,0)
    def test_source_exact_1_MiB_boundary_admits(self):self.accept(1048576,driver.MAX_SOURCE_BYTES)
    def test_source_one_byte_beyond_refuses_before_read(self):self.refuse(1048577,driver.MAX_SOURCE_BYTES)
    def test_provider_exact_64_MiB_boundary_admits(self):self.accept(67108864,driver.MAX_PROVIDER_BYTES)
    def test_provider_one_byte_beyond_refuses_before_read(self):self.refuse(67108865,driver.MAX_PROVIDER_BYTES)
    def test_retained_Ubuntu_8020928_byte_Python_fits_provider_allowance(self):self.accept(8020928,driver.MAX_PROVIDER_BYTES)
    def test_retained_Ubuntu_provider_keeps_source_allowance_distinct(self):self.refuse(8020928,driver.MAX_SOURCE_BYTES)

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ProviderAdmissionControls))
    print(json.dumps({'tests_run':result.testsRun,'errors':len(result.errors),'failures':len(result.failures),'skips':len(result.skipped),'actual_guard_calls':len(GUARD_CALLS)},sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() and not GUARD_CALLS else 2)
