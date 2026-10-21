"""Size-only TAR metadata controls using benign ASCII and zero-filled bytes."""
import argparse
from contextlib import ExitStack
import gzip
import io
import json
from pathlib import Path
import sys
import tarfile
import unittest
from unittest import mock

PARSER=argparse.ArgumentParser(description=__doc__)
PARSER.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parent/'source')
PARSER.add_argument('--case',action='append',default=[])
ARGS=PARSER.parse_args()
sys.path.insert(0,str(ARGS.source_root.resolve(strict=True)))
import bottle_source_screen as screen
import stage_results as stage

ALLOWANCE=8388608
GUARD_CALLS=[]
OBSERVATIONS=[]

class ReadObservation(io.BytesIO):
    def __init__(self,raw):super().__init__(raw);self.reads=[]
    def read(self,size=-1):
        start=self.tell();value=super().read(size)
        self.reads.append({'start':start,'requested':size,'returned':len(value)})
        return value

class ArchiveCapacityControls(unittest.TestCase):
    def setUp(self):
        self.assertEqual(screen.MAX_METADATA_BYTES,ALLOWANCE)
        self.rules=stage.load_rules();self.guards=ExitStack();self.addCleanup(self.guards.close)
        def guard(*args,**settings):
            GUARD_CALLS.append('external');raise AssertionError('Authored source fixture provider required')
        for target in ('subprocess.Popen','os.system','os.fork','os.posix_spawn','os.posix_spawnp','os.kill','os.killpg'):
            self.guards.enter_context(mock.patch(target,side_effect=guard))
        self.addCleanup(lambda:self.assertEqual(GUARD_CALLS,[]))
    def header(self,name='public.txt',size=0,kind=tarfile.REGTYPE):
        member=tarfile.TarInfo(name);member.size=size;member.type=kind
        return member.tobuf(format=tarfile.USTAR_FORMAT)
    def pax_record(self,size,key='public-key'):
        prefix=(str(size)+' '+key+'=').encode('ascii')
        record=prefix+b'a'*(size-len(prefix)-1)+b'\n'
        self.assertEqual(len(record),size);return record
    def extension(self,size,kind=tarfile.XHDTYPE):
        payload=self.pax_record(size) if kind in (tarfile.XHDTYPE,tarfile.XGLTYPE) else b'a'*(size-1)+b'\0'
        return self.header('public-metadata',size,kind)+payload+b'\0'*((-size)%512)
    def inspect(self,raw):return screen.archive_metadata('public-capacity.tar.gz',gzip.compress(raw,mtime=0),self.rules)
    def observe_parser(self,raw):
        tracked=ReadObservation(raw)
        patch=mock.patch.object(screen,'expanded_archive',return_value=tracked)
        return tracked,patch
    def accepted(self,raw,headers,trailer):
        stream,value=self.inspect(raw)
        with stream:self.assertEqual(stream.getbuffer().nbytes,len(raw))
        self.assertEqual(value['physical_metadata_bytes'],headers+trailer)
        self.assertEqual(value['physical_header_and_extension_bytes'],headers)
        self.assertEqual(value['tar_trailer_bytes'],trailer)
        OBSERVATIONS.append({'case':self.id().split('.')[-1],'accepted':True,'header_and_extension_bytes':headers,'trailer_bytes':trailer,'combined_bytes':headers+trailer})
    def refused_parser(self,raw,expected_reads):
        tracked,patch=self.observe_parser(raw)
        with patch,self.assertRaisesRegex(RuntimeError,'metadata capacity required before parser reading'):
            self.inspect(raw)
        self.assertEqual([(r['start'],r['requested']) for r in tracked.reads],expected_reads)
        self.assertTrue(tracked.closed)
        OBSERVATIONS.append({'case':self.id().split('.')[-1],'accepted':False,'underlying_parser_reads':tracked.reads})
    def test_one_header_and_trailer_at_combined_boundary_accept(self):
        trailer=ALLOWANCE-512;self.accepted(self.header()+b'\0'*trailer,512,trailer)
    def test_one_header_and_trailer_one_byte_beyond_refuse_before_trailer_read(self):
        trailer=ALLOWANCE-512+1;raw=self.header()+b'\0'*trailer;tracked,patch=self.observe_parser(raw)
        with patch,self.assertRaisesRegex(RuntimeError,'combined physical TAR metadata and trailer capacity'):
            self.inspect(raw)
        self.assertFalse(any(r['requested']==trailer for r in tracked.reads));self.assertTrue(tracked.closed)
        OBSERVATIONS.append({'case':self.id().split('.')[-1],'accepted':False,'combined_bytes':ALLOWANCE+1,'underlying_reads':tracked.reads})
    def test_two_headers_and_trailer_at_combined_boundary_accept(self):
        trailer=ALLOWANCE-1024;self.accepted(self.header('public-one')+self.header('public-two')+b'\0'*trailer,1024,trailer)
    def test_PAX_extension_and_trailer_at_combined_boundary_accept(self):
        extension=self.extension(ALLOWANCE-2048);self.accepted(extension+self.header()+b'\0'*1024,ALLOWANCE-1024,1024)
    def test_PAX_extension_and_trailer_one_byte_beyond_refuse(self):
        raw=self.extension(ALLOWANCE-2048)+self.header()+b'\0'*1025
        with self.assertRaisesRegex(RuntimeError,'combined physical TAR metadata and trailer capacity'):self.inspect(raw)
        OBSERVATIONS.append({'case':self.id().split('.')[-1],'accepted':False,'combined_bytes':ALLOWANCE+1})
    def test_local_PAX_payload_beyond_remaining_refuses_before_payload_read(self):
        self.refused_parser(self.extension(ALLOWANCE-511)+self.header()+b'\0'*1024,[(0,512)])
    def test_global_PAX_payload_beyond_remaining_refuses_before_payload_read(self):
        self.refused_parser(self.extension(ALLOWANCE-511,tarfile.XGLTYPE)+self.header()+b'\0'*1024,[(0,512)])
    def test_GNU_long_name_beyond_remaining_refuses_before_payload_read(self):
        self.refused_parser(self.extension(ALLOWANCE-511,tarfile.GNUTYPE_LONGNAME)+self.header()+b'\0'*1024,[(0,512)])
    def test_GNU_long_link_beyond_remaining_refuses_before_payload_read(self):
        self.refused_parser(self.extension(ALLOWANCE-511,tarfile.GNUTYPE_LONGLINK)+self.header()+b'\0'*1024,[(0,512)])
    def test_cumulative_PAX_payloads_use_remaining_allowance(self):
        first=ALLOWANCE//2-512;raw=self.extension(first,tarfile.XGLTYPE)+self.extension(ALLOWANCE//2)+self.header()+b'\0'*1024
        self.refused_parser(raw,[(0,512),(512,first),(ALLOWANCE//2,512)])
    def test_next_header_after_exact_parser_allowance_refuses_before_header_read(self):
        payload=ALLOWANCE-512
        self.refused_parser(self.extension(payload)+self.header()+b'\0'*1024,[(0,512),(512,payload)])
    def test_standard_parser_uses_public_fileobj_interface(self):
        original=tarfile.open;observed=[]
        def public_open(*args,**settings):
            fileobj=settings['fileobj'];self.assertEqual(settings['mode'],'r:')
            self.assertTrue(all(callable(getattr(fileobj,key)) for key in ('read','seek','tell')))
            self.assertNotIn('tarinfo',settings);observed.append(True)
            return original(*args,**settings)
        with mock.patch.object(screen.tarfile,'open',side_effect=public_open):self.accepted(self.header()+b'\0'*1024,512,1024)
        self.assertEqual(observed,[True])
    def compressed_regular(self,size):
        output=io.BytesIO()
        with gzip.GzipFile(fileobj=output,mode='wb',mtime=0) as stream:
            stream.write(self.header(size=size));chunk=b'\0'*(2**20)
            whole,tail=divmod(size,len(chunk))
            for _ in range(whole):stream.write(chunk)
            stream.write(chunk[:tail]);stream.write(b'\0'*((-size)%512+1024))
        return output.getvalue()
    def test_128_MiB_regular_file_preserves_allowance_and_body_exemption(self):
        size=128*2**20;stream,value=screen.archive_metadata('public-regular.tar.gz',self.compressed_regular(size),self.rules)
        with stream:
            self.assertEqual(stream.getbuffer().nbytes,size+1536)
            with tarfile.open(fileobj=stream,mode='r:') as archive:
                member=archive.next();self.assertTrue(member.isfile());self.assertEqual(member.size,size)
                with archive.extractfile(member) as body:
                    body.seek(size-32);self.assertEqual(body.read(),b'\0'*32)
        self.assertEqual(value['physical_metadata_bytes'],1536)
        OBSERVATIONS.append({'case':self.id().split('.')[-1],'accepted':True,'regular_file_bytes':size,'combined_metadata_bytes':1536})
    def test_128_MiB_regular_file_plus_one_preserves_original_size_refusal(self):
        size=128*2**20+1
        with self.assertRaisesRegex(RuntimeError,'original archive member count/size'):
            screen.archive_metadata('public-regular.tar.gz',self.compressed_regular(size),self.rules)
        OBSERVATIONS.append({'case':self.id().split('.')[-1],'accepted':False,'regular_file_bytes':size})

if __name__=='__main__':
    suite=unittest.TestSuite(ArchiveCapacityControls(case) for case in ARGS.case) if ARGS.case else unittest.defaultTestLoader.loadTestsFromTestCase(ArchiveCapacityControls)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps({'tests_run':result.testsRun,'errors':len(result.errors),'failures':len(result.failures),'skips':len(result.skipped),'actual_guard_calls':len(GUARD_CALLS),'observations':OBSERVATIONS},sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() and not GUARD_CALLS else 2)
