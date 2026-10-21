"""Guarded streaming producer/reader/policy controls and finite image metadata fixtures."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import native_image_evidence as images
import test_provider_observation as legacy
from types import SimpleNamespace

class StreamingProviderControls(legacy.ProviderControls):
    def setUp(self):super().setUp();self.context['stream_images']=True
    def test_actual_observed_clang_extent_streams_before_cc_version(self):
        with self.cc.open('r+b') as stream:stream.truncate(290664032)
        code,value=self.perform();self.assertEqual(code,0);self.assertEqual(len(value['commands']),20)
        row=next(r for r in value['census']['streamed_files'] if r['path']==str(self.cc));self.assertEqual(row['kind'],'metadata-provider');self.assertEqual(row['bytes'],290664032)
        proof=next(r for r in value['census']['image_evidence'] if r['original_path']==str(self.cc));self.assertLess(proof['evidence']['retained_bytes'],1024);self.assertNotEqual(proof['evidence']['retained_sha256'],row['sha256'])
    def test_public_projection_retains_finite_native_headers_with_whole_image_joins(self):
        _,value=self.perform();public=self.root/'public';legacy.staging.stage(SimpleNamespace(source=self.args.output,output=public,packet_sha256=legacy.subject.digest(legacy.ROOT/'SOURCE_PINS.json',1e30)))
        observed=legacy.subject.admit_public_projection(public,legacy.subject.digest(public/'OBSERVATION.json',1e30));self.assertEqual(observed,value)
        for row in value['census']['image_evidence']:self.assertTrue((public/row['path']).is_file())
        self.assertLess(sum(p.stat().st_size for p in public.rglob('*') if p.is_file()),2**20)
    def test_changed_retained_header_refuses_private_reader(self):
        _,value=self.perform();p=self.args.output/value['census']['image_evidence'][0]['path'];p.write_bytes(p.read_bytes()[:-1]+b'x')
        with self.assertRaises(RuntimeError):legacy.subject.admit_observation(self.args.output,legacy.subject.digest(self.args.output/'OBSERVATION.json',1e30))
    def test_missing_native_header_refuses_before_public_copy(self):
        _,value=self.perform();(self.args.output/value['census']['image_evidence'][0]['path']).unlink()
        with self.assertRaises((RuntimeError,OSError)):legacy.staging.stage(SimpleNamespace(source=self.args.output,output=self.root/'public',packet_sha256=legacy.subject.digest(legacy.ROOT/'SOURCE_PINS.json',1e30)))
        self.assertFalse((self.root/'public').exists())
    def test_resealed_header_and_review_view_still_require_fresh_physical_return(self):
        _,value=self.perform();record=value['census']['image_evidence'][0];p=self.args.output/record['path'];raw=p.read_bytes()[:-1]+b'X';p.write_bytes(raw)
        proof=record['evidence'];proof['retained_sha256']=images.sha(raw);proof['ranges'][-1]['sha256']=images.sha(raw)
        value['stable_view']=legacy.subject.stable_view(value);value['stable_view_sha256']=legacy.subject.sha(legacy.subject.canonical(value['stable_view']));legacy.subject.write(self.args.output/'OBSERVATION.json',value)
        with self.assertRaisesRegex(RuntimeError,'header return join'):legacy.subject.admit_observation(self.args.output,legacy.subject.digest(self.args.output/'OBSERVATION.json',1e30))
    def test_same_byte_native_inode_replacement_refuses_policy(self):
        _,value=self.perform();args=self.policy_args(value);raw=self.cc.read_bytes();self.cc.rename(self.cc.with_suffix('.original'));self.write(self.cc,raw,0o755)
        with self.assertRaises(RuntimeError):legacy.subject.materialize(args,self.context,time.monotonic())
    def test_changed_whole_native_tail_refuses_policy_even_with_same_header(self):
        with self.cc.open('ab') as stream:stream.write(b'\0'*32)
        _,value=self.perform();args=self.policy_args(value)
        with self.cc.open('r+b') as stream:stream.seek(-1,2);stream.write(b'X')
        with self.assertRaises(RuntimeError):legacy.subject.materialize(args,self.context,time.monotonic())
    def test_final_public_roster_seam_requires_original_raw_byte_return(self):
        _,value=self.perform();public=self.root/'public';legacy.staging.stage(SimpleNamespace(source=self.args.output,output=public,packet_sha256=legacy.subject.digest(legacy.ROOT/'SOURCE_PINS.json',1e30)))
        subject=legacy.subject;expected=subject.digest(public/'OBSERVATION.json',1e30);self.assertTrue(subject.admit_public_projection(public,expected)['passed']);target=public/'developer.stdout.txt';original=target.read_bytes();changed=original[:-1]+b'X';self.assertNotEqual(changed,original);calls=[];physical=subject.physical_public_files
        def last_physical(root):
            result=physical(root);calls.append(True)
            if len(calls)==2:target.write_bytes(changed)
            return result
        with patch.object(subject,'physical_public_files',side_effect=last_physical),self.assertRaisesRegex(RuntimeError,'public bytes/hash/physical return'):
            subject.admit_public_projection(public,expected)
        self.assertEqual(len(calls),2);target.write_bytes(original);self.assertTrue(subject.admit_public_projection(public,expected)['passed'])
    def test_final_public_roster_seam_requires_original_reader_source_return(self):
        import shutil
        _,value=self.perform();public=self.root/'public';legacy.staging.stage(SimpleNamespace(source=self.args.output,output=public,packet_sha256=legacy.subject.digest(legacy.ROOT/'SOURCE_PINS.json',1e30)))
        subject=legacy.subject;expected=subject.digest(public/'OBSERVATION.json',1e30);source=self.root/'reader source';source.mkdir()
        for row in json.loads((legacy.ROOT/'SOURCE_PINS.json').read_bytes())['files']+[dict(path='SOURCE_PINS.json')]:
            target=source/row['path'];target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(legacy.ROOT/row['path'],target)
        target=source/'fetch_decision.py';original=target.read_bytes();calls=[];physical=subject.physical_public_files
        def last_physical(root):
            result=physical(root);calls.append(True)
            if len(calls)==2:target.write_bytes(original[:-1]+b'X')
            return result
        with patch.object(subject,'ROOT',source):
            self.assertTrue(subject.admit_public_projection(public,expected)['passed'])
            with patch.object(subject,'physical_public_files',side_effect=last_physical),self.assertRaisesRegex(RuntimeError,'reader source return'):subject.admit_public_projection(public,expected)
            self.assertEqual(len(calls),2);target.write_bytes(original);self.assertTrue(subject.admit_public_projection(public,expected)['passed'])
    def test_policy_reader_preserves_complete_outer_deadline_before_native_read(self):
        _,value=self.perform();args=self.policy_args(value)
        with patch.object(legacy.transfer,'registry',return_value=dict(execution_admitted=True,SYNTHETIC='reviewed tools')):self.assertEqual(legacy.subject.materialize(args,self.context,time.monotonic()),0)
        path=args.output/'NATIVE_POLICY.json';expected=legacy.subject.digest(path,1e30);deadline=time.monotonic()+30
        with patch.object(legacy.probe,'load',return_value=images),patch.object(images,'fingerprint',wraps=images.fingerprint) as replay:
            legacy.probe.native_policy(path,expected,self.admitted,absolute_deadline=deadline)
        self.assertTrue(replay.call_args_list);self.assertTrue(all(call.args[1]<=deadline for call in replay.call_args_list))
        with patch.object(legacy.probe,'load',return_value=images),patch.object(images.os,'open',side_effect=AssertionError('Image opened after expired phase')),self.assertRaisesRegex(RuntimeError,'deadline'):
            legacy.probe.native_policy(path,expected,self.admitted,absolute_deadline=time.monotonic()-1)
    def test_aggregate_image_refusal_precedes_file_open(self):
        census=legacy.subject.Census(self.root,1e30,legacy.transfer,True);census.image_total=images.MAX_IMAGE_TOTAL
        with patch.object(images.os,'open',side_effect=AssertionError('Image opened after refused admission')),self.assertRaisesRegex(RuntimeError,'before reading'):census.file(str(self.cc),'metadata-provider')
    def test_script_provider_preserves_original_full_byte_aggregate_before_retention(self):
        census=legacy.subject.Census(self.root,1e30,legacy.transfer,True);census.total=legacy.subject.MAX_TOTAL
        with patch.object(legacy.subject,'stable',side_effect=AssertionError('Full script read after refused admission')),self.assertRaisesRegex(RuntimeError,'before reading'):census.file(str(self.config),'metadata-provider')

class ImageEvidenceControls(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory(prefix='finite native image metadata ');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
    def layout(self,raw,remaining=images.MAX_RETAINED_BYTES):
        calls=[]
        def read(start,length):calls.append((start,length));return raw[start:start+length]
        value,retained=images.layout(read,len(raw),remaining);return value,retained,calls
    def test_exact_per_image_limit_admits_and_one_byte_beyond_refuses(self):
        images.admit_size(1073741824,images.MAX_IMAGE_TOTAL)
        with self.assertRaisesRegex(RuntimeError,'before reading'):images.admit_size(1073741825,images.MAX_IMAGE_TOTAL)
    def test_metadata_receipt_exact_capacity_and_one_byte_over_before_write(self):
        with patch.object(legacy.subject,'MAX_RAW',128):
            legacy.subject.write(self.root/'exact.json','x'*125)
            with self.assertRaisesRegex(RuntimeError,'before writing'):legacy.subject.write(self.root/'over.json','x'*126)
        self.assertEqual((self.root/'exact.json').stat().st_size,128);self.assertFalse((self.root/'over.json').exists())
    def test_exact_aggregate_limit_admits_and_one_byte_beyond_refuses(self):
        remaining=images.MAX_IMAGE_TOTAL
        for _ in range(4):images.admit_size(images.MAX_IMAGE_BYTES,remaining);remaining-=images.MAX_IMAGE_BYTES
        self.assertEqual(remaining,0)
        with self.assertRaises(RuntimeError):images.admit_size(1,remaining)
    def test_per_image_refusal_precedes_os_open(self):
        p=self.root/'image';p.write_bytes(legacy.image());actual=images.state(p);actual[3]=images.MAX_IMAGE_BYTES+1
        with patch.object(images,'state',return_value=actual),patch.object(images.os,'open',side_effect=AssertionError('Unadmitted image opened')),self.assertRaisesRegex(RuntimeError,'before reading'):images.fingerprint(p,1e30)
    def test_exact_load_command_limit_accepts(self):
        count=images.MAX_LOAD_COMMAND_BYTES;raw=struct.pack('<IIIIIIII',0xfeedfacf,0x100000c,0,2,1,count,0,0)+struct.pack('<II',0x1b,count)+b'\0'*(count-8)
        proof,retained,calls=self.layout(raw);self.assertEqual(proof['retained_bytes'],count+32);images.validate(retained,dict(proof,image_bytes=len(raw),image_sha256=images.sha(raw)),{'bytes':len(raw),'sha256':images.sha(raw)})
    def test_one_byte_over_load_commands_refuses_before_payload_read(self):
        raw=struct.pack('<IIIIIIII',0xfeedfacf,0x100000c,0,2,1,images.MAX_LOAD_COMMAND_BYTES+1,0,0)+b'\0'*(images.MAX_LOAD_COMMAND_BYTES+1);calls=[]
        def read(start,length):calls.append((start,length));return raw[start:start+length]
        with self.assertRaisesRegex(RuntimeError,'before reading'):images.layout(read,len(raw))
        self.assertEqual(calls,[(0,8),(0,32)])
    def test_exact_retained_remaining_and_one_byte_beyond(self):
        raw=legacy.image();self.layout(raw,len(raw))
        with self.assertRaisesRegex(RuntimeError,'before reading'):self.layout(raw,len(raw)-1)
    def test_fat32_selects_arm64_and_preserves_offsets(self):
        thin=legacy.image(['/usr/lib/libSystem.B.dylib']);raw=struct.pack('>II',0xcafebabe,1)+struct.pack('>IIIII',0x100000c,0,28,len(thin),0)+thin
        proof,retained,calls=self.layout(raw);self.assertEqual(proof['slice_offset'],28);self.assertEqual(proof['ranges'][-1]['image_offset'],28);self.assertEqual(proof['imports'],['/usr/lib/libSystem.B.dylib'])
        images.validate(retained,dict(proof,image_bytes=len(raw),image_sha256=images.sha(raw)),{'bytes':len(raw),'sha256':images.sha(raw)})
    def test_fat64_and_swapped_tables_select_arm64(self):
        thin=legacy.image()
        for endian,magic in [('>',b'\xca\xfe\xba\xbf'),('<',b'\xbf\xba\xfe\xca')]:
            raw=magic+struct.pack(endian+'I',1)+struct.pack(endian+'IIQQII',0x100000c,0,40,len(thin),0,0)+thin;proof,retained,calls=self.layout(raw);self.assertEqual(proof['slice_offset'],40)
    def test_fat_other_architecture_refuses(self):
        thin=legacy.image();raw=struct.pack('>II',0xcafebabe,1)+struct.pack('>IIIII',0x1000007,0,28,len(thin),0)+thin
        with self.assertRaises(RuntimeError):self.layout(raw)
    def test_ambiguous_arm64_architecture_refuses(self):
        thin=legacy.image();raw=struct.pack('>II',0xcafebabe,2)+struct.pack('>IIIII',0x100000c,0,48,len(thin),0)+struct.pack('>IIIII',0x100000c,0,48+len(thin),len(thin),0)+thin+thin
        with self.assertRaises(RuntimeError):self.layout(raw)
    def test_truncated_or_mismatched_selected_slice_refuses(self):
        thin=legacy.image();raw=struct.pack('>II',0xcafebabe,1)+struct.pack('>IIIII',0x100000c,1,28,len(thin),0)+thin
        with self.assertRaises(RuntimeError):self.layout(raw)
        with self.assertRaises(RuntimeError):self.layout(raw[:-1])
    def test_missing_range_or_changed_range_hash_refuses(self):
        raw=legacy.image();proof,retained,calls=self.layout(raw);proof.update(image_bytes=len(raw),image_sha256=images.sha(raw));whole={'bytes':len(raw),'sha256':images.sha(raw)}
        with self.assertRaises(RuntimeError):images.validate(retained[:-1],proof,whole)
        other=copy.deepcopy(proof);other['ranges'][0]['sha256']='0'*64
        with self.assertRaises(RuntimeError):images.validate(retained,other,whole)
    def test_streamed_whole_digest_covers_bytes_outside_retained_header(self):
        p=self.root/'image';prefix=legacy.image();p.write_bytes(prefix+b'\0'*4096);before,evidence,raw=images.fingerprint(p,1e30)
        with p.open('r+b') as stream:stream.seek(-1,2);stream.write(b'X')
        after,changed,same=images.fingerprint(p,1e30);self.assertNotEqual(before['sha256'],after['sha256']);self.assertEqual(raw,same);self.assertEqual(evidence['retained_sha256'],changed['retained_sha256'])
    def test_changed_physical_return_is_detected(self):
        p=self.root/'image';p.write_bytes(legacy.image());real=images.state;calls=[]
        def changed(path):
            value=real(path);calls.append(True)
            if len(calls)>=3:value[1]+=1
            return value
        with patch.object(images,'state',side_effect=changed),self.assertRaisesRegex(RuntimeError,'physical return'):images.fingerprint(p,1e30)

if __name__=='__main__':
    suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(StreamingProviderControls),unittest.defaultTestLoader.loadTestsFromTestCase(ImageEvidenceControls)])
    result=unittest.TextTestRunner(verbosity=2).run(suite);print(json.dumps({'tests':result.testsRun,'passed':result.wasSuccessful(),'external_workload_guard_calls':legacy.CALLS},sort_keys=True));raise SystemExit(0 if result.wasSuccessful() and not legacy.CALLS else 1)
