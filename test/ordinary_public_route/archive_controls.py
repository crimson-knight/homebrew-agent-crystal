"""Physical archive text-metadata screening and clean refusal controls."""
import gzip
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest import mock
import publication_controls as public
import bottle_source_screen as screen
import stage_results as stage
import route_support as support

GUARD_CALLS=[]

class ArchiveMetadataControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):public.PublicationControls.setUpClass()
    def setUp(self):
        self.case=public.PublicationControls('runTest');self.case.setUp();self.addCleanup(self.case.doCleanups);self.packet=self.case.packet
    def authored(self,field=None,value=None,kind=None,global_pax=None,format=tarfile.PAX_FORMAT):
        source,archive=self.case.fixture([(screen.PREFIX+'uri.cr',self.case.public['uri.cr'])]);buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode='w',format=format,pax_headers=global_pax) as output:
            body=self.case.public['uri.cr'];member=tarfile.TarInfo(screen.PREFIX+'uri.cr');member.size=len(body);member.uname='public-builder';member.gname='public-group'
            if field in ('uname','gname','name'):setattr(member,field,value)
            if field=='pax-key':member.pax_headers={value:'public-value'}
            if field=='pax-value':member.pax_headers={'public-key':value}
            output.addfile(member,io.BytesIO(body))
            if kind:
                link=tarfile.TarInfo('agent-crystal/1.21.0-incremental-1_2/share/public-link');link.type=kind;link.linkname=value or 'src/uri.cr';output.addfile(link)
        self.replace(source,archive,gzip.compress(buf.getvalue(),compresslevel=9,mtime=0));return source,archive
    def replace(self,source,archive,raw):
        archive.write_bytes(raw);value=support.read(source/'authored.bottle.json');next(iter(value.values()))['bottle']['tags']['arm64_tahoe']['sha256']=support.sha(raw);support.write(source/'authored.bottle.json',value);support.write(source/'BOTTLE_INPUTS.json',public.bottle.bottle_inputs(source,public.bottle.ROOT_URL))
    def refuse(self,source,archive):
        before=support.stable(archive)[0];dest=self.case.root/'clean negative projection'
        with self.assertRaises((ValueError,RuntimeError,tarfile.TarError,gzip.BadGzipFile)):stage.stage(source,dest,self.packet,retain_clean_refusals=True)
        result=stage.verify_projection(dest,self.packet);self.assertFalse(result['screening_complete']);self.assertGreater(result['refusal_count'],0);self.assertFalse((dest/archive.name).exists());self.assertEqual(support.stable(archive)[0],before)
        with self.assertRaises(RuntimeError):stage.verify_projection(dest,self.packet,complete=True)
        rows=support.read(dest/'STAGING_DIAGNOSTICS.json')['refusals'];self.assertTrue(all(r['matching_contents_included'] is False for r in rows));self.assertNotIn(self.case.secret().decode(),json.dumps(rows));return rows
    def short_secret(self):return 'gh'+'p_'+'Q'*24
    def test_positive_public_bodies_headers_and_symlink_accept(self):
        source,archive=self.authored(kind=tarfile.SYMTYPE,value='src/uri.cr');dest=self.case.root/'positive metadata';result=stage.stage(source,dest,self.packet);self.assertTrue(result['screening_complete']);stage.verify_projection(dest,self.packet,complete=True);rows=support.read(dest/'STAGING_DIAGNOSTICS.json')['archive_metadata_checks'];self.assertTrue(rows[0]['effective_and_physical_metadata_screened']);self.assertEqual(rows[0]['gzip_members'],1)
    def test_exact_public_promoted_source_archive_metadata_accepts(self):
        path=public.ROOT/'inputs/public-alpha-main.tar.gz';row,raw=support.stable(path);self.assertEqual(row['sha256'],'1fc53c2285e208497bf3cb58fb6b36a4ec44eb4ea4a14442766ee9cce7aaccc4');stream,result=screen.archive_metadata('public-source.tar.gz',raw,self.case.rules);stream.close();self.assertEqual(result['members'],28);self.assertTrue(result['effective_and_physical_metadata_screened'])
    def test_exact_public_SDK_archive_metadata_accepts(self):
        path=public.FIXTURES/'sdk58c.tar.gz';row,raw=support.stable(path);self.assertEqual(row['sha256'],'3a6d9c982ece74ef3b72eea0e2569bbfe31cd1767b3c4c7e8723d8f5f6d4b9bf');stream,result=screen.archive_metadata('public-SDK.tar.gz',raw,self.case.rules);stream.close();self.assertEqual(result['members'],174);self.assertTrue(result['effective_and_physical_metadata_screened'])
    def test_symlink_target_credential_refuses_with_field_hash(self):
        source,archive=self.authored(kind=tarfile.SYMTYPE,value=self.case.secret().decode());row=self.refuse(source,archive)[0];self.assertEqual(row['metadata_field'],'linkname');self.assertEqual(row['sha256'],support.sha(self.case.secret()))
    def test_hardlink_credential_target_is_screened_before_kind_refusal(self):
        source,archive=self.authored(kind=tarfile.LNKTYPE,value=self.case.secret().decode());self.assertEqual(self.refuse(source,archive)[0]['metadata_field'],'linkname')
    def test_safe_hardlink_keeps_original_kind_refusal(self):self.refuse(*self.authored(kind=tarfile.LNKTYPE,value='src/uri.cr'))
    def test_uname_credential_refuses(self):self.refuse(*self.authored(field='uname',value=self.short_secret()))
    def test_gname_credential_refuses(self):self.refuse(*self.authored(field='gname',value=self.short_secret()))
    def test_effective_member_name_credential_refuses(self):self.refuse(*self.authored(field='name',value='public/'+self.short_secret()))
    def test_local_PAX_key_credential_refuses(self):self.refuse(*self.authored(field='pax-key',value=self.short_secret()))
    def test_local_PAX_value_credential_refuses(self):self.refuse(*self.authored(field='pax-value',value=self.case.secret().decode()))
    def test_global_PAX_key_credential_refuses(self):self.refuse(*self.authored(global_pax={self.short_secret():'public-value'}))
    def test_global_PAX_value_credential_refuses(self):self.refuse(*self.authored(global_pax={'public-key':self.case.secret().decode()}))
    def test_safe_local_and_global_PAX_metadata_accept(self):
        source,archive=self.authored(field='pax-value',value='public-value',global_pax={'global-public-key':'public-global-value'});dest=self.case.root/'safe PAX';stage.stage(source,dest,self.packet);stage.verify_projection(dest,self.packet,complete=True)
    def test_GNU_long_link_target_credential_refuses(self):self.refuse(*self.authored(kind=tarfile.SYMTYPE,value='public/'*24+self.case.secret().decode(),format=tarfile.GNU_FORMAT))
    def test_GNU_long_name_credential_refuses(self):self.refuse(*self.authored(field='name',value='public/'*24+self.short_secret(),format=tarfile.GNU_FORMAT))
    def test_safe_GNU_long_link_metadata_accepts(self):
        source,archive=self.authored(kind=tarfile.SYMTYPE,value='public/'*24+'uri.cr',format=tarfile.GNU_FORMAT);dest=self.case.root/'safe GNU';stage.stage(source,dest,self.packet);stage.verify_projection(dest,self.packet,complete=True)
    def pax_record(self,key,value):
        payload=(key+'='+value+'\n').encode();size=len(payload)+2
        while True:
            current=len(payload)+len(str(size))+1
            if current==size:return str(size).encode()+b' '+payload
            size=current
    def test_overwritten_duplicate_PAX_value_is_physically_screened(self):
        source,archive=self.authored();body=gzip.decompress(archive.read_bytes());records=self.pax_record('public-key',self.case.secret().decode())+self.pax_record('public-key','public-restored');header=tarfile.TarInfo('public-PAX-record');header.type=tarfile.XHDTYPE;header.size=len(records);raw=header.tobuf(format=tarfile.USTAR_FORMAT)+records+b'\0'*((-len(records))%512)+body;self.replace(source,archive,gzip.compress(raw,compresslevel=9,mtime=0));self.assertEqual(self.refuse(source,archive)[0]['metadata_field'],'physical-header-and-extension')
    def test_unused_header_text_after_NUL_is_screened(self):
        source,archive=self.authored();body=bytearray(gzip.decompress(archive.read_bytes()));value=b'public\0'+self.short_secret().encode();body[157:257]=value+b'\0'*(100-len(value));body[148:156]=b' '*8;checksum=sum(body[:512]);body[148:156]=('%06o\0 '%checksum).encode();self.replace(source,archive,gzip.compress(bytes(body),compresslevel=9,mtime=0));self.assertEqual(self.refuse(source,archive)[0]['metadata_field'],'physical-header-and-extension')
    def test_nonzero_member_padding_refuses(self):
        source,archive=self.authored();body=bytearray(gzip.decompress(archive.read_bytes()));offset=512+len(self.case.public['uri.cr']);body[offset:offset+len(self.case.secret())]=self.case.secret();self.replace(source,archive,gzip.compress(bytes(body),compresslevel=9,mtime=0));self.assertEqual(self.refuse(source,archive)[0]['metadata_field'],'member-padding')
    def test_nonzero_TAR_trailer_refuses(self):
        source,archive=self.authored();body=gzip.decompress(archive.read_bytes())+self.case.secret();self.replace(source,archive,gzip.compress(body,compresslevel=9,mtime=0));self.assertEqual(self.refuse(source,archive)[0]['metadata_field'],'tar-trailer')
    def gzip_field(self,flag,value):
        source,archive=self.authored();raw=bytearray(archive.read_bytes());raw[3]|=flag;extra=(len(value).to_bytes(2,'little')+value) if flag==4 else value+b'\0';self.replace(source,archive,bytes(raw[:10])+extra+bytes(raw[10:]));return source,archive
    def test_gzip_filename_credential_refuses(self):self.refuse(*self.gzip_field(8,self.case.secret()))
    def test_gzip_comment_credential_refuses(self):self.refuse(*self.gzip_field(16,self.case.secret()))
    def test_gzip_extra_credential_refuses(self):self.refuse(*self.gzip_field(4,self.case.secret()))
    def test_safe_gzip_filename_metadata_accepts(self):
        source,archive=self.gzip_field(8,b'public-source.tar');dest=self.case.root/'safe gzip filename';stage.stage(source,dest,self.packet);stage.verify_projection(dest,self.packet,complete=True)
    def test_concatenated_gzip_member_refuses(self):
        source,archive=self.authored();self.replace(source,archive,archive.read_bytes()+gzip.compress(self.case.secret(),compresslevel=9,mtime=0));self.refuse(source,archive)
    def test_truncated_gzip_trailer_refuses(self):
        source,archive=self.authored();self.replace(source,archive,archive.read_bytes()[:-4]);self.refuse(source,archive)
    def test_decompressed_capacity_precedes_retention(self):
        source,archive=self.authored()
        with mock.patch.object(screen,'MAX_TAR_BYTES',1024):self.refuse(source,archive)
    def test_physical_metadata_capacity_refuses(self):
        source,archive=self.authored()
        with mock.patch.object(screen,'MAX_METADATA_BYTES',128):self.refuse(source,archive)
