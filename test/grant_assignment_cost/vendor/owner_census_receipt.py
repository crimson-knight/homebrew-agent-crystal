"""Lossless bounded census transport; LLVM bytes independently establish completeness."""
import gzip
import hashlib
import json
import re
import zlib
from owner_census import census_stream, verify_report, MAX_IR_BYTES, MAX_DEFINITIONS

MAX_REPORT_BYTES = 32 * 2**20
MAX_COMPRESSED_BYTES = 8 * 2**20
FORMAT = 'atlas-complete-owner-census-gzip-v1'
REPORT_FIELDS = {'schema_version', 'metric', 'ir_sha256', 'ir_bytes', 'definition_count', 'bucket_counts', 'definitions', 'selected_family_definitions', 'frontend_inferred_cache_census_qualified', 'retained_frontend_memory_qualified', 'memory_savings_accepted'}
ROW_FIELDS = {'symbol', 'header_line', 'header_sha256', 'body_lines', 'self_type', 'original_owner', 'method_signature', 'method_family', 'model', 'bucket', 'last_line', 'definition_sha256'}
RECEIPT_FIELDS = {'format', 'encoding', 'decoded_bytes', 'decoded_sha256', 'compressed_bytes', 'compressed_sha256', 'ir_sha256', 'definition_count', 'numerical_performance_acceptance'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def qualify_report(report):
    require(type(report) is dict and set(report) == REPORT_FIELDS, 'Exact complete census schema required')
    require(type(report['schema_version']) is int and report['schema_version'] == 1 and report['metric'] == 'lowered single-module LLVM definitions', 'Exact lowered-definition measurement required')
    require(digest(report['ir_sha256']) and type(report['ir_bytes']) is int and 0 < report['ir_bytes'] <= MAX_IR_BYTES, 'Exact finite LLVM source identity required')
    require(type(report['definition_count']) is int and 0 < report['definition_count'] <= MAX_DEFINITIONS and type(report['definitions']) is list, 'Finite complete definition roster required')
    require(all(report[key] is False for key in ('frontend_inferred_cache_census_qualified', 'retained_frontend_memory_qualified', 'memory_savings_accepted')), 'Original frontend and memory qualification boundaries required')
    require(len(report['definitions']) <= MAX_DEFINITIONS and type(report['bucket_counts']) is dict and all(type(key) is str and type(count) is int and count > 0 for key, count in report['bucket_counts'].items()), 'Typed finite complete bucket counts required')
    require(type(report['selected_family_definitions']) is list and all(type(symbol) is str for symbol in report['selected_family_definitions']), 'Typed complete selected-symbol roster required')
    for row in report['definitions']:
        require(type(row) is dict and set(row) == ROW_FIELDS and digest(row['header_sha256']) and digest(row['definition_sha256']), 'Complete definition hashes and fields required')
        require(all(type(row[key]) is int and row[key] > 0 for key in ('header_line', 'last_line', 'body_lines')) and row['last_line'] >= row['header_line'] and row['body_lines'] == row['last_line'] - row['header_line'] + 1, 'Exact LLVM line interval required')
    verify_report(report)
    return report


def encode(report):
    qualify_report(report)
    raw = canonical(report)
    require(0 < len(raw) <= MAX_REPORT_BYTES, 'Complete decoded census stays inside32MiB')
    compressed = gzip.compress(raw, compresslevel=6, mtime=0)
    require(0 < len(compressed) <= MAX_COMPRESSED_BYTES, 'Complete compressed census stays inside8MiB')
    receipt = dict(format=FORMAT, encoding='gzip+canonical-json', decoded_bytes=len(raw), decoded_sha256=sha(raw), compressed_bytes=len(compressed), compressed_sha256=sha(compressed), ir_sha256=report['ir_sha256'], definition_count=report['definition_count'], numerical_performance_acceptance=False)
    return receipt, compressed


def bounded_integer(text):
    require(len(text) <= 20, 'Finite census JSON integer required')
    return int(text)


def decode(receipt, compressed, expected_ir_sha256):
    require(type(receipt) is dict and set(receipt) == RECEIPT_FIELDS and receipt['format'] == FORMAT and receipt['encoding'] == 'gzip+canonical-json', 'Exact lossless census receipt required')
    require(receipt['numerical_performance_acceptance'] is False and digest(expected_ir_sha256) and receipt['ir_sha256'] == expected_ir_sha256, 'External exact LLVM identity and original numerical boundary required')
    for field, cap in (('decoded_bytes', MAX_REPORT_BYTES), ('compressed_bytes', MAX_COMPRESSED_BYTES), ('definition_count', MAX_DEFINITIONS)):
        require(type(receipt[field]) is int and 0 < receipt[field] <= cap, 'Typed finite census receipt field required: ' + field)
    require(digest(receipt['decoded_sha256']) and digest(receipt['compressed_sha256']) and type(compressed) is bytes and len(compressed) == receipt['compressed_bytes'] and sha(compressed) == receipt['compressed_sha256'], 'Exact compressed census bytes required')
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        raw = inflater.decompress(compressed, MAX_REPORT_BYTES + 1)
    except zlib.error as error:
        raise RuntimeError('Valid complete gzip census required') from error
    require(len(raw) <= MAX_REPORT_BYTES and inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail, 'One complete gzip member within the decoded ceiling required')
    require(len(raw) == receipt['decoded_bytes'] and sha(raw) == receipt['decoded_sha256'], 'Exact complete decoded census bytes required')
    try:
        report = json.loads(raw, parse_int=bounded_integer)
        require(canonical(report) == raw, 'Canonical unique-key complete census JSON required')
    except (ValueError, UnicodeError) as error:
        raise RuntimeError('Canonical complete census JSON required') from error
    qualify_report(report)
    require(report['ir_sha256'] == expected_ir_sha256 and report['definition_count'] == receipt['definition_count'], 'Exact externally bound complete census identity required')
    return report


def verify_against_ir(report, ir_stream):
    """Rebuild every definition from the independent retained LLVM stream."""
    qualify_report(report)
    require(census_stream(ir_stream) == report, 'Every retained definition and field must equal the independent LLVM census')
    return True
