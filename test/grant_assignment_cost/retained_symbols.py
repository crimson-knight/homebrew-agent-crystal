"""Read retained ARM64 Mach-O metadata; execution and disassembly are separate gates."""
import hashlib
import re
import struct

MAX_BINARY_BYTES = 64 * 2**20
MAX_SYMBOLS = 250000


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def region(raw, offset, size):
    need(type(offset) is int and type(size) is int and 0 <= offset <= len(raw)
         and 0 <= size <= len(raw) - offset, 'Contained Mach-O byte region required')
    return raw[offset:offset + size]


def c_string(raw, offset, end):
    need(0 <= offset < end <= len(raw), 'Contained Mach-O string required')
    finish = raw.find(b'\0', offset, end)
    need(finish >= offset and finish - offset <= 65536, 'Bounded terminated Mach-O string required')
    return raw[offset:finish].decode('utf-8')


def decode_starts(raw, base):
    values, cursor, address = [], 0, base
    while cursor < len(raw):
        delta, shift = 0, 0
        while True:
            need(cursor < len(raw) and shift < 64, 'Complete bounded ULEB128 required')
            item = raw[cursor]
            cursor += 1
            delta |= (item & 127) << shift
            if not item & 128:
                break
            shift += 7
        if delta == 0:
            need(not any(raw[cursor:]), 'Zero function-start padding required')
            return values
        address += delta
        values.append(address)
        need(len(values) <= MAX_SYMBOLS, 'Bounded function-start roster required')
    raise RuntimeError('Terminated function-start stream required')


def read_macho(raw):
    need(type(raw) is bytes and 32 <= len(raw) <= MAX_BINARY_BYTES, 'Bounded complete binary bytes required')
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from('<IiiIIIII', raw)
    need(magic == 0xfeedfacf and cpu == 0x100000c and kind == 2,
         'Retained thin little-endian ARM64 executable required')
    need(0 < count <= 128 and 8 * count <= size <= len(raw) - 32, 'Bounded load-command roster required')
    sections, symtab, functions, base, cursor = [], None, None, None, 32
    for unused in range(count):
        need(cursor + 8 <= 32 + size, 'Contained load-command header required')
        command, length = struct.unpack_from('<II', raw, cursor)
        need(8 <= length <= 32 + size - cursor and length % 8 == 0, 'Contained aligned load command required')
        if command == 0x19:
            need(length >= 72, 'Complete64-bit segment required')
            name, address, vm_size, file_offset, file_size, maximum, initial, number, segment_flags = struct.unpack_from('<16sQQQQiiII', raw, cursor + 8)
            need(length == 72 + 80 * number and len(sections) + number <= 255, 'Exact bounded segment sections required')
            if name.rstrip(b'\0') == b'__TEXT':
                need(base is None, 'Unique text segment required')
                base = address
            for index in range(number):
                offset = cursor + 72 + index * 80
                name, segment, address, extent, file_offset = struct.unpack_from('<16s16sQQI', raw, offset)
                sections.append(dict(name=name.rstrip(b'\0').decode('ascii'), segment=segment.rstrip(b'\0').decode('ascii'), address=address, bytes=extent, file_offset=file_offset))
        elif command == 2:
            need(symtab is None and length == 24, 'Unique complete symbol table required')
            symtab = struct.unpack_from('<IIII', raw, cursor + 8)
        elif command == 0x26:
            need(functions is None and length == 16, 'Unique function-start command required')
            functions = struct.unpack_from('<II', raw, cursor + 8)
        cursor += length
    need(cursor == 32 + size and symtab is not None and functions is not None and base is not None,
         'Complete load commands, symbols, and function starts required')
    text = [(index + 1, section) for index, section in enumerate(sections)
            if section['name'] == '__text' and section['segment'] == '__TEXT']
    need(len(text) == 1, 'Unique text section required')
    text_index, section = text[0]
    region(raw, section['file_offset'], section['bytes'])
    starts = decode_starts(region(raw, *functions), base)
    need(starts and starts == sorted(set(starts)) and all(section['address'] <= item < section['address'] + section['bytes'] for item in starts), 'Strict ordered contained function starts required')
    ends = dict(zip(starts, starts[1:] + [section['address'] + section['bytes']]))
    offset, number, string_offset, string_size = symtab
    need(0 < number <= MAX_SYMBOLS, 'Bounded symbol count required')
    region(raw, offset, number * 16)
    region(raw, string_offset, string_size)
    rows = []
    for index in range(number):
        string_index, symbol_type, section_number, description, address = struct.unpack_from('<IBBHQ', raw, offset + index * 16)
        need(string_index < string_size and section_number <= len(sections), 'Contained symbol string and section required')
        if symbol_type & 0xe0 or symbol_type & 0x0e != 0x0e or section_number != text_index:
            continue
        symbol = c_string(raw, string_offset + string_index, string_offset + string_size)
        if symbol == '__mh_execute_header' and address == base:
            continue
        need(section['address'] <= address <= section['address'] + section['bytes'], 'Defined text symbol address required')
        extent = ends[address] - address if address in ends else None
        code_offset = section['file_offset'] + address - section['address']
        rows.append(dict(symbol=symbol, symbol_table_index=index, address=address,
                         function_start=address in ends, next_function_extent_bytes=extent,
                         first64_code_bytes_hex=region(raw, code_offset, min(extent, 64)).hex() if extent is not None else None,
                         extent_sha256=sha(region(raw, code_offset, extent)) if extent is not None else None))
    need(rows, 'Nonempty defined text-symbol roster required')
    return dict(binary_sha256=sha(raw), binary_bytes=len(raw), symbol_table_entries=number,
                defined_text_symbols=len(rows), function_starts=len(starts), text=section,
                extent_metric='LC_FUNCTION_STARTS interval to next function start or text end; includes alignment; aliases share intervals',
                frontend_cache_completeness=False, retained_memory_attribution=False, definitions=rows)


FAMILIES = (
    ('assignment_entry', re.compile(r'@Grant::ValueObjects#set_attributes[<:]')),
    ('assignment_conversion', re.compile(r'@Grant::Columns#assign_mass_assignment_column[<:]')),
    ('canonical_assignment_conversion', re.compile(r'@Grant::Columns#assign_canonical_mass_assignment_column[<:]')),
    ('assignment_type_name_resolver', re.compile(r'@Grant::Columns#build_mass_assignment_converted_type_name_reader[<:]')),
    ('canonical_value_container', re.compile(r'^_?\*Grant::Columns::MassAssignmentValue(?:#|::)')),
    ('scope_attributes', re.compile(r'#__apply_scope_attributes[<:]')),
    ('named_tuple_assignment', re.compile(r'#__set_named_attributes[<:]')),
    ('virtual_assignment', re.compile(r'^_?\*Grant::Columns::VirtualAttributeRegistry::assign[<:]')),
    ('model_hydration', re.compile(r'@Grant::Columns#from_rs[<:]')),
    ('column_plan', re.compile(r'@Grant::Columns::ClassMethods::__column_(?:plan|ordinal)[<:]')),
    ('type_conversion', re.compile(r'^_?\*Grant::Type(?:@Grant::Type)?::convert_type[<:]')),
    ('checked_conversion_wrapper', re.compile(r'^_?\*Grant::Type(?:@Grant::Type)?::convert_column_value[<:]')),
    ('type_hydration', re.compile(r'^_?\*Grant::Type(?:@Grant::Type)?::from_rs[<:]')),
    ('base_plus_signature_mention', re.compile(r'Grant::Base\+')),
    ('association_assignment', re.compile(r'(?:_grant_assign_association|_grant_write_assoc_)')),
    ('polymorphic_dispatch', re.compile(r'^_?\*Grant::Polymorphic::(?:load_polymorphic!?|load_polymorphic_batch|update_counter|touch_target|adjust_polymorphic_counter_cache|touch_polymorphic_target|registered_type\?)[<:]')),
)


def family_rows(value):
    result = {}
    for family, pattern in FAMILIES:
        rows = [row for row in value['definitions'] if pattern.search(row['symbol'])]
        need(all(row['function_start'] for row in rows), 'Selected family symbols require function-start interval proof')
        addresses = {row['address']: row['next_function_extent_bytes'] for row in rows}
        result[family] = dict(symbol_count=len(rows), distinct_function_intervals=len(addresses),
                              next_function_extent_bytes=sum(addresses.values()), definitions=rows)
    return result
