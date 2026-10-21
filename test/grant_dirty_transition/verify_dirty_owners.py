"""Require global carrier owners and retain bounded ARM64 direct-call evidence."""
import struct

from retained_symbols import need, sha

HELPERS = ('has_different_assignment_values?', 'has_equal_assignment_values?', 'record_column_assignment')
FIELDS = ('id', 'first_name', 'email', 'age', 'is_active', 'score', 'country_code', 'notes', 'rating', 'balance',
          'group_number', 'settings_text', 'created_at', 'updated_at', 'parent_id', 'sequence_number')


def calls(raw, census, row):
    need(row['function_start'] and type(row['next_function_extent_bytes']) is int, 'Complete function-start interval required')
    extent = row['next_function_extent_bytes']
    need(0 < extent <= 256 * 2**10 and extent % 4 == 0, 'Bounded aligned selected function interval required')
    text = census['text']
    offset = text['file_offset'] + row['address'] - text['address']
    code = raw[offset:offset + extent]
    need(len(code) == extent and sha(code) == row['extent_sha256'], 'Exact complete selected machine-code interval required')
    found = []
    for index in range(0, extent, 4):
        word = struct.unpack_from('<I', code, index)[0]
        if word & 0xfc000000 in (0x14000000, 0x94000000):
            immediate = word & 0x3ffffff
            if immediate & 0x2000000:
                immediate -= 0x4000000
            found.append(dict(address=row['address'] + index, word_hex=code[index:index + 4].hex(),
                              opcode='BL' if word & 0xfc000000 == 0x94000000 else 'B',
                              target=row['address'] + index + 4 * immediate))
    return found


def verify(raw, census, arm):
    need(arm in ('original', 'comparison', 'transition', 'restored'), 'Exact four-arm owner identity required')
    need(sha(raw) == census['binary_sha256'], 'Exact census/binary join required')
    rows = census['definitions']
    owners = {}
    for helper in HELPERS:
        selected = [row for row in rows if 'Grant::Dirty::' + helper + '<' in row['symbol']]
        count = 1 if arm in ('comparison', 'transition') and (helper != HELPERS[2] or arm == 'transition') else 0
        need(len(selected) == count and len({row['address'] for row in selected}) == count,
             'Exact global helper symbol/interval count required: ' + helper)
        for row in selected:
            need('Grant::Dirty::CapturedColumnAssignment' in row['symbol'] and 'AcceptancePerson' not in row['symbol'],
                 'One model-independent fixed-carrier signature required')
        owners[helper] = selected
    selected_rows = {}
    paths = []
    for index in range(2):
        model = 'AcceptancePerson%04d' % index
        for field in FIELDS:
            setters = [row for row in rows if row['symbol'].startswith(('_*' + model + '#' + field + '=<', '*' + model + '#' + field + '=<'))]
            need(setters, 'Original typed public setter retained: ' + model + '/' + field)
            for row in setters:
                selected_rows[row['address']] = row
            paths.append(dict(model=model, field=field, setters=setters))
    for selected in owners.values():
        for row in selected:
            selected_rows[row['address']] = row
    call_rows = {address: calls(raw, census, row) for address,row in selected_rows.items()}
    if arm in ('comparison', 'transition'):
        target_names = HELPERS[:2] if arm == 'comparison' else HELPERS[2:]
        for path in paths:
            sources = [row['address'] for row in path['setters']]
            for name in target_names:
                target = owners[name][0]['address']
                found = [call for address in sources for call in call_rows[address] if call['target'] == target]
                need(found, 'Actual direct setter-to-shared-helper call required: ' + path['model'] + '/' + path['field'] + '/' + name)
                path.setdefault('required_calls', {})[name] = found
        if arm == 'transition':
            transition = owners[HELPERS[2]][0]['address']
            for name in HELPERS[:2]:
                need(any(call['target'] == owners[name][0]['address'] for call in call_rows[transition]),
                     'Actual full-transition-to-comparator call required: ' + name)
    intervals = [{key:row[key] for key in ('symbol','address','next_function_extent_bytes','extent_sha256')} for row in selected_rows.values()]
    return dict(format='atlas-grant-fixed-carrier-linked-owner-proof-v1', arm=arm, binary_sha256=census['binary_sha256'],
                global_helper_owners=owners, typed_setter_paths=paths, selected_intervals=intervals,
                selected_direct_calls=[dict(source_address=address, calls=value) for address,value in call_rows.items()],
                owner_and_direct_call_predicate_passed=True, compiler_memory_attribution_accepted=False,
                allocation_or_stack_copy_improvement_accepted=False, target_cells_accepted=0)
