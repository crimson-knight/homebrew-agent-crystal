"""Exact source-derived key alignment, with original producer products preserved."""
import hashlib
import re
from pathlib import Path

ORIGINALS = {
    'library_floor': '53f30ec32473991292d8b8139751062982231f18443ec1a727d6e1a1eb9a8b98',
    'declarations': 'c5b9369872d10f8fcbb41d8fa3ba876e7434800aa5d3946c892d6fd13d306218',
    'new_empty': '52b27bd7a68b659238c62454c29f3c10c2b54f69cbd8cb68746acf2e79c7d8c6',
    'new_keywords': '1525f9879b639b91bc38138695f236f49b32f6b07dff6a7f617846545d72fac5',
    'new_broad_hash': '2840c874a1fc24e82af25af695310a5de1a7006ef4bf998103374bdb9294a01f',
    'canonical_create': 'a2fc694a59408b369fd96a9f62245879102287ace178a5de4d261bdd488b92c3',
}
PROJECTED_BROAD = '1896c1ed5af1505e6ac3efe22cf35be47b3dbf72d6b237289f24f967e7371bd9'


def need(value, message):
    if not value:
        raise RuntimeError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def measured_source(profile, raw):
    """Admit exact original bytes, then add only reviewed pre-arrow spaces."""
    need(profile in ORIGINALS and type(raw) is bytes and digest(raw) == ORIGINALS[profile],
         'Exact named original producer source required before formatting projection')
    if profile != 'new_broad_hash':
        return raw
    lines = raw.splitlines(keepends=True)
    blocks = []
    current = None
    for index, line in enumerate(lines):
        if re.fullmatch(rb'attributes_\d{4} : Grant::ModelArgs = \{\n', line):
            need(current is None, 'Separate reviewed hash blocks required')
            current = []
            blocks.append(current)
        elif current is not None:
            if line == b'} of String | Symbol => Grant::Columns::Type\n':
                current = None
            else:
                match = re.fullmatch(rb'  ("[a-z_]+") => (.*\n)', line)
                need(match is not None, 'Exact original quoted-key entry grammar required')
                current.append((index, match.group(1)))
    need(current is None and len(blocks) == 2 and all(len(block) == 14 for block in blocks),
         'Complete original two fourteen-entry hash blocks required')
    changed = 0
    for block in blocks:
        width = max(len(key) for _, key in block)
        for index, key in block:
            before = lines[index]
            after = before.replace(key + b' =>', key + b' ' * (width - len(key) + 1) + b'=>', 1)
            need(re.sub(rb' +=>', b' =>', before) == re.sub(rb' +=>', b' =>', after),
                 'Only horizontal spaces immediately before reviewed arrows may change')
            changed += before != after
            lines[index] = after
    output = b''.join(lines)
    need(changed == 26 and len(output) - len(raw) == 176 and digest(output) == PROJECTED_BROAD,
         'Exact reviewed twenty-six-line/176-space output required')
    return output


def projection(profile, original):
    output = measured_source(profile, original)
    return dict(format='atlas-grant-frontend-format-projection-v1', profile=profile,
                original_product_sha256=digest(original), measured_source_sha256=digest(output),
                projection_source_sha256=digest(Path(__file__).read_bytes()),
                changed_lines=26 if profile == 'new_broad_hash' else 0,
                added_horizontal_spaces=176 if profile == 'new_broad_hash' else 0,
                source_tokens_preserved=True, actual_pinned_formatter_acceptance_required=True)
