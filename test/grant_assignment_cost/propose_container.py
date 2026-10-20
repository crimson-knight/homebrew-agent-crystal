"""Prepare a one-file proposed value-boundary overlay; original input stays exact."""
import argparse
import difflib
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONTAINER = '''
  # Keeps dynamic column assignment on one value shape across callers.
  #
  # :nodoc:
  struct MassAssignmentValue
    getter value : Type

    def initialize(@value : Type)
    end
  end
'''
HEADER = '  def assign_mass_assignment_column(attribute_name : String, value : Grant::Columns::Type) : Nil\n'
WRAPPER = HEADER + '''    assign_canonical_mass_assignment_column(attribute_name, MassAssignmentValue.new(value))
  end

  private def assign_canonical_mass_assignment_column(attribute_name : String, assignment_value : MassAssignmentValue) : Nil
    value = assignment_value.value
'''


def need(value, message):
    if not value:
        raise RuntimeError(message)


def derive(raw):
    original = (ROOT / 'source/columns.original.cr.txt').read_bytes()
    need(raw == original, 'Exact frozen d784 columns source required')
    text = raw.decode('utf-8')
    anchor = '  alias Type = DB::Any | SupportedArrayTypes | UUID | BigDecimal | Int8 | Int16\n'
    need(text.count(anchor) == text.count(HEADER) == 1, 'Unique exact container and assignment anchors required')
    candidate = text.replace(anchor, anchor + CONTAINER, 1).replace(HEADER, WRAPPER, 1)
    return candidate.encode('utf-8')


def verify(raw, candidate):
    need(candidate == derive(raw), 'Exact one-container, one-wrapper source proposal required')
    start = raw.index(HEADER.encode()) + len(HEADER)
    end = raw.index(b'\n  def read_attribute(', start)
    candidate_start = candidate.index(WRAPPER.encode()) + len(WRAPPER)
    candidate_end = candidate.index(b'\n  def read_attribute(', candidate_start)
    need(raw[start:end] == candidate[candidate_start:candidate_end], 'Complete original assignment body remains byte-identical')
    return dict(changed_library_files=['src/grant/columns.cr'], original_sha256=hashlib.sha256(raw).hexdigest(),
                candidate_sha256=hashlib.sha256(candidate).hexdigest(), assignment_body_byte_identical=True,
                original_method_signature_retained=True, runtime_and_api_compatibility_accepted=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not args.output.exists() and not args.output.is_symlink(), 'Fresh proposal output required')
    raw = (ROOT / 'source/columns.original.cr.txt').read_bytes()
    candidate = derive(raw)
    verify(raw, candidate)
    args.output.mkdir(parents=True)
    for arm, content in [('original', raw), ('candidate', candidate), ('restored', raw)]:
        (args.output / (arm + '.columns.cr.txt')).write_bytes(content)
    patch = ''.join(difflib.unified_diff(raw.decode().splitlines(True), candidate.decode().splitlines(True),
                                       fromfile='a/src/grant/columns.cr', tofile='b/src/grant/columns.cr'))
    (args.output / 'candidate.patch.txt').write_text(patch)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
