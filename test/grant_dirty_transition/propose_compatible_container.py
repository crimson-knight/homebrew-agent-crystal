"""A separately named resolver proposal preserves the caller's static error type."""
import argparse
import difflib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from propose_container import HEADER, need

CONTAINER = '''
  # Keeps column input and its original conversion diagnostics together.
  #
  # :nodoc:
  struct MassAssignmentValue
    getter value : Type

    def initialize(@value : Type, @converted_type_name_reader : Proc(String, String)? = nil)
    end

    def converted_type_name(column_name : String) : String
      reader = @converted_type_name_reader || raise ArgumentError.new("Column conversion type reader is unavailable")
      reader.call(column_name)
    end
  end
'''
WRAPPER = HEADER + '''    assignment_value = MassAssignmentValue.new(value, build_mass_assignment_converted_type_name_reader(value))
    assign_canonical_mass_assignment_column(attribute_name, assignment_value)
  end

  private def build_mass_assignment_converted_type_name_reader(value : T) : Proc(String, String) forall T
    ->(column_name : String) do
      {% begin %}
        case column_name
        {% for column in @type.instance_vars.select(&.annotation(Grant::Column)) %}
          {% ann = column.annotation(Grant::Column) %}
          when {{column.name.stringify}}
            {% if ann[:nilable] == true %}
              {% setter_type = column.type %}
            {% else %}
              {% setter_type = ann[:setter_type] %}
            {% end %}
            "#{typeof(begin
              converted_value = Grant::Type.convert_type(value, {{setter_type}})
              if converted_value.is_a?({{setter_type}})
                raise ArgumentError.new("A converted value has no rejection type")
              else
                converted_value
              end
            end)}"
        {% end %}
        else
          raise ArgumentError.new("Column conversion type is unavailable for #{column_name}")
        end
      {% end %}
    end
  end

  private def assign_canonical_mass_assignment_column(attribute_name : String, assignment_value : MassAssignmentValue) : Nil
    value = assignment_value.value
'''


def derive(raw):
    need(raw == (ROOT / 'source/columns.original.cr.txt').read_bytes(), 'Exact frozen original source required')
    text = raw.decode()
    anchor = '  alias Type = DB::Any | SupportedArrayTypes | UUID | BigDecimal | Int8 | Int16\n'
    start = text.index(HEADER)
    end = text.index('\n  def read_attribute(', start)
    original_body = text[start + len(HEADER):end]
    old = '#{typeof(converted_value)}'
    replacement = '#{assignment_value.converted_type_name({{column.name.stringify}})}'
    need(original_body.count(old) == 1, 'One exact original inferred-type diagnostic required')
    body = original_body.replace(old, replacement)
    candidate = text[:start] + WRAPPER + body + text[end:]
    return candidate.replace(anchor, anchor + CONTAINER, 1).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not args.output.exists() and not args.output.is_symlink(), 'Fresh compatible proposal output required')
    raw = (ROOT / 'source/columns.original.cr.txt').read_bytes()
    candidate = derive(raw)
    args.output.mkdir(parents=True)
    (args.output / 'candidate.columns.cr.txt').write_bytes(candidate)
    patch = ''.join(difflib.unified_diff(raw.decode().splitlines(True), candidate.decode().splitlines(True), fromfile='a/src/grant/columns.cr', tofile='b/src/grant/columns.cr'))
    (args.output / 'candidate.patch.txt').write_text(patch)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
