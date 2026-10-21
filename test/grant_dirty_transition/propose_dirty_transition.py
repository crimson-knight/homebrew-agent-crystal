"""Derive two four-file overlays while preserving every typed-setter perimeter byte."""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PATHS = ('src/grant/columns.cr', 'src/grant/dirty.cr', 'src/grant/dirty/captured_column_assignment.cr',
         'src/grant/dirty/recorded_column_assignment.cr')
COLUMNS_SHA256 = 'eebf80691fb9caf87755697c0758ded0ab1e99c5fbcb1750034bed4b86d6c2bb'
DIRTY_SHA256 = '789499c5fd0415deadda94ff55e856a4aa551eb8602a846b9360e6349a24ba73'
BLOCK = '''          if old_db_value != new_db_value
            originals = dirty_originals
            originals[{{decl.var.stringify}}] = old_db_value unless originals.has_key?({{decl.var.stringify}})
            original = originals[{{decl.var.stringify}}]
            if original == new_db_value
              @changed_attributes.try(&.delete({{decl.var.stringify}}))
            else
              dirty_pending[{{decl.var.stringify}}] = {original, new_db_value}
            end
          end'''
CAPTURE = '''          captured_assignment = Grant::Dirty::CapturedColumnAssignment.new(
            {{decl.var.stringify}}, old_db_value, new_db_value,
            @original_attributes, @changed_attributes,
          )
'''
CONTROL = CAPTURE + BLOCK.replace('if old_db_value != new_db_value', 'if Grant::Dirty.has_different_assignment_values?(captured_assignment)').replace(
    '            if original == new_db_value', '''            original_assignment = Grant::Dirty::CapturedColumnAssignment.new(
              {{decl.var.stringify}}, original, new_db_value,
              @original_attributes, @changed_attributes,
            )
            if Grant::Dirty.has_equal_assignment_values?(original_assignment)''')
FULL = CAPTURE + '''          recorded_assignment = Grant::Dirty.record_column_assignment(captured_assignment)
          @original_attributes = recorded_assignment.collection_of_original_attribute_values
          @changed_attributes = recorded_assignment.collection_of_pending_attribute_changes'''
COMPARATORS = '''
  # Preserves the original first comparison after crossing the fixed value fields.
  #
  # :nodoc:
  @[NoInline]
  def self.has_different_assignment_values?(captured : CapturedColumnAssignment) : Bool
    captured.previous_database_value != captured.current_database_value
  end

  # Preserves the original reversion comparison and its operand direction.
  #
  # :nodoc:
  @[NoInline]
  def self.has_equal_assignment_values?(captured : CapturedColumnAssignment) : Bool
    captured.previous_database_value == captured.current_database_value
  end
'''
TRANSITION = '''
  # Records the complete transition while preserving existing lazy hash references.
  #
  # :nodoc:
  @[NoInline]
  def self.record_column_assignment(captured : CapturedColumnAssignment) : RecordedColumnAssignment
    collection_of_original_attribute_values = captured.collection_of_original_attribute_values
    collection_of_pending_attribute_changes = captured.collection_of_pending_attribute_changes
    if has_different_assignment_values?(captured)
      attribute_name = captured.attribute_name
      previous_database_value = captured.previous_database_value
      current_database_value = captured.current_database_value
      collection_of_original_attribute_values ||= Hash(String, Grant::Base::DirtyValue).new
      unless collection_of_original_attribute_values.has_key?(attribute_name)
        collection_of_original_attribute_values[attribute_name] = previous_database_value
      end
      original_database_value = collection_of_original_attribute_values[attribute_name]
      original_assignment = CapturedColumnAssignment.new(
        attribute_name, original_database_value, current_database_value,
        collection_of_original_attribute_values, collection_of_pending_attribute_changes,
      )
      if has_equal_assignment_values?(original_assignment)
        if pending_attribute_changes = collection_of_pending_attribute_changes
          pending_attribute_changes.delete(attribute_name)
        end
      else
        collection_of_pending_attribute_changes ||= Hash(String, Tuple(Grant::Base::DirtyValue, Grant::Base::DirtyValue)).new
        collection_of_pending_attribute_changes[attribute_name] = {original_database_value, current_database_value}
      end
    end
    RecordedColumnAssignment.new(collection_of_original_attribute_values, collection_of_pending_attribute_changes)
  end
'''


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def derive(arm):
    need(arm in ('original', 'comparison', 'transition', 'restored'), 'Explicit four-arm dirty transition required')
    columns = (ROOT / 'source/columns.original.cr.txt').read_bytes()
    dirty = (ROOT / 'source/dirty.original.cr.txt').read_bytes()
    need(sha(columns) == COLUMNS_SHA256 and sha(dirty) == DIRTY_SHA256, 'Exact d784 original column and dirty source required')
    need(columns.count(BLOCK.encode()) == 2 and dirty.count(b'module Grant::Dirty\n') == 1, 'Exact nullable/required setter and module anchors required')
    values = dict(zip(PATHS, (columns, dirty, None, None)))
    if arm in ('original', 'restored'):
        return values
    replacement = CONTROL if arm == 'comparison' else FULL
    values[PATHS[0]] = columns.replace(BLOCK.encode(), replacement.encode())
    # The complete perimeter and unrelated mass-assignment/dirty APIs retain exact bytes.
    need(values[PATHS[0]].replace(replacement.encode(), BLOCK.encode()) == columns, 'Byte-identical full typed-setter perimeter required')
    requirements = 'require "./dirty/captured_column_assignment"\n'
    if arm == 'transition':
        requirements += 'require "./dirty/recorded_column_assignment"\n'
    additions = COMPARATORS + (TRANSITION if arm == 'transition' else '')
    values[PATHS[1]] = requirements.encode() + dirty.replace(b'module Grant::Dirty\n', b'module Grant::Dirty\n' + additions.encode(), 1)
    values[PATHS[2]] = (ROOT / 'source/captured_column_assignment.cr.txt').read_bytes()
    if arm == 'transition':
        values[PATHS[3]] = (ROOT / 'source/recorded_column_assignment.cr.txt').read_bytes()
    return values
