# Re-pins the reviewed hash chain after an edit to the formula or to a pinned test script.
#
#   Formula/agent-crystal.rb (without its bottle block) -> test/sdk_source_lock.json alpha.formula_sha256
#   each pinned file below -> every place in the repository that names its sha256
#
# A pinned file's old sha256 is the one committed at HEAD; the script replaces it
# with the file's current sha256 wherever it appears, and repeats until nothing
# changes (the lock names a test script, workflows name the lock). Run it from a
# branch, review the diff, and push with credentials that may edit workflows.
# usage: ruby scripts/repin_formula.rb
require "digest"
require "json"

ROOT = File.expand_path("..", __dir__)
LIST_OF_PINNED_FILES = %w[
  test/linux_projection_identity.py
  test/sdk_install_qualification.py
  test/linux_native_projection.py
  test/sdk_cpu_diagnostic.py
  test/sdk_source_lock.json
]
LIST_OF_REFERENCING_GLOBS = %w[.github/workflows/*.yml test/*.py test/*.json]

# The sha256 the SDK checks pin: the formula without its bottle block, which the
# Bottles workflow rewrites on every release.
def formula_sha256(text)
  Digest::SHA256.hexdigest(text.sub(/^  bottle do\n.*?^  end\n\n/m, ""))
end

def committed_sha256(relative_path)
  committed = IO.popen(["git", "-C", ROOT, "show", "HEAD:#{relative_path}"], err: File::NULL, &:read)
  $?.success? ? Digest::SHA256.hexdigest(committed) : nil
end

lock_path = File.join(ROOT, "test/sdk_source_lock.json")
lock_text = File.read(lock_path)
recorded = lock_text[/"formula_sha256": "([0-9a-f]{64})"/, 1] || abort("sdk_source_lock.json has no alpha.formula_sha256")
current = formula_sha256(File.read(File.join(ROOT, "Formula/agent-crystal.rb")))
if recorded != current
  File.write(lock_path, lock_text.sub(%("formula_sha256": "#{recorded}"), %("formula_sha256": "#{current}")))
  JSON.parse(File.read(lock_path))
  puts "formula #{recorded} -> #{current}"
end

list_of_referencing_files = LIST_OF_REFERENCING_GLOBS.flat_map { |glob| Dir.glob(File.join(ROOT, glob)) }.sort
pinned_sha256 = LIST_OF_PINNED_FILES.to_h { |relative_path| [relative_path, committed_sha256(relative_path)] }
loop do
  changed = false
  LIST_OF_PINNED_FILES.each do |relative_path|
    old_sha256 = pinned_sha256[relative_path]
    new_sha256 = Digest::SHA256.file(File.join(ROOT, relative_path)).hexdigest
    next if old_sha256.nil? || old_sha256 == new_sha256

    list_of_referencing_files.each do |path|
      next if path == File.join(ROOT, relative_path)
      text = File.read(path)
      next unless text.include?(old_sha256)
      File.write(path, text.gsub(old_sha256, new_sha256))
      puts "#{relative_path} #{old_sha256[0, 12]} -> #{new_sha256[0, 12]} in #{path.delete_prefix(ROOT + "/")}"
      changed = true
    end
    pinned_sha256[relative_path] = new_sha256
  end
  break unless changed
end
