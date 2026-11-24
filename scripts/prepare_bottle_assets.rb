# Prepares the bottles `brew bottle --json` wrote for upload to the tap release.
# Each bottle must match the sha256 its JSON records; a mismatch stops the publish.
# Writes, inside <bottles-dir>:
#   upload/<filename>   each bottle under the name Homebrew downloads it by
#   release_tag.txt     agent-crystal-<version>
#   bottle_tags.txt     the bottle tags, comma separated
#   release_notes.md    one row per bottle with its sha256
# usage: ruby scripts/prepare_bottle_assets.rb <bottles-dir>
require "digest"
require "fileutils"
require "json"

bottles_dir = ARGV.fetch(0)
upload_dir = File.join(bottles_dir, "upload")
FileUtils.mkdir_p(upload_dir)

list_of_json_paths = Dir.glob(File.join(bottles_dir, "*.bottle.json")).sort
abort "no *.bottle.json in #{bottles_dir}" if list_of_json_paths.empty?

list_of_versions = []
list_of_rows = []
list_of_json_paths.each do |json_path|
  JSON.parse(File.read(json_path)).each_value do |entry|
    list_of_versions << entry.fetch("formula").fetch("pkg_version")
    entry.fetch("bottle").fetch("tags").each do |tag, bottle|
      local_path = File.join(bottles_dir, bottle.fetch("local_filename"))
      actual_sha256 = Digest::SHA256.file(local_path).hexdigest
      unless actual_sha256 == bottle.fetch("sha256")
        abort "#{bottle["local_filename"]}: sha256 #{actual_sha256} is not the recorded #{bottle["sha256"]}"
      end
      FileUtils.cp(local_path, File.join(upload_dir, bottle.fetch("filename")))
      list_of_rows << [tag, bottle.fetch("filename"), actual_sha256, File.size(local_path)]
    end
  end
end

list_of_versions.uniq!
abort "bottles disagree on the version: #{list_of_versions.join(", ")}" unless list_of_versions.size == 1
release_tag = "agent-crystal-#{list_of_versions.first}"

File.write(File.join(bottles_dir, "release_tag.txt"), release_tag)
File.write(File.join(bottles_dir, "bottle_tags.txt"), list_of_rows.map(&:first).join(", "))
notes = +"Prebuilt bottles of agent-crystal #{list_of_versions.first}. The formula pins each one by sha256.\n\n"
notes << "| Bottle tag | File | sha256 | Bytes |\n|---|---|---|---|\n"
list_of_rows.each { |tag, filename, sha256, bytes| notes << "| #{tag} | #{filename} | `#{sha256}` | #{bytes} |\n" }
File.write(File.join(bottles_dir, "release_notes.md"), notes)
puts notes
