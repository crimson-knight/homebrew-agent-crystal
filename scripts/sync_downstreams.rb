# Moves every downstream of this compiler to the release this tap now ships.
#
#   ruby scripts/sync_downstreams.rb plan                  list each pin that names an earlier release
#   ruby scripts/sync_downstreams.rb sync --work-dir DIR   open one pull request per repository that needs one
#   ruby scripts/sync_downstreams.rb bottles               start each tap's bottles workflow once its sync merged
#   ruby scripts/sync_downstreams.rb check                 exit 1 while any downstream is behind
#
# The downstreams are listed in downstreams.json beside this script's directory. A pin
# names a release by its version, the tap commit that carries its bottles, the compiler
# commit it was tagged at, its source archive sha256 or a bottle sha256. Every earlier
# release this tap bottled is read from its git history, so the script needs a full
# clone (not --depth 1) with the new release's bottles commit already on it: run it after
# bottles.yml has published the compiler's bottles and verify-bottles.yml passed.
#
# Automatic downstreams get their pins rewritten to the new release, and each formula
# under list_of_formulae_to_rebuild gets its revision raised, its old bottle block
# removed and a comment naming the compiler it is built with, so Homebrew rebuilds it on
# the new compiler and the tap's bottles workflow publishes new bottles. By-hand
# downstreams are listed with their how_to_sync; check fails for them too until done.
# Uses git and gh with the caller's credentials (pushing a workflow edit needs the
# workflow scope).
require "fileutils"
require "json"
require "open3"

module DownstreamSync
  ROOT = File.expand_path("..", __dir__)
  MANIFEST_PATH = File.join(ROOT, "downstreams.json")
  FORMULA_PATH = "Formula/agent-crystal.rb"
  LOCK_PATH = "test/sdk_source_lock.json"
  BOTTLES_COMMIT_SUBJECT = /\Aagent-crystal-(\S+): bottles for /
  FULL_VERSION_PATTERN = /(?<![\w.])\d+\.\d+\.\d+-incremental-\d+(?![\w.])/
  SHORT_VERSION_PATTERN = /(?<![\w.-])incremental-\d+(?![\w.])/
  BOTTLE_BLOCK_PATTERN = /^  bottle do\n.*?^  end\n\n/m
  COMPILER_COMMENT_PATTERN = /^  # Built with agent-crystal \S+ .*\n(?:  # scripts\/sync_downstreams\.rb .*\n)?/
  COMPILER_DEPENDENCY_LINE = %(  depends_on "crimson-knight/agent-crystal/agent-crystal")
  REPORTED_PINS_PER_FILE = 5

  class SyncRefused < StandardError; end

  # One compiler release as this tap bottled it.
  Release = Struct.new(:version, :bottles_commit, :source_commit, :archive_sha256, :bottle_sha256_by_tag,
    keyword_init: true) do
    def short_version
      version[/incremental-\d+\z/]
    end
  end

  # A pin that names an earlier release, and what it becomes.
  StalePin = Struct.new(:file, :line_number, :old_token, :new_token, keyword_init: true)

  module_function

  def run_command(*list_of_arguments, chdir: ROOT)
    output, status = Open3.capture2e(*list_of_arguments, chdir: chdir)
    raise SyncRefused, "#{list_of_arguments.join(" ")} failed:\n#{output}" unless status.success?

    output
  end

  def read_release_at(commit)
    formula_text = run_command("git", "show", "#{commit}:#{FORMULA_PATH}")
    lock_text = IO.popen(["git", "-C", ROOT, "show", "#{commit}:#{LOCK_PATH}"], err: File::NULL, &:read)
    source_commit = $?.success? ? JSON.parse(lock_text).dig("alpha", "source_commit") : nil
    Release.new(
      version: formula_text[/^  version "([^"]+)"$/, 1],
      bottles_commit: commit,
      source_commit: source_commit,
      archive_sha256: formula_text[/^  sha256 "([0-9a-f]{64})"$/, 1],
      bottle_sha256_by_tag: formula_text.scan(/^    sha256 cellar: \S+ (\w+):\s+"([0-9a-f]{64})"$/).to_h
    )
  end

  # The newest bottles commit is the current release; every older one is an earlier release.
  def read_list_of_releases
    list_of_bottles_commits = run_command("git", "log", "--format=%H%x09%s").lines.map do |line|
      commit, subject = line.chomp.split("\t", 2)
      commit if subject.to_s.match?(BOTTLES_COMMIT_SUBJECT)
    end.compact
    raise SyncRefused, "No bottles commit in this tap's history; run bottles.yml first." if list_of_bottles_commits.empty?

    list_of_releases = list_of_bottles_commits.map { |commit| read_release_at(commit) }
    current_version = File.read(File.join(ROOT, FORMULA_PATH))[/^  version "([^"]+)"$/, 1]
    unless list_of_releases.first.version == current_version
      raise SyncRefused, "The formula is at #{current_version}, but the newest bottles commit is for " \
                         "#{list_of_releases.first.version}. Publish its bottles (bottles.yml) first."
    end

    list_of_releases
  end

  # Old token => new token, for every hash an earlier release could be pinned by.
  def replacement_by_old_token(current_release, list_of_earlier_releases)
    replacements = {}
    list_of_earlier_releases.each do |earlier_release|
      replacements[earlier_release.bottles_commit] = current_release.bottles_commit
      if earlier_release.source_commit && earlier_release.source_commit != current_release.source_commit
        replacements[earlier_release.source_commit] = current_release.source_commit
      end
      if earlier_release.archive_sha256 != current_release.archive_sha256
        replacements[earlier_release.archive_sha256] = current_release.archive_sha256
      end
      earlier_release.bottle_sha256_by_tag.each do |tag, sha256|
        new_sha256 = current_release.bottle_sha256_by_tag[tag]
        replacements[sha256] = new_sha256 if new_sha256 && new_sha256 != sha256
      end
    end
    replacements.delete(nil)
    replacements
  end

  def list_of_stale_pins_in(file, text, current_release, replacements)
    list_of_stale_pins = []
    text.each_line.with_index(1) do |line, line_number|
      replacements.each do |old_token, new_token|
        next unless line.include?(old_token)

        list_of_stale_pins << StalePin.new(file: file, line_number: line_number, old_token: old_token, new_token: new_token)
      end
      line.scan(FULL_VERSION_PATTERN).uniq.each do |version|
        next if version == current_release.version

        list_of_stale_pins << StalePin.new(file: file, line_number: line_number, old_token: version, new_token: current_release.version)
      end
      line.gsub(FULL_VERSION_PATTERN, "").scan(SHORT_VERSION_PATTERN).uniq.each do |short_version|
        next if short_version == current_release.short_version

        list_of_stale_pins << StalePin.new(file: file, line_number: line_number, old_token: short_version, new_token: current_release.short_version)
      end
    end
    list_of_stale_pins
  end

  def rewrite_pins(text, current_release, replacements)
    rewritten = replacements.reduce(text) { |result, (old_token, new_token)| result.gsub(old_token, new_token) }
    rewritten = rewritten.gsub(FULL_VERSION_PATTERN, current_release.version)
    rewritten.gsub(SHORT_VERSION_PATTERN, current_release.short_version)
  end

  # Raises the revision (Homebrew then rebuilds the formula and its users upgrade to it),
  # drops the bottle block built on the earlier compiler, and names the compiler it builds on.
  def rebuild_formula_text(text, current_release)
    unless text.include?(COMPILER_DEPENDENCY_LINE)
      raise SyncRefused, "the formula has no #{COMPILER_DEPENDENCY_LINE.strip} line"
    end

    rebuilt = text.sub(BOTTLE_BLOCK_PATTERN, "")
    if rebuilt.match?(/^  revision (\d+)$/)
      rebuilt = rebuilt.sub(/^  revision (\d+)$/) { "  revision #{Regexp.last_match(1).to_i + 1}" }
    else
      # Homebrew's component order puts revision right after license (or sha256 when there is no license).
      anchor_pattern = rebuilt.match?(/^  license .*\n/) ? /^(  license .*\n)/ : /^(  sha256 "[0-9a-f]{64}"\n)/
      rebuilt = rebuilt.sub(anchor_pattern) { "#{Regexp.last_match(1)}  revision 1\n" }
      raise SyncRefused, "the formula has no top-level license or sha256 line to put a revision after" unless rebuilt.match?(/^  revision 1$/)
    end
    compiler_comment = "  # Built with agent-crystal #{current_release.version} (tap commit #{current_release.bottles_commit[0, 12]}).\n" \
                       "  # scripts/sync_downstreams.rb in crimson-knight/homebrew-agent-crystal raises the revision when it moves.\n"
    rebuilt = rebuilt.sub(COMPILER_COMMENT_PATTERN, "")
    rebuilt.sub(/^#{Regexp.escape(COMPILER_DEPENDENCY_LINE)}(.*)$/) { "#{compiler_comment}#{COMPILER_DEPENDENCY_LINE}#{Regexp.last_match(1)}" }
  end

  def formula_names_compiler?(text, current_release)
    text.include?("# Built with agent-crystal #{current_release.version} ")
  end

  def formula_has_bottles?(text)
    text.match?(BOTTLE_BLOCK_PATTERN)
  end

  def read_manifest
    JSON.parse(File.read(MANIFEST_PATH)).fetch("list_of_downstreams")
  end

  def read_remote_file(downstream, file)
    output, status = Open3.capture2e("gh", "api", "-H", "Accept: application/vnd.github.raw",
      "repos/#{downstream.fetch("repository")}/contents/#{file}?ref=#{downstream.fetch("branch")}")
    raise SyncRefused, "#{downstream.fetch("repository")}:#{file} could not be read:\n#{output}" unless status.success?

    output
  end

  def sync_branch_name(current_release)
    "agent-crystal-#{current_release.version}-sync"
  end

  # Every problem that keeps a downstream behind the current release, as text lines.
  def list_of_problems_for(downstream, current_release, replacements, read_file)
    list_of_problems = []
    downstream.fetch("list_of_pin_files").each do |file|
      list_of_stale_pins = list_of_stale_pins_in(file, read_file.call(file), current_release, replacements)
      list_of_stale_pins.first(REPORTED_PINS_PER_FILE).each do |stale_pin|
        list_of_problems << "#{stale_pin.file}:#{stale_pin.line_number} names #{stale_pin.old_token} (now #{stale_pin.new_token})"
      end
      hidden_count = list_of_stale_pins.size - REPORTED_PINS_PER_FILE
      list_of_problems << "#{file}: #{hidden_count} more stale pins" if hidden_count.positive?
    end
    downstream.fetch("list_of_formulae_to_rebuild", []).each do |file|
      text = read_file.call(file)
      list_of_problems << "#{file} is not rebuilt on agent-crystal #{current_release.version}" unless formula_names_compiler?(text, current_release)
      if downstream["bottles_workflow"] && !formula_has_bottles?(text)
        list_of_problems << "#{file} has no bottles yet (ruby scripts/sync_downstreams.rb bottles)"
      end
    end
    list_of_problems
  end

  def report_downstreams(current_release, replacements)
    behind_count = 0
    read_manifest.each do |downstream|
      read_file = ->(file) { read_remote_file(downstream, file) }
      list_of_problems = list_of_problems_for(downstream, current_release, replacements, read_file)
      label = "#{downstream.fetch("repository")}@#{downstream.fetch("branch")} (#{downstream.fetch("sync")})"
      if list_of_problems.empty?
        puts "OK      #{label}"
      else
        behind_count += 1
        puts "BEHIND  #{label}"
        list_of_problems.each { |problem| puts "          #{problem}" }
        puts "          how: #{downstream["how_to_sync"]}" if downstream["how_to_sync"]
      end
    end
    behind_count
  end

  def open_sync_pull_request(downstream, current_release, replacements, work_directory)
    repository = downstream.fetch("repository")
    branch = sync_branch_name(current_release)
    existing = run_command("gh", "pr", "list", "-R", repository, "--head", branch, "--state", "all",
      "--json", "url", "--jq", ".[].url").strip
    return puts("PR      #{repository}: #{existing} (already open or merged)") unless existing.empty?

    clone_directory = File.join(work_directory, repository.tr("/", "_"))
    FileUtils.rm_rf(clone_directory)
    run_command("git", "clone", "--quiet", "--depth", "1", "--branch", downstream.fetch("branch"),
      "https://github.com/#{repository}.git", clone_directory, chdir: work_directory)
    run_command("git", "switch", "--quiet", "-c", branch, chdir: clone_directory)
    list_of_changes = []
    downstream.fetch("list_of_pin_files").each do |file|
      path = File.join(clone_directory, file)
      text = File.read(path)
      list_of_stale_pins = list_of_stale_pins_in(file, text, current_release, replacements)
      next if list_of_stale_pins.empty?

      File.write(path, rewrite_pins(text, current_release, replacements))
      list_of_stale_pins.each { |pin| list_of_changes << "#{pin.file}:#{pin.line_number} #{pin.old_token} -> #{pin.new_token}" }
    end
    downstream.fetch("list_of_formulae_to_rebuild", []).each do |file|
      path = File.join(clone_directory, file)
      text = File.read(path)
      next if formula_names_compiler?(text, current_release)

      File.write(path, rebuild_formula_text(text, current_release))
      list_of_changes << "#{file}: revision raised, bottle block removed, built with agent-crystal #{current_release.version}"
    end
    return puts("OK      #{repository}: nothing to change") if list_of_changes.empty?

    title = "Build on agent-crystal #{current_release.version}"
    body = <<~BODY
      Moves this repository to crimson-knight/crystal v#{current_release.version}: compiler commit #{current_release.source_commit}, source archive sha256 #{current_release.archive_sha256}, bottles at crimson-knight/homebrew-agent-crystal #{current_release.bottles_commit}.

      #{list_of_changes.map { |change| "- #{change}" }.join("\n")}

      Opened by `ruby scripts/sync_downstreams.rb sync` in crimson-knight/homebrew-agent-crystal (downstreams.json).#{downstream["bottles_workflow"] ? " After this merges, `ruby scripts/sync_downstreams.rb bottles` starts #{downstream["bottles_workflow"]} on #{downstream.fetch("branch")}, which publishes the rebuilt bottles." : ""}
    BODY
    run_command("git", "commit", "--quiet", "-am", title, chdir: clone_directory)
    run_command("git", "push", "--quiet", "-u", "origin", branch, chdir: clone_directory)
    url = run_command("gh", "pr", "create", "-R", repository, "--base", downstream.fetch("branch"), "--head", branch,
      "--title", title, "--body", body, chdir: clone_directory).strip
    puts "PR      #{repository}: #{url}"
    list_of_changes.each { |change| puts "          #{change}" }
  end

  def start_bottles(current_release)
    read_manifest.each do |downstream|
      workflow = downstream["bottles_workflow"]
      next unless workflow

      repository = downstream.fetch("repository")
      list_of_texts = downstream.fetch("list_of_formulae_to_rebuild").map { |file| read_remote_file(downstream, file) }
      if list_of_texts.any? { |text| !formula_names_compiler?(text, current_release) }
        puts "WAIT    #{repository}: its sync pull request has not merged"
      elsif list_of_texts.all? { |text| formula_has_bottles?(text) }
        puts "OK      #{repository}: bottles published"
      else
        run_command("gh", "workflow", "run", workflow, "-R", repository, "--ref", downstream.fetch("branch"))
        puts "STARTED #{repository}: #{workflow} on #{downstream.fetch("branch")}"
      end
    end
  end

  def main(list_of_arguments)
    list_of_releases = read_list_of_releases
    current_release = list_of_releases.first
    replacements = replacement_by_old_token(current_release, list_of_releases.drop(1))
    puts "Release #{current_release.version}: compiler #{current_release.source_commit}, " \
         "archive #{current_release.archive_sha256}, bottles #{current_release.bottles_commit}"
    case list_of_arguments.first
    when "plan"
      report_downstreams(current_release, replacements)
    when "check"
      behind_count = report_downstreams(current_release, replacements)
      if behind_count.positive?
        warn "#{behind_count} downstream(s) still build on an earlier release; the release is not done."
        exit 1
      end
      puts "Every downstream builds on #{current_release.version}."
    when "sync"
      work_directory_index = list_of_arguments.index("--work-dir")
      work_directory = work_directory_index && list_of_arguments[work_directory_index + 1]
      raise SyncRefused, "sync needs --work-dir DIR (a scratch directory for the clones)" unless work_directory

      FileUtils.mkdir_p(work_directory)
      read_manifest.each do |downstream|
        if downstream.fetch("sync") == "automatic"
          open_sync_pull_request(downstream, current_release, replacements, File.expand_path(work_directory))
        else
          puts "BY HAND #{downstream.fetch("repository")}: #{downstream.fetch("how_to_sync")}"
        end
      end
    when "bottles"
      start_bottles(current_release)
    else
      warn "usage: ruby scripts/sync_downstreams.rb plan | sync --work-dir DIR | bottles | check"
      exit 2
    end
  rescue SyncRefused, KeyError, JSON::ParserError => error
    warn "sync_downstreams refused: #{error.message}"
    exit 1
  end
end

DownstreamSync.main(ARGV) if $PROGRAM_NAME == __FILE__
