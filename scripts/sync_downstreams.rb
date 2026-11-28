# Moves every downstream of this compiler to the release this tap now ships.
#
#   ruby scripts/sync_downstreams.rb plan                  list each pin that names an earlier release
#   ruby scripts/sync_downstreams.rb sync --work-dir DIR   open one pull request per repository that needs one
#   ruby scripts/sync_downstreams.rb bottles               start each tap's bottles workflow once its sync merged
#   ruby scripts/sync_downstreams.rb check                 exit 1 while any downstream is behind
#
# The downstreams are listed in downstreams.json at the root of this tap. A pin names a
# release by its version (with or without the tag's "v"), a compiler commit (full, 12 or
# 7 characters), the tap commit that carries its bottles, its source archive sha256 or a
# bottle sha256. The releases come from crimson-knight/crystal's v*-incremental-* tags and
# from this tap's "agent-crystal-<version>: bottles for" commits, so the script runs in a
# full clone (not --depth 1) that contains origin/main, after bottles.yml has published
# the new release's bottles and verify-bottles.yml passed.
#
# A downstream tap that rebuilds formulae on the compiler (list_of_formulae_to_rebuild) is
# itself pinned elsewhere (agentc-mdm pins amber_cli bottles), so its commits and bottle
# sha256s from before its rebuild count as earlier-release pins in every other repository.
#
# Automatic downstreams get their pins rewritten, and each formula under
# list_of_formulae_to_rebuild gets its revision raised, its old bottle block removed and a
# comment naming the compiler it is built with, so Homebrew rebuilds it on the new compiler
# and the tap's bottles workflow publishes new bottles. By-hand downstreams are listed with
# their how_to_sync; check fails for them too until done. A pin file line that carries
# "sync-downstreams: keep" is history, never a pin, and is left alone.
#
# Uses git and gh with the caller's credentials (pushing a workflow edit needs the
# workflow scope).
require "fileutils"
require "json"
require "open3"
require "rbconfig"

module DownstreamSync
  ROOT = File.expand_path("..", __dir__)
  MANIFEST_PATH = File.join(ROOT, "downstreams.json")
  FORMULA_PATH = "Formula/agent-crystal.rb"
  LOCK_PATH = "test/sdk_source_lock.json"
  COMPILER_REPOSITORY_URL = "https://github.com/crimson-knight/crystal.git"
  BOTTLES_COMMIT_SUBJECT = /\Aagent-crystal-(\S+): bottles for /
  RELEASE_TAG_PATTERN = %r{\A([0-9a-f]{40})\trefs/tags/v(\d+\.\d+\.\d+-incremental-\d+)(\^\{\})?\z}
  BOTTLE_BLOCK_PATTERN = /^  bottle do\n.*?^  end\n(?:\n)?/m
  BOTTLE_SHA256_PATTERN = /^    sha256 (?:cellar: \S+ )?(\w+):\s+"([0-9a-f]{64})"$/
  COMPILER_COMMENT_PATTERN = /^  # Built with agent-crystal \S+ .*\n(?:  # scripts\/sync_downstreams\.rb .*\n)?/
  COMPILER_DEPENDENCY_LINE = %(  depends_on "crimson-knight/agent-crystal/agent-crystal")
  HEAD_KEG_PATTERN = %r{agent-crystal/HEAD-[0-9a-f]+}
  KEEP_MARKER = "sync-downstreams: keep"
  LIST_OF_SHORT_COMMIT_LENGTHS = [12, 7].freeze
  REPORTED_PINS_PER_FILE = 5
  LIST_OF_MODES = %w[plan check sync bottles].freeze

  class SyncRefused < StandardError; end

  # One compiler release: its version and every hash a pin could name it by.
  Release = Struct.new(:version, :source_commit, :bottles_commit, :archive_sha256, :bottle_sha256_by_tag,
    keyword_init: true) do
    def short_version
      version[/incremental-\d+\z/]
    end
  end

  # How one earlier-release token is found in a line, and what it becomes (nil: a person picks).
  TokenRule = Struct.new(:pattern, :new_token, :label, keyword_init: true) do
    def has_a_replacement?
      !new_token.nil?
    end
  end

  # A pin that names an earlier release.
  StalePin = Struct.new(:file, :line_number, :old_token, :new_token, keyword_init: true)

  module_function

  def run_command(*list_of_arguments, chdir: ROOT)
    output, status = Open3.capture2e(*list_of_arguments, chdir: chdir)
    raise SyncRefused, "#{list_of_arguments.join(" ")} failed:\n#{output}" unless status.success?

    output
  end

  # Refuses a clone that cannot see every release, or one behind origin/main.
  def require_a_current_full_clone
    if run_command("git", "rev-parse", "--is-shallow-repository").strip == "true"
      raise SyncRefused, "this clone is shallow; earlier releases are invisible to it. Run git fetch --unshallow."
    end
    run_command("git", "fetch", "--quiet", "origin", "main")
    _output, status = Open3.capture2e("git", "merge-base", "--is-ancestor", "origin/main", "HEAD", chdir: ROOT)
    raise SyncRefused, "HEAD does not contain origin/main; pull main first." unless status.success?
  end

  # version => compiler commit, for every v*-incremental-* tag of crimson-knight/crystal. A
  # lightweight tag names its commit directly; an annotated tag's peeled (^{}) line wins.
  def read_compiler_commit_by_version(ls_remote_text = run_command("git", "ls-remote", "--tags", COMPILER_REPOSITORY_URL))
    list_of_matches = ls_remote_text.each_line.map { |line| line.chomp.match(RELEASE_TAG_PATTERN) }.compact
    commit_by_version = {}
    list_of_matches.reject { |match| match[3] }.each { |match| commit_by_version[match[2]] = match[1] }
    list_of_matches.select { |match| match[3] }.each { |match| commit_by_version[match[2]] = match[1] }
    commit_by_version
  end

  def read_tap_release_at(commit)
    formula_text = run_command("git", "show", "#{commit}:#{FORMULA_PATH}")
    lock_text = IO.popen(["git", "-C", ROOT, "show", "#{commit}:#{LOCK_PATH}"], err: File::NULL, &:read)
    source_commit = $?.success? ? JSON.parse(lock_text).dig("alpha", "source_commit") : nil
    Release.new(
      version: formula_text[/^  version "([^"]+)"$/, 1],
      source_commit: source_commit,
      bottles_commit: commit,
      archive_sha256: formula_text[/^  sha256 "([0-9a-f]{64})"$/, 1],
      bottle_sha256_by_tag: formula_text.scan(BOTTLE_SHA256_PATTERN).to_h
    )
  end

  # The current release first, then every earlier one this tap bottled or the fork tagged.
  def read_list_of_releases(compiler_commit_by_version)
    list_of_bottles_commits = run_command("git", "log", "--format=%H%x09%s").lines.map do |line|
      commit, subject = line.chomp.split("\t", 2)
      commit if subject.to_s.match?(BOTTLES_COMMIT_SUBJECT)
    end.compact
    raise SyncRefused, "No bottles commit in this tap's history; run bottles.yml first." if list_of_bottles_commits.empty?

    list_of_tap_releases = list_of_bottles_commits.map { |commit| read_tap_release_at(commit) }
    list_of_tap_releases.each { |release| release.source_commit ||= compiler_commit_by_version[release.version] }
    current_release = list_of_tap_releases.first
    current_version = File.read(File.join(ROOT, FORMULA_PATH))[/^  version "([^"]+)"$/, 1]
    unless current_release.version == current_version
      raise SyncRefused, "The formula is at #{current_version}, but the newest bottles commit is for " \
                         "#{current_release.version}. Publish its bottles (bottles.yml) first."
    end
    current_release.source_commit ||= compiler_commit_by_version[current_release.version]
    raise SyncRefused, "No compiler commit is known for #{current_release.version}." unless current_release.source_commit

    newer_version = compiler_commit_by_version.keys.max_by { |version| version_key(version) }
    if newer_version && (version_key(newer_version) <=> version_key(current_release.version)) == 1
      raise SyncRefused, "crimson-knight/crystal has v#{newer_version}, but this tap ships #{current_release.version}; move the formula first."
    end

    bottled_versions = list_of_tap_releases.map(&:version)
    list_of_tagged_releases = compiler_commit_by_version.reject { |version, _| bottled_versions.include?(version) }
                                                         .map { |version, commit| Release.new(version: version, source_commit: commit, bottle_sha256_by_tag: {}) }
    [current_release] + list_of_tap_releases.drop(1) + list_of_tagged_releases
  end

  def version_key(version)
    version.scan(/\d+/).map(&:to_i)
  end

  def hex_pattern(token)
    /(?<![0-9a-f])(?<!HEAD-)#{Regexp.escape(token)}(?![0-9a-f])/
  end

  def list_of_commit_rules(old_commit, new_commit, label)
    return [] if old_commit.nil? || old_commit == new_commit

    full_rule = TokenRule.new(pattern: hex_pattern(old_commit), new_token: new_commit, label: label)
    list_of_short_rules = LIST_OF_SHORT_COMMIT_LENGTHS.map do |length|
      TokenRule.new(pattern: hex_pattern(old_commit[0, length]), new_token: new_commit && new_commit[0, length], label: label)
    end
    [full_rule] + list_of_short_rules
  end

  def list_of_sha256_rules(old_sha256_by_tag, new_sha256_by_tag, label)
    old_sha256_by_tag.map do |tag, old_sha256|
      new_sha256 = new_sha256_by_tag && new_sha256_by_tag[tag]
      next if old_sha256 == new_sha256

      TokenRule.new(pattern: hex_pattern(old_sha256), new_token: new_sha256, label: "#{label} #{tag} bottle")
    end.compact
  end

  # Every way an earlier release can be named, and what it becomes in the current one.
  def list_of_release_rules(current_release, list_of_earlier_releases)
    list_of_rules = []
    list_of_earlier_releases.each do |earlier_release|
      label = earlier_release.version
      list_of_rules.concat(list_of_commit_rules(earlier_release.source_commit, current_release.source_commit, "#{label} compiler"))
      list_of_rules.concat(list_of_commit_rules(earlier_release.bottles_commit, current_release.bottles_commit, "#{label} bottles"))
      if earlier_release.archive_sha256 && earlier_release.archive_sha256 != current_release.archive_sha256
        list_of_rules << TokenRule.new(pattern: hex_pattern(earlier_release.archive_sha256),
          new_token: current_release.archive_sha256, label: "#{label} archive")
      end
      list_of_rules.concat(list_of_sha256_rules(earlier_release.bottle_sha256_by_tag, current_release.bottle_sha256_by_tag, label))
      next if earlier_release.version == current_release.version

      list_of_rules << TokenRule.new(pattern: /(?<![\w.])(v?)#{Regexp.escape(earlier_release.version)}(?!\d|\.\d)/,
        new_token: "\\1#{current_release.version}", label: label)
    end
    list_of_short_versions = list_of_earlier_releases.map(&:short_version).uniq - [current_release.short_version]
    list_of_short_versions.each do |short_version|
      list_of_rules << TokenRule.new(pattern: /(?<![\w.-])#{Regexp.escape(short_version)}(?!\d|\.\d)/,
        new_token: current_release.short_version, label: short_version)
    end
    list_of_rules << TokenRule.new(pattern: HEAD_KEG_PATTERN, new_token: nil, label: "a HEAD keg, pinned to no release")
    list_of_rules
  end

  def list_of_stale_pins_in(file, text, list_of_rules)
    list_of_stale_pins = []
    text.each_line.with_index(1) do |line, line_number|
      next if line.include?(KEEP_MARKER)

      list_of_rules.each do |rule|
        line.to_enum(:scan, rule.pattern).map { Regexp.last_match }.each do |match|
          new_token = rule.has_a_replacement? ? match[0].sub(rule.pattern, rule.new_token) : "(#{rule.label}; pin it by hand)"
          list_of_stale_pins << StalePin.new(file: file, line_number: line_number, old_token: match[0], new_token: new_token)
        end
      end
    end
    list_of_stale_pins
  end

  def rewrite_pins(text, list_of_rules)
    list_of_rules_with_replacements = list_of_rules.select(&:has_a_replacement?)
    text.each_line.map do |line|
      next line if line.include?(KEEP_MARKER)

      list_of_rules_with_replacements.reduce(line) { |result, rule| result.gsub(rule.pattern, rule.new_token) }
    end.join
  end

  # The line after which Homebrew's component order puts `revision`: after the whole
  # license statement (it can span lines), or after the top-level sha256.
  def revision_anchor_index(list_of_lines)
    license_index = list_of_lines.index { |line| line.start_with?("  license ") }
    if license_index
      depth = 0
      list_of_lines[license_index..-1].each_with_index do |line, offset|
        depth += line.count("[(") - line.count("])")
        return license_index + offset if depth <= 0
      end
      raise SyncRefused, "the formula's license statement never closes"
    end
    sha256_index = list_of_lines.index { |line| line.match?(/\A  sha256 "[0-9a-f]{64}"\n\z/) }
    raise SyncRefused, "the formula has no top-level license or sha256 line to put a revision after" unless sha256_index

    sha256_index
  end

  def require_valid_ruby(text)
    output, status = Open3.capture2e(RbConfig.ruby, "-c", stdin_data: text)
    raise SyncRefused, "the rewritten formula does not parse:\n#{output}" unless status.success?
  end

  # Raises the revision (Homebrew then rebuilds the formula and its users upgrade to it),
  # drops the bottle block built on the earlier compiler, and names the compiler it builds on.
  def rebuild_formula_text(text, current_release)
    unless text.include?(COMPILER_DEPENDENCY_LINE)
      raise SyncRefused, "the formula has no #{COMPILER_DEPENDENCY_LINE.strip} line"
    end

    rebuilt = text.sub(BOTTLE_BLOCK_PATTERN, "")
    raise SyncRefused, "the formula's bottle block could not be removed" if rebuilt.match?(/^  bottle do$/)

    if rebuilt.match?(/^  revision (\d+)$/)
      rebuilt = rebuilt.sub(/^  revision (\d+)$/) { "  revision #{Regexp.last_match(1).to_i + 1}" }
    else
      list_of_lines = rebuilt.lines
      list_of_lines.insert(revision_anchor_index(list_of_lines) + 1, "  revision 1\n")
      rebuilt = list_of_lines.join
    end
    compiler_comment = "  # Built with agent-crystal #{current_release.version} (tap commit #{current_release.bottles_commit[0, 12]}).\n" \
                       "  # scripts/sync_downstreams.rb (crimson-knight/homebrew-agent-crystal) raises the revision when agent-crystal moves.\n"
    rebuilt = rebuilt.sub(COMPILER_COMMENT_PATTERN, "")
    rebuilt = rebuilt.sub(/^#{Regexp.escape(COMPILER_DEPENDENCY_LINE)}(.*)$/) { "#{compiler_comment}#{COMPILER_DEPENDENCY_LINE}#{Regexp.last_match(1)}" }
    require_valid_ruby(rebuilt)
    rebuilt
  end

  def formula_names_compiler?(text, current_release)
    text.include?("# Built with agent-crystal #{current_release.version} ")
  end

  def formula_has_bottles?(text)
    text.match?(BOTTLE_BLOCK_PATTERN)
  end

  def formula_is_rebuilt_and_bottled?(text, current_release)
    formula_names_compiler?(text, current_release) && formula_has_bottles?(text)
  end

  def read_manifest
    JSON.parse(File.read(MANIFEST_PATH)).fetch("list_of_downstreams")
  end

  def read_remote_file(repository, file, ref)
    @text_by_remote_file ||= {}
    @text_by_remote_file[[repository, file, ref]] ||= read_remote_file_uncached(repository, file, ref)
  end

  def read_remote_file_uncached(repository, file, ref)
    output, status = Open3.capture2e("gh", "api", "-H", "Accept: application/vnd.github.raw",
      "repos/#{repository}/contents/#{file}?ref=#{ref}")
    raise SyncRefused, "#{repository}:#{file}@#{ref} could not be read:\n#{output}" unless status.success?

    output
  end

  def read_remote_json(path)
    JSON.parse(run_command("gh", "api", path))
  end

  # The commits and bottle sha256s a downstream tap published before it rebuilt on the
  # current compiler; other repositories that pin them are behind too.
  def list_of_downstream_tap_rules(downstream, current_release)
    repository = downstream.fetch("repository")
    branch = downstream.fetch("branch")
    list_of_formula_files = downstream.fetch("list_of_formulae_to_rebuild", [])
    return [] if list_of_formula_files.empty?

    list_of_branch_commits = read_remote_json("repos/#{repository}/commits?sha=#{branch}&per_page=100").map { |commit| commit.fetch("sha") }
    head_commit = list_of_branch_commits.first
    list_of_rules = []
    index_of_first_current_commit = list_of_formula_files.map do |file|
      list_of_formula_commits = read_remote_json("repos/#{repository}/commits?sha=#{branch}&path=#{file}&per_page=15").map { |commit| commit.fetch("sha") }
      head_text = read_remote_file(repository, file, head_commit)
      head_is_current = formula_is_rebuilt_and_bottled?(head_text, current_release)
      list_of_formula_commits.each do |commit|
        text = commit == head_commit ? head_text : read_remote_file(repository, file, commit)
        next if formula_is_rebuilt_and_bottled?(text, current_release)

        list_of_rules.concat(list_of_sha256_rules(text.scan(BOTTLE_SHA256_PATTERN).to_h,
          head_is_current ? head_text.scan(BOTTLE_SHA256_PATTERN).to_h : nil, "#{repository} #{File.basename(file, ".rb")}"))
      end
      oldest_current_commit = list_of_formula_commits.take_while do |commit|
        formula_is_rebuilt_and_bottled?(read_remote_file(repository, file, commit), current_release)
      end.last
      oldest_current_commit ? list_of_branch_commits.index(oldest_current_commit) : nil
    end
    all_formulae_current = index_of_first_current_commit.none?(&:nil?)
    stale_from_index = all_formulae_current ? index_of_first_current_commit.compact.min + 1 : 0
    list_of_branch_commits.drop(stale_from_index).each do |commit|
      list_of_rules.concat(list_of_commit_rules(commit, all_formulae_current ? head_commit : nil, "#{repository} before its rebuild"))
    end
    list_of_rules.uniq { |rule| rule.pattern.source }
  end

  def sync_branch_name(current_release)
    "agent-crystal-#{current_release.version}-sync"
  end

  # Every problem that keeps a downstream behind the current release, as text lines.
  def list_of_problems_for(downstream, current_release, list_of_rules, read_file)
    list_of_problems = []
    downstream.fetch("list_of_pin_files").each do |file|
      list_of_stale_pins = list_of_stale_pins_in(file, read_file.call(file), list_of_rules)
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

  # The rules that apply inside one downstream: the release rules, plus the stale pins of
  # every other downstream tap.
  def list_of_rules_for(downstream, list_of_release_rules, downstream_rules_by_repository)
    downstream_rules_by_repository.reject { |repository, _| repository == downstream.fetch("repository") }
                                  .values.flatten + list_of_release_rules
  end

  def report_downstreams(list_of_downstreams, current_release, list_of_release_rules, downstream_rules_by_repository)
    behind_count = 0
    list_of_downstreams.each do |downstream|
      repository = downstream.fetch("repository")
      read_file = ->(file) { read_remote_file(repository, file, downstream.fetch("branch")) }
      list_of_rules = list_of_rules_for(downstream, list_of_release_rules, downstream_rules_by_repository)
      list_of_problems = list_of_problems_for(downstream, current_release, list_of_rules, read_file)
      label = "#{repository}@#{downstream.fetch("branch")} (#{downstream.fetch("sync")})"
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

  def remote_branch_exists?(repository, branch)
    !run_command("git", "ls-remote", "--heads", "https://github.com/#{repository}.git", branch).strip.empty?
  end

  def open_sync_pull_request(downstream, current_release, list_of_rules, work_directory)
    repository = downstream.fetch("repository")
    branch = sync_branch_name(current_release)
    list_of_pull_requests = JSON.parse(run_command("gh", "pr", "list", "-R", repository, "--head", branch, "--state", "all",
      "--json", "url,state"))
    pull_request_in_use = list_of_pull_requests.find { |pull_request| %w[OPEN MERGED].include?(pull_request.fetch("state")) }
    return puts("PR      #{repository}: #{pull_request_in_use.fetch("url")} (#{pull_request_in_use.fetch("state").downcase})") if pull_request_in_use

    title = "Build on agent-crystal #{current_release.version}"
    if remote_branch_exists?(repository, branch)
      if list_of_pull_requests.any?
        raise SyncRefused, "#{repository}: #{branch} has only a closed pull request; reopen it or delete the branch, then rerun."
      end

      url = run_command("gh", "pr", "create", "-R", repository, "--base", downstream.fetch("branch"), "--head", branch,
        "--title", title, "--body", "Moves this repository to crimson-knight/crystal v#{current_release.version} (branch pushed by an earlier sync run).").strip
      return puts("PR      #{repository}: #{url} (from the branch an earlier run pushed)")
    end

    clone_directory = File.join(work_directory, repository.tr("/", "_"))
    FileUtils.rm_rf(clone_directory)
    run_command("git", "clone", "--quiet", "--depth", "1", "--branch", downstream.fetch("branch"),
      "https://github.com/#{repository}.git", clone_directory, chdir: work_directory)
    run_command("git", "switch", "--quiet", "-c", branch, chdir: clone_directory)
    list_of_changes = []
    downstream.fetch("list_of_pin_files").each do |file|
      path = File.join(clone_directory, file)
      text = File.read(path)
      list_of_stale_pins = list_of_stale_pins_in(file, text, list_of_rules)
      next if list_of_stale_pins.empty?

      File.write(path, rewrite_pins(text, list_of_rules))
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

    after_merge_note = downstream["bottles_workflow"] ? " After this merges, `ruby scripts/sync_downstreams.rb bottles` starts #{downstream["bottles_workflow"]} on #{downstream.fetch("branch")}, which publishes the rebuilt bottles." : ""
    body = <<~BODY
      Moves this repository to crimson-knight/crystal v#{current_release.version}: compiler commit #{current_release.source_commit}, source archive sha256 #{current_release.archive_sha256}, bottles at crimson-knight/homebrew-agent-crystal #{current_release.bottles_commit}.

      #{list_of_changes.map { |change| "- #{change}" }.join("\n")}

      Opened by `ruby scripts/sync_downstreams.rb sync` in crimson-knight/homebrew-agent-crystal (downstreams.json).#{after_merge_note}
    BODY
    run_command("git", "commit", "--quiet", "-am", title, chdir: clone_directory)
    run_command("git", "push", "--quiet", "-u", "origin", branch, chdir: clone_directory)
    url = run_command("gh", "pr", "create", "-R", repository, "--base", downstream.fetch("branch"), "--head", branch,
      "--title", title, "--body", body, chdir: clone_directory).strip
    puts "PR      #{repository}: #{url}"
    list_of_changes.each { |change| puts "          #{change}" }
  end

  def bottles_run_in_flight?(repository, workflow, branch)
    list_of_runs = JSON.parse(run_command("gh", "run", "list", "-R", repository, "--workflow", workflow, "--branch", branch,
      "--event", "workflow_dispatch", "--limit", "5", "--json", "status"))
    list_of_runs.any? { |run| %w[queued in_progress waiting pending requested].include?(run.fetch("status")) }
  end

  def start_bottles(list_of_downstreams, current_release)
    list_of_downstreams.each do |downstream|
      workflow = downstream["bottles_workflow"]
      next unless workflow

      repository = downstream.fetch("repository")
      branch = downstream.fetch("branch")
      list_of_formula_texts = downstream.fetch("list_of_formulae_to_rebuild").map { |file| read_remote_file(repository, file, branch) }
      if list_of_formula_texts.any? { |text| !formula_names_compiler?(text, current_release) }
        puts "WAIT    #{repository}: its sync pull request has not merged"
      elsif list_of_formula_texts.all? { |text| formula_has_bottles?(text) }
        puts "OK      #{repository}: bottles published"
      elsif bottles_run_in_flight?(repository, workflow, branch)
        puts "RUNNING #{repository}: #{workflow} is already running on #{branch}"
      else
        run_command("gh", "workflow", "run", workflow, "-R", repository, "--ref", branch)
        puts "STARTED #{repository}: #{workflow} on #{branch}"
      end
    end
  end

  def read_work_directory(list_of_arguments)
    work_directory_index = list_of_arguments.index("--work-dir")
    work_directory = work_directory_index && list_of_arguments[work_directory_index + 1]
    raise SyncRefused, "sync needs --work-dir DIR (a scratch directory for the clones)" unless work_directory

    File.expand_path(work_directory)
  end

  def sync_downstreams(list_of_downstreams, current_release, list_of_release_rules, downstream_rules_by_repository, work_directory)
    FileUtils.mkdir_p(work_directory)
    list_of_refusals = []
    list_of_downstreams.each do |downstream|
      if downstream.fetch("sync") == "automatic"
        list_of_rules = list_of_rules_for(downstream, list_of_release_rules, downstream_rules_by_repository)
        open_sync_pull_request(downstream, current_release, list_of_rules, work_directory)
      else
        puts "BY HAND #{downstream.fetch("repository")}: #{downstream.fetch("how_to_sync")}"
      end
    rescue SyncRefused => error
      list_of_refusals << error.message
      warn "REFUSED #{downstream.fetch("repository")}: #{error.message}"
    end
    list_of_refusals
  end

  def main(list_of_arguments)
    mode = list_of_arguments.first
    unless LIST_OF_MODES.include?(mode)
      warn "usage: ruby scripts/sync_downstreams.rb plan | sync --work-dir DIR | bottles | check"
      exit 2
    end
    work_directory = read_work_directory(list_of_arguments) if mode == "sync"

    require_a_current_full_clone
    list_of_releases = read_list_of_releases(read_compiler_commit_by_version)
    current_release = list_of_releases.first
    list_of_release_rules = list_of_release_rules(current_release, list_of_releases.drop(1))
    list_of_downstreams = read_manifest
    downstream_rules_by_repository = list_of_downstreams.each_with_object({}) do |downstream, rules_by_repository|
      rules_by_repository[downstream.fetch("repository")] = list_of_downstream_tap_rules(downstream, current_release)
    end
    puts "Release #{current_release.version}: compiler #{current_release.source_commit}, " \
         "archive #{current_release.archive_sha256}, bottles #{current_release.bottles_commit}"
    case mode
    when "plan"
      report_downstreams(list_of_downstreams, current_release, list_of_release_rules, downstream_rules_by_repository)
    when "check"
      behind_count = report_downstreams(list_of_downstreams, current_release, list_of_release_rules, downstream_rules_by_repository)
      if behind_count.positive?
        warn "#{behind_count} downstream(s) still build on an earlier release; the release is not done."
        exit 1
      end
      puts "Every downstream builds on #{current_release.version}."
    when "sync"
      list_of_refusals = sync_downstreams(list_of_downstreams, current_release, list_of_release_rules,
        downstream_rules_by_repository, work_directory)
      exit 1 unless list_of_refusals.empty?
    when "bottles"
      start_bottles(list_of_downstreams, current_release)
    end
  rescue SyncRefused, KeyError, JSON::ParserError => error
    warn "sync_downstreams refused: #{error.message}"
    exit 1
  end
end

DownstreamSync.main(ARGV) if $PROGRAM_NAME == __FILE__
