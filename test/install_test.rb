#!/usr/bin/env ruby
# Exercises the complete installer with private commands and bootstrap bytes.
# Matching-fixture bootstrap cases change exactly the expected SHA in a copy.
# Actual official Homebrew bootstrap execution remains a separate install gate.
require "digest"
require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "shellwords"
require "tmpdir"

module InstallerBehaviorTest
  OFFICIAL_COMMIT = "be041513824fd2666a0e93cf5c3b0ca3bb0eb4b6".freeze
  OFFICIAL_SHA256 = "5f333bbe53bc490e51e7ccb1df8779b3dd6ee73a1a7379efda216edb08ccb148".freeze
  COMMAND_TIMEOUT_SECONDS = 10
  OUTPUT_LIMIT_BYTES = 65_536
  BOOTSTRAP = <<'BASH'.freeze
#!/bin/bash
set -euo pipefail
printf '%s' "${NONINTERACTIVE:-}" > "$FIXTURE_BOOTSTRAP_MARKER"
printf '%s\n' "$0" > "$FIXTURE_EXECUTED_BOOTSTRAP_PATH"
while IFS= read -r line; do printf '%s\n' "$line"; done < "${FIXTURE_WRAPPER_PREFIX}brew" > "$FIXTURE_BIN/brew"
/bin/chmod 755 "$FIXTURE_BIN/brew"
exit "${FIXTURE_BOOTSTRAP_EXIT:-0}"
BASH
  DISPATCHER = <<'FIXTURE'.freeze
require "digest"
require "json"
require "securerandom"
require "shellwords"
command = ARGV.shift
File.open(ENV.fetch("FIXTURE_TRACE"), "a") { |file| file.puts(JSON.generate(command: command, arguments: ARGV)) }
case command
when "brew"
  case ARGV
  when ["--prefix"]
    puts ENV.fetch("FIXTURE_BREW_PREFIX")
  when ["shellenv"]
    puts "export PATH=#{Shellwords.escape(ENV.fetch('FIXTURE_BIN'))}"
  else
    if ARGV.first == "tap"
      exit Integer(ENV.fetch("FIXTURE_TAP_EXIT", "0"))
    elsif ARGV.first == "install"
      commands = ["acrystal", "agent-crystal", "crystal-alpha"]
      commands.delete("crystal-alpha") if ENV["FIXTURE_MISSING_ALPHA"] == "1"
      commands.each do |name|
        path = File.join(ENV.fetch("FIXTURE_BIN"), name)
        File.write(path, File.read(ENV.fetch("FIXTURE_WRAPPER_PREFIX") + name))
        File.chmod(0755, path)
      end
    else
      abort "Unexpected private brew command: #{ARGV.inspect}"
    end
  end
when "acrystal", "agent-crystal", "crystal-alpha"
  if ARGV == ["--version"]
    puts "#{command} private fixture version 1"
  elsif command == "crystal-alpha" && ARGV == ["eval", "puts 40 + 2"]
    puts ENV.fetch("FIXTURE_ALPHA_RESULT", "42")
  else
    abort "Unexpected private compiler command: #{command} #{ARGV.inspect}"
  end
when "curl"
  position = ARGV.index("--output")
  abort "Missing private curl output" unless position && ARGV[position + 1]
  path = ARGV[position + 1]
  if ENV.fetch("FIXTURE_DOWNLOAD_EXIT", "0") != "0"
    File.binwrite(path, "partial fixture download\n")
    exit Integer(ENV.fetch("FIXTURE_DOWNLOAD_EXIT"))
  end
  File.binwrite(path, File.binread(ENV.fetch("FIXTURE_BOOTSTRAP")))
when "shasum"
  abort "Unexpected checksum arguments" unless ARGV.length == 3 && ARGV[0, 2] == ["-a", "256"]
  puts "#{Digest::SHA256.file(ARGV.last).hexdigest}  #{ARGV.last}"
when "mktemp"
  abort "Unexpected mktemp template" unless ARGV.length == 1 && ARGV.first.end_with?("XXXXXX")
  path = ARGV.first.sub(/X{6}\z/, SecureRandom.hex(6))
  File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0600).close
  puts path
when "rm"
  abort "Unexpected cleanup arguments" unless ARGV[0, 2] == ["-f", "--"] && ARGV.length == 3
  path = File.expand_path(ARGV.last)
  abort "Cleanup path escaped private temp root" unless path.start_with?(File.expand_path(ENV.fetch("TMPDIR")) + File::SEPARATOR)
  File.unlink(path) if File.exist?(path)
when "dirname"
  abort "Unexpected dirname arguments" unless ARGV.length == 1
  puts File.dirname(ARGV.first)
when "uname"
  # A private fallback prevents host-specific installed Homebrew from entering a case.
  puts "PrivateFixtureOS"
else
  abort "Unexpected private command: #{command}"
end
FIXTURE

  def self.require_condition(value, message)
    raise message unless value
  end

  def self.execute(environment, script, directory)
    output = {stdout: +"", stderr: +""}
    status = nil
    Open3.popen3(environment, "/bin/bash", script, chdir: directory, pgroup: true, unsetenv_others: true) do |input, stdout, stderr, thread|
      input.close
      readers = {stdout => :stdout, stderr => :stderr}
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + COMMAND_TIMEOUT_SECONDS
      begin
        until readers.empty? && !thread.alive?
          trace = File.exist?(environment.fetch("FIXTURE_TRACE")) ? File.read(environment.fetch("FIXTURE_TRACE")) : ""
          require_condition(Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline,
                            "Installer exceeded finite fixture deadline; stdout=#{output[:stdout].inspect}; stderr=#{output[:stderr].inspect}; trace=#{trace}")
          ready = IO.select(readers.keys, nil, nil, 0.05)
          next unless ready
          ready.first.each do |reader|
            data = reader.read_nonblock(4096, exception: false)
            if data.nil?
              readers.delete(reader)
            elsif data != :wait_readable
              key = readers.fetch(reader)
              output[key] << data
              require_condition(output[key].bytesize <= OUTPUT_LIMIT_BYTES, "Installer fixture output exceeded its cap")
            end
          end
        end
        status = thread.value
      ensure
        if thread.alive?
          begin
            Process.kill("KILL", -thread.pid)
          rescue Errno::ESRCH
          end
          thread.join
        end
      end
    end
    output.merge(exit_status: status.exitstatus)
  end

  def self.run_case(parent, label, installer, options = {})
    directory = File.join(parent, label + " with spaces")
    commands = File.join(directory, "private commands")
    temporary = File.join(directory, "tmp with spaces")
    prefix = File.join(directory, "Homebrew prefix")
    home = File.join(directory, "home with spaces")
    tap = File.join(directory, "tap with spaces")
    [commands, temporary, File.join(prefix, "bin"), home, File.join(tap, "Formula")].each { |path| FileUtils.mkdir_p(path) }
    dispatcher = File.join(directory, "private dispatcher.rb")
    File.write(dispatcher, DISPATCHER)
    wrapper_prefix = File.join(directory, "wrapper ")
    %w(brew acrystal agent-crystal crystal-alpha curl shasum mktemp rm dirname uname).each do |command|
      body = "#!/bin/sh\nexec #{Shellwords.escape(RbConfig.ruby)} #{Shellwords.escape(dispatcher)} #{Shellwords.escape(command)} \"$@\"\n"
      if command == "uname"
        # Apple's system Ruby queries uname -p during startup. Keep that native
        # metadata route independent of the Ruby command dispatcher.
        body = "#!/bin/sh\nif [ \"${1:-}\" = -s ]; then printf '%s\\n' PrivateFixtureOS; else exec /usr/bin/uname \"$@\"; fi\n"
      end
      File.write(wrapper_prefix + command, body)
      if command == "brew"
        prefix_brew = File.join(prefix, "bin", "brew")
        File.write(prefix_brew, body)
        File.chmod(0755, prefix_brew)
      end
      next if %w(acrystal agent-crystal crystal-alpha).include?(command)
      next if command == "brew" && options[:missing_brew]
      path = File.join(commands, command)
      File.write(path, body)
      File.chmod(0755, path)
    end
    bootstrap = File.join(directory, "private bootstrap.sh")
    File.write(bootstrap, BOOTSTRAP)
    actual_source = installer
    source_shape = "exact_installer_bytes"
    if options[:matching_bootstrap]
      expected = %(readonly HOMEBREW_INSTALL_SHA256="#{OFFICIAL_SHA256}")
      replacement = %(readonly HOMEBREW_INSTALL_SHA256="#{Digest::SHA256.hexdigest(BOOTSTRAP)}")
      require_condition(installer.scan(expected).length == 1, "Exact official checksum declaration required before fixture substitution")
      actual_source = installer.sub(expected, replacement)
      require_condition(installer.lines.zip(actual_source.lines).count { |left, right| left != right } == 1,
                        "Matching bootstrap fixture must change exactly one checksum declaration")
      source_shape = "whole_installer_with_only_fixture_bootstrap_sha_substituted"
    end
    script = File.join(directory, "installer with spaces.sh")
    File.write(script, actual_source)
    formula = File.join(tap, "Formula", "agent-crystal.rb")
    File.write(formula, "# Private formula path fixture\n")
    environment = {
      "HOME" => home, "PATH" => commands, "TMPDIR" => temporary, "LC_ALL" => "C", "TZ" => "UTC",
      "AGENT_CRYSTAL_TAP" => "fixture/alpha", "AGENT_CRYSTAL_FORMULA" => "fixture-alpha",
      "AGENT_CRYSTAL_FORMULA_PATH" => options[:custom_tap] ? formula : "",
      "FIXTURE_TRACE" => File.join(directory, "trace.jsonl"), "FIXTURE_BIN" => commands,
      "FIXTURE_BREW_PREFIX" => prefix, "FIXTURE_WRAPPER_PREFIX" => wrapper_prefix,
      "FIXTURE_BOOTSTRAP" => bootstrap, "FIXTURE_BOOTSTRAP_MARKER" => File.join(directory, "bootstrap marker"),
      "FIXTURE_EXECUTED_BOOTSTRAP_PATH" => File.join(directory, "executed bootstrap path"),
      "FIXTURE_MISSING_ALPHA" => options[:missing_alpha] ? "1" : "0",
      "FIXTURE_ALPHA_RESULT" => options.fetch(:alpha_result, "42"),
      "FIXTURE_TAP_EXIT" => options.fetch(:tap_exit, "0"),
      "FIXTURE_DOWNLOAD_EXIT" => options.fetch(:download_exit, "0"),
      "FIXTURE_BOOTSTRAP_EXIT" => options.fetch(:bootstrap_exit, "0")
    }
    result = execute(environment, script, directory)
    events = File.exist?(environment["FIXTURE_TRACE"]) ? File.readlines(environment["FIXTURE_TRACE"]).map { |line| JSON.parse(line) } : []
    marker = environment["FIXTURE_BOOTSTRAP_MARKER"]
    curl = events.select { |event| event.fetch("command") == "curl" }
    curl.each do |event|
      arguments = event.fetch("arguments")
      require_condition(arguments.include?("https://raw.githubusercontent.com/Homebrew/install/#{OFFICIAL_COMMIT}/install.sh"), "Pinned official bootstrap URL must reach download fixture")
      %w(--fail --location --silent --show-error --proto --tlsv1.2 --connect-timeout --max-time --max-filesize --output).each do |flag|
        require_condition(arguments.include?(flag), "Bounded download option missing: #{flag}")
      end
      {"--proto" => "=https", "--connect-timeout" => "15", "--max-time" => "120", "--max-filesize" => "1048576"}.each do |flag, value|
        require_condition(arguments[arguments.index(flag) + 1] == value, "Pinned download option differs: #{flag}")
      end
    end
    require_condition(Dir.children(temporary).empty?, "Bootstrap temporary file survived terminal installer result")
    details = {
      id: label, source_shape: source_shape, exit_status: result.fetch(:exit_status),
      executed_script_sha256: Digest::SHA256.hexdigest(actual_source),
      stdout_sha256: Digest::SHA256.hexdigest(result.fetch(:stdout)), stderr_sha256: Digest::SHA256.hexdigest(result.fetch(:stderr)),
      private_command_events: events, bootstrap_fixture_executed: File.exist?(marker),
      bootstrap_temp_files_remaining: Dir.children(temporary).length, paths_with_spaces: true
    }
    if options[:matching_bootstrap] && result[:exit_status] == 0
      require_condition(File.read(marker) == "1", "Matching bootstrap must execute with NONINTERACTIVE=1")
      executed = File.read(environment["FIXTURE_EXECUTED_BOOTSTRAP_PATH"]).strip
      downloaded = curl.fetch(0).fetch("arguments")
      require_condition(executed == downloaded[downloaded.index("--output") + 1], "Executed bootstrap must be the exact verified temporary file")
      require_condition(!File.exist?(executed), "Executed bootstrap file must be removed by EXIT cleanup")
    end
    begin
      yield result, events, details, tap
    rescue => error
      raise "#{label}: #{error.message}; exit=#{result[:exit_status].inspect}; stderr=#{result[:stderr].inspect}; events=#{events.inspect}"
    end
    details
  end

  def self.expect_success(result, events)
    require_condition(result[:exit_status] == 0, "Expected installer success: #{result[:stderr]}")
    require_condition(result[:stderr].empty?, "Successful fixture must complete with empty stderr: #{result[:stderr]}")
    require_condition(events.any? { |row| row["command"] == "brew" && row["arguments"] == ["shellenv"] },
                      "Successful installer must execute Homebrew's actual prefix shellenv entry")
    %w(acrystal agent-crystal crystal-alpha).each do |command|
      require_condition(events.count { |row| row["command"] == command && row["arguments"] == ["--version"] } == 1,
                        "Whole installer must verify #{command} version exactly once")
    end
    require_condition(events.count { |row| row["command"] == "crystal-alpha" && row["arguments"] == ["eval", "puts 40 + 2"] } == 1,
                      "Whole installer must exercise the Alpha eval result")
    require_condition(events.count { |row| row["command"] == "brew" && row["arguments"].first == "install" } == 1,
                      "Successful installer must perform exactly one formula install")
  end

  def self.main
    root = File.expand_path("..", __dir__)
    path = File.join(root, "install.sh")
    installer = File.binread(path)
    source_hash = Digest::SHA256.hexdigest(installer)
    require_condition(installer.include?(%(readonly HOMEBREW_INSTALL_COMMIT="#{OFFICIAL_COMMIT}")) &&
                      installer.include?(%(readonly HOMEBREW_INSTALL_SHA256="#{OFFICIAL_SHA256}")), "Official bootstrap source pins differ")
    outcomes = []
    Dir.mktmpdir("alpha installer behavioral ", root) do |temporary|
      outcomes << run_case(temporary, "existing_homebrew_success", installer) do |result, events, details, _tap|
        expect_success(result, events)
        require_condition(events.none? { |row| row["command"] == "curl" }, "Existing Homebrew must stay on its existing path")
        require_condition(!details[:bootstrap_fixture_executed], "Existing Homebrew must complete without bootstrap execution")
      end
      outcomes << run_case(temporary, "missing_alpha_refusal", installer, missing_alpha: true) do |result, events, _details, _tap|
        require_condition(result[:exit_status] != 0 && result[:stderr].include?("crystal-alpha was not installed on PATH"), "Missing Alpha must fail at command discovery")
        require_condition(events.none? { |row| %w(acrystal agent-crystal crystal-alpha).include?(row["command"]) }, "Missing Alpha refusal must precede version/eval calls")
      end
      outcomes << run_case(temporary, "wrong_alpha_eval_refusal", installer, alpha_result: "41") do |result, events, _details, _tap|
        require_condition(result[:exit_status] != 0 && result[:stderr].include?("crystal-alpha did not compile and run the verification expression"), "Wrong Alpha eval must refuse installation success")
        require_condition(events.any? { |row| row["command"] == "crystal-alpha" && row["arguments"].first == "eval" }, "Wrong-result control must reach the real installer eval entry")
      end
      outcomes << run_case(temporary, "custom_tap_failure_before_install", installer, custom_tap: true, tap_exit: "17") do |result, events, _details, tap|
        require_condition(result[:exit_status] == 17, "Custom tap failure must propagate its actual exit")
        require_condition(events.any? { |row| row["command"] == "brew" && row["arguments"] == ["tap", "--custom-remote", "fixture/alpha", tap] }, "Custom tap path with spaces must remain one argument")
        require_condition(events.none? { |row| row["command"] == "brew" && row["arguments"].first == "install" }, "Failed custom tap must stop before formula install")
      end
      outcomes << run_case(temporary, "download_failure_cleanup", installer, missing_brew: true, download_exit: "22") do |result, events, details, _tap|
        require_condition(result[:exit_status] == 22, "Download failure must propagate")
        require_condition(events.none? { |row| row["command"] == "shasum" } && !details[:bootstrap_fixture_executed], "Failed download must stop before checksum/execution")
      end
      outcomes << run_case(temporary, "wrong_bootstrap_bytes_zero_execution", installer, missing_brew: true) do |result, events, details, _tap|
        require_condition(result[:exit_status] != 0 && result[:stderr].include?("Homebrew bootstrap checksum differs"), "Wrong bootstrap bytes must fail the real expected digest check")
        require_condition(events.count { |row| row["command"] == "shasum" } == 1 && !details[:bootstrap_fixture_executed], "Checksum rejection must have zero bootstrap executions")
        require_condition(events.none? { |row| row["command"] == "brew" }, "Checksum rejection must precede Homebrew operations")
      end
      outcomes << run_case(temporary, "matching_fixture_bootstrap_success_cleanup", installer, missing_brew: true, matching_bootstrap: true, custom_tap: true) do |result, events, details, tap|
        expect_success(result, events)
        require_condition(details[:bootstrap_fixture_executed], "Matching checksum fixture must actually execute")
        require_condition(events.any? { |row| row["command"] == "brew" && row["arguments"] == ["tap", "--custom-remote", "fixture/alpha", tap] }, "Successful bootstrap must retain custom tap path with spaces")
      end
      outcomes << run_case(temporary, "matching_fixture_bootstrap_failure_cleanup", installer, missing_brew: true, matching_bootstrap: true, bootstrap_exit: "19") do |result, events, details, _tap|
        require_condition(result[:exit_status] == 19 && details[:bootstrap_fixture_executed], "Matching fixture failure must execute and propagate")
        require_condition(events.none? { |row| row["command"] == "brew" }, "Bootstrap failure must stop before Homebrew operations")
      end
      outcomes << run_case(temporary, "restored_existing_homebrew_success", installer) do |result, events, _details, _tap|
        expect_success(result, events)
        require_condition(events == outcomes.first.fetch(:private_command_events), "Restored exact-source success must reproduce original command sequence")
      end
    end
    require_condition(Digest::SHA256.file(path).hexdigest == source_hash, "Original installer source changed during behavioral tests")
    require_condition(outcomes.length == 9, "Complete installer behavioral roster required")
    outcomes.each { |row| row[:passed] = true }
    report = {
      passed: true, scope: "Whole-script private-command behavioral fixtures; official Homebrew bootstrap execution and public/clean-device installation remain separate gates",
      cases: outcomes.length, outcomes: outcomes, installer_source_sha256: source_hash,
      test_source_sha256: Digest::SHA256.file(__FILE__).hexdigest, private_dispatcher_sha256: Digest::SHA256.hexdigest(DISPATCHER),
      fixture_bootstrap_sha256: Digest::SHA256.hexdigest(BOOTSTRAP), official_bootstrap_commit: OFFICIAL_COMMIT, official_bootstrap_sha256: OFFICIAL_SHA256,
      original_installer_unchanged: true, actual_official_bootstrap_executions: 0, actual_compiler_or_formula_installs: 0,
      command_timeout_seconds: COMMAND_TIMEOUT_SECONDS, output_cap_bytes_per_stream: OUTPUT_LIMIT_BYTES,
      runtime: {ruby_version: RUBY_DESCRIPTION, ruby_path: RbConfig.ruby, ruby_sha256: Digest::SHA256.file(RbConfig.ruby).hexdigest,
                bash_path: "/bin/bash", bash_sha256: Digest::SHA256.file("/bin/bash").hexdigest,
                uname_path: "/usr/bin/uname", uname_sha256: Digest::SHA256.file("/usr/bin/uname").hexdigest,
                chmod_path: "/bin/chmod", chmod_sha256: Digest::SHA256.file("/bin/chmod").hexdigest}
    }
    puts JSON.pretty_generate(report)
  end
end

InstallerBehaviorTest.main
