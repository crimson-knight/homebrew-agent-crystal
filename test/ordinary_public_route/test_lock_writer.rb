# frozen_string_literal: true
require "minitest/autorun"
require "tmpdir"
require "fileutils"
require "digest"
require "json"
ROOT = File.expand_path(__dir__)
MAIN = TOPLEVEL_BINDING.eval("self")
HANDLER = {calls: [], scenario: nil, identity: nil}
Kernel.define_singleton_method(:system) { |*_| raise "Actual Kernel child refused in writer source fixtures" }
Kernel.module_eval do
  define_method(:system) { |*_| raise "Actual child refused in writer source fixtures" }
  define_method(:`) { |*_| raise "Actual shell expansion refused in writer source fixtures" }
end
Process.define_singleton_method(:fork) { |*_| raise "Actual fork refused in writer source fixtures" }
Process.define_singleton_method(:spawn) { |*_| raise "Actual child process refused in writer source fixtures" }
Process.define_singleton_method(:exec) { |*_| raise "Actual process replacement refused in writer source fixtures" }
IO.define_singleton_method(:popen) { |*_| raise "Actual pipe child refused in writer source fixtures" }
MAIN.define_singleton_method(:exec) { |*_| raise "Actual executable invocation refused in writer source fixtures" }
MAIN.define_singleton_method(:system) do |*arguments|
  HANDLER[:calls] << arguments
  File.write("shard.lock", "version: 2.0\nshards: {}\n")
  File.write("shard.yml", "changed\n") if HANDLER[:scenario] == :changed_manifest
  File.write(ENV.fetch("MEMORY_BUDGET_MINECART"), "changed provider\n") if HANDLER[:scenario] == :changed_provider
  HANDLER[:scenario] != :failure
end

class LockWriterControls < Minitest::Test
  def setup
    @directory = Dir.mktmpdir("source writer with spaces ")
    @previous = Dir.pwd
    Dir.chdir(@directory)
    File.write("shard.yml", "name: synthetic\nversion: 0.1.0\n")
    File.write("minecart", "SYNTHETIC unexecuted provider\n")
    @minecart = File.realpath(File.join(@directory, "minecart"))
    ENV["MEMORY_BUDGET_MINECART"] = @minecart
    HANDLER[:calls] = []
    HANDLER[:scenario] = nil
    @identity = Object.new
    @identity.define_singleton_method(:profile) { {"schema_version" => 3, "minecart_sha256" => Digest::SHA256.file(ENV.fetch("MEMORY_BUDGET_MINECART")).hexdigest} }
    @identity.define_singleton_method(:compiler_path) { "/SYNTHETIC/admitted/backend" }
    @identity.define_singleton_method(:environment) { {"SYNTHETIC" => "native and Git overlay"} }
    HANDLER[:identity] = @identity
    File.write("profile_helper.rb", <<~SOURCE)
      module MemoryBudget
        module ToolchainProfile
          def self.resolve(root)
            HANDLER.fetch(:identity)
          end
        end
      end
    SOURCE
    @arguments = ARGV.dup
    ARGV.replace([File.join(@directory, "profile_helper.rb"), @directory])
  end

  def teardown
    ARGV.replace(@arguments)
    Dir.chdir(@previous)
    FileUtils.remove_entry(@directory)
    ENV.delete("MEMORY_BUDGET_MINECART")
  end

  def execute
    load File.join(ROOT, "write_consumer_lock.rb")
  end

  def test_strict_writer_uses_admitted_backend_and_keeps_scripts_enabled
    execute
    assert_equal 1, HANDLER[:calls].length
    environment, executable, *arguments = HANDLER[:calls].first
    assert_equal @minecart, executable
    assert_equal ["install", "--strict-pinning", "--skip-ai-docs", "--jobs=1"], arguments
    assert_equal "/SYNTHETIC/admitted/backend", environment.fetch("CRYSTAL")
    assert_nil environment.fetch("CRYSTAL_VERSION")
    assert_equal "1", environment.fetch("CRYSTAL_WORKERS")
    assert File.file?("shard.lock")
  end

  def test_writer_failure_remains_nonzero
    HANDLER[:scenario] = :failure
    _, errors = capture_io { assert_raises(SystemExit) { execute } }
    assert_match "Strict writer failed", errors
  end

  def test_changed_manifest_refuses_after_writer_return
    HANDLER[:scenario] = :changed_manifest
    _, errors = capture_io { assert_raises(SystemExit) { execute } }
    assert_match "changed the package manifest", errors
  end

  def test_existing_lock_refuses_before_writer
    File.write("shard.lock", "SYNTHETIC existing lock\n")
    capture_io { assert_raises(SystemExit) { execute } }
    assert_empty HANDLER[:calls]
  end

  def test_schema_one_refuses_before_writer
    @identity.define_singleton_method(:profile) { {"schema_version" => 1} }
    capture_io { assert_raises(SystemExit) { execute } }
    assert_empty HANDLER[:calls]
  end

  def test_changed_provider_refuses_after_writer
    HANDLER[:scenario] = :changed_provider
    _, errors = capture_io { assert_raises(SystemExit) { execute } }
    assert_match "Writer Minecart changed", errors
  end

  def test_actual_lock_validator_checks_expected_public_dependency
    FileUtils.cp(File.join(ROOT, "consumer/EXPECTED_LOCK.yml"), "shard.lock")
    ARGV.replace([File.join(ROOT, "consumer/EXPECTED_LOCK.yml")])
    output, errors = capture_io { load File.join(ROOT, "validate_consumer_lock.rb") }
    assert_empty errors
    result = JSON.parse(output)
    assert_equal true, result.fetch("actual_writer_lock")
    assert_equal Digest::SHA256.file("shard.lock").hexdigest, result.fetch("lock_sha256")
    File.write("shard.lock", "version: 2.0\nshards: {}\n")
    capture_io { assert_raises(SystemExit) { load File.join(ROOT, "validate_consumer_lock.rb") } }
  end
end
