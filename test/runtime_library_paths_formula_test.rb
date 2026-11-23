require "minitest/autorun"
require "pathname"
require "tmpdir"

module Kernel
  def system(*)
    raise "Source-only process guard"
  end

  def spawn(*)
    raise "Source-only process guard"
  end

  def exec(*)
    raise "Source-only process guard"
  end
end

module OS
  class << self
    attr_accessor :linux

    def linux?
      linux
    end
  end
end

class Pathname
  def write_env_script(target, environment)
    $observed_wrappers[to_s] = {target: target.to_s, environment: environment}
    write("observed source-only wrapper\n")
  end
end

class RuntimeLibraryFormulaTest < Minitest::Test
  SOURCE = Pathname.new(__dir__).join("../Formula/agent-crystal.rb").read
  RUNTIME_METHOD = SOURCE.match(/^  def runtime_library_paths\n.*?^  end\n/m)[0]
  WRAPPER_METHOD = SOURCE.match(/^  def install_wrapper\(command_name\)\n.*?^  end\n/m)[0]

  def setup
    @directory = Dir.mktmpdir("runtime-formula-source-")
    @root = Pathname.new(@directory).realpath
    Object.const_set(:HOMEBREW_PREFIX, @root)
    $observed_wrappers = {}
    @formula = Class.new do
      attr_accessor :pkgshare, :bin, :libexec, :dependencies, :observed_dependency_options

      def runtime_dependencies(**options)
        self.observed_dependency_options = options
        dependencies
      end

      class_eval(RUNTIME_METHOD)
      class_eval(WRAPPER_METHOD)
    end.new
    @formula.pkgshare = @root / "share/agent-crystal"
    @formula.bin = @root / "bin"
    @formula.libexec = @root / "libexec"
    [@formula.pkgshare, @formula.bin, @formula.libexec, @root / "lib"].each(&:mkpath)
    OS.linux = true
  end

  def teardown
    Object.send(:remove_const, :HOMEBREW_PREFIX)
    FileUtils.remove_entry(@directory)
  end

  def dependency(path)
    formula = Struct.new(:opt_lib).new(path)
    Struct.new(:to_formula).new(formula)
  end

  def test_runtime_method_selects_existing_recursive_opt_libraries_and_prefix_once
    first, second, absent = @root / "opt/openssl@3/lib", @root / "opt/openssl@4/lib", @root / "opt/absent/lib"
    [first, second].each(&:mkpath)
    @formula.dependencies = [dependency(second), dependency(first), dependency(absent), dependency(first)]
    assert_equal [(@root / "lib").to_s, first.to_s, second.to_s].sort, @formula.runtime_library_paths
    assert_equal({read_from_tab: false, undeclared: false}, @formula.observed_dependency_options)
  end

  def test_each_linux_alias_uses_the_same_serialized_static_manifest
    paths = [(@root / "lib").to_s, (@root / "opt/openssl@3/lib").to_s, (@root / "opt/openssl@4/lib").to_s].sort
    (@formula.pkgshare / "runtime_library_paths.txt").write(paths.join("\n") + "\n")
    %w[acrystal agent-crystal crystal-alpha].each { |name| @formula.install_wrapper(name) }
    assert_equal 3, $observed_wrappers.length
    $observed_wrappers.each_value do |row|
      assert_equal((@formula.libexec / "agent-crystal-bin").to_s, row[:target])
      assert_equal("${LD_RUN_PATH:+${LD_RUN_PATH}:}" + paths.join(":"), row[:environment]["LD_RUN_PATH"])
      assert_equal "lib:#{@formula.pkgshare}/src", row[:environment]["CRYSTAL_PATH"]
    end
  end

  def test_darwin_alias_uses_the_original_environment_template
    OS.linux = false
    @formula.install_wrapper("crystal-alpha")
    assert_equal({"CRYSTAL_PATH" => "lib:#{@formula.pkgshare}/src"}, $observed_wrappers.values.first[:environment])
  end

  def test_missing_linux_manifest_refuses_wrapper_creation
    assert_raises(Errno::ENOENT) { @formula.install_wrapper("crystal-alpha") }
    assert_empty $observed_wrappers
  end
end

class ReleaseDateFormulaTest < Minitest::Test
  SOURCE = Pathname.new(__dir__).join("../Formula/agent-crystal.rb").read
  INSTALL_METHOD = SOURCE.match(/^  def install\n.*?^  end\n/m)[0]
  RELEASE_DATE_STEP = INSTALL_METHOD.match(
    /^    source_date_epoch = \(buildpath\/"src\/SOURCE_DATE_EPOCH"\)\.read\.strip\n.*?^    ENV\["SOURCE_DATE_EPOCH"\] = source_date_epoch\n/m,
  )[0]

  def setup
    @directory = Dir.mktmpdir("release-date-formula-source-")
    @original_epoch = ENV["SOURCE_DATE_EPOCH"]
    ENV["SOURCE_DATE_EPOCH"] = "1795392000"
    @formula = Class.new do
      attr_accessor :buildpath

      def odie(message)
        raise ArgumentError, message
      end

      class_eval("def apply_release_date\n#{RELEASE_DATE_STEP}end\n")
    end.new
    @formula.buildpath = Pathname.new(@directory)
    (@formula.buildpath / "src").mkpath
  end

  def teardown
    ENV["SOURCE_DATE_EPOCH"] = @original_epoch
    FileUtils.remove_entry(@directory)
  end

  def test_install_replaces_the_build_time_with_the_tarball_release_date
    (@formula.buildpath / "src/SOURCE_DATE_EPOCH").write("1784160000\n")
    @formula.apply_release_date
    assert_equal "1784160000", ENV["SOURCE_DATE_EPOCH"]
  end

  def test_release_date_that_is_not_unix_seconds_stops_the_build
    (@formula.buildpath / "src/SOURCE_DATE_EPOCH").write("2026-07-16\n")
    assert_raises(ArgumentError) { @formula.apply_release_date }
    assert_equal "1795392000", ENV["SOURCE_DATE_EPOCH"]
  end

  def test_missing_release_date_file_stops_the_build
    assert_raises(Errno::ENOENT) { @formula.apply_release_date }
    assert_equal "1795392000", ENV["SOURCE_DATE_EPOCH"]
  end

  def test_release_date_is_set_once_before_every_compiler_build_step
    assert_equal 1, INSTALL_METHOD.scan(/ENV\["SOURCE_DATE_EPOCH"\]|SOURCE_DATE_EPOCH=/).length
    refute_match(/^\s+(if|unless)\b/, RELEASE_DATE_STEP.lines.first)
    position = INSTALL_METHOD.index(RELEASE_DATE_STEP)
    ['system "make", "deps"', 'system "make", "llvm_ext"', 'system "make", "crystal"'].each do |step|
      assert_operator position, :<, INSTALL_METHOD.index(step), "#{step} runs before the release date is set"
    end
  end
end
