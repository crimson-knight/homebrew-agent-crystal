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
