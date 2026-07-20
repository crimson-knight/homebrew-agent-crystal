class AgentCrystal < Formula
  desc "AgentC-enhanced Crystal compiler with incremental compilation and WASM support"
  homepage "https://github.com/crimson-knight/crystal/tree/incremental-compilation"
  url "https://github.com/crimson-knight/crystal/archive/refs/tags/v1.21.0-incremental-1.tar.gz"
  version "1.21.0-incremental-1"
  sha256 "2c85084ce5ed4973d7f1f73987ba990b7b16381f60dd8ccc8a92b2bec1203b05"
  license "Apache-2.0"

  head "https://github.com/crimson-knight/crystal.git", branch: "incremental-compilation"

  livecheck do
    url "https://github.com/crimson-knight/crystal/releases"
    regex(/^v?(\d+(?:\.\d+)+(?:-[A-Za-z0-9.-]+)?)$/i)
  end

  depends_on "bdw-gc"
  depends_on "gmp"
  depends_on "libevent"
  depends_on "libyaml"
  depends_on "llvm@21"
  depends_on "openssl@3"
  depends_on "pcre2"
  depends_on "pkgconf"

  uses_from_macos "libffi"

  resource "boot" do
    boot_version = Version.new("1.20.0-1")
    version boot_version

    on_macos do
      url "https://github.com/crystal-lang/crystal/releases/download/#{boot_version.major_minor_patch}/crystal-#{boot_version}-darwin-universal.tar.gz"
      sha256 "d852706dc1c58bd9abc68756f6eceb88f5ac10b01f2bd0d9a3b93e1f26b5036c"
    end

    on_linux do
      on_intel do
        url "https://github.com/crystal-lang/crystal/releases/download/#{boot_version.major_minor_patch}/crystal-#{boot_version}-linux-x86_64.tar.gz"
        sha256 "e7138481c02a38966e642d9c17550da62a2a18685d94e7841f763055990d91ee"
      end

      on_arm do
        url "https://github.com/crystal-lang/crystal/releases/download/#{boot_version.major_minor_patch}/crystal-#{boot_version}-linux-aarch64.tar.gz"
        sha256 "4d4bb93c15ad0b2b766c2d244c1f0d2de2758e6382939e7a8d9fdf250fbf9afe"
      end
    end
  end

  def install
    llvm = deps.find { |dep| dep.name.match?(/^llvm(@\d+)?$/) }
               .to_formula
    non_keg_only_runtime_deps = deps.filter_map { |dep| dep.to_formula unless dep.build? }
                                    .reject(&:keg_only?)

    resource("boot").stage "boot"
    ENV.prepend_path "PATH", buildpath/"boot/bin"
    ENV.prepend_path "PATH", buildpath/"boot/embedded/bin" if (buildpath/"boot/embedded/bin").directory?
    ENV["LLVM_CONFIG"] = llvm.opt_bin/"llvm-config"
    ENV["CRYSTAL_LIBRARY_PATH"] = ENV["HOMEBREW_LIBRARY_PATHS"]
    ENV.append_path "CRYSTAL_LIBRARY_PATH", MacOS.sdk_path_if_needed/"usr/lib" if OS.mac? && MacOS.sdk_path_if_needed
    non_keg_only_runtime_deps.each do |dep|
      ENV.prepend_path "CRYSTAL_LIBRARY_PATH", dep.opt_lib
    end

    crystal_install_dir = libexec
    stdlib_install_dir = pkgshare

    config_library_path = "\\$$ORIGIN/#{HOMEBREW_PREFIX.relative_path_from(crystal_install_dir)}/lib"
    config_path = "\\$$ORIGIN/#{stdlib_install_dir.relative_path_from(crystal_install_dir)}/src"

    release_flags = ["release=true", "FLAGS=--no-debug"]
    crystal_build_opts = release_flags + [
      "CRYSTAL_CONFIG_LIBRARY_PATH=#{config_library_path}",
      "CRYSTAL_CONFIG_PATH=#{config_path}",
      "interpreter=true",
    ]
    crystal_build_opts << "CRYSTAL_CONFIG_BUILD_COMMIT=#{Utils.git_short_head}" if build.head?

    (buildpath/".build").mkpath
    system "make", "deps"
    system "make", "llvm_ext"
    system "make", "crystal", *crystal_build_opts

    crystal_install_dir.install ".build/crystal" => "agent-crystal-bin"
    stdlib_install_dir.install "src"
    (lib/"crystal").mkpath

    install_wrapper("acrystal")
    install_wrapper("agent-crystal")

    install_completion("bash", "etc/completion.bash", "acrystal")
    install_completion("bash", "etc/completion.bash", "agent-crystal")
    install_completion("zsh", "etc/completion.zsh", "acrystal")
    install_completion("zsh", "etc/completion.zsh", "agent-crystal")
    install_completion("fish", "etc/completion.fish", "acrystal")
    install_completion("fish", "etc/completion.fish", "agent-crystal")
  end

  def install_wrapper(command_name)
    wrapper_env = {}
    wrapper_env["CRYSTAL_PATH"] = "lib:#{pkgshare}/src"
    wrapper_env["LD_RUN_PATH"] = "${LD_RUN_PATH:+${LD_RUN_PATH}:}#{HOMEBREW_PREFIX}/lib" if OS.linux?

    (bin/command_name).write_env_script(libexec/"agent-crystal-bin", wrapper_env)
  end

  def install_completion(shell, source, command_name)
    content = (buildpath/source).read

    case shell
    when "bash"
      completion_dir = bash_completion
      file_name = command_name
      content = content.gsub("complete -o default -F _crystal crystal",
                             "complete -o default -F _crystal #{command_name}")
    when "zsh"
      completion_dir = zsh_completion
      file_name = "_#{command_name}"
      content = content.sub("#compdef crystal", "#compdef #{command_name}")
                       .sub("compdef _crystal crystal", "compdef _crystal #{command_name}")
    when "fish"
      completion_dir = fish_completion
      file_name = "#{command_name}.fish"
      content = content.gsub("complete -c crystal", "complete -c #{command_name}")
    else
      odie "Unsupported shell completion target: #{shell}"
    end

    (completion_dir/file_name).write content
  end

  test do
    assert_match "Crystal", shell_output("#{bin}/acrystal --version")
    assert_match "Crystal", shell_output("#{bin}/agent-crystal --version")
    assert_equal "42\n", shell_output("#{bin}/acrystal eval 'puts 40 + 2'")
  end
end
