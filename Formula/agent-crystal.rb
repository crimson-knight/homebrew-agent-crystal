class AgentCrystal < Formula
  desc "AgentC-enhanced Crystal compiler with incremental compilation and WASM support"
  homepage "https://github.com/crimson-knight/crystal/tree/incremental-compilation"
  url "https://github.com/crimson-knight/crystal/archive/refs/tags/v1.22.3-incremental-6.tar.gz"
  version "1.22.3-incremental-6"
  sha256 "c8d091a1f3cd94d6d941b74caa5b7e60fd15e291eb55f0364a428ba2ac66d5f5"
  license "Apache-2.0"

  # Install `stable`: it is the tagged release tarball verified by the sha256 above.
  # `head` follows the moving tip of the incremental-compilation branch with no hash,
  # so it is reserved for compiler development on that branch.
  head "https://github.com/crimson-knight/crystal.git", branch: "incremental-compilation"

  livecheck do
    url "https://github.com/crimson-knight/crystal/releases"
    regex(/^v?(\d+(?:\.\d+)+(?:-[A-Za-z0-9.-]+)?)$/i)
  end

  depends_on "cmake" => :build
  # The test builds programs with -Duse_pcre2 -Duse_libyaml, -Duse_gmp and
  # -Duse_openssl to prove each C library is one flag away. Programs need these
  # only when they pass those flags (or, for OpenSSL, require "openssl").
  depends_on "gmp" => :test
  depends_on "libyaml" => :test
  depends_on "openssl@3" => :test
  depends_on "pcre2" => :test
  depends_on "llvm@21"
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

  # The Boehm collector the compiler and every program it builds link statically.
  # Its heap blocks are sized for the target's memory pages, so free blocks fill
  # whole pages and go back to the operating system (see `gc_heap_block_size`).
  resource "bdw-gc" do
    url "https://github.com/bdwgc/bdwgc/releases/download/v8.2.12/gc-8.2.12.tar.gz"
    sha256 "42e5194ad06ab6ffb806c83eb99c03462b495d979cda782f3c72c08af833cd4e"
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
    if OS.mac? && (sdk_path = MacOS.sdk_path)
      ENV.append_path "CRYSTAL_LIBRARY_PATH", sdk_path/"usr/lib"
    end
    non_keg_only_runtime_deps.each do |dep|
      ENV.prepend_path "CRYSTAL_LIBRARY_PATH", dep.opt_lib
    end

    crystal_install_dir = libexec
    stdlib_install_dir = pkgshare

    # Build bdw-gc with Homebrew's `bdw-gc` formula options as static libraries, and
    # run the collector's own tests against each block size: one in libexec/gc for
    # the programs the compiler builds, and, where the compiler is better served by
    # another block size, one linked into the compiler alone.
    build_collector(gc_heap_block_size, libexec/"gc")
    compiler_gc_lib = gc_lib
    if compiler_gc_heap_block_size != gc_heap_block_size
      build_collector(compiler_gc_heap_block_size, buildpath/"gc-compiler")
      compiler_gc_lib = buildpath/"gc-compiler/lib"
    end

    # The compiler's collector comes first at build time; the programs' collector
    # comes first in the installed compiler's default library path. The linker takes
    # the first folder that holds a libgc.
    ENV.prepend_path "CRYSTAL_LIBRARY_PATH", compiler_gc_lib

    config_library_path = [
      "\\$$ORIGIN/#{gc_lib.relative_path_from(crystal_install_dir)}",
      "\\$$ORIGIN/#{HOMEBREW_PREFIX.relative_path_from(crystal_install_dir)}/lib",
    ].join(":")
    config_path = "\\$$ORIGIN/#{stdlib_install_dir.relative_path_from(crystal_install_dir)}/src"

    release_flags = ["release=true", "FLAGS=--no-debug"]
    crystal_build_opts = release_flags + [
      "CRYSTAL_CONFIG_LIBRARY_PATH=#{config_library_path}",
      "CRYSTAL_CONFIG_PATH=#{config_path}",
      "interpreter=true",
    ]
    crystal_build_opts << "CRYSTAL_CONFIG_BUILD_COMMIT=#{Utils.git_short_head}" if build.head?

    # `crystal --version` prints the date in SOURCE_DATE_EPOCH. Homebrew sets it from
    # the time of the build, so pass the release tarball's own date: the version string
    # is then the same on every day the compiler is built.
    source_date_epoch = (buildpath/"src/SOURCE_DATE_EPOCH").read.strip
    odie "src/SOURCE_DATE_EPOCH is not Unix seconds: #{source_date_epoch}" unless source_date_epoch.match?(/\A\d+\z/)
    ENV["SOURCE_DATE_EPOCH"] = source_date_epoch

    (buildpath/".build").mkpath
    system "make", "deps"
    system "make", "llvm_ext"
    system "make", "crystal", *crystal_build_opts

    crystal_install_dir.install ".build/crystal" => "agent-crystal-bin"
    stdlib_install_dir.install "src"
    # Match the upstream install target: this object belongs to the compiler build.
    rm stdlib_install_dir/"src/llvm/ext/llvm_ext.o"
    (lib/"crystal").mkpath

    if OS.linux?
      list_of_library_paths = runtime_library_paths
      (pkgshare/"runtime_library_paths.txt").write(list_of_library_paths.join("\n") + "\n")
    end

    install_wrapper("acrystal")
    install_wrapper("agent-crystal")
    install_wrapper("crystal-alpha")
    libexec.install "scripts/seed_macro_run.cr"

    install_completion("bash", "etc/completion.bash", "acrystal")
    install_completion("bash", "etc/completion.bash", "agent-crystal")
    install_completion("bash", "etc/completion.bash", "crystal-alpha")
    install_completion("zsh", "etc/completion.zsh", "acrystal")
    install_completion("zsh", "etc/completion.zsh", "agent-crystal")
    install_completion("zsh", "etc/completion.zsh", "crystal-alpha")
    install_completion("fish", "etc/completion.fish", "acrystal")
    install_completion("fish", "etc/completion.fish", "agent-crystal")
    install_completion("fish", "etc/completion.fish", "crystal-alpha")
  end

  # Compiles the standard library's ECR helper once for this keg, into
  # pkgshare/macro_run_seed: clean builds of apps that render ECR templates run it
  # instead of compiling it. It runs after install because the compiler only uses a
  # seed built by its final executable, which Homebrew relinks at the end of install.
  # The compiler cache for that one run lives in Homebrew's temporary folder and is
  # removed afterward.
  post_install_steps do
    remove "agent-crystal-seed-cache", base: :temp, recursive: true
    run "crystal-alpha", base:           :bin,
                         args:           ["run", "{{libexec}}/seed_macro_run.cr", "--",
                                          "{{bin}}/crystal-alpha", "{{pkgshare}}/src"],
                         env:            { "CRYSTAL_CACHE_DIR" => "{{temp}}/agent-crystal-seed-cache" },
                         writable_paths: ["{{pkgshare}}", "{{temp}}/agent-crystal-seed-cache"]
    remove "agent-crystal-seed-cache", base: :temp, recursive: true
  end

  def caveats
    <<~EOS
      Install the hash-verified stable release:
        brew install crimson-knight/agent-crystal/agent-crystal

      A keg built with --HEAD reports a version such as HEAD-<commit>. Replace it with
      the verified release:
        brew uninstall agent-crystal && brew install crimson-knight/agent-crystal/agent-crystal

      Programs start lean: Regex, YAML, text encodings and compression run on Mica,
      and BigInt, BigFloat, BigRational and BigDecimal on Crystal::BigNum (64-bit
      targets; 32-bit targets such as wasm32 use GMP), all written in Crystal, and
      link no C library. Each C library is one flag away; install it before
      building with that flag:
        -Duse_pcre2          brew install pcre2
        -Duse_libyaml        brew install libyaml
        -Devloop=libevent    brew install libevent
        -Duse_gmp            brew install gmp   (kept for this release only)
        -Duse_openssl        brew install openssl@3   (kept for this release only)
      TLS (HTTP::Client, HTTP::Server#bind_tls, WebSockets), Digest, OAuth and
      OAuth2 run on Beryl, written in Crystal, and link no OpenSSL. A program
      that requires "openssl" itself needs: brew install openssl@3
      When one is missing, the compiler's link error names the flag and the command.
    EOS
  end

  def gc_lib
    libexec/"gc/lib"
  end

  # Builds bdw-gc with `block_size`-byte heap blocks into `prefix`, after its own tests pass.
  def build_collector(block_size, prefix)
    resource("bdw-gc").stage do
      gc_args = %w[
        -Denable_cplusplus=ON
        -Denable_large_config=ON
        -Dwithout_libatomic_ops=OFF
        -Dwith_libatomic_ops=OFF
        -DBUILD_SHARED_LIBS=OFF
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
        -Dbuild_tests=ON
      ]
      if block_size != 4_096
        gc_args << "-DCMAKE_C_FLAGS=-DHBLKSIZE=#{block_size}"
        gc_args << "-DCMAKE_CXX_FLAGS=-DHBLKSIZE=#{block_size}"
      end

      system "cmake", "-S", ".", "-B", "build",
             *gc_args, *std_cmake_args(install_prefix: prefix),
             "-DBUILD_TESTING=ON" # Pass this *after* `std_cmake_args`
      system "cmake", "--build", "build"
      system "ctest", "--test-dir", "build",
             "--parallel", ENV.make_jobs,
             "--output-on-failure",
             "--repeat", "until-pass:3"
      system "cmake", "--install", "build"
    end
  end

  # Heap block size of the collector in the programs the compiler builds, in bytes.
  # A free block goes back to the operating system only when it covers whole memory
  # pages, and the collector's incremental mode requires the page size to be a
  # multiple of the block size. arm64 macOS has 16 KB pages and gets 8 KB blocks: a
  # pair of free neighbors fills a page, and a small server keeps the 4 KB peak (an
  # Amber app under load peaked at 21.5 MiB with 8 KB blocks, 21.9 MiB with 4 KB
  # and 25.2 MiB with 16 KB). arm64 Linux kernels have 4 KB, 16 KB or 64 KB pages,
  # so it gets the page size of the machine running the build, up to 16 KB. Every
  # other target keeps the collector's 4 KB default, which matches x86_64 pages.
  def gc_heap_block_size
    return 4_096 if Hardware::CPU.arch != :arm64
    return 8_192 if OS.mac?

    Etc.sysconf(Etc::SC_PAGESIZE).clamp(4_096, 16_384)
  end

  # Heap block size of the collector linked into the compiler itself, in bytes. The
  # compiler frees gigabytes between stages, so on arm64 macOS it keeps 16 KB
  # blocks, which return every free block: to the end of IR generation of a
  # 300-model Grant app, 81 to 84 s of collection against 93 s with 8 KB blocks and
  # 120 s with 4 KB. Every other target uses the programs' block size.
  def compiler_gc_heap_block_size
    return 16_384 if Hardware::CPU.arch == :arm64 && OS.mac?

    gc_heap_block_size
  end

  def runtime_library_paths
    list_of_library_paths = runtime_dependencies(read_from_tab: false, undeclared: false)
                            .map { |dependency| dependency.to_formula.opt_lib }
                            .select(&:directory?)
                            .map(&:to_s)
    (list_of_library_paths + [(HOMEBREW_PREFIX/"lib").to_s]).uniq.sort
  end

  def install_wrapper(command_name)
    wrapper_env = {}
    wrapper_env["CRYSTAL_PATH"] = "lib:#{pkgshare}/src"
    if OS.linux?
      list_of_library_paths = (pkgshare/"runtime_library_paths.txt").read.lines(chomp: true)
      wrapper_env["LD_RUN_PATH"] = "${LD_RUN_PATH:+${LD_RUN_PATH}:}#{list_of_library_paths.join(":")}"
    end

    (bin/command_name).write_env_script(libexec/"agent-crystal-bin", wrapper_env)
  end

  def install_completion(shell, source, command_name)
    content = (buildpath/source).read

    case shell
    when "bash"
      completion_dir = bash_completion
      file_name = command_name
      content = content.gsub(/^(complete(?: -o default)? -F _crystal) crystal$/,
                             "\\1 #{command_name}")
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
    assert_match "Crystal", shell_output("#{bin}/crystal-alpha --version")
    assert_equal "42\n", shell_output("#{bin}/acrystal eval 'puts 40 + 2'")
    assert_equal "42\n", shell_output("#{bin}/crystal-alpha eval 'puts 40 + 2'")
    assert_path_exists pkgshare/"macro_run_seed/ecr-process.cr/macro_run"

    # A program built by the installed compiler carries this formula's collector:
    # it loads no shared libgc, and the collector reports the block size chosen
    # for this target. The largest small-object size class is half a block.
    (testpath/"gc_block_size.cr").write <<~CRYSTAL
      list_of_block_sizes = {65_536, 32_768, 16_384, 8_192, 4_096}
      block_size = list_of_block_sizes.find do |candidate|
        LibGC.size(GC.malloc((candidate // 2 - 24).to_u64)) == candidate // 2
      end
      puts "heap block size: \#{block_size}"
    CRYSTAL
    system bin/"crystal-alpha", "build", "gc_block_size.cr", "-o", "gc_block_size"
    list_of_shared_libraries = shell_output(OS.mac? ? "otool -L gc_block_size" : "ldd gc_block_size")
    refute_match(/libgc\b/, list_of_shared_libraries)
    assert_equal "heap block size: #{gc_heap_block_size}\n", shell_output("./gc_block_size")

    # The compiler's own collector starts its heap with 64 blocks.
    compiler_first_heap_kib = compiler_gc_heap_block_size * 64 / 1024
    assert_match "Grow heap to #{compiler_first_heap_kib} KiB",
                 shell_output("GC_PRINT_STATS=1 #{bin}/crystal-alpha --version 2>&1")

    # Regex and YAML run on the Mica engines by default, so a program links
    # neither PCRE2 nor libyaml. Each C library is one flag away.
    (testpath/"engines.cr").write <<~CRYSTAL
      require "yaml"
      list_of_numbers = "a1b22".scan(/[0-9]+/).map(&.[0])
      puts "\#{Regex::Engine} \#{list_of_numbers.join(",")} \#{YAML.parse("port: 3000")["port"]}"
    CRYSTAL
    library_listing = OS.mac? ? "otool -L" : "ldd"
    system bin/"crystal-alpha", "build", "engines.cr", "-o", "engines_default"
    assert_equal "Regex::MicaEngine 1,22 3000\n", shell_output("./engines_default")
    refute_match(/libpcre|libyaml/, shell_output("#{library_listing} engines_default"))
    system bin/"crystal-alpha", "build", "-Duse_pcre2", "-Duse_libyaml", "engines.cr", "-o", "engines_c"
    assert_equal "Regex::PCRE2 1,22 3000\n", shell_output("./engines_c")
    list_of_c_libraries = shell_output("#{library_listing} engines_c")
    assert_match(/libpcre2-8/, list_of_c_libraries)
    assert_match(/libyaml/, list_of_c_libraries)

    # The big numbers run on Crystal::BigNum by default and link no GMP;
    # -Duse_gmp links libgmp and gives the same results.
    (testpath/"big_numbers.cr").write <<~CRYSTAL
      require "big"
      puts "\#{BigInt.new(2)**100} \#{BigRational.new(1, 3) + BigRational.new(1, 6)} \#{BigDecimal.new("1.25") * 2} \#{BigFloat.new("1.5") * 2}"
    CRYSTAL
    expected_big_numbers = "1267650600228229401496703205376 1/2 2.5 3.0\n"
    system bin/"crystal-alpha", "build", "big_numbers.cr", "-o", "big_numbers_default"
    assert_equal expected_big_numbers, shell_output("./big_numbers_default")
    refute_match(/libgmp/, shell_output("#{library_listing} big_numbers_default"))
    system bin/"crystal-alpha", "build", "-Duse_gmp", "big_numbers.cr", "-o", "big_numbers_gmp"
    assert_equal expected_big_numbers, shell_output("./big_numbers_gmp")
    assert_match(/libgmp/, shell_output("#{library_listing} big_numbers_gmp"))

    # Digest, HMAC in OAuth and OAuth2, and TLS run on Beryl, so a program that
    # requires them links no OpenSSL. -Duse_openssl puts TLS back on OpenSSL.
    (testpath/"no_openssl.cr").write <<~CRYSTAL
      require "digest"
      require "http"
      require "oauth"
      require "oauth2"
      puts "\#{Digest::SHA256.hexdigest("abc")[0, 8]} \#{Digest::MD5.hexdigest("abc")[0, 8]} \#{HTTP::Server::TLSServerContext}"
    CRYSTAL
    system bin/"crystal-alpha", "build", "no_openssl.cr", "-o", "no_openssl_default"
    assert_equal "ba7816bf 90015098 Crystal::Beryl::TLS::Context::Server\n", shell_output("./no_openssl_default")
    refute_match(/libssl|libcrypto/, shell_output("#{library_listing} no_openssl_default"))
    system bin/"crystal-alpha", "build", "-Duse_openssl", "no_openssl.cr", "-o", "no_openssl_openssl"
    assert_equal "ba7816bf 90015098 OpenSSL::SSL::Context::Server\n", shell_output("./no_openssl_openssl")
    assert_match(/libssl/, shell_output("#{library_listing} no_openssl_openssl"))
  end
end
