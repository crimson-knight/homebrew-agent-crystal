# Tests the pin detection, rewriting and formula rebuild of scripts/sync_downstreams.rb.
#   ruby test/sync_downstreams_test.rb
require "json"
require "minitest/autorun"
require_relative "../scripts/sync_downstreams"

class SyncDownstreamsTest < Minitest::Test
  CURRENT_RELEASE = DownstreamSync::Release.new(
    version: "1.22.3-incremental-6",
    source_commit: "31372f755ad61f6fb754fe463210f268b791e17a",
    bottles_commit: "c" * 40,
    archive_sha256: "a" * 64,
    bottle_sha256_by_tag: { "arm64_tahoe" => "b" * 64 }
  )
  BOTTLED_EARLIER_RELEASE = DownstreamSync::Release.new(
    version: "1.22.3-incremental-4",
    source_commit: "b9b8ba04ec40b13e620ef1035ec4d51a24d4f287",
    bottles_commit: "e" * 40,
    archive_sha256: "d" * 64,
    bottle_sha256_by_tag: { "arm64_tahoe" => "f" * 64, "arm64_linux" => "9" * 64 }
  )
  TAGGED_EARLIER_RELEASE = DownstreamSync::Release.new(
    version: "1.21.0-incremental-1",
    source_commit: "9c1e8ec64f6be6343e90d3979bc9536c4b050292",
    bottle_sha256_by_tag: {}
  )
  FORMULA_TEXT = <<~RUBY
    class AmberCli < Formula
      url "https://example.invalid/amber_cli-2.0.18.tar.gz"
      sha256 "#{"1" * 64}"
      license "MIT"

      bottle do
        root_url "https://example.invalid/amber_cli-2.0.18"
        sha256 arm64_tahoe: "#{"2" * 64}"
      end

      depends_on "crimson-knight/agent-crystal/agent-crystal"
      depends_on "libpq"
    end
  RUBY

  def list_of_rules
    DownstreamSync.list_of_release_rules(CURRENT_RELEASE, [BOTTLED_EARLIER_RELEASE, TAGGED_EARLIER_RELEASE])
  end

  def stale_tokens(text)
    DownstreamSync.list_of_stale_pins_in("file", text, list_of_rules).map(&:old_token)
  end

  def rewrite(text)
    DownstreamSync.rewrite_pins(text, list_of_rules)
  end

  def test_releases_come_from_the_fork_tags
    ls_remote_text = <<~TEXT
      9c1e8ec64f6be6343e90d3979bc9536c4b050292\trefs/tags/v1.21.0-incremental-1
      b9dcbf3c742c632f4d0b474195809751f3a68b30\trefs/tags/v1.22.3-incremental-6
      31372f755ad61f6fb754fe463210f268b791e17a\trefs/tags/v1.22.3-incremental-6^{}
      1111111111111111111111111111111111111111\trefs/tags/v1.22.3
    TEXT
    assert_equal({ "1.21.0-incremental-1" => "9c1e8ec64f6be6343e90d3979bc9536c4b050292",
                   "1.22.3-incremental-6" => "31372f755ad61f6fb754fe463210f268b791e17a" },
      DownstreamSync.read_compiler_commit_by_version(ls_remote_text))
  end

  def test_every_hash_of_an_earlier_release_is_found_and_moved
    text = "tap: #{"e" * 40}\ncompiler: b9b8ba04ec40b13e620ef1035ec4d51a24d4f287\narchive: #{"d" * 64}\nbottle: #{"f" * 64}\n"
    assert_equal 4, stale_tokens(text).size
    assert_equal "tap: #{"c" * 40}\ncompiler: #{CURRENT_RELEASE.source_commit}\narchive: #{"a" * 64}\nbottle: #{"b" * 64}\n", rewrite(text)
    assert_empty stale_tokens(rewrite(text))
  end

  def test_short_commits_and_releases_tagged_before_bottles_are_found
    text = <<~YAML
      CRYSTAL_ALPHA_COMMIT: 9c1e8ec64f6be6343e90d3979bc9536c4b050292 # tag v1.21.0-incremental-1
      crystal --version | grep -q '^Crystal 1\\.21\\.0 \\[9c1e8ec\\]'
      build: b9b8ba04ec40 on 1.22.3-incremental-4
    YAML
    assert_equal ["9c1e8ec64f6be6343e90d3979bc9536c4b050292", "v1.21.0-incremental-1", "9c1e8ec", "b9b8ba04ec40", "1.22.3-incremental-4"],
      stale_tokens(text)
    rewritten = rewrite(text)
    assert_includes rewritten, "CRYSTAL_ALPHA_COMMIT: #{CURRENT_RELEASE.source_commit} # tag v1.22.3-incremental-6"
    assert_includes rewritten, "\\[31372f7\\]"
    assert_includes rewritten, "build: 31372f755ad6 on 1.22.3-incremental-6"
  end

  def test_versions_inside_names_and_at_sentence_ends_are_found
    text = "# whose bottles carry incremental-4.\nalpha-1.22.3-incremental-4-minecart\nagent-crystal--1.22.3-incremental-4_1.arm64_tahoe\n"
    assert_equal ["incremental-4", "1.22.3-incremental-4", "1.22.3-incremental-4"], stale_tokens(text)
    assert_equal "# whose bottles carry incremental-6.\nalpha-1.22.3-incremental-6-minecart\nagent-crystal--1.22.3-incremental-6_1.arm64_tahoe\n",
      rewrite(text)
  end

  def test_the_current_release_and_other_text_are_left_alone
    text = "alpha-1.22.3-incremental-6-minecart and incremental-6\nbranch: incremental-compilation\nversion 1.22.30-incremental-40\n"
    assert_empty stale_tokens(text)
    assert_equal text, rewrite(text)
  end

  def test_a_line_marked_keep_is_history
    text = "# Mica became the default in 1.21.0-incremental-1. sync-downstreams: keep\n"
    assert_empty stale_tokens(text)
    assert_equal text, rewrite(text)
  end

  def test_a_head_keg_and_a_dropped_bottle_tag_are_left_for_a_person
    text = %({"path": "/opt/homebrew/Cellar/agent-crystal/HEAD-9c1e8ec/bin"}\nlinux: #{"9" * 64}\n)
    list_of_stale_pins = DownstreamSync.list_of_stale_pins_in("pins.json", text, list_of_rules)
    assert_equal ["agent-crystal/HEAD-9c1e8ec", "9" * 64], list_of_stale_pins.map(&:old_token)
    assert(list_of_stale_pins.all? { |pin| pin.new_token.include?("pin it by hand") })
    assert_equal text, rewrite(text)
  end

  def test_problems_name_stale_pins_and_unbuilt_formulae
    downstream = { "repository" => "o/tap", "branch" => "main", "sync" => "automatic", "bottles_workflow" => "bottles.yml",
                   "list_of_pin_files" => [".github/workflows/bottles.yml"], "list_of_formulae_to_rebuild" => ["Formula/amber_cli.rb"] }
    text_by_file = { ".github/workflows/bottles.yml" => "COMPILER_TAP_COMMIT: #{"e" * 40}\n", "Formula/amber_cli.rb" => FORMULA_TEXT }
    list_of_problems = DownstreamSync.list_of_problems_for(downstream, CURRENT_RELEASE, list_of_rules, text_by_file.method(:fetch))
    assert_equal 2, list_of_problems.size
    assert_match(/bottles\.yml:1 names e{40}/, list_of_problems[0])
    assert_match(/not rebuilt on agent-crystal 1\.22\.3-incremental-6/, list_of_problems[1])

    rebuilt = DownstreamSync.rebuild_formula_text(FORMULA_TEXT, CURRENT_RELEASE)
    text_by_file = { ".github/workflows/bottles.yml" => "COMPILER_TAP_COMMIT: #{"c" * 40}\n", "Formula/amber_cli.rb" => rebuilt }
    list_of_problems = DownstreamSync.list_of_problems_for(downstream, CURRENT_RELEASE, list_of_rules, text_by_file.method(:fetch))
    assert_equal ["Formula/amber_cli.rb has no bottles yet (ruby scripts/sync_downstreams.rb bottles)"], list_of_problems

    bottled = rebuilt.sub("  revision 1\n", "  revision 1\n\n  bottle do\n    sha256 arm64_tahoe: \"#{"3" * 64}\"\n  end\n")
    text_by_file["Formula/amber_cli.rb"] = bottled
    assert_empty DownstreamSync.list_of_problems_for(downstream, CURRENT_RELEASE, list_of_rules, text_by_file.method(:fetch))
  end

  def test_rebuild_adds_a_revision_drops_the_bottles_and_names_the_compiler
    rebuilt = DownstreamSync.rebuild_formula_text(FORMULA_TEXT, CURRENT_RELEASE)
    assert_match(/^  license "MIT"\n  revision 1\n/, rebuilt)
    refute_includes rebuilt, "bottle do"
    assert_match(/^  # Built with agent-crystal 1\.22\.3-incremental-6 \(tap commit c{12}\)\.\n  # scripts\/sync_downstreams\.rb .*\n  depends_on "crimson-knight\/agent-crystal\/agent-crystal"\n/, rebuilt)
    assert DownstreamSync.formula_names_compiler?(rebuilt, CURRENT_RELEASE)
    refute DownstreamSync.formula_has_bottles?(rebuilt)
  end

  def test_rebuild_removes_a_bottle_block_with_no_blank_line_after_it
    tight = FORMULA_TEXT.sub("  end\n\n  depends_on", "  end\n  depends_on")
    rebuilt = DownstreamSync.rebuild_formula_text(tight, CURRENT_RELEASE)
    refute_includes rebuilt, "bottle do"
    refute DownstreamSync.formula_has_bottles?(rebuilt)
  end

  def test_rebuild_puts_the_revision_after_a_license_that_spans_lines
    spanning = FORMULA_TEXT.sub(%(  license "MIT"\n), %(  license any_of: [\n    "MIT",\n    "Apache-2.0",\n  ]\n))
    rebuilt = DownstreamSync.rebuild_formula_text(spanning, CURRENT_RELEASE)
    assert_match(/^  \]\n  revision 1\n/, rebuilt)
  end

  def test_rebuild_raises_an_existing_revision_and_replaces_the_compiler_comment
    with_revision = FORMULA_TEXT.sub(%(  license "MIT"\n), %(  license "MIT"\n  revision 2\n))
    once = DownstreamSync.rebuild_formula_text(with_revision, BOTTLED_EARLIER_RELEASE.dup.tap { |release| release.bottles_commit = "e" * 40 })
    twice = DownstreamSync.rebuild_formula_text(once, CURRENT_RELEASE)
    assert_match(/^  revision 4$/, twice)
    assert_equal 1, twice.scan("# Built with agent-crystal").size
    assert DownstreamSync.formula_names_compiler?(twice, CURRENT_RELEASE)
    refute DownstreamSync.formula_names_compiler?(twice, BOTTLED_EARLIER_RELEASE)
  end

  def test_rebuild_refuses_a_formula_that_does_not_build_with_the_compiler
    assert_raises(DownstreamSync::SyncRefused) do
      DownstreamSync.rebuild_formula_text(FORMULA_TEXT.sub("crimson-knight/agent-crystal/agent-crystal", "crystal"), CURRENT_RELEASE)
    end
  end

  def test_rebuild_refuses_a_formula_it_would_leave_unparsable
    broken = FORMULA_TEXT.sub("  depends_on \"libpq\"\n", "  depends_on \"libpq\" do\n")
    assert_raises(DownstreamSync::SyncRefused) { DownstreamSync.rebuild_formula_text(broken, CURRENT_RELEASE) }
  end

  def test_the_manifest_lists_pin_files_for_every_downstream
    list_of_downstreams = JSON.parse(File.read(DownstreamSync::MANIFEST_PATH)).fetch("list_of_downstreams")
    refute_empty list_of_downstreams
    list_of_downstreams.each do |downstream|
      assert_includes %w[automatic by_hand], downstream.fetch("sync")
      refute_empty downstream.fetch("list_of_pin_files")
      assert downstream["how_to_sync"], "#{downstream["repository"]} says how to sync it by hand" if downstream["sync"] == "by_hand"
    end
  end
end
