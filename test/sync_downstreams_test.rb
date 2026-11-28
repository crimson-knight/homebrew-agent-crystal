# Tests the pin rewriting and formula rebuild of scripts/sync_downstreams.rb.
#   ruby test/sync_downstreams_test.rb
require "json"
require "minitest/autorun"
require_relative "../scripts/sync_downstreams"

class SyncDownstreamsTest < Minitest::Test
  CURRENT_RELEASE = DownstreamSync::Release.new(
    version: "1.22.3-incremental-6",
    bottles_commit: "c" * 40,
    source_commit: "3" * 40,
    archive_sha256: "a" * 64,
    bottle_sha256_by_tag: { "arm64_tahoe" => "b" * 64 }
  )
  EARLIER_RELEASE = DownstreamSync::Release.new(
    version: "1.22.3-incremental-4",
    bottles_commit: "e" * 40,
    source_commit: "4" * 40,
    archive_sha256: "d" * 64,
    bottle_sha256_by_tag: { "arm64_tahoe" => "f" * 64, "arm64_linux" => "9" * 64 }
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

  def replacements
    DownstreamSync.replacement_by_old_token(CURRENT_RELEASE, [EARLIER_RELEASE])
  end

  def test_every_hash_of_an_earlier_release_maps_to_the_current_one
    assert_equal "c" * 40, replacements["e" * 40]
    assert_equal "3" * 40, replacements["4" * 40]
    assert_equal "a" * 64, replacements["d" * 64]
    assert_equal "b" * 64, replacements["f" * 64]
    refute replacements.key?("9" * 64), "a bottle tag the current release lacks has nothing to map to"
  end

  def test_rewrite_moves_commits_and_versions_and_keeps_other_text
    text = <<~YAML
      COMPILER_TAP_COMMIT: #{"e" * 40}
      # The compiler whose bottles carry incremental-4, crystal-alpha 1.21.0-incremental-1 before that.
      branch: incremental-compilation
    YAML
    rewritten = DownstreamSync.rewrite_pins(text, CURRENT_RELEASE, replacements)
    assert_includes rewritten, "COMPILER_TAP_COMMIT: #{"c" * 40}"
    assert_includes rewritten, "carry incremental-6, crystal-alpha 1.22.3-incremental-6 before"
    assert_includes rewritten, "branch: incremental-compilation"
    assert_empty DownstreamSync.list_of_stale_pins_in("x.yml", rewritten, CURRENT_RELEASE, replacements)
  end

  def test_stale_pins_name_the_file_and_line
    text = "ok line\nversion: 1.22.3-incremental-3\nsha: #{"d" * 64}\n"
    list_of_stale_pins = DownstreamSync.list_of_stale_pins_in("lock.json", text, CURRENT_RELEASE, replacements)
    assert_equal [2, 3], list_of_stale_pins.map(&:line_number)
    assert_equal ["1.22.3-incremental-3", "d" * 64], list_of_stale_pins.map(&:old_token)
  end

  def test_the_current_version_is_not_stale
    text = "alpha-1.22.3-incremental-6-minecart and incremental-6\n"
    assert_empty DownstreamSync.list_of_stale_pins_in("a", text, CURRENT_RELEASE, replacements)
  end

  def test_rebuild_adds_a_revision_drops_the_bottles_and_names_the_compiler
    rebuilt = DownstreamSync.rebuild_formula_text(FORMULA_TEXT, CURRENT_RELEASE)
    assert_match(/^  license "MIT"\n  revision 1\n/, rebuilt)
    refute_includes rebuilt, "bottle do"
    assert_match(/^  # Built with agent-crystal 1\.22\.3-incremental-6 \(tap commit c{12}\)\.\n  # scripts\/sync_downstreams\.rb .*\n  depends_on "crimson-knight\/agent-crystal\/agent-crystal"\n/, rebuilt)
    assert DownstreamSync.formula_names_compiler?(rebuilt, CURRENT_RELEASE)
    refute DownstreamSync.formula_has_bottles?(rebuilt)
  end

  def test_rebuild_raises_an_existing_revision_and_replaces_the_compiler_comment
    once = DownstreamSync.rebuild_formula_text(FORMULA_TEXT.sub(%(  license "MIT"\n), %(  revision 2\n  license "MIT"\n)), EARLIER_RELEASE)
    twice = DownstreamSync.rebuild_formula_text(once, CURRENT_RELEASE)
    assert_match(/^  revision 4$/, twice)
    assert_equal 1, twice.scan("# Built with agent-crystal").size
    assert DownstreamSync.formula_names_compiler?(twice, CURRENT_RELEASE)
    refute DownstreamSync.formula_names_compiler?(twice, EARLIER_RELEASE)
  end

  def test_rebuild_refuses_a_formula_that_does_not_build_with_the_compiler
    assert_raises(DownstreamSync::SyncRefused) do
      DownstreamSync.rebuild_formula_text(FORMULA_TEXT.sub("crimson-knight/agent-crystal/agent-crystal", "crystal"), CURRENT_RELEASE)
    end
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
