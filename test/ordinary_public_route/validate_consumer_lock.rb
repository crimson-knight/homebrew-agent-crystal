# frozen_string_literal: true
require "json"
require "yaml"
require "digest"
expected = YAML.safe_load(File.read(ARGV.fetch(0)), permitted_classes: [], permitted_symbols: [], aliases: false)
actual = YAML.safe_load(File.read("shard.lock"), permitted_classes: [], permitted_symbols: [], aliases: false)
abort "Actual writer lock differs from the selected public SDK dependency" unless actual == expected
puts JSON.generate({"manifest_sha256" => Digest::SHA256.file("shard.yml").hexdigest,
  "lock_sha256" => Digest::SHA256.file("shard.lock").hexdigest,
  "dependencies" => actual.fetch("shards"), "actual_writer_lock" => true})
