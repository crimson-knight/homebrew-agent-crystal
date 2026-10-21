# frozen_string_literal: true
require "digest"
require File.expand_path(ARGV.fetch(0))
identity = MemoryBudget::ToolchainProfile.resolve(File.expand_path(ARGV.fetch(1)))
schema = identity.profile.fetch("schema_version")
abort "Strict writer requires admitted schema 3" unless schema.is_a?(Integer) && schema == 3
installer = File.realpath(ENV.fetch("MEMORY_BUDGET_MINECART"))
expected = identity.profile.fetch("minecart_sha256")
abort "Writer Minecart digest differs" unless Digest::SHA256.file(installer).hexdigest == expected
manifest = Digest::SHA256.file("shard.yml").hexdigest
abort "Writer starts with an absent lock" if File.exist?("shard.lock")
environment = identity.environment.merge("CRYSTAL" => identity.compiler_path, "CRYSTAL_VERSION" => nil, "CRYSTAL_WORKERS" => "1")
succeeded = system(environment, installer, "install", "--strict-pinning", "--skip-ai-docs", "--jobs=1")
identity.environment
abort "Writer Minecart changed" unless Digest::SHA256.file(installer).hexdigest == expected
abort "Writer changed the package manifest" unless Digest::SHA256.file("shard.yml").hexdigest == manifest
abort "Strict writer failed" unless succeeded && File.file?("shard.lock") && !File.symlink?("shard.lock")
