# Agent Crystal Homebrew Tap

This tap packages Agent Crystal, the AgentC-enhanced Crystal compiler with
incremental compilation, and installs three command names:

- `crystal-alpha` (canonical; the name hooks, generators, and gates call)
- `acrystal` (alias)
- `agent-crystal` (alias)

All three run the same compiler. Use `crystal-alpha` in scripts and docs. It
installs beside stock `crystal` from homebrew-core and does not replace it, so
the two can be installed together.

## Install

```bash
brew tap crimson-knight/agent-crystal
brew install agent-crystal
```

The formula builds the compiler from source, which takes about 30 minutes. It
works on macOS and on Linux through Linuxbrew.

## One-Liner Installer

```bash
curl -fsSL https://raw.githubusercontent.com/crimson-knight/homebrew-agent-crystal/main/install.sh | bash
```

That installer bootstraps Homebrew when necessary on macOS and Linux, then installs the `crimson-knight/agent-crystal` tap. Today that is the simplest copy-paste path for macOS, Ubuntu/Debian, Fedora, and Asahi Linux systems that can use Homebrew.

## Verify

```bash
crystal-alpha --version
acrystal --version
agent-crystal --version
```
