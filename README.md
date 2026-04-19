# Agent Crystal Homebrew Tap

This tap packages Agent Crystal and installs two command names:

- `acrystal`
- `agent-crystal`

`acrystal` is the short everyday command. `agent-crystal` is the explicit long form.

## Install

```bash
brew tap crimsonknight/agent-crystal
brew install agent-crystal
```

## One-Liner Installer

```bash
curl -fsSL https://raw.githubusercontent.com/crimson-knight/homebrew-agent-crystal/main/install.sh | bash
```

That installer bootstraps Homebrew when necessary on macOS and Linux, then installs the `crimsonknight/agent-crystal` tap. Today that is the simplest copy-paste path for macOS, Ubuntu/Debian, Fedora, and Asahi Linux systems that can use Homebrew.

## Verify

```bash
acrystal --version
agent-crystal --version
```
