# Agent Crystal Homebrew Tap

This tap packages Agent Crystal and installs three command names:

- `acrystal`
- `agent-crystal`
- `crystal-alpha`

`acrystal` is the short everyday command. `agent-crystal` is the explicit long form.
`crystal-alpha` is the entry point used by Amber V2 and the memory-budget tools.
All three commands use the same compiler backend and standard library.

## Install

```bash
brew tap crimson-knight/agent-crystal
brew install agent-crystal
```

## One-Liner Installer

```bash
curl -fsSL https://raw.githubusercontent.com/crimson-knight/homebrew-agent-crystal/main/install.sh | bash
```

That installer bootstraps Homebrew when necessary on macOS and Linux, then installs the `crimson-knight/agent-crystal` tap. Today that is the simplest copy-paste path for macOS, Ubuntu/Debian, Fedora, and Asahi Linux systems that can use Homebrew.

## Verify

```bash
acrystal --version
agent-crystal --version
crystal-alpha --version
```
