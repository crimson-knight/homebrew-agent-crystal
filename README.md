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

## Checksum-verified installer

```bash
(
set -euo pipefail
curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  --connect-timeout 15 --max-time 120 --max-filesize 1048576 \
  https://raw.githubusercontent.com/crimson-knight/homebrew-agent-crystal/22cb077900945471d7281b8f3f60633bc9ebf08e/install.sh \
  --output install-agent-crystal.sh
printf '%s  %s\n' \
  970e0e1c0d72cd9c3041220662d65d391edcac42eed7acb7849a7704817c9dcb \
  install-agent-crystal.sh | shasum -a 256 --check
bash install-agent-crystal.sh
)
```

This pins the downloaded installer to a specific commit and verifies its bytes
before execution. The installer uses existing Homebrew when available. When
Homebrew is needed, it downloads the official bootstrap at commit
`be041513824fd2666a0e93cf5c3b0ca3bb0eb4b6` and requires SHA-256
`5f333bbe53bc490e51e7ccb1df8779b3dd6ee73a1a7379efda216edb08ccb148`
before running that file. It then installs the `crimson-knight/agent-crystal` tap.

Installation verifies all three commands and compiles and runs an expression
through `crystal-alpha`. CI exercises the formula and repository installer on
macOS 14 and Ubuntu 24.04. Memory budget tooling records the installed compiler
backend, standard-library tree and native dependencies in its own reviewed
toolchain profile.

## Verify

```bash
acrystal --version
agent-crystal --version
crystal-alpha --version
```
