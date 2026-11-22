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
macOS 26 and Ubuntu 24.04. Memory budget tooling records the installed compiler
backend, standard-library tree and native dependencies in its own reviewed
toolchain profile.

## Garbage collector

The formula builds its own Boehm collector (bdw-gc 8.2.12, pinned by SHA-256) and
links it statically into the compiler and into every program the compiler builds.
The collector's heap blocks are sized for the machine's memory pages, because a free
block goes back to the operating system only when it covers whole pages: 8 KB on
arm64 macOS (16 KB pages, so two free neighbors fill a page), the kernel's page size
up to 16 KB on arm64 Linux (4 KB on most kernels), and the collector's 4 KB default
on x86_64 Linux and every other target. On Apple Silicon a churn test returned 92 of
130 MB of freed memory with 8 KB blocks against 31 of 117 MB with 4 KB blocks, and an
Amber app under load peaked at 21.5 MiB with 8 KB blocks against 21.9 MiB with 4 KB
and 25.2 MiB with 16 KB blocks.

## Verify

```bash
acrystal --version
agent-crystal --version
crystal-alpha --version
```
