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

## Prebuilt bottles

`brew install` pours a prebuilt bottle on macOS arm64, Linux arm64 and Linux
x86_64, so installing takes seconds. Each bottle is an asset of the tap release
`agent-crystal-<version>`, and the formula pins each one by SHA-256 in its
`bottle do` block. Other platforms, and `--build-from-source`, build the compiler
from the hash-pinned release tarball.

Every version ships with bottles. After the formula moves to a new version
(autobump starts this itself):

```bash
gh workflow run bottles.yml -R crimson-knight/homebrew-agent-crystal --ref main
```

The workflow builds and tests a bottle on each platform, checks each file against
the SHA-256 `brew bottle` recorded, publishes the release assets, writes the
`bottle do` block, and then installs from the tap on each platform and requires
that Homebrew poured the bottle.

The SDK checks pin the formula without its `bottle do` block, so publishing
bottles keeps every reviewed pin. After any other edit to the formula or to a
pinned test script, run `ruby scripts/repin_formula.rb` and review the diff.

## Lean by default

Programs link no C library for Regex, YAML, text encodings or compression: Mica
runs them in Crystal. `require "big"` (BigInt, BigFloat, BigRational, BigDecimal)
is pure Crystal too and needs nothing installed. The formula therefore installs
only what the compiler and a default Amber V2 app need (llvm@21, openssl@3,
pkgconf). Each C library is one flag away; install it before building with that
flag:

| Build with | Install |
|---|---|
| `-Duse_pcre2` | `brew install pcre2` |
| `-Duse_libyaml` | `brew install libyaml` |
| `-Devloop=libevent` | `brew install libevent` |
| `-Duse_gmp` (GMP for big numbers; kept for this release only) | `brew install gmp` |

When one is missing, the compiler's link error names the flag and the command.

## Garbage collector

The formula builds its own Boehm collector (bdw-gc 8.2.12, pinned by SHA-256) and
links it statically into the compiler and into every program the compiler builds.
The collector's heap blocks are sized for the machine's memory pages, because a free
block goes back to the operating system only when it covers whole pages. On arm64
macOS (16 KB pages) the programs the compiler builds get 8 KB blocks, two of which
fill a page, and the compiler itself gets 16 KB blocks. On arm64 Linux both use the
kernel's page size up to 16 KB (4 KB on most kernels), and on x86_64 Linux and every
other target the collector's 4 KB default. On Apple Silicon an Amber app under load
peaked at 21.5 MiB with 8 KB blocks, against 21.9 MiB with 4 KB and 25.2 MiB with
16 KB. The compiler spent 81 to 84 s collecting to the end of IR generation of a
300-model Grant app with 16 KB blocks, against 93 s with 8 KB and 120 s with 4 KB.

## Verify

```bash
acrystal --version
agent-crystal --version
crystal-alpha --version
```
