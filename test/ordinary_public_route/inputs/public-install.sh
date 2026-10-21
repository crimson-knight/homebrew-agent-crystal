#!/usr/bin/env bash

set -euo pipefail

readonly AGENT_CRYSTAL_TAP="${AGENT_CRYSTAL_TAP:-crimson-knight/agent-crystal}"
readonly AGENT_CRYSTAL_FORMULA="${AGENT_CRYSTAL_FORMULA:-agent-crystal}"
readonly AGENT_CRYSTAL_FORMULA_PATH="${AGENT_CRYSTAL_FORMULA_PATH:-}"
readonly HOMEBREW_INSTALL_COMMIT="be041513824fd2666a0e93cf5c3b0ca3bb0eb4b6"
readonly HOMEBREW_INSTALL_SHA256="5f333bbe53bc490e51e7ccb1df8779b3dd6ee73a1a7379efda216edb08ccb148"

log() {
  printf '%s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

detect_brew_prefix() {
  if command -v brew >/dev/null 2>&1; then
    brew --prefix
    return 0
  fi

  case "$(uname -s)" in
    Darwin)
      if [[ -x /opt/homebrew/bin/brew ]]; then
        echo /opt/homebrew
      elif [[ -x /usr/local/bin/brew ]]; then
        echo /usr/local
      else
        return 1
      fi
      ;;
    Linux)
      if [[ -x /home/linuxbrew/.linuxbrew/bin/brew ]]; then
        echo /home/linuxbrew/.linuxbrew
      elif [[ -x "${HOME}/.linuxbrew/bin/brew" ]]; then
        echo "${HOME}/.linuxbrew"
      else
        return 1
      fi
      ;;
    *)
      return 1
      ;;
  esac
}

ensure_homebrew() {
  if command -v brew >/dev/null 2>&1; then
    return 0
  fi

  log "Homebrew not found. Installing the checksum-verified official Homebrew bootstrap."
  install_homebrew

  local brew_prefix
  brew_prefix="$(detect_brew_prefix)" || die "Homebrew installation finished, but brew was not found"
  eval "$("${brew_prefix}/bin/brew" shellenv)"
}

install_homebrew() (
  command -v shasum >/dev/null 2>&1 || die "shasum is required to verify the Homebrew bootstrap"
  local bootstrap_file actual_checksum
  bootstrap_file="$(mktemp "${TMPDIR:-/tmp}/agent-crystal-homebrew.XXXXXX")"
  trap 'rm -f -- "$bootstrap_file"' EXIT
  curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 120 --max-filesize 1048576 \
    "https://raw.githubusercontent.com/Homebrew/install/${HOMEBREW_INSTALL_COMMIT}/install.sh" \
    --output "$bootstrap_file"
  actual_checksum="$(shasum -a 256 "$bootstrap_file")"
  [[ "${actual_checksum%% *}" == "$HOMEBREW_INSTALL_SHA256" ]] || die "Homebrew bootstrap checksum differs"
  NONINTERACTIVE=1 /bin/bash "$bootstrap_file"
)

ensure_brew_shellenv() {
  local brew_prefix
  brew_prefix="$(detect_brew_prefix)" || die "Homebrew is required but was not found"
  eval "$("${brew_prefix}/bin/brew" shellenv)"
}

install_formula() {
  if [[ -n "${AGENT_CRYSTAL_FORMULA_PATH}" ]]; then
    # Newer Homebrew refuses to install a formula from a bare file path
    # ("Homebrew requires formulae to be in a tap"), so register the
    # checkout containing the formula as the tap and install through it.
    local tap_dir
    tap_dir="$(cd "$(dirname "${AGENT_CRYSTAL_FORMULA_PATH}")/.." && pwd)"
    log "Registering ${tap_dir} as tap ${AGENT_CRYSTAL_TAP}"
    brew tap --custom-remote "${AGENT_CRYSTAL_TAP}" "${tap_dir}"
    log "Installing ${AGENT_CRYSTAL_TAP}/${AGENT_CRYSTAL_FORMULA} from local tap"
    brew install --build-from-source "${AGENT_CRYSTAL_TAP}/${AGENT_CRYSTAL_FORMULA}"
    return 0
  fi

  log "Tapping ${AGENT_CRYSTAL_TAP}"
  brew tap "${AGENT_CRYSTAL_TAP}"

  log "Installing ${AGENT_CRYSTAL_FORMULA}"
  brew install "${AGENT_CRYSTAL_FORMULA}"
}

verify_install() {
  command -v acrystal >/dev/null 2>&1 || die "acrystal was not installed on PATH"
  command -v agent-crystal >/dev/null 2>&1 || die "agent-crystal was not installed on PATH"
  command -v crystal-alpha >/dev/null 2>&1 || die "crystal-alpha was not installed on PATH"

  log
  log "Installed successfully:"
  acrystal --version
  agent-crystal --version
  crystal-alpha --version
  [[ "$(crystal-alpha eval 'puts 40 + 2')" == "42" ]] || die "crystal-alpha did not compile and run the verification expression"
}

main() {
  ensure_homebrew
  ensure_brew_shellenv
  install_formula
  verify_install
}

main "$@"
