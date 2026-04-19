#!/usr/bin/env bash

set -euo pipefail

readonly AGENT_CRYSTAL_TAP="${AGENT_CRYSTAL_TAP:-crimson-knight/agent-crystal}"
readonly AGENT_CRYSTAL_FORMULA="${AGENT_CRYSTAL_FORMULA:-agent-crystal}"
readonly AGENT_CRYSTAL_FORMULA_PATH="${AGENT_CRYSTAL_FORMULA_PATH:-}"

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

  log "Homebrew not found. Installing the official Homebrew distribution."
  NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

  local brew_prefix
  brew_prefix="$(detect_brew_prefix)" || die "Homebrew installation finished, but brew was not found"
  eval "$("${brew_prefix}/bin/brew" shellenv)"
}

ensure_brew_shellenv() {
  local brew_prefix
  brew_prefix="$(detect_brew_prefix)" || die "Homebrew is required but was not found"
  eval "$("${brew_prefix}/bin/brew" shellenv)"
}

install_formula() {
  if [[ -n "${AGENT_CRYSTAL_FORMULA_PATH}" ]]; then
    log "Installing local formula at ${AGENT_CRYSTAL_FORMULA_PATH}"
    brew install --build-from-source "${AGENT_CRYSTAL_FORMULA_PATH}"
    return 0
  fi

  log "Tapping ${AGENT_CRYSTAL_TAP}"
  brew tap "${AGENT_CRYSTAL_TAP}"

  log "Installing ${AGENT_CRYSTAL_FORMULA}"
  brew install "${AGENT_CRYSTAL_FORMULA}"
}

verify_install() {
  command -v acrystal >/dev/null 2>&1 || die "`acrystal` was not installed on PATH"
  command -v agent-crystal >/dev/null 2>&1 || die "`agent-crystal` was not installed on PATH"

  log
  log "Installed successfully:"
  acrystal --version
}

main() {
  ensure_homebrew
  ensure_brew_shellenv
  install_formula
  verify_install
}

main "$@"
