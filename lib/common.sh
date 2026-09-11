#!/usr/bin/env bash
# Shared plumbing for the Blue Team lab scripts.
#
# Source it, do not run it:
#     . "$(dirname "$0")/../lib/common.sh"
#
# It gives you colours that behave when piped, a dependency checker that tells
# you how to install the thing instead of just complaining it is missing, and a
# confirm() that defaults to "no" because the alternative is how labs die.

set -o errexit
set -o nounset
set -o pipefail

# --- output -----------------------------------------------------------------
# Colour only when a human is looking. Piping to a file should give you a file,
# not a file full of escape codes.
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
  C_RST=$'\033[0m'; C_DIM=$'\033[2m';  C_B=$'\033[1m'
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[36m'
else
  C_RST=''; C_DIM=''; C_B=''; C_RED=''; C_GRN=''; C_YEL=''; C_BLU=''
fi

say()  { printf '%s\n' "$*"; }
info() { printf '%s==>%s %s\n' "$C_BLU" "$C_RST" "$*"; }
ok()   { printf '%s  ok%s  %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s warn%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
bad()  { printf '%s fail%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }
die()  { bad "$*"; exit 1; }
hint() { printf '%s       %s%s\n' "$C_DIM" "$*" "$C_RST"; }

rule() { printf '%s%s%s\n' "$C_DIM" "$(printf '─%.0s' $(seq 1 "${1:-72}"))" "$C_RST"; }

banner() {
  rule
  printf '%s%s%s\n' "$C_B" "$1" "$C_RST"
  [[ $# -gt 1 ]] && printf '%s%s%s\n' "$C_DIM" "$2" "$C_RST"
  rule
}

# --- timestamps -------------------------------------------------------------
# UTC. Always UTC. A timeline in local time is a timeline you will re-do.
utc()      { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
utc_short(){ date -u '+%H:%M:%S'; }
stamp()    { date -u '+%Y%m%d-%H%M%S'; }

# --- dependencies -----------------------------------------------------------
# need <command> [install hint]
need() {
  local cmd="$1" tip="${2:-}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    bad "missing: $cmd"
    [[ -n "$tip" ]] && hint "try: $tip"
    return 1
  fi
  return 0
}

need_all() {
  local missing=0
  while [[ $# -gt 0 ]]; do
    need "$1" "${2:-}" || missing=1
    shift 2 2>/dev/null || shift
  done
  [[ $missing -eq 0 ]] || die "install the above, then run this again"
}

# --- interaction ------------------------------------------------------------
# Defaults to no. If you want yes you can type three letters.
confirm() {
  local prompt="${1:-continue?}" reply
  read -r -p "$prompt [y/N] " reply || true
  [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# Refuse to keep going as root unless the script genuinely needs it. Most of
# these do not, and running a triage script as root is how a read-only task
# becomes a write.
refuse_root() {
  [[ "${EUID:-$(id -u)}" -ne 0 ]] || die "do not run this as root; it does not need it"
}

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "this one genuinely needs root: re-run with sudo"
}

# --- files ------------------------------------------------------------------
outdir() {
  local d="${1:-out/$(stamp)}"
  mkdir -p "$d"
  printf '%s' "$d"
}

# sha256 that works on both Linux and macOS without a second thought
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"
  else shasum -a 256 "$@"; fi
}
