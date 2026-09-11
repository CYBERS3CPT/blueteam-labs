#!/usr/bin/env bash
# memory-capture.sh — volatile state first, then memory, then hash everything
#
# Order matters and it is not negotiable. Every command you run destroys a little
# of what the next one would have seen, so the cheap volatile state comes first
# and the expensive memory image comes second. Power comes last, if at all.
#
#   ./memory-capture.sh volatile <outdir>    processes, network, sessions, mounts
#   ./memory-capture.sh memory <outdir>      full RAM via AVML or LiME
#   ./memory-capture.sh all <outdir>         volatile, then memory. The normal case.
#   ./memory-capture.sh checklist            the decision you make before any of it
#
# Output goes to EXTERNAL media. Writing a memory image to the local disk
# overwrites unallocated space that may itself be evidence.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
set +o errexit

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

LOG=""
note() { local l="$(utc)  $*"; printf '%s\n' "$l"; [[ -n "$LOG" ]] && printf '%s\n' "$l" >> "$LOG"; }

check_external() {
  local dir="$1"
  local dev root
  dev=$(df -P "$dir" 2>/dev/null | awk 'NR==2{print $1}')
  root=$(df -P / 2>/dev/null | awk 'NR==2{print $1}')
  if [[ "$dev" == "$root" ]]; then
    bad "$dir is on the SAME filesystem as /"
    hint "a memory image written locally overwrites unallocated space that may be evidence"
    hint "mount external media and point this at it"
    confirm "continue anyway? (record the reason in your notes)" || exit 1
  else
    ok "$dir is on $dev, separate from the system disk"
  fi
}

cmd_checklist() {
  banner "Before you touch the keyboard" "the decision, not the commands"
  cat <<'TXT'

  1. WHICH ROLE ARE YOU?
     First responder secures and preserves. Examiner acquires. Analyst
     interprets. Most catastrophic errors are an analyst behaving like a first
     responder, or the reverse. Decide, then stay in it.

  2. IS FULL-DISK ENCRYPTION IN USE, AND IS IT UNLOCKED?
     Determine this BEFORE deciding anything about power. Powering off an
     unlocked FDE machine turns the disk into a brick, and no amount of later
     skill undoes it.

  3. IS THE ADVERSARY ACTIVE RIGHT NOW?
     This drives urgency more than anything else on the list.

  4. WHAT DOES CONTAINMENT COST?
     Isolating the host stops the bleeding and tells the adversary they are
     detected. Monitoring preserves intelligence and accepts ongoing risk.
     Both are defensible. An undocumented choice is not.

  5. HAVE YOU RECORDED THE TIME AND THE CLOCK DRIFT?
     Compare the system clock against a known reference and write the
     difference down. Every timestamp you later quote depends on it.

  6. WHERE IS THE OUTPUT GOING?
     External media. Always. And there must be room: a memory image is the
     size of RAM, and RAM is bigger than people remember.

  Acquiring memory CHANGES memory. That is unavoidable and it is acceptable —
  ACPO principle 2 covers exactly this. What is not acceptable is doing it
  without recording the tool, the version and the footprint.

TXT
}

cmd_volatile() {
  local out="${1:-}"; [[ -n "$out" ]] || die "usage: $0 volatile <outdir>"
  mkdir -p "$out" || die "cannot write to $out"
  check_external "$out"
  LOG="$out/collection-notes.txt"
  : > "$LOG"

  banner "Volatile state" "cheapest first — each command costs a little of the next"
  note "START volatile collection on $(hostname)"
  note "TOOLS $(uname -srmo 2>/dev/null || uname -srm)"

  # Clock first. Everything else is timestamped relative to a clock you have
  # not yet verified, which is a problem you fix by recording it now.
  note "CLOCK system=$(date -u '+%Y-%m-%dT%H:%M:%SZ') (compare against a known reference and record the drift)"

  grab() {  # grab <file> <description> <command...>
    local f="$out/$1" desc="$2"; shift 2
    printf '  %-26s %-34s' "$1" "$desc"
    if "$@" > "$f" 2>/dev/null; then
      local h; h=$(sha256 "$f" | awk '{print $1}')
      printf '%9s B\n' "$(wc -c < "$f" | tr -d ' ')"
      note "GRAB  $1  sha256=$h  cmd=$*"
    else
      printf '   unavailable\n'; rm -f "$f"
    fi
  }

  # Order: the things that change fastest, first.
  grab network-connections.txt "sockets and owning process" ss -tunapp
  grab network-arp.txt         "arp cache"                  ip neigh
  grab network-routes.txt      "routing"                    ip route show table all
  grab network-interfaces.txt  "interfaces"                 ip -d addr
  grab processes-tree.txt      "process tree"               ps auxfww
  grab processes-full.txt      "full process list"          ps -eo pid,ppid,user,lstart,etime,stat,args
  grab open-files.txt          "open files and sockets"     lsof -n -P
  grab loaded-modules.txt      "kernel modules"             lsmod
  grab mounts.txt              "mounts"                     cat /proc/mounts
  grab sessions-who.txt        "logged in now"              who -a
  grab sessions-last.txt       "recent logins"              last -F -n 100
  grab sessions-failed.txt     "failed logins"              lastb -F -n 100
  grab cron-list.txt           "user crontabs"              bash -c 'for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s|^|$u: |"; done'
  grab systemd-units.txt       "running units"              systemctl list-units --type=service --state=running --no-pager
  grab systemd-timers.txt      "timers"                     systemctl list-timers --all --no-pager
  grab uptime.txt              "uptime"                     uptime
  grab dmesg.txt               "kernel ring buffer"         dmesg

  # Deleted-but-running binaries. A process whose executable no longer exists on
  # disk is one of the highest-signal things on a live Linux host.
  info "processes running a deleted executable"
  ls -l /proc/[0-9]*/exe 2>/dev/null | grep -i '(deleted)' | tee "$out/deleted-executables.txt" | sed 's/^/  /' \
    || say "  (none — which is the normal answer)"
  [[ -s "$out/deleted-executables.txt" ]] && {
    warn "that is a strong indicator. Capture memory before anything else changes."
    note "FINDING processes with deleted executables present"
  }

  say ""
  note "END volatile collection"
  ok "$out  ($(find "$out" -type f | wc -l | tr -d ' ') file(s))"
  hint "next: $0 memory $out"
}

cmd_memory() {
  local out="${1:-}"; [[ -n "$out" ]] || die "usage: $0 memory <outdir>"
  mkdir -p "$out"; check_external "$out"
  LOG="${LOG:-$out/collection-notes.txt}"
  require_root

  local ram_kb ram_gb free_gb
  ram_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
  ram_gb=$(( ram_kb / 1024 / 1024 ))
  free_gb=$(df -BG --output=avail "$out" 2>/dev/null | tail -1 | tr -dc '0-9')

  banner "Memory acquisition" "${ram_gb} GB of RAM, ${free_gb:-?} GB free at the destination"
  if [[ -n "$free_gb" && "$free_gb" -lt "$ram_gb" ]]; then
    bad "not enough space: the image will be about ${ram_gb} GB"
    exit 1
  fi
  note "MEMORY ram=${ram_gb}GB dest_free=${free_gb}GB"

  local img="$out/memory-$(hostname -s 2>/dev/null || echo host)-$(stamp).lime"
  local tool=""
  if command -v avml >/dev/null 2>&1; then
    tool="avml $(avml --version 2>&1 | head -1)"
    info "avml"
    note "TOOL  $tool"
    note "ACQUIRE start"
    avml "$img" || { bad "avml failed"; note "ACQUIRE FAILED"; exit 1; }
  elif [[ -e /proc/kcore ]] && command -v dd >/dev/null 2>&1; then
    warn "no AVML — falling back to /proc/kcore, which is PARTIAL"
    hint "record this in the report. kcore is not a full physical memory image."
    tool="dd from /proc/kcore"
    note "TOOL  $tool (partial acquisition)"
    dd if=/proc/kcore of="$img" bs=1M 2>&1 | tail -2 | sed 's/^/  /'
  else
    die "no acquisition method available — install AVML or build LiME"
  fi
  note "ACQUIRE end"

  info "hashing"
  local h; h=$(sha256 "$img" | awk '{print $1}')
  printf '  %s\n  %s\n' "$(basename "$img")" "sha256 $h"
  printf '%s  %s\n' "$h" "$(basename "$img")" > "$img.sha256"
  note "HASH  $(basename "$img") sha256=$h bytes=$(wc -c < "$img" | tr -d ' ')"

  say ""
  ok "$img"
  hint "Volatility 3 wants a symbol table for this kernel. Build it now, while the"
  hint "host is still available: dwarf2json, from this kernel's debug symbols."
  say ""
  cat <<'NEXT'
  What you just captured that a disk image would not contain:
    - processes with no file on disk
    - injected code, and hollowed processes
    - network connections with their owning process
    - encryption keys, including full-disk encryption keys
    - decrypted content of otherwise encrypted files
    - command history, clipboard, credentials in cleartext
    - malware configuration AFTER decryption

  All of it disappears the moment the power does.
NEXT
}

case "${1:-}" in
  volatile)  shift; cmd_volatile "$@" ;;
  memory)    shift; cmd_memory "$@" ;;
  all)       cmd_volatile "${2:-}"; say ""; cmd_memory "${2:-}" ;;
  checklist) shift; cmd_checklist "$@" ;;
  ''|-h|--help|help) usage 0 ;;
  *) bad "unknown command: $1"; usage 1 ;;
esac
