#!/usr/bin/env bash
# harden.sh — apply a baseline, measure the delta, and be honest about the number
#
# The delta is the deliverable, not the score. Improving from 62 to 78 is real
# progress; it is not evidence that the host is secure, and presenting it as such
# is how security theatre gets funded.
#
#   ./harden.sh before              capture the baseline score. Do this FIRST.
#   ./harden.sh plan                what it would change, and what each could break
#   ./harden.sh apply               apply, with a backup of every file it touches
#   ./harden.sh after               re-score and print the delta
#   ./harden.sh rollback            put everything back
#   ./harden.sh limits              what the score does not measure. Read this.
#
# Every change is reversible and every original is kept. A hardening baseline
# applied without testing breaks things, and change management still applies.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
set +o errexit

STATE="${HARDEN_STATE:-./harden-state}"
BACKUP="$STATE/backup"
mkdir -p "$STATE"

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

score_now() {
  need lynis "sudo apt install -y lynis" || return 1
  local log="$STATE/lynis-$1.log"
  lynis audit system --quick --quiet --logfile "$log" --report-file "$STATE/lynis-$1.dat" >/dev/null 2>&1
  local s
  s=$(awk -F= '/hardening_index/{print $2}' "$STATE/lynis-$1.dat" 2>/dev/null | tail -1)
  printf '%s' "${s:-0}"
}

cmd_before() {
  banner "Baseline" "capture this BEFORE you change anything"
  require_root
  info "running lynis (a minute or two)"
  local s; s=$(score_now before)
  echo "$s" > "$STATE/score-before"
  ok "hardening index: $s"
  say ""
  info "top warnings"
  awk -F'|' '/^warning\[\]=/{print "  " $2}' "$STATE/lynis-before.dat" 2>/dev/null | head -12
  say ""
  hint "next: $0 plan"
}

# name|description|what it could break|test command|apply command
changes() {
cat <<'CH'
ssh-root|SSH: PermitRootLogin no|nothing, unless someone actually logs in as root over SSH — check first|grep -iE '^\s*PermitRootLogin' /etc/ssh/sshd_config|sed -i 's/^#\?\s*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
ssh-maxauth|SSH: MaxAuthTries 3|automation retrying with several keys in one session|grep -iE '^\s*MaxAuthTries' /etc/ssh/sshd_config|sed -i 's/^#\?\s*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
ssh-x11|SSH: X11Forwarding no|anyone forwarding a GUI over SSH, which is rarer than the config suggests|grep -iE '^\s*X11Forwarding' /etc/ssh/sshd_config|sed -i 's/^#\?\s*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sysctl-rp|Kernel: reverse path filtering|asymmetric routing, if this host is a router|sysctl net.ipv4.conf.all.rp_filter|echo 'net.ipv4.conf.all.rp_filter=1' >> /etc/sysctl.d/99-hardening.conf
sysctl-aslr|Kernel: full ASLR|nothing in practice|sysctl kernel.randomize_va_space|echo 'kernel.randomize_va_space=2' >> /etc/sysctl.d/99-hardening.conf
sysctl-redirect|Kernel: ignore ICMP redirects|a host relying on redirects for routing|sysctl net.ipv4.conf.all.accept_redirects|echo 'net.ipv4.conf.all.accept_redirects=0' >> /etc/sysctl.d/99-hardening.conf
sysctl-sysrq|Kernel: disable magic SysRq|out-of-band recovery on a physical console|sysctl kernel.sysrq|echo 'kernel.sysrq=0' >> /etc/sysctl.d/99-hardening.conf
pam-faillock|PAM: account lockout after 5 failures|a service account with a stale password locking itself out|grep -rl pam_faillock /etc/pam.d/ 2>/dev/null|echo 'PAM lockout: configure pam_faillock per distribution'
core-dumps|Disable core dumps|debugging a crash, and only that|grep -E '^\*\s+hard\s+core' /etc/security/limits.conf|echo '* hard core 0' >> /etc/security/limits.conf
CH
}

cmd_plan() {
  banner "Plan" "what it would change, and what each one could break"
  say ""
  printf '  %-16s %-42s %s\n' "change" "what" "current"
  printf '  %s\n' "$(printf '─%.0s' $(seq 1 92))"
  while IFS='|' read -r name desc breaks test apply; do
    [[ -z "$name" ]] && continue
    local cur; cur=$(eval "$test" 2>/dev/null | head -1 | cut -c1-32)
    printf '  %-16s %-42s %s\n' "$name" "${desc:0:41}" "${cur:-<unset>}"
    printf '  %-16s %s%s%s\n' "" "$C_DIM" "could break: $breaks" "$C_RST"
  done < <(changes)
  say ""
  cat <<'NEXT'
  The "could break" column is the deliverable requirement, not decoration. The
  Session 12 brief asks, for two of your changes: what could it break, and how
  would you test? Answer it from this table, then test it — on something that is
  not production.
NEXT
}

cmd_apply() {
  require_root
  banner "Applying" "every original is backed up first"
  mkdir -p "$BACKUP"
  for f in /etc/ssh/sshd_config /etc/sysctl.d/99-hardening.conf /etc/security/limits.conf; do
    [[ -f "$f" ]] && { cp -a "$f" "$BACKUP/$(basename "$f")" 2>/dev/null && ok "backed up $f"; }
  done
  : > "$STATE/applied"

  while IFS='|' read -r name desc breaks test apply; do
    [[ -z "$name" ]] && continue
    printf '  %-16s ' "$name"
    if [[ "$apply" == echo\ * ]]; then
      printf 'manual — %s\n' "${apply#echo \'}"
      continue
    fi
    if eval "$apply" 2>/dev/null; then
      printf 'applied\n'; echo "$name" >> "$STATE/applied"
    else
      printf 'FAILED\n'
    fi
  done < <(changes)

  say ""
  info "validating sshd config before anything restarts"
  if sshd -t 2>/dev/null; then
    ok "sshd config is valid"
    hint "restart it yourself, from a session you can afford to lose:"
    hint "  sudo systemctl restart sshd     (keep this terminal open until you have a second one)"
  else
    bad "sshd config is INVALID — rolling back that file"
    [[ -f "$BACKUP/sshd_config" ]] && cp -a "$BACKUP/sshd_config" /etc/ssh/sshd_config && ok "restored"
  fi
  say ""
  sysctl -p /etc/sysctl.d/99-hardening.conf >/dev/null 2>&1 && ok "sysctl applied" || warn "sysctl reload failed"
  say ""
  hint "next: $0 after"
}

cmd_after() {
  require_root
  [[ -f "$STATE/score-before" ]] || die "no baseline — you needed to run '$0 before' first, and that is the whole point"
  banner "Re-scoring"
  local before after
  before=$(cat "$STATE/score-before")
  after=$(score_now after)
  echo "$after" > "$STATE/score-after"

  say ""
  printf '  before  %s\n  after   %s\n' "$before" "$after"
  local delta=$(( after - before ))
  if [[ $delta -gt 0 ]]; then ok "+$delta"
  elif [[ $delta -eq 0 ]]; then warn "no change"
  else bad "$delta — something regressed. Look at it before you write it up."; fi

  say ""
  info "warnings resolved"
  if [[ -f "$STATE/lynis-before.dat" && -f "$STATE/lynis-after.dat" ]]; then
    comm -23 \
      <(awk -F'|' '/^warning\[\]=/{print $2}' "$STATE/lynis-before.dat" | sort -u) \
      <(awk -F'|' '/^warning\[\]=/{print $2}' "$STATE/lynis-after.dat"  | sort -u) \
      | head -15 | sed 's/^/  - /'
  fi
  say ""
  info "still outstanding"
  awk -F'|' '/^warning\[\]=/{print "  - " $2}' "$STATE/lynis-after.dat" 2>/dev/null | head -10
  say ""
  cmd_limits
}

cmd_limits() {
  banner "What the score does not measure" "write this paragraph, for THIS host"
  cat <<'TXT'

  The score measures            The score misses
  ────────────────────────────  ──────────────────────────────────────────────
  presence of settings          whether they match YOUR threat model
  compliance with a generic     application-layer security entirely
    baseline
  local, detectable state       network position and segmentation
                                the NOPASSWD: ALL you left because a script
                                  needed it
                                whether anyone is monitoring this host
                                the business process that requires the weak
                                  configuration

  A hardening score is a proxy, not a posture. Improving from 62 to 78 is real
  progress. It is not evidence that the host is secure, and presenting it as
  such is how security theatre gets funded.

  The deliverable asks for a paragraph on what the score does not measure FOR
  THIS HOST. Generic text scores nothing. Name the specific thing you know is
  wrong and the score did not see.

TXT
}

cmd_rollback() {
  require_root
  banner "Rollback"
  [[ -d "$BACKUP" ]] || die "no backup at $BACKUP"
  for f in "$BACKUP"/*; do
    [[ -f "$f" ]] || continue
    case "$(basename "$f")" in
      sshd_config)          cp -a "$f" /etc/ssh/sshd_config && ok "restored sshd_config" ;;
      99-hardening.conf)    cp -a "$f" /etc/sysctl.d/99-hardening.conf && ok "restored sysctl" ;;
      limits.conf)          cp -a "$f" /etc/security/limits.conf && ok "restored limits.conf" ;;
    esac
  done
  # A file we created rather than modified has no backup; remove it.
  [[ -f /etc/sysctl.d/99-hardening.conf && ! -f "$BACKUP/99-hardening.conf" ]] && {
    rm -f /etc/sysctl.d/99-hardening.conf; ok "removed 99-hardening.conf (we created it)"; }
  sshd -t 2>/dev/null && ok "sshd config valid" || bad "sshd config invalid after rollback — check it by hand"
  hint "restart sshd yourself when you are ready"
}

case "${1:-}" in
  before)   shift; cmd_before "$@" ;;
  plan)     shift; cmd_plan "$@" ;;
  apply)    shift; cmd_apply "$@" ;;
  after)    shift; cmd_after "$@" ;;
  rollback) shift; cmd_rollback "$@" ;;
  limits)   shift; cmd_limits "$@" ;;
  ''|-h|--help|help) usage 0 ;;
  *) bad "unknown command: $1"; usage 1 ;;
esac
