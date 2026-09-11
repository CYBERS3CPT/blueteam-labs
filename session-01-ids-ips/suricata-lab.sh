#!/usr/bin/env bash
# suricata-lab.sh — get Suricata from "installed" to "actually detecting things"
#
# Suricata will happily run for weeks with a broken rule file, an interface that
# does not exist, and zero alerts, and it will never once mention this to you.
# This script asks the awkward questions on your behalf.
#
#   ./suricata-lab.sh check                 sanity-check the installation
#   ./suricata-lab.sh rules                 update rulesets and validate config
#   ./suricata-lab.sh new-rule <name>       scaffold a custom rule, with the sid
#   ./suricata-lab.sh test-rule <file>      validate one rule file, nothing else
#   ./suricata-lab.sh replay <file.pcap>    run against a pcap, show the alerts
#   ./suricata-lab.sh watch [iface]         live capture, alerts as they land
#   ./suricata-lab.sh stats                 what has fired, ranked

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

SURICATA_CFG="${SURICATA_CFG:-/etc/suricata/suricata.yaml}"
LOCAL_RULES="${LOCAL_RULES:-/etc/suricata/rules/local.rules}"
EVE_LOG="${EVE_LOG:-/var/log/suricata/eve.json}"
# Custom rules start at 1000000. Anything below that belongs to somebody else
# and they will not thank you for the collision.
SID_BASE=1000000

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

cmd_check() {
  banner "Suricata pre-flight" "the five things that are wrong when nothing alerts"
  need suricata "sudo apt install -y suricata" || exit 1

  info "version"
  suricata -V | sed 's/^/     /'

  info "configuration parses"
  if suricata -T -c "$SURICATA_CFG" -l /tmp >/dev/null 2>&1; then
    ok "config and rules load cleanly"
  else
    bad "config test failed — the detail:"
    suricata -T -c "$SURICATA_CFG" -l /tmp 2>&1 | tail -20 | sed 's/^/     /'
    exit 1
  fi

  info "capture interface"
  local iface
  iface=$(awk '/^af-packet:/{f=1} f && /interface:/{print $3; exit}' "$SURICATA_CFG" 2>/dev/null || true)
  if [[ -z "$iface" ]]; then
    warn "no af-packet interface found in $SURICATA_CFG"
  elif ip link show "$iface" >/dev/null 2>&1; then
    ok "interface '$iface' exists"
    # Promiscuous mode is the difference between seeing the network and seeing
    # the three packets that were addressed to you personally.
    ip link show "$iface" | grep -q PROMISC \
      && ok "promiscuous mode is on" \
      || warn "'$iface' is not in promiscuous mode — you will only see your own traffic"
  else
    bad "interface '$iface' does not exist on this host"
  fi

  info "HOME_NET"
  local home
  home=$(awk -F'"' '/HOME_NET:/{print $2; exit}' "$SURICATA_CFG" 2>/dev/null || true)
  if [[ "$home" == *"192.168.0.0/16"* && "$home" == *"10.0.0.0/8"* ]]; then
    warn "HOME_NET is still the shipped default: $home"
    hint "set it to your actual network, or every rule with \$EXTERNAL_NET is lying to you"
  else
    ok "HOME_NET: ${home:-<unset>}"
  fi

  info "rules present"
  local n
  n=$(find /etc/suricata/rules /var/lib/suricata/rules -name '*.rules' 2>/dev/null | wc -l | tr -d ' ')
  [[ "$n" -gt 0 ]] && ok "$n rule file(s)" || warn "no rule files — run: $0 rules"

  info "eve.json is being written"
  if [[ -f "$EVE_LOG" ]]; then
    local age=$(( $(date +%s) - $(stat -c %Y "$EVE_LOG" 2>/dev/null || stat -f %m "$EVE_LOG") ))
    [[ $age -lt 300 ]] && ok "last written ${age}s ago" \
                       || warn "last written ${age}s ago — is Suricata actually running?"
  else
    warn "$EVE_LOG does not exist yet"
  fi
}

cmd_rules() {
  banner "Rule update" "this is the slow one — start it and go make coffee"
  need suricata-update "sudo apt install -y suricata-update" || exit 1
  require_root
  suricata-update update-sources
  suricata-update
  info "validating the result before you restart anything"
  suricata -T -c "$SURICATA_CFG" -l /tmp && ok "rules load" || die "rules do not load — do NOT restart"
  hint "then: sudo systemctl restart suricata"
}

cmd_new_rule() {
  local name="${1:-}"; [[ -n "$name" ]] || die "usage: $0 new-rule <short-name>"
  # Pick the next free sid so you stop guessing and stop colliding.
  local next=$SID_BASE
  if [[ -f "$LOCAL_RULES" ]]; then
    local highest
    highest=$(grep -oE 'sid:[0-9]+' "$LOCAL_RULES" | cut -d: -f2 | sort -n | tail -1 || true)
    [[ -n "$highest" ]] && next=$((highest + 1))
  fi
  cat <<RULE

# ---- paste into $LOCAL_RULES ----
# $name
# Written $(utc). Rev 1 because you will edit it, and the rev must move when you do.
alert http \$HOME_NET any -> \$EXTERNAL_NET any ( \\
    msg:"BLUETEAM $name"; \\
    flow:established,to_server; \\
    http.host; content:"example.invalid"; \\
    classtype:trojan-activity; \\
    sid:$next; rev:1; \\
)
# ---------------------------------

RULE
  hint "next free sid in $LOCAL_RULES is $next"
  hint "test it with: $0 test-rule $LOCAL_RULES"
}

cmd_test_rule() {
  local f="${1:-$LOCAL_RULES}"
  [[ -f "$f" ]] || die "no such file: $f"
  banner "Validating $f"
  local tmp; tmp=$(mktemp -d)
  if suricata -T -c "$SURICATA_CFG" -S "$f" -l "$tmp" 2>&1 | tee "$tmp/out" | grep -qi 'error'; then
    bad "rule file has errors:"
    grep -i 'error' "$tmp/out" | sed 's/^/     /'
    rm -rf "$tmp"; exit 1
  fi
  ok "$(grep -cE '^\s*(alert|drop|reject|pass)' "$f") rule(s), all valid"
  rm -rf "$tmp"
}

cmd_replay() {
  local pcap="${1:-}"; [[ -f "$pcap" ]] || die "usage: $0 replay <file.pcap>"
  need suricata || exit 1
  need jq "sudo apt install -y jq" || exit 1
  local out; out=$(outdir "out/replay-$(stamp)")
  banner "Replaying $(basename "$pcap")" "offline mode: nothing touches the network"
  suricata -r "$pcap" -c "$SURICATA_CFG" -l "$out" >/dev/null 2>&1 || warn "suricata exited non-zero"
  local n; n=$(jq -sr '[.[] | select(.event_type=="alert")] | length' "$out/eve.json" 2>/dev/null || echo 0)
  if [[ "$n" -eq 0 ]]; then
    warn "zero alerts"
    hint "that is a result, not a failure — but check the pcap actually contains what you think"
  else
    ok "$n alert(s)"
    jq -r 'select(.event_type=="alert")
           | "\(.timestamp[0:19])  \(.src_ip):\(.src_port // "-") -> \(.dest_ip):\(.dest_port // "-")  \(.alert.signature)"' \
       "$out/eve.json" | sort | uniq -c | sort -rn | head -40 | sed 's/^/  /'
  fi
  say ""
  hint "full output in $out"
}

cmd_watch() {
  local iface="${1:-}"
  need jq || exit 1
  [[ -f "$EVE_LOG" ]] || die "$EVE_LOG not found — is Suricata running?"
  banner "Live alerts" "ctrl-c to stop; this only shows alerts, not the other 99% of eve.json"
  [[ -n "$iface" ]] && hint "(interface filter is cosmetic here — Suricata decides what it captures)"
  tail -F "$EVE_LOG" | jq -r --unbuffered '
    select(.event_type=="alert")
    | "\(.timestamp[11:19])  \(.alert.severity)  \(.src_ip) -> \(.dest_ip)  \(.alert.signature)"'
}

cmd_stats() {
  need jq || exit 1
  [[ -f "$EVE_LOG" ]] || die "$EVE_LOG not found"
  banner "What has actually fired" "ranked, because the top three are usually 95% of the volume"
  jq -r 'select(.event_type=="alert") | .alert.signature' "$EVE_LOG" 2>/dev/null \
    | sort | uniq -c | sort -rn | head -25 | sed 's/^/  /'
  say ""
  info "top talkers"
  jq -r 'select(.event_type=="alert") | .src_ip' "$EVE_LOG" 2>/dev/null \
    | sort | uniq -c | sort -rn | head -10 | sed 's/^/  /'
  say ""
  hint "if one signature is 90% of your alerts, that is a tuning job, not a threat"
}

case "${1:-}" in
  check)      shift; cmd_check "$@" ;;
  rules)      shift; cmd_rules "$@" ;;
  new-rule)   shift; cmd_new_rule "$@" ;;
  test-rule)  shift; cmd_test_rule "$@" ;;
  replay)     shift; cmd_replay "$@" ;;
  watch)      shift; cmd_watch "$@" ;;
  stats)      shift; cmd_stats "$@" ;;
  ''|-h|--help|help) usage 0 ;;
  *) bad "unknown command: $1"; usage 1 ;;
esac
