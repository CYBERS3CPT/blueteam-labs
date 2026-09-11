#!/usr/bin/env bash
# firewall-review.sh — read a ruleset the way an attacker would
#
# Firewalls are rarely wrong. They are frequently right about a policy that
# stopped being true two years ago. This reads nftables, iptables or pf and
# flags the patterns that mean the ruleset has drifted from its intent.
#
#   ./firewall-review.sh                 auto-detect and review the live ruleset
#   ./firewall-review.sh --file rules.txt
#   ./firewall-review.sh --explain       what each finding means, and why
#
# Read-only. It never loads, flushes or modifies a rule. It cannot: it does not
# call anything that writes.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
set +o errexit

FILE=""; EXPLAIN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --file) FILE="$2"; shift 2 ;;
    --explain) EXPLAIN=1; shift ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown: $1" ;;
  esac
done

N=0
finding() { bad "$1"; [[ -n "${2:-}" ]] && hint "$2"; N=$((N+1)); }

cmd_explain() {
  banner "What each finding means"
  cat <<'TXT'

  DEFAULT POLICY ACCEPT
    A default-accept chain is not a firewall, it is a suggestion. Every rule
    you write is a special case, and the one you forget is open. Default deny
    means the forgotten case fails closed, which is the only direction a
    forgotten case should fail.

  ANY/ANY ACCEPT
    Usually added at 23h00 to make something work, with every intention of
    tightening it tomorrow. There is no record of tomorrow arriving.

  MANAGEMENT PORTS FROM ANYWHERE
    SSH, RDP, database ports and admin interfaces open to 0.0.0.0/0. The
    argument is always "it needs a password". So does everything in every
    credential dump.

  RULES AFTER A CATCH-ALL
    Rules below a terminating accept or drop never evaluate. They look like
    policy in the file and do nothing on the wire, which is the worst possible
    combination: the reviewer sees a control that does not exist.

  NO LOGGING ON THE DROP
    A drop you cannot see is a drop you cannot investigate. The first question
    in every firewall incident is "was it blocked?" and the second is "how many
    times?". Both need a log rule.

  ESTABLISHED WITHOUT RELATED
    Breaks FTP, some VPNs and ICMP error handling in ways that look like an
    application fault and get "fixed" by someone adding an any/any rule.

  COMMENTS ABSENT
    A rule with no comment is a rule nobody can safely delete, which is why
    rulesets only ever grow. The comment is the control, not the courtesy.

TXT
  exit 0
}
[[ $EXPLAIN -eq 1 ]] && cmd_explain

# ── load ────────────────────────────────────────────────────────────────────
RULES=""; KIND=""
if [[ -n "$FILE" ]]; then
  [[ -f "$FILE" ]] || die "no such file: $FILE"
  RULES=$(cat "$FILE")
  KIND=$(grep -qE '^\s*(table|chain)\s' <<< "$RULES" && echo nft || \
         grep -qE '^-A|^:INPUT' <<< "$RULES" && echo iptables || echo pf)
elif command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1 \
     && [[ -n "$(nft list ruleset 2>/dev/null)" ]]; then
  KIND=nft; RULES=$(nft list ruleset 2>/dev/null)
elif command -v iptables-save >/dev/null 2>&1; then
  KIND=iptables; RULES=$(iptables-save 2>/dev/null; ip6tables-save 2>/dev/null)
elif command -v pfctl >/dev/null 2>&1; then
  KIND=pf; RULES=$(pfctl -sr 2>/dev/null)
else
  die "no ruleset found. Pass one with --file, or run this with sudo."
fi
[[ -n "$RULES" ]] || die "the ruleset is empty — which is itself a finding, if this host is meant to have one"

banner "Firewall review" "$KIND · $(wc -l <<< "$RULES" | tr -d ' ') line(s)"

# ── default policy ──────────────────────────────────────────────────────────
info "default policy"
case "$KIND" in
  nft)
    grep -oE 'type filter hook (input|forward|output)[^;]*policy [a-z]+' <<< "$RULES" \
      | sed 's/^/  /' || say "  (none declared — nft defaults to accept)"
    grep -qE 'hook input.*policy accept' <<< "$RULES" && \
      finding "input chain policy is ACCEPT" "default-deny is the only direction a forgotten rule should fail"
    ;;
  iptables)
    grep -E '^:(INPUT|FORWARD|OUTPUT)' <<< "$RULES" | sed 's/^/  /'
    grep -qE '^:INPUT ACCEPT' <<< "$RULES" && \
      finding "INPUT policy is ACCEPT" "every rule is now a special case, and the forgotten one is open"
    grep -qE '^:FORWARD ACCEPT' <<< "$RULES" && \
      finding "FORWARD policy is ACCEPT" "this host will route between whatever it can reach"
    ;;
  pf)
    grep -qE '^\s*block\s+(all|in all)' <<< "$RULES" && ok "block-by-default present" \
      || finding "no default block rule" "pf evaluates last-match; without a leading block, anything unmatched passes"
    ;;
esac

# ── any/any ─────────────────────────────────────────────────────────────────
info "permissive rules"
ANY=$(grep -inE '(accept|pass).*(0\.0\.0\.0/0|::/0|\bany\b.*\bany\b)' <<< "$RULES" \
      | grep -viE 'ct state (established|related)|conntrack|lo\b|loopback' | head -12)
if [[ -n "$ANY" ]]; then
  sed 's/^/  /' <<< "$ANY"
  finding "$(wc -l <<< "$ANY" | tr -d ' ') rule(s) accept from anywhere" \
          "each of these was added to make something work, with every intention of tightening it"
else ok "none"; fi

# ── management ports ────────────────────────────────────────────────────────
info "management and database ports exposed"
declare -A PORTS=( [22]=SSH [23]=telnet [3389]=RDP [5900]=VNC [3306]=MySQL [5432]=PostgreSQL
                   [1433]=MSSQL [27017]=MongoDB [6379]=Redis [9200]=Elasticsearch
                   [2375]=docker-api [2379]=etcd [11211]=memcached [5601]=Kibana )
for p in "${!PORTS[@]}"; do
  hit=$(grep -iE "(dport|port)[ =]+$p\b" <<< "$RULES" | grep -iE 'accept|pass' | head -2)
  [[ -z "$hit" ]] && continue
  # No source is not "restricted": an iptables rule without -s, or an nft rule
  # without saddr, matches every address there is. Absence of a constraint is
  # the constraint being absent.
  if grep -qE '0\.0\.0\.0/0|::/0|\bany\b' <<< "$hit" \
     || ! grep -qE '(-s |--source|saddr|\bfrom\b)' <<< "$hit"; then
    finding "${PORTS[$p]} ($p) accepted from anywhere" "$(head -1 <<< "$hit" | xargs)"
  else
    ok "${PORTS[$p]} ($p) is restricted by source"
  fi
done
# Unauthenticated by design, and routinely exposed anyway.
for p in 2375 6379 11211 9200 2379; do
  grep -qE "(dport|port)[ =]+$p\b" <<< "$RULES" && \
    warn "port $p appears at all — ${PORTS[$p]} has no authentication by default"
done

# ── unreachable rules ───────────────────────────────────────────────────────
info "rules that never evaluate"
# Find a terminating catch-all, then see whether anything follows it in the
# same chain. Those lines are policy in the file and nothing on the wire.
CATCH=$(grep -nE '^\s*-A (INPUT|FORWARD)\s+-j (DROP|REJECT|ACCEPT)\s*$|^\s*(drop|accept|reject)\s*$|^\s*block\s+all\s*$' \
        <<< "$RULES" | head -1 | cut -d: -f1)
if [[ -n "$CATCH" ]]; then
  AFTER=$(tail -n +$((CATCH+1)) <<< "$RULES" | grep -cE '^\s*(-A|accept|drop|pass|block|tcp|udp)' || echo 0)
  if [[ "$AFTER" -gt 0 ]]; then
    finding "$AFTER rule(s) appear after a catch-all at line $CATCH" \
            "they look like policy and do nothing. Which is worse than absent."
  else ok "nothing follows the catch-all"; fi
else
  warn "no explicit catch-all found — the chain relies entirely on its default policy"
fi

# ── logging ─────────────────────────────────────────────────────────────────
info "logging"
if grep -qiE '\blog\b|LOG|nflog|ulog' <<< "$RULES"; then
  ok "$(grep -ciE '\blog\b|LOG|nflog' <<< "$RULES") rule(s) log"
  grep -qiE 'log.*(drop|reject|block)|(drop|reject|block).*log' <<< "$RULES" \
    || finding "logging exists but not on the drops" "the first question in a firewall incident is 'was it blocked?'"
else
  finding "nothing logs" "a drop you cannot see is a drop you cannot investigate"
fi

# ── state ───────────────────────────────────────────────────────────────────
info "connection tracking"
if grep -qiE 'state (NEW,)?(RELATED,)?ESTABLISHED|ct state' <<< "$RULES"; then
  grep -qiE 'related' <<< "$RULES" && ok "established AND related" \
    || finding "established without related" "breaks FTP, some VPNs and ICMP errors — in ways that look like an application fault"
else
  warn "no stateful rule found — is this a stateless ruleset on purpose?"
fi

# ── comments ────────────────────────────────────────────────────────────────
info "comments"
TOTAL=$(grep -cE '^\s*(-A|accept|drop|pass|block|tcp|udp)' <<< "$RULES")
CMT=$(grep -cE 'comment|#' <<< "$RULES")
printf '  %s rule(s), %s carry a comment\n' "$TOTAL" "$CMT"
if [[ "$TOTAL" -gt 5 && "$CMT" -lt $((TOTAL / 3)) ]]; then
  finding "most rules have no comment" \
          "a rule nobody can safely delete is why rulesets only ever grow"
fi

say ""
rule
[[ $N -eq 0 ]] && ok "no findings" || bad "$N finding(s)"
hint "$0 --explain  for what each one means and why it matters"
say ""
cat <<'NEXT'
  Two questions this script cannot answer, and you have to:

    - Which of these rules is still needed? Anything with no comment and no
      owner is a candidate for removal, and removal is the only thing that
      makes a ruleset smaller.
    - What does the CLOUD firewall say? Host rules are half the story. The
      security group, NSG or VPC ACL in front of this machine is the other
      half, and it is frequently the permissive one.
NEXT
exit 0
