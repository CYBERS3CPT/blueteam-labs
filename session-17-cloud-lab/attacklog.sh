#!/usr/bin/env bash
# attacklog.sh — log the attack as you run it, not afterwards from memory
#
# The Session 7 discipline, pointed at your own attack. Every action, with a UTC
# timestamp, the exact command, the result, and — the column that matters — what
# it SHOULD have generated in the logs. Block 3 is comparing this file against
# the audit log, and the comparison is only as good as this file.
#
#   ./attacklog.sh init <engagement> <operator>
#   ./attacklog.sh add <stage> "<command>" "<result>" ["<expected event>"]
#   ./attacklog.sh run <stage> -- <command...>      run it AND log it
#   ./attacklog.sh note "<free text>"
#   ./attacklog.sh show
#   ./attacklog.sh gaps                             the comparison template
#
# Stages: foothold enumerate escalate persist data exfil

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

LOG="${ATTACK_LOG:-./attack-log.csv}"
META="${LOG%.csv}.meta"
STAGES="foothold enumerate escalate persist data exfil"

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
check_stage() {
  [[ " $STAGES " == *" $1 "* ]] || die "stage must be one of: $STAGES"
}

cmd_init() {
  local eng="${1:-}" op="${2:-}"
  [[ -n "$eng" && -n "$op" ]] || die "usage: $0 init <engagement> <operator>"
  [[ -f "$LOG" ]] && die "$LOG already exists — appending to an existing log is the point"
  echo "utc,stage,command,result,expected_event,api_calls" > "$LOG"
  cat > "$META" <<M
engagement: $eng
operator:   $op
started:    $(utc)
scope:      (paste the scope statement reference here)
M
  ok "started $LOG"
  hint "log every action AS YOU DO IT. Reconstructed logs are how the comparison fails."
}

cmd_add() {
  [[ -f "$LOG" ]] || die "no $LOG — run: $0 init <engagement> <operator>"
  local stage="${1:-}" cmd="${2:-}" result="${3:-}" expect="${4:-}"
  [[ -n "$stage" && -n "$cmd" ]] || die "usage: $0 add <stage> \"<command>\" \"<result>\" [\"<expected event>\"]"
  check_stage "$stage"
  printf '%s,%s,"%s","%s","%s",\n' "$(utc)" "$stage" \
    "${cmd//\"/\"\"}" "${result//\"/\"\"}" "${expect//\"/\"\"}" >> "$LOG"
  ok "logged [$stage] $(utc_short)"
}

cmd_run() {
  [[ -f "$LOG" ]] || die "no $LOG — run: $0 init first"
  local stage="${1:-}"; shift || true
  check_stage "$stage"
  [[ "${1:-}" == "--" ]] && shift
  [[ $# -gt 0 ]] || die "usage: $0 run <stage> -- <command...>"

  local cmd="$*" t0 t1 out rc
  t0=$(utc)
  info "[$stage] $cmd"
  set +o errexit
  out=$("$@" 2>&1); rc=$?
  set -o errexit
  t1=$(utc)

  # Counting API calls matters: enumeration is the loudest stage in the whole
  # chain and the least monitored, and "412 calls in ninety seconds" is a far
  # better finding than "I enumerated the account".
  local calls=""
  if [[ "$cmd" == *aws* || "$cmd" == *cloudfox* || "$cmd" == *pacu* ]]; then
    calls=$(grep -ciE 'describe|list|get' <<< "$out" || true)
  fi

  printf '%s,%s,"%s","exit %s",%s,%s\n' "$t0" "$stage" "${cmd//\"/\"\"}" "$rc" "" "${calls:-}" >> "$LOG"
  printf '%s\n' "$out" | head -25 | sed 's/^/     /'
  [[ $(printf '%s\n' "$out" | wc -l) -gt 25 ]] && hint "(output truncated in the terminal; it is not in the log either — paste what matters)"
  say ""
  [[ $rc -eq 0 ]] && ok "exit 0 at $t1" || warn "exit $rc at $t1  <- a failure is a finding too: which control stopped you?"
  [[ -n "$calls" && "$calls" -gt 0 ]] && hint "~$calls read-only API call(s) in that one command"
  return 0
}

cmd_note() {
  [[ -f "$LOG" ]] || die "no $LOG"
  printf '%s,note,"%s","","",\n' "$(utc)" "${1//\"/\"\"}" >> "$LOG"
  ok "noted"
}

cmd_show() {
  [[ -f "$LOG" ]] || die "no $LOG"
  banner "Attack log" "$(head -3 "$META" 2>/dev/null | tr '\n' ' ')"
  column -s, -t < "$LOG" 2>/dev/null | cut -c1-150 | sed 's/^/  /' || cat "$LOG"
  say ""
  local n; n=$(($(wc -l < "$LOG") - 1))
  info "$n entry/entries"
  for s in $STAGES; do
    local c; c=$(grep -c ",$s," "$LOG" || true)
    printf '  %-12s %s\n' "$s" "$c"
    [[ "$c" -eq 0 ]] && hint "  nothing logged for '$s' yet"
  done
}

cmd_gaps() {
  [[ -f "$LOG" ]] || die "no $LOG"
  local out="detection-gaps-$(stamp).csv"
  {
    echo "utc,stage,action,expected_event,found_in_log,event_name,latency_s,existing_rule,new_rule_written,notes"
    tail -n +2 "$LOG" | while IFS= read -r line; do
      local utcv stage cmd
      utcv=$(cut -d, -f1 <<< "$line")
      stage=$(cut -d, -f2 <<< "$line")
      cmd=$(cut -d, -f3 <<< "$line" | tr -d '"' | cut -c1-60)
      [[ "$stage" == "note" ]] && continue
      printf '%s,%s,"%s","",,,,,,\n' "$utcv" "$stage" "$cmd"
    done
  } > "$out"
  ok "wrote $out"
  say ""
  cat <<'TXT'
  Fill it in with the audit log open beside you. For every row:

    found_in_log      yes / partial / NO
    event_name        exact. "CreatePolicyVersion", not "an IAM event"
    latency_s         how long until it was queryable. Response time depends on it.
    existing_rule     would anything you already have have fired?
    new_rule_written  if not, write one now, while it is fresh

  Every row where found_in_log is NO is a detection you do not have. That
  column, filtered to NO, is the single most valuable artefact you produce in
  this entire course — more than the attack, more than the report.

  And expect this pattern. It repeats every time:
    - enumeration was invisible
    - escalation was logged perfectly, and nobody would have looked
    - persistence was the quietest stage of all
    - data access was not logged at all
    - exfiltration by sharing produced one line, and it did not say "exfiltration"
TXT
}

case "${1:-}" in
  init) shift; cmd_init "$@" ;;
  add)  shift; cmd_add "$@" ;;
  run)  shift; cmd_run "$@" ;;
  note) shift; cmd_note "$@" ;;
  show) shift; cmd_show "$@" ;;
  gaps) shift; cmd_gaps "$@" ;;
  ''|-h|--help|help) usage 0 ;;
  *) bad "unknown command: $1"; usage 1 ;;
esac
