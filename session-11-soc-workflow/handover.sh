#!/usr/bin/env bash
# handover.sh — the note that stops an investigation restarting from zero
#
# Handover is where incidents get lost. Not because anyone is careless, but
# because the outgoing analyst knows forty things and writes down six of them,
# and the incoming one spends ninety minutes rediscovering the other thirty-four.
#
#   ./handover.sh new [INC-ID]      interactive; asks the questions in order
#   ./handover.sh blank [INC-ID]    just the template, fill it in yourself
#   ./handover.sh clock <deadline>  how long is left on a regulatory clock
#
# The sections are not decorative. "Open questions / not yet checked" is the one
# that saves the most time and the one people leave empty, because writing down
# what you did not do feels like an admission. It is the opposite.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

ask() {  # ask <prompt> [default]
  local prompt="$1" default="${2:-}" reply
  if [[ -n "$default" ]]; then
    read -r -p "  $prompt [$default]: " reply || true
    printf '%s' "${reply:-$default}"
  else
    read -r -p "  $prompt: " reply || true
    printf '%s' "$reply"
  fi
}

ask_multi() {  # collect lines until an empty one
  local prompt="$1" line out=""
  say "  $prompt (blank line to finish)"
  while true; do
    read -r -p "    - " line || break
    [[ -z "$line" ]] && break
    out+="  - $line"$'\n'
  done
  printf '%s' "$out"
}

cmd_clock() {
  local deadline="${1:-}"
  [[ -n "$deadline" ]] || die "usage: $0 clock 'YYYY-MM-DD HH:MM'"
  local d now left
  d=$(date -u -d "$deadline" +%s 2>/dev/null || date -u -j -f "%Y-%m-%d %H:%M" "$deadline" +%s 2>/dev/null) \
    || die "could not parse '$deadline' — try 'YYYY-MM-DD HH:MM'"
  now=$(date -u +%s); left=$(( d - now ))
  if (( left < 0 )); then
    bad "EXPIRED $(( -left / 3600 ))h $(( (-left % 3600) / 60 ))m ago"
  elif (( left < 7200 )); then
    bad "$(( left / 3600 ))h $(( (left % 3600) / 60 ))m remaining"
  elif (( left < 21600 )); then
    warn "$(( left / 3600 ))h $(( (left % 3600) / 60 ))m remaining"
  else
    ok "$(( left / 3600 ))h $(( (left % 3600) / 60 ))m remaining"
  fi
  hint "the clock started when you became AWARE, not when you confirmed."
}

render() {
  cat <<HO
# Handover note — ${INC:-INC-____}

| | |
|---|---|
| Severity | ${SEV:-P_} |
| From | ${FROM:-____} |
| To | ${TO:-____} |
| Time (UTC) | $(utc) |

## Situation

${SIT:-One paragraph. Plain language. What is happening, as you would say it out
loud to someone who has just walked in. No jargon that needs a second question.}

## Confirmed facts

${FACTS:-  - fact, with source and timestamp (UTC)
  - fact, with source and timestamp (UTC)}

## Working hypotheses

*Labelled as hypotheses, with confidence. If it is not a fact it goes here, and
the next analyst gets to disagree with it — which is the point.*

${HYPS:-  - hypothesis (confidence: low / medium / high)}

## Actions taken

| Time (UTC) | Action | By | Result |
|---|---|---|---|
${ACTIONS:-|  |  |  |  |}

## Current state

| | |
|---|---|
| Contained | ${CONTAINED:-what is contained, and explicitly what is NOT} |
| Systems affected | ${AFFECTED:-____} |
| Systems believed unaffected | ${UNAFFECTED:-____ (and how you know)} |
| Evidence collected | ${EVIDENCE:-what, and where it is} |

## Next steps

*Priority order, with an owner each. "Someone should" is not an owner.*

${NEXT:-  1. ____ (owner: ____)}

## Open questions / not yet checked

*The honest list. This section saves more time than every other section combined,
and it is the one people leave blank because writing down what you did not do
feels like an admission. It is the opposite: it is the difference between the
next analyst continuing your work and starting it again.*

${OPEN:-  - ____}

## Clocks running

| Clock | Started (UTC) | Expires (UTC) | Notified? |
|---|---|---|---|
${CLOCKS:-| RGPD Art. 33 (72h from awareness) |  |  |  |
| NIS2 early warning (24h) |  |  |  |
| NIS2 notification (72h) |  |  |  |}

---
*Generated $(utc). Two moments need their own timestamp and their own owner:
**incident declared** and **containment decided**. Both start clocks — one legal,
one operational — and both are usually reconstructed afterwards, badly.*
HO
}

cmd_blank() {
  INC="${1:-}"
  local f="handover-${INC:-$(stamp)}.md"
  render > "$f"
  ok "wrote $f"
}

cmd_new() {
  INC="${1:-}"
  banner "Handover note" "answer what you can; blank is fine, wrong is not"
  say ""
  INC=$(ask "Incident ID" "${INC:-INC-$(date -u +%Y%m%d)-01}")
  SEV=$(ask "Severity (P1..P4)" "P3")
  FROM=$(ask "From (you)")
  TO=$(ask "To")
  say ""
  SIT=$(ask "Situation, one sentence")
  say ""
  FACTS=$(ask_multi "Confirmed facts — each with source and UTC timestamp")
  HYPS=$(ask_multi "Working hypotheses — add (confidence: low/medium/high)")
  say ""
  CONTAINED=$(ask "What is contained, and what is NOT")
  AFFECTED=$(ask "Systems affected")
  UNAFFECTED=$(ask "Systems believed unaffected (and how you know)")
  EVIDENCE=$(ask "Evidence collected, and where it is")
  say ""
  NEXT=$(ask_multi "Next steps, priority order, with an owner each")
  say ""
  say "  Now the section that matters most."
  OPEN=$(ask_multi "Open questions / not yet checked")
  [[ -z "$OPEN" ]] && {
    warn "you left 'not yet checked' empty"
    hint "nobody has ever checked everything. an empty list reads as either"
    hint "overconfidence or a rushed handover, and both cost the next analyst time."
    OPEN=$(ask_multi "try again — even one line")
  }

  local f="handover-${INC}.md"
  render > "$f"
  say ""
  ok "wrote $f"
  hint "read it back as though you were the person receiving it at 02h00."
  hint "if a sentence needs you present to make sense, rewrite it."
}

case "${1:-}" in
  new)   shift; cmd_new "$@" ;;
  blank) shift; cmd_blank "$@" ;;
  clock) shift; cmd_clock "$@" ;;
  ''|-h|--help|help) usage 0 ;;
  *) bad "unknown command: $1"; usage 1 ;;
esac
