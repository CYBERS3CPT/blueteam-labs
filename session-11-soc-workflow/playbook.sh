#!/usr/bin/env bash
# playbook.sh — write the containment section before you need it
#
# A playbook is not a runbook. A runbook says "isolate a host in the EDR" and
# lists the clicks. A playbook says who decides, what it costs, who gets told,
# and which clock starts. The second is the hard one, which is why most
# organisations have the first and call it the second.
#
#   ./playbook.sh new <scenario>      interactive; asks the hard questions in order
#   ./playbook.sh blank <scenario>    the template
#   ./playbook.sh matrix              a severity matrix with worked examples
#   ./playbook.sh check <file.md>     does it answer the questions that matter?
#   ./playbook.sh scenarios           the ones worth writing first

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
ask() { local r; read -r -p "  $1: " r || true; printf '%s' "${r:-${2:-}}"; }
ask_multi() {
  say "  $1 (blank line to finish)"
  local line out=""
  while true; do read -r -p "    - " line || break; [[ -z "$line" ]] && break; out+="- $line"$'\n'; done
  printf '%s' "$out"
}

cmd_scenarios() {
  banner "Worth writing first" "in this order, because this is the order they happen"
  cat <<'TXT'

  1. SUSPECTED RANSOMWARE
     The one everyone writes. Write it anyway, because the containment cost
     section is where you discover nobody has agreed who can stop production.

  2. COMPROMISED CREDENTIAL / IMPOSSIBLE TRAVEL
     The most common real incident. The whole playbook hinges on whether you
     have standing authority to disable an account, and at what seniority that
     authority stops.

  3. DATA EXPOSURE (public bucket, misdirected email, leak site)
     Because the regulatory clock starts here and the technical work is small.

  4. PHISHING WITH CONFIRMED CLICKS
     Volume incident. Needs a fast path, or it eats the whole team.

  5. INSIDER / DEPARTING EMPLOYEE
     Needs HR and Legal in the room from minute one, and the technical steps
     are the easy part.

  6. THIRD-PARTY / SUPPLIER BREACH NOTIFICATION
     You have no telemetry, no access, and a clock. Write this one before it
     arrives on a Friday.

TXT
}

cmd_matrix() {
  local f="severity-matrix.md"
  cat > "$f" <<'M'
# Severity matrix

Impact × urgency. Both defined, with **worked examples**, before the incident —
an abstract definition gets argued about at 23h00 and an example does not.

|                  | Low urgency | Medium urgency | High urgency |
|------------------|-------------|----------------|--------------|
| **High impact**  | P2          | P1             | **P1**       |
| **Medium impact**| P3          | P2             | P1           |
| **Low impact**   | P4          | P3             | P2           |

## Impact

| Level | Means | Worked example |
|---|---|---|
| High | Regulated data, safety, or a business process stops | |
| Medium | One team blocked, or non-regulated data of limited scope | |
| Low | Single user, no data, no process | |

## Urgency

| Level | Means | Worked example |
|---|---|---|
| High | Spreading now, adversary active, or data leaving | |
| Medium | Contained but not eradicated | |
| Low | Historic, or fully contained | |

## Worked examples — fill at least four

| Scenario | Impact | Urgency | Priority | Why |
|---|---|---|---|---|
| Ransomware on one workstation, contained, no shares reached | | | | |
| Public bucket with personal data of 40,000 subjects | | | | |
| Phishing click, no credential entered, EDR blocked the payload | | | | |
| Domain admin credential used from an unrecognised address, now | | | | |

---

**Everything cannot be a P1.** If most things land on P1, that is not a matrix,
it is an anxiety — and it means the impact definitions are too broad. Fix the
definitions, not the scores.
M
  ok "wrote $f"
  hint "the worked examples are the deliverable. The grid is just a grid."
}

render() {
cat <<PB
# Playbook — ${SCEN:-<scenario>}

| | |
|---|---|
| Owner | ${OWNER:-____} |
| Last reviewed (UTC) | $(utc) |
| Review cadence | ${CADENCE:-annually, and after every use} |

## Trigger conditions

*What makes this playbook the right one. Be specific enough that an L1 at 03h00
picks it without asking.*

${TRIGGER:-- ____}

## Roles

| Role | Who | Authority |
|---|---|---|
| Incident lead | ${LEAD:-____} | declares the incident, owns the timeline |
| Technical lead | ____ | executes containment |
| Communications | ____ | internal and external messaging |
| Legal / DPO | ____ | regulatory assessment |
| **Decision-maker for containment** | ${DECIDER:-____} | **and who deputises at 03h00** |

## Triage steps

1. Read the rule that fired. Not the alert title — the logic.
2. Verify against the raw event, not the summary.
3. Asset context: owner, criticality, exposure, data classification.
4. User context: role, normal hours, normal locations, recent changes.
5. Pivot: same host, same user, same window, same destination.
6. Is the adversary active NOW? This drives urgency more than anything else.
7. Declare or close — and record the time and the reason either way.

## Containment options, with their business cost

*The section that makes this a playbook. "Isolate the host" is an instruction.
"Isolate the host; the user loses access for about four hours; the adversary will
likely notice" is a decision somebody can actually make.*

| Option | Business cost | Adversary learns? | Who authorises | Reversible? |
|---|---|---|---|---|
${CONTAIN:-| Isolate the host | | yes | | yes |
| Disable the account | | yes | | yes |
| Block the C2 domain | loses visibility | yes | | yes |
| Monitor and observe | accepts ongoing risk | no | **named person** | n/a |
| Full network isolation | business stops | yes | | slowly |}

## Communication and regulatory clocks

| Audience | Trigger | Deadline | Owner |
|---|---|---|---|
| SOC manager, IT lead | incident declared | immediate | |
| Legal and DPO | any suspicion of personal data | immediate | |
| Executive | P1, or any clock starting | 1 hour | |
| Supervisory authority | personal data breach | **72 h from awareness** | |
| CNCS | NIS2 significant incident | **24 h early warning, 72 h notification** | |
| Data subjects | high risk to rights and freedoms | without undue delay | |

*The clocks start at **aware**, not at **confirmed**. Waiting for certainty is
how organisations miss the deadline.*

## Evidence to preserve, before containment destroys it

${EVIDENCE:-- Memory, if the host is to be isolated or rebuilt
- Volatile state: connections, processes, sessions
- Relevant logs, exported OUT of the affected environment
- The alert itself, and the rule version that produced it}

## Closure criteria

*What has to be true to close this. "It stopped" is not a criterion.*

${CLOSURE:-- Root cause identified, or explicitly recorded as undetermined
- All affected assets identified and remediated
- Persistence checked for, specifically
- Detection written or tuned for the next occurrence
- Post-mortem scheduled}

## After

- Blameless post-mortem within 5 working days
- Three improvements, each owned, each with a date
- **Where we got lucky** — the section people omit and the most valuable one

---
*Generated $(utc). Test this playbook before you need it: read it aloud to
someone who was not in the room and see how many questions they ask.*
PB
}

cmd_blank() { SCEN="${1:-scenario}"; local f="playbook-$(tr -cd '[:alnum:]-' <<< "${SCEN// /-}").md"; render > "$f"; ok "wrote $f"; }

cmd_new() {
  SCEN=$(ask "Scenario (e.g. suspected ransomware)" "${1:-}")
  banner "Playbook — $SCEN" "the questions in the order they get skipped"
  OWNER=$(ask "Owner of this playbook")
  CADENCE=$(ask "Review cadence" "annually, and after every use")
  say ""
  TRIGGER=$(ask_multi "Trigger conditions — specific enough for an L1 at 03h00")
  say ""
  LEAD=$(ask "Incident lead")
  DECIDER=$(ask "Who decides containment")
  local deputy; deputy=$(ask "  ...and who deputises at 03h00")
  [[ -n "$deputy" ]] && DECIDER="$DECIDER (out of hours: $deputy)"
  [[ -z "$deputy" ]] && { warn "no out-of-hours deputy named"
                          hint "the incident that needs a containment decision at 03h00 is the"
                          hint "one where nobody can reach the person named in the playbook." ; }
  say ""
  say "  Containment options. For each, the COST is the part that matters."
  CONTAIN=$(ask_multi "One line each: option | cost | adversary learns? | authoriser | reversible?" \
            | sed 's/^- /| /; s/$/ |/')
  say ""
  EVIDENCE=$(ask_multi "Evidence to preserve BEFORE containment destroys it")
  say ""
  CLOSURE=$(ask_multi "Closure criteria — 'it stopped' is not one")

  local f="playbook-$(tr -cd '[:alnum:]-' <<< "${SCEN// /-}").md"
  render > "$f"
  say ""
  ok "wrote $f"
  hint "now: $0 check $f"
}

cmd_check() {
  local f="${1:-}"; [[ -f "$f" ]] || die "usage: $0 check <playbook.md>"
  banner "Checking $(basename "$f")" "the questions that decide whether it works at 03h00"
  local n=0
  q() {  # q <pattern> <what> <why>
    if grep -qiE "$1" "$f"; then ok "$2"
    else bad "$2"; hint "$3"; n=$((n+1)); fi
  }
  q 'trigger'                    "trigger conditions present"        "an L1 cannot pick the right playbook without them"
  q 'contain'                    "containment section present"       "this is the section that makes it a playbook"
  q 'cost|business impact'       "containment COSTS stated"          "an option without its cost is an instruction, not a decision"
  q '72 ?h|72 hours|Art\. ?33|NIS2'  "regulatory clocks named"       "the clock starts at aware, and it needs to be in the document"
  q 'closure|close|criteria'     "closure criteria present"          "'it stopped' is not a criterion"
  q 'evidence|preserve|memory'   "evidence preservation before containment" "containment destroys the thing you needed"
  q '03h00|out of hours|deputis|deputy|on-call' "out-of-hours authority named" \
      "the decision you need at 03h00 is the one nobody is awake to make"

  # Placeholders left in a playbook are worse than blanks: they read as complete.
  local ph; ph=$(grep -c '____' "$f" || true)
  say ""
  if [[ "$ph" -gt 0 ]]; then
    warn "$ph unfilled placeholder(s)"
    hint "a playbook with ____ where a name should be reads as complete and is not"
    n=$((n+1))
  fi
  rule
  [[ $n -eq 0 ]] && ok "it answers the questions" || bad "$n gap(s)"
  say ""
  hint "final test: read it aloud to someone who was not in the room."
  hint "count their questions. That is your real score."
  [[ $n -eq 0 ]]
}

case "${1:-}" in
  new)       shift; cmd_new "$@" ;;
  blank)     shift; cmd_blank "$@" ;;
  matrix)    shift; cmd_matrix "$@" ;;
  check)     shift; cmd_check "$@" ;;
  scenarios) shift; cmd_scenarios "$@" ;;
  ''|-h|--help|help) usage 0 ;;
  *) bad "unknown command: $1"; usage 1 ;;
esac
