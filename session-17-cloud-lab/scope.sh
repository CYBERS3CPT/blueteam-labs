#!/usr/bin/env bash
# scope.sh — the document you write before you touch anything.
#
# In cloud, "I was only testing" is not a defence. The resources belong to a
# provider, the data belongs to somebody else, and the account boundary is the
# only thing between a lab exercise and unauthorised access to a computer system.
#
# So: scope statement, three-part authorisation, rules of engagement, and the
# clause everyone forgets until the morning they need it.
#
#   ./scope.sh new                 build one, by interview
#   ./scope.sh check <file.md>     is this signed, bounded and current?
#   ./scope.sh --explain           why three authorisations, not one
#
# Output is Markdown. Print it, sign it, keep it where you can reach it at 03h00.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
. "$HERE/../lib/common.sh"

explain() {
cat <<'EOF'

  WHY THREE AUTHORISATIONS, NOT ONE

  1. THE CLIENT, IN WRITING
     Someone with the authority to grant it. The person who invited you to the
     meeting frequently is not that person. "Our CTO said it was fine" is an
     anecdote; a signature is a document.

  2. THE CLOUD PROVIDER'S POLICY
     Every major provider publishes what you may test without notifying them,
     and what you may never test at all. Read the current page, not the blog
     post from three years ago that someone linked in a wiki. Denial-of-service
     and load testing are almost universally the excluded categories.

  3. ANY THIRD PARTY IN SCOPE
     The SaaS identity provider. The managed database. The payment processor.
     The client cannot authorise testing against a system they do not own, and
     that is exactly the boundary an over-enthusiastic recon phase crosses first.

  THE CLAUSE EVERYONE FORGETS

     If you discover an active adversary mid-assessment, the engagement stops
     and becomes an incident.

  Agree that BEFORE you start, in the document, with a named phone number.
  Because at 03h00 on a Saturday, in the middle of finding a genuine intruder,
  nobody wants to be negotiating who to call.

  WHAT SCOPE ACTUALLY MEANS IN CLOUD

  Not an IP range. An IP range in cloud is a lie that changes every deploy.
  Scope is: account IDs, subscription IDs, project IDs, regions, resource tags.
  Name the accounts. Everything not named is out of scope, including the
  interesting thing you find that is obviously connected.

EOF
}

bold() { printf '%s%s%s\n' "$C_B" "$*" "$C_RST"; }

ask()  { local p="$1" d="${2:-}" a; read -r -p "  $p${d:+ [$d]}: " a || true; printf '%s' "${a:-$d}"; }
askm() { # multi-line list, blank line ends it
  local p="$1" line out=""
  printf '  %s (blank line to end):\n' "$p" >&2
  while IFS= read -r line; do [ -z "$line" ] && break; out+="- $line"$'\n'; done
  printf '%s' "$out"
}

# An empty section in a scope document is not brevity, it is a gap that reads
# as coverage. Every list either has entries or says so in words.
askm_req() {
  local p="$1" none="$2" out
  out=$(askm "$p")
  [ -n "$out" ] || out="- $none"$'\n'
  printf '%s' "$out"
}

new() {
  banner "Scope and authorisation" "the document you write before you touch anything"
  printf '  Answer as though it will be read back to you by someone unfriendly.\n\n'

  local client engagement window_start window_end
  client=$(ask "Client organisation")
  engagement=$(ask "Engagement name" "Cloud security assessment")

  printf '\n'
  bold "  IN SCOPE — name the accounts, not the addresses"
  printf '  IP ranges in cloud are a lie that changes every deploy.\n'
  local accounts regions tags
  accounts=$(askm_req "Account / subscription / project IDs" \
    "NOT SPECIFIED — this document authorises nothing until this list is filled in")
  regions=$(askm_req "Regions" "NOT SPECIFIED — assume none are in scope")
  tags=$(askm_req "Resource tags that define the boundary (e.g. env=lab)" \
    "None. The account IDs above are the whole boundary.")

  printf '\n'
  bold "  OUT OF SCOPE — be specific, especially about the tempting things"
  local outs
  outs=$(askm_req "Explicitly excluded systems, accounts and techniques" \
    "Nothing beyond the blanket exclusions below.")

  printf '\n'
  bold "  AUTHORISATION — all three"
  local auth_name auth_role auth_date provider provider_url third
  auth_name=$(ask "1. Client authoriser — full name")
  auth_role=$(ask "   their role (must be able to grant this)")
  auth_date=$(ask "   date of their written authorisation (YYYY-MM-DD)")
  provider=$(ask  "2. Cloud provider")
  provider_url=$(ask "   URL of the policy you read, today")
  printf '\n'
  printf '  3. Third parties: the client cannot authorise testing against systems\n'
  printf '     they do not own. Identity provider, managed DB, payment processor.\n'
  third=$(askm_req "Third-party systems in scope and their authorisation status" \
    "None in scope. If a third-party system is reached during testing, it is out of scope and testing against it stops immediately.")

  printf '\n'
  bold "  WINDOW AND CONTACTS"
  window_start=$(ask "Testing window starts (YYYY-MM-DD HH:MM, with timezone)")
  window_end=$(ask   "Testing window ends")
  local poc_us poc_them poc_them_phone escalation
  poc_us=$(ask   "Our point of contact")
  poc_them=$(ask "Their point of contact")
  poc_them_phone=$(ask "Their contact — phone reachable out of hours")
  escalation=$(ask "Who to call if we find an active adversary" "$poc_them")

  local out="scope-$(printf '%s' "$client" | tr '[:upper:] ' '[:lower:]-' | tr -cd 'a-z0-9-').md"

  cat > "$out" <<EOF
# Scope and authorisation — $engagement

**Client:** $client
**Document generated:** $(utc)

---

## 1. In scope

Scope in cloud is defined by account and tag, not by address.
Anything not listed below is out of scope, **including anything interesting
discovered during the engagement that appears to be connected.**

### Accounts / subscriptions / projects
$accounts

### Regions
$regions

### Resource tags
$tags


## 2. Out of scope

$outs

Additionally, and regardless of anything above:

- Denial of service, load testing and resource exhaustion.
- Any technique targeting the provider's own control plane or shared infrastructure.
- Any system owned by a third party without that third party's own authorisation.
- Modification or deletion of production data.
- Social engineering of client staff, unless separately and explicitly authorised.

## 3. Authorisation

### 3.1 Client

| | |
|---|---|
| Authorised by | **$auth_name** |
| Role | $auth_role |
| Written authorisation dated | $auth_date |

Signature: ______________________________    Date: ________________

### 3.2 Cloud provider policy

| | |
|---|---|
| Provider | $provider |
| Policy consulted | $provider_url |
| Date consulted | $(date -u '+%Y-%m-%d') |

The published policy was read on the date above, not recalled from memory.

### 3.3 Third parties

The client cannot authorise testing against systems the client does not own.

$third


## 4. Rules of engagement

- **Testing window:** $window_start to $window_end. Nothing runs outside it.
- **Rate:** enumeration is throttled. An assessment that degrades the service
  has become the incident it was meant to prevent.
- **Data:** no production data is read beyond what proves the finding, none is
  copied off the client's estate, and nothing is retained after the report.
- **Evidence:** every action is logged locally with a UTC timestamp, so the
  client's own detections can be reconciled against our activity.
- **Changes:** nothing is modified without written approval, including
  "temporary" changes.
- **Cleanup:** every resource we create is tagged, inventoried and destroyed.

### 4.1 Stop conditions

Testing stops immediately, and $poc_them is contacted, if:

- A production service degrades.
- We obtain access materially beyond the agreed scope.
- We encounter personal data not anticipated in this document.
- **We find evidence of an active adversary.**

### 4.2 Active adversary clause

> If an active adversary is discovered mid-assessment, the engagement stops and
> becomes an incident.

We do not continue testing. We do not touch the evidence. We do not tip off the
adversary by changing anything. We call **$escalation** on **$poc_them_phone**,
and from that moment the client's incident response process has authority over
ours.

This is agreed here, in advance, precisely so that nobody is negotiating it at
03h00 on a Saturday.

## 5. Contacts

| Role | Name | Reachable |
|---|---|---|
| Assessment lead | $poc_us | during window |
| Client contact | $poc_them | during window |
| Out-of-hours escalation | $escalation | $poc_them_phone |

## 6. Deliverable

A written report: findings with evidence, severity with reasoning, and
remediation that names an owner. Findings are not risks until someone has
described the consequence and accepted or funded it.

---

*Signed copies to be held by both parties before any testing begins.*
EOF

  ok "wrote $out"
  printf '\n'
  printf '  Two things left, and they are the two that matter:\n'
  printf '    1. Get it signed. An unsigned scope document is a wish.\n'
  printf '    2. Put %s on a phone you carry.\n' "$poc_them_phone"
  printf '\n'
}

check() {
  local f="${1:?usage: scope.sh check <file.md>}"
  [ -f "$f" ] || die "no such file: $f"
  local bad=0
  info "Checking $f"

  chk() { # pattern, message
    if grep -qiE "$1" "$f"; then printf '  ok    %s\n' "$2"
    else printf '  MISS  %s\n' "$2"; bad=$((bad+1)); fi
  }

  chk 'account|subscription|project id'   "scope is defined by account, not address"
  chk 'out of scope'                      "explicit exclusions"
  chk 'denial of service'                 "DoS excluded (every provider forbids it)"
  chk 'authorised by'                     "named client authoriser"
  chk 'policy consulted|provider polic'   "provider policy consulted"
  chk 'third part'                        "third-party systems addressed"
  chk 'testing window'                    "bounded testing window"
  chk 'stop condition'                    "stop conditions"
  chk 'active adversary'                  "active adversary clause"
  chk 'out-of-hours|out of hours'         "out-of-hours escalation contact"
  chk '\+?[0-9][0-9 ().-]{7,}'            "a phone number that is actually written down"

  # Placeholders left in the signature block are the classic failure: the
  # document exists, is circulated, and nobody ever signed it.
  if grep -qE '^Signature: _+' "$f"; then
    printf '  NOTE  signature line is still blank in this copy — '
    printf 'an unsigned scope document is a wish\n'
  fi

  # A window that has already closed is worse than no window: it reads as
  # authorisation while granting none.
  local today; today=$(date -u '+%Y-%m-%d')
  local last
  last=$(grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' "$f" | sort | tail -1 || true)
  if [ -n "$last" ] && [ "$last" \< "$today" ]; then
    printf '  WARN  latest date in the document is %s, today is %s — ' "$last" "$today"
    printf 'the window may have closed\n'
    bad=$((bad+1))
  fi

  printf '\n'
  if [ "$bad" -gt 0 ]; then
    warn "$bad item(s) missing. Do not start."
    exit 1
  fi
  ok "Bounded, authorised three ways, and reachable out of hours."
}

case "${1:-}" in
  new)        new ;;
  check)      shift; check "$@" ;;
  --explain)  explain ;;
  *) sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
esac
