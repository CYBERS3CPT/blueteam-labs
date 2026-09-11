#!/usr/bin/env bash
# deprovision-check.sh — disabling the account is step one of thirteen
#
# A disabled account with a live refresh token is not deprovisioned. Neither is
# one whose SSH key is still in six authorized_keys files, or whose personal
# access token is still in a CI pipeline. This walks the thirteen steps and, for
# the ones it can check, actually checks them.
#
#   ./deprovision-check.sh checklist            all thirteen, for the report
#   ./deprovision-check.sh keycloak <user>      sessions, tokens, credentials, roles
#   ./deprovision-check.sh local <user>         SSH keys, cron, sudo, processes
#   ./deprovision-check.sh ssh-keys <user>      where their key still is
#   ./deprovision-check.sh report <user>        everything, as a findings list
#
# Read-only. It reports; it never revokes. Revocation is a deliberate act by
# somebody who read the report.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
set +o errexit

KC_URL="${KC_URL:-http://localhost:8080}"
KC_REALM="${KC_REALM:-blueteam}"
KC_ADMIN="${KC_ADMIN:-admin}"
KC_PW="${KC_ADMIN_PW:-admin}"

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

OPEN=0
gap()  { bad "$1"; [[ -n "${2:-}" ]] && hint "$2"; OPEN=$((OPEN+1)); }
done_() { ok "$1"; }

kc_token() {
  curl -s -d "grant_type=password" -d "client_id=admin-cli" \
       -d "username=$KC_ADMIN" -d "password=$KC_PW" \
       "$KC_URL/realms/master/protocol/openid-connect/token" 2>/dev/null \
    | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}
kc_get() {
  local t="$1" path="$2"
  curl -s -H "Authorization: Bearer $t" "$KC_URL/admin/realms/$KC_REALM/$path" 2>/dev/null
}

cmd_checklist() {
  banner "Deprovisioning" "step one of thirteen"
  cat <<'TXT'

  CREDENTIALS AND SESSIONS
    [ ]  1. Account disabled in the authoritative directory
    [ ]  2. Active sessions terminated, across every application
    [ ]  3. Refresh tokens revoked — they outlive the account
    [ ]  4. Personal access tokens and API keys revoked
             (repositories, cloud, CI, monitoring, ticketing)
    [ ]  5. SSH keys removed from authorized_keys EVERYWHERE
    [ ]  6. MFA devices deregistered
    [ ]  7. Shared credentials the person knew, rotated

  ACCOUNTS, ASSETS AND EVIDENCE
    [ ]  8. SaaS applications with local accounts, checked individually
             (this is what SCIM exists to avoid, and why its absence is a risk)
    [ ]  9. Enrolled devices unenrolled or wiped
    [ ] 10. Physical badge deactivated — the Session 12 convergence
    [ ] 11. Service accounts they owned, reassigned to a NAMED owner
    [ ] 12. Mailbox and data handover, per the retention policy
    [ ] 13. Evidence preserved BEFORE any deletion

  Steps 3, 5 and 11 are the ones that survive step 1 and get forgotten.

  Step 11 deserves its own sentence. An unowned service account does not stop
  working when its owner leaves; it stops being anybody's responsibility, which
  is worse. Reassign it the same day, or disable it and find out what breaks
  while you still have someone to ask.

TXT
}

cmd_keycloak() {
  local user="${1:-}"; [[ -n "$user" ]] || die "usage: $0 keycloak <username>"
  need curl || exit 1
  banner "Keycloak: $user" "$KC_URL realm=$KC_REALM"
  local t; t=$(kc_token)
  [[ -n "$t" ]] || die "could not authenticate to Keycloak"

  local u; u=$(kc_get "$t" "users?username=$user&exact=true")
  local uid; uid=$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' <<< "$u" | head -1)
  [[ -n "$uid" ]] || die "no such user: $user"

  # 1. enabled
  if grep -q '"enabled":false' <<< "$u"; then done_ "1. account disabled"
  else gap "1. account is still ENABLED" "start here"; fi

  # 2. sessions
  local s; s=$(kc_get "$t" "users/$uid/sessions")
  local ns; ns=$(grep -o '"id"' <<< "$s" | wc -l | tr -d ' ')
  if [[ "$ns" -eq 0 ]]; then done_ "2. no active sessions"
  else gap "2. $ns active session(s) still open" \
           "disabling the account does not end a session that already exists"; fi

  # 3. offline (refresh) tokens — the classic survivor
  local o; o=$(kc_get "$t" "users/$uid/offline-sessions/account")
  local no; no=$(grep -o '"id"' <<< "$o" | wc -l | tr -d ' ')
  if [[ "$no" -eq 0 ]]; then done_ "3. no offline sessions on the account client"
  else gap "3. $no offline session(s) — refresh tokens outlive the account" \
           "check every client, not just 'account'"; fi

  # 6. MFA
  local cr; cr=$(kc_get "$t" "users/$uid/credentials")
  local mfa; mfa=$(grep -o '"type":"\(otp\|webauthn[^"]*\)"' <<< "$cr" | wc -l | tr -d ' ')
  if [[ "$mfa" -eq 0 ]]; then done_ "6. no MFA credentials registered"
  else warn "6. $mfa MFA credential(s) still registered"
       hint "harmless while disabled; a loose end if the account is ever re-enabled"; fi

  # 11. roles that suggest ownership of something
  local rr; rr=$(kc_get "$t" "users/$uid/role-mappings/realm")
  local roles; roles=$(grep -o '"name":"[^"]*"' <<< "$rr" | cut -d'"' -f4 | grep -v '^default-roles' | tr '\n' ' ')
  [[ -n "$roles" ]] && { warn "11. still holds realm roles: $roles"
                         hint "anything privileged here may be attached to a service somebody depends on"; }

  say ""
  hint "Keycloak covers steps 1, 2, 3 and 6. The other nine live elsewhere,"
  hint "which is exactly why deprovisioning fails: no single system owns it."
}

cmd_ssh_keys() {
  local user="${1:-}"; [[ -n "$user" ]] || die "usage: $0 ssh-keys <username-or-key-comment>"
  banner "SSH keys mentioning '$user'" "step 5, the one that survives everything else"
  local found=0
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    if grep -qi "$user" "$f" 2>/dev/null; then
      bad "$f"
      grep -in "$user" "$f" 2>/dev/null | cut -c1-110 | sed 's/^/     /'
      found=$((found+1))
    fi
  done < <(find /home /root /etc/ssh /srv /opt -maxdepth 5 -name 'authorized_keys*' -type f 2>/dev/null)

  if [[ $found -eq 0 ]]; then
    done_ "no authorized_keys on THIS host mention '$user'"
    hint "this host. The key is in a file on every host they ever logged into,"
    hint "and this script cannot see those. Configuration management can."
  else
    gap "$found file(s) on this host still trust a key for '$user'" \
        "an SSH key is a credential that survives account deletion entirely"
  fi

  say ""
  info "git and CI remotes worth checking by hand"
  cat <<'TXT'
     - deploy keys on every repository they touched
     - personal access tokens in CI variables and in webhooks
     - keys in cloud provider key pairs, and in instance metadata
     - anything in a secrets manager with their name on it
TXT
}

cmd_local() {
  local user="${1:-}"; [[ -n "$user" ]] || die "usage: $0 local <username>"
  banner "Local host: $user"

  if id "$user" >/dev/null 2>&1; then
    local shell; shell=$(getent passwd "$user" | cut -d: -f7)
    if [[ "$shell" =~ (nologin|false)$ ]]; then done_ "shell is $shell"
    else gap "shell is $shell — the account can still log in" "usermod -s /usr/sbin/nologin $user"; fi
    local lock; lock=$(passwd -S "$user" 2>/dev/null | awk '{print $2}')
    [[ "$lock" == "L" ]] && done_ "password locked" || gap "password not locked (state: ${lock:-?})"
  else
    done_ "no local account called '$user'"
  fi

  local g; g=$(id -nG "$user" 2>/dev/null)
  [[ -n "$g" ]] && { info "groups: $g"
    for d in sudo wheel docker lxd adm disk shadow; do
      grep -qw "$d" <<< "$g" && gap "still in '$d'" "that group is effectively root"
    done; }

  crontab -l -u "$user" >/dev/null 2>&1 && gap "has a crontab" "crontab -l -u $user" || done_ "no crontab"
  grep -rl "\b$user\b" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | while read -r f; do
    gap "named in $f" "a sudoers entry outlives the account it names"
  done
  local procs; procs=$(pgrep -u "$user" 2>/dev/null | wc -l | tr -d ' ')
  [[ "${procs:-0}" -gt 0 ]] && gap "$procs process(es) still running as $user" "pgrep -au $user"
  local sys; sys=$(grep -rl "User=$user" /etc/systemd/system 2>/dev/null | head -5)
  [[ -n "$sys" ]] && gap "systemd unit(s) run as this user" "$(tr '\n' ' ' <<< "$sys")"
}

cmd_report() {
  local user="${1:-}"; [[ -n "$user" ]] || die "usage: $0 report <username>"
  cmd_keycloak "$user"; say ""
  cmd_ssh_keys "$user"; say ""
  cmd_local "$user"; say ""
  rule
  if [[ $OPEN -eq 0 ]]; then
    ok "nothing outstanding that this script can see"
    hint "which is not the same as complete. Nine of the thirteen steps are"
    hint "in systems this script cannot reach. Walk the checklist by hand."
  else
    bad "$OPEN item(s) outstanding"
  fi
  say ""
  hint "$0 checklist   for the full thirteen"
}

case "${1:-}" in
  checklist) shift; cmd_checklist "$@" ;;
  keycloak)  shift; cmd_keycloak "$@" ;;
  ssh-keys)  shift; cmd_ssh_keys "$@" ;;
  local)     shift; cmd_local "$@" ;;
  report)    shift; cmd_report "$@" ;;
  ''|-h|--help|help) usage 0 ;;
  *) bad "unknown command: $1"; usage 1 ;;
esac
