#!/usr/bin/env bash
# keycloak-lab.sh — a realm you can break on purpose, and then fix
#
#   ./keycloak-lab.sh up                 run Keycloak in dev mode
#   ./keycloak-lab.sh realm              create the blueteam realm, client, users, group
#   ./keycloak-lab.sh endpoints          the URLs worth knowing
#   ./keycloak-lab.sh review             the five findings, checked against YOUR realm
#   ./keycloak-lab.sh export             partial export (config, not credentials)
#   ./keycloak-lab.sh down
#
# It never touches the master realm for applications. Compromising master
# compromises everything, which is why it exists separately and why the wizard
# that puts your app there is wrong.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

NAME="${KC_NAME:-blueteam-keycloak}"
PORT="${KC_PORT:-8080}"
REALM="${KC_REALM:-blueteam}"
ADMIN="${KC_ADMIN:-admin}"
ADMIN_PW="${KC_ADMIN_PW:-admin}"
BASE="http://localhost:${PORT}"

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
kc() { docker exec "$NAME" /opt/keycloak/bin/kcadm.sh "$@"; }

cmd_up() {
  need docker || exit 1
  banner "Keycloak" "dev mode — no TLS, no persistence, no illusions"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" -p "${PORT}:8080" \
    -e KEYCLOAK_ADMIN="$ADMIN" -e KEYCLOAK_ADMIN_PASSWORD="$ADMIN_PW" \
    quay.io/keycloak/keycloak:latest start-dev >/dev/null || die "docker run failed"
  info "waiting for it to answer"
  for i in $(seq 1 40); do
    curl -sf "$BASE/realms/master/.well-known/openid-configuration" >/dev/null 2>&1 && { say ""; ok "up at $BASE"; break; }
    printf '.'; sleep 2
    [[ $i -eq 40 ]] && { say ""; die "did not come up — docker logs $NAME"; }
  done
  [[ "$ADMIN_PW" == "admin" ]] && warn "admin password is 'admin'. In a lab that is a choice; anywhere else it is a finding."
  hint "next: $0 realm"
}

cmd_realm() {
  need docker || exit 1
  banner "Creating realm '$REALM'" "never the master realm — that is the administrative one"
  kc config credentials --server "$BASE" --realm master --user "$ADMIN" --password "$ADMIN_PW" >/dev/null \
    || die "could not authenticate to master"

  kc create realms -s realm="$REALM" -s enabled=true >/dev/null 2>&1 && ok "realm created" || warn "realm already exists"

  # Public client, authorisation code + PKCE, and a PRECISE redirect URI. The
  # wildcard version is the first finding in the review section, so we do not
  # ship it as the default.
  kc create clients -r "$REALM" \
    -s clientId=my-app -s enabled=true -s publicClient=true \
    -s 'redirectUris=["http://localhost:3000/callback"]' \
    -s 'webOrigins=["http://localhost:3000"]' \
    -s standardFlowEnabled=true \
    -s directAccessGrantsEnabled=false \
    -s 'attributes={"pkce.code.challenge.method":"S256"}' >/dev/null 2>&1 \
    && ok "client 'my-app' (public, code+PKCE, exact redirect URI)" || warn "client exists"

  kc create groups -r "$REALM" -s name=staff >/dev/null 2>&1 && ok "group 'staff'" || warn "group exists"

  for u in ana bruno; do
    kc create users -r "$REALM" -s username="$u" -s enabled=true -s emailVerified=false \
       -s email="$u@example.invalid" >/dev/null 2>&1 && ok "user '$u'" || warn "user '$u' exists"
    kc set-password -r "$REALM" --username "$u" --new-password "Lab-$u-pass!" >/dev/null 2>&1 || true
  done

  say ""
  ok "realm ready"
  hint "admin console: $BASE/admin  ($ADMIN / $ADMIN_PW)"
  hint "note emailVerified=false on both users. That is deliberate — see 'review'."
  hint "next: $0 endpoints, then log in and watch the flow in devtools"
}

cmd_endpoints() {
  banner "Endpoints for realm '$REALM'"
  cat <<E
  discovery   $BASE/realms/$REALM/.well-known/openid-configuration
  authorize   $BASE/realms/$REALM/protocol/openid-connect/auth
  token       $BASE/realms/$REALM/protocol/openid-connect/token
  jwks        $BASE/realms/$REALM/protocol/openid-connect/certs
  logout      $BASE/realms/$REALM/protocol/openid-connect/logout
  userinfo    $BASE/realms/$REALM/protocol/openid-connect/userinfo

  A browser flow you can actually watch (devtools, network tab, preserve log):

  $BASE/realms/$REALM/protocol/openid-connect/auth?client_id=my-app\\
&response_type=code&scope=openid%20profile%20email\\
&redirect_uri=http://localhost:3000/callback\\
&code_challenge_method=S256&code_challenge=<S256 of your verifier>

E
  hint "reading one real flow is worth more than any diagram, including the one in the slides"
  hint "decode the resulting id_token with ../session-13-keycloak/jwt-decode.py"
}

cmd_review() {
  need docker || exit 1
  need jq || exit 1
  banner "Defensive review of realm '$REALM'" "the five findings, checked against what you built"
  kc config credentials --server "$BASE" --realm master --user "$ADMIN" --password "$ADMIN_PW" >/dev/null \
    || die "could not authenticate"

  local n=0
  local clients; clients=$(kc get clients -r "$REALM" 2>/dev/null)

  info "1. wildcard redirect URIs"
  local wild
  wild=$(echo "$clients" | jq -r '.[] | select(.redirectUris[]? | test("\\*")) | .clientId' 2>/dev/null | sort -u)
  if [[ -n "$wild" ]]; then
    bad "wildcard redirect URI on: $(echo "$wild" | tr '\n' ' ')"; n=$((n+1))
    hint "authorisation code exfiltration to an attacker-controlled path"
  else ok "none"; fi

  info "2. direct grant (ROPC)"
  local ropc
  ropc=$(echo "$clients" | jq -r '.[] | select(.directAccessGrantsEnabled==true) | .clientId' 2>/dev/null)
  if [[ -n "$ropc" ]]; then
    bad "direct grant enabled on: $(echo "$ropc" | tr '\n' ' ')"; n=$((n+1))
    hint "the application handles the password, so MFA is bypassed entirely. Turn it off."
  else ok "disabled everywhere"; fi

  info "3. token lifetimes"
  local r; r=$(kc get "realms/$REALM" 2>/dev/null)
  local at; at=$(echo "$r" | jq -r '.accessTokenLifespan // 300')
  printf '  access token  %ss\n' "$at"
  if [[ "$at" -gt 900 ]]; then
    bad "access token lifespan ${at}s (> 15 min)"; n=$((n+1))
    hint "a stolen token stays useful for that long, and revocation does not reach it"
  else ok "within a defensible range"; fi

  info "4. brute force protection"
  if [[ "$(echo "$r" | jq -r '.bruteForceProtected')" == "true" ]]; then ok "enabled"
  else bad "brute force detection disabled"; n=$((n+1)); fi

  info "5. full scope allowed"
  local full
  full=$(echo "$clients" | jq -r '.[] | select(.fullScopeAllowed==true) | .clientId' 2>/dev/null)
  if [[ -n "$full" ]]; then
    warn "fullScopeAllowed on: $(echo "$full" | tr '\n' ' ')"
    hint "every role the user holds ends up in the token for every client. Narrow it."
  else ok "none"; fi

  info "bonus: email verification"
  local unver; unver=$(kc get users -r "$REALM" 2>/dev/null | jq -r '.[] | select(.emailVerified==false) | .username')
  [[ -n "$unver" ]] && { warn "unverified email on: $(echo "$unver" | tr '\n' ' ')"
                         hint "if anything in your app trusts the 'email' claim, that is an account-takeover path"; }

  info "bonus: admin events"
  local ae; ae=$(kc get "realms/$REALM/events/config" 2>/dev/null | jq -r '.adminEventsEnabled')
  if [[ "$ae" == "true" ]]; then ok "admin events logged"
  else
    bad "admin events NOT logged"; n=$((n+1))
    hint "an attacker who adds a redirect URI to your client has built a durable"
    hint "back door, and it generates exactly one log line. If you keep it."
  fi

  say ""
  rule
  [[ $n -eq 0 ]] && ok "no high findings" || bad "$n finding(s) to fix and record"
  hint "the deliverable wants three: what it was, why it is risky, what you changed it to"
}

cmd_export() {
  need docker || exit 1
  local f="realm-${REALM}-$(stamp).json"
  kc config credentials --server "$BASE" --realm master --user "$ADMIN" --password "$ADMIN_PW" >/dev/null
  kc get "realms/$REALM" > "$f" 2>/dev/null || die "export failed"
  ok "wrote $f"
  warn "this is CONFIGURATION, not credentials"
  hint "it is not a backup: you cannot restore users' passwords from it."
  hint "it is also not harmless: client secrets and mappings live in there."
}

cmd_down() { need docker || exit 1; docker rm -f "$NAME" >/dev/null 2>&1 && ok "removed" || warn "not running"; }

case "${1:-}" in
  up)        shift; cmd_up "$@" ;;
  realm)     shift; cmd_realm "$@" ;;
  endpoints) shift; cmd_endpoints "$@" ;;
  review)    shift; cmd_review "$@" ;;
  export)    shift; cmd_export "$@" ;;
  down)      shift; cmd_down "$@" ;;
  ''|-h|--help|help) usage 0 ;;
  *) bad "unknown command: $1"; usage 1 ;;
esac
