#!/usr/bin/env bash
# honeypot-lab.sh — stand up Cowrie, watch people try, turn it into intelligence
#
# A honeypot's value is not that it catches attackers. It is that it has a
# false positive rate of approximately zero: nobody has a legitimate reason to
# SSH into a machine that does not exist. One hit is worth a thousand IDS alerts.
#
#   ./honeypot-lab.sh up              start Cowrie in Docker on 2222
#   ./honeypot-lab.sh down            stop it and keep the logs
#   ./honeypot-lab.sh status          is it alive, and has anyone visited
#   ./honeypot-lab.sh watch           live login attempts
#   ./honeypot-lab.sh report          credentials tried, commands run, ranked
#   ./honeypot-lab.sh iocs            export attacker IPs and hashes for your EWS
#   ./honeypot-lab.sh placement       the design questions, answered badly by most

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

NAME="${HONEYPOT_NAME:-blueteam-cowrie}"
PORT="${HONEYPOT_PORT:-2222}"
DATA="${HONEYPOT_DATA:-$PWD/cowrie-data}"
IMAGE="cowrie/cowrie:latest"

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

cmd_up() {
  need docker "https://docs.docker.com/engine/install/" || exit 1
  banner "Starting Cowrie" "SSH honeypot on port $PORT — NOT on 22, see 'placement'"

  if [[ "$PORT" == "22" ]]; then
    bad "refusing to bind port 22"
    hint "you will lock yourself out of your own lab, and then blame the honeypot"
    exit 1
  fi

  mkdir -p "$DATA"/{log,dl}
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" \
    -p "${PORT}:2222" \
    -v "$DATA/log:/cowrie/cowrie-git/var/log/cowrie" \
    -v "$DATA/dl:/cowrie/cowrie-git/var/lib/cowrie/downloads" \
    "$IMAGE" >/dev/null
  sleep 3
  if docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
    ok "running on port $PORT"
    hint "data in $DATA"
    hint "try it yourself: ssh -p $PORT root@localhost   (password: anything)"
  else
    bad "container exited — logs:"
    docker logs "$NAME" 2>&1 | tail -20 | sed 's/^/     /'
    exit 1
  fi
}

cmd_down() {
  need docker || exit 1
  docker stop "$NAME" >/dev/null 2>&1 && ok "stopped" || warn "was not running"
  docker rm "$NAME"   >/dev/null 2>&1 || true
  hint "logs kept in $DATA — the whole point was to collect them"
}

cmd_status() {
  need docker || exit 1
  banner "Honeypot status"
  if docker ps --format '{{.Names}}\t{{.Status}}' | grep -q "^$NAME"; then
    ok "$(docker ps --format '{{.Status}}' --filter "name=$NAME")"
  else
    warn "not running"
  fi
  local log="$DATA/log/cowrie.json"
  if [[ -f "$log" ]]; then
    local attempts sessions
    attempts=$(grep -c 'cowrie.login' "$log" 2>/dev/null || echo 0)
    sessions=$(grep -c 'cowrie.session.connect' "$log" 2>/dev/null || echo 0)
    info "$sessions connection(s), $attempts login attempt(s)"
    [[ "$sessions" -eq 0 ]] && hint "nobody has visited yet. on a lab network, that is expected."
  else
    warn "no log yet at $log"
  fi
}

cmd_watch() {
  need jq || exit 1
  local log="$DATA/log/cowrie.json"
  [[ -f "$log" ]] || die "no log yet — has anything connected?"
  banner "Live attempts" "ctrl-c to stop"
  tail -F "$log" | jq -r --unbuffered '
    select(.eventid | test("login|command.input|session.connect"))
    | "\(.timestamp[11:19])  \(.src_ip // "-")  \(.eventid | sub("cowrie.";""))  \(.username // "")/\(.password // "")\(.input // "")"'
}

cmd_report() {
  need jq || exit 1
  local log="$DATA/log/cowrie.json"
  [[ -f "$log" ]] || die "no log at $log"
  banner "Honeypot report" "$(utc)"

  info "top source addresses"
  jq -r 'select(.src_ip) | .src_ip' "$log" | sort | uniq -c | sort -rn | head -15 | sed 's/^/  /'

  say ""; info "credentials tried, most popular first"
  hint "this list is the real-world password policy argument, free of charge"
  jq -r 'select(.eventid=="cowrie.login.failed" or .eventid=="cowrie.login.success")
         | "\(.username)/\(.password)"' "$log" | sort | uniq -c | sort -rn | head -20 | sed 's/^/  /'

  say ""; info "commands run after a successful login"
  jq -r 'select(.eventid=="cowrie.command.input") | .input' "$log" 2>/dev/null \
    | sort | uniq -c | sort -rn | head -20 | sed 's/^/  /' || say "  (none)"

  say ""; info "files downloaded onto the honeypot"
  if [[ -d "$DATA/dl" ]] && [[ -n "$(ls -A "$DATA/dl" 2>/dev/null)" ]]; then
    sha256 "$DATA"/dl/* 2>/dev/null | sed 's/^/  /'
    warn "these are live samples. treat them as Session 3 material, not as files."
  else
    say "  (none)"
  fi
}

cmd_iocs() {
  need jq || exit 1
  local log="$DATA/log/cowrie.json"
  [[ -f "$log" ]] || die "no log at $log"
  local out="honeypot-iocs-$(stamp).csv"
  {
    echo "type,value,first_seen_utc,count,source"
    jq -r 'select(.src_ip) | "\(.src_ip)\t\(.timestamp)"' "$log" \
      | sort | awk -F'\t' '{if(!(seen[$1]++)) first[$1]=$2; cnt[$1]++}
                            END{for(i in cnt) printf "ip,%s,%s,%d,cowrie\n", i, first[i], cnt[i]}' \
      | sort -t, -k4 -rn
    if [[ -d "$DATA/dl" ]]; then
      for f in "$DATA"/dl/*; do
        [[ -f "$f" ]] || continue
        printf 'sha256,%s,%s,1,cowrie-download\n' "$(sha256 "$f" | awk '{print $1}')" "$(utc)"
      done
    fi
  } > "$out"
  ok "wrote $out ($(($(wc -l < "$out") - 1)) indicator(s))"
  hint "feed this into the Session 5 EWS, or straight into a Suricata/Sigma rule"
  hint "and note the confidence: a honeypot hit is A1. Very little else is."
}

cmd_placement() {
  banner "Where to put it" "the questions people skip, and then wonder why it caught nothing"
  cat <<'TXT'

  1. INTERNAL, NOT EXTERNAL.
     An internet-facing honeypot catches the entire internet and tells you
     nothing you did not already know. One on your internal server VLAN, on an
     address nobody has a reason to touch, catches lateral movement. That is
     the alert worth waking up for.

  2. IT MUST NOT BE REACHABLE FROM ITSELF.
     Egress from the honeypot goes nowhere. If it is compromised — and the
     whole design assumes it will be — it must not become a pivot into your
     network. Write the firewall rule before you start the container.

  3. GIVE IT A BORING, PLAUSIBLE NAME.
     "honeypot-01" is a name that tells the intruder to leave. "bkp-fs-03" is
     a name that tells them to look closer.

  4. ALERT ON EVERY SINGLE PACKET.
     This is the one control in the whole course where a single event is worth
     an immediate page. There is no tuning to do, because there is no
     legitimate traffic. If you find yourself tuning it, it is in the wrong place.

  5. DECIDE THE LEGAL POSITION FIRST.
     You are recording other people's activity, and on an internal network some
     of those people work for you. Interception, employee monitoring and data
     retention all apply. Get it in writing before, not after.

  6. WRITE DOWN WHO CHECKS IT.
     An unmonitored honeypot is a compromised host you are paying to run.

TXT
}

case "${1:-}" in
  up)        shift; cmd_up "$@" ;;
  down)      shift; cmd_down "$@" ;;
  status)    shift; cmd_status "$@" ;;
  watch)     shift; cmd_watch "$@" ;;
  report)    shift; cmd_report "$@" ;;
  iocs)      shift; cmd_iocs "$@" ;;
  placement) shift; cmd_placement "$@" ;;
  ''|-h|--help|help) usage 0 ;;
  *) bad "unknown command: $1"; usage 1 ;;
esac
