#!/usr/bin/env bash
# soc-stack.sh — Wazuh + TheHive + Cortex, and the checks that catch the
# three ways this goes wrong on the night.
#
#   ./soc-stack.sh preflight     RAM, disk, ports, vm.max_map_count
#   ./soc-stack.sh pull          pull the images (do this in the break)
#   ./soc-stack.sh up            bring the stack up
#   ./soc-stack.sh status        is it healthy, and are agents reporting
#   ./soc-stack.sh agent-cmd     print the agent enrolment command
#   ./soc-stack.sh down          stop, keep the data
#   ./soc-stack.sh nuke          stop and delete the data. Asks twice.
#
# The three failures, in order of frequency: not enough RAM; vm.max_map_count
# too low for the indexer; and an agent that installed fine and is not reporting.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

WAZUH_DIR="${WAZUH_DIR:-./wazuh-docker/single-node}"
MIN_RAM_GB=8
MIN_DISK_GB=25

usage() { sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

cmd_preflight() {
  banner "Pre-flight" "run this BEFORE the block, not during it"
  local fail=0

  info "memory"
  local ram
  ram=$(free -g 2>/dev/null | awk '/^Mem:/{print $2}' || sysctl -n hw.memsize 2>/dev/null | awk '{printf "%d", $1/1024/1024/1024}')
  if [[ "${ram:-0}" -ge $MIN_RAM_GB ]]; then ok "${ram} GB"
  else bad "${ram:-?} GB — the indexer alone wants 4, and it will OOM silently"; fail=1
       hint "pair up with someone who has the RAM. You still do all of Block 3."; fi

  info "disk"
  local disk; disk=$(df -BG . 2>/dev/null | awk 'NR==2{gsub("G","",$4); print $4}' || echo '?')
  if [[ "${disk:-0}" -ge $MIN_DISK_GB ]]; then ok "${disk} GB free"
  else bad "${disk:-?} GB free — want ${MIN_DISK_GB}+"; fail=1; fi

  info "vm.max_map_count"
  # The indexer is Elasticsearch-shaped and it will refuse to start below 262144.
  # The error it prints is not obviously about this.
  local mmc; mmc=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
  if [[ "$mmc" -ge 262144 ]]; then ok "$mmc"
  else bad "$mmc — too low"; fail=1
       hint "sudo sysctl -w vm.max_map_count=262144"
       hint "persist it: echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf"; fi

  info "docker"
  if need docker; then
    docker info >/dev/null 2>&1 && ok "daemon reachable" || { bad "daemon not reachable"; fail=1; }
    docker compose version >/dev/null 2>&1 && ok "compose v2" \
      || { bad "docker compose v2 not available"; fail=1; }
  else fail=1; fi

  info "ports"
  for p in 443 1514 1515 9000 9001 9200; do
    if (command -v ss >/dev/null && ss -ltn 2>/dev/null | grep -q ":$p ") || \
       (command -v lsof >/dev/null && lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1); then
      warn "port $p already in use"
    fi
  done
  ok "port check done"

  say ""
  [[ $fail -eq 0 ]] && ok "clear to proceed" || { bad "fix the above first"; exit 1; }
}

cmd_pull() {
  need docker || exit 1
  banner "Pulling images" "several GB — this is a break activity, not a block activity"
  if [[ ! -d "$WAZUH_DIR" ]]; then
    info "cloning wazuh-docker"
    git clone --depth 1 -b v4.x https://github.com/wazuh/wazuh-docker.git || die "clone failed"
  fi
  ( cd "$WAZUH_DIR" && docker compose pull ) || warn "wazuh pull had problems"
  docker pull strangebee/thehive:5.2 || warn "thehive pull failed"
  docker pull thehiveproject/cortex:latest || warn "cortex pull failed"
  ok "done — now you can bring it up in seconds instead of minutes"
}

cmd_up() {
  need docker || exit 1
  [[ -d "$WAZUH_DIR" ]] || die "no $WAZUH_DIR — run: $0 pull"
  banner "Starting the stack"
  ( cd "$WAZUH_DIR"
    [[ -f config/wazuh_indexer_ssl_certs/root-ca.pem ]] || {
      info "generating certificates (once)"
      docker compose -f generate-indexer-certs.yml run --rm generator
    }
    docker compose up -d ) || die "compose up failed"
  info "waiting for the dashboard (the indexer takes a minute or two)"
  for i in $(seq 1 40); do
    if curl -sk --max-time 3 https://localhost:443 >/dev/null 2>&1; then
      ok "dashboard up: https://localhost"
      break
    fi
    printf '.'; sleep 5
    [[ $i -eq 40 ]] && { say ""; warn "still not answering — check: docker compose logs"; }
  done
  say ""
  hint "default credentials are in the compose file. Change them. Yes, in a lab."
  hint "then: $0 agent-cmd"
}

cmd_agent_cmd() {
  local ip
  ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}') \
    || ip=$(ipconfig getifaddr en0 2>/dev/null) || ip="<manager-ip>"
  banner "Agent enrolment" "manager appears to be $ip"
  cat <<AGENT

  Debian / Ubuntu  (victim-lin)
    curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.0-1_amd64.deb
    sudo WAZUH_MANAGER='$ip' dpkg -i ./wazuh-agent_4.9.0-1_amd64.deb
    sudo systemctl daemon-reload
    sudo systemctl enable --now wazuh-agent

  Windows  (victim-win, elevated PowerShell)
    msiexec.exe /i wazuh-agent-4.9.0-1.msi /q WAZUH_MANAGER='$ip'
    NET START WazuhSvc

  Then verify from HERE, not from the agent:
    $0 status

AGENT
  warn "an agent that installed but is not reporting is the most common failure"
  hint "if it does not appear: firewall on 1514/1515, or the manager IP is wrong"
}

cmd_status() {
  need docker || exit 1
  banner "Stack status"
  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' \
    | grep -Ei 'wazuh|thehive|cortex|cassandra|elastic|NAMES' | sed 's/^/  /' || warn "nothing running"

  say ""
  info "agents"
  local mgr
  mgr=$(docker ps --format '{{.Names}}' | grep -m1 'wazuh.manager' || true)
  if [[ -n "$mgr" ]]; then
    if docker exec "$mgr" /var/ossec/bin/agent_control -l 2>/dev/null | sed 's/^/  /'; then :; else
      warn "could not query agent_control"
    fi
    say ""
    hint "Active = reporting. Never connected = the enrolment did not reach the manager."
    hint "Disconnected = it did, once, and then stopped. Check the agent's own log."
  else
    warn "wazuh manager container not found"
  fi

  say ""
  info "endpoints"
  for u in "https://localhost:443|Wazuh dashboard" "http://localhost:9000|TheHive" "http://localhost:9001|Cortex"; do
    local url="${u%%|*}" name="${u##*|}"
    if curl -sk --max-time 3 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null | grep -qE '^[234]'; then
      ok "$name  $url"
    else
      warn "$name  $url  (not answering)"
    fi
  done
}

cmd_down() {
  need docker || exit 1
  [[ -d "$WAZUH_DIR" ]] && ( cd "$WAZUH_DIR" && docker compose down )
  docker stop thehive cortex >/dev/null 2>&1 || true
  ok "stopped — data volumes kept"
}

cmd_nuke() {
  need docker || exit 1
  bad "this deletes the volumes: alerts, cases, agent registrations, everything"
  confirm "really?" || exit 0
  confirm "really really? there is no undo and your Block 3 case lives in there" || exit 0
  [[ -d "$WAZUH_DIR" ]] && ( cd "$WAZUH_DIR" && docker compose down -v )
  docker rm -f thehive cortex >/dev/null 2>&1 || true
  ok "gone"
}

case "${1:-}" in
  preflight) shift; cmd_preflight "$@" ;;
  pull)      shift; cmd_pull "$@" ;;
  up)        shift; cmd_up "$@" ;;
  status)    shift; cmd_status "$@" ;;
  agent-cmd) shift; cmd_agent_cmd "$@" ;;
  down)      shift; cmd_down "$@" ;;
  nuke)      shift; cmd_nuke "$@" ;;
  ''|-h|--help|help) usage 0 ;;
  *) bad "unknown command: $1"; usage 1 ;;
esac
