#!/usr/bin/env bash
# lab-doctor.sh — is your malware lab actually a lab, or just two VMs?
#
# Run this ON THE ANALYSIS HOST, before you detonate anything. It checks the
# things that turn a lab into an incident: an internet route that should not
# exist, a shared folder nobody remembered, a snapshot that was never taken.
#
#   ./lab-doctor.sh            run every check
#   ./lab-doctor.sh isolation  just the network checks (the ones that matter)
#   ./lab-doctor.sh tools      just the toolchain
#   ./lab-doctor.sh ghidra     just Ghidra and its JDK
#   ./lab-doctor.sh artefacts  what a sample can see about this VM
#
# Exit code is the number of failed checks, so you can gate a pipeline on it.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
set +o errexit   # we want to run every check, not stop at the first sad one

FAILED=0
check_fail() { bad "$*"; FAILED=$((FAILED+1)); }

c_isolation() {
  banner "Isolation" "the only section where a failure means: stop, do not detonate"

  info "can this host reach the internet?"
  if timeout 4 ping -c1 -W2 8.8.8.8 >/dev/null 2>&1; then
    check_fail "8.8.8.8 is reachable — this host is NOT isolated"
    hint "if this is the analysis host and not the victim, that may be fine. know which you are on."
  else
    ok "no route to 8.8.8.8"
  fi

  info "does DNS resolve to the real internet?"
  if command -v dig >/dev/null 2>&1; then
    local a; a=$(timeout 4 dig +short +time=2 +tries=1 example.com A 2>/dev/null | head -1)
    if [[ -z "$a" ]]; then
      ok "no DNS answer (or DNS is dead, which is also fine here)"
    elif [[ "$a" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.) ]]; then
      ok "DNS answers from a private address ($a) — INetSim or similar. Correct."
    else
      check_fail "DNS resolved example.com to a public address ($a)"
      hint "the victim will resolve the C2 for real. point it at INetSim."
    fi
  else
    warn "dig not installed, skipping DNS check"
  fi

  info "default route"
  ip route 2>/dev/null | grep '^default' | sed 's/^/     /' || say "     (none — good)"

  info "interfaces — more than one on a victim VM is a finding"
  local n; n=$(ip -o link show 2>/dev/null | grep -vc ' lo:' || echo 0)
  if [[ "$n" -le 1 ]]; then ok "$n non-loopback interface"
  else warn "$n non-loopback interfaces — is one of them a NAT adapter you forgot?"; fi

  info "shared folders / guest integrations"
  local shared=0
  mount 2>/dev/null | grep -qiE 'vboxsf|vmhgfs|prl_fs|9p|virtiofs' && { check_fail "a host shared folder is mounted"; shared=1; }
  [[ $shared -eq 0 ]] && ok "no host shared folders mounted"
  hint "a shared folder is a two-way path. ransomware does not respect your intent for it."
}

c_tools() {
  banner "Toolchain"
  local tools=(
    "tcpdump:sudo apt install -y tcpdump"
    "file:coreutils, you already have it"
    "strings:sudo apt install -y binutils"
    "yara:sudo apt install -y yara"
    "rabin2:sudo apt install -y radare2"
    "xxd:sudo apt install -y xxd"
    "jq:sudo apt install -y jq"
    "python3:surely"
  )
  for t in "${tools[@]}"; do
    if command -v "${t%%:*}" >/dev/null 2>&1; then ok "${t%%:*}"
    else check_fail "${t%%:*} missing"; hint "${t#*:}"; fi
  done

  info "INetSim"
  if command -v inetsim >/dev/null 2>&1 || systemctl is-active --quiet inetsim 2>/dev/null; then
    ok "present"
    systemctl is-active --quiet inetsim 2>/dev/null && ok "running" || warn "installed but not running"
  else
    warn "not found — fine if your fake services live elsewhere"
  fi
}

c_ghidra() {
  banner "Ghidra" "when Ghidra will not start, it is the JDK. It is always the JDK."
  local gh="${GHIDRA_HOME:-}"
  if [[ -z "$gh" ]]; then
    gh=$(find "$HOME" /opt /usr/local -maxdepth 3 -name 'ghidraRun' -type f 2>/dev/null | head -1)
    gh="${gh%/ghidraRun}"
  fi
  if [[ -n "$gh" && -d "$gh" ]]; then
    ok "found at $gh"
    [[ -f "$gh/Ghidra/application.properties" ]] && \
      grep -E 'application.version|application.release.name' "$gh/Ghidra/application.properties" | sed 's/^/     /'
  else
    check_fail "Ghidra not found"
    hint "set GHIDRA_HOME, or unpack the release somewhere findable"
    return
  fi

  info "java"
  if command -v java >/dev/null 2>&1; then
    local v; v=$(java -version 2>&1 | head -1)
    say "     $v"
    local major; major=$(java -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -1)
    if [[ -n "$major" && "$major" -ge 17 ]]; then ok "JDK $major is recent enough"
    else check_fail "JDK $major is too old for current Ghidra"; hint "install a JDK 17+ and set JAVA_HOME"; fi
  else
    check_fail "no java on PATH"
    hint "this is the answer 90% of the time. install a JDK 17+."
  fi

  info "headless analyzer present"
  [[ -x "$gh/support/analyzeHeadless" ]] && ok "analyzeHeadless available (scriptable imports)" \
                                         || warn "analyzeHeadless not found"
}

c_artefacts() {
  banner "What a sample can see about this VM" "not a pass/fail — a list to write down"
  hint "the exercise is not to remove all of these. it is to know which remain, and say so."

  info "hypervisor hints in the CPU"
  grep -qi hypervisor /proc/cpuinfo 2>/dev/null && say "     [x] CPUID hypervisor bit set" || say "     [ ] CPUID hypervisor bit"

  info "DMI / SMBIOS strings"
  for f in sys_vendor product_name board_vendor bios_vendor; do
    local v; v=$(cat "/sys/class/dmi/id/$f" 2>/dev/null || true)
    [[ -n "$v" ]] && printf '     %-14s %s\n' "$f" "$v"
  done | grep -iE 'vmware|virtualbox|qemu|kvm|xen|innotek|parallels|bochs' && \
    say "     ^ these strings are trivially readable by any sample" || \
    say "     (nothing obviously virtual in DMI — unusual, and good)"

  info "MAC OUI"
  ip -o link show 2>/dev/null | awk '{print $2, $(NF-2)}' | grep -vi '^lo' | while read -r i m; do
    case "${m:0:8}" in
      00:0c:29|00:50:56|00:05:69|00:1c:14) printf '     %-10s %s  <- VMware\n' "$i" "$m" ;;
      08:00:27|0a:00:27)                   printf '     %-10s %s  <- VirtualBox\n' "$i" "$m" ;;
      52:54:00)                            printf '     %-10s %s  <- QEMU/KVM\n' "$i" "$m" ;;
      *)                                   printf '     %-10s %s\n' "$i" "$m" ;;
    esac
  done

  info "plausibility — the cheapest and most effective check a sample makes"
  local ram cpus disk files
  ram=$(awk '/MemTotal/{printf "%.0f", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo '?')
  cpus=$(nproc 2>/dev/null || echo '?')
  disk=$(df -BG --output=size / 2>/dev/null | tail -1 | tr -dc '0-9' || echo '?')
  files=$(find "$HOME" -maxdepth 2 -type f 2>/dev/null | wc -l | tr -d ' ')
  printf '     %-14s %s GB %s\n' "RAM"    "$ram"  "$([[ "$ram"  =~ ^[0-9]+$ && "$ram"  -lt 4  ]] && echo '<- a real desktop has more')"
  printf '     %-14s %s %s\n'    "CPUs"   "$cpus" "$([[ "$cpus" =~ ^[0-9]+$ && "$cpus" -lt 2  ]] && echo '<- nobody has one core')"
  printf '     %-14s %s GB %s\n' "disk /" "$disk" "$([[ "$disk" =~ ^[0-9]+$ && "$disk" -lt 80 ]] && echo '<- small')"
  printf '     %-14s %s %s\n'    "home files" "$files" "$([[ "$files" -lt 20 ]] && echo '<- nobody lives here')"
  printf '     %-14s %s\n'       "uptime" "$(uptime -p 2>/dev/null || uptime)"
  hint "uptime of four minutes plus an empty home directory is the loudest signal on this list"

  info "analysis tooling visible by process name"
  pgrep -al 'wireshark|tcpdump|procmon|x64dbg|ida|ghidra|fiddler|regshot' 2>/dev/null | sed 's/^/     /' \
    || say "     (none running)"
}

case "${1:-all}" in
  all)       c_isolation; say ""; c_tools; say ""; c_ghidra; say ""; c_artefacts ;;
  isolation) c_isolation ;;
  tools)     c_tools ;;
  ghidra)    c_ghidra ;;
  artefacts) c_artefacts ;;
  -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) die "unknown: $1" ;;
esac

say ""
rule
if [[ $FAILED -eq 0 ]]; then
  ok "no failed checks"
else
  bad "$FAILED failed check(s)"
  hint "isolation failures mean stop. tooling failures mean install something."
fi
exit "$FAILED"
