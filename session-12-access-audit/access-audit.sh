#!/usr/bin/env bash
# access-audit.sh — the Linux access audit, as a findings list you can hand over
#
# Read-only. It looks, it does not fix. Every finding comes out with the command
# that produced it, so the person who receives the list can reproduce it without
# asking you anything — which is the only kind of finding worth writing down.
#
#   ./access-audit.sh                 run everything, print findings
#   ./access-audit.sh --csv out.csv   also write a findings CSV
#   ./access-audit.sh --section sudo  just one section
#   ./access-audit.sh --sections      list the sections
#
# Sections: accounts sudo groups setuid perms acls creds ssh pam mac services
#
# Deliberately not run as root. Most of this is readable as a normal user, and
# a triage that runs as root is a read-only task one typo away from a write.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
set +o errexit

CSV=""; ONLY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --csv) CSV="$2"; shift 2 ;;
    --section) ONLY="$2"; shift 2 ;;
    --sections) echo "accounts sudo groups setuid perms acls creds ssh pam mac services"; exit 0 ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown: $1" ;;
  esac
done

[[ -n "$CSV" ]] && echo "severity,section,finding,evidence_command,detail" > "$CSV"
N_HIGH=0; N_MED=0; N_LOW=0

# f <severity> <section> <finding> <command> [detail]
f() {
  local sev="$1" sec="$2" what="$3" cmd="$4" detail="${5:-}"
  case "$sev" in
    high) bad "$what"; N_HIGH=$((N_HIGH+1)) ;;
    med)  warn "$what"; N_MED=$((N_MED+1)) ;;
    *)    printf '  note %s\n' "$what"; N_LOW=$((N_LOW+1)) ;;
  esac
  [[ -n "$detail" ]] && hint "$detail"
  hint "evidence: $cmd"
  [[ -n "$CSV" ]] && printf '%s,%s,"%s","%s","%s"\n' "$sev" "$sec" "$what" "$cmd" "$detail" >> "$CSV"
}

want() { [[ -z "$ONLY" || "$ONLY" == "$1" ]]; }

# ── accounts ────────────────────────────────────────────────────────────────
want accounts && {
banner "Accounts"
CMD="awk -F: '\$3>=1000 && \$7!~/nologin|false/' /etc/passwd"
awk -F: '$3>=1000 && $7!~/nologin|false/ {print "  " $1 "  uid=" $3 "  shell=" $7}' /etc/passwd

# UID 0 is root. A second UID 0 is a backdoor wearing a username.
dupe0=$(awk -F: '$3==0 {print $1}' /etc/passwd | grep -v '^root$' || true)
[[ -n "$dupe0" ]] && f high accounts "non-root account(s) with UID 0: $(echo "$dupe0" | tr '\n' ' ')" \
  "awk -F: '\$3==0' /etc/passwd" "a second UID 0 is root with a different name"

# An account with no password at all logs in with the empty string.
if [[ -r /etc/shadow ]]; then
  empty=$(awk -F: '$2=="" {print $1}' /etc/shadow || true)
  [[ -n "$empty" ]] && f high accounts "account(s) with an EMPTY password: $(echo "$empty" | tr '\n' ' ')" \
    "awk -F: '\$2==\"\"' /etc/shadow"
else
  hint "/etc/shadow unreadable as this user — re-run the 'accounts' section with sudo for the password checks"
fi

never=$(lastlog 2>/dev/null | awk 'NR>1 && /Never logged in/ {print $1}' | head -20 || true)
[[ -n "$never" ]] && f low accounts "$(echo "$never" | wc -l | tr -d ' ') account(s) have never logged in" \
  "lastlog | grep 'Never logged in'" "unused accounts are access nobody is reviewing"
}

# ── sudo ────────────────────────────────────────────────────────────────────
want sudo && {
banner "sudo" "this is where the whole exercise is usually undone"
SUDOERS=$(sudo -n grep -RhvE '^\s*#|^\s*$' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || \
          grep -RhvE '^\s*#|^\s*$' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true)
if [[ -z "$SUDOERS" ]]; then
  warn "cannot read sudoers as this user — re-run this section with sudo"
else
  echo "$SUDOERS" | sed 's/^/  /'
  echo "$SUDOERS" | grep -q 'NOPASSWD:\s*ALL' && \
    f high sudo "NOPASSWD: ALL present in sudoers" \
      "sudo grep -RvE '^\\s*#|^\\s*\$' /etc/sudoers /etc/sudoers.d/" \
      "password-less root. every other control on this host is now decorative."
  echo "$SUDOERS" | grep -qE '^\s*[^#]*ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL' && \
    f med sudo "an unrestricted (ALL) ALL rule exists" \
      "sudo grep -RvE '^\\s*#' /etc/sudoers"

  # GTFOBins territory. sudo on any of these is sudo on everything, because they
  # all spawn a shell or read arbitrary files.
  for b in vim vi nano less more man awk find sed tar zip perl python python3 ruby \
           git nmap ftp env systemctl journalctl docker; do
    echo "$SUDOERS" | grep -qE "(^|[ ,/])$b(\$| )" && \
      f high sudo "sudo rule permits '$b' — that is a root shell" \
        "sudo grep -RvE '^\\s*#' /etc/sudoers | grep $b" \
        "see GTFOBins. read it once and your sudoers reviews change permanently."
  done
fi
}

# ── groups ──────────────────────────────────────────────────────────────────
want groups && {
banner "Dangerous group membership"
for g in sudo wheel admin adm root; do
  m=$(getent group "$g" 2>/dev/null | cut -d: -f4)
  [[ -n "$m" ]] && printf '  %-10s %s\n' "$g" "$m"
done
for g in docker lxd libvirt kvm disk shadow; do
  m=$(getent group "$g" 2>/dev/null | cut -d: -f4)
  [[ -n "$m" ]] && f high groups "'$g' has members: $m" "getent group $g" \
    "$(case $g in
        docker|lxd) echo 'effectively root: mount the host filesystem into a container you control';;
        disk)       echo 'raw block device access. read /etc/shadow, write anywhere.';;
        shadow)     echo 'read every password hash on the host';;
        *)          echo 'privileged group';;
      esac)"
done
}

# ── setuid ──────────────────────────────────────────────────────────────────
want setuid && {
banner "setuid / setgid binaries" "compare against a baseline; the list itself is not a finding"
FOUND=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%M %u %p\n' 2>/dev/null | sort -k3 || true)
echo "$FOUND" | sed 's/^/  /' | head -40
n=$(echo "$FOUND" | grep -c . || echo 0)
say "  ($n total)"
# Anything setuid outside the usual system paths deserves a question.
odd=$(echo "$FOUND" | awk '{print $3}' | grep -vE '^/(usr/)?(bin|sbin|lib|libexec|usr/lib)' || true)
[[ -n "$odd" ]] && f high setuid "setuid binary outside the standard paths: $(echo "$odd" | tr '\n' ' ')" \
  "find / -xdev -perm -4000 -type f" "a setuid binary in /home, /tmp or /opt is a finding until proven otherwise"
}

# ── permissions ─────────────────────────────────────────────────────────────
want perms && {
banner "World-writable"
ww=$(find / -xdev -type f -perm -0002 ! -type l -printf '%M %u %p\n' 2>/dev/null | head -30 || true)
if [[ -n "$ww" ]]; then
  echo "$ww" | sed 's/^/  /'
  f high perms "$(echo "$ww" | grep -c .) world-writable file(s)" \
    "find / -xdev -type f -perm -0002" "anyone on this host can modify these"
else ok "no world-writable files"; fi

# A world-writable directory without the sticky bit means anyone can delete
# anyone else's files in it. /tmp has the sticky bit for exactly this reason.
wwd=$(find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -20 || true)
[[ -n "$wwd" ]] && f high perms "world-writable director(ies) WITHOUT the sticky bit" \
  "find / -xdev -type d -perm -0002 ! -perm -1000" \
  "anyone can delete anyone else's files there: $(echo "$wwd" | tr '\n' ' ')"
}

# ── ACLs ────────────────────────────────────────────────────────────────────
want acls && {
banner "POSIX ACLs" "ls -l shows a '+' — people miss it, constantly"
if command -v getfacl >/dev/null 2>&1; then
  withacl=$(find /etc /srv /opt /home -maxdepth 3 -type f -exec ls -ld {} \; 2>/dev/null | grep '^\S*+' | head -20 || true)
  if [[ -n "$withacl" ]]; then
    echo "$withacl" | sed 's/^/  /'
    f med acls "file(s) carry POSIX ACLs beyond their mode bits" \
      "find /etc /srv /opt /home -type f -exec ls -ld {} \; | grep '+'" \
      "the mode bits are not the whole story; getfacl to see the rest"
  else ok "none found in /etc /srv /opt /home"; fi
else hint "getfacl not installed (sudo apt install -y acl)"; fi
}

# ── credentials on disk ─────────────────────────────────────────────────────
want creds && {
banner "Credentials lying around"
keys=$(find /home /root /opt /srv -maxdepth 4 \
        \( -name 'id_*' ! -name '*.pub' -o -name '*.pem' -o -name '.netrc' -o -name '.pgpass' \) \
        -type f 2>/dev/null | head -20 || true)
if [[ -n "$keys" ]]; then
  while read -r k; do
    [[ -z "$k" ]] && continue
    perm=$(stat -c '%a %U' "$k" 2>/dev/null || stat -f '%Lp %Su' "$k")
    printf '  %-56s %s\n' "$k" "$perm"
    [[ "${perm%% *}" =~ ^[0-7][0-7][1-7]$ ]] && \
      f high creds "private key readable by others: $k ($perm)" "stat -c '%a %U' $k"
  done <<< "$keys"
else ok "no obvious key material"; fi

hard=$(grep -rIlE --exclude-dir=.git --exclude-dir=node_modules \
        '(password|passwd|secret|api[_-]?key|token)\s*[=:]\s*["'"'"']?[A-Za-z0-9/+_-]{8,}' \
        /opt /srv /etc 2>/dev/null | head -10 || true)
[[ -n "$hard" ]] && f high creds "possible hardcoded credential(s) in: $(echo "$hard" | tr '\n' ' ')" \
  "grep -rIlE '(password|secret|api_key)\\s*=' /opt /srv /etc" \
  "a credential on disk is an access control failure, and rotation is the fix — not deletion"
}

# ── ssh ─────────────────────────────────────────────────────────────────────
want ssh && {
banner "SSH"
CFG=$(sshd -T 2>/dev/null || sudo -n sshd -T 2>/dev/null || true)
if [[ -z "$CFG" ]]; then
  warn "sshd -T needs root; falling back to reading the file"
  CFG=$(grep -viE '^\s*#|^\s*$' /etc/ssh/sshd_config 2>/dev/null || true)
fi
echo "$CFG" | grep -iE 'permitrootlogin|passwordauthentication|permitemptypass|allowusers|allowgroups|maxauthtries|x11forwarding' | sed 's/^/  /'
echo "$CFG" | grep -qiE '^permitrootlogin\s+yes' && \
  f high ssh "PermitRootLogin yes" "sshd -T | grep permitrootlogin"
echo "$CFG" | grep -qiE '^permitemptypasswords\s+yes' && \
  f high ssh "PermitEmptyPasswords yes" "sshd -T | grep permitemptypass"
echo "$CFG" | grep -qiE '^passwordauthentication\s+yes' && \
  f med ssh "password authentication enabled" "sshd -T | grep passwordauth" \
    "key-only is the target; password auth is what fail2ban exists to paper over"
}

# ── PAM ─────────────────────────────────────────────────────────────────────
want pam && {
banner "PAM"
if [[ -d /etc/pam.d ]]; then
  grep -q pam_faillock /etc/pam.d/* 2>/dev/null && ok "pam_faillock present (lockout)" \
    || f med pam "no pam_faillock — no account lockout" "grep -r pam_faillock /etc/pam.d/"
  grep -q pam_pwquality /etc/pam.d/* 2>/dev/null && ok "pam_pwquality present" \
    || f med pam "no pam_pwquality — no password strength enforcement" "grep -r pam_pwquality /etc/pam.d/"
  nullok=$(grep -rl 'nullok' /etc/pam.d/ 2>/dev/null || true)
  [[ -n "$nullok" ]] && f high pam "'nullok' present in: $(echo "$nullok" | tr '\n' ' ')" \
    "grep -r nullok /etc/pam.d/" "empty passwords are accepted"
else hint "no /etc/pam.d on this system"; fi
}

# ── MAC ─────────────────────────────────────────────────────────────────────
want mac && {
banner "Mandatory access control"
if command -v aa-status >/dev/null 2>&1; then
  aa-status --enabled 2>/dev/null && ok "AppArmor enabled" || warn "AppArmor present but not enabled"
  aa-status 2>/dev/null | head -6 | sed 's/^/  /'
elif command -v getenforce >/dev/null 2>&1; then
  mode=$(getenforce)
  case "$mode" in
    Enforcing)  ok "SELinux enforcing" ;;
    Permissive) f med mac "SELinux is permissive" "getenforce" \
                  "permissive logs what it would have blocked. useful while tuning, useless as a control." ;;
    *)          f med mac "SELinux disabled" "getenforce" ;;
  esac
else
  f med mac "no AppArmor or SELinux" "aa-status / getenforce" "no mandatory access control layer"
fi
}

# ── services ────────────────────────────────────────────────────────────────
want services && {
banner "Listening services" "every one is an access path somebody has to justify"
if command -v ss >/dev/null 2>&1; then
  ss -ltnp 2>/dev/null | sed 's/^/  /' | head -25
  ext=$(ss -ltn 2>/dev/null | awk 'NR>1 && $4 !~ /^(127\.|\[::1\])/ {print $4}' | head -15 || true)
  [[ -n "$ext" ]] && f low services "$(echo "$ext" | wc -l | tr -d ' ') socket(s) bound beyond loopback" \
    "ss -ltn" "$(echo "$ext" | tr '\n' ' ')"
else hint "ss not available"; fi
}

# ── summary ─────────────────────────────────────────────────────────────────
say ""
rule
printf '  %s%d high%s   %s%d medium%s   %d note(s)\n' \
  "$C_RED" "$N_HIGH" "$C_RST" "$C_YEL" "$N_MED" "$C_RST" "$N_LOW"
[[ -n "$CSV" ]] && ok "findings CSV: $CSV"
say ""
cat <<'NEXT'
  Before any of this becomes a ticket:

    - "Restrict access" is not a remediation. The remediation is the command or
      the setting, written out, that the person receiving the finding can run.
    - Severity needs one line of justification. Not a colour.
    - A finding with no evidence column cannot be reproduced, and will be closed
      as "could not reproduce" by somebody who did not try very hard.
NEXT
exit 0
