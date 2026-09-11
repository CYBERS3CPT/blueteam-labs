#!/usr/bin/env bash
# passive-recon.sh — passive only, and it will stop you if you try otherwise
#
# Everything here is passive or semi-passive: certificate transparency, WHOIS,
# public DNS, archived pages. Nothing scans, nothing brute-forces, nothing
# touches a port. The `-passive` flag on amass is not decoration.
#
#   ./passive-recon.sh <domain> [-o outdir]
#
# Output is a directory with one file per source and a combined, deduplicated
# host list — plus an evidence log with UTC timestamps, because a finding with
# no capture time is not a finding.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

DOMAIN=""; OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) DOMAIN="$1"; shift ;;
  esac
done
[[ -n "$DOMAIN" ]] || die "usage: $0 <domain> [-o outdir]"
[[ "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || die "that does not look like a domain: $DOMAIN"

OUT="${OUT:-$(outdir "recon-${DOMAIN}-$(stamp)")}"
LOG="$OUT/evidence-log.csv"
echo "utc,source,command,result_count,notes" > "$LOG"

logit() { printf '%s,%s,"%s",%s,"%s"\n' "$(utc)" "$1" "$2" "${3:-0}" "${4:-}" >> "$LOG"; }

banner "Passive recon: $DOMAIN" "$(utc) — nothing here touches the target"

# ── certificate transparency ────────────────────────────────────────────────
# The highest-yield passive source there is. CT logs contain hostnames that were
# never published anywhere else, because somebody requested a certificate for a
# staging box and forgot it existed.
info "certificate transparency (crt.sh)"
if need curl && need jq; then
  if curl -sf --max-time 45 "https://crt.sh/?q=%25.${DOMAIN}&output=json" -o "$OUT/crtsh.json"; then
    jq -r '.[].name_value' "$OUT/crtsh.json" 2>/dev/null \
      | tr '[:upper:]' '[:lower:]' | tr '\n' '\n' | sed 's/^\*\.//' \
      | grep -E "\.?${DOMAIN//./\\.}$" | sort -u > "$OUT/hosts-crtsh.txt" || true
    n=$(wc -l < "$OUT/hosts-crtsh.txt" | tr -d ' ')
    ok "$n unique host(s)"
    logit crt.sh "crt.sh/?q=%25.${DOMAIN}&output=json" "$n" "passive"
  else
    warn "crt.sh did not answer (it is frequently slow; try again later)"
    logit crt.sh "crt.sh query" 0 "no answer"
  fi
fi

# ── whois ───────────────────────────────────────────────────────────────────
info "whois"
if need whois "sudo apt install -y whois"; then
  whois "$DOMAIN" > "$OUT/whois.txt" 2>/dev/null || true
  grep -iE '^\s*(registrar|creation date|created|expiry|expires|name server|nserver|status)' "$OUT/whois.txt" \
    | head -15 | sed 's/^/     /' || true
  logit whois "whois $DOMAIN" 1 "registration metadata"
fi

# ── passive enumeration ─────────────────────────────────────────────────────
info "amass (passive)"
if command -v amass >/dev/null 2>&1; then
  # -passive is load-bearing. Without it amass will resolve and probe.
  timeout 180 amass enum -passive -d "$DOMAIN" -o "$OUT/hosts-amass.txt" >/dev/null 2>&1 || true
  n=$(wc -l < "$OUT/hosts-amass.txt" 2>/dev/null | tr -d ' ' || echo 0)
  ok "$n host(s)"
  logit amass "amass enum -passive -d $DOMAIN" "$n" "passive only"
else
  hint "amass not installed — skipping"
fi

info "theHarvester (passive sources only)"
if command -v theHarvester >/dev/null 2>&1; then
  timeout 180 theHarvester -d "$DOMAIN" -b crtsh,rapiddns,otx -f "$OUT/harvester" >/dev/null 2>&1 || true
  ok "written to $OUT/harvester.*"
  logit theHarvester "theHarvester -d $DOMAIN -b crtsh,rapiddns,otx" 1 "passive sources only"
else
  hint "theHarvester not installed — skipping"
fi

# ── combine ─────────────────────────────────────────────────────────────────
info "combined host list"
cat "$OUT"/hosts-*.txt 2>/dev/null | tr '[:upper:]' '[:lower:]' | sed 's/^\*\.//' \
  | grep -E "\.?${DOMAIN//./\\.}$" | sort -u > "$OUT/hosts-all.txt" || true
TOTAL=$(wc -l < "$OUT/hosts-all.txt" 2>/dev/null | tr -d ' ' || echo 0)
ok "$TOTAL unique hostname(s)"
[[ "$TOTAL" -gt 0 ]] && head -20 "$OUT/hosts-all.txt" | sed 's/^/     /'
[[ "$TOTAL" -gt 20 ]] && say "     … and $((TOTAL-20)) more"

# ── typosquats ──────────────────────────────────────────────────────────────
info "lookalike domains (dnstwist)"
if command -v dnstwist >/dev/null 2>&1; then
  # --mx is the flag that matters. A registered lookalike is noise; a registered
  # lookalike with mail exchange records is someone preparing to send email as you.
  timeout 240 dnstwist --registered --mx --format csv "$DOMAIN" > "$OUT/typosquats.csv" 2>/dev/null || true
  n=$(($(wc -l < "$OUT/typosquats.csv" 2>/dev/null | tr -d ' ') - 1)); [[ $n -lt 0 ]] && n=0
  ok "$n registered permutation(s)"
  if [[ $n -gt 0 ]]; then
    mx=$(awk -F, 'NR>1 && $0 ~ /MX/ {c++} END{print c+0}' "$OUT/typosquats.csv")
    [[ "$mx" -gt 0 ]] && warn "$mx of them have MX records configured — that is the actionable subset"
  fi
  logit dnstwist "dnstwist --registered --mx $DOMAIN" "$n" "passive"
else
  hint "dnstwist not installed — skipping"
fi

say ""
rule
ok "output: $OUT"
ok "evidence log: $LOG"
cat <<'NEXT'

  Before any of this goes in a report:
    - Every row needs an Admiralty rating. CT logs are A1. A parked lookalike
      domain with no MX is A2 at best, and probably not worth a row.
    - Verify by hand. A hostname in a CT log is proof a certificate was issued,
      not proof the host exists today.
    - Record what you could NOT see. Coverage gaps belong in the methodology.
NEXT
