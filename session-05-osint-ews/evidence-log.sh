#!/usr/bin/env bash
# evidence-log.sh — capture a web page so that it survives a lawyer
#
# The OSINT finding you make carelessly in week five is the one that gets
# challenged. This archives a page as WARC, hashes it immediately, screenshots
# it with the URL bar visible where it can, and appends a row to an evidence log
# with the capture time in UTC and the tool version that produced it.
#
#   ./evidence-log.sh init <case>              start a case directory
#   ./evidence-log.sh capture <url> ["note"]   archive + hash + log
#   ./evidence-log.sh note "<text>"            a log row with no artefact
#   ./evidence-log.sh verify                   re-hash everything, report drift
#   ./evidence-log.sh show                     the log
#   ./evidence-log.sh pack                     a sealed, hashed bundle
#
# Everything is passive: it fetches the page as a browser would and nothing else.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

CASE="${EVIDENCE_CASE:-./evidence}"
LOG="$CASE/evidence-log.csv"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
need_case() { [[ -f "$LOG" ]] || die "no case at $CASE — run: $0 init <case-ref>"; }

cmd_init() {
  local ref="${1:-}"; [[ -n "$ref" ]] || die "usage: $0 init <case-reference>"
  mkdir -p "$CASE/artefacts"
  [[ -f "$LOG" ]] && die "$LOG already exists — appending to an existing log is the point"
  echo "item_id,utc,type,url,description,file,sha256,bytes,tool,collector,method" > "$LOG"
  cat > "$CASE/case.txt" <<M
case reference : $ref
opened (UTC)   : $(utc)
collector      : ${EVIDENCE_COLLECTOR:-$(id -un)}
host           : $(uname -srm)
method         : passive / semi-passive collection from public sources only
M
  ok "case $ref at $CASE"
  hint "set EVIDENCE_COLLECTOR to your real name — 'ssilva' is not a collector"
}

next_id() { printf 'ITEM-%03d' "$(( $(wc -l < "$LOG") ))"; }

logrow() {  # logrow type url description file sha bytes tool method
  printf '%s,%s,%s,"%s","%s","%s",%s,%s,"%s","%s","%s"\n' \
    "$(next_id)" "$(utc)" "$1" "$2" "$3" "$4" "$5" "$6" "$7" \
    "${EVIDENCE_COLLECTOR:-$(id -un)}" "$8" >> "$LOG"
}

cmd_capture() {
  need_case
  local url="${1:-}" note="${2:-}"
  [[ "$url" =~ ^https?:// ]] || die "usage: $0 capture <http(s)://url> [\"note\"]"
  need curl "sudo apt install -y curl" || exit 1

  local id; id=$(next_id)
  local base="$CASE/artefacts/${id}"
  banner "Capturing $id" "$url"
  warn "this touches the target's web server. It is semi-passive, not passive."
  hint "one normal GET, with a normal user agent. Record it as such in the method column."

  # WARC first: it preserves the request AND response headers, which is what
  # makes it evidence rather than a screenshot of a browser.
  local tool=""
  if command -v wget >/dev/null 2>&1; then
    info "wget --warc"
    wget --warc-file="$base" --warc-cdx -q -p --no-check-certificate \
         --user-agent="$UA" --timeout=25 --tries=2 -O "$base.html" "$url" 2>/dev/null || \
      warn "wget returned non-zero — the partial capture is still evidence, note it"
    tool="wget $(wget --version 2>/dev/null | head -1 | awk '{print $3}')"
  else
    info "curl (no WARC — install wget for a proper archive)"
    curl -sL --max-time 25 -A "$UA" -D "$base.headers" -o "$base.html" "$url" || true
    tool="curl $(curl --version 2>/dev/null | head -1 | awk '{print $2}')"
  fi

  # Hash immediately. A hash taken later proves less with every minute.
  local n=0
  for f in "$base".*; do
    [[ -f "$f" ]] || continue
    local h b
    h=$(sha256 "$f" | awk '{print $1}')
    b=$(wc -c < "$f" | tr -d ' ')
    printf '  %-46s %10s B\n' "$(basename "$f")" "$b"
    printf '  %s\n' "  sha256 $h"
    logrow "capture" "$url" "${note:-web page capture}" "$(basename "$f")" "$h" "$b" "$tool" "semi-passive GET"
    n=$((n+1))
  done
  [[ $n -gt 0 ]] || { bad "nothing captured"; return 1; }

  # A screenshot, if there is a headless browser to make one. Record that the
  # URL is in the log even when it is not in the picture.
  for b in chromium chromium-browser google-chrome; do
    if command -v "$b" >/dev/null 2>&1; then
      info "screenshot"
      "$b" --headless --disable-gpu --no-sandbox --hide-scrollbars \
           --screenshot="$base.png" --window-size=1440,2400 "$url" >/dev/null 2>&1 || true
      if [[ -f "$base.png" ]]; then
        local h; h=$(sha256 "$base.png" | awk '{print $1}')
        ok "$(basename "$base.png")  sha256 ${h:0:16}…"
        logrow "screenshot" "$url" "rendered screenshot" "$(basename "$base.png")" \
               "$h" "$(wc -c < "$base.png" | tr -d ' ')" "$b headless" "semi-passive GET"
      fi
      break
    fi
  done

  ok "$id logged"
}

cmd_note() {
  need_case
  local text="${1:-}"; [[ -n "$text" ]] || die "usage: $0 note \"<text>\""
  logrow "note" "" "$text" "" "" "" "" "observation"
  ok "noted"
}

cmd_verify() {
  need_case
  banner "Verifying artefacts" "every hash, re-computed"
  local bad_n=0 ok_n=0 missing=0
  while IFS=, read -r id utc typ url desc file sha rest; do
    [[ "$id" == "item_id" ]] && continue
    file=$(tr -d '"' <<< "$file"); sha=$(tr -d '"' <<< "$sha")
    [[ -z "$file" ]] && continue
    local path="$CASE/artefacts/$file"
    if [[ ! -f "$path" ]]; then
      bad "$id  MISSING  $file"; missing=$((missing+1)); continue
    fi
    local now; now=$(sha256 "$path" | awk '{print $1}')
    if [[ "$now" == "$sha" ]]; then ok_n=$((ok_n+1))
    else bad "$id  HASH CHANGED  $file"; hint "logged $sha"; hint "now    $now"; bad_n=$((bad_n+1)); fi
  done < "$LOG"
  say ""
  printf '  %d verified, %d changed, %d missing\n' "$ok_n" "$bad_n" "$missing"
  if [[ $bad_n -gt 0 || $missing -gt 0 ]]; then
    say ""
    cat <<'M'
  Do not quietly re-hash and move on. Record what happened and when you noticed,
  because the next question is "how do we know it was not modified before you
  first hashed it?" and the only good answer is a log that shows the change.
M
    exit 1
  fi
}

cmd_show() {
  need_case
  banner "Evidence log" "$(head -1 "$CASE/case.txt" 2>/dev/null)"
  # column(1) collapses consecutive separators, which silently shifts every
  # column right of an empty field. Fill the blanks before it gets the chance.
  sed 's/,,/,-,/g; s/,,/,-,/g; s/,$/,-/' "$LOG" \
    | column -s, -t 2>/dev/null | cut -c1-170 | sed 's/^/  /' || cat "$LOG"
  say ""
  info "$(( $(wc -l < "$LOG") - 1 )) row(s)"
}

cmd_pack() {
  need_case
  cmd_verify >/dev/null || die "verification failed — fix that before packing"
  local out="$CASE-$(stamp).tar.gz"
  tar czf "$out" -C "$(dirname "$CASE")" "$(basename "$CASE")"
  local h; h=$(sha256 "$out" | awk '{print $1}')
  printf '%s  %s\n' "$h" "$(basename "$out")" > "$out.sha256"
  ok "$out"
  ok "$out.sha256  ($h)"
  say ""
  hint "give the hash to whoever receives the bundle, by a different channel"
  hint "than the bundle. A hash that travels with the file proves nothing."
}

case "${1:-}" in
  init)    shift; cmd_init "$@" ;;
  capture) shift; cmd_capture "$@" ;;
  note)    shift; cmd_note "$@" ;;
  verify)  shift; cmd_verify "$@" ;;
  show)    shift; cmd_show "$@" ;;
  pack)    shift; cmd_pack "$@" ;;
  ''|-h|--help|help) usage 0 ;;
  *) bad "unknown command: $1"; usage 1 ;;
esac
