#!/usr/bin/env bash
# hunt.sh — the artefact questions, asked of a collection, one at a time
#
# Session 8 has a table of questions and the artefacts that answer them. This is
# that table, executable. Point it at a mounted image or a triage collection and
# ask a question rather than remembering a filename.
#
#   ./hunt.sh questions                       what you can ask
#   ./hunt.sh <question> --root /mnt/evidence
#   ./hunt.sh sigma --root /mnt/evidence      chainsaw over the event logs
#   ./hunt.sh all --root /mnt/evidence --out ./hunt
#
# Questions: ran opened browsed usb logons deleted exfil persist
#
# Read-only. It never writes into --root.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
set +o errexit

ROOT=""; OUT=""; Q=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) ROOT="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) Q="$1"; shift ;;
  esac
done
[[ -n "$OUT" ]] && mkdir -p "$OUT"

# find, but only inside --root, case-insensitively, and never following out
f() { find "$ROOT" -maxdepth "${2:-8}" -iname "$1" -type f 2>/dev/null | head -"${3:-25}"; }
d() { find "$ROOT" -maxdepth "${2:-8}" -iname "$1" -type d 2>/dev/null | head -"${3:-10}"; }
report() { printf '  %-34s %s\n' "$1" "$2"; }
found() {  # found <label> <paths...>
  local label="$1"; shift
  if [[ $# -gt 0 && -n "${1:-}" ]]; then
    ok "$label"
    printf '     %s\n' "$@" | sed "s|$ROOT|<root>|"
    return 0
  fi
  printf '  %s— %s: not present%s\n' "$C_DIM" "$label" "$C_RST"
  return 1
}

cmd_questions() {
  banner "What you can ask" "Session 8's artefact map, as commands"
  cat <<'TXT'

  ran        What executed?           Prefetch · Amcache · ShimCache · UserAssist
                                      · Security 4688 · Sysmon 1
  opened     What was opened?         RecentDocs · JumpLists · LNK · Office MRU
  browsed    Where did they browse?   ShellBags · TypedPaths · browser history
  usb        What was plugged in?     USBSTOR · setupapi.dev.log · LNK volume serials
  logons     Who logged in, whence?   Security 4624/4625 + logon type · TerminalServices
  deleted    What was deleted?        $UsnJrnl · Recycle Bin $I/$R · $LogFile
  exfil      Was data taken?          SRUM bytes-sent · browser uploads · Sysmon 3
  persist    How do they come back?   Run keys · Services · Scheduled Tasks · WMI
  sigma      Hunt the event logs      chainsaw + Sigma rules

  Each one locates the artefacts and tells you what to run next. It does not
  parse them for you — parsing is where the assumptions live, and you should
  know which tool made yours.

TXT
}

q_ran() {
  banner "What ran?"
  found "Prefetch" $(d "Prefetch" 6 3) && \
    hint "parse: PECmd.exe -d <dir> --csv .  |  count, last-run times, and loaded files"
  found "Amcache" $(f "Amcache.hve" 8 3) && \
    hint "parse: AmcacheParser.exe -f Amcache.hve --csv .  |  path AND sha1, which is rare"
  found "SYSTEM hive (ShimCache lives here)" $(f "SYSTEM" 8 3) && \
    hint "parse: AppCompatCacheParser.exe -f SYSTEM --csv .  |  presence, not execution"
  found "NTUSER.DAT (UserAssist)" $(f "NTUSER.DAT" 8 5) && \
    hint "parse: rip.pl -r NTUSER.DAT -p userassist  |  GUI launches with run counts"
  found "Security.evtx" $(f "Security.evtx" 8 2) && \
    hint "4688 process creation, if command-line auditing was enabled. Check first."
  found "Sysmon operational log" $(f "*Sysmon*.evtx" 8 2) && \
    hint "Event ID 1 is the best process-creation record Windows produces"
  say ""
  hint "ShimCache proves PRESENCE, not execution. Prefetch proves execution."
  hint "People conflate them in reports and it is the easiest thing to get wrong."
}

q_opened() {
  banner "What was opened?"
  found "RecentDocs (in NTUSER.DAT)" $(f "NTUSER.DAT" 8 5) && \
    hint "rip.pl -r NTUSER.DAT -p recentdocs"
  found "Automatic JumpLists" $(d "AutomaticDestinations" 10 3) && \
    hint "JLECmd.exe -d <dir> --csv .  |  the AppID maps to the application"
  found "Recent LNK files" $(d "Recent" 10 3) && \
    hint "LECmd.exe -d <dir> --csv .  |  original path AND volume serial"
  say ""
  hint "LNK files routinely prove access to a share or a USB device you never imaged."
}

q_browsed() {
  banner "Where did they browse?"
  found "USRCLASS.DAT (ShellBags)" $(f "UsrClass.dat" 10 5) && \
    hint "SBECmd.exe -d <dir> --csv .  |  folders browsed, INCLUDING ones now gone"
  found "Chrome/Edge History" $(f "History" 10 5) && {
    hint "sqlite3 History \"SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'), url FROM urls;\""
    for h in $(f "History" 10 5); do
      [[ -f "$h-wal" ]] && { warn "$(basename "$(dirname "$h")")/History-wal exists"
                             hint "the recent rows are in there. Copy all three files."; }
    done
  }
  found "Firefox places.sqlite" $(f "places.sqlite" 10 3)
  say ""
  hint "ShellBags survive the folder. A bag for D:\\projects on a machine with no"
  hint "D: drive is a removable device, and it is frequently the whole finding."
}

q_usb() {
  banner "What was plugged in?"
  found "SYSTEM hive (USBSTOR)" $(f "SYSTEM" 8 3) && \
    hint "rip.pl -r SYSTEM -p usbstor  |  vendor, product, serial, first/last connect"
  found "setupapi.dev.log" $(f "setupapi.dev.log" 10 3) && \
    hint "grep -i 'device install' — first-ever connection time, in local time"
  found "SOFTWARE hive (EMDMgmt volume names)" $(f "SOFTWARE" 8 3)
  say ""
  hint "Correlate the USBSTOR serial with LNK volume serials to place FILES on the"
  hint "device. Serial alone proves it was connected, not that anything was copied."
}

q_logons() {
  banner "Who logged in, and from where?"
  found "Security.evtx" $(f "Security.evtx" 8 2) && {
    hint "4624 success, 4625 failure, 4634 logoff, 4672 special privileges"
    hint "logon types: 2 interactive · 3 network · 4 batch · 5 service · 7 unlock · 10 RDP"
  }
  found "TerminalServices logs" $(f "*TerminalServices*.evtx" 8 4) && \
    hint "RDP connect/disconnect WITH the source address"
  found "Linux auth log" $(f "auth.log*" 8 4) $(f "secure*" 8 4)
  found "wtmp / btmp" $(f "wtmp" 8 2) $(f "btmp" 8 2) && \
    hint "last -f wtmp  |  lastb -f btmp  |  no classic last on your box? ./wtmp-read.py wtmp"
  say ""
  hint "Type 10 at 03h00 from an address nobody recognises is the shape of the"
  hint "finding. Type 3 from a server is usually a service doing its job."
}

q_deleted() {
  banner "What was deleted?"
  found "\$UsnJrnl" $(f '$UsnJrnl*' 6 3) $(f 'UsnJrnl*' 6 3) && \
    hint "MFTECmd.exe -f \$J --csv .  |  creation, deletion and rename, often after the file is gone"
  found "\$MFT" $(f '$MFT' 6 2) $(f 'MFT' 6 2) && \
    hint "MFTECmd.exe -f \$MFT --csv .  |  and compare \$SI against \$FN timestamps"
  found "Recycle Bin" $(d '$Recycle.Bin' 6 3) && \
    hint "RBCmd.exe -d <dir> --csv .  |  \$I holds the original path and deletion time"
  say ""
  hint "\$UsnJrnl is the artefact people forget, and it frequently answers 'when was"
  hint "this deleted, and by what' after both the file and its MFT record are gone."
}

q_exfil() {
  banner "Was data taken?"
  found "SRUM database" $(f "SRUDB.dat" 10 2) && \
    hint "SrumECmd.exe -f SRUDB.dat --csv .  |  per-application BYTES SENT. Invaluable."
  found "Browser History (uploads)" $(f "History" 10 3) && \
    hint "check the downloads table, and POSTs in the cache"
  found "Sysmon log (network)" $(f "*Sysmon*.evtx" 8 2) && \
    hint "Event ID 3 — network connection with the owning process"
  found "Cloud sync client logs" $(d "OneDrive" 8 3) $(d "Dropbox" 8 3) $(d "Google*Drive" 8 3) && \
    hint "sync clients log what they uploaded, and people forget they are exfiltration paths"
  say ""
  hint "SRUM is the one. It answers 'how much left, from which application' when"
  hint "nothing else in the image can."
}

q_persist() {
  banner "How do they come back?"
  found "SOFTWARE hive (Run keys, services)" $(f "SOFTWARE" 8 3) && \
    hint "rip.pl -r SOFTWARE -p run  |  and -p services"
  found "NTUSER.DAT (per-user Run)" $(f "NTUSER.DAT" 8 5) && \
    hint "rip.pl -r NTUSER.DAT -p run"
  found "Scheduled Tasks" $(d "Tasks" 8 4) && \
    hint "the XML is readable; look at the Command and the trigger"
  found "WMI repository" $(f "OBJECTS.DATA" 10 2) && \
    hint "PyWMIPersistenceFinder.py — event consumers are the quiet kind of persistence"
  found "systemd units" $(d "systemd" 8 4)
  found "cron" $(d "cron.d" 8 3) $(f "crontab" 8 3)
  say ""
  hint "Run keys are the loud kind. WMI event subscriptions and a modified"
  hint "scheduled task are the ones that survive a rebuild of the obvious things."
}

q_sigma() {
  banner "Sigma hunt" "chainsaw over whatever event logs are in the collection"
  command -v chainsaw >/dev/null 2>&1 || die "chainsaw not installed — github.com/WithSecureLabs/chainsaw"
  local rules="${SIGMA_RULES:-./sigma/rules}"
  [[ -d "$rules" ]] || die "no Sigma rules at $rules — set SIGMA_RULES"
  local map="${CHAINSAW_MAPPING:-./mappings/sigma-event-logs-all.yml}"
  local logs; logs=$(d "*[Ll]ogs*" 8 1); logs="${logs:-$ROOT}"
  info "logs: ${logs/$ROOT/<root>}   rules: $rules"
  local args=(hunt "$logs" -s "$rules" --level high --level critical)
  [[ -f "$map" ]] && args+=(--mapping "$map")
  [[ -n "$OUT" ]] && args+=(--json --output "$OUT/chainsaw.json")
  chainsaw "${args[@]}" 2>&1 | tail -40 | sed 's/^/  /'
  say ""
  hint "a hit is a lead, not a finding. Open the raw event and read it."
  hint "then ask the Session 11 question: what would this rule's false positive rate be?"
}

case "${Q:-questions}" in
  questions) cmd_questions ;;
  ran|opened|browsed|usb|logons|deleted|exfil|persist|sigma)
      [[ -n "$ROOT" && -d "$ROOT" ]] || die "--root <mounted image or collection> is required"
      "q_$Q" ;;
  all)
      [[ -n "$ROOT" && -d "$ROOT" ]] || die "--root is required"
      for x in ran opened browsed usb logons deleted exfil persist; do "q_$x"; say ""; done ;;
  *) bad "unknown question: $Q"; cmd_questions; exit 1 ;;
esac
exit 0
