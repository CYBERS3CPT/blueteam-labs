#!/usr/bin/env bash
# android-collect.sh — a logical Android collection that you can write up
#
# It collects what a non-rooted device will actually give you, hashes everything
# as it lands, and records the device clock against a known reference. Mobile
# clocks are usually network-synchronised — and "usually" is not a finding.
#
#   ./android-collect.sh check          is a device connected, and what is it
#   ./android-collect.sh collect        bugreport, dumpsys, packages, hashes
#   ./android-collect.sh pull <db>      pull one database WITH its -wal and -shm
#   ./android-collect.sh leapp <dir>    run ALEAPP over a collection
#
# NO PERSONAL DEVICES. The script asks you to confirm it, because the rule is
# the one part of this session that has consequences outside the classroom.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

OUT="${ANDROID_OUT:-android-$(stamp)}"

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

device_guard() {
  need adb "sudo apt install -y android-tools-adb" || exit 1
  local n; n=$(adb devices | grep -c "device$" || true)
  [[ "$n" -gt 0 ]] || die "no device in 'device' state — check the cable, and the authorisation prompt on the handset"
  [[ "$n" -eq 1 ]] || die "$n devices connected. Disconnect the others; ambiguity here is how the wrong phone gets imaged."
}

cmd_check() {
  device_guard
  banner "Device" "record all of this — it is the identification section of the report"
  local props=(ro.product.model ro.product.manufacturer ro.build.version.release
               ro.build.version.security_patch ro.build.fingerprint ro.boot.verifiedbootstate)
  for p in "${props[@]}"; do
    printf '  %-38s %s\n' "$p" "$(adb shell getprop "$p" 2>/dev/null | tr -d '\r')"
  done

  info "clock"
  local dev_epoch host_epoch drift
  dev_epoch=$(adb shell date +%s 2>/dev/null | tr -d '\r')
  host_epoch=$(date +%s)
  if [[ "$dev_epoch" =~ ^[0-9]+$ ]]; then
    drift=$(( dev_epoch - host_epoch ))
    printf '  %-38s %s\n' "device (UTC)" "$(date -u -d "@$dev_epoch" 2>/dev/null || date -u -r "$dev_epoch")"
    printf '  %-38s %s\n' "examiner host (UTC)" "$(date -u)"
    if [[ ${drift#-} -le 5 ]]; then ok "drift ${drift}s — negligible, and now recorded"
    else warn "drift ${drift}s — record this. Every device timestamp needs it applied."; fi
  else
    warn "could not read the device clock"
  fi

  info "automatic time"
  local auto; auto=$(adb shell settings get global auto_time 2>/dev/null | tr -d '\r')
  [[ "$auto" == "1" ]] && ok "auto_time=1 (network synchronised)" \
                       || warn "auto_time=$auto — the clock may have been set by hand"

  info "lock state / encryption"
  adb shell getprop ro.crypto.state 2>/dev/null | tr -d '\r' | sed 's/^/  crypto.state  /'
  adb shell getprop ro.crypto.type  2>/dev/null | tr -d '\r' | sed 's/^/  crypto.type   /'
  hint "file-based encryption means BFU vs AFU decides what you can reach. Record which you are in."

  info "root / elevated access"
  if adb shell 'su -c id' 2>/dev/null | grep -q 'uid=0'; then
    warn "su is available — a file system extraction is possible, and must be justified in the report"
  else
    ok "no su — expect a LOGICAL extraction, and say so explicitly"
  fi

  info "multiple users / work profile"
  adb shell pm list users 2>/dev/null | tr -d '\r' | sed 's/^/  /'
  hint "anything beyond UserInfo{0:...} is another /data/user/<n> to collect"
}

cmd_collect() {
  device_guard
  banner "Logical collection" "-> $OUT"
  say ""
  say "  Confirm, out loud if it helps:"
  say "    - this device is the lab device, an emulator, or an instructor-supplied extraction"
  say "    - it does not belong to you, a colleague, a family member or a client"
  say "    - you have documented authority to examine it"
  say ""
  confirm "all three true?" || die "then stop. This is the rule with consequences outside the classroom."

  mkdir -p "$OUT"
  local LOG="$OUT/collection-log.csv"
  echo "utc,artefact,command,bytes,sha256" > "$LOG"

  grab() {  # grab <name> <command...>
    local name="$1"; shift
    local f="$OUT/$name"
    printf '  %-28s' "$name"
    if "$@" > "$f" 2>/dev/null; then
      local b h
      b=$(wc -c < "$f" | tr -d ' ')
      h=$(sha256 "$f" | awk '{print $1}')
      printf '%10s B\n' "$b"
      printf '%s,%s,"%s",%s,%s\n' "$(utc)" "$name" "$*" "$b" "$h" >> "$LOG"
    else
      printf '   failed\n'
      rm -f "$f"
    fi
  }

  info "device state"
  grab device-props.txt      adb shell getprop
  grab packages.txt          adb shell pm list packages -f -u
  grab users.txt             adb shell pm list users
  grab settings-global.txt   adb shell settings list global
  grab settings-secure.txt   adb shell settings list secure

  info "activity and usage"
  grab usagestats.txt        adb shell dumpsys usagestats
  grab notifications.txt     adb shell dumpsys notification --noredact
  grab battery.txt           adb shell dumpsys battery
  grab wifi.txt              adb shell dumpsys wifi
  grab connectivity.txt      adb shell dumpsys connectivity
  grab account.txt           adb shell dumpsys account

  info "logs"
  grab logcat.txt            adb logcat -d
  grab dmesg.txt             adb shell dmesg

  info "bugreport — the broad, non-invasive one. It takes a few minutes."
  if adb bugreport "$OUT/bugreport.zip" >/dev/null 2>&1; then
    local b h; b=$(wc -c < "$OUT/bugreport.zip" | tr -d ' ')
    h=$(sha256 "$OUT/bugreport.zip" | awk '{print $1}')
    ok "bugreport.zip ($((b/1024/1024)) MB)"
    printf '%s,bugreport.zip,"adb bugreport",%s,%s\n' "$(utc)" "$b" "$h" >> "$LOG"
  else
    warn "bugreport failed (older devices want: adb bugreport > file.txt)"
  fi

  say ""
  ok "collection: $OUT"
  ok "log with hashes: $LOG"
  hint "state the extraction level in the report: this is LOGICAL, and it excludes"
  hint "app private data, deleted content, and anything protected by FBE."
}

cmd_pull() {
  device_guard
  local db="${1:-}"; [[ -n "$db" ]] || die "usage: $0 pull /path/to/database.db"
  mkdir -p "$OUT/pulled"
  banner "Pulling $db" "with its -wal and -shm, which is the whole point"
  local got=0
  for suffix in "" "-wal" "-shm" "-journal"; do
    local src="${db}${suffix}"
    local dst="$OUT/pulled/$(basename "$src")"
    if adb pull "$src" "$dst" >/dev/null 2>&1; then
      ok "$(basename "$src")  $(wc -c < "$dst" | tr -d ' ') B  $(sha256 "$dst" | awk '{print $1}')"
      got=$((got+1))
    else
      [[ -z "$suffix" ]] && warn "could not pull $src (permission? path?)"
    fi
  done
  [[ $got -gt 0 ]] || die "nothing pulled"
  if [[ -f "$OUT/pulled/$(basename "$db")-wal" ]]; then
    warn "a -wal file exists and is not empty"
    hint "the most recent rows — including messages deleted moments before seizure —"
    hint "live in the WAL, not in the main database. Query the set, not the file."
  fi
  command -v sqlite3 >/dev/null && {
    info "journal mode"
    sqlite3 "$OUT/pulled/$(basename "$db")" "PRAGMA journal_mode;" 2>/dev/null | sed 's/^/  /'
    info "tables"
    sqlite3 "$OUT/pulled/$(basename "$db")" ".tables" 2>/dev/null | sed 's/^/  /'
  }
}

cmd_leapp() {
  local dir="${1:-$OUT}"
  [[ -d "$dir" ]] || die "usage: $0 leapp <collection-dir>"
  command -v aleapp >/dev/null 2>&1 || command -v aleapp.py >/dev/null 2>&1 \
    || die "ALEAPP not found (pip install aleapp)"
  local rpt="$dir/aleapp-report"
  banner "ALEAPP" "$dir -> $rpt"
  if [[ -f "$dir/bugreport.zip" ]]; then
    aleapp -t zip -i "$dir/bugreport.zip" -o "$rpt" || warn "aleapp exited non-zero"
  else
    aleapp -t fs -i "$dir" -o "$rpt" || warn "aleapp exited non-zero"
  fi
  ok "report in $rpt"
  say ""
  cat <<'TXT'
  Now the part that is not optional:

  ALEAPP tells you WHERE TO LOOK. It is not a finding until you have confirmed
  it in the underlying database, with the path and the query recorded. Parsers
  make assumptions about schema versions, and a vendor schema change produces
  wrong timestamps silently, with no error in the report.

  That is why Session 9 asks for dual-tool validation, and why the methodology
  names both tools AND both versions.
TXT
}

case "${1:-}" in
  check)   shift; cmd_check "$@" ;;
  collect) shift; cmd_collect "$@" ;;
  pull)    shift; cmd_pull "$@" ;;
  leapp)   shift; cmd_leapp "$@" ;;
  ''|-h|--help|help) usage 0 ;;
  *) bad "unknown command: $1"; usage 1 ;;
esac
