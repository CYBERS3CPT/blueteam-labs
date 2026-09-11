#!/usr/bin/env bash
# acquire.sh — a disk acquisition that survives cross-examination
#
# It does four things you would otherwise do from memory at 02h00 and get wrong:
#   hashes the source BEFORE imaging, verifies the write block actually applied,
#   hashes the image afterwards, and writes contemporaneous notes as it goes
#   rather than reconstructing them later. Reconstructed notes are not
#   contemporaneous, and in cross-examination the difference is obvious.
#
#   ./acquire.sh list                         what block devices exist
#   ./acquire.sh blockcheck /dev/sdX          apply and VERIFY a software write block
#   ./acquire.sh image /dev/sdX --case C-001 --exhibit EX-01 --examiner "Name"
#   ./acquire.sh verify evidence-001.E01      re-verify an existing image
#   ./acquire.sh coc --case C-001 ...         chain of custody form, pre-filled
#
# A hardware write blocker remains the defensible option. blockdev --setro is a
# software measure that can be silently ineffective depending on the subsystem,
# which is exactly why this script tests it by trying to write.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

NOTES=""
note() {  # every action, timestamped, as it happens
  local line="$(utc)  $*"
  printf '%s\n' "$line"
  [[ -n "$NOTES" ]] && printf '%s\n' "$line" >> "$NOTES"
}

usage() { sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

cmd_list() {
  banner "Block devices" "identify the target by SERIAL, never by /dev name"
  hint "/dev names are assigned in the order the kernel noticed things. They move."
  if command -v lsblk >/dev/null 2>&1; then
    lsblk -o NAME,SIZE,TYPE,MODEL,SERIAL,MOUNTPOINT,RO 2>/dev/null | sed 's/^/  /'
  else
    warn "lsblk not available (macOS: use diskutil list)"
    command -v diskutil >/dev/null && diskutil list | sed 's/^/  /'
  fi
  say ""
  hint "RO=1 means read-only at the block layer. That column is the one to check."
}

cmd_blockcheck() {
  local dev="${1:-}"; [[ -b "$dev" ]] || die "usage: $0 blockcheck /dev/sdX  (must be a block device)"
  require_root
  banner "Write block on $dev" "apply, then PROVE it — do not assume"

  note "SET-RO  applying blockdev --setro to $dev"
  blockdev --setro "$dev" || die "could not set read-only"

  local ro; ro=$(blockdev --getro "$dev")
  [[ "$ro" == "1" ]] || die "blockdev reports RO=$ro — the flag did not take"
  ok "blockdev --getro returns 1"

  # The actual test. If this write SUCCEEDS, the block is not a block, and you
  # have just modified evidence — which is why it targets one sector and why
  # the script stops hard either way.
  info "attempting a one-sector write, which must FAIL"
  if dd if=/dev/zero of="$dev" bs=512 count=1 conv=notrunc 2>/dev/null; then
    bad "THE WRITE SUCCEEDED. This device is NOT write-blocked."
    bad "The evidence may have been modified. Stop, document, and escalate."
    note "BLOCK-FAIL  test write to $dev SUCCEEDED — device is writable"
    exit 2
  fi
  ok "write refused, as it must be"
  note "BLOCK-OK  test write to $dev refused; write block verified"

  info "automount"
  if systemctl is-active --quiet udisks2 2>/dev/null; then
    warn "udisks2 is running — it has mounted evidence before"
    hint "sudo systemctl stop udisks2   (and disable it on your examination machine, permanently)"
  else
    ok "udisks2 not active"
  fi
}

cmd_image() {
  local dev="" case_ref="" exhibit="" examiner="" fmt="e01" outdir="."
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --case) case_ref="$2"; shift 2 ;;
      --exhibit) exhibit="$2"; shift 2 ;;
      --examiner) examiner="$2"; shift 2 ;;
      --format) fmt="$2"; shift 2 ;;
      --out) outdir="$2"; shift 2 ;;
      *) dev="$1"; shift ;;
    esac
  done
  [[ -b "$dev" ]] || die "usage: $0 image /dev/sdX --case C-001 --exhibit EX-01 --examiner \"Name\""
  [[ -n "$case_ref" && -n "$exhibit" && -n "$examiner" ]] || die "--case, --exhibit and --examiner are all required (they go in the report)"
  require_root

  mkdir -p "$outdir"
  local base="$outdir/${case_ref}-${exhibit}"
  NOTES="${base}-notes.txt"
  : > "$NOTES"

  banner "Acquisition" "$case_ref / $exhibit / $examiner"
  note "START   acquisition of $dev"
  note "TOOLS   $(uname -srm)"
  command -v dc3dd    >/dev/null && note "TOOL    $(dc3dd --version 2>&1 | head -1)"
  command -v ewfacquire >/dev/null && note "TOOL    $(ewfacquire -V 2>&1 | head -1)"

  # Device identity, recorded before anything else
  note "DEVICE  $(lsblk -dno MODEL,SERIAL,SIZE "$dev" 2>/dev/null | xargs)"
  local ro; ro=$(blockdev --getro "$dev" 2>/dev/null || echo "?")
  note "RO      blockdev --getro = $ro"
  if [[ "$ro" != "1" ]]; then
    bad "device is NOT read-only"
    hint "run: $0 blockcheck $dev   — and do not proceed until it passes"
    exit 1
  fi

  local size; size=$(blockdev --getsize64 "$dev")
  info "source is $((size/1024/1024/1024)) GB — this will take a while"
  df -h "$outdir" | tail -1 | sed 's/^/     /'
  confirm "proceed with acquisition of $dev?" || { note "ABORT   operator declined"; exit 0; }

  # 1. hash the source FIRST. Without this, the image hash proves only that the
  #    image has not changed since you made it — not that it matches the source.
  info "hashing source (pass 1 of 2 over the whole device; yes, it doubles the time)"
  note "HASH-SRC-START"
  local src_hash; src_hash=$(sha256 "$dev" | awk '{print $1}')
  note "HASH-SRC $src_hash"
  ok "source sha256: $src_hash"

  # 2. acquire
  local image
  if [[ "$fmt" == "e01" ]] && command -v ewfacquire >/dev/null 2>&1; then
    image="${base}.E01"
    note "ACQUIRE ewfacquire -> $image"
    ewfacquire -u -t "${base}" -f encase6 -d sha256 -c best \
      -C "$case_ref" -E "$exhibit" -e "$examiner" \
      -D "acquired $(utc)" "$dev" 2>&1 | tee -a "$NOTES"
  else
    [[ "$fmt" == "e01" ]] && warn "ewfacquire not found — falling back to raw"
    image="${base}.dd"
    need dc3dd "sudo apt install -y dc3dd" || die "need dc3dd or ewfacquire"
    note "ACQUIRE dc3dd -> $image"
    dc3dd if="$dev" of="$image" hash=sha256 log="${base}-dc3dd.log" 2>&1 | tee -a "$NOTES"
  fi

  # 3. hash the image
  info "hashing image"
  local img_hash; img_hash=$(sha256 "$image" 2>/dev/null | awk '{print $1}')
  note "HASH-IMG $img_hash"

  # 4. verify
  say ""
  rule
  if [[ "$image" == *.E01 ]]; then
    info "ewfverify (verifies the embedded per-block digests)"
    ewfverify "$image" 2>&1 | tail -8 | sed 's/^/     /' | tee -a "$NOTES"
    note "COMPARE E01 stores its own source digest; compare it against HASH-SRC above"
  elif [[ "$src_hash" == "$img_hash" ]]; then
    ok "source and image hashes MATCH"
    note "COMPARE MATCH"
  else
    bad "source and image hashes DO NOT MATCH"
    bad "  source: $src_hash"
    bad "  image:  $img_hash"
    note "COMPARE MISMATCH src=$src_hash img=$img_hash"
    say ""
    cat <<'MM'
  This is not a disaster. An UNRECORDED mismatch is.

    1. It is already recorded, above, in the notes file. Leave it there.
    2. Re-acquire if the media allows, and compare the two images.
    3. Determine and document the cause if you can — failing media, a device
       writing to itself, a bad cable.
    4. If you cannot, say so, and state which findings the discrepancy affects.

  What you do NOT do is re-run until a pair matches and report only that one.
  That is not a documentation failure; it is misconduct.
MM
  fi

  note "END     acquisition complete"
  say ""
  ok "image:  $image"
  ok "notes:  $NOTES"
  hint "next: $0 coc --case $case_ref --exhibit $exhibit --examiner \"$examiner\" --source-hash $src_hash --image-hash $img_hash"
}

cmd_verify() {
  local img="${1:-}"; [[ -f "$img" ]] || die "usage: $0 verify <image>"
  banner "Verifying $(basename "$img")"
  if [[ "$img" == *.E01 ]]; then
    need ewfverify || exit 1
    ewfverify "$img" | sed 's/^/  /'
    command -v ewfinfo >/dev/null && { say ""; info "embedded metadata"; ewfinfo "$img" | sed 's/^/  /' | head -25; }
  else
    info "sha256 (this reads the whole image; go and do something else)"
    sha256 "$img" | sed 's/^/  /'
    hint "compare against the value recorded in the acquisition notes"
  fi
}

cmd_coc() {
  local case_ref="" exhibit="" examiner="" sh="" ih="" desc=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --case) case_ref="$2"; shift 2 ;;
      --exhibit) exhibit="$2"; shift 2 ;;
      --examiner) examiner="$2"; shift 2 ;;
      --source-hash) sh="$2"; shift 2 ;;
      --image-hash) ih="$2"; shift 2 ;;
      --description) desc="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  local f="chain-of-custody-${case_ref:-CASE}-${exhibit:-EX}.md"
  cat > "$f" <<COC
# Chain of Custody

| | |
|---|---|
| Case reference | ${case_ref:-________} |
| Exhibit ID | ${exhibit:-________} |
| Description | ${desc:-make / model / serial / capacity / condition} |
| Seized by | ________  (name, role, organisation) |
| Seized at | ________  (date, time **in UTC**, location) |
| Authority | ________  (warrant / policy / consent — reference number) |
| Initial seal number | ________ |

## Acquisition

| | |
|---|---|
| Examiner | ${examiner:-________} |
| Date/time (UTC) | $(utc) |
| Method and tool | ________  (tool name **and version** — versions matter when a bug is found later) |
| Write blocker | ________  (make / model / serial) |
| Source hash (SHA-256) | ${sh:-________} |
| Image hash (SHA-256) | ${ih:-________} |
| Verified by | ________ |

## Transfers

One row per movement. **One gap defeats the whole record** — not weakens, defeats.
The opposing expert needs to find exactly one.

| From | To | Date/time (UTC) | Purpose | Seal broken | New seal | Signatures |
|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |

## Storage

| | |
|---|---|
| Location | ________ |
| Access control | ________  (who else has the combination?) |
| Environmental conditions | ________ |

## Disposal

| | |
|---|---|
| Date | ________ |
| Method | ________ |
| Authorised by | ________ |

---
*Generated $(utc). The questions a classmate will ask you: where was this item
between 14:20 and 16:45, who else had access to the safe, what is the seal number
and when was it broken, which timezone is that timestamp in and how do you know
the clock was right, and who verified the hash — against what.*
COC
  ok "wrote $f"
  hint "fill it in now, not later. Later is how the gaps appear."
}

case "${1:-}" in
  list)       shift; cmd_list "$@" ;;
  blockcheck) shift; cmd_blockcheck "$@" ;;
  image)      shift; cmd_image "$@" ;;
  verify)     shift; cmd_verify "$@" ;;
  coc)        shift; cmd_coc "$@" ;;
  ''|-h|--help|help) usage 0 ;;
  *) bad "unknown command: $1"; usage 1 ;;
esac
