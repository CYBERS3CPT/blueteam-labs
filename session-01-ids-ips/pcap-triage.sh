#!/usr/bin/env bash
# pcap-triage.sh — the first ten minutes with a capture, without the GUI
#
# Wireshark is better than this for everything except the first ten minutes.
# In the first ten minutes you want to know who talked to whom, what they asked
# DNS, which TLS names went past, and whether anything looks like a beacon. That
# is this script.
#
#   ./pcap-triage.sh capture.pcap                everything
#   ./pcap-triage.sh capture.pcap --section dns
#   ./pcap-triage.sh capture.pcap --beacons      the periodicity check
#   ./pcap-triage.sh capture.pcap --out ./triage
#
# Sections: overview talkers dns tls http files beacons
#
# Read-only. It does not replay, inject, or resolve anything against the network.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
set +o errexit

PCAP=""; ONLY=""; OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --section) ONLY="$2"; shift 2 ;;
    --beacons) ONLY="beacons"; shift ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) PCAP="$1"; shift ;;
  esac
done
[[ -n "$PCAP" && -f "$PCAP" ]] || die "usage: $0 <capture.pcap> [--section <name>]"
need tshark "sudo apt install -y tshark" || exit 1
[[ -n "$OUT" ]] && mkdir -p "$OUT"

want() { [[ -z "$ONLY" || "$ONLY" == "$1" ]]; }
save() { [[ -n "$OUT" ]] && tee "$OUT/$1" || cat; }

want overview && {
banner "Overview: $(basename "$PCAP")"
capinfos -c -d -u -a -e "$PCAP" 2>/dev/null | sed 's/^/  /' | head -12 \
  || tshark -r "$PCAP" -q -z io,phs 2>/dev/null | head -20 | sed 's/^/  /'
say ""
info "protocol hierarchy — where the bytes actually are"
tshark -r "$PCAP" -q -z io,phs 2>/dev/null | sed -n '/^===/,/^===/p' | head -30 | sed 's/^/  /'
}

want talkers && {
banner "Conversations" "by bytes, because volume is where exfiltration hides"
tshark -r "$PCAP" -q -z conv,ip 2>/dev/null | head -25 | sed 's/^/  /' | save talkers.txt
say ""
info "external destinations only"
# RFC1918, loopback and multicast stripped: what left the building.
tshark -r "$PCAP" -T fields -e ip.dst 2>/dev/null \
  | grep -vE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|22[4-9]\.|23[0-9]\.|255\.|0\.0\.0\.0|$)' \
  | sort | uniq -c | sort -rn | head -20 | sed 's/^/  /' | save external.txt
}

want dns && {
banner "DNS" "the cheapest place to find C2, and the first thing people skip"
info "queried names"
tshark -r "$PCAP" -Y 'dns.flags.response==0' -T fields -e dns.qry.name 2>/dev/null \
  | sort | uniq -c | sort -rn | head -30 | sed 's/^/  /' | save dns-queries.txt

say ""
info "NXDOMAIN — a burst of these is a DGA, or a typo in a config"
tshark -r "$PCAP" -Y 'dns.flags.rcode==3' -T fields -e dns.qry.name 2>/dev/null \
  | sort -u | head -20 | sed 's/^/  /'

say ""
info "long or high-entropy labels — tunnelling and DGA look like this"
tshark -r "$PCAP" -Y 'dns.flags.response==0' -T fields -e dns.qry.name 2>/dev/null | sort -u \
  | awk '{ n=split($0,a,"."); lbl=a[1];
           if (length(lbl) >= 25) print "  " length(lbl) "  " $0 }' | sort -rn | head -15
hint "a 40-character first label is not a hostname, it is a payload"

say ""
info "TXT queries — small, boring, and a complete covert channel"
tshark -r "$PCAP" -Y 'dns.qry.type==16' -T fields -e dns.qry.name 2>/dev/null \
  | sort | uniq -c | sort -rn | head -10 | sed 's/^/  /' || say "  (none)"
}

want tls && {
banner "TLS" "SNI survives encryption; that is the whole point of looking"
tshark -r "$PCAP" -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name 2>/dev/null \
  | grep -v '^$' | sort | uniq -c | sort -rn | head -25 | sed 's/^/  /' | save tls-sni.txt

say ""
info "JA3 fingerprints, if your tshark builds them"
tshark -r "$PCAP" -Y 'tls.handshake.type==1' -T fields -e tls.handshake.ja3_full 2>/dev/null \
  | grep -v '^$' | md5sum 2>/dev/null >/dev/null && \
  tshark -r "$PCAP" -Y 'tls.handshake.type==1' -T fields -e tls.handshake.ja3 2>/dev/null \
    | grep -v '^$' | sort | uniq -c | sort -rn | head -10 | sed 's/^/  /' \
  || hint "not available in this tshark build"

say ""
info "self-signed or odd certificates"
tshark -r "$PCAP" -Y 'tls.handshake.type==11' -T fields \
  -e tls.handshake.certificate 2>/dev/null | wc -l | xargs printf '  %s certificate message(s)\n'
hint "pull them properly with: tshark -r $PCAP --export-objects tls,./certs"
}

want http && {
banner "HTTP" "still plaintext more often than anyone admits"
info "hosts"
tshark -r "$PCAP" -Y 'http.request' -T fields -e http.host 2>/dev/null \
  | sort | uniq -c | sort -rn | head -20 | sed 's/^/  /' | save http-hosts.txt
say ""
info "user agents — one weird one in a sea of normal is the finding"
tshark -r "$PCAP" -Y 'http.request' -T fields -e http.user_agent 2>/dev/null \
  | sort | uniq -c | sort -rn | head -15 | sed 's/^/  /'
say ""
info "POSTs — where credentials and exfiltration go"
tshark -r "$PCAP" -Y 'http.request.method=="POST"' -T fields \
  -e http.host -e http.request.uri 2>/dev/null | sort -u | head -15 | sed 's/^/  /' || say "  (none)"
}

want files && {
banner "Transferred objects"
if [[ -n "$OUT" ]]; then
  mkdir -p "$OUT/objects"
  for proto in http tftp smb imf; do
    tshark -r "$PCAP" --export-objects "$proto,$OUT/objects" -q >/dev/null 2>&1
  done
  n=$(find "$OUT/objects" -type f 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$n" -gt 0 ]]; then
    ok "$n object(s) exported to $OUT/objects"
    find "$OUT/objects" -type f -exec sha256 {} \; 2>/dev/null | head -20 | sed 's/^/  /'
    warn "these came off the wire. Treat them as Session 3 material, not as files."
  else
    say "  (none)"
  fi
else
  hint "pass --out <dir> to export transferred objects"
fi
}

want beacons && {
banner "Beacon check" "regularity is the signal; humans are not regular"
info "candidate pairs with >= 8 connections"
# A beacon is a conversation whose inter-arrival times cluster tightly. Humans
# browsing produce a wide spread; a scheduled callback produces a narrow one.
tshark -r "$PCAP" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport 2>/dev/null \
 | awk -F'\t' 'NF>=3 && $2!="" && $3!="" {
     # external destinations only
     if ($3 ~ /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|22[4-9]\.)/) next
     key = $2 " -> " $3 (($4!="") ? ":" $4 : "")
     if (key in last) { d = $1 - last[key]; if (d > 0.05) { sum[key]+=d; sq[key]+=d*d; n[key]++ } }
     last[key] = $1
   }
   END {
     for (k in n) if (n[k] >= 8) {
       mean = sum[k]/n[k]
       var  = sq[k]/n[k] - mean*mean
       sd   = (var > 0) ? sqrt(var) : 0
       jitter = (mean > 0) ? sd/mean : 1
       printf "%.3f\t%d\t%.1f\t%.1f\t%s\n", jitter, n[k], mean, sd, k
     }
   }' | sort -n | head -20 | \
 awk -F'\t' 'BEGIN{printf "  %-8s %6s %9s %9s  %s\n","jitter","count","mean(s)","sd(s)","conversation"}
   { verdict = ($1 < 0.10) ? "  <- very regular" : (($1 < 0.25) ? "  <- regular" : "")
     printf "  %-8.3f %6d %9.1f %9.1f  %s%s\n", $1, $2, $3, $4, $5, verdict }'
say ""
hint "jitter is sd/mean. Below 0.10 is a scheduled callback, not a person."
hint "malleable profiles add jitter on purpose — 0.3 with a clean mean is still worth a look."
hint "and check the mean: 60.0s exactly is a cron job or a beacon, never a browser."
}

say ""
rule
[[ -n "$OUT" ]] && ok "artefacts in $OUT"
cat <<'NEXT'
  Turn a finding into a rule while it is fresh:
    ./suricata-lab.sh new-rule <short-name>     scaffolds it with the next free sid
    ./suricata-lab.sh replay <this pcap>        and prove it fires on this capture

  A detection you have not tested against the traffic that motivated it is a
  guess. Testing takes ninety seconds.
NEXT
exit 0
