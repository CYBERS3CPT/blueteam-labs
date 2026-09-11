#!/usr/bin/env python3
"""
timeline-reduce.py — turn a super timeline into a finding.

A 4-million-row timeline is a dataset. A 200-row filtered timeline is a finding.
The difference is an anchor event and a defensible filter — and the filter has to
travel with the output, or your 200 rows are unexplainable and therefore useless.

Usage
    ./timeline-reduce.py tl.csv --anchor "YYYY-MM-DD 03:12:00" --window 12h
    ./timeline-reduce.py tl.csv --anchor-grep "ransom" --window 24h
    ./timeline-reduce.py tl.csv --anchor ... --user ana --types exec,filecreate
    ./timeline-reduce.py tl.csv --peaks            find candidate anchors for me

Input is psort.py CSV output (`psort.py -o dynamic`), or anything with a parseable
datetime in the first column. Output is a CSV, plus a `.filter.txt` next to it
recording exactly how it was produced.

Everything is UTC. If your input is not UTC, fix that first — a timeline mixing
timezones is worse than no timeline, because it looks authoritative.
"""

import argparse
import csv
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Artefact groupings. The names on the left are what an analyst asks for; the
# patterns on the right are what plaso actually writes.
TYPE_PATTERNS = {
    "exec":       r"prefetch|amcache|shimcache|userassist|bam/dam|srum|4688|process",
    "filecreate": r"filestat|usnjrnl|\$mft|mft|file created|lnk|link",
    "logon":      r"4624|4625|4634|4648|logon|winlogon|lastlog|wtmp|secure|auth\.log",
    "registry":   r"winreg|registry|ntuser|usrclass|run key|runonce",
    "browser":    r"chrome|firefox|edge|safari|history|cookie|download|webhist",
    "network":    r"firewall|dns|netflow|connection|sysmon.*3\b",
    "persist":    r"task scheduler|scheduled task|service|7045|systemd|cron|autorun|runonce",
    "usb":        r"usbstor|setupapi|volume serial|removable",
}

# Ordered most-specific first: strptime is happy to match a shorter format and
# silently throw away the offset, which is how a timeline quietly becomes local time.
TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",   "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",      "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",      "%d/%m/%Y %H:%M:%S",
    "%Y-%m-%d",
)


def parse_ts(s):
    if not s:
        return None
    s = s.strip().replace("Z", "+0000")
    # plaso dynamic output looks like "2025-06-14T03:12:00.000000+00:00"
    s = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", s)
    for fmt in TS_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def parse_window(w):
    m = re.fullmatch(r"(\d+)\s*([smhd])", w.strip().lower())
    if not m:
        raise ValueError(f"window looks wrong: {w!r} — try 30m, 12h, 2d")
    n, unit = int(m.group(1)), m.group(2)
    field = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]
    return timedelta(**{field: n})


def load(path):
    """Yield (datetime, rowdict). Tolerant about which column holds the time."""
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        sample = fh.read(8192)
        fh.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(fh, dialect=dialect)
        if not reader.fieldnames:
            sys.exit(" fail  no header row in that CSV")

        ts_col = next((c for c in reader.fieldnames
                       if c and c.lower() in ("datetime", "timestamp", "date", "time")),
                      reader.fieldnames[0])

        for row in reader:
            dt = parse_ts(row.get(ts_col, ""))
            # plaso splits date and time across two columns in some outputs
            if dt is None and len(reader.fieldnames) > 1:
                dt = parse_ts(f"{row.get(reader.fieldnames[0],'')} {row.get(reader.fieldnames[1],'')}")
            if dt:
                yield dt, row


def rowtext(row):
    return " ".join(str(v) for v in row.values() if v).lower()


def cmd_peaks(path, top=15):
    """Find candidate anchors: the busiest minutes, and the rare-but-loud events."""
    per_hour, per_minute = Counter(), Counter()
    total = 0
    for dt, _ in load(path):
        total += 1
        per_hour[dt.replace(minute=0, second=0, microsecond=0)] += 1
        per_minute[dt.replace(second=0, microsecond=0)] += 1
    if not total:
        sys.exit(" fail  no parseable timestamps")

    print(f"\n  {total:,} event(s) across {len(per_hour)} hour(s)\n")
    print("  Busiest minutes — a spike is usually an install, an update, or the thing you are looking for")
    for ts, n in per_minute.most_common(top):
        bar = "█" * min(40, n * 40 // max(per_minute.values()))
        print(f"    {ts:%Y-%m-%d %H:%M}  {n:>7,}  {bar}")

    quiet = [ts for ts, n in sorted(per_hour.items()) if n <= 2]
    if quiet:
        print(f"\n  Hours with almost nothing ({len(quiet)}) — activity here stands out,")
        print("  which is why 03h00 is such a productive place to look:")
        for ts in quiet[:8]:
            print(f"    {ts:%Y-%m-%d %H:00}  {per_hour[ts]} event(s)")
    print("\n  Pick one, then: --anchor \"YYYY-MM-DD HH:MM:SS\" --window 12h\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csvfile")
    ap.add_argument("--anchor", help="anchor time, UTC, e.g. 'YYYY-MM-DD HH:MM:SS'")
    ap.add_argument("--anchor-grep", help="use the FIRST row matching this regex as the anchor")
    ap.add_argument("--window", default="12h", help="± around the anchor (default 12h)")
    ap.add_argument("--user", help="keep only rows mentioning this user")
    ap.add_argument("--path", help="keep only rows mentioning this path fragment")
    ap.add_argument("--types", help="comma-separated: " + ",".join(TYPE_PATTERNS))
    ap.add_argument("--exclude", help="regex; drop matching rows (known-good noise)")
    ap.add_argument("--max", type=int, default=300, help="warn above this many rows (default 300)")
    ap.add_argument("--out", help="output CSV (default: <input>.reduced.csv)")
    ap.add_argument("--peaks", action="store_true", help="suggest anchors instead of filtering")
    args = ap.parse_args()

    if not Path(args.csvfile).is_file():
        sys.exit(f" fail  no such file: {args.csvfile}")

    if args.peaks:
        cmd_peaks(args.csvfile)
        return

    if not (args.anchor or args.anchor_grep):
        sys.exit(" fail  need --anchor or --anchor-grep (or --peaks to find one)\n"
                 "       a timeline without an anchor is a dataset, not a finding")

    window = parse_window(args.window)

    anchor = None
    if args.anchor:
        anchor = parse_ts(args.anchor)
        if not anchor:
            sys.exit(f" fail  could not parse anchor: {args.anchor!r}")
    else:
        rx = re.compile(args.anchor_grep, re.I)
        for dt, row in load(args.csvfile):
            if rx.search(rowtext(row)):
                anchor = dt
                print(f"  anchor from --anchor-grep {args.anchor_grep!r}: {anchor:%Y-%m-%d %H:%M:%S} UTC")
                break
        if not anchor:
            sys.exit(f" fail  nothing matched {args.anchor_grep!r}")

    lo, hi = anchor - window, anchor + window
    type_rx = None
    if args.types:
        wanted = [t.strip() for t in args.types.split(",") if t.strip()]
        unknown = [t for t in wanted if t not in TYPE_PATTERNS]
        if unknown:
            sys.exit(f" fail  unknown type(s): {', '.join(unknown)}\n"
                     f"       available: {', '.join(TYPE_PATTERNS)}")
        type_rx = re.compile("|".join(TYPE_PATTERNS[t] for t in wanted), re.I)
    excl_rx = re.compile(args.exclude, re.I) if args.exclude else None

    kept, total, dropped = [], 0, Counter()
    fieldnames = None
    for dt, row in load(args.csvfile):
        total += 1
        fieldnames = fieldnames or list(row.keys())
        if not (lo <= dt <= hi):
            dropped["outside window"] += 1; continue
        txt = rowtext(row)
        if args.user and args.user.lower() not in txt:
            dropped["user"] += 1; continue
        if args.path and args.path.lower() not in txt:
            dropped["path"] += 1; continue
        if type_rx and not type_rx.search(txt):
            dropped["artefact type"] += 1; continue
        if excl_rx and excl_rx.search(txt):
            dropped["excluded"] += 1; continue
        kept.append((dt, row))

    kept.sort(key=lambda x: x[0])
    out = Path(args.out or (Path(args.csvfile).with_suffix("") .name + ".reduced.csv"))
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for _, row in kept:
            w.writerow(row)

    # The filter travels with the output. Without this file, the reduction is
    # not reproducible, and an irreproducible reduction is not evidence.
    filt = out.with_suffix(".filter.txt")
    filt.write_text(
        "Timeline reduction\n"
        f"  produced      {datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}\n"
        f"  source        {args.csvfile}\n"
        f"  anchor (UTC)  {anchor:%Y-%m-%d %H:%M:%S}\n"
        f"  window        ±{args.window}  ({lo:%Y-%m-%d %H:%M:%S} .. {hi:%Y-%m-%d %H:%M:%S} UTC)\n"
        f"  user          {args.user or '(any)'}\n"
        f"  path          {args.path or '(any)'}\n"
        f"  types         {args.types or '(all)'}\n"
        f"  exclude       {args.exclude or '(none)'}\n"
        f"  rows in       {total}\n"
        f"  rows out      {len(kept)}\n"
        "\nEquivalent psort.py expression:\n"
        f'  psort.py -o dynamic -w out.csv timeline.plaso \\\n'
        f'    "date > \'{lo:%Y-%m-%d %H:%M:%S}\' AND date < \'{hi:%Y-%m-%d %H:%M:%S}\'"\n'
        "\nInclude this file in the report appendix. Without it the reduced\n"
        "timeline cannot be reproduced, and a finding that cannot be reproduced\n"
        "is an assertion.\n"
    )

    print()
    print(f"  anchor    {anchor:%Y-%m-%d %H:%M:%S} UTC")
    print(f"  window    ±{args.window}")
    print(f"  in        {total:,} rows")
    for reason, n in dropped.most_common():
        print(f"    dropped {n:>9,}  {reason}")
    print(f"  out       {len(kept):,} rows  -> {out}")
    print(f"  filter    {filt}")

    if len(kept) > args.max:
        print()
        print(f"  {len(kept):,} rows is still a dataset. Narrow the window, add --types,")
        print("  or pick a tighter anchor. Nobody reads 2,000 rows, including you.")
    elif len(kept) == 0:
        print()
        print("  Zero rows. Either the anchor is wrong or the filters are. Try --peaks.")
    else:
        print()
        print("  First and last, for sanity:")
        for dt, row in (kept[0], kept[-1]):
            preview = " | ".join(str(v)[:28] for v in list(row.values())[1:4])
            print(f"    {dt:%Y-%m-%d %H:%M:%S}  {preview}")
    print()


if __name__ == "__main__":
    main()
