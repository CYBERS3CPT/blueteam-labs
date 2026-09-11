#!/usr/bin/env python3
"""
epoch.py — convert the timestamps mobile forensics actually throws at you.

Getting the epoch wrong produces timestamps that are plausible and wrong by
decades, or by hours. Both are worse than a blank field, because a blank field
gets questioned and a plausible wrong answer does not.

Usage
    ./epoch.py 1793318400                 guess the epoch, show every reading
    ./epoch.py 1793318400 --as unix
    ./epoch.py 784500000 --as apple
    ./epoch.py 13400000000000000 --as filetime
    ./epoch.py --list                     the epochs, and where each turns up
    ./epoch.py --sql                      SQL snippets for the common databases

With no --as, it prints every interpretation and marks the ones that land in a
plausible range. That is how you check an unfamiliar column: convert one value
you already know the answer to, and see which epoch agrees with you.
"""

import argparse
import sys
from datetime import datetime, timedelta, timezone

UTC = timezone.utc

EPOCHS = {
    "unix":      ("Unix seconds",        datetime(1970, 1, 1, tzinfo=UTC), 1,
                  "Linux, many Android tables, most REST APIs"),
    "unix_ms":   ("Unix milliseconds",   datetime(1970, 1, 1, tzinfo=UTC), 1_000,
                  "Most Android app databases. If a 'unix' value lands in 1970, try this."),
    "unix_us":   ("Unix microseconds",   datetime(1970, 1, 1, tzinfo=UTC), 1_000_000,
                  "Some Android and Linux userspace"),
    "apple":     ("Apple / Cocoa",       datetime(2001, 1, 1, tzinfo=UTC), 1,
                  "iOS plists, KnowledgeC, sms.db, CoreData. THE one people miss."),
    "apple_ns":  ("Apple nanoseconds",   datetime(2001, 1, 1, tzinfo=UTC), 1_000_000_000,
                  "Some Biome / SEGB values"),
    "webkit":    ("WebKit / Chrome",     datetime(1601, 1, 1, tzinfo=UTC), 1_000_000,
                  "Chrome history, cookies, downloads"),
    "filetime":  ("Windows FILETIME",    datetime(1601, 1, 1, tzinfo=UTC), 10_000_000,
                  "Windows artefacts, 100-nanosecond intervals"),
    "gps":       ("GPS time",            datetime(1980, 1, 6, tzinfo=UTC), 1,
                  "GNSS data; note it does not count leap seconds"),
    "mac_hfs":   ("HFS+ / classic Mac",  datetime(1904, 1, 1, tzinfo=UTC), 1,
                  "Old HFS+ volumes, some resource forks"),
}

# Anything outside this is almost certainly the wrong epoch rather than a
# genuine timestamp. Widen the window below if you are reading very old media.
# A rolling window: twenty years back, five forward. No edit needed in 2031.
_Y = datetime.now(UTC).year
PLAUSIBLE = (datetime(_Y - 20, 1, 1, tzinfo=UTC), datetime(_Y + 5, 1, 1, tzinfo=UTC))

SQL = """
-- Android: unix milliseconds (the common case)
SELECT datetime(date/1000, 'unixepoch') AS utc, address, body FROM sms;

-- Android: unix seconds
SELECT datetime(ts, 'unixepoch') AS utc, * FROM events;

-- iOS: Apple absolute time -> UTC   (+978307200 seconds from 2001 to 1970)
SELECT datetime(ZDATE + 978307200, 'unixepoch') AS utc, * FROM ZOBJECT;

-- iOS KnowledgeC: start, end and the duration people forget to compute
SELECT datetime(ZSTARTDATE + 978307200, 'unixepoch') AS start_utc,
       datetime(ZENDDATE   + 978307200, 'unixepoch') AS end_utc,
       CAST(ZENDDATE - ZSTARTDATE AS INT)            AS seconds,
       ZSTREAMNAME, ZVALUESTRING
FROM   ZOBJECT
WHERE  ZSTREAMNAME IN ('/app/inFocus', '/display/isBacklit')
ORDER  BY ZSTARTDATE;

-- Chrome: WebKit microseconds since 1601
SELECT datetime(last_visit_time/1000000 - 11644473600, 'unixepoch') AS utc, url, title
FROM   urls ORDER BY last_visit_time DESC;

-- Chrome downloads
SELECT datetime(start_time/1000000 - 11644473600, 'unixepoch') AS utc,
       target_path, tab_url
FROM   downloads;

-- Before trusting any of the above: check the journal mode. If it says 'wal',
-- the recent rows are in the -wal file and you need all three files.
PRAGMA journal_mode;
"""


def convert(value, key):
    name, base, div, _ = EPOCHS[key]
    try:
        return base + timedelta(seconds=value / div)
    except (OverflowError, OSError, ValueError):
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("value", nargs="?", help="the raw number from the database")
    ap.add_argument("--as", dest="epoch", choices=sorted(EPOCHS), help="force one epoch")
    ap.add_argument("--list", action="store_true", help="the epochs, and where each turns up")
    ap.add_argument("--sql", action="store_true", help="SQL snippets for the common databases")
    args = ap.parse_args()

    if args.list:
        print()
        for k, (name, base, div, where) in EPOCHS.items():
            print(f"  {k:<10} {name:<22} base {base:%Y-%m-%d}  /{div}")
            print(f"             {where}")
        print()
        return

    if args.sql:
        print(SQL)
        return

    if not args.value:
        ap.print_help()
        sys.exit(1)

    try:
        raw = float(args.value.replace(",", "").replace("_", ""))
    except ValueError:
        sys.exit(f" fail  not a number: {args.value}")

    if args.epoch:
        dt = convert(raw, args.epoch)
        print(dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else " fail  out of range")
        return

    print(f"\n  raw value: {args.value}\n")
    hits = []
    for k, (name, _, _, where) in EPOCHS.items():
        dt = convert(raw, k)
        if dt is None:
            print(f"  {k:<10} {'out of range':<26}")
            continue
        plausible = PLAUSIBLE[0] <= dt <= PLAUSIBLE[1]
        mark = " <-- plausible" if plausible else ""
        if plausible:
            hits.append((k, dt))
        print(f"  {k:<10} {dt:%Y-%m-%dT%H:%M:%SZ}{mark}")
    print()
    if len(hits) == 1:
        k, dt = hits[0]
        print(f"  Only {k} lands in a plausible range: {dt:%Y-%m-%d %H:%M:%S} UTC")
        print(f"  {EPOCHS[k][3]}")
    elif len(hits) > 1:
        print(f"  {len(hits)} epochs are plausible: {', '.join(k for k, _ in hits)}")
        print("  Disambiguate by converting a value you already know the answer to —")
        print("  a message you sent yourself, a photo you took, a login you made.")
    else:
        print(f"  Nothing lands in {PLAUSIBLE[0].year}-{PLAUSIBLE[1].year}. Either the column is not a timestamp,")
        print("  or it is an offset, a duration, or a counter. Check the schema.")
    print()


if __name__ == "__main__":
    main()
