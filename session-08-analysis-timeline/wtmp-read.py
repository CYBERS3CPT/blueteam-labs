#!/usr/bin/env python3
"""
wtmp-read.py — read a classic wtmp/btmp file from an evidence collection.

Debian 13 and current Kali replaced `last` with the wtmpdb version, which reads
a SQLite database and has no idea what to do with the binary wtmp of the
Debian 12 server you just collected. `utmpdump` went with it. This is the
fifty-line replacement, standard library only.

Usage
    ./wtmp-read.py collection/var/log/wtmp              sessions, like `last`
    ./wtmp-read.py collection/var/log/wtmp --raw        every record, as stored
    ./wtmp-read.py collection/var/log/btmp --raw        failed logins
    ./wtmp-read.py wtmp --csv > wtmp.csv                for your timeline

Times are printed in UTC, because wtmp stores seconds since the epoch. They are
still the HOST's clock, though: if that clock was wrong, so is every line here,
and the correction belongs in your notes, not in this output.

It assumes the glibc x86_64 record layout (384 bytes). If the file size is not
a multiple of that, it refuses rather than guessing: a misaligned parse prints
plausible-looking garbage, and plausible garbage is the worst kind.
"""

import argparse
import csv
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

# struct utmp, glibc, x86_64: type, pid, line, id, user, host, exit, session,
# tv_sec, tv_usec, addr_v6, unused
FMT = "<hxxi32s4s32s256shhiii16s20s"
SIZE = struct.calcsize(FMT)  # 384
TYPES = {0: "EMPTY", 1: "RUN_LVL", 2: "BOOT", 3: "NEW_TIME", 4: "OLD_TIME",
         5: "INIT", 6: "LOGIN", 7: "USER", 8: "DEAD", 9: "ACCOUNTING"}


def cstr(b):
    return b.split(b"\0", 1)[0].decode("utf-8", "replace")


def records(path):
    data = Path(path).read_bytes()
    if len(data) % SIZE:
        sys.exit(f" fail  {path}: {len(data)} bytes is not a multiple of {SIZE}.\n"
                 "       Not a glibc x86_64 utmp file, or truncated. Refusing to guess:\n"
                 "       a misaligned parse prints plausible garbage.")
    for off in range(0, len(data), SIZE):
        t, pid, line, _id, user, host, _e1, _e2, _sess, sec, usec, _addr, _ = \
            struct.unpack_from(FMT, data, off)
        yield {
            "offset": off,
            "type": TYPES.get(t, str(t)),
            "pid": pid,
            "line": cstr(line),
            "user": cstr(user),
            "host": cstr(host),
            "time": datetime.fromtimestamp(sec + usec / 1e6, tz=timezone.utc),
        }


def fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%SZ")


def sessions(recs):
    """Pair USER records with the DEAD record on the same line, as `last` does."""
    open_, out = {}, []
    for r in recs:
        if r["type"] == "USER":
            open_[r["line"]] = r
        elif r["type"] == "DEAD" and r["line"] in open_:
            s = open_.pop(r["line"])
            out.append((s, r))
        elif r["type"] == "BOOT":
            out.append((r, None))
    for s in open_.values():
        out.append((s, "open"))
    return sorted(out, key=lambda x: x[0]["time"], reverse=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--raw", action="store_true", help="every record, in file order")
    ap.add_argument("--csv", action="store_true", help="CSV of every record, UTC")
    a = ap.parse_args()

    recs = list(records(a.file))
    if a.csv:
        w = csv.writer(sys.stdout)
        w.writerow(["datetime", "type", "user", "line", "host", "pid", "offset"])
        for r in recs:
            w.writerow([r["time"].isoformat(), r["type"], r["user"], r["line"], r["host"], r["pid"], r["offset"]])
        return
    if a.raw:
        for r in recs:
            print(f"  {fmt(r['time'])}  {r['type']:<8} {r['user']:<10} {r['line']:<8} {r['host']:<18} pid={r['pid']}  @{r['offset']}")
    else:
        for s, e in sessions(recs):
            if s["type"] == "BOOT":
                print(f"  {'reboot':<10} {'system boot':<8} {s['host']:<18} {fmt(s['time'])}")
                continue
            end = "still logged in (or never logged out)" if e == "open" else \
                  f"- {fmt(e['time'])}  ({str(e['time'] - s['time']).split('.')[0]})"
            print(f"  {s['user']:<10} {s['line']:<8} {s['host']:<18} {fmt(s['time'])} {end}")
    print(f"\n  {len(recs)} record(s), {SIZE} bytes each. Times are UTC, on the host's clock —", file=sys.stderr)
    print("  apply the drift you recorded at collection before you quote any of them.", file=sys.stderr)


if __name__ == "__main__":
    main()
