#!/usr/bin/env python3
"""
ios-backup.py — find things in an iOS backup, where nothing is where you expect.

An iOS backup stores every file under a SHA-1 of "domain-relativePath", in a
two-hex-character directory. Manifest.db is the index, and without it the backup
is forty thousand files with meaningless names. This reads the index.

Usage
    ./ios-backup.py info <backup-dir>                 device, iOS, last backup
    ./ios-backup.py domains <backup-dir>              what is in it, by size
    ./ios-backup.py find <backup-dir> whatsapp        search paths and domains
    ./ios-backup.py get <backup-dir> <fileID|path>    copy one file out, hashed
    ./ios-backup.py knowledge <backup-dir>            KnowledgeC activity, decoded
    ./ios-backup.py sms <backup-dir>                  messages with real timestamps

Read-only: it opens the backup's databases with SQLite in immutable mode and
never writes into the backup directory.
"""

import argparse
import hashlib
import plistlib
import shutil
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

APPLE_EPOCH = 978307200  # seconds between 1970-01-01 and 2001-01-01


def die(msg):
    print(f" fail  {msg}", file=sys.stderr)
    sys.exit(1)


def ro_connect(path):
    """Immutable mode: SQLite will not create a journal, will not write, and
    will not care that the file is on read-only media."""
    return sqlite3.connect(f"file:{path}?immutable=1", uri=True)


def manifest(backup):
    m = Path(backup) / "Manifest.db"
    if not m.is_file():
        die(f"no Manifest.db in {backup} — is this an iOS backup directory?")
    return ro_connect(m)


def file_path(backup, file_id):
    return Path(backup) / file_id[:2] / file_id


def apple_ts(v):
    try:
        return datetime.fromtimestamp(float(v) + APPLE_EPOCH, timezone.utc)
    except Exception:
        return None


def cmd_info(backup):
    b = Path(backup)
    print()
    for name in ("Info.plist", "Manifest.plist", "Status.plist"):
        p = b / name
        if not p.is_file():
            print(f"  {name:<16} absent")
            continue
        try:
            data = plistlib.loads(p.read_bytes())
        except Exception as exc:
            print(f"  {name:<16} unreadable ({exc})")
            continue
        print(f"  ── {name}")
        keys = ("Device Name", "Product Name", "Product Type", "Product Version",
                "Build Version", "Serial Number", "Phone Number", "Last Backup Date",
                "IMEI", "ICCID", "Unique Identifier", "Target Identifier",
                "IsEncrypted", "Date", "BackupState", "IsFullBackup", "Version")
        for k in keys:
            if k in data:
                v = data[k]
                if isinstance(v, (bytes, bytearray)):
                    v = f"<{len(v)} bytes>"
                print(f"     {k:<22} {v}")
        print()

    enc = False
    mp = b / "Manifest.plist"
    if mp.is_file():
        try:
            enc = bool(plistlib.loads(mp.read_bytes()).get("IsEncrypted"))
        except Exception:
            pass
    if enc:
        print("  This backup is ENCRYPTED.")
        print("  Counter-intuitively, that means it contains MORE: Keychain items,")
        print("  Health data and Safari passwords are only included when the backup")
        print("  is encrypted. Worth knowing when advising what to request.")
    else:
        print("  This backup is NOT encrypted, so it excludes Keychain, Health and")
        print("  Safari passwords. State that as a limitation rather than reporting")
        print("  their absence as a finding.")
    print()


def cmd_domains(backup, top=30):
    con = manifest(backup)
    rows = con.execute("""
        SELECT domain, COUNT(*) n, COALESCE(SUM(LENGTH(file)),0) meta
        FROM Files WHERE flags = 1 GROUP BY domain ORDER BY n DESC LIMIT ?""",
        (top,)).fetchall()
    print()
    print(f"  {'domain':<52} {'files':>8}")
    print("  " + "─" * 62)
    for domain, n, _ in rows:
        print(f"  {domain[:51]:<52} {n:>8}")
    total = con.execute("SELECT COUNT(*) FROM Files WHERE flags=1").fetchone()[0]
    print("  " + "─" * 62)
    print(f"  {'total':<52} {total:>8}")
    print()
    print("  AppDomain-<bundle id> is third-party app data. AppDomainGroup and")
    print("  AppDomainPlugin are shared containers and extensions — people search")
    print("  the first and miss the other two.")
    print()


def cmd_find(backup, term, limit=60):
    con = manifest(backup)
    like = f"%{term}%"
    rows = con.execute("""
        SELECT fileID, domain, relativePath FROM Files
        WHERE flags = 1 AND (domain LIKE ? OR relativePath LIKE ?)
        ORDER BY domain, relativePath LIMIT ?""", (like, like, limit)).fetchall()
    if not rows:
        print(f"\n  nothing matching {term!r}\n")
        return
    print()
    for fid, domain, rel in rows:
        p = file_path(backup, fid)
        size = p.stat().st_size if p.is_file() else 0
        mark = "" if p.is_file() else "  (indexed but not present)"
        print(f"  {fid}  {size:>10,}  {domain}")
        print(f"  {'':38}{rel}{mark}")
    print()
    print(f"  {len(rows)} match(es). Pull one with:")
    print(f"    ./ios-backup.py get {backup} <fileID>")
    print()


def cmd_get(backup, ident, outdir="."):
    con = manifest(backup)
    row = con.execute("SELECT fileID, domain, relativePath FROM Files WHERE fileID = ?",
                      (ident,)).fetchone()
    if not row:
        row = con.execute("""SELECT fileID, domain, relativePath FROM Files
                             WHERE relativePath LIKE ? AND flags = 1 LIMIT 1""",
                          (f"%{ident}%",)).fetchone()
    if not row:
        die(f"no file matching {ident!r}")
    fid, domain, rel = row
    src = file_path(backup, fid)
    if not src.is_file():
        die(f"indexed as {domain}/{rel} but not present in the backup")

    out = Path(outdir) / f"{fid}_{Path(rel).name or 'file'}"
    shutil.copy2(src, out)
    h = hashlib.sha256(out.read_bytes()).hexdigest()
    print()
    print(f"  domain   {domain}")
    print(f"  path     {rel}")
    print(f"  copied   {out}  ({out.stat().st_size:,} bytes)")
    print(f"  sha256   {h}")
    print()
    # SQLite databases travel with companions. Copying one of three is how the
    # last hour of activity goes missing.
    extra = 0
    for suffix in ("-wal", "-shm"):
        row2 = con.execute("SELECT fileID FROM Files WHERE domain=? AND relativePath=?",
                           (domain, rel + suffix)).fetchone()
        if row2:
            s2 = file_path(backup, row2[0])
            if s2.is_file():
                d2 = Path(outdir) / f"{row2[0]}_{Path(rel).name}{suffix}"
                shutil.copy2(s2, d2)
                print(f"  also     {d2.name}  ({d2.stat().st_size:,} bytes)")
                extra += 1
    if extra:
        print()
        print("  The -wal was taken too. The most recent rows live there, and copying")
        print("  the database alone is how the last hour goes missing.")
    print()


def cmd_knowledge(backup, limit=40):
    con = manifest(backup)
    row = con.execute("""SELECT fileID FROM Files
                         WHERE relativePath LIKE '%CoreDuet/Knowledge/knowledgeC.db'
                         LIMIT 1""").fetchone()
    if not row:
        die("knowledgeC.db not in this backup (it is not always included)")
    kc = file_path(backup, row[0])
    if not kc.is_file():
        die("knowledgeC.db is indexed but not present")

    k = ro_connect(kc)
    print()
    print("  Device use, reconstructed. App focus, lock and unlock, screen state.")
    print()
    try:
        rows = k.execute("""
            SELECT ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE, ZENDDATE
            FROM ZOBJECT
            WHERE ZSTREAMNAME IN ('/app/inFocus','/display/isBacklit','/device/isLocked')
            ORDER BY ZSTARTDATE DESC LIMIT ?""", (limit,)).fetchall()
    except sqlite3.DatabaseError as exc:
        die(f"could not read knowledgeC: {exc}")

    print(f"  {'start (UTC)':<21} {'dur':>7}  {'stream':<20} value")
    print("  " + "─" * 76)
    for stream, value, start, end in rows:
        s = apple_ts(start)
        dur = ""
        if start is not None and end is not None:
            try:
                dur = f"{int(float(end) - float(start))}s"
            except Exception:
                pass
        print(f"  {s.strftime('%Y-%m-%d %H:%M:%S') if s else '?':<21} {dur:>7}  "
              f"{(stream or '')[:19]:<20} {(value or '')[:34]}")
    print()
    print("  Timestamps are Apple absolute time (seconds since 2001-01-01), already")
    print("  converted. Read as Unix they would land in 1970 and nobody notices the year.")
    print()


def cmd_sms(backup, limit=40):
    con = manifest(backup)
    row = con.execute("""SELECT fileID FROM Files
                         WHERE relativePath LIKE '%SMS/sms.db' LIMIT 1""").fetchone()
    if not row:
        die("sms.db not in this backup")
    p = file_path(backup, row[0])
    if not p.is_file():
        die("sms.db indexed but not present")
    s = ro_connect(p)
    # Apple changed message.date from seconds to nanoseconds around iOS 11.
    # Divide only when the number is absurd, rather than guessing by version.
    rows = s.execute(f"""
        SELECT CASE WHEN m.date > 1000000000000 THEN m.date/1000000000 ELSE m.date END,
               m.is_from_me, h.id, m.text
        FROM message m LEFT JOIN handle h ON m.handle_id = h.ROWID
        WHERE m.text IS NOT NULL ORDER BY m.date DESC LIMIT {int(limit)}""").fetchall()
    print()
    for date, from_me, handle, text in rows:
        t = apple_ts(date)
        arrow = "->" if from_me else "<-"
        print(f"  {t.strftime('%Y-%m-%d %H:%M:%S') if t else '?':<21} {arrow} "
              f"{(handle or 'unknown')[:22]:<24} {(text or '')[:52]}")
    print()
    print("  Note the date column: Apple moved it from seconds to nanoseconds around")
    print("  iOS 11. This query handles both by magnitude rather than by version,")
    print("  because the backup does not always tell you which it is.")
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["info", "domains", "find", "get", "knowledge", "sms"])
    ap.add_argument("backup")
    ap.add_argument("term", nargs="?")
    ap.add_argument("--out", default=".")
    ap.add_argument("--limit", type=int, default=40)
    a = ap.parse_args()

    if not Path(a.backup).is_dir():
        die(f"not a directory: {a.backup}")

    if a.command == "info":       cmd_info(a.backup)
    elif a.command == "domains":  cmd_domains(a.backup, a.limit)
    elif a.command == "find":
        if not a.term: die("find needs a search term")
        cmd_find(a.backup, a.term)
    elif a.command == "get":
        if not a.term: die("get needs a fileID or a path fragment")
        cmd_get(a.backup, a.term, a.out)
    elif a.command == "knowledge": cmd_knowledge(a.backup, a.limit)
    elif a.command == "sms":       cmd_sms(a.backup, a.limit)


if __name__ == "__main__":
    main()
