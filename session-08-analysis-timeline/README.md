# Session 8 — Analysis Methods and the Forensic Report

**Exercises:** [`EXERCISES.md`](EXERCISES.md) — fourteen of them, on three
sources from the same case: the USB pen you acquired in Session 7, a super
timeline of the finance workstation it was plugged into, and a triage collection
from the web server whose volatile state you met last week. See
[`samples/`](samples/README.md) for what is in each, and which clock it keeps.

```bash
(cd samples && shasum -a 256 -c SHA256SUMS)
mkdir -p out && gunzip -c samples/fin02-timeline.csv.gz > out/fin02.csv
./timeline-reduce.py out/fin02.csv --peaks
```

## `timeline-reduce.py`

```bash
./timeline-reduce.py tl.csv --peaks                       # find me an anchor
./timeline-reduce.py tl.csv --anchor "YYYY-MM-DD 03:12:00" --window 12h
./timeline-reduce.py tl.csv --anchor-grep "ransom" --window 24h
./timeline-reduce.py tl.csv --anchor ... --user ana --types exec,persist
```

Input is `psort.py -o dynamic` CSV, or anything with a parseable datetime.

### It writes the filter next to the output

Every run produces `<output>.filter.txt` containing the anchor, the window, every
filter applied, the row counts, and the equivalent `psort.py` expression.

That file is not a courtesy. Without it your 200 rows cannot be reproduced, and a
finding that cannot be reproduced is an assertion. Put it in the appendix.

### "Equivalent" means equivalent

The `psort.py` expression in the filter file covers the time window. When you
also used `--user`, `--path`, `--types` or `--exclude`, the file says the
expression is **not** equivalent, and records the exact command line instead —
because pasting a psort query that returns 4 000 rows next to a table of 34 is
how a reproducibility appendix becomes an argument.

### `--peaks`

Finds candidate anchors: the busiest minutes, and the hours with almost nothing.
Both are useful. A spike is usually an install, an update, or the thing you are
looking for. A quiet hour is where a single event stands out — which is why 03h00
is such a productive place to look.

### Artefact types

`exec`, `filecreate`, `logon`, `registry`, `browser`, `network`, `persist`, `usb`.
These are the names an analyst asks for, mapped to the strings plaso actually
writes. `--types exec,persist` is usually the first cut worth making.

### Everything is UTC

If your input is not UTC, fix that before you reduce it. A timeline mixing
timezones is worse than no timeline, because it looks authoritative.

---

## `wtmp-read.py`

```bash
./wtmp-read.py collection/var/log/wtmp           # sessions, like last
./wtmp-read.py collection/var/log/btmp --raw     # every record
./wtmp-read.py collection/var/log/wtmp --csv     # for the timeline
```

Debian 13 and current Kali replaced `last` with the `wtmpdb` version, which reads
SQLite and cannot open the classic binary `wtmp` of a Debian 12 server. `utmpdump`
went with it. This reads the glibc x86_64 record (384 bytes), prints UTC, and
**refuses** a file whose size is not a multiple of the record: a misaligned parse
prints plausible garbage, and plausible garbage is the worst kind.

The times are the host's clock. If that clock was wrong, apply the drift you
recorded at collection; the script will not do it for you, on purpose.

---

## `hunt.sh`

Session 8's artefact map, executable. Ask a question instead of remembering a
filename.

```bash
./hunt.sh questions
./hunt.sh ran     --root /mnt/evidence
./hunt.sh deleted --root /mnt/evidence
./hunt.sh all     --root /mnt/evidence --out ./hunt
SIGMA_RULES=~/sigma/rules ./hunt.sh sigma --root /mnt/evidence
```

Questions: `ran` `opened` `browsed` `usb` `logons` `deleted` `exfil` `persist`
`sigma`. Read-only — it never writes into `--root`.

### It locates, it does not parse

Each question finds the artefacts and tells you the command to run next. It
deliberately stops there: parsing is where the assumptions live, and you should
know which tool made yours — and be able to name it and its version in the
methodology.

### The distinctions it keeps reminding you about

- **ShimCache proves presence, not execution.** Prefetch proves execution.
  Conflating them is the easiest thing to get wrong in a report.
- **A USBSTOR serial proves the device was connected**, not that anything was
  copied. Correlate it with LNK volume serials to place files on it.
- **ShellBags survive the folder.** A bag for `D:\projects` on a machine with no
  `D:` drive is a removable device, and it is frequently the whole finding.
- **`$UsnJrnl` is the artefact people forget.** It answers "when was this deleted,
  and by what" after both the file and its MFT record are gone.
- **SRUM answers the exfiltration question** — per-application bytes sent — when
  nothing else in the image can.

### `browsed` checks for the `-wal`

If a browser `History-wal` exists it says so, because the recent rows are in
there and copying the `.db` alone is how you miss the last hour.
