# Session 8 — samples

Three sources, one case. Everything is invented: **Tagus Logística**
(`tagus-logistica.example`) is still fictional, still having a bad October, and
still under `.example` with RFC 5737 addresses so none of it resolves.

```bash
shasum -a 256 -c SHA256SUMS      # you know the drill by now
```

## What is here, and what is not

| Source | Where | What it is |
|---|---|---|
| **EX-01**, João's USB pen | `../../session-07-forensic-acquisition/samples/EX-01.img.gz` — or, better, **your own verified E01 from Session 7** | 16 MiB FAT16. Not copied here on purpose: one exhibit, one hash, one place |
| **TAGUS-FIN-02**, João's workstation | `fin02-timeline.csv.gz` | A super timeline, as `psort.py -o dynamic` would write it, 13–17 October. ~5 000 rows of a finance clerk's week, a Windows update, and one very bad Wednesday evening |
| **tagus-web-01**, the company web server | `web01-collection/` | A UAC-style triage collection: logs, `wtmp`, crontabs, shell histories, a `bodyfile`. The volatile capture from Session 7 came from this host |

The workstation is a timeline and not an image because a Windows 11 disk does not
fit in a git repository and should not be in one. The rows are the shape plaso
really writes; the machine they describe never existed.

## The clocks, before you start

Write these down. Every finding in this session depends on one of them.

| Source | How it records time | What you must do |
|---|---|---|
| EX-01 (FAT16) | **Local time, no offset stored**, 2-second resolution, access *date* only | Find out which local time, then convert. Plaso and TSK will happily call it UTC if you let them |
| TAGUS-FIN-02 | Mostly UTC (FILETIME). The registry says the machine was on `GMT Standard Time` | Find the one source in there that is *not* UTC. It is not hiding very hard |
| tagus-web-01 | UTC, per `etc/timezone`, but **the clock ran ~4 minutes slow** (Session 7) | Correct before quoting. And syslog lines have no year |

## web01-collection

```
bodyfile/bodyfile.txt     TSK bodyfile of the interesting paths (+ some boring ones)
etc/                      accounts, sudoers.d, sshd drop-ins, system crontabs, units
home/*/.bash_history      as found
var/log/                  auth.log, auth.log.1, syslog, nginx/access.log, wtmp
var/spool/cron/crontabs/  per-user crontabs
var/www/                  the web root, and www-data's home
uac.log                   what collected it, when, on which clock
```

`wtmp` is the classic binary format of a Debian 12 host. If your examination box
is Debian 13 or current Kali, `last -f` will not read it — `last` is now the
`wtmpdb` version and expects SQLite — and `utmpdump` is gone too. Use
`../wtmp-read.py`, which exists for exactly this reason.

## Handling

Same as always: hash on arrival, work on copies in `out/`, write your notes as you
go, and keep findings and opinions in different paragraphs. Exercise 13 will check.
