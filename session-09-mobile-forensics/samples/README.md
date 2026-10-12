# Session 9 — samples

Two exhibits from one case, for `epoch.py`, `android-collect.sh` and
`ios-backup.py` to be pointed at. Everything here is invented: **TechCorp**
(`techcorp.pt`) is a fictional company, **ConcorrenteLda** is the fictional
competitor it is losing an employee to, and every number is a `+3519` prefix that
belongs to nobody.

```bash
shasum -a 256 -c SHA256SUMS      # before anything else. Yes, every time.
```

## The case

A TechCorp employee is under investigation for exfiltrating data before leaving
for a competitor. Two devices were seized on **7 October, 21:40 local**, both
powered on and unlocked (AFU).

| Exhibit | What it is | Databases |
|---|---|---|
| **EX-09-A** | Corporate Android handset, logical collection | `mmssms.db`, `mmssms_wal_recovered.db`, `calls.db`, `contacts2.db`, `wifi_history.db`, `location_cache.db` |
| **EX-09-B** | Personal iPhone, unencrypted iTunes backup | `sms.db`, `KnowledgeC.db` |

Two devices, two epochs, two clocks, and one timeline you have to build across
both. That is the session.

## What these files are not

Read this before you quote a schema in a report.

- **The schemas are reduced.** A real `mmssms.db` has fifty-odd columns and a
  `canonical_addresses` table; a real `KnowledgeC.db` has `ZSOURCE`,
  `ZSTRUCTUREDMETADATA` and a dozen joins before you see an app name. These keep
  the columns the queries need and drop the rest, so the exercise is the epoch and
  the correlation, not the join. **Do not learn the schema from here** — learn it
  from the device you have in front of you, and record the version you saw.
- **`mmssms_wal_recovered.db` is a result, not evidence.** It is what carving the
  write-ahead log *would* hand you, laid out as a table with a `note` column. The
  real artefact is a `-wal` file next to `mmssms.db`, which is why
  `android-collect.sh pull` takes `-wal` and `-shm` too. Here the recovery has
  already happened; in the lab it has not, and that is the step people skip.
- **The clocks are clean.** Every value is UTC on whole minutes, with no drift
  between the two devices. Real seizures are not like this, so
  `android-collect.sh check` still records device clock against examiner host
  before you touch anything — not because it will find drift here, but because
  the one time it does, you will not have thought to look.

## The epochs

| File | Column | Epoch | Convert with |
|---|---|---|---|
| `mmssms.db`, `mmssms_wal_recovered.db` | `date` | Unix **ms** | `datetime(date/1000,'unixepoch')` |
| `calls.db` | `date` | Unix ms | `datetime(date/1000,'unixepoch')` |
| `contacts2.db` | `last_updated` | Unix ms | `datetime(last_updated/1000,'unixepoch')` |
| `wifi_history.db` | `first_connected`, `last_connected` | Unix ms | `datetime(last_connected/1000,'unixepoch')` |
| `location_cache.db` | `timestamp` | Unix ms | `datetime(timestamp/1000,'unixepoch')` |
| `sms.db` | `message.date` | **Apple** (seconds) | `datetime(date+978307200,'unixepoch')` |
| `KnowledgeC.db` | `ZSTARTDATE`, `ZENDDATE` | **Apple** (seconds) | `datetime(ZSTARTDATE+978307200,'unixepoch')` |

Do not take that table on trust — it is exactly the kind of table that is right
for one vendor and wrong for the next. Check a value:

```bash
../epoch.py 1791356400000        # one plausible epoch: unix_ms
../epoch.py 813049200 --as apple
```

An Apple value read as Unix lands in **1970** and nobody notices the year. A Unix
millisecond value read as seconds lands in the year **58 735**, which at least looks
wrong. The dangerous direction is the quiet one.

## Opening them without writing to them

```bash
sqlite3 "file:mmssms.db?immutable=1" "SELECT count(*) FROM sms;"
```

`immutable=1` is what `ios-backup.py` uses for every database it touches. Plain
`sqlite3 mmssms.db` will create a journal next to your exhibit and change its
hash, and you will have to explain that.

## Queries that get you started

Android SMS, sent and received:

```sql
SELECT datetime(date/1000,'unixepoch') AS t, address, body,
       CASE type WHEN 1 THEN 'IN' WHEN 2 THEN 'OUT' END AS dir
FROM sms ORDER BY date;
```

Recovered (deleted) messages:

```sql
SELECT datetime(date/1000,'unixepoch') AS t, address, body, note
FROM recovered_messages ORDER BY date;
```

Calls:

```sql
SELECT datetime(date/1000,'unixepoch') AS t, number, duration,
       CASE type WHEN 1 THEN 'IN' WHEN 2 THEN 'OUT' WHEN 3 THEN 'MISSED' END AS dir
FROM calls ORDER BY date;
```

iOS messages:

```sql
SELECT datetime(m.date+978307200,'unixepoch') AS t, h.id, m.text,
       CASE m.is_from_me WHEN 1 THEN 'OUT' ELSE 'IN' END AS dir
FROM message m JOIN handle h ON m.handle_id = h.ROWID ORDER BY m.date;
```

`KnowledgeC`, lock state and app focus — the two streams that tell you whether
anyone was holding the phone:

```sql
SELECT datetime(ZSTARTDATE+978307200,'unixepoch') AS start,
       datetime(ZENDDATE+978307200,'unixepoch')   AS end,
       ZSTREAMNAME, ZVALUESTRING
FROM ZOBJECT ORDER BY ZSTARTDATE;
```

Wi-Fi and location:

```sql
SELECT ssid, bssid, datetime(first_connected/1000,'unixepoch') AS first,
       datetime(last_connected/1000,'unixepoch') AS last, times_connected
FROM wifi_connections ORDER BY last;

SELECT datetime(timestamp/1000,'unixepoch') AS t, latitude, longitude,
       accuracy, provider, location_name
FROM locations ORDER BY timestamp;
```

## What to notice

Not answers — places where the evidence argues with itself, which is where the
work is.

- **Accuracy is part of the finding.** The 11:00 location fix is `cell` with
  **450 m** accuracy; the 15:00 one is `cell` with **1200 m**. A 1200 m circle over
  Lisbon is not a place, it is a district, and quoting its `location_name` as a
  location is how a report gets taken apart. Meanwhile one `wifi_connections` row
  for the same hour names a specific access point. Which of the two would you put
  in front of a lawyer, and why?
- **Two devices, two stories about Starbucks.** EX-09-A's GPS and
  `wifi_history.db` put the handset there in the morning. EX-09-B's
  `/wifi/connected` stream puts the iPhone there in the afternoon. Both can be
  true. Say which device you mean, every time, or your timeline becomes fiction.
- **`contacts2.db` has one row with a different `last_updated`.** Six contacts
  share a timestamp; one does not. Convert them and see whose, and when.
- **Locked means nobody was typing.** `KnowledgeC` has `/device/isLocked` windows.
  Any claim about a person acting on the device inside one of those windows needs
  a better explanation than the database gives you.
- **The deleted thread is the most incriminating and the weakest.** It only exists
  in a file whose provenance is "I carved it". What else would you need to collect
  to stand behind it?

## Housekeeping

`.gitignore` excludes lab output, not these: the databases are committed on purpose
and are 8–12 KB each. If you write parser output while working, keep it in `out/`.
