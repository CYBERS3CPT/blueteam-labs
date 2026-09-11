# Session 9 — Mobile Device Forensics

## `epoch.py`

```bash
./epoch.py 1793318400            # try every epoch, mark the plausible ones
./epoch.py 784500000 --as apple
./epoch.py --list                # the epochs, and where each turns up
./epoch.py --sql                 # snippets for the databases you will actually open
```

Getting the epoch wrong produces timestamps that are **plausible and wrong** — by
decades, or by hours. A blank field gets questioned; a plausible wrong answer does
not. That is why this exists.

With no `--as`, it converts every way and marks anything landing in a rolling
plausible window (twenty years back, five forward). If exactly one epoch is plausible, you have your answer. If several are,
convert a value you already know — a message you sent yourself, a photo you took —
and see which epoch agrees with you.

The one people miss is **Apple/Cocoa**: seconds since 2001-01-01, all over iOS.
Read as Unix, it gives you 1970-something and nobody notices the year.

---

## `android-collect.sh`

```bash
./android-collect.sh check              # device identity, clock drift, BFU/AFU, root
./android-collect.sh collect            # logical collection, everything hashed
./android-collect.sh pull /data/.../x.db
./android-collect.sh leapp ./android-<timestamp>/
```

### `check` records the clock drift

Device clock against the examiner host, both in UTC, difference recorded. Mobile
clocks are usually network-synchronised — and "usually" is not a finding. Every
timestamp you later quote from this device needs that drift applied, or at least
stated.

### `pull` takes the `-wal` and `-shm` too

Always. In write-ahead-log mode the most recent rows — including messages the user
"deleted" moments before seizure — live in the WAL and not in the main database.
Pulling the `.db` alone is the single most common way to miss the thing you were
looking for.

### It asks you to confirm the device is not personal

Because that is the rule in this session with consequences outside the classroom.
`collect` will not proceed without it.

### ALEAPP output is not a finding

It tells you where to look. The finding is what you confirm in the underlying
database, with the path and query recorded. Parsers make assumptions about schema
versions, and a vendor change produces wrong timestamps **silently**. Hence dual-tool
validation, and hence the methodology naming both tools and both versions.

---

## `ios-backup.py`

```bash
./ios-backup.py info      ./backup      # device, iOS version, encrypted?
./ios-backup.py domains   ./backup      # what is in it
./ios-backup.py find      ./backup whatsapp
./ios-backup.py get       ./backup <fileID>
./ios-backup.py knowledge ./backup      # KnowledgeC activity, decoded
./ios-backup.py sms       ./backup
```

Read-only: every database is opened with SQLite's `immutable=1`, so nothing is
written into the backup — not even a journal.

### Nothing is where you expect

An iOS backup stores each file under a SHA-1 of `domain-relativePath`, in a
two-hex-character directory. `Manifest.db` is the index, and without reading it
the backup is forty thousand files with meaningless names.

### `get` takes the `-wal` too

If the file is a SQLite database and the backup contains its `-wal` or `-shm`,
they come with it, and the tool says why. Copying one of three is how the last
hour of activity goes missing.

### Encryption is the counter-intuitive bit

`info` says it plainly: an **encrypted** backup contains *more* than an
unencrypted one. Keychain items, Health data and Safari passwords are only
included when the backup is encrypted — which matters when you are advising
someone what to ask for.

When it is unencrypted, the tool tells you to record their absence as a
**limitation**, not to report it as a finding.

### `knowledge` and the epoch

`KnowledgeC` timestamps are Apple absolute time — seconds since 2001-01-01 — and
are converted here. Read as Unix they land in 1970 and nobody notices the year.

`sms` handles Apple moving `message.date` from seconds to nanoseconds around iOS
11 by magnitude rather than by version, because the backup does not always tell
you which it is.
