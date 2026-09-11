# Session 7 — Forensic Principles and Evidence

## `acquire.sh`

```bash
./acquire.sh list                      # identify by SERIAL, not by /dev name
sudo ./acquire.sh blockcheck /dev/sdb  # apply a write block, then PROVE it
sudo ./acquire.sh image /dev/sdb --case C-001 --exhibit EX-01 --examiner "Your Name"
./acquire.sh verify C-001-EX-01.E01
./acquire.sh coc --case C-001 --exhibit EX-01 --examiner "Your Name"
```

### `blockcheck` tries to write

Deliberately. `blockdev --getro` returning 1 tells you the flag was set, not that
it works — `--setro` can be silently ineffective depending on the subsystem, and
Linux automounters have written to evidence before.

So the script attempts a one-sector write. **If that write succeeds, it stops
hard and tells you the evidence may have been modified.** Which is bad news
delivered early, and early is the only useful time for it.

A hardware write blocker remains the defensible option. This is the software
fallback, tested.

### Two hash passes, on purpose

`image` hashes the source **before** imaging and the image **after**. That is two
full reads of the device and it roughly doubles the time, and it is not optional:
without the source hash, the image hash proves only that the image has not
changed since you made it — not that it matches the source. Which is a different
claim, and the one that gets challenged.

### When the hashes do not match

The script records the mismatch in the notes file and then tells you what to do,
because the instinct is to re-run and the instinct is wrong:

> Re-running until you get a matching pair and reporting only that one is not a
> documentation failure. It is misconduct.

### Contemporaneous notes

Every action is written to `<case>-<exhibit>-notes.txt` **as it happens**, with a
UTC timestamp. Notes reconstructed afterwards are not contemporaneous, and under
cross-examination the difference is obvious.

---

## `memory-capture.sh`

```bash
./memory-capture.sh checklist              # the decision, before the commands
sudo ./memory-capture.sh all /mnt/evidence
sudo ./memory-capture.sh volatile /mnt/evidence
sudo ./memory-capture.sh memory /mnt/evidence
```

### Order is not negotiable

Volatile state first, memory second, power last. Every command you run destroys a
little of what the next one would have seen, so the cheap things go first. Within
`volatile`, the collection is ordered by how fast each source changes: sockets and
ARP before process lists before mounts.

### It refuses to write to the system disk quietly

A memory image written locally overwrites unallocated space that may itself be
evidence. If the destination is on the same filesystem as `/` it says so and makes
you confirm — and tells you to record the reason.

### The deleted-executable check

`/proc/*/exe` entries marked `(deleted)` mean a process is running a binary that
no longer exists on disk. It is one of the highest-signal things on a live Linux
host, and it takes one command.

### Contemporaneous notes, again

Every grab is logged with its SHA-256 and the exact command, to
`collection-notes.txt`, as it happens. Same discipline as `acquire.sh`.

### Acquiring memory changes memory

Unavoidable, and acceptable — ACPO principle 2 covers exactly this. What is not
acceptable is doing it without recording the tool, the version and the footprint,
so the script records all three.

If AVML is missing it falls back to `/proc/kcore` and tells you loudly that the
result is **partial**, because reporting a kcore dump as a full physical memory
image is a claim you cannot support.
