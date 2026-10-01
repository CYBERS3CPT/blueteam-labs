# Session 7 — Exercises

Hands-on and Kali-first, built on `acquire.sh` and `memory-capture.sh` and on the
fixtures in `samples/`. Nothing here needs a real suspect, a real disk or a real
crime. The crime is fictional. The mistakes are realistic, which is worse.

**The scenario.** Session 6 ended with *Tagus Logística* receiving a very
persuasive email from its "CEO". It is now two days later. Two transfers of just
under €50 000 have left for a "confidential supplier", the finance clerk's USB pen
has been found in a drawer, and the company web server is quietly talking to an
address nobody recognises. Your colleague Tiago did the first response before
leaving on holiday. You are now the examiner, and you have inherited his work.

Every domain is under `.example`, every IP in the RFC 5737 documentation ranges,
every IBAN obviously fake. Nothing here resolves, routes or pays.

## Before you start

```bash
cd blueteam-labs/session-07-forensic-acquisition
sudo apt install -y dc3dd ewf-tools sleuthkit util-linux
mkdir -p out    # git-ignored; your images, notes and forms go here
```

Ground rules, same as the session:

- **Research VM, snapshot first**, revert when done. `blockcheck` attempts a real
  write to a real block device. Point it at the loop devices these exercises
  create, never at your own disk.
- **Work on copies.** The thing you unpack from `samples/` is the "original".
  Anything you attach writable is a copy of it, so a failed write block costs you a
  copy and a lesson, not the case.
- **Every action goes in your own notes file, in UTC, as you do it.** Start it now:
  `echo "$(date -u +%FT%TZ)  START  session 7 exercises" > out/my-notes.txt`.
  Exercise 6 is about what happens when you don't.

| # | Exercise | Tools | Time |
|---|---|---|---|
| 1 | Hash on arrival | `shasum`, `gunzip` | 5 min |
| 2 | Name it by serial, not by `/dev` | `acquire.sh list`, `losetup` | 10 min |
| 3 | A write block you have actually tested | `acquire.sh blockcheck`, `blockdev` | 15 min |
| 4 | An acquisition that survives cross-examination | `acquire.sh image`, `ewfverify` | 25 min |
| 5 | The hash that didn't match | `cmp`, `fsstat`, `ifind`, `istat` | 25 min |
| 6 | Tiago's notes, annotated | a red pen | 20 min |
| 7 | Cross-examine the chain of custody | `acquire.sh coc` | 20 min |
| 8 | The capture somebody tidied | `sha256sum -c`, `grep`, `awk` | 30 min |
| 9 | Patch the tool | `memory-capture.sh`, your editor | 15 min |
| 10 | Your own live capture | `memory-capture.sh all` | 30 min |
| 11 | Four hours and a lot of hardware | paper | 25 min |
| 12 | The write-up | `report-scaffold.py forensic` | 45 min |

Do them in order the first time. Exercise 12 assumes you did the rest, and
Session 8 assumes you did Exercise 4.

---

## 1 · Hash on arrival

Before you open anything, prove what you received.

```bash
(cd samples && shasum -a 256 -c SHA256SUMS)
gunzip -c samples/EX-01.img.gz > out/EX-01.img
shasum -a 256 out/EX-01.img | tee -a out/my-notes.txt
chmod a-w out/EX-01.img
```

Everything should say `OK`, and the image should hash to the value in
`samples/README.md`. If not, stop: you are about to analyse something other than
what everyone else has, and the discussion on Thursday will be very confusing.

1. You now hold three hashes that all describe "EX-01": the `.gz` file, the raw
   image, and (after Exercise 4) the `.E01`. Which one goes in the chain of
   custody as the *evidence* hash, and why are the other two still worth
   recording?
2. `chmod a-w` is called a seatbelt in the README, not a write blocker. What,
   specifically, can still write to that file?

**Deliverable:** the hash lines in `out/my-notes.txt`.

---

## 2 · Name it by serial, not by `/dev`

Tiago's notes say the pen "showed up as /dev/sdb (I think. could have been sdc)".
Here is why that sentence would haunt him.

```bash
cp out/EX-01.img out/EX-01-work.img && chmod u+w out/EX-01-work.img
L=$(sudo losetup -f --show out/EX-01-work.img); echo "$L"
./acquire.sh list
lsblk -o NAME,SIZE,MODEL,SERIAL,RO "$L"
```

1. What does `lsblk` show for MODEL and SERIAL on your loop device? Nothing, most
   likely. So what *do* you record to identify this source unambiguously? (Hint:
   for an image file, the image path and its hash *are* the identity.)
2. Plug any USB stick into your VM, run `./acquire.sh list`, unplug it, plug in a
   second one, and run it again. Did the `/dev` name stay with the stick or with
   the order of arrival? Write the one-sentence rule this teaches.
3. Where on a physical stick do you find the serial that matches what `lsblk`
   reports — and where do you write it on the CoC?

---

## 3 · A write block you have actually tested

`blockdev --getro` returning `1` means a flag was set. It does not mean the flag
works. `blockcheck` finds out the only honest way: it tries to write.

```bash
sudo ./acquire.sh blockcheck "$L"
sudo blockdev --getro "$L"
```

1. Read the output. Which line is the *proof*, and which line is merely a claim?
2. Now do what Tiago did at 17:02 — plug the same pen into another port. For a
   loop device, "another port" is a second device over the same file:
   ```bash
   L2=$(sudo losetup -f --show out/EX-01-work.img); echo "$L2"
   sudo blockdev --getro "$L"; sudo blockdev --getro "$L2"
   ```
   Same bytes underneath, two answers. Where did the read-only flag go? (It never
   belonged to the pen; it belonged to the device node.) Look at Tiago's notes:
   was his second acquisition — the one he reported — write-blocked at all?
3. For image files there is a better way than `--setro` after the fact:
   `sudo losetup -f --show -r out/EX-01.img`. Why is "read-only from the moment it
   exists" stronger than "read-only shortly after it appeared"? What did Tiago's
   desktop do at 16:46, in that window?
4. A hardware write blocker is still the defensible option. Write two sentences
   for your methodology explaining why you used a software block tonight and what
   you did to make it defensible anyway.

`blockcheck` stops hard if the test write succeeds. On a working copy that is a
lesson. On the original it is a confession. Hence the copy.

---

## 4 · An acquisition that survives cross-examination

The real thing. Use a read-only loop of the *original* this time.

```bash
sudo losetup -D                                    # tidy up the earlier loops
L=$(sudo losetup -f --show -r out/EX-01.img)
sudo ./acquire.sh blockcheck "$L"                  # still prove it
sudo ./acquire.sh image "$L" --case C-007 --exhibit EX-01 \
     --examiner "Your Name" --out out/acq
less out/acq/C-007-EX-01-notes.txt
```

`image` hashes the source first, acquires to E01 with the case metadata embedded,
then has `ewfverify` decompress the whole thing and hash the data again.

1. In the notes, find `HASH-SRC`, `HASH-IMG` and `HASH-E01`. Two of them match.
   Why does the third never match the other two, and why is comparing it with the
   source hash a classic mistake that *looks* like rigour?
2. Run the acquisition a second time to `--out out/acq2`. Compare the two
   `HASH-E01` values, then the two `HASH-IMG` values. What does that tell you about
   which hash belongs in the CoC?
3. `ewfinfo out/acq/C-007-EX-01.E01`. Which of your inputs ended up embedded in the
   container? Which hash did `ewfacquire` actually *store* in it — and is it the
   one you care about?
4. Now the raw route: add `--format raw --out out/raw`. Compare sizes with the
   E01. When would you choose raw anyway?
5. Fill in the form: `./acquire.sh coc --case C-007 --exhibit EX-01 --examiner
   "Your Name" --source-hash … --image-hash …` (the script prints the exact
   command at the end of `image`). Fill in **every** blank. Now, not later.

**Deliverable:** `out/acq/`, the notes file inside it, and your completed CoC.
**Bring the E01 to Session 8.** Everything next week runs on it.

---

## 5 · The hash that didn't match

Tiago acquired the pen twice. The first image did not match. He tried to delete it,
failed for lack of permissions on the share, and wrote "No issues" in the summary.
His failure to delete it is the best thing that happened to this case.

```bash
gunzip -c samples/colleague/EX-01-attempt1.img.gz > out/attempt1.img
shasum -a 256 out/attempt1.img out/EX-01.img
cmp -l out/EX-01.img out/attempt1.img | head
cmp -l out/EX-01.img out/attempt1.img | wc -l
```

`cmp -l` prints 1-based byte offsets. Turn the first one into a sector number
(`(offset - 1) / 512`), then find out what lives there:

```bash
fsstat out/EX-01.img | sed -n '/File System Layout/,/Cluster Area/p'
ifind -d <SECTOR> out/EX-01.img
istat out/EX-01.img <INODE>
```

1. How many bytes differ, and in how many sectors? What is in the bad image where
   the good one has data? What does that pattern usually mean? (Tiago's notes
   mention "a few red lines" in `dmesg`. That was the evidence of the cause, and
   he ignored it.)
2. Which file owns that sector? Is it allocated? Which *parts* of that file are
   intact in both images, and which part was lost in the first?
3. Write the **impact statement**: one paragraph, as it would appear in the
   report, stating which findings the first acquisition could have affected if it
   had been the only copy — and whether any finding drawn from the second is
   affected. "None" is a legitimate answer only if you can say why.
4. Rewrite Tiago's summary ("Acquisition completed successfully. Source and image
   hashes matched. No issues.") so that it is true. Then explain, in one sentence,
   why the original version was not just sloppy but misconduct.

---

## 6 · Tiago's notes, annotated

```bash
less samples/colleague/EX-01-notes.txt
```

Tiago is not a villain. He is a tired person with a coffee-stained notebook, which
is the most common threat actor in digital forensics. Go through his notes line
by line and list every defect, each with the principle it breaks (ACPO 1–4, or
ISO/IEC 27037) and what he should have written instead.

| Line / time | Defect | Principle | What it should have said |
|---|---|---|---|

There are at least twelve. A few to get you started, so you know the size of
thing you are looking for: the notes were "typed up from memory on friday"; the
times have no timezone; "dc3dd (whatever version Kali has)".

Then answer:

1. Which **single** defect would an opposing expert open with, and why that one?
2. The source was hashed at 17:10 — *after* both acquisitions, and after the pen
   was moved between ports without a write block. What does that hash prove, and
   what can it no longer prove?
3. Which of the defects can still be repaired today, and which are permanent? For
   the permanent ones, what goes in the Limitations section instead?

---

## 7 · Cross-examine the chain of custody

```bash
less samples/colleague/EX-01-chain-of-custody.md
```

Pair up. One of you is Tiago (back from holiday, tanned, defensive). The other is
counsel for João Pereira. Counsel gets ten questions; Tiago must answer from the
form and the notes only — no "I'm sure it was fine".

Start with the classics from the slides, which this form is practically begging
for:

- Where was the pen between 14:30 and 16:45?
- Who else had access to the safe? Is "maybe facilities" an answer?
- What is the seal number, and when was it broken? (The seal is "tape".)
- Which timezone is "16:48" in, which day, and how do you know the clock was right?
- Who verified the hash, and against what? ("me" is not a second person.)
- What did Rui check on Friday, for how long, and where is that recorded?

Then swap roles and do it again with **your** form from Exercise 4. You will
find gaps in it too. That is the point; it is much cheaper here than in a court.

**Deliverable:** a corrected version of the form, with every gap either filled
from the notes or explicitly marked as unknown and carried into Limitations.
The authority line ("the CFO said it was ok") deserves a sentence of its own —
see the session's slide on where an internal investigation ends.

---

## 8 · The capture somebody tidied

`samples/victim-lin-capture/` is what `memory-capture.sh volatile` wrote on the
Tagus web server, `tagus-web-01`, plus five lines the operator typed in afterwards.
Every grab was hashed into `collection-notes.txt` as it happened. Check that this
is still true:

```bash
cd samples/victim-lin-capture
grep -o 'GRAB  [^ ]*  sha256=[0-9a-f]*' collection-notes.txt \
  | awk '{sub("sha256=","",$3); print $3"  "$2}' | shasum -a 256 -c
cd -
```

1. Which file fails, and what does the operator's own addendum say happened to it?
   What *kind* of line was removed? Look at the `STARTED` column in
   `processes-full.txt` and ask yourself what a login record from the evening of
   the 16th would have shown. Why might that be the most important line in the
   whole capture?
2. The capture can't give the line back. Where on the *disk* of `tagus-web-01`
   does the same information still live, and which command reads it? Add it to
   the acquisition plan for that host, at the top.
3. PID 4127 is called `[kworker/u8:3]`. Give at least **four** independent reasons,
   each from a different file in the capture, why it is not a kernel thread.
4. Where is its executable now, and why does that make memory the only remaining
   copy? Name the one-line command that would have recovered the binary from the
   running process before anyone touched it. (Session slides: "deleted-but-running".)
5. The operator ran `kill -STOP 4127` at "09:14". By which clock? Convert it — and
   every other time in the capture — to real UTC using the drift recorded in the
   notes. Write the corrected timeline for the evening of the 16th.
6. `kill -STOP`, `htop` "for a few minutes", and no memory image. For each, say
   what it cost, which ACPO principle it touches, and whether it was defensible
   *if documented properly*. (Principle 2 does not forbid touching. It forbids
   touching without being able to explain it.)
7. The cron line in `cron-list.txt`: what is it doing every ten minutes, under
   which user, and what does that suggest about how the attacker got in? Do **not**
   fetch the URL. It doesn't resolve anyway, and the habit is the point.

---

## 9 · Patch the tool

Look at `samples/victim-lin-capture/` again. One file in that directory has no
`GRAB` line and no hash in the notes, and it is the most important file in the set.

1. Which one? Find the code in `memory-capture.sh` that writes it and explain why
   it escaped the hashing that every other file gets.
2. Fix it, so that file is hashed and logged like the others.
3. **Bonus:** extend the same block so that, for each deleted-but-running
   executable, the script copies `/proc/<pid>/exe` to the output directory,
   hashes the copy and logs both, *before* anything else changes. Test it on your
   `victim-lin` with the harmless sleeper from Exercise 10.
4. Send it as a pull request. The commit message must say what was wrong and why
   it mattered, in that order. "Fix bug" is not a commit message, it is a shrug.

---

## 10 · Your own live capture

On `victim-lin`, with a **second virtual disk** attached and mounted at
`/mnt/evidence` (your hypervisor can add one in ten seconds; do it before you
start, not during).

First, give yourself something worth finding — a harmless process whose
executable no longer exists:

```bash
cp /bin/sleep /dev/shm/.definitely-not-malware
/dev/shm/.definitely-not-malware 3600 &
rm /dev/shm/.definitely-not-malware
```

Then do it properly:

```bash
./memory-capture.sh checklist                      # answer all six, in your notes
sudo ./memory-capture.sh volatile /tmp/evidence    # watch it object
sudo ./memory-capture.sh all /mnt/evidence/C-007
```

1. What did it say about `/tmp/evidence`, and why does the script make you
   *confirm* rather than simply refusing? What would you write in your notes if
   you genuinely had no other option?
2. Did it find your sleeper? Which files mention it, and which file would you show
   a non-technical manager?
3. Compare your `collection-notes.txt` with the operator's in Exercise 8. Yours
   should have no "added later" section. If it does, put what's in it in a
   separate, timestamped file — never in the middle of the original.
4. AVML or `/proc/kcore`? If the script fell back to kcore, what exactly does the
   report have to say about the memory image, and what can't you claim from it?
5. Answer the slide's question in writing: what did you capture that a disk image
   of `victim-lin` would not contain? Be specific to *your* capture.

Kill the sleeper when you are done: `pkill -f definitely-not-malware`. It is
harmless, but leaving processes called that running on shared lab machines is how
you end up in someone else's exercise.

---

## 11 · Four hours and a lot of hardware

On site at Tagus Logística, you find: the finance workstation (on, logged in, the
one that sent the transfers); a second workstation (on, logged in); `tagus-web-01`
(on, beaconing); a NAS (on, 12 TB); a router with no logging configured; João's
phone and two others, offered voluntarily; the absent CFO's laptop (off); and
email plus cloud accounting hosted with a provider.

You have four hours, one colleague, two hardware write blockers and a 2 TB disk.
In pairs, produce:

1. The **acquisition order**, with one line of justification per item. Where do
   memory captures go, and where does the 12 TB NAS go?
2. What you **document but leave untouched**, and why. "The CFO's laptop is off"
   is a fact; what you do about it is a decision. Write the decision.
3. What you **cannot image**, and the **preservation request** you send instead.
   Draft it: to whom, what data, which accounts, what period, and the legal basis.
   Remember that sign-in logs on many default tiers live for 30 days. Count from
   the 15th. How urgent is this, really?
4. The point at which you **stop and escalate**, and to whom. The transfers went to
   an account abroad. Does that change who you call?
5. What you do with the three phones. (Session 9 will have opinions. Write yours
   first.)

There is a defensible range of answers. There are also answers that will make the
room go quiet. Aim for the former.

---

## 12 · The write-up

The Session 7 deliverable: verified acquisition + completed chain of custody +
acquisition report.

```bash
../session-06-socmint-phishing/report-scaffold.py forensic --case C-007 \
    --exhibit EX-01 --analyst "Your Name" --out out/report.md
# ... fill it in ...
../session-06-socmint-phishing/report-scaffold.py forensic --check out/report.md
```

It must contain:

| Component | From |
|---|---|
| Chain of custody, every field | Exercises 4 and 7 |
| Source hash and image hash, **recorded separately**, plus which hash is which | Exercises 1 and 4 |
| `ewfverify` output | Exercise 4 |
| Your contemporaneous notes, in UTC, with tool names and versions | `out/my-notes.txt`, `out/acq/*-notes.txt` |
| Memory capture and volatile state, hashed | Exercise 10 |
| Methodology: the standard you followed, and where you deviated and why | Exercise 3 |
| An account of the earlier, failed acquisition and its impact | Exercise 5 |
| Limitations | Exercises 5, 6 and 8 |

Two traps, both common:

- **The inherited work.** You did not acquire `attempt1`, and you did not write
  Tiago's notes. Your report must still deal with them honestly: say what was done
  before you, by whom, what it did to the evidence, and what you did about it.
  Pretending the case began when you arrived is not tidiness. It is a gap with
  good formatting.
- **Limitations.** "More time would have helped" is not a limitation. "The source
  was hashed only after it had been attached twice, once without a verified write
  block, so the earliest provable state of EX-01 is its state at 17:10 on the
  16th" is.

Write the executive summary last. It is the first thing read and the last thing
knowable.
