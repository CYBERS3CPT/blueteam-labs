# Session 8 — Exercises

Hands-on and Kali-first, built on `timeline-reduce.py`, `hunt.sh` and
`wtmp-read.py`, on the fixtures in `samples/`, and on the image you acquired in
Session 7. Everything is fictional and everything is defensive. You are not
looking for the attacker's next move; you are working out what already happened,
in what order, and how sure you can be.

**The case so far.** *Tagus Logística* received a convincing email from its
"CEO" (Session 6). Two transfers of just under €50 000 left the next evening's
banking session. You acquired the finance clerk's USB pen, inherited a colleague's
work, and caught a volatile capture somebody had tidied (Session 7). Tonight you
have three sources:

| | Source | Where |
|---|---|---|
| **EX-01** | João Pereira's USB pen | your Session 7 E01, or `../session-07-forensic-acquisition/samples/EX-01.img.gz` |
| **FIN-02** | João's workstation, as a super timeline | `samples/fin02-timeline.csv.gz` |
| **WEB-01** | the web server, as a triage collection | `samples/web01-collection/` |

The question in scope, as the client put it: *"What happened, who did it, and how
do we stop it happening again?"* Only the first part is entirely yours. Keep the
other two in mind for when you are tempted to answer them with adjectives.

## Before you start

```bash
cd blueteam-labs/session-08-analysis-timeline
sudo apt install -y sleuthkit ewf-tools foremost bulk-extractor plaso
mkdir -p out    # git-ignored
(cd samples && shasum -a 256 -c SHA256SUMS)
gunzip -c samples/fin02-timeline.csv.gz > out/fin02.csv
echo "$(date -u +%FT%TZ)  START  session 8 exercises" > out/my-notes.txt
```

Ground rules:

- **Work on copies, never on the E01 you will hand in.** Analysis tools are not
  write blockers, and some of them create sidecar files next to whatever they open.
- **UTC everywhere in your notes**, and every time you convert a timestamp, write
  down from what, to what, and why.
- **Name the source artefact** for every claim. "The pen was plugged in at 18:06"
  is not a finding until it says *which* artefact says so.

| # | Exercise | Tools | Time |
|---|---|---|---|
| 1 | Bring the exhibit | `ewfverify`, `ewfexport` | 10 min |
| 2 | What kind of disk is this? | `mmls`, `fsstat` | 10 min |
| 3 | Deleted, and back | `fls`, `istat`, `icat`, `tsk_recover` | 20 min |
| 4 | FAT keeps local time | `istat -z`, `fls -m`, `mactime` | 20 min |
| 5 | Carving, honestly | `foremost`, `bulk_extractor` | 20 min |
| 6 | Plaso on the pen, and checking plaso | `log2timeline.py`, `python3` | 25 min |
| 7 | Find an anchor | `timeline-reduce.py --peaks` | 15 min |
| 8 | From dataset to finding | `timeline-reduce.py` | 25 min |
| 9 | One serial, three sources | `grep`, your notes | 20 min |
| 10 | Two traps that look like findings | `grep`, `timeline-reduce.py --path` | 20 min |
| 11 | The web server, by its own account | `wtmp-read.py`, `mactime`, `grep` | 35 min |
| 12 | The blind spot in `hunt.sh` | `hunt.sh`, your editor | 15 min |
| 13 | Finding, or opinion? | a pencil | 15 min |
| 14 | The report | `report-scaffold.py forensic` | 60 min+ |

Exercises 1–6 are Block 1 (the filesystem), 7–10 Block 2 (artefacts), 11–14
Block 3 (timeline and report). The report is due before Session 9; there is a
week, and the week is not a hint to start on the last evening.

---

## 1 · Bring the exhibit

You will analyse a raw working copy. Make it from your E01, and prove the copy is
the evidence.

```bash
ewfverify -d sha256 ../session-07-forensic-acquisition/out/acq/C-007-EX-01.E01
ewfexport -t out/EX-01 -f raw -u ../session-07-forensic-acquisition/out/acq/C-007-EX-01.E01
shasum -a 256 out/EX-01.raw | tee -a out/my-notes.txt
```

No E01 from last week? `gunzip -c ../session-07-forensic-acquisition/samples/EX-01.img.gz
> out/EX-01.raw` — and write in your notes that you are working from the course
copy, not your own acquisition, because the report will have to say so.

1. The SHA-256 of `out/EX-01.raw` must equal the source hash on your Session 7
   chain of custody. Does it? Write the comparison in your notes, both values in
   full.
2. Which file do you now treat as the exhibit, and which as a working copy? Where
   is each stored, and who can write to them?

---

## 2 · What kind of disk is this?

```bash
mmls out/EX-01.raw
fsstat out/EX-01.raw | head -40
```

1. `mmls` complains. Why? What does that tell you about the layout, and what
   offset do you use with every other TSK tool? (The answer is short and
   satisfying.)
2. Record the filesystem type, the volume ID (serial) and the volume label, exactly
   as `fsstat` prints them. The serial will matter in Exercise 9 more than anything
   else on this page. Write it in **two** formats: `0x7a60e001` and `7A60-E001`.
3. What is the cluster size, and where does the data area start? You will need both
   to read raw sectors later.

---

## 3 · Deleted, and back

```bash
fls -r out/EX-01.raw
fls -rd out/EX-01.raw
istat out/EX-01.raw <INODE>
icat -r out/EX-01.raw <INODE> > out/recovered.txt
shasum -a 256 out/recovered.txt | tee -a out/my-notes.txt
tsk_recover -e out/EX-01.raw out/recovered-all/
```

1. Which entries are deleted? For each, record the long name, the 8.3 name, the
   size and the timestamps `istat` shows. Why does the 8.3 name begin with `_`?
2. Is the recovered content complete? Compare its size with the size in the
   directory entry, and read it end to end. Why was recovery this easy on FAT, and
   would you expect the same on ext4? (The slides have an opinion.)
3. There is a file whose name starts with `.~lock.`. Which application leaves those,
   when does it delete them, and what does its *existence* tell you about how the
   file was last closed? Read its content and record every field.
4. `LEIA-ME.txt` offers a reward. Ignore the reward; what does the file establish
   about the pen's owner, and how strong is that as attribution?

---

## 4 · FAT keeps local time

FAT stores a date and a time **with no timezone**. Whoever reads it decides what
zone it was in, and tools are not shy about deciding for you.

```bash
istat -z UTC out/EX-01.raw <INODE>
istat -z Europe/Lisbon out/EX-01.raw <INODE>
fls -r -m / -z UTC out/EX-01.raw > out/body-utc.txt
fls -r -m / -z Europe/Lisbon out/EX-01.raw > out/body-lisbon.txt
mactime -b out/body-lisbon.txt -d -z UTC > out/pen-timeline.csv
```

1. Do the two `istat` runs print different *numbers*, or only different labels?
   Now compare `body-utc.txt` and `body-lisbon.txt` — the bodyfile stores epoch
   seconds. By how much do they differ, and which one is right?
2. How do you *know* the pen was written in Lisbon time and not in UTC? You need an
   independent source. (There is one in FIN-02, and it was written by Windows, which
   knew its own timezone. Come back to this after Exercise 9.)
3. In October, Lisbon is on WEST (UTC+1). Convert every timestamp on the pen to UTC
   and build a short table: file, M/A/C as stored, M/A/C in UTC. What do you write
   for the **access** column, given that FAT keeps only a date?
4. Look at `algarve_lista.txt` and `fornecedores_iban.csv`. Their seconds are
   both even. Coincidence? What is FAT's time resolution, and what does that do
   to any claim of "X happened 1 second before Y"?
5. The deleted file: is there a **deletion** timestamp anywhere on this
   filesystem? If not, what are the earliest and latest moments it could have been
   deleted, and what are your sources for each bound? (You will need FIN-02 and
   Tiago's notes from Session 7. This is a Limitations paragraph in the making.)

---

## 5 · Carving, honestly

```bash
foremost -t all -i out/EX-01.raw -o out/carved/
cat out/carved/audit.txt
bulk_extractor -o out/bulk/ out/EX-01.raw
ls out/bulk/; cat out/bulk/email.txt; cat out/bulk/domain.txt | head -30
```

`bulk-extractor` is packaged in Kali but not in Debian 13. If `apt` cannot find
it, the poor analyst's version still gives you byte offsets:
`strings -td out/EX-01.raw | grep -E '[[:alnum:]._-]+@[[:alnum:].-]+'`.
It finds less, and knowing *what* it misses (UTF-16, compressed streams) is part
of the answer.

1. How many files did `foremost` carve? If the answer disappoints you, explain why
   it was always going to be that number for *this* pen. (Hint: what are the files,
   and what does carving look for?)
2. `bulk_extractor` found email addresses and domains. List them. Which are at
   offsets inside **allocated** files, and which only in unallocated space? (Turn
   an offset into a sector, then `ifind -d`. You did this in Session 7, Exercise 5.)
3. One domain differs from the company's by a single letter. Where else in this
   course have you seen it? Write the pivot down; it is the bridge between the pen
   and the phishing email, and your report needs that bridge.
4. A carved or feature-extracted hit has no timestamp of its own. What can you
   honestly say about *when* that email address got onto the pen?

---

## 6 · Plaso on the pen, and checking plaso

The super timeline starts in the break. Run it twice, with and without a
timezone, and then do the thing most people skip: check it against the bytes.

```bash
log2timeline.py --version | tee -a out/my-notes.txt
log2timeline.py --status_view none --storage_file out/pen-a.plaso out/EX-01.raw
log2timeline.py --status_view none --timezone Europe/Lisbon \
                --storage_file out/pen-b.plaso out/EX-01.raw
psort.py -o dynamic -w out/pen-a.csv out/pen-a.plaso
psort.py -o dynamic -w out/pen-b.csv out/pen-b.plaso
grep -i 'transferencias_out' out/pen-a.csv out/pen-b.csv | cut -c1-140
```

Now decode the same directory entry by hand. A FAT date is a 16-bit word:
7 bits of year since 1980, 4 bits of month, 5 bits of day. The time word is
5 bits of hour, 6 of minute, 5 of *two-second* units.

```bash
python3 - out/EX-01.raw <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read()
i = d.find(b'TRANSF~1CSV')                     # the 8.3 name in the directory
t, dt = struct.unpack_from('<HH', d, i + 22)   # write time, write date
print(f"{1980 + (dt >> 9)}-{(dt >> 5) & 15:02d}-{dt & 31:02d} "
      f"{t >> 11:02d}:{(t >> 5) & 63:02d}:{(t & 31) * 2:02d}  (local, no zone)")
PY
```

1. Put four answers side by side for `transferencias_out.csv`: the bytes, `istat`
   (Exercise 4), plaso without `--timezone`, plaso with it. Do they agree? If not,
   which is right, and how do you **prove** it rather than prefer it?
2. When we tested this exercise, plaso `20260720` disagreed with the bytes by a
   whole **month**, on every FAT entry, and `--timezone` made no difference to any
   of them. Your version may behave differently. Either way: what goes in the
   methodology section, and why is the tool **version** the most important word in
   that sentence? (ISO/IEC 27041, from Session 7, is the standard about exactly
   this.)
3. Search both CSVs for `novo_iban`. Is the deleted file in the super timeline?
   What does that tell you about building a case from plaso output alone?
4. Put plaso's (unchecked) time for the spreadsheet next to the banking session in
   FIN-02 (Exercise 8). What story does *that* timeline tell? A timeline with a
   wrong clock is worse than no timeline, because it looks exactly as
   authoritative as a right one.

---

## 7 · Find an anchor

FIN-02 is about 5 000 rows. Real ones are millions; the method is the same.

```bash
./timeline-reduce.py out/fin02.csv --peaks
```

1. The busiest minutes cluster around one time. What happened then? Open a few
   rows and name it. Is it relevant to the case?
2. The "quiet hours" list includes several 03:00s, and one hour that is neither
   night nor routine. Look at the 03:00 events first: benign or not, and how do you
   know? Then look at the odd one out. What is it, and why is it *alone* in its hour?
   (Keep the answer; it is Exercise 9's punchline.)
3. Neither the spike nor the quiet hours is your anchor. What is? Choose one and
   justify it in one sentence a non-technical reader would accept.

---

## 8 · From dataset to finding

```bash
./timeline-reduce.py out/fin02.csv --anchor-grep "assunto confidencial" --window 12h
./timeline-reduce.py out/fin02.csv --anchor-grep "assunto confidencial" --window 2h \
    --exclude 'mpavbase|\.ost|intranet|meteo|receitas|news\.example' \
    --out out/fin02-evening.csv
cat out/fin02-evening.filter.txt
```

1. The first run says the result "is still a dataset". How many rows, and why is
   ±12h the wrong window here?
2. The second run gets you to a few dozen rows. Read **every one** and write the
   evening of the 15th as a table: time (UTC), artefact, what it shows. Mark each
   row F (fact as the artefact states it) or I (your interpretation).
3. Every `--exclude` term is a decision that a row is irrelevant. Defend each one —
   or remove it. Which term would you be least comfortable defending in front of
   opposing counsel?
4. Read the `.filter.txt`. It says the `psort.py` expression covers the time window
   only. Why does that sentence matter, and what would happen if you pasted only the
   psort expression into your appendix?
5. Now reduce the morning of the 16th the same way, with your own anchor. What did
   João do between 07:38 and 07:48, and what does it suggest about his state of
   mind? Be careful which column that last part goes in.

---

## 9 · One serial, three sources

```bash
grep -i '7a60e001' out/fin02.csv | cut -c1-220
grep -i '0012A7F3C2' out/fin02.csv | cut -c1-220
grep -i 'setupapi' out/fin02.csv | cut -c1-220
```

1. The **volume serial** `0x7a60e001` appears in LNK files on FIN-02. Where did you
   last see it? What exactly does that match prove — and what does it *not* prove?
   (Two different things can have the same 32-bit volume serial. How likely is it
   here, and does it matter, given the rest?)
2. The **device serial** `0012A7F3C2` is in USBSTOR. What does it prove on its own?
   The Session 8 slides say it proves a connection, not a copy. Which artefact turns
   it into "these files were on this device at that time"?
3. The `setupapi.dev.log` entry and the USBSTOR entry for the same device disagree
   by almost exactly one hour. Which is right? Explain the discrepancy precisely —
   which file stores local time, which parser assumed UTC, and why the hour that
   was "alone" in Exercise 7 now makes sense.
4. Now close the loop from Exercise 4: Windows wrote LNK times for files on the pen
   in UTC, converting from the pen's local FAT times with the machine's own timezone.
   Compare the LNK time of `novo_iban_fornecedor.txt` with its FAT time. What does
   that tell you about the timezone the pen's times are in?

---

## 10 · Two traps that look like findings

Both are the kind of thing that ends up in a report's executive summary and then
in the other side's rebuttal.

**Trap A — the tool that never ran.**

```bash
grep -i 'remotesupport' out/fin02.csv | cut -c1-220
```

1. Which artefacts mention `RemoteSupport_QS.exe`? Which kinds of artefact are
   **missing** that would have shown it executed? (`hunt.sh questions`, under
   `ran`, lists them.)
2. Write two sentences: one that a careless analyst would put in the report, and
   the one you will put there instead.
3. Where did it come from? Read the `Zone.Identifier`. What does `ReferrerUrl`
   suggest about how João was led to the download? Then reduce ±10 minutes around
   the download and read what he wrote to "Rita" shortly afterwards.

**Trap B — the timestomp that wasn't.**

```bash
./timeline-reduce.py out/fin02.csv --anchor "2025-10-15 18:09:00" --window 300d \
    --path 'isencao_dupla_aprovacao' --out out/fin02-pdf.csv
cut -c1-180 out/fin02-pdf.csv
```

4. The `$STANDARD_INFORMATION` creation time is in March. The `$FILE_NAME` creation
   time is 15 October. The slides call that "a strong indicator of manipulation".
   Look at what ran one second before the `$FN` time, and at the file created next to
   it. What is the far likelier, entirely boring explanation?
5. How would you phrase this in the report so that it is neither an accusation nor
   a silent omission?

---

## 11 · The web server, by its own account

WEB-01's clock was ~4 minutes slow (Session 7, measured against a phone, which you
noted was not a great reference). Its logs are in that slow clock. Correct
**once**, when you build the table, and say so.

```bash
C=samples/web01-collection
./hunt.sh logons  --root "$C"
./wtmp-read.py "$C/var/log/wtmp"
grep -h 'deploy\|192.0.2.77' "$C"/var/log/auth.log* | head -20
grep -c 'Failed password.*192.0.2.77' "$C"/var/log/auth.log
grep '192.0.2.77' "$C/var/log/nginx/access.log"
mactime -b "$C/bodyfile/bodyfile.txt" -d -z UTC 2025-10-16..2025-10-17
```

1. Try `last -f "$C/var/log/wtmp"` first. What happens on your machine, and why?
   This is a real and recent trap, and it is why `wtmp-read.py` exists.
2. The `deploy` line Session 7's operator "tidied" out of `sessions-last.txt`: is it
   here? Quote it from `wtmp` **and** from `auth.log`. Two independent sources now
   agree on what was removed from the capture. Write that down; it is a strong
   finding about a weak capture.
3. Build the timeline of the evening of the 16th, in corrected UTC: the first web
   request from `192.0.2.77`, the first failed password, how many failed, the
   success, `sudo -l`, the shell as `www-data`, the crontab installed, the session
   end. Add PID 4127's start time from Session 7's `processes-full.txt`.
4. How did `192.0.2.77` know which username to try, and what password pattern?
   (`grep` the nginx log for a `200`, then read what it fetched. Try not to laugh;
   then try not to cry.)
5. `/var/www/.bash_history` is zero bytes, modified at the end of the `www-data`
   shell. `/home/deploy/.bash_history` is not empty. What can you conclude from each?
   Which statement in the slides' Linux artefact table is this an example of?
6. `syslog` shows the cron job running every ten minutes until when? What does
   that tell you about the `kill -STOP` in Session 7 — did it stop the persistence?
7. `auth.log` records `ops` running `nano` on a file under `/mnt/evidence` at 09:20.
   Which file, and what does that do to the Session 7 capture's evidential value?
   (Not "destroy". Be precise.)
8. Three configuration files made this possible. Find them (the bodyfile helps),
   quote the line from each, and note how long each had been in place. These are
   your defensive recommendations, already written; you just have to cite them.

---

## 12 · The blind spot in `hunt.sh`

```bash
./hunt.sh persist --root samples/web01-collection
```

1. It finds `etc/cron.d` and `etc/crontab`. Does it find the crontab that actually
   matters in this case? Where is that file, and why does `hunt.sh` miss it?
2. Patch `q_persist` so it finds per-user crontabs (both the Debian
   `var/spool/cron/crontabs/` and the RHEL `var/spool/cron/` layouts), and prints a
   hint worth reading. Keep it read-only.
3. Run it again, then think of one more Linux persistence location `hunt.sh` does
   not check (Session 3 had a list). Add it too, or write down why you didn't.
4. Pull request, with a commit message that says what was missed and on which
   evidence you noticed. "It found nothing" is a result; "it found nothing because
   it did not look" is a bug.

---

## 13 · Finding, or opinion?

For each statement, mark **F** (finding: the artefact says this), **I**
(inference: reasonable, but yours), or **X** (not supported — rewrite or drop).
For every I, write the reasoning and a confidence. For every X, write the version
that is supported.

| # | Statement |
|---|---|
| 1 | `novo_iban_fornecedor.txt` was created on EX-01 at 18:07:12 UTC on 15 October. |
| 2 | João deleted the note to cover his tracks. |
| 3 | The pen was connected to FIN-02 at 18:06:55 UTC on 15 October. |
| 4 | João copied the IBAN from the pen to the bank portal. |
| 5 | RemoteSupport_QS.exe was executed on FIN-02. |
| 6 | The file `isencao_dupla_aprovacao.pdf` was timestomped. |
| 7 | The attacker who phished João also compromised WEB-01. |
| 8 | `deploy` logged in to WEB-01 from 192.0.2.77 after 212 failed attempts. |
| 9 | No commands were run as www-data, because its history is empty. |
| 10 | The transfers were made under instructions received by email from a lookalike domain. |

Statement 7 deserves a paragraph of its own. What do you actually have that links
the two hosts, and what would you need?

---

## 14 · The report

The Session 8 deliverable: a full forensic report on the case, with a reduced
timeline and at least one specific limitation.

```bash
../session-06-socmint-phishing/report-scaffold.py forensic --case C-007 \
    --exhibit EX-01 --analyst "Your Name" --out out/report.md
# ... fill it in ...
../session-06-socmint-phishing/report-scaffold.py forensic --check out/report.md
```

| Component | From |
|---|---|
| Exhibits, with hashes matching your Session 7 CoC | Exercise 1 |
| Methodology: every tool **with its version**, the standard followed, the timezone each tool assumed | Exercises 2–6, 11 |
| At least **eight findings**, each in UTC, each naming its source artefact | Exercises 3, 4, 8, 9, 11 |
| The reduced timeline, with its `.filter.txt` | Exercise 8 |
| Analysis, separated from findings, labelled, with confidence | Exercises 10, 13 |
| Limitations: specific, with the findings each one affects | Exercises 4, 5, 11 |
| Defensive recommendations, each citing the finding it comes from | Exercise 11 |
| Commands, as run, in an appendix | `out/my-notes.txt` |

Four things that separate a good report on this case from a merely long one:

- **The bridge.** EX-01, FIN-02 and WEB-01 are three exhibits. The report must say
  explicitly what connects each pair, and where a connection is only a hypothesis
  (Exercise 13, statement 7), say that too.
- **João.** He is the person who made the transfers, and the evidence supports a
  victim far better than a culprit. Your findings will not say either word. Your
  analysis may, if you can support it, and if you can't, it shouldn't.
- **Clock statements.** One paragraph at the top: which clocks, which offsets,
  which corrections, applied where. Then never mention timezones again, because
  everything below is UTC.
- **Negative results.** "No Prefetch entry exists for RemoteSupport_QS.exe" is a
  finding. So is "no deletion timestamp exists for the note on EX-01". Write them.

Write the executive summary last. It is the first thing read and the last thing
knowable.
