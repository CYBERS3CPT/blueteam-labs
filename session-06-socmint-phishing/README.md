# Session 6 — SOCMINT, Dark Web and Phishing (assessed)

Analysis targets for the whole session live in `samples/` — seven `.eml`
messages and five profiles, all fictional (`.example` domains, documentation
IPs). Hash them first (`shasum -a 256 -c samples/SHA256SUMS`), then read them
with the tools below. See `samples/README.md` for what each one exercises, and
`EXERCISES.md` for the eleven-exercise walk-through that uses them.

## `eml-triage.py` — header forensics

```bash
./eml-triage.py message.eml
./eml-triage.py samples/*.eml --brief
./eml-triage.py message.eml --json
```

Works the ten checks in order, every time. Nothing connects to the network: it
reads the file you gave it and no more.

### The check that matters most is number 10

*Would DMARC `p=reject` have stopped this?*

When the answer is **no**, that is the interesting case — and it is the one that
surprises people. A lookalike domain the attacker **owns** passes SPF, DKIM and
DMARC perfectly, because it is their domain and they published the records.
DMARC stops exact-domain spoofing. It does nothing for lookalikes. If your
anti-phishing programme is "we deployed DMARC", this is the slide you missed.

### Homoglyphs are decoded, not eyeballed

The confusables table covers the characters that actually turn up in domains —
Cyrillic а е о р с х, Greek ο α, the dotless ı. Punycode is decoded and shown.
`U+202E` in an attachment filename is flagged, because "invoice⁠[RLO]cod.exe"
renders as "invoiceexe.doc" and that is the entire trick.

### "No findings" is not "benign"

A well-resourced actor sends well-formed email from a domain they own. The tool
says so rather than letting a clean run read as a clean verdict.

---

## `profile-score.py` — the fake profile rubric

```bash
./profile-score.py --rubric      # print it; this is your methodology section
./profile-score.py               # score one, interactively
./profile-score.py --template    # CSV for scoring five at once
./profile-score.py --batch profiles.csv
```

Nine indicators, 20 points, four interpretation bands.

### Two things it enforces

**Evidence per score.** Any indicator scored above zero without an evidence note
is listed at the end as indefensible. A score without evidence is an opinion with
a number attached, and it will not survive the debrief.

**Dormancy is not inauthenticity.** A real person with an abandoned account
scores on "age vs volume" and "engagement" for entirely innocent reasons. Flag
the account as dormant and those two are discounted, visibly, in the output — so
the adjustment appears in the sheet rather than happening quietly in your head.

---

## `report-scaffold.py`

Used in this session, and again in Sessions 8, 15, 16 and 17 — the shape is the
transferable skill.

```bash
./report-scaffold.py --list
./report-scaffold.py osint --case CASE-001 --target "Entity Name" --analyst "Your Name"
./report-scaffold.py forensic --case C-001 --exhibit EX-01
./report-scaffold.py cloud --case CLD-001
./report-scaffold.py osint --check draft.md     # when you think it is done
```

### The two sections people leave out

**Limitations.** What separates an honest report from a confident one. The
template says it in the prompt: *"More time would have helped" is not a
limitation; "the mailbox export covered 30 days and the activity predates it" is.*

**Defensive recommendations.** The only reason anyone commissioned the work, and
the section that turns reconnaissance-with-a-cover-page into a deliverable. Each
recommendation must name the finding it derives from.

`--check` flags both by name when they are missing.

### `--check` also finds thin sections

Present and empty is the other failure. Any section with fewer than twelve words
is listed, because a heading with nothing under it reads as an oversight to
everyone except the person who wrote it.

It exits non-zero on missing sections, so it works in a submission pipeline.

### Write the executive summary last

It is the first thing read and the last thing knowable.
