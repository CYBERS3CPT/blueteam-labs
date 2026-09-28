# Session 6 — Exercises

Hands-on and Kali-first, built on the scripts in this folder (with a few friends
from Sessions 1, 3 and 5). Everything runs against the fixtures in `samples/` or
against infrastructure you are allowed to touch. No real victim is needed, and
none is created.

**The scenario.** *Tagus Logística* (`tagus-logistica.example`, fictional) is
having a bad October: seven messages landed in its mailboxes and five profiles
have been circling its staff. You are the analyst.

Every domain is under `.example` and every IP is in the RFC 5737 documentation
ranges, so nothing here resolves or reaches anyone.

## Before you start

```bash
cd blueteam-labs/session-06-socmint-phishing
sudo apt install -y jq ripmime mpack zbar-tools libimage-exiftool-perl \
                    idn dnsutils whois dnstwist python3-yara
mkdir -p out    # git-ignored; your output goes here
```

Ground rules, same as the session:

- **Research VM, snapshot first**, revert when done.
- **The fixtures are the target.** Where an exercise touches the live internet it
  says so and says what you may point it at.
- **Nothing gets uploaded** — not the attachment, not the QR image. Session 3
  explained why.

| # | Exercise | Tools | Time |
|---|---|---|---|
| 1 | Chain of custody | `shasum` | 5 min |
| 2 | Seven messages, ten checks | `eml-triage.py` | 25 min |
| 3 | The tool is not the analyst | `eml-triage.py --json`, `jq` | 20 min |
| 4 | Homoglyphs, by the byte | `idn`, `xxd`, `grep -P` | 15 min |
| 5 | The attachment that lies twice | `ripmime`, `file`, `xxd`, `static-triage.sh` | 20 min |
| 6 | The URL is in the picture | `munpack`, `zbarimg` | 15 min |
| 7 | Read a domain's mail posture | `dig`, `passive-recon.sh` | 20 min |
| 8 | Detection engineering | `yara`, `suricata-lab.sh` | 30 min |
| 9 | Five profiles, one lazy colleague | `exiftool`, `profile-score.py` | 30 min |
| 10 | Username correlation, honestly | `sherlock`, `holehe` | 20 min |
| 11 | The write-up | `report-scaffold.py` | 45 min |

Do them in order the first time. Exercise 11 assumes you did the rest.

---

## 1 · Chain of custody

Before you open anything, prove what you received.

```bash
shasum -a 256 -c samples/SHA256SUMS
shasum -a 256 samples/*.eml samples/profiles/* > out/received.sha256
```

Everything should say `OK`. If one does not, stop — you are analysing something
other than what everyone else has. A hash taken *after* you have poked a file
proves only what it looks like after poking. Hash on arrival, especially when it
feels silly.

**Deliverable:** `out/received.sha256`, for the appendix of Exercise 11.

---

## 2 · Seven messages, ten checks

```bash
./eml-triage.py samples/*.eml --brief | less -R
```

Fill in one row per message, not per mood:

| File | SPF | DKIM | DMARC | Published `p=` | Reached inbox? | Check 10 | Verdict | One line of evidence |
|---|---|---|---|---|---|---|---|---|

"Reached inbox?" is deliberately separate from the authentication verdict. A
`dmarc=fail` under `p=none` is a message in someone's inbox with a note attached
that no filter acted on.

Answer in writing:

1. Which messages would a published DMARC `p=reject` have stopped, and which not?
   One sentence each on *why not*.
2. One message is legitimate. Which, and what makes you sure? Name the headers,
   not the feeling.
3. Message 01 shows a 17-minute gap between hops. Queue, or something worth a
   second look? What would let you decide?

---

## 3 · The tool is not the analyst

A tool that is right most of the time is dangerous, because you stop checking.

```bash
./eml-triage.py samples/*.eml --json 2>/dev/null \
  | jq -r 'to_entries[] | .value[] | [.severity, .finding] | @tsv' \
  | sort | uniq -c | sort -rn
```

1. Which finding fires on nearly every message, including the legitimate one?
   What is it actually measuring? A finding that fires on everything trains people
   to skip the list.
2. Read check 10 for **message 02**. Is what it prints true for that message?
3. Which message has the **fewest** findings, and how worried should that make
   you? (Re-read the "no findings is not benign" note in the README.)

---

## 4 · Homoglyphs, by the byte

Your eyes are the vulnerability; take them out of the loop.

```bash
grep -h '^From:' samples/04-*.eml
idn --idna-to-unicode xn--tagus-logstica-ebm.example
grep -P '[^\x00-\x7F]' -n samples/*.eml | cut -c1-120
```

1. Which byte sequence is the impostor? Give its Unicode code point and name.
2. Write the real domain and the fake one side by side in your report font, and
   screenshot it. That screenshot is a better awareness slide than any sentence
   about homoglyphs.
3. Run `dnstwist --format csv tagus-logistica.example | head -30` (offline
   permutation; `.example` never resolves). Which *kinds* of lookalike does it
   generate — and is the style used in message 02 among them?

---

## 5 · The attachment that lies twice

Message 05 carries a "delivery note" that misstates its extension and its type.
Catch both without executing anything.

```bash
mkdir -p out/05 && ripmime -i samples/05-*.eml -d out/05
ls out/05 | cat -A          # the filename as bytes
file out/05/*
xxd out/05/* | head -4
../session-03-malware-triage/static-triage.sh out/05/* -o out/05-triage
```

1. How does the filename render in a mail client versus how it is really spelled?
   Which code point does the trick?
2. `file` says one thing, the declared `Content-Type` another. Which do you
   believe, and why?
3. Which **mail-gateway control** would have neutralised this regardless of user
   behaviour? Name it concretely enough for the mail admin to configure it.

It is a harmless stub. You still don't run it. The habit is the point.

---

## 6 · The URL is in the picture

Message 07 made `eml-triage.py` shrug: authentication passes, no URLs, one PNG.
That shrug is the attack.

```bash
mkdir -p out/07 && (cd out/07 && munpack -f ../../samples/07-*.eml)
file out/07/*
zbarimg --raw out/07/*.png
```

1. Read the decoded hostname right to left. Who actually owns it? Which part is
   decoration?
2. Why does steering the target to their *phone* matter? Name two laptop controls
   it sidesteps.
3. `eml-triage.py` is standard-library only and cannot read QR codes. Write a
   short wrapper that extracts images from an `.eml` and runs `zbarimg` on each,
   then run it across all seven samples. How many QR codes are in the set?

---

## 7 · Read a domain's mail posture

**Live internet, passive only.** Point this at your assessment target or your own
domain — DNS lookups are passive but still logged, so stay in scope.

```bash
D=example.pt        # replace with your authorised target
dig +short TXT "$D" | grep -i spf
dig +short TXT "_dmarc.$D"
dig +short MX "$D"
./session-05-osint-ews/passive-recon.sh "$D" -o out/recon
```

1. Does the domain publish SPF and DMARC? What is the DMARC `p=`? If it is `none`,
   what does that mean for messages 01 and 04 in this folder?
2. `passive-recon.sh` runs `dnstwist --mx`. Why is a lookalike *with* MX records
   more urgent than one without? (The README's "someone preparing to send email
   as you" note.)
3. Add one registered lookalike you find to your Session 5 early-warning feed.

---

## 8 · Detection engineering

You have read the attacks. Now write something that would have caught them.

The RLO attachment leaves a stable signature — the `U+202E` byte sequence
`E2 80 AE` inside a MIME header. A starter YARA rule:

```
rule S06_RLO_in_attachment_name {
  strings:
    $cd  = "filename" nocase
    $raw = { E2 80 AE }
    $pct = "%E2%80%AE" nocase
  condition:
    $cd and ($raw or $pct)
}
```

```bash
yara S06_RLO.yar samples/*.eml       # which of the seven does it flag?
```

1. Which message does it match, and does it match any it should not? A rule that
   fires on the control is worse than no rule.
2. Write a second rule for the homoglyph case: `xn--` appearing in a `From` or
   URL host. What is its false-positive risk on real mail, where punycode is
   sometimes legitimate?
3. Turn the campaign infrastructure into one Suricata idea — a DNS query for a
   known lookalike, say. Scaffold it with
   `../session-01-ids-ips/suricata-lab.sh new-rule s06-lookalike` and explain what
   telemetry it needs to fire.

---

## 9 · Five profiles, one lazy colleague

```bash
./profile-score.py --rubric
exiftool samples/profiles/*
./profile-score.py --batch samples/profiles/profiles-colleague.csv
```

The metadata tells stories the profile text does not. Answer:

1. One image names its generator; one is marked as AI in IPTC; one is a stock
   photo; one had its metadata wiped; one is an ordinary phone photo with GPS.
   Which is which — and which of these is the *least* suspicious, and why?
2. The colleague's sheet scores several indicators with no evidence. The tool
   lists them. Pick two and say what evidence would justify the score, or drop it.
3. Two profiles share an identical bio. What does that one shared string let you
   conclude that neither profile alone would?
4. Re-score the profile you most disagree with, with evidence, and be ready to
   defend it. Where two analysts differ, one assumed something the evidence did
   not say — that gap is the whole exercise.

---

## 10 · Username correlation, honestly

**Live internet, passive.** Use your *own* handle, or one you are authorised to
investigate. Never a classmate's.

```bash
sherlock <your-handle>
holehe <your-email>
```

1. `sherlock` reports a hit when a URL returns a profile-shaped response. Pick
   three hits and verify them by hand. How many are actually you? That ratio is
   the false-positive rate, and it is why a raw `sherlock` dump is not a finding.
2. Rate each verified hit on the Admiralty scale. What is the highest reliability
   you can honestly assign before external corroboration?
3. Write the one-sentence caveat about tool output that belongs in every OSINT
   report's limitations section.

---

## 11 · The write-up

Turn the evening into a deliverable.

```bash
./report-scaffold.py osint --case C-006 --target "Tagus Logistica" \
    --analyst "Your Name" > out/report.md
# ... fill it in ...
./report-scaffold.py osint --check out/report.md
```

Your report should cover: the seven-message triage (Ex. 2–6), the domain posture
(Ex. 7), the detections you wrote (Ex. 8), and the profile assessment (Ex. 9),
with your evidence hashes (Ex. 1) as an appendix.

The two sections people leave out are **Limitations** and **Defensive
recommendations**. `--check` flags them by name, and also flags any section
present but nearly empty. It exits non-zero on missing sections, so it works in a
submission pipeline.

Each recommendation must name the finding it derives from. Write the executive
summary last: it is the first thing read and the last thing knowable.
