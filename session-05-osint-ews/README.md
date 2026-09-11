# Session 5 — OSINT Process and Early Warning Systems

## `ews.py` — the Early Warning System

Small enough to read in one sitting, which is the point.

```bash
./ews.py init              # writes ews.toml
./ews.py run --dry-run     # fetch, filter, dedupe, print. Send nothing.
./ews.py run               # for real
./ews.py test-webhook      # prove the plumbing before you need it
```

Works with `feedparser` if you have it, and falls back to `urllib` plus a
deliberately naive RSS parser if you do not. Requires Python 3.11+ for `tomllib`.

### The part everyone skips

Step 2. Run `--dry-run` and keep tightening `keywords` and `exclude` **until the
output is boring**. An EWS that reports every CVE reports nothing, and a channel
that cries wolf is muted within two weeks — at which point you have built a
system that makes you *less* likely to notice an incident.

The `exclude` list is not a convenience. Every entry is a risk you are accepting
on purpose, and it belongs in the documentation with a reason next to it.

### Deduplication

Non-negotiable. Without it the same CVE arrives from four feeds for six days.
State lives in `.ews-state.json`, capped at 5000 hashes (months of history,
about 350 KB). Delete it to start fresh; expect one noisy run if you do.

First run is forced to dry-run, because otherwise day one is a wall of text and
nobody reads day two.

---

## `passive-recon.sh` — passive, and it means it

```bash
./passive-recon.sh example.pt
./passive-recon.sh example.pt -o ./case-001
```

Certificate transparency, WHOIS, passive `amass`, passive `theHarvester`,
`dnstwist`. Nothing scans, nothing brute-forces, nothing touches a port.

Writes an **evidence log with UTC capture times** alongside the results, because
a finding with no capture time is not a finding.

### Two notes

**`-passive` on amass is load-bearing.** Without it, amass resolves and probes,
and your passive engagement quietly became an active one.

**`--mx` on dnstwist is the flag that matters.** A registered lookalike is noise.
A registered lookalike *with mail exchange records configured* is someone
preparing to send email as you.

---

## `evidence-log.sh`

```bash
export EVIDENCE_COLLECTOR="Your Name"
./evidence-log.sh init CASE-001
./evidence-log.sh capture https://example.pt/about "leadership page"
./evidence-log.sh note "BASE contract 12345 located; supplier confirmed"
./evidence-log.sh verify
./evidence-log.sh pack
```

The finding you make carelessly in week five is the one that gets challenged.

### WARC, not a screenshot

`wget --warc-file` preserves the **request and response headers**, which is what
makes a capture evidence rather than a picture of a browser. A screenshot is
added too where a headless Chromium exists, but it is the supporting artefact,
not the primary one.

### Hash immediately

Every artefact is hashed as it lands, and the hash goes in the log with the UTC
capture time and the **tool version**. A hash taken later proves less with every
minute that passed, and tool versions matter when a parser bug is found
afterwards.

### `verify` re-hashes everything

If a hash has changed it **exits non-zero and tells you not to quietly re-hash
and move on**. The next question is always "how do we know it was not modified
before you first hashed it?", and the only good answer is a log that shows the
change and when you noticed.

### It says "semi-passive" out loud

Fetching a page touches the target's web server. That is semi-passive, not
passive, and the method column records it as such. Getting that distinction right
in the log is what stops it becoming an argument in the report.

### `pack` seals the bundle

Verifies, tars, hashes the tarball, writes the hash beside it. Then give the hash
to the recipient **by a different channel than the bundle** — a hash that travels
with the file proves nothing.
