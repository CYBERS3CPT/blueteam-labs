# Session 16 — Cloud Threats, Tooling and Risk

## `triage-findings.py`

```bash
prowler aws --output-formats json-ocsf --output-directory ./out
./triage-findings.py out/prowler-output.ocsf.json
./triage-findings.py out/prowler-output.ocsf.json --tier 1
./triage-findings.py scoutsuite_results.js --format scout
./triage-findings.py findings.csv --format csv --out triaged.csv
./triage-findings.py out/*.json --suppress suppressions.yml
```

Reads Prowler (OCSF or native), ScoutSuite, or any CSV with recognisable columns.

### The four tiers

Your first scan of a real account returns several hundred findings, and that is
the moment most cloud security programmes fail. They fail in four predictable
ways: fixing from the top of the list (which is ordered by the tool's opinion),
fixing everything (you will not finish), ignoring it (wallpaper), or emailing the
CSV to the platform team (closed as "known").

The order that works:

1. **Exposure** — reachable from the internet, or granting access outside.
2. **Identity** — can escalate privilege, or grant permissions.
3. **Detectability** — logging gaps, which make everything else invisible.
4. **Hygiene** — the benchmark tail.

Tier 3 is third by **sequence**, not by importance. Every detectability finding is
a reason you would not know that a tier 1 or tier 2 finding had been exploited,
and the tool says so at the end so it does not get lost.

### Suppressions need four fields

`check`, `reason`, `who`, `until`. Entries missing any of them are **ignored,
loudly**, and expired ones are ignored too.

A suppression without a reason, a named owner and an expiry is not a decision —
it is something somebody hid. The expiry is what makes it reviewable, and
reviewable is the whole difference.

See `suppressions.example.yml`. "False positive" is not a reason.

### It does not sort by severity

Deliberately. Severity is the scanner's opinion about a check in the abstract.
Tier is your opinion about this finding in your environment, and the second one
is the one that decides what gets fixed on Monday.

---

## `risk-register.py`

```bash
./risk-register.py --template register.csv
./risk-register.py new                  # interactive, one entry
./risk-register.py register.csv         # prioritised report
./risk-register.py register.csv --check # would this survive an audit?
./risk-register.py --explain
```

### A finding is not a risk

> *"We have 312 findings"* is a task list.
>
> *"A single leaked CI credential gives an attacker write access to production
> storage holding personal data of 40,000 citizens, and we would not detect the
> reads"* is a risk statement.

The second gets funded. `--check` rejects the first shape: a description under
twelve words, assets with no scale, impact as a colour.

### It sorts by risk reduction per effort-day

Not by raw score. The control that reduces three risks at once wins, even if none
of them is the highest — and that ordering is invisible if you rank by severity.

### Impact must be a range

A single number is rejected with a reason:

> a single fabricated number is less honest than a wide range

"Between EUR 40k and EUR 400k, 80% confident" is defensible. A colour is not an
estimate at all.

### The two fields regulators ask for

**Owner** and **accepted by**. `--check` refuses an `accept` treatment with no
named acceptor — *that is not acceptance, it is being ignored* — refuses "the
security team" as an owner, and flags a `review_date` that has already passed,
because an acceptance without a live review date has lapsed.

It exits non-zero, so a submission pipeline can refuse an incomplete register.
