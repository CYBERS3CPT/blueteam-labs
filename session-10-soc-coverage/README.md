# Session 10 — SOC Fundamentals: Types and Maturity

## `attack-layer.py`

Turns a CSV of your own detection rules into an ATT&CK Navigator layer.

```bash
./attack-layer.py --template rules.csv    # start here
./attack-layer.py rules.csv --report      # what your coverage actually looks like
./attack-layer.py rules.csv               # writes coverage.json
./attack-layer.py rules.csv --gaps        # how to choose the three that matter
```

Import at `mitre-attack.github.io/attack-navigator` → Open Existing Layer.

### It refuses to build a dishonest layer

Two checks, and they fail the build rather than warning politely:

**Too many 3s.** If more than 40% of your rules are scored "strong", it stops. A
score of 3 means behavioural and hard to evade without changing the technique
itself. Most rules detect one implementation of one tool. That is a 1.

**No 1s at all.** Every real detection estate has partial coverage. A layer
without any suggests the scoring was aspirational rather than measured.

`--force` exists. You will be asked to defend the layer either way, and it is
cheaper to lose that argument with a script than with a colleague.

### Every scored row must name a data source

Non-negotiable, enforced at load time. You cannot detect a technique whose
telemetry you do not collect, and a rule over a log source present on 40% of
endpoints is 40% of a detection. `--report` then shows which sources you depend
on and which are single points of failure — one source going quiet takes its
whole row of coverage with it.

### Multiple rules on one technique

The cell takes the **best** score, not the sum, and the comment says so. Three
partial rules are still partial.

---

## `metrics.py`

```bash
./metrics.py --template alerts.csv    # the columns, with examples
./metrics.py alerts.csv
./metrics.py alerts.csv --period "Q4" --out metrics.txt
./metrics.py --explain                # what each number misleads about
```

### It will not print a throughput number alone

Goodhart's Law arrives in any SOC within one quarter. The mitigation is not to
avoid efficiency metrics — it is to **never report one without its quality pair**.
So alerts handled appears beside reopen rate, escalations beside escalation
accuracy, and per-analyst volume beside per-analyst reopens, with a line telling
you not to rank people on the first column.

### MTTD from the alert is the flattering one

It measures how fast you responded to *yourself*, and it only ever improves.

The tool computes MTTD from **adversary action** where `adversary_utc` is
present, and when it is absent from every row it says so rather than quietly
printing the flattering version:

> *This is THE metric, and you cannot compute it. The incident timeline already
> contains it — it is just never copied into the case.*

### Rules that have never produced an incident

Listed by name. Tune them or retire them: a rule nobody acts on trains people not
to act, and that habit does not stay confined to the noisy rule.
