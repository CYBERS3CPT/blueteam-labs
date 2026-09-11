#!/usr/bin/env python3
"""
report-scaffold.py — the report structure, with the sections that carry the marks.

Every assessed deliverable in this course wants the same shape, because the shape
is the transferable skill. This writes it, with the prompts in place and the
two sections people leave out already flagged.

Usage
    ./report-scaffold.py osint --case CASE-001 --target "Entity Name"
    ./report-scaffold.py forensic --case C-001 --exhibit EX-01
    ./report-scaffold.py cloud --case CLD-001
    ./report-scaffold.py --list
    ./report-scaffold.py osint --check draft.md      does a draft have every section?

The two sections people leave out are LIMITATIONS and DEFENSIVE RECOMMENDATIONS.
The first is what separates an honest report from a confident one. The second is
the only reason anyone commissioned the work.
"""

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

COMMON_TAIL = """
## Limitations

*The section that separates an honest report from a confident one. Be specific.
"More time would have helped" is not a limitation; "the mailbox export covered
30 days and the activity predates it" is.*

- What could you not determine, and why?
- What did you not attempt, and why?
- Which findings would change if the missing thing became available?

## Data handling

| | |
|---|---|
| Personal data collected | |
| Lawful basis | |
| Pseudonymisation applied | |
| Where the raw data is held | |
| Retention and deletion date | |

*State a date. Then meet it — the statement is part of the assessment and so is
honouring it.*
"""

TEMPLATES = {
 "osint": ("OSINT assessment report", """# OSINT Assessment — {target}

| | |
|---|---|
| Case reference | {case} |
| Analyst | {analyst} |
| Date (UTC) | {now} |
| Target | {target} |
| Classification | |

## Executive summary

*One page. For a decision-maker, not an analyst. If they read only this, what
must they know and what should they do?*

## Scope and legal basis

| | |
|---|---|
| Question asked, and by whom | |
| In scope | |
| **Out of scope** | |
| Collection posture | passive / semi-passive — and nothing else |
| Lawful basis | usually legitimate interest; the balancing test goes in the file |
| Minimisation rule | what you will *not* collect, though you could |
| Retention and deletion date | |

## Methodology

- Sources consulted
- Tools used, **with versions**
- Collection posture, per source
- **Coverage gaps** — what you could not access, and why

*An investigation that omits its own coverage gaps overstates its conclusions.*

## Findings

*Every finding carries a source, a UTC capture time, and an Admiralty rating.
Unsourced claims score zero.*

| # | Finding | Source | URL / query | Captured (UTC) | Admiralty |
|---|---|---|---|---|---|
| 1 | | | | | |

## Attack-surface assessment

*What is exposed, and what an adversary could assemble from it. This is where
the individual findings become a picture.*

## Defensive recommendations

***This section is the point of the report.*** An OSINT report that stops at
"here is what we found" is reconnaissance with a cover page.

Each recommendation must name the finding it derives from, and be specific
enough to action.

| # | Recommendation | Derives from | Priority | Effort |
|---|---|---|---|---|
| 1 | | Finding # | | |

*Weak: "employees share too much on social media".*
*Strong: "six staff list the EDR product in public profiles; remove product names
from the standard job description template".*

## Sources appendix

| # | Source | Full URL | Captured (UTC) | Hash |
|---|---|---|---|---|
"""),

 "forensic": ("Forensic examination report", """# Forensic Examination Report

| | |
|---|---|
| Case reference | {case} |
| Exhibit | {exhibit} |
| Examiner | {analyst} |
| Report date (UTC) | {now} |

## Scope and authorisation

| | |
|---|---|
| What you were asked | |
| By whom | |
| Under what authority | warrant / policy / consent, with a reference |
| Dates of examination | |

## Exhibits

| Exhibit | Description | Source hash (SHA-256) | Image hash (SHA-256) | CoC ref |
|---|---|---|---|---|
| {exhibit} | | | | |

## Methodology and tools

| Tool | **Version** | Used for |
|---|---|---|
| | | |

Standard followed: *ISO/IEC 27037 / ACPO / other — name it, and note any deviation and why.*

## Findings

*Factual. Sourced. Timestamped in UTC, with the clock drift applied or stated.*

| # | Finding | Artefact | Timestamp (UTC) | Evidence ref |
|---|---|---|---|---|
| 1 | | | | |

## Timeline

*Reduced, with the filter expression included so it can be reproduced.*

| Time (UTC) | Source artefact | Event | Confidence |
|---|---|---|---|

Filter applied:

```
<paste the filter expression, or the .filter.txt produced by timeline-reduce.py>
```

## Analysis

***Clearly separated from findings.*** Everything here is an inference. Label it,
give the reasoning, and state the confidence.

## Conclusions

*Answering the questions in scope, and only those.*

## Reproducibility

- Commands, as run
- Tool versions
- Hashes of every artefact extracted
- **Negative results** — "I searched X and found nothing" is a finding
"""),

 "cloud": ("Cloud assessment report", """# Cloud Assessment Report

| | |
|---|---|
| Case reference | {case} |
| Assessor | {analyst} |
| Date (UTC) | {now} |
| Environment | account / subscription / project identifiers |

## Scope and authorisation

| | |
|---|---|
| Accounts / subscriptions / projects in scope | |
| Explicitly out of scope | |
| Dates and hours | |
| Techniques permitted | |
| **Techniques forbidden** | denial of service, always |
| Client authorisation | reference to the written instruction |
| **Provider policy** | which, and when you read it |
| Emergency contacts, both sides | with a number that is answered |
| If a live intrusion is found | agreed in advance: the engagement stops |

## Cost controls

*Evidence that budget alerts and quotas were configured **before** deployment.*

## Methodology

| Tool | Version | Used for |
|---|---|---|
| | | |

## Findings

| # | Finding | Enabling misconfiguration | Severity | Justification |
|---|---|---|---|---|
| 1 | | | | |

*Triaged by exposure, then identity, then detectability, then hygiene — not by
the scanner's severity label.*

## Attack narrative

*The chain as a story a manager can follow, with UTC timestamps.*

## Detection assessment

***This section is what makes it a Blue Team report** rather than a penetration
test with a different cover page.*

| Stage | Logged? | Event name | Latency | Existing rule? | Rule written |
|---|---|---|---|---|---|
| foothold | | | | | |
| enumerate | | | | | |
| escalate | | | | | |
| persist | | | | | |
| data access | | | | | |
| exfiltration | | | | | |

### Detection gaps

*Every row above where "Logged?" is NO. This is the most valuable output of the
whole exercise.*

## Remediation

*Prioritised by exposure first. Specific: the setting or the command, not
"restrict access".*

## Earliest break

*The one control that would have stopped the chain soonest, and why you would
fund that one before the others.*

## Teardown

*`terraform destroy` output, the region sweep, and the cost check.*
"""),
}


def build(kind, case, target, exhibit, analyst):
    title, body = TEMPLATES[kind]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return body.format(case=case or "________", target=target or "________",
                       exhibit=exhibit or "________", analyst=analyst or "________",
                       now=now) + COMMON_TAIL


def check(kind, path):
    """Does a draft have every required heading, and the two people forget?"""
    text = Path(path).read_text(encoding="utf-8")
    _, body = TEMPLATES[kind]
    required = re.findall(r"^## (.+)$", body + COMMON_TAIL, re.M)
    present = {h.strip().lower() for h in re.findall(r"^#{1,3}\s*(.+?)\s*$", text, re.M)}

    missing = []
    for h in required:
        clean = re.sub(r"\*+", "", h).strip().lower()
        if not any(clean[:18] in p for p in present):
            missing.append(h)

    print()
    print(f"  {path}  ({len(text.split())} words)")
    print()
    if missing:
        print(f"  {len(missing)} section(s) missing:")
        for m in missing:
            note = ""
            ml = m.lower()
            if "limitation" in ml:
                note = "   <- the one that separates honest from confident"
            if "recommend" in ml:
                note = "   <- the only reason anyone commissioned the work"
            if "data handling" in ml:
                note = "   <- not optional when personal data was collected"
            print(f"    - {m}{note}")
    else:
        print("  every required section is present")

    print()
    # Thin sections are the other failure: present, and empty.
    for h in required:
        clean = re.escape(re.sub(r"\*+", "", h).strip())
        m = re.search(rf"^#{{1,3}}\s*{clean}\s*$(.*?)(?=^#{{1,3}}\s|\Z)", text, re.M | re.S)
        if m and len(m.group(1).split()) < 12:
            print(f"  thin: '{h}' has {len(m.group(1).split())} word(s)")
    print()
    if missing:
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kind", nargs="?", choices=sorted(TEMPLATES))
    ap.add_argument("--case"); ap.add_argument("--target")
    ap.add_argument("--exhibit"); ap.add_argument("--analyst")
    ap.add_argument("--out"); ap.add_argument("--check")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list:
        print()
        for k, (title, _) in sorted(TEMPLATES.items()):
            print(f"  {k:<10} {title}")
        print()
        return
    if not args.kind:
        ap.print_help(); sys.exit(1)
    if args.check:
        check(args.kind, args.check); return

    text = build(args.kind, args.case, args.target, args.exhibit, args.analyst)
    out = Path(args.out or f"report-{args.kind}-{args.case or 'draft'}.md")
    if out.exists():
        sys.exit(f" fail  {out} exists — not overwriting your draft")
    out.write_text(text, encoding="utf-8")
    print(f"  wrote {out}")
    print()
    print("  Fill it top to bottom, but write the executive summary LAST.")
    print("  And when you think it is done:")
    print(f"    ./report-scaffold.py {args.kind} --check {out}")
    print()


if __name__ == "__main__":
    main()
