#!/usr/bin/env python3
"""
risk-register.py — risk entries that get funded, and acceptances that survive.

"We have 312 findings" is a task list. "A single leaked CI credential gives an
attacker write access to production storage holding personal data of 40,000
citizens, and we would not detect the reads" is a risk statement. The second one
gets funded; the first gets filed.

This builds the second kind, refuses the colour-only version, and validates that
anything marked ACCEPT carries a named acceptor and a review date.

Usage
    ./risk-register.py --template register.csv
    ./risk-register.py new                      interactive, one entry
    ./risk-register.py register.csv             the report, prioritised
    ./risk-register.py register.csv --check     would this survive an audit?
    ./risk-register.py --explain                quantifying without pretending
"""

import argparse
import csv
import statistics
import sys
from datetime import date, datetime, timezone
from pathlib import Path

COLS = ["risk_id", "description", "assets", "threat_source", "vulnerability",
        "likelihood_per_year", "impact_low_eur", "impact_high_eur", "confidence_pct",
        "current_controls", "control_type", "treatment", "effort_days",
        "owner", "accepted_by", "accepted_date", "review_date", "linked_findings"]

TEMPLATE = """risk_id,description,assets,threat_source,vulnerability,likelihood_per_year,impact_low_eur,impact_high_eur,confidence_pct,current_controls,control_type,treatment,effort_days,owner,accepted_by,accepted_date,review_date,linked_findings
CLD-001,"A leaked CI/CD credential permits write access to production storage containing personal data, with no data-plane logging to detect reads","prod-data bucket (est. 40000 data subjects)","External actor with access to a public repository or build log","Long-lived static key; over-broad role; data-plane logging off",0.33,80000,600000,80,"gitleaks in CI",detective,mitigate,15,Head of Platform,,,,PROWLER-1042 PROWLER-1099
CLD-002,"Public access block disabled on a bucket serving a static site; no customer data present but the pattern normalises the exception","www-assets bucket","Opportunistic scanning",No account-level block,1.0,2000,15000,70,"quarterly content review",detective,accept,0,Head of Platform,CISO,YYYY-MM-DD,YYYY-MM-DD,PROWLER-0210
"""

EXPLAIN = """
  QUANTIFYING WITHOUT PRETENDING

  A risk score of "High" is a colour. It does not prioritise, because everything
  important is High and everything High gets the same attention, which is none.

  The minimum that genuinely works:

    HOW MANY      records, systems or users are affected      -> a magnitude
    HOW OFTEN     could this plausibly happen per year        -> a frequency
    WHAT WOULD    it cost: response, downtime, regulatory,     -> a RANGE
      IT COST     contractual, reputational
    HOW SURE      are you                                      -> a confidence

  Estimate as a range with a stated confidence. "Between EUR 40k and EUR 400k,
  80% confident" is defensible and useful. A single fabricated number is neither,
  and a colour is not an estimate at all.

  ANNUALISED LOSS EXPECTANCY

  likelihood per year x midpoint of the impact range. It is crude. It is also
  comparable across entries, which is the entire point — you are not trying to
  predict a loss, you are trying to rank twelve things honestly.

  RANK BY RISK REDUCTION PER UNIT OF EFFORT

  Not by raw score. The control that reduces three risks at once wins, even if
  none of them is the highest. This tool sorts by ALE per effort-day for exactly
  that reason.

  THE TWO FIELDS REGULATORS ASK FOR

  OWNER and ACCEPTED BY. A risk with no named acceptor has not been accepted, it
  has been ignored — and "the security team" is not a name. Neither is a review
  date of "annually".
"""


def num(v, default=0.0):
    try:
        return float(str(v).replace(",", "").replace("EUR", "").strip() or default)
    except ValueError:
        return default


def ale(r):
    lo, hi = num(r.get("impact_low_eur")), num(r.get("impact_high_eur"))
    return num(r.get("likelihood_per_year")) * ((lo + hi) / 2)


def eur(v):
    if v >= 1_000_000:
        return f"EUR {v/1_000_000:.1f}M"
    if v >= 1000:
        return f"EUR {v/1000:.0f}k"
    return f"EUR {v:.0f}"


def cmd_template(path):
    p = Path(path)
    if p.exists():
        sys.exit(f" fail  {p} exists")
    p.write_text(TEMPLATE)
    print(f"  wrote {p}")
    print()
    print("  Two worked entries. Replace them, and note what the second one does:")
    print("  it is an ACCEPT, and it carries a named acceptor and a review date.")
    print("  (The dates are placeholders — --check will reject them until you set")
    print("  real ones, which is the shortest lesson in what an acceptance needs.)")


def cmd_new():
    print()
    print("  One entry. Blank is allowed; wrong is not.")
    print()
    r = {}
    ask = lambda k, prompt, default="": input(f"  {prompt}: ").strip() or default  # noqa: E731
    r["risk_id"] = ask("risk_id", "Risk ID (e.g. CLD-004)")
    print()
    print("  The description is threat + vulnerability + asset + consequence, in")
    print("  one paragraph. Not a restatement of the finding.")
    r["description"] = ask("description", "Description")
    r["assets"] = ask("assets", "Assets affected, WITH SCALE (records, users, systems)")
    r["threat_source"] = ask("threat", "Threat source — who, with what capability")
    r["vulnerability"] = ask("vuln", "The specific weakness")
    print()
    r["likelihood_per_year"] = ask("likelihood", "Likelihood per year (0.1 = once a decade, 2 = twice a year)")
    print("  Impact as a RANGE. Response, downtime, regulatory, contractual, reputational.")
    r["impact_low_eur"] = ask("low", "  low (EUR)")
    r["impact_high_eur"] = ask("high", "  high (EUR)")
    r["confidence_pct"] = ask("conf", "  confidence in that range (%)", "80")
    print()
    r["current_controls"] = ask("controls", "Current controls")
    r["control_type"] = ask("type", "preventive / detective / corrective", "detective")
    r["treatment"] = ask("treatment", "mitigate / transfer / avoid / accept", "mitigate").lower()
    r["effort_days"] = ask("effort", "Effort estimate, in days", "5")
    r["owner"] = ask("owner", "Owner — a NAMED INDIVIDUAL, not a team")
    if r["treatment"].startswith("accept"):
        print()
        print("  You are accepting this. Write it as though a regulator will read it,")
        print("  because one might.")
        r["accepted_by"] = ask("acceptor", "  Accepted by (named individual)")
        r["accepted_date"] = ask("date", "  Date (YYYY-MM-DD)", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    else:
        r["accepted_by"] = r["accepted_date"] = ""
    r["review_date"] = ask("review", "Review date (YYYY-MM-DD — not 'annually')")
    r["linked_findings"] = ask("findings", "Linked scanner finding IDs")

    out = Path(f"risk-{r['risk_id'] or 'entry'}.csv")
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS)
        w.writeheader()
        w.writerow({k: r.get(k, "") for k in COLS})
    print()
    print(f"  wrote {out}")
    print(f"  ALE (likelihood x impact midpoint): {eur(ale(r))} per year")
    print()


def cmd_report(path):
    rows = list(csv.DictReader(open(path, newline="", encoding="utf-8")))
    if not rows:
        sys.exit(" fail  no rows")
    for r in rows:
        r["_ale"] = ale(r)
        r["_eff"] = max(num(r.get("effort_days"), 1), 0.5)
        r["_ratio"] = r["_ale"] / r["_eff"]

    print()
    print(f"  {len(rows)} risk(s)   total annualised exposure {eur(sum(r['_ale'] for r in rows))}")
    print()
    print("  BY RISK REDUCTION PER EFFORT-DAY")
    print("  (not by raw score — the control that reduces three risks wins)")
    print()
    print(f"  {'id':<10} {'ALE/yr':>10} {'days':>5} {'per day':>10}  {'treat':<9} owner")
    print("  " + "─" * 74)
    for r in sorted(rows, key=lambda x: -x["_ratio"]):
        print(f"  {r.get('risk_id','?')[:9]:<10} {eur(r['_ale']):>10} "
              f"{r['_eff']:>5.0f} {eur(r['_ratio']):>10}  "
              f"{r.get('treatment','')[:8]:<9} {r.get('owner','')[:24]}")
    print()

    accepted = [r for r in rows if r.get("treatment", "").lower().startswith("accept")]
    if accepted:
        print("  ACCEPTED")
        for r in accepted:
            who = r.get("accepted_by") or "(nobody named)"
            print(f"    {r.get('risk_id')}  {eur(r['_ale'])}/yr   accepted by {who}"
                  f"   review {r.get('review_date') or '(none)'}")
        print()

    for r in sorted(rows, key=lambda x: -x["_ale"])[:3]:
        print(f"  {r.get('risk_id')}  {eur(r['_ale'])}/yr  "
              f"(range {eur(num(r.get('impact_low_eur')))}–{eur(num(r.get('impact_high_eur')))}, "
              f"{r.get('confidence_pct','?')}% confident)")
        print(f"     {r.get('description','')[:110]}")
    print()


def cmd_check(path):
    rows = list(csv.DictReader(open(path, newline="", encoding="utf-8")))
    problems = 0
    print()
    for r in rows:
        rid = r.get("risk_id", "?")
        issues = []

        desc = r.get("description", "")
        if len(desc.split()) < 12:
            issues.append("description is too short to be a risk statement — "
                          "threat + vulnerability + asset + consequence")
        if not r.get("assets"):
            issues.append("no assets named")
        if not any(ch.isdigit() for ch in r.get("assets", "")):
            issues.append("assets have no scale — how many records, users, systems?")
        if num(r.get("likelihood_per_year")) <= 0:
            issues.append("no likelihood")
        lo, hi = num(r.get("impact_low_eur")), num(r.get("impact_high_eur"))
        if lo <= 0 or hi <= 0:
            issues.append("impact is not quantified — a colour is not an estimate")
        elif hi == lo:
            issues.append("impact is a single number, not a range — "
                          "a single fabricated number is less honest than a wide range")
        if not r.get("confidence_pct"):
            issues.append("no confidence stated for the range")
        if not r.get("owner"):
            issues.append("no owner")
        elif any(w in r["owner"].lower() for w in ("team", "security", "it dept", "everyone")):
            issues.append(f"owner '{r['owner']}' is not a person")
        if not r.get("control_type"):
            issues.append("controls not labelled preventive / detective / corrective")

        if r.get("treatment", "").lower().startswith("accept"):
            if not r.get("accepted_by"):
                issues.append("ACCEPTED with no named acceptor — "
                              "that is not acceptance, it is being ignored")
            for f in ("accepted_date", "review_date"):
                v = r.get(f, "")
                if not v:
                    issues.append(f"ACCEPTED with no {f}")
                else:
                    try:
                        d = date.fromisoformat(v)
                        if f == "review_date" and d < date.today():
                            issues.append(f"review_date {v} has passed — "
                                          "an acceptance without a live review date has lapsed")
                    except ValueError:
                        issues.append(f"{f} '{v}' is not a date")
        if not r.get("review_date"):
            issues.append("no review date")
        if not r.get("linked_findings"):
            issues.append("not linked to any finding — the register and the scan drift apart")

        if issues:
            print(f"  {rid}")
            for i in issues:
                print(f"    ! {i}")
            problems += len(issues)
        else:
            print(f"  {rid}  complete")
    print()
    if problems:
        print(f"  {problems} issue(s).")
        print()
        print("  The two fields regulators ask for are OWNER and ACCEPTED BY. A risk")
        print("  with no named acceptor has not been accepted; it has been ignored.")
        print("  And 'annually' is not a review date.")
        print()
        sys.exit(1)
    print("  Every entry is complete, quantified, owned and linked.")
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csvfile", nargs="?")
    ap.add_argument("--template", nargs="?", const="register.csv")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--explain", action="store_true")
    a = ap.parse_args()

    if a.explain:
        print(EXPLAIN); return
    if a.template:
        cmd_template(a.template); return
    if a.csvfile == "new":
        try:
            cmd_new()
        except (KeyboardInterrupt, EOFError):
            print("\n  cancelled\n")
        return
    if not a.csvfile:
        ap.print_help(); sys.exit(1)
    if not Path(a.csvfile).is_file():
        sys.exit(f" fail  no such file: {a.csvfile}")
    (cmd_check if a.check else cmd_report)(a.csvfile)


if __name__ == "__main__":
    main()
