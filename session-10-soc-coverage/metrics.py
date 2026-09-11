#!/usr/bin/env python3
"""
metrics.py — SOC metrics that reflect reality, and refusal to print the ones
that corrupt behaviour on their own.

Goodhart's Law arrives in any SOC within one quarter: when a measure becomes a
target it stops being a good measure. The mitigation is not to avoid efficiency
metrics — it is to never report one without its quality pair. This tool enforces
the pairing.

Usage
    ./metrics.py --template alerts.csv        start here
    ./metrics.py alerts.csv                   the report
    ./metrics.py alerts.csv --period 2024-Q4 --out metrics.txt
    ./metrics.py --explain                    what each number means and misleads about

CSV columns (extra columns are ignored)
    alert_id         anything unique
    rule             the rule that fired
    received_utc     ISO 8601
    adversary_utc    when the ADVERSARY acted, if known — this is the one that matters
    triaged_utc      when a human made a decision
    escalated        yes/no
    incident         yes/no        did it turn out to be one
    contained_utc    when containment was decided
    resolved_utc     when it was closed
    reopened         yes/no
    analyst          who
"""

import argparse
import csv
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

TEMPLATE = """alert_id,rule,received_utc,adversary_utc,triaged_utc,escalated,incident,contained_utc,resolved_utc,reopened,analyst
A-001,Encoded PowerShell,2024-10-01T09:12:00Z,2024-10-01T08:47:00Z,2024-10-01T09:31:00Z,yes,yes,2024-10-01T10:05:00Z,2024-10-02T14:00:00Z,no,ana
A-002,Impossible travel,2024-10-01T11:02:00Z,,2024-10-01T11:40:00Z,no,no,,2024-10-01T11:42:00Z,no,bruno
A-003,Encoded PowerShell,2024-10-02T03:20:00Z,,2024-10-02T08:15:00Z,no,no,,2024-10-02T08:16:00Z,yes,ana
A-004,Public bucket,2024-10-03T15:00:00Z,2024-10-03T14:55:00Z,2024-10-03T15:08:00Z,yes,yes,2024-10-03T15:30:00Z,2024-10-04T09:00:00Z,no,bruno
"""

EXPLAIN = """
  MTTD — mean time to detect
    Measured from ADVERSARY ACTION, not from the alert. Measured from the alert
    it tells you how fast you responded to yourself, which is a number that only
    ever improves and never means anything.
    If adversary_utc is empty for most rows, this tool says so rather than
    quietly computing the flattering version.

  MTTR — mean time to respond
    Define which: respond, or recover? They differ by hours or by days. Pick one
    and stay with it, because a series that silently changed definition is worse
    than no series.

  DWELL TIME
    Adversary action to containment. The number a board understands and a
    regulator asks for. Also the one that exposes a detection gap most clearly.

  ALERT-TO-INCIDENT RATIO
    Detection quality. A very low ratio means noise; a very high one means you
    are probably not alerting on enough.

  FALSE POSITIVES PER RULE
    Where tuning effort should go. Act on the top five monthly and you will do
    more for SOC quality than any tool purchase.

  ESCALATION ACCURACY
    Of what L1 escalated, how much was a real incident. Low means L1 is
    escalating defensively; very high means they are probably closing things
    they should not.

  REOPEN RATE
    The quality pair for anything about speed. Closing fast and reopening often
    is not efficiency, it is rework with better optics.

  THE METRICS THAT CORRUPT BEHAVIOUR
    Tickets closed per hour  -> closing without investigating
    Alerts processed         -> preferring the noisy, easy alerts
    Detections deployed      -> shipping untuned rules to hit a target
    SIEM uptime              -> optimising the tool rather than the outcome

    This tool prints none of them alone. Where it prints a throughput figure it
    prints its quality pair beside it, because the pair is the honest unit.
"""


def parse(ts):
    if not ts or not ts.strip():
        return None
    s = ts.strip().replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def hours(a, b):
    if not a or not b:
        return None
    return (b - a).total_seconds() / 3600


def fmt(h):
    if h is None:
        return "—"
    if h < 1:
        return f"{h*60:.0f} min"
    if h < 48:
        return f"{h:.1f} h"
    return f"{h/24:.1f} d"


def stat_line(label, values, note=""):
    if not values:
        print(f"  {label:<34} {'no data':>10}   {note}")
        return
    med = statistics.median(values)
    mean = statistics.fmean(values)
    print(f"  {label:<34} {fmt(med):>10}   median   (mean {fmt(mean)}, n={len(values)})")
    if note:
        print(f"  {'':34} {note}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csvfile", nargs="?")
    ap.add_argument("--template", nargs="?", const="alerts.csv")
    ap.add_argument("--period", default="")
    ap.add_argument("--explain", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()

    if args.explain:
        print(EXPLAIN); return
    if args.template:
        p = Path(args.template)
        if p.exists():
            sys.exit(f" fail  {p} exists")
        p.write_text(TEMPLATE)
        print(f"  wrote {p}")
        print("  Export your own from the case system into these columns. The one that")
        print("  matters and is usually absent is adversary_utc — without it, MTTD is")
        print("  a measure of how fast you answered yourself.")
        return
    if not args.csvfile:
        ap.print_help(); sys.exit(1)
    if not Path(args.csvfile).is_file():
        sys.exit(f" fail  no such file: {args.csvfile}")

    with open(args.csvfile, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        sys.exit(" fail  no rows")

    yes = lambda r, k: str(r.get(k, "")).strip().lower() in ("yes", "y", "true", "1")  # noqa: E731

    mttd_true, mttd_alert, mttr, dwell = [], [], [], []
    for r in rows:
        recv = parse(r.get("received_utc"))
        adv = parse(r.get("adversary_utc"))
        tri = parse(r.get("triaged_utc"))
        con = parse(r.get("contained_utc"))
        res = parse(r.get("resolved_utc"))
        if adv and recv:
            mttd_true.append(hours(adv, recv))
        if recv and tri:
            mttd_alert.append(hours(recv, tri))
        if recv and res:
            mttr.append(hours(recv, res))
        if adv and con:
            dwell.append(hours(adv, con))

    incidents = [r for r in rows if yes(r, "incident")]
    escalated = [r for r in rows if yes(r, "escalated")]
    reopened = [r for r in rows if yes(r, "reopened")]
    esc_correct = [r for r in escalated if yes(r, "incident")]
    missed = [r for r in incidents if not yes(r, "escalated")]

    out = []
    def p(s=""):
        out.append(s); print(s)

    p()
    p(f"  SOC metrics{'  ·  ' + args.period if args.period else ''}")
    p(f"  {len(rows)} alert(s) · {len(incidents)} incident(s)")
    p("  " + "─" * 72)
    p()
    p("  DETECTION")
    stat_line("MTTD from adversary action", mttd_true)
    if not mttd_true:
        p("  " + " " * 34 + "  adversary_utc is empty on every row.")
        p("  " + " " * 34 + "  This is THE metric, and you cannot compute it.")
        p("  " + " " * 34 + "  Start recording it: the incident timeline already")
        p("  " + " " * 34 + "  contains it, it is just never copied into the case.")
    stat_line("MTTD from alert (the flattering one)", mttd_alert,
              "measures how fast you answered yourself")
    p()

    p("  RESPONSE")
    stat_line("MTTR (received -> resolved)", mttr)
    stat_line("Dwell time (adversary -> contained)", dwell)
    p()

    p("  QUALITY  — each of these is the pair for a throughput number above")
    ratio = (len(incidents) / len(rows) * 100) if rows else 0
    p(f"  {'Alert-to-incident ratio':<34} {ratio:>9.1f}%")
    if ratio < 2:
        p("  " + " " * 34 + "  under 2%: the estate is noisy. Tune before you hire.")
    elif ratio > 40:
        p("  " + " " * 34 + "  over 40%: high. Are you alerting on enough?")
    if escalated:
        acc = len(esc_correct) / len(escalated) * 100
        p(f"  {'Escalation accuracy':<34} {acc:>9.1f}%   ({len(esc_correct)}/{len(escalated)})")
        if acc < 40:
            p("  " + " " * 34 + "  L1 is escalating defensively. Usually a playbook gap,")
            p("  " + " " * 34 + "  or no authority to close anything.")
    if missed:
        p(f"  {'Incidents NOT escalated':<34} {len(missed):>9}   <- read these individually")
    reopen_rate = (len(reopened) / len(rows) * 100) if rows else 0
    p(f"  {'Reopen rate':<34} {reopen_rate:>9.1f}%")
    if reopen_rate > 10:
        p("  " + " " * 34 + "  closing fast and reopening often is rework, not speed")
    p()

    by_rule = Counter(r.get("rule", "?") for r in rows)
    fp_by_rule = Counter(r.get("rule", "?") for r in rows if not yes(r, "incident"))
    p("  TUNING  — the top five here, monthly, beats any tool purchase")
    p(f"  {'rule':<40} {'alerts':>7} {'false pos':>10} {'FP rate':>8}")
    for rule, n in by_rule.most_common(8):
        fp = fp_by_rule[rule]
        p(f"  {rule[:39]:<40} {n:>7} {fp:>10} {fp/n*100:>7.0f}%")
    noisy = [r for r, n in by_rule.items() if n >= 3 and fp_by_rule[r] == n]
    if noisy:
        p()
        p("  Rules that have never once produced an incident:")
        for r in noisy[:5]:
            p(f"    - {r}  ({by_rule[r]} alerts)")
        p("  Tune them or retire them. A rule nobody acts on trains people not to act.")
    p()

    per_analyst = defaultdict(lambda: [0, 0])
    for r in rows:
        a = r.get("analyst", "?") or "?"
        per_analyst[a][0] += 1
        if yes(r, "reopened"):
            per_analyst[a][1] += 1
    if len(per_analyst) > 1:
        p("  BY ANALYST  — volume WITH its quality pair, never volume alone")
        p(f"  {'analyst':<20} {'handled':>8} {'reopened':>10}")
        for a, (n, ro) in sorted(per_analyst.items(), key=lambda x: -x[1][0]):
            p(f"  {a[:19]:<20} {n:>8} {ro:>10}")
        p()
        p("  Do not rank people on the first column. Someone handling twice as many")
        p("  alerts is either very good or not investigating, and only the second")
        p("  column tells you which.")
        p()

    p("  " + "─" * 72)
    p("  ./metrics.py --explain   for what each number misleads about")
    p()

    if args.out:
        Path(args.out).write_text("\n".join(out), encoding="utf-8")
        print(f"  wrote {args.out}")


if __name__ == "__main__":
    main()
