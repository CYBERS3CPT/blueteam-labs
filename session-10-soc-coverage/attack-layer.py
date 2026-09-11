#!/usr/bin/env python3
"""
attack-layer.py — turn your detection rules into an ATT&CK Navigator layer.

Coverage maps are usually wrong in the optimistic direction, and an optimistic
map is worse than no map, because it directs resources away from the real gaps.
So this tool is opinionated: it refuses to produce a layer where everything is
scored 3, and it makes you write down which data source each rule depends on —
because you cannot detect a technique whose telemetry you do not collect.

Usage
    ./attack-layer.py --template rules.csv        start here
    ./attack-layer.py rules.csv                   build coverage.json
    ./attack-layer.py rules.csv --name "Q4 coverage" --out q4.json
    ./attack-layer.py rules.csv --gaps            what is uncovered, ranked
    ./attack-layer.py rules.csv --report          a summary you can show someone

Import the JSON at mitre-attack.github.io/attack-navigator (Open Existing Layer).

CSV columns
    technique   T1059.001         required — sub-techniques welcome
    rule        the rule name     required — so the cell says WHICH rule covers it
    score       0..3              0 none, 1 partial, 2 good, 3 strong
    source      data source       required above score 0
    session     where it came from (optional, nice in the comment)
    notes       anything          optional
"""

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

SCORE_MEANING = {
    0: "no coverage",
    1: "partial — detects one variant, or one tool, or only with luck",
    2: "good — detects the common implementations",
    3: "strong — behavioural, hard to evade without changing the technique",
}

# Navigator wants a colour ramp. Low coverage should look like a problem.
GRADIENT = {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 3}

TEMPLATE = """technique,rule,score,source,session,notes
T1071.001,BLUETEAM C2 domain lookup (Suricata),2,dns query logs,1,written in session 1
T1059.001,Encoded PowerShell (Sigma),2,process creation 4688 / sysmon 1,8,
T1547.001,Run key persistence (Sigma),1,registry sysmon 12/13,8,only HKCU covered
T1566.001,Office spawns shell (Sigma),3,process creation with parent,8,
T1021.001,RDP logon type 10,1,security 4624,8,no alerting on it yet
T1105,Training sample downloader (YARA),1,file write + EDR,4,file-based only
T1595,Honeypot touch,3,honeypot connection log,2,zero false positives by design
"""


def die(msg):
    print(f" fail  {msg}", file=sys.stderr)
    sys.exit(1)


def load(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as fh:
        for i, row in enumerate(csv.DictReader(fh), start=2):
            tid = (row.get("technique") or "").strip().upper()
            if not tid:
                continue
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", tid):
                die(f"line {i}: '{tid}' is not a technique ID (expected T1059 or T1059.001)")
            try:
                score = int(row.get("score") or 0)
            except ValueError:
                die(f"line {i}: score '{row.get('score')}' is not a number 0-3")
            if not 0 <= score <= 3:
                die(f"line {i}: score {score} out of range 0-3")
            rule = (row.get("rule") or "").strip()
            if not rule:
                die(f"line {i}: every row needs a rule name — the cell must say what covers it")
            source = (row.get("source") or "").strip()
            if score > 0 and not source:
                die(f"line {i}: '{rule}' is scored {score} with no data source.\n"
                    f"       You cannot detect a technique whose telemetry you do not collect.\n"
                    f"       Name the source, or score it 0.")
            rows.append({"technique": tid, "rule": rule, "score": score,
                         "source": source, "session": (row.get("session") or "").strip(),
                         "notes": (row.get("notes") or "").strip()})
    if not rows:
        die("no usable rows")
    return rows


def build(rows, name, description):
    by_tech = defaultdict(list)
    for r in rows:
        by_tech[r["technique"]].append(r)

    techniques = []
    for tid, entries in sorted(by_tech.items()):
        # Several rules on one technique: take the best, but say so, because
        # "three partial rules" is not the same as "one strong rule".
        best = max(e["score"] for e in entries)
        lines = []
        for e in sorted(entries, key=lambda x: -x["score"]):
            bit = f"[{e['score']}] {e['rule']}"
            if e["source"]:
                bit += f"  (source: {e['source']})"
            if e["session"]:
                bit += f"  [session {e['session']}]"
            if e["notes"]:
                bit += f"\n      {e['notes']}"
            lines.append(bit)
        if len(entries) > 1:
            lines.append(f"-- scored {best}: the best single rule, not the sum. "
                         f"{len(entries)} partial rules are still partial.")
        techniques.append({
            "techniqueID": tid,
            "score": best,
            "comment": "\n".join(lines),
            "enabled": True,
            "showSubtechniques": "." in tid,
        })

    return {
        "name": name,
        "versions": {"attack": "15", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description,
        "filters": {"platforms": ["Windows", "Linux", "macOS", "Network", "Containers"]},
        "sorting": 3,
        "layout": {"layout": "side", "showName": True, "showID": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": GRADIENT,
        "legendItems": [{"label": f"{k} — {v}", "color": col}
                        for (k, v), col in zip(SCORE_MEANING.items(),
                                               ["#ff6666", "#ffb266", "#ffe766", "#8ec843"])],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "metadata": [
            {"name": "generated", "value": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
            {"name": "rules", "value": str(len(rows))},
            {"name": "techniques", "value": str(len(by_tech))},
        ],
    }


def honesty_check(rows):
    """Coverage maps are wrong in the optimistic direction. Say so, loudly."""
    scores = Counter(r["score"] for r in rows)
    problems = []
    threes = scores[3]
    if threes and threes / len(rows) > 0.4:
        problems.append(
            f"{threes} of {len(rows)} rules are scored 3 ({threes*100//len(rows)}%).\n"
            "       A layer where most cells are 'strong' is not credible. Score 3 means\n"
            "       behavioural and hard to evade without changing the technique itself.\n"
            "       Most rules detect one implementation. That is a 1.")
    if scores[1] == 0 and len(rows) > 4:
        problems.append(
            "Nothing is scored 1 (partial).\n"
            "       Every real detection estate has partial coverage. A layer with none\n"
            "       suggests the scoring was aspirational rather than measured.")
    no_source = [r for r in rows if r["score"] > 0 and not r["source"]]
    if no_source:
        problems.append(f"{len(no_source)} scored rule(s) with no data source named.")
    return problems


def report(rows):
    by_tech = defaultdict(list)
    for r in rows:
        by_tech[r["technique"]].append(r)
    scores = Counter(max(e["score"] for e in v) for v in by_tech.values())
    sources = Counter(r["source"] for r in rows if r["source"])

    print()
    print(f"  {len(rows)} rule(s) across {len(by_tech)} technique(s)")
    print()
    for s in (3, 2, 1, 0):
        n = scores[s]
        bar = "█" * min(30, n * 2)
        print(f"    {s}  {SCORE_MEANING[s][:38]:<40} {n:>3}  {bar}")
    print()
    print("  Data sources you depend on — if one of these goes quiet, so does the coverage:")
    for src, n in sources.most_common(10):
        print(f"    {n:>3}  {src}")
    print()
    print("  Single points of failure (one rule = one source):")
    singles = [s for s, n in sources.items() if n == 1]
    for s in singles[:8]:
        print(f"    - {s}")
    if not singles:
        print("    none")
    print()
    problems = honesty_check(rows)
    if problems:
        print("  Honesty check:")
        for p in problems:
            print(f"    ! {p}")
        print()


def gaps(rows):
    """The point is not 'what is uncovered' — that is most of ATT&CK. It is which
    gaps sit next to something you already collect."""
    covered = {r["technique"].split(".")[0] for r in rows if r["score"] > 0}
    sources = {r["source"] for r in rows if r["source"]}
    print()
    print(f"  You have coverage on {len(covered)} base technique(s).")
    print()
    print("  The useful question is not 'what is uncovered' — that is most of ATT&CK.")
    print("  It is: which gaps could be closed with telemetry you ALREADY collect?")
    print()
    print("  Your current sources:")
    for s in sorted(sources):
        print(f"    - {s}")
    print()
    print("  For each candidate gap, weigh:")
    print("    threat relevance   does the actor targeting this sector use it?")
    print("    kill chain position early detection is worth more than late")
    print("    blast radius       what does the technique enable next?")
    print("    feasibility        do you already have the source, or is it a two-year project?")
    print("    reuse              does this detection also cover neighbouring techniques?")
    print()
    print("  A gap that is expensive to close and rarely exploited is a documented")
    print("  accepted risk, not a remediation item. Write it down as such, with")
    print("  who accepted it.")
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csvfile", nargs="?")
    ap.add_argument("--template", nargs="?", const="rules.csv")
    ap.add_argument("--name", default="Blue Team detection coverage")
    ap.add_argument("--out", default="coverage.json")
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--gaps", action="store_true")
    ap.add_argument("--force", action="store_true", help="build anyway despite the honesty check")
    args = ap.parse_args()

    if args.template:
        p = Path(args.template)
        if p.exists():
            die(f"{p} already exists")
        p.write_text(TEMPLATE)
        print(f"  wrote {p}")
        print("  Replace the examples with YOUR rules. Score honestly — a rule that")
        print("  detects one variant of a technique is a 1, not a 3.")
        return

    if not args.csvfile:
        ap.print_help()
        sys.exit(1)
    if not Path(args.csvfile).is_file():
        die(f"no such file: {args.csvfile}")

    rows = load(args.csvfile)

    if args.report:
        report(rows); return
    if args.gaps:
        gaps(rows); return

    problems = honesty_check(rows)
    if problems and not args.force:
        print()
        print("  Honesty check failed:")
        for p in problems:
            print(f"    ! {p}")
        print()
        print("  Re-score, or re-run with --force if you genuinely mean it.")
        print("  (You will be asked to defend this layer. Better now than then.)")
        print()
        sys.exit(2)

    desc = (f"Generated from {Path(args.csvfile).name} — {len(rows)} rules. "
            "Scores: 0 none, 1 partial, 2 good, 3 strong. Each cell comment names "
            "the rule and the data source it depends on.")
    layer = build(rows, args.name, desc)
    Path(args.out).write_text(json.dumps(layer, indent=2))

    print()
    print(f"  {len(rows)} rule(s) -> {len(layer['techniques'])} technique(s)")
    print(f"  wrote {args.out}")
    print()
    print("  Import at mitre-attack.github.io/attack-navigator  ->  Open Existing Layer")
    print()
    if problems:
        print("  (built with --force; the honesty check had opinions)")
        print()


if __name__ == "__main__":
    main()
