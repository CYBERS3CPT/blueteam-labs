#!/usr/bin/env python3
"""
profile-score.py — the fake profile rubric, as something you can defend.

A score without a published rubric is an opinion with a number attached. This
prints the rubric, takes your per-indicator scores, applies the dormancy
adjustment, and produces a scored sheet you can put in an appendix.

Usage
    ./profile-score.py                    interactive, one profile
    ./profile-score.py --rubric           print the rubric and exit
    ./profile-score.py --batch sheet.csv  score several from a CSV
    ./profile-score.py --template         write a CSV template

The number is the least interesting output. The evidence column is the finding.
"""

import argparse
import csv
import sys
from pathlib import Path

RUBRIC = [
    ("age_vs_volume",   3, "Account age vs activity volume",
     "Created recently with hundreds of posts — or dormant for years, then suddenly active."),
    ("generated_face",  3, "Generated-face artefacts",
     "Fixed eye position, warped background, asymmetric accessories, teeth and ears."),
    ("reverse_image",   3, "Reverse-searchable imagery",
     "Stock photo, or a real person's photograph used elsewhere."),
    ("follow_ratio",    2, "Follower / following ratio",
     "Following thousands, followed by dozens."),
    ("engagement",      2, "Engagement pattern",
     "Posts with no replies; replies only from similar accounts."),
    ("bio_template",    2, "Bio template reuse",
     "Identical phrasing across 'different' people."),
    ("register",        2, "Linguistic register mismatch",
     "Claimed nationality vs idiom; machine-translation artefacts."),
    ("network",         2, "Network composition",
     "Connected almost exclusively to other suspicious accounts."),
    ("originality",     1, "Content originality",
     "Only reshares, never original material."),
]
MAX = sum(w for _, w, _, _ in RUBRIC)

BANDS = [
    (0,  4,  "No indication of inauthenticity"),
    (5,  9,  "Some indicators; insufficient for a conclusion. Collect more, or report as inconclusive"),
    (10, 14, "Probable synthetic or misrepresented account"),
    (15, MAX, "Strong indication of inauthenticity"),
]

# Dormancy is not inauthenticity. A real person with an abandoned account scores
# on indicators 1 and 5 for entirely innocent reasons, and the rubric has to say
# so out loud or it will manufacture findings.
DORMANCY_DISCOUNT = ("age_vs_volume", "engagement")


def band(total):
    for lo, hi, text in BANDS:
        if lo <= total <= hi:
            return text
    return "out of range"


def print_rubric():
    print(f"\n  Fake profile rubric — maximum {MAX} points\n")
    for key, w, name, look in RUBRIC:
        print(f"  [{w}]  {name}")
        print(f"       {look}")
        print(f"       key: {key}\n")
    print("  Interpretation")
    for lo, hi, text in BANDS:
        print(f"    {lo:>2}-{hi:<3} {text}")
    print(f"\n  Adjustment: if the account is merely dormant, discount "
          f"{' and '.join(DORMANCY_DISCOUNT)}.")
    print("  Dormant is not fake. Say so in the write-up rather than quietly not scoring it.\n")


def score_one(values, dormant=False, handle="", notes=None):
    notes = notes or {}
    rows, total = [], 0
    for key, w, name, _ in RUBRIC:
        raw = int(values.get(key, 0) or 0)
        raw = max(0, min(w, raw))
        applied = 0 if (dormant and key in DORMANCY_DISCOUNT) else raw
        total += applied
        rows.append({"indicator": name, "key": key, "weight": w,
                     "score": raw, "applied": applied,
                     "discounted": dormant and key in DORMANCY_DISCOUNT,
                     "evidence": notes.get(key, "")})
    return {"handle": handle, "dormant": dormant, "total": total,
            "max": MAX, "assessment": band(total), "rows": rows}


def render(result):
    print()
    print(f"  Profile: {result['handle'] or '(unnamed)'}")
    print("  " + "─" * 70)
    print(f"  {'indicator':<38}{'w':>3}{'score':>7}{'applied':>9}")
    print("  " + "─" * 70)
    for r in result["rows"]:
        flag = "  (discounted: dormant)" if r["discounted"] else ""
        print(f"  {r['indicator'][:37]:<38}{r['weight']:>3}{r['score']:>7}{r['applied']:>9}{flag}")
        if r["evidence"]:
            print(f"      evidence: {r['evidence']}")
    print("  " + "─" * 70)
    print(f"  {'TOTAL':<38}{result['max']:>3}{'':>7}{result['total']:>9}")
    print()
    print(f"  Assessment: {result['assessment']}")
    if result["dormant"]:
        print("  Dormancy adjustment applied.")
    print()
    missing = [r["indicator"] for r in result["rows"] if r["applied"] > 0 and not r["evidence"]]
    if missing:
        print("  Scored without evidence — fix before this goes in a report:")
        for m in missing:
            print(f"    - {m}")
        print()


def interactive():
    print_rubric()
    handle = input("  Profile handle or reference: ").strip()
    dormant = input("  Is the account merely dormant rather than suspicious? [y/N] ").strip().lower().startswith("y")
    values, notes = {}, {}
    print("\n  Score each 0..weight. Evidence is not optional; leave it blank and the\n"
          "  tool will tell you which rows are indefensible.\n")
    for key, w, name, look in RUBRIC:
        print(f"  {name}  (0-{w})")
        print(f"    {look}")
        while True:
            try:
                v = input(f"    score [0-{w}]: ").strip() or "0"
                v = int(v)
                if 0 <= v <= w:
                    break
            except ValueError:
                pass
            print(f"    a number between 0 and {w}, please")
        values[key] = v
        if v > 0:
            notes[key] = input("    evidence (URL, observation, capture time): ").strip()
        print()
    render(score_one(values, dormant, handle, notes))


def template(path="profiles.csv"):
    cols = ["handle", "dormant"] + [k for k, _, _, _ in RUBRIC] + [f"{k}_evidence" for k, _, _, _ in RUBRIC]
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerow({"handle": "example_account", "dormant": "no",
                    **{k: 0 for k, _, _, _ in RUBRIC}})
    print(f"  wrote {path} — one row per profile, weights are in --rubric")


def batch(path):
    with open(path, newline="") as fh:
        rows = list(csv.DictReader(fh))
    results = []
    for row in rows:
        dormant = str(row.get("dormant", "")).strip().lower() in ("y", "yes", "true", "1")
        values = {k: row.get(k, 0) for k, _, _, _ in RUBRIC}
        notes = {k: row.get(f"{k}_evidence", "") for k, _, _, _ in RUBRIC}
        r = score_one(values, dormant, row.get("handle", ""), notes)
        results.append(r)
        render(r)
    print("  " + "─" * 70)
    print(f"  {len(results)} profile(s) scored")
    for r in sorted(results, key=lambda x: -x["total"]):
        print(f"    {r['total']:>3}/{MAX}  {r['handle'][:30]:<30}  {r['assessment'][:40]}")
    print()
    print("  Now defend the ones you disagree about. Where two analysts scored the")
    print("  same profile differently, one of them assumed something the evidence")
    print("  did not say — and that assumption is what the rubric exists to surface.")
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rubric", action="store_true")
    ap.add_argument("--template", nargs="?", const="profiles.csv")
    ap.add_argument("--batch")
    args = ap.parse_args()

    if args.rubric:
        print_rubric()
    elif args.template:
        template(args.template)
    elif args.batch:
        batch(args.batch)
    else:
        try:
            interactive()
        except (KeyboardInterrupt, EOFError):
            print("\n  cancelled\n")
            sys.exit(130)


if __name__ == "__main__":
    main()
