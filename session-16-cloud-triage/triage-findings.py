#!/usr/bin/env python3
"""
triage-findings.py — turn 300 scanner findings into an ordered list somebody
will actually work through.

Your first scan of a real account returns several hundred findings. This is the
moment most cloud security programmes fail, and they fail in four predictable
ways: fixing from the top of the list (which is ordered by the tool's opinion),
fixing everything (you will not finish), ignoring it (it becomes wallpaper), or
emailing the CSV to the platform team (it gets closed as "known").

The triage that works has four tiers, in this order:

    1. EXPOSURE       reachable from the internet, or granting access outside
    2. IDENTITY       can escalate privilege, or grant permissions
    3. DETECTABILITY  logging gaps, which make everything else invisible
    4. HYGIENE        the benchmark tail

Usage
    ./triage-findings.py prowler-out.json              Prowler OCSF or native JSON
    ./triage-findings.py scoutsuite.json --format scout
    ./triage-findings.py findings.csv --format csv
    ./triage-findings.py prowler.json --tier 1         just the ones that matter today
    ./triage-findings.py prowler.json --out triaged.csv
    ./triage-findings.py prowler.json --suppress suppressions.yml

Suppression file (YAML-ish, one entry per block; no parser needed):

    - check: s3_bucket_public_access
      resource: public-website-assets
      reason: deliberate static site; no customer data; reviewed quarterly
      who: S. Silva
      until: YYYY-MM-DD      # a real date. No date, no suppression.
"""

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import date, datetime
from pathlib import Path

TIERS = {
    1: ("EXPOSURE",      "reachable from the internet, or granting access outside the organisation"),
    2: ("IDENTITY",      "can escalate privilege, or grant permissions"),
    3: ("DETECTABILITY", "logging gaps — they make everything else invisible"),
    4: ("HYGIENE",       "the benchmark tail; real, but it is not why you are here"),
}

# Ordered: first match wins, so exposure beats identity beats logging.
RULES = [
    (1, r"public|anonymous|0\.0\.0\.0/0|::/0|world.read|internet.facing|unauthenticated|"
        r"allusers|authenticatedusers|cross.account|external.account|shared.with|"
        r"publicly.accessible|open.to.the.world|exposed"),
    (2, r"\biam\b|privilege|assume.?role|passrole|admin|policy.version|attach.*policy|"
        r"wildcard.*action|\*.*action|root.account|mfa|access.key|credential|"
        r"service.account|trust.polic|permission.boundar|escalat|"
        # IMDSv1 is a credential-theft path, not a hygiene item: an SSRF in any
        # application on the instance hands over the instance role.
        r"imdsv1|imds|metadata.*(v1|token)|instance.profile"),
    (3, r"log|trail|audit|monitor|alarm|flow.?log|guardduty|securityhub|config.record|"
        r"detection|event|retention|insight"),
]


def tier_of(text):
    t = text.lower()
    for tier, pattern in RULES:
        if re.search(pattern, t):
            return tier
    return 4


# ── loaders ─────────────────────────────────────────────────────────────────
def load_prowler(path):
    """Prowler writes OCSF JSON, an array of native objects, or JSON-lines."""
    raw = Path(path).read_text()
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = data.get("findings", [data])
    except json.JSONDecodeError:
        data = [json.loads(line) for line in raw.splitlines() if line.strip()]

    out = []
    for f in data:
        # OCSF shape
        if "finding_info" in f or "status_code" in f:
            status = (f.get("status_code") or f.get("status") or "").upper()
            if status in ("PASS", "SKIPPED", "MUTED"):
                continue
            meta = f.get("finding_info", {})
            res = f.get("resources") or [{}]
            out.append({
                "check": meta.get("uid") or f.get("metadata", {}).get("event_code", "") or "?",
                "title": meta.get("title") or f.get("message", ""),
                "severity": (f.get("severity") or "unknown").lower(),
                "resource": (res[0].get("uid") or res[0].get("name") or ""),
                "region": (f.get("cloud", {}).get("region") or ""),
                "service": (res[0].get("group", {}) or {}).get("name", "") or f.get("cloud", {}).get("provider", ""),
                "detail": f.get("risk_details") or meta.get("desc", ""),
            })
        else:  # older / native
            status = (f.get("Status") or f.get("status") or "").upper()
            if status in ("PASS", "INFO", "MANUAL"):
                continue
            out.append({
                "check": f.get("CheckID") or f.get("check_id", "?"),
                "title": f.get("CheckTitle") or f.get("check_title", ""),
                "severity": (f.get("Severity") or f.get("severity") or "unknown").lower(),
                "resource": f.get("ResourceId") or f.get("resource_id", ""),
                "region": f.get("Region") or f.get("region", ""),
                "service": f.get("ServiceName") or f.get("service_name", ""),
                "detail": f.get("Risk") or f.get("risk", ""),
            })
    return out


def load_scout(path):
    """ScoutSuite's JS wrapper: strip the assignment, keep the JSON."""
    raw = Path(path).read_text()
    raw = re.sub(r"^\s*scoutsuite_results\s*=\s*", "", raw).strip().rstrip(";")
    data = json.loads(raw)
    out = []
    for svc, body in (data.get("services") or {}).items():
        for fid, f in (body.get("findings") or {}).items():
            n = f.get("flagged_items", 0)
            if not n:
                continue
            out.append({
                "check": fid,
                "title": f.get("description", fid),
                "severity": (f.get("level") or "unknown").lower(),
                "resource": f"{n} item(s)",
                "region": "",
                "service": svc,
                "detail": f.get("rationale", ""),
            })
    return out


def load_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    low = lambda r, *names: next((r[k] for k in r if k.lower() in names and r[k]), "")  # noqa: E731
    return [{
        "check": low(r, "check", "check_id", "checkid", "rule", "id") or "?",
        "title": low(r, "title", "check_title", "description", "finding") or "",
        "severity": (low(r, "severity", "level", "risk") or "unknown").lower(),
        "resource": low(r, "resource", "resource_id", "resourceid", "arn") or "",
        "region": low(r, "region") or "",
        "service": low(r, "service", "service_name") or "",
        "detail": low(r, "detail", "risk", "rationale") or "",
    } for r in rows]


# ── suppressions ────────────────────────────────────────────────────────────
def load_suppressions(path):
    """Deliberately tiny parser. A suppression must carry a reason, an owner and
    an expiry, or it is not a suppression — it is a thing somebody hid."""
    if not path:
        return []
    entries, cur = [], None
    for ln, line in enumerate(Path(path).read_text().splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("- "):
            if cur:
                entries.append(cur)
            cur, s = {}, s[2:].strip()
        if ":" in s and cur is not None:
            k, v = s.split(":", 1)
            cur[k.strip()] = v.strip()
    if cur:
        entries.append(cur)

    good = []
    for e in entries:
        missing = [k for k in ("check", "reason", "who", "until") if not e.get(k)]
        if missing:
            print(f" warn  suppression for {e.get('check','?')} is missing: {', '.join(missing)}",
                  file=sys.stderr)
            print("       a suppression without a reason, an owner and an expiry is not a",
                  file=sys.stderr)
            print("       decision — it is something somebody hid. Ignoring it.", file=sys.stderr)
            continue
        try:
            if date.fromisoformat(e["until"]) < date.today():
                print(f" warn  suppression for {e['check']} expired on {e['until']} — ignoring it",
                      file=sys.stderr)
                continue
        except ValueError:
            print(f" warn  suppression for {e['check']}: 'until' is not a date — ignoring it",
                  file=sys.stderr)
            continue
        good.append(e)
    return good


def suppressed(f, sups):
    for s in sups:
        if s["check"] in f["check"] or s["check"] in f["title"]:
            if not s.get("resource") or s["resource"] in f["resource"]:
                return s
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--format", choices=["prowler", "scout", "csv"], default="prowler")
    ap.add_argument("--tier", type=int, choices=[1, 2, 3, 4])
    ap.add_argument("--suppress")
    ap.add_argument("--out")
    args = ap.parse_args()

    if not Path(args.file).is_file():
        sys.exit(f" fail  no such file: {args.file}")

    loader = {"prowler": load_prowler, "scout": load_scout, "csv": load_csv}[args.format]
    try:
        findings = loader(args.file)
    except Exception as exc:
        sys.exit(f" fail  could not parse as {args.format}: {exc}")
    if not findings:
        print("\n  No failing findings. Either the account is in good shape, or the")
        print("  scan was scoped narrowly. Check which before celebrating.\n")
        return

    sups = load_suppressions(args.suppress)
    kept, hidden = [], []
    for f in findings:
        s = suppressed(f, sups)
        (hidden if s else kept).append((f, s) if s else f)
    for f in kept:
        f["tier"] = tier_of(f"{f['check']} {f['title']} {f['detail']} {f['service']}")

    by_tier = defaultdict(list)
    for f in kept:
        by_tier[f["tier"]].append(f)

    print()
    print(f"  {len(findings)} failing finding(s) in {Path(args.file).name}")
    if hidden:
        print(f"  {len(hidden)} suppressed (each with a reason, an owner and an expiry)")
    print()
    for t in (1, 2, 3, 4):
        name, why = TIERS[t]
        n = len(by_tier[t])
        bar = "█" * min(40, n)
        print(f"  {t}  {name:<14} {n:>4}  {bar}")
        print(f"     {why}")
    print()

    show = [args.tier] if args.tier else [1, 2, 3, 4]
    for t in show:
        items = by_tier[t]
        if not items:
            continue
        name, _ = TIERS[t]
        print("─" * 74)
        print(f"  TIER {t} — {name}   ({len(items)})")
        print("─" * 74)
        counts = Counter(f["check"] for f in items)
        seen = set()
        for f in sorted(items, key=lambda x: (-counts[x["check"]], x["check"])):
            if f["check"] in seen:
                continue
            seen.add(f["check"])
            n = counts[f["check"]]
            mult = f"  ×{n}" if n > 1 else ""
            print(f"  [{f['severity'][:4]:<4}] {f['title'][:64]}{mult}")
            if f["resource"]:
                print(f"         {f['resource'][:66]}")
        print()

    if args.out:
        cols = ["tier", "tier_name", "severity", "check", "title", "resource",
                "region", "service", "detail"]
        with open(args.out, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for f in sorted(kept, key=lambda x: (x["tier"], x["check"])):
                w.writerow({**f, "tier_name": TIERS[f["tier"]][0]})
        print(f"  wrote {args.out}")
        print()

    print("─" * 74)
    print("  Work tier 1 to exhaustion before you open tier 2.")
    print()
    print("  And do not fix anything yet. Produce the ordered list, agree it with")
    print("  whoever owns the resources, and fix in that order. A finding fixed")
    print("  out of order is a finding you will explain twice.")
    print()
    if by_tier[3]:
        print(f"  Note the {len(by_tier[3])} detectability finding(s). They are tier 3 by")
        print("  sequence, not by importance: every one of them is a reason you would")
        print("  not know that a tier 1 or tier 2 finding had been exploited.")
        print()


if __name__ == "__main__":
    main()
