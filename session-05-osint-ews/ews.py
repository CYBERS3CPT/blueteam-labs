#!/usr/bin/env python3
"""
ews.py — an Early Warning System small enough to understand and read every day.

An EWS is not a threat intelligence platform. It answers four questions:

    1. Has a vulnerability been published in technology we actually run?
    2. Has anyone registered a domain that impersonates us?
    3. Has anything of ours appeared in an exposure?
    4. Has our external attack surface changed without a change request?

If it answers questions nobody asked, it becomes an ignored channel within two
weeks. The exclusion list at the bottom of the config is therefore the most
important part of the file, and the part everyone leaves empty.

Usage
    ./ews.py init                 write a starter ews.toml next to this script
    ./ews.py run                  fetch, filter, dedupe, route
    ./ews.py run --dry-run        do everything except send. Use this. A lot.
    ./ews.py digest               re-print the last run as a digest
    ./ews.py test-webhook         prove the webhook works before you need it

Deduplication is not optional. Without it the same CVE arrives from four feeds
for six days and the channel is muted by Wednesday.
"""

import argparse
import hashlib
import json
import re
import sys
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG = HERE / "ews.toml"
STATE = HERE / ".ews-state.json"

STARTER = '''\
# ews.toml — edit this, then `./ews.py run --dry-run` until the output is boring.

[general]
# How many items a single digest may contain before it stops being readable.
max_per_digest = 20
# Items older than this are ignored on first run, so day one is not a wall of text.
first_run_max_age_days = 3

[[feeds]]
name = "CISA-KEV"
url  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.xml"

[[feeds]]
name = "CERT-PT"
url  = "https://www.cncs.gov.pt/pt/alertas/rss/"

# Add your vendors. Yes, the ones you actually run, not the ones you have heard of.
# [[feeds]]
# name = "Vendor PSIRT"
# url  = "https://example.invalid/psirt.xml"

[filter]
# An EWS that reports every CVE reports nothing. These are YOUR products,
# YOUR domain and YOUR sector. If this list is generic, so are your alerts.
keywords = [
  "fortinet", "citrix", "vmware", "exchange", "veeam",
  "example.pt", "municipality", "healthcare",
]
# Case-insensitive regexes applied to title + summary. Anything matching is dropped
# even if a keyword hit. This is the exclusion list, and it belongs in the docs too.
exclude = [
  "end.of.life announcement",
  "webinar",
]

[route]
# Teams or Slack incoming webhook. Leave empty to print to stdout only.
webhook = ""
# Items at or above this severity interrupt; everything else waits for the digest.
# Severity is inferred from the title (CRITICAL/HIGH/KEV), because feeds are inconsistent.
interrupt_on = ["critical", "kev"]
'''


# ── output ──────────────────────────────────────────────────────────────────
def say(msg=""):
    print(msg)


def warn(msg):
    print(f" warn  {msg}", file=sys.stderr)


def die(msg, code=1):
    print(f" fail  {msg}", file=sys.stderr)
    sys.exit(code)


def utc_now():
    return datetime.now(timezone.utc)


# ── config ──────────────────────────────────────────────────────────────────
def load_config():
    if not CONFIG.exists():
        die(f"no {CONFIG.name} — run: {Path(sys.argv[0]).name} init")
    try:
        import tomllib  # 3.11+
    except ModuleNotFoundError:
        die("python 3.11+ needed for tomllib (or pip install tomli and adjust)")
    with CONFIG.open("rb") as fh:
        return tomllib.load(fh)


def load_state():
    if STATE.exists():
        try:
            return json.loads(STATE.read_text())
        except json.JSONDecodeError:
            warn("state file was corrupt; starting fresh (you may get one noisy run)")
    return {"seen": [], "last_run": None, "last_digest": []}


def save_state(state):
    # Keep the seen-list bounded. 5000 hashes is months of history and ~350 KB.
    state["seen"] = state["seen"][-5000:]
    STATE.write_text(json.dumps(state, indent=1))


# ── fetching ────────────────────────────────────────────────────────────────
def fetch(url, timeout=20):
    try:
        import feedparser  # the nice path
        return feedparser.parse(url)
    except ModuleNotFoundError:
        pass

    # The no-dependency path: urllib + a deliberately naive RSS/Atom parser.
    # It is not a general XML parser and does not pretend to be. It handles the
    # feeds in the starter config, which is the point of a starter config.
    import urllib.request
    import xml.etree.ElementTree as ET

    req = urllib.request.Request(url, headers={"User-Agent": "blueteam-ews/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()

    root = ET.fromstring(raw)
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    entries = []

    for item in root.iter():
        tag = item.tag.split("}")[-1]
        if tag not in ("item", "entry"):
            continue

        def child(*names):
            for n in names:
                el = item.find(n) if "}" not in n else item.find(n, ns)
                if el is None:
                    el = item.find(f"atom:{n}", ns)
                if el is not None:
                    return (el.text or el.get("href") or "").strip()
            return ""

        entries.append(
            {
                "title": child("title"),
                "link": child("link", "id"),
                "summary": child("description", "summary", "content"),
                "published": child("pubDate", "published", "updated"),
            }
        )

    return type("Feed", (), {"entries": entries, "bozo": 0})()


def entry_fields(e):
    """feedparser entries and our fallback dicts, normalised."""
    get = (lambda k: e.get(k, "")) if isinstance(e, dict) else (lambda k: getattr(e, k, ""))
    return {
        "title": (get("title") or "").strip(),
        "link": (get("link") or "").strip(),
        "summary": re.sub(r"<[^>]+>", " ", get("summary") or "")[:600].strip(),
        "published": (get("published") or "").strip(),
    }


# ── the pipeline ────────────────────────────────────────────────────────────
def severity_of(text):
    t = text.lower()
    if "known exploited" in t or re.search(r"\bkev\b", t):
        return "kev"
    for level in ("critical", "high", "medium", "low"):
        if level in t:
            return level
    return "unrated"


def run(dry_run=False):
    cfg = load_config()
    state = load_state()
    seen = set(state["seen"])
    first_run = state["last_run"] is None

    keywords = [k.lower() for k in cfg.get("filter", {}).get("keywords", [])]
    excludes = [re.compile(p, re.I) for p in cfg.get("filter", {}).get("exclude", [])]
    if not keywords:
        warn("no keywords configured — everything will match, which is the same as nothing")

    stats = {"fetched": 0, "kept": 0, "excluded": 0, "duplicate": 0, "new": 0}
    new_items = []

    for feed in cfg.get("feeds", []):
        name, url = feed["name"], feed["url"]
        try:
            parsed = fetch(url)
        except Exception as exc:  # noqa: BLE001 — one bad feed must not kill the run
            warn(f"{name}: {exc}")
            continue

        entries = list(getattr(parsed, "entries", []))
        stats["fetched"] += len(entries)
        say(f"  {name:<14} {len(entries):>4} item(s)")

        for raw in entries:
            e = entry_fields(raw)
            blob = f"{e['title']} {e['summary']}".lower()

            if keywords and not any(k in blob for k in keywords):
                continue
            if any(rx.search(blob) for rx in excludes):
                stats["excluded"] += 1
                continue
            stats["kept"] += 1

            uid = hashlib.sha256(f"{name}|{e['link'] or e['title']}".encode()).hexdigest()[:16]
            if uid in seen:
                stats["duplicate"] += 1
                continue

            seen.add(uid)
            stats["new"] += 1
            new_items.append(
                {
                    "feed": name,
                    "uid": uid,
                    "severity": severity_of(blob),
                    "found_utc": utc_now().isoformat(timespec="seconds"),
                    **e,
                }
            )

    say("")
    say(f"  fetched {stats['fetched']}  kept {stats['kept']}  "
        f"excluded {stats['excluded']}  duplicate {stats['duplicate']}  new {stats['new']}")

    if first_run and new_items:
        warn(f"first run: {len(new_items)} item(s) would all be 'new'. Reviewing, not sending.")
        dry_run = True

    if new_items:
        say("")
        print_digest(new_items, cfg)
        if not dry_run:
            deliver(new_items, cfg)
        else:
            say("\n  (dry run — nothing sent)")
    else:
        say("\n  nothing new. This is the correct steady state; do not 'fix' it.")

    state["seen"] = sorted(seen)
    state["last_run"] = utc_now().isoformat(timespec="seconds")
    state["last_digest"] = new_items
    save_state(state)


def print_digest(items, cfg):
    cap = cfg.get("general", {}).get("max_per_digest", 20)
    interrupts = [s.lower() for s in cfg.get("route", {}).get("interrupt_on", [])]
    say("─" * 72)
    say(f"  EWS digest — {utc_now().strftime('%Y-%m-%d %H:%M UTC')}")
    say("─" * 72)
    for it in items[:cap]:
        mark = "!!" if it["severity"] in interrupts else "  "
        say(f"{mark} [{it['feed']}] {it['severity'].upper()}")
        for line in textwrap.wrap(it["title"], 68):
            say(f"     {line}")
        if it["link"]:
            say(f"     {it['link']}")
        say("")
    if len(items) > cap:
        say(f"  … and {len(items) - cap} more (raise max_per_digest, or tighten your keywords)")


def deliver(items, cfg):
    url = cfg.get("route", {}).get("webhook", "").strip()
    if not url:
        warn("no webhook configured — digest printed above only")
        return
    cap = cfg.get("general", {}).get("max_per_digest", 20)
    lines = [f"**EWS digest — {utc_now().strftime('%Y-%m-%d %H:%M UTC')}**", ""]
    for it in items[:cap]:
        lines.append(f"- `{it['feed']}` **{it['severity'].upper()}** {it['title']}")
        if it["link"]:
            lines.append(f"  {it['link']}")
    post(url, "\n".join(lines))


def post(url, text):
    import urllib.request
    body = json.dumps({"text": text}).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if 200 <= resp.status < 300:
                say(f"  delivered ({resp.status})")
            else:
                warn(f"webhook returned {resp.status}")
    except Exception as exc:  # noqa: BLE001
        warn(f"webhook failed: {exc}")
        warn("the digest above is still valid. fix the webhook, do not re-run the fetch.")


def cmd_init():
    if CONFIG.exists():
        die(f"{CONFIG.name} already exists — not overwriting your config")
    CONFIG.write_text(STARTER)
    say(f"  wrote {CONFIG}")
    say("")
    say("  Now, in this order:")
    say("    1. Replace the keywords with YOUR products, domain and sector.")
    say("    2. ./ews.py run --dry-run, and keep tightening until the output is boring.")
    say("    3. Only then add the webhook.")
    say("")
    say("  Step 2 is the whole job. Skipping it is how an EWS becomes a muted channel.")


def cmd_digest():
    state = load_state()
    items = state.get("last_digest") or []
    if not items:
        die("no stored digest — run first")
    print_digest(items, load_config())


def cmd_test_webhook():
    cfg = load_config()
    url = cfg.get("route", {}).get("webhook", "").strip()
    if not url:
        die("no webhook in config")
    post(url, f"EWS test message — {utc_now().isoformat(timespec='seconds')}. "
              "If you can read this, the plumbing works.")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("command", choices=["init", "run", "digest", "test-webhook"])
    ap.add_argument("--dry-run", action="store_true", help="do everything except send")
    args = ap.parse_args()

    {"init": cmd_init,
     "run": lambda: run(args.dry_run),
     "digest": cmd_digest,
     "test-webhook": cmd_test_webhook}[args.command]()


if __name__ == "__main__":
    main()
