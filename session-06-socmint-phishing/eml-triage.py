#!/usr/bin/env python3
"""
eml-triage.py — read an email the way the receiving mail server did.

Header forensics, in the order you should work it, every time. The verdict is
never "authentication failed" on its own; the verdict is what the receiving
POLICY did about it, which is a different question and the one that decides
whether the message reached an inbox.

Usage
    ./eml-triage.py message.eml
    ./eml-triage.py *.eml --brief
    ./eml-triage.py message.eml --json

Checks, in order:
    1. Authentication-Results — SPF, DKIM, DMARC, and the policy applied
    2. Received chain, read bottom-up, with hop timing
    3. Return-Path vs From              (classic envelope spoofing)
    4. From display name vs address     (the reader never sees the address)
    5. Reply-To divergence
    6. Message-ID domain consistency
    7. Homoglyphs and IDN, decoded — not eyeballed
    8. URLs: displayed text vs actual destination
    9. Attachments: claimed type vs magic bytes
   10. Would DMARC p=reject have stopped this? If not, why not?

Nothing here connects to the network. It reads the file you gave it and no more.
"""

import argparse
import email
import email.policy
import hashlib
import json
import re
import sys
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

# ── output ──────────────────────────────────────────────────────────────────
TTY = sys.stdout.isatty()
def c(code, s):
    return f"\033[{code}m{s}\033[0m" if TTY else s
RED, YEL, GRN, DIM, BOLD, CYA = "31", "33", "32", "2", "1", "36"

FINDINGS = []
def finding(sev, what, detail=""):
    FINDINGS.append({"severity": sev, "finding": what, "detail": detail})
    mark = {"high": c(RED, "  !!"), "medium": c(YEL, "   !"), "info": c(DIM, "    ")}[sev]
    print(f"{mark} {what}")
    if detail:
        print(f"      {c(DIM, detail)}")

def head(t):
    print()
    print(c(CYA, f"── {t} " + "─" * max(0, 66 - len(t))))


# ── homoglyph / IDN ─────────────────────────────────────────────────────────
# Not an exhaustive table — an exhaustive table is Unicode's problem. These are
# the ones that actually turn up in domains, because they render identically in
# most sans-serif faces at 11pt.
CONFUSABLES = {
    "а": "a (Cyrillic а)", "е": "e (Cyrillic е)", "о": "o (Cyrillic о)",
    "р": "p (Cyrillic р)", "с": "c (Cyrillic с)", "х": "x (Cyrillic х)",
    "у": "y (Cyrillic у)", "і": "i (Cyrillic і)", "ј": "j (Cyrillic ј)",
    "ο": "o (Greek ο)",    "α": "a (Greek α)",    "ɡ": "g (Latin ɡ)",
    "‐": "- (hyphen)",     "‑": "- (non-breaking hyphen)",
    "ı": "i (dotless ı)",  "ӏ": "l (Cyrillic ӏ)",
}

def check_confusables(text, label):
    hits = {ch: name for ch, name in CONFUSABLES.items() if ch in text}
    if hits:
        finding("high", f"non-ASCII lookalike characters in {label}",
                "; ".join(f"U+{ord(ch):04X} looks like {name}" for ch, name in hits.items()))
        return True
    # xn-- is punycode. It is legitimate technology and it is also how every
    # homoglyph domain is actually registered.
    if "xn--" in text.lower():
        try:
            decoded = text.encode().decode("idna")
        except Exception:
            decoded = "(could not decode)"
        finding("high", f"punycode in {label}", f"{text} decodes to {decoded}")
        return True
    return False


def domain_of(addr):
    return addr.rsplit("@", 1)[-1].lower().strip(">").strip() if "@" in addr else ""


def org_domain(d):
    """Crude eTLD+1. Good enough for 'is this the same organisation' on the
    domains that appear in phishing. Not a substitute for the public suffix list."""
    parts = d.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


# ── the analysis ────────────────────────────────────────────────────────────
def analyse(path, brief=False):
    FINDINGS.clear()
    raw = Path(path).read_bytes()
    msg = email.message_from_bytes(raw, policy=email.policy.default)

    print()
    print(c(BOLD, f"  {Path(path).name}"))
    print(f"  {c(DIM, 'sha256 ' + hashlib.sha256(raw).hexdigest())}")
    print(f"  {c(DIM, f'{len(raw)} bytes')}")

    from_hdr = str(msg.get("From", ""))
    disp, from_addr = parseaddr(from_hdr)
    from_dom = domain_of(from_addr)
    reply_to = str(msg.get("Reply-To", ""))
    return_path = str(msg.get("Return-Path", "")).strip("<> ")
    msg_id = str(msg.get("Message-ID", ""))
    subject = str(msg.get("Subject", ""))

    if not brief:
        head("the message")
        print(f"  Subject      {subject[:70]}")
        print(f"  From         {from_hdr[:70]}")
        print(f"  Return-Path  {return_path or '(absent)'}")
        print(f"  Reply-To     {reply_to or '(absent)'}")
        print(f"  Message-ID   {msg_id[:70]}")
        print(f"  Date         {msg.get('Date', '(absent)')}")

    # 1 ── authentication ────────────────────────────────────────────────────
    head("1. authentication results")
    ar = " ".join(str(v) for v in msg.get_all("Authentication-Results", []))
    if not ar:
        finding("medium", "no Authentication-Results header",
                "the receiving server did not record a verdict, or it was stripped in transit")
    else:
        verdicts = {}
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{mech}=(\w+)", ar, re.I)
            verdicts[mech] = m.group(1).lower() if m else "absent"
            colour = {"pass": GRN, "fail": RED, "softfail": YEL,
                      "none": YEL, "neutral": YEL, "absent": DIM}.get(verdicts[mech], DIM)
            print(f"  {mech.upper():<6} {c(colour, verdicts[mech])}")
        for mech in ("spf", "dkim"):
            if verdicts[mech] in ("fail", "softfail"):
                finding("high", f"{mech.upper()} {verdicts[mech]}")
        if verdicts["dmarc"] == "fail":
            finding("high", "DMARC fail",
                    "whether it was delivered depends on the sender's published policy, not this verdict")
        elif verdicts["dmarc"] == "absent":
            finding("medium", "no DMARC verdict recorded")
        pol = re.search(r"\b(?:dmarc=\w+\s*)?\(p=(\w+)", ar, re.I) or re.search(r"\bp=(\w+)", ar, re.I)
        if pol:
            print(f"  {c(DIM, 'published policy p=' + pol.group(1))}")

    # 2 ── received chain ────────────────────────────────────────────────────
    head("2. received chain (bottom-up = the actual route)")
    received = msg.get_all("Received", []) or []
    if not received:
        finding("medium", "no Received headers at all", "the file may be a saved draft rather than a delivered message")
    else:
        hops = list(reversed([str(r) for r in received]))
        prev_dt = None
        for i, hop in enumerate(hops, 1):
            flat = " ".join(hop.split())
            frm = re.search(r"from\s+([^\s;]+)", flat, re.I)
            by = re.search(r"\bby\s+([^\s;]+)", flat, re.I)
            ip = re.search(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?", flat)
            when = ""
            if ";" in flat:
                try:
                    dt = parsedate_to_datetime(flat.rsplit(";", 1)[1].strip())
                    when = dt.strftime("%H:%M:%S")
                    if prev_dt:
                        gap = (dt - prev_dt).total_seconds()
                        # A long pause between hops is usually a queue, sometimes a
                        # manually injected header. Either way it is worth noticing.
                        if gap > 300:
                            when += c(YEL, f"  (+{int(gap//60)}m)")
                    prev_dt = dt
                except Exception:
                    pass
            print(f"  {i}. {c(DIM, when or '--:--:--'):<18} "
                  f"from {(frm.group(1) if frm else '?')[:26]:<26} "
                  f"by {(by.group(1) if by else '?')[:24]:<24} "
                  f"{c(DIM, ip.group(1) if ip else '')}")
        first = " ".join(hops[0].split())
        if from_dom and org_domain(from_dom) not in first.lower():
            finding("medium", "first hop does not mention the From domain",
                    f"the message claims to be from {from_dom}; hop 1 is {first[:60]}")

    # 3-6 ── the identity mismatches ─────────────────────────────────────────
    head("3-6. identity consistency")
    rp_dom = domain_of(return_path)
    if return_path and rp_dom and rp_dom != from_dom:
        sev = "info" if org_domain(rp_dom) == org_domain(from_dom) else "high"
        finding(sev, "Return-Path domain differs from From domain",
                f"envelope {rp_dom}  vs  header {from_dom}"
                + ("  (same organisation — common with mailing lists and ESPs)" if sev == "info" else "  (classic envelope spoofing)"))
    else:
        print(f"  {c(GRN, 'Return-Path and From agree')}")

    # The display name is what the reader sees. The address is what the reader
    # does not see. This is the entire trick.
    if disp and "@" in disp:
        d2 = domain_of(disp)
        if d2 and org_domain(d2) != org_domain(from_dom):
            finding("high", "display name contains an address from a different domain",
                    f'display says "{disp}" but the message is from {from_addr}')
    elif disp and from_dom:
        brandish = re.sub(r"[^a-z]", "", disp.lower())
        if brandish and len(brandish) > 3 and brandish not in from_dom.replace(".", ""):
            finding("medium", "display name does not relate to the sending domain",
                    f'"{disp}" <{from_addr}> — the reader sees the left side only')

    if reply_to:
        _, rt_addr = parseaddr(reply_to)
        rt_dom = domain_of(rt_addr)
        if rt_dom and org_domain(rt_dom) != org_domain(from_dom):
            finding("high", "Reply-To points at a different organisation",
                    f"replies go to {rt_addr}, not to {from_addr}")

    if msg_id and from_dom:
        mid_dom = domain_of(msg_id.strip("<> "))
        if mid_dom and org_domain(mid_dom) != org_domain(from_dom):
            finding("medium", "Message-ID domain does not match the sender",
                    f"{mid_dom} vs {from_dom}  (weak on its own; corroborating in combination)")

    # 7 ── homoglyphs ────────────────────────────────────────────────────────
    head("7. homoglyphs and IDN (decoded, not eyeballed)")
    any_conf = False
    for label, value in (("From", from_hdr), ("Reply-To", reply_to),
                         ("Return-Path", return_path), ("Subject", subject)):
        if value:
            any_conf |= check_confusables(value, label)
    if not any_conf:
        print(f"  {c(GRN, 'nothing confusable in the headers')}")

    # 8 ── URLs ──────────────────────────────────────────────────────────────
    head("8. URLs")
    body = ""
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            try:
                body += part.get_content()
            except Exception:
                pass
    urls = sorted(set(re.findall(r'https?://[^\s"\'<>)\]]+', body)))
    if not urls:
        print(f"  {c(DIM, 'none found')}")
    else:
        for u in urls[:15]:
            host = re.sub(r"^https?://([^/:]+).*", r"\1", u)
            note = ""
            if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host):
                note = c(RED, "  <- bare IP")
            elif any(s in host for s in ("bit.ly", "tinyurl", "t.co", "is.gd", "cutt.ly")):
                note = c(YEL, "  <- shortener, destination unknown")
            elif from_dom and org_domain(host) != org_domain(from_dom):
                note = c(DIM, "  <- off-domain")
            print(f"  {u[:78]}{note}")
            check_confusables(host, f"URL host {host}")
        if len(urls) > 15:
            print(f"  {c(DIM, f'… and {len(urls)-15} more')}")
        # The displayed text saying one thing while href says another is the
        # oldest trick in the file and still works.
        # group 1 is the href, group 2 is what the reader sees. Order matters.
        for href, text in re.findall(r'<a[^>]+href="([^"]+)"[^>]*>([^<]{4,80})</a>', body, re.I | re.S)[:20]:
            if re.match(r"^https?://", text.strip(), re.I):
                th, hh = [re.sub(r"^https?://([^/:]+).*", r"\1", x.strip()) for x in (text, href)]
                if th and hh and org_domain(th) != org_domain(hh):
                    finding("high", "link text shows one domain and points at another",
                            f"shows {th}  ->  goes to {hh}")

    # 9 ── attachments ───────────────────────────────────────────────────────
    head("9. attachments")
    MAGIC = {b"MZ": "PE executable", b"PK\x03\x04": "zip (or docx/xlsx/jar)",
             b"%PDF": "PDF", b"\x7fELF": "ELF executable", b"\xd0\xcf\x11\xe0": "OLE (legacy Office)",
             b"Rar!": "RAR", b"7z\xbc\xaf": "7-Zip", b"#!": "script with shebang"}
    found = False
    for part in msg.walk():
        fn = part.get_filename()
        if not fn:
            continue
        found = True
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        magic = next((desc for sig, desc in MAGIC.items() if payload.startswith(sig)), "unrecognised")
        print(f"  {fn[:48]:<48} {len(payload):>9} B  {magic}")
        print(f"  {c(DIM, '  sha256 ' + hashlib.sha256(payload).hexdigest())}")
        ext = Path(fn).suffix.lower()
        if ext in (".pdf", ".docx", ".xlsx", ".txt", ".jpg", ".png") and magic.startswith(("PE", "ELF")):
            finding("high", f"attachment '{fn}' claims {ext} but is a {magic}")
        if ext in (".exe", ".scr", ".js", ".vbs", ".hta", ".lnk", ".iso", ".img"):
            finding("high", f"attachment '{fn}' has a high-risk extension")
        # Right-to-left override: makes "invoice[RLO]cod.exe" render as "invoiceexe.doc".
        if "‮" in fn:
            finding("high", f"attachment filename contains U+202E (right-to-left override)",
                    "the displayed extension is not the real one")
    if not found:
        print(f"  {c(DIM, 'none')}")

    # 10 ── the verdict ──────────────────────────────────────────────────────
    head("10. would DMARC p=reject have stopped this?")
    if not ar:
        print("  Cannot say — no Authentication-Results to reason from.")
    else:
        spf_dom = domain_of(return_path)
        aligned = bool(spf_dom and from_dom and org_domain(spf_dom) == org_domain(from_dom))
        dmarc_fail = bool(re.search(r"dmarc=fail", ar, re.I))
        if dmarc_fail:
            print(f"  {c(GRN, 'Yes.')} DMARC failed, so a published p=reject would have rejected it.")
        elif not aligned:
            print(f"  {c(GRN, 'Probably yes.')} The envelope domain is not aligned with the From domain.")
        else:
            print(f"  {c(RED, 'No.')} Authentication passes and the domains align.")
            print("  This is the important case: a lookalike domain the attacker OWNS")
            print("  will pass SPF, DKIM and DMARC perfectly, because it is their domain.")
            print("  DMARC stops exact-domain spoofing. It does nothing for lookalikes.")

    # ── summary ──────────────────────────────────────────────────────────────
    head("summary")
    if not FINDINGS:
        print(f"  {c(GRN, 'no structural findings')} — which is not the same as 'benign'.")
        print(f"  {c(DIM, 'a well-resourced actor sends well-formed email from a domain they own.')}")
    else:
        for sev in ("high", "medium", "info"):
            for f in [x for x in FINDINGS if x["severity"] == sev]:
                print(f"  [{sev:<6}] {f['finding']}")
    print()
    return list(FINDINGS)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+")
    ap.add_argument("--brief", action="store_true", help="skip the header dump")
    ap.add_argument("--json", action="store_true", help="machine-readable findings")
    args = ap.parse_args()

    out = {}
    for f in args.files:
        if not Path(f).is_file():
            print(f" fail  no such file: {f}", file=sys.stderr)
            continue
        out[f] = analyse(f, brief=args.brief or args.json)
    if args.json:
        print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
