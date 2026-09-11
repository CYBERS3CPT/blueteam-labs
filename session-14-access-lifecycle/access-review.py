#!/usr/bin/env python3
"""
access-review.py — an access review a manager could actually sign.

A review that produces a list is not a review. A review that produces signed
decisions with reasons is. So this produces a CSV where the default is REVOKE,
keeping requires a tick AND a reason, and the "last used" column sits next to
every entitlement — because unused access is the easy thing to revoke and the
thing nobody shows the reviewer.

Usage
    ./access-review.py --url http://localhost:8080 --realm blueteam \\
                       --user admin --password admin
    ./access-review.py ... --out review-Q4.csv
    ./access-review.py ... --inactive-days 90
    ./access-review.py --check review-Q4.csv     validate a completed review

Reads a Keycloak realm through the admin API. Nothing is modified. The tool
cannot revoke anything and that is deliberate: a review is a decision record,
and executing it is a separate, deliberate step.
"""

import argparse
import csv
import json
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta

# Roles that let the holder grant themselves more. Anything here is effectively
# administrator, whatever it is called.
PRIVILEGED = {"admin", "realm-admin", "manage-users", "manage-realm", "manage-clients",
              "create-client", "manage-authorization", "manage-identity-providers"}

# Plain-language translations. "realm-admin" means nothing to the person signing.
PLAIN = {
    "admin":          "full administrator of this realm",
    "realm-admin":    "full administrator of this realm",
    "manage-users":   "can create, modify and delete any user",
    "manage-realm":   "can change realm-wide security settings",
    "manage-clients": "can create and modify applications, including redirect URIs",
    "create-client":  "can register new applications",
    "view-users":     "can read every user record",
    "offline_access": "can hold a token that survives logout",
    "uma_authorization": "(Keycloak default, usually harmless)",
    "default-roles-": "(Keycloak default bundle)",
}


def plain(role):
    for k, v in PLAIN.items():
        if role.startswith(k):
            return v
    return role


class KC:
    def __init__(self, url, realm, user, password, admin_realm="master"):
        self.url, self.realm = url.rstrip("/"), realm
        self.token = self._auth(user, password, admin_realm)

    def _auth(self, user, password, admin_realm):
        data = urllib.parse.urlencode({
            "grant_type": "password", "client_id": "admin-cli",
            "username": user, "password": password}).encode()
        req = urllib.request.Request(
            f"{self.url}/realms/{admin_realm}/protocol/openid-connect/token", data=data)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.load(r)["access_token"]
        except Exception as exc:
            sys.exit(f" fail  could not authenticate: {exc}\n"
                     f"       is {self.url} reachable, and are the credentials right?")

    def get(self, path, **params):
        q = ("?" + urllib.parse.urlencode(params)) if params else ""
        req = urllib.request.Request(f"{self.url}/admin/realms/{self.realm}/{path}{q}",
                                     headers={"Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except Exception:
            return []


def build(kc, inactive_days):
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=inactive_days)

    users = kc.get("users", max=2000, briefRepresentation="false")
    if not users:
        sys.exit(" fail  no users returned — wrong realm, or no permission")

    # Last login comes from the events endpoint. If event logging is off, this is
    # empty — and an access review without 'last used' is a review nobody reads.
    logins = {}
    for ev in kc.get("events", type="LOGIN", max=10000):
        uid, ts = ev.get("userId"), ev.get("time")
        if uid and ts and ts > logins.get(uid, 0):
            logins[uid] = ts
    if not logins:
        print(" warn  no LOGIN events available — the 'last used' column will be empty.",
              file=sys.stderr)
        print("       Enable user event logging, or this review is a list of names.",
              file=sys.stderr)

    rows = []
    for u in users:
        uid = u["id"]
        realm_roles = [r["name"] for r in kc.get(f"users/{uid}/role-mappings/realm")]
        client_roles = []
        for cid, data in (kc.get(f"users/{uid}/role-mappings") or {}).get("clientMappings", {}).items():
            client_roles += [f"{cid}:{r['name']}" for r in data.get("mappings", [])]
        all_roles = realm_roles + client_roles

        creds = kc.get(f"users/{uid}/credentials")
        has_otp = any(c.get("type") == "otp" for c in creds)
        has_webauthn = any("webauthn" in (c.get("type") or "") for c in creds)

        privileged = any(r in PRIVILEGED for r in realm_roles)
        last_ms = logins.get(uid)
        last = datetime.fromtimestamp(last_ms / 1000, timezone.utc) if last_ms else None
        created = datetime.fromtimestamp(u["createdTimestamp"] / 1000, timezone.utc) \
            if u.get("createdTimestamp") else None

        flags = []
        if privileged and not (has_otp or has_webauthn):
            flags.append("PRIVILEGED_NO_MFA")
        if not u.get("enabled", True):
            flags.append("DISABLED_NOT_REMOVED")
        if not u.get("emailVerified", False):
            flags.append("EMAIL_UNVERIFIED")
        if last and last < cutoff:
            flags.append(f"INACTIVE_{inactive_days}D")
        if not last and created and created < cutoff:
            flags.append("NEVER_LOGGED_IN")
        if privileged:
            flags.append("PRIVILEGED")

        # One row per entitlement, batched by user. A reviewer decides per
        # entitlement, not per person — "keep Ana" is not a decision.
        interesting = [r for r in all_roles if not r.startswith("default-roles")] or ["(none)"]
        for role in interesting:
            rows.append({
                "username": u.get("username", ""),
                "full_name": f'{u.get("firstName","")} {u.get("lastName","")}'.strip(),
                "email": u.get("email", ""),
                "entitlement": role,
                "what_it_means": plain(role),
                "last_used_utc": last.strftime("%Y-%m-%d") if last else "",
                "days_since": (now - last).days if last else "",
                "mfa": "webauthn" if has_webauthn else ("totp" if has_otp else "NONE"),
                "enabled": "yes" if u.get("enabled", True) else "no",
                "flags": " ".join(flags),
                "DECISION_keep_or_revoke": "REVOKE",   # the default, deliberately
                "reason_if_keeping": "",
                "reviewer": "",
                "reviewed_date": "",
            })
    return rows


def write(rows, out):
    cols = list(rows[0].keys())
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        # Group by resource, not by person: the reviewer stays in one context.
        for r in sorted(rows, key=lambda x: (x["entitlement"], x["username"])):
            w.writerow(r)


def summarise(rows, out):
    users = {r["username"] for r in rows}
    flagged = [r for r in rows if r["flags"]]
    noflag = lambda f: len({r["username"] for r in rows if f in r["flags"]})  # noqa: E731
    print()
    print(f"  {len(rows)} entitlement(s) across {len(users)} user(s) -> {out}")
    print()
    for flag, why in (
        ("PRIVILEGED_NO_MFA", "administrator without MFA. Fix before the review, not in it."),
        ("NEVER_LOGGED_IN",   "provisioned and never used. The easiest revocations you will ever make."),
        ("DISABLED_NOT_REMOVED", "disabled is not deprovisioned — tokens and keys outlive it."),
        ("INACTIVE_",         "no recent login."),
        ("EMAIL_UNVERIFIED",  "if anything trusts the email claim, that is a takeover path."),
        ("PRIVILEGED",        "can grant themselves more than they have."),
    ):
        n = noflag(flag)
        if n:
            print(f"    {n:>4} user(s)  {flag:<22} {why}")
    print()
    print("  The default in every row is REVOKE. Keeping requires a tick AND a reason.")
    print("  That is the difference between a review and a rubber stamp — and the")
    print("  revocation rate is the metric that tells you which one happened.")
    print()
    print(f"  When it comes back:  ./access-review.py --check {out}")
    print()


def check(path):
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        sys.exit(" fail  empty file")

    keep = [r for r in rows if r.get("DECISION_keep_or_revoke", "").strip().upper().startswith("K")]
    revoke = [r for r in rows if r.get("DECISION_keep_or_revoke", "").strip().upper().startswith("R")]
    blank = [r for r in rows if not r.get("DECISION_keep_or_revoke", "").strip()]
    noreason = [r for r in keep if not r.get("reason_if_keeping", "").strip()]
    noreviewer = [r for r in rows if not r.get("reviewer", "").strip()]

    print()
    print(f"  {len(rows)} row(s):  {len(keep)} keep,  {len(revoke)} revoke,  {len(blank)} undecided")
    rate = (len(revoke) * 100 // len(rows)) if rows else 0
    print(f"  revocation rate: {rate}%")
    print()

    problems = 0
    if blank:
        print(f"  ! {len(blank)} row(s) with no decision — an undecided row is a kept row by accident")
        problems += 1
    if noreason:
        print(f"  ! {len(noreason)} row(s) kept with no reason:")
        for r in noreason[:10]:
            print(f"      {r['username']:<18} {r['entitlement']}")
        problems += 1
    if noreviewer:
        print(f"  ! {len(noreviewer)} row(s) with no reviewer named")
        problems += 1
    if rate == 0 and len(rows) > 10:
        print("  ! nothing was revoked at all.")
        print("    That happens when a review is approved wholesale in four minutes.")
        print("    If it is genuinely correct, say so in writing and move on. If it is")
        print("    not, this is the moment it was supposed to be caught.")
        problems += 1

    still_no_mfa = [r for r in keep if "PRIVILEGED_NO_MFA" in r.get("flags", "")]
    if still_no_mfa:
        print(f"  ! {len(still_no_mfa)} privileged entitlement(s) kept, still without MFA:")
        for r in still_no_mfa[:10]:
            print(f"      {r['username']:<18} {r['entitlement']}  reason: {r.get('reason_if_keeping','')[:40]}")
        problems += 1

    print()
    if problems:
        print(f"  {problems} issue(s). A review with these in it will not survive an audit,")
        print("  and more importantly it did not do the job it was run to do.")
        sys.exit(1)
    print("  Complete: every row decided, every 'keep' justified, every row attributed.")
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://localhost:8080")
    ap.add_argument("--realm", default="blueteam")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="admin")
    ap.add_argument("--admin-realm", default="master")
    ap.add_argument("--inactive-days", type=int, default=90)
    ap.add_argument("--out", default=f"access-review-{datetime.now(timezone.utc):%Y%m%d}.csv")
    ap.add_argument("--check", help="validate a completed review instead of building one")
    args = ap.parse_args()

    if args.check:
        check(args.check); return

    kc = KC(args.url, args.realm, args.user, args.password, args.admin_realm)
    rows = build(kc, args.inactive_days)
    if not rows:
        sys.exit(" fail  nothing to review")
    write(rows, args.out)
    summarise(rows, args.out)


if __name__ == "__main__":
    main()
