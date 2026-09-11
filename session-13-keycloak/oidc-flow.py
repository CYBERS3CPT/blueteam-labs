#!/usr/bin/env python3
"""
oidc-flow.py — run a real authorisation code + PKCE flow and narrate every step.

Reading one real flow is worth more than any diagram. This performs one against
your own Keycloak, prints every request and redirect as it happens, and stops to
explain the two things people get wrong: what PKCE actually prevents, and which
token goes where.

Usage
    ./oidc-flow.py --issuer http://localhost:8080/realms/blueteam --client my-app
    ./oidc-flow.py --issuer ... --client my-app --port 3000
    ./oidc-flow.py --issuer ... --client my-app --secret <s>   confidential client
    ./oidc-flow.py --discover --issuer ...                     just read the metadata

It opens a browser, listens on localhost for the redirect, exchanges the code,
and prints the tokens decoded. Standard library only.
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
import secrets
import sys
import threading
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime, timezone

TTY = sys.stdout.isatty()
def c(code, s): return f"\033[{code}m{s}\033[0m" if TTY else s
CYA, DIM, GRN, YEL, RED, BOLD = "36", "2", "32", "33", "31", "1"

def step(n, title):
    print()
    print(c(CYA, f"  ── {n}. {title} " + "─" * max(0, 58 - len(title))))

def note(s):
    print(c(DIM, f"     {s}"))

def get_json(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)

def b64url(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def decode_segment(seg):
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


class Catcher(http.server.BaseHTTPRequestHandler):
    result = {}
    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        Catcher.result = {k: v[0] for k, v in q.items()}
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        body = ("<h2>Authorisation code received</h2>"
                "<p>Go back to the terminal. The code is in the address bar of this "
                "page, which is exactly why it must be single-use and exchanged over "
                "the back channel.</p>")
        self.wfile.write(body.encode())
    def log_message(self, *a):
        pass  # the script narrates; the server should be quiet


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--issuer", required=True, help="e.g. http://localhost:8080/realms/blueteam")
    ap.add_argument("--client", default="my-app")
    ap.add_argument("--secret", help="only for confidential clients")
    ap.add_argument("--port", type=int, default=3000)
    ap.add_argument("--scope", default="openid profile email")
    ap.add_argument("--discover", action="store_true")
    args = ap.parse_args()

    issuer = args.issuer.rstrip("/")
    redirect = f"http://localhost:{args.port}/callback"

    step(1, "discovery")
    note(f"GET {issuer}/.well-known/openid-configuration")
    try:
        meta = get_json(f"{issuer}/.well-known/openid-configuration")
    except Exception as exc:
        sys.exit(f"\n fail  discovery failed: {exc}\n        is the realm running, and spelled right?")
    for k in ("issuer", "authorization_endpoint", "token_endpoint",
              "jwks_uri", "end_session_endpoint"):
        if k in meta:
            print(f"     {k:<26} {meta[k]}")
    methods = meta.get("code_challenge_methods_supported", [])
    print(f"     {'pkce methods':<26} {methods or '(not advertised)'}")
    if "S256" not in methods:
        print(c(YEL, "     ! S256 is not advertised. Plain PKCE is barely PKCE."))
    if args.discover:
        return

    # ── PKCE ────────────────────────────────────────────────────────────────
    step(2, "PKCE: generate the verifier and its challenge")
    verifier = b64url(os.urandom(40))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    print(f"     verifier   {verifier[:44]}…   {c(DIM, '(stays HERE, never sent yet)')}")
    print(f"     challenge  {challenge[:44]}…   {c(DIM, 'S256(verifier), sent in step 3')}")
    note("")
    note("What PKCE prevents: an attacker who intercepts the authorisation code")
    note("cannot redeem it, because redemption requires the verifier — and the")
    note("verifier never travelled over the front channel. The challenge did,")
    note("and a SHA-256 is not reversible.")
    note("")
    note("What PKCE does NOT prevent: a wildcard redirect URI sending the code to")
    note("an attacker-controlled path in the first place. Different problem,")
    note("different control, and it is finding number one in keycloak-lab review.")

    # ── authorise ───────────────────────────────────────────────────────────
    step(3, "front channel: send the user to the authorisation endpoint")
    params = {
        "client_id": args.client, "response_type": "code",
        "redirect_uri": redirect, "scope": args.scope,
        "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    auth_url = meta["authorization_endpoint"] + "?" + urllib.parse.urlencode(params)
    print(f"     {auth_url[:100]}…")
    note("")
    note("Note what is NOT in this URL: the password, and the verifier. The")
    note("application never sees either. That separation is the whole design.")

    srv = http.server.HTTPServer(("localhost", args.port), Catcher)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    print()
    print(f"  {c(BOLD, 'Opening a browser. Log in as one of your realm users.')}")
    print(f"  {c(DIM, 'If it does not open, paste the URL above.')}")
    try:
        webbrowser.open(auth_url)
    except Exception:
        pass

    srv.socket.settimeout(180)
    for _ in range(180):
        if Catcher.result:
            break
        threading.Event().wait(1)
    if not Catcher.result:
        sys.exit("\n fail  no redirect received within 180s")

    step(4, "the redirect comes back")
    res = Catcher.result
    if "error" in res:
        print(c(RED, f"     error: {res.get('error')}  {res.get('error_description','')}"))
        if res.get("error") == "invalid_redirect_uri":
            note("the redirect URI must match the client configuration EXACTLY")
        sys.exit(1)
    for k, v in res.items():
        print(f"     {k:<14} {v[:70]}")
    if res.get("state") != state:
        sys.exit(c(RED, "\n fail  STATE MISMATCH. Stop. This is what state is for: it binds the\n"
                        "       response to the request you made, and a mismatch means the\n"
                        "       response belongs to someone else's request."))
    print(c(GRN, "     state matches — the response belongs to the request we made"))
    note("")
    note("The code is in a URL, which means it is in the browser history, in any")
    note("proxy log, and in the Referer of whatever loads next. Single-use and")
    note("short-lived are not optional properties.")

    # ── token ───────────────────────────────────────────────────────────────
    step(5, "back channel: exchange the code for tokens")
    data = {"grant_type": "authorization_code", "code": res["code"],
            "redirect_uri": redirect, "client_id": args.client,
            "code_verifier": verifier}
    if args.secret:
        data["client_secret"] = args.secret
    note(f"POST {meta['token_endpoint']}")
    note("     grant_type=authorization_code, code=…, code_verifier=…  <- now it goes")
    req = urllib.request.Request(meta["token_endpoint"],
                                 data=urllib.parse.urlencode(data).encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            tokens = json.load(r)
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:400]
        print(c(RED, f"     token exchange failed: {e.code}"))
        print(f"     {body}")
        if "invalid_grant" in body:
            note("invalid_grant usually means the verifier did not match the challenge,")
            note("or the code was already used. Codes are single-use, by design.")
        sys.exit(1)

    print(c(GRN, "     exchanged"))
    for k in ("token_type", "expires_in", "refresh_expires_in", "scope", "session_state"):
        if k in tokens:
            print(f"     {k:<20} {tokens[k]}")

    # ── the tokens ──────────────────────────────────────────────────────────
    step(6, "which token goes where")
    for name, why in (("id_token", "proves AUTHENTICATION. For your app, once, at login. Never send it to an API."),
                      ("access_token", "grants AUTHORISATION to an API. Send with every request. Never inspect it as identity."),
                      ("refresh_token", "obtains new access tokens. Treat as a credential; rotation and reuse detection matter.")):
        if name not in tokens:
            continue
        print()
        print(f"     {c(BOLD, name)}")
        print(f"     {c(DIM, why)}")
        parts = tokens[name].split(".")
        if len(parts) == 3:
            payload = decode_segment(parts[1])
            for k in ("iss", "aud", "sub", "azp", "exp", "typ", "email", "email_verified",
                      "preferred_username", "acr"):
                if k in payload:
                    v = payload[k]
                    if k == "exp":
                        left = int(v) - datetime.now(timezone.utc).timestamp()
                        v = f"{datetime.fromtimestamp(v, timezone.utc):%H:%M:%SZ}  ({int(left)//60} min left)"
                    if k == "email_verified" and v is False:
                        v = c(RED, "false  <- and 'email' is present. Account-takeover path.")
                    print(f"       {k:<20} {v}")
        else:
            print(f"       {c(DIM, 'opaque — not a JWT, which is a legitimate choice for an access token')}")

    print()
    print(c(CYA, "  ── what to take away " + "─" * 52))
    print("""
     Confusing the ID token and the access token is the most common OIDC
     integration bug, and it produces real vulnerabilities: applications
     accepting an ID token as an API credential, or reading an access token
     as an identity assertion.

     Rule of thumb:
       ID token      -> your app, once, at login
       access token  -> the API, with every request

     Now decode them properly, and check what your application would trust:
       ./jwt-decode.py "<id_token>" --jwks {jwks}
""".format(jwks=meta.get("jwks_uri", "<jwks uri>")))


if __name__ == "__main__":
    main()
