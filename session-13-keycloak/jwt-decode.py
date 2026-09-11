#!/usr/bin/env python3
"""
jwt-decode.py — decode a token locally, because pasting a real one into a
website is how a lab token becomes a production incident.

It decodes, it checks the claims your application must check, and it does NOT
verify the signature unless you hand it a JWKS — because a tool that says
"valid!" without verifying anything is worse than no tool.

Usage
    ./jwt-decode.py <token>
    ./jwt-decode.py --file token.txt
    ./jwt-decode.py <token> --jwks http://localhost:8080/realms/blueteam/protocol/openid-connect/certs
    ./jwt-decode.py <token> --expect-iss http://localhost:8080/realms/blueteam --expect-aud my-app
    echo "$TOKEN" | ./jwt-decode.py -

Most JWT vulnerabilities are not cryptographic. They are applications that
decode without verifying, or trust a claim they should not. This prints exactly
which claims you are trusting, so the second one is a decision rather than an
accident.
"""

import argparse
import base64
import json
import sys
from datetime import datetime, timezone

TTY = sys.stdout.isatty()
def c(code, s): return f"\033[{code}m{s}\033[0m" if TTY else s
RED, YEL, GRN, DIM, BOLD, CYA = "31", "33", "32", "2", "1", "36"

# Claims an application must check, and what goes wrong when it does not.
MUST_CHECK = {
    "iss": "Is this MY issuer? A token from another realm is still a valid token.",
    "aud": "Is this token FOR ME? An access token for another client is not yours to accept.",
    "exp": "Still valid? Allow a little clock skew, not a lot.",
    "nbf": "Not before — rare, and it bites when it is present.",
}

INTERESTING = {
    "azp":            "authorised party — which client obtained this",
    "sub":            "the stable user identifier. Use THIS as the key, not email.",
    "email":          "an attribute, not an identity",
    "email_verified": "if false and you trust 'email', that is account takeover",
    "acr":            "authentication context — how strongly they proved it",
    "amr":            "authentication methods used",
    "typ":            "Bearer / ID / Refresh — do not confuse them",
    "scope":          "what was requested",
    "realm_access":   "Keycloak realm roles",
    "resource_access":"Keycloak client roles",
    "sid":            "session id — useful for revocation",
    "jti":            "token id — useful for replay detection",
}


def b64url(seg):
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def ts(v):
    try:
        return datetime.fromtimestamp(int(v), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return str(v)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("token", nargs="?", help="the JWT, or - for stdin")
    ap.add_argument("--file")
    ap.add_argument("--jwks", help="JWKS URL — only then is the signature checked")
    ap.add_argument("--expect-iss")
    ap.add_argument("--expect-aud")
    args = ap.parse_args()

    if args.file:
        token = open(args.file).read().strip()
    elif args.token == "-" or not args.token:
        token = sys.stdin.read().strip()
    else:
        token = args.token.strip()

    token = token.replace("Bearer ", "").strip().strip('"').strip("'")
    parts = token.split(".")
    if len(parts) != 3:
        sys.exit(f" fail  that is not a JWT ({len(parts)} segment(s), expected 3)")

    try:
        header = json.loads(b64url(parts[0]))
        payload = json.loads(b64url(parts[1]))
    except Exception as exc:
        sys.exit(f" fail  could not decode: {exc}")

    print()
    print(c(CYA, "── header " + "─" * 62))
    print(json.dumps(header, indent=2))

    alg = header.get("alg", "")
    if alg.lower() == "none":
        print()
        print(c(RED, '  !! alg is "none". If a library accepts this, anyone can mint tokens.'))
    if alg.startswith("HS"):
        print()
        print(c(YEL, "   ! symmetric algorithm (HS*). The verification key is the signing key."))
        print(c(DIM,  "     An attacker with the client secret can mint tokens. Prefer RS/ES."))

    print()
    print(c(CYA, "── payload " + "─" * 61))
    print(json.dumps(payload, indent=2, default=str))

    print()
    print(c(CYA, "── what your application MUST check " + "─" * 36))
    now = datetime.now(timezone.utc).timestamp()
    for claim, why in MUST_CHECK.items():
        v = payload.get(claim)
        if v is None:
            mark = c(DIM, "absent")
            if claim in ("iss", "aud"):
                mark = c(RED, "ABSENT")
            print(f"  {claim:<6} {mark}")
            print(f"         {c(DIM, why)}")
            continue
        extra = ""
        if claim in ("exp", "nbf"):
            delta = int(v) - now
            if claim == "exp":
                extra = (c(RED, f"  EXPIRED {int(-delta)//60} min ago") if delta < 0
                         else c(GRN, f"  valid for another {int(delta)//60} min"))
                if delta > 3600:
                    extra += c(YEL, "  <- long-lived; a stolen token stays useful")
            v = f"{ts(v)}"
        print(f"  {claim:<6} {v}{extra}")
        print(f"         {c(DIM, why)}")

    if args.expect_iss:
        good = payload.get("iss") == args.expect_iss
        print()
        print(("  " + c(GRN, "iss matches")) if good else
              ("  " + c(RED, f"iss MISMATCH: {payload.get('iss')} != {args.expect_iss}")))
    if args.expect_aud:
        aud = payload.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        good = args.expect_aud in auds
        print(("  " + c(GRN, "aud matches")) if good else
              ("  " + c(RED, f"aud MISMATCH: {aud} does not contain {args.expect_aud}")))

    print()
    print(c(CYA, "── claims worth noticing " + "─" * 47))
    for claim, why in INTERESTING.items():
        if claim in payload:
            v = payload[claim]
            v = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
            flag = ""
            if claim == "email_verified" and payload[claim] is False:
                flag = c(RED, "  <- and 'email' is present. That combination is an account-takeover path.")
            print(f"  {claim:<16} {v[:60]}{flag}")
            print(f"                   {c(DIM, why)}")

    print()
    print(c(CYA, "── signature " + "─" * 59))
    if not args.jwks:
        print(c(YEL, "  NOT VERIFIED."))
        print(c(DIM, "  This tool decoded the token. Decoding is not verifying, and an"))
        print(c(DIM, "  application that stops here is the most common JWT vulnerability"))
        print(c(DIM, "  there is. Pass --jwks to actually check it."))
    else:
        try:
            import urllib.request
            with urllib.request.urlopen(args.jwks, timeout=10) as r:
                jwks = json.load(r)
            kid = header.get("kid")
            key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
            if not key:
                print(c(RED, f"  no key with kid={kid} in the JWKS"))
                print(c(DIM,  "  the token was signed by a key this issuer does not publish"))
            else:
                print(c(GRN, f"  kid {kid} found in JWKS (alg {key.get('alg')}, use {key.get('use')})"))
                try:
                    import jwt as pyjwt  # PyJWT, if present
                    from jwt import PyJWKClient
                    signing = PyJWKClient(args.jwks).get_signing_key_from_jwt(token)
                    pyjwt.decode(token, signing.key,
                                 algorithms=[header.get("alg")],
                                 audience=args.expect_aud,
                                 issuer=args.expect_iss,
                                 options={"verify_aud": bool(args.expect_aud),
                                          "verify_iss": bool(args.expect_iss)})
                    print(c(GRN, "  SIGNATURE VERIFIED"))
                except ModuleNotFoundError:
                    print(c(YEL, "  PyJWT not installed — key located, signature not checked"))
                    print(c(DIM,  "  pip install pyjwt[crypto] to complete this"))
                except Exception as exc:
                    print(c(RED, f"  VERIFICATION FAILED: {exc}"))
        except Exception as exc:
            print(c(RED, f"  could not fetch JWKS: {exc}"))
    print()


if __name__ == "__main__":
    main()
