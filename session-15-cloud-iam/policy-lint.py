#!/usr/bin/env python3
"""
policy-lint.py — read an IAM policy the way an attacker would.

It does not care whether the policy is valid JSON that AWS accepts. It cares
whether the policy grants more than it says it does, which is a different
question and the one that gets exploited.

Usage
    ./policy-lint.py policy.json
    ./policy-lint.py policy.json --trust        it is a role trust policy
    ./policy-lint.py *.json --brief
    ./policy-lint.py policy.json --explain      the escalation paths, spelled out

Exit code is the number of HIGH findings, so it gates a pipeline.
"""

import argparse
import json
import re
import sys
from pathlib import Path

TTY = sys.stdout.isatty()
def c(code, s): return f"\033[{code}m{s}\033[0m" if TTY else s
RED, YEL, GRN, DIM, CYA, BOLD = "31", "33", "32", "2", "36", "1"

# Actions that let the holder grant themselves more than they have. Anything in
# here is effectively administrator, whatever the policy is called.
ESCALATION = {
    "iam:PassRole": "attach a more privileged role to a resource you control",
    "iam:CreatePolicyVersion": "rewrite an existing policy, including your own",
    "iam:SetDefaultPolicyVersion": "activate an older, broader version of a policy",
    "iam:AttachUserPolicy": "attach any managed policy to yourself",
    "iam:AttachRolePolicy": "attach any managed policy to a role you can assume",
    "iam:AttachGroupPolicy": "attach any managed policy to your group",
    "iam:PutUserPolicy": "write yourself an inline policy",
    "iam:PutRolePolicy": "write an inline policy onto a role",
    "iam:PutGroupPolicy": "write an inline policy onto a group",
    "iam:CreateAccessKey": "mint credentials for another principal",
    "iam:CreateLoginProfile": "set a console password on another principal",
    "iam:UpdateLoginProfile": "change another principal's console password",
    "iam:UpdateAssumeRolePolicy": "let yourself, or anyone, assume a role",
    "iam:CreateRole": "create a role, then pass it",
    "sts:AssumeRole": "become another principal (check the trust policy)",
    "lambda:CreateFunction": "run code as a role, given iam:PassRole",
    "lambda:UpdateFunctionCode": "replace the code a privileged function runs",
    "ec2:RunInstances": "run code as an instance profile, given iam:PassRole",
    "glue:CreateDevEndpoint": "a shell as a passed role",
    "cloudformation:CreateStack": "create anything, as the stack's role",
    "ssm:SendCommand": "run commands on instances, as their role",
    "ssm:StartSession": "a shell on an instance",
}

# Pairs that are far worse together than apart.
COMBOS = [
    ({"iam:PassRole", "lambda:CreateFunction"}, "run arbitrary code as any role you can pass"),
    ({"iam:PassRole", "ec2:RunInstances"}, "boot an instance carrying any role you can pass"),
    ({"iam:PassRole", "cloudformation:CreateStack"}, "create anything, as any role you can pass"),
    ({"iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"}, "rewrite and activate your own permissions"),
]

EXPLAIN = """
  WHY iam:PassRole IS THE ONE TO INTERNALISE

  PassRole on its own does nothing. Combined with a service that runs code —
  Lambda, EC2, ECS, Glue, CloudFormation — it becomes "run whatever I like as
  whatever role I am allowed to pass". If the Resource is "*", that is every
  role in the account, which includes the administrative ones.

  The fix is not to remove PassRole. Services need it. The fix is to constrain
  the Resource to the specific role ARNs that principal may pass, and to add
  the iam:PassedToService condition so it can only be passed to the service you
  intended.

      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::123456789012:role/app-execution-role",
      "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}

  THE TWO ARNs PEOPLE CONFUSE

      arn:aws:s3:::bucket        the bucket itself.  s3:ListBucket lives here.
      arn:aws:s3:::bucket/*      the objects in it.  s3:GetObject lives here.

  A policy naming one and not the other fails in a way that looks like a
  permissions bug and is a reading-comprehension bug. It is also how "Resource":
  "arn:aws:s3:::bucket/*" ends up alongside a wildcard action, because somebody
  widened the action while debugging the resource.

  CONDITIONS ARE THE MOST UNDERUSED ELEMENT IN CLOUD SECURITY

  Scope by circumstance, not only by identity and resource:
      aws:SecureTransport          require TLS
      aws:SourceVpce               only from your VPC endpoint
      aws:PrincipalOrgID           only principals in your organisation
      aws:MultiFactorAuthPresent   only with MFA
      s3:x-amz-server-side-encryption   only encrypted writes
"""


def findings_for(doc, is_trust=False):
    out = []
    def F(sev, title, detail=""):
        out.append((sev, title, detail))

    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]

    for i, st in enumerate(stmts, 1):
        sid = st.get("Sid") or f"statement {i}"
        effect = st.get("Effect", "")
        acts = st.get("Action") or st.get("NotAction") or []
        acts = [acts] if isinstance(acts, str) else list(acts)
        res = st.get("Resource") or st.get("NotResource") or []
        res = [res] if isinstance(res, str) else list(res)
        cond = st.get("Condition") or {}
        princ = st.get("Principal")

        if "NotAction" in st and effect == "Allow":
            F("high", f"{sid}: Allow with NotAction",
              "allows everything except the listed actions, including actions that do not exist yet")
        if "NotResource" in st and effect == "Allow":
            F("high", f"{sid}: Allow with NotResource",
              "same shape, same problem, on resources")

        if effect != "Allow":
            continue

        if "*" in acts:
            F("high", f"{sid}: Action is \"*\"", "every action in every service")
        for a in acts:
            if a.endswith(":*"):
                F("med", f"{sid}: whole-service wildcard {a}",
                  "includes the destructive and the identity-changing ones")

        if "*" in res:
            sev = "high" if any(a == "*" or a.endswith(":*") or a in ESCALATION for a in acts) else "med"
            F(sev, f"{sid}: Resource is \"*\"", "every resource in the account")

        for a in acts:
            base = a.split(":")[0] + ":*"
            hit = ESCALATION.get(a) or (ESCALATION.get(base) if base in ESCALATION else None)
            if hit:
                unconstrained = "*" in res
                F("high" if unconstrained else "med",
                  f"{sid}: {a}" + ("  (Resource: *)" if unconstrained else ""),
                  hit)
            elif a.endswith(":*") and a.split(":")[0] in {"iam", "sts", "lambda", "cloudformation", "ssm"}:
                F("high", f"{sid}: {a} includes escalation actions",
                  "the wildcard covers the ones in the escalation catalogue")

        act_set = set(acts)
        for combo, why in COMBOS:
            if combo <= act_set or ("*" in act_set):
                if combo <= act_set:
                    F("high", f"{sid}: {' + '.join(sorted(combo))}", why)

        if "iam:PassRole" in acts and "*" in res and "iam:PassedToService" not in json.dumps(cond):
            F("high", f"{sid}: iam:PassRole on * with no PassedToService condition",
              "pass any role to any service — this is the escalation path, complete")

        # s3 bucket vs objects
        for r in res:
            if isinstance(r, str) and r.startswith("arn:aws:s3:::") and "/" not in r[13:]:
                if any(a in ("s3:GetObject", "s3:PutObject", "s3:DeleteObject") for a in acts):
                    F("med", f"{sid}: object actions on a bucket ARN",
                      f"{r} is the bucket; objects are {r}/*  — this will not work as written")
            if isinstance(r, str) and r.endswith("/*") and "s3:ListBucket" in acts:
                F("med", f"{sid}: s3:ListBucket on an object ARN",
                  "ListBucket applies to the bucket ARN, not to bucket/*")

        if not cond and effect == "Allow" and not is_trust:
            F("low", f"{sid}: no Condition",
              "the most underused element in cloud security — scope by circumstance too")
        elif cond and "aws:SecureTransport" not in json.dumps(cond) and not is_trust:
            F("low", f"{sid}: no aws:SecureTransport condition", "require TLS explicitly")

        if is_trust or princ is not None:
            p = json.dumps(princ)
            if princ == "*" or '"AWS": "*"' in p.replace(" ", " "):
                F("high", f"{sid}: Principal is \"*\"",
                  "anyone, in any account, anywhere — unless a Condition narrows it, and there is none" if not cond else
                  "anyone, narrowed only by the Condition. Read that Condition very carefully.")
            if re.search(r'arn:aws:iam::\d+:root', p):
                F("med", f"{sid}: trusts an entire account (:root)",
                  "every principal in that account, present and future")
            if "Federated" in p and "sts:AssumeRoleWithWebIdentity" in json.dumps(acts):
                if "StringEquals" not in json.dumps(cond) and "StringLike" not in json.dumps(cond):
                    F("high", f"{sid}: web identity federation with no subject condition",
                      "any repository, any user of that identity provider, can assume this role")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*")
    ap.add_argument("--trust", action="store_true", help="treat as a role trust policy")
    ap.add_argument("--brief", action="store_true")
    ap.add_argument("--explain", action="store_true")
    args = ap.parse_args()

    if args.explain:
        print(EXPLAIN); return
    if not args.files:
        ap.print_help(); sys.exit(1)

    total_high = 0
    for path in args.files:
        p = Path(path)
        if not p.is_file():
            print(f" fail  no such file: {path}", file=sys.stderr); continue
        try:
            doc = json.loads(p.read_text())
        except json.JSONDecodeError as exc:
            print(f" fail  {path}: not JSON ({exc})", file=sys.stderr); continue

        f = findings_for(doc, args.trust)
        highs = [x for x in f if x[0] == "high"]
        total_high += len(highs)

        print()
        print(f"  {c(BOLD, p.name)}   {len(f)} finding(s)")
        if not f:
            print(c(GRN, "  nothing flagged — which is not the same as least privilege"))
            print(c(DIM, "  a policy can be tightly scoped and still grant more than the task needs"))
            continue
        order = {"high": 0, "med": 1, "low": 2}
        for sev, title, detail in sorted(f, key=lambda x: order[x[0]]):
            mark = {"high": c(RED, "  !!"), "med": c(YEL, "   !"), "low": c(DIM, "    ")}[sev]
            print(f"{mark} {title}")
            if detail and not args.brief:
                print(f"      {c(DIM, detail)}")

    print()
    if total_high:
        print(f"  {c(RED, str(total_high) + ' HIGH finding(s)')}")
        print(c(DIM, "  ./policy-lint.py --explain   for the escalation paths, spelled out"))
    else:
        print(c(GRN, "  no HIGH findings"))
    print()
    print(c(DIM, "  And the check no linter can do: run the task with this policy, then run"))
    print(c(DIM, "  something OUTSIDE the task and confirm it fails. Without that negative"))
    print(c(DIM, "  test, a reduction is a guess with better formatting."))
    print()
    sys.exit(min(total_high, 125))


if __name__ == "__main__":
    main()
