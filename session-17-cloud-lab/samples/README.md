# Session 17 — samples

**Tagus Logística**, two weeks after the Friday in Session 16. Rita wanted an
independent opinion before the Board met in January, so Tiago engaged an
assessment firm, Rede Azul Segurança, for a week of testing against non-prod.
These are the papers from that week. There is no attack log here, and no
record of what the assessors did. This session is about the parts of an
assessment that come before the attack and after it: the scope that was signed,
the teardown that was reported, and what Tiago found when he looked for himself.

1. **12 December.** The scope document, built with `scope.sh new`, edited by
   hand, signed.
2. **15–19 December.** The testing window.
3. **19 December, 18:47.** Marta Lopes (Rede Azul) emails: testing complete,
   teardown done, sweep attached, clean.
4. **22 December.** Tiago looks anyway, with his own admin user, and writes
   down what he finds. His notes end with four questions.

Everything is invented. Account IDs are AWS's documentation IDs (and
`210987654321`, which stands for the assessment firm's account), domains are
`.example`, and the phone numbers are deliberately not valid numbers. The JSON
files have the shape the AWS CLI returns for the commands Tiago's notes name,
so `jq` against them works as it would against the real thing.

```bash
shasum -a 256 -c SHA256SUMS
```

## What is here

| Path | What it is | Exercises |
|---|---|---|
| `engagement/tagus-nonprod-scope-v1.md` | The signed scope, in `scope.sh` format | 1, 2, 4 |
| `engagement/closing-email.txt` | Rede Azul's closing email, 19 December | 4, 8, 11 |
| `engagement/teardown-sweep-2025-12-19.txt` | The sweep output attached to that email | 8 |
| `engagement/redeazul-assessor-role.json` | The cross-account role they asked to keep, with its policy | 8, 11 |
| `inventory/tiago-notes.md` | What Tiago did on the 22nd, in his words | 10, 11 |
| `inventory/cost-explorer-nonprod-*.csv` | Daily cost by usage type, non-prod, 12–22 Dec | 10 |
| `inventory/lambda-functions-eu-west-1.json` | `aws lambda list-functions`, one region | 10 |
| `inventory/lambda-tags-ra-oidc-probe.json` | `aws lambda list-tags` for the function that should not be there | 10 |
| `inventory/iam-roles-created-in-december.json` | Roles created in December, copied by hand from the console | 10 |
| `inventory/iam-credential-report-444455556666.csv` | The IAM credential report | 10 |
| `inventory/secret-policy-tagus-invoices-db-nonprod.json` | `aws secretsmanager get-resource-policy` | 10 |
| `inventory/snapshots-us-east-2.json` | `aws ec2 describe-snapshots`, us-east-2 | 10 |
| `inventory/snapshot-attribute-*.json` | `aws ec2 describe-snapshot-attribute` | 10 |

## The accounts

| Account | What it is |
|---|---|
| `444455556666` | Tagus **non-prod**, the account the assessment was for |
| `111122223333` | Tagus **prod** |
| `777788889999` | NuvemCerta, the contractor from Sessions 15–16 |
| `210987654321` | Rede Azul Segurança, the assessment firm |

## The people

| Name | Who |
|---|---|
| Rita Almeida | CEO, Tagus Logística |
| Tiago Fonseca | IT, Tagus. Runs the cloud, signed the scope |
| Marta Lopes | Assessment lead, Rede Azul Segurança |
| Rui Costa | NuvemCerta, still holding a support role (Session 15) |

## Handling

Hash on arrival, work in `out/` (git-ignored), notes as you go, in UTC. Do not
delete anything in your head yet either: Exercise 11 asks whether one of the
things on this list is evidence.
