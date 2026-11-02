# Session 15 — samples

**Tagus Logística** (`tagus-logistica.example`) survived October: a phished
finance clerk, two transfers of just under €50 000, a compromised web server
(Sessions 6–8). The Board concluded what boards conclude: *move to the cloud,
where security is the provider's job*. A contractor, **NuvemCerta, Lda.**
(`nuvemcerta.example`), did it in three weeks and declared it production-ready.

You have just inherited it. Everything here is what they handed over, plus a few
things they did not mean to.

Everything is invented. AWS account IDs are the ones AWS reserves for
documentation (`111122223333`, `444455556666`, `777788889999`), IPs are RFC 5737,
domains are `.example`, and the database password opens nothing anywhere. It does
look like a real password, which is the point of Exercise 11.

```bash
shasum -a 256 -c SHA256SUMS      # cloud evidence is still evidence
```

## What is here

| Path | What it is | Exercises |
|---|---|---|
| `handover-nuvemcerta.md` | The contractor's handover note, ticks included | 1, 2 |
| `buckets/*.json` | `aws s3api get-*` output for three buckets, as NuvemCerta collected it | 3, 5 |
| `iam/policies/*.json` | The five identity policies in use | 6, 8, 9 |
| `iam/trust/*.json` | The trust policies of three roles: who may *become* them | 7 |
| `iam/scp-deny-public-buckets.json` | The guardrail NuvemCerta proposed for the organisation | 14 |
| `cloudtrail/nonprod-2025-11-25.json.gz` | One day of CloudTrail from the **non-prod** account, while the invoice processor was being tested | 3, 7, 8 |
| `terraform/` | The contractor's Terraform repository: module, CI workflow, and a state file that was committed with it | 3, 11, 12 |

## The accounts

| Account | What it is | Region(s) in use |
|---|---|---|
| `111122223333` | Tagus **prod** | `eu-west-1`, and one that nobody chose (Exercise 3) |
| `444455556666` | Tagus **non-prod** | `eu-west-1`, `us-east-1` |
| `777788889999` | **NuvemCerta's own account**, trusted by a role in prod | not yours |

## About the CloudTrail file

It is a single JSON document with a `Records` array, the shape CloudTrail writes
to S3, reduced to the fields that matter. One day, about a hundred records, all
UTC, as CloudTrail always is. It contains the invoice processor doing its job, a
contractor's console session, and two GitHub Actions runs. Only one of those
runs was expected.

Non-prod had **data events** enabled when the day started. Look carefully at
what that means for the rest of the day. Exercise 8 depends on it, and so does
any claim you make about who read what.

Event names are CloudTrail's, not IAM's. They are not always the same word
(`HeadObject`, `ListObjects`, `UpdateFunctionCode20150331v2`). That difference is
half of Exercise 8.

## About the Terraform state

`terraform/state-from-contractor-repo.json` is a Terraform state file, trimmed to
the resources the exercises need. It is not called `terraform.tfstate` because
this repository's `.gitignore` refuses to commit files with that name, which is
exactly the protection NuvemCerta's repository did not have.

## Handling

The usual: hash on arrival, work in `out/` (git-ignored), notes as you go, in
UTC. And one cloud-specific rule:

> **None of this touches a real AWS account.** The labs run against local
> emulators with fake credentials, in a profile of their own. If you ever see an
> account ID in a response that is not `000000000000` (LocalStack) or
> `123456789012` (Moto), stop and find out why before running anything else.
