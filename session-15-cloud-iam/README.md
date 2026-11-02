# Session 15 — Principles of Cloud Computing

> **Exercises:** [`EXERCISES.md`](EXERCISES.md), sixteen of them, on the fixtures in
> [`samples/`](samples/): Tagus Logística's brand-new cloud, as a contractor
> handed it over. Bucket dumps, five policies, three trust policies, a day of
> CloudTrail, and a Terraform repository with its state file still in it.

## `localstack-lab.sh`

```bash
./localstack-lab.sh up
./localstack-lab.sh bucket blueteam-lab-data
./localstack-lab.sh posture blueteam-lab-data   # the four questions
./localstack-lab.sh harden blueteam-lab-data    # answer them properly
./localstack-lab.sh policy-lab                  # the reduction exercise
./localstack-lab.sh negative blueteam-lab-data  # prove something is denied
```

### The four questions

They belong to **any** storage resource in **any** provider, and they are the
whole of `posture`:

1. Can the public reach it?
2. Is it encrypted, and **who holds the key**?
3. Is versioning on? *(this is a ransomware control)*
4. Is access logged — **data-plane**, not just management-plane?

Question 4 is the one that bites. Server access logs do record object reads, but
on a best-effort basis, hours late, with no integrity validation, and usually into
a bucket that the same people can delete from. The audit-grade answer to "who
*read* which object" is CloudTrail **data events**: a separate setting, off by
default, and billed per event. Management events alone record that the bucket was
configured, not that it was emptied. With neither, an attacker who reads ten
thousand objects leaves no trace at all.

### `up` sets fake credentials on purpose, in a profile of their own

`aws configure set aws_access_key_id test --profile blueteam-lab` is not laziness.
Without fake credentials the CLI falls back to your **real** ones when the
endpoint override is missed, and a lab exercise becomes a live API call against
an account you care about. And without `--profile`, `aws configure set` writes
into `[default]` and silently replaces whatever was there, which might be your
employer's keys.

### The image is pinned, and that is deliberate

Since March 2026 the `localstack/localstack` image refuses to start without an
account token, so `latest` stopped being a lab and started being a sign-up form.
The script pins `4.14.0`, the last release that starts without one. It is
frozen, which for S3 and IAM basics does not matter. If you have a token, set
`LS_IMAGE` and `LOCALSTACK_AUTH_TOKEN` and the script passes it through.

### `negative` is the half everyone skips

A policy reduction is proven by two results, not one: the task still works, **and**
something outside the task now fails. A reduction you did not test is a guess with
better formatting.

It also tells you the truth about LocalStack: without a paid plan it does not
enforce IAM at all. "Tested against LocalStack" is an honest methodology line,
and writing it is better than implying a verification you did not perform.
Exercise 9 runs the same negative test against **Moto**, which does enforce
identity policies, and Exercise 10 measures where each emulator is still wrong.

### The ARN mistake

`arn:aws:s3:::bucket` and `arn:aws:s3:::bucket/*` are different resources.
`ListBucket` lives on the first, `GetObject` on the second. A policy naming one
and not the other fails in a way that looks like a permissions bug and is a
reading-comprehension bug. `policy-lab` says so, because everyone does it once.

---

## `policy-lint.py`

```bash
./policy-lint.py policy.json
./policy-lint.py trust.json --trust
./policy-lint.py policies/*.json --brief
./policy-lint.py --explain              # the escalation paths, spelled out
```

Exit code is the number of HIGH findings, so it gates a pipeline.

### It does not check whether AWS would accept the policy

It checks whether the policy **grants more than it says it does**, which is a
different question and the one that gets exploited.

### `iam:PassRole` is the one to internalise

On its own it does nothing. Combined with a service that runs code — Lambda, EC2,
ECS, Glue, CloudFormation — it becomes *"run whatever I like as whatever role I
am allowed to pass"*. With `"Resource": "*"` that is every role in the account,
including the administrative ones.

The fix is not to remove it. Services need it. The fix is a constrained resource
and an `iam:PassedToService` condition, and the linter flags its absence.

It also flags the **combinations** that are far worse together than apart:
`PassRole` + `CreateFunction`, `CreatePolicyVersion` + `SetDefaultPolicyVersion`.

### The two S3 ARNs

`arn:aws:s3:::bucket` is the bucket — `ListBucket` lives there.
`arn:aws:s3:::bucket/*` is the objects — `GetObject` lives there.

A policy naming one and not the other fails in a way that looks like a
permissions bug and is a reading-comprehension bug. The linter catches both
directions.

### "Nothing flagged" is not "least privilege"

It says so:

> a policy can be tightly scoped and still grant more than the task needs

And it ends by reminding you of the check no linter can do: run the task, then
run something outside the task and confirm it fails. `localstack-lab.sh negative`
does that half.
