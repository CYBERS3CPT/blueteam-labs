# Session 15 — Principles of Cloud Computing

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

Question 4 is the one that bites. Server access logging covers the management
plane. Data-plane events — who *read* which object — are a separate setting,
usually off by default and separately billed. An attacker who reads ten thousand
objects generates one event, or none.

### `up` sets fake credentials on purpose

`aws configure set aws_access_key_id test` is not laziness. Without it the CLI
falls back to your **real** profile when the endpoint override is missed, and a
lab exercise becomes a live API call against an account you care about.

### `negative` is the half everyone skips

A policy reduction is proven by two results, not one: the task still works, **and**
something outside the task now fails. A reduction you did not test is a guess with
better formatting.

It also tells you the truth about LocalStack: it does not enforce IAM the way the
real thing does. "Tested against LocalStack" is an honest methodology line, and
writing it is better than implying a verification you did not perform.

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
