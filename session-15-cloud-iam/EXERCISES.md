# Session 15 — Exercises

Hands-on and Kali-first, built on `localstack-lab.sh` and `policy-lint.py`, on
the fixtures in `samples/`, and on two local AWS emulators. Nothing here touches
a real AWS account, and nothing needs a credit card. Everything is fictional and
everything is defensive: you are not breaking into Tagus's cloud, you are finding
out what is already wrong with it before somebody else does.

**The case so far.** *Tagus Logística* was phished (Session 6), lost two transfers
of just under €50 000, and had its web server compromised through three
configuration files (Sessions 7–8). The Board's answer was the cloud. A contractor,
NuvemCerta, built it in three weeks, ticked every box in the handover note, and
kept a support role for themselves. The handover is in `samples/`. So is a day of
CloudTrail they did not think anybody would read.

The client's question: *"Is it safe now?"* The honest answer starts with "which
part, according to what evidence, and who is responsible for it?". Tonight you
build that answer.

## Before you start

```bash
cd blueteam-labs/session-15-cloud-iam
sudo apt install -y awscli jq docker.io trivy gitleaks
pipx install checkov                      # or: docker run bridgecrew/checkov
mkdir -p out                              # git-ignored
(cd samples && shasum -a 256 -c SHA256SUMS)
gunzip -c samples/cloudtrail/nonprod-2025-11-25.json.gz > out/trail.json
echo "$(date -u +%FT%TZ)  START  session 15 exercises" > out/my-notes.txt
```

Terraform: Kali does not package it. Either install it from HashiCorp's apt
repository, use OpenTofu (`tofu`, same commands, open licence), or run it from a
container: `docker run --rm --network host -v "$PWD":/tf -w /tf hashicorp/terraform:1.17 <command>`.

Ground rules:

- **Fake credentials only, in their own profile.** `localstack-lab.sh` creates the
  profile `blueteam-lab`; Exercise 9 adds `moto-*`. Never put a real key in either.
  If you have real AWS credentials on this machine, run `cat ~/.aws/credentials`
  now and know which profile they are in. Exercise 4 explains why this matters.
- **Check the account ID before you trust a result.** LocalStack answers
  `000000000000`, Moto `123456789012`. Anything else means you are not where you
  think you are.
- **Name the source for every claim.** "The DB is in the US" is not a finding
  until it says which file, which field, which value.

| # | Exercise | Tools | Time |
|---|---|---|---|
| 1 | Read the handover like an auditor | a pencil | 15 min |
| 2 | Shared responsibility, Tagus edition | a pencil | 15 min |
| 3 | Where does the data actually live? | `jq` | 20 min |
| 4 | A lab that cannot reach AWS | `localstack-lab.sh up` | 10 min |
| 5 | The four questions, from someone else's dump | `jq` | 20 min |
| 6 | Read the policies like an attacker | `policy-lint.py` | 25 min |
| 7 | Trust policies: who can become you | `policy-lint.py --trust`, `jq` | 25 min |
| 8 | From the trail to the policy | `jq` | 30 min |
| 9 | Reduce, and prove the negative — twice | LocalStack, Moto | 35 min |
| 10 | Two emulators, three answers | your notes | 15 min |
| 11 | State is a secret | `jq`, `gitleaks` | 15 min |
| 12 | Scan it, then read the scanners | `checkov`, `trivy` | 25 min |
| 13 | Your module, against the lab | `terraform` / `tofu` | 30 min |
| 14 | A guardrail that never fires | a pencil, the IAM docs | 20 min |
| 15 | Patch the linter | `policy-lint.py`, your editor | 20 min |
| 16 | The deliverable | everything above | 60 min+ |

Exercises 1–3 are Block 1 (definitions, on a real case), 4–10 Block 2 (identity
and storage), 11–15 Block 3 (infrastructure as code and guardrails). The
deliverable is due before Session 16; Session 16 scans what you build here.

---

## 1 · Read the handover like an auditor

Read `samples/handover-nuvemcerta.md` once, end to end, without stopping. Then
again with a pencil.

1. The note makes seven claims about security (the bullet list, the ticks, and the
   sentence about the provider). For each one: is it **true**, **false**,
   **unverifiable as written**, or **true and irrelevant**? One line of reasoning
   per claim.
2. *"Everything is in the cloud, so physical security, patching and availability
   are AWS's responsibility now."* Which service in the table makes this sentence
   false in all three of its parts? (Look at what WEB-02 is running.)
3. *"All data is encrypted, so RGPD is covered."* Write the two-sentence reply you
   would send to the Board. Encryption at rest answers which of the RGPD questions,
   and which ones does it not even touch?
4. *"Region: we used the default region."* What is the default region, and who
   chose it? Keep the question open: Exercise 3 answers it with evidence.
5. *"Checkov runs on every deployment. ✅ 0 failed checks."* Hold that thought
   until Exercise 12. Write down now what would have to be true for that tick to
   mean anything.

---

## 2 · Shared responsibility, Tagus edition

Draw the shared responsibility diagram from the slides **by hand**, then make it
Tagus-specific: one column per service in the handover table (Microsoft 365,
invoice-processor, the S3 buckets, RDS, WEB-02, the SFTP service, GitHub Actions).

1. Classify each one: IaaS, PaaS, SaaS, FaaS. Two are arguable. Say which, and
   argue one way.
2. For each, write **one control that is unambiguously Tagus's** and how you would
   evidence it to an auditor: the command, the export, or the screenshot.
3. In Session 8, WEB-01 was compromised through three configuration files.
   Under the new architecture, which of those three problems moved to the
   provider, which still belong to Tagus, and which simply moved to a different
   file? (The two rows that never move in the diagram are your answer, if you
   need a hint.)
4. Pick the SFTP service. Name one thing you **cannot see** there, and what
   exactly you would ask the provider for, by document name if you know it.

---

## 3 · Where does the data actually live?

The handover says "the default region". Sovereignty questions are answered with
evidence, so collect it from three independent sources.

```bash
for f in samples/buckets/*.json; do jq -r '"\(.Bucket)\t\(.Region)"' "$f"; done

jq -r '.resources[] | .type as $t | .instances[].attributes
       | [$t, (.arn // .id), (.region // .availability_zone // "?")] | @tsv' \
   samples/terraform/state-from-contractor-repo.json

grep -n 'region' samples/terraform/*.tf

jq -r '.Records[] | select(.awsRegion != "eu-west-1")
       | [.eventTime, .eventName, .awsRegion, (.requestParameters.bucketName // "-")] | @tsv' out/trail.json
```

1. Build a table: resource, account, region, **source** (which file and field
   said so), and what data it holds. Where two sources agree, say so. Where only
   one source says it, say that too.
2. NuvemCerta did think about the region. Where, exactly, in `main.tf`? And what
   did they forget, given that **provider-level** defaults apply to every resource
   that does not override them? Which of Tagus's data ended up outside the EU,
   and is it more or less sensitive than the data they protected?
3. The trail shows activity in `us-east-1`. Separate the events that are regional
   by nature (some AWS services log global calls there) from the ones that put
   **Tagus data** there. Which bucket, created by whom, at what time (UTC)?
4. `tagus-ci-artifacts` holds `fixtures/clientes-faturacao-2025-10.csv`. Read the
   `fixtures/README.txt` field in its JSON. Name the **three** separate problems in
   that one sentence: where the data is, what kind of account it is in, and why it
   is there at all.
5. Write the sovereignty paragraph for the deliverable: where the data lives today,
   where it should, what the transfer mechanism would have to be if it stays, and
   what the fix costs (a `region` line is not a migration; a database is).

---

## 4 · A lab that cannot reach AWS

```bash
./localstack-lab.sh up
aws --profile blueteam-lab --endpoint-url=http://localhost:4566 sts get-caller-identity
cat ~/.aws/credentials
```

The script pins LocalStack to `4.14.0`. Since March 2026, newer images refuse to
start without an account token. The free Hobby plan exists, but it is for
non-commercial use, and its terms are LocalStack's to change. A frozen image is
fine for S3 and IAM basics. The point is that your lab does not depend on
someone else's licence. Read the comment at the top of the script.

1. What account ID does `get-caller-identity` return? Why is checking it the first
   thing you do in any cloud session, lab or not?
2. Look at `~/.aws/credentials`. The script writes fake keys to a profile called
   `blueteam-lab`. Read the comment above those lines. An earlier version wrote to
   `[default]`. Describe what that would have done on the laptop of a student who
   works at an AWS customer, and why the failure would have been **silent**.
3. Now run the same `get-caller-identity` **without** `--endpoint-url` but with
   `--profile blueteam-lab`. What happens, and why is that the safe failure? What
   would have happened with your real profile instead?

---

## 5 · The four questions, from someone else's dump

`localstack-lab.sh posture` asks four questions of a live bucket. Ask them of
NuvemCerta's dumps instead, where you cannot run anything and must read what is
there.

```bash
jq '{Bucket, Region, GetPublicAccessBlock, GetBucketPolicyStatus}' samples/buckets/tagus-invoices-prod.json
jq '{GetBucketEncryption, GetBucketVersioning, ListObjectVersions_summary}' samples/buckets/tagus-invoices-prod.json
jq '{GetBucketLogging, GetBucketLifecycleConfiguration, CloudTrailDataEvents}' samples/buckets/tagus-invoices-prod.json
```

For **each** of the three buckets, answer the four questions (public? encrypted,
and who holds the key? versioning? access logged?), and give the field that
answers each one.

1. `tagus-invoices-prod` has no public access block at bucket **or** account level,
   and yet `IsPublic: false`. Is it public? Is it *safe*? What is the difference,
   and what single action by one person would change the first answer?
2. Versioning is `Suspended`, not absent. What happened to the 212 noncurrent
   versions under `processed/`? What happens to the **next** overwrite? Is
   "versions cost money" a cost saving, given what is still stored?
3. The bucket logs into **itself**, under `logs/`, and a lifecycle rule deletes
   `logs/` after 7 days. List three consequences, at least one about evidence.
   And `CloudTrailDataEvents` says management events only: so if 10 000 invoices
   were read last Tuesday, which record of it exists, for how long, and who can
   delete it?
4. `tagus-website-assets` is public, and that is correct: it is a website. Now
   read its object listing. What is in `migration/`, whose files are they, and why
   is this the most serious finding on this page? (Session 8, Exercise 11.8 told
   you which three files on that host mattered. Assume `etc.tar.gz` holds `/etc`.)
5. For the website bucket, `BlockPublicPolicy` and `RestrictPublicBuckets` are
   `false`. Is that a finding? What would you change instead, so the site stays
   public but nothing else in it can be?

Record everything as **finding → evidence → fix**. Then do the fix for real on
your own bucket in LocalStack (`./localstack-lab.sh bucket`, then `harden`) and
check with `posture`. Note that `harden` does not fix logging. What would you add,
and **where** would the logs go?

---

## 6 · Read the policies like an attacker

```bash
./policy-lint.py samples/iam/policies/*.json
./policy-lint.py --explain | less
```

1. Rank the five policies from most to least dangerous **in your own judgement**,
   then compare with the linter's HIGH count. Where do you disagree, and why?
2. `invoice-app.json` gives the invoice processor `s3:*`, `kms:*` and
   `secretsmanager:*` on everything. Write the one-sentence attack path: "If the
   invoice processor is compromised, the attacker can…". Be concrete about
   *which* data, given what Exercise 3 found.
3. `ci-deploy.json` contains `iam:PassRole` on `*` and `lambda:CreateFunction`.
   The linter has a rule for exactly that combination
   (`--explain` describes it). Did it print the combination line? Read
   `findings_for()` and find out why not. Note it; Exercise 15 fixes it.
4. `support-readonly.json` is called *read only*. What can it actually do? Name
   three destructive actions it allows. Then look at the linter's output: two of
   its findings are about `iam:*`. Are they right, and for the right reason? (Read
   the policy again: where is `iam:*`?)
5. `backup-job.json` gets **zero** findings. Is it safe? Read the `WriteVault`
   and `ManageVault` statements and describe what an attacker who compromised the
   backup job could do to the backups, in two steps. Which word in the README
   ("Nothing flagged is not least privilege") is this an example of?
6. `finance-reports.json` came with a ticket: *"Finance get AccessDenied on the
   reports, NuvemCerta proposes s3:* to fix it."* The linter flags two problems in
   it. Are they real, given that the `Resource` lists **both** ARNs? (Each action
   only ever matches the ARN type it applies to. Is listing both in one statement
   wrong, or just untidy?) If the policy is not the cause, list three other things
   that produce an S3 `AccessDenied` and that you would check first. Then write
   the reply to the ticket. Widening a policy to make an error go away is how
   `s3:*` got into `invoice-app.json` in the first place.
7. `AppOcr` uses `"Resource": "*"` for `textract:AnalyzeExpense`, and the linter
   flags it. Look the action up in the AWS *Service Authorization Reference*:
   does it support resource-level permissions at all? When is `"*"` the only
   correct answer, and how do you justify it in the table so a reviewer does
   not flag it again?

---

## 7 · Trust policies: who can become you

An identity policy says what a role may do. The **trust** policy says who may
become the role. People audit the first and forget the second.

```bash
./policy-lint.py --trust samples/iam/trust/*.json
jq -r '.Records[] | select(.eventName=="AssumeRoleWithWebIdentity")
       | [.eventTime, .userIdentity.userName, .sourceIPAddress] | @tsv' out/trail.json
```

1. `ci-deploy-trust.json` trusts GitHub's OIDC provider and checks the audience.
   The linter says **nothing flagged**. What does the condition actually check, and
   what does it not? Who on the planet can assume this role?
2. The trail shows two `AssumeRoleWithWebIdentity` calls for `ci-deploy`. Which
   repository was expected, and which was not? Whose repository is the second, at
   what time (UTC), and what did the session do next? (Follow the session with
   `select(.userIdentity.arn? // "" | test("ci-deploy"))`.)
3. The unexpected session listed the buckets at 20:17. Did it **read** the
   customer file in `tagus-ci-artifacts`? Answer with evidence, or with the
   precise reason you cannot. (Find `PutEventSelectors` in the trail and read it.
   Who ran it, and at what time?) Then write the finding, the inference, and
   the limitation as three separate sentences.
4. Write the fixed trust policy. Use `StringEquals` on
   `token.actions.githubusercontent.com:sub`, pinned to
   `repo:tagus-logistica/invoice-processor:ref:refs/heads/main`. Then read GitHub's
   current documentation on **immutable subject claims**: for repositories created
   after 15 July 2026 the `sub` changes format. What breaks if Tagus recreates the
   repository and keeps your policy? Does it fail open or closed?
5. Since early 2026, IAM refuses to **create** a GitHub OIDC trust policy without
   a `sub` condition. This one exists anyway. Why, and what does that tell you
   about guardrails that only apply to new resources?
6. `contractor-access-trust.json` trusts `arn:aws:iam::777788889999:root`. Who is
   that, in practice? Add the two conditions you would require of a third-party
   support role (one is about **who** is calling, the other about **how** they
   authenticated), and explain the *confused deputy* problem the first one solves.
   Then read `main.tf`: what policy is attached to this role, and what does the
   comment next to it say?

---

## 8 · From the trail to the policy

The slides' honest method, step 2: run with broad permissions in non-prod, with
logging on, then read what was actually called. NuvemCerta did the first half.
You do the second.

```bash
# who is in this trail at all?
jq -r '.Records[] | (.userIdentity.arn // .userIdentity.userName // .userIdentity.invokedBy)' \
   out/trail.json | sort | uniq -c | sort -rn

# what did the processor's role call?
jq -r '.Records[] | select((.userIdentity.arn // "") | test("invoice-app-nonprod"))
       | [.eventSource, .eventName, (.userIdentity.invokedBy // "-")] | @tsv' \
   out/trail.json | sort | uniq -c

# S3 data events: from when, to when?
jq -r '.Records[] | select(.eventCategory=="Data") | .eventTime' out/trail.json | sort | sed -n '1p;$p'
jq -r '.Records[] | select(.eventName=="ListObjects") | .requestParameters.prefix' out/trail.json | sort -u
```

1. Filter **only** the processor's role. Who else is in the trail, and what would
   your policy look like if you had forgotten to filter?
2. `AssumeRole` appears six times. Is that something the role does, or something
   done **to** it? Does it belong in the role's identity policy? (Look at
   `userIdentity.type`.)
3. Translate every event name into the **IAM action** it requires. Three of them
   are not the same word: `HeadObject`, `ListObjects`, and the `kms` call.
   Which IAM action authorises each?
4. `kms:Decrypt` appears with `invokedBy: secretsmanager.amazonaws.com`. The role
   did not call KMS: Secrets Manager did, on its behalf. Does the role need
   `kms:Decrypt` in its policy? The answer depends on **which kind of key**
   protects the secret. What would you run to find out, and what are the two
   possible answers?
5. There are 41 `AnalyzeExpense` calls but only 7 `GetObject`. Did the processor
   stop reading invoices? Find the moment the S3 events stop, and the event that
   explains it. What does this do to the method "derive the policy from the
   trail"?
6. The processor writes logs to CloudWatch. Search the trail for `logs:`.
   What do you conclude about using a trail as the **only** source for a policy,
   and which step of the honest method covers the gap?
7. Now write the policy. Bucket **and** prefix for each object action, `ListBucket`
   on the bucket ARN with an `s3:prefix` condition for `incoming/`, the secret by
   ARN (mind the random six-character suffix Secrets Manager appends), Textract on
   `*` with a reason, and `aws:SecureTransport`. Save it as `out/invoice-app.min.json`.
8. Build the **justification table**: one row per permission that survived, with
   the evidence (event name and count, or the documentation page) and the reason.
   This table is a deliverable component.

---

## 9 · Reduce, and prove the negative — twice

**Part A: LocalStack.** Run the reduction on your own bucket, step by step, as
`./localstack-lab.sh policy-lab` lays it out. Then:

```bash
./localstack-lab.sh negative blueteam-lab-data
```

It will tell you the negative test **passed when it should have failed**, and
why: LocalStack (without a paid plan) does not enforce IAM. Write down exactly
what that means for anything you "verified" against it.

**Part B: Moto, which does enforce identity policies.** Moto is an open-source
AWS emulator (Apache 2.0). With `INITIAL_NO_AUTH_ACTION_COUNT` it accepts a few
unauthenticated calls, then starts checking signatures and policies like the
real thing, more or less. Exercise 10 deals with the "more or less".

```bash
# port 5050, not 5000: on macOS, 5000 belongs to the AirPlay receiver
docker run -d --name blueteam-moto -p 127.0.0.1:5050:5000 \
  -e INITIAL_NO_AUTH_ACTION_COUNT=3 motoserver/moto:5.2.5
until curl -sf -o /dev/null http://127.0.0.1:5050/moto-api/; do sleep 1; done

mo() { aws --endpoint-url=http://127.0.0.1:5050 "$@"; }
for k in aws_access_key_id aws_secret_access_key; do aws configure set $k test --profile moto-boot; done
aws configure set region eu-west-1 --profile moto-boot

# the three free calls: create an administrator, then the door locks behind you
mo --profile moto-boot iam create-user --user-name lab-admin
mo --profile moto-boot iam put-user-policy --user-name lab-admin --policy-name all \
   --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
read -r AK SK < <(mo --profile moto-boot iam create-access-key --user-name lab-admin \
   --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)
aws configure set aws_access_key_id "$AK" --profile moto-admin
aws configure set aws_secret_access_key "$SK" --profile moto-admin
aws configure set region eu-west-1 --profile moto-admin

mo --profile moto-boot s3 ls                      # refused, as it should be now
mo --profile moto-admin sts get-caller-identity   # 123456789012, user/lab-admin
```

Now, as `moto-admin`: create `tagus-invoices-lab`, put one object in
`incoming/` and one in `finance/`, create a user `invoice-app`, attach **your**
policy from Exercise 8 (adapted to the bucket name), create its access key, and
store it as profile `moto-app`.

1. As `moto-app`: read from `incoming/`. Then read from `finance/`. Record both
   results, verbatim, with the command. This is the first negative test tonight
   that can actually fail. Did it?
2. Attach NuvemCerta's original `invoice-app.json` instead and repeat. Same two
   commands, same two results? Write the two-row table that proves your reduction
   **removed** something.
3. Try `DeleteObject` on `processed/` with your policy. Should it work? Did it?
   If your answer and Moto's differ, which one is wrong?
4. `docker rm -f blueteam-moto` when done. What happened to everything you
   created? Why is that a feature for a lab, and why does it mean your evidence
   has to be in your notes, not in the emulator?

---

## 10 · Two emulators, three answers

An emulator is a model of AWS, and every model is wrong somewhere. Find out where,
so that your methodology section says it before a reviewer does.

Run each test in Moto (and in LocalStack where it applies) and fill the table.
The "real AWS" column comes from the IAM documentation, not from a guess.

| # | Test | Real AWS | LocalStack 4.14 | Moto 5.2.5 |
|---|---|---|---|---|
| a | Identity policy allows `incoming/*`; read `finance/x` | denied | ? | ? |
| b | Allow `s3:*` on `*` **plus** an explicit `Deny` on `finance/*`; read `finance/x` | denied (explicit deny wins) | ? | ? |
| c | Policy requires `aws:SecureTransport=true`; read over plain HTTP (the endpoint is `http://`) | ? | ? | ? |
| d | User with **no** identity policy; bucket policy (same account) allows that user `GetObject` | ? | ? | ? |

1. For (c) and (d), look up what real AWS does. For (d), the key phrase in the
   IAM policy evaluation logic is *"within the same account"*.
2. Which emulator is **too permissive** where, and which is **too strict** where?
   Which kind of error is more dangerous when you are proving a reduction, and
   which when you are proving that something works?
3. Write the methodology paragraph for your deliverable in three sentences: what
   you tested, against what, and what the result does **not** prove. "Tested
   against Moto 5.2.5, which does not evaluate Conditions" is a strong sentence.
   "Tested" alone is not.

---

## 11 · State is a secret

```bash
jq '.outputs' samples/terraform/state-from-contractor-repo.json
jq -r '.resources[] | select(.type=="random_password" or .type=="aws_db_instance")
       | .instances[].attributes | {result, password}' samples/terraform/state-from-contractor-repo.json
cat samples/terraform/outputs.tf
gitleaks dir samples/terraform -v
```

1. How many times does the database password appear in the state, and where?
   The state lists those attributes under `sensitive_attributes`. Did that keep
   them out of the file? What does `sensitive` actually do, and for whom?
2. `outputs.tf` wraps the password in `nonsensitive()`. What did someone have to
   do to make that work, and what does the comment say about why?
3. `gitleaks` reports **no leaks**. The password is in the file three times.
   Explain the result in terms of how secret scanners decide what a secret is.
   What does this do to the sentence "we run secret scanning in CI"?
4. The state was committed to the contractor's repository. Deleting the file in a
   new commit fixes what, exactly? Write the incident response in order: what you
   rotate, what you check in the database's own logs (and for what period), and
   what you change so it cannot happen again. Then combine it with Exercise 3: the
   database is `publicly_accessible`. How does that change the urgency?
5. Where should the state live instead? Name the backend, and the four
   properties it needs (the slides have a table).

---

## 12 · Scan it, then read the scanners

```bash
checkov -d samples/terraform --compact > out/checkov-before.txt; tail -3 out/checkov-before.txt
checkov -d samples/terraform --compact --skip-check "$(grep skip_check samples/terraform/ci.yml | cut -d: -f2- | tr -d ' ')" \
  | grep -E '^(Passed|Failed|Skipped)'
trivy config samples/terraform > out/trivy-before.txt; grep -E '^(Tests|Failures)' out/trivy-before.txt
```

`tfsec` is deprecated; `trivy config` is where its rules went.

1. The handover says **"0 failed checks"**. Read `ci.yml` closely, line by line.
   Three settings make that sentence true and meaningless at the same time. One
   of them would be enough on its own; find the one that is (compare the
   directory checkov scans with the one Terraform applies). Which of the skipped
   checks would have flagged something you found by hand in Exercise 3 or 11?
2. `main.tf` contains `#checkov:skip=CKV_AWS_145`. Does checkov honour it? (Count
   *Skipped* in the output.) Find the resource checkov reports `CKV_AWS_145` on,
   and explain why the suppression suppresses nothing. Then rewrite it so it
   **would** work, with a reason, and decide whether it should exist at all.
3. checkov **passes** the S3 access-logging check. You found in Exercise 5 that the
   logging is a problem. Which is right, and what does the check actually test?
4. Neither scanner reports anything about `s3:*` on `*` in the invoice processor's
   policy. Why not? (Look at how `main.tf` loads the policy.) What do you run
   instead, and where in the pipeline?
5. Compare checkov and trivy on the RDS instance. Name one thing each finds that
   the other does not, and one contextual finding you would **accept** with a
   documented reason (the slides call KMS-vs-AES256 "contextual"; is it here?).
6. Fix at least three findings in a copy of the module (`cp -r samples/terraform
   out/tf-fixed`). For anything you do not fix, write the suppression **in the
   code**, on the right resource, with a reason a reviewer can disagree with. Save
   `out/checkov-after.txt`.

---

## 13 · Your module, against the lab

Write your own module, not a patch of NuvemCerta's: the bucket from Exercise 5
done right, and the role and policy from Exercise 8. Point it at LocalStack:

```hcl
provider "aws" {
  region                      = "eu-west-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true
  endpoints {
    s3  = "http://localhost:4566"
    iam = "http://localhost:4566"
    sts = "http://localhost:4566"
  }
}
```

```bash
cd out/my-module
terraform init
terraform plan -out=tf.plan        # read every line before the next command
terraform apply tf.plan
../../localstack-lab.sh posture tagus-invoices-lab
terraform show -json tf.plan > tf.plan.json && checkov -f tf.plan.json --framework terraform_plan
```

1. The credentials are hard-coded in the provider block. Why is that acceptable
   here and nowhere else? What would you put there for a real account, and where
   do the real credentials come from instead?
2. Read the plan. How many resources, and does any attribute say
   `(known after apply)` that you would want to know **before** apply? Paste the
   plan's summary line into your notes.
3. `posture` must answer all four questions well. If question 4 still fails, what
   did you choose to do about logging, and where do the logs go?
4. Scan the **plan**, not just the code. Does the result differ from scanning the
   directory? Why might it?
5. Add a deliberate mistake (`status = "Suspended"`), plan again, and read the
   diff Terraform shows. Then revert. This is what a reviewer sees in a pull
   request, so make sure you can read it.

---

## 14 · A guardrail that never fires

`samples/iam/scp-deny-public-buckets.json` is NuvemCerta's proposed guardrail:
"no public buckets, ever, in any Tagus account". It is short, it is a Deny, and
it looks right.

1. Read the `Condition`. Look the key up in the *Service Authorization Reference*
   for Amazon S3 (the list of condition keys for `PutBucketPublicAccessBlock`).
   Does `s3:PublicAccessBlockConfiguration` exist?
2. The IAM documentation says that when a condition key **is not present** in the
   request context, the condition does not match (outside `...IfExists` and
   `Null`). So: when does this Deny apply? Write the answer as one word, then as a
   sentence for the Board.
3. Why is this worse than having no guardrail? (Think about what the organisation
   now believes.)
4. Design one that works. A common pattern: turn on S3 Block Public Access at the
   **account** level, then use an SCP to deny `s3:PutAccountPublicAccessBlock`
   to everyone except a named break-glass role (`aws:PrincipalArn`). What does
   that leave open for `tagus-website-assets`, and how would you serve the website
   without a public bucket at all?
5. Neither emulator enforces SCPs for free. How would you **test** a guardrail
   before rolling it out to production? (Hint: an OU with one sandbox account in
   it, plus IAM Access Analyzer's policy validation, which flags unknown condition
   keys.) A guardrail you did not test is decoration.

---

## 15 · Patch the linter

`policy-lint.py` is part of this course, and in Exercises 6 and 7 you caught it
being wrong three times. That is the point of reading tools rather than just
running them.

1. **The missing `sub`** (Exercise 7). Find the web-identity check in
   `findings_for()`. Why does a `StringEquals` on `aud` satisfy it? Rewrite it so
   that a GitHub OIDC trust without a condition on
   `token.actions.githubusercontent.com:sub` is HIGH, and a `StringLike` on `sub`
   containing `*` in the repository part is at least MED.
2. **Combinations across statements** (Exercise 6.3). The combination rule
   only looks inside one statement. Make it look at the whole policy's allowed
   actions, so `ci-deploy.json` prints the `PassRole + CreateFunction` line.
3. **`NotAction` read backwards** (Exercise 6.4). The linter treats the actions
   listed under `NotAction` as granted. Make it report the `NotAction` finding
   only, with a detail line that names what is excluded.
4. Run the linter over every file in `samples/iam/` before and after, and keep both
   outputs. Every change must make a finding appear, disappear, or become more
   accurate. Say which, for each change.
5. Pull request, with a commit message that names the fixture that proved each bug.
   "Fixed linter" is not a commit message.

---

## 16 · The deliverable

The Session 15 deliverable, built on Tagus rather than on an empty bucket:

| Component | From |
|---|---|
| Terraform module, with variables and outputs, and how state is handled | Exercises 11, 13 |
| The final least-privilege policy for the invoice processor, with at least one `Condition` | Exercise 8 |
| **Justification table**: one row per surviving permission, with evidence (event + count, or documentation) | Exercise 8 |
| **Negative test**: one action denied that previously worked, with the command and output, and **which emulator** | Exercises 9, 10 |
| Scan output before and after, with the findings you fixed | Exercise 12 |
| Suppressions, each **in the code**, on the right resource, with a reason | Exercise 12 |
| A guardrail that would prevent your worst finding structurally, and how you would test it | Exercise 14 |
| Sovereignty note: where the data lives, where it should, what constrains the choice | Exercise 3 |
| Findings list from the handover review, each with evidence and owner | Exercises 1, 5, 6, 7, 11 |

Four things that separate a good submission from a long one:

- **The trust policies.** Most submissions will reduce `invoice-app.json` and
  stop. The worst finding tonight is not in an identity policy. It is the role
  that any GitHub repository could assume, and the evidence that one did.
- **Limitations, specific.** Which emulator, which version, what it does not
  evaluate, and which of your claims that affects. One paragraph, with the
  table from Exercise 10.
- **Ownership.** Every finding names who fixes it: Tagus, NuvemCerta, or AWS.
  If you wrote "AWS" anywhere, check it against the diagram from Exercise 2.
  The two rows that never move are where most of tonight's findings live.
- **The Board's question.** End with two sentences that answer *"Is it safe
  now?"* in words a non-technical reader will act on. Not "it depends".

Write the summary last. It is the first thing read and the last thing knowable.
