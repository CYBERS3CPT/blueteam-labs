# Session 16 — Exercises

Hands-on and Kali-first, built on `triage-findings.py` and `risk-register.py`,
on the fixtures in `samples/`, and on whatever you left running after Session 15.
Nothing here touches a real AWS account. Everything is fictional and everything
is defensive.

**The case so far.** *Tagus Logística* was phished (Session 6), lost two transfers
of just under €50 000, and had a web server compromised through three
configuration files (Sessions 7–8). The Board moved to the cloud. NuvemCerta
built it in three weeks, and in Session 15 you read their handover and found a
CI role that any GitHub repository can assume, a public website carrying the old
server's `/etc`, and a database in a region nobody chose.

A week later Tiago ran Prowler, as the slides say to. He got 312 findings. He
did what most people do with 312 findings, and then on Friday afternoon GuardDuty
raised something that one of them had predicted. The scan, his suppressions, the
Board's risk register draft, and Friday's evidence are all in `samples/`. So are
his notes, which end with three questions.

Tonight you answer them: what should have been fixed first, what happened on
Friday, and what the register should have said before it did.

## Before you start

```bash
cd blueteam-labs/session-16-cloud-triage
sudo apt install -y jq python3 docker.io
pipx install prowler                       # 5.x; for your own lab, not for the fixtures
mkdir -p out                               # git-ignored
(cd samples && shasum -a 256 -c SHA256SUMS)
gunzip -c samples/incident/cloudtrail-prod-2025-12-05.json.gz > out/trail.json
P=samples/prowler/prowler-output-111122223333-20251203081402.ocsf.json
N=samples/prowler/prowler-output-444455556666-20251203084137.ocsf.json
echo "$(date -u +%FT%TZ)  START  session 16 exercises" > out/my-notes.txt
```

Ground rules:

- **Do not fix anything until Exercise 7 is done.** The point of triage is that
  the order is decided before the work starts. A finding fixed out of order is a
  finding you will explain twice.
- **Read the tool, not just its output.** Both scripts are about 300 lines. In
  Exercises 3–6 and 12 you will catch them disagreeing with their own README.
  That is deliberate, and Exercise 14 is where you fix them.
- **Name the source for every claim.** "The credential was used after the
  instance was gone" is not a finding until it names the record.

| # | Exercise | Tools | Time |
|---|---|---|---|
| 1 | Before the scan: what can it not see? | your S15 notes | 15 min |
| 2 | 312, counted honestly | `jq` | 15 min |
| 3 | Run the triage, then read it | `triage-findings.py` | 20 min |
| 4 | The tiers read the prose | `triage-findings.py --out`, `jq` | 25 min |
| 5 | Muted is not fixed | `jq`, the mutelist | 15 min |
| 6 | Five suppressions, four fields each | `triage-findings.py --suppress` | 20 min |
| 7 | Your order, by hand | everything above | 30 min |
| 8 | A rule no benchmark has | `conftest` (OPA) | 30 min |
| 9 | Friday, 13:58 to 18:19 | the access log, `jq` | 30 min |
| 10 | What was read? | `jq`, the policy, the bucket dump from S15 | 25 min |
| 11 | The response, reviewed | Tiago's notes, the trail | 25 min |
| 12 | The register, checked | `risk-register.py --check` | 20 min |
| 13 | Three entries that get funded | `risk-register.py` | 40 min |
| 14 | Patch the tools | your editor | 30 min |
| 15 | The deliverable | everything above | 60 min+ |

Exercises 1–2 and 9–11 are Block 1 (how cloud breaches happen, on a real one),
3–8 Block 2 (tooling and the 300-findings problem), 12–13 Block 3 (risk). The
deliverable is due before Session 17, which attacks what you triage here.

---

## 1 · Before the scan: what can it not see?

Open your Session 15 findings list. Before you look at a single line of Prowler
output, predict.

1. For each of your five worst Session 15 findings, write down whether a CSPM
   scanner **will** report it, **might** report it (as something else), or
   **cannot** report it. One line of reasoning each. Think about what a scanner
   reads: the configuration of resources, through the API, today.
2. Three things from Session 15 are almost certainly invisible to any scanner:
   the content of the objects in `migration/`, the state file in the
   contractor's repository, and the GitHub repository that assumed `ci-deploy`
   on 25 November. For each, name the control that **would** have caught it, and
   where in the lifecycle it sits (commit, deploy, runtime, audit).
3. Prowler has a check for `iam:PassRole` plus `lambda:CreateFunction`. Does it
   have one for a GitHub OIDC trust policy with no `sub` condition? Find out
   from the check list of the version you installed (`prowler aws --list-checks`,
   or the source tree), not from memory. Write down the version.
4. Keep this list. In Exercise 7 you compare it with what the scan actually said,
   and the gap is the first paragraph of your triage.

---

## 2 · 312, counted honestly

```bash
jq length $P $N
jq -r '.[] | .status_code' $P $N | sort | uniq -c
jq -r '.[] | select(.status_code=="FAIL") | .severity' $P $N | sort | uniq -c | sort -rn
jq -r '.[] | select(.status_code=="FAIL") | .metadata.event_code' $P $N | sort | uniq -c | sort -rn | head -20
jq -r '.[] | select(.status_code=="FAIL") | .cloud.region' $P $N | sort | uniq -c | sort -rn
```

1. How many failing findings, and how many **distinct checks** produced them?
   Write both numbers in your notes. Which is the one you would tell a manager?
2. Several checks fail exactly 17 or 18 times in each account. Why 17? Why 18
   for some? Which region does Tagus actually use, and what do the other
   sixteen have in them?
3. `cloudtrail_multi_region_enabled` fails 16 times in prod. Is that sixteen
   problems or one? Write it as **one** finding, with the evidence that it is one.
   Then look at the same check in non-prod. What is different, and why does it
   matter to anything that happened in `us-east-1` (Session 15, Exercise 3)?
4. Sort the failing findings by severity, as the tool's authors see it. Where does
   the publicly accessible RDS instance land? Where does `ec2_ebs_default_encryption`
   land? Would you fund them in that order?
5. Count the findings whose `status` is not `New`. Hold the number for Exercise 5.

---

## 3 · Run the triage, then read it

```bash
./triage-findings.py $P | less
./triage-findings.py $P $N          # the README says this works
./triage-findings.py $P --tier 1
```

1. The second command fails. Read the README's usage block and the `argparse`
   lines in the script. Who is right? Until Exercise 14 fixes it, how do you
   triage both accounts together? (`jq -s 'add' $P $N > out/both.json` is one
   answer. Is merging the right answer, or should the two accounts be triaged
   separately? Argue it in two sentences.)
2. The README promises grouping: the same check on many resources is printed once,
   with `×N`. Count the `×` in your output. There are none. Read `load_prowler()`:
   what does it put in `check` for an OCSF finding, and what does that value look
   like? (`jq -r '.[0].finding_info.uid' $P`.) Which field should it have used?
3. Because of (2), the tier 1 listing opens with seventeen identical lines. What
   are they, and what is the first **exposure** in the listing, in the sense the
   README defines it?
4. The closing message says *"Work tier 1 to exhaustion before you open tier 2."*
   Following that literally, with this output, what would Tiago have spent his
   Thursday doing?

---

## 4 · The tiers read the prose

```bash
./triage-findings.py $P --out out/triaged-prod.csv > /dev/null
python3 - <<'EOF'
import csv, collections
rows = list(csv.DictReader(open("out/triaged-prod.csv")))
by = collections.defaultdict(collections.Counter)
for r in rows:
    by[r["tier"]][r["check"].split("-")[2]] += 1
for t in sorted(by):
    print(f"\nTIER {t}")
    for c, n in by[t].most_common():
        print(f"  {n:>3}  {c}")
EOF
```

`tier_of()` runs regular expressions over the check, the title, the risk text
and the service name, and the first tier that matches wins.

1. Make a table: every check in tier 1 that is **not** an exposure. For each, find
   the word that put it there (`jq -r '.[] | select(.metadata.event_code=="accessanalyzer_enabled") | .risk_details' $P | head -1`).
   Is the word in the title, or in Prowler's risk prose?
2. Now the opposite. `ec2_securitygroup_allow_ingress_from_internet_to_all_ports`
   is **Critical** in Prowler: a security group with every port open to the
   internet. Which tier did the tool give it? Read `RULES` and say exactly why.
   What one change to the tier 1 pattern fixes it, and what does that change
   drag into tier 1 with it?
3. `s3_bucket_secure_transport_policy` fails on three buckets. Two land in one
   tier and one in another. Same check, same title, same risk text. What is
   different? (Look at the bucket names, and at what the tool includes in the
   text it matches.)
4. `cloudwatch_log_metric_filter_policy_changes` is in tier 2 (identity). It is
   a missing alarm. Which tier should it be in, and which word moved it?
5. Write the paragraph for your deliverable on what an automated tier is worth:
   what it gets right (it is fast, it is consistent, it puts most of the right
   things in tier 1), and where you overrode it, with the reason. "The tool said
   tier 4" is not a reason to leave an all-ports-open security group until last.

---

## 5 · Muted is not fixed

```bash
jq -r '.[] | select(.status=="Suppressed")
       | [.metadata.event_code, .finding_info.name, .cloud.account.uid, .status_code] | @tsv' $P $N
cat samples/prowler/mutelist-nuvemcerta.yaml
```

1. List the muted findings. For each, find the mutelist entry that muted it and
   the comment that is its only justification. Fill in, for each one, the four
   fields `triage-findings.py` demands of a suppression: **what, why, who, until**.
   How many of the 32 cells can you fill from the mutelist?
2. Find out what Prowler itself does with muted findings in its console summary
   and its HTML report, in the version you installed. Then check
   `triage-findings.py`: read the `status` test in `load_prowler()`, and run it.
   Does it drop them, or show them? Does it say they were muted? Decide which
   behaviour is worse: hiding them silently, or showing them with no sign that
   someone decided to mute them.
3. The mutelist entry for `rds_instance_no_public_access` says *"office connects
   with DBeaver"*. Its `Resources` is `"*"`. What will happen to the **next**
   publicly accessible database anybody creates in prod?
4. One of the muted findings is the root cause of Friday's incident. Which one?
   Come back to this answer after Exercise 9 and check it.
5. The mutelist was passed to the scan by NuvemCerta's configuration, and Tiago
   kept it "because that is how it was set up". Write the rule for your
   deliverable: who may add to a mutelist, what each entry must carry, and who
   reviews it, and when.

---

## 6 · Five suppressions, four fields each

```bash
./triage-findings.py $P --suppress samples/suppressions-tagus.yml > out/triage-suppressed.txt
head -20 out/triage-suppressed.txt
```

1. The tool rejects two entries and says why. Which two, and is it right about
   both? For the expired one: was it a bad suppression, or a good one that
   nobody renewed? How would you tell the difference?
2. It accepts three, which hide 31 findings between them. For each accepted
   entry, list what it actually hides. You will need to read `suppressed()`: it
   matches substrings, of `check` against the check **and** title, and of
   `resource` against the resource.
3. Entry 2, `check: cloudtrail`, has all four fields. Its reason is the one the
   README says is not a reason. Its owner is a department. It expires in 2099.
   The tool takes it. List everything it hides, including the findings that are
   not about CloudTrail at all.
4. Entry 3 came from NuvemCerta. Its `check` is `public` and its `resource` is
   `tagus`. What does it hide in prod? Which of those is the single most exposed
   resource Tagus owns? Who signed it, and should a contractor be able to accept
   a risk on Tagus's behalf?
5. Entry 4, the IMDSv2 one, is rejected for a missing `until`. Suppose Rui adds
   one. Would it then hide anything? (Compare its `resource` with the resource
   field of the finding it is aimed at.) So the tool refused it for the right
   reason and would have accepted the fixed version for no reason at all. What
   does that say about validating a suppression's **fields** but not its
   **effect**?
6. Entry 1 says the website bucket holds *"no customer data"*. Check that
   against Session 15, Exercise 5.4. Rewrite the entry so that it is true, and
   decide whether it should still exist.
7. Write a suppressions file you would sign: at most three entries, each scoped
   to a check **ID** and a resource **ARN**, with a reason a reviewer can disagree
   with, a named person, and an expiry inside six months. Run it, and show that
   it hides exactly what you meant and nothing else.

---

## 7 · Your order, by hand

Now produce the list Tiago should have had on Thursday morning. Not the tool's
order: yours, with the tool's output as one input.

1. Collapse the 312 into **distinct problems**: one row per thing somebody has to
   do. (Sixteen regions without a trail is one thing to do.) How many rows?
2. Add the problems from Exercise 1 that the scanner cannot see. Mark them
   "not in scan" and give the source.
3. Order them in the four tiers, by your judgement, with one line of reasoning
   each. The first ten are what you present; the rest are an appendix.
4. Find WEB-02 in your list. Where is it, and where did the tool put it? (It
   appears under three or four checks. Which one is the one that matters, and
   was it visible in the tool's output at all?)
5. For your top five, name an **owner**: Tagus, NuvemCerta, or AWS. If you wrote
   "AWS" anywhere, check it against the shared responsibility diagram.
6. Only now: fix the top two **in your own lab** (LocalStack or Moto from Session
   15), and re-scan to prove it. `prowler aws -c <check>` against your endpoint, or
   your `posture` / Moto commands. Record before and after.

---

## 8 · A rule no benchmark has

The worst Session 15 finding was a GitHub OIDC trust with no `sub` condition, and
no scanner in Exercise 1 reports it. Write the rule yourself, as policy as code,
and test it on Session 15's trust policies.

```bash
mkdir -p out/policy
# mount the repository root, so that Session 15's files are inside the container
docker run --rm -v "$PWD/..":/w -w /w/session-16-cloud-triage openpolicyagent/conftest:latest \
  test --policy out/policy ../session-15-cloud-iam/samples/iam/trust/*.json
```

Start from this skeleton (`out/policy/trust.rego`):

```rego
package main

import rego.v1

github := "token.actions.githubusercontent.com"

deny contains msg if {
	some st in input.Statement
	st.Effect == "Allow"
	contains(st.Principal.Federated, github)
	not has_sub_condition(st)
	msg := sprintf("%s: GitHub OIDC trust without a sub condition: any repository can assume this role", [st.Sid])
}

has_sub_condition(st) if {
	some op, kv in st.Condition
	some key, _ in kv
	key == sprintf("%s:sub", [github])
}
```

1. Run it. Which file fails, and does the message say what is wrong in words a
   developer will act on?
2. A `StringLike` on `sub` with `repo:tagus-logistica/*` passes your rule. Should
   it? Extend the rule: a wildcard in the **organisation or repository** part of
   `sub` is a deny; a wildcard in the **ref** part is a warning (`warn contains
   msg if ...`). Write one passing and one failing test file for each case.
3. Add a second rule: a trust policy that allows an `AWS` principal from another
   account **without** an `sts:ExternalId` condition. Which Session 15 file
   fails? Is the external ID the right control for that role, or is it the
   confused-deputy control for a different problem? (Session 15, Exercise 7.6.)
4. Where in the pipeline does this run? The trust policies are loaded with
   `file()` in `main.tf`, which is why checkov never saw them (Session 15,
   Exercise 12.4). Write the CI step.
5. Estimate the false positive rate on a real estate. When is a trust policy
   without `sub` legitimate, if ever?

---

## 9 · Friday, 13:58 to 18:19

The Block 1 exercise, on a breach you have the evidence for. Build the timeline
first, then map it.

```bash
cut -d' ' -f1 samples/incident/web02-access.log | sort | uniq -c | sort -rn
grep '^198\.51\.100\.77 ' samples/incident/web02-access.log
grep 169.254 samples/incident/web02-access.log
jq -r '.Records[] | select(.sourceIPAddress=="198.51.100.77")
       | [.eventTime, .eventSource, .eventName, (.errorCode // "ok")] | @tsv' out/trail.json
jq '.Findings[] | {Type, Severity, CreatedAt, UpdatedAt, Count: .Service.Count,
                   first: .Service.EventFirstSeen, last: .Service.EventLastSeen}' \
   samples/incident/guardduty-prod-eu-west-1.json
```

1. Build the timeline, in UTC, from all three sources, one row per event, with a
   **source** column. Start at the first request from `198.51.100.77` and end at
   its last API call. Mark every row with what you **know** and what you
   **infer**.
2. Which request handed over the credentials? What is the response size, and
   what does an IMDS credentials document contain? What is `preview.php?src=` for,
   in normal use (look at the customers' requests), and what is the weakness
   called?
3. The attacker also fetched `/latest/user-data`, 2210 bytes. What is usually in
   user data, and why does it matter more here than in most places? Which Prowler
   check exists for it, and is it in Tiago's scan?
4. With IMDSv2 required, which of the attacker's requests would have failed, and
   why? (What does IMDSv2 need that a `GET` through `preview.php` cannot send?)
5. Map each stage to an ATT&CK technique (cloud matrix): initial access, credential
   access, discovery, collection. For each, name the **control** that would have
   stopped it, and be specific: which setting, which policy, which detection.
6. Where was detection **realistically** possible first? GuardDuty created the
   finding at 14:26. A human read it at 16:50. What was missing in between?
   (`EventBridgeRulesForGuardDuty` in the export is not a GuardDuty field; it is
   Tiago's note that there were none.) Write the EventBridge rule that would have
   paged someone.
7. Was IMDSv1 on WEB-02 in the scan? In which tier did `triage-findings.py` put
   it, and what was its `status`? Go back to Exercise 5.4.

---

## 10 · What was read?

Rita's question to Tiago: *were the customers' invoices read?* Tiago's answer:
*probably not, CloudTrail shows only AccessDenied from that IP.* Test the answer.

```bash
cat samples/incident/web02-portal-policy.json
jq -r '.Records[] | [.eventTime, .eventName, .eventCategory, .awsRegion] | @tsv' out/trail.json | sort -u -k2,2
jq '.GetDetector.Features' samples/incident/guardduty-prod-eu-west-1.json
jq '{GetBucketLogging, GetBucketLifecycleConfiguration, CloudTrailDataEvents}' \
   ../session-15-cloud-iam/samples/buckets/tagus-invoices-prod.json
```

1. List the actions the role **was** allowed. Is any of them in the trail? Why not?
   (Two separate reasons: one is in the mutelist, the other in Session 15's
   bucket dump.) Now say in one sentence what the AccessDenied events prove,
   and what they cannot.
2. The credentials were taken at 14:04:06. The first logged call is at 14:11:41.
   An attacker with a fresh credential nearly always asks *who am I* and *what is
   here* first: `sts:GetCallerIdentity`, `s3:ListBuckets`. CloudTrail records
   both. Neither is in this trail. Which region does each one log in when the
   client uses the **global** endpoint, and which when it uses the **regional**
   one? Given the trail's coverage (Exercise 2.3), what does their absence tell
   you, and what does it **not** tell you?
3. Where **is** the record of what was read, if anywhere? Name it, the path where
   it lives, who can read it (check the policy: can the attacker?), and on which
   date the lifecycle rule deletes Friday's entries. Today is Monday the 8th, a
   holiday. What is the first command you run, and where do the copies go?
4. GuardDuty had `S3_DATA_EVENTS` enabled. It does not depend on CloudTrail data
   events. Find out from the GuardDuty documentation what S3 Protection would have
   needed to raise an S3 finding here, and why a detector created the day before
   may not have. Do not guess; cite the page.
5. Write the answer to Rita as three separate sentences: the **finding**, the
   **inference**, and the **limitation**. Then the one sentence she should
   actually hear, which starts with "We cannot yet say".

---

## 11 · The response, reviewed

Read `tiago-notes.md` end to end. Tiago acted fast, in good faith, alone, on a
Friday evening. Review the response as you would want yours reviewed.

```bash
jq -r '.Records[] | select(.userIdentity.type=="Root")
       | [.eventTime, .eventName, (.requestParameters | tostring | .[0:120])] | @tsv' out/trail.json
jq '.Records[] | select(.eventName=="RunInstances") | .requestParameters' out/trail.json
jq -r '.Records[] | select(.sourceIPAddress=="198.51.100.77")
       | [.eventTime, .userIdentity.sessionContext.attributes.creationDate, .eventName] | @tsv' out/trail.json
```

1. *"Rui says the instance role credentials die with the instance."* Test it
   against the trail. What happened at 18:19:40, and why does an **AccessDenied**
   prove the credential still worked? From `creationDate`, estimate when that
   credential expires (look up how long EC2 role credentials are valid). How do
   you revoke a role's existing sessions without deleting the role?
2. The new WEB-02 was launched at 17:47. Read its `RunInstances` request: AMI,
   role, security group, `metadataOptions`. What did the rebuild fix? Is the new
   instance vulnerable to exactly the same request?
3. List what the termination at 17:52 destroyed, in order of volatility (Session
   7). What would you have needed, and in which order should the steps have
   happened? The slides give four: snapshot, tag, isolate, disable termination.
   Why is "isolate" a security group change and not a stop?
4. Tiago used **root**, and GuardDuty noticed. Is that a finding against Tiago,
   or against the account? What should have existed instead, and when should it
   have been created? (Session 12: break-glass, tested.)
5. The access log on Tiago's laptop: what is its evidential weight? What is
   missing (hash, time of copy, chain of custody, error log), and what can you
   still do about each?
6. *"Do we have to tell anyone?"* Tagus is the controller for its customers'
   invoices (names, NIFs, IBANs). Under RGPD Article 33, when did the 72 hours
   start, and when do they end? Does "we cannot say what was read" make it
   notifiable or not? Draft the first two lines of the notification to the CNPD,
   and the internal note that records the decision if you decide **not** to
   notify. Both are defensible; neither is optional.
7. Answer Tiago's three questions. Kindly, and in writing.

---

## 12 · The register, checked

```bash
./risk-register.py samples/register-draft.csv
./risk-register.py samples/register-draft.csv --check; echo "exit $?"
./risk-register.py --explain | less
```

1. `--check` flags four of the six entries. Go through its complaints. Is each one
   right? Which one would a regulator ask about first?
2. Two entries pass as **complete**. Read TAG-004 as an auditor. Who accepted the
   risk, on whose behalf? What is the review date? What is the effort? Why is a
   risk with zero effort at the **top** of a ranking called "risk reduction per
   effort-day", when accepting it reduces nothing? Read `cmd_report()` and find the
   line.
3. TAG-002 is flagged for its single-number impact and its owner. It is **not**
   flagged for its assets, and the check says assets must have a *scale*. Which
   character in `"tagus-invoices-prod RDS PostgreSQL (us-east-1)"` satisfied
   the scale check? Find another entry that passes the same way.
4. TAG-006 was accepted by the CEO on **2 December**: IMDSv1 on WEB-02, likelihood
   once in five years. What happened three days later? Compute its ALE as written,
   then look at the impact columns again. What did the tool not notice?
5. TAG-003 is the best entry in the file. Say why, in terms of the four parts of a
   risk statement (threat, vulnerability, asset, consequence). Then find its one
   weakness: its `linked_findings` cites a Prowler check and a Session 15
   exercise. Is the second one a finding ID? What should it be?
6. TAG-005 is an acceptance of the data-plane logging gap, with no acceptor.
   After Exercise 10, can it still be accepted? What did it cost on Friday?

---

## 13 · Three entries that get funded

Build three entries for the Board, using everything above. Start from the
template or the interview:

```bash
./risk-register.py --template out/register.csv     # then edit; register.csv is git-ignored
./risk-register.py new                             # one entry, by interview
```

Requirements, as in the slides:

1. A **risk statement**, not a finding restatement: threat, vulnerability, asset,
   consequence. At least one entry must combine findings that the scanner
   reported separately (for example: IMDSv1 + a role that reads the whole bucket +
   data events off = a breach you cannot scope).
2. **Likelihood with reasoning.** Tagus has had one incident in its first two
   weeks in the cloud. Does that change your estimate, and in which direction?
3. **Impact as a range**, with confidence, and a sentence on what the range covers
   (response, notification, regulatory, contractual, the IBAN fraud from
   Session 6).
4. **Controls labelled honestly**: preventive or merely detective. GuardDuty is
   detective. An EventBridge rule nobody created is not a control.
5. **One acceptance**, with a named acceptor who has the authority (not the
   contractor), a live review date, and a sentence written as if a regulator will
   read it. Good candidates: the public website bucket **after** the migration
   files are removed, or `us-east-1` data residency until the database migration
   is scheduled.
6. The **logging decision**: which data-plane logging you would enable, on which
   buckets, at what cost, and what you are deliberately **not** logging. That
   sentence belongs in the register; Friday is why.

Run `--check` until it exits 0. Then read the report's ranking: does the order
match your judgement? If not, which column is wrong, the effort or the
impact?

---

## 14 · Patch the tools

Both scripts are part of this course. In Exercises 3–6 and 12 you caught them
being wrong against fixtures that look like real input. Fix them.

1. **`triage-findings.py` takes one file** (Exercise 3.1). Accept several, and
   say per file how many findings came from each. Keep the account ID visible in
   the output: two accounts merged into one list must still be told apart.
2. **The check is the finding UID** (Exercise 3.2). Use `metadata.event_code`
   for OCSF input. Once grouping works, the listing shows **one** resource per
   check. Print the resource count and the regions instead, so that the 17
   copies of one finding read as one line, and the one WEB-02 line is not
   buried behind them.
3. **Muted findings are invisible as such** (Exercise 5.2). Count findings with
   `status == "Suppressed"` separately, print them in their own section, and
   refuse to treat them as suppressed: a mutelist entry has no reason, owner or
   expiry, so by the tool's own rule it is something somebody hid.
4. **Tiers from prose** (Exercise 4). Make the rules match on the check ID and
   title only, or give the risk text a lower weight. Show, with before-and-after
   CSVs, which findings moved, and say for each move whether it got better or
   worse. "Internet" belongs somewhere; decide where.
5. **Suppressions by substring** (Exercise 6). Match `check` exactly against
   the check ID, and `resource` against the full ARN or a glob. Reject `until`
   more than a year away, and `who` values that are not a person (reuse the
   list from `risk-register.py`).
6. **`risk-register.py`**: take accepted risks out of the reduction ranking
   (list them separately, with their ALE), reject `impact_high_eur <
   impact_low_eur`, and make the scale check ask for a number **with a unit**
   (records, users, systems, invoices) rather than any digit.
7. For every change: the fixture that proved the bug, the output before, the
   output after. Commit messages name the fixture. "Fixed triage" is not a
   commit message.

---

## 15 · The deliverable

The Session 16 deliverable, built on Tagus rather than on an empty account:

| Component | From |
|---|---|
| Attack path: Friday's breach, mapped stage by stage to ATT&CK, with the control per stage | Exercise 9 |
| Scan output: raw counts (findings, distinct checks, muted), per account | Exercise 2 |
| Triage: your ordered list, with what you overrode in the tool and why | Exercises 4, 7 |
| Fixes: two findings fixed in your lab, with before-and-after evidence | Exercise 7 |
| Custom rule: the OIDC trust rule, with tests, and where it runs | Exercise 8 |
| Suppression: one, with what, why, who and the revisit date, and proof of what it hides | Exercise 6 |
| Risk register: three entries, full fields, impact as a **range with confidence** | Exercise 13 |
| Acceptance: one, with a named acceptor who has the authority, and a live review date | Exercise 13 |
| Logging decision: what data-plane logging you enable, what you do not, and why | Exercises 10, 13 |
| Incident review: the answer to Tiago's three questions | Exercises 10, 11 |

Four things that separate a good submission from a long one:

- **The muted finding.** Most submissions will triage the 312 and stop. The
  root cause of Friday was in the scan, at the right severity, in a sensible tier,
  and marked `Suppressed` by a contractor with a YAML comment. Say so.
- **What the scan cannot see.** One paragraph, from Exercise 1, on what you
  checked by other means. A triage that covers only the scanner's output has
  inherited the scanner's blind spots without saying so.
- **"We cannot yet say."** The honest answer to Rita, and what you did on
  Monday so that it would not stay that way. It needs a date, because the
  logs that answer it are deleted on a schedule.
- **Ownership.** Every item in your top ten names who fixes it. Tagus owns
  the decision to mute, to accept, and to wait for "phase 2". NuvemCerta owns
  some of the work. AWS owns very little of it.

Write the summary last. It is the first thing read, and you cannot write it
until everything else is done.
