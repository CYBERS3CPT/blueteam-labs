# Session 17 — Exercises

Hands-on and Kali-first, built on `scope.sh`, `attacklog.sh` and
`teardown-check.sh`, on the fixtures in `samples/`, and on your own LocalStack
lab from Session 15. Nothing here touches a real AWS account. Everything is
fictional, and the only environment anything runs against is one you started
on your own machine tonight and will destroy before you leave.

**The case so far.** *Tagus Logística* was phished (Session 6), had a web server
compromised (Sessions 7–8), and moved to AWS with a contractor, NuvemCerta, who
kept a support role and left a CI trust that any GitHub repository could use
(Session 15). Tiago ran Prowler, muted what he was told to mute, and on a Friday
afternoon one of the muted findings was used (Session 16).

Rita then asked for an independent assessment before the January Board. Tiago
engaged Rede Azul Segurança for a week against non-prod. The assessors said
"clean" on the Friday evening. On the Monday, Tiago looked for himself. The
scope, the closing email, the sweep they attached, and what Tiago found are in
`samples/`. His notes end with four questions.

Tonight you answer them, and you hold your own lab to the standard you are
about to hold Rede Azul to: a scope you would sign, a log of what you did that
survives comparison, and a teardown you can prove.

## Before you start

```bash
cd blueteam-labs/session-17-cloud-lab
sudo apt install -y awscli jq docker.io
mkdir -p out                              # git-ignored
(cd samples && shasum -a 256 -c SHA256SUMS)
../session-15-cloud-iam/localstack-lab.sh up     # LocalStack 4.14.0, profile blueteam-lab
export AWS_PROFILE=blueteam-lab AWS_ENDPOINT_URL=http://localhost:4566
aws sts get-caller-identity
echo "$(date -u +%FT%TZ)  START  session 17 exercises" > out/my-notes.txt
```

The account ID must be `000000000000`. If it is anything else, stop: you are
not where you think you are, and Exercises 5 and 9 create resources. The
`AWS_ENDPOINT_URL` variable needs AWS CLI 2.13 or later (`aws --version`); an
older CLI ignores it and talks to AWS, which is exactly what this check catches.
Every terminal you open tonight needs the `export` line again.

Ground rules:

- **Your lab, your scope, before your first command.** Exercise 3 comes before
  Exercise 5 for a reason. Nothing in this sheet is run against an endpoint
  that is not `localhost`.
- **Read the tool, not just its output.** All three scripts are short. In
  Exercises 2, 5, 6, 8 and 9 you will catch them saying something their own
  code does not do. That is deliberate, and Exercise 12 is where you fix them.
- **Do not "clean up" the fixtures in your head.** Several of Tiago's findings
  are evidence before they are mess. Exercise 11 decides which.

| # | Exercise | Tools | Time |
|---|---|---|---|
| 1 | Read the scope like the client's lawyer | a pencil | 20 min |
| 2 | What `check` checks | `scope.sh check`, `sed` | 15 min |
| 3 | A scope for your own lab | `scope.sh new` | 15 min |
| 4 | The clause, and the person it names | the scope, the email | 15 min |
| 5 | Log as you go, then count honestly | `attacklog.sh`, LocalStack | 25 min |
| 6 | The template that loses things | `attacklog.sh gaps` | 15 min |
| 7 | Predict the log | your attack log, AWS docs | 30 min |
| 8 | The sweep that said clean | the sweep, the role, `teardown-check.sh` | 20 min |
| 9 | Five survivors of your own | LocalStack, `teardown-check.sh sweep` | 30 min |
| 10 | What was left behind | `jq`, Tiago's inventory | 25 min |
| 11 | Sunday | your notes so far | 20 min |
| 12 | Patch the tools | your editor | 40 min |
| 13 | The deliverable | everything above | 60 min+ |

Exercises 1–4 are Block 1 (authorisation), 5–7 Block 2 and the first half of
Block 3 (your own chain, and finding yourself in the logs), 8–11 the teardown
that the session closes with, applied to someone else's engagement first.

---

## 1 · Read the scope like the client's lawyer

`samples/engagement/tagus-nonprod-scope-v1.md`. It was built with `scope.sh
new` and then edited by hand before signing. Read it once, fully, before any
tool.

1. **Who authorised it?** Read section 3.1. Then reread the README's first
   authorisation: *someone with the authority to grant it*. Can the person who
   runs the cloud authorise a third party to access it, including production?
   Who at Tagus can? What would you have asked for before starting?
2. **What is in scope?** Two accounts, one of them prod, "read-only". List what
   a read-only role can do in prod that would trouble Rita. (Think about what
   `logs:FilterLogEvents` returns, and what Session 16's GuardDuty finding was
   about.) Is "read-only" a boundary, or a description of intent?
3. **Regions: All. Tags: none.** Then, in section 4, *"All of them are tagged
   `engagement=redeazul-2025-12`"*. Which of those two statements does a
   teardown rely on? What does "All" regions cost Tagus when it is time to prove
   nothing was left?
4. **Third parties.** Two systems Tagus does not own are listed as in scope,
   with *"Tagus to inform"*. Is informing authorising? Who would have had to
   sign for GitHub, and for the SFTP provider? Find the line in section 2 that
   contradicts section 3.3. It was written by the generator, not by anybody.
5. **Rules of engagement.** Three lines were added or rewritten by hand: find
   them (you will do it with a tool in Exercise 2.6, do it by eye first). For
   each one, say what it contradicts: another line in the same document, or the
   line the generator had written there before somebody replaced it (read the
   template in `scope.sh`):
   - 500 authentication attempts per minute, against a third party;
   - personal data copied to the assessor's own AWS account;
   - test resources created "without further approval".
6. **The window.** `2025-12-15 09:00 to 2025-12-19 18:00`. In which time zone?
   In December, Lisbon and UTC agree. What happens to this sentence in June?
7. **The provider policy.** What is the URL, and when was it written? Find the
   current AWS penetration testing policy yourself and write down its URL and
   today's date. Does the current policy say anything about what Rede Azul did
   in section 4 (the SFTP line)?
8. Write a short list: what you would refuse to sign, what you would sign with
   a change, and what you would sign as is. One line each, with the reason.

---

## 2 · What `check` checks

```bash
./scope.sh check samples/engagement/tagus-nonprod-scope-v1.md; echo "exit $?"
```

1. Eleven `ok` and one `WARN`. Which item fails, and why does it fail tonight
   but would not have failed on 14 December 2025? So the only objection the tool
   has is the calendar.
2. Prove it:
   ```bash
   sed 's/2025-/2099-/g' samples/engagement/tagus-nonprod-scope-v1.md > out/scope-2099.md
   ./scope.sh check out/scope-2099.md; echo "exit $?"
   ```
   Bounded, authorised three ways, reachable out of hours. Read `check()` and
   say, for each of the eleven lines, what it actually tests.
3. Write the shortest file that passes. (One line is enough. Try it.) What does
   that tell you about a check that reads for keywords?
4. **The phone number.** Delete the escalation phone number from your 2099 copy
   (leave the rest of the row) and run `check` again. Does it still find "a
   phone number that is actually written down"? Which string in the document is
   it matching now?
5. **The authoriser.** `check` looks for the words `authorised by`. Make the
   name in that row `TBD` and run it again.
6. **Diff against the generator.** Run `./scope.sh new`, give it the same
   answers the signed document shows (accounts, regions, authoriser, contacts),
   and `diff` its output against the signed copy. Every line in the diff that is
   not your typing is a hand edit. Does the diff find all three lines from
   Exercise 1.5? What else does it find?
7. A check that cannot fail on meaning is still useful. Say what for, in one
   sentence, and what it must never be used for.

---

## 3 · A scope for your own lab

```bash
./scope.sh new
```

The scope for **tonight**, for the LocalStack container you started above.
The generator names the file `scope-<client>.md`, which `.gitignore` excludes,
so it will not be committed by accident. Move it to `out/` anyway.

1. Accounts: `000000000000`. Regions: the one you will use. Tags: one tag you
   will actually put on everything you create in Exercise 9.
2. The client authoriser is you, as owner of the machine. Write down why that
   is legitimate tonight and would not be for an employer's laptop.
3. The provider: LocalStack runs on your machine, so the provider whose policy
   matters is **Docker Hub's image licence** and nobody else's, until the day
   you point this at a real account. Write that sentence into section 3.2, then
   add the AWS policy URL you found in Exercise 1.7 for that day.
4. Out of scope: write the three things you will be tempted by tonight. (Your
   real `~/.aws/credentials` is a good start. Session 15, Exercise 4 explains
   why.)
5. `./scope.sh check out/scope-*.md`. It should pass. Now say what in your
   document it did not read.

---

## 4 · The clause, and the person it names

The scope's active adversary clause, section 4.2, names who to call. Then read
the last paragraph of `samples/engagement/closing-email.txt`.

1. Who is the escalation contact, which company do they work for, and what is
   their role in Tagus's AWS accounts (Session 15)? What is their phone
   number's "out of hours"?
2. On Tuesday, Rede Azul saw activity in non-prod from a GitHub repository
   that was neither theirs nor Tagus's. Read stop condition 4 and the clause
   below it. Should testing have stopped? Who decides that, and when?
3. "Rui is aware." Read Session 15, Exercise 8, and Session 16, Exercise 5
   (who muted what). Whose repository was it most likely to be? What did telling Rui do to the
   evidence, and to Tagus's ability to investigate quietly?
4. Rewrite section 4.2 and the contacts table so that the call goes to
   someone at Tagus who can open an incident, with a number that is answered
   out of hours, and a second name if the first does not answer. Say why the
   contractor with standing access to the estate is the one name that must not
   be on it.
5. The clause says *we do not tip off the adversary by changing anything*.
   Rede Azul had a builder role in non-prod for five days. List two things
   their own testing changed that an adversary watching the account could have
   noticed.

---

## 5 · Log as you go, then count honestly

Your own lab. Only `localhost`.

```bash
cd out
export ATTACK_LOG=$PWD/attack-log.csv
../attacklog.sh init lab-$(whoami) "$(whoami)"
../attacklog.sh run enumerate -- aws sts get-caller-identity
../attacklog.sh run enumerate -- aws s3api list-buckets
../attacklog.sh run enumerate -- aws iam list-users
../attacklog.sh run enumerate -- aws iam list-roles
../attacklog.sh run enumerate -- aws lambda list-functions
../attacklog.sh show
```

1. Look at the `api_calls` column. Each command made at least one API call.
   What does the column say for `list-buckets` on an empty lab? For `list-roles`?
2. Read `cmd_run()`. What is it counting? Create two IAM users called
   `getty` and `describer` and run `list-users` again. How many "calls" now?
3. LocalStack logs every request it serves. Count them for the same period:
   ```bash
   docker logs blueteam-localstack 2>&1 | grep -E 'AWS [a-z0-9-]+\.[A-Za-z]+ =>' | tail -20
   ```
   Put the two numbers side by side for each command. Which one would you put
   in a report as *"N calls in M seconds"*?
4. `cmd_run` counts only when the command line contains `aws`, `cloudfox` or
   `pacu`. Name a tool from this session's slides that it would count as zero.
   (Note too that `AWS_ENDPOINT_URL` is not in the logged command. Six months
   from now, how would a reader of this log know it ran against `localhost`?)
5. Now the session's chain, on your own lab, as the slides describe it in
   Block 2. Log **every** step with `run` or `add` as you do it, including the
   ones that fail. Use `note` for what you were thinking when you changed
   direction. Write the expected event in `add`'s fourth argument every time.

---

## 6 · The template that loses things

```bash
../attacklog.sh add enumerate "aws s3api list-objects-v2 --bucket lab --query 'Contents[].[Key,Size]'" "ok, 3 objects" "ListObjectsV2 (S3 data event)"
../attacklog.sh gaps
```

1. Open the `detection-gaps-*.csv`. Find the row you just added. What happened
   to the command? To the expected event you typed?
2. Read `cmd_gaps()`. Which column of your log does it never copy? You filled it
   in, every time, in Exercise 5.5. Where did it go?
3. Run `show`. Does `column -s,` agree with the CSV about where the fields
   are, for the row with a comma in it?
4. The README calls the NO rows *"the most valuable artefact in the whole
   course"*. Say what this template does to that artefact, and how long it would
   take a tired student at 20:40 to notice.
5. Fill in your gaps file anyway, by hand, from your own log. You will fix the
   tool in Exercise 12.

---

## 7 · Predict the log

LocalStack does not write CloudTrail. That is a limitation of the lab, not a
reason to skip the comparison: you predict what a real account would have
recorded, with a source for every prediction, and you compare it with what
LocalStack's request log shows that CloudTrail would not.

For every row in your attack log:

1. **Would CloudTrail record it, by default?** Management event, data event,
   or not recorded at all. Cite the AWS documentation page for each service you
   used. Be exact for these: `GetCallerIdentity`, `ListBuckets`,
   `GetObject`, `Invoke` (Lambda), `GetSecretValue`, `PutResourcePolicy`,
   `ModifySnapshotAttribute`, `AssumeRole`.
2. **Which event name, in which account?** For a cross-account `AssumeRole`,
   which of the two accounts sees it? (Session 15's trail is a worked example.)
3. **How long until it is queryable?** Find what AWS says about CloudTrail
   delivery time, and whether it is a promise.
4. **Would anything you already have fire?** Check your Session 16 detection
   list. Then write the rule for your most serious NO, with its expected false
   positive rate and the reason for that rate.
5. Now the other direction: which calls in LocalStack's request log are
   **not** in your attack log? (`localstack-lab.sh` and your own typing both
   count.) A comparison only works if the attack log is complete.
6. Fill `found_in_log` and `event_name` in your gaps file with your predictions,
   marked as predictions. A prediction labelled as a measurement is the Session 7
   mistake, in a new place.

---

## 8 · The sweep that said clean

From the session folder (`cd ..` if you are still in `out/`).

`samples/engagement/teardown-sweep-2025-12-19.txt`, attached to the closing
email, and `samples/engagement/redeazul-assessor-role.json`, the role it was run
with.

1. How many regions did it check? Read `cmd_sweep()`: where does that number
   come from when `describe-regions` fails? Which regions are not on that list?
2. List every AWS action the sweep calls. Then list every action the assessor
   role allows. How many appear in both?
3. So every call was denied. Read the code: what does each check do with an
   `AccessDenied`? Why does an empty bucket list print `ok  no buckets`?
4. Reproduce it on your own machine, without AWS, by pointing the sweep at a
   port where nothing answers:
   ```bash
   AWS_ENDPOINT_URL=http://127.0.0.1:9 ./teardown-check.sh sweep; echo "exit $?"
   ```
   It takes a minute or two, because the CLI retries. What does the screen say? What does the exit code say? Which of the two did
   the closing email quote?
5. Look at the command in the email: `... sweep | tee teardown-sweep.txt`. Read
   `warn()` and `bad()` in `lib/common.sh`. Suppose the sweep **had** found a
   survivor: would its name be in the attached file? Run the sweep against your
   lab with `2>/dev/null` and see.
6. The email says *"no access keys"*. Does the sweep's output say that? Read
   what it printed under IAM, and say what an empty section means here.
7. Who chose to run the sweep with the role that could see the least? Was the
   tool wrong, or was it used wrong? (Tiago's first question. The honest answer
   has two parts.)

---

## 9 · Five survivors of your own

Plant the things `terraform destroy` leaves behind, in your lab, and see what
the sweep sees. The commands below carry no tags. Add your scope's tag to each
one yourself (`--tags`, `--tag-specifications`, `tag-resource`, depending on the
service), and write down which ones you forgot: that list is Exercise 10.4 and
10.5, in your own lab.

```bash
aws sts get-caller-identity --query Account --output text   # 000000000000, or stop
aws s3api create-bucket --bucket lab-evidence --create-bucket-configuration LocationConstraint=eu-west-1
aws s3api put-bucket-versioning --bucket lab-evidence --versioning-configuration Status=Enabled
aws iam create-user --user-name lab-tmp && aws iam create-access-key --user-name lab-tmp
aws secretsmanager create-secret --name lab/db --secret-string not-a-secret
aws secretsmanager put-resource-policy --secret-id lab/db --resource-policy \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::210987654321:root"},"Action":"secretsmanager:GetSecretValue","Resource":"*"}]}'
V=$(aws ec2 create-volume --availability-zone us-east-2a --size 1 --region us-east-2 --query VolumeId --output text)
S=$(aws ec2 create-snapshot --volume-id "$V" --region us-east-2 --query SnapshotId --output text)
aws ec2 modify-snapshot-attribute --snapshot-id "$S" --region us-east-2 \
  --attribute createVolumePermission --operation-type add --user-ids 210987654321
```

Add a Lambda function too (the slides' lab module has one; any zip with a
handler will do). Then:

```bash
./teardown-check.sh sweep > out/sweep.out 2> out/sweep.err; echo "exit $?"
```

1. Make a table: survivor, found by the sweep (yes/no), where it was reported
   (stdout or stderr), and the line.
2. The snapshot count per region is in the hundreds or thousands. Are those
   yours? Check one snapshot's `OwnerId` against your account ID. What is the
   emulator doing with `--owner-ids self`, and what does Session 15, Exercise 10
   say about trusting one emulator?
3. You shared a snapshot with an external account. Did the "shared with an
   external account" section find it? Read the code: in which region does it
   look, and how many snapshots does it check?
4. The secret with a resource policy granting another account: which part of
   the sweep would have found it?
5. The Lambda function: same question.
6. The sweep checks keys on users, but not who the keys belong to or when they
   were last used. What would you want it to print for `lab-tmp`?
7. Write the list of what a sweep must check that this one does not. Keep it:
   Exercise 12 implements it, and Exercise 10 uses it today.

---

## 10 · What was left behind

Tiago's inventory, `samples/inventory/`. Work from the files, with `jq`.

1. **Cost.** Open the Cost Explorer CSV. Which usage type appears on the 17th
   and not before? What does it cost per day, and roughly how many GB is that?
   Tiago nearly closed the file. What would make a cost check find a survivor
   that is sensitive but cheap?
2. **The snapshot.** In `snapshots-us-east-2.json`: when was it made, from
   what, is it encrypted, who can use it? `VolumeId` is `vol-ffffffff`: look up
   what that means and say what it tells you about how the snapshot got to
   us-east-2, and what else therefore existed, at least for a while.
   Why would Tagus's default EBS encryption setting not apply here?
3. **The data.** The description says what volume it is a copy of. Compare
   with section 4 of the scope: is a 20 GB disk *"a sample of up to 50 records"*?
4. **The function.** `ra-oidc-probe` is tagged. Find out why tag-based cleanup
   missed it:
   ```bash
   jq '.Tags.engagement | @json' samples/inventory/lambda-tags-ra-oidc-probe.json
   ```
   Write the exact `resourcegroupstaggingapi get-resources` filter that would
   have missed it, and one that would not.
5. **The role.** `ra-lab-exec` has no tags at all, and the scope says every
   resource is tagged. Is the role a survivor or a dependency of one? What do
   you need to see before deleting it (think `probe-read`)?
6. **The user.** In the credential report: `ra-tmp`. When was its key created,
   when last used, for what? Is it tagged? (How would you find out?) Who could
   still use that key tonight?
7. **The secret.** `tagus/invoices/db-nonprod` grants `GetSecretValue` to
   `210987654321`. Is that Rede Azul's *"evidence store"*? What does removing
   the policy fix, and what does it not fix? (The secret's value has been
   readable from another account for a week.)
8. **What Tiago did not look at.** He listed Lambda in one region, roles
   created in December by hand, and found us-east-2 by its cost. Using your list
   from Exercise 9.7, write the commands he still has to run, in which regions,
   and in what order. Which one would you run first, and why?

---

## 11 · Sunday

`RedeAzul-Assessor` was last used on Sunday 21 December at 09:14, two days
after the window closed. Rede Azul asked to keep the role *"in case we need to
re-verify a finding"*.

1. Read the role's trust policy. Who, exactly, can assume it? Is there an
   `ExternalId`? A condition on source identity? How long can a session last?
2. Read its permissions. *"It is read-only."* What can `logs:FilterLogEvents`
   and `cloudtrail:LookupEvents` return, in an account where a database secret
   was readable from outside for a week?
3. The scope says *"Nothing runs outside it"*. Is Sunday's use authorised? Does
   it matter whether the person was Marta? Write down who would have to say
   yes for it to be authorised, and whether they did.
4. **What to pull, before anything changes.** Name the CloudTrail events you
   would look for in non-prod for that session (the `AssumeRole`, and
   everything done with it), the fields that identify who assumed it and from
   where, and how far back the event history goes if there is no trail
   delivering to S3. Which of these did Tiago export? Which did he not?
5. **Who to call.** Tiago asks if it is Rui. Answer from Exercise 4.
6. **Order of work.** These are on Tiago's list: delete the role; unshare the
   snapshot; remove the secret's resource policy; rotate the database
   credential; delete `ra-tmp`'s key; delete the function and its role; ask Rede
   Azul, in writing, for their own logs of the engagement and what they hold.
   Put them in order. For each, say whether doing it destroys evidence, and if
   so what you preserve first.
7. Tiago wrote *"I have not deleted anything. I have not called anyone."* One of
   those was right. Which?

---

## 12 · Patch the tools

All three scripts are part of this course, and in Exercises 2, 5, 6, 8 and 9
you caught them being wrong. Fix them.

1. **`teardown-check.sh` swallows errors** (Exercise 8). Every AWS call that
   fails must be reported as `could not check`, with the error, and the run
   must end with a count of checks that could not run. A sweep with any of them
   must not print `ok` anywhere, and must exit non-zero.
2. **Regions** (Exercise 8.1). If `describe-regions` fails, refuse to continue
   instead of guessing five.
3. **Ownership** (Exercise 9.2). Filter snapshots, images and volumes on the
   account ID from `sts get-caller-identity`, not on `--owner-ids self` alone.
4. **Sharing** (Exercise 9.3). Check snapshot permissions in every region, for
   every snapshot.
5. **What it never looked at** (Exercises 9.4–9.6). Lambda functions, secrets
   with resource policies, IAM users with active keys and their last use. Each
   in every region where the service is regional.
6. **stdout and stderr** (Exercise 8.5). A survivor's name must reach a file
   written with `| tee`. Decide whether that means `warn` goes to stdout, or
   the sweep writes its own report file. Say why.
7. **`attacklog.sh`** (Exercises 5 and 6). Write real CSV (Python's `csv`
   module, or proper quoting in `gaps`), carry `expected_event` into the gaps
   template, and stop calling the count `api_calls`: either count real calls
   (`--debug`, or the endpoint's own log) or name the column for what it is.
8. **`scope.sh check`** (Exercise 2). Pick two of the eleven checks and make
   them check meaning: a phone number that is a phone number, in the escalation
   row; an authoriser row that is not empty or `TBD`. Leave the rest as keyword
   checks and say so in the output.
9. For every change: the fixture or lab state that proved the bug, the output
   before, the output after. Commit messages name it.

---

## 13 · The deliverable

The session's final deliverable is the cloud assessment report on **your own**
laboratory, as the slides describe it. Tonight's exercises add three parts to
it, and a short note to Rita.

| Component | From |
|---|---|
| Scope and authorisation for your lab, with what `check` did not read | Exercises 2, 3 |
| Attack log, complete, with your call count measured from the endpoint | Exercise 5 |
| Detection mapping: per action, predicted event, management or data, source | Exercises 6, 7 |
| Detection gaps: the three largest, and the rule for the worst | Exercise 7 |
| Teardown evidence: `terraform destroy`, **and** your patched sweep, clean, with stderr | Exercises 9, 12 |
| Review of the Rede Azul engagement: scope, clause, sweep, survivors | Exercises 1, 4, 8, 10 |
| Tiago's four questions, answered | Exercises 8, 10, 11, 4 |

**The note to Rita.** One page, no jargon, for someone who signs things. What
the assessment was, what was found that it left behind, what was done on
Monday and in which order, what is still unknown and by when it will be known,
and the two changes to how Tagus engages anyone with access to its accounts
next time.

Four things that separate a good submission from a long one:

- **The scope is where it went wrong.** Most of what Tiago found on the 22nd
  was allowed, or not forbidden, by a document that passed `check`. Say which
  lines, and what you would have refused to sign.
- **"Clean" is a claim about a tool and a credential.** The sweep said what it
  could see. Say what it could not, and why the screen and the exit code
  disagreed.
- **Evidence before tidiness.** Every survivor is also a record of what was
  done. The order of the Monday list matters more than its length.
- **Your own lab, same standard.** If your teardown evidence is a sweep that
  printed `ok`, show its stderr and its exit code. If it is a cost check, show
  the next day's.

Write the note to Rita last. It is the first thing read.
