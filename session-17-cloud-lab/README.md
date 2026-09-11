# Session 17 — Cloud Assessment Laboratory

> Everything here runs against **an environment you own, that you created for
> this purpose, and that you will destroy before you leave**. Every major cloud
> provider publishes a policy on customer security testing. Read yours before you
> test, every time, because they change. Denial of service testing is on the
> never list, everywhere.

## `attacklog.sh`

```bash
./attacklog.sh init lab-yourname "Your Name"
./attacklog.sh run enumerate -- cloudfox aws --profile lab all-checks
./attacklog.sh add escalate "aws iam create-policy-version ..." "ok" "CreatePolicyVersion"
./attacklog.sh show
./attacklog.sh gaps          # the comparison template for Block 3
```

### It counts your API calls

`run` counts the read-only calls in the output of anything AWS-shaped. This
matters: enumeration is the loudest stage of the entire chain and the least
monitored, and **"412 calls in ninety seconds"** is a far better finding than
"I enumerated the account".

### A failed stage is a finding

`run` reports a non-zero exit and asks the useful question: *which control
stopped you?* That is the control working, and it belongs in the report alongside
the ones that did not.

### `gaps` builds the Block 3 template

One row per logged action, with columns for: found in the audit log (yes /
partial / **NO**), the exact event name, the latency, whether an existing rule
would have fired, and the rule you wrote when it would not.

**The rows where `found_in_log` is NO are the most valuable artefact in the whole
course** — more than the attack, more than the report. They are a measured list
of detections you do not have.

---

## `teardown-check.sh`

```bash
./teardown-check.sh terraform ./tf-lab   # destroy, then prove state is empty
./teardown-check.sh sweep                # the survivors, in EVERY region
./teardown-check.sh checklist            # the full list, for the report
```

Set `AWS_ENDPOINT_URL` to point at LocalStack. Without it, this talks to a real
account — which is either exactly what you want or exactly what you do not.

### State empty is not account empty

Terraform only knows what it created. `sweep` looks for what it does not:

- **Snapshots, AMIs and volumes**, which outlive the instance they came from.
  This is the number one survivor, every time.
- **Versioned buckets**, where delete markers are not deletion and an "empty"
  bucket still holds every object.
- **Access keys and roles** created during the exercise.
- **Anything shared with an external account** — which is not a cost problem,
  it is a data problem.

And it checks **every region**, because the forgotten instance is never in the one
you deployed to.

### Leave the budget alert in place

It is the only thing that will tell you about what the sweep missed. The real
proof of teardown is the cost check the following day.

---

## `scope.sh`

```bash
./scope.sh new                 # build one, by interview
./scope.sh check <file.md>     # is this signed, bounded and current?
./scope.sh --explain           # why three authorisations, not one
```

The document you write **before** you touch anything. In cloud, "I was only
testing" is not a defence: the resources belong to a provider, the data belongs
to somebody else, and the account boundary is the only thing between a lab
exercise and unauthorised access to a computer system.

### Scope is not an IP range

An IP range in cloud is a lie that changes every deploy. Scope is account IDs,
subscription IDs, project IDs, regions and resource tags. `new` asks for those
and writes the sentence that matters:

> Anything not listed below is out of scope, **including anything interesting
> discovered during the engagement that appears to be connected.**

### Three authorisations, not one

1. **The client, in writing.** Someone with the authority to grant it — the
   person who invited you to the meeting frequently is not that person.
2. **The provider's published policy**, read today, not recalled from a blog
   post someone linked in a wiki. Denial of service is universally excluded.
3. **Any third party in scope.** The client cannot authorise testing against a
   system the client does not own.

Leave a list blank and the generator writes the refusal in words rather than an
empty heading — an empty section reads as coverage.

### The clause everyone forgets

> If an active adversary is discovered mid-assessment, the engagement stops and
> becomes an incident.

With a named person and an out-of-hours phone number, agreed in advance,
precisely so nobody is negotiating it at 03h00 on a Saturday.

`check` runs the whole thing past a reviewer's eye — account-based scope, DoS
exclusion, named authoriser, provider policy, third parties, window, stop
conditions, adversary clause, a reachable phone number — warns when the latest
date in the document has already passed (a closed window reads as authorisation
while granting none), and exits non-zero. Do not start on a non-zero.
