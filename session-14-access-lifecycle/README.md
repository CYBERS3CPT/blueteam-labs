# Session 14 — Access Lifecycle and Federation

## `access-review.py`

```bash
./access-review.py --url http://localhost:8080 --realm blueteam --user admin --password admin
./access-review.py ... --inactive-days 90 --out review-Q4.csv
./access-review.py --check review-Q4.csv     # when it comes back signed
```

Reads a Keycloak realm through the admin API. **Nothing is modified.** The tool
cannot revoke anything, deliberately: a review is a decision record, and executing
it is a separate, deliberate step by someone who read it.

### The default in every row is REVOKE

Keeping requires a tick **and** a reason. Approve-by-default is not a review, it
is a signature — and the revocation rate is the metric that tells you which one
you got.

### One row per entitlement, grouped by entitlement

Not one row per person. A reviewer decides per entitlement; "keep Ana" is not a
decision. Grouping by entitlement rather than by user also keeps the reviewer in
one context instead of context-switching down a list of names.

### `what_it_means` is a real column

`realm-admin` means nothing to the person signing. "Full administrator of this
realm" means something. If the reviewer cannot tell what they are approving, the
approval is worthless, and that is a design failure rather than a reviewer failure.

### `--check` is the other half

When the CSV comes back it looks for: rows with no decision (an undecided row is
a kept row by accident), "keep" with no reason, no reviewer named, privileged
entitlements kept while still lacking MFA — and a revocation rate of zero, which
is what a wholesale four-minute approval looks like from the outside.

It exits non-zero when it finds them, so a pipeline can refuse an unsigned review.

### If `last_used` is empty

Keycloak event logging is off. Turn it on before running this, or the review is a
list of names — and "last used" is the single most decision-enabling column on
the sheet.

---

## `deprovision-check.sh`

```bash
./deprovision-check.sh checklist          # all thirteen steps, for the report
./deprovision-check.sh keycloak ana
./deprovision-check.sh ssh-keys ana
./deprovision-check.sh local ana
./deprovision-check.sh report ana         # everything, as a findings list
```

Read-only. It reports; it never revokes. Revocation is a deliberate act by
somebody who read the report.

### Disabling the account is step one of thirteen

Steps 3, 5 and 11 are the ones that survive step 1 and get forgotten:

- **Refresh tokens outlive the account.** The script queries Keycloak's offline
  sessions specifically.
- **SSH keys survive account deletion entirely.** The key is in a file on every
  host they ever logged into.
- **Service accounts they owned** do not stop working when their owner leaves.
  They stop being anybody's responsibility, which is worse.

### It tells you what it cannot see

`ssh-keys` checks *this host* and says so plainly: the key is on every host they
ever reached, and this script cannot see those — configuration management can.

`report` ends with a line that matters more than the count:

> nothing outstanding **that this script can see** — which is not the same as
> complete. Nine of the thirteen steps are in systems this script cannot reach.

That is the honest framing, and it is also the argument for SCIM: without it,
step 8 is a manual list somebody maintains.
