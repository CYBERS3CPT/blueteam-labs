# Blue Team Labs

Scripts for *Curso de Especialização — Operacional de Cibersegurança Defensiva*,
one folder per session. Seventeen sessions, seventeen weeks of somebody asking
"is there a script for that?"

Now there is.

---

## What this is

Each script does one job that you would otherwise do from memory at 23h00 and
get subtly wrong. They are opinionated on purpose: several of them refuse to
produce output they consider dishonest, and say why. That is not a bug.

They are also written to be **read**. If you only run them, you have got about a
third of the value. The comments explain the reasoning, and the reasoning is the
part that transfers to the job.

## Layout

```
lib/common.sh                      shared plumbing: colours, dependency checks, UTC

session-01-ids-ips/                suricata-lab.sh      rules, and whether they fire
                                   pcap-triage.sh       six questions of a capture file
session-02-firewalls-honeypots/    honeypot-lab.sh      Cowrie, watching people try
                                   firewall-review.sh   read a ruleset like an attacker
session-03-malware-triage/         static-triage.sh     offline, never uploads
                                   yara-gen.py          rules that survive a benign corpus
session-04-lab-and-ghidra/         lab-doctor.sh        is the lab actually isolated
                                   ghidra-headless.sh   analysis without the GUI
session-05-osint-ews/              ews.py               an early-warning feed you own
                                   passive-recon.sh     passive means passive
                                   evidence-log.sh      capture a page so it holds up
session-06-socmint-phishing/       eml-triage.py        headers, links, what it claims
                                   profile-score.py     is this account a person
                                   report-scaffold.py   the sections you keep forgetting
session-07-forensic-acquisition/   acquire.sh           an image that survives challenge
                                   memory-capture.sh    volatile order, enforced
session-08-analysis-timeline/      timeline-reduce.py   two million lines to two hundred
                                   hunt.sh              artefacts, asked as questions
                                   wtmp-read.py         the wtmp your new last can't read
session-09-mobile-forensics/       epoch.py             every timestamp format mobile uses
                                   android-collect.sh   logical collection, with consent
                                   ios-backup.py        read a backup without a licence
session-10-soc-coverage/           attack-layer.py      honest ATT&CK coverage
                                   metrics.py           every speed metric, paired
session-11-soc-workflow/           soc-stack.sh         Wazuh + TheHive + Cortex
                                   handover.sh          the note that saves the next shift
                                   playbook.sh          containment decided in daylight
session-12-access-audit/           access-audit.sh      who can actually log in
                                   harden.sh            baseline, measured before and after
session-13-keycloak/               keycloak-lab.sh      a realm you can break safely
                                   jwt-decode.py        decoding is not verifying
                                   oidc-flow.py         the whole flow, narrated
session-14-access-lifecycle/       access-review.py     no approve-by-default
                                   deprovision-check.sh the thirteen things people miss
session-15-cloud-iam/              localstack-lab.sh    cloud practice without a bill
                                   policy-lint.py       a policy read as an attack path
session-16-cloud-triage/           triage-findings.py   312 findings into a morning
                                   risk-register.py     findings become risks, with owners
session-17-cloud-lab/              scope.sh             written before you touch anything
                                   attacklog.sh         log the attack as you run it
                                   teardown-check.sh    prove the lab is actually gone
```

**24 shell scripts, 17 Python.** No dates anywhere: the material is meant to be
re-run for every edition of the course.

Every folder has its own README with the reasoning. Every script answers `--help`.

## Getting started

```bash
git clone <this repo>
cd blueteam-labs
./session-01-ids-ips/suricata-lab.sh check
```

No install step. Bash scripts source `lib/common.sh` by relative path; Python
scripts are standard library only, except where a README says otherwise. Nothing
here is packaged, because packaging teaching scripts is how they stop being read.

**Requirements** are checked at runtime. If something is missing the script tells
you what to install rather than dying with a stack trace.

## Rules of engagement

Non-negotiable, and they are in the scripts as well as here.

- **Your own lab, or an environment you have written authority to test.** Not
  your employer's, not a client's, not a classmate's.
- **No personal devices.** `android-collect.sh` will ask you to confirm this and
  will not proceed without it.
- **Passive means passive.** `passive-recon.sh` will not scan, will not probe,
  and will not brute force. The `-passive` flag on amass is load-bearing.
- **Nothing uploads a sample anywhere.** `static-triage.sh` runs entirely
  offline, because submitting a client's binary to a public service can tell the
  adversary you are looking.
- **Cloud providers publish testing policies.** Read yours before every
  engagement. They change. Denial of service testing is on the never list,
  everywhere.

## Some opinions, baked in

A few scripts will argue with you. Briefly, so it is not a surprise:

| Script | What it refuses |
|---|---|
| `attack-layer.py` | Building a coverage layer where most cells are scored "strong". Most rules detect one implementation; that is a 1. |
| `attack-layer.py` | A scored rule with no data source named. You cannot detect a technique whose telemetry you do not collect. |
| `jwt-decode.py` | Saying "valid" without a JWKS. Decoding is not verifying, and that confusion is the most common JWT vulnerability there is. |
| `acquire.sh` | Imaging a device whose write block it has not tested by attempting a write. |
| `triage-findings.py` | Honouring a suppression without a reason, a named owner and an expiry date. |
| `access-review.py` | Defaulting to "keep". Approve-by-default is a signature, not a review. |
| `honeypot-lab.sh` | Binding port 22. You will lock yourself out and blame the honeypot. |
| `yara-gen.py` | Emitting a rule it has not tested against a benign corpus. `--test` exits non-zero on a false positive. |
| `memory-capture.sh` | Writing the capture to the system disk it is capturing. Quietly, without lecturing you. |
| `wtmp-read.py` | Parsing a file whose size is not a whole number of records. A misaligned parse prints plausible garbage. |
| `metrics.py` | Reporting mean time to detect without the coverage figure beside it. A fast number on a narrow scope is a flattering number. |
| `harden.sh` | Running `after` without a `before`. A baseline you cannot diff is a claim, not a measurement. |
| `deprovision-check.sh` | Pretending to be complete. It tells you which of the thirteen steps it cannot see from here. |
| `risk-register.py` | An `accept` treatment with no named acceptor. That is not acceptance, it is being ignored. |
| `scope.sh` | A scope document with no third-party position, no stop conditions, or a window that has already closed. |

## Two conventions worth knowing

**Everything is UTC.** Every timestamp these scripts emit, every log line, every
filename. A timeline mixing timezones is worse than no timeline, because it looks
authoritative.

**Evidence travels with findings.** Where a script produces findings it also
produces the command that found them, so the person receiving the list can
reproduce it without asking you anything. A finding that cannot be reproduced
gets closed as "could not reproduce" by somebody who did not try very hard, and
you will not be in the room.

## Contributing

If a script was wrong, or right in a way that was not useful, open an issue and
say which and why. Findings welcome; opinions clearly labelled as such, please.

## Licence

MIT. See `LICENSE`.
