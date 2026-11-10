# Session 16 — samples

**Tagus Logística**, one week after the handover. Session 15 read what
NuvemCerta delivered. Then three things happened, and all three are here:

1. **3 December.** Tiago (IT) ran Prowler against both accounts, as the slides
   say to. 312 failing findings. NuvemCerta's mutelist was passed to the scan,
   because "that is how it was set up".
2. **4 December.** Tiago started a suppressions file for `triage-findings.py`
   and turned GuardDuty on in `eu-west-1`, because the scan said it was off. A
   risk register draft went to the Board on the same day.
3. **5 December, a Friday.** GuardDuty raised a High finding at 14:26. Somebody
   saw it at 16:50.

You are the person Tiago sends his notes to on Monday the 8th, a public
holiday, with three questions at the bottom.

Everything is invented. Account IDs are AWS's documentation IDs, IPs are RFC 5737,
the ASNs are RFC 5398, domains are `.example`. The check IDs, titles, severities,
descriptions and risk texts in the scan are **Prowler's own**, taken from the
metadata of Prowler 5.14.1, so the triage tool reacts to them exactly as it
would to a real scan.

```bash
shasum -a 256 -c SHA256SUMS
```

## What is here

| Path | What it is | Exercises |
|---|---|---|
| `prowler/prowler-output-111122223333-*.ocsf.json` | Prowler OCSF output, **prod** account | 2–7 |
| `prowler/prowler-output-444455556666-*.ocsf.json` | Prowler OCSF output, **non-prod** account | 2, 3, 7 |
| `prowler/mutelist-nuvemcerta.yaml` | The mutelist NuvemCerta configured, passed to both scans | 5 |
| `suppressions-tagus.yml` | Tiago's suppressions for `triage-findings.py`, two of them from NuvemCerta | 6 |
| `register-draft.csv` | The risk register draft sent to the Board on 4 December | 12, 13 |
| `incident/web02-access.log` | nginx access log from WEB-02, copied by Tiago at 17:38, before he terminated the instance | 9 |
| `incident/cloudtrail-prod-2025-12-05.json.gz` | The prod trail for Friday, as Tiago pulled it on Monday | 9, 10, 11 |
| `incident/guardduty-prod-eu-west-1.json` | The detector and its two findings, exported on Monday | 9, 10, 11 |
| `incident/web02-portal-policy.json` | The identity policy of WEB-02's instance role | 10 |
| `incident/tiago-notes.md` | What Tiago did, in his words | 9, 11 |

## The accounts

| Account | What it is | CloudTrail |
|---|---|---|
| `111122223333` | Tagus **prod** | `tagus-trail`: **single-region**, `eu-west-1` |
| `444455556666` | Tagus **non-prod** | `nonprod-trail`: multi-region |

The difference in the right-hand column matters in Exercise 10.

## About the Prowler files

The OCSF JSON that `prowler aws --output-formats json-ocsf` writes, trimmed of the
compliance mappings (which run to several kilobytes per finding and add nothing
here). PASS findings are kept, but only some of them: a real scan has far more.

Two fields are worth knowing before you start:

- `status_code` is the result of the check: `PASS` or `FAIL`.
- `status` is what Prowler did with the result: `New`, or `Suppressed` when the
  mutelist matched. A muted finding is **still `FAIL`**.

## About the CloudTrail file

Same shape as Session 15's: one JSON document with a `Records` array, in UTC.
About fifty records: the invoice processor's hourly run, an IP nobody
recognises, and Tiago. What is **not** in it is most of the exercise.

Lisbon is on UTC in December, so Tiago's local times and the trail's agree.
That is luck. Do not build a habit on it.

## Handling

Hash on arrival, work in `out/` (git-ignored), notes as you go, in UTC. This time
the notes may be read by a regulator: Exercise 11 asks whether this is a
notifiable breach.
