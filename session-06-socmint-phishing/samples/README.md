# Session 6 — samples

Analysis targets for `eml-triage.py` and `profile-score.py`. Everything here is
invented. **Tagus Logística** (`tagus-logistica.example`) is a fictional company,
every domain sits under `.example` (RFC 2606) and every IP address is in the
documentation ranges (RFC 5737). If any of it ever resolves, someone else has
made a mistake.

The point of these files is to be *read* with the tools, not admired. Hash them
on arrival, then get to work.

```bash
shasum -a 256 -c SHA256SUMS      # prove you have what everyone else has
./eml-triage.py samples/*.eml --brief
```

## The seven messages

Each one is a target for a different set of the ten checks. One of them is
legitimate — the control. Knowing which, and being able to say *why* in terms of
headers rather than vibes, is the exercise.

| File | What it exercises |
|---|---|
| `01-invoice-exact-spoof.eml` | Exact-domain spoof; SPF/DKIM/DMARC fail; the case a published `p=reject` would have stopped |
| `02-ceo-lookalike-bec.eml` | A lookalike domain that passes all authentication because the sender owns it — the case DMARC does **not** cover |
| `03-helpdesk-display-name.eml` | Display name says one thing, address says another; `Reply-To` points elsewhere |
| `04-password-expiry-homoglyph.eml` | A Cyrillic character inside the domain (punycode); link text vs destination |
| `05-shipping-rlo-attachment.eml` | Attachment whose declared type and real type disagree, with a right-to-left-override filename. A harmless stub — you still don't run it |
| `06-newsletter-legit.eml` | Legitimate mail through an ESP. The control. "No findings" is a finding |
| `07-mfa-quishing.eml` | Authentication passes, no URLs in the text — the link lives inside a QR image |

## The five profiles

In `profiles/`. Read `profiles/PROFILES.md` for what each account looks like on
the page, then score them. The images carry metadata worth an `exiftool` pass —
they tell stories the profile text does not.

`profiles/profiles-colleague.csv` is a colleague's scoring sheet, left behind
before a holiday. It is wrong in instructive ways. Run it, then argue with it:

```bash
./profile-score.py --batch samples/profiles/profiles-colleague.csv
```

The tool lists every score entered without evidence. That list is the review.

## Handling

Fictional data gets the real procedure, because sloppiness practised on fixtures
is still sloppiness. Pseudonymise in write-ups, state coverage gaps, and delete
working copies on the date you said you would.
