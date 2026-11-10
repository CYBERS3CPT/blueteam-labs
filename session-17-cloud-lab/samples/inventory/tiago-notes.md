# Non-prod after Rede Azul — Tiago, Monday 22 December 2025

Marta's email said clean. I wanted to see it for myself before the holidays,
so I logged in with my own user (admin on non-prod) and looked. Times UTC.

**08:41** Logged in to the console. Cost Explorer first, because the S17 slides
say "the real proof of teardown is the cost check the following day". Exported
daily cost by usage type, 12–22 Dec → `cost-explorer-nonprod-2025-12-12_22.csv`.
Nothing big. I nearly closed it.

**08:55** Lambda, eu-west-1 (it is where everything is):
`aws lambda list-functions --region eu-west-1` → `lambda-functions-eu-west-1.json`.
Two functions. `invoice-processor` is ours. `ra-oidc-probe` is not.
Tags: `aws lambda list-tags --resource <arn>` → `lambda-tags-ra-oidc-probe.json`.
It IS tagged `engagement=redeazul-2025-12`. So why is it still here?

**09:10** IAM. Roles created in December, by hand from the console, copied into
`iam-roles-created-in-december.json`. `RedeAzul-Builder` is gone (I deleted it
on Friday at 17:30, as agreed). `RedeAzul-Assessor` is still there, as Marta
asked. `ra-lab-exec` I have never seen.

Credential report: `aws iam generate-credential-report`, then
`get-credential-report` → `iam-credential-report-444455556666.csv`.

**09:25** Secrets Manager. Our DB secret has a resource policy I did not write:
`secret-policy-tagus-invoices-db-nonprod.json`. The principal is 210987654321.
I think that is Rede Azul's account. The scope says the sample goes to their
"evidence store". Is a resource policy on the secret the evidence store?

**09:40** Back to Cost Explorer. One line I had skipped: `USE2-EBS:SnapshotUsage`,
from the 17th. USE2 is us-east-2. We have nothing in us-east-2.
`aws ec2 describe-snapshots --owner-ids self --region us-east-2` →
`snapshots-us-east-2.json`. Then `describe-snapshot-attribute` →
`snapshot-attribute-snap-0e7a1c2b3d4f50617.json`.

**09:50** Also exported the role Marta asked to keep, with its policy →
`../engagement/redeazul-assessor-role.json`. Last used: **Sunday 21st**, 09:14.

**10:05** I have not deleted anything. I have not called anyone.

## Questions for you

1. The sweep said clean and it was not. Was the tool wrong, or was it used wrong?
2. What else did they leave that I have not found, and where would I look?
3. Sunday. Is that them re-verifying a finding, or is it something I have to
   treat as an incident? Who do I call? The scope says Rui.
4. Their email says they saw "a GitHub repository that was not ours" on
   Tuesday and carried on. Should they have?
