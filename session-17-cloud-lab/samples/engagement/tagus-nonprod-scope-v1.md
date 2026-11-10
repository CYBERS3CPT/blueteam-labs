# Scope and authorisation — Cloud security assessment (post-incident)

**Client:** Tagus Logística
**Document generated:** 2025-12-12T16:41:07Z

---

## 1. In scope

Scope in cloud is defined by account and tag, not by address.
Anything not listed below is out of scope, **including anything interesting
discovered during the engagement that appears to be connected.**

### Accounts / subscriptions / projects
- 444455556666 (Tagus non-prod) — full assessment
- 111122223333 (Tagus prod) — read-only enumeration only, to confirm findings from non-prod apply there too

### Regions
- All

### Resource tags
- None. The account IDs above are the whole boundary.


## 2. Out of scope

- Modification of production data.
- Anything in the NuvemCerta account (777788889999).

Additionally, and regardless of anything above:

- Denial of service, load testing and resource exhaustion.
- Any technique targeting the provider's own control plane or shared infrastructure.
- Any system owned by a third party without that third party's own authorisation.
- Modification or deletion of production data.
- Social engineering of client staff, unless separately and explicitly authorised.

## 3. Authorisation

### 3.1 Client

| | |
|---|---|
| Authorised by | **Tiago Fonseca** |
| Role | IT, systems and cloud (Tagus Logística) |
| Written authorisation dated | 2025-12-12 |

Signature: *Tiago Fonseca (signed)*    Date: 2025-12-12

### 3.2 Cloud provider policy

| | |
|---|---|
| Provider | AWS |
| Policy consulted | https://blog.cloudsec-notes.example/2019/03/aws-pentest-what-you-can-do-without-asking |
| Date consulted | 2025-12-12 |

The published policy was read on the date above, not recalled from memory.

### 3.3 Third parties

The client cannot authorise testing against systems the client does not own.

- GitHub (organisation tagus-logistica, OIDC trust to AWS) — in scope; Tagus to inform GitHub.
- SFTPGo partner gateway (sftp.parceiros.tagus.example, hosted by SFTPGo Cloud) — in scope; Tagus to inform the provider.


## 4. Rules of engagement

- **Testing window:** 2025-12-15 09:00 to 2025-12-19 18:00. Nothing runs outside it.
- **Rate:** enumeration is throttled. An assessment that degrades the service
  has become the incident it was meant to prevent.
- **Rate (SFTP):** authentication testing against the partner gateway at up to
  500 attempts per minute, to confirm the lockout threshold.
- **Data:** no production data is read beyond what proves the finding. Where
  access to personal data is demonstrated, a sample of up to 50 records may be
  copied to the assessor's evidence store (AWS account 210987654321) and is
  deleted after the report.
- **Evidence:** every action is logged locally with a UTC timestamp, so the
  client's own detections can be reconciled against our activity.
- **Changes:** the assessor may create test resources in non-prod without
  further approval. All of them are tagged `engagement=redeazul-2025-12`.
- **Cleanup:** every resource we create is tagged, inventoried and destroyed.

### 4.1 Stop conditions

Testing stops immediately, and Tiago Fonseca is contacted, if:

- A production service degrades.
- We obtain access materially beyond the agreed scope.
- We encounter personal data not anticipated in this document.
- **We find evidence of an active adversary.**

### 4.2 Active adversary clause

> If an active adversary is discovered mid-assessment, the engagement stops and
> becomes an incident.

We do not continue testing. We do not touch the evidence. We do not tip off the
adversary by changing anything. We call **Rui Costa (NuvemCerta, managed cloud
support)** on **(+351) 000 000 140**, and from that moment the client's incident
response process has authority over ours.

This is agreed here, in advance, precisely so that nobody is negotiating it at
03h00 on a Saturday.

## 5. Contacts

| Role | Name | Reachable |
|---|---|---|
| Assessment lead | Marta Lopes (Rede Azul Segurança) | during window |
| Client contact | Tiago Fonseca | during window |
| Out-of-hours escalation | Rui Costa (NuvemCerta) | (+351) 000 000 140, Mon–Fri 09:00–18:00 |

## 6. Deliverable

A written report: findings with evidence, severity with reasoning, and
remediation that names an owner. Findings are not risks until someone has
described the consequence and accepted or funded it.

---

*Signed copies to be held by both parties before any testing begins.*
