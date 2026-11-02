# Tagus Logística — Cloud Landing, Phase 1 — Handover

**From:** NuvemCerta, Lda. (Rui Costa, rui.costa@nuvemcerta.example)
**To:** Tagus Logística, IT
**Status:** Delivered ✅ Production-ready ✅

After last month's incident the Board asked for the critical systems to move to
the cloud, where security is handled by the provider. Phase 1 is complete.

## What we built

| Service | What it does | Where |
|---|---|---|
| **Microsoft 365** | Email, Teams, OneDrive (unchanged, already in place) | Microsoft |
| **invoice-processor** | Lambda function: reads supplier invoices (PDF) from `incoming/`, extracts fields with Textract, writes JSON to `processed/`, removes the PDF | AWS, account 111122223333 (prod) / 444455556666 (nonprod) |
| **tagus-invoices-prod** | S3 bucket for invoices. Encrypted ✅ | AWS |
| **tagus-invoices-prod (RDS)** | PostgreSQL with supplier master data and IBANs | AWS |
| **tagus-website-assets** | The public website, now static on S3 (replaces tagus-web-01) | AWS |
| **WEB-02** | EC2 VM running the old customer portal (PHP 7.4, as-is) until phase 2 | AWS |
| **SFTP for the bank** | Managed SFTP endpoint used by the bank for statements | provider *SFTPGo-as-a-Service* |
| **ci-deploy** | GitHub Actions deploys the Lambda automatically | GitHub + AWS |

## Security

- Everything is in the cloud, so physical security, patching and availability
  are AWS's responsibility now.
- All data is encrypted, so RGPD is covered.
- Region: we used the default region.
- Least privilege: each component has its own role.
- NuvemCerta keeps a support role (`NuvemCerta-Admin`) to help with incidents.
  Temporary.
- Checkov runs on every deployment. ✅ 0 failed checks.

## Credentials

The database password is in the Terraform outputs (`terraform output
db_password`). Please change it after the handover.

## Phase 2 (proposal attached)

Move WEB-02 to containers, single sign-on, backups.
