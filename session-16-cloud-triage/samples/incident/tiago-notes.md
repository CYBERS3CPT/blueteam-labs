# WEB-02 — my notes (Tiago, IT)

Times are Lisbon. (Winter, so same as UTC. I checked.)

## Fri 5 Dec

- **16:50** Opened the GuardDuty console to see if it was doing anything (I
  turned it on yesterday morning, eu-west-1, after the Prowler scan said it was
  off everywhere). One finding, **High**: `InstanceCredentialExfiltration.OutsideAWS`,
  role `web02-portal`. Created 14:26. No email came. I did not know it does not
  send email by itself.
- **16:58** Called Rui (NuvemCerta). He says IMDSv1 on WEB-02 is a known item,
  muted in Prowler, fixed in phase 2. New detectors give false positives the
  first week while they learn. Not to worry.
- **17:05** Not convinced. The IP is in the Netherlands. Our customers are in
  Portugal and Spain.
- **17:20** Decided to rebuild WEB-02 clean from the AMI. The only login I have
  that can do that is root (NuvemCerta has the admin role, we have no IAM users
  yet, SSO is phase 2).
- **17:31** Logged in as root (MFA on my phone).
- **17:38** Copied `/var/log/nginx/access.log` to my laptop with scp, in case.
  Not error.log, not the PHP logs, there was no time.
- **17:47** Launched the new WEB-02 from `ami-0b1c2d3e4f5a6b7c8` (the AMI
  NuvemCerta used), same role, same security group so the portal keeps working.
  Moved the elastic IP to it.
- **17:52** Terminated the old one. The volume was delete-on-termination, so it
  is gone, but it was compromised anyway, so better gone.
- **17:55** Portal works. Customers did not notice.
- Did **not** change any passwords or keys. Rui says the instance role
  credentials die with the instance.

## Mon 8 Dec (holiday, working from home)

- **09:12** Exported GuardDuty (`guardduty-prod-eu-west-1.json`). There is a
  second finding now, about root. That one is me.
- The High one says **last seen 18:19** on Friday. That is after I terminated
  the instance. ??
- Pulled the CloudTrail for Friday from the console (`cloudtrail-prod-2025-12-05.json.gz`).
  The IP only has **AccessDenied**. Nothing worked. So I think the
  invoices were not touched.

## Questions

1. Is it closed?
2. Rita asks whether the customers' invoices were read. I told her probably
   not, because CloudTrail shows only AccessDenied from that IP. Was that
   right?
3. Do we have to tell anyone?
