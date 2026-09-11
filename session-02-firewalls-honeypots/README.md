# Session 2 — Firewalls, HoneyPots and Physical Security

## `honeypot-lab.sh`

Cowrie in Docker, plus the analysis you would otherwise do by hand with `grep`
at 23h00.

```bash
./honeypot-lab.sh up          # port 2222 — it refuses to bind 22, for your own good
./honeypot-lab.sh watch       # live attempts
./honeypot-lab.sh report      # credentials tried, commands run, files dropped
./honeypot-lab.sh iocs        # CSV for the Session 5 EWS
./honeypot-lab.sh placement   # read this before deciding where to put it
```

### The one thing worth internalising

A honeypot has a false positive rate of approximately zero. Nobody has a
legitimate reason to SSH into a machine that does not exist. That makes a single
hit more actionable than a thousand IDS alerts — and it is why the alerting rule
needs no tuning at all. If you are tuning it, it is in the wrong place.

### Environment

| Variable | Default |
|---|---|
| `HONEYPOT_NAME` | `blueteam-cowrie` |
| `HONEYPOT_PORT` | `2222` |
| `HONEYPOT_DATA` | `./cowrie-data` |

### Downloads are live malware

Anything in `cowrie-data/dl/` was uploaded by someone who meant it. `report`
hashes them rather than opening them. Treat them as Session 3 material.

---

## `firewall-review.sh`

```bash
sudo ./firewall-review.sh              # auto-detects nftables, iptables or pf
./firewall-review.sh --file rules.txt
./firewall-review.sh --explain         # what each finding means, and why
```

Read-only. It never loads, flushes or modifies a rule — it does not call anything
that writes.

### What it looks for

Firewalls are rarely wrong. They are frequently *right about a policy that stopped
being true two years ago*. The findings are the shapes that drift takes:

- **Default policy ACCEPT** — not a firewall, a suggestion. Every rule becomes a
  special case, and the one you forget is open.
- **Any/any accepts** — added at 23h00 to make something work, with every
  intention of tightening it tomorrow. There is no record of tomorrow arriving.
- **Management ports from anywhere** — SSH, RDP, and the databases. Plus a
  separate warning for Redis, memcached, etcd, Elasticsearch and the Docker API,
  which have no authentication by default and turn up exposed anyway.
- **Rules after a catch-all** — they look like policy in the file and do nothing
  on the wire. That is worse than being absent, because the reviewer sees a
  control that does not exist.
- **No logging on the drops** — the first question in any firewall incident is
  "was it blocked?" and the second is "how many times?".
- **`established` without `related`** — breaks FTP, some VPNs and ICMP error
  handling, in ways that look like an application fault and get "fixed" by
  someone adding an any/any rule.

### The two questions it cannot answer

**Which rules are still needed?** Anything with no comment and no owner is a
candidate for removal, and removal is the only thing that makes a ruleset smaller.

**What does the cloud firewall say?** Host rules are half the story. The security
group in front of the machine is the other half, and it is usually the permissive
one.
