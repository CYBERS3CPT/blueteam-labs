# Session 1 — IDS and IPS

## `suricata-lab.sh`

Suricata is very good at running perfectly while detecting nothing. This wraps the
checks you would otherwise forget.

```bash
./suricata-lab.sh check                # the five things that are wrong when nothing alerts
./suricata-lab.sh rules                # update rulesets, validate BEFORE restarting
./suricata-lab.sh new-rule c2-beacon   # scaffolds a rule with the next free sid
./suricata-lab.sh test-rule            # validate local.rules, nothing else
./suricata-lab.sh replay capture.pcap  # offline run, alerts summarised
./suricata-lab.sh watch                # live alerts only, not the whole of eve.json
./suricata-lab.sh stats                # what has fired, ranked
```

### Why `check` exists

In order of how often it is the answer:

1. `HOME_NET` is still the shipped default, so every `$EXTERNAL_NET` rule is nonsense.
2. The interface in `suricata.yaml` does not exist on this host.
3. The interface is not in promiscuous mode, so you see your own traffic and nothing else.
4. The rule file has a syntax error and Suricata fell back to the last good state.
5. Suricata is not running. It happens more than anyone admits.

### Environment

| Variable | Default |
|---|---|
| `SURICATA_CFG` | `/etc/suricata/suricata.yaml` |
| `LOCAL_RULES` | `/etc/suricata/rules/local.rules` |
| `EVE_LOG` | `/var/log/suricata/eve.json` |

### Note on sids

Custom rules start at `1000000`. Below that belongs to the ruleset vendors, and a
sid collision produces a rule that silently never fires — which is the worst
possible failure mode, because everything looks fine.

---

## `pcap-triage.sh`

The first ten minutes with a capture, without opening the GUI.

```bash
./pcap-triage.sh capture.pcap
./pcap-triage.sh capture.pcap --section dns
./pcap-triage.sh capture.pcap --beacons
./pcap-triage.sh capture.pcap --out ./triage      # also exports transferred objects
```

Sections: `overview` `talkers` `dns` `tls` `http` `files` `beacons`.

Read-only. It does not replay, inject, or resolve anything against the network.

### The beacon check

Regularity is the signal, because humans are not regular. The script computes
**jitter = standard deviation ÷ mean** of inter-arrival times per conversation:

| Jitter | Reading |
|---|---|
| < 0.10 | A scheduled callback. Not a person. |
| < 0.25 | Regular enough to explain. |
| > 0.30 | Probably human, or a beacon with deliberate jitter. |

Also watch the **mean**. Exactly 60.0 seconds is a cron job or a beacon; it is
never a browser.

### DNS is the section people skip

It is the cheapest place to find C2. The script flags NXDOMAIN bursts (a DGA, or
a typo in a config), long first labels (a 40-character label is not a hostname,
it is a payload) and TXT queries, which are small, boring and a complete covert
channel.

### Then write the rule

```bash
./suricata-lab.sh new-rule c2-beacon
./suricata-lab.sh replay capture.pcap
```

A detection you have not tested against the traffic that motivated it is a guess.
Testing takes ninety seconds.
