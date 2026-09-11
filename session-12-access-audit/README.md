# Session 12 — Access Control to Assets

## `access-audit.sh`

```bash
./access-audit.sh                      # everything
./access-audit.sh --csv findings.csv   # plus a findings CSV
./access-audit.sh --section sudo       # one section
./access-audit.sh --sections           # what the sections are
```

Read-only. It looks, it does not fix.

### It is deliberately not run as root

Most of this is readable as a normal user, and a triage script running as root is
a read-only task one typo away from a write. The two checks that genuinely need
privilege (`/etc/shadow`, `sudoers`) say so and carry on.

### Every finding carries its evidence command

So the person receiving the list can reproduce it without asking you anything. A
finding that cannot be reproduced gets closed as "could not reproduce" by someone
who did not try very hard, and you will not be in the room.

### The sudo section is the one that matters

`NOPASSWD: ALL` makes every other control on the host decorative. So does
membership of `docker` or `lxd` — both let you mount the host filesystem into a
container you control, which is root with extra steps.

And it checks for `sudo` rules on the GTFOBins classics: `vim`, `less`, `find`,
`awk`, `python`, `git`, `systemctl`. Each of those spawns a shell. A sudoers rule
permitting one binary "for convenience" is a root shell with a paper trail that
looks like restraint.

### What the output is not

It is a findings list, not a report. "Restrict access" is not a remediation — the
remediation is the command or the setting, written out. And severity needs a line
of justification, not a colour.

---

## `harden.sh`

```bash
sudo ./harden.sh before      # capture the baseline. Do this FIRST.
     ./harden.sh plan        # what it would change, and what each could break
sudo ./harden.sh apply       # with a backup of every file it touches
sudo ./harden.sh after       # the delta, and the warnings resolved
sudo ./harden.sh rollback
     ./harden.sh limits      # what the score does not measure
```

### `after` refuses to run without `before`

> *no baseline — you needed to run `before` first, and that is the whole point*

The delta is the deliverable. A single score is a number with nothing to compare
it to.

### The plan has a "could break" column

Not decoration. The Session 12 brief asks, for two of your changes: *what could
it break, and how would you test?* The table answers the first half so you can
spend your time on the second.

Examples it names: `MaxAuthTries 3` breaks automation that retries with several
keys in one session; reverse-path filtering breaks asymmetric routing if the host
is a router; disabling magic SysRq removes out-of-band recovery on a physical
console.

### It will not restart sshd for you

It validates the config with `sshd -t`, rolls that file back automatically if the
config is invalid, and then tells you to restart it yourself **from a session you
can afford to lose** — keeping the current terminal open until you have a second
one working. The alternative is a very quiet lab machine.

### `limits` is part of the deliverable

A hardening score is a proxy, not a posture. Improving from 62 to 78 is real
progress and it is not evidence that the host is secure. The deliverable wants
that paragraph written **for this host** — generic text scores nothing, so name
the specific thing you know is wrong and the score did not see.
