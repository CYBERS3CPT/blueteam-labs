# Session 11 — SOC Team and Workflow

## `soc-stack.sh`

```bash
./soc-stack.sh preflight    # run this BEFORE the block
./soc-stack.sh pull         # several GB — a break activity
./soc-stack.sh up
./soc-stack.sh agent-cmd    # enrolment commands, with your manager IP filled in
./soc-stack.sh status       # healthy? and are the agents actually reporting?
```

### The three failures, in order of frequency

1. **Not enough RAM.** The indexer alone wants 4 GB and it OOMs quietly.
2. **`vm.max_map_count` too low.** Below 262144 the indexer refuses to start, and
   the error it prints is not obviously about this.
3. **An agent that installed fine and is not reporting.** Which is why `status`
   queries `agent_control` from the manager rather than trusting the agent.

`preflight` checks all three before you spend twenty minutes finding out.

### Agent states

`Active` means reporting. `Never connected` means enrolment never reached the
manager — firewall on 1514/1515, or the wrong manager IP. `Disconnected` means it
did reach it once and then stopped, which is the agent's own log's problem.

---

## `handover.sh`

```bash
./handover.sh new INC-<id>            # interactive, asks in order
./handover.sh blank                   # just the template
./handover.sh clock "YYYY-MM-DD HH:MM"  # how long is left on a clock
```

### The section that matters

**Open questions / not yet checked.** It saves more time than every other section
combined, and it is the one people leave blank, because writing down what you did
not do feels like an admission.

It is the opposite. It is the difference between the next analyst *continuing*
your work and *starting* it. The interactive mode notices when you leave it empty
and asks again, once, politely.

### Two moments need their own timestamp

**Incident declared** and **containment decided**. One starts a legal clock, the
other an operational one, and both are normally reconstructed afterwards from
memory — badly. The template has a row for each.

`clock` exists because the regulatory deadline runs from when you became *aware*,
not from when you confirmed, and mental arithmetic at 23h00 is not a control.

---

## `playbook.sh`

```bash
./playbook.sh scenarios                 # which six to write, in order
./playbook.sh matrix                    # severity matrix with worked examples
./playbook.sh new "suspected ransomware"
./playbook.sh check playbook-suspected-ransomware.md
```

### A playbook is not a runbook

A runbook says "isolate a host in the EDR" and lists the clicks. A playbook says
**who decides, what it costs, who gets told, and which clock starts**. The second
is the hard one, which is why most organisations have the first and call it the
second.

### The containment table has a cost column

Every option carries its business cost, whether the adversary learns, who
authorises it, and whether it is reversible. That turns:

> "Isolate the host"  *(an instruction)*

into:

> "Isolate the host; the user loses access for about four hours; the adversary
> will likely notice"  *(a decision somebody can actually make)*

### It asks who deputises at 03h00

And warns you when you leave it blank, because the incident that needs a
containment decision at 03h00 is precisely the one where nobody can reach the
person named in the playbook.

### `check` counts unfilled placeholders

A playbook with `____` where a name should be **reads as complete and is not**,
which is worse than a blank section. `check` exits non-zero on any gap.

The final test is not scriptable: read it aloud to someone who was not in the
room, and count their questions.
