# Session 4 — Lab Completion and Ghidra

## `lab-doctor.sh`

Run it before you detonate anything. Exit code is the number of failed checks, so
it works as a gate.

```bash
./lab-doctor.sh             # everything
./lab-doctor.sh isolation   # the section where a failure means STOP
./lab-doctor.sh ghidra      # when Ghidra will not start, it is the JDK
./lab-doctor.sh artefacts   # what a sample can see about this VM
```

### The isolation section is the one that matters

Everything else is an inconvenience. A live default route on the victim VM is an
outbound connection to a real C2 from your real network, and an awkward
conversation with somebody's incident response team.

The check for a mounted host shared folder is there because it is the single most
common "but I was careful" failure. A shared folder is a two-way path, and
ransomware does not respect your intent for it.

### The artefacts section has no pass or fail

It lists what the VM tells a sample about itself. The exercise is not to remove
every item — you cannot. It is to know which remain, and to write that down,
because it is the difference between "the sample did nothing" and "the sample
declined to run in this environment, for these reasons".

Loudest signal on the list, every time: an uptime of four minutes and an empty
home directory.

---

## `ghidra-headless.sh`

```bash
export GHIDRA_HOME=/opt/ghidra_11.x
./ghidra-headless.sh analyse sample.bin       # start this in the break
./ghidra-headless.sh suspects sample.bin      # what to open first
./ghidra-headless.sh extract sample.bin       # functions, strings, imports
./ghidra-headless.sh decompile sample.bin resolve_api_by_hash
```

Auto-analysis is the slow part of Block 2. Run it in the break and arrive at the
keyboard with a project that is ready.

### `suspects` gives you a reading order

Ghidra hands you four hundred `FUN_` names and no priority. This ranks functions
by the **capability groups** their callees touch — injection, dynamic resolution,
anti-analysis, persistence, network, crypto, credentials, filesystem.

One group is a library wrapper. **Three groups is a function doing something.**

It is a reading order, not a verdict. The verdict comes from reading it.

### `extract` sorts strings by cross-reference count

A string with zero references is dead weight. One with eleven is a decision
point in the code, and that is where an analysis actually starts — not at the
top of the list.

### The Ghidra scripts are written at runtime

Three small Java files, generated into a temp directory and cleaned up
afterwards, so this stays a single file you can read end to end.

Everything is static. Nothing here runs the binary.
