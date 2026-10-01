# Session 7 — samples

Evidence for `acquire.sh` and `memory-capture.sh`, and for the habit of distrusting
both. Everything here is invented. **Tagus Logística** (`tagus-logistica.example`)
is the same fictional company that was phished in Session 6, and it went about as
well as you would expect: two transfers, just under €50 000 each, to a "confidential
supplier" whose IBAN starts with `XX`. Every IP is in the RFC 5737 documentation
ranges, every domain under `.example`, every IBAN fake enough to make a bank laugh.

```bash
shasum -a 256 -c SHA256SUMS      # before anything else. Yes, every time.
```

## What is here

| Path | What it is | What it is for |
|---|---|---|
| `EX-01.img.gz` | 16 MiB raw image of João Pereira's USB pen, label `FERIAS`, gzipped | **The** exhibit. You acquire it tonight and analyse it in Session 8 |
| `colleague/EX-01-attempt1.img.gz` | Tiago's first acquisition of the same pen, which he tried to delete | Exercise 5. The hash that did not match |
| `colleague/EX-01-notes.txt` | Tiago's "contemporaneous" notes | Exercise 6. Count the problems; there are more than you think |
| `colleague/EX-01-chain-of-custody.md` | Tiago's chain of custody form | Exercise 7. A classmate's cross-examination, pre-loaded |
| `victim-lin-capture/` | `memory-capture.sh volatile` output from `tagus-web-01`, plus the operator's own additions | Exercises 8 and 9. One file is not what it was when it was hashed |

The `.img.gz` files are stored compressed because a 16 MiB stick that is mostly
empty compresses to 18 KB, and because git is not an evidence locker. **The
hashes that matter are of the decompressed image**. `SHA256SUMS` covers the files
as stored; the images, once unpacked, are:

| Image | SHA-256 of the raw data |
|---|---|
| `EX-01.img` | `da195105fbe2ff30440965d5606873bca77a79ca07c1f2b3e7d4b9b5b22af439` |
| `EX-01-attempt1.img` | `18d8d9c8fb5cc4efe9f6e96f894fe87ac4cc7d82321b3d33e9d6dbc1648d5817` |

Three different hashes can describe "the same evidence" tonight — the `.gz`, the
raw data, and later the `.E01` file. A good report says which one it means.

## Unpacking

```bash
mkdir -p out
gunzip -c samples/EX-01.img.gz > out/EX-01.img
shasum -a 256 out/EX-01.img        # must be da195105…b22af439
chmod a-w out/EX-01.img            # a seatbelt, not a write blocker
```

`out/` and `*.img` are git-ignored. Your acquisitions stay on your machine.

## About the pen

It is a "superfloppy": a FAT16 filesystem starting at sector 0, no partition
table. Plenty of cheap promotional sticks ship like that, and it means `fls`,
`fsstat` and friends work on the image directly, without an offset. It was
formatted a long time ago, used for holiday plans, and then for something else.

What is on it is Session 8's business. Tonight's business is getting it off the
stick without changing it, and being able to prove that you did not.

## Handling

Fictional evidence gets the real procedure, because a shortcut practised on
fixtures is still practised. Hash on arrival, work on copies, write your notes
as you go, and never, ever "tidy up" a file after you have hashed it. Exercise 8
shows what that looks like from the outside.
