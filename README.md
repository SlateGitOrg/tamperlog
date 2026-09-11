# tamperlog

> A hash-chained audit log that also detects re-chained truncation - the attack pure hash chaining silently passes.

`COMPACT` · **Cybersecurity** · Advanced · ~5-6 days · Public sector - electoral and records systems

**Primary language:** Go
**Tags:** `merkle`, `integrity`, `audit-log`, `cryptography`, `append-only`, `streaming`

---

> **Implementation note.** The catalogue specifies **Go** for this
> project and that remains the target. This repository ships a runnable
> **Python** reference implementation of the core differentiator so the
> behaviour is executable and tested today; port it to Go as step one
> of your own build.

## The problem

Audit logs are the evidence used to reconstruct an incident. An attacker with write access to the log defeats the investigation entirely. Hash chaining is the usual answer - but hash chaining alone does not detect an attacker who simply deletes the last 400 entries and re-chains the remainder, which is the easiest attack available and the one that matters most.

## ⭐ The differentiator

Adds **periodic Merkle checkpointing with externally-anchored roots**, making truncation detectable: the verifier knows a checkpoint existed at sequence 10,000 and can prove entries are missing. A generic hash-chain implementation verifies internal consistency and then cheerfully declares a re-chained truncated log valid - which is the precise failure an attacker relies on.

This is the sentence to lead with when someone asks you to walk through the
project. Everything else in this repo exists to make it true and to prove it.

## Data

Self-contained. A generator produces multi-million-entry logs, and a documented tamper suite covers insertion, modification, deletion, reordering, and **re-chained truncation** - the case that separates this from a weekend hash-chain exercise.

> No paid API key is required to run or demo this project. Where a paid
> service would add value it is wired as an optional enhancement behind an
> interface with an offline mock as the default implementation.

## Stack

- Go
- BoltDB for the append-only store
- A Merkle tree implementation with inclusion and consistency proofs
- CLI, testing/quick for property tests

## Core capabilities

- Append-only log with per-entry hash chaining and a monotonic sequence
- Periodic Merkle checkpoints with roots anchored to an external witness store
- Inclusion and consistency proofs for any entry or checkpoint range
- Verifier CLI reporting the exact sequence range affected by any tamper
- Streaming ingestion benchmark at sustained write rates

## Repository layout

```
cmd/log/
cmd/verify/
internal/chain/
internal/merkle/
internal/witness/
tamper-suite/
test/
bench/
```

## Build plan

1. Chain first, then immediately write the re-chained-truncation tamper case and watch the chain verifier pass it. That failure is the motivation for everything else.
2. Merkle checkpoints and the witness anchor.
3. Inclusion + consistency proofs, then the verifier's range reporting.
4. Benchmark last.

## Testing strategy

Every tamper class must be detected **with the correct affected range**. The critical assertion: re-chained truncation - which pure chaining misses - is caught by checkpoint inconsistency. A test that only covers modification would pass on a design that is broken where it counts.

Tests assert **correctness**, not merely that the code runs. A green suite on
this repo is a claim about behaviour under adversarial conditions; treat any
test that would pass against a deliberately broken implementation as a bug in
the test.

## Quality & safety layer

The witness store is separate from the log store by design; the README states plainly that a single-store deployment reduces the guarantee and why.

## Measurable outcome

> A two-million-entry log verifies in seconds, and a re-chained truncation that a naive chain verifier declares valid is caught with the exact missing range named.

State it in these terms — business units, not technical ones — in your CV
bullet and in the first thirty seconds of describing the project.

## Interview questions this project answers

- **Why is a hash chain insufficient on its own?**
- **What is a consistency proof and when do you need one?**
- **Where do you anchor the root, and what does that assume?**

## What this deliberately is *not*

- Not a blockchain. The witness is a second store, and the README explains why that is the right trade here.


## Run it now

```bash
python -m unittest discover -s tests -v   # the suite
python -m src.demo                        # the 60-second artefact
```

Requires Python 3.11+. The runnable core uses **only the standard
library** (including `sqlite3`), so there is nothing to install.

## Getting started

```bash
git clone <your-fork-url> tamperlog
cd tamperlog
go build ./...
./log generate --entries 2000000
./verify --db log.db --witness witness.db
./tamper-suite/run.sh          # all classes, incl. re-chained truncation
```

Docker is supported but optional — every path above works on a plain
Windows/macOS/Linux laptop without a cloud account.

## Definition of done

- [ ] The differentiator above is implemented, and a test proves it
- [ ] The measurable outcome is produced by a command anyone can run
- [ ] `README` explains the one decision a generic version gets wrong
- [ ] CI runs the full suite on every push and is green on `main`
- [ ] A recruiter can see the headline artefact in under 60 seconds

## Licence

MIT — see [LICENSE](LICENSE).
