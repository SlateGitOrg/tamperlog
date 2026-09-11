"""The tamper suite. Every class an attacker with write access would try."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .log import Entry, GENESIS, TamperLog


@dataclass(frozen=True)
class Tamper:
    name: str
    description: str
    # Does plain hash chaining catch it? Recorded so the comparison is explicit.
    caught_by_chain_alone: bool


TAMPERS: tuple[Tamper, ...] = (
    Tamper("modify", "change the payload of one entry in place", True),
    Tamper(
        "modify_rehashed",
        "change a payload AND recompute the hashes, as a competent attacker "
        "would",
        # Also invisible to plain chaining, for the same reason re-chained
        # truncation is: the attacker restored internal consistency. Chaining
        # only catches attackers who do not bother.
        False,
    ),
    Tamper("insert", "splice an extra entry into the middle", True),
    Tamper("delete_middle", "remove an entry from the middle", True),
    Tamper("reorder", "swap two adjacent entries", True),
    Tamper("truncate_naive", "drop the tail without fixing up the chain", True),
    Tamper(
        "truncate_rechained",
        "drop the tail AND re-chain the remainder so it is internally "
        "consistent",
        False,
    ),
)


def _rechain(entries: list[Entry]) -> list[Entry]:
    """Rebuild hashes so the sequence is internally consistent again."""
    out: list[Entry] = []
    prev = GENESIS
    for i, e in enumerate(entries):
        seq = i + 1
        h = Entry.compute_hash(seq, e.payload, prev)
        out.append(Entry(seq, e.payload, prev, h))
        prev = h
    return out


def apply_tamper(entries: list[Entry], kind: str) -> list[Entry]:
    e = list(entries)
    mid = len(e) // 2

    if kind == "modify":
        target = e[mid]
        return e[:mid] + [replace(target, payload=b"EDITED")] + e[mid + 1:]

    if kind == "modify_rehashed":
        # The naive `modify` leaves a stale entry_hash, which chain
        # verification catches immediately. A competent attacker recomputes,
        # so this is the version worth testing the Merkle root against.
        edited = e[:mid] + [replace(e[mid], payload=b"EDITED")] + e[mid + 1:]
        return _rechain(edited)

    if kind == "insert":
        fake = Entry(
            seq=e[mid].seq, payload=b"INSERTED",
            prev_hash=e[mid].prev_hash,
            entry_hash=Entry.compute_hash(e[mid].seq, b"INSERTED", e[mid].prev_hash),
        )
        return e[:mid] + [fake] + e[mid:]

    if kind == "delete_middle":
        return e[:mid] + e[mid + 1:]

    if kind == "reorder":
        return e[:mid] + [e[mid + 1], e[mid]] + e[mid + 2:]

    if kind == "truncate_naive":
        # Just drop the tail. The chain is still internally consistent for what
        # remains, so this one needs the checkpoint too.
        return e[: len(e) - 400]

    if kind == "truncate_rechained":
        # The attack that matters: drop the tail and rebuild the hashes so the
        # remaining log verifies perfectly against itself.
        return _rechain(e[: len(e) - 400])

    raise ValueError(f"unknown tamper: {kind}")


def build_log(entries: int = 2_000, checkpoint_every: int = 100) -> TamperLog:
    from .log import Witness

    log = TamperLog(Witness(), checkpoint_every=checkpoint_every)
    for i in range(entries):
        log.append(f"user=alice action=read record={i}".encode())
    return log
