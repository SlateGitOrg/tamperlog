"""An append-only audit log that detects the attack hash chaining misses.

THE DIFFERENTIATOR LIVES HERE.

Hash chaining is the standard answer to log tampering, and it does detect
insertion, modification and reordering. It does NOT detect the easiest attack
available to anyone with write access: delete the last 400 entries and re-chain
the remainder. The result is internally consistent, a chain verifier declares it
valid, and the investigation proceeds on evidence that has been edited.

Periodic Merkle checkpoints anchored to a separate witness close that gap. The
verifier knows a checkpoint existed covering sequence 10,000, so it can prove
entries are missing rather than merely failing to notice.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def leaf_hash(data: bytes) -> bytes:
    # Domain separation between leaves and internal nodes. Without it an
    # attacker can present an internal node as a leaf and forge inclusion
    # proofs - the classic second-preimage attack on naive Merkle trees.
    return sha256(b"\x00", data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01", left, right)


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return sha256(b"")
    level = list(leaves)
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # odd node promoted
        level = nxt
    return level[0]


@dataclass(frozen=True)
class Entry:
    seq: int
    payload: bytes
    prev_hash: bytes
    entry_hash: bytes

    @staticmethod
    def compute_hash(seq: int, payload: bytes, prev_hash: bytes) -> bytes:
        return sha256(seq.to_bytes(8, "big"), payload, prev_hash)


@dataclass(frozen=True)
class Checkpoint:
    """A signed commitment to the log's contents up to `seq`."""

    seq: int
    root: bytes
    entry_count: int


class Witness:
    """A SEPARATE store holding checkpoint roots.

    Separate is the whole point. If the witness lives in the same store as the
    log, an attacker who can rewrite one can rewrite the other, and the
    guarantee reduces to plain chaining again. The README says this out loud
    rather than implying a stronger property than the deployment provides.
    """

    def __init__(self) -> None:
        self._checkpoints: dict[int, Checkpoint] = {}

    def record(self, cp: Checkpoint) -> None:
        self._checkpoints[cp.seq] = cp

    def get(self, seq: int) -> Checkpoint | None:
        return self._checkpoints.get(seq)

    def latest(self) -> Checkpoint | None:
        if not self._checkpoints:
            return None
        return self._checkpoints[max(self._checkpoints)]

    def all(self) -> list[Checkpoint]:
        return [self._checkpoints[k] for k in sorted(self._checkpoints)]


GENESIS = b"\x00" * 32


class TamperLog:
    def __init__(self, witness: Witness, checkpoint_every: int = 100) -> None:
        self.entries: list[Entry] = []
        self.witness = witness
        self.checkpoint_every = checkpoint_every

    def append(self, payload: bytes) -> Entry:
        seq = len(self.entries) + 1
        prev = self.entries[-1].entry_hash if self.entries else GENESIS
        entry = Entry(seq, payload, prev, Entry.compute_hash(seq, payload, prev))
        self.entries.append(entry)

        if seq % self.checkpoint_every == 0:
            self.witness.record(self.checkpoint())
        return entry

    def checkpoint(self) -> Checkpoint:
        leaves = [leaf_hash(e.entry_hash) for e in self.entries]
        return Checkpoint(
            seq=len(self.entries), root=merkle_root(leaves),
            entry_count=len(self.entries),
        )

    # -- proofs -------------------------------------------------------------

    def inclusion_proof(self, seq: int) -> list[tuple[str, bytes]]:
        """Sibling hashes from a leaf to the root, with their side."""
        index = seq - 1
        level = [leaf_hash(e.entry_hash) for e in self.entries]
        proof: list[tuple[str, bytes]] = []
        while len(level) > 1:
            nxt: list[bytes] = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    if i == index:
                        proof.append(("right", level[i + 1]))
                    elif i + 1 == index:
                        proof.append(("left", level[i]))
                    nxt.append(node_hash(level[i], level[i + 1]))
                else:
                    nxt.append(level[i])
            index //= 2
            level = nxt
        return proof


def verify_inclusion(
    entry_hash: bytes, proof: list[tuple[str, bytes]], root: bytes
) -> bool:
    current = leaf_hash(entry_hash)
    for side, sibling in proof:
        current = (
            node_hash(sibling, current) if side == "left"
            else node_hash(current, sibling)
        )
    return current == root


# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    failure: str | None = None
    # The sequence range affected. "Something is wrong" is not actionable;
    # "entries 9,601 to 10,000 are missing" is.
    affected_from: int | None = None
    affected_to: int | None = None

    def describe(self) -> str:
        if self.ok:
            return "log verified"
        span = ""
        if self.affected_from is not None:
            span = f" (sequence {self.affected_from}"
            span += f"-{self.affected_to})" if self.affected_to else ")"
        return f"{self.failure}{span}"


def verify_chain_only(entries: list[Entry]) -> VerifyResult:
    """Plain hash-chain verification. The common implementation.

    It is genuinely good at insertion, modification and reordering. It is
    completely blind to a re-chained truncation, which is the point of
    including it here.
    """
    prev = GENESIS
    for i, e in enumerate(entries):
        expected_seq = i + 1
        if e.seq != expected_seq:
            return VerifyResult(False, "sequence discontinuity",
                                expected_seq, e.seq)
        if e.prev_hash != prev:
            return VerifyResult(False, "chain break", e.seq, e.seq)
        if e.entry_hash != Entry.compute_hash(e.seq, e.payload, e.prev_hash):
            return VerifyResult(False, "entry hash mismatch", e.seq, e.seq)
        prev = e.entry_hash
    return VerifyResult(True)


def verify(entries: list[Entry], witness: Witness) -> VerifyResult:
    """Chain verification PLUS checkpoint consistency."""
    chain = verify_chain_only(entries)
    if not chain.ok:
        return chain

    for cp in witness.all():
        if cp.seq > len(entries):
            return VerifyResult(
                False,
                "truncation detected: a checkpoint commits to entries that are "
                "no longer present",
                len(entries) + 1, cp.seq,
            )
        leaves = [leaf_hash(e.entry_hash) for e in entries[: cp.seq]]
        if merkle_root(leaves) != cp.root:
            return VerifyResult(
                False, "checkpoint root mismatch", 1, cp.seq,
            )
    return VerifyResult(True)
