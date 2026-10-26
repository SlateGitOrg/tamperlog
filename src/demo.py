"""Demo: plain hash chaining versus chaining plus checkpoints.

Run: python -m src.demo
"""

from __future__ import annotations

import time

from .log import verify, verify_chain_only
from .tamper import TAMPERS, apply_tamper, build_log

N = 20_000


def main() -> None:
    print("\n  TAMPERLOG - the attack a hash chain declares valid")
    print("  " + "-" * 72)

    start = time.perf_counter()
    log = build_log(N, checkpoint_every=1_000)
    built = time.perf_counter() - start
    print(f"  Built a {N:,}-entry log with {len(log.witness.all())} checkpoints "
          f"in {built:.2f}s")

    start = time.perf_counter()
    ok = verify(log.entries, log.witness)
    took = time.perf_counter() - start
    print(f"  Verified in {took:.2f}s: {ok.describe()}\n")

    print(f"  {'tamper':<22}{'chain only':<14}{'+ checkpoints':<16}affected range")
    print("  " + "-" * 72)
    missed_by_chain = 0
    for t in TAMPERS:
        tampered = apply_tamper(log.entries, t.name)
        chain = verify_chain_only(tampered)
        full = verify(tampered, log.witness)
        chain_verdict = "MISSED" if chain.ok else "detected"
        full_verdict = "MISSED" if full.ok else "detected"
        if chain.ok:
            missed_by_chain += 1
        rng = "-" if full.ok else full.affected_range
        print(f"  {t.name:<22}{chain_verdict:<14}{full_verdict:<16}{rng}")

    print(f"\n  The {missed_by_chain} MISSED cells in the first column are the point.")
    print("  All are attacks by someone who bothered to restore internal")
    print("  consistency - which is to say, by anyone serious. A chain verifier")
    print("  reports those logs as valid and the investigation proceeds on")
    print("  evidence that has been edited.\n")

    print("  Caveat, stated plainly: the witness must live in a store the")
    print("  attacker cannot also rewrite. Co-locate them and this reduces to")
    print("  plain chaining again.\n")


if __name__ == "__main__":
    main()
