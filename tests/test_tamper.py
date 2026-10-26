"""Every tamper class, detected, with the affected range named."""

from __future__ import annotations

import unittest

from src.log import (
    TamperLog, Witness, merkle_root, leaf_hash, verify, verify_chain_only,
    verify_inclusion,
)
from src.tamper import TAMPERS, apply_tamper, build_log


class TestHappyPath(unittest.TestCase):
    def test_an_untampered_log_verifies(self):
        log = build_log(2_000)
        self.assertTrue(verify(log.entries, log.witness).ok)

    def test_a_verifier_that_rejects_everything_would_fail_this(self):
        for n in (1, 99, 100, 101, 1_000):
            log = build_log(n)
            self.assertTrue(verify(log.entries, log.witness).ok, f"n={n}")

    def test_checkpoints_are_recorded_at_the_configured_interval(self):
        log = build_log(1_000, checkpoint_every=100)
        self.assertEqual(len(log.witness.all()), 10)
        self.assertEqual(log.witness.latest().seq, 1_000)


class TestTamperDetection(unittest.TestCase):
    def test_every_tamper_class_is_detected(self):
        for t in TAMPERS:
            with self.subTest(tamper=t.name):
                log = build_log(2_000)
                tampered = apply_tamper(log.entries, t.name)
                result = verify(tampered, log.witness)
                self.assertFalse(result.ok, f"{t.name} was not detected")

    def test_THE_ATTACK_CHAINING_MISSES(self):
        """Re-chained truncation: valid to a chain verifier, caught here."""
        log = build_log(2_000)
        tampered = apply_tamper(log.entries, "truncate_rechained")

        # Chain-only verification declares the edited log perfectly valid.
        chain = verify_chain_only(tampered)
        self.assertTrue(
            chain.ok,
            "the re-chained log should be internally consistent - that is "
            "precisely why chaining alone is insufficient",
        )

        # With checkpoints, it is caught.
        full = verify(tampered, log.witness)
        self.assertFalse(full.ok)
        self.assertIn("truncation", full.failure)

    def test_a_rehashed_in_place_edit_also_defeats_plain_chaining(self):
        """The same lesson, for modification rather than truncation."""
        log = build_log(2_000)
        tampered = apply_tamper(log.entries, "modify_rehashed")
        self.assertTrue(verify_chain_only(tampered).ok,
                        "a re-chained edit is internally consistent")
        result = verify(tampered, log.witness)
        self.assertFalse(result.ok)
        self.assertIn("checkpoint root mismatch", result.failure)

    def test_the_affected_range_is_named(self):
        log = build_log(2_000)
        tampered = apply_tamper(log.entries, "truncate_rechained")
        result = verify(tampered, log.witness)
        self.assertEqual(result.affected_from, 1_601)
        self.assertEqual(result.affected_to, 1_700,
                         "the first checkpoint past the surviving tail")
        self.assertIn("1601", result.describe())

    def test_chaining_alone_DOES_catch_the_other_classes(self):
        # The comparison has to be fair: chaining is not useless, it has one
        # specific blind spot.
        for t in TAMPERS:
            if not t.caught_by_chain_alone:
                continue
            with self.subTest(tamper=t.name):
                log = build_log(2_000)
                tampered = apply_tamper(log.entries, t.name)
                self.assertFalse(verify_chain_only(tampered).ok)

        # Plain tail truncation leaves a consistent chain, so chaining misses
        # it; only the checkpoint notices.
        log = build_log(2_000)
        tampered = apply_tamper(log.entries, "truncate_naive")
        self.assertTrue(verify_chain_only(tampered).ok)
        self.assertFalse(verify(tampered, log.witness).ok)

    def test_modification_is_pinned_to_the_exact_entry(self):
        log = build_log(1_000)
        tampered = apply_tamper(log.entries, "modify")
        result = verify(tampered, log.witness)
        self.assertFalse(result.ok)
        self.assertEqual(result.affected_from, 501)


class TestMerkleMechanics(unittest.TestCase):
    def test_inclusion_proof_verifies_against_the_root(self):
        log = build_log(128, checkpoint_every=1_000)
        cp = log.checkpoint()
        for seq in (1, 7, 64, 128):
            proof = log.inclusion_proof(seq)
            self.assertTrue(
                verify_inclusion(log.entries[seq - 1].entry_hash, proof, cp.root),
                f"inclusion proof failed for seq {seq}",
            )

    def test_an_inclusion_proof_for_the_wrong_entry_fails(self):
        log = build_log(128, checkpoint_every=1_000)
        cp = log.checkpoint()
        proof = log.inclusion_proof(7)
        self.assertFalse(
            verify_inclusion(log.entries[8].entry_hash, proof, cp.root))

    def test_leaf_and_node_hashes_are_domain_separated(self):
        """Without separation an internal node can be passed off as a leaf."""
        from src.log import node_hash
        a, b = leaf_hash(b"a"), leaf_hash(b"b")
        internal = node_hash(a, b)
        self.assertNotEqual(internal, leaf_hash(internal))

    def test_odd_leaf_counts_are_handled(self):
        for n in (1, 3, 5, 7, 9, 1_001):
            log = build_log(n, checkpoint_every=100_000)
            cp = log.checkpoint()
            proof = log.inclusion_proof(n)
            self.assertTrue(
                verify_inclusion(log.entries[n - 1].entry_hash, proof, cp.root),
                f"odd-length tree failed at n={n}",
            )

    def test_the_root_changes_when_any_entry_changes(self):
        log = build_log(64, checkpoint_every=100_000)
        before = log.checkpoint().root
        tampered = apply_tamper(log.entries, "modify_rehashed")
        after = merkle_root([leaf_hash(e.entry_hash) for e in tampered])
        self.assertNotEqual(before, after)

    def test_an_empty_log_has_a_stable_root(self):
        self.assertEqual(merkle_root([]), merkle_root([]))


class TestScale(unittest.TestCase):
    def test_a_large_log_verifies(self):
        log = build_log(20_000, checkpoint_every=1_000)
        self.assertTrue(verify(log.entries, log.witness).ok)

    def test_a_large_log_detects_rechained_truncation(self):
        log = build_log(20_000, checkpoint_every=1_000)
        tampered = apply_tamper(log.entries, "truncate_rechained")
        self.assertTrue(verify_chain_only(tampered).ok)
        self.assertFalse(verify(tampered, log.witness).ok)


if __name__ == "__main__":
    unittest.main()
