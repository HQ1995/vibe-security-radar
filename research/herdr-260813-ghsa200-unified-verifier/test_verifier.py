#!/usr/bin/env python3
"""Unit tests for the unified fail-closed verifier.

Covers all ten fail-closed conditions plus the explicit superseded-edge
positive control. Stdlib-only (unittest).
"""

from __future__ import annotations

import unittest

import verifier


def _row(**kw) -> dict:
    row = dict(kw)
    row.setdefault("case_id", "GHSA-0000-0000-0000")
    return row


def _pass_row(**kw) -> dict:
    gates = {g: "PASS" for g in verifier.SEVEN_GATES}
    row = {"case_id": "GHSA-0000-0000-0000", "verdict": "ACCEPT", "gates": gates}
    row.update(kw)
    return row


class TestFailClosed(unittest.TestCase):
    def test_nonterminal_lane(self):
        blockers = verifier.check_lane_terminal({"lane": "upgrade_b", "state": "ACTIVE"})
        self.assertTrue(blockers)
        self.assertEqual(verifier.check_lane_terminal({"lane": "upgrade_a", "state": "TERMINAL"}), [])

    def test_pass_missing_gate(self):
        row = _pass_row()
        row["gates"]["release_gate"] = "NARROW"
        self.assertTrue(verifier.check_seven_gates(row))
        self.assertEqual(verifier.check_seven_gates(_pass_row()), [])

    def test_contributor_missing_scope(self):
        row = _row(contribution_class="AI_NEW_SURFACE_CONTRIBUTOR")
        self.assertTrue(verifier.check_scope_statement(row))
        row["scope_statement"] = "thread-root only"
        self.assertEqual(verifier.check_scope_statement(row), [])

    def test_incomplete_remediation_missing_patch_delta(self):
        row = _row(contribution_class="AI_INCOMPLETE_REMEDIATION")
        self.assertTrue(verifier.check_remediation_patch_delta(row))
        row["remediation_patch_delta_gate"] = "PASS"
        self.assertEqual(verifier.check_remediation_patch_delta(row), [])

    def test_proposal_missing_independent_review(self):
        worker = [_pass_row(case_id="GHSA-1111-1111-1111")]
        self.assertTrue(verifier.check_independent_review(worker, []))
        review = [_row(case_id="GHSA-1111-1111-1111", verdict="ACCEPT")]
        self.assertEqual(verifier.check_independent_review(worker, review), [])

    def test_review_stale_sha_no_supersede(self):
        review = {"bound_sha": "a" * 40, "current_sha": "b" * 40}
        self.assertTrue(verifier.check_hypothesis_chain(review))

    def test_review_stale_sha_with_supersede_positive(self):
        review = {
            "bound_sha": "7bebb1a6eebe7ea01339abaec72e26f93233659dc90f2b850a443d0a7d0d652b",
            "current_sha": "154798fc107a02a296228deea6515b65e37be574eb166440b3277738a25d0160",
            "superseded_edge": True,
            "stale_source": {"expected_sha256": "7bebb1a6eebe7ea01339abaec72e26f93233659dc90f2b850a443d0a7d0d652b",
                             "current_sha256": "154798fc107a02a296228deea6515b65e37be574eb166440b3277738a25d0160"},
        }
        self.assertEqual(verifier.check_hypothesis_chain(review), [])

    def test_conflicting_review(self):
        reviews = [
            _row(case_id="GHSA-2222-2222-2222", verdict="ACCEPT"),
            _row(case_id="GHSA-2222-2222-2222", verdict="REJECT"),
        ]
        self.assertTrue(verifier.check_conflicting_review(reviews))

    def test_duplicate_public_id_overlap(self):
        rows = [
            _row(case_id="GHSA-3333-3333-3333", aliases=["CVE-2026-9999"]),
            _row(case_id="GHSA-4444-4444-4444", aliases=["CVE-2026-9999"]),
        ]
        self.assertTrue(verifier.check_duplicate_overlap(rows))

    def test_unresolved_unknown_blocked(self):
        self.assertTrue(verifier.check_unresolved(_row(verdict="UNKNOWN")))
        self.assertTrue(verifier.check_unresolved(_row(verdict="BLOCKED")))
        self.assertEqual(verifier.check_unresolved(_row(verdict="ACCEPT")), [])

    def test_conservation_failure(self):
        assigned = [1, 2, 3]
        rows = [_row(ordinal=1), _row(ordinal=2)]  # missing 3
        self.assertTrue(verifier.check_conservation(assigned, rows))
        rows_dup = [_row(ordinal=1), _row(ordinal=1)]
        self.assertTrue(verifier.check_conservation(assigned, rows_dup))
        self.assertEqual(verifier.check_conservation(assigned, [_row(ordinal=1), _row(ordinal=2), _row(ordinal=3)]), [])


class TestVerifyHolds(unittest.TestCase):
    def test_verify_outputs_hold(self):
        import json
        from pathlib import Path

        manifest_path = Path(__file__).resolve().parent / "manifest.json"
        root = manifest_path.resolve().parents[1]
        manifest = json.loads(manifest_path.read_text())
        result = verifier.verify(manifest, root)
        self.assertEqual(result["status"], "HOLD")
        self.assertFalse(result["integration_ready"])
        self.assertFalse(result["publication_ready"])
        self.assertTrue(result["blocker_count"] >= 0)
        self.assertTrue(any("nonterminal" in b for b in result["blockers"]))


if __name__ == "__main__":
    unittest.main()
