#!/usr/bin/env python3
"""Focused regression checks for the fp211 canonical admission overlay."""

import unittest
from copy import deepcopy

import verify


class Fp211CanonicalTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary, cls.rows = verify.verify()
        cls.by_key = {row["row_key"]: row for row in cls.rows}

    def test_verdicts_and_publication_gate(self) -> None:
        self.assertEqual(
            self.summary["counts"]["canonical_rows_by_state"],
            {"NARROW": 83, "PASS": 65, "REJECT": 54, "UNKNOWN": 9},
        )
        self.assertEqual(self.summary["counts"]["strict_confirmed_mechanisms"], 51)
        self.assertEqual(
            self.summary["counts"]["released_publication_admitted_mechanisms"], 48
        )
        self.assertTrue(self.summary["canonical_overlay_ready"])
        self.assertFalse(self.summary["integration_ready"])
        self.assertFalse(self.summary["publication_ready"])
        for row in self.rows:
            audit = row["fp211_adjudication"]
            self.assertEqual(
                row["counting"]["fp211_released_publication_admitted"],
                verify.build.released_publication_admitted(audit, row["source_tier"]),
            )

    def test_filebrowser_semantic_controls_do_not_dedupe_shared_edge(self) -> None:
        negative = self.by_key["post:filebrowser-delete-scope@canonical"]
        positive = self.by_key["post:filebrowser-dangling-write@canonical"]
        self.assertEqual(negative["fp211_adjudication"]["verdict"], "FALSE_POSITIVE")
        self.assertEqual(negative["fp211_adjudication"]["causal_class"], "WRONG_EDGE")
        for field in ("ai_hunk_gate", "but_for_gate", "fix_reversal_gate"):
            self.assertEqual(negative["fp211_adjudication"][field], "FAIL")
        self.assertFalse(negative["counting"]["fp211_released_publication_admitted"])
        self.assertEqual(positive["fp211_adjudication"]["verdict"], "CONFIRM")
        self.assertEqual(
            positive["fp211_adjudication"]["causal_class"],
            "AI_INCOMPLETE_REMEDIATION",
        )
        self.assertTrue(positive["counting"]["fp211_released_publication_admitted"])
        self.assertTrue(positive["source_tier"].endswith("_RELEASED"))
        self.assertEqual(
            negative["fp211_adjudication"]["candidate_set"],
            positive["fp211_adjudication"]["candidate_set"],
        )
        self.assertEqual(
            negative["fp211_adjudication"]["minimum_fix_set"],
            positive["fp211_adjudication"]["minimum_fix_set"],
        )

    def test_na_released_is_hold_and_balanced_swap_is_rejected(self) -> None:
        positive = deepcopy(
            self.rows[165]["fp211_adjudication"]
        )
        positive["release_gate"] = "NA"
        self.assertTrue(verify.build.strict_confirmed(positive))
        self.assertFalse(
            verify.build.released_publication_admitted(positive, "STRICT_RELEASED")
        )

        audits = verify.load_jsonl(verify.ROOT / verify.build.AUDIT_ROWS)
        swapped = deepcopy(audits)
        semantic_fields = (
            "verdict",
            "causal_class",
            "confidence",
            *verify.GATE_FIELDS,
            "candidate_set",
            "carrier_set",
            "minimum_fix_set",
            "duplicate_of",
            "false_positive_class",
            "baseline_state",
            "public_ids_keep",
            "public_ids_remove",
        )
        for field in semantic_fields:
            swapped[164][field], swapped[165][field] = (
                swapped[165][field],
                swapped[164][field],
            )
        self.assertEqual(swapped[164]["ordinal"], 165)
        self.assertEqual(
            swapped[164]["row_key"], "post:filebrowser-delete-scope@canonical"
        )
        self.assertEqual(swapped[165]["ordinal"], 166)
        self.assertEqual(
            swapped[165]["row_key"], "post:filebrowser-dangling-write@canonical"
        )
        with self.assertRaises(AssertionError):
            verify.build.assert_semantic_controls(swapped)

    def test_ten_polluted_ids_are_removed_but_declared(self) -> None:
        removed = {
            value
            for row in self.rows
            for value in row["fp211_adjudication"]["public_ids_remove"]
        }
        self.assertEqual(removed, set(self.summary["removed_public_ids"]))
        self.assertEqual(len(removed), 10)
        self.assertTrue(
            all(
                value in row["declared_public_ids"]
                for row in self.rows
                for value in row["fp211_adjudication"]["public_ids_remove"]
            )
        )
        self.assertTrue(
            all(
                value not in row["public_ids"]
                for row in self.rows
                for value in row["fp211_adjudication"]["public_ids_remove"]
            )
        )

    def test_false_positive_duplicates_remain_audited_hypotheses(self) -> None:
        for row_key in (
            "strict-200-v3:alias-c45218004b47b9754c596ca1",
            "strict-200-v3:alias-c6e0a965a87d452bf5cc44af",
        ):
            row = self.by_key[row_key]
            self.assertEqual(row["row_state"], "REJECT")
            self.assertEqual(row["fp211_adjudication"]["verdict"], "FALSE_POSITIVE")
            self.assertIsNotNone(row["fp211_adjudication"]["duplicate_of"])
            self.assertFalse(row["counting"]["fp211_causal_valid"])

    def test_edge_sets_are_authoritative_without_cartesian_edges(self) -> None:
        row = self.by_key["post:gitea-draft-attachment@canonical"]
        audit = row["fp211_adjudication"]
        self.assertEqual(len(audit["candidate_set"]), 2)
        self.assertEqual(len(audit["minimum_fix_set"]), 2)
        self.assertEqual(len(row["candidate_fix_edges"]), 1)
        self.assertEqual(
            audit["edge_authority"], "candidate_set/carrier_set/minimum_fix_set"
        )
        self.assertEqual(
            audit["legacy_top_level_edge_policy"],
            "PRESERVED_HISTORICAL_ROUTING_EVIDENCE",
        )

    def test_generated_snapshot_is_english_only(self) -> None:
        self.assertTrue(
            all(not verify.HAN.search(row.get("mechanism", "")) for row in self.rows)
        )


if __name__ == "__main__":
    unittest.main()
