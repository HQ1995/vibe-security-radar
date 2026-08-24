#!/usr/bin/env python3
"""Regression checks for the canonical71 HOLD snapshot."""

import unittest
from copy import deepcopy

import build
import verify


class Canonical71Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary, cls.counted = verify.verify()
        cls.rows = verify.load_rows()
        cls.hyp = verify.by_kind(cls.rows, "PRESERVED_HYPOTHESIS")
        cls.pub = verify.by_kind(cls.rows, "PRESERVED_PUBLIC_CASE")

    def test_hold_and_seventy_two(self) -> None:
        self.assertEqual(self.summary["canonical_strict_count"], 72)
        self.assertEqual(self.summary["counts"]["strict_released_first_party_ghsa"], 72)
        self.assertEqual(self.summary["counts"]["corrected_baseline_47"], 47)
        self.assertEqual(self.summary["counts"]["fp211_released_admitted_raw"], 48)
        self.assertEqual(self.summary["counts"]["netnew22_keep"], 21)
        self.assertEqual(self.summary["counts"]["actual_gogs_keep"], 2)
        self.assertEqual(self.summary["counts"]["b3_keep"], 2)
        self.assertEqual(self.summary["checkpoint"]["uncorrected_count_not_terminal"], 73)
        self.assertEqual(self.summary["checkpoint"]["corrected_strict_count"], 72)
        self.assertEqual(
            self.summary["checkpoint"]["downgraded"],
            ["GHSA-4FXP-2M36-QV64"],
        )
        self.assertFalse(self.summary["integration_ready"])
        self.assertFalse(self.summary["publication_ready"])
        self.assertEqual(self.summary["status"], "HOLD")
        self.assertFalse(self.summary["public_200_claim_supported"])
        self.assertNotIn("GHSA-7C3W-FXGH-FRC7", self.summary["strict_released_case_ids"])
        self.assertNotIn("GHSA-F38V-77QJ-H4JQ", self.summary["strict_released_case_ids"])
        self.assertNotIn("GHSA-4FXP-2M36-QV64", self.summary["strict_released_case_ids"])
        self.assertIn("GHSA-G3XQ-3GMV-QQ8G", self.summary["strict_released_case_ids"])
        self.assertIn("GHSA-PV2J-RGHR-V5R9", self.summary["strict_released_case_ids"])

    def test_final_review_narrow_downgrades_old_baseline_count(self) -> None:
        counted_ids = {row["case_id"] for row in self.counted}
        self.assertNotIn("GHSA-4FXP-2M36-QV64", counted_ids)
        self.assertTrue(
            all(
                row["case_id"] != "GHSA-4FXP-2M36-QV64"
                for row in self.rows
                if row["record_kind"] == "STRICT_RELEASED_CASE"
            )
        )
        hyp = next(
            row
            for row in self.hyp
            if "GHSA-4FXP-2M36-QV64" in row.get("public_ids", [])
            or "GHSA-4FXP-2M36-QV64" in row.get("declared_public_ids", [])
        )
        self.assertTrue(hyp["released_publication_admitted"])
        self.assertEqual(hyp["overlay_state"], "NARROW")
        self.assertEqual(hyp["gates"]["identity_gate"], "NARROW")
        self.assertEqual(
            hyp["authority_packet"],
            "autoresearch/herdr-260813-ghsa200-final-candidate-review-codex",
        )
        edge = next(
            row
            for row in verify.by_kind(self.rows, "SUPERSEDES_EDGE")
            if row["case_id"] == "GHSA-4FXP-2M36-QV64"
        )
        self.assertTrue(edge["applies_to_counted_set"])
        self.assertEqual(edge["from_verdict"], "fp211_released_publication_admitted")
        self.assertEqual(edge["to_verdict"], "NARROW")

    def test_source_conservation_is_not_the_counted_set(self) -> None:
        self.assertEqual(len(self.hyp), 211)
        self.assertEqual(len(self.pub), 212)
        self.assertEqual(len(self.counted), 72)
        self.assertTrue(all(row["counted"] is False for row in self.hyp))
        self.assertTrue(all(row["counted"] is False for row in self.pub))
        self.assertTrue(all(row["counted"] is True for row in self.counted))

    def test_filebrowser_and_ordinal_200(self) -> None:
        by_key = {row["row_key"]: row for row in self.hyp}
        negative = by_key[verify.FILEBROWSER_NEG]
        positive = by_key[verify.FILEBROWSER_POS]
        self.assertEqual(negative["fp211_verdict"], "FALSE_POSITIVE")
        self.assertEqual(positive["fp211_verdict"], "CONFIRM")
        dual = [row for row in self.pub if row["ordinal"] == 200]
        self.assertEqual({row["case_id"] for row in dual}, set(verify.ORD200))

    def test_null_and_na_fail_the_predicate(self) -> None:
        row = deepcopy(self.counted[0])
        row["release_gate"] = None
        self.assertFalse(build.seven_pass(row))
        row["release_gate"] = "NA"
        self.assertFalse(build.seven_pass(row))
        row["release_gate"] = "PASS"
        self.assertTrue(build.seven_pass(row))

    def test_no_cartesian_edges_on_multi_sha_row(self) -> None:
        multi = [item for item in self.counted if len(item["candidate_set"]) > 1]
        self.assertTrue(multi)
        xw8c = next(item for item in self.counted if item["case_id"] == "GHSA-XW8C-RRVX-F7XQ")
        self.assertEqual(len(xw8c["candidate_set"]), 2)
        self.assertEqual(len(xw8c["minimum_fix_set"]), 1)
        for row in self.counted:
            self.assertNotIn("candidate_fix_edges", row)
            self.assertEqual(row["edge_authority"], "candidate_set/carrier_set/minimum_fix_set")

    def test_append_only_absent_identities(self) -> None:
        source = {row["case_id"] for row in self.pub}
        appends = verify.by_kind(self.rows, "APPEND_IDENTITY")
        self.assertEqual(len(appends), 3)
        self.assertTrue(all(row["case_id"] not in source for row in appends))
        upgrades = [row for row in self.counted if row["action"] == "SUPERSEDE"]
        self.assertTrue(all(row["in_fp211_212"] for row in upgrades))
        self.assertTrue(all(row["case_id"] in source for row in upgrades))


if __name__ == "__main__":
    unittest.main()
