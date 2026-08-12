#!/usr/bin/env python3
"""Small regression check for the generated canonical HOLD ledger."""

import unittest

import verify


class CanonicalLedgerTest(unittest.TestCase):
    def test_structural_contract(self) -> None:
        summary, additions, controls = verify.verify_structural()
        self.assertFalse(summary["integration_ready"])
        self.assertEqual(summary["source_envelopes"]["broad_released_max"], 199)
        self.assertEqual(summary["counts"]["canonical_source_components"], 211)
        self.assertEqual(
            summary["counts"]["released_rows_by_state"],
            {"PASS": 181, "NARROW": 12, "UNKNOWN": 2, "REJECT": 4},
        )
        self.assertEqual(len(additions), 28)
        self.assertEqual(len(controls), 30)
        self.assertEqual(
            {state: sum(row["row_state"] == state for row in controls) for state in ("REJECT", "UNKNOWN")},
            {"REJECT": 29, "UNKNOWN": 1},
        )

        zae = next(
            row
            for row in verify.load_jsonl(verify.HERE / "ledger.jsonl")
            if row["row_key"] == "strict-200-v3:alias-99ee5f834a00aca5862a1926"
        )
        self.assertEqual(zae["candidate_fix_edges"][0]["fix_sha"], "9f66c42f06f3b87107ce327bede6416a582f0e60")
        self.assertEqual(zae["release_evidence"]["fix_sha"], "481ce44d818d66e31d8837bc48519660ce4c267f")
        self.assertEqual(len(zae["atomic_fix_members"]), 6)

        ha_mcp = next(
            row
            for row in verify.load_jsonl(verify.HERE / "ledger.jsonl")
            if row["row_key"] == "strict-200-v3:alias-02fb7aeb21b9f4e1ab18fbce"
        )
        self.assertEqual(ha_mcp["atomic_fix_members"], ["0ca572a1452cbabc9004993d6a649afa3c0f435d"])
        self.assertEqual(ha_mcp["release_evidence"]["fix_sha"], "dc8eaa16a8550f885614655f14b6fd9fe429b278")

        mysti = next(
            row
            for row in verify.load_jsonl(verify.HERE / "ledger.jsonl")
            if row["row_key"] == "strict-200-v3:alias-08f4ee97e5be53cda71a58d8"
        )
        self.assertEqual(mysti["atomic_fix_members"], ["c6daf9107a8dc14088feff4671657e6319e36628"])
        self.assertEqual(mysti["release_evidence"]["fix_sha"], "6d709229b5199f6769fb3cf763e5122dcc43c079")
        self.assertIsNone(mysti["release_evidence"]["fixed_tag"])

        attachments = next(
            row
            for row in verify.load_jsonl(verify.HERE / "ledger.jsonl")
            if row["row_key"] == "strict-200-v3:alias-b2364e4376391dd977cef4fa"
        )
        self.assertEqual(attachments["row_state"], "REJECT")
        quay = next(
            row
            for row in verify.load_jsonl(verify.HERE / "ledger.jsonl")
            if row["row_key"] == "strict-200-v3:alias-994d3f3f9e29079393c87538"
        )
        self.assertEqual(quay["row_state"], "UNKNOWN")
        media = next(
            row
            for row in verify.load_jsonl(verify.HERE / "ledger.jsonl")
            if row["row_key"] == "strict-200-v3:alias-948cde45baab136c086accc3"
        )
        self.assertEqual(media["candidate_fix_edges"][0]["fix_sha"], "f865a5455ee03924a444e9ba0f1c4743d8fb6566")
        self.assertEqual(media["row_state"], "PASS")


if __name__ == "__main__":
    unittest.main()
