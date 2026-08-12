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
            {"PASS": 191, "NARROW": 4, "UNKNOWN": 1, "REJECT": 3},
        )
        self.assertEqual(len(additions), 28)
        self.assertEqual(len(controls), 30)
        self.assertEqual(
            {state: sum(row["row_state"] == state for row in controls) for state in ("REJECT", "UNKNOWN")},
            {"REJECT": 29, "UNKNOWN": 1},
        )


if __name__ == "__main__":
    unittest.main()
