import copy
import json
import tempfile
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ledger_store import read_patches, validate_update
from audit_record_gates import check_record


class LedgerStoreContracts(unittest.TestCase):
    def setUp(self):
        self.row = {
            "class_id": "alias-test",
            "status": "AI_ROOT_CAUSE",
            "advisory_ids": ["CVE-2026-12345", "GHSA-AAAA-BBBB-CCCC"],
            "round6_research": {
                "introducer_sha": "a" * 40,
                "ai_marker": "Co-Authored-By: Claude",
                "reasoning": "The introducing commit added the vulnerable sink.",
            },
        }

    def test_accepts_additional_natural_language(self):
        updated = copy.deepcopy(self.row)
        updated["causal_narrative"] = {
            "before": "The parent rejected the input.",
            "after": "The new path accepted it without authorization.",
        }
        validate_update(self.row, updated)

    def test_rejects_advisory_id_loss(self):
        updated = copy.deepcopy(self.row)
        updated["advisory_ids"].pop()
        with self.assertRaisesRegex(ValueError, "cannot be removed"):
            validate_update(self.row, updated)

    def test_rejects_incomplete_closed_envelope(self):
        updated = copy.deepcopy(self.row)
        updated["round6_research"]["ai_marker"] = None
        with self.assertRaisesRegex(ValueError, "envelope gate"):
            validate_update(self.row, updated)

    def test_rejects_not_ai_publication_fields(self):
        updated = copy.deepcopy(self.row)
        updated.update(status="NOT_AI", site_scope="AI_ROOT_CAUSE", site_tier="ALL_GATES_PASS")
        with self.assertRaisesRegex(ValueError, "NOT_AI must not carry site_scope/site_tier"):
            validate_update(self.row, updated)

    def test_batch_patches_are_sorted_before_locking(self):
        patches = [
            {"expected_revision": 1, "row": {"class_id": "alias-z"}},
            {"expected_revision": 1, "row": {"class_id": "alias-a"}},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "patches.jsonl"
            path.write_text("".join(json.dumps(item) + "\n" for item in patches))
            ordered = read_patches(path, require_assessments=False)
        self.assertEqual(
            [item["row"]["class_id"] for item in ordered],
            ["alias-a", "alias-z"],
        )

    def test_accepts_verified_non_git_svn_bic(self):
        record = {
            "class_id": "alias-svn",
            "verdict": "NOT_AI",
            "advisory_ids": ["CVE-2026-12345"],
            "introducer_sha": None,
            "introducer_parent": None,
            "introducer_parent_absent": True,
            "fix_sha": "b" * 40,
            "direct_fix_sha": "b" * 40,
            "ai_marker": "absent on SVN revision r7446",
            "flaw_origin": "WordPress SVN changeset r7446 first wrote the flaw.",
            "evidence": "SVN revision r7445 lacks the file; the later Git import is not the BIC.",
            "reasoning": "The canonical public BIC is non-Git SVN revision r7446.",
            "remaining_gap": None,
        }
        self.assertEqual(check_record(record), [])
        updated = copy.deepcopy(self.row)
        updated["status"] = "NOT_AI"
        updated["round6_research"] = record
        validate_update(self.row, updated)

    def test_false_positive_requires_rejection_evidence(self):
        record = {
            "class_id": "alias-fp",
            "verdict": "FALSE_POSITIVE",
            "advisory_ids": ["CVE-2025-63391"],
            "introducer_sha": None,
            "introducer_parent": None,
            "introducer_parent_absent": False,
            "fix_sha": None,
            "direct_fix_sha": None,
            "ai_marker": None,
            "flaw_origin": "Advisory withdrawn by CNA.",
            "evidence": "CVE.org record REJECTED 2026-06-29: not a security issue.",
            "reasoning": "Withdrawn by CNA; the endpoint is intentional pre-auth design.",
            "remaining_gap": None,
        }
        self.assertEqual(check_record(record), [])
        from audit_envelope import violations
        row = {"class_id": "alias-fp", "status": "FALSE_POSITIVE", "advisory_ids": ["CVE-2025-63391"], "causal_research": record}
        self.assertEqual(violations(row), [])


if __name__ == "__main__":
    unittest.main()
