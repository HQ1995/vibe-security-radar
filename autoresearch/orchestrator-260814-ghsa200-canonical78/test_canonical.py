#!/usr/bin/env python3
"""Regression checks for the canonical78 HOLD snapshot."""

import unittest
from copy import deepcopy

import build
import verify


class Canonical78Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary, cls.counted = verify.verify()
        cls.rows = verify.load_rows()
        cls.hyp = verify.by_kind(cls.rows, "PRESERVED_HYPOTHESIS")
        cls.pub = verify.by_kind(cls.rows, "PRESERVED_PUBLIC_CASE")
        cls.prior_rows = build.load_jsonl(build.ROOT / build.P_C73_LEDGER)
        cls.prior_summary = build.load_json(build.ROOT / build.P_C73_SUM)
        cls.prior_counted = [
            row for row in cls.prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"
        ]
        cls.new_counted = cls.counted[build.PRIOR_STRICT :]

    def test_base_byte_conservation(self) -> None:
        self.assertEqual(len(self.prior_counted), 73)
        self.assertEqual(self.counted[:73], self.prior_counted)
        self.assertEqual(
            [build.compact_json(row) for row in self.counted[:73]],
            [build.compact_json(row) for row in self.prior_counted],
        )
        self.assertEqual(
            [row for row in self.prior_rows if row["record_kind"] == "PRESERVED_HYPOTHESIS"],
            self.hyp,
        )
        self.assertEqual(
            [row for row in self.prior_rows if row["record_kind"] == "PRESERVED_PUBLIC_CASE"],
            self.pub,
        )
        self.assertEqual(len(self.hyp), 211)
        self.assertEqual(len(self.pub), 212)
        self.assertEqual(len(self.counted), 78)
        self.assertTrue(all(row["counted"] is False for row in self.hyp))
        self.assertTrue(all(row["counted"] is False for row in self.pub))
        self.assertTrue(all(row["counted"] is True for row in self.counted))
        self.assertEqual(
            self.summary["strict_released_case_ids"][:73],
            self.prior_summary["strict_released_case_ids"],
        )
        self.assertTrue(self.summary["conservation"]["base_counted_rows_byte_identical"])
        self.assertEqual(self.summary["conservation"]["fp211_hypotheses"], 211)
        self.assertEqual(self.summary["conservation"]["fp211_source_ghsa_cases"], 212)

    def test_seventy_eight_unique_ids_and_fingerprints(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        fps = [row["mechanism_fingerprint"] for row in self.counted]
        mechs = [row["mechanism_key"] for row in self.counted]
        self.assertEqual(len(ids), 78)
        self.assertEqual(len(set(ids)), 78)
        self.assertEqual(len(fps), 78)
        self.assertEqual(len(set(fps)), 78)
        self.assertEqual(len(mechs), 78)
        self.assertEqual(len(set(mechs)), 78)
        self.assertEqual(ids[73:], list(build.NEW_IDS))
        self.assertEqual([row["ordinal"] for row in self.new_counted], [74, 75, 76, 77, 78])
        prior_ids = set(self.prior_summary["strict_released_case_ids"])
        self.assertEqual(set(ids) - prior_ids, set(build.NEW_IDS))
        self.assertTrue(prior_ids <= set(ids))
        self.assertEqual(ids.count("GHSA-Q855-8RH5-JFGQ"), 1)

    def test_all_gates(self) -> None:
        for row in self.counted:
            for field in build.GATES:
                self.assertEqual(row[field], "PASS")
                self.assertIsNotNone(row[field])
                self.assertNotEqual(row[field], "NA")
        for row in self.new_counted:
            self.assertEqual(row["contribution_class"], "AI_INCOMPLETE_REMEDIATION")
            self.assertEqual(row[build.REMEDIATION_GATE], "PASS")
            self.assertTrue(build.seven_pass(row))
        poisoned = deepcopy(self.new_counted[0])
        poisoned["release_gate"] = None
        self.assertFalse(build.seven_pass(poisoned))
        poisoned["release_gate"] = "NA"
        self.assertFalse(build.seven_pass(poisoned))
        poisoned["release_gate"] = "PASS"
        self.assertTrue(build.seven_pass(poisoned))
        poisoned[build.REMEDIATION_GATE] = None
        self.assertNotEqual(poisoned[build.REMEDIATION_GATE], "PASS")

    def test_candidate_mapping_refuses_cartesian_edges(self) -> None:
        for row in self.new_counted:
            self.assertEqual(row["candidate_set"], build.EXPECTED_CANDIDATES[row["case_id"]])
            self.assertEqual(row["minimum_fix_set"], [build.FIX_PT])
            self.assertEqual(len(row["candidate_set"]), 1)
            self.assertEqual(len(row["minimum_fix_set"]), 1)
            self.assertNotIn("candidate_fix_edges", row)
            self.assertTrue(row["cartesian_candidate_fix_refused"])
        https = [row for row in self.new_counted if row["case_id"] in build.HTTPS_IDS]
        sast = [row for row in self.new_counted if row["case_id"] in build.SAST_IDS]
        self.assertEqual(len(https), 3)
        self.assertEqual(len(sast), 2)
        self.assertTrue(all(row["candidate_set"] == [build.CAND_HTTPS] for row in https))
        self.assertTrue(all(row["candidate_set"] == [build.CAND_SAST] for row in sast))
        pairs = {
            (row["case_id"], row["candidate_set"][0], row["minimum_fix_set"][0])
            for row in self.new_counted
        }
        cartesian = {
            (case_id, cand, build.FIX_PT)
            for case_id in build.NEW_IDS
            for cand in (build.CAND_HTTPS, build.CAND_SAST)
        }
        self.assertEqual(len(pairs), 5)
        self.assertEqual(len(cartesian), 10)
        self.assertTrue(pairs < cartesian)
        for row in self.counted:
            self.assertNotIn("candidate_fix_edges", row)
            self.assertEqual(row["edge_authority"], "candidate_set/carrier_set/minimum_fix_set")

    def test_release_containment(self) -> None:
        for row in self.new_counted:
            vuln = row["vulnerable_release"]
            fixed = row["fixed_release"]
            self.assertEqual(vuln["name"], "@asymmetric-effort/specifyjs")
            self.assertEqual(fixed["name"], "@asymmetric-effort/specifyjs")
            self.assertEqual(vuln["version"], "0.2.135")
            self.assertEqual(fixed["version"], "0.2.136")
            self.assertEqual(vuln["tag"], "v0.2.135")
            self.assertEqual(fixed["tag"], "v0.2.136")
            self.assertEqual(vuln["sha"], build.VULN_SHA)
            self.assertEqual(vuln["npm_gitHead"], build.VULN_SHA)
            self.assertEqual(fixed["sha"], build.FIX_PT)
            self.assertEqual(fixed["npm_gitHead"], build.FIX_PT)
            self.assertTrue(vuln["contains_candidate"])
            self.assertFalse(vuln["contains_fix"])
            self.assertTrue(fixed["contains_fix"])
            self.assertTrue(fixed["equals_minimum_fix"])
            self.assertEqual(vuln["advisory_range"], "< 0.2.136")
            self.assertEqual(fixed["advisory_first_patched"], "0.2.136")
            refs = row["first_party_source_refs"]
            self.assertEqual(
                refs[0],
                "https://github.com/advisories/GHSA-" + row["case_id"].split("-", 1)[1].lower(),
            )
            self.assertTrue(any(item.endswith(".json") and "pages/ghsa/" in item for item in refs))
            self.assertEqual(row["repository"], "asymmetric-effort/specifyjs")

    def test_no_duplicates_or_excluded_identities(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertNotIn("GHSA-7C3W-FXGH-FRC7", ids)
        self.assertNotIn("GHSA-F38V-77QJ-H4JQ", ids)
        self.assertNotIn("GHSA-4FXP-2M36-QV64", ids)
        self.assertNotIn("GHSA-XW57-23P8-9WC5", ids)
        self.assertNotIn("GHSA-QCR8-X557-7CP3", ids)
        source = {row["case_id"] for row in self.pub}
        self.assertTrue(all(case_id not in source for case_id in build.NEW_IDS))
        cve_aliases = [
            item for row in self.counted for item in row["aliases"] if item.startswith("CVE-")
        ]
        self.assertTrue(all(item not in ids for item in cve_aliases))
        self.assertIn("CVE-2026-50288", self.new_counted[0]["aliases"])
        self.assertIn("CVE-2026-50290", self.new_counted[4]["aliases"])

    def test_hold_boundaries(self) -> None:
        self.assertEqual(self.summary["canonical_strict_count"], 78)
        self.assertEqual(self.summary["counts"]["strict_released_first_party_ghsa"], 78)
        self.assertEqual(self.summary["counts"]["specifyjs_five_keep"], 5)
        self.assertEqual(self.summary["checkpoint"]["prior_strict_count"], 73)
        self.assertEqual(self.summary["checkpoint"]["corrected_strict_count"], 78)
        self.assertEqual(
            self.summary["checkpoint"]["appended_specifyjs_five"],
            list(build.NEW_IDS),
        )
        self.assertFalse(self.summary["integration_ready"])
        self.assertFalse(self.summary["publication_ready"])
        self.assertFalse(self.summary["causal_admission"])
        self.assertFalse(self.summary["public_200_claim_supported"])
        self.assertEqual(self.summary["status"], "HOLD")
        report = (verify.HERE / "report.md").read_text()
        self.assertNotIn("more than 200", report.lower())
        self.assertIn("greater-than-200", report)
        self.assertIn("Integration_ready is false", report)
        self.assertIn("Publication_ready is false", report)
        manifest = build.load_json(verify.HERE / "manifest.json")
        self.assertFalse(manifest["integration_ready"])
        self.assertFalse(manifest["publication_ready"])
        self.assertFalse(manifest["public_200_claim_supported"])
        self.assertEqual(manifest["status"], "HOLD")
        self.assertEqual(manifest["canonical_strict_count"], 78)

    def test_exact_scope_is_canonical73_plus_five(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        prior_ids = self.prior_summary["strict_released_case_ids"]
        self.assertEqual(ids[:73], prior_ids)
        self.assertEqual(ids[73:], list(build.NEW_IDS))
        self.assertEqual(set(ids), set(prior_ids) | set(build.NEW_IDS))
        self.assertEqual(len(self.new_counted), 5)
        self.assertEqual(self.summary["counts"]["specifyjs_five_keep"], 5)
        self.assertEqual(
            self.summary["counts"]["strict_released_first_party_ghsa"],
            73 + 5,
        )
        sources = {row["admission_source"] for row in self.counted}
        self.assertEqual(
            sources,
            {
                "fp211_released_publication_admitted",
                "netnew22_redteam_keep",
                "actual_gogs_redteam_keep",
                "b3_redteam_keep",
                "q855_redteam_keep",
                "specifyjs_five_redteam_keep",
            },
        )
        self.assertTrue(
            all(row["admission_source"] == "specifyjs_five_redteam_keep" for row in self.new_counted)
        )

    def test_no_shell_or_credential_leakage(self) -> None:
        artifacts = [
            (verify.HERE / "report.md").read_text(),
            (verify.HERE / "summary.json").read_text(),
            (verify.HERE / "manifest.json").read_text(),
        ]
        artifacts.extend(build.compact_json(row) for row in self.new_counted)
        for text in artifacts:
            build.assert_no_leak(text)
        script_text = (verify.HERE / "build.py").read_text() + (verify.HERE / "verify.py").read_text()
        self.assertNotIn("os" + ".environ", script_text)
        self.assertNotIn("environ" + ".copy", script_text)
        self.assertNotIn("print" + "env", script_text)
        self.assertTrue(all("clone_path" not in row for row in self.new_counted))


if __name__ == "__main__":
    unittest.main()
