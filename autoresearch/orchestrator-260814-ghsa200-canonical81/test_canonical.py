#!/usr/bin/env python3
"""Regression checks for the canonical81 HOLD snapshot."""

import unittest
from copy import deepcopy

import build
import verify


class Canonical81Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary, cls.counted = verify.verify()
        cls.rows = verify.load_rows()
        cls.hyp = verify.by_kind(cls.rows, "PRESERVED_HYPOTHESIS")
        cls.pub = verify.by_kind(cls.rows, "PRESERVED_PUBLIC_CASE")
        cls.prior_rows = build.load_jsonl(build.ROOT / build.P_C78_LEDGER)
        cls.prior_summary = build.load_json(build.ROOT / build.P_C78_SUM)
        cls.prior_counted = [
            row for row in cls.prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"
        ]
        cls.new_counted = cls.counted[build.PRIOR_STRICT :]

    def test_base_byte_conservation(self) -> None:
        self.assertEqual(len(self.prior_counted), 78)
        self.assertEqual(self.counted[:78], self.prior_counted)
        self.assertEqual(
            [build.compact_json(row) for row in self.counted[:78]],
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
        self.assertEqual(
            [build.compact_json(row) for row in self.prior_rows if row["record_kind"] == "PRESERVED_HYPOTHESIS"],
            [build.compact_json(row) for row in self.hyp],
        )
        self.assertEqual(
            [build.compact_json(row) for row in self.prior_rows if row["record_kind"] == "PRESERVED_PUBLIC_CASE"],
            [build.compact_json(row) for row in self.pub],
        )
        self.assertEqual(len(self.hyp), 211)
        self.assertEqual(len(self.pub), 212)
        self.assertEqual(len(self.counted), 81)
        self.assertTrue(all(row["counted"] is False for row in self.hyp))
        self.assertTrue(all(row["counted"] is False for row in self.pub))
        self.assertTrue(all(row["counted"] is True for row in self.counted))
        self.assertEqual(
            self.summary["strict_released_case_ids"][:78],
            self.prior_summary["strict_released_case_ids"],
        )
        self.assertTrue(self.summary["conservation"]["base_counted_rows_byte_identical"])
        self.assertEqual(self.summary["conservation"]["fp211_hypotheses"], 211)
        self.assertEqual(self.summary["conservation"]["fp211_source_ghsa_cases"], 212)

    def test_eighty_one_unique_ids_and_fingerprints(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        fps = [row["mechanism_fingerprint"] for row in self.counted]
        mechs = [row["mechanism_key"] for row in self.counted]
        self.assertEqual(len(ids), 81)
        self.assertEqual(len(set(ids)), 81)
        self.assertEqual(len(fps), 81)
        self.assertEqual(len(set(fps)), 81)
        self.assertEqual(len(mechs), 81)
        self.assertEqual(len(set(mechs)), 81)
        self.assertEqual(ids[78:], list(build.NEW_IDS))
        self.assertEqual([row["ordinal"] for row in self.new_counted], [79, 80, 81])
        prior_ids = set(self.prior_summary["strict_released_case_ids"])
        self.assertEqual(set(ids) - prior_ids, set(build.NEW_IDS))
        self.assertTrue(prior_ids <= set(ids))
        self.assertEqual(ids.count("GHSA-Q855-8RH5-JFGQ"), 1)

    def test_exact_ordinals_and_mapping(self) -> None:
        self.assertEqual(
            [(row["case_id"], row["ordinal"]) for row in self.new_counted],
            [
                (build.CASE_X4HG, 79),
                (build.CASE_322X, 80),
                (build.CASE_PMCH, 81),
            ],
        )
        self.assertEqual(self.new_counted[0]["candidate_set"], [build.CAND_X4HG])
        self.assertEqual(self.new_counted[0]["minimum_fix_set"], [build.FIX_X4HG])
        self.assertEqual(self.new_counted[0]["contribution_class"], "AI_DIRECT_ROOT")
        self.assertEqual(self.new_counted[1]["candidate_set"], [build.CAND_322X])
        self.assertEqual(self.new_counted[1]["minimum_fix_set"], [build.FIX_322X])
        self.assertEqual(self.new_counted[1]["contribution_class"], "AI_DIRECT_ROOT")
        self.assertEqual(self.new_counted[2]["candidate_set"], [build.CAND_PMCH])
        self.assertEqual(self.new_counted[2]["minimum_fix_set"], [build.FIX_PMCH])
        self.assertEqual(self.new_counted[2]["contribution_class"], "AI_INCOMPLETE_REMEDIATION")
        for row in self.new_counted:
            self.assertEqual(row["candidate_set"], build.EXPECTED_CANDIDATES[row["case_id"]])
            self.assertEqual(row["minimum_fix_set"], build.EXPECTED_FIXES[row["case_id"]])
            self.assertEqual(row["mechanism_key"], build.EXPECTED_MECHS[row["case_id"]])

    def test_all_gates(self) -> None:
        for row in self.counted:
            for field in build.GATES:
                self.assertEqual(row[field], "PASS")
                self.assertIsNotNone(row[field])
                self.assertNotEqual(row[field], "NA")
            self.assertTrue(build.seven_pass(row))
        poisoned = deepcopy(self.new_counted[0])
        poisoned["release_gate"] = None
        self.assertFalse(build.seven_pass(poisoned))
        poisoned["release_gate"] = "NA"
        self.assertFalse(build.seven_pass(poisoned))
        poisoned["release_gate"] = "PASS"
        self.assertTrue(build.seven_pass(poisoned))

    def test_patch_delta_only_for_pmch(self) -> None:
        self.assertNotIn(build.REMEDIATION_GATE, self.new_counted[0])
        self.assertNotIn(build.REMEDIATION_GATE, self.new_counted[1])
        self.assertEqual(self.new_counted[2][build.REMEDIATION_GATE], "PASS")
        self.assertEqual(self.new_counted[2]["case_id"], build.CASE_PMCH)
        self.assertEqual(self.new_counted[2]["contribution_class"], "AI_INCOMPLETE_REMEDIATION")
        self.assertTrue(all(row["contribution_class"] == "AI_DIRECT_ROOT" for row in self.new_counted[:2]))
        appends = [
            row
            for row in self.rows
            if row["record_kind"] == "APPEND_IDENTITY" and row["case_id"] in build.NEW_IDS
        ]
        self.assertNotIn(build.REMEDIATION_GATE, appends[0])
        self.assertNotIn(build.REMEDIATION_GATE, appends[1])
        self.assertEqual(appends[2][build.REMEDIATION_GATE], "PASS")

    def test_candidate_mapping_refuses_cartesian_edges(self) -> None:
        for row in self.new_counted:
            self.assertEqual(len(row["candidate_set"]), 1)
            self.assertEqual(len(row["minimum_fix_set"]), 1)
            self.assertNotIn("candidate_fix_edges", row)
            self.assertTrue(row["cartesian_candidate_fix_refused"])
        pairs = {
            (row["case_id"], row["candidate_set"][0], row["minimum_fix_set"][0])
            for row in self.new_counted
        }
        self.assertEqual(
            pairs,
            {
                (build.CASE_X4HG, build.CAND_X4HG, build.FIX_X4HG),
                (build.CASE_322X, build.CAND_322X, build.FIX_322X),
                (build.CASE_PMCH, build.CAND_PMCH, build.FIX_PMCH),
            },
        )
        noggin_cartesian = {
            (case_id, cand, fix)
            for case_id in build.NOGGIN_IDS
            for cand in (build.CAND_X4HG, build.CAND_322X)
            for fix in (build.FIX_X4HG, build.FIX_322X)
        }
        noggin_pairs = {pair for pair in pairs if pair[0] in build.NOGGIN_IDS}
        self.assertEqual(len(noggin_pairs), 2)
        self.assertEqual(len(noggin_cartesian), 8)
        self.assertTrue(noggin_pairs < noggin_cartesian)
        self.assertNotIn((build.CASE_X4HG, build.CAND_X4HG, build.FIX_322X), pairs)
        self.assertNotIn((build.CASE_322X, build.CAND_322X, build.FIX_X4HG), pairs)
        for row in self.counted:
            self.assertNotIn("candidate_fix_edges", row)
            self.assertEqual(row["edge_authority"], "candidate_set/carrier_set/minimum_fix_set")

    def test_release_containment_pinned_artifacts(self) -> None:
        x4hg, row_322x, pmch = self.new_counted
        for row in (x4hg, row_322x):
            vuln = row["vulnerable_release"]
            fixed = row["fixed_release"]
            self.assertEqual(vuln["name"], "@asymmetric-effort/nogginlessdom")
            self.assertEqual(fixed["name"], "@asymmetric-effort/nogginlessdom")
            self.assertEqual(vuln["version"], "0.0.21")
            self.assertEqual(fixed["version"], "0.0.22")
            self.assertEqual(vuln["tag"], "v0.0.21")
            self.assertEqual(fixed["tag"], "v0.0.22")
            self.assertEqual(vuln["sha"], build.NPM_VULN_SHA)
            self.assertEqual(vuln["npm_gitHead"], build.NPM_VULN_SHA)
            self.assertEqual(fixed["sha"], build.NPM_FIX_SHA)
            self.assertEqual(fixed["npm_gitHead"], build.NPM_FIX_SHA)
            self.assertEqual(vuln["tarball_sha256"], build.NPM_VULN_TAR_SHA)
            self.assertEqual(fixed["tarball_sha256"], build.NPM_FIX_TAR_SHA)
            self.assertEqual(vuln["tarball"], build.NPM_VULN_TAR)
            self.assertEqual(fixed["tarball"], build.NPM_FIX_TAR)
            self.assertTrue(vuln["contains_candidate"])
            self.assertFalse(vuln["contains_fix"])
            self.assertTrue(fixed["contains_fix"])
            self.assertFalse(fixed["equals_minimum_fix"])
            self.assertEqual(vuln["advisory_range"], "<= 0.0.21")
            self.assertEqual(fixed["advisory_first_patched"], "0.0.22")
            self.assertEqual(row["repository"], "asymmetric-effort/NogginLessDom")
        vuln = pmch["vulnerable_release"]
        fixed = pmch["fixed_release"]
        self.assertEqual(vuln["name"], "langroid")
        self.assertEqual(fixed["name"], "langroid")
        self.assertEqual(vuln["ecosystem"], "PyPI")
        self.assertEqual(vuln["version"], "0.63.0")
        self.assertEqual(fixed["version"], "0.64.0")
        self.assertEqual(vuln["wheel_sha256"], build.PYPI_VULN_WHEEL)
        self.assertEqual(vuln["sdist_sha256"], build.PYPI_VULN_SDIST)
        self.assertEqual(fixed["wheel_sha256"], build.PYPI_FIX_WHEEL)
        self.assertEqual(fixed["sdist_sha256"], build.PYPI_FIX_SDIST)
        self.assertEqual(vuln["sql_chat_agent_blob"], build.PYPI_VULN_BLOB)
        self.assertEqual(fixed["sql_chat_agent_blob"], build.PYPI_FIX_BLOB)
        self.assertEqual(vuln["sha"], build.PYPI_VULN_SHA)
        self.assertEqual(fixed["sha"], build.PYPI_FIX_SHA)
        self.assertTrue(vuln["contains_candidate"])
        self.assertFalse(vuln["contains_fix"])
        self.assertTrue(fixed["contains_fix"])
        self.assertFalse(fixed["equals_minimum_fix"])
        self.assertEqual(pmch["repository"], "langroid/langroid")
        for row in self.new_counted:
            refs = row["first_party_source_refs"]
            self.assertEqual(
                refs[0],
                "https://github.com/advisories/GHSA-" + row["case_id"].split("-", 1)[1].lower(),
            )
            self.assertTrue(any("pages/ghsa/" in item for item in refs))

    def test_gopacket_excluded(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        self.assertNotIn(build.EXCLUDE_GOPACKET, ids)
        self.assertNotIn("GHSA-6R28-9PPF-4HJ5", ids)
        self.assertIn(build.EXCLUDE_GOPACKET, self.summary["excluded"])
        self.assertIn(build.EXCLUDE_GOPACKET, self.summary["checkpoint"]["narrow_noncounting"])
        self.assertEqual(self.summary["counts"]["batch9_three_narrow_excluded"], 1)
        report = (verify.HERE / "report.md").read_text()
        self.assertIn(build.EXCLUDE_GOPACKET, report)
        self.assertIn("gopacket", report)
        keep_edges = [
            row
            for row in self.rows
            if row["record_kind"] == "SUPERSEDES_EDGE"
            and row.get("case_id") == build.EXCLUDE_GOPACKET
            and row.get("to_verdict") == "KEEP"
        ]
        self.assertEqual(keep_edges, [])

    def test_no_duplicates_or_excluded_identities(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertNotIn("GHSA-7C3W-FXGH-FRC7", ids)
        self.assertNotIn("GHSA-F38V-77QJ-H4JQ", ids)
        self.assertNotIn("GHSA-4FXP-2M36-QV64", ids)
        self.assertNotIn("GHSA-XW57-23P8-9WC5", ids)
        self.assertNotIn("GHSA-QCR8-X557-7CP3", ids)
        self.assertNotIn(build.EXCLUDE_GOPACKET, ids)
        source = {row["case_id"] for row in self.pub}
        self.assertTrue(all(case_id not in source for case_id in build.NEW_IDS))
        cve_aliases = [
            item for row in self.counted for item in row["aliases"] if item.startswith("CVE-")
        ]
        self.assertTrue(all(item not in ids for item in cve_aliases))
        self.assertEqual(self.new_counted[2]["aliases"], ["CVE-2026-50180"])
        self.assertEqual(self.new_counted[0]["aliases"], [])
        self.assertEqual(self.new_counted[1]["aliases"], [])

    def test_hold_boundaries(self) -> None:
        self.assertEqual(self.summary["canonical_strict_count"], 81)
        self.assertEqual(self.summary["counts"]["strict_released_first_party_ghsa"], 81)
        self.assertEqual(self.summary["counts"]["batch9_three_keep"], 2)
        self.assertEqual(self.summary["counts"]["langroid_one_keep"], 1)
        self.assertEqual(self.summary["checkpoint"]["prior_strict_count"], 78)
        self.assertEqual(self.summary["checkpoint"]["corrected_strict_count"], 81)
        self.assertEqual(self.summary["checkpoint"]["appended_batch9_two"], list(build.NOGGIN_IDS))
        self.assertEqual(self.summary["checkpoint"]["appended_langroid_one"], [build.CASE_PMCH])
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
        self.assertEqual(manifest["canonical_strict_count"], 81)

    def test_exact_scope_is_canonical78_plus_three(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        prior_ids = self.prior_summary["strict_released_case_ids"]
        self.assertEqual(ids[:78], prior_ids)
        self.assertEqual(ids[78:], list(build.NEW_IDS))
        self.assertEqual(set(ids), set(prior_ids) | set(build.NEW_IDS))
        self.assertEqual(len(self.new_counted), 3)
        self.assertEqual(
            self.summary["counts"]["strict_released_first_party_ghsa"],
            78 + 3,
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
                "batch9_three_redteam_keep",
                "langroid_one_redteam_keep",
            },
        )
        self.assertEqual(self.new_counted[0]["admission_source"], "batch9_three_redteam_keep")
        self.assertEqual(self.new_counted[1]["admission_source"], "batch9_three_redteam_keep")
        self.assertEqual(self.new_counted[2]["admission_source"], "langroid_one_redteam_keep")

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
        self.assertTrue(all("clone" not in row for row in self.new_counted))


if __name__ == "__main__":
    unittest.main()
