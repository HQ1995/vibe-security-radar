#!/usr/bin/env python3
"""Regression checks for the canonical85 HOLD snapshot."""

import unittest
from copy import deepcopy

import build
import verify


class Canonical85Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary, cls.counted = verify.verify()
        cls.rows = verify.load_rows()
        cls.hyp = verify.by_kind(cls.rows, "PRESERVED_HYPOTHESIS")
        cls.pub = verify.by_kind(cls.rows, "PRESERVED_PUBLIC_CASE")
        cls.prior_rows = build.load_jsonl(build.ROOT / build.P_C84_LEDGER)
        cls.prior_summary = build.load_json(build.ROOT / build.P_C84_SUM)
        cls.prior_counted = [
            row for row in cls.prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"
        ]
        cls.new_counted = cls.counted[build.PRIOR_STRICT :]
        cls.cap_8359 = build.load_capsule_8359()
        cls.neg = {row["case_id"]: row for row in build.load_negative()["controls"]}
        cls.manifest = build.load_json(verify.HERE / "manifest.json")

    def test_base_byte_conservation(self) -> None:
        self.assertEqual(len(self.prior_rows), 581)
        self.assertEqual(len(self.rows), 582)
        self.assertEqual(self.rows[:581], self.prior_rows)
        self.assertEqual(
            [build.compact_json(row) for row in self.rows[:581]],
            [build.compact_json(row) for row in self.prior_rows],
        )
        prior_text = (build.ROOT / build.P_C84_LEDGER).read_text()
        current_text = (verify.HERE / "ledger.jsonl").read_text()
        self.assertTrue(current_text.startswith(prior_text if prior_text.endswith("\n") else prior_text + "\n"))
        self.assertEqual(len(self.prior_counted), 84)
        self.assertEqual(self.counted[:84], self.prior_counted)
        self.assertEqual(len(self.hyp), 211)
        self.assertEqual(len(self.pub), 212)
        self.assertEqual(len(self.counted), 85)
        self.assertTrue(all(row["counted"] is False for row in self.hyp))
        self.assertTrue(all(row["counted"] is False for row in self.pub))
        self.assertTrue(all(row["counted"] is True for row in self.counted))
        self.assertEqual(
            self.summary["strict_released_case_ids"][:84],
            self.prior_summary["strict_released_case_ids"],
        )
        self.assertTrue(self.summary["conservation"]["base_counted_rows_byte_identical"])
        self.assertTrue(self.summary["conservation"]["base_ledger_rows_byte_identical"])
        self.assertEqual(self.summary["conservation"]["fp211_hypotheses"], 211)
        self.assertEqual(self.summary["conservation"]["fp211_source_ghsa_cases"], 212)
        self.assertFalse(self.summary["conservation"]["cve_aliases_counted"])
        prior_append = self.prior_summary["conservation"]["append_identities"]
        self.assertEqual(len(prior_append), 14)
        self.assertEqual(self.summary["conservation"]["prior_append_identities"], prior_append)
        self.assertEqual(
            self.summary["conservation"]["new_append_identities"],
            [build.CASE_8359],
        )
        self.assertEqual(
            self.summary["conservation"]["append_identities"],
            prior_append + [build.CASE_8359],
        )
        self.assertEqual(len(self.summary["conservation"]["append_identities"]), 15)
        self.assertTrue(self.summary["conservation"]["new_identities_append"])
        self.assertFalse(self.summary["conservation"]["same_id_source_layer_promoted"])
        self.assertFalse(self.summary["conservation"]["upgrades_append"])
        self.assertEqual(self.summary["conservation"]["appended_strict_rows"], 1)
        self.assertEqual(self.summary["counts"]["by_record_kind"]["APPEND_IDENTITY"], 12)
        self.assertEqual(self.summary["counts"]["by_record_kind"]["PACKET_AUTHORITY"], 18)
        self.assertEqual(self.summary["counts"]["by_record_kind"]["PRESERVED_HYPOTHESIS"], 211)
        self.assertEqual(self.summary["counts"]["by_record_kind"]["PRESERVED_PUBLIC_CASE"], 212)

    def test_eighty_five_unique_ids_and_fingerprints(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        fps = [row["mechanism_fingerprint"] for row in self.counted]
        mechs = [row["mechanism_key"] for row in self.counted]
        self.assertEqual(len(ids), 85)
        self.assertEqual(len(set(ids)), 85)
        self.assertEqual(len(fps), 85)
        self.assertEqual(len(set(fps)), 85)
        self.assertEqual(len(mechs), 85)
        self.assertEqual(len(set(mechs)), 85)
        self.assertEqual(ids[84:], [build.CASE_8359])
        self.assertEqual([row["ordinal"] for row in self.new_counted], [85])
        prior_ids = set(self.prior_summary["strict_released_case_ids"])
        self.assertEqual(set(ids) - prior_ids, {build.CASE_8359})
        self.assertTrue(prior_ids <= set(ids))
        self.assertEqual(ids.count(build.CASE_8359), 1)
        self.assertNotIn(build.ALIAS_8359, ids)
        self.assertNotIn(build.CASE_954P, ids)
        self.assertNotIn(build.CASE_282G, ids)
        self.assertNotIn(build.CASE_45Q4, ids)

    def test_8359_exact_mapping_and_alias_not_counted(self) -> None:
        row = self.new_counted[0]
        self.assertEqual(row["case_id"], build.CASE_8359)
        self.assertEqual(row["ordinal"], 85)
        self.assertEqual(row["candidate_set"], [build.CAND_8359])
        self.assertEqual(row["carrier_set"], [build.CAND_8359])
        self.assertEqual(row["minimum_fix_set"], [build.FIX_8359])
        self.assertEqual(row["candidate_parent"], build.PARENT_8359)
        self.assertEqual(row["aliases"], [build.ALIAS_8359])
        self.assertNotIn(build.ALIAS_8359, [item["case_id"] for item in self.counted])
        self.assertNotIn(build.FIX_954P, row["candidate_set"])
        self.assertNotIn(build.FIX_954P, row["minimum_fix_set"])
        self.assertEqual(row["sibling_954p_closer_not_counted"], build.FIX_954P)
        self.assertEqual(row["n_parents"], 1)
        self.assertTrue(row["candidate_on_release_first_parent"])
        self.assertTrue(row["carrier_on_release_first_parent"])
        self.assertFalse(row["authorship_transfer"])
        self.assertEqual(row["contribution_class"], "AI_INCOMPLETE_REMEDIATION")
        self.assertEqual(row["mechanism_key"], build.MECH_KEY_8359)
        self.assertEqual(row["mechanism_fingerprint"], build.MECH_FP_8359)
        self.assertEqual(row["admission_source"], "w3_p123_narrow_redteam_keep")
        self.assertEqual(row[build.REMEDIATION_GATE], "PASS")
        self.assertFalse(row["in_fp211_212"])
        self.assertEqual(row["action"], "APPEND")
        self.assertNotIn("candidate_fix_edges", row)
        self.assertTrue(row["cartesian_candidate_fix_refused"])

    def test_strict_inclusion_separate_from_global_hold(self) -> None:
        row = self.new_counted[0]
        cap = self.cap_8359
        self.assertTrue(row["leader_strict_case_accepted"])
        self.assertTrue(row["counted"])
        self.assertNotIn("causal_admission", row)
        self.assertIsNot(row.get("causal_admission"), True)
        self.assertTrue(cap["leader_strict_case_accepted"])
        self.assertFalse(cap["causal_admission"])
        self.assertFalse(cap["publication_ready"])
        self.assertFalse(self.summary["causal_admission"])
        self.assertFalse(self.summary["publication_admission"])
        self.assertFalse(self.summary["publication_ready"])
        self.assertFalse(self.summary["integration_ready"])
        self.assertEqual(self.summary["status"], "HOLD")
        self.assertFalse(self.summary["public_200_claim_supported"])
        self.assertFalse(self.manifest["integration_ready"])
        self.assertFalse(self.manifest["publication_ready"])
        self.assertFalse(self.manifest["causal_admission"])
        self.assertFalse(self.manifest["public_200_claim_supported"])
        self.assertEqual(self.manifest["status"], "HOLD")
        auth = self.manifest["packet_authority"]
        self.assertEqual(len(auth), 21)
        self.assertEqual(auth[-1]["packet"], build.P_PKT)
        self.assertEqual(auth[-1]["authority_rank"], 42)
        self.assertEqual(auth[-1]["role"], "redteam")
        self.assertEqual(
            self.manifest["conservation"]["new_append_identities"],
            [build.CASE_8359],
        )
        self.assertTrue(self.manifest["conservation"]["new_identities_append"])

    def test_all_gates_and_patch_delta(self) -> None:
        for row in self.counted:
            for field in build.GATES:
                self.assertEqual(row[field], "PASS")
                self.assertIsNotNone(row[field])
                self.assertNotEqual(row[field], "NA")
            self.assertTrue(build.seven_pass(row))
        for row in self.new_counted:
            self.assertEqual(row[build.REMEDIATION_GATE], "PASS")
            poisoned = deepcopy(row)
            poisoned["release_gate"] = None
            self.assertFalse(build.seven_pass(poisoned))
            poisoned["release_gate"] = "NA"
            self.assertFalse(build.seven_pass(poisoned))
            poisoned["release_gate"] = "PASS"
            self.assertTrue(build.seven_pass(poisoned))

    def test_release_containment_pinned_artifacts(self) -> None:
        vuln = self.new_counted[0]["vulnerable_release"]
        fix = self.new_counted[0]["fixed_release"]
        self.assertEqual(vuln["tag"], "0.61.0")
        self.assertEqual(fix["tag"], "0.62.0")
        self.assertEqual(vuln["peeled"], build.PEEL_061)
        self.assertEqual(fix["peeled"], build.PEEL_062)
        self.assertEqual(vuln["first_containing_candidate"], "0.56.0")
        self.assertEqual(vuln["first_containing_candidate_peeled"], build.PEEL_056)
        self.assertEqual(vuln["pre_attempt_tag"], "0.55.0")
        self.assertEqual(vuln["pre_attempt_peeled"], build.PEEL_055)
        self.assertTrue(vuln["contains_candidate"])
        self.assertFalse(vuln["contains_fix"])
        self.assertTrue(vuln["file_exemption_present"])
        self.assertTrue(vuln["contains_954p_closer"])
        self.assertTrue(fix["contains_fix"])
        self.assertFalse(fix["file_exemption_present"])
        self.assertTrue(fix["resolve_local_ref_path_present"])
        self.assertTrue(vuln["immutable"])
        self.assertTrue(fix["immutable"])

    def test_negative_controls_absent(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        for case_id in (
            build.CASE_PIMCORE,
            build.CASE_HHJV,
            build.CASE_73HC,
            build.CASE_282G,
            build.CASE_45Q4,
            build.CASE_954P,
        ):
            self.assertNotIn(case_id, ids)
            ctrl = self.neg[case_id]
            self.assertEqual(ctrl["verdict"], "REJECT")
            self.assertFalse(ctrl["countable"])
            self.assertTrue(ctrl["must_be_absent_from_all_counted_ids"])
        pim = self.neg[build.CASE_PIMCORE]
        self.assertEqual(pim["gates"]["ai_hunk_gate"], "FAIL")
        self.assertEqual(pim["object_shas"]["human_regex_member"], build.HUMAN_PIMCORE)
        hhjv = self.neg[build.CASE_HHJV]
        self.assertEqual(hhjv["fail_gates"], ["ai_hunk_gate", "topology_gate", "but_for_gate"])
        self.assertTrue(hhjv["authorship_transfer"])
        zit = self.neg[build.CASE_282G]
        self.assertEqual(zit["fail_gates"], ["ai_hunk_gate", "topology_gate", "but_for_gate"])
        self.assertEqual(zit["object_shas"]["hypothesized_squash_carrier"], build.CAND_282G)
        vik = self.neg[build.CASE_45Q4]
        self.assertEqual(vik["fail_gates"], ["ai_hunk_gate", "but_for_gate"])
        self.assertEqual(vik["gates"]["topology_gate"], "PASS")
        http = self.neg[build.CASE_954P]
        self.assertEqual(http["fail_gates"], ["but_for_gate", "remediation_patch_delta_gate"])
        self.assertEqual(http["object_shas"]["shared_candidate_not_merged"], build.CAND_8359)
        self.assertEqual(http["object_shas"]["minimum_fix"], build.FIX_954P)
        self.assertTrue(http["shared_candidate_does_not_merge_cases"])
        self.assertIn(build.CASE_282G, self.summary["excluded"])
        self.assertIn(build.CASE_45Q4, self.summary["excluded"])
        self.assertIn(build.CASE_954P, self.summary["excluded"])
        self.assertEqual(self.summary["counts"]["zitadel_282g_negative_control_rejected"], 1)
        self.assertEqual(self.summary["counts"]["vikunja_45q4_negative_control_rejected"], 1)
        self.assertEqual(self.summary["counts"]["datamodel_954p_negative_control_rejected"], 1)

    def test_no_duplicates_or_excluded_identities(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        self.assertEqual(len(ids), len(set(ids)))
        cve_aliases = [
            item for row in self.counted for item in row["aliases"] if item.startswith("CVE-")
        ]
        self.assertTrue(all(item not in ids for item in cve_aliases))
        self.assertIn(build.ALIAS_8359, cve_aliases)
        self.assertNotIn(build.CASE_8359, {row["case_id"] for row in self.pub})
        self.assertEqual(len(self.pub), 212)
        self.assertEqual(len(self.hyp), 211)

    def test_hold_boundaries(self) -> None:
        self.assertEqual(self.summary["canonical_strict_count"], 85)
        self.assertEqual(self.summary["counts"]["strict_released_first_party_ghsa"], 85)
        self.assertEqual(self.summary["counts"]["ledger_records"], 582)
        self.assertEqual(self.summary["checkpoint"]["prior_strict_count"], 84)
        self.assertEqual(self.summary["checkpoint"]["corrected_strict_count"], 85)
        report = (verify.HERE / "report.md").read_text()
        self.assertNotIn("more than 200", report.lower())
        self.assertIn("greater-than-200", report)
        self.assertIn("Integration_ready is false", report)
        self.assertIn("Publication_ready is false", report)
        self.assertIn("Causal admission is false", report)
        self.assertNotIn("causal_admission is true", report)
        self.assertIn("new_identities_append is true", report)
        self.assertIn("prior packet authorities do not admit them", report)
        self.assertNotIn("only prior", report.lower())

    def test_exact_scope_is_canonical84_plus_one(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        prior_ids = self.prior_summary["strict_released_case_ids"]
        self.assertEqual(ids[:84], prior_ids)
        self.assertEqual(ids[84:], [build.CASE_8359])
        self.assertEqual(len(self.new_counted), 1)
        sources = {row["admission_source"] for row in self.counted}
        self.assertIn("w3_p123_narrow_redteam_keep", sources)
        self.assertNotIn("worker_pass", sources)
        self.assertEqual(ids[82], build.CASE_425G)
        self.assertEqual(ids[83], build.CASE_HC8V)

    def test_no_shell_or_credential_leakage(self) -> None:
        artifacts = [
            (verify.HERE / "report.md").read_text(),
            (verify.HERE / "summary.json").read_text(),
            (verify.HERE / "manifest.json").read_text(),
            (verify.HERE / "8359_acceptance.json").read_text(),
            (verify.HERE / "negative_controls.json").read_text(),
        ]
        artifacts.extend(build.compact_json(row) for row in self.new_counted)
        for text in artifacts:
            build.assert_no_leak(text)
            self.assertIsNone(build.HAN.search(text))
            self.assertNotIn("/home/hanqing/.cache", text)
            self.assertNotIn("pages/ghsa/", text)
        script_text = (verify.HERE / "build.py").read_text() + (verify.HERE / "verify.py").read_text()
        self.assertNotIn("os" + ".environ", script_text)
        self.assertNotIn("environ" + ".copy", script_text)
        self.assertNotIn("print" + "env", script_text)
        self.assertTrue(all("clone_path" not in row for row in self.new_counted))
        self.assertTrue(all("clone" not in row for row in self.new_counted))

    def test_manifest_hash_matches_outputs(self) -> None:
        ledger_hash = build.sha256_file(verify.HERE / "ledger.jsonl")
        summary_hash = build.sha256_file(verify.HERE / "summary.json")
        report_hash = build.sha256_file(verify.HERE / "report.md")
        self.assertEqual(self.manifest["outputs"]["ledger.jsonl_sha256"], ledger_hash)
        self.assertEqual(self.manifest["outputs"]["summary.json_sha256"], summary_hash)
        self.assertEqual(self.manifest["outputs"]["report.md_sha256"], report_hash)
        self.assertEqual(self.summary["ledger_sha256"], ledger_hash)


if __name__ == "__main__":
    unittest.main()
