#!/usr/bin/env python3
"""Regression checks for the canonical84 HOLD snapshot."""

import unittest
from copy import deepcopy

import build
import verify


class Canonical84Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary, cls.counted = verify.verify()
        cls.rows = verify.load_rows()
        cls.hyp = verify.by_kind(cls.rows, "PRESERVED_HYPOTHESIS")
        cls.pub = verify.by_kind(cls.rows, "PRESERVED_PUBLIC_CASE")
        cls.prior_rows = build.load_jsonl(build.ROOT / build.P_C82_LEDGER)
        cls.prior_summary = build.load_json(build.ROOT / build.P_C82_SUM)
        cls.prior_counted = [
            row for row in cls.prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"
        ]
        cls.new_counted = cls.counted[build.PRIOR_STRICT :]
        cls.cap_425g = build.load_capsule_425g()
        cls.cap_hc8v = build.load_capsule_hc8v()
        cls.neg = {row["case_id"]: row for row in build.load_negative()["controls"]}
        cls.manifest = build.load_json(verify.HERE / "manifest.json")

    def test_base_byte_conservation(self) -> None:
        self.assertEqual(len(self.prior_rows), 579)
        self.assertEqual(len(self.rows), 581)
        self.assertEqual(self.rows[:579], self.prior_rows)
        self.assertEqual(
            [build.compact_json(row) for row in self.rows[:579]],
            [build.compact_json(row) for row in self.prior_rows],
        )
        prior_text = (build.ROOT / build.P_C82_LEDGER).read_text()
        current_text = (verify.HERE / "ledger.jsonl").read_text()
        self.assertTrue(current_text.startswith(prior_text if prior_text.endswith("\n") else prior_text + "\n"))
        self.assertEqual(len(self.prior_counted), 82)
        self.assertEqual(self.counted[:82], self.prior_counted)
        self.assertEqual(len(self.hyp), 211)
        self.assertEqual(len(self.pub), 212)
        self.assertEqual(len(self.counted), 84)
        self.assertTrue(all(row["counted"] is False for row in self.hyp))
        self.assertTrue(all(row["counted"] is False for row in self.pub))
        self.assertTrue(all(row["counted"] is True for row in self.counted))
        self.assertEqual(
            self.summary["strict_released_case_ids"][:82],
            self.prior_summary["strict_released_case_ids"],
        )
        self.assertTrue(self.summary["conservation"]["base_counted_rows_byte_identical"])
        self.assertTrue(self.summary["conservation"]["base_ledger_rows_byte_identical"])
        self.assertEqual(self.summary["conservation"]["fp211_hypotheses"], 211)
        self.assertEqual(self.summary["conservation"]["fp211_source_ghsa_cases"], 212)
        self.assertFalse(self.summary["conservation"]["cve_aliases_counted"])
        prior_append = self.prior_summary["conservation"]["append_identities"]
        self.assertEqual(len(prior_append), 12)
        self.assertEqual(self.summary["conservation"]["prior_append_identities"], prior_append)
        self.assertEqual(
            self.summary["conservation"]["new_append_identities"],
            [build.CASE_425G, build.CASE_HC8V],
        )
        self.assertEqual(
            self.summary["conservation"]["append_identities"],
            prior_append + [build.CASE_425G, build.CASE_HC8V],
        )
        self.assertEqual(len(self.summary["conservation"]["append_identities"]), 14)
        self.assertTrue(self.summary["conservation"]["new_identities_append"])
        self.assertFalse(self.summary["conservation"]["same_id_source_layer_promoted"])
        self.assertFalse(self.summary["conservation"]["upgrades_append"])
        self.assertEqual(self.summary["conservation"]["appended_strict_rows"], 2)
        self.assertEqual(self.summary["counts"]["by_record_kind"]["APPEND_IDENTITY"], 12)
        self.assertEqual(self.summary["counts"]["by_record_kind"]["PACKET_AUTHORITY"], 18)

    def test_eighty_four_unique_ids_and_fingerprints(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        fps = [row["mechanism_fingerprint"] for row in self.counted]
        mechs = [row["mechanism_key"] for row in self.counted]
        self.assertEqual(len(ids), 84)
        self.assertEqual(len(set(ids)), 84)
        self.assertEqual(len(fps), 84)
        self.assertEqual(len(set(fps)), 84)
        self.assertEqual(len(mechs), 84)
        self.assertEqual(len(set(mechs)), 84)
        self.assertEqual(ids[82:], [build.CASE_425G, build.CASE_HC8V])
        self.assertEqual([row["ordinal"] for row in self.new_counted], [83, 84])
        prior_ids = set(self.prior_summary["strict_released_case_ids"])
        self.assertEqual(set(ids) - prior_ids, {build.CASE_425G, build.CASE_HC8V})
        self.assertTrue(prior_ids <= set(ids))
        self.assertEqual(ids.count(build.CASE_425G), 1)
        self.assertEqual(ids.count(build.CASE_HC8V), 1)
        self.assertNotIn(build.ALIAS_HC8V, ids)
        self.assertNotIn(build.LINEAGE_425G, ids)

    def test_425g_exact_mapping_and_lineage_duplicate_rejected(self) -> None:
        row = self.new_counted[0]
        self.assertEqual(row["case_id"], build.CASE_425G)
        self.assertEqual(row["ordinal"], 83)
        self.assertEqual(row["candidate_set"], [build.CAND_425G])
        self.assertEqual(row["carrier_set"], [build.CARRIER_425G])
        self.assertEqual(row["minimum_fix_set"], [build.FIX_425G])
        self.assertEqual(row["candidate_parent"], build.PARENT_425G)
        self.assertNotIn(build.LINEAGE_425G, row["candidate_set"])
        self.assertNotIn(build.LINEAGE_425G, row["carrier_set"])
        self.assertEqual(row["lineage_evidence_not_counted"], [build.LINEAGE_425G])
        self.assertEqual(row["contribution_class"], "AI_INCOMPLETE_REMEDIATION")
        self.assertEqual(row["mechanism_key"], build.MECH_KEY_425G)
        self.assertEqual(row["mechanism_fingerprint"], build.MECH_FP_425G)
        self.assertEqual(row["aliases"], [])
        self.assertEqual(row["admission_source"], "425g_redteam_keep")
        self.assertFalse(row["in_fp211_212"])
        self.assertEqual(row["action"], "APPEND")
        self.assertNotIn("candidate_fix_edges", row)
        self.assertTrue(row["cartesian_candidate_fix_refused"])
        self.assertEqual(row[build.REMEDIATION_GATE], "PASS")

    def test_hc8v_exact_mapping_and_alias_not_counted(self) -> None:
        row = self.new_counted[1]
        self.assertEqual(row["case_id"], build.CASE_HC8V)
        self.assertEqual(row["ordinal"], 84)
        self.assertEqual(row["candidate_set"], [build.CAND_HC8V])
        self.assertEqual(row["carrier_set"], [build.CARRIER_HC8V])
        self.assertEqual(row["minimum_fix_set"], [build.FIX_HC8V])
        self.assertEqual(row["candidate_parent"], build.PARENT_HC8V)
        self.assertEqual(row["aliases"], [build.ALIAS_HC8V])
        self.assertNotIn(build.ALIAS_HC8V, [item["case_id"] for item in self.counted])
        self.assertTrue(row["candidate_any_parent"])
        self.assertFalse(row["candidate_on_release_first_parent"])
        self.assertTrue(row["carrier_on_release_first_parent"])
        self.assertFalse(row["authorship_transfer"])
        self.assertNotIn(build.ORIG_2081, row["candidate_set"])
        self.assertNotIn(build.V6_CLOSER, row["minimum_fix_set"])
        self.assertEqual(row["contribution_class"], "AI_INCOMPLETE_REMEDIATION")
        self.assertEqual(row["mechanism_key"], build.MECH_KEY_HC8V)
        self.assertEqual(row["mechanism_fingerprint"], build.MECH_FP_HC8V)
        self.assertEqual(row["admission_source"], "hc8v_redteam_keep")
        self.assertEqual(row[build.REMEDIATION_GATE], "PASS")
        self.assertTrue(row["v5_and_v6_are_one_ghsa_case"])
        self.assertFalse(row["in_fp211_212"])
        self.assertEqual(row["action"], "APPEND")

    def test_strict_inclusion_separate_from_global_hold(self) -> None:
        for row, cap in (
            (self.new_counted[0], self.cap_425g),
            (self.new_counted[1], self.cap_hc8v),
        ):
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
        self.assertEqual(len(auth), 20)
        self.assertEqual(auth[-2]["packet"], build.P_425G_PKT)
        self.assertEqual(auth[-1]["packet"], build.P_HC8V_PKT)
        self.assertEqual(auth[-2]["authority_rank"], 40)
        self.assertEqual(auth[-1]["authority_rank"], 41)
        self.assertEqual(auth[-2]["role"], "redteam")
        self.assertEqual(auth[-1]["role"], "redteam")
        self.assertEqual(
            self.manifest["conservation"]["new_append_identities"],
            [build.CASE_425G, build.CASE_HC8V],
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
        vuln83 = self.new_counted[0]["vulnerable_release"]
        fix83 = self.new_counted[0]["fixed_release"]
        self.assertEqual(vuln83["version"], "1.3.5")
        self.assertEqual(fix83["version"], "1.4.0")
        self.assertEqual(vuln83["kind"], "pypi_wheel_and_sdist")
        self.assertEqual(vuln83["sha256_sdist"], build.PYPI_VULN_SDIST)
        self.assertEqual(vuln83["sha256_wheel"], build.PYPI_VULN_WHEEL)
        self.assertEqual(fix83["sha256_sdist"], build.PYPI_FIX_SDIST)
        self.assertEqual(fix83["sha256_wheel"], build.PYPI_FIX_WHEEL)
        self.assertTrue(vuln83["contains_ai_fail_open"])
        self.assertFalse(vuln83["jsonschema_required"])
        self.assertTrue(fix83["contains_fix"])
        self.assertTrue(fix83["jsonschema_required"])
        self.assertFalse(vuln83["yanked"])
        self.assertFalse(fix83["yanked"])
        vuln84 = self.new_counted[1]["vulnerable_release"]
        fix84 = self.new_counted[1]["fixed_release"]
        self.assertEqual(vuln84["tag"], "v5.19.1")
        self.assertEqual(fix84["tag"], "v5.19.2")
        self.assertEqual(vuln84["peeled"], build.VULN_HC8V)
        self.assertEqual(fix84["peeled"], build.FIX_PEEL_HC8V)
        self.assertEqual(vuln84["tarball_sha256"], build.TARBALL_V5191)
        self.assertEqual(fix84["tarball_sha256"], build.TARBALL_V5192)
        self.assertTrue(vuln84["contains_candidate"])
        self.assertFalse(vuln84["contains_fix"])
        self.assertTrue(fix84["contains_fix"])
        self.assertTrue(fix84["worktree_fs_equals_fix_blob"])
        self.assertTrue(vuln84["immutable"])
        self.assertTrue(fix84["immutable"])

    def test_negative_controls_absent(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        for case_id in (build.CASE_PIMCORE, build.CASE_HHJV, build.CASE_73HC):
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
        self.assertEqual(hhjv["object_shas"]["human_device_shell_member"], build.HUMAN_HHJV)
        self.assertEqual(hhjv["object_shas"]["hypothesized_squash_carrier"], build.SQUASH_HHJV)
        hc73 = self.neg[build.CASE_73HC]
        self.assertEqual(
            hc73["fail_gates"],
            ["ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate"],
        )
        self.assertEqual(hc73["reject_class"], "SIBLING_ROUTE_PARENT_HAD_EQUIVALENT_ENTRYPOINT")
        self.assertEqual(hc73["object_shas"]["claimed_ai_sibling"], build.CLAIMED_73HC)
        self.assertEqual(hc73["object_shas"]["unmarked_health_origin"], build.ORIGIN_73HC)
        self.assertIn(build.CASE_PIMCORE, self.summary["excluded"])
        self.assertIn(build.CASE_HHJV, self.summary["excluded"])
        self.assertIn(build.CASE_73HC, self.summary["excluded"])
        self.assertEqual(self.summary["counts"]["pimcore_2mhj_negative_control_rejected"], 1)
        self.assertEqual(self.summary["counts"]["hhjv_negative_control_rejected"], 1)
        self.assertEqual(self.summary["counts"]["route73hc_negative_control_rejected"], 1)

    def test_no_duplicates_or_excluded_identities(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        self.assertEqual(len(ids), len(set(ids)))
        cve_aliases = [
            item for row in self.counted for item in row["aliases"] if item.startswith("CVE-")
        ]
        self.assertTrue(all(item not in ids for item in cve_aliases))
        self.assertIn(build.ALIAS_HC8V, cve_aliases)
        self.assertNotIn(build.CASE_425G, {row["case_id"] for row in self.pub})
        self.assertNotIn(build.CASE_HC8V, {row["case_id"] for row in self.pub})

    def test_hold_boundaries(self) -> None:
        self.assertEqual(self.summary["canonical_strict_count"], 84)
        self.assertEqual(self.summary["counts"]["strict_released_first_party_ghsa"], 84)
        self.assertEqual(self.summary["counts"]["ledger_records"], 581)
        self.assertEqual(self.summary["checkpoint"]["prior_strict_count"], 82)
        self.assertEqual(self.summary["checkpoint"]["corrected_strict_count"], 84)
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

    def test_exact_scope_is_canonical82_plus_two(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        prior_ids = self.prior_summary["strict_released_case_ids"]
        self.assertEqual(ids[:82], prior_ids)
        self.assertEqual(ids[82:], [build.CASE_425G, build.CASE_HC8V])
        self.assertEqual(len(self.new_counted), 2)
        sources = {row["admission_source"] for row in self.counted}
        self.assertIn("425g_redteam_keep", sources)
        self.assertIn("hc8v_redteam_keep", sources)
        self.assertNotIn("worker_pass", sources)

    def test_no_shell_or_credential_leakage(self) -> None:
        artifacts = [
            (verify.HERE / "report.md").read_text(),
            (verify.HERE / "summary.json").read_text(),
            (verify.HERE / "manifest.json").read_text(),
            (verify.HERE / "425g_acceptance.json").read_text(),
            (verify.HERE / "hc8v_acceptance.json").read_text(),
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
