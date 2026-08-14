#!/usr/bin/env python3
"""Regression checks for the canonical82 HOLD snapshot."""

import unittest
from copy import deepcopy

import build
import verify


class Canonical82Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary, cls.counted = verify.verify()
        cls.rows = verify.load_rows()
        cls.hyp = verify.by_kind(cls.rows, "PRESERVED_HYPOTHESIS")
        cls.pub = verify.by_kind(cls.rows, "PRESERVED_PUBLIC_CASE")
        cls.prior_rows = build.load_jsonl(build.ROOT / build.P_C81_LEDGER)
        cls.prior_summary = build.load_json(build.ROOT / build.P_C81_SUM)
        cls.prior_counted = [
            row for row in cls.prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"
        ]
        cls.new_counted = cls.counted[build.PRIOR_STRICT :]
        cls.cap = build.load_capsule()
        cls.neg = build.load_negative()["controls"][0]
        cls.manifest = build.load_json(verify.HERE / "manifest.json")

    def test_base_byte_conservation(self) -> None:
        self.assertEqual(len(self.prior_counted), 81)
        self.assertEqual(self.counted[:81], self.prior_counted)
        self.assertEqual(
            [build.compact_json(row) for row in self.counted[:81]],
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
        self.assertEqual(len(self.counted), 82)
        self.assertTrue(all(row["counted"] is False for row in self.hyp))
        self.assertTrue(all(row["counted"] is False for row in self.pub))
        self.assertTrue(all(row["counted"] is True for row in self.counted))
        self.assertEqual(
            self.summary["strict_released_case_ids"][:81],
            self.prior_summary["strict_released_case_ids"],
        )
        self.assertTrue(self.summary["conservation"]["base_counted_rows_byte_identical"])
        self.assertEqual(self.summary["conservation"]["fp211_hypotheses"], 211)
        self.assertEqual(self.summary["conservation"]["fp211_source_ghsa_cases"], 212)
        self.assertFalse(self.summary["conservation"]["new_identities_append"])
        self.assertTrue(self.summary["conservation"]["same_id_source_layer_promoted"])

    def test_eighty_two_unique_ids_and_fingerprints(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        fps = [row["mechanism_fingerprint"] for row in self.counted]
        mechs = [row["mechanism_key"] for row in self.counted]
        self.assertEqual(len(ids), 82)
        self.assertEqual(len(set(ids)), 82)
        self.assertEqual(len(fps), 82)
        self.assertEqual(len(set(fps)), 82)
        self.assertEqual(len(mechs), 82)
        self.assertEqual(len(set(mechs)), 82)
        self.assertEqual(ids[81:], [build.CASE_QF5V])
        self.assertEqual([row["ordinal"] for row in self.new_counted], [82])
        prior_ids = set(self.prior_summary["strict_released_case_ids"])
        self.assertEqual(set(ids) - prior_ids, {build.CASE_QF5V})
        self.assertTrue(prior_ids <= set(ids))
        self.assertEqual(ids.count(build.CASE_QF5V), 1)
        self.assertNotIn(build.CASE_M63V, ids)
        self.assertNotEqual(build.MECH_FP, self.counted[0]["mechanism_fingerprint"])

    def test_qf5v_exact_mapping_and_member_rejected(self) -> None:
        row = self.new_counted[0]
        self.assertEqual(row["case_id"], build.CASE_QF5V)
        self.assertEqual(row["ordinal"], 82)
        self.assertEqual(row["candidate_set"], [build.CAND_QF5V])
        self.assertEqual(row["minimum_fix_set"], [build.FIX_QF5V])
        self.assertEqual(row["carrier_set"], [])
        self.assertEqual(row["candidate_parent"], build.PARENT_QF5V)
        self.assertEqual(row["hypothesized_unreleased_member"], build.MEMBER_QF5V)
        self.assertNotIn(build.MEMBER_QF5V, row["candidate_set"])
        self.assertNotIn(build.MEMBER_QF5V, row["carrier_set"])
        self.assertTrue(row["member_binding_rejected"])
        self.assertEqual(row["contribution_class"], "AI_INCOMPLETE_REMEDIATION")
        self.assertEqual(row["mechanism_key"], build.MECH_KEY)
        self.assertEqual(row["mechanism_fingerprint"], build.MECH_FP)
        self.assertEqual(row["aliases"], [build.ALIAS_QF5V])
        self.assertNotIn(build.ALIAS_QF5V, [item["case_id"] for item in self.counted])
        self.assertEqual(row["admission_source"], "qf5v_redteam_keep")
        self.assertTrue(row["in_fp211_212"])
        self.assertNotIn("candidate_fix_edges", row)
        self.assertTrue(row["cartesian_candidate_fix_refused"])
        self.assertEqual(
            (row["case_id"], row["candidate_set"][0], row["minimum_fix_set"][0]),
            (build.CASE_QF5V, build.CAND_QF5V, build.FIX_QF5V),
        )

    def test_strict_inclusion_separate_from_global_hold(self) -> None:
        row = self.new_counted[0]
        self.assertTrue(row["leader_strict_case_accepted"])
        self.assertTrue(row["counted"])
        self.assertNotIn("causal_admission", row)
        self.assertIsNot(row.get("causal_admission"), True)
        self.assertTrue(self.cap["leader_strict_case_accepted"])
        self.assertTrue(self.cap["countable_in_this_snapshot"])
        self.assertFalse(self.cap["causal_admission"])
        self.assertFalse(self.cap["publication_admission"])
        self.assertFalse(self.cap["publication_ready"])
        self.assertEqual(self.cap["verdict"], "KEEP")
        self.assertFalse(self.summary["causal_admission"])
        self.assertFalse(self.summary["publication_admission"])
        self.assertFalse(self.summary["publication_ready"])
        self.assertFalse(self.summary["integration_ready"])
        self.assertEqual(self.summary["status"], "HOLD")
        self.assertFalse(self.prior_summary["causal_admission"])
        self.assertNotEqual(self.cap["leader_strict_case_accepted"], self.cap["causal_admission"])
        self.assertNotEqual(row["leader_strict_case_accepted"], self.summary["causal_admission"])

    def test_all_gates_and_patch_delta(self) -> None:
        for row in self.counted:
            for field in build.GATES:
                self.assertEqual(row[field], "PASS")
                self.assertIsNotNone(row[field])
                self.assertNotEqual(row[field], "NA")
            self.assertTrue(build.seven_pass(row))
        self.assertEqual(self.new_counted[0][build.REMEDIATION_GATE], "PASS")
        poisoned = deepcopy(self.new_counted[0])
        poisoned["release_gate"] = None
        self.assertFalse(build.seven_pass(poisoned))
        poisoned["release_gate"] = "NA"
        self.assertFalse(build.seven_pass(poisoned))
        poisoned["release_gate"] = "PASS"
        self.assertTrue(build.seven_pass(poisoned))

    def test_candidate_mapping_refuses_cartesian_edges(self) -> None:
        row = self.new_counted[0]
        self.assertEqual(len(row["candidate_set"]), 1)
        self.assertEqual(len(row["minimum_fix_set"]), 1)
        self.assertNotIn("candidate_fix_edges", row)
        self.assertTrue(row["cartesian_candidate_fix_refused"])
        for item in self.counted:
            self.assertNotIn("candidate_fix_edges", item)
            self.assertEqual(item["edge_authority"], "candidate_set/carrier_set/minimum_fix_set")

    def test_release_containment_pinned_artifacts(self) -> None:
        row = self.new_counted[0]
        vuln = row["vulnerable_release"]
        fixed = row["fixed_release"]
        self.assertEqual(vuln["name"], "github.com/fission/fission")
        self.assertEqual(fixed["name"], "github.com/fission/fission")
        self.assertEqual(vuln["tag"], "v1.24.0")
        self.assertEqual(fixed["tag"], "v1.25.0")
        self.assertEqual(vuln["sha"], build.VULN_PEEL)
        self.assertEqual(vuln["peeled"], build.VULN_PEEL)
        self.assertEqual(vuln["go_proxy_origin_hash"], build.VULN_PEEL)
        self.assertEqual(fixed["sha"], build.FIX_PEEL)
        self.assertEqual(fixed["peeled"], build.FIX_PEEL)
        self.assertTrue(vuln["contains_candidate"])
        self.assertFalse(vuln["contains_fix"])
        self.assertFalse(vuln["contains_member"])
        self.assertTrue(fixed["contains_fix"])
        self.assertFalse(fixed["equals_minimum_fix"])
        self.assertTrue(vuln["github_release_prerelease"])
        self.assertTrue(vuln["github_prerelease_flag_is_not_sole_release_proof"])
        self.assertEqual(vuln["podspec_safety_blob"], build.BLOB_V124)
        self.assertEqual(fixed["podspec_safety_blob"], build.BLOB_FIX)
        self.assertEqual(vuln["six_cap_map_sha256"], build.MAP_SHA)
        self.assertTrue(fixed["fix_parent_podspec_blob_equals_v1_24_0"])
        self.assertEqual(row["repository"], "fission/fission")
        refs = row["first_party_source_refs"]
        self.assertEqual(refs[0], "https://github.com/advisories/GHSA-qf5v-m7p4-95rp")
        self.assertIn(build.P_CAPSULE, refs)
        self.assertFalse(any("pages/ghsa/" in item for item in refs))
        self.assertTrue(self.cap["vulnerable_release"]["commit_only_substitution_refused"])
        self.assertTrue(self.cap["fixed_release"]["commit_only_substitution_refused"])

    def test_qf5v_absent_from_base_counted_present_in_source(self) -> None:
        prior_ids = [row["case_id"] for row in self.prior_counted]
        self.assertNotIn(build.CASE_QF5V, prior_ids)
        source_ids = {row["case_id"] for row in self.pub}
        self.assertIn(build.CASE_QF5V, source_ids)
        pub = [row for row in self.pub if row["case_id"] == build.CASE_QF5V]
        self.assertEqual(len(pub), 1)
        self.assertEqual(pub[0]["ordinal"], 130)
        self.assertEqual(pub[0]["row_key"], "post:fission-capabilities@canonical")
        self.assertFalse(pub[0]["counted"])
        appends = [row for row in self.rows if row["record_kind"] == "APPEND_IDENTITY"]
        self.assertEqual(len(appends), 12)
        self.assertFalse(any(row["case_id"] == build.CASE_QF5V for row in appends))

    def test_pimcore_negative_control_absent(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        self.assertNotIn(build.CASE_PIMCORE, ids)
        self.assertNotIn(build.CASE_PIMCORE, {row["case_id"] for row in self.pub})
        self.assertEqual(self.neg["case_id"], build.CASE_PIMCORE)
        self.assertEqual(self.neg["verdict"], "REJECT")
        self.assertFalse(self.neg["countable"])
        self.assertTrue(self.neg["must_be_absent_from_all_counted_ids"])
        self.assertEqual(self.neg["gates"]["identity_gate"], "PASS")
        self.assertEqual(self.neg["gates"]["fix_reversal_gate"], "PASS")
        self.assertEqual(self.neg["gates"]["release_gate"], "PASS")
        self.assertEqual(self.neg["gates"]["uniqueness_gate"], "PASS")
        self.assertEqual(self.neg["gates"]["ai_hunk_gate"], "FAIL")
        self.assertEqual(self.neg["gates"]["topology_gate"], "FAIL")
        self.assertEqual(self.neg["gates"]["but_for_gate"], "FAIL")
        self.assertEqual(self.neg["gates"][build.REMEDIATION_GATE], "FAIL")
        self.assertTrue(self.neg["authorship_transfer"])
        self.assertEqual(self.neg["object_shas"]["human_regex_member"], build.HUMAN_PIMCORE)
        self.assertEqual(self.neg["object_shas"]["hypothesized_squash_carrier"], build.SQUASH_PIMCORE)
        self.assertNotEqual(build.SQUASH_PIMCORE, build.HUMAN_PIMCORE)
        self.assertTrue(self.neg["copilot_members_do_not_touch_classdefinition"])
        self.assertEqual(
            self.neg["rule"],
            "An AI-marked squash carrier cannot transfer authorship to a human member.",
        )
        self.assertIn(build.CASE_PIMCORE, self.summary["excluded"])
        self.assertEqual(self.summary["counts"]["pimcore_2mhj_negative_control_rejected"], 1)

    def test_no_duplicates_or_excluded_identities(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertNotIn("GHSA-7C3W-FXGH-FRC7", ids)
        self.assertNotIn("GHSA-F38V-77QJ-H4JQ", ids)
        self.assertNotIn("GHSA-4FXP-2M36-QV64", ids)
        self.assertNotIn("GHSA-XW57-23P8-9WC5", ids)
        self.assertNotIn("GHSA-QCR8-X557-7CP3", ids)
        self.assertNotIn(build.EXCLUDE_GOPACKET, ids)
        self.assertNotIn(build.CASE_M63V, ids)
        self.assertNotIn(build.CASE_PIMCORE, ids)
        self.assertNotIn(build.ALIAS_QF5V, ids)
        cve_aliases = [
            item for row in self.counted for item in row["aliases"] if item.startswith("CVE-")
        ]
        self.assertTrue(all(item not in ids for item in cve_aliases))
        self.assertIn(build.ALIAS_QF5V, cve_aliases)

    def test_hold_boundaries_inherit_canonical81(self) -> None:
        self.assertEqual(self.summary["canonical_strict_count"], 82)
        self.assertEqual(self.summary["counts"]["strict_released_first_party_ghsa"], 82)
        self.assertEqual(self.summary["counts"]["qf5v_keep"], 1)
        self.assertEqual(self.summary["checkpoint"]["prior_strict_count"], 81)
        self.assertEqual(self.summary["checkpoint"]["corrected_strict_count"], 82)
        self.assertEqual(self.summary["checkpoint"]["appended_qf5v_one"], [build.CASE_QF5V])
        self.assertFalse(self.summary["integration_ready"])
        self.assertFalse(self.summary["publication_ready"])
        self.assertFalse(self.summary["causal_admission"])
        self.assertFalse(self.summary["public_200_claim_supported"])
        self.assertEqual(self.summary["status"], "HOLD")
        self.assertFalse(self.manifest["integration_ready"])
        self.assertFalse(self.manifest["publication_ready"])
        self.assertFalse(self.manifest["causal_admission"])
        self.assertFalse(self.manifest["public_200_claim_supported"])
        self.assertEqual(self.manifest["status"], "HOLD")
        self.assertEqual(self.manifest["canonical_strict_count"], 82)
        report = (verify.HERE / "report.md").read_text()
        self.assertNotIn("more than 200", report.lower())
        self.assertIn("greater-than-200", report)
        self.assertIn("Integration_ready is false", report)
        self.assertIn("Publication_ready is false", report)
        self.assertIn("Causal admission is false", report)
        self.assertIn("leader_strict_case_accepted is true", report)
        self.assertNotIn("causal_admission is true", report)

    def test_exact_scope_is_canonical81_plus_qf5v(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        prior_ids = self.prior_summary["strict_released_case_ids"]
        self.assertEqual(ids[:81], prior_ids)
        self.assertEqual(ids[81:], [build.CASE_QF5V])
        self.assertEqual(set(ids), set(prior_ids) | {build.CASE_QF5V})
        self.assertEqual(len(self.new_counted), 1)
        self.assertEqual(self.summary["counts"]["strict_released_first_party_ghsa"], 81 + 1)
        sources = {row["admission_source"] for row in self.counted}
        self.assertIn("qf5v_redteam_keep", sources)
        self.assertNotIn("worker_pass", sources)
        self.assertEqual(self.new_counted[0]["admission_source"], "qf5v_redteam_keep")

    def test_no_shell_or_credential_leakage(self) -> None:
        artifacts = [
            (verify.HERE / "report.md").read_text(),
            (verify.HERE / "summary.json").read_text(),
            (verify.HERE / "manifest.json").read_text(),
            (verify.HERE / "qf5v_acceptance.json").read_text(),
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


if __name__ == "__main__":
    unittest.main()
