#!/usr/bin/env python3
"""Regression checks for the canonical94 HOLD snapshot."""

import unittest
from copy import deepcopy
from pathlib import Path

import build
import verify


class Canonical94Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary, cls.counted = verify.verify()
        cls.rows = verify.load_rows()
        cls.hyp = verify.by_kind(cls.rows, "PRESERVED_HYPOTHESIS")
        cls.pub = verify.by_kind(cls.rows, "PRESERVED_PUBLIC_CASE")
        cls.appends = verify.by_kind(cls.rows, "APPEND_IDENTITY")
        cls.supers = verify.by_kind(cls.rows, "SUPERSEDES_EDGE")
        cls.prior_rows = build.load_jsonl(build.ROOT / build.P_C93_LEDGER)
        cls.prior_summary = build.load_json(build.ROOT / build.P_C93_SUM)
        cls.prior_counted = [
            row for row in cls.prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"
        ]
        cls.new_counted = cls.counted[build.PRIOR_STRICT :]
        cls.cap = build.load_capsule()
        cls.neg = {row["case_id"]: row for row in build.load_negative()["controls"]}
        cls.manifest = build.load_json(verify.HERE / "manifest.json")

    def test_base_prefix_byte_identity_and_hash(self) -> None:
        self.assertEqual(len(self.prior_rows), 595)
        self.assertEqual(len(self.rows), 597)
        self.assertEqual(self.rows[:595], self.prior_rows)
        prior_text = (build.ROOT / build.P_C93_LEDGER).read_text()
        current_text = (verify.HERE / "ledger.jsonl").read_text()
        self.assertTrue(
            current_text.startswith(prior_text if prior_text.endswith("\n") else prior_text + "\n")
        )
        self.assertEqual(
            build.sha256_file(build.ROOT / build.P_C93_LEDGER),
            "6d652a089329eb23108083fb73ca1a8a3aa00583415b235381f3b37da389dc3d",
        )
        self.assertEqual(len(self.prior_counted), 93)
        self.assertEqual(self.counted[:93], self.prior_counted)
        self.assertEqual(len(self.hyp), 211)
        self.assertEqual(len(self.pub), 212)
        self.assertEqual(len(self.counted), 94)
        self.assertEqual(len(self.appends), 15)
        self.assertEqual(len(self.supers), 47)
        self.assertTrue(self.summary["conservation"]["base_counted_rows_byte_identical"])
        self.assertTrue(self.summary["conservation"]["base_ledger_rows_byte_identical"])
        prior_append = self.prior_summary["conservation"]["append_identities"]
        self.assertEqual(len(prior_append), 20)
        self.assertEqual(self.summary["conservation"]["prior_append_identities"], prior_append)
        self.assertEqual(
            self.summary["conservation"]["new_append_identities"],
            [build.CASE_76PC],
        )
        self.assertEqual(
            self.summary["conservation"]["append_identities"],
            prior_append + [build.CASE_76PC],
        )
        self.assertEqual(len(self.summary["conservation"]["append_identities"]), 21)
        self.assertTrue(self.summary["conservation"]["new_identities_append"])
        self.assertFalse(self.summary["conservation"]["same_id_source_layer_promoted"])
        self.assertEqual(self.summary["conservation"]["appended_strict_rows"], 1)
        tail = current_text.splitlines()[595:]
        self.assertEqual(len(tail), 2)
        kinds = [__import__("json").loads(line)["record_kind"] for line in tail]
        self.assertEqual(kinds, ["APPEND_IDENTITY", "STRICT_RELEASED_CASE"])

    def test_ninety_four_unique_ids_one_appended(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        fps = [row["mechanism_fingerprint"] for row in self.counted]
        mechs = [row["mechanism_key"] for row in self.counted]
        self.assertEqual(len(ids), 94)
        self.assertEqual(len(set(ids)), 94)
        self.assertEqual(len(set(fps)), 94)
        self.assertEqual(len(set(mechs)), 94)
        self.assertEqual(ids[93:], [build.CASE_76PC])
        self.assertEqual([row["ordinal"] for row in self.new_counted], [94])
        prior_ids = set(self.prior_summary["strict_released_case_ids"])
        self.assertEqual(set(ids) - prior_ids, {build.CASE_76PC})
        self.assertTrue(prior_ids <= set(ids))
        self.assertEqual(len(self.new_counted), 1)
        self.assertNotIn(build.CASE_76PC, prior_ids)
        self.assertNotIn(build.CASE_49MQ, ids)
        self.assertNotIn(build.CASE_G353, ids)
        self.assertNotIn(build.CASE_Q447, ids)
        self.assertNotIn(build.CASE_2Q7J, ids)
        self.assertNotIn(build.CASE_6C8G, ids)
        self.assertIn(build.CASE_MFMP, ids)
        self.assertIn(build.CASE_M649, ids)
        self.assertIn(build.CASE_5WP8, ids)

    def test_public_id_alias_stored_never_counted(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        row94 = self.new_counted[0]
        self.assertEqual(row94["aliases"], [build.ALIAS_76PC])
        self.assertTrue(all(item.startswith("GHSA-") for item in ids))
        self.assertEqual(ids.count(build.CASE_76PC), 1)
        self.assertNotIn(build.ALIAS_76PC, ids)
        self.assertFalse(self.summary["conservation"]["cve_aliases_counted"])

    def test_direct_root_empty_carrier_no_merge_transfer(self) -> None:
        row94 = self.new_counted[0]
        self.assertEqual(row94["contribution_class"], "AI_DIRECT_ROOT")
        self.assertTrue(row94["whole_ghsa_direct_root"])
        self.assertEqual(row94["candidate_set"], [build.CAND])
        self.assertEqual(row94["carrier_set"], [])
        self.assertTrue(row94["empty_carrier"])
        self.assertNotIn(build.MERGE, row94["candidate_set"])
        self.assertNotIn(build.MERGE, row94["carrier_set"])
        self.assertTrue(row94["merge_90e3a4b8_not_transferred"])
        self.assertIn("session-log-${sessionId}.jsonl", row94["scope_statement"])
        self.assertIn("carrier_set is empty", row94["scope_statement"])
        self.assertIn("90e3a4b8", row94["scope_statement"])
        self.assertIn("49MQ", row94["scope_statement"])
        self.assertTrue(self.summary["uniqueness"]["empty_carrier"])
        self.assertTrue(self.summary["uniqueness"]["merge_90e3a4b8_not_transferred"])
        self.assertTrue(self.summary["uniqueness"]["49mq_not_promoted"])
        self.assertIn(build.CASE_49MQ, self.summary["excluded"])
        self.assertIn("merge_90e3a4b8_not_transferred", self.summary["excluded"])

    def test_all_gates_exact_pass(self) -> None:
        for row in self.counted:
            for field in build.GATES:
                self.assertEqual(row[field], "PASS")
                self.assertIsNotNone(row[field])
                self.assertNotEqual(row[field], "NA")
            self.assertTrue(build.seven_pass(row))
        for row in self.new_counted:
            poisoned = deepcopy(row)
            poisoned["release_gate"] = None
            self.assertFalse(build.seven_pass(poisoned))
            poisoned["release_gate"] = "NA"
            self.assertFalse(build.seven_pass(poisoned))

    def test_exact_candidate_carrier_fix_no_cartesian(self) -> None:
        row94 = self.new_counted[0]
        self.assertEqual(row94["candidate_set"], [build.CAND])
        self.assertEqual(row94["carrier_set"], [])
        self.assertEqual(row94["minimum_fix_set"], [build.FIX])
        self.assertEqual(row94["candidate_parent"], build.PARENT)
        self.assertEqual(row94["fix_parent"], build.FIX_PARENT)
        self.assertNotIn("candidate_fix_edges", row94)
        self.assertTrue(row94["cartesian_candidate_fix_refused"])
        self.assertEqual(row94["mechanism_key"], build.MECH_KEY)
        self.assertNotIn(build.MERGE, row94["candidate_set"])
        self.assertNotIn(build.FIX, row94["candidate_set"])

    def test_packet_pins_and_exclusions(self) -> None:
        pins = build.pin_inputs()
        self.assertEqual(
            pins["hostile_result"]["sha256"],
            "64616eccb295c6951889fa04d0d0ea2b24da3977fb76d3b466780d268f75df29",
        )
        self.assertEqual(
            pins["hostile_cases"]["sha256"],
            "a44283803dbb28608719a8de828892b9d3437752e58e3f8953836cb93c9b1134",
        )
        self.assertEqual(
            pins["hostile_assignment"]["sha256"],
            "41e474e8fcb1d17b038dc3cf4240eef6055aba846d6a7a57ddb5b2ec09ccf521",
        )
        self.assertEqual(
            pins["hostile_report"]["sha256"],
            "f06fe2621a12364b5c43224a38ebaf332d0a73a436dc6fc71b128cf3003252eb",
        )
        self.assertEqual(
            pins["hostile_replay"]["sha256"],
            "35291ef91575bd6e8f7671fc2788d72602ac985a40a85a79f36cc1e85c555d06",
        )
        self.assertEqual(
            pins["canonical93_ledger"]["sha256"],
            "6d652a089329eb23108083fb73ca1a8a3aa00583415b235381f3b37da389dc3d",
        )
        self.assertEqual(
            pins["canonical93_summary"]["sha256"],
            "cf8a3eb231830303803e2e1a198207b2a8e117990a675982e8d9e346c9cc46c0",
        )
        self.assertEqual(
            pins["canonical93_manifest"]["sha256"],
            "fee404f0f7a2883cd37903f21664b82b91fe68e43c9e24af8a7400341d7be965",
        )
        self.assertEqual(
            pins["fp211_public_cases"]["sha256"],
            "e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257",
        )
        self.assertEqual(
            pins["research_truth_layers"]["sha256"],
            "70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f",
        )
        self.assertEqual(self.new_counted[0]["admission_source"], "76pc_hostile_redteam_keep")
        self.assertEqual(self.cap["source_hashes"]["hostile_packet"], build.P_HOSTILE)
        self.assertEqual(self.cap["excluded_from_this_promotion"], [build.CASE_49MQ])
        self.assertEqual(self.manifest["packet_authority"][-1]["packet"], build.P_HOSTILE)
        self.assertEqual(self.manifest["packet_authority"][-1]["authority_rank"], 53)
        ids = [row["case_id"] for row in self.counted]
        self.assertNotIn(build.CASE_49MQ, ids)
        self.assertNotIn(build.CASE_G353, ids)
        self.assertNotIn(build.CASE_Q447, ids)
        self.assertNotIn(build.CASE_2Q7J, ids)
        self.assertFalse(any(row["case_id"] == build.CASE_76PC for row in self.supers))

    def test_pinned_git_parents_tags_and_blobs(self) -> None:
        row94 = self.new_counted[0]
        case = self.cap["cases"][build.CASE_76PC]
        self.assertEqual(case["object_shas"]["counted_candidate"], build.CAND)
        self.assertEqual(case["object_shas"]["candidate_parent"], build.PARENT)
        self.assertEqual(case["object_shas"]["minimum_fix"], build.FIX)
        self.assertEqual(case["object_shas"]["fix_parent"], build.FIX_PARENT)
        self.assertEqual(case["object_shas"]["first_parent_landing_merge"], build.MERGE)
        self.assertEqual(case["object_shas"]["origin_web_server_ts"], build.BLOB_ORIGIN)
        self.assertEqual(case["object_shas"]["merge_web_server_ts"], build.BLOB_MERGE)
        self.assertEqual(case["object_shas"]["vulnerable_web_server_ts_v5_0_1"], build.BLOB_VULN)
        self.assertEqual(case["object_shas"]["closer_web_server_ts"], build.BLOB_CLOSER)
        self.assertEqual(
            case["object_shas"]["fixed_web_server_ts_v5_1_0_and_npm_5_1_1"],
            build.BLOB_FIXED,
        )
        self.assertNotEqual(build.BLOB_ORIGIN, build.BLOB_MERGE)
        self.assertNotEqual(build.BLOB_CLOSER, build.BLOB_FIXED)
        self.assertEqual(row94["candidate_parent"], build.PARENT)
        self.assertEqual(row94["fix_parent"], build.FIX_PARENT)

    def test_release_hashes_and_containment(self) -> None:
        row94 = self.new_counted[0]
        self.assertEqual(row94["vulnerable_release"]["tag"], "v5.0.1")
        self.assertEqual(row94["vulnerable_release"]["npm_version"], "5.0.1")
        self.assertEqual(row94["fixed_release"]["tag"], "v5.1.1")
        self.assertEqual(row94["fixed_release"]["npm_version"], "5.1.1")
        self.assertEqual(row94["vulnerable_release"]["git_tag_commit"], build.PEEL_VULN)
        self.assertEqual(row94["vulnerable_release"]["npm_githead"], build.PEEL_VULN)
        self.assertEqual(row94["fixed_release"]["git_tag_commit"], build.PEEL_FIX)
        self.assertEqual(row94["fixed_release"]["npm_githead"], build.PEEL_FIX)
        self.assertEqual(
            row94["fixed_release"]["supporting_fixed_tag"]["git_tag_commit"],
            build.PEEL_510,
        )
        self.assertTrue(row94["vulnerable_release"]["contains_candidate_any_parent"])
        self.assertFalse(row94["vulnerable_release"]["contains_fix_any_parent"])
        self.assertTrue(row94["fixed_release"]["contains_fix_any_parent"])
        self.assertFalse(row94["vulnerable_release"]["has_isValidSessionId"])
        self.assertTrue(row94["fixed_release"]["has_isValidSessionId"])
        self.assertTrue(row94["fixed_release"]["supporting_fixed_tag"]["unpublished_npm"])

    def test_negative_controls_absent(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        for case_id in (
            build.CASE_PIMCORE,
            build.CASE_HHJV,
            build.CASE_73HC,
            build.CASE_282G,
            build.CASE_45Q4,
            build.CASE_954P,
            build.CASE_C8JX,
            build.CASE_FPXG,
            build.CASE_6G9V,
            build.CASE_9722,
            build.CASE_6C8G,
            build.CASE_2QRV,
            build.CASE_R5JH,
            build.CASE_G353,
            build.CASE_Q447,
            build.CASE_2Q7J,
            build.CASE_49MQ,
        ):
            self.assertNotIn(case_id, ids)
        for case_id, ctrl in self.neg.items():
            self.assertEqual(ctrl["verdict"], "REJECT")
            self.assertFalse(ctrl["countable"])
            self.assertNotIn(case_id, ids)

    def test_no_raw_pages_clones_caches_secrets_non_ascii(self) -> None:
        owned = Path(verify.HERE)
        names = {p.name for p in owned.iterdir() if p.is_file()}
        self.assertEqual(
            names,
            {
                "acceptance.json",
                "build.py",
                "ledger.jsonl",
                "manifest.json",
                "report.md",
                "summary.json",
                "test_canonical.py",
                "verify.py",
            },
        )
        self.assertNotIn("negative_controls.json", names)
        self.assertFalse(any(p.suffix in {".crate", ".whl", ".tgz"} for p in owned.rglob("*")))
        self.assertFalse((owned / "pages").exists())
        self.assertFalse((owned / "work").exists())
        self.assertFalse((owned / "__pycache__").exists())
        for p in owned.iterdir():
            if not p.is_file():
                continue
            text = p.read_bytes().decode("ascii")
            self.assertIsNone(build.HAN.search(text))
        artifacts = [
            (owned / "summary.json").read_text(),
            (owned / "manifest.json").read_text(),
            (owned / "report.md").read_text(),
            (owned / "acceptance.json").read_text(),
        ]
        artifacts.extend(build.compact_json(row) for row in self.new_counted)
        for text in artifacts:
            build.assert_no_leak(text)
            self.assertNotIn("/home/hanqing/.cache", text)
            self.assertNotIn("pages/ghsa/", text)
            self.assertNotIn("pages/GHSA", text)
        ledger = (owned / "ledger.jsonl").read_text()
        build.assert_no_leak(ledger)
        self.assertNotIn("/home/hanqing/.cache", ledger)
        script_text = (owned / "build.py").read_text() + (owned / "verify.py").read_text()
        self.assertNotIn("os" + ".environ", script_text)
        self.assertNotIn("environ" + ".copy", script_text)
        self.assertNotIn("print" + "env", script_text)
        self.assertTrue(all("clone" not in row for row in self.new_counted))
        self.assertTrue(all("clone_path" not in row for row in self.new_counted))

    def test_hold_boundaries_and_manifest_hashes(self) -> None:
        self.assertEqual(self.summary["canonical_strict_count"], 94)
        self.assertEqual(self.summary["counts"]["strict_released_first_party_ghsa"], 94)
        self.assertEqual(self.summary["counts"]["ledger_records"], 597)
        self.assertEqual(self.summary["counts"]["by_record_kind"]["APPEND_IDENTITY"], 15)
        self.assertEqual(self.summary["counts"]["by_record_kind"]["SUPERSEDES_EDGE"], 47)
        self.assertFalse(self.summary["integration_ready"])
        self.assertFalse(self.summary["publication_ready"])
        self.assertFalse(self.summary["publication_admission"])
        self.assertFalse(self.summary["causal_admission"])
        self.assertFalse(self.summary["public_200_claim_supported"])
        self.assertEqual(self.summary["status"], "HOLD")
        report = (verify.HERE / "report.md").read_text()
        self.assertNotIn("more than 200", report.lower())
        self.assertIn("greater-than-200", report)
        ledger_hash = build.sha256_file(verify.HERE / "ledger.jsonl")
        summary_hash = build.sha256_file(verify.HERE / "summary.json")
        report_hash = build.sha256_file(verify.HERE / "report.md")
        self.assertEqual(self.manifest["outputs"]["ledger.jsonl_sha256"], ledger_hash)
        self.assertEqual(self.manifest["outputs"]["summary.json_sha256"], summary_hash)
        self.assertEqual(self.manifest["outputs"]["report.md_sha256"], report_hash)
        self.assertEqual(self.summary["ledger_sha256"], ledger_hash)
        self.assertEqual(self.counted[90]["case_id"], build.CASE_5WP8)
        self.assertEqual(self.counted[91]["case_id"], build.CASE_MFMP)
        self.assertEqual(self.counted[92]["case_id"], build.CASE_M649)
        self.assertEqual(self.counted[93]["case_id"], build.CASE_76PC)


if __name__ == "__main__":
    unittest.main()
