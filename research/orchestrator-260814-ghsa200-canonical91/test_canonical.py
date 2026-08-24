#!/usr/bin/env python3
"""Regression checks for the canonical91 HOLD snapshot."""

import unittest
from copy import deepcopy
from pathlib import Path

import build
import verify


class Canonical91Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary, cls.counted = verify.verify()
        cls.rows = verify.load_rows()
        cls.hyp = verify.by_kind(cls.rows, "PRESERVED_HYPOTHESIS")
        cls.pub = verify.by_kind(cls.rows, "PRESERVED_PUBLIC_CASE")
        cls.prior_rows = build.load_jsonl(build.ROOT / build.P_C90_LEDGER)
        cls.prior_summary = build.load_json(build.ROOT / build.P_C90_SUM)
        cls.prior_counted = [
            row for row in cls.prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"
        ]
        cls.new_counted = cls.counted[build.PRIOR_STRICT :]
        cls.cap = build.load_capsule()
        cls.neg = {row["case_id"]: row for row in build.load_negative()["controls"]}
        cls.manifest = build.load_json(verify.HERE / "manifest.json")

    def test_base_prefix_byte_identity_and_hash(self) -> None:
        self.assertEqual(len(self.prior_rows), 589)
        self.assertEqual(len(self.rows), 591)
        self.assertEqual(self.rows[:589], self.prior_rows)
        prior_text = (build.ROOT / build.P_C90_LEDGER).read_text()
        current_text = (verify.HERE / "ledger.jsonl").read_text()
        self.assertTrue(current_text.startswith(prior_text if prior_text.endswith("\n") else prior_text + "\n"))
        self.assertEqual(
            build.sha256_file(build.ROOT / build.P_C90_LEDGER),
            "daf706e14d514ad62d197e61aa8ec7f52eefd958bc19a4a7c58591a0be8654ec",
        )
        self.assertEqual(len(self.prior_counted), 90)
        self.assertEqual(self.counted[:90], self.prior_counted)
        self.assertEqual(len(self.hyp), 211)
        self.assertEqual(len(self.pub), 212)
        self.assertEqual(len(self.counted), 91)
        self.assertTrue(self.summary["conservation"]["base_counted_rows_byte_identical"])
        self.assertTrue(self.summary["conservation"]["base_ledger_rows_byte_identical"])
        prior_append = self.prior_summary["conservation"]["append_identities"]
        self.assertEqual(len(prior_append), 18)
        self.assertEqual(self.summary["conservation"]["prior_append_identities"], prior_append)
        self.assertEqual(self.summary["conservation"]["new_append_identities"], [])
        self.assertEqual(self.summary["conservation"]["append_identities"], prior_append)
        self.assertEqual(len(self.summary["conservation"]["append_identities"]), 18)
        self.assertFalse(self.summary["conservation"]["new_identities_append"])
        self.assertTrue(self.summary["conservation"]["same_id_source_layer_promoted"])
        self.assertEqual(self.summary["conservation"]["appended_strict_rows"], 1)

    def test_ninety_one_unique_ids_one_promoted(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        fps = [row["mechanism_fingerprint"] for row in self.counted]
        mechs = [row["mechanism_key"] for row in self.counted]
        self.assertEqual(len(ids), 91)
        self.assertEqual(len(set(ids)), 91)
        self.assertEqual(len(set(fps)), 91)
        self.assertEqual(len(set(mechs)), 91)
        self.assertEqual(ids[90:], [build.CASE_5WP8])
        self.assertEqual([row["ordinal"] for row in self.new_counted], [91])
        prior_ids = set(self.prior_summary["strict_released_case_ids"])
        self.assertEqual(set(ids) - prior_ids, {build.CASE_5WP8})
        self.assertTrue(prior_ids <= set(ids))
        self.assertEqual(len(self.new_counted), 1)
        self.assertNotIn(build.CASE_5WP8, prior_ids)
        self.assertNotIn(build.CASE_2QRV, ids)
        self.assertNotIn(build.CASE_R5JH, ids)
        self.assertNotIn(build.CASE_J8Q9, ids)
        self.assertIn(build.CASE_46Q5, ids)

    def test_public_id_alias_stored_never_counted(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        row = self.new_counted[0]
        self.assertEqual(row["aliases"], [])
        self.assertTrue(all(item.startswith("GHSA-") for item in ids))
        self.assertEqual(ids.count(build.CASE_5WP8), 1)
        self.assertFalse(self.summary["conservation"]["cve_aliases_counted"])

    def test_incomplete_remediation_scope(self) -> None:
        row = self.new_counted[0]
        self.assertEqual(row["contribution_class"], "AI_INCOMPLETE_REMEDIATION")
        self.assertFalse(row["whole_ghsa_direct_root"])
        self.assertIn("empty-strict", row["scope_statement"])
        self.assertIn("1712debb", row["scope_statement"])
        self.assertIn("3c4368da", row["scope_statement"])
        self.assertIn("91f6c2bf", row["scope_statement"])
        self.assertIn("GHSA-HHJV", row["scope_statement"])
        self.assertIn("whole_ghsa_direct_root_5wp8", self.summary["excluded"])
        self.assertIn(build.CASE_2QRV, self.summary["excluded"])
        self.assertIn(build.CASE_R5JH, self.summary["excluded"])
        self.assertTrue(self.summary["uniqueness"]["member_3c4368da_not_transferred"])
        self.assertTrue(self.summary["uniqueness"]["distinct_from_counted_46q5"])
        self.assertTrue(self.summary["uniqueness"]["distinct_from_negative_hhjv"])

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
        row = self.new_counted[0]
        self.assertEqual(row["candidate_set"], [build.CAND_5WP8])
        self.assertEqual(row["carrier_set"], [build.CARR_5WP8])
        self.assertEqual(row["candidate_set"], row["carrier_set"])
        self.assertEqual(row["minimum_fix_set"], [build.FIX_5WP8])
        self.assertEqual(row["candidate_parent"], build.PARENT_5WP8)
        self.assertEqual(row["fix_parent"], build.FIX_PARENT_5WP8)
        self.assertNotIn("candidate_fix_edges", row)
        self.assertTrue(row["cartesian_candidate_fix_refused"])
        self.assertEqual(row["mechanism_key"], build.MECH_KEY_5WP8)
        self.assertEqual(row["mechanism_fingerprint"], build.MECH_FP_5WP8)
        self.assertNotIn(build.MEM_5WP8, row["candidate_set"])
        self.assertNotIn(build.MEM_5WP8, row["carrier_set"])
        self.assertNotIn(build.BLK_5WP8, row["candidate_set"])

    def test_dual_packet_pins_and_exclusions(self) -> None:
        pins = build.pin_inputs()
        self.assertEqual(
            pins["nearclosed_result"]["sha256"],
            "571765397f5729cd115d852cc20e6e5f925fb4df96668bf129798e46b0a95c74",
        )
        self.assertEqual(
            pins["hostile_result"]["sha256"],
            "d31aa8c08f367301b0a74133169f230851372082b5daaac220dd33934480124b",
        )
        self.assertEqual(
            pins["nearclosed_cases"]["sha256"],
            "c11ac29971f8fd4836a21ce60f8ce657f3fdd43eba3eaa8cb1e413377583628f",
        )
        self.assertEqual(
            pins["hostile_cases"]["sha256"],
            "832900b9ed2521d6858ff5670c7d8afbae8a46b42d7bf5fcef52b07f095a66d5",
        )
        self.assertEqual(
            pins["fp211_public_cases"]["sha256"],
            "e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257",
        )
        self.assertEqual(
            pins["research_truth_layers"]["sha256"],
            "70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f",
        )
        self.assertEqual(self.new_counted[0]["admission_source"], "incomplete_remediation_dual_keep")
        self.assertEqual(self.cap["source_hashes"]["nearclosed_e_packet"], build.P_NEAR)
        self.assertEqual(self.cap["source_hashes"]["hostile_packet"], build.P_HOSTILE)
        self.assertEqual(self.cap["excluded_from_this_promotion"], [build.CASE_2QRV, build.CASE_R5JH])
        self.assertEqual(self.manifest["packet_authority"][-2]["packet"], build.P_NEAR)
        self.assertEqual(self.manifest["packet_authority"][-1]["packet"], build.P_HOSTILE)
        self.assertEqual(self.manifest["packet_authority"][-2]["authority_rank"], 49)
        self.assertEqual(self.manifest["packet_authority"][-1]["authority_rank"], 50)
        ids = [row["case_id"] for row in self.counted]
        self.assertNotIn(build.CASE_2QRV, ids)
        self.assertNotIn(build.CASE_R5JH, ids)

    def test_local_git_objects_parent_ancestry_reversal(self) -> None:
        self.assertEqual(
            verify.gitx("rev-parse", f"{build.CAND_5WP8}^", repo=verify.CLONE_5WP8),
            build.PARENT_5WP8,
        )
        self.assertEqual(
            verify.gitx("rev-parse", f"{build.FIX_5WP8}^", repo=verify.CLONE_5WP8),
            build.FIX_PARENT_5WP8,
        )
        self.assertFalse(
            verify.is_ancestor(verify.CLONE_5WP8, build.MEM_5WP8, build.CAND_5WP8)
        )
        self.assertFalse(
            verify.is_ancestor(verify.CLONE_5WP8, build.FIX_5WP8, build.PEEL_5WP8_VULN)
        )

    def test_release_hashes_and_containment(self) -> None:
        row = self.new_counted[0]
        self.assertEqual(row["vulnerable_release"]["tag"], "v0.6.1")
        self.assertEqual(row["fixed_release"]["tag"], "v0.6.2")
        self.assertEqual(row["vulnerable_release"]["git_tag_commit"], build.PEEL_5WP8_VULN)
        self.assertEqual(row["fixed_release"]["git_tag_commit"], build.PEEL_5WP8_FIX)
        self.assertTrue(row["vulnerable_release"]["contains_candidate_any_parent"])
        self.assertFalse(row["vulnerable_release"]["contains_fix_any_parent"])
        self.assertTrue(row["fixed_release"]["contains_fix_any_parent"])
        self.assertEqual(row["vulnerable_release"]["crates_io_zeptoclaw_checksum"], build.CRATE_061)
        self.assertEqual(row["fixed_release"]["crates_io_zeptoclaw_checksum"], build.CRATE_062)
        self.assertEqual(row["vulnerable_release"]["supporting_earlier_peel"], build.PEEL_5WP8_058)

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
        ):
            self.assertNotIn(case_id, ids)
        for case_id, ctrl in self.neg.items():
            self.assertEqual(ctrl["verdict"], "REJECT")
            self.assertFalse(ctrl["countable"])
            self.assertNotIn(case_id, ids)

    def test_no_raw_pages_clones_caches_secrets_non_ascii(self) -> None:
        owned = Path(verify.HERE)
        names = {p.name for p in owned.iterdir() if p.is_file()}
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
            (owned / "5wp8_acceptance.json").read_text(),
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
        self.assertEqual(self.summary["canonical_strict_count"], 91)
        self.assertEqual(self.summary["counts"]["strict_released_first_party_ghsa"], 91)
        self.assertEqual(self.summary["counts"]["ledger_records"], 591)
        self.assertFalse(self.summary["integration_ready"])
        self.assertFalse(self.summary["publication_ready"])
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
        self.assertEqual(self.counted[87]["case_id"], build.CASE_8RW6)
        self.assertEqual(self.counted[88]["case_id"], build.CASE_XMXX)
        self.assertEqual(self.counted[89]["case_id"], build.CASE_PQH8)
        self.assertEqual(self.counted[90]["case_id"], build.CASE_5WP8)


if __name__ == "__main__":
    unittest.main()
