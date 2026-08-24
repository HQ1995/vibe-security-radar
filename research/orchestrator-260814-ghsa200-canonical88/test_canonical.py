#!/usr/bin/env python3
"""Regression checks for the canonical88 HOLD snapshot."""

import unittest
from copy import deepcopy
from pathlib import Path

import build
import verify


class Canonical88Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary, cls.counted = verify.verify()
        cls.rows = verify.load_rows()
        cls.hyp = verify.by_kind(cls.rows, "PRESERVED_HYPOTHESIS")
        cls.pub = verify.by_kind(cls.rows, "PRESERVED_PUBLIC_CASE")
        cls.prior_rows = build.load_jsonl(build.ROOT / build.P_C87_LEDGER)
        cls.prior_summary = build.load_json(build.ROOT / build.P_C87_SUM)
        cls.prior_counted = [
            row for row in cls.prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"
        ]
        cls.new_counted = cls.counted[build.PRIOR_STRICT :]
        cls.cap = build.load_capsule_8rw6()
        cls.neg = {row["case_id"]: row for row in build.load_negative()["controls"]}
        cls.manifest = build.load_json(verify.HERE / "manifest.json")

    def test_base_prefix_byte_identity_and_hash(self) -> None:
        self.assertEqual(len(self.prior_rows), 584)
        self.assertEqual(len(self.rows), 585)
        self.assertEqual(self.rows[:584], self.prior_rows)
        prior_text = (build.ROOT / build.P_C87_LEDGER).read_text()
        current_text = (verify.HERE / "ledger.jsonl").read_text()
        self.assertTrue(current_text.startswith(prior_text if prior_text.endswith("\n") else prior_text + "\n"))
        self.assertEqual(
            build.sha256_file(build.ROOT / build.P_C87_LEDGER),
            "b6dc7e781017e60a94725696b5a08b229a5cb026ffd098e6306e9a8941f9fdbe",
        )
        self.assertEqual(len(self.prior_counted), 87)
        self.assertEqual(self.counted[:87], self.prior_counted)
        self.assertEqual(len(self.hyp), 211)
        self.assertEqual(len(self.pub), 212)
        self.assertEqual(len(self.counted), 88)
        self.assertTrue(self.summary["conservation"]["base_counted_rows_byte_identical"])
        self.assertTrue(self.summary["conservation"]["base_ledger_rows_byte_identical"])
        prior_append = self.prior_summary["conservation"]["append_identities"]
        self.assertEqual(len(prior_append), 17)
        self.assertEqual(self.summary["conservation"]["prior_append_identities"], prior_append)
        self.assertEqual(self.summary["conservation"]["new_append_identities"], [build.CASE_8RW6])
        self.assertEqual(
            self.summary["conservation"]["append_identities"],
            prior_append + [build.CASE_8RW6],
        )
        self.assertEqual(len(self.summary["conservation"]["append_identities"]), 18)

    def test_eighty_eight_unique_ids_one_new(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        fps = [row["mechanism_fingerprint"] for row in self.counted]
        mechs = [row["mechanism_key"] for row in self.counted]
        self.assertEqual(len(ids), 88)
        self.assertEqual(len(set(ids)), 88)
        self.assertEqual(len(set(fps)), 88)
        self.assertEqual(len(set(mechs)), 88)
        self.assertEqual(ids[87:], [build.CASE_8RW6])
        self.assertEqual([row["ordinal"] for row in self.new_counted], [88])
        prior_ids = set(self.prior_summary["strict_released_case_ids"])
        self.assertEqual(set(ids) - prior_ids, {build.CASE_8RW6})
        self.assertTrue(prior_ids <= set(ids))
        self.assertEqual(len(self.new_counted), 1)
        self.assertNotIn(build.CASE_8RW6, prior_ids)

    def test_no_cve_alias_and_narrow_scope(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        row = self.new_counted[0]
        self.assertEqual(row["aliases"], [])
        self.assertNotIn("CVE-", "".join(ids))
        self.assertEqual(row["contribution_class"], "AI_NEW_SURFACE_CONTRIBUTOR")
        self.assertFalse(row["whole_ghsa_direct_root"])
        self.assertTrue(row["human_pluck_doc_siblings_excluded"])
        self.assertEqual(row["production_default_planner"], "best-effort")
        self.assertTrue(row["record_id_reuses_pipeline_filter"])
        self.assertIn("filter_fields_by_permission", row["scope_statement"])
        self.assertIn("Do not count whole-GHSA direct root", row["scope_statement"])
        self.assertIn("pluck_select", row["scope_statement"])
        self.assertIn("whole_ghsa_direct_root_8rw6", self.summary["excluded"])
        self.assertIn("human_pluck_select_8rw6", self.summary["excluded"])
        self.assertIn("human_doc_output_reduce_8rw6", self.summary["excluded"])

    def test_all_gates_exact_pass(self) -> None:
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

    def test_exact_candidate_empty_carrier_fix_no_cartesian(self) -> None:
        row = self.new_counted[0]
        self.assertEqual(row["candidate_set"], [build.CAND_8RW6])
        self.assertEqual(row["carrier_set"], [])
        self.assertEqual(row["minimum_fix_set"], [build.FIX_8RW6])
        self.assertEqual(row["candidate_parent"], build.PARENT_8RW6)
        self.assertEqual(row["fix_parent"], build.FIX_PARENT_8RW6)
        self.assertNotIn("candidate_fix_edges", row)
        self.assertNotIn("carrier_parent", row)
        self.assertTrue(row["cartesian_candidate_fix_refused"])
        self.assertEqual(row["mechanism_key"], build.MECH_KEY_8RW6)
        self.assertEqual(row["mechanism_fingerprint"], build.MECH_FP_8RW6)
        bound = set(row["candidate_set"] + row["carrier_set"] + row["minimum_fix_set"])
        self.assertNotIn(build.HUMAN_DOC, bound)
        self.assertNotIn(build.FIX_PARENT_8RW6, bound)

    def test_hostile_source_pins(self) -> None:
        pins = build.pin_inputs()
        self.assertEqual(
            pins["hostile_case"]["sha256"],
            "243a5e18cc2628398b0e2b3843ba910c418eb3d9479ce64b2364ac4c3b48de50",
        )
        self.assertEqual(
            pins["hostile_result"]["sha256"],
            "56cbb18b7a1896232eb62c49880941115d637fce9caa8b853339493038b18a4c",
        )
        self.assertEqual(
            pins["hostile_report"]["sha256"],
            "925b72330cdcd4e6a8c660f11abff91d09f247103d481a86dae92b00d21ca022",
        )
        self.assertEqual(
            pins["hostile_replay"]["sha256"],
            "c3fc9607f07ce6d17fc3d127db99cb1af35a1bc8a9d5451c26ad8f9c28105721",
        )
        self.assertEqual(self.new_counted[0]["admission_source"], "8rw6_hostile_redteam_keep")
        self.assertEqual(self.cap["source_hashes"]["authoritative_packet"], build.P_HOSTILE)
        self.assertEqual(self.manifest["packet_authority"][-1]["role"], "redteam")
        self.assertEqual(self.manifest["packet_authority"][-1]["authority_rank"], 46)

    def test_local_git_objects_parent_ancestry_reversal(self) -> None:
        self.assertEqual(verify.gitx("rev-parse", f"{build.CAND_8RW6}^"), build.PARENT_8RW6)
        self.assertEqual(verify.gitx("rev-parse", f"{build.FIX_8RW6}^"), build.FIX_PARENT_8RW6)

    def test_release_hashes_and_crate_containment(self) -> None:
        vuln = self.new_counted[0]["vulnerable_release"]
        fix = self.new_counted[0]["fixed_release"]
        self.assertEqual(vuln["version"], "3.1.3")
        self.assertEqual(fix["version"], "3.1.4")
        self.assertEqual(vuln["crates_io_surrealdb_core_checksum"], build.CRATE_313)
        self.assertEqual(fix["crates_io_surrealdb_core_checksum"], build.CRATE_314)
        self.assertEqual(vuln["git_tag_commit"], build.PEEL_313)
        self.assertEqual(fix["git_tag_commit"], build.PEEL_314)
        self.assertTrue(vuln["pipeline_has_forward_each_cut"])
        self.assertFalse(vuln["pipeline_has_rev"])
        self.assertTrue(fix["pipeline_blob_equals_fix"])
        self.assertFalse(fix["contains_fix_sha_as_ancestor"])
        self.assertTrue(fix["contains_fix_bytes"])
        self.assertEqual(self.cap["identity"]["engine_crate"], "surrealdb-core")
        self.assertEqual(self.cap["identity"]["fixed"], "3.1.4")

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
            (owned / "8rw6_acceptance.json").read_text(),
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
        self.assertEqual(self.summary["canonical_strict_count"], 88)
        self.assertEqual(self.summary["counts"]["strict_released_first_party_ghsa"], 88)
        self.assertEqual(self.summary["counts"]["ledger_records"], 585)
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
        self.assertEqual(self.counted[86]["case_id"], build.CASE_V52W)


if __name__ == "__main__":
    unittest.main()
