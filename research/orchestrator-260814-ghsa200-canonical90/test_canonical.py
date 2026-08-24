#!/usr/bin/env python3
"""Regression checks for the canonical90 HOLD snapshot."""

import unittest
from copy import deepcopy
from pathlib import Path

import build
import verify


class Canonical90Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary, cls.counted = verify.verify()
        cls.rows = verify.load_rows()
        cls.hyp = verify.by_kind(cls.rows, "PRESERVED_HYPOTHESIS")
        cls.pub = verify.by_kind(cls.rows, "PRESERVED_PUBLIC_CASE")
        cls.prior_rows = build.load_jsonl(build.ROOT / build.P_C88_LEDGER)
        cls.prior_summary = build.load_json(build.ROOT / build.P_C88_SUM)
        cls.prior_counted = [
            row for row in cls.prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"
        ]
        cls.new_counted = cls.counted[build.PRIOR_STRICT :]
        cls.cap = build.load_capsule()
        cls.neg = {row["case_id"]: row for row in build.load_negative()["controls"]}
        cls.manifest = build.load_json(verify.HERE / "manifest.json")

    def test_base_prefix_byte_identity_and_hash(self) -> None:
        self.assertEqual(len(self.prior_rows), 585)
        self.assertEqual(len(self.rows), 589)
        self.assertEqual(self.rows[:585], self.prior_rows)
        prior_text = (build.ROOT / build.P_C88_LEDGER).read_text()
        current_text = (verify.HERE / "ledger.jsonl").read_text()
        self.assertTrue(current_text.startswith(prior_text if prior_text.endswith("\n") else prior_text + "\n"))
        self.assertEqual(
            build.sha256_file(build.ROOT / build.P_C88_LEDGER),
            "35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074",
        )
        self.assertEqual(len(self.prior_counted), 88)
        self.assertEqual(self.counted[:88], self.prior_counted)
        self.assertEqual(len(self.hyp), 211)
        self.assertEqual(len(self.pub), 212)
        self.assertEqual(len(self.counted), 90)
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
        self.assertEqual(self.summary["conservation"]["appended_strict_rows"], 2)

    def test_ninety_unique_ids_two_promoted(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        fps = [row["mechanism_fingerprint"] for row in self.counted]
        mechs = [row["mechanism_key"] for row in self.counted]
        self.assertEqual(len(ids), 90)
        self.assertEqual(len(set(ids)), 90)
        self.assertEqual(len(set(fps)), 90)
        self.assertEqual(len(set(mechs)), 90)
        self.assertEqual(ids[88:], [build.CASE_XMXX, build.CASE_PQH8])
        self.assertEqual([row["ordinal"] for row in self.new_counted], [89, 90])
        prior_ids = set(self.prior_summary["strict_released_case_ids"])
        self.assertEqual(set(ids) - prior_ids, {build.CASE_XMXX, build.CASE_PQH8})
        self.assertTrue(prior_ids <= set(ids))
        self.assertEqual(len(self.new_counted), 2)
        self.assertNotIn(build.CASE_XMXX, prior_ids)
        self.assertNotIn(build.CASE_PQH8, prior_ids)
        self.assertNotIn(build.CASE_6C8G, ids)
        self.assertNotIn(build.ALIAS_XMXX, ids)

    def test_public_id_alias_stored_never_counted(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        xmxx = self.new_counted[0]
        pqh8 = self.new_counted[1]
        self.assertEqual(xmxx["aliases"], [build.ALIAS_XMXX])
        self.assertEqual(pqh8["aliases"], [])
        self.assertTrue(all(item.startswith("GHSA-") for item in ids))
        self.assertNotIn(build.ALIAS_XMXX, ids)
        self.assertEqual(ids.count(build.CASE_XMXX), 1)
        self.assertIn("alias of GHSA-XMXX-7P24-H892", self.summary["excluded"][build.ALIAS_XMXX])
        self.assertFalse(self.summary["conservation"]["cve_aliases_counted"])

    def test_scoped_contributor_statements(self) -> None:
        xmxx = self.new_counted[0]
        pqh8 = self.new_counted[1]
        self.assertEqual(xmxx["contribution_class"], "AI_NEW_SURFACE_CONTRIBUTOR")
        self.assertEqual(pqh8["contribution_class"], "AI_NEW_SURFACE_CONTRIBUTOR")
        self.assertFalse(xmxx["whole_ghsa_direct_root"])
        self.assertFalse(pqh8["whole_ghsa_direct_root"])
        self.assertIn("/v1/responses", xmxx["scope_statement"])
        self.assertIn("startup-captured resolvedAuth", xmxx["scope_statement"])
        self.assertIn("Chat Completions", xmxx["scope_statement"])
        self.assertIn("list-vulnerabilities.ts", pqh8["scope_statement"])
        self.assertIn("get-events-for-cluster.ts", pqh8["scope_statement"])
        self.assertIn("validateTimeframe", pqh8["scope_statement"])
        self.assertIn("list-problems", pqh8["scope_statement"])
        self.assertIn("whole_ghsa_direct_root_xmxx", self.summary["excluded"])
        self.assertIn("whole_ghsa_direct_root_pqh8", self.summary["excluded"])
        self.assertIn(build.CASE_6C8G, self.summary["excluded"])

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

    def test_exact_candidate_empty_carrier_fix_no_cartesian(self) -> None:
        xmxx, pqh8 = self.new_counted
        self.assertEqual(xmxx["candidate_set"], [build.CAND_XMXX])
        self.assertEqual(pqh8["candidate_set"], [build.CAND_PQH8])
        self.assertEqual(xmxx["carrier_set"], [])
        self.assertEqual(pqh8["carrier_set"], [])
        self.assertEqual(xmxx["minimum_fix_set"], [build.FIX_XMXX])
        self.assertEqual(pqh8["minimum_fix_set"], [build.FIX_PQH8])
        self.assertEqual(xmxx["candidate_parent"], build.PARENT_XMXX)
        self.assertEqual(pqh8["candidate_parent"], build.PARENT_PQH8)
        self.assertEqual(xmxx["fix_parent"], build.FIX_PARENT_XMXX)
        self.assertEqual(pqh8["fix_parent"], build.FIX_PARENT_PQH8)
        self.assertNotIn("candidate_fix_edges", xmxx)
        self.assertNotIn("candidate_fix_edges", pqh8)
        self.assertTrue(xmxx["cartesian_candidate_fix_refused"])
        self.assertTrue(pqh8["cartesian_candidate_fix_refused"])
        self.assertEqual(xmxx["mechanism_key"], build.MECH_KEY_XMXX)
        self.assertEqual(pqh8["mechanism_key"], build.MECH_KEY_PQH8)
        self.assertEqual(xmxx["mechanism_fingerprint"], build.MECH_FP_XMXX)
        self.assertEqual(pqh8["mechanism_fingerprint"], build.MECH_FP_PQH8)

    def test_dual_packet_pins_and_6c8g_exclusion(self) -> None:
        pins = build.pin_inputs()
        self.assertEqual(
            pins["nearclosed_result"]["sha256"],
            "bb70dcfcce2253e954ffadeadece81774426c5b70b8739aba49344f21d81dcda",
        )
        self.assertEqual(
            pins["ccb_result"]["sha256"],
            "5c06b04888a83ea762702f4403dda0894af27c4209001d78ebc3b35c7d8c203f",
        )
        self.assertEqual(
            pins["nearclosed_cases"]["sha256"],
            "3645fede5d364ddb006b4726e9dafcde78e0adbf62a4b96f1ec290b188da07cb",
        )
        self.assertEqual(
            pins["ccb_cases"]["sha256"],
            "24250aa21c24e01ddf042fe42b233e1ff2eac7a12abd0d4eb6626d0f3ec65979",
        )
        self.assertEqual(self.new_counted[0]["admission_source"], "scoped_contributor_dual_keep")
        self.assertEqual(self.cap["source_hashes"]["nearclosed_b_packet"], build.P_NEAR)
        self.assertEqual(self.cap["source_hashes"]["causal_consensus_b_packet"], build.P_CCB)
        self.assertEqual(self.cap["excluded_from_this_promotion"], [build.CASE_6C8G])
        self.assertEqual(self.manifest["packet_authority"][-2]["packet"], build.P_NEAR)
        self.assertEqual(self.manifest["packet_authority"][-1]["packet"], build.P_CCB)
        self.assertEqual(self.manifest["packet_authority"][-2]["authority_rank"], 47)
        self.assertEqual(self.manifest["packet_authority"][-1]["authority_rank"], 48)
        self.assertNotIn(build.CASE_6C8G, [row["case_id"] for row in self.counted])

    def test_local_git_objects_parent_ancestry_reversal(self) -> None:
        self.assertEqual(
            verify.gitx("rev-parse", f"{build.CAND_XMXX}^", repo=verify.CLONE_XMXX),
            build.PARENT_XMXX,
        )
        self.assertEqual(
            verify.gitx("rev-parse", f"{build.FIX_XMXX}^", repo=verify.CLONE_XMXX),
            build.FIX_PARENT_XMXX,
        )
        self.assertEqual(
            verify.gitx("rev-parse", f"{build.CAND_PQH8}^", repo=verify.CLONE_PQH8),
            build.PARENT_PQH8,
        )
        self.assertEqual(
            verify.gitx("rev-parse", f"{build.FIX_PQH8}^", repo=verify.CLONE_PQH8),
            build.FIX_PARENT_PQH8,
        )

    def test_release_hashes_and_containment(self) -> None:
        xmxx, pqh8 = self.new_counted
        self.assertEqual(xmxx["vulnerable_release"]["tag"], "v2026.4.14")
        self.assertEqual(xmxx["fixed_release"]["tag"], "v2026.4.15")
        self.assertEqual(xmxx["vulnerable_release"]["git_tag_commit"], build.PEEL_XMXX_VULN)
        self.assertEqual(xmxx["fixed_release"]["git_tag_commit"], build.PEEL_XMXX_FIX)
        self.assertTrue(xmxx["vulnerable_release"]["contains_candidate_any_parent"])
        self.assertFalse(xmxx["vulnerable_release"]["contains_fix_any_parent"])
        self.assertTrue(xmxx["fixed_release"]["contains_fix_any_parent"])
        self.assertEqual(pqh8["vulnerable_release"]["tag"], "v2.1.0")
        self.assertEqual(pqh8["fixed_release"]["tag"], "v2.1.1")
        self.assertEqual(pqh8["vulnerable_release"]["git_tag_commit"], build.PEEL_PQH8_VULN)
        self.assertEqual(pqh8["fixed_release"]["git_tag_commit"], build.PEEL_PQH8_FIX)
        self.assertTrue(pqh8["vulnerable_release"]["contains_candidate_any_parent"])
        self.assertFalse(pqh8["vulnerable_release"]["contains_fix_any_parent"])
        self.assertTrue(pqh8["fixed_release"]["contains_fix_any_parent"])
        self.assertEqual(pqh8["vulnerable_release"]["supporting_earlier_peel"], build.PEEL_PQH8_V12)

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
            (owned / "xmxx_pqh8_acceptance.json").read_text(),
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
        self.assertEqual(self.summary["canonical_strict_count"], 90)
        self.assertEqual(self.summary["counts"]["strict_released_first_party_ghsa"], 90)
        self.assertEqual(self.summary["counts"]["ledger_records"], 589)
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


if __name__ == "__main__":
    unittest.main()
