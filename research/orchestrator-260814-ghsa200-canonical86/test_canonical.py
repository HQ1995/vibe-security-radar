#!/usr/bin/env python3
"""Regression checks for the canonical86 HOLD snapshot."""

import unittest
from copy import deepcopy
from pathlib import Path

import build
import verify


class Canonical86Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary, cls.counted = verify.verify()
        cls.rows = verify.load_rows()
        cls.hyp = verify.by_kind(cls.rows, "PRESERVED_HYPOTHESIS")
        cls.pub = verify.by_kind(cls.rows, "PRESERVED_PUBLIC_CASE")
        cls.prior_rows = build.load_jsonl(build.ROOT / build.P_C85_LEDGER)
        cls.prior_summary = build.load_json(build.ROOT / build.P_C85_SUM)
        cls.prior_counted = [
            row for row in cls.prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"
        ]
        cls.new_counted = cls.counted[build.PRIOR_STRICT :]
        cls.cap = build.load_capsule_frvj()
        cls.neg = {row["case_id"]: row for row in build.load_negative()["controls"]}
        cls.manifest = build.load_json(verify.HERE / "manifest.json")

    def test_base_prefix_byte_identity_and_hash(self) -> None:
        self.assertEqual(len(self.prior_rows), 582)
        self.assertEqual(len(self.rows), 583)
        self.assertEqual(self.rows[:582], self.prior_rows)
        prior_text = (build.ROOT / build.P_C85_LEDGER).read_text()
        current_text = (verify.HERE / "ledger.jsonl").read_text()
        self.assertTrue(current_text.startswith(prior_text if prior_text.endswith("\n") else prior_text + "\n"))
        self.assertEqual(
            build.sha256_file(build.ROOT / build.P_C85_LEDGER),
            "2927924603a76a2565d9c244c3b79f70d4693c127f1bc6fcc63e8099172ba568",
        )
        self.assertEqual(len(self.prior_counted), 85)
        self.assertEqual(self.counted[:85], self.prior_counted)
        self.assertEqual(len(self.hyp), 211)
        self.assertEqual(len(self.pub), 212)
        self.assertEqual(len(self.counted), 86)
        self.assertTrue(self.summary["conservation"]["base_counted_rows_byte_identical"])
        self.assertTrue(self.summary["conservation"]["base_ledger_rows_byte_identical"])
        prior_append = self.prior_summary["conservation"]["append_identities"]
        self.assertEqual(len(prior_append), 15)
        self.assertEqual(self.summary["conservation"]["prior_append_identities"], prior_append)
        self.assertEqual(self.summary["conservation"]["new_append_identities"], [build.CASE_FRVJ])
        self.assertEqual(
            self.summary["conservation"]["append_identities"],
            prior_append + [build.CASE_FRVJ],
        )
        self.assertEqual(len(self.summary["conservation"]["append_identities"]), 16)

    def test_eighty_six_unique_ids_one_new(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        fps = [row["mechanism_fingerprint"] for row in self.counted]
        mechs = [row["mechanism_key"] for row in self.counted]
        self.assertEqual(len(ids), 86)
        self.assertEqual(len(set(ids)), 86)
        self.assertEqual(len(set(fps)), 86)
        self.assertEqual(len(set(mechs)), 86)
        self.assertEqual(ids[85:], [build.CASE_FRVJ])
        self.assertEqual([row["ordinal"] for row in self.new_counted], [86])
        prior_ids = set(self.prior_summary["strict_released_case_ids"])
        self.assertEqual(set(ids) - prior_ids, {build.CASE_FRVJ})
        self.assertTrue(prior_ids <= set(ids))
        self.assertEqual(len(self.new_counted), 1)
        self.assertNotIn(build.ALIAS_FRVJ, ids)
        self.assertNotIn(build.CASE_R2WG, ids)

    def test_cve_alias_absent_from_counted_ids(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        self.assertNotIn(build.ALIAS_FRVJ, ids)
        self.assertEqual(self.new_counted[0]["aliases"], [build.ALIAS_FRVJ])
        self.assertIn(build.ALIAS_FRVJ, self.summary["excluded"])

    def test_all_gates_exact_pass(self) -> None:
        for row in self.counted:
            for field in build.GATES:
                self.assertEqual(row[field], "PASS")
                self.assertIsNotNone(row[field])
                self.assertNotEqual(row[field], "NA")
            self.assertTrue(build.seven_pass(row))
        row = self.new_counted[0]
        self.assertEqual(row[build.REMEDIATION_GATE], "PASS")
        poisoned = deepcopy(row)
        poisoned["release_gate"] = None
        self.assertFalse(build.seven_pass(poisoned))
        poisoned["release_gate"] = "NA"
        self.assertFalse(build.seven_pass(poisoned))

    def test_exact_candidate_fix_no_cartesian(self) -> None:
        row = self.new_counted[0]
        self.assertEqual(row["candidate_set"], [build.CAND_FRVJ])
        self.assertEqual(row["carrier_set"], [])
        self.assertEqual(row["minimum_fix_set"], [build.FIX_FRVJ])
        self.assertEqual(row["candidate_parent"], build.PARENT_FRVJ)
        self.assertEqual(row["fix_parent"], build.FIX_PARENT_FRVJ)
        self.assertNotIn("candidate_fix_edges", row)
        self.assertTrue(row["cartesian_candidate_fix_refused"])
        self.assertEqual(row["mechanism_key"], build.MECH_KEY_FRVJ)
        self.assertEqual(row["mechanism_fingerprint"], build.MECH_FP_FRVJ)
        self.assertNotEqual(row["mechanism_key"], "open-webui.terminals.sanitize-proxy-path.single-unquote")
        self.assertTrue(row["distinct_from_r2wg"])

    def test_hostile_source_pins(self) -> None:
        pins = build.pin_inputs()
        self.assertEqual(
            pins["hostile_case"]["sha256"],
            "e7a8f1a543f9750acd3a71265b403950de8c0dfa28ad39de8b231dec78ae7c94",
        )
        self.assertEqual(
            pins["hostile_result"]["sha256"],
            "09f6766fd94bf30ee0232e7ad05cc69fe9f92748181a18794a234f3cb2c51013",
        )
        self.assertEqual(
            pins["hostile_report"]["sha256"],
            "c389b9f8d3f7f65a953d1e0cbac43334449800ce670d3f0a3936ac0a5d82adf5",
        )
        self.assertEqual(
            pins["hostile_replay"]["sha256"],
            "09d040976e91bbf99a1c3e43bbac9ce3ea55b370dcc05bdb5b02a5fa96a7e8a5",
        )
        self.assertEqual(
            pins["worker_cases"]["sha256"],
            "6a13b08e9b569dfab705385985d5ea49f561c26e8ac28831e620c3e4dce1a742",
        )
        self.assertEqual(self.new_counted[0]["admission_source"], "frvj_hostile2_redteam_keep")
        self.assertEqual(self.cap["source_hashes"]["authoritative_packet"], build.P_HOSTILE)
        self.assertEqual(self.manifest["packet_authority"][-1]["role"], "redteam")
        self.assertEqual(self.manifest["packet_authority"][-2]["role"], "worker")

    def test_local_git_objects_parent_ancestry_reversal(self) -> None:
        verify.verify_git()
        self.assertEqual(verify.gitx("rev-parse", f"{build.CAND_FRVJ}^"), build.PARENT_FRVJ)
        self.assertEqual(verify.gitx("rev-parse", f"{build.FIX_FRVJ}^"), build.FIX_PARENT_FRVJ)

    def test_release_hashes_and_range(self) -> None:
        vuln = self.new_counted[0]["vulnerable_release"]
        fix = self.new_counted[0]["fixed_release"]
        self.assertEqual(vuln["version"], "0.9.6")
        self.assertEqual(fix["version"], "0.10.0")
        self.assertEqual(vuln["sha256"], build.WHEEL_096)
        self.assertEqual(fix["sha256"], build.WHEEL_010)
        self.assertTrue(vuln["contains_attempt_sanitizer"])
        self.assertFalse(vuln["contains_fail_closed"])
        self.assertTrue(fix["contains_fail_closed"])
        self.assertFalse(vuln["yanked"])
        self.assertFalse(fix["yanked"])
        self.assertEqual(self.cap["identity"]["introduced"], "0.9.6")
        self.assertEqual(self.cap["identity"]["fixed"], "0.10.0")

    def test_negative_controls_absent(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        for case_id in (
            build.CASE_PIMCORE,
            build.CASE_HHJV,
            build.CASE_73HC,
            build.CASE_282G,
            build.CASE_45Q4,
            build.CASE_954P,
            build.CASE_R2WG,
        ):
            self.assertNotIn(case_id, ids)
        for case_id, ctrl in self.neg.items():
            self.assertEqual(ctrl["verdict"], "REJECT")
            self.assertFalse(ctrl["countable"])
            self.assertNotIn(case_id, ids)

    def test_no_raw_wheels_pages_clones_secrets_non_ascii(self) -> None:
        owned = Path(verify.HERE)
        names = {p.name for p in owned.iterdir() if p.is_file()}
        self.assertNotIn("negative_controls.json", names)
        self.assertFalse(any(p.suffix == ".whl" for p in owned.rglob("*")))
        self.assertFalse((owned / "pages").exists())
        self.assertFalse((owned / "work").exists())
        for p in owned.iterdir():
            if not p.is_file():
                continue
            text = p.read_bytes().decode("ascii")
            self.assertIsNone(build.HAN.search(text))
        artifacts = [
            (owned / "summary.json").read_text(),
            (owned / "manifest.json").read_text(),
            (owned / "report.md").read_text(),
            (owned / "frvj_acceptance.json").read_text(),
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
        self.assertEqual(self.summary["canonical_strict_count"], 86)
        self.assertEqual(self.summary["counts"]["strict_released_first_party_ghsa"], 86)
        self.assertEqual(self.summary["counts"]["ledger_records"], 583)
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
        self.assertEqual(self.counted[84]["case_id"], build.CASE_8359)


if __name__ == "__main__":
    unittest.main()
