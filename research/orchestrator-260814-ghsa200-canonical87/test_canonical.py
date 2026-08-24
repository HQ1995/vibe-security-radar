#!/usr/bin/env python3
"""Regression checks for the canonical87 HOLD snapshot."""

import unittest
from copy import deepcopy
from pathlib import Path

import build
import verify


class Canonical87Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary, cls.counted = verify.verify()
        cls.rows = verify.load_rows()
        cls.hyp = verify.by_kind(cls.rows, "PRESERVED_HYPOTHESIS")
        cls.pub = verify.by_kind(cls.rows, "PRESERVED_PUBLIC_CASE")
        cls.prior_rows = build.load_jsonl(build.ROOT / build.P_C86_LEDGER)
        cls.prior_summary = build.load_json(build.ROOT / build.P_C86_SUM)
        cls.prior_counted = [
            row for row in cls.prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"
        ]
        cls.new_counted = cls.counted[build.PRIOR_STRICT :]
        cls.cap = build.load_capsule_v52w()
        cls.neg = {row["case_id"]: row for row in build.load_negative()["controls"]}
        cls.manifest = build.load_json(verify.HERE / "manifest.json")

    def test_base_prefix_byte_identity_and_hash(self) -> None:
        self.assertEqual(len(self.prior_rows), 583)
        self.assertEqual(len(self.rows), 584)
        self.assertEqual(self.rows[:583], self.prior_rows)
        prior_text = (build.ROOT / build.P_C86_LEDGER).read_text()
        current_text = (verify.HERE / "ledger.jsonl").read_text()
        self.assertTrue(current_text.startswith(prior_text if prior_text.endswith("\n") else prior_text + "\n"))
        self.assertEqual(
            build.sha256_file(build.ROOT / build.P_C86_LEDGER),
            "3150a7925cc31645b00862595d553db49ec5e07076d87e6c42beec401a647ee7",
        )
        self.assertEqual(len(self.prior_counted), 86)
        self.assertEqual(self.counted[:86], self.prior_counted)
        self.assertEqual(len(self.hyp), 211)
        self.assertEqual(len(self.pub), 212)
        self.assertEqual(len(self.counted), 87)
        self.assertTrue(self.summary["conservation"]["base_counted_rows_byte_identical"])
        self.assertTrue(self.summary["conservation"]["base_ledger_rows_byte_identical"])
        prior_append = self.prior_summary["conservation"]["append_identities"]
        self.assertEqual(len(prior_append), 16)
        self.assertEqual(self.summary["conservation"]["prior_append_identities"], prior_append)
        self.assertEqual(self.summary["conservation"]["new_append_identities"], [build.CASE_V52W])
        self.assertEqual(
            self.summary["conservation"]["append_identities"],
            prior_append + [build.CASE_V52W],
        )
        self.assertEqual(len(self.summary["conservation"]["append_identities"]), 17)

    def test_eighty_seven_unique_ids_one_new(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        fps = [row["mechanism_fingerprint"] for row in self.counted]
        mechs = [row["mechanism_key"] for row in self.counted]
        self.assertEqual(len(ids), 87)
        self.assertEqual(len(set(ids)), 87)
        self.assertEqual(len(set(fps)), 87)
        self.assertEqual(len(set(mechs)), 87)
        self.assertEqual(ids[86:], [build.CASE_V52W])
        self.assertEqual([row["ordinal"] for row in self.new_counted], [87])
        prior_ids = set(self.prior_summary["strict_released_case_ids"])
        self.assertEqual(set(ids) - prior_ids, {build.CASE_V52W})
        self.assertTrue(prior_ids <= set(ids))
        self.assertEqual(len(self.new_counted), 1)
        self.assertNotIn(build.CASE_V52W, prior_ids)

    def test_no_cve_alias_and_bundled_scope(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        row = self.new_counted[0]
        self.assertEqual(row["aliases"], [])
        self.assertNotIn("CVE-", "".join(ids))
        self.assertEqual(row["counted_bundled_issues"], [1, 2])
        self.assertEqual(row["excluded_bundled_issues"], [3, 4])
        self.assertIn("bundled_issue_3_readonly", self.summary["excluded"])
        self.assertIn("bundled_issue_4_compose_bind", self.summary["excluded"])
        self.assertIn("rest_body_164", self.summary["excluded"])

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

    def test_exact_candidate_carrier_fix_no_cartesian(self) -> None:
        row = self.new_counted[0]
        self.assertEqual(row["candidate_set"], [build.CAND_V52W])
        self.assertEqual(row["carrier_set"], [build.CARR_V52W])
        self.assertEqual(row["minimum_fix_set"], [build.FIX_V52W])
        self.assertEqual(row["candidate_parent"], build.PARENT_V52W)
        self.assertEqual(row["carrier_parent"], build.PARENT_V52W)
        self.assertEqual(row["fix_parent"], build.FIX_PARENT_V52W)
        self.assertNotIn("candidate_fix_edges", row)
        self.assertTrue(row["cartesian_candidate_fix_refused"])
        self.assertEqual(row["mechanism_key"], build.MECH_KEY_V52W)
        self.assertEqual(row["mechanism_fingerprint"], build.MECH_FP_V52W)
        bound = set(row["candidate_set"] + row["carrier_set"] + row["minimum_fix_set"])
        self.assertNotIn(build.REST_164, bound)
        self.assertNotIn(build.FIX_PARENT_V52W, bound)

    def test_hostile_source_pins(self) -> None:
        pins = build.pin_inputs()
        self.assertEqual(
            pins["hostile_case"]["sha256"],
            "4d0eb83d36943f1551de7c661d1ad43d53e5843d57cae316ea3fa7958d216995",
        )
        self.assertEqual(
            pins["hostile_result"]["sha256"],
            "123164d8d6be09f941bfe469256aba6ce77c9eaaba929a21e53a70ec50d58803",
        )
        self.assertEqual(
            pins["hostile_report"]["sha256"],
            "2032ee5d2b67fad9a10023014d9c337613e6c3fcd8e74a93ff0512885899e281",
        )
        self.assertEqual(
            pins["hostile_replay"]["sha256"],
            "c5ab146c7163599338a5611acb1f9f2264d6ef63e5b54c7ec4171ae40defd03c",
        )
        self.assertEqual(self.new_counted[0]["admission_source"], "v52w_hostile_redteam_keep")
        self.assertEqual(self.cap["source_hashes"]["authoritative_packet"], build.P_HOSTILE)
        self.assertEqual(self.manifest["packet_authority"][-1]["role"], "redteam")
        self.assertEqual(self.manifest["packet_authority"][-1]["authority_rank"], 45)

    def test_local_git_objects_parent_ancestry_reversal(self) -> None:
        verify.verify_git()
        self.assertEqual(verify.gitx("rev-parse", f"{build.CAND_V52W}^"), build.PARENT_V52W)
        self.assertEqual(verify.gitx("rev-parse", f"{build.CARR_V52W}^"), build.PARENT_V52W)
        self.assertEqual(verify.gitx("rev-parse", f"{build.FIX_V52W}^"), build.FIX_PARENT_V52W)

    def test_release_hashes_and_npm_containment(self) -> None:
        vuln = self.new_counted[0]["vulnerable_release"]
        fix = self.new_counted[0]["fixed_release"]
        self.assertEqual(vuln["version"], "1.8.0")
        self.assertEqual(fix["version"], "1.8.1")
        self.assertEqual(vuln["tarball_sha256"], build.NPM_180)
        self.assertEqual(fix["tarball_sha256"], build.NPM_181)
        self.assertEqual(vuln["git_tag_commit"], build.PEEL_180)
        self.assertEqual(fix["git_tag_commit"], build.PEEL_181)
        self.assertFalse(vuln["contains_allowed_hosts"])
        self.assertFalse(vuln["contains_max_body_bytes"])
        self.assertTrue(fix["contains_allowed_hosts"])
        self.assertTrue(fix["contains_max_body_bytes"])
        self.assertTrue(fix["startHttpServer_blob_equals_fix"])
        self.assertEqual(self.cap["identity"]["introduced"], "1.8.0")
        self.assertEqual(self.cap["identity"]["fixed"], "1.8.1")

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
        for case_id, ctrl in self.neg.items():
            self.assertEqual(ctrl["verdict"], "REJECT")
            self.assertFalse(ctrl["countable"])
            self.assertNotIn(case_id, ids)

    def test_no_raw_pages_clones_caches_secrets_non_ascii(self) -> None:
        owned = Path(verify.HERE)
        names = {p.name for p in owned.iterdir() if p.is_file()}
        self.assertNotIn("negative_controls.json", names)
        self.assertFalse(any(p.suffix in {".whl", ".tgz"} for p in owned.rglob("*")))
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
            (owned / "v52w_acceptance.json").read_text(),
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
        self.assertEqual(self.summary["canonical_strict_count"], 87)
        self.assertEqual(self.summary["counts"]["strict_released_first_party_ghsa"], 87)
        self.assertEqual(self.summary["counts"]["ledger_records"], 584)
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
        self.assertEqual(self.counted[85]["case_id"], build.CASE_FRVJ)


if __name__ == "__main__":
    unittest.main()
