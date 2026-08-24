#!/usr/bin/env python3
"""Regression checks for the canonical93 HOLD snapshot."""

import unittest
from copy import deepcopy
from pathlib import Path

import build
import verify


class Canonical93Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary, cls.counted = verify.verify()
        cls.rows = verify.load_rows()
        cls.hyp = verify.by_kind(cls.rows, "PRESERVED_HYPOTHESIS")
        cls.pub = verify.by_kind(cls.rows, "PRESERVED_PUBLIC_CASE")
        cls.appends = verify.by_kind(cls.rows, "APPEND_IDENTITY")
        cls.supers = verify.by_kind(cls.rows, "SUPERSEDES_EDGE")
        cls.prior_rows = build.load_jsonl(build.ROOT / build.P_C91_LEDGER)
        cls.prior_summary = build.load_json(build.ROOT / build.P_C91_SUM)
        cls.prior_counted = [
            row for row in cls.prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"
        ]
        cls.new_counted = cls.counted[build.PRIOR_STRICT :]
        cls.cap = build.load_capsule()
        cls.neg = {row["case_id"]: row for row in build.load_negative()["controls"]}
        cls.manifest = build.load_json(verify.HERE / "manifest.json")

    def test_base_prefix_byte_identity_and_hash(self) -> None:
        self.assertEqual(len(self.prior_rows), 591)
        self.assertEqual(len(self.rows), 595)
        self.assertEqual(self.rows[:591], self.prior_rows)
        prior_text = (build.ROOT / build.P_C91_LEDGER).read_text()
        current_text = (verify.HERE / "ledger.jsonl").read_text()
        self.assertTrue(current_text.startswith(prior_text if prior_text.endswith("\n") else prior_text + "\n"))
        self.assertEqual(
            build.sha256_file(build.ROOT / build.P_C91_LEDGER),
            "70b7658fadf41f18c72734a2006601961a2180681bf81353373bccab95ff659e",
        )
        self.assertEqual(len(self.prior_counted), 91)
        self.assertEqual(self.counted[:91], self.prior_counted)
        self.assertEqual(len(self.hyp), 211)
        self.assertEqual(len(self.pub), 212)
        self.assertEqual(len(self.counted), 93)
        self.assertEqual(len(self.appends), 14)
        self.assertEqual(len(self.supers), 47)
        self.assertTrue(self.summary["conservation"]["base_counted_rows_byte_identical"])
        self.assertTrue(self.summary["conservation"]["base_ledger_rows_byte_identical"])
        prior_append = self.prior_summary["conservation"]["append_identities"]
        self.assertEqual(len(prior_append), 18)
        self.assertEqual(self.summary["conservation"]["prior_append_identities"], prior_append)
        self.assertEqual(
            self.summary["conservation"]["new_append_identities"],
            [build.CASE_MFMP, build.CASE_M649],
        )
        self.assertEqual(
            self.summary["conservation"]["append_identities"],
            prior_append + [build.CASE_MFMP, build.CASE_M649],
        )
        self.assertEqual(len(self.summary["conservation"]["append_identities"]), 20)
        self.assertTrue(self.summary["conservation"]["new_identities_append"])
        self.assertFalse(self.summary["conservation"]["same_id_source_layer_promoted"])
        self.assertEqual(self.summary["conservation"]["appended_strict_rows"], 2)
        tail = current_text.splitlines()[591:]
        self.assertEqual(len(tail), 4)
        kinds = [__import__("json").loads(line)["record_kind"] for line in tail]
        self.assertEqual(
            kinds,
            ["APPEND_IDENTITY", "STRICT_RELEASED_CASE", "APPEND_IDENTITY", "STRICT_RELEASED_CASE"],
        )

    def test_ninety_three_unique_ids_two_appended(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        fps = [row["mechanism_fingerprint"] for row in self.counted]
        mechs = [row["mechanism_key"] for row in self.counted]
        self.assertEqual(len(ids), 93)
        self.assertEqual(len(set(ids)), 93)
        self.assertEqual(len(set(fps)), 93)
        self.assertEqual(len(set(mechs)), 93)
        self.assertEqual(ids[91:], [build.CASE_MFMP, build.CASE_M649])
        self.assertEqual([row["ordinal"] for row in self.new_counted], [92, 93])
        prior_ids = set(self.prior_summary["strict_released_case_ids"])
        self.assertEqual(set(ids) - prior_ids, {build.CASE_MFMP, build.CASE_M649})
        self.assertTrue(prior_ids <= set(ids))
        self.assertEqual(len(self.new_counted), 2)
        self.assertNotIn(build.CASE_MFMP, prior_ids)
        self.assertNotIn(build.CASE_M649, prior_ids)
        self.assertNotIn(build.CASE_G353, ids)
        self.assertNotIn(build.CASE_Q447, ids)
        self.assertNotIn(build.CASE_2Q7J, ids)
        self.assertNotIn(build.CASE_6C8G, ids)
        self.assertIn(build.CASE_HM7V, ids)
        self.assertIn(build.CASE_5WP8, ids)

    def test_public_id_alias_stored_never_counted(self) -> None:
        ids = [row["case_id"] for row in self.counted]
        mfmp, m649 = self.new_counted
        self.assertEqual(mfmp["aliases"], [])
        self.assertEqual(m649["aliases"], [])
        self.assertTrue(all(item.startswith("GHSA-") for item in ids))
        self.assertEqual(ids.count(build.CASE_MFMP), 1)
        self.assertEqual(ids.count(build.CASE_M649), 1)
        self.assertFalse(self.summary["conservation"]["cve_aliases_counted"])

    def test_scoped_contributor_and_shared_sha_positive_control(self) -> None:
        mfmp, m649 = self.new_counted
        self.assertEqual(mfmp["contribution_class"], "AI_SCOPED_CONTRIBUTOR")
        self.assertEqual(m649["contribution_class"], "AI_SCOPED_CONTRIBUTOR")
        self.assertFalse(mfmp["whole_ghsa_direct_root"])
        self.assertFalse(m649["whole_ghsa_direct_root"])
        self.assertEqual(mfmp["candidate_set"], m649["candidate_set"])
        self.assertEqual(mfmp["candidate_set"], [build.CAND])
        self.assertNotEqual(mfmp["minimum_fix_set"], m649["minimum_fix_set"])
        self.assertNotEqual(mfmp["mechanism_fingerprint"], m649["mechanism_fingerprint"])
        self.assertNotEqual(mfmp["scope_statement"], m649["scope_statement"])
        self.assertIn("OptionName HTML-text", mfmp["scope_statement"])
        self.assertIn("GroupRoles", mfmp["scope_statement"])
        self.assertIn("tel:", m649["scope_statement"])
        self.assertIn("mailto:", m649["scope_statement"])
        self.assertIn("data-name", m649["scope_statement"])
        self.assertIn("HM7V", m649["scope_statement"])
        self.assertTrue(self.summary["uniqueness"]["shared_candidate_sha_not_duplication"])
        self.assertTrue(self.summary["uniqueness"]["mfmp_distinct_from_m649"])
        self.assertTrue(self.summary["uniqueness"]["m649_distinct_from_counted_hm7v"])
        self.assertIn("whole_ghsa_direct_root_mfmp", self.summary["excluded"])
        self.assertIn("whole_ghsa_direct_root_m649", self.summary["excluded"])
        self.assertIn("shared_closer_hm7v_m649", self.summary["excluded"])
        self.assertIn(build.CASE_G353, self.summary["excluded"])
        hm7v = next(row for row in self.counted if row["case_id"] == build.CASE_HM7V)
        self.assertIn(build.FIX_M649, hm7v["minimum_fix_set"])
        self.assertNotEqual(hm7v["mechanism_key"], m649["mechanism_key"])

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
        mfmp, m649 = self.new_counted
        self.assertEqual(mfmp["candidate_set"], [build.CAND])
        self.assertEqual(m649["candidate_set"], [build.CAND])
        self.assertEqual(mfmp["carrier_set"], [build.CAND])
        self.assertEqual(m649["carrier_set"], [build.CAND])
        self.assertEqual(mfmp["candidate_set"], mfmp["carrier_set"])
        self.assertEqual(m649["candidate_set"], m649["carrier_set"])
        self.assertEqual(mfmp["minimum_fix_set"], [build.FIX_MFMP])
        self.assertEqual(m649["minimum_fix_set"], [build.FIX_M649])
        self.assertEqual(mfmp["candidate_parent"], build.PARENT)
        self.assertEqual(m649["candidate_parent"], build.PARENT)
        self.assertEqual(mfmp["fix_parent"], build.FIX_PARENT_MFMP)
        self.assertEqual(m649["fix_parent"], build.FIX_PARENT_M649)
        self.assertNotIn("candidate_fix_edges", mfmp)
        self.assertNotIn("candidate_fix_edges", m649)
        self.assertTrue(mfmp["cartesian_candidate_fix_refused"])
        self.assertTrue(m649["cartesian_candidate_fix_refused"])
        self.assertEqual(mfmp["mechanism_key"], build.MECH_KEY_MFMP)
        self.assertEqual(m649["mechanism_key"], build.MECH_KEY_M649)
        self.assertNotIn(build.MEM_0EA20, mfmp["candidate_set"])
        self.assertNotIn(build.MEM_0EA20, m649["candidate_set"])
        self.assertNotIn(build.MEM_5631, m649["candidate_set"])
        self.assertNotIn(build.MEM_5631, m649["minimum_fix_set"])

    def test_dual_packet_pins_and_exclusions(self) -> None:
        pins = build.pin_inputs()
        self.assertEqual(
            pins["nearclosed_result"]["sha256"],
            "5ff70d476b1e30acd41b156c53d9f66b4acfdfc27a6ead70ef8d68a44892e912",
        )
        self.assertEqual(
            pins["hostile_result"]["sha256"],
            "ad71f4488df0d9a50392df0ff7bc106851c3f095ea64d57161bd6e823cafad18",
        )
        self.assertEqual(
            pins["nearclosed_cases"]["sha256"],
            "203963af356be6bd0bc9c780f1f10ae0a7d8ca956a291d693bb03901edd7e1be",
        )
        self.assertEqual(
            pins["hostile_cases"]["sha256"],
            "2090af09f332c9d6e26671445f9eddef8995334ff4b88a2700237fa03d77fbaf",
        )
        self.assertEqual(
            pins["fp211_public_cases"]["sha256"],
            "e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257",
        )
        self.assertEqual(
            pins["research_truth_layers"]["sha256"],
            "70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f",
        )
        self.assertEqual(self.new_counted[0]["admission_source"], "scoped_contributor_wave_l_dual_keep")
        self.assertEqual(self.cap["source_hashes"]["nearclosed_l_packet"], build.P_NEAR)
        self.assertEqual(self.cap["source_hashes"]["hostile_packet"], build.P_HOSTILE)
        self.assertEqual(self.cap["excluded_from_this_promotion"], [build.CASE_G353])
        self.assertEqual(self.manifest["packet_authority"][-2]["packet"], build.P_NEAR)
        self.assertEqual(self.manifest["packet_authority"][-1]["packet"], build.P_HOSTILE)
        self.assertEqual(self.manifest["packet_authority"][-2]["authority_rank"], 51)
        self.assertEqual(self.manifest["packet_authority"][-1]["authority_rank"], 52)
        ids = [row["case_id"] for row in self.counted]
        self.assertNotIn(build.CASE_G353, ids)
        self.assertNotIn(build.CASE_Q447, ids)
        self.assertNotIn(build.CASE_2Q7J, ids)
        self.assertFalse(
            any(row["case_id"] in (build.CASE_MFMP, build.CASE_M649) for row in self.supers)
        )

    def test_local_git_objects_parent_ancestry_reversal(self) -> None:
        self.assertEqual(
            verify.gitx("rev-parse", f"{build.CAND}^", repo=verify.CLONE),
            build.PARENT,
        )
        self.assertEqual(
            verify.gitx("rev-parse", f"{build.FIX_MFMP}^", repo=verify.CLONE),
            build.FIX_PARENT_MFMP,
        )
        self.assertEqual(
            verify.gitx("rev-parse", f"{build.FIX_M649}^", repo=verify.CLONE),
            build.FIX_PARENT_M649,
        )
        self.assertFalse(verify.is_ancestor(verify.CLONE, build.MEM_0EA20, build.CAND))
        self.assertFalse(verify.is_ancestor(verify.CLONE, build.FIX_MFMP, build.PEEL_742))
        self.assertFalse(verify.is_ancestor(verify.CLONE, build.FIX_M649, build.PEEL_751))

    def test_release_hashes_and_containment(self) -> None:
        mfmp, m649 = self.new_counted
        self.assertEqual(mfmp["vulnerable_release"]["tag"], "7.4.2")
        self.assertEqual(mfmp["fixed_release"]["tag"], "7.4.3")
        self.assertEqual(mfmp["vulnerable_release"]["git_tag_commit"], build.PEEL_742)
        self.assertEqual(mfmp["fixed_release"]["git_tag_commit"], build.PEEL_743)
        self.assertTrue(mfmp["vulnerable_release"]["contains_candidate_any_parent"])
        self.assertFalse(mfmp["vulnerable_release"]["contains_fix_any_parent"])
        self.assertTrue(mfmp["fixed_release"]["contains_fix_any_parent"])
        self.assertEqual(m649["vulnerable_release"]["tag"], "7.5.1")
        self.assertEqual(m649["fixed_release"]["tag"], "7.6.0")
        self.assertEqual(m649["vulnerable_release"]["git_tag_commit"], build.PEEL_751)
        self.assertEqual(m649["fixed_release"]["git_tag_commit"], build.PEEL_760)
        self.assertTrue(m649["vulnerable_release"]["contains_candidate_any_parent"])
        self.assertFalse(m649["vulnerable_release"]["contains_fix_any_parent"])
        self.assertTrue(m649["fixed_release"]["contains_fix_any_parent"])

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
        self.assertEqual(self.summary["canonical_strict_count"], 93)
        self.assertEqual(self.summary["counts"]["strict_released_first_party_ghsa"], 93)
        self.assertEqual(self.summary["counts"]["ledger_records"], 595)
        self.assertEqual(self.summary["counts"]["by_record_kind"]["APPEND_IDENTITY"], 14)
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
        self.assertEqual(self.counted[90]["case_id"], build.CASE_5WP8)
        self.assertEqual(self.counted[91]["case_id"], build.CASE_MFMP)
        self.assertEqual(self.counted[92]["case_id"], build.CASE_M649)


if __name__ == "__main__":
    unittest.main()
