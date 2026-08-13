#!/usr/bin/env python3
"""Small regression check for the generated canonical HOLD ledger."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import verify


class CanonicalLedgerTest(unittest.TestCase):
    def test_no_live_result_write_preserves_live_evidence_and_is_stable(self) -> None:
        previous = verify.load_json(verify.HERE / "result.json")
        with TemporaryDirectory() as tmp:
            here = Path(tmp)
            for name, content in (("ledger.jsonl", "{}\n"), ("source_manifest.json", "{}\n"), ("summary.json", "{}\n")):
                (here / name).write_text(content)
            summary = {
                "ledger_sha256": verify.sha256(here / "ledger.jsonl"),
                "source_manifest_sha256": verify.sha256(here / "source_manifest.json"),
                "counts": previous["structural_counts"],
                "source_envelopes": {"strict_document_rows": 134, "broad_released_max": 199, "widest_max": 211},
                "blockers": previous["blockers"],
            }
            previous.update(
                ledger_sha256=summary["ledger_sha256"],
                source_manifest_sha256=summary["source_manifest_sha256"],
                summary_sha256=verify.sha256(here / "summary.json"),
            )
            result_path = here / "result.json"
            result_path.write_text(json.dumps(previous, ensure_ascii=False, indent=2, sort_keys=True) + "\n")

            def structural(*, check_result: bool = True):
                self.assertFalse(check_result)
                verify.verify_result_hashes(summary)
                return summary, [], [{}] * previous["route_controls"]

            with (
                patch.object(verify, "HERE", here),
                patch.object(verify, "verify_structural", side_effect=structural),
                patch.object(sys, "argv", ["verify.py", "--write-result"]),
            ):
                before = result_path.read_bytes()
                verify.main()
                verify.main()
                self.assertEqual(result_path.read_bytes(), before)
                (here / "ledger.jsonl").write_text("stale\n")
                with self.assertRaises(AssertionError):
                    verify.main()
                self.assertEqual(result_path.read_bytes(), before)

    def test_structural_contract(self) -> None:
        summary, additions, controls = verify.verify_structural()
        self.assertFalse(summary["integration_ready"])
        self.assertEqual(summary["source_envelopes"]["broad_released_max"], 199)
        self.assertEqual(summary["counts"]["canonical_source_components"], 211)
        self.assertEqual(
            summary["counts"]["released_rows_by_state"],
            {"PASS": 144, "NARROW": 24, "UNKNOWN": 8, "REJECT": 23},
        )
        self.assertEqual(summary["source_envelopes"]["strict_document_rows"], 134)
        self.assertEqual(len(additions), 30)
        self.assertEqual(len(controls), 30)
        self.assertEqual(
            {state: sum(row["row_state"] == state for row in controls) for state in ("REJECT", "UNKNOWN")},
            {"REJECT": 29, "UNKNOWN": 1},
        )

        zae = next(
            row
            for row in verify.load_jsonl(verify.HERE / "ledger.jsonl")
            if row["row_key"] == "strict-200-v3:alias-99ee5f834a00aca5862a1926"
        )
        self.assertEqual(zae["candidate_fix_edges"][0]["fix_sha"], "9f66c42f06f3b87107ce327bede6416a582f0e60")
        self.assertEqual(zae["release_evidence"]["fix_sha"], "481ce44d818d66e31d8837bc48519660ce4c267f")
        self.assertEqual(len(zae["atomic_fix_members"]), 6)

        ha_mcp = next(
            row
            for row in verify.load_jsonl(verify.HERE / "ledger.jsonl")
            if row["row_key"] == "strict-200-v3:alias-02fb7aeb21b9f4e1ab18fbce"
        )
        self.assertEqual(ha_mcp["atomic_fix_members"], ["0ca572a1452cbabc9004993d6a649afa3c0f435d"])
        self.assertEqual(ha_mcp["release_evidence"]["fix_sha"], "dc8eaa16a8550f885614655f14b6fd9fe429b278")

        mysti = next(
            row
            for row in verify.load_jsonl(verify.HERE / "ledger.jsonl")
            if row["row_key"] == "strict-200-v3:alias-08f4ee97e5be53cda71a58d8"
        )
        self.assertEqual(mysti["atomic_fix_members"], ["c6daf9107a8dc14088feff4671657e6319e36628"])
        self.assertEqual(mysti["release_evidence"]["fix_sha"], "6d709229b5199f6769fb3cf763e5122dcc43c079")
        self.assertIsNone(mysti["release_evidence"]["fixed_tag"])

        attachments = next(
            row
            for row in verify.load_jsonl(verify.HERE / "ledger.jsonl")
            if row["row_key"] == "strict-200-v3:alias-b2364e4376391dd977cef4fa"
        )
        self.assertEqual(attachments["row_state"], "REJECT")
        quay = next(
            row
            for row in verify.load_jsonl(verify.HERE / "ledger.jsonl")
            if row["row_key"] == "strict-200-v3:alias-994d3f3f9e29079393c87538"
        )
        self.assertEqual(quay["row_state"], "UNKNOWN")
        media = next(
            row
            for row in verify.load_jsonl(verify.HERE / "ledger.jsonl")
            if row["row_key"] == "strict-200-v3:alias-948cde45baab136c086accc3"
        )
        self.assertEqual(media["candidate_fix_edges"][0]["fix_sha"], "f865a5455ee03924a444e9ba0f1c4743d8fb6566")
        self.assertEqual(media["row_state"], "PASS")

        ledger = verify.load_jsonl(verify.HERE / "ledger.jsonl")
        graphiti = next(row for row in ledger if row["row_key"] == "strict-200-v3:alias-081a549b9da97e4d5e1e54c4")
        self.assertEqual(graphiti["row_state"], "UNKNOWN")
        self.assertEqual(graphiti["candidate_fix_edges"][0]["candidate_sha"], "1d94f7a3e3cebeba404aa4b48cf3d0742750595f")
        coder = next(row for row in ledger if row["row_key"] == "strict-200-v3:alias-ed3fab545510d72c9e9ecc14")
        self.assertEqual(coder["row_state"], "REJECT")
        self.assertIsNone(coder["release_evidence"]["vulnerable_tag"])
        actual = next(row for row in ledger if row["row_key"] == "strict-200-v3:alias-3ed594d20d11056d42d54528")
        self.assertEqual(actual["row_state"], "PASS")
        self.assertEqual(actual["atomic_fix_members"], ["48699c46b1b5cc296bc76dd637edb47b0c02d926"])
        faraday = next(row for row in ledger if row["row_key"] == "post:faraday-uri-authority@canonical")
        self.assertEqual(faraday["row_state"], "PASS")
        self.assertEqual(faraday["candidate_fix_edges"][0]["candidate_sha"], "a6d3a3a0bf59c2ab307d0abd91bc126aef5561bc")
        mruby = next(row for row in ledger if row["row_key"] == "strict-200-v3:alias-0c32bc35f9b2fdfd939667e3")
        self.assertEqual(mruby["row_state"], "REJECT")
        mlflow = next(row for row in ledger if row["row_key"] == "strict-200-v3:alias-125fe49a49acf7ef2baeb111")
        self.assertEqual(mlflow["row_state"], "PASS")
        self.assertEqual(mlflow["candidate_fix_edges"][0]["candidate_sha"], "3e590361e0e251382ae30cbc9993d604bfdb67d5")
        garmin = next(row for row in ledger if row["row_key"] == "strict-200-v3:alias-4018863fbab23917960da976")
        self.assertEqual(garmin["row_state"], "PASS")
        self.assertEqual(garmin["atomic_fix_members"], ["77a3837f1f79d486663c9646438e70e8319e1a48"])
        solidcam = next(row for row in ledger if row["row_key"] == "strict-200-v3:alias-061ebce41071bc874d061809")
        self.assertEqual(solidcam["row_state"], "PASS")
        self.assertIn("GHSA-92VG-F4FQ-FXM9", solidcam["public_ids"])
        grep = next(row for row in ledger if row["row_key"] == "strict-200-v3:alias-2b440d3fa3dacafd8d29beca")
        self.assertEqual(grep["row_state"], "REJECT")
        feishu = next(row for row in ledger if row["row_key"] == "strict-200-v3:alias-9c7a2c50a4f4725177cca843")
        self.assertEqual(feishu["row_state"], "UNKNOWN")
        kiro = next(row for row in ledger if row["row_key"] == "strict-200-v3:alias-bd1a0da23e1a76c824287b27")
        self.assertEqual(kiro["row_state"], "PASS")
        sortcmp = next(row for row in ledger if row["row_key"] == "strict-200-v3:alias-c819cf08c0a8bf17cf425ccc")
        self.assertEqual(sortcmp["row_state"], "REJECT")
        self.assertIsNone(sortcmp["release_evidence"]["vulnerable_tag"])
        guard = next(row for row in ledger if row["row_key"] == "strict-200-v3:component-openclaw-gateway-config-guard")
        self.assertEqual(guard["row_state"], "REJECT")
        sipsorcery = next(row for row in ledger if row["row_key"] == "posthold:I01")
        self.assertEqual(sipsorcery["row_state"], "PASS")
        relyra = next(row for row in ledger if row["row_key"] == "posthold:I02")
        self.assertEqual(relyra["row_state"], "NARROW")
        for row_key in ("post:scriban-lazy-range@canonical", "post:gitpython-split-mode@canonical"):
            duplicate = next(row for row in ledger if row["row_key"] == row_key)
            self.assertEqual(duplicate["row_state"], "DUPLICATE")
            self.assertFalse(any(duplicate["counting"].values()))

    def test_live_requires_cache_root(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            verify.require_live_cache_root(None)
        self.assertEqual(str(ctx.exception), "ERROR: --live requires --cache-root")

    def test_live_cache_root_must_be_a_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing-cache-root"
            with self.assertRaises(SystemExit) as ctx:
                verify.require_live_cache_root(missing)
            self.assertEqual(str(ctx.exception), f"ERROR: live cache root not found: {missing.resolve()}")

    def test_live_cache_repo_must_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(SystemExit) as ctx:
                verify.live_cache_repo(root, "v2_missing")
            self.assertEqual(str(ctx.exception), f"ERROR: live cache repository not found: {root / 'v2_missing'}")

    def test_live_cache_object_must_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / ".git").mkdir()
            with self.assertRaises(SystemExit) as ctx:
                verify.require_live_cache_object(repo, "v1.24.0")
            self.assertEqual(str(ctx.exception), f"ERROR: live cache object not found: {repo}:v1.24.0")

    def test_live_cache_is_not_checkout_relative(self) -> None:
        source = Path(verify.__file__).read_text()
        self.assertIn('parser.add_argument("--cache-root"', source)
        self.assertNotIn('ROOT / ".ai-slop/cache', source)
        self.assertNotIn("LIVE_CACHE_ROWS", source)


if __name__ == "__main__":
    unittest.main()
