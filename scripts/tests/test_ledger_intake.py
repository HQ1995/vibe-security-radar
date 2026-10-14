from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("ledger_intake_under_test", SCRIPTS / "ledger_store.py")
store = importlib.util.module_from_spec(spec)
spec.loader.exec_module(store)


class Result:
    def __init__(self, rows=()):
        self.rows = list(rows)

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


class FakeDB:
    def __init__(self, rows=(), fail_history=False, fail_commit=False):
        self.rows = {r["class_id"]: (n, store.raw_row(r)) for n, r in enumerate(rows)}
        self.versions, self.changes, self.events = [], [], []
        self.fail_history, self.fail_commit = fail_history, fail_commit

    def __enter__(self):
        self.before = deepcopy((self.rows, self.versions, self.changes))
        self.events.append("begin")
        return self

    def __exit__(self, kind, value, traceback):
        if kind is not None or self.fail_commit:
            self.rows, self.versions, self.changes = self.before
            self.events.append("rollback")
            if kind is None:
                raise RuntimeError("fixture commit failure")
        else:
            self.events.append("commit")

    def snapshot(self):
        return "".join(raw + "\n" for _, raw in sorted(self.rows.values())).encode()

    def execute(self, sql, params=()):
        text = " ".join(sql.split())
        if text.startswith("LOCK TABLE"):
            self.events.append(text)
        elif sql == store.SNAPSHOT_SHA256_SQL:
            self.events.append("snapshot_digest")
            value = store.sha256(self.snapshot())
            if hasattr(self, "after_digest"):
                self.after_digest()
            return Result([(value,)])
        elif text == "SELECT COALESCE(MAX(ordinal), -1) + 1 FROM ledger_rows":
            self.events.append("next_ordinal")
            return Result([(max((ordinal for ordinal, _ in self.rows.values()), default=-1) + 1,)])
        elif text.startswith("INSERT INTO ledger_change_sets"):
            self.changes.append(params)
            self.events.append("changeset")
        elif text.startswith("UPDATE ledger_change_sets"):
            self.events.append("committed_at")
        else:
            raise AssertionError(f"Unexpected SQL: {text}")
        return Result()

    def cursor(self):
        db = self

        class Cursor:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def executemany(self, sql, params):
                text = " ".join(sql.split())
                db.events.append(text)
                for values in params:
                    if text.startswith("INSERT INTO ledger_rows"):
                        cid, ordinal, status, repo, ids, raw, changeset, actor = values
                        if cid in db.rows or ordinal in {v[0] for v in db.rows.values()}:
                            raise RuntimeError("fixture unique violation")
                        assert status == "UNANALYZED"
                        assert json.loads(raw)["advisory_ids"] == ids
                        assert "1, %s, %s)" in text
                        db.rows[cid] = (ordinal, raw)
                    elif text.startswith("INSERT INTO ledger_versions"):
                        if db.fail_history:
                            raise RuntimeError("fixture history failure")
                        assert "'IMPORT'" in text and "%s, 1, %s" in text
                        cid, changeset, raw, checksum, actor = values
                        assert store.sha256(raw) == checksum
                        db.versions.append(values)
                    else:
                        raise AssertionError(text)

        return Cursor()


class IntakeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.file = self.root / "intake.jsonl"
        self.files = {}
        self.ledger = self.root / "verified-export.jsonl"
        ledger_patch = patch.object(store, "DEFAULT_LEDGER", self.ledger)
        ledger_patch.start()
        self.addCleanup(ledger_patch.stop)
        jsonb = types.ModuleType("psycopg.types.json")
        jsonb.Jsonb = lambda value: value
        modules = {"psycopg": types.ModuleType("psycopg"),
                   "psycopg.types": types.ModuleType("psycopg.types"),
                   "psycopg.types.json": jsonb}
        self.patcher = patch.dict(sys.modules, modules)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def row(self, ident="CVE-2026-10000", *, aliases=()):
        item = {"id": ident, "published": "2026-09-01T00:00:00Z",
                "identifiers": [{"value": alias} for alias in aliases]}
        path = self.root / (ident + ".json")
        path.write_text(json.dumps([item]))
        ids = {ident.upper(), *(i.upper() for i in aliases)}
        row = {
            "class_id": store.intake_class_id(ids), "status": "UNANALYZED",
            "advisory_ids": [ident], "repo": "acme/product",
            "source_intake": {
                "window": {"start": "2026-08-26T00:00:00Z", "end": "2026-09-26T20:42:47Z"},
                "delta_sha256": "d" * 64,
                "records": [{
                    "path": str(path), "pointer": "/0",
                    "sha256": store.sha256(json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False)),
                }],
                "repository_mapping": {"repository": "acme/product", "basis": "fixture corroborated product source"},
            },
        }
        if aliases:
            row["advisory_aliases"] = list(aliases)
        return row

    def call(self, rows, db=None, guard=None, *, export_bytes=None):
        self.file.write_text("".join(json.dumps(r) + "\n" for r in rows))
        db = db or FakeDB()
        self.ledger.write_bytes(db.snapshot() if export_bytes is None else export_bytes)
        guard = guard if guard is not None else Mock(return_value=[])
        export = Mock(side_effect=lambda path: db.events.append("export"))
        with patch.object(store, "connect", return_value=db) as connect, \
                patch.object(store, "foreign_active_claims", guard), \
                patch.object(store, "export_jsonl_incremental", export), \
                patch("builtins.print"):
            result = store.intake(self.file, "leader", "fixture intake")
        connect.assert_called_once_with(write=True)
        return result, db, guard, export

    def test_append_revision_one_import_and_export_after_commit(self):
        old = {"class_id": "old", "status": "NOT_AI", "advisory_ids": ["CVE-2026-99999"]}
        row = self.row()
        result, db, guard, export = self.call([row], FakeDB([old]))
        self.assertEqual(result["inserted"], [row["class_id"]])
        self.assertEqual(db.rows[row["class_id"]][0], 1)
        self.assertEqual(len(db.versions), 1)
        self.assertEqual(len(db.changes), 1)
        self.assertEqual(db.events[1], "LOCK TABLE ledger_rows IN SHARE ROW EXCLUSIVE MODE")
        self.assertLess(db.events.index("commit"), db.events.index("export"))
        self.assertEqual(json.loads(db.rows["old"][1]), old)
        self.assertEqual(guard.call_count, 2)

    def test_exact_repeat_no_history_or_changeset_and_repairs_export(self):
        row = self.row()
        _, db, _, _ = self.call([row])
        old = deepcopy((db.rows, db.versions, db.changes))
        result, db, _, export = self.call([deepcopy(row)], db)
        self.assertEqual(result["inserted"], [])
        self.assertEqual(result["skipped_exact"], [row["class_id"]])
        self.assertIsNone(result["change_set_id"])
        self.assertEqual((db.rows, db.versions, db.changes), old)
        export.assert_called_once()

    def test_global_source_nullable_identifiers_and_typed_identity_boundary(self):
        ident, alias = "GHSA-2345-6789-cfgh", "GHSA-2345-6789-jmpq"
        for identifiers, valid in (
            (None, True), ([], True), ([{"type": "GHSA", "value": ident}], True),
            ("invalid", False), ([42], False),
            ([{"type": "CVE", "value": ident}], False),
            ([{"type": "GHSA", "value": alias}], False),
        ):
            with self.subTest(identifiers=identifiers):
                row = self.row(ident)
                record = row["source_intake"]["records"][0]
                item = {"ghsa_id": ident, "cve_id": None, "identifiers": identifiers}
                Path(record["path"]).write_text(json.dumps([item]))
                record["sha256"] = store.sha256(json.dumps(
                    item, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
                if valid:
                    _, db, _, _ = self.call([row])
                    self.assertIn(row["class_id"], db.rows)
                else:
                    with self.assertRaisesRegex(ValueError, "identifier"):
                        store.validate_intake_row(row, {})

        for fields in (
            {"ghsa_id": None}, {"ghsa_id": "CVE-2026-10000"},
            {"cve_id": ident}, {"cve_id": True}, {"cve_id": 42},
        ):
            with self.subTest(fields=fields):
                row = self.row(ident)
                record = row["source_intake"]["records"][0]
                item = {"ghsa_id": ident, "cve_id": None, "identifiers": [], **fields}
                Path(record["path"]).write_text(json.dumps([item]))
                record["sha256"] = store.sha256(json.dumps(
                    item, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
                with self.assertRaisesRegex(ValueError, "type/value mismatch"):
                    store.validate_intake_row(row, {})

    def test_intake_window_matches_capture_precision_and_utc_syntax(self):
        for start, valid in (
            ("2026-08-26t00:00:00z", True),
            ("2026-08-26T00:00:00.123456000Z", True),
            ("2026-08-26T00:00:00.1234561Z", False),
            ("2026-08-26T00:00:00,1234561Z", False),
            ("20260826T000000Z", False),
        ):
            with self.subTest(start=start):
                row = self.row()
                row["source_intake"]["window"]["start"] = start
                if valid:
                    store.validate_intake_row(row, {})
                else:
                    with self.assertRaisesRegex(ValueError, "ordered UTC"):
                        store.validate_intake_row(row, {})

    def test_two_increment_windows_append_once_and_repeat_without_history(self):
        old = {"class_id": "legacy", "status": "NOT_AI", "advisory_ids": ["CVE-2025-99999"]}
        first, second = self.row(), self.row("CVE-2026-10001")
        second["source_intake"]["window"] = {
            "start": first["source_intake"]["window"]["end"], "end": "2026-09-27T00:00:00Z"}
        _, db, _, _ = self.call([first], FakeDB([old]))
        legacy_bytes = db.rows["legacy"]
        result, db, _, _ = self.call([first, second], db)
        self.assertEqual(result["inserted"], [second["class_id"]])
        self.assertEqual(result["skipped_exact"], [first["class_id"]])
        self.assertEqual((len(db.rows), len(db.versions), len(db.changes)), (3, 2, 2))
        self.assertEqual(db.rows["legacy"], legacy_bytes)
        self.assertEqual({v[0] for v in db.rows.values()}, {0, 1, 2})
        before = deepcopy((db.rows, db.versions, db.changes))
        result, db, _, _ = self.call([second, first], db)
        self.assertIsNone(result["change_set_id"])
        self.assertEqual(result["inserted"], [])
        self.assertEqual((db.rows, db.versions, db.changes), before)

    def test_existing_class_different_payload_rejected(self):
        row = self.row()
        db = FakeDB([row])
        changed = deepcopy(row)
        changed["source_intake"]["repository_mapping"]["basis"] = "changed"
        with self.assertRaisesRegex(ValueError, "different payload"):
            self.call([changed], db)
        self.assertEqual(len(db.changes), 0)
        self.assertEqual(db.events[-1], "rollback")

    def test_collision_case_insensitive_primary_and_all_trusted_alias_fields(self):
        ident = "GHSA-2345-6789-cfgh"
        row = self.row(ident)
        shapes = [
            {"advisory_ids": [ident.lower()]},
            {"advisory_ids": ["CVE-2026-99999"], "advisory_aliases": [ident.lower()]},
            {"advisory_ids": ["CVE-2026-99999"], "advisory_aliases": [{"id": ident.lower()}]},
            {"advisory_ids": ["CVE-2026-99999"], "advisory_identity": {"member_ids": [ident.lower()]}},
        ]
        for shape in shapes:
            with self.subTest(shape=shape):
                db = FakeDB([{"class_id": "other", "status": "NOT_AI", **shape}])
                with self.assertRaisesRegex(ValueError, "advisory ID overlap"):
                    self.call([row], db)
                self.assertEqual(len(db.changes), 0)

    def test_overlap_inside_batch_aborts_all_rows(self):
        common = "GHSA-2345-6789-cfgh"
        a, b = self.row(aliases=[common]), self.row("CVE-2026-10001", aliases=[common.upper()])
        db = FakeDB()
        with self.assertRaisesRegex(ValueError, "advisory ID overlap"):
            self.call([a, b], db)
        self.assertEqual(db.rows, {})
        self.assertEqual(db.changes, [])

    def test_invalid_status_ids_and_provenance_rejected_before_connect(self):
        modifications = [
            lambda r: r.update(status="NOT_AI"),
            lambda r: r.update(advisory_ids=[]),
            lambda r: r.update(advisory_ids=["https://example.test/advisory"]),
            lambda r: r.update(advisory_ids=["CVE-2026-10000", "cve-2026-10000"]),
            lambda r: r.update(class_id="arbitrary"),
            lambda r: r.pop("source_intake"),
            lambda r: r["source_intake"].update(delta_sha256="not a hash"),
            lambda r: r["source_intake"].update(records=[]),
            lambda r: r["source_intake"]["window"].update(start="2026-01-01"),
            lambda r: r["source_intake"]["repository_mapping"].update(repository="other/product"),
        ]
        for modify in modifications:
            row = self.row()
            modify(row)
            self.file.write_text(json.dumps(row) + "\n")
            with self.subTest(modify=modify), patch.object(store, "connect") as connect:
                with self.assertRaises(ValueError):
                    store.intake(self.file, "leader", "fixture")
                connect.assert_not_called()

    def test_invalid_pointer_hash_and_hidden_source_alias_rejected(self):
        for mutation in ["pointer", "sha256", "source_alias"]:
            row = self.row()
            ref = row["source_intake"]["records"][0]
            if mutation == "pointer":
                ref["pointer"] = "/99"
            elif mutation == "sha256":
                ref["sha256"] = "0" * 64
            else:
                data = {"id": "CVE-2026-10000", "cve_id": "CVE-2026-10001"}
                Path(ref["path"]).write_text(json.dumps([data]))
                ref["sha256"] = store.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                store.validate_intake_row(row, {})

    def test_prior_identity_pin_justifies_preserved_id(self):
        row = self.row(aliases=["GHSA-2345-6789-cfgh"])
        old_id = store.intake_class_id({"CVE-2026-10000"})
        prior = self.root / "prior.jsonl"
        prior.write_text(json.dumps({"class_id": old_id, "public_ids": ["CVE-2026-10000"]}) + "\n")
        row["class_id"] = old_id
        with self.assertRaisesRegex(ValueError, "prior_identity"):
            store.validate_intake_row(row, {})
        row["source_intake"]["prior_identity"] = {
            "path": str(prior), "sha256": store.sha256(prior.read_bytes()), "line": 1,
        }
        store.validate_intake_row(row, {})
        row["source_intake"]["prior_identity"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "file hash mismatch"):
            store.validate_intake_row(row, {})

    def test_failed_history_or_commit_rolls_back_without_export(self):
        for option in ["fail_history", "fail_commit"]:
            row = self.row()
            db = FakeDB(**{option: True})
            self.ledger.write_bytes(db.snapshot())
            self.file.write_text(json.dumps(row) + "\n")
            with patch.object(store, "connect", return_value=db), \
                    patch.object(store, "foreign_active_claims", return_value=[]), \
                    patch.object(store, "export_jsonl_incremental") as export:
                with self.assertRaises(RuntimeError):
                    store.intake(self.file, "leader", "fixture")
                export.assert_not_called()
            self.assertEqual((db.rows, db.versions, db.changes), ({}, [], []))

    def test_claims_cover_class_public_ids_and_are_rechecked_under_lock(self):
        row = self.row(aliases=["GHSA-2345-6789-cfgh"])
        result, db, guard, export = self.call([row])
        for call in guard.call_args_list:
            self.assertEqual(call.args[0], {row["class_id"], "CVE-2026-10000", "GHSA-2345-6789-CFGH"})
        guard = Mock(side_effect=[[], [{"owner": "other", "class_id": "CVE-2026-10000"}]])
        db = FakeDB()
        with self.assertRaisesRegex(ValueError, "foreign active claims"):
            self.call([row], db, guard)
        self.assertEqual(db.rows, {})
        self.assertEqual(db.events[-1], "rollback")

    def test_foreign_claim_blocks_before_database(self):
        row = self.row()
        self.file.write_text(json.dumps(row) + "\n")
        with patch.object(store, "foreign_active_claims", return_value=[{"owner": "other"}]), \
                patch.object(store, "connect") as connect:
            with self.assertRaisesRegex(ValueError, "foreign active claims"):
                store.intake(self.file, "leader", "fixture")
            connect.assert_not_called()

    def test_claims_api_preserves_expiry_slots_and_casefold_public_ids(self):
        path = self.root / "claims.jsonl"
        events = [{"fixture": "events"}]
        states = {("ghsa-2345-6789-cfgh", "historical"): {
            "slot": "historical", "owner": "foreign", "claimed": True,
            "lease_until": "2000-01-02T00:00:00Z", "expired": True,
        }}
        api = types.SimpleNamespace(load=Mock(return_value=events),
                                    state=Mock(return_value=states), DEFAULT_CLAIMS=path)
        with patch.dict(sys.modules, {"claims": api}):
            blockers = store.foreign_active_claims({"GHSA-2345-6789-CFGH"}, "leader")
            self.assertEqual(len(blockers), 1)
            self.assertEqual(blockers[0]["slot"], "historical")
            self.assertEqual(store.foreign_active_claims({"GHSA-2345-6789-CFGH"}, "foreign"), [])
            states[("ghsa-2345-6789-cfgh", "historical")]["claimed"] = False
            self.assertEqual(store.foreign_active_claims({"GHSA-2345-6789-CFGH"}, "leader"), [])
        api.load.assert_called_with(path)
        api.state.assert_called_with(events)

    def test_claims_api_errors_propagate(self):
        api = types.SimpleNamespace(load=Mock(return_value=[]),
                                    state=Mock(side_effect=ValueError("invalid claim receipt")),
                                    DEFAULT_CLAIMS=self.root / "claims")
        with patch.dict(sys.modules, {"claims": api}), self.assertRaisesRegex(ValueError, "invalid claim"):
            store.foreign_active_claims({"x"}, "leader")

    def test_apply_updates_existing_foreign_guard_is_preserved(self):
        holder = {"class_id": "occupied", "slot": "main", "owner": "foreign",
                  "lease_until": "2000-01-01"}
        with patch.object(store, "read_patches", return_value=[{"row": {"class_id": "occupied"}}]), \
                patch.object(store, "foreign_active_claims", return_value=[holder]), \
                patch.object(store, "connect") as connect:
            with self.assertRaisesRegex(SystemExit, "expiry does not release occupancy"):
                store.apply_updates(self.file, "leader", "fixture")
            connect.assert_not_called()

    def test_invented_extra_identity_is_not_justified_by_computed_hash(self):
        row = self.row()
        row["advisory_aliases"] = ["GHSA-2345-6789-cfgh"]
        row["class_id"] = store.intake_class_id(store.intake_public_ids(row))
        with self.assertRaisesRegex(ValueError, "prior_identity"):
            store.validate_intake_row(row, {})

    def test_source_union_and_pinned_prior_must_cover_every_id(self):
        row = self.row("CVE-2026-10001")
        row["advisory_ids"].append("CVE-2026-10000")
        old_id = store.intake_class_id({"CVE-2026-10000"})
        row["class_id"] = old_id
        prior = self.root / "prior-union.jsonl"
        prior.write_text(json.dumps({"class_id": old_id, "public_ids": ["CVE-2026-10000"]}) + "\n")
        row["source_intake"]["prior_identity"] = {
            "path": str(prior), "sha256": store.sha256(prior.read_bytes()), "line": 1,
        }
        store.validate_intake_row(row, {})
        row["advisory_aliases"] = ["GHSA-2345-6789-cfgh"]
        with self.assertRaisesRegex(ValueError, "not covered"):
            store.validate_intake_row(row, {})

    def test_escaped_nul_legacy_payload_survives_without_json_cast_or_rewrite(self):
        old = {
            "class_id": "old", "status": "NOT_AI", "advisory_ids": ["CVE-2026-99999"],
            "advisory_aliases": ["GHSA-2345-6789-cfgh"],
            "causal_research": {"reasoning": "scan until character " + chr(0)},
        }
        db = FakeDB([old])
        before = db.rows["old"]
        self.assertIn(chr(92) + "u0000", before[1])
        self.assertIn(chr(0), json.loads(before[1])["causal_research"]["reasoning"])
        row = self.row()
        result, db, _, _ = self.call([row], db)
        self.assertEqual(result["inserted"], [row["class_id"]])
        self.assertEqual(db.rows["old"], before)
        self.assertLess(db.events.index("LOCK TABLE ledger_rows IN SHARE ROW EXCLUSIVE MODE"),
                        db.events.index("snapshot_digest"))
        self.assertLess(db.events.index("snapshot_digest"), db.events.index("changeset"))
        self.assertFalse(any("raw_json::" in event for event in db.events))
        with self.assertRaisesRegex(ValueError, "advisory ID overlap"):
            self.call([self.row("GHSA-2345-6789-cfgh")], db)
        self.assertEqual(db.rows["old"], before)

    def test_stale_local_export_aborts_before_any_write_or_export(self):
        db = FakeDB()
        with self.assertRaisesRegex(ValueError, "locked database snapshot"):
            self.call([self.row()], db, export_bytes=b"stale-export\\n")
        self.assertEqual((db.rows, db.versions, db.changes), ({}, [], []))
        self.assertNotIn("next_ordinal", db.events)
        self.assertNotIn("export", db.events)
        self.assertEqual(db.events[-1], "rollback")

    def test_missing_export_fails_without_fallback_database_transfer(self):
        db = FakeDB()
        self.file.write_text(json.dumps(self.row()) + chr(10))
        self.ledger.unlink(missing_ok=True)
        with patch.object(store, "connect", return_value=db), \
                patch.object(store, "foreign_active_claims", return_value=[]), \
                patch.object(store, "export_jsonl_incremental") as export:
            with self.assertRaises(FileNotFoundError):
                store.intake(self.file, "leader", "fixture")
            export.assert_not_called()
        self.assertEqual((db.rows, db.versions, db.changes), ({}, [], []))

    def test_uses_verified_bytes_once_and_database_max_ordinal(self):
        old = {"class_id": "old", "status": "NOT_AI", "advisory_ids": ["CVE-2026-99999"]}
        db = FakeDB([old])
        db.rows["old"] = (80, db.rows["old"][1])
        db.after_digest = lambda: self.ledger.write_bytes(b"changed-after-read")
        row = self.row()
        result, db, _, _ = self.call([row], db)
        self.assertEqual(result["inserted"], [row["class_id"]])
        self.assertEqual(db.rows[row["class_id"]][0], 81)

    def test_duplicate_class_and_cli_shape(self):
        row = self.row()
        with self.assertRaisesRegex(ValueError, "duplicate class_id"):
            self.call([row, deepcopy(row)])
        args = store.build_parser().parse_args(
            ["intake", str(self.file), "--actor", "leader", "--description", "new advisories"]
        )
        self.assertEqual((args.command, args.file, args.actor), ("intake", self.file, "leader"))


if __name__ == "__main__":
    unittest.main()
