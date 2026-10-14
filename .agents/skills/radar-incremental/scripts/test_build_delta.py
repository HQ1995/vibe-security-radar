"""Offline checks for identity preservation and conservative intake routing."""
from dataclasses import replace
import hashlib
import httpx
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest

from build_delta import (SourceRecord, class_id, load_occupancy, load_records, load_prior_deltas, normalize,
                         reconcile, timestamp)
from fetch import API_VERSION, Capturer, CaptureError, stream_url


class IntakeChecks(unittest.TestCase):
    def test_occupancy_reads_claims_list_output_and_saved_mappings(self):
        holder = {"class_id": "alias-a", "claimed": True, "owner": "leader", "claim_id": "c1"}
        with tempfile.TemporaryDirectory() as tmp:
            listing = Path(tmp) / "claims.jsonl"
            listing.write_text(json.dumps({"class_id": "alias-a", "claimed": True, "holders": [holder]}) + "\n"
                               + json.dumps({"class_id": "alias-b", "claimed": False, "holders": []}) + "\n")
            self.assertEqual(load_occupancy(listing), {"alias-a": [holder]})
            saved = Path(tmp) / "occupancy.json"
            saved.write_text(json.dumps({"alias-a": [holder]}))
            self.assertEqual(load_occupancy(saved), {"alias-a": [holder]})

    def test_increment_keeps_identity_and_uncertainty(self):
        cve = "CVE-2026-10000"
        ghsa = "GHSA-2345-6789-CFGH"
        source = SourceRecord("github", ghsa, (cve, ghsa), "2026-09-01", "2026-09-02", False, (), "a", "raw", "/0")
        ledger = [{"class_id": "alias-existing", "advisory_ids": [cve]}]
        universe = [{"class_id": "alias-existing", "public_ids": [cve, ghsa]}]
        occupied = {"alias-existing": [{"owner": "original-leader", "expired": True}]}
        row = reconcile([source], ledger, universe, occupied)[0]
        self.assertEqual(row["class_id"], "alias-existing")
        self.assertEqual(row["routing"], "EXISTING_OWNER_HANDOFF")
        self.assertFalse(row["ledger_write"])
        self.assertEqual(row["research_acceptance"], "NOT_ASSESSED_BY_INTAKE")
        self.assertEqual(reconcile([source], ledger, universe, occupied), [row])
        ledger.append({"class_id": "alias-second", "advisory_ids": [ghsa]})
        self.assertEqual(reconcile([source], ledger, universe, {})[0]["routing"], "IDENTITY_CONFLICT")
        new = reconcile([source], [], [], {})[0]
        self.assertEqual(new["class_id"], class_id([ghsa.lower(), cve]))
        self.assertEqual(new["routing"], "REPOSITORY_DISCOVERY")
        replay = reconcile([source], [], [], {}, [new])[0]
        self.assertEqual(replay["class_id"], new["class_id"])
        self.assertEqual(replay["identity"], "EXISTING_UNIVERSE_NOT_IN_LEDGER")
        self.assertEqual(replay["content_delta"], "UNCHANGED")
        self.assertEqual(reconcile([replace(source, sha256="revision")], [], [], {}, [new])[0]["content_delta"], "CHANGED")
        alias_only = [{"class_id": "alias-previous", "advisory_ids": ["CVE-2025-99999"],
                       "advisory_aliases": [{"id": ghsa}]}]
        self.assertEqual(reconcile([source], alias_only, [], {})[0]["class_id"], "alias-previous")

    def test_retirement_and_mutating_source_stay_explicit(self):
        a = SourceRecord("github", "GHSA-2345-6789-cfgh", ("CVE-2026-10000",), "2020-01-01", "2026-09-02", True, (), "a", "raw", "/0")
        b = replace(a, source="nvd", source_id="CVE-2026-10000", retired=False, sha256="b")
        row = reconcile([a, b], [], [], {})[0]
        self.assertEqual(row["routing"], "ADVISORY_STATUS_REVIEW")
        self.assertFalse(row["all_sources_retired"])
        conflict = reconcile([a, replace(a, sha256="changed")], [], [], {})[0]
        self.assertEqual(conflict["routing"], "SOURCE_CAPTURE_CONFLICT")
        self.assertEqual(len(conflict["source_records"]), 2)

    def test_reference_is_not_an_alias_or_product_proof(self):
        row = normalize({"id": "CVE-2026-10000", "published": "2026-09-01", "lastModified": "2026-09-02",
                         "references": [{"url": "https://github.com/github/advisory-database/blob/main/a.json"},
                                        {"url": "https://github.com/acme/tool/commit/" + "f" * 40},
                                        {"url": "https://github.com/advisories/GHSA-2345-6789-cfgh"}]},
                        "nvd", "raw", "/0")
        self.assertEqual(row.ids, ("CVE-2026-10000",))
        self.assertEqual(row.repo_candidates, ("https://github.com/acme/tool",))
        advisory = {"ghsa_id": "GHSA-2345-6789-cfgh", "published_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-02T00:00:00Z",
                    "withdrawn_at": None, "identifiers": [], "type": "reviewed", "source_code_location": "https://github.com/acme/tool",
                    "references": ["https://github.com/acme/tool/security/advisories/GHSA-2345-6789-cfgh"]}
        self.assertEqual(normalize(advisory, "github", "raw", "/0").reviewed_product_repository, "https://github.com/acme/tool")
        advisory["references"] = ["https://github.com/another/tool/security/advisories/GHSA-2345-6789-cfgh"]
        self.assertIsNone(normalize(advisory, "github", "raw", "/0").reviewed_product_repository)

    def global_advisory(self, **changes):
        return dict({"ghsa_id": "GHSA-2345-6789-cfgh", "cve_id": "CVE-2026-10000",
                     "published_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-02T00:00:00Z",
                     "withdrawn_at": None, "identifiers": [], "references": []}, **changes)

    def test_global_lifecycle_requires_present_typed_datetimes(self):
        for field in ("published_at", "updated_at", "withdrawn_at"):
            invalid = [False, True, 0, [], {}, "", "2026-09-01", "not-a-timestamp",
                       "2026-09-01T12:00:00", "2026-02-30T00:00:00Z", "2026-09-01T00:00:00+00:60"]
            if field != "withdrawn_at":
                invalid.append(None)
            for value in invalid:
                with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, field):
                    normalize(self.global_advisory(**{field: value}), "github", "raw", "/0")
            missing = self.global_advisory()
            del missing[field]
            with self.subTest(missing=field), self.assertRaisesRegex(ValueError, field):
                normalize(missing, "github", "raw", "/0")
        for value in ("2026-09-02T00:00:00Z", "2026-09-02T01:00:00.123+01:00", "2026-09-02t00:00:00z"):
            row = normalize(self.global_advisory(withdrawn_at=value, updated_at=value), "github", "raw", "/0")
            self.assertTrue(row.retired)
            self.assertEqual(reconcile([row], [], [], {})[0]["routing"], "ADVISORY_STATUS_REVIEW")
        self.assertFalse(normalize(self.global_advisory(), "github", "raw", "/0").retired)

    def test_submicrosecond_reactivation_and_equal_instant_retirement(self):
        old_time = "2026-09-26T20:42:47.1234561Z"
        new_time = "2026-09-26T20:42:47.1234562Z"
        old = normalize(self.global_advisory(updated_at=old_time, withdrawn_at=old_time), "github", "raw", "/0")
        active = normalize(self.global_advisory(updated_at=new_time), "github", "raw", "/0")
        prior = reconcile([old], [], [], {})
        row = reconcile([active], [], [], {}, prior)[0]
        self.assertEqual(row["routing"], "REPOSITORY_DISCOVERY")
        self.assertEqual(row["retired_source_records"], [])
        self.assertLess(timestamp(old_time), timestamp(new_time))
        # Arbitrary precision stays exact without depending on a Decimal context.
        self.assertLess(timestamp("2026-09-26T20:42:47." + "0" * 40 + "1Z"),
                        timestamp("2026-09-26T20:42:47." + "0" * 40 + "2Z"))
        # Same instant, different offset/trailing-zero spelling: retain retirement.
        equivalent = "2026-09-26T16:42:47.123456100-04:00"
        self.assertEqual(timestamp(old_time), timestamp(equivalent))
        tied = normalize(self.global_advisory(updated_at=equivalent), "github", "raw", "/0")
        self.assertEqual(reconcile([tied], [], [], {}, prior)[0]["routing"], "ADVISORY_STATUS_REVIEW")
        for observations in ([old, tied], [tied, old]):
            state = reconcile(observations, [], [], {})[0]
            self.assertEqual(state["retired_source_records"], ["github:GHSA-2345-6789-CFGH"])
        self.assertLess(timestamp("2026-09-26T23:59:59.999999999Z"),
                        timestamp("2026-09-27T01:00:00+01:00"))
        self.assertEqual(timestamp("2026-09-26T20:42:47.000000000Z"), timestamp("2026-09-26T20:42:47Z"))

    def test_global_nullable_arrays_and_entry_shapes(self):
        for field in ("identifiers", "references"):
            for value in (None, []):
                row = normalize(self.global_advisory(**{field: value}), "github", "raw", "/0")
                self.assertEqual(row.source_id, "GHSA-2345-6789-CFGH")
                self.assertFalse(row.retired)
            for value in (False, 0, "", {}, [None], [False], [[]]):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    normalize(self.global_advisory(**{field: value}), "github", "raw", "/0")
            missing = self.global_advisory()
            del missing[field]
            with self.assertRaises(ValueError):
                normalize(missing, "github", "raw", "/0")
        with self.assertRaises(ValueError):
            normalize(self.global_advisory(references=[{"url": "https://example.com"}]), "github", "raw", "/0")
        # References remain leads, not identity edges. Null identifiers do not discard cve_id.
        row = normalize(self.global_advisory(identifiers=None, references=["https://github.com/advisories/GHSA-cfgh-jmpq-rvwx"]), "github", "raw", "/0")
        self.assertEqual(row.ids, ("CVE-2026-10000", "GHSA-2345-6789-CFGH"))

    def test_global_typed_identifiers_cannot_change_source_identity(self):
        for entry in ({}, {"type": "CVE"}, {"value": "CVE-2026-10000"},
                      {"type": "CVE", "value": "GHSA-cfgh-jmpq-rvwx"},
                      {"type": "GHSA", "value": "CVE-2026-10000"},
                      {"type": "OTHER", "value": "CVE-2026-10000"},
                      {"type": [], "value": "CVE-2026-10000"},
                      {"type": "CVE", "value": False},
                      {"type": "CVE", "value": "CVE-broken"},
                      {"type": "GHSA", "value": "GHSA-cfgh-jmpq-rvwx"}):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                normalize(self.global_advisory(identifiers=[entry]), "github", "raw", "/0")
        for changes in ({"ghsa_id": "CVE-2026-10000"}, {"ghsa_id": None},
                        {"cve_id": "GHSA-cfgh-jmpq-rvwx"}, {"state": "published"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                normalize(self.global_advisory(**changes), "github", "raw", "/0")
        row = normalize(self.global_advisory(identifiers=[{"type": "GHSA", "value": "GHSA-2345-6789-CFGH"},
                                                        {"type": "CVE", "value": "CVE-2026-10000"}]), "github", "raw", "/0")
        self.assertEqual(row.source_id, "GHSA-2345-6789-CFGH")
        self.assertEqual(row.ids, ("CVE-2026-10000", "GHSA-2345-6789-CFGH"))

    def test_invalid_global_item_aborts_a_complete_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory)
            def respond(request, data):
                if request.url.host == "api.github.com" and request.url.params.get("type") == "reviewed" and not request.url.params.get("is_withdrawn"):
                    return [self.global_advisory(), self.global_advisory(ghsa_id="GHSA-cfgh-jmpq-rvwx", withdrawn_at=False)]
                return data
            coverage = self.capture(capture, respond)
            self.assertEqual(coverage["status"], "COMPLETE")
            with self.assertRaisesRegex(ValueError, "withdrawn_at"):
                load_records(capture, coverage)

    def test_prior_global_projection_rechecks_pinned_raw_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_path, delta = root / "source.body", root / "delta.jsonl"
            good = self.global_advisory()
            current_window = {"start": "2026-09-02T00:00:00Z", "end": "2026-09-03T00:00:00Z"}
            def write_prior(raw, projection=None):
                raw_path.write_text(json.dumps([raw]))
                record = normalize(good, "github", str(raw_path), "/0")
                row = reconcile([record], [], [], {})[0]
                observation = row["source_records"][0]
                # Simulate an earlier permissive helper with a genuine object hash.
                observation["sha256"] = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
                observation.update(projection or {})
                delta.write_text(json.dumps(row) + "\n")
                delta.with_name("summary.json").write_text(json.dumps({
                    "delta_sha256": hashlib.sha256(delta.read_bytes()).hexdigest(), "components": 1,
                    "status": "INTAKE_CLASSIFIED_NOT_RESEARCH_ACCEPTANCE", "prior_deltas": [],
                    "coverage": {"status": "COMPLETE", "window": {"start": "2026-09-01T00:00:00Z", "end": "2026-09-02T00:00:00Z"}}}))
            write_prior(good)
            self.assertEqual(len(load_prior_deltas([delta], current_window)), 1)
            for changes in ({"withdrawn_at": False}, {"published_at": None},
                            {"identifiers": [{"type": "CVE", "value": "GHSA-cfgh-jmpq-rvwx"}]}):
                write_prior(dict(good, **changes))
                with self.subTest(raw=changes), self.assertRaises(ValueError):
                    load_prior_deltas([delta], current_window)
            for projection in ({"retired": True}, {"retired": 0}, {"source_id": "GHSA-cfgh-jmpq-rvwx"},
                               {"sha256": "0" * 64}, {"published": "2026-09-01"}, {"pointer": "/-1"}):
                write_prior(good, projection)
                with self.subTest(projection=projection), self.assertRaises(ValueError):
                    load_prior_deltas([delta], current_window)
            write_prior(good)
            raw_path.unlink()
            with self.assertRaises(FileNotFoundError):
                load_prior_deltas([delta], current_window)

    def capture(self, root, handler=None, window=None):
        window = window or {"start": "2026-08-26T00:00:00Z", "end": "2026-09-26T00:00:00Z", "inclusive": True}
        def respond(request):
            data = [] if request.url.host == "api.github.com" else {
                "startIndex": 0, "resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
            if handler:
                data = handler(request, data)
            return httpx.Response(200, json=data, headers={"x-github-api-version-selected": API_VERSION})
        with httpx.Client(transport=httpx.MockTransport(respond)) as client:
            return Capturer(root, window, client, sleep=lambda _: None).run()

    def test_publication_cutoff_and_earliest_preserve_submicroseconds(self):
        first = "2026-08-26T00:00:00.1234571Z"
        start = "2026-08-26T00:00:00.123456Z"
        end = "2026-08-26T00:00:00.123457Z"
        ghsa = self.global_advisory(published_at="2026-08-26T00:00:00.1234572Z")
        nvd = {"id": "CVE-2026-10000", "published": first, "lastModified": "2026-09-02T00:00:00Z"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def respond(request, data):
                if request.url.host != "api.github.com":
                    return {"startIndex": 0, "resultsPerPage": 1, "totalResults": 1, "vulnerabilities": [{"cve": nvd}]}
                if request.url.params.get("type") == "reviewed" and not request.url.params.get("is_withdrawn"):
                    return [ghsa]
                return data
            self.capture(root / "capture", respond, {
                "start": start, "end": end, "inclusive": True})
            for name in ("ledger.jsonl", "universe.jsonl"):
                (root / name).write_text("")
            (root / "occupancy.json").write_text("{}")
            result = subprocess.run([sys.executable, "-B", str(Path(__file__).with_name("build_delta.py")),
                                     "--capture", str(root / "capture"), "--ledger", str(root / "ledger.jsonl"),
                                     "--universe", str(root / "universe.jsonl"), "--occupancy", str(root / "occupancy.json"),
                                     "--out", str(root / "out")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            row = json.loads((root / "out/delta.jsonl").read_text())
            self.assertFalse(row["source_publication_in_window"])
            self.assertFalse(row["older_publication_in_component"])
            self.assertEqual(row["earliest_source_publication"], "2026-08-26T00:00:00.1234571+00:00")

    def test_capture_uses_complete_pinned_manifest_only(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory)
            coverage = self.capture(capture)
            (capture / "stray.body").write_text("not a source page")
            self.assertEqual(load_records(capture, coverage), [])
            (capture / "nvd-published-0000.body").write_bytes(b"changed")
            with self.assertRaisesRegex(CaptureError, "hash mismatch"):
                load_records(capture, coverage)
            coverage["streams"][0]["complete"] = False
            with self.assertRaisesRegex(ValueError, "must be complete"):
                load_records(capture, coverage)
            coverage["streams"][0].update(complete=True, page_receipts=[], pages=0)
            with self.assertRaises((ValueError, CaptureError)):
                load_records(capture, coverage)

    def test_manifest_cannot_hide_raw_pagination_or_unique_count_failure(self):
        ghsa = self.global_advisory()
        for corruption in ("next_link", "nvd_total", "duplicate_ids"):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as directory:
                capture = Path(directory)
                coverage = self.capture(capture)
                name = "nvd-modified" if corruption == "nvd_total" else "ghsa-reviewed"
                stream = next(s for s in coverage["streams"] if s["name"] == name)
                ref = stream["page_receipts"][0]
                body = capture / stream["body_paths"][0]
                receipt_path = capture / ref["path"]
                receipt = json.loads(receipt_path.read_text())
                if corruption == "nvd_total":
                    payload = {"startIndex": 0, "resultsPerPage": 0, "totalResults": 10, "vulnerabilities": []}
                else:
                    payload = [ghsa] * (2 if corruption == "duplicate_ids" else 1)
                    stream["rows"] = stream["unique_ids"] = ref["rows"] = len(payload)
                    if corruption == "next_link":
                        receipt["headers"]["link"] = '<' + ref["url"] + '&after=next>; rel="next"'
                raw = json.dumps(payload).encode()
                body.write_bytes(raw)
                receipt["sha256"] = ref["sha256"] = hashlib.sha256(raw).hexdigest()
                receipt_path.write_text(json.dumps(receipt))
                with self.assertRaises((ValueError, CaptureError)):
                    load_records(capture, coverage)

    def test_foreign_claims_cover_offledger_and_public_ids_case_insensitively(self):
        ident = "GHSA-2345-6789-CFGH"
        source = SourceRecord("github", ident, (ident,), "2026-09-01", "2026-09-02", False, (), "a", "raw", "/0")
        previous = reconcile([source], [], [], {})[0]
        for key in [ident.lower(), previous["class_id"].upper()]:
            holder = {"owner": "foreign", "claimed": True, "expired": True}
            with self.subTest(key=key):
                for prior in [[], [previous]]:
                    row = reconcile([source], [], [], {key: [holder]}, prior)[0]
                    self.assertEqual(row["routing"], "EXISTING_OWNER_HANDOFF")
                    self.assertEqual(row["occupancy"], [holder])

    def test_three_windows_preserve_offledger_identity_and_latest_source_hash(self):
        first = SourceRecord("nvd", "CVE-2026-10000", ("CVE-2026-10000",), "2026-09-01", "2026-09-02", False, (), "a", "raw", "/0")
        other = replace(first, source_id="CVE-2026-10001", ids=("CVE-2026-10001",), sha256="b")
        cycle1 = reconcile([first, other], [], [], {})
        cycle2 = reconcile([replace(other, sha256="changed")], [], [], {}, cycle1)
        cycle3 = reconcile([first, replace(other, sha256="changed")], [], [], {}, cycle1 + cycle2)
        self.assertEqual({r["class_id"] for r in cycle1}, {r["class_id"] for r in cycle3})
        self.assertTrue(all(r["identity"] == "EXISTING_UNIVERSE_NOT_IN_LEDGER" for r in cycle3))
        self.assertTrue(all(r["content_delta"] == "UNCHANGED" for r in cycle3))
        self.assertEqual(cycle3, reconcile([replace(other, sha256="changed"), first], [], [], {}, cycle1 + cycle2))

    def test_prior_alias_conflict_does_not_disappear_in_next_window(self):
        cve, ghsa = "CVE-2026-10000", "GHSA-2345-6789-CFGH"
        source = SourceRecord("github", ghsa, (cve, ghsa), "2026-09-01", "2026-09-02", False, (), "a", "raw", "/0")
        universe = [{"class_id": "alias-old-a", "public_ids": [cve]}, {"class_id": "alias-old-b", "public_ids": [ghsa]}]
        first = reconcile([source], [], universe, {})
        self.assertEqual(first[0]["routing"], "IDENTITY_CONFLICT")
        later = replace(source, source="nvd", source_id=cve, ids=(cve,), sha256="b")
        self.assertEqual(reconcile([later], [], universe, {}, first)[0]["routing"], "IDENTITY_CONFLICT")

    def test_first_alias_bridge_between_separate_owners_needs_review(self):
        cve, ghsa = "CVE-2026-10000", "GHSA-2345-6789-CFGH"
        a, b = class_id([cve]), class_id([ghsa])
        ledger = [{"class_id": a, "advisory_ids": [cve]}]
        universe = [{"class_id": a, "public_ids": [cve]}, {"class_id": b, "public_ids": [ghsa]}]
        nvd = SourceRecord("nvd", cve, (cve,), "2026-09-01", "2026-09-02", False, (), "a", "raw", "/0")
        github = replace(nvd, source="github", source_id=ghsa, ids=(ghsa,), sha256="b")
        first = reconcile([nvd, github], ledger, universe, {})
        self.assertEqual(len(first), 2)
        self.assertTrue(all(row["identity"] != "CONFLICT" for row in first))
        edge = replace(github, ids=(cve, ghsa), sha256="first-alias-edge", modified="2026-09-03")
        for prior in ([], first):
            for old_rows in (universe, list(reversed(universe))):
                with self.subTest(prior=bool(prior), reversed=old_rows != universe):
                    row = reconcile([edge], ledger, old_rows, {}, prior)[0]
                    self.assertEqual((row["identity"], row["routing"]), ("CONFLICT", "IDENTITY_CONFLICT"))
                    self.assertEqual(row["ledger_class_ids"], [a])
                    self.assertEqual(row["prior_universe_class_ids"], sorted([a, b]))
                    later = reconcile([nvd], ledger, old_rows, {}, prior + [row])[0]
                    self.assertEqual(later["routing"], "IDENTITY_CONFLICT")
                    self.assertEqual(later["public_ids"], [cve, ghsa])

    def test_unique_canonical_owner_for_existing_alias_component_still_passes(self):
        cve, ghsa = "CVE-2026-10000", "GHSA-2345-6789-CFGH"
        source = SourceRecord("github", ghsa, (cve, ghsa), "2026-09-01", "2026-09-02", False, (), "a", "raw", "/0")
        ledger = [{"class_id": "canonical", "advisory_ids": [cve]}]
        # The explicit baseline alias already links the legacy name to the ledger.
        universe = [{"class_id": "legacy-name", "public_ids": [cve, ghsa]}]
        first = reconcile([source], ledger, universe, {})
        for prior in ([], first):
            for current in (source, replace(source, ids=(ghsa,)),
                            replace(source, ids=(cve, ghsa, "CVE-2026-10001"))):
                with self.subTest(prior=bool(prior), ids=current.ids):
                    row = reconcile([current], ledger, universe, {}, prior)[0]
                    self.assertEqual((row["identity"], row["class_id"], row["routing"]),
                                     ("EXISTING_LEDGER", "canonical", "EXISTING_SOURCE_REVALIDATION"))
        two = ledger + [{"class_id": "second-owner", "advisory_ids": [ghsa]}]
        self.assertEqual(reconcile([source], two, universe, {})[0]["routing"], "IDENTITY_CONFLICT")

    def test_one_ledger_owner_cannot_clear_a_prior_multiple_owner_conflict(self):
        cve, ghsa = "CVE-2026-10000", "GHSA-2345-6789-CFGH"
        source = SourceRecord("github", ghsa, (cve, ghsa), "2026-09-01", "2026-09-02", False, (), "a", "raw", "/0")
        universe = [{"class_id": "alias-old-a", "public_ids": [cve]}, {"class_id": "alias-old-b", "public_ids": [ghsa]}]
        prior = reconcile([source], [], universe, {})
        current = replace(source, source="nvd", source_id=cve, ids=(cve,), sha256="b")
        ledger = [{"class_id": "alias-old-a", "advisory_ids": [cve]}]
        row = reconcile([current], ledger, universe, {}, prior)[0]
        self.assertEqual((row["identity"], row["routing"]), ("CONFLICT", "IDENTITY_CONFLICT"))
        self.assertEqual(row["class_id"], prior[0]["class_id"])
        self.assertEqual(row["ledger_class_ids"], ["alias-old-a"])
        self.assertEqual(row["prior_universe_class_ids"], ["alias-old-a", "alias-old-b"])
        third = reconcile([current], ledger, universe, {}, prior + [row])[0]
        self.assertEqual(third["routing"], "IDENTITY_CONFLICT")
        # A unique canonical identity still takes precedence over one legacy
        # universe name; this is not evidence that two original owners merged.
        unique = reconcile([source], ledger, [{"class_id": "legacy-name", "public_ids": [cve, ghsa]}], {})[0]
        self.assertEqual(unique["identity"], "EXISTING_LEDGER")
        two_ledger = reconcile([source], ledger + [{"class_id": "alias-old-b", "advisory_ids": [ghsa]}], [], {})[0]
        self.assertEqual(two_ledger["routing"], "IDENTITY_CONFLICT")

    def test_omitted_retirement_persists_until_newer_same_source_reactivation(self):
        cve, ghsa = "CVE-2026-10000", "GHSA-2345-6789-CFGH"
        withdrawn = SourceRecord("github", ghsa, (cve, ghsa), "2026-09-01", "2026-09-02", True, (), "withdrawn", "raw", "/0")
        live = replace(withdrawn, source="nvd", source_id=cve, ids=(cve,), retired=False, sha256="live")
        first = reconcile([withdrawn, live], [], [], {})
        omitted = reconcile([replace(live, sha256="update")], [], [], {}, first)[0]
        self.assertEqual(omitted["routing"], "ADVISORY_STATUS_REVIEW")
        self.assertEqual(omitted["retired_source_records"], ["github:" + ghsa])
        self.assertFalse(omitted["all_sources_retired"])
        still_omitted = reconcile([live], [], [], {}, first + [omitted])[0]
        self.assertEqual(still_omitted["routing"], "ADVISORY_STATUS_REVIEW")
        for modified in ["2026-09-01", "2026-09-02"]:
            stale = replace(withdrawn, retired=False, modified=modified, sha256="stale")
            row = reconcile([stale, live], [], [], {}, first + [omitted])[0]
            self.assertEqual(row["routing"], "ADVISORY_STATUS_REVIEW")
        reactivated = replace(withdrawn, retired=False, modified="2026-09-03", sha256="reactivated")
        cleared = reconcile([reactivated, live], [], [], {}, first + [omitted])[0]
        self.assertEqual(cleared["retired_source_records"], [])
        self.assertEqual(cleared["routing"], "REPOSITORY_DISCOVERY")
        # Omitting GHSA again must not resurrect its superseded retirement.
        later = reconcile([live], [], [], {}, first + [omitted, cleared])[0]
        self.assertEqual(later["retired_source_records"], [])
        self.assertEqual(later["routing"], "REPOSITORY_DISCOVERY")

    def test_all_sources_retired_uses_retained_active_status_too(self):
        ghsa, cve = "GHSA-2345-6789-CFGH", "CVE-2026-10000"
        active = SourceRecord("github", ghsa, (cve, ghsa), "2026-09-01", "2026-09-02", False, (), "a", "raw", "/0")
        rejected = replace(active, source="nvd", source_id=cve, ids=(cve,), retired=True, sha256="b")
        first = reconcile([active, rejected], [], [], {})
        later = reconcile([rejected], [], [], {}, first)[0]
        self.assertEqual(later["routing"], "ADVISORY_STATUS_REVIEW")
        self.assertFalse(later["all_sources_retired"])
        withdrawn = replace(active, retired=True, modified="2026-09-03", sha256="c")
        later = reconcile([withdrawn], [], [], {}, first)[0]
        self.assertTrue(later["all_sources_retired"])
        self.assertEqual(later["retired_source_records"], ["github:" + ghsa, "nvd:" + cve])

    def test_prior_delta_hash_ancestry_and_window_gaps_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first/delta.jsonl", root / "second/delta.jsonl"
            for path in [first, second]:
                path.parent.mkdir()
                path.write_text(json.dumps({"class_id": path.parent.name, "source_records": []}) + "\n")
            pin = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
            def summary(path, start, end, priors):
                data = {"delta_sha256": pin(path), "prior_deltas": priors, "components": 1,
                        "status": "INTAKE_CLASSIFIED_NOT_RESEARCH_ACCEPTANCE",
                        "coverage": {"status": "COMPLETE", "window": {"start": start, "end": end}}}
                path.with_name("summary.json").write_text(json.dumps(data))
            summary(first, "2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z", [])
            summary(second, "2026-09-02T00:00:00Z", "2026-09-03T00:00:00Z", [{"sha256": pin(first)}])
            window = {"start": "2026-09-03T00:00:00Z", "end": "2026-09-04T00:00:00Z"}
            self.assertEqual(len(load_prior_deltas([first, second], window)), 2)
            with self.assertRaisesRegex(ValueError, "ancestry"):
                load_prior_deltas([second], window)
            with self.assertRaisesRegex(ValueError, "overlap"):
                load_prior_deltas([first, second], dict(window, start="2026-09-03T00:00:01Z"))
            with self.assertRaisesRegex(ValueError, "[Dd]uplicate"):
                load_prior_deltas([first, first], window)
            first.write_bytes(first.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                load_prior_deltas([first, second], window)

    def test_successive_empty_windows_can_share_the_same_delta_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for day in (1, 2):
                path = Path(directory) / str(day) / "delta.jsonl"
                path.parent.mkdir()
                path.write_bytes(b"")
                pin = hashlib.sha256(b"").hexdigest()
                path.with_name("summary.json").write_text(json.dumps({
                    "delta_sha256": pin, "components": 0,
                    "status": "INTAKE_CLASSIFIED_NOT_RESEARCH_ACCEPTANCE",
                    "prior_deltas": [{"sha256": pin}] if day == 2 else [],
                    "coverage": {"status": "COMPLETE", "window": {
                        "start": f"2026-09-{day:02d}T00:00:00Z", "end": f"2026-09-{day+1:02d}T00:00:00Z"}}}))
                paths.append(path)
            self.assertEqual(load_prior_deltas(paths, {
                "start": "2026-09-03T00:00:00Z", "end": "2026-09-04T00:00:00Z"}), [])

    def test_withdrawn_and_rejected_updates_are_not_fresh_admission(self):
        old = normalize({"id": "CVE-2026-10000", "published": "2020-01-01", "lastModified": "2026-09-02", "vulnStatus": "Analyzed"}, "nvd", "raw", "/0")
        prior = reconcile([old], [], [], {})
        rejected = normalize({"id": "CVE-2026-10000", "published": "2020-01-01", "lastModified": "2026-09-03", "vulnStatus": "Rejected"}, "nvd", "raw", "/0")
        row = reconcile([rejected], [], [], {}, prior)[0]
        self.assertEqual(row["routing"], "ADVISORY_STATUS_REVIEW")
        self.assertEqual(row["content_delta"], "CHANGED")
        self.assertEqual(row["class_id"], prior[0]["class_id"])
        self.assertTrue(row["all_sources_retired"])


if __name__ == "__main__":
    unittest.main()
