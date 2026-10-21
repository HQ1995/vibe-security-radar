#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import parse_qs

import httpx

spec = importlib.util.spec_from_file_location("incremental_fetch", Path(__file__).with_name("fetch.py"))
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)

WINDOW = {"start": "2026-09-26T00:00:00Z", "end": "2026-09-26T20:42:47Z", "inclusive": True}
DAYS = {"start": "2026-09-24T06:00:00Z", "end": "2026-09-26T20:42:47Z", "inclusive": True}


def ghsa(ident="GHSA-aaaa-bbbb-cccc"):
    return {"ghsa_id": ident, "updated_at": WINDOW["start"]}


def nvd(count=0, total=0, start=0, offset=0):
    return {"startIndex": start, "resultsPerPage": count, "totalResults": total,
            "vulnerabilities": [{"cve": {"id": f"CVE-2026-{10000 + offset + i}"}}
                                for i in range(count)]}


def response(payload, status=200, headers=None):
    return httpx.Response(status, json=payload, headers={
        "x-github-api-version-selected": fetch.API_VERSION, **(headers or {}),
    })


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "capture"
        self.requests, self.sleeps = [], []

    def run_capture(self, handler=None, **kwargs):
        def handle(request):
            self.requests.append(request)
            if handler:
                return handler(request)
            if request.url.host == "api.github.com":
                return response([ghsa()])
            return response(nvd())
        with httpx.Client(transport=httpx.MockTransport(handle)) as client:
            return fetch.Capturer(self.output, WINDOW, client, sleep=self.sleeps.append,
                                  **kwargs).run()

    def coverage(self):
        return json.loads((self.output / "coverage.json").read_text())

    def test_all_six_streams_and_pacing(self):
        report = self.run_capture()
        self.assertEqual(report["status"], "COMPLETE")
        self.assertEqual(len(report["streams"]), 6)
        self.assertEqual(report["body_paths"], [f"{s}-0000.body" for s in fetch.STREAMS])
        self.assertEqual(self.sleeps, [0.3] * 4 + [6.1] * 2)
        self.assertEqual([s["source"] for s in report["streams"]], ["ghsa"] * 4 + ["nvd"] * 2)
        queries = [parse_qs(r.url.query.decode()) for r in self.requests]
        self.assertEqual(queries[0]["type"], ["reviewed"])
        self.assertEqual(queries[1]["type"], ["unreviewed"])
        self.assertEqual(queries[2]["is_withdrawn"], ["true"])
        self.assertEqual(queries[3]["is_withdrawn"], ["true"])
        self.assertIn("lastModStartDate", queries[4])
        self.assertIn("pubStartDate", queries[5])
        self.assertEqual(queries[4]["lastModStartDate"], [WINDOW["start"]])
        self.assertEqual(queries[5]["pubEndDate"], [WINDOW["end"]])

    def test_hash_verified_resume_without_network(self):
        self.run_capture()
        self.requests.clear()
        report = self.run_capture(lambda r: self.fail("Resume should not make HTTP requests"))
        self.assertEqual(report["status"], "COMPLETE")
        self.assertTrue(all(s["page_receipts"][0]["reused"] for s in report["streams"]))
        self.assertEqual(self.requests, [])

    def test_corrupt_cached_body_is_incomplete_not_refetched(self):
        self.run_capture()
        (self.output / "ghsa-reviewed-0000.body").write_text("[]")
        self.requests.clear()
        report = self.run_capture()
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertIn("hash mismatch", report["errors"][0]["error"])
        self.assertFalse(report["streams"][0]["complete"])
        self.assertEqual(self.requests, [])

    def test_frozen_window_and_output_contract(self):
        path = self.root / "window.json"
        path.write_text(json.dumps(WINDOW))
        window, pin = fetch.frozen_window(path, start=WINDOW["start"], end=WINDOW["end"])
        self.assertEqual(window, WINDOW)
        self.assertEqual(pin["sha256"], fetch.digest(path.read_bytes()))
        with self.assertRaises(fetch.CaptureError):
            fetch.frozen_window(path, end="2026-09-27T00:00:00Z")
        self.run_capture()
        old = (self.output / "coverage.json").read_bytes()
        with httpx.Client(transport=httpx.MockTransport(lambda r: self.fail())) as client:
            other = dict(WINDOW, end="2026-09-25T00:00:00Z")
            with self.assertRaises(fetch.CaptureError):
                fetch.Capturer(self.output, other, client).run()
        self.assertEqual((self.output / "coverage.json").read_bytes(), old)

    def test_frozen_window_precision_and_asserted_boundary(self):
        path = self.root / "window.json"
        original = "2026-09-27T00:00:00.1234561Z"
        different = "2026-09-27T00:00:00.1234562Z"
        window = dict(WINDOW, start=original, end="2026-09-28T00:00:00Z")
        path.write_text(json.dumps(window))
        with self.assertRaisesRegex(fetch.CaptureError, "precision"):
            fetch.frozen_window(path, start=different)
        with self.assertRaisesRegex(fetch.CaptureError, "precision"):
            fetch.frozen_window(path, start=original)
        with self.assertRaisesRegex(fetch.CaptureError, "precision"):
            fetch.Capturer(self.output, window, None)
        self.assertFalse(self.output.exists())
        window["start"] = "2026-09-27T00:00:00.123456Z"
        path.write_text(json.dumps(window))
        with self.assertRaisesRegex(fetch.CaptureError, "differs"):
            fetch.frozen_window(path, start="2026-09-27T00:00:00.123457Z")
        with self.assertRaisesRegex(fetch.CaptureError, "precision"):
            fetch.frozen_window(path, start=different)
        same = "2026-09-27T00:00:00.123456000+00:00"
        self.assertEqual(fetch.frozen_window(path, start=same)[0], window)
        self.assertEqual(fetch.timestamp(same), fetch.timestamp(window["start"]))
        for invalid in ("2026-09-27T00:00:00.0000001Z", "20260927T000000.1234561Z",
                        "2026-09-27T00:00:00,1234561Z"):
            with self.subTest(value=invalid), self.assertRaises(fetch.CaptureError):
                fetch.timestamp(invalid)

    def test_ghsa_link_pagination(self):
        initial = fetch.stream_url("ghsa-reviewed", WINDOW)
        next_url = initial + "&after=cursor123"
        def handler(request):
            if str(request.url) == initial:
                return response([ghsa()], headers={"link": f'<{next_url}>; rel="next"'})
            if str(request.url) == next_url:
                return response([ghsa("GHSA-dddd-eeee-ffff")])
            return response([] if request.url.host == "api.github.com" else nvd())
        report = self.run_capture(handler)
        self.assertEqual(report["status"], "COMPLETE")
        self.assertEqual(report["streams"][0]["pages"], 2)
        self.assertEqual(report["streams"][0]["unique_ids"], 2)

    def test_untrusted_and_mutated_next_links_not_requested(self):
        initial = fetch.stream_url("ghsa-reviewed", WINDOW)
        bad = [
            initial.replace("api.github.com", "evil.example") + "&after=x",
            initial.replace("https://", "http://") + "&after=x",
            initial.replace("api.github.com", "api.github.com@evil.example") + "&after=x",
            initial.replace("/advisories", "/other") + "&after=x",
            initial.replace("type=reviewed", "type=unreviewed") + "&after=x",
            initial + "&after=x&type=reviewed",
            initial + "&after=x&token=secret",
        ]
        for i, url in enumerate(bad):
            with self.subTest(url=url):
                self.output = self.root / f"bad-{i}"
                self.requests.clear()
                report = self.run_capture(lambda r: response(
                    [ghsa()], headers={"link": f'<{url}>; rel="next"'}))
                self.assertEqual(report["status"], "INCOMPLETE")
                self.assertEqual(len(self.requests), 1)

    def test_cursor_loop_and_duplicate_id_fail(self):
        initial = fetch.stream_url("ghsa-reviewed", WINDOW)
        next_url = initial + "&after=x"
        def handler(request):
            return response([ghsa()], headers={"link": f'<{next_url}>; rel="next"'})
        report = self.run_capture(handler)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertIn("Duplicate identity", report["errors"][0]["error"])
        self.assertEqual(len(self.requests), 2)

    def test_nvd_multiple_pages_and_terminal_unique_count(self):
        def handler(request):
            if request.url.host == "api.github.com":
                return response([])
            index = int(request.url.params["startIndex"])
            return response(nvd(2000 if index == 0 else 1, 2001, index, index))
        report = self.run_capture(handler)
        self.assertEqual(report["status"], "COMPLETE")
        for result in report["streams"][4:]:
            self.assertEqual((result["pages"], result["rows"], result["unique_ids"]),
                             (2, 2001, 2001))
            self.assertEqual(result["total_results"], 2001)

    def test_nvd_window_is_paged_per_utc_day(self):
        def handler(request):
            if request.url.host == "api.github.com":
                return response([])
            day = int(request.url.params.get("lastModStartDate", request.url.params.get("pubStartDate"))[8:10])
            index = int(request.url.params["startIndex"])
            return response(nvd(2000 if index == 0 else day, 2000 + day, index, 10000 * (day - 23) + index))
        with httpx.Client(transport=httpx.MockTransport(lambda r: (self.requests.append(r), handler(r))[1])) as client:
            report = fetch.Capturer(self.output, DAYS, client, sleep=self.sleeps.append).run()
        self.assertEqual(report["status"], "COMPLETE")
        nvd_queries = [parse_qs(r.url.query.decode()) for r in self.requests if r.url.host != "api.github.com"]
        self.assertEqual([(q["lastModStartDate"][0], q["lastModEndDate"][0], q["startIndex"][0]) for q in nvd_queries[:6]], [
            ("2026-09-24T06:00:00Z", "2026-09-24T23:59:59.999Z", "0"), ("2026-09-24T06:00:00Z", "2026-09-24T23:59:59.999Z", "2000"),
            ("2026-09-25T00:00:00.000Z", "2026-09-25T23:59:59.999Z", "0"), ("2026-09-25T00:00:00.000Z", "2026-09-25T23:59:59.999Z", "2000"),
            ("2026-09-26T00:00:00.000Z", "2026-09-26T20:42:47Z", "0"), ("2026-09-26T00:00:00.000Z", "2026-09-26T20:42:47Z", "2000")])
        for result in report["streams"][4:]:
            self.assertEqual((result["pages"], result["total_results"], result["unique_ids"], result["slices_complete"]),
                             (6, 6075, 6075, 3))

    def test_a_drifted_nvd_day_is_recaptured_alone(self):
        drift = [True]
        def handler(request):
            if request.url.host == "api.github.com":
                return response([])
            day = int(request.url.params.get("lastModStartDate", request.url.params.get("pubStartDate"))[8:10])
            index = int(request.url.params["startIndex"])
            total = 2001 - (day == 25 and index > 0 and drift[0])
            return response(nvd(2000 if index == 0 else total - 2000, total, index, 10000 * (day - 24) + index))
        self.assertEqual(self.run_capture_days(handler)["streams"][4]["slices_complete"], 1)
        for receipt in self.output.glob("nvd-modified-000[23].*"):
            receipt.rename(self.root / receipt.name)
        drift[0] = False
        self.requests.clear()
        report = self.run_capture_days(handler)
        self.assertEqual(report["status"], "COMPLETE")
        self.assertTrue(all(p["reused"] for p in report["streams"][4]["page_receipts"][:2]))
        self.assertEqual(report["streams"][4]["unique_ids"], 3 * 2001)

    def run_capture_days(self, handler):
        with httpx.Client(transport=httpx.MockTransport(lambda r: (self.requests.append(r), handler(r))[1])) as client:
            return fetch.Capturer(self.output, DAYS, client, sleep=self.sleeps.append).run()

    def test_nvd_drift_count_duplicate_and_empty_failures(self):
        bad_pages = [
            nvd(1, 2002, 2000, 2000),
            nvd(1, 2001, 1999, 2000),
            nvd(0, 2001, 2000, 2000),
            nvd(1, 2001, 2000, 0),
            {"startIndex": 2000, "resultsPerPage": 1, "totalResults": 2001,
             "vulnerabilities": []},
        ]
        for i, bad in enumerate(bad_pages):
            self.output = self.root / f"nvd-bad-{i}"
            def handler(request):
                if request.url.host == "api.github.com":
                    return response([])
                return response(nvd(2000, 2001) if request.url.params["startIndex"] == "0" else bad)
            report = self.run_capture(handler)
            self.assertEqual(report["status"], "INCOMPLETE")
            self.assertEqual(report["streams"][4]["rows"], 2000)
            self.assertFalse(report["streams"][4]["complete"])
            self.assertEqual(report["streams"][5]["status"], "NOT_STARTED")
            self.assertTrue((self.output / "nvd-modified-0001.receipt.json").exists())

    def test_http_failures_retained_and_never_retried(self):
        for status in [401, 403, 429, 500, 302]:
            self.output = self.root / str(status)
            self.requests.clear()
            report = self.run_capture(lambda r: response({"message": "no"}, status))
            self.assertEqual(report["status"], "INCOMPLETE")
            receipt = json.loads((self.output / "ghsa-reviewed-0000.receipt.json").read_text())
            self.assertEqual(receipt["status"], status)
            self.assertEqual(len(self.requests), 1)
            report = self.run_capture(lambda r: self.fail("No retry of recorded HTTP failure"))
            self.assertEqual(report["status"], "INCOMPLETE")
            self.assertEqual(len(self.requests), 1)

    def test_transport_failure_has_receipt_and_no_zero_success(self):
        def handler(request):
            raise httpx.ReadTimeout("private detail must not be saved")
        report = self.run_capture(handler)
        self.assertEqual(report["status"], "INCOMPLETE")
        receipt = json.loads((self.output / "ghsa-reviewed-0000.receipt.json").read_text())
        self.assertIsNone(receipt["status"])
        self.assertEqual(receipt["error"], "ReadTimeout")
        self.assertNotIn("private detail", json.dumps(report) + json.dumps(receipt))
        self.assertFalse(report["streams"][0]["complete"])

    def test_no_credentials_or_cookies_in_receipts(self):
        def handler(request):
            if request.url.host == "api.github.com":
                self.assertEqual(request.headers["Authorization"], "Bearer github-secret")
                return response([], headers={"set-cookie": "cookie-secret",
                                             "authorization": "echo-secret"})
            self.assertEqual(request.headers["apiKey"], "nvd-secret")
            return response(nvd(), headers={"set-cookie": "cookie-secret"})
        report = self.run_capture(handler, github_token="github-secret", nvd_key="nvd-secret")
        self.assertEqual(report["status"], "COMPLETE")
        saved = "".join(p.read_text() for p in self.output.glob("*.json"))
        for secret in ["github-secret", "nvd-secret", "echo-secret", "cookie-secret"]:
            self.assertNotIn(secret, saved)

    def make_probe(self, name, payload, url, headers=None):
        probe = self.root / "probes"
        probe.mkdir(exist_ok=True)
        body = json.dumps(payload).encode()
        (probe / (name + ".body")).write_bytes(body)
        (probe / (name + ".receipt.json")).write_text(json.dumps({
            "url": url, "status": 200, "sha256": fetch.digest(body),
            "captured_at": "2026-09-26T20:42:51+00:00",
            "headers": {"x-github-api-version-selected": fetch.API_VERSION,
                        "set-cookie": "do-not-copy", **(headers or {})},
        }))
        return probe

    def test_explicit_exact_url_probe_adoption(self):
        probe = self.make_probe("ghsa-reviewed-0000", [ghsa()],
                                fetch.stream_url("ghsa-reviewed", WINDOW))
        self.make_probe("nvd-0000", nvd(), fetch.stream_url("nvd-modified", WINDOW))
        report = self.run_capture(adopt_probes=probe)
        self.assertEqual(report["status"], "COMPLETE")
        self.assertEqual(len(self.requests), 4)
        receipt = json.loads((self.output / "ghsa-reviewed-0000.receipt.json").read_text())
        self.assertIn("adopted_from", receipt)
        self.assertNotIn("set-cookie", receipt["headers"])

    def test_probe_wrong_window_rejected(self):
        probe = self.make_probe("ghsa-reviewed-0000", [],
                                fetch.stream_url("ghsa-reviewed", WINDOW).replace("2026-09-26T00", "2026-09-25T00"))
        report = self.run_capture(adopt_probes=probe)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(self.requests, [])
        self.assertIn("URL", report["errors"][0]["error"])

    def test_schema_or_api_version_failure_retains_raw(self):
        for i, reply in enumerate([
            response({"message": "not a list"}),
            response([], headers={"x-github-api-version-selected": "2022-11-28"}),
        ]):
            self.output = self.root / f"schema-{i}"
            report = self.run_capture(lambda r: reply)
            self.assertEqual(report["status"], "INCOMPLETE")
            self.assertTrue((self.output / "ghsa-reviewed-0000.body").exists())
            self.assertTrue((self.output / "ghsa-reviewed-0000.receipt.json").exists())

    def test_page_cap_is_incomplete(self):
        initial = fetch.stream_url("ghsa-reviewed", WINDOW)
        report = self.run_capture(lambda r: response(
            [ghsa()], headers={"link": f'<{initial}&after=x>; rel="next"'}), max_pages=1)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["streams"][0]["rows"], 1)
        self.assertIn("Page limit", report["errors"][0]["error"])


if __name__ == "__main__":
    unittest.main()
