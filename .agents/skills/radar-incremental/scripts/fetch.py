#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx

API_VERSION = "2026-03-10"
GHSA = "https://api.github.com/advisories"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
STREAMS = (
    "ghsa-reviewed", "ghsa-unreviewed",
    "ghsa-reviewed-withdrawn", "ghsa-unreviewed-withdrawn",
    "nvd-modified", "nvd-published",
)
SAFE_HEADERS = {
    "date", "content-type", "etag", "last-modified", "link", "retry-after",
    "x-github-api-version-selected", "x-ratelimit-limit", "x-ratelimit-remaining",
    "x-ratelimit-reset", "x-ratelimit-resource", "x-ratelimit-used",
}
SCHEMA = "radar-incremental-fetch/v1"


class CaptureError(Exception):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def timestamp(value):
    if not isinstance(value, str):
        raise CaptureError("Expected a UTC timestamp string")
    match = re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(?:\.([0-9]+))?(?:[Zz]|[+-]00:00)", value)
    if match is None:
        raise CaptureError("Expected an explicit UTC date-time")
    if len((match[1] or "").rstrip("0")) > 6:
        raise CaptureError("Timestamp precision exceeds microseconds")
    try:
        parsed = datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
    except ValueError as exc:
        raise CaptureError("Invalid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise CaptureError("Timestamp must explicitly use UTC")
    return parsed


def frozen_window(path, start=None, end=None):
    raw = path.read_bytes()
    data = json.loads(raw)
    first, last = timestamp(data["start"]), timestamp(data["end"])
    if first >= last or (last - first).total_seconds() > 120 * 86400:
        raise CaptureError("Window must be positive and at most 120 days for NVD")
    for given, expected in [(start, first), (end, last)]:
        if given is not None and timestamp(given) != expected:
            raise CaptureError("CLI date differs from the frozen window")
    return {"start": data["start"], "end": data["end"],
            "inclusive": True}, {"path": str(path.resolve()), "sha256": digest(raw)}


def nvd_slices(window):
    last = timestamp(window["end"])
    start, cursor, slices = window["start"], timestamp(window["start"]), []
    while True:
        midnight = datetime.combine(cursor.date() + timedelta(days=1), datetime.min.time(), timezone.utc)
        if midnight >= last:
            return slices + [{"start": start, "end": window["end"]}]
        before = midnight - timedelta(milliseconds=1)
        slices.append({"start": start, "end": before.strftime("%Y-%m-%dT%H:%M:%S.") + f"{before.microsecond // 1000:03d}Z"})
        start, cursor = midnight.strftime("%Y-%m-%dT%H:%M:%S.000Z"), midnight


def stream_url(name, window, start_index=0):
    if name.startswith("ghsa-"):
        params = {
            "type": "unreviewed" if "unreviewed" in name else "reviewed",
            "modified": window["start"] + ".." + window["end"],
            "sort": "updated", "direction": "asc", "per_page": "100",
        }
        if name.endswith("-withdrawn"):
            params["is_withdrawn"] = "true"
        return GHSA + "?" + urlencode(params)
    prefix = "lastMod" if name == "nvd-modified" else "pub"
    return NVD + "?" + urlencode({
        prefix + "StartDate": window["start"], prefix + "EndDate": window["end"],
        "resultsPerPage": 2000, "startIndex": start_index,
    })


def github_next(link, initial_url):
    if not link:
        return None
    found = []
    for part in re.split(r",(?=\s*<)", link):
        match = re.fullmatch(r"\s*<([^<>]+)>\s*(;.*)", part)
        if not match:
            raise CaptureError("Malformed GitHub Link header")
        relations = re.findall(r';\s*rel=(?:"([^"]*)"|([^;\s]+))', match[2])
        if not relations:
            raise CaptureError("GitHub Link relation missing")
        if any("next" in (a or b).split() for a, b in relations):
            found.append(match[1])
    if len(found) > 1:
        raise CaptureError("Multiple next links")
    if not found:
        return None
    url = found[0]
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc != "api.github.com"
            or parsed.path != "/advisories" or parsed.fragment):
        raise CaptureError("Untrusted GitHub next-link origin/path")
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query = dict(pairs)
    if len(query) != len(pairs):
        raise CaptureError("Duplicate GitHub pagination parameters")
    base = dict(parse_qsl(urlsplit(initial_url).query))
    pagination = set(query) - set(base)
    if (any(query.get(k) != v for k, v in base.items())
            or pagination not in ({"after"}, {"page"})
            or not all(query[k] for k in pagination)):
        raise CaptureError("GitHub next link changes frozen query contract")
    if "page" in query and (not query["page"].isdigit() or int(query["page"]) < 2):
        raise CaptureError("Invalid GitHub page number")
    return url


def save_json(path, value, exclusive=False):
    content = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if exclusive:
        with path.open("x", encoding="utf-8") as out:
            out.write(content)
    else:
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)


@contextmanager
def output_lock(output):
    output.mkdir(parents=True, exist_ok=True)
    with (output / ".fetch.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CaptureError("Another fetch owns this output directory") from exc
        yield


class Capturer:
    def __init__(self, output, window, client, *, adopt_probes=None,
                 github_token=None, nvd_key=None, sleep=time.sleep, timeout=45,
                 max_pages=10000):
        for field in ("start", "end"):
            timestamp(window[field])
        if not 0 < timeout <= 120 or not 0 < max_pages <= 10000:
            raise CaptureError("Timeout must be <=120s; max pages must be <=10000")
        self.output, self.window, self.client = Path(output), window, client
        self.adopt_probes = Path(adopt_probes) if adopt_probes else None
        self.github_token, self.nvd_key = github_token, nvd_key
        self.sleep, self.timeout, self.max_pages = sleep, timeout, max_pages
        self.contract = {
            "schema": SCHEMA, "window": window, "github_api_version": API_VERSION,
            "streams": {s: stream_url(s, window if s.startswith("ghsa-") else nvd_slices(window)[0])
                        for s in STREAMS},
            "nvd_slices": nvd_slices(window),
            "pacing_seconds": {"ghsa": 0.3, "nvd": 6.1},
            "redirects": False, "automatic_retries": 0,
        }

    def _checked(self, body, receipt, url, *, local=False, ghsa=False):
        if receipt.get("url") != url:
            raise CaptureError("Cached URL does not match frozen page URL")
        if receipt.get("status") != 200:
            raise CaptureError("Retained non-200/failure receipt; no automatic retry")
        if digest(body) != receipt.get("sha256"):
            raise CaptureError("Cached body hash mismatch")
        timestamp(receipt.get("captured_at"))
        if local and receipt.get("contract_sha256") != digest(
                json.dumps(self.contract, sort_keys=True).encode()):
            raise CaptureError("Cached page contract mismatch")
        headers = {k.lower(): v for k, v in receipt.get("headers", {}).items()}
        if ghsa and headers.get("x-github-api-version-selected") != API_VERSION:
            raise CaptureError("GitHub API version not verified")
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeDecodeError) as exc:
            raise CaptureError("Response is not valid JSON") from exc
        return payload

    def page(self, name, page, url):
        stem = f"{name}-{page:04d}"
        body_path, receipt_path = (self.output / (stem + suffix)
                                   for suffix in (".body", ".receipt.json"))
        if receipt_path.exists():
            receipt = json.loads(receipt_path.read_text())
            body = body_path.read_bytes() if body_path.exists() else b""
            return self._checked(body, receipt, url, local=True,
                                 ghsa=name.startswith("ghsa-")), receipt, True
        if body_path.exists():
            raise CaptureError("Orphaned raw body; inspect interrupted capture, do not overwrite")
        base = {
            "schema": SCHEMA, "url": url, "stream": name, "page": page,
            "contract_sha256": digest(json.dumps(self.contract, sort_keys=True).encode()),
        }
        probe_name = {"ghsa-reviewed": "ghsa-reviewed-0000",
                      "nvd-modified": "nvd-0000"}.get(name)
        probe = self.adopt_probes / (probe_name + ".receipt.json") if (
            self.adopt_probes and probe_name and page == 0) else None
        if probe and probe.exists():
            original = json.loads(probe.read_text())
            source_body = probe.with_name(probe_name + ".body")
            body = source_body.read_bytes()
            self._checked(body, original, url, ghsa=name.startswith("ghsa-"))
            receipt = {
                **base, "status": 200, "sha256": digest(body),
                "captured_at": original["captured_at"],
                "headers": {k.lower(): v for k, v in original.get("headers", {}).items()
                            if k.lower() in SAFE_HEADERS},
                "adopted_from": {"receipt": str(probe.resolve()),
                                 "receipt_sha256": digest(probe.read_bytes()),
                                 "body": str(source_body.resolve()),
                                 "body_sha256": digest(body)},
            }
        else:
            if self.client is None:
                raise CaptureError("Missing retained page; offline validation never fetches")
            is_ghsa = name.startswith("ghsa-")
            self.sleep(0.3 if is_ghsa else 6.1)
            headers = {"Accept": "application/vnd.github+json" if is_ghsa
                       else "application/json"}
            if is_ghsa:
                headers["X-GitHub-Api-Version"] = API_VERSION
                if self.github_token:
                    headers["Authorization"] = "Bearer " + self.github_token
            elif self.nvd_key:
                headers["apiKey"] = self.nvd_key
            started, tick = utc_now(), time.monotonic()
            try:
                response = self.client.get(url, headers=headers, timeout=self.timeout,
                                           follow_redirects=False)
                body = response.content
                receipt = {
                    **base, "status": response.status_code, "sha256": digest(body),
                    "started_at": started, "captured_at": utc_now(),
                    "elapsed_seconds": time.monotonic() - tick,
                    "headers": {k: v for k, v in response.headers.items()
                                if k.lower() in SAFE_HEADERS},
                }
            except httpx.HTTPError as exc:
                receipt = {
                    **base, "status": None, "sha256": None, "started_at": started,
                    "captured_at": utc_now(), "elapsed_seconds": time.monotonic() - tick,
                    "error": type(exc).__name__,
                }
                save_json(receipt_path, receipt, exclusive=True)
                raise CaptureError("HTTP transport failure: " + type(exc).__name__) from exc
        with body_path.open("xb") as out:
            out.write(body)
        save_json(receipt_path, receipt, exclusive=True)
        payload = self._checked(body, receipt, url, local=True,
                                ghsa=name.startswith("ghsa-"))
        return payload, receipt, False

    def stream(self, name, result):
        slices = [self.window] if name.startswith("ghsa-") else nvd_slices(self.window)
        initial = stream_url(name, slices[0])
        url, expected_index, total, part, done = initial, 0, None, 0, 0
        seen_urls, seen_ids = set(), set()
        for page in range(self.max_pages):
            if url in seen_urls:
                raise CaptureError("Repeated pagination URL")
            seen_urls.add(url)
            data, receipt, reused = self.page(name, page, url)
            ids = []
            if name.startswith("ghsa-"):
                if not isinstance(data, list) or len(data) > 100:
                    raise CaptureError("Invalid GitHub advisory page schema/count")
                for record in data:
                    ident = record.get("ghsa_id") if isinstance(record, dict) else None
                    if not isinstance(ident, str) or not re.fullmatch(
                            r"GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}", ident):
                        raise CaptureError("GitHub advisory identity missing/invalid")
                    ids.append(ident.upper())
                next_url = github_next(receipt.get("headers", {}).get("link"), initial)
                if next_url and not ids:
                    raise CaptureError("Empty GitHub page has a next cursor")
            else:
                if not isinstance(data, dict):
                    raise CaptureError("Invalid NVD page schema")
                index, count, reported = (data.get(k) for k in
                                          ("startIndex", "resultsPerPage", "totalResults"))
                if any(type(v) is not int or v < 0 for v in (index, count, reported)):
                    raise CaptureError("NVD pagination values must be nonnegative integers")
                if index != expected_index:
                    raise CaptureError("NVD startIndex drift")
                if total is not None and total != reported:
                    raise CaptureError("NVD totalResults drift across pages")
                total = reported
                records = data.get("vulnerabilities")
                if (not isinstance(records, list) or count != len(records)
                        or count != min(2000, max(0, total - index)) or index > total):
                    raise CaptureError("NVD count/total mismatch or incomplete page")
                for wrapper in records:
                    cve = wrapper.get("cve") if isinstance(wrapper, dict) else None
                    ident = cve.get("id") if isinstance(cve, dict) else None
                    if not isinstance(ident, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", ident):
                        raise CaptureError("NVD CVE identity missing/invalid")
                    ids.append(ident)
                expected_index += count
                next_url = (stream_url(name, slices[part], expected_index)
                            if expected_index < total else None)
                result["total_results"] = done + total
            if len(set(ids)) != len(ids) or seen_ids.intersection(ids):
                raise CaptureError("Duplicate identity within stream; pagination drift")
            seen_ids.update(ids)
            if total is not None and next_url is None and part + 1 < len(slices):
                if len(seen_ids) != done + total:
                    raise CaptureError("NVD terminal unique count does not equal total")
                part, done, expected_index, total = part + 1, done + total, 0, None
                next_url = stream_url(name, slices[part])
            if not name.startswith("ghsa-"):
                result["slices_complete"] = part if next_url else len(slices)
            result["pages"] += 1
            result["rows"] += len(ids)
            result["unique_ids"] = len(seen_ids)
            result["body_paths"].append(f"{name}-{page:04d}.body")
            result["page_receipts"].append({
                "path": f"{name}-{page:04d}.receipt.json", "url": url,
                "sha256": receipt["sha256"], "status": receipt["status"],
                "captured_at": receipt["captured_at"], "reused": reused,
                "rows": len(ids), "next_url": next_url,
            })
            if next_url is None:
                if total is not None and len(seen_ids) != done + total:
                    raise CaptureError("NVD terminal unique count does not equal total")
                result["complete"] = True
                result["status"] = "COMPLETE"
                result["termination"] = "Link exhausted" if name.startswith("ghsa-") else "unique_count=totalResults"
                return
            url = next_url
        raise CaptureError("Page limit reached; stream incomplete")

    def run(self, window_pin=None):
        with output_lock(self.output):
            contract_path = self.output / "fetch-contract.json"
            coverage = {
                "schema": SCHEMA, "status": "IN_PROGRESS", "window": self.window,
                "window_source": window_pin, "github_api_version": API_VERSION,
                "started_at": utc_now(), "streams": [], "body_paths": [], "errors": [],
                "consistency_limit": "Remote APIs are not atomic snapshots. Cursor loops, "
                "duplicate IDs, NVD total/start/count drift are rejected; "
                "constant-count concurrent changes cannot be ruled out.",
            }
            coverage_path = self.output / "coverage.json"
            if contract_path.exists():
                if json.loads(contract_path.read_text()) != self.contract:
                    raise CaptureError("Output contract differs; use a separate directory")
            else:
                save_json(contract_path, self.contract, exclusive=True)
            for name in STREAMS:
                coverage["streams"].append({
                    "name": name, "source": "ghsa" if name.startswith("ghsa-") else "nvd",
                    "complete": False, "status": "NOT_STARTED", "pages": 0, "rows": 0,
                    "unique_ids": 0, "errors": [], "body_paths": [], "page_receipts": [],
                })
            save_json(coverage_path, coverage)
            for result in coverage["streams"]:
                result["status"] = "IN_PROGRESS"
                try:
                    self.stream(result["name"], result)
                except (CaptureError, OSError, ValueError, KeyError, TypeError) as exc:
                    error = str(exc) if isinstance(exc, CaptureError) else type(exc).__name__
                    result["status"] = "FAILED"
                    result["errors"].append(error)
                    coverage["errors"].append({"stream": result["name"], "error": error})
                    coverage["status"] = "INCOMPLETE"
                coverage["body_paths"] = [p for s in coverage["streams"] for p in s["body_paths"]]
                save_json(coverage_path, coverage)
                if coverage["status"] == "INCOMPLETE":
                    break
            if all(s["complete"] for s in coverage["streams"]):
                coverage["status"] = "COMPLETE"
            coverage["finished_at"] = utc_now()
            save_json(coverage_path, coverage)
            return coverage


def main(argv=None):
    parser = argparse.ArgumentParser(description='Capture six frozen advisory streams')
    parser.add_argument("--window", required=True, type=Path)
    parser.add_argument("--start", help="Optional assertion; must match window.json")
    parser.add_argument("--end", help="Optional assertion; must match window.json")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--adopt-probes", type=Path,
                        help="Explicitly adopt exact-URL, 200, hash-verified initial probes")
    parser.add_argument("--timeout", type=float, default=45)
    parser.add_argument("--max-pages", type=int, default=10000)
    args = parser.parse_args(argv)
    try:
        window, pin = frozen_window(args.window, args.start, args.end)
        with httpx.Client(follow_redirects=False) as client:
            report = Capturer(
                args.output, window, client, adopt_probes=args.adopt_probes,
                github_token=os.environ.get("GITHUB_TOKEN"),
                nvd_key=os.environ.get("NVD_API_KEY"), timeout=args.timeout,
                max_pages=args.max_pages,
            ).run(pin)
        print(json.dumps({"status": report["status"], "coverage": str(args.output / "coverage.json"),
                          "streams_complete": sum(s["complete"] for s in report["streams"])}))
        return 0 if report["status"] == "COMPLETE" else 1
    except (CaptureError, OSError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "FAILED", "error": str(exc) if isinstance(exc, CaptureError)
                          else type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
