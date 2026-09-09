#!/usr/bin/env python3
"""Fail a site build when a published advisory source is unreachable."""
from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_cache import load as cache_load, save as cache_save, fresh as cache_fresh

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = ROOT / "web/src/generated/research-data.json"
USER_AGENT = "vibe-security-radar-link-check"


def check_url(url: str, attempts: int = 6) -> tuple[int, str]:
    for method in ("HEAD", "GET"):
        for attempt in range(attempts):
            try:
                request = Request(url, method=method, headers={"User-Agent": USER_AGENT})
                with urlopen(request, timeout=10) as response:
                    return response.status, response.geturl()
            except HTTPError as error:
                # 405 Method Not Allowed or 403 on HEAD: fall back to GET.
                if method == "HEAD" and error.code in (405, 403):
                    break
                if error.code < 500 and error.code != 429:
                    return error.code, url
            except (TimeoutError, URLError, ValueError):
                pass
            if attempt + 1 < attempts:
                time.sleep(min(30.0, 2.0 * (2**attempt)))
    return 0, url


def main(argv: list[str] | None = None) -> int:
    path = Path(argv[1]) if argv and len(argv) > 1 else DEFAULT_DATA
    payload = json.loads(path.read_text(encoding="utf-8"))
    argv = argv if argv is not None else sys.argv[1:]
    force = "--force-online" in argv
    sources = {
        str(case.get("case_id") or ""): str(case.get("advisory_url") or "").strip()
        for case in payload.get("cases") or []
    }
    missing = sorted(case_id for case_id, url in sources.items() if not url)
    reachable = {case_id: url for case_id, url in sources.items() if url}

    cache = {} if force else cache_load()
    entries = cache.get("advisory_links") or {}
    results = {}
    stale = {}
    for case_id, url in reachable.items():
        entry = entries.get(url)
        if not force and cache_fresh(entry):
            results[case_id] = (entry["status"], entry["final_url"])
        else:
            stale[case_id] = url

    if stale:
        with ThreadPoolExecutor(max_workers=8) as pool:
            online = dict(
                zip(
                    stale.keys(),
                    pool.map(check_url, stale.values()),
                    strict=True,
                )
            )
        results.update(online)
        for case_id, (status, final_url) in online.items():
            if 200 <= status < 400:
                entries[stale[case_id]] = {
                    "verified_at": time.time(),
                    "status": status,
                    "final_url": final_url,
                }
        cache["advisory_links"] = entries
        cache_save(cache)
    broken = [
        {"case_id": case_id, "url": reachable[case_id], "status": status}
        for case_id, (status, _) in results.items()
        if status < 200 or status >= 400
    ]
    print(
        json.dumps(
            {
                "advisory_links": "FAIL" if missing or broken else "OK",
                "checked": len(sources),
                "missing": missing,
                "broken": broken,
            },
            sort_keys=True,
        )
    )
    return 1 if missing or broken else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
