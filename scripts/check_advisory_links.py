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

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = ROOT / "web/src/generated/research-data.json"
USER_AGENT = "vibe-security-radar-link-check"


def check_url(url: str, attempts: int = 2) -> tuple[int, str]:
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
                time.sleep(0.5)
    return 0, url


def main(argv: list[str] | None = None) -> int:
    path = Path(argv[1]) if argv and len(argv) > 1 else DEFAULT_DATA
    payload = json.loads(path.read_text(encoding="utf-8"))
    sources = {
        str(case.get("case_id") or ""): str(case.get("advisory_url") or "").strip()
        for case in payload.get("cases") or []
    }
    missing = sorted(case_id for case_id, url in sources.items() if not url)
    reachable = {case_id: url for case_id, url in sources.items() if url}
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = dict(
            zip(
                reachable,
                pool.map(check_url, reachable.values()),
                strict=True,
            )
        )
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
