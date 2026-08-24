#!/usr/bin/env python3
"""Refresh only the seven Batch 1 alias blockers against first-party APIs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
B1 = ROOT / "autoresearch/herdr-260812-alias-qa"
INPUTS = [
    B1 / "ledger.jsonl",
    B1 / "requests.json",
    B1 / "summary.json",
    B1 / "input_snapshot.json",
    B1 / "report.md",
    B1 / "result.json",
    ROOT / "docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-B-2026-08-12.md",
    ROOT / "docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md",
    ROOT / "docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-D-2026-08-12.md",
    ROOT / "docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md",
]
TARGETS = {
    "misp-mass-assignment@canonical": ("MISP/MISP", ["CVE-2026-56422"]),
    "omnifaces-combined-resource@canonical": ("omnifaces/omnifaces", ["GHSA-FP43-VJ7G-PG92"]),
    "gitea-draft-attachment@canonical": ("go-gitea/gitea", ["CVE-2026-58432", "GHSA-Q9PG-JJ6X-J9P6"]),
    "gitea-oauth-reactivation@canonical": ("go-gitea/gitea", ["CVE-2026-55987", "GHSA-VRHC-JJFC-M3M3"]),
    "praisonai-jwt-default@canonical": ("MervinPraison/PraisonAI", ["CVE-2026-57148", "GHSA-F38V-77QJ-H4JQ"]),
    "gitea-private-org-members@canonical": ("go-gitea/gitea", ["CVE-2026-58427", "GHSA-PRR9-9MP4-5GP2"]),
    "openclaw-feishu-webhook@canonical": (
        "openclaw/openclaw",
        ["CVE-2026-32974", "GHSA-G353-MGV3-8PCJ", "CVE-2026-44109", "GHSA-XH72-V6V9-MWHC"],
    ),
}
COMMIT_URL = re.compile(r"https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})", re.I)
REQUESTS: list[dict[str, object]] = []


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path: Path, value: object) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    tmp.replace(path)


def cache(kind: str, key: str) -> Path:
    path = OUT / "api-cache" / kind / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', key)}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def cve(cve_id: str) -> dict:
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "ai-slop-b2-alias/2026-08-12"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            value, status = json.load(response), response.status
    except urllib.error.HTTPError as error:
        value, status = {"_http_status": error.code, "_error": "HTTP error"}, error.code
    except (urllib.error.URLError, TimeoutError):
        value, status = {"_http_status": 0, "_error": "network error"}, 0
    write_json(cache("cve", cve_id), value)
    REQUESTS.append({"source": "live", "url": url, "status": status})
    return value


def github(endpoint: str, kind: str, key: str) -> dict:
    env = os.environ.copy()
    env["GH_PROMPT_DISABLED"] = "1"
    process = subprocess.run(
        ["gh", "api", endpoint, "-H", "Accept: application/vnd.github+json"],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    status_match = re.search(r"HTTP (\d{3})", process.stderr)
    status = 200 if process.returncode == 0 else int(status_match.group(1)) if status_match else 0
    value = json.loads(process.stdout) if process.returncode == 0 else {"_http_status": status, "_error": "gh api failed"}
    write_json(cache(kind, key), value)
    REQUESTS.append({"source": "live", "command": f"gh api {endpoint}", "status": status})
    return value


def strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def status_of(value: dict) -> int:
    return int(value.get("_http_status", 200))


def main() -> None:
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    snapshots = [
        {"path": str(path.relative_to(ROOT)), "sha256": digest(path), "size": path.stat().st_size, "mtime_ns": path.stat().st_mtime_ns}
        for path in INPUTS
    ]
    rows = [json.loads(line) for line in (B1 / "ledger.jsonl").read_text().splitlines()]
    selected = {row["key"]: row for row in rows if row["key"] in TARGETS}
    assert set(selected) == set(TARGETS) and len(rows) == 76

    live: dict[str, dict] = {}
    commit_refs: set[tuple[str, str]] = set()
    for key, (repo, ids) in TARGETS.items():
        row_evidence = {"repo": repo, "ids": {}, "selected_fixes": selected[key]["proposed_fixes"]}
        for public_id in ids:
            if public_id.startswith("CVE-"):
                value = cve(public_id)
                row_evidence["ids"][public_id] = {"cve": value}
            else:
                global_value = github(f"advisories/{public_id}", "ghsa-global", public_id)
                repo_value = github(
                    f"repos/{repo}/security-advisories/{public_id}",
                    "ghsa-repo",
                    f"{repo}__{public_id}",
                )
                row_evidence["ids"][public_id] = {"global": global_value, "repo": repo_value}
        for fix in selected[key]["proposed_fixes"]:
            commit_refs.add((repo, fix))
        for text in strings(row_evidence):
            for match in COMMIT_URL.finditer(text):
                if match.group(1).lower() == repo.lower():
                    commit_refs.add((repo, match.group(2).lower()))
        live[key] = row_evidence

    commits: dict[str, dict] = {}
    for repo, sha in sorted(commit_refs, key=lambda item: (item[0].lower(), item[1])):
        value = github(f"repos/{repo}/commits/{sha}", "commit", f"{repo}__{sha}")
        commits[f"{repo}@{sha}"] = value

    ended = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    compact = {}
    for key, item in live.items():
        compact[key] = {
            "repo": item["repo"],
            "selected_fixes": item["selected_fixes"],
            "ids": {
                public_id: {
                    source: {
                        "status": status_of(value),
                        "state": value.get("cveMetadata", {}).get("state") if source == "cve" else value.get("state"),
                        "ghsa_id": value.get("ghsa_id"),
                        "cve_id": value.get("cve_id"),
                        "published_at": value.get("published_at"),
                        "withdrawn_at": value.get("withdrawn_at"),
                    }
                    for source, value in sources.items()
                }
                for public_id, sources in item["ids"].items()
            },
        }
    summary = {
        "started_at": started,
        "ended_at": ended,
        "target_rows": len(TARGETS),
        "batch1_rows_not_reaudited": len({row["row_id"] for row in rows}) - len(TARGETS),
        "requests": len(REQUESTS),
        "request_status_counts": {
            str(status): sum(1 for request in REQUESTS if request["status"] == status)
            for status in sorted({int(request["status"]) for request in REQUESTS})
        },
        "commit_objects": len(commits),
        "unresolved_commit_objects": sum(1 for value in commits.values() if status_of(value) != 200),
        "input_snapshot": snapshots,
        "rows": compact,
    }
    write_json(OUT / "input_snapshot.json", {"captured_at": started, "inputs": snapshots})
    write_json(OUT / "live_requests.json", REQUESTS)
    write_json(OUT / "live_evidence.json", live)
    write_json(OUT / "commit_evidence.json", commits)
    write_json(OUT / "live_summary.json", summary)
    assert summary["target_rows"] == 7 and summary["batch1_rows_not_reaudited"] == 67
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
