#!/usr/bin/env python3
"""Freeze the round11 top-500 open cases and write one-case audit bundles."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys_path_lane = Path(__file__).resolve().parent
if str(sys_path_lane) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(sys_path_lane))

from rank import (
    CLONE_INDEX,
    EXCLUDED_MANIFEST,
    LANE,
    LEDGER,
    MAX_PER_REPO,
    ROOT,
    TARGET,
    jsonl,
    load_live_inputs,
    normalize_repo,
    official_ids,
    recompute_selection,
)

QUEUE = ROOT / ".ai-slop/state/research-queue/round11"
HISTORY = ROOT / "artifacts/ledger-history/versions"
SITE = ROOT / "web/src/generated/research-data.json"
CACHE_DIRS = [
    QUEUE / "advisory-cache",
    ROOT / ".ai-slop/state/research-queue/round10/advisory-cache",
    ROOT / ".ai-slop/state/research-queue/round9/advisory-cache",
]


def clone_url(repo: str) -> str:
    if "." in repo.partition("/")[0]:
        return f"https://{repo}.git"
    return f"https://github.com/{repo}.git"


def load_revisions() -> dict[str, int]:
    revisions: dict[str, int] = {}
    if not HISTORY.exists():
        return revisions
    for path in sorted(HISTORY.glob("*.jsonl")):
        for row in jsonl(path):
            revisions[row["class_id"]] = max(revisions.get(row["class_id"], 0), row["revision"])
    return revisions


def _cache_path(ghsa: str) -> Path:
    name = f"{ghsa.upper()}.json"
    for directory in CACHE_DIRS:
        candidate = directory / name
        if candidate.exists():
            return candidate
    CACHE_DIRS[0].mkdir(parents=True, exist_ok=True)
    return CACHE_DIRS[0] / name


def advisory(ghsa: str) -> dict:
    cache = _cache_path(ghsa)
    last_error: Exception | None = None
    cache.parent.mkdir(parents=True, exist_ok=True)
    if not cache.exists():
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ai-slop-round11",
        }
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            f"https://api.github.com/advisories/{ghsa}",
            headers=headers,
        )
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=45) as response:
                    cache.write_bytes(response.read())
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    return {
                        "id": ghsa,
                        "source": f"https://api.github.com/advisories/{ghsa}",
                        "fetch_error": "HTTP 404",
                    }
                if exc.code != 429 and exc.code < 500:
                    raise
                last_error = exc
            except (TimeoutError, urllib.error.URLError) as exc:
                last_error = exc
            if attempt < 2:
                time.sleep(2**attempt)
        else:
            return {
                "id": ghsa,
                "source": f"https://api.github.com/advisories/{ghsa}",
                "fetch_error": str(last_error),
            }
    raw = json.loads(cache.read_text())
    return {
        "id": raw.get("ghsa_id") or ghsa,
        "cve_id": raw.get("cve_id"),
        "summary": raw.get("summary"),
        "description": raw.get("description"),
        "severity": raw.get("severity"),
        "cvss": raw.get("cvss"),
        "cwes": raw.get("cwes"),
        "published_at": raw.get("published_at"),
        "updated_at": raw.get("updated_at"),
        "withdrawn_at": raw.get("withdrawn_at"),
        "vulnerabilities": raw.get("vulnerabilities"),
        "references": [
            item.get("url") if isinstance(item, dict) else str(item)
            for item in raw.get("references") or []
        ],
        "source": f"https://api.github.com/advisories/{ghsa}",
        "fetch_error": raw.get("fetch_error"),
    }


def tokens(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9_./-]{4,}", text.lower())
        if token not in {"with", "from", "that", "this", "when", "into", "none"}
    }


def same_repo_hits(repo: str, advisory_text: str, site_cases: list[dict]) -> list[dict]:
    target = tokens(advisory_text)
    hits = []
    for case in site_cases:
        if normalize_repo(case.get("repository")) != repo:
            continue
        description = " ".join(
            str(case.get(key) or "")
            for key in ("mechanism", "scope_statement", "case_id", "cause_category")
        )
        overlap = len(target & tokens(description))
        hits.append((overlap, case))
    hits.sort(key=lambda item: (-item[0], item[1].get("case_id") or ""))
    return [
        {
            "case_id": case.get("case_id"),
            "aliases": case.get("aliases"),
            "mechanism": case.get("mechanism"),
            "scope_statement": case.get("scope_statement"),
            "candidate_set": case.get("candidate_set"),
            "minimum_fix_set": case.get("minimum_fix_set"),
            "ai_marker": (case.get("code_evidence") or {}).get("ai_marker"),
            "token_overlap": overlap,
        }
        for overlap, case in hits[:8]
    ]


def main() -> None:
    LANE.mkdir(parents=True, exist_ok=True)
    (LANE / "primary").mkdir(exist_ok=True)
    QUEUE.mkdir(parents=True, exist_ok=True)
    (QUEUE / "advisory-cache").mkdir(parents=True, exist_ok=True)

    inputs = load_live_inputs()
    selected = recompute_selection(inputs)
    revisions = load_revisions()
    site_cases = json.loads(SITE.read_text()).get("cases") or []
    ledger_sha = inputs["ledger_sha256"]
    clone_index = inputs["clone_index"]

    ghsas = []
    for score, class_id, row, signals in selected:
        ids = row.get("advisory_ids") or []
        ghsa = next(str(value).upper() for value in ids if str(value).upper().startswith("GHSA-"))
        ghsas.append(ghsa)
    advisories: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {executor.submit(advisory, ghsa): ghsa for ghsa in dict.fromkeys(ghsas)}
        for future in as_completed(futures):
            ghsa = futures[future]
            advisories[ghsa] = future.result()

    manifest = []
    per_repo: Counter[str] = Counter()
    for ordinal, (score, class_id, row, signals) in enumerate(selected):
        worker = f"w{ordinal:03d}"
        repo = normalize_repo(row.get("repo"))
        ids = row.get("advisory_ids") or []
        ghsa = next(str(value).upper() for value in ids if str(value).upper().startswith("GHSA-"))
        clone_dir = clone_index.get(repo)
        if not clone_dir or not (Path(clone_dir) / ".git").exists():
            clone_dir = str(ROOT / ".ai-slop/state/repos" / repo.replace("/", "_"))
        advisory_record = advisories[ghsa]
        bundle = {
            "schema_version": "causal-audit-bundle/1",
            "class_id": class_id,
            "repo": repo,
            "clone_dir": clone_dir,
            "clone_url": clone_url(repo),
            "advisory_ids": ids,
            "base_ledger_revision": revisions.get(class_id, 1),
            "ledger_snapshot_sha256": ledger_sha,
            "advisory": advisory_record,
            "same_repository_prior_hits": same_repo_hits(
                repo,
                " ".join(str(advisory_record.get(key) or "") for key in ("summary", "description")),
                site_cases,
            ),
            "protocol": "docs/AUDIT-PROTOCOL.md",
            "context_rule": "This bundle is the only case-specific starting context; do not read the ledger or another case.",
        }
        bundle_path = QUEUE / f"case-{class_id}.json"
        bundle_path.write_text(json.dumps(bundle, ensure_ascii=False, indent=1) + "\n")
        per_repo[repo] += 1
        manifest.append(
            {
                "ordinal": ordinal,
                "worker": worker,
                "class_id": class_id,
                "status_at_selection": row["status"],
                "base_ledger_revision": revisions.get(class_id, 1),
                "repo": repo,
                "advisory_ids": ids,
                "score": score,
                "signals": signals,
                "bundle": str(bundle_path.relative_to(ROOT)),
                "bundle_sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
                "clone_dir": clone_dir,
                "clone_url": clone_url(repo),
                "primary_out": f"research/round11-top500-20260829/primary/{worker}.json",
            }
        )

    (LANE / "manifest.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in manifest)
    )
    used_advisories = {value for row in manifest for value in official_ids(row)}
    excluded = jsonl(EXCLUDED_MANIFEST)
    excluded_classes = {row["class_id"] for row in excluded}
    excluded_advisories = {str(value).upper() for row in excluded for value in row.get("advisory_ids") or []}
    overlap = len({row["class_id"] for row in manifest} & excluded_classes) + len(
        used_advisories & excluded_advisories
    )
    summary = {
        "target": TARGET,
        "eligible": sum(
            1
            for row in inputs["ledger"]
            if row.get("status") in {"UNANALYZED", "PARTIALLY_ANALYZED"}
            and row["class_id"] not in excluded_classes
            and not (official_ids(row) & excluded_advisories)
        ),
        "excluded_manifest": str(EXCLUDED_MANIFEST.relative_to(ROOT)),
        "excluded_cases": len(excluded_classes),
        "excluded_overlap": overlap,
        "selected_statuses": dict(Counter(row["status_at_selection"] for row in manifest)),
        "selected_repositories": len(per_repo),
        "score_max": selected[0][0],
        "score_min": selected[-1][0],
        "repo_cap": MAX_PER_REPO,
        "clone_ready_cases": sum("clone_ready" in row["signals"] for row in manifest),
        "known_tp_repo_cases": sum(
            any(signal.startswith("known_tp_repo") for signal in row["signals"]) for row in manifest
        ),
        "ledger_sha256_at_freeze": ledger_sha,
        "selection_rule": (
            "Deterministic score over current UNANALYZED/PARTIALLY_ANALYZED union after "
            "excluding every class/advisory in research/round10-top200-20260828/manifest.jsonl; "
            "direct repo AI-commit scan dominates, then known-TP repo, AI commit count, "
            "advisory quality/recency, clone readiness; max five cases per repo; GHSA required."
        ),
    }
    (LANE / "selection-summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
