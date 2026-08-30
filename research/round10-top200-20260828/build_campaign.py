#!/usr/bin/env python3
"""Select and bundle the 200 highest-signal open ledger cases."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import urllib.error
import urllib.request
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round10-top200-20260828"
QUEUE = ROOT / ".ai-slop/state/research-queue/round10"
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
SCAN_RESULTS = ROOT / ".ai-slop/state/funnel-ai-writer-20260826/scan-results.jsonl"
CLONE_INDEX = ROOT / ".ai-slop/state/funnel-ai-writer-20260826/existing-clone-index.json"
HISTORY = ROOT / "artifacts/ledger-history/versions"
SITE = ROOT / "web/src/generated/research-data.json"
EXCLUDED_MANIFEST = ROOT / "research/round9-top200-20260828/external-review-manifest.jsonl"
MAX_PER_REPO = 5
TARGET = 200


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def normalize_repo(repo: str | None) -> str:
    value = (repo or "").strip().lower()
    return value.removeprefix("https://").removeprefix("http://").removeprefix("github.com/")


def load_revisions() -> dict[str, int]:
    revisions: dict[str, int] = {}
    for path in sorted(HISTORY.glob("*.jsonl")):
        for row in jsonl(path):
            revisions[row["class_id"]] = max(revisions.get(row["class_id"], 0), row["revision"])
    return revisions


def clone_url(repo: str) -> str:
    if "." in repo.partition("/")[0]:
        return f"https://{repo}.git"
    return f"https://github.com/{repo}.git"


def advisory(ghsa: str) -> dict | None:
    cache = QUEUE / "advisory-cache" / f"{ghsa.upper()}.json"
    last_error: Exception | None = None
    cache.parent.mkdir(parents=True, exist_ok=True)
    if not cache.exists():
        request = urllib.request.Request(
            f"https://api.github.com/advisories/{ghsa}",
            headers={
                "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=45) as response:
                    cache.write_bytes(response.read())
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    return None
                if exc.code != 429 and exc.code < 500:
                    raise
                last_error = exc
            except (TimeoutError, urllib.error.URLError) as exc:
                last_error = exc
            if attempt < 2:
                time.sleep(2**attempt)
        else:
            assert last_error is not None
    raw = (
        json.loads(cache.read_text())
        if cache.exists()
        else {"ghsa_id": ghsa, "fetch_error": str(last_error)}
    )
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
        "references": [item.get("url") if isinstance(item, dict) else str(item) for item in raw.get("references") or []],
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
    (LANE / "review").mkdir(exist_ok=True)
    QUEUE.mkdir(parents=True, exist_ok=True)

    ledger = jsonl(LEDGER)
    excluded = jsonl(EXCLUDED_MANIFEST)
    excluded_class_ids = {row["class_id"] for row in excluded}
    excluded_advisory_ids = {
        str(advisory_id).upper()
        for row in excluded
        for advisory_id in row.get("advisory_ids") or []
    }
    eligible = [
        row
        for row in ledger
        if row.get("status") in {"UNANALYZED", "PARTIALLY_ANALYZED"}
        and row["class_id"] not in excluded_class_ids
        and not ({str(value).upper() for value in row.get("advisory_ids") or []} & excluded_advisory_ids)
    ]
    scans: dict[str, dict] = {}
    for item in jsonl(SCAN_RESULTS):
        repo = normalize_repo(item.get("repo"))
        if not repo:
            continue
        if repo not in scans or int(item.get("ai_commit_count") or 0) > int(scans[repo].get("ai_commit_count") or 0):
            scans[repo] = item
    tp_repos = Counter(
        normalize_repo(row.get("repo"))
        for row in ledger
        if row.get("status") in {"AI_ROOT_CAUSE", "AI_CODE_FLAWED"}
    )
    clone_index = {normalize_repo(key): value for key, value in json.loads(CLONE_INDEX.read_text()).items()}
    revisions = load_revisions()
    site_cases = json.loads(SITE.read_text()).get("cases") or []

    ranked = []
    for row in eligible:
        repo = normalize_repo(row.get("repo"))
        score = 0.0
        signals = []
        if row.get("leftover_bucket") == "has_ai":
            score += 100
            signals.append("repo_ai_commit_scan")
        if tp_repos[repo]:
            score += 45 + min(10, tp_repos[repo] * 2)
            signals.append(f"known_tp_repo:{tp_repos[repo]}")
        ai_count = int((scans.get(repo) or {}).get("ai_commit_count") or 0)
        if ai_count:
            score += min(30, 5 * math.log2(ai_count + 1))
            signals.append(f"ai_commits:{ai_count}")
        kind = row.get("leftover_kind")
        if kind == "reviewed":
            score += 15
            signals.append("reviewed_advisory")
        elif kind == "unreviewed":
            score += 8
            signals.append("unreviewed_advisory")
        elif kind == "nvd_only":
            signals.append("nvd_only")
        ids = row.get("advisory_ids") or []
        if any(str(value).upper().startswith("GHSA-") for value in ids):
            score += 15
            signals.append("ghsa_bundle")
        if any(str(value).upper().startswith("CVE-2026-") for value in ids):
            score += 8
            signals.append("2026")
        elif any(str(value).upper().startswith("CVE-2025-") for value in ids):
            score += 3
            signals.append("2025")
        if len(ids) >= 2:
            score += 5
        clone_dir = clone_index.get(repo)
        if clone_dir and (Path(clone_dir) / ".git").exists():
            score += 20
            signals.append("clone_ready")
        if row.get("status") == "PARTIALLY_ANALYZED":
            score += 5
            prior = row.get("partial_wave_verdict")
            if prior == "EVIDENCE_GAP":
                score += 8
                signals.append("prior_evidence_gap")
            elif prior == "NOT_AI":
                score -= 70
                signals.append("prior_not_ai")
            elif prior == "BLOCKED":
                score -= 80
                signals.append("prior_blocked")
        ranked.append((round(score, 3), row["class_id"], row, signals))
    ranked.sort(key=lambda item: (-item[0], item[1]))

    selected = []
    per_repo: Counter[str] = Counter()
    used_advisory_ids: set[str] = set()
    for score, class_id, row, signals in ranked:
        repo = normalize_repo(row.get("repo"))
        if per_repo[repo] >= MAX_PER_REPO:
            continue
        ghsas = [
            str(value).upper()
            for value in row.get("advisory_ids") or []
            if str(value).upper().startswith("GHSA-")
        ]
        if not ghsas:
            continue
        ghsa = ghsas[0]
        advisory_record = advisory(ghsa)
        if advisory_record is None:
            continue
        official_ids = {str(value).upper() for value in row.get("advisory_ids") or []}
        if official_ids & used_advisory_ids:
            continue
        selected.append((score, class_id, row, signals, advisory_record))
        per_repo[repo] += 1
        used_advisory_ids.update(official_ids)
        if len(selected) == TARGET:
            break
    assert len(selected) == TARGET
    assert len({item[1] for item in selected}) == TARGET
    assert not ({item[1] for item in selected} & excluded_class_ids)
    assert not (used_advisory_ids & excluded_advisory_ids)

    assert len(used_advisory_ids) == sum(len(set(map(str.upper, item[2]["advisory_ids"]))) for item in selected)
    ledger_sha = hashlib.sha256(LEDGER.read_bytes()).hexdigest()
    manifest = []
    for ordinal, (score, class_id, row, signals, advisory_record) in enumerate(selected):
        worker = f"w{ordinal:03d}"
        repo = normalize_repo(row.get("repo"))
        ids = row.get("advisory_ids") or []
        ghsa = next(str(value).upper() for value in ids if str(value).upper().startswith("GHSA-"))
        clone_dir = clone_index.get(repo)
        if not clone_dir or not (Path(clone_dir) / ".git").exists():
            clone_dir = str(ROOT / ".ai-slop/state/repos" / repo.replace("/", "_"))
        bundle = {
            "schema_version": "causal-audit-bundle/1",
            "class_id": class_id,
            "repo": repo,
            "clone_dir": clone_dir,
            "clone_url": clone_url(repo),
            "advisory_ids": ids,
            "base_ledger_revision": revisions[class_id],
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
        manifest.append(
            {
                "ordinal": ordinal,
                "worker": worker,
                "class_id": class_id,
                "status_at_selection": row["status"],
                "base_ledger_revision": revisions[class_id],
                "repo": repo,
                "advisory_ids": ids,
                "score": score,
                "signals": signals,
                "bundle": str(bundle_path.relative_to(ROOT)),
                "bundle_sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
                "clone_dir": clone_dir,
                "clone_url": clone_url(repo),
                "primary_out": f"research/round10-top200-20260828/primary/{worker}.json",
                "review_out": f"research/round10-top200-20260828/review/{worker}.json",
            }
        )

    manifest_path = LANE / "manifest.jsonl"
    manifest_path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in manifest))
    summary = {
        "target": TARGET,
        "eligible": len(eligible),
        "excluded_manifest": str(EXCLUDED_MANIFEST.relative_to(ROOT)),
        "excluded_cases": len(excluded_class_ids),
        "selected_statuses": dict(Counter(row[2]["status"] for row in selected)),
        "selected_repositories": len(per_repo),
        "score_max": selected[0][0],
        "score_min": selected[-1][0],
        "repo_cap": MAX_PER_REPO,
        "clone_ready_cases": sum("clone_ready" in row[3] for row in selected),
        "known_tp_repo_cases": sum(any(signal.startswith("known_tp_repo") for signal in row[3]) for row in selected),
        "ledger_sha256": ledger_sha,
        "selection_rule": "Deterministic score over current UNANALYZED/PARTIALLY_ANALYZED union after excluding every class/advisory in round9 external-review-manifest; direct repo AI-commit scan dominates, then known-TP repo, AI commit count, advisory quality/recency, clone readiness; max five cases per repo; GHSA required.",
    }
    (LANE / "selection-summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
