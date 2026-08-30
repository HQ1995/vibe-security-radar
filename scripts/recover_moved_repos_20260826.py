#!/usr/bin/env python3
"""Recall product git for funnel clusters whose clone 404'd or never parsed.

Looks for GitHub transfers/renames (API follows the old slug), org/user page
false slugs, and reviewed in-window clusters with no product git. Does not
write the ledger.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import oss_git_repos as oss
import recover_advisory_ids_20260826 as rec

ROOT = rec.ROOT
STATE = rec.STATE
CLUSTERS = STATE / "upstream-deduped-20260826.jsonl"
SCAN_RESULTS = ROOT / ".ai-slop/state/funnel-ai-writer-20260826/scan-results.jsonl"
OUT_JSON = ROOT / "artifacts/moved-repo-recall-20260826.json"
OUT_MD = ROOT / "artifacts/moved-repo-recall-20260826.md"

FALSE_SLUG_OWNERS = frozenset(
    {"advisories", "apps", "gist", "github", "nvd", "orgs", "security", "sponsors", "users"}
)
POCISH = (
    "cve",
    "cves",
    "cvec",
    "vuln",
    "vuldb",
    "poc",
    "disclosure",
    "exploit",
    "blob0",
    "jjjjjzr",
)


def latest_scan_rows() -> dict[str, dict]:
    latest: dict[str, dict] = {}
    if not SCAN_RESULTS.is_file():
        return latest
    with SCAN_RESULTS.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            repo = row.get("repo")
            if repo:
                latest[repo] = row
    return latest


def clone_not_found(row: dict) -> bool:
    err = f"{row.get('clone_error') or ''} {row.get('scan_error') or ''}"
    return "Repository not found" in err


def github_slug_of(ident: str) -> str | None:
    raw = (ident or "").strip().lower().rstrip("/")
    if raw.startswith("github.com/"):
        raw = raw[len("github.com/") :]
    if raw.count("/") != 1:
        return None
    owner, name = raw.split("/", 1)
    if "." in owner:
        return None
    return f"{owner}/{name}"


def is_pocish(slug: str) -> bool:
    blob = slug.lower()
    return any(token in blob for token in POCISH)


def classify_slug(slug: str) -> str:
    owner, _, name = slug.partition("/")
    if owner in FALSE_SLUG_OWNERS:
        return "false_slug"
    if is_pocish(slug):
        return "pocish"
    return "candidate"


def github_request(path: str, token: str) -> tuple[int, dict | list | None]:
    url = "https://api.github.com" + path
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "ai-slop-moved-repo-recall",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            return resp.status, payload
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            payload = json.loads(body.decode("utf-8")) if body else None
        except json.JSONDecodeError:
            payload = None
        return exc.code, payload
    except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError):
        return 0, None


def resolve_github(slug: str, token: str) -> dict:
    status, payload = github_request(f"/repos/{slug}", token)
    if status == 200 and isinstance(payload, dict):
        full = str(payload.get("full_name") or "").lower()
        return {
            "status": "ok",
            "http": status,
            "full_name": full,
            "moved": full != slug.lower(),
            "private": bool(payload.get("private")),
            "archived": bool(payload.get("archived")),
            "html_url": payload.get("html_url"),
        }
    if status == 404:
        owner, _, name = slug.partition("/")
        q = urllib.parse.quote(f"{name} in:name")
        search_status, search = github_request(
            f"/search/repositories?q={q}&per_page=5", token
        )
        items = (search or {}).get("items") if isinstance(search, dict) else []
        hits = []
        for item in items or []:
            full = str(item.get("full_name") or "").lower()
            if full.rsplit("/", 1)[-1] == name.lower():
                hits.append(
                    {
                        "full_name": full,
                        "stars": item.get("stargazers_count"),
                        "html_url": item.get("html_url"),
                    }
                )
        return {
            "status": "not_found",
            "http": status,
            "search_http": search_status,
            "same_name_hits": hits[:5],
        }
    if status in {301, 302}:
        return {"status": "redirect", "http": status, "payload": payload}
    return {"status": "error", "http": status}


def load_reviewed_no_repo() -> list[dict]:
    out = []
    with CLUSTERS.open(encoding="utf-8") as handle:
        for line in handle:
            cluster = json.loads(line)
            if (
                cluster.get("in_window")
                and cluster.get("reviewed")
                and not cluster.get("repo")
            ):
                out.append(cluster)
    return out


def index_reviewed_ghsa() -> dict[str, Path]:
    root = rec.GHSA_ROOT / "github-reviewed"
    out: dict[str, Path] = {}
    if not root.is_dir():
        return out
    for path in root.rglob("GHSA-*.json"):
        out[path.stem.upper()] = path
    return out


_GHSA_INDEX: dict[str, Path] | None = None


def ghsa_urls(ghsa_id: str) -> list[str]:
    global _GHSA_INDEX
    if _GHSA_INDEX is None:
        _GHSA_INDEX = index_reviewed_ghsa()
    path = _GHSA_INDEX.get(ghsa_id.upper())
    if path is None:
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return oss.collect_urls(raw)


def identities_from_cluster(cluster: dict) -> dict[str, str]:
    urls: list[str] = []
    for ghsa_id in cluster.get("ghsa_ids") or []:
        urls.extend(ghsa_urls(ghsa_id))
    return oss.identities_from_urls(urls)


def main() -> int:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    scan = latest_scan_rows()
    not_found = sorted(
        repo for repo, row in scan.items() if clone_not_found(row) and github_slug_of(repo)
    )
    classified = Counter(classify_slug(github_slug_of(r) or r) for r in not_found)
    resolved = []
    candidates = [r for r in not_found if classify_slug(github_slug_of(r) or r) == "candidate"]
    if token:
        for ident in candidates:
            slug = github_slug_of(ident)
            if not slug:
                continue
            hit = resolve_github(slug, token)
            hit["from"] = ident
            resolved.append(hit)
            time.sleep(0.05)
    else:
        print("no GITHUB_TOKEN; skip live GitHub resolve", flush=True)

    moved = [h for h in resolved if h.get("moved")]
    alive_same = [h for h in resolved if h.get("status") == "ok" and not h.get("moved")]
    name_hits = [
        h
        for h in resolved
        if h.get("status") == "not_found" and h.get("same_name_hits")
    ]

    reviewed = load_reviewed_no_repo()
    recovered_no_repo = []
    for cluster in reviewed:
        hits = identities_from_cluster(cluster)
        if not hits:
            continue
        recovered_no_repo.append(
            {
                "class_id": cluster["class_id"],
                "public_ids": cluster.get("public_ids"),
                "identities": hits,
            }
        )

    report = {
        "ledger_untouched": True,
        "scan_not_found_github": len(not_found),
        "classified": dict(classified),
        "github_token": bool(token),
        "candidates_probed": len(resolved),
        "moved": moved,
        "alive_same_slug": alive_same,
        "not_found_same_name_hits": name_hits,
        "false_slugs": [
            r for r in not_found if classify_slug(github_slug_of(r) or r) == "false_slug"
        ],
        "reviewed_no_repo": len(reviewed),
        "reviewed_no_repo_now_has_git_urls": recovered_no_repo,
    }
    OUT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Moved-repo recall — 2026-08-26",
        "",
        "Recall pass over funnel clone-404 GitHub slugs and in-window reviewed",
        "clusters with no product git. Ledger not written.",
        "",
        f"- Scan `Repository not found` GitHub identities: **{len(not_found)}**",
        f"- Classified: `{dict(classified)}`",
        f"- Live GitHub probes of non-PoC candidates: **{len(resolved)}**",
        f"- Transfers / renames (API `full_name` ≠ old slug): **{len(moved)}**",
        f"- Same slug now cloneable: **{len(alive_same)}**",
        f"- 404 but same-name search hits: **{len(name_hits)}**",
        f"- False slugs (`orgs/` `users/` …): **{len(report['false_slugs'])}**",
        f"- In-window reviewed, no repo: **{len(reviewed)}**",
        f"- Of those, GHSA URLs now parse to git identities: **{len(recovered_no_repo)}**",
        "",
        "## Transfers / renames",
        "",
    ]
    if not moved:
        lines.append("None on this pass.")
    for hit in moved:
        lines.append(
            f"- `{hit['from']}` → `{hit['full_name']}`"
            f"{' (archived)' if hit.get('archived') else ''}"
        )
    lines += ["", "## Same slug now alive", ""]
    if not alive_same:
        lines.append("None.")
    for hit in alive_same:
        lines.append(f"- `{hit['from']}`")
    lines += ["", "## 404 with same-name hits", ""]
    if not name_hits:
        lines.append("None.")
    for hit in name_hits:
        names = ", ".join(
            f"`{x['full_name']}` ({x.get('stars')}★)" for x in hit.get("same_name_hits") or []
        )
        lines.append(f"- `{hit['from']}` → {names}")
    lines += ["", "## False slugs", ""]
    for slug in report["false_slugs"]:
        lines.append(f"- `{slug}`")
    lines += ["", "## Reviewed no-repo with newly parsed git URLs", ""]
    if not recovered_no_repo:
        lines.append("None on this pass (GHSA cache miss or still no forge URL).")
    for row in recovered_no_repo:
        ids = ", ".join(row.get("public_ids") or [])
        idents = ", ".join(f"`{k}`" for k in (row.get("identities") or {}))
        lines.append(f"- `{row['class_id']}` ({ids}): {idents}")
    lines.append("")
    OUT_MD.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({k: report[k] for k in (
        "scan_not_found_github",
        "classified",
        "candidates_probed",
        "reviewed_no_repo",
        "reviewed_no_repo_now_has_git_urls",
    ) if k != "reviewed_no_repo_now_has_git_urls"} | {
        "moved_n": len(moved),
        "alive_n": len(alive_same),
        "name_hits_n": len(name_hits),
        "reviewed_recovered_n": len(recovered_no_repo),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
