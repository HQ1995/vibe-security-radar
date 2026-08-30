#!/usr/bin/env python3
"""Dedupe the upstream advisory universe and emit a ledger fill table.

Does not write artifacts/funnel-account-*.jsonl.

Clustering: connected components of GHSA `id` ∪ `aliases`, plus NVD 2025/2026
CVEs that never appear in those components. Withdrawn GHSA / REJECTED CVE
clusters are dropped. class_id uses census canonical case and the CVE+GHSA
member hash (the funnel identity); extra aliases (PYSEC/GO/…) stay on the
cluster as `extra_aliases`.

Outputs:
  .ai-slop/state/refresh-20260826/upstream-deduped-20260826.jsonl
  .ai-slop/state/refresh-20260826/ledger-fill-20260826.jsonl
  .ai-slop/state/refresh-20260826/recovered-oss-git-20260826.jsonl
  artifacts/upstream-dedup-20260826.md
  artifacts/upstream-dedup-20260826.json
  artifacts/no-repo-oss-git-20260826.json
"""
from __future__ import annotations

import gzip
import json
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import date
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import oss_git_repos as oss
import recover_advisory_ids_20260826 as rec

WINDOW_START = date(2025, 5, 1)
WINDOW_END = date(2026, 8, 26)
NVD_DROP = {"REJECTED"}
PUBLIC_PREFIXES = ("CVE-", "GHSA-")

STATE = rec.STATE
CLUSTERS_OUT = STATE / "upstream-deduped-20260826.jsonl"
FILL_OUT = STATE / "ledger-fill-20260826.jsonl"
RECOVERED_OUT = STATE / "recovered-oss-git-20260826.jsonl"
RECOVERED_JSON = rec.ROOT / "artifacts" / "no-repo-oss-git-20260826.json"
STUB_CACHE = STATE / "github-root-listing-20260826.json"
REPORT_JSON = rec.ROOT / "artifacts/upstream-dedup-20260826.json"
REPORT_MD = rec.ROOT / "artifacts/upstream-dedup-20260826.md"
META = rec.ROOT / "artifacts" / "funnel-universe-meta-20260826.json"


def parse_day(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def in_window(day: date | None) -> bool:
    return day is not None and WINDOW_START <= day <= WINDOW_END


def is_public(ident: str) -> bool:
    return ident.startswith("CVE-") or ident.upper().startswith("GHSA-")


def find(parent: dict[str, str], x: str) -> str:
    parent.setdefault(x, x)
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x


def union(parent: dict[str, str], a: str, b: str) -> None:
    ra, rb = find(parent, a), find(parent, b)
    if ra != rb:
        parent[rb] = ra


def iter_all_window_ghsa():
    reviewed = rec.GHSA_ROOT / "github-reviewed"
    if reviewed.is_dir():
        yield from reviewed.rglob("*.json")
    unreviewed = rec.GHSA_ROOT / "unreviewed"
    for year in ("2025", "2026"):
        year_dir = unreviewed / year
        if year_dir.is_dir():
            yield from year_dir.rglob("*.json")


def load_sources() -> tuple[dict[str, dict], dict[str, dict], dict[str, str], int]:
    ghsa: dict[str, dict] = {}
    parent: dict[str, str] = {}
    n_files = 0
    for path in iter_all_window_ghsa():
        n_files += 1
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        ident = raw.get("id")
        if not ident:
            continue
        cid = rec.canon(ident)
        urls = oss.collect_urls(raw)
        ghsa[cid] = {
            "id": cid,
            "aliases": [rec.canon(a) for a in (raw.get("aliases") or []) if a],
            "published": (raw.get("published") or "")[:10],
            "withdrawn": bool(raw.get("withdrawn")),
            "reviewed": "github-reviewed" in path.parts,
            "repos_simple": sorted(rec.repos_from_urls(urls)),
            "repos_oss": sorted(oss.identities_from_urls(urls)),
        }
        find(parent, cid)
        for alias in ghsa[cid]["aliases"]:
            union(parent, cid, alias)

    nvd: dict[str, dict] = {}
    for year in (2025, 2026):
        path = rec.NVD_DIR / f"nvdcve-2.0-{year}.json.gz"
        if not path.is_file():
            continue
        with gzip.open(path) as handle:
            payload = json.load(handle)
        for item in payload.get("vulnerabilities") or []:
            cve = item.get("cve") or {}
            ident = cve.get("id")
            if not ident:
                continue
            cid = rec.canon(ident)
            urls = oss.collect_urls(cve)
            nvd[cid] = {
                "id": cid,
                "published": (cve.get("published") or "")[:10],
                "status": cve.get("vulnStatus") or "",
                "repos_simple": sorted(rec.repos_from_urls(urls)),
                "repos_oss": sorted(oss.identities_from_urls(urls)),
            }
            find(parent, cid)
    return ghsa, nvd, parent, n_files


def primary_repo(repos: list[str]) -> str:
    slugs = []
    seen = set()
    for raw in repos:
        key = raw.strip().lower().rstrip("/")
        if key.startswith("github.com/"):
            key = key[len("github.com/") :]
        if key in seen:
            continue
        seen.add(key)
        slugs.append(key)
    for key in slugs:
        if key.startswith("git.kernel.org"):
            return rec.KERNEL_REPO
        if key.startswith("gitlab.com/"):
            return key
        if "/" in key and "." not in key.split("/")[0]:
            return key
    return slugs[0] if slugs else ""


def build_clusters(ghsa: dict, nvd: dict, parent: dict) -> list[dict]:
    groups: dict[str, set[str]] = defaultdict(set)
    for ident in parent:
        groups[find(parent, ident)].add(ident)

    clusters: list[dict] = []
    for members in groups.values():
        ghsa_ids = sorted(m for m in members if m.upper().startswith("GHSA-") and m in ghsa)
        cve_ids = sorted(m for m in members if m.startswith("CVE-"))
        extras = sorted(
            m
            for m in members
            if not m.startswith("CVE-") and not m.upper().startswith("GHSA-")
        )
        recs = [ghsa[g] for g in ghsa_ids]
        withdrawn = any(r["withdrawn"] for r in recs)
        rejected = any((nvd.get(c) or {}).get("status") in NVD_DROP for c in cve_ids)
        if withdrawn or rejected:
            continue
        for rec_obj in recs:
            extras.extend(a for a in rec_obj["aliases"] if not is_public(a))
        extras = sorted(set(extras))
        public_ids = sorted({*ghsa_ids, *cve_ids})
        if not public_ids:
            continue
        days = [parse_day(r["published"]) for r in recs]
        days += [parse_day((nvd.get(c) or {}).get("published")) for c in cve_ids]
        days = [d for d in days if d]
        published = min(days).isoformat() if days else ""
        simple: set[str] = set()
        oss_ids: set[str] = set()
        for rec_obj in recs:
            simple.update(rec_obj.get("repos_simple") or [])
            oss_ids.update(rec_obj.get("repos_oss") or [])
        for cve in cve_ids:
            rec_nvd = nvd.get(cve) or {}
            simple.update(rec_nvd.get("repos_simple") or [])
            oss_ids.update(rec_nvd.get("repos_oss") or [])
        simple_product = oss.product_identities(simple)
        oss_product = oss.product_identities(oss_ids)
        skipped = [
            ident
            for ident in sorted(simple | oss_ids)
            if oss.non_product_reason(ident)
        ]
        skip_reasons = Counter(oss.non_product_reason(ident) for ident in skipped)
        simple_primary = primary_repo(sorted(simple_product))
        oss_primary = primary_repo(sorted(oss_product))
        if simple_primary:
            repo = simple_primary
            repo_source = "simple"
        elif oss_primary:
            repo = oss_primary
            repo_source = "recovered"
        else:
            repo = ""
            repo_source = ""
        merged: list[str] = []
        seen_repos: set[str] = set()
        for key in ([repo] if repo else []) + sorted(set(simple_product) | set(oss_product)):
            if not key or key in seen_repos:
                continue
            seen_repos.add(key)
            merged.append(key)
        reviewed = any(r["reviewed"] for r in recs)
        clusters.append(
            {
                "class_id": "alias-" + rec.suffix_of(public_ids),
                "public_ids": public_ids,
                "extra_aliases": extras,
                "ghsa_ids": ghsa_ids,
                "reviewed": reviewed,
                "unreviewed_only": bool(recs) and not reviewed,
                "nvd_only": not recs,
                "published": published,
                "in_window": in_window(parse_day(published)),
                "any_in_window": any(in_window(d) for d in days),
                "repo": repo,
                "repo_source": repo_source,
                "repo_skip_reason": (
                    "" if repo else (skip_reasons.most_common(1)[0][0] if skip_reasons else "")
                ),
                "repos": merged[:8],
            }
        )
    return clusters


def ledger_state(row: dict) -> str:
    ids = row.get("advisory_ids") or []
    if not ids:
        return "missing"
    members = [rec.canon(x) for x in ids]
    if rec.suffix_of(members) == row["class_id"][6:]:
        return "hash_ok"
    return "hash_fail"


def unique_subset(ids: list[str], want: str) -> list[str] | None:
    ids = list(dict.fromkeys(ids))
    n = len(ids)
    if n == 0 or n > 12:
        return None
    hits = []
    for k in range(1, n + 1):
        for combo in combinations(ids, k):
            if rec.suffix_of(combo) == want:
                hits.append(combo)
                if len(hits) > 1:
                    return None
    return rec.as_list(hits[0]) if len(hits) == 1 else None


def github_slug_of(repo: str) -> str | None:
    host, owner, name = oss.split_identity(repo)
    if host != "github.com" or not owner or not name:
        return None
    return f"{owner}/{name}"


def _gql_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _entries_from_gql_repo(node: dict | None) -> list[dict]:
    if not node:
        return []
    entries = (
        (((node.get("defaultBranchRef") or {}).get("target") or {}).get("tree") or {}).get(
            "entries"
        )
        or []
    )
    out: list[dict] = []
    for item in entries:
        kind = item.get("type")
        name = item.get("name")
        if not name:
            continue
        if kind == "tree":
            out.append({"name": name, "type": "dir"})
        elif kind == "blob":
            out.append({"name": name, "type": "file"})
    return out


def fetch_github_roots_graphql(slugs: list[str]) -> dict[str, list[dict] | None]:
    """One GraphQL request for many repo roots. Cost is 1 regardless of batch size."""
    if not slugs:
        return {}
    fields = [
        "rateLimit { cost remaining }",
    ]
    for i, slug in enumerate(slugs):
        owner, _, name = slug.partition("/")
        if not owner or not name:
            continue
        fields.append(
            f'  r{i}: repository(owner: "{_gql_escape(owner)}", name: "{_gql_escape(name)}") '
            "{ defaultBranchRef { target { ... on Commit { tree { entries { name type } } } } } }"
        )
    query = "query {\n" + "\n".join(fields) + "\n}"
    proc = subprocess.run(
        ["gh", "api", "graphql", "-f", f"query={query}"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return {slug: None for slug in slugs}
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {slug: None for slug in slugs}
    data = payload.get("data") or {}
    out: dict[str, list[dict] | None] = {}
    for i, slug in enumerate(slugs):
        out[slug] = _entries_from_gql_repo(data.get(f"r{i}"))
    return out


def apply_no_source_filter(clusters: list[dict]) -> dict[str, int]:
    """Drop GitHub facades whose tree has no product source (Claude Code type)."""
    slugs: set[str] = set()
    for cluster in clusters:
        slug = github_slug_of(cluster.get("repo") or "")
        if slug:
            slugs.add(slug)
    cache: dict[str, dict] = {}
    if STUB_CACHE.is_file():
        try:
            raw_cache = json.loads(STUB_CACHE.read_text())
        except json.JSONDecodeError:
            raw_cache = {}
        cache = {
            key: val
            for key, val in raw_cache.items()
            if isinstance(val, dict) and val.get("status") in {"has_source", "no_source"}
        }
    missing = sorted(slug for slug in slugs if slug not in cache)
    print(f"  github unique {len(slugs)} stub-cache miss {len(missing)}", flush=True)
    fetched = 0
    batch_size = 50
    for start in range(0, len(missing), batch_size):
        batch = missing[start : start + batch_size]
        results = fetch_github_roots_graphql(batch)
        for slug, entries in results.items():
            fetched += 1
            if entries is None:
                continue
            cache[slug] = {
                "status": oss.classify_root_listing(entries),
                "n_entries": len(entries),
            }
        done = min(start + batch_size, len(missing))
        if done % 500 == 0 or done == len(missing):
            print(f"    graphql {done}/{len(missing)}", flush=True)
            STUB_CACHE.parent.mkdir(parents=True, exist_ok=True)
            STUB_CACHE.write_text(json.dumps(cache, indent=2, sort_keys=True) + "\n")
    if missing:
        STUB_CACHE.parent.mkdir(parents=True, exist_ok=True)
        STUB_CACHE.write_text(json.dumps(cache, indent=2, sort_keys=True) + "\n")
    dropped = 0
    for cluster in clusters:
        slug = github_slug_of(cluster.get("repo") or "")
        if not slug:
            continue
        info = cache.get(slug) or {}
        if info.get("status") != "no_source":
            continue
        cluster["repo"] = ""
        cluster["repo_source"] = ""
        cluster["repo_skip_reason"] = "no_source"
        cluster["repos"] = []
        dropped += 1
    return {
        "github_unique": len(slugs),
        "fetched": fetched,
        "graphql_batches": (len(missing) + batch_size - 1) // batch_size if missing else 0,
        "clusters_no_source": dropped,
    }


def write_md(report: dict) -> str:
    u = report["universe"]
    f = report["fill"]
    lines = [
        "# Upstream advisory universe, deduped (2026-08-26)",
        "",
        "Independent rebuild. Ledger **not** modified.",
        f"Window `{WINDOW_START.isoformat()}` .. `{WINDOW_END.isoformat()}`.",
        "Identity = CVE+GHSA connected component; withdrawn GHSA and REJECTED CVE dropped.",
        "Repo parse = GitHub / gitlab.com / kernel, plus OSS forges the simple parser missed.",
        "",
        "## Raw → unique",
        "",
        f"- GHSA files (reviewed all years + unreviewed 2025/2026): **{u['ghsa_files']}**",
        f"- NVD 2025/2026 CVE records: **{u['nvd_records']}**",
        f"- Raw public IDs before union: **{u['raw_public_ids']}**",
        f"- After alias-union, drop withdrawn/rejected: **{u['clusters']}** unique classes",
        f"- In window (min published): **{u['in_window']}**",
        f"  - reviewed: **{u['in_window_reviewed']}**",
        f"  - unreviewed-only: **{u['in_window_unreviewed']}**",
        f"  - NVD-only (no GHSA): **{u['in_window_nvd_only']}**",
        f"- In window with a parsed product repo: **{u['in_window_with_repo']}**",
        f"  - simple GitHub / gitlab.com / kernel: **{u['in_window_with_simple_repo']}**",
        f"  - recovered (Bitbucket, self-hosted GitLab, googlesource, cgit/gitweb, …): **{u['in_window_repo_recovered']}**",
        f"- Dropped advisory / PoC / no-source GitHub facade (no product git left): **{u.get('non_product_dropped_total', 0)}**",
        f"  - advisory { (u.get('non_product_dropped') or {}).get('advisory', 0) }"
        f" / poc { (u.get('non_product_dropped') or {}).get('poc', 0) }"
        f" / no_source { (u.get('non_product_dropped') or {}).get('no_source', 0) }",
        f"- In window, still no cloneable product OSS git: **{u['in_window_no_repo']}**",
        f"- In window, reviewed, with repo: **{u['in_window_reviewed_with_repo']}**",
        "",
        "## vs current ledger (24,124 rows, unchanged)",
        "",
        f"- Ledger class_id = an upstream class: **{u['ledger_exact']}**",
        f"- In-window upstream class not in the book: **{u['in_window_not_in_ledger']}**",
        f"  - reviewed+repo: **{u['in_window_reviewed_repo_not_in_ledger']}**",
        "",
        "## Fill table (missing / hash-fail rows only)",
        "",
        (
            "Current ledger is hash-ok on all 24,124 rows; fill sidecar is empty."
            if f["missing"] == 0 and f["fail"] == 0
            else f"- Missing `advisory_ids` filled: **{f['missing_filled']}** / {f['missing']}\n"
            f"- Hash-fail corrected: **{f['fail_filled']}** / {f['fail']}\n"
            f"- Still unfilled: **{f['unfilled']}"
        ),
        "",
        "Recovered OSS-git clusters: `.ai-slop/state/refresh-20260826/recovered-oss-git-20260826.jsonl`",
        "Summary: `artifacts/no-repo-oss-git-20260826.json`. Ledger not written.",
        "",
    ]
    if report["samples"]["unfilled"]:
        lines.append("### Unfilled samples")
        lines.append("")
        for item in report["samples"]["unfilled"][:10]:
            lines.append(
                f"- `{item['class_id']}` `{item.get('repo')}` "
                f"status={item.get('status')} k={item.get('advisories')}"
            )
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    print("loading GHSA + NVD…", flush=True)
    ghsa, nvd, parent, n_files = load_sources()
    print(f"  ghsa {len(ghsa)} files {n_files} nvd {len(nvd)}", flush=True)
    clusters = build_clusters(ghsa, nvd, parent)
    print(f"  clusters {len(clusters)}", flush=True)
    stub_stats = apply_no_source_filter(clusters)
    print(f"  no_source {stub_stats}", flush=True)

    STATE.mkdir(parents=True, exist_ok=True)
    CLUSTERS_OUT.write_text(
        "".join(json.dumps(c, ensure_ascii=False) + "\n" for c in clusters),
        encoding="utf-8",
    )

    by_id = {c["class_id"]: c for c in clusters}
    k1_index: dict[str, str] = {}
    collide = set()
    for cluster in clusters:
        for ident in cluster["public_ids"]:
            key = "alias-" + rec.suffix_of([ident])
            if key in k1_index and k1_index[key] != cluster["class_id"]:
                collide.add(key)
            else:
                k1_index[key] = cluster["class_id"]
    for key in collide:
        k1_index.pop(key, None)

    ledger = [
        json.loads(line)
        for line in rec.LEDGER.read_text().splitlines()
        if line.strip()
    ]
    ledger_ids = {r["class_id"] for r in ledger}
    states = Counter(ledger_state(r) for r in ledger)

    fills: list[dict] = []
    unfilled: list[dict] = []
    for row in ledger:
        state = ledger_state(row)
        if state == "hash_ok":
            continue
        cid = row["class_id"]
        want = cid[6:]
        fill_ids = None
        source = None
        extra: list[str] = []
        cluster = by_id.get(cid)
        if cluster is not None:
            fill_ids = cluster["public_ids"]
            source = "exact_cluster"
            extra = cluster.get("extra_aliases") or []
        if fill_ids is None and cid in k1_index:
            cluster = by_id[k1_index[cid]]
            singleton = unique_subset(cluster["public_ids"], want)
            if singleton:
                fill_ids = singleton
                source = "k1_of_cluster"
                extra = [x for x in cluster["public_ids"] + cluster.get("extra_aliases", []) if x not in fill_ids]
        if fill_ids is None and row.get("advisory_ids"):
            subset = unique_subset([rec.canon(x) for x in row["advisory_ids"]], want)
            if subset:
                fill_ids = subset
                source = "subset_of_existing"
                extra = [rec.canon(x) for x in row["advisory_ids"] if rec.canon(x) not in subset]
        if fill_ids is None:
            unfilled.append(
                {
                    "class_id": cid,
                    "status": row["status"],
                    "repo": row.get("repo"),
                    "advisories": row.get("advisories"),
                    "ledger_state": state,
                }
            )
            continue
        assert rec.suffix_of(fill_ids) == want, cid
        fills.append(
            {
                "class_id": cid,
                "advisory_ids": fill_ids,
                "advisory_ids_source": source,
                **({"advisory_aliases": extra} if extra else {}),
                "ledger_status": row["status"],
                "ledger_repo": row.get("repo"),
                "ledger_state": state,
            }
        )

    FILL_OUT.write_text(
        "".join(json.dumps(x, ensure_ascii=False) + "\n" for x in fills),
        encoding="utf-8",
    )

    in_window = [c for c in clusters if c["in_window"]]
    recovered = [c for c in in_window if c.get("repo_source") == "recovered"]
    skip_no_product = Counter(
        c.get("repo_skip_reason")
        for c in in_window
        if not c.get("repo") and c.get("repo_skip_reason")
    )
    simple_repo_n = sum(1 for c in in_window if c.get("repo_source") == "simple")
    with_repo = sum(1 for c in in_window if c.get("repo"))
    recovered_by_kind = Counter(
        "reviewed" if c["reviewed"] else ("unreviewed" if c["unreviewed_only"] else ("nvd_only" if c["nvd_only"] else "other"))
        for c in recovered
    )
    recovered_hosts = Counter(oss.host_of(c["repo"]) if "." in c["repo"].split("/")[0] else "github.com" for c in recovered)
    kind_repo = {
        "reviewed_with_repo": sum(1 for c in in_window if c["reviewed"] and c.get("repo")),
        "reviewed_no_repo": sum(1 for c in in_window if c["reviewed"] and not c.get("repo")),
        "unreviewed_with_repo": sum(1 for c in in_window if c["unreviewed_only"] and c.get("repo")),
        "unreviewed_no_repo": sum(1 for c in in_window if c["unreviewed_only"] and not c.get("repo")),
        "nvd_only_with_repo": sum(1 for c in in_window if c["nvd_only"] and c.get("repo")),
        "nvd_only_no_repo": sum(1 for c in in_window if c["nvd_only"] and not c.get("repo")),
    }
    RECOVERED_OUT.write_text(
        "".join(json.dumps({
            "class_id": c["class_id"],
            "public_ids": c["public_ids"],
            "repo": c["repo"],
            "repos": c.get("repos") or [],
            "kind": (
                "reviewed" if c["reviewed"] else (
                    "unreviewed" if c["unreviewed_only"] else (
                        "nvd_only" if c["nvd_only"] else "other"
                    )
                )
            ),
        }, ensure_ascii=False) + "\n" for c in recovered),
        encoding="utf-8",
    )
    recovered_report = {
        "window": [WINDOW_START.isoformat(), WINDOW_END.isoformat()],
        "method": (
            "All in-window clusters re-parsed. Simple GitHub/gitlab.com/kernel primaries kept. "
            "Previously empty clusters filled from Bitbucket, self-hosted GitLab, googlesource/"
            "gitiles, cgit/gitweb, Savannah, and project git.* hosts. Broadcom/Liferay CMS dropped. "
            "Advisory databases, PoC/CVE dumps, third-party Claude Code wrappers, "
            "source-available (BSL/SSPL/fair-code), and unattested GitHub/GitLab dumps excluded; "
            "anthropics/claude-code and kernel/GNOME forges kept."
        ),
        "in_window": len(in_window),
        "with_simple_repo": simple_repo_n,
        "recovered_true_oss_git": len(recovered),
        "still_no_oss_git": len(in_window) - with_repo,
        "with_repo_total": with_repo,
        "non_product_dropped": dict(skip_no_product),
        "non_product_dropped_total": sum(skip_no_product.values()),
        "recovered_by_kind": dict(recovered_by_kind),
        "recovered_hosts": recovered_hosts.most_common(30),
        "reviewed_recovered": [
            {"class_id": c["class_id"], "ids": c["public_ids"], "repo": c["repo"]}
            for c in recovered
            if c["reviewed"]
        ],
    }
    RECOVERED_JSON.write_text(json.dumps(recovered_report, indent=2) + "\n", encoding="utf-8")

    raw_public = len(ghsa) + len(nvd)
    universe = {
        "ghsa_files": n_files,
        "ghsa_records": len(ghsa),
        "nvd_records": len(nvd),
        "raw_public_ids": raw_public,
        "clusters": len(clusters),
        "in_window": len(in_window),
        "in_window_reviewed": sum(1 for c in in_window if c["reviewed"]),
        "in_window_unreviewed": sum(1 for c in in_window if c["unreviewed_only"]),
        "in_window_nvd_only": sum(1 for c in in_window if c["nvd_only"]),
        "in_window_with_simple_repo": simple_repo_n,
        "in_window_repo_recovered": len(recovered),
        "in_window_with_repo": with_repo,
        "in_window_no_repo": len(in_window) - with_repo,
        "non_product_dropped": dict(skip_no_product),
        "non_product_dropped_total": sum(skip_no_product.values()),
        "github_no_source": stub_stats,
        "in_window_reviewed_with_repo": kind_repo["reviewed_with_repo"],
        "in_window_by_kind_and_repo": kind_repo,
        "ledger_exact": sum(1 for r in ledger if r["class_id"] in by_id),
        "in_window_not_in_ledger": sum(1 for c in in_window if c["class_id"] not in ledger_ids),
        "in_window_reviewed_repo_not_in_ledger": sum(
            1
            for c in in_window
            if c["reviewed"] and c.get("repo") and c["class_id"] not in ledger_ids
        ),
    }
    fill_stats = {
        "missing": states["missing"],
        "fail": states["hash_fail"],
        "missing_filled": sum(1 for x in fills if x["ledger_state"] == "missing"),
        "fail_filled": sum(1 for x in fills if x["ledger_state"] == "hash_fail"),
        "unfilled": len(unfilled),
        "fill_sources": dict(Counter(x["advisory_ids_source"] for x in fills)),
    }
    report = {
        "window": [WINDOW_START.isoformat(), WINDOW_END.isoformat()],
        "ledger_untouched": True,
        "clusters_path": str(CLUSTERS_OUT),
        "fill_path": str(FILL_OUT),
        "recovered_path": str(RECOVERED_OUT),
        "universe": universe,
        "recovered": {
            "count": len(recovered),
            "by_kind": dict(recovered_by_kind),
            "hosts": recovered_hosts.most_common(20),
        },
        "fill": fill_stats,
        "ledger": {
            "rows": len(ledger),
            "hash_ok": states["hash_ok"],
            "hash_fail": states["hash_fail"],
            "missing": states["missing"],
        },
        "samples": {
            "unfilled": unfilled[:20],
            "fill_missing": [
                {
                    "class_id": x["class_id"],
                    "repo": x.get("ledger_repo"),
                    "ids": x["advisory_ids"],
                    "source": x["advisory_ids_source"],
                }
                for x in fills
                if x["ledger_state"] == "missing"
            ][:15],
        },
    }
    REPORT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    REPORT_MD.write_text(write_md(report), encoding="utf-8")
    meta = {
        "window": [WINDOW_START.isoformat(), WINDOW_END.isoformat()],
        "identity": "CVE+GHSA connected component; withdrawn GHSA and REJECTED CVE dropped; class_id hashes CVE+GHSA only",
        "ledger_untouched": True,
        "layers": {
            "ghsa_files": n_files,
            "nvd_2025_2026": len(nvd),
            "unique_classes_after_alias_and_drop": len(clusters),
            "in_window_published": len(in_window),
            "in_window_reviewed": universe["in_window_reviewed"],
            "in_window_unreviewed": universe["in_window_unreviewed"],
            "in_window_nvd_only_cve": universe["in_window_nvd_only"],
            "in_window_with_product_source_repo": with_repo,
            "in_window_no_product_source_repo": len(in_window) - with_repo,
            "of_which_simple_github_gitlabcom_kernel": simple_repo_n,
            "of_which_recovered_oss_forge": len(recovered),
            "ledger_rows": len(ledger),
            "unique_cve_ghsa_on_ledger": universe.get("unique_cve_ghsa_on_ledger"),
            "ledger_note": "24124 is the existing AI-writer-repo funnel book (+263 window-extend reviewed), not a filter applied to 93038 today.",
        },
        "in_window_by_kind_and_repo": kind_repo,
        "dropped_not_product_source": {
            **dict(skip_no_product),
            "total": sum(skip_no_product.values()),
            "meanings": {
                "advisory": "advisory-database / CSAF / vulndb, not the vulnerable product",
                "poc": "CVE-named dumps, exploit/PoC aggregators",
                "no_source": "public GitHub whose tree has no product source (Claude Code type)",
            },
        },
        "ledger_vs_in_window": {
            "in_window_not_in_ledger": universe["in_window_not_in_ledger"],
            "reviewed_with_repo_not_in_ledger": universe["in_window_reviewed_repo_not_in_ledger"],
        },
        "repo_parser": {
            "simple": "github.com/owner/repo, gitlab.com/group/project, any git.kernel.org URL",
            "oss_recall": "Bitbucket, self-hosted GitLab, googlesource/gitiles, cgit/gitweb, Savannah, project git.* hosts; Broadcom/Liferay CMS excluded",
            "no_source_scan": "GitHub GraphQL default-branch root tree, 50 repos per query, cost 1; no src/lib/packages and no root source files → no_source (Claude Code type)",
            "recovered_from_empty": len(recovered),
            "recovered_by_kind": dict(recovered_by_kind),
        },
        "github_root_scan": stub_stats,
    }
    if META.is_file():
        prev = json.loads(META.read_text())
        meta["layers"]["unique_cve_ghsa_on_ledger"] = (
            prev.get("layers") or {}
        ).get("unique_cve_ghsa_on_ledger")
        meta["layers"]["ledger_rows"] = (prev.get("layers") or {}).get("ledger_rows", len(ledger))
    META.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "universe": universe,
        "recovered": report["recovered"],
        "fill": fill_stats,
        "ledger": report["ledger"],
    }, indent=2))
    print(f"wrote {CLUSTERS_OUT}")
    print(f"wrote {RECOVERED_OUT} ({len(recovered)} recovered)")
    print(f"wrote {FILL_OUT} ({len(fills)} rows)")
    print(f"wrote {REPORT_MD}")
    print(f"wrote {META}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
