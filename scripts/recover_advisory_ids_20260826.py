#!/usr/bin/env python3
"""Independently recover original advisory member sets for funnel rows.

class_id = 'alias-' + sha256('\\n'.join(sorted(members)) + '\\n').hexdigest()[:24]
with census canonical case (GHSA- prefix + body lower; everything else upper).

Zero-inference pinning, in order:
  1. unique subset of the row's current advisory_ids (hash-fail supersets)
  2. GHSA record {id} ∪ aliases — every subset, globally unique suffix
  3. k=1 over the ID universe (GHSA clone + NVD 2025/2026 + cohort)
  4. unique size-k subset of the row's per-repo ID pool (k = row.advisories)

Writes pin/lane artifacts under `.ai-slop/state/refresh-20260826/` only.
Does not write the funnel ledger.

Usage:
  python3 scripts/recover_advisory_ids_20260826.py
"""
from __future__ import annotations

import gzip
import hashlib
import json
import math
import re
import sys
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "artifacts" / "funnel-account-20260817.jsonl"
CENSUS_MAP = ROOT / ".ai-slop/state/research-queue/round6/.alias_class_member_map.json"
COHORT_A = ROOT / ".ai-slop/state/cohort-v1/advisory-repos-since-2025-05.json"
COHORT_B = ROOT / ".ai-slop/state/cohort-v1/advisory-repos-since-2025-05-01.json"
GHSA_ROOT = Path.home() / ".cache/cve-analyzer/advisory-database/advisories"
NVD_DIR = Path.home() / ".cache/cve-analyzer/nvd-feeds"
STATE = ROOT / ".ai-slop/state/refresh-20260826"
LANE = STATE / "lane-advisory-recover-20260826.jsonl"
PINS_OUT = STATE / "advisory-recover-pins.json"
REPORT = ROOT / "artifacts/advisory-recover-report-20260826.json"

KERNEL_REPO = "git.kernel.org/pub/scm/linux/kernel/git/stable/linux"
MAX_COMBOS = 20_000_000
COLLIDE = object()

GITHUB_RE = re.compile(
    r"https?://(?:www\.)?github\.com/([^/]+)/([^/#?]+)", re.I
)
GITLAB_RE = re.compile(
    r"https?://(?:www\.)?gitlab\.com/([^/]+/[^/#?]+)", re.I
)
KERNEL_RE = re.compile(r"https?://git\.kernel\.org/", re.I)
SKIP_GH_OWNERS = {
    "advisories",
    "apps",
    "cveproject",
    "gist",
    "github",
    "nvd",
    "orgs",
    "security",
    "sponsors",
    "users",
}


def canon(value: str) -> str:
    value = str(value).strip()
    if value.upper().startswith("GHSA-"):
        return "GHSA-" + value.split("-", 1)[1].lower()
    return value.upper()


def suffix_of(members: list[str] | tuple[str, ...]) -> str:
    return hashlib.sha256(
        ("\n".join(sorted(members)) + "\n").encode()
    ).hexdigest()[:24]


def as_list(members: frozenset[str] | tuple[str, ...] | list[str]) -> list[str]:
    return sorted(members)


def register(index: dict[str, frozenset[str] | object], members) -> None:
    frozen = frozenset(canon(x) for x in members if x)
    if not frozen:
        return
    key = suffix_of(frozen)
    prev = index.get(key)
    if prev is None:
        index[key] = frozen
    elif prev is not COLLIDE and prev != frozen:
        index[key] = COLLIDE


def github_slug(url: str) -> str | None:
    match = GITHUB_RE.search(url)
    if not match:
        return None
    owner, repo = match.group(1).lower(), match.group(2).lower()
    if repo.endswith(".git"):
        repo = repo[:-4]
    if owner in SKIP_GH_OWNERS:
        return None
    if owner == "gist":
        return None
    return f"{owner}/{repo}"


def repos_from_urls(urls: list[str]) -> set[str]:
    out: set[str] = set()
    for url in urls:
        if not url:
            continue
        if KERNEL_RE.search(url):
            out.add(KERNEL_REPO)
        slug = github_slug(url)
        if slug:
            out.add(slug)
            out.add("github.com/" + slug)
        gl = GITLAB_RE.search(url)
        if gl:
            path = gl.group(1).lower().rstrip("/")
            if path.endswith(".git"):
                path = path[:-4]
            out.add("gitlab.com/" + path)
    return out


def ledger_repo_keys(repo: str) -> set[str]:
    raw = (repo or "").strip().lower().rstrip("/")
    if not raw:
        return set()
    for prefix in ("https://", "http://", "git://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix) :]
    keys = {raw}
    if raw.startswith("github.com/"):
        keys.add(raw[len("github.com/") :])
    elif raw == KERNEL_REPO or "git.kernel.org" in raw:
        keys.add(KERNEL_REPO)
        keys.add("git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux")
    elif not raw.startswith("gitlab.") and "/" in raw and "." not in raw.split("/")[0]:
        keys.add("github.com/" + raw)
    return keys


def load_cohort_pools() -> dict[str, set[str]]:
    pools: dict[str, set[str]] = defaultdict(set)

    def ingest(mapping: dict) -> None:
        for repo, ids in mapping.items():
            if not isinstance(ids, list):
                continue
            keys = ledger_repo_keys(str(repo))
            for ident in ids:
                cid = canon(ident)
                for key in keys:
                    pools[key].add(cid)

    ingest(json.loads(COHORT_A.read_text()))
    wrapped = json.loads(COHORT_B.read_text())
    ingest(wrapped.get("repositories") or {})
    return pools


def iter_ghsa_records():
    reviewed = GHSA_ROOT / "github-reviewed"
    if reviewed.is_dir():
        yield from reviewed.rglob("*.json")
    unreviewed = GHSA_ROOT / "unreviewed"
    for year in ("2025", "2026"):
        year_dir = unreviewed / year
        if not year_dir.is_dir():
            continue
        for month_dir in sorted(year_dir.iterdir()):
            if not month_dir.is_dir():
                continue
            if year == "2025" and month_dir.name < "05":
                continue
            yield from month_dir.rglob("*.json")


def load_ghsa(index: dict, pools: dict[str, set[str]], universe: set[str]) -> dict:
    """Return id -> official aliases (canon). Side-effect: fill index/pools/universe."""
    aliases_of: dict[str, list[str]] = {}
    n_files = 0
    for path in iter_ghsa_records():
        n_files += 1
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        ident = rec.get("id")
        if not ident:
            continue
        cid = canon(ident)
        aliases = [canon(a) for a in (rec.get("aliases") or []) if a]
        members = [cid, *aliases]
        aliases_of[cid] = aliases
        universe.update(members)
        for k in range(1, len(members) + 1):
            for combo in combinations(members, k):
                register(index, combo)
        urls = [r.get("url") or "" for r in (rec.get("references") or [])]
        for aff in rec.get("affected") or []:
            for rng in aff.get("ranges") or []:
                if rng.get("type") == "GIT" and rng.get("repo"):
                    urls.append(rng["repo"])
        for repo in repos_from_urls(urls):
            for member in members:
                pools[repo].add(member)
    aliases_of["_files"] = n_files  # type: ignore[assignment]
    return aliases_of


def load_nvd(index: dict, pools: dict[str, set[str]], universe: set[str]) -> int:
    n = 0
    for year in (2025, 2026):
        path = NVD_DIR / f"nvdcve-2.0-{year}.json.gz"
        if not path.is_file():
            continue
        with gzip.open(path) as handle:
            payload = json.load(handle)
        for item in payload.get("vulnerabilities") or []:
            cve = item.get("cve") or {}
            ident = cve.get("id")
            if not ident:
                continue
            cid = canon(ident)
            universe.add(cid)
            register(index, [cid])
            n += 1
            urls = [r.get("url") or "" for r in (cve.get("references") or [])]
            for repo in repos_from_urls(urls):
                pools[repo].add(cid)
    return n


def unique_subset(ids: list[str], want: str) -> list[str] | None:
    ids = list(dict.fromkeys(canon(x) for x in ids if x))
    n = len(ids)
    if n == 0:
        return None
    ks: list[int]
    if n <= 16:
        ks = list(range(1, n + 1))
    else:
        ks = [k for k in (1, 2, 3, n - 2, n - 1) if 1 <= k <= n]
    hits: list[tuple[str, ...]] = []
    seen: set[frozenset[str]] = set()
    for k in ks:
        for combo in combinations(ids, k):
            if suffix_of(combo) != want:
                continue
            frozen = frozenset(combo)
            if frozen in seen:
                continue
            seen.add(frozen)
            hits.append(combo)
            if len(hits) > 1:
                return None
    if len(hits) == 1:
        return as_list(hits[0])
    return None


def pool_for_row(repo: str, pools: dict[str, set[str]]) -> list[str]:
    acc: set[str] = set()
    for key in ledger_repo_keys(repo):
        acc.update(pools.get(key) or ())
    return sorted(acc)


def pin_from_pool(pool: list[str], want: str, k: int) -> list[str] | None:
    n = len(pool)
    if k < 1 or k > n:
        return None
    ncomb = math.comb(n, k)
    if ncomb > MAX_COMBOS:
        return None
    hits: list[tuple[str, ...]] = []
    for combo in combinations(pool, k):
        if suffix_of(combo) != want:
            continue
        hits.append(combo)
        if len(hits) > 1:
            return None
    if len(hits) == 1:
        return as_list(hits[0])
    return None


def pin_group(rows: list[dict], pools: dict[str, set[str]]) -> dict[str, list[str]]:
    """One combinations pass per (repo, k) over leftover rows."""
    found: dict[str, list[str]] = {}
    groups: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for row in rows:
        k = row.get("advisories")
        if not isinstance(k, int) or k < 2:
            continue
        groups[(row.get("repo") or "", k)].append(row)
    for (repo, k), group in groups.items():
        pool = pool_for_row(repo, pools)
        n = len(pool)
        if n < k:
            continue
        ncomb = math.comb(n, k)
        if ncomb > MAX_COMBOS:
            continue
        wants = {r["class_id"][6:]: r["class_id"] for r in group}
        hits: dict[str, list[tuple[str, ...]]] = defaultdict(list)
        for combo in combinations(pool, k):
            key = suffix_of(combo)
            if key in wants:
                hits[key].append(combo)
        for key, combos in hits.items():
            uniq = {frozenset(c): c for c in combos}
            if len(uniq) == 1:
                found[wants[key]] = as_list(next(iter(uniq.values())))
    return found


def extras_for(row: dict, members: list[str], aliases_of: dict[str, list[str]]) -> list[str]:
    member_set = set(members)
    extra: list[str] = []
    seen = set(member_set)
    for ident in row.get("advisory_ids") or []:
        cid = canon(ident)
        if cid not in seen:
            extra.append(cid)
            seen.add(cid)
    for ident in members:
        if not ident.upper().startswith("GHSA-"):
            continue
        for alias in aliases_of.get(ident) or []:
            if alias not in seen:
                extra.append(alias)
                seen.add(alias)
    return extra


def main() -> int:
    print("loading ledger…", flush=True)
    rows = [json.loads(line) for line in LEDGER.read_text().splitlines() if line.strip()]
    status_before = Counter(r["status"] for r in rows)
    print(f"rows {len(rows)} status {dict(status_before)}", flush=True)

    index: dict[str, frozenset[str] | object] = {}
    pools: dict[str, set[str]] = defaultdict(set)
    universe: set[str] = set()

    print("loading cohort pools…", flush=True)
    for key, ids in load_cohort_pools().items():
        pools[key].update(ids)
        universe.update(ids)
        for ident in ids:
            register(index, [ident])

    print("loading GHSA clone (reviewed + windowed unreviewed)…", flush=True)
    aliases_of = load_ghsa(index, pools, universe)
    n_ghsa_files = aliases_of.pop("_files", 0)
    print(f"  ghsa files {n_ghsa_files} alias-sets indexed {len(index)}", flush=True)

    print("loading NVD 2025/2026…", flush=True)
    n_nvd = load_nvd(index, pools, universe)
    print(f"  nvd records {n_nvd} universe {len(universe)}", flush=True)

    k1 = {key: val for key, val in index.items() if val is not COLLIDE and len(val) == 1}

    stats = Counter()
    planned: dict[str, dict] = {}
    leftover: list[dict] = []

    for row in rows:
        cid = row["class_id"]
        want = cid[6:]
        current = [canon(x) for x in (row.get("advisory_ids") or [])]
        if current and suffix_of(current) == want:
            stats["already_hash_ok"] += 1
            continue

        recovered = None
        source = None
        if current:
            subset = unique_subset(current, want)
            if subset is not None:
                recovered, source = subset, "subset_of_existing"

        if recovered is None:
            hit = index.get(want)
            if hit is not None and hit is not COLLIDE:
                recovered = as_list(hit)
                source = (
                    "hash_pin_k1_20260826"
                    if len(hit) == 1
                    else "hash_pin_aliasset_20260826"
                )

        if recovered is None and (row.get("advisories") == 1 or not current):
            hit = k1.get(want)
            if hit is not None and hit is not COLLIDE:
                recovered = as_list(hit)
                source = "hash_pin_k1_20260826"

        if recovered is None:
            leftover.append(row)
            continue

        assert suffix_of(recovered) == want, cid
        extra = extras_for(row, recovered, aliases_of)
        planned[cid] = {
            "class_id": cid,
            "advisory_ids": recovered,
            "advisory_ids_source": source,
            **({"advisory_aliases": extra} if extra else {}),
        }
        stats[source] += 1

    print(f"after alias/k1/subset: planned {len(planned)} leftover {len(leftover)}", flush=True)

    pool_hits = pin_group(leftover, pools)
    still: list[dict] = []
    for row in leftover:
        cid = row["class_id"]
        members = pool_hits.get(cid)
        source = "hash_pin_repopool_20260826"
        if members is None:
            k = row.get("advisories")
            if k == 1:
                members = pin_from_pool(pool_for_row(row.get("repo") or "", pools), cid[6:], 1)
                source = "hash_pin_k1_20260826"
        if members is None:
            still.append(row)
            continue
        assert suffix_of(members) == cid[6:], cid
        extra = extras_for(row, members, aliases_of)
        planned[cid] = {
            "class_id": cid,
            "advisory_ids": members,
            "advisory_ids_source": source,
            **({"advisory_aliases": extra} if extra else {}),
        }
        stats[source] += 1

    stats["unpinned"] = len(still)
    print("stats", dict(stats), flush=True)

    remaining_status = Counter(r["status"] for r in still)
    remaining_repos = Counter(r.get("repo") for r in still).most_common(20)
    remaining_k = Counter(r.get("advisories") for r in still)
    print("unpinned status", dict(remaining_status), "k", dict(remaining_k), flush=True)
    print("unpinned top repos", remaining_repos[:10], flush=True)

    STATE.mkdir(parents=True, exist_ok=True)
    pin_dump = {cid: item["advisory_ids"] for cid, item in planned.items()}
    PINS_OUT.write_text(json.dumps(pin_dump, indent=2) + "\n", encoding="utf-8")
    lane_items = list(planned.values())
    LANE.write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in lane_items),
        encoding="utf-8",
    )

    tp_missing_before = sum(
        1
        for r in rows
        if r["status"] in ("AI_ROOT_CAUSE", "AI_CODE_FLAWED") and not r.get("advisory_ids")
    )
    tp_fail_before = sum(
        1
        for r in rows
        if r["status"] in ("AI_ROOT_CAUSE", "AI_CODE_FLAWED")
        and r.get("advisory_ids")
        and suffix_of([canon(x) for x in r["advisory_ids"]]) != r["class_id"][6:]
    )
    tp_unpinned = [
        r for r in still if r["status"] in ("AI_ROOT_CAUSE", "AI_CODE_FLAWED")
    ]

    report = {
        "rows": len(rows),
        "stats": dict(stats),
        "unpinned": len(still),
        "unpinned_status": dict(remaining_status),
        "unpinned_advisories": {str(k): v for k, v in remaining_k.items()},
        "unpinned_top_repos": remaining_repos,
        "unpinned_samples": [
            {
                "class_id": r["class_id"],
                "status": r["status"],
                "repo": r.get("repo"),
                "advisories": r.get("advisories"),
            }
            for r in still[:40]
        ],
        "tp_missing_before": tp_missing_before,
        "tp_hash_fail_before": tp_fail_before,
        "tp_unpinned": [
            {"class_id": r["class_id"], "repo": r.get("repo"), "status": r["status"]}
            for r in tp_unpinned
        ],
        "lane": str(LANE),
        "pins": str(PINS_OUT),
        "universe": len(universe),
        "index_entries": sum(1 for v in index.values() if v is not COLLIDE),
        "ghsa_files": n_ghsa_files,
        "nvd_records": n_nvd,
    }
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {LANE} ({len(lane_items)} items)", flush=True)
    print(f"wrote {REPORT}", flush=True)
    print("ledger not modified", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
