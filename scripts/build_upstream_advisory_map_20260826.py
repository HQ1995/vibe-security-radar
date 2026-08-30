#!/usr/bin/env python3
"""Build an independent upstream advisory-cluster catalog and compare it to the ledger.

Does not write artifacts/funnel-account-*.jsonl.

Upstream clusters = connected components of GHSA `id` ∪ `aliases`, plus NVD
2025/2026 CVEs that never appear in those components. class_id uses the same
census hash as the funnel ledger.

Outputs:
  .ai-slop/state/refresh-20260826/upstream-clusters-20260826.jsonl
  artifacts/advisory-old-vs-new-20260826.json
  artifacts/advisory-old-vs-new-20260826.md
"""
from __future__ import annotations

import gzip
import json
import sys
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import recover_advisory_ids_20260826 as rec

WINDOW_START = date(2025, 5, 1)
WINDOW_END = date(2026, 8, 26)
REJECTED = {"REJECTED", "RECEIVED", "AWAITING_ANALYSIS"}  # NVD statuses to flag
NVD_DROP = {"REJECTED"}

STATE = rec.STATE
CLUSTERS_OUT = STATE / "upstream-clusters-20260826.jsonl"
COMPARE_JSON = rec.ROOT / "artifacts/advisory-old-vs-new-20260826.json"
COMPARE_MD = rec.ROOT / "artifacts/advisory-old-vs-new-20260826.md"


def parse_day(value: str | None) -> date | None:
    if not value:
        return None
    text = str(value)[:10]
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def in_window(day: date | None) -> bool:
    return day is not None and WINDOW_START <= day <= WINDOW_END


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


def load_ghsa_graph() -> tuple[dict[str, dict], dict[str, str], int]:
    """Return records_by_id, union-find parent, file count."""
    records: dict[str, dict] = {}
    parent: dict[str, str] = {}
    n_files = 0
    for path in rec.iter_ghsa_records():
        n_files += 1
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        ident = raw.get("id")
        if not ident:
            continue
        cid = rec.canon(ident)
        reviewed = "github-reviewed" in path.parts
        urls = [r.get("url") or "" for r in (raw.get("references") or [])]
        for aff in raw.get("affected") or []:
            for rng in aff.get("ranges") or []:
                if rng.get("type") == "GIT" and rng.get("repo"):
                    urls.append(rng["repo"])
        rec_obj = {
            "id": cid,
            "aliases": [rec.canon(a) for a in (raw.get("aliases") or []) if a],
            "published": (raw.get("published") or "")[:10],
            "withdrawn": bool(raw.get("withdrawn")),
            "reviewed": reviewed,
            "repos": sorted(rec.repos_from_urls(urls)),
            "summary": (raw.get("summary") or "")[:200],
        }
        records[cid] = rec_obj
        find(parent, cid)
        for alias in rec_obj["aliases"]:
            union(parent, cid, alias)
    return records, parent, n_files


def load_nvd() -> dict[str, dict]:
    out: dict[str, dict] = {}
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
            urls = [r.get("url") or "" for r in (cve.get("references") or [])]
            out[cid] = {
                "id": cid,
                "published": (cve.get("published") or "")[:10],
                "status": cve.get("vulnStatus") or "",
                "repos": sorted(rec.repos_from_urls(urls)),
            }
    return out


def build_clusters(ghsa: dict[str, dict], parent: dict[str, str], nvd: dict[str, dict]) -> list[dict]:
    groups: dict[str, set[str]] = defaultdict(set)
    for ident in parent:
        groups[find(parent, ident)].add(ident)

    clusters: list[dict] = []
    used_cves: set[str] = set()
    for members in groups.values():
        ghsa_ids = sorted(m for m in members if m.upper().startswith("GHSA-"))
        if not ghsa_ids:
            continue
        recs = [ghsa[g] for g in ghsa_ids if g in ghsa]
        aliases = set(members)
        for rec_obj in recs:
            aliases.update(rec_obj["aliases"])
        members_sorted = sorted(aliases)
        used_cves.update(m for m in members_sorted if m.startswith("CVE-"))
        days = [parse_day(r["published"]) for r in recs]
        days = [d for d in days if d]
        published = min(days).isoformat() if days else ""
        repos: set[str] = set()
        for rec_obj in recs:
            repos.update(rec_obj["repos"])
        for cve in members_sorted:
            if cve in nvd:
                repos.update(nvd[cve]["repos"])
        reviewed = any(r["reviewed"] for r in recs)
        withdrawn = any(r["withdrawn"] for r in recs)
        nvd_rejected = any(
            (nvd.get(m) or {}).get("status") in NVD_DROP for m in members_sorted
        )
        clusters.append(
            {
                "class_id": "alias-" + rec.suffix_of(members_sorted),
                "member_ids": members_sorted,
                "ghsa_ids": ghsa_ids,
                "reviewed": reviewed,
                "unreviewed_only": bool(recs) and not reviewed,
                "published": published,
                "in_window": in_window(parse_day(published)),
                "withdrawn": withdrawn,
                "nvd_rejected": nvd_rejected,
                "repos": sorted(
                    r
                    for r in repos
                    if not r.startswith("github.com/") or r[len("github.com/") :] not in repos
                )[:12],
            }
        )

    for cid, rec_obj in nvd.items():
        if cid in used_cves:
            continue
        if rec_obj.get("status") in NVD_DROP:
            continue
        members = [cid]
        clusters.append(
            {
                "class_id": "alias-" + rec.suffix_of(members),
                "member_ids": members,
                "ghsa_ids": [],
                "reviewed": False,
                "unreviewed_only": False,
                "nvd_only": True,
                "published": rec_obj["published"],
                "in_window": in_window(parse_day(rec_obj["published"])),
                "withdrawn": False,
                "nvd_rejected": False,
                "repos": rec_obj["repos"][:12],
            }
        )
    return clusters


def index_subsets(clusters: list[dict]) -> dict[str, str]:
    """Map class_id of small subsets -> parent cluster class_id."""
    mapping: dict[str, str] = {}
    for cluster in clusters:
        parent_id = cluster["class_id"]
        members = cluster["member_ids"]
        mapping[parent_id] = parent_id
        for ident in members:
            mapping.setdefault("alias-" + rec.suffix_of([ident]), parent_id)
        if 2 <= len(members) <= 6:
            from itertools import combinations

            for k in range(2, len(members)):
                for combo in combinations(members, k):
                    mapping.setdefault("alias-" + rec.suffix_of(combo), parent_id)
    return mapping


def ledger_row_state(row: dict) -> str:
    ids = row.get("advisory_ids") or []
    if not ids:
        return "missing"
    members = [rec.canon(x) for x in ids]
    if rec.suffix_of(members) == row["class_id"][6:]:
        return "hash_ok"
    return "hash_fail"


def write_md(report: dict) -> str:
    old = report["ledger"]
    up = report["upstream"]
    join = report["join"]
    lines = [
        "# Upstream advisory catalog vs funnel ledger (2026-08-26)",
        "",
        "Independent rebuild from GitHub `advisory-database` (reviewed + windowed unreviewed)",
        "and NVD 2025/2026. Ledger was **not** modified.",
        "",
        f"Window: `{WINDOW_START.isoformat()}` .. `{WINDOW_END.isoformat()}`.",
        "",
        "## Upstream catalog",
        "",
        f"- GHSA files parsed: **{up['ghsa_files']}**",
        f"- NVD 2025/2026 records: **{up['nvd_records']}**",
        f"- Alias clusters (GHSA connected components): **{up['ghsa_clusters']}**",
        f"- Extra NVD-only CVE singletons: **{up['nvd_only_clusters']}**",
        f"- Total upstream clusters: **{up['clusters']}**",
        f"- In window: **{up['in_window']}** (reviewed {up['in_window_reviewed']} / unreviewed-only {up['in_window_unreviewed']} / NVD-only {up['in_window_nvd_only']})",
        f"- Withdrawn in window: **{up['in_window_withdrawn']}**",
        "",
        "## Ledger (old book, unchanged)",
        "",
        f"- Rows: **{old['rows']}**",
        f"- Hash-ok `advisory_ids`: **{old['hash_ok']}**",
        f"- Hash-fail: **{old['hash_fail']}**",
        f"- Missing `advisory_ids`: **{old['missing']}**",
        "",
        "## Join by class_id",
        "",
        f"- Ledger class_id equals an upstream cluster: **{join['exact_cluster']}**",
        f"- Ledger class_id is a unique subset of an upstream cluster: **{join['subset_of_cluster']}**",
        f"- Ledger class_id not in today's GHSA/NVD graph: **{join['not_in_upstream']}**",
        "",
        "Among rows currently **missing** `advisory_ids`:",
        "",
        f"- Exact upstream cluster: **{join['missing_exact']}**",
        f"- Subset of an upstream cluster: **{join['missing_subset']}**",
        f"- Still unexplained: **{join['missing_unexplained']}**",
        "",
        "Among rows currently **hash-fail**:",
        "",
        f"- Exact upstream cluster: **{join['fail_exact']}**",
        f"- Subset of an upstream cluster: **{join['fail_subset']}**",
        f"- Still unexplained: **{join['fail_unexplained']}**",
        "",
        "## New upstream clusters not in the ledger",
        "",
        "In-window, not withdrawn, not NVD-rejected, class_id absent from the book.",
        "Not added — counts only.",
        "",
        f"- Reviewed (first-party quality bar of the original funnel): **{join['new_reviewed_in_window']}**",
        f"- Unreviewed-only: **{join['new_unreviewed_in_window']}**",
        f"- NVD-only CVE singletons: **{join['new_nvd_only_in_window']}**",
        "",
        "### Sample missing-ledger rows that pin exactly to an upstream cluster",
        "",
    ]
    for item in report["samples"]["missing_exact"][:15]:
        lines.append(
            f"- `{item['class_id']}` `{item['repo']}` status={item['status']} "
            f"→ `{', '.join(item['member_ids'])}`"
        )
    lines.extend(
        [
            "",
            "### Sample hash-fail rows whose class_id is a subset of today's cluster",
            "",
        ]
    )
    for item in report["samples"]["fail_subset"][:10]:
        lines.append(
            f"- `{item['class_id']}` `{item['repo']}` ledger={item['ledger_ids']} "
            f"upstream={item['upstream_ids']}"
        )
    lines.extend(
        [
            "",
            "### Sample new reviewed in-window clusters not in the book",
            "",
        ]
    )
    for item in report["samples"]["new_reviewed"][:15]:
        lines.append(
            f"- `{item['class_id']}` published={item['published']} "
            f"`{', '.join(item['member_ids'][:4])}` repos={item['repos'][:2]}"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    print("loading GHSA graph…", flush=True)
    ghsa, parent, n_files = load_ghsa_graph()
    print(f"  ghsa records {len(ghsa)} files {n_files}", flush=True)
    print("loading NVD…", flush=True)
    nvd = load_nvd()
    print(f"  nvd {len(nvd)}", flush=True)
    clusters = build_clusters(ghsa, parent, nvd)
    print(f"  clusters {len(clusters)}", flush=True)

    STATE.mkdir(parents=True, exist_ok=True)
    CLUSTERS_OUT.write_text(
        "".join(json.dumps(c, ensure_ascii=False) + "\n" for c in clusters),
        encoding="utf-8",
    )
    print(f"wrote {CLUSTERS_OUT}", flush=True)

    by_id = {c["class_id"]: c for c in clusters}
    subset_map = index_subsets(clusters)
    ledger = [
        json.loads(line)
        for line in rec.LEDGER.read_text().splitlines()
        if line.strip()
    ]
    ledger_ids = {r["class_id"] for r in ledger}

    old = Counter(ledger_row_state(r) for r in ledger)
    join = Counter()
    samples = {
        "missing_exact": [],
        "fail_subset": [],
        "new_reviewed": [],
        "unexplained_missing": [],
    }

    for row in ledger:
        cid = row["class_id"]
        state = ledger_row_state(row)
        if cid in by_id:
            kind = "exact"
        elif cid in subset_map:
            kind = "subset"
        else:
            kind = "absent"
        join[{"exact": "exact_cluster", "subset": "subset_of_cluster", "absent": "not_in_upstream"}[kind]] += 1
        if state == "missing":
            join[{"exact": "missing_exact", "subset": "missing_subset", "absent": "missing_unexplained"}[kind]] += 1
            if kind == "exact" and len(samples["missing_exact"]) < 20:
                samples["missing_exact"].append(
                    {
                        "class_id": cid,
                        "repo": row.get("repo"),
                        "status": row["status"],
                        "member_ids": by_id[cid]["member_ids"],
                    }
                )
            if kind == "absent" and len(samples["unexplained_missing"]) < 20:
                samples["unexplained_missing"].append(
                    {
                        "class_id": cid,
                        "repo": row.get("repo"),
                        "status": row["status"],
                        "advisories": row.get("advisories"),
                    }
                )
        elif state == "hash_fail":
            join[{"exact": "fail_exact", "subset": "fail_subset", "absent": "fail_unexplained"}[kind]] += 1
            if kind == "subset" and len(samples["fail_subset"]) < 15:
                parent_id = subset_map[cid]
                samples["fail_subset"].append(
                    {
                        "class_id": cid,
                        "repo": row.get("repo"),
                        "ledger_ids": [rec.canon(x) for x in row.get("advisory_ids") or []],
                        "upstream_ids": by_id[parent_id]["member_ids"],
                    }
                )

    for cluster in clusters:
        if cluster["class_id"] in ledger_ids:
            continue
        if not cluster.get("in_window") or cluster.get("withdrawn") or cluster.get("nvd_rejected"):
            continue
        if cluster.get("reviewed"):
            join["new_reviewed_in_window"] += 1
            if len(samples["new_reviewed"]) < 20:
                samples["new_reviewed"].append(
                    {
                        "class_id": cluster["class_id"],
                        "published": cluster["published"],
                        "member_ids": cluster["member_ids"],
                        "repos": cluster.get("repos") or [],
                    }
                )
        elif cluster.get("nvd_only"):
            join["new_nvd_only_in_window"] += 1
        elif cluster.get("unreviewed_only"):
            join["new_unreviewed_in_window"] += 1

    up = {
        "ghsa_files": n_files,
        "nvd_records": len(nvd),
        "clusters": len(clusters),
        "ghsa_clusters": sum(1 for c in clusters if c.get("ghsa_ids")),
        "nvd_only_clusters": sum(1 for c in clusters if c.get("nvd_only")),
        "in_window": sum(1 for c in clusters if c.get("in_window")),
        "in_window_reviewed": sum(
            1 for c in clusters if c.get("in_window") and c.get("reviewed")
        ),
        "in_window_unreviewed": sum(
            1 for c in clusters if c.get("in_window") and c.get("unreviewed_only")
        ),
        "in_window_nvd_only": sum(
            1 for c in clusters if c.get("in_window") and c.get("nvd_only")
        ),
        "in_window_withdrawn": sum(
            1 for c in clusters if c.get("in_window") and c.get("withdrawn")
        ),
    }
    report = {
        "window": [WINDOW_START.isoformat(), WINDOW_END.isoformat()],
        "ledger_untouched": True,
        "upstream_path": str(CLUSTERS_OUT),
        "ledger": {
            "rows": len(ledger),
            "hash_ok": old["hash_ok"],
            "hash_fail": old["hash_fail"],
            "missing": old["missing"],
            "status": dict(Counter(r["status"] for r in ledger)),
        },
        "upstream": up,
        "join": dict(join),
        "samples": samples,
    }
    COMPARE_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    COMPARE_MD.write_text(write_md(report), encoding="utf-8")
    print(json.dumps({"upstream": up, "ledger": report["ledger"], "join": dict(join)}, indent=2))
    print(f"wrote {COMPARE_JSON}")
    print(f"wrote {COMPARE_MD}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
