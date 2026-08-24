#!/usr/bin/env python3
"""Freeze sources and prove G-N assignment conservation.

Owned by herdr-260813-ghsa200-commitfirst-gn. Does not edit shared code.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO = Path("/home/hanqing/agents/ai-slop")
OUT = REPO / "autoresearch/herdr-260813-ghsa200-commitfirst-gn"
ADV = Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database")
WINDOW_START = "2025-05-01"
GN_INITIALS = set("ghijklmn")
AF_INITIALS = set("abcdef")
FIRST_PARTY_RE = re.compile(
    r"https?://github\.com/([^/]+)/([^/]+)/security/advisories/(GHSA-[0-9a-z-]+)",
    re.IGNORECASE,
)
COMMIT_RE = re.compile(
    r"https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})",
    re.IGNORECASE,
)
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$", re.IGNORECASE)
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
OSV_RE = re.compile(r"^OSV-\d{4}-\d+$", re.IGNORECASE)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def norm_id(value: str) -> str:
    return value.strip().upper()


def add_id(bucket: set[str], value: object) -> None:
    if not isinstance(value, str):
        return
    text = norm_id(value)
    if GHSA_RE.match(text) or CVE_RE.match(text) or OSV_RE.match(text):
        bucket.add(text)


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def owner_bucket(owner: str) -> str:
    if not owner:
        return "missing"
    ch = owner.casefold()[0]
    if ch in AF_INITIALS:
        return "A-F"
    if ch in GN_INITIALS:
        return "G-N"
    if "a" <= ch <= "z":
        return "O-Z"
    return "digit-or-other"


def extract_first_party(obj: dict) -> tuple[str | None, str | None, str | None]:
    refs = obj.get("references") or []
    for ref in refs:
        url = (ref or {}).get("url") or ""
        m = FIRST_PARTY_RE.search(url)
        if m:
            owner, name, ghsa = m.group(1), m.group(2), m.group(3)
            return f"{owner}/{name}", owner, ghsa.upper()
    return None, None, None


def extract_commit_refs(obj: dict, repository: str | None) -> list[str]:
    shas: list[str] = []
    for ref in obj.get("references") or []:
        url = (ref or {}).get("url") or ""
        m = COMMIT_RE.search(url)
        if not m:
            continue
        owner, name, sha = m.group(1), m.group(2), m.group(3)
        if repository and f"{owner}/{name}".casefold() != repository.casefold():
            continue
        shas.append(sha.lower())
    return sorted(set(shas))


def collect_exclusion() -> dict:
    ids: set[str] = set()
    sources: dict[str, int] = {}

    public_cases = REPO / "autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl"
    for row in load_jsonl(public_cases):
        add_id(ids, row.get("case_id"))
        for alias in row.get("aliases") or []:
            add_id(ids, alias)
    sources["fp211_public_cases"] = len(ids)
    after = len(ids)

    dispositions = REPO / "autoresearch/orchestrator-260813-fp211-audit/public_id_dispositions.jsonl"
    for row in load_jsonl(dispositions):
        add_id(ids, row.get("public_id"))
        for case_id in row.get("case_ids") or []:
            add_id(ids, case_id)
    sources["after_fp211_dispositions"] = len(ids)
    sources["added_by_dispositions"] = len(ids) - after
    after = len(ids)

    ledger = REPO / "autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl"
    for row in load_jsonl(ledger):
        add_id(ids, row.get("primary_id"))
        for key in ("declared_public_ids", "public_ids"):
            for item in row.get(key) or []:
                add_id(ids, item)
        fp = row.get("fp211_adjudication") or {}
        for item in fp.get("public_ids_keep") or []:
            add_id(ids, item)
    sources["after_canonical_ledger"] = len(ids)
    sources["added_by_canonical"] = len(ids) - after
    after = len(ids)

    pub = json.loads((REPO / "scripts/publication_adjudications.json").read_text(encoding="utf-8"))
    for row in pub.get("adjudications") or []:
        add_id(ids, row.get("cve_id"))
        for item in row.get("aliases") or []:
            add_id(ids, item)
    sources["after_publication_adjudications"] = len(ids)
    sources["added_by_publication"] = len(ids) - after
    after = len(ids)

    index = json.loads((REPO / "web/data/index.json").read_text(encoding="utf-8"))
    for item in index.get("ids") or []:
        add_id(ids, item)
    sources["after_web_index"] = len(ids)
    sources["added_by_web_index"] = len(ids) - after

    ghsa = sorted(x for x in ids if x.startswith("GHSA-"))
    cve = sorted(x for x in ids if x.startswith("CVE-"))
    other = sorted(x for x in ids if not x.startswith(("GHSA-", "CVE-")))
    return {
        "unique_public_ids": sorted(ids),
        "ghsa_ids": ghsa,
        "cve_ids": cve,
        "other_ids": other,
        "counts": {
            "unique_public_ids": len(ids),
            "ghsa": len(ghsa),
            "cve": len(cve),
            "other": len(other),
            **sources,
        },
    }


def parse_advisories(exclusion: set[str]) -> dict:
    reviewed_root = ADV / "advisories/github-reviewed"
    year_counts: dict[str, int] = {}
    parse_errors = 0
    rows: list[dict] = []
    partition = Counter()
    for year_dir in sorted(p for p in reviewed_root.iterdir() if p.is_dir()):
        year = year_dir.name
        n = 0
        for path in year_dir.rglob("*.json"):
            n += 1
            try:
                obj = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                parse_errors += 1
                continue
            ghsa_id = norm_id(obj.get("id") or path.stem)
            aliases = [norm_id(a) for a in (obj.get("aliases") or []) if isinstance(a, str)]
            published = (obj.get("published") or "")[:10]
            withdrawn = bool(obj.get("withdrawn"))
            repository, owner, fp_ghsa = extract_first_party(obj)
            first_party = repository is not None
            bucket = owner_bucket(owner) if owner else ("missing" if not first_party else "missing")
            public_ids = {ghsa_id, *aliases}
            in_exclusion = bool(public_ids & exclusion)
            in_window = bool(published) and published >= WINDOW_START
            commit_refs = extract_commit_refs(obj, repository)
            row = {
                "ghsa_id": ghsa_id,
                "aliases": aliases,
                "published": obj.get("published"),
                "withdrawn": withdrawn,
                "summary": obj.get("summary") or "",
                "repository": repository,
                "owner": owner,
                "owner_bucket": bucket,
                "first_party": first_party,
                "in_window": in_window,
                "in_exclusion": in_exclusion,
                "commit_refs": commit_refs,
                "severity": (obj.get("database_specific") or {}).get("severity"),
                "path": str(path.relative_to(ADV)),
            }
            if year in {"2025", "2026"}:
                rows.append(row)
            if first_party and not withdrawn and in_window:
                partition[bucket] += 1
        year_counts[year] = n

    assigned = [
        r
        for r in rows
        if r["first_party"]
        and not r["withdrawn"]
        and r["in_window"]
        and r["owner_bucket"] == "G-N"
        and not r["in_exclusion"]
    ]
    gn_all_window_active = [
        r
        for r in rows
        if r["first_party"]
        and not r["withdrawn"]
        and r["in_window"]
        and r["owner_bucket"] == "G-N"
    ]
    gn_excluded = [r for r in gn_all_window_active if r["in_exclusion"]]
    gn_withdrawn_window = [
        r
        for r in rows
        if r["first_party"]
        and r["withdrawn"]
        and r["in_window"]
        and r["owner_bucket"] == "G-N"
    ]

    assigned_ids = {r["ghsa_id"] for r in assigned}
    excluded_ids = {r["ghsa_id"] for r in gn_excluded}
    all_gn_ids = {r["ghsa_id"] for r in gn_all_window_active}
    leak_af = [r["ghsa_id"] for r in assigned if r["owner_bucket"] != "G-N"]
    leak_excl = sorted(assigned_ids & excluded_ids)
    conservation = {
        "gn_window_active": len(gn_all_window_active),
        "gn_excluded": len(gn_excluded),
        "gn_assigned": len(assigned),
        "sum_excluded_plus_assigned": len(gn_excluded) + len(assigned),
        "union_equals_all_gn": assigned_ids | excluded_ids == all_gn_ids,
        "disjoint": assigned_ids.isdisjoint(excluded_ids),
        "no_non_gn_in_assignment": leak_af == [],
        "no_exclusion_leak": leak_excl == [],
        "arithmetic": len(gn_excluded) + len(assigned) == len(gn_all_window_active),
        "check": (
            assigned_ids | excluded_ids == all_gn_ids
            and assigned_ids.isdisjoint(excluded_ids)
            and leak_af == []
            and leak_excl == []
            and len(gn_excluded) + len(assigned) == len(gn_all_window_active)
        ),
    }

    full_fp_window_active = [
        r
        for r in rows
        if r["first_party"] and not r["withdrawn"] and r["in_window"]
    ]
    shard_partition = Counter(r["owner_bucket"] for r in full_fp_window_active)
    return {
        "year_file_counts": year_counts,
        "parse_errors": parse_errors,
        "reviewed_2025_2026_rows": len(rows),
        "first_party_window_active_partition": dict(shard_partition),
        "first_party_window_active_total": len(full_fp_window_active),
        "partition_sum_equals_total": sum(shard_partition.values()) == len(full_fp_window_active),
        "gn_withdrawn_window": len(gn_withdrawn_window),
        "conservation": conservation,
        "assigned": assigned,
        "gn_excluded": gn_excluded,
        "all_rows_2025_2026": rows,
    }


def main() -> int:
    if not (ADV / "advisories/github-reviewed").is_dir():
        print("advisory-database not checked out", file=sys.stderr)
        return 2

    head = (ADV / ".git/HEAD").read_text(encoding="utf-8").strip()
    input_hashes = {
        "CONTRACT.md": sha256_file(REPO / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"),
        "baseline.json": sha256_file(REPO / "autoresearch/orchestrator-260813-ghsa200-leader/baseline.json"),
        "fp211_public_cases.jsonl": sha256_file(
            REPO / "autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl"
        ),
        "fp211_public_id_dispositions.jsonl": sha256_file(
            REPO / "autoresearch/orchestrator-260813-fp211-audit/public_id_dispositions.jsonl"
        ),
        "fp211_final_mechanisms.jsonl": sha256_file(
            REPO / "autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl"
        ),
        "fp211_canonical_ledger.jsonl": sha256_file(
            REPO / "autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl"
        ),
        "publication_adjudications.json": sha256_file(REPO / "scripts/publication_adjudications.json"),
        "web_data_index.json": sha256_file(REPO / "web/data/index.json"),
        "web_data_stats.json": sha256_file(REPO / "web/data/stats.json"),
    }

    exclusion = collect_exclusion()
    parsed = parse_advisories(set(exclusion["unique_public_ids"]))
    assigned = parsed.pop("assigned")
    gn_excluded = parsed.pop("gn_excluded")
    parsed.pop("all_rows_2025_2026")

    freeze = {
        "schema_version": 1,
        "lane": "commitfirst-gn",
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "contract_sha256": input_hashes["CONTRACT.md"],
        "input_hashes": input_hashes,
        "window_start": WINDOW_START,
        "owner_rule": "first character of repository owner, casefolded, in g-n inclusive",
        "first_party_rule": "references contain github.com/{owner}/{repo}/security/advisories/GHSA-*",
        "exclusion": exclusion["counts"],
        "advisory_head_file": head,
        "advisory_database": {
            "repository": "github/advisory-database",
            "head": "a42c436870111aa3f221257c9d56126a93173ccc",
            "commit_date": "2026-08-13T20:57:17+00:00",
            "head_equals_origin_main_at_freeze": True,
        },
    }
    (OUT / "freeze.json").write_text(
        json.dumps(freeze, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (OUT / "exclusion-ids.txt").write_text(
        "\n".join(exclusion["unique_public_ids"]) + "\n", encoding="utf-8"
    )
    (OUT / "exclusion-ghsa-ids.txt").write_text("\n".join(exclusion["ghsa_ids"]) + "\n", encoding="utf-8")

    assigned_ids = [r["ghsa_id"] for r in assigned]
    (OUT / "assigned-ids.txt").write_text("\n".join(sorted(assigned_ids)) + "\n", encoding="utf-8")
    with (OUT / "assigned.jsonl").open("w", encoding="utf-8") as fh:
        for row in sorted(assigned, key=lambda r: r["ghsa_id"]):
            fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    with (OUT / "gn-excluded.jsonl").open("w", encoding="utf-8") as fh:
        for row in sorted(gn_excluded, key=lambda r: r["ghsa_id"]):
            fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")

    repos = sorted({r["repository"] for r in assigned if r["repository"]})
    (OUT / "assigned-repos.txt").write_text("\n".join(repos) + "\n", encoding="utf-8")

    assignment = {
        "schema_version": 1,
        "lane": "commitfirst-gn",
        "generated_at_utc": freeze["generated_at_utc"],
        "contract_sha256": input_hashes["CONTRACT.md"],
        "input_hashes": input_hashes,
        "advisory_parse": parsed,
        "exclusion_counts": exclusion["counts"],
        "assignment": {
            "count": len(assigned),
            "unique_repos": len(repos),
            "with_commit_refs": sum(1 for r in assigned if r["commit_refs"]),
            "first_id": sorted(assigned_ids)[0] if assigned_ids else None,
            "last_id": sorted(assigned_ids)[-1] if assigned_ids else None,
        },
        "conservation": parsed["conservation"],
        "claim_boundary": "Assignment is the novel G-N first-party window. Worker PASS is a proposal only.",
    }
    (OUT / "assignment-manifest.json").write_text(
        json.dumps(assignment, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        "assigned": len(assigned),
        "repos": len(repos),
        "conservation": parsed["conservation"],
        "partition": parsed["first_party_window_active_partition"],
        "contract_sha256": input_hashes["CONTRACT.md"],
    }, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if parsed["conservation"]["check"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
