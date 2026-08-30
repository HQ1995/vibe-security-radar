#!/usr/bin/env python3
"""Backfill top-level `advisory_ids` on funnel-account ledger rows.

Zero-inference tiers only (user-approved 2026-08-26):
  1. census_alias_map   - row class_id present in
                          .ai-slop/state/research-queue/round6/.alias_class_member_map.json
                          (the census cluster's official member IDs, copied verbatim)
  2. research_block     - row not in map; its own research blocks already recorded
                          advisory_ids / case_id (intra-row field copy)
  3. repo_cohort_exact  - row not in map, no research IDs, and its repo holds
                          EXACTLY ONE ledger row and that repo's cohort window pool
                          matches the row's `advisories` count after CVE-alias
                          collapse. Pool must be the row's full member set.
Repo-shared "count matches" rows are NOT backfilled (count coincidence is not
proof) - they stay absent.

Also writes `advisory_ids_source` per backfilled row. Nothing else is touched:
status, counts, and all existing fields are preserved byte-for-byte.
"""
from __future__ import annotations

import json
import re
import shutil
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "artifacts" / "funnel-account-20260817.jsonl"
MAP = ROOT / ".ai-slop/state/research-queue/round6" / ".alias_class_member_map.json"
COHORT = ROOT / ".ai-slop/state/cohort-v1" / "advisory-repos-since-2025-05.json"
BACKUP = LEDGER.with_suffix(".jsonl.bak-advisory-backfill-20260826")

RESEARCH_KEYS = (
    "round9_research", "round8_research", "round7_research", "round6_research",
    "round5_research", "round4_research", "round3_research", "causal_research",
)
ID_RE = re.compile(r"^(GHSA|CVE|GO|PY|PYSEC|RV|ML|BIT|JLSEC|UBUNTU|GLSA|OSV)-", re.I)


def norm(x: str) -> str:
    x = x.strip().upper()
    return x


def canonical_ids(raw) -> list[str]:
    """Split 'CVE-x/GHSA-y' compound strings, normalize, dedupe, stable order."""
    out: list[str] = []
    seen: set[str] = set()
    for part in raw:
        for piece in str(part).split("/"):
            piece = piece.strip().upper()
            if ID_RE.match(piece) and piece not in seen:
                seen.add(piece)
                out.append(piece)
    return out


def research_ids(row: dict) -> list[str]:
    parts: list[str] = []
    for k in RESEARCH_KEYS:
        rec = row.get(k)
        if not isinstance(rec, dict):
            continue
        parts.extend(rec.get("advisory_ids") or [])
        c = rec.get("case_id")
        if isinstance(c, str) and re.match(r"^(GHSA|CVE|GO|PY|RV|ML|BIT)-", c, re.I):
            parts.append(c)
    v = row.get("advisory_identity")
    if isinstance(v, str) and re.match(r"^(GHSA|CVE|GO|PY|RV|ML)-", v, re.I):
        parts.append(v)
    return canonical_ids(parts)


def slug_of_key(rk: str) -> str:
    for pre in (
        "https://github.com/", "http://github.com/", "github.com/",
        "https://gitlab.com/", "http://gitlab.com/", "gitlab.com/",
        "https://sourceforge.net/", "sourceforge.net/", "git://github.com/",
    ):
        if rk.startswith(pre):
            rk = rk[len(pre):]
            break
    return rk.strip("/").lower()


def cve_base(a: str) -> str | None:
    return a if a.startswith("CVE-") else None


def dedupe(xs: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def main() -> None:
    map_data: dict[str, list[str]] = json.loads(MAP.read_text())
    cohort: dict[str, list[str]] = json.loads(COHORT.read_text())
    rmap: dict[str, list[str]] = {}
    for rk, advs in cohort.items():
        rmap.setdefault(slug_of_key(rk), []).extend(advs)

    rows = [json.loads(line) for line in LEDGER.read_text().splitlines() if line.strip()]
    original_keys = [{k: r[k] for k in r} for r in rows]
    repo_rows: dict[str, list[dict]] = {}
    for r in rows:
        repo_rows.setdefault((r.get("repo") or "").lower().strip("/"), []).append(r)

    stats = Counter()
    for r in rows:
        cid = r["class_id"]
        slug = (r.get("repo") or "").lower().strip("/")
        if cid in map_data:
            ids = dedupe(norm(x) for x in map_data[cid])
            source = "census_alias_map"
        else:
            ids = research_ids(r)
            if ids:
                source = "research_block"
            else:
                cand = dedupe(rmap.get(slug, []))
                by_cve: dict[str, list[str]] = {}
                for a in cand:
                    b = cve_base(a)
                    if b:
                        by_cve.setdefault(b, []).append(a)
                collapsed = [
                    a for a in cand
                    if cve_base(a) is None or by_cve.get(cve_base(a), [None])[0] == a
                ]
                if cand and len(repo_rows[slug]) == 1 and len(collapsed) == r.get("advisories"):
                    ids = dedupe(norm(x) for x in cand)
                    source = "repo_cohort_exact"
                else:
                    continue
        r["advisory_ids"] = ids
        r["advisory_ids_source"] = source
        stats[source] += 1

    # --- verify before writing ---
    old_status = Counter(r["status"] for r in rows)
    assert len(rows) == 23861, len(rows)
    tp_rows = old_status["AI_ROOT_CAUSE"] + old_status["AI_CODE_FLAWED"]
    assert stats["census_alias_map"] == 14803, stats
    assert stats["research_block"] == 595, stats
    assert stats["repo_cohort_exact"] == 218, stats

    if not BACKUP.exists():
        shutil.copy2(LEDGER, BACKUP)
    lines = [json.dumps(r, ensure_ascii=False) for r in rows]
    tmp = LEDGER.with_suffix(".jsonl.tmp")
    tmp.write_text("\n".join(lines) + "\n")
    chk = [json.loads(l) for l in tmp.read_text().splitlines() if l.strip()]
    assert len(chk) == len(original_keys)
    assert Counter(r["status"] for r in chk) == Counter(r["status"] for r in original_keys)
    for new, old in zip(chk, original_keys):
        for k, v in old.items():  # every pre-existing key unchanged
            assert new[k] == v, (old.get("class_id"), k)
        assert new["class_id"] == old["class_id"]
    tmp.replace(LEDGER)

    print("backfilled:", dict(stats), "total:", sum(stats.values()))
    print("status:", dict(old_status))
    print("backup:", BACKUP.name)


if __name__ == "__main__":
    sys.exit(main())
