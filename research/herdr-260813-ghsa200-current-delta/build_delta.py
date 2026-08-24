#!/usr/bin/env python3
"""GHSA 200+ current-delta worker: build first-party advisory delta from frozen
2026-07-23 advisory-database snapshot to current HEAD, apply baseline exclusions
and identity-collision routing, then emit seven-gate rows for promising novel
cases researched through vulnerable-repo Git history.

Owned paths:
  repo out:  autoresearch/herdr-260813-ghsa200-current-delta/
  scratch:   /tmp/ghsa200-worker-clones/current-delta/

Never prints credentials. Never stores raw API pages in the repo.
"""
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path("/home/hanqing/agents/ai-slop")
OWN = REPO / "autoresearch" / "herdr-260813-ghsa200-current-delta"
SCRATCH = Path("/tmp/ghsa200-worker-clones/current-delta")
GITDIR = SCRATCH / "advisory-database.git"

FROZEN_COMMIT = "39d8887723797efc1804585dd06585c9fd751226"
CURRENT_COMMIT = "6e8a7ca9f3d8463dc037f2308b57f6cf72b55e86"

LEADER = REPO / "autoresearch" / "orchestrator-260813-ghsa200-leader"
FP211 = REPO / "autoresearch" / "orchestrator-260813-fp211-audit"

SIBLING_DIRS = [
    "herdr-260813-ghsa200-fresh-am",
    "herdr-260813-ghsa200-fresh-nz",
    "herdr-260813-ghsa200-gap",
    "herdr-260813-ghsa200-remediation",
    "herdr-260813-ghsa200-upgrade-b",
    "herdr-260813-ghsa200-upgrade-a",
]


def git(*args: str) -> str:
    out = subprocess.run(
        ["git", "-c", "core.abbrev=40", "--git-dir", str(GITDIR), *args],
        capture_output=True, text=True, check=True)
    return out.stdout


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()




def main() -> int:
    OWN.mkdir(parents=True, exist_ok=True)
    (SCRATCH / "raw").mkdir(parents=True, exist_ok=True)

    freeze = {
        "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "frozen_snapshot": {
            "source": "official github/advisory-database local snapshot",
            "commit": FROZEN_COMMIT,
            "tree": git("rev-parse", f"{FROZEN_COMMIT}^{{tree}}").strip(),
            "commit_date_utc": git("show", "-s", "--format=%cI", FROZEN_COMMIT).strip(),
        },
        "current_head": {
            "source": "official github/advisory-database clone",
            "commit": CURRENT_COMMIT,
            "tree": git("rev-parse", f"{CURRENT_COMMIT}^{{tree}}").strip(),
            "commit_date_utc": git("show", "-s", "--format=%cI", CURRENT_COMMIT).strip(),
        },
        "baseline_exclusion": {},
        "sibling_declared": {},
    }

    # --- baseline 381 declared public IDs + their GHSA case ids ---
    base_ids: set[str] = set()
    base_gvs: set[str] = set()
    base_cases: dict[str, str] = {}
    with open(FP211 / "public_id_dispositions.jsonl") as f:
        for line in f:
            row = json.loads(line)
            pid = row["public_id"]
            base_ids.add(pid)
            base_gvs.add(row.get("id_type", ""))
            for c in row.get("case_ids", []):
                base_cases[c] = pid
    # also GHSA-type declared IDs
    with open(FP211 / "public_cases.jsonl") as f:
        for line in f:
            row = json.loads(line)
            cid = row.get("case_id") or row.get("ghsa")
            if cid:
                base_ids.add(cid)
            for a in row.get("aliases", []):
                base_ids.add(a)
    freeze["baseline_exclusion"] = {
        "declared_public_ids": sorted(base_ids),
        "count": len(base_ids),
        "ghsa_case_ids": sorted(set(base_cases)),
        "source_files": [
            "autoresearch/orchestrator-260813-fp211-audit/public_id_dispositions.jsonl",
            "autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl",
        ],
        "source_hashes": {
            "public_id_dispositions": sha256_file(FP211 / "public_id_dispositions.jsonl"),
            "public_cases": sha256_file(FP211 / "public_cases.jsonl"),
        },
    }

    # --- sibling worker declared IDs (identity-collision routing targets) ---
    sibling_ids: dict[str, str] = {}
    for d in SIBLING_DIRS:
        sdir = REPO / "autoresearch" / d
        if not sdir.exists():
            continue
        ids: set[str] = set()
        for pat in ["**/*.jsonl", "**/*freeze*.json", "**/*.json"]:
            for p in sdir.glob(pat):
                try:
                    data = p.read_text()
                except Exception:
                    continue
                # GHSA pattern: 4-4-4-4 uppercase alnum
                import re
                for m in re.findall(r"GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}", data):
                    ids.add(m)
                for m in re.findall(r"CVE-\d{4}-\d{4,7}", data):
                    ids.add(m)
        sibling_ids[d] = sorted(ids)
    freeze["sibling_declared"] = {
        d: {"ids": ids, "count": len(ids)} for d, ids in sorted(sibling_ids.items())
    }

    out = OWN / "exclusion-freeze.json"
    out.write_text(json.dumps(freeze, indent=2, sort_keys=True) + "\n")
    print(f"wrote {out}")
    print(f"baseline declared IDs: {len(base_ids)}")
    for d, v in sorted(freeze["sibling_declared"].items()):
        print(f"  sibling {d}: {v['count']} ids")
    print(f"freeze sha256: {sha256_file(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
