#!/usr/bin/env python3
"""Even-partition conservation and all-ID routing. Writes only this lane."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from paths import EXISTING_ACTIVE_ROOT, NEW_CLONE_ROOT, resolve_existing_or_new

LANE = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-delta-even")
ROOT = Path("/home/hanqing/agents/ai-slop")
MANIFEST = ROOT / "autoresearch/herdr-260813-ghsa200-freshness-qa/manifests/github_reviewed_window_added_ids.txt"
DECLARED = ROOT / "autoresearch/herdr-260813-ghsa200-freshness-qa/manifests/leader_declared_ids.txt"
CASES = ROOT / "autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl"
# Existing advisory-database stays under /tmp; a NEW clone would go under NEW_CLONE_ROOT.
ADVISORY_ROOT = resolve_existing_or_new("advisory-database") / "advisories/github-reviewed"
EVEN_NIBBLES = set("02468ace")

AI_RECALL = re.compile(
    r"\b(copilot|claude|cursor|chatgpt|openai|gpt-?\d|codex|windsurf|cascade|"
    r"devin|aider|continue\.dev|gemini|anthropic|generated with|co-authored-by:"
    r"|co-authored-by)\b",
    re.I,
)
REM_RECALL = re.compile(
    r"incomplete (fix|remediation)|reintroduc|patch bypass|residual|"
    r"incomplete.?fix|regression of",
    re.I,
)
REPO_RE = re.compile(r"https?://github\.com/([^/]+)/([^/#?\s]+)")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def nibble(ghsa_id: str) -> str:
    digest = hashlib.sha256(ghsa_id.upper().encode("ascii")).hexdigest()
    return digest[-1]


def load_ids(path: Path) -> list[str]:
    ids = [ln.strip().upper() for ln in path.read_text().splitlines() if ln.strip()]
    return ids


def extract_repo(blob: dict) -> str | None:
    refs = blob.get("references") or []
    package_repos = []
    advisory_repos = []
    other = []
    for ref in refs:
        url = ref.get("url") or ""
        m = REPO_RE.search(url)
        if not m:
            continue
        owner, repo = m.group(1), m.group(2)
        if owner.lower() in {"advisories", "github", "nvd"}:
            continue
        ident = f"{owner}/{repo}"
        rtype = (ref.get("type") or "").upper()
        if rtype == "PACKAGE":
            package_repos.append(ident)
        elif "/security/advisories/" in url:
            advisory_repos.append(ident)
        else:
            other.append(ident)
    for pool in (package_repos, advisory_repos, other):
        if pool:
            return pool[0]
    return None


def commit_refs(blob: dict) -> list[str]:
    out = []
    for ref in blob.get("references") or []:
        url = ref.get("url") or ""
        m = re.search(r"github\.com/[^/]+/[^/]+/commit/([0-9a-f]{7,40})", url, re.I)
        if m:
            out.append(m.group(1))
    return out


def released_versions(blob: dict) -> dict:
    affected = []
    for item in blob.get("affected") or []:
        pkg = item.get("package") or {}
        events = []
        for rng in item.get("ranges") or []:
            events.extend(rng.get("events") or [])
        affected.append(
            {
                "ecosystem": pkg.get("ecosystem"),
                "name": pkg.get("name"),
                "events": events,
                "last_known": (item.get("database_specific") or {}).get("last_known_affected_version_range"),
            }
        )
    return {"affected": affected}


def main() -> None:
    LANE.mkdir(parents=True, exist_ok=True)
    window = load_ids(MANIFEST)
    if len(window) != 731 or len(set(window)) != 731:
        raise SystemExit(f"manifest not 731 unique, got {len(window)}/{len(set(window))}")

    even, odd = [], []
    nibble_map = {}
    for gid in window:
        nib = nibble(gid)
        nibble_map[gid] = nib
        (even if nib in EVEN_NIBBLES else odd).append(gid)
    even_set, odd_set = set(even), set(odd)
    if even_set | odd_set != set(window) or even_set & odd_set:
        raise SystemExit("partition conservation failed")
    if len(even) + len(odd) != 731:
        raise SystemExit("count conservation failed")

    declared = set(load_ids(DECLARED))
    if len(declared) != 212:
        raise SystemExit(f"declared count {len(declared)}")

    declared_aliases = set()
    for line in CASES.read_text().splitlines():
        row = json.loads(line)
        declared_aliases.add(row["case_id"].upper())
        for alias in row.get("aliases") or []:
            declared_aliases.add(str(alias).upper())

    # Index official JSON by uppercase id
    index = {}
    for path in ADVISORY_ROOT.rglob("GHSA-*.json"):
        index[path.stem.upper()] = path

    routes = []
    for gid in even:
        path = index.get(gid)
        rec = {
            "ghsa_id": gid,
            "partition": "EVEN",
            "sha256_last_nibble": nibble_map[gid],
            "official_json": str(path) if path else None,
            "route": None,
            "deep_review_eligible": False,
            "recall_flags": [],
            "repository": None,
            "aliases": [],
            "withdrawn": None,
            "commit_refs": [],
            "released": None,
        }
        if gid in declared:
            rec["route"] = "EXCLUDE_DECLARED"
            rec["reason"] = "Identity is one of the 212 leader declared case IDs"
            routes.append(rec)
            continue
        if not path:
            rec["route"] = "EXCLUDE_MISSING_OFFICIAL_JSON"
            rec["reason"] = "No github-reviewed JSON at current official HEAD"
            routes.append(rec)
            continue
        blob = json.loads(path.read_text())
        rec["aliases"] = [str(a).upper() for a in (blob.get("aliases") or [])]
        rec["withdrawn"] = blob.get("withdrawn")
        rec["repository"] = extract_repo(blob)
        rec["commit_refs"] = commit_refs(blob)
        rec["released"] = released_versions(blob)
        rec["summary"] = blob.get("summary") or ""
        text = (blob.get("summary") or "") + "\n" + (blob.get("details") or "")
        if blob.get("withdrawn"):
            rec["route"] = "EXCLUDE_WITHDRAWN"
            rec["reason"] = f"Official withdrawn timestamp {blob.get('withdrawn')}"
            routes.append(rec)
            continue
        alias_hits = [a for a in rec["aliases"] if a in declared_aliases]
        if alias_hits:
            rec["route"] = "EXCLUDE_ALIAS_OF_DECLARED"
            rec["reason"] = f"Aliases overlap leader declared identities: {alias_hits}"
            rec["route_overlap"] = alias_hits
            routes.append(rec)
            continue
        if not rec["repository"]:
            rec["route"] = "EXCLUDE_MISSING_REPO"
            rec["reason"] = "Official JSON has no first-party GitHub owner/repo identity"
            routes.append(rec)
            continue
        # Remaining: assigned for triage
        flags = []
        if AI_RECALL.search(text):
            flags.append("AI_KEYWORD_RECALL")
        if REM_RECALL.search(text):
            flags.append("REM_REINTRO_KEYWORD_RECALL")
        if rec["commit_refs"]:
            flags.append("HAS_COMMIT_REF")
        rec["recall_flags"] = flags
        rec["deep_review_eligible"] = bool(flags)
        rec["route"] = "ASSIGNED_TRIAGE"
        rec["reason"] = "Even-partition novel official GHSA with repo identity; not declared/withdrawn/alias"
        routes.append(rec)

    route_counts = Counter(r["route"] for r in routes)
    assigned = [r for r in routes if r["route"] == "ASSIGNED_TRIAGE"]
    eligible = [r for r in assigned if r["deep_review_eligible"]]

    (LANE / "partition_even_ids.txt").write_text("".join(x + "\n" for x in even))
    (LANE / "partition_odd_ids.txt").write_text("".join(x + "\n" for x in odd))
    (LANE / "routing.jsonl").write_text("".join(json.dumps(r, ensure_ascii=True) + "\n" for r in routes))

    source_hashes = {
        "github_reviewed_window_added_ids.txt": sha256_file(MANIFEST),
        "leader_declared_ids.txt": sha256_file(DECLARED),
        "fp211_public_cases.jsonl": sha256_file(CASES),
        "freshness_qa_source_freeze.json": sha256_file(
            ROOT / "autoresearch/herdr-260813-ghsa200-freshness-qa/source_freeze.json"
        ),
        "leader_contract.md": sha256_file(ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"),
        "advisory_database_head": "6e8a7ca9f3d8463dc037f2308b57f6cf72b55e86",
        "frozen_head": "39d8887723797efc1804585dd06585c9fd751226",
        "expected_window_added_sha256": "724fa2b8648e270de72b99ba52ffb738a1f87c07e649450b5d7b62dca547034a",
    }
    if source_hashes["github_reviewed_window_added_ids.txt"] != source_hashes["expected_window_added_sha256"]:
        raise SystemExit("window added manifest hash mismatch")

    conservation = {
        "window_added": 731,
        "even": len(even),
        "odd": len(odd),
        "even_plus_odd": len(even) + len(odd),
        "intersection": 0,
        "union": 731,
        "conserved": True,
        "rule": "EVEN iff last hex nibble of SHA256(uppercase GHSA ID) is in 02468ace",
    }
    (LANE / "source_hashes.json").write_text(json.dumps({"source_hashes": source_hashes, "partition_conservation": conservation}, indent=2) + "\n")

    summary = {
        "even": len(even),
        "odd": len(odd),
        "route_counts": dict(route_counts),
        "assigned_triage": len(assigned),
        "deep_review_eligible": len(eligible),
        "eligible_ids": [r["ghsa_id"] for r in eligible],
    }
    (LANE / "partition_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
