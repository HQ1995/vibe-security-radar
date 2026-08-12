#!/usr/bin/env python3
"""Fail-closed structural and optional live verifier for the canonical ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import build


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ID_RE = re.compile(r"^(?:CVE-\d{4}-\d+|GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4})$")
AI_MARKERS = ("[ai]", "ai-assisted", "claude", "cursor", "codex")


def load_json(path: Path):
    return json.loads(path.read_text())


def load_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-C", str(repo), *args],
        check=check,
        text=True,
        capture_output=True,
    )


def gh_json(endpoint: str) -> dict:
    result = subprocess.run(["gh", "api", endpoint], check=True, text=True, capture_output=True)
    return json.loads(result.stdout)


def verify_structural() -> tuple[dict, list[dict], list[dict]]:
    manifest = load_json(HERE / "source_manifest.json")
    adjudications = load_json(HERE / "adjudications.json")
    ledger = load_jsonl(HERE / "ledger.jsonl")
    summary = load_json(HERE / "summary.json")

    for item in manifest["sources"]:
        path = ROOT / item["path"]
        assert path.is_file(), item["path"]
        assert sha256(path) == item["sha256"], item["path"]

    expected_ledger, expected_summary = build.build_outputs()
    assert (HERE / "ledger.jsonl").read_text() == expected_ledger
    assert (HERE / "summary.json").read_text() == expected_summary
    assert summary["ledger_sha256"] == sha256(HERE / "ledger.jsonl")
    assert summary["source_manifest_sha256"] == sha256(HERE / "source_manifest.json")
    assert summary["adjudications_sha256"] == sha256(HERE / "adjudications.json")

    assert len(ledger) == 247
    assert len({row["row_key"] for row in ledger}) == len(ledger)
    for row in ledger:
        assert row["row_state"] in {"PASS", "REJECT", "NARROW", "BLOCKED", "UNKNOWN", "DUPLICATE"}
        assert row["public_ids"] == sorted(set(row["public_ids"]))
        assert all(ID_RE.fullmatch(value) for value in row["public_ids"])
        assert set(row["counting"]) == {
            "canonical_instance",
            "strict_document_max",
            "broad_released_max",
            "widest_max",
        }
        assert all(isinstance(value, bool) for value in row["counting"].values())

    base_count = 213
    base = ledger[:base_count]
    additions = [row for row in ledger if row["source_layer"] == "POST_HOLD_REDTEAM" and row["record_kind"] == "COMPONENT_ROW"]
    controls = [row for row in ledger if row["record_kind"] == "POST_HOLD_ROUTE_CONTROL"]
    assert len(additions) == 28
    assert Counter(row["row_state"] for row in additions) == Counter({"PASS": 26, "NARROW": 2})
    assert len(controls) == 6 and all(row["row_state"] == "REJECT" for row in controls)
    assert all(not any(row["counting"].values()) for row in controls)

    base_components = [row for row in base if row["record_kind"] == "COMPONENT_ROW" and row["counting"]["canonical_instance"]]
    base_ids = {value for row in base_components for value in row["public_ids"]}
    new_ids = [value for row in additions for value in row["public_ids"]]
    assert len(new_ids) == len(set(new_ids)) == 39
    assert not (base_ids & set(new_ids))

    fingerprints = [row["mechanism_fingerprint"] for row in additions]
    assert len(fingerprints) == len(set(fingerprints)) == 28
    source_hashes = {item["path"]: item["sha256"] for item in manifest["sources"]}
    for row in additions:
        source_ref = row["source_refs"][0]
        assert source_ref["sha256"] == source_hashes[source_ref["path"]]
        raw = next(item for item in adjudications["components"] if item["row_key"] == row["row_key"])
        assert row["mechanism_fingerprint"] == build.mechanism_fingerprint(raw)
        for sha_value in (
            row["release_evidence"]["candidate_sha"],
            row["release_evidence"]["fix_sha"],
            row["ai_provenance"]["marker_sha"],
            *row["atomic_fix_members"],
        ):
            assert SHA_RE.fullmatch(sha_value)

    base_shas = {
        value
        for row in base
        for edge in row.get("candidate_fix_edges", [])
        for key, value in edge.items()
        if key.endswith("_sha") and isinstance(value, str)
    }
    new_shas = {
        value
        for row in additions
        for value in (
            row["candidate_fix_edges"][0]["candidate_sha"],
            row["candidate_fix_edges"][0].get("carrier_sha"),
            row["release_evidence"]["fix_sha"],
            *row["atomic_fix_members"],
        )
        if value
    }
    assert not (base_shas & new_shas)

    occurrences: dict[str, list[dict]] = defaultdict(list)
    for row in additions:
        values = {
            row["candidate_fix_edges"][0]["candidate_sha"],
            row["candidate_fix_edges"][0].get("carrier_sha"),
            row["release_evidence"]["fix_sha"],
            *row["atomic_fix_members"],
        }
        for value in values - {None}:
            occurrences[value].append(row)
    for rows in occurrences.values():
        if len(rows) > 1:
            assert all(row["reuse_justification"] for row in rows)

    canonical = [row for row in ledger if row["record_kind"] == "COMPONENT_ROW" and row["counting"]["canonical_instance"]]
    released = [row for row in canonical if row["source_tier"].endswith("_RELEASED")]
    assert len(canonical) == 212
    assert Counter(row["source_tier"] for row in canonical) == Counter(
        {"STRICT_RELEASED": 132, "INCOMPLETE_RELEASED": 68, "INCOMPLETE_COMMIT_ONLY": 11, "STRICT_COMMIT_ONLY": 1}
    )
    assert Counter(row["row_state"] for row in released) == Counter(
        {"PASS": 189, "NARROW": 4, "UNKNOWN": 4, "REJECT": 3}
    )
    assert summary["source_envelopes"] == {
        "strict_document_rows": 132,
        "broad_released_max": 200,
        "widest_max": 212,
        "final_count": None,
    }
    assert summary["status"] == "HOLD"
    assert summary["integration_ready"] is False
    return summary, additions, controls


def verify_live(additions: list[dict]) -> dict:
    checked_advisories: set[tuple[str, str]] = set()
    row_cves = {row["row_key"]: {value for value in row["public_ids"] if value.startswith("CVE-")} for row in additions}
    observed_cves: dict[str, set[str]] = defaultdict(set)

    for row in additions:
        evidence = row["release_evidence"]
        repo = Path.home() / ".cache/cve-analyzer/repos" / evidence["repo_cache"]
        assert repo.joinpath(".git").exists(), repo
        atom = row["candidate_fix_edges"][0]["candidate_sha"]
        for sha_value in {atom, evidence["candidate_sha"], evidence["fix_sha"], row["ai_provenance"]["marker_sha"], *row["atomic_fix_members"]}:
            git(repo, "cat-file", "-e", f"{sha_value}^{{commit}}")
        parents = git(repo, "rev-list", "--parents", "-n", "1", atom).stdout.split()
        assert len(parents) == 2, f"non-atomic candidate: {row['row_key']}"
        marker_message = git(repo, "show", "-s", "--format=%s%n%b", row["ai_provenance"]["marker_sha"]).stdout.lower()
        assert any(marker in marker_message for marker in AI_MARKERS), row["row_key"]
        assert git(repo, "merge-base", "--is-ancestor", evidence["candidate_sha"], evidence["vulnerable_tag"], check=False).returncode == 0
        assert git(repo, "merge-base", "--is-ancestor", evidence["fix_sha"], evidence["vulnerable_tag"], check=False).returncode == 1
        assert git(repo, "merge-base", "--is-ancestor", evidence["fix_sha"], evidence["fixed_tag"], check=False).returncode == 0

        for ghsa in (value for value in row["public_ids"] if value.startswith("GHSA-")):
            key = (row["repository"], ghsa)
            if key in checked_advisories:
                continue
            advisory = gh_json(f"repos/{row['repository']}/security-advisories/{ghsa.lower()}")
            assert advisory["ghsa_id"].upper() == ghsa
            assert advisory["state"] == "published" and advisory["withdrawn_at"] is None
            repo_ids = {item["value"].upper() for item in advisory["identifiers"]}
            observed_cves[row["row_key"]].update(value for value in repo_ids if value.startswith("CVE-"))
            if row_cves[row["row_key"]] and not (repo_ids & row_cves[row["row_key"]]):
                global_advisory = gh_json(f"advisories/{ghsa.lower()}")
                global_ids = {item["value"].upper() for item in global_advisory["identifiers"]}
                observed_cves[row["row_key"]].update(value for value in global_ids if value.startswith("CVE-"))
            checked_advisories.add(key)

    for row_key, expected in row_cves.items():
        assert observed_cves[row_key] == expected, (row_key, observed_cves[row_key], expected)
    return {
        "release_edges": len(additions),
        "published_repo_advisories": len(checked_advisories),
        "public_ids": len({value for row in additions for value in row["public_ids"]}),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="also replay Git containment and first-party advisory status")
    parser.add_argument("--write-result", action="store_true")
    args = parser.parse_args()
    summary, additions, controls = verify_structural()
    live_counts = verify_live(additions) if args.live else None
    result = {
        "status": "HOLD",
        "validation": "PASS",
        "integration_ready": False,
        "validated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "ledger_sha256": summary["ledger_sha256"],
        "structural_counts": summary["counts"],
        "live_counts": live_counts,
        "route_controls": len(controls),
        "blockers": summary["blockers"],
    }
    if args.write_result:
        (HERE / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    live_suffix = "" if live_counts is None else f", {live_counts['release_edges']} release edges, {live_counts['published_repo_advisories']} advisories"
    print(f"PASS: 247 records, source envelope 132/200/212, HOLD{live_suffix}")


if __name__ == "__main__":
    main()
