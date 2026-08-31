#!/usr/bin/env python3
"""Validate physical Round12 outputs; --allow-missing supports in-flight checks."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LANE = Path(__file__).resolve().parent
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
VERDICTS = {"AI_ROOT_CAUSE", "AI_CODE_FLAWED", "NOT_AI", "FALSE_POSITIVE", "EVIDENCE_GAP", "BLOCKED"}
OPEN = {"EVIDENCE_GAP", "BLOCKED"}
CHECKS = {
    "vulnerability_mechanism",
    "atomic_bic",
    "immediate_parent_absence",
    "squash_member_decomposition",
    "affected_release_membership",
    "fixed_release_membership",
    "direct_fix_or_unpatched",
    "bic_only_ai_attribution",
}
sys.path.insert(0, str(ROOT / "scripts"))
from audit_record_gates import check_record  # noqa: E402


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def nonempty_strings(value) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value)


def commit_exists(clone: Path, sha: str, env: dict[str, str]) -> bool:
    try:
        return subprocess.run(
            ["git", "-C", str(clone), "cat-file", "-e", f"{sha}^{{commit}}"],
            env=env,
            capture_output=True,
            timeout=15,
        ).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-missing", action="store_true")
    args = parser.parse_args()
    manifest = jsonl(LANE / "manifest.jsonl")
    problems: list[str] = []
    records: list[dict] = []
    result_hashes: dict[str, str] = {}

    if len(manifest) != 50 or len({row["worker"] for row in manifest}) != 50 or len({row["class_id"] for row in manifest}) != 50:
        problems.append("manifest must contain 50 unique workers and class_ids")

    for assignment in manifest:
        worker = assignment["worker"]
        bundle_path = ROOT / assignment["bundle"]
        output_path = ROOT / assignment["primary_out"]
        actual_bundle_hash = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
        if actual_bundle_hash != assignment["bundle_sha256"]:
            problems.append(f"{worker}: bundle hash mismatch")
        if not output_path.exists():
            if not args.allow_missing:
                problems.append(f"{worker}: missing output")
            continue
        try:
            record = json.loads(output_path.read_text())
        except Exception as exc:
            problems.append(f"{worker}: invalid JSON: {exc}")
            continue
        records.append(record)
        result_hashes[worker] = hashlib.sha256(output_path.read_bytes()).hexdigest()
        bundle = json.loads(bundle_path.read_text())

        for key, expected in (
            ("worker", worker),
            ("class_id", assignment["class_id"]),
            ("repo", assignment["repo"]),
            ("advisory_ids", assignment["advisory_ids"]),
        ):
            if record.get(key) != expected:
                problems.append(f"{worker}: {key} does not match assignment")
        if record.get("schema_version") != "independent-case-audit/v1":
            problems.append(f"{worker}: bad schema_version")
        if not isinstance(record.get("review_agent_id"), str) or not record["review_agent_id"].strip():
            problems.append(f"{worker}: missing review_agent_id")
        if not re.match(r"^(GHSA-[0-9A-Za-z-]+|CVE-\d{4}-\d+)$", str(record.get("case_id") or "")):
            problems.append(f"{worker}: case_id is not official")

        binding = record.get("input_binding")
        if not isinstance(binding, dict):
            problems.append(f"{worker}: missing input_binding")
        else:
            if binding.get("bundle_sha256") != assignment["bundle_sha256"] or not SHA256.match(str(binding.get("bundle_sha256") or "")):
                problems.append(f"{worker}: bundle input binding mismatch")
            if binding.get("clone_head_sha") != bundle["clone_head_sha"]:
                problems.append(f"{worker}: clone HEAD input binding mismatch")

        verdict = record.get("verdict")
        if verdict not in VERDICTS:
            problems.append(f"{worker}: invalid verdict {verdict!r}")
        checks = record.get("protocol_checks")
        if not isinstance(checks, dict) or set(checks) != CHECKS:
            problems.append(f"{worker}: protocol_checks keys differ")
        else:
            for name, check in checks.items():
                if not isinstance(check, dict) or check.get("status") not in {"PASS", "GAP", "N/A"} or not nonempty_strings(check.get("evidence")):
                    problems.append(f"{worker}: malformed protocol check {name}")
            statuses = {name: value.get("status") for name, value in checks.items() if isinstance(value, dict)}
            if verdict in {"AI_ROOT_CAUSE", "AI_CODE_FLAWED", "NOT_AI"} and set(statuses.values()) != {"PASS"}:
                problems.append(f"{worker}: closed causal verdict requires eight PASS checks")
            if verdict in OPEN and "GAP" not in statuses.values():
                problems.append(f"{worker}: open verdict requires a GAP check")
            if verdict != "FALSE_POSITIVE" and "N/A" in statuses.values():
                problems.append(f"{worker}: N/A only allowed for FALSE_POSITIVE")

        for key in ("introducer_sha", "introducer_parent", "fix_sha", "direct_fix_sha"):
            value = record.get(key)
            if value is not None and not (isinstance(value, str) and SHA40.match(value)):
                problems.append(f"{worker}: {key} must be null or 40-hex")
        if not isinstance(record.get("introducer_parent_absent"), bool):
            problems.append(f"{worker}: introducer_parent_absent must be bool")
        if not isinstance(record.get("squash_decomposed"), bool):
            problems.append(f"{worker}: squash_decomposed must be bool")
        if not isinstance(record.get("decomposed_shas"), list) or any(not SHA40.match(str(value)) for value in record.get("decomposed_shas") or []):
            problems.append(f"{worker}: decomposed_shas must be 40-hex list")
        if not nonempty_strings(record.get("evidence")):
            problems.append(f"{worker}: evidence must be a nonempty string list")
        for key in ("bug_semantics", "flaw_origin", "reasoning"):
            if not isinstance(record.get(key), str) or not record[key].strip():
                problems.append(f"{worker}: {key} must be nonempty")
        marker = record.get("ai_marker")
        if not isinstance(marker, dict) or marker.get("state") not in {"PRESENT", "ABSENT", "UNKNOWN"} or not nonempty_strings(marker.get("evidence")):
            problems.append(f"{worker}: malformed ai_marker")
        if verdict in OPEN and not (isinstance(record.get("remaining_gap"), str) and record["remaining_gap"].strip()):
            problems.append(f"{worker}: open verdict requires remaining_gap")
        if verdict not in OPEN and record.get("remaining_gap") not in (None, ""):
            problems.append(f"{worker}: closed verdict has remaining_gap")

        clone = Path(assignment["clone_dir"])
        env = {**os.environ, "GIT_NO_LAZY_FETCH": "1"}
        for sha in [record.get("introducer_sha"), record.get("introducer_parent"), record.get("fix_sha"), record.get("direct_fix_sha"), *(record.get("decomposed_shas") or [])]:
            if sha and not commit_exists(clone, sha, env):
                problems.append(f"{worker}: commit object unavailable: {sha}")
        problems.extend(f"{worker}: syntax gate: {problem}" for problem in check_record(record))

    agent_ids = [record.get("review_agent_id") for record in records]
    if len(agent_ids) != len(set(agent_ids)):
        problems.append("review_agent_id values are not unique")
    if len(records) != len({record.get("worker") for record in records}):
        problems.append("result workers are duplicated")

    summary = {
        "manifest": len(manifest),
        "records": len(records),
        "missing": [row["worker"] for row in manifest if not (ROOT / row["primary_out"]).exists()],
        "verdicts": dict(Counter(record.get("verdict") for record in records)),
        "problems": problems,
        "result_sha256": result_hashes,
    }
    print(json.dumps(summary, indent=1))
    return bool(problems)


if __name__ == "__main__":
    raise SystemExit(main())
