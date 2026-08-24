#!/usr/bin/env python3
"""Fail-closed verifier for the snapshot-only unified ledger."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ID_RE = re.compile(r"^(?:CVE-\d{4}-\d+|GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4})$")
STATES = {"PASS", "REJECT", "NARROW", "BLOCKED", "UNKNOWN", "DUPLICATE"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path):
    return json.loads(path.read_text())


def load_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


summary = load_json(ROOT / "summary.json")
ledger = load_jsonl(ROOT / "ledger.jsonl")

manifest = {item["path"]: item for item in summary["snapshot_manifest"]}
actual_snapshot_paths = {
    path.relative_to(ROOT).as_posix()
    for path in (ROOT / "snapshot").rglob("*")
    if path.is_file()
}
assert set(manifest) == actual_snapshot_paths
for relative, item in manifest.items():
    path = ROOT / relative
    assert item["source_path"] and not Path(item["source_path"]).is_absolute()
    assert path.stat().st_size == item["bytes"]
    assert sha256(path) == item["sha256"]

assert summary["snapshot_file_count"] == len(manifest) == 57
assert summary["ledger_sha256"] == sha256(ROOT / "ledger.jsonl")
assert summary["status"] == "COMPLETE"
assert summary["integration_ready"] is False
assert summary["source_envelopes"]["final_count"] is None

assert len(ledger) == 213
assert len({row["row_key"] for row in ledger}) == len(ledger)
assert {row["row_state"] for row in ledger} == STATES
for row in ledger:
    assert row["schema_version"] == 1
    assert set(row["counting"]) == {"canonical_instance", "strict_document_max", "broad_released_max", "widest_max"}
    assert all(isinstance(value, bool) for value in row["counting"].values())
    assert row["public_ids"] == sorted(set(row["public_ids"]))
    assert all(ID_RE.fullmatch(value) for value in row["public_ids"])
    assert row["primary_id"] is None or row["primary_id"] in row["public_ids"]
    for edge in row["candidate_fix_edges"]:
        assert all(SHA_RE.fullmatch(value) for key, value in edge.items() if key.endswith("_sha"))
    for source_ref in row["source_refs"]:
        assert source_ref["path"] in manifest
        assert source_ref["sha256"] == manifest[source_ref["path"]]["sha256"]

component = [row for row in ledger if row["record_kind"] == "COMPONENT_ROW"]
canonical = [row for row in component if row["counting"]["canonical_instance"]]
baseline = [row for row in component if row["source_layer"] == "STRICT_200_BASELINE"]
post = [row for row in component if row["source_layer"] == "POST_STRICT_DOCUMENTS"]
post_canonical = [row for row in post if row["counting"]["canonical_instance"]]
route_controls = [row for row in ledger if row["record_kind"] == "BATCH1_ROUTE_CONTROL"]
proposals = [row for row in ledger if row["record_kind"] == "BATCH1_PENDING_PROPOSAL"]

assert (len(component), len(canonical), len(baseline), len(post), len(post_canonical)) == (186, 184, 110, 76, 74)
assert len(route_controls) == 22
assert Counter(row["row_state"] for row in route_controls) == Counter({"REJECT": 17, "BLOCKED": 3, "UNKNOWN": 2})
assert len(proposals) == 5
assert all(row["row_state"] == "UNKNOWN" and row["state_axes"]["source_verdict"] == "PASS" for row in proposals)
assert all(not any(row["counting"].values()) for row in route_controls + proposals)

duplicates = [row for row in component if row["row_state"] == "DUPLICATE"]
assert len(duplicates) == 2
assert {row["row_key"] for row in duplicates} == {
    "post:coolify-shell-grammar@batch-e",
    "post:coolify-activity-scope@batch-e",
}
assert all(row["duplicate_of"] in {candidate["row_key"] for candidate in ledger} for row in duplicates)
assert all(not any(row["counting"].values()) for row in duplicates)

by_tier = Counter(row["source_tier"] for row in canonical)
assert by_tier == Counter({
    "STRICT_RELEASED": 125,
    "INCOMPLETE_RELEASED": 47,
    "INCOMPLETE_COMMIT_ONLY": 11,
    "STRICT_COMMIT_ONLY": 1,
})
assert sum(row["counting"]["strict_document_max"] for row in component) == 125
assert sum(row["counting"]["broad_released_max"] for row in component) == 172
assert sum(row["counting"]["widest_max"] for row in component) == 184
assert summary["source_envelopes"]["strict_document_rows"] == 125
assert summary["source_envelopes"]["broad_released_max"] == 172
assert summary["source_envelopes"]["widest_max"] == 184

control_rows = [
    row for row in post
    if row["state_axes"]["negative_control_outcome"] in {"KEEP", "REJECT", "NARROW", "UNKNOWN"}
]
assert len(control_rows) == 20
assert Counter(row["state_axes"]["negative_control_outcome"] for row in control_rows) == Counter(
    {"KEEP": 15, "REJECT": 3, "NARROW": 1, "UNKNOWN": 1}
)
assert len(summary["negative_control_audit"]["rows"]) == 20
assert summary["negative_control_audit"]["outcomes"] == {"KEEP": 15, "NARROW": 1, "REJECT": 3, "UNKNOWN": 1}

assert Counter(row["state_axes"]["alias_qa_action"] for row in post) == Counter(
    {"KEEP": 65, "ADD_ALIAS": 2, "SPLIT": 1, "REMOVE_ID": 2, "UNKNOWN": 6}
)
assert sum(len(row["alias_amendments"]) for row in baseline) == 4

baseline_ids = {value for row in baseline for value in row["public_ids"]}
post_declared_ids = {value for row in post_canonical for value in row["declared_public_ids"]}
post_official_ids = {value for row in post_canonical for value in row["public_ids"]}
assert (len(baseline_ids), len(post_declared_ids), len(post_official_ids)) == (200, 119, 121)
assert not (baseline_ids & post_official_ids)
assert len(baseline_ids | post_official_ids) == 321

projections = summary["status_projections_not_final_counts"]
assert projections["after_three_known_rejects"] == {
    "strict_document_rows": 125,
    "broad_released": 169,
    "widest": 181,
}
assert projections["after_three_rejects_and_sampled_causal_unknown"] == {
    "strict_document_rows": 124,
    "broad_released": 168,
    "widest": 180,
}
assert projections["if_filebrowser_umbrella_is_duplicate_too"] == {
    "broad_released": 167,
    "widest": 179,
}

# The strict summary stores a canonical UTF-8 JSON digest, not the JSONL byte digest.
strict_rows = load_jsonl(ROOT / "snapshot/strict/ledger.jsonl")
strict_summary = load_json(ROOT / "snapshot/strict/summary.json")
canonical_payload = json.dumps(strict_rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
assert hashlib.sha256(canonical_payload).hexdigest() == strict_summary["ledger_sha256"]
assert sha256(ROOT / "snapshot/strict/ledger.jsonl") == "0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81"

result_path = ROOT / "result.json"
if result_path.exists():
    result = load_json(result_path)
    assert result["status"] == "COMPLETE"
    assert result["output_dir"] == str(ROOT)
    assert result["counts"]["ledger_records"] == len(ledger)
    assert result["counts"]["canonical_source_components"] == len(canonical)
    assert result["counts"]["snapshot_files"] == 57
    assert result["counts"]["strict_document_rows"] == 125
    assert result["counts"]["broad_released_source_max"] == 172
    assert result["counts"]["widest_source_max"] == 184
    assert result["counts"]["integration_ready"] is False
    assert result["blockers"] == summary["blockers"]
    assert result["claim_boundary"] == summary["claim_boundary"]
    assert set(result["artifact_map"]) == {"ledger", "summary", "verifier", "builder", "report", "result"}
    assert result["validation"]["status"] == "PASS"
    for artifact in result["artifact_map"].values():
        assert (ROOT / artifact["path"]).is_file()
        if artifact.get("sha256"):
            assert sha256(ROOT / artifact["path"]) == artifact["sha256"]

print("PASS: 57 snapshots, 213 records, maxima 125/172/184, integration_ready=false")
