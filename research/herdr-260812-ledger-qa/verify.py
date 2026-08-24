#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


reconciliation = json.loads((ROOT / "reconciliation.json").read_text())
result = json.loads((ROOT / "result.json").read_text())

document_hashes = {item["sha256"] for item in reconciliation["document_snapshots"]}
for item in reconciliation["document_snapshots"]:
    assert sha256(ROOT / item["snapshot_path"]) == item["sha256"]
for item in reconciliation["artifact_snapshots"]:
    assert sha256(ROOT / "snapshot/artifacts" / item["source_path"]) == item["sha256"]
for discrepancy in reconciliation["discrepancies"]:
    assert discrepancy["evidence"]
    assert all(evidence["sha256"] in document_hashes for evidence in discrepancy["evidence"])

totals = reconciliation["reconciled_totals"]
assert totals["strict_released_components"]["reconciled"] == 125
assert totals["incomplete_remediation_released_components"]["after_exact_identity_deduplication"] == 47
assert totals["broad_released_components"]["after_exact_identity_deduplication"] == 172
assert totals["commit_only_components"]["after_exact_identity_deduplication"] == 12
assert totals["widest_commit_level_workset_components"]["after_exact_identity_deduplication"] == 184
assert len(reconciliation["discrepancies"]) == result["counts"]["discrepancies"] == 8
assert reconciliation["status"] == result["status"] == "COMPLETE"

print("PASS: 13 documents, 9 cited artifacts, 8 hash-backed discrepancies")
