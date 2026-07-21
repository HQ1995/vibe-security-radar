#!/usr/bin/env python3
"""Validate a committed Website publication, receipt, and optional activation."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from pathlib import Path

# Keep a clean trusted checkout free of ignored bytecode before replaying the
# verifier contract. Existing bytecode remains a fail-closed shadow.
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from web_data.release_evidence import (  # noqa: E402
    ReleaseEvidenceError,
    validate_active_release,
    validate_archived_artifact_order,
    validate_release_evidence,
)
from web_data.writer import (  # noqa: E402
    PublishedDataError,
    _MAX_PUBLISHED_RECEIPT_BYTES,
    _stable_regular_bytes,
    publication_bundle_sha256,
    validate_published_release,
)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verify_formal_release(
    *,
    data_dir: Path,
    evidence_root: Path | None = None,
    require_active: bool = False,
    verify_artifact_order: bool = True,
    trusted_repo_root: Path | None = None,
    require_inventory: bool = True,
) -> dict[str, object]:
    """Return exact publication proof hashes or fail closed."""

    if require_active and evidence_root is None:
        raise ValueError("--require-active requires --evidence-root")
    publication, receipt, raw_manifest = validate_published_release(data_dir)
    inventory = publication.inventory
    recall_point = receipt.get("recall_point_estimate")
    recall_interval = receipt.get("recall_interval")
    targets = receipt.get("targets")
    recall_target = targets.get("recall") if isinstance(targets, dict) else None
    if inventory is None:
        raise PublishedDataError("formal release detector inventory is missing")
    if (
        receipt.get("schema_version") != 4
        or inventory.get("campaign_mode") != "formal"
        or inventory.get("complete") is not True
        or receipt.get("detector_inventory_id") != inventory.get("inventory_id")
        or receipt.get("detector_inventory_sha256") != _canonical_sha256(inventory)
        or receipt.get("detector_inventory_source_snapshot_sha256")
        != inventory.get("source_snapshot_sha256")
        or receipt.get("detector_inventory_alias_class_manifest_sha256")
        != inventory.get("source_alias_class_manifest_sha256")
        or receipt.get("detector_inventory_alias_class_count")
        != inventory.get("alias_class_count")
        or receipt.get("campaign_id") != inventory.get("campaign_id")
        or receipt.get("contract_sha256") != inventory.get("contract_sha256")
        or receipt.get("recall_inventory_id") != inventory.get("inventory_id")
        or receipt.get("recall_evaluation_status") != "complete_end_to_end"
        or receipt.get("recall_evaluation_complete") is not True
        or receipt.get("protected_census_complete") is not True
        or not isinstance(receipt.get("protected_census_manifest_sha256"), str)
        or len(receipt["protected_census_manifest_sha256"]) != 64
        or isinstance(receipt.get("protected_overlap_class_count"), bool)
        or not isinstance(receipt.get("protected_overlap_class_count"), int)
        or receipt["protected_overlap_class_count"] < 0
        or not isinstance(receipt.get("verifier_contract_sha256"), str)
        or len(receipt["verifier_contract_sha256"]) != 64
        or not isinstance(receipt.get("verifier_git_commit"), str)
        or len(receipt["verifier_git_commit"]) not in {40, 64}
        or not isinstance(receipt.get("verifier_git_tree"), str)
        or len(receipt["verifier_git_tree"]) not in {40, 64}
        or isinstance(recall_point, bool)
        or not isinstance(recall_point, (int, float))
        or not math.isfinite(float(recall_point))
        or not isinstance(recall_interval, list)
        or len(recall_interval) != 2
        or any(
            isinstance(bound, bool)
            or not isinstance(bound, (int, float))
            or not math.isfinite(float(bound))
            for bound in recall_interval
        )
        or isinstance(recall_target, bool)
        or not isinstance(recall_target, (int, float))
        or not math.isfinite(float(recall_target))
        or float(recall_point) < float(recall_target)
        or float(recall_interval[0]) < float(recall_target)
    ):
        raise PublishedDataError(
            "formal release detector inventory is incomplete or unbound"
        )
    receipt_bytes = _stable_regular_bytes(
        Path(data_dir) / "release-receipt.json",
        "release receipt",
        max_bytes=_MAX_PUBLISHED_RECEIPT_BYTES,
    )
    try:
        reread_receipt = json.loads(receipt_bytes)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PublishedDataError(
            f"release receipt changed after validation: {exc}"
        ) from exc
    if reread_receipt != receipt:
        raise PublishedDataError("release receipt changed after validation")
    generation_id = publication.index["generation_id"]
    manifest_sha256 = _canonical_sha256(raw_manifest)
    if receipt.get("publication_manifest_sha256") != manifest_sha256:
        raise PublishedDataError(
            "release receipt publication_manifest_sha256 does not match raw files"
        )
    summary: dict[str, object] = {
        "schema_version": 1,
        "generation_id": generation_id,
        "generated_at": publication.index["generated_at"],
        "publication_bundle_sha256": publication_bundle_sha256(publication),
        "publication_manifest_sha256": manifest_sha256,
        "release_receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "raw_file_count": len(raw_manifest),
        "active_release_verified": False,
        "detector_inventory_verified": inventory is not None,
        "recall_evidence_bound": True,
        "verifier_contract_bound": True,
        "verifier_contract_replayed": evidence_root is not None,
    }
    if evidence_root is not None:
        bundle = validate_release_evidence(
            evidence_root / generation_id,
            expected_generation_id=generation_id,
            trusted_repo_root=trusted_repo_root,
        )
        archived_receipt_bytes = _stable_regular_bytes(
            bundle.path / "release-receipt.json",
            "archived release receipt",
            max_bytes=_MAX_PUBLISHED_RECEIPT_BYTES,
        )
        archived_receipt = json.loads(archived_receipt_bytes)
        if archived_receipt != receipt:
            raise PublishedDataError(
                "archived release receipt does not match the publication"
            )
        summary["evidence_bundle_sha256"] = bundle.bundle_sha256
        summary["recall_evidence_replayed"] = True
        if verify_artifact_order:
            validate_archived_artifact_order(
                bundle.path,
                trusted_repo_root=trusted_repo_root,
            )
            summary["artifact_order_verified"] = True
    if require_active:
        assert evidence_root is not None
        active = validate_active_release(
            root=evidence_root,
            generation_id=generation_id,
            trusted_repo_root=trusted_repo_root,
        )
        summary["evidence_bundle_sha256"] = active["evidence_bundle_sha256"]
        summary["active_release_verified"] = True
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--require-active", action="store_true")
    parser.add_argument(
        "--require-inventory",
        action="store_true",
        help="require a complete formal detector inventory bound into the receipt",
    )
    parser.add_argument(
        "--trusted-repo-root",
        type=Path,
        help=(
            "Explicit Git trust anchor for isolated verification; production "
            "defaults to this verifier's repository."
        ),
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = verify_formal_release(
            data_dir=args.data_dir,
            evidence_root=args.evidence_root,
            require_active=args.require_active,
            trusted_repo_root=args.trusted_repo_root,
            require_inventory=args.require_inventory,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        PublishedDataError,
        ReleaseEvidenceError,
    ) as exc:
        error = {"ok": False, "error": str(exc)}
        print(json.dumps(error, sort_keys=True), file=sys.stderr)
        return 2
    if args.as_json:
        print(json.dumps({"ok": True, **result}, sort_keys=True))
    else:
        print(
            f"verified generation {result['generation_id']} "
            f"({result['raw_file_count']} raw files)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
