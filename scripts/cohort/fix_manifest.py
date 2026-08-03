"""Strict fix-only manifest contract for claim-grade candidate generation.

The candidate-generation process may learn where to start its backwards walk,
but it must never load golden origins, landed commits, or expected relations.
This deliberately small schema makes that boundary mechanically checkable.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence

from cohort.relations import canonical_repository_identity


ARTIFACT_KIND = "sealed_fix_manifest"
_TOP_LEVEL_KEYS = frozenset(
    {"schema_version", "artifact_kind", "split_id", "frozen_at", "fixes"}
)
_FIX_KEYS = frozenset({"advisory", "repository_identity", "fix_sha"})


class FixManifestContractError(ValueError):
    """A fix-only manifest contains malformed or evaluation-only data."""


def _full_sha(value: object) -> str:
    sha = str(value or "").strip().lower()
    if len(sha) != 40 or any(character not in "0123456789abcdef" for character in sha):
        raise FixManifestContractError("fix_sha must be a full 40-hex SHA")
    return sha


def normalize_fix_manifest(
    payload: Mapping[str, object],
    aliases: Mapping[str, str],
) -> dict[str, object]:
    """Validate the complete payload and reject every non-fix field."""

    if not isinstance(payload, Mapping):
        raise FixManifestContractError("fix manifest must be an object")
    keys = frozenset(str(key) for key in payload)
    if keys != _TOP_LEVEL_KEYS:
        unexpected = sorted(keys - _TOP_LEVEL_KEYS)
        missing = sorted(_TOP_LEVEL_KEYS - keys)
        raise FixManifestContractError(
            f"fix manifest keys must be exact; unexpected={unexpected}, missing={missing}"
        )
    if payload.get("schema_version") != 1:
        raise FixManifestContractError("fix manifest must use schema_version 1")
    if payload.get("artifact_kind") != ARTIFACT_KIND:
        raise FixManifestContractError(f"artifact_kind must be {ARTIFACT_KIND}")
    split_id = str(payload.get("split_id") or "").strip()
    frozen_at = str(payload.get("frozen_at") or "").strip()
    if not split_id or not frozen_at:
        raise FixManifestContractError("fix manifest requires split_id and frozen_at")

    raw_fixes = payload.get("fixes")
    if not isinstance(raw_fixes, Sequence) or isinstance(raw_fixes, (str, bytes)):
        raise FixManifestContractError("fixes must be a list of objects")
    fixes: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for raw in raw_fixes:
        if not isinstance(raw, Mapping):
            raise FixManifestContractError("fix row must be an object")
        row_keys = frozenset(str(key) for key in raw)
        if row_keys != _FIX_KEYS:
            unexpected = sorted(row_keys - _FIX_KEYS)
            missing = sorted(_FIX_KEYS - row_keys)
            raise FixManifestContractError(
                f"fix row keys must be exact; unexpected={unexpected}, missing={missing}"
            )
        advisory = str(raw.get("advisory") or "").strip()
        if not advisory:
            raise FixManifestContractError("fix row requires advisory")
        try:
            identity = canonical_repository_identity(
                str(raw.get("repository_identity") or ""), aliases
            )
        except ValueError as exc:
            raise FixManifestContractError("fix row has invalid repository_identity") from exc
        if not identity or "/" not in identity:
            raise FixManifestContractError("fix row has invalid repository_identity")
        fix_sha = _full_sha(raw.get("fix_sha"))
        key = (advisory, identity, fix_sha)
        if key in seen:
            raise FixManifestContractError("fix manifest contains a duplicate fix row")
        seen.add(key)
        fixes.append(
            {
                "advisory": advisory,
                "repository_identity": identity,
                "fix_sha": fix_sha,
            }
        )
    if not fixes:
        raise FixManifestContractError("fix manifest must contain at least one fix")
    fixes.sort(
        key=lambda row: (
            row["repository_identity"],
            row["advisory"],
            row["fix_sha"],
        )
    )
    return {
        "schema_version": 1,
        "artifact_kind": ARTIFACT_KIND,
        "split_id": split_id,
        "frozen_at": frozen_at,
        "fixes": fixes,
    }


def generation_fix_overlay(
    manifest: Mapping[str, object],
) -> dict[str, list[dict[str, str]]]:
    """Convert an already-normalized manifest to generator fix roots."""

    split_id = str(manifest["split_id"])
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    fixes = manifest["fixes"]
    assert isinstance(fixes, list)
    for row in fixes:
        assert isinstance(row, Mapping)
        identity = str(row["repository_identity"])
        grouped[identity].append(
            {
                "advisory": str(row["advisory"]),
                "fix_sha": str(row["fix_sha"]),
                "published": "",
                "source": f"sealed_fix_manifest:{split_id}",
            }
        )
    return dict(sorted(grouped.items()))
