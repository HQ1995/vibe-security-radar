#!/usr/bin/env python3
"""Validate a strict supplement and merge it with the frozen base ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from cohort.root_adjudication import canonical_sha256
from cohort_atomic_mechanism_review import _atomic_json, _atomic_jsonl, _jsonl


PUBLIC_ID = re.compile(
    r"^(?:CVE-\d{4}-\d{4,}|GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4})$"
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
AI_MARKER = re.compile(
    r"(?:co[- ]?authored|generated with|claude|copilot|cursor|jules|rovo|codex|gemini|chatgpt|\[ai\])",
    re.IGNORECASE,
)
ORIGIN_KINDS = {"direct_commit", "squash_member"}
CONTRIBUTION_KINDS = {
    "direct_origin",
    "dangerous_revert",
    "guard_weakening",
    "new_surface_contributor",
}
ALIAS_RELATIONSHIPS = {
    "first_party_cve_alias",
    "first_party_same_mechanism_advisory",
}


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--supplement", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _validate_edge(repo: Path, component_id: str, edge: object) -> dict[str, str]:
    if not isinstance(edge, dict):
        raise SystemExit(f"malformed edge: {component_id}")
    candidate = str(edge.get("candidate_sha", "")).lower()
    fix = str(edge.get("fix_sha", "")).lower()
    carrier = str(edge.get("carrier_sha", "")).lower()
    origin_kind = str(edge.get("origin_kind", ""))
    ai_signal = str(edge.get("ai_signal", "")).strip()
    if (
        not SHA40.fullmatch(candidate)
        or not SHA40.fullmatch(fix)
        or candidate == fix
        or origin_kind not in ORIGIN_KINDS
        or not AI_MARKER.search(ai_signal)
        or (carrier and not SHA40.fullmatch(carrier))
        or carrier in {candidate, fix}
        or (origin_kind == "squash_member") != bool(carrier)
    ):
        raise SystemExit(f"malformed edge: {component_id}")
    for sha in [candidate, fix, *([carrier] if carrier else [])]:
        if _git(repo, "cat-file", "-t", sha).strip() != "commit":
            raise SystemExit(f"edge object is not a commit: {component_id} {sha}")
    commit_text = _git(repo, "show", "-s", "--format=%an <%ae>%n%B", candidate)
    if not AI_MARKER.search(commit_text):
        raise SystemExit(f"candidate lacks an explicit AI marker: {component_id}")
    ancestor = carrier if carrier else candidate
    subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", ancestor, fix],
        check=True,
        capture_output=True,
    )
    return {
        "candidate_sha": candidate,
        "fix_sha": fix,
        "origin_kind": origin_kind,
        "ai_signal": ai_signal,
        **({"carrier_sha": carrier} if carrier else {}),
    }


def _apply_alias_amendments(
    ledger: list[dict[str, object]], amendments: object
) -> int:
    if not isinstance(amendments, list):
        raise SystemExit("alias amendments must be a list")
    by_component = {str(row["component_id"]): row for row in ledger}
    public_ids = {value for row in ledger for value in row["public_ids"]}
    for raw in amendments:
        if not isinstance(raw, dict):
            raise SystemExit("malformed alias amendment")
        component_id = str(raw.get("component_id", ""))
        public_id = str(raw.get("public_id", "")).upper()
        relationship = str(raw.get("relationship", ""))
        evidence = str(raw.get("evidence", "")).strip()
        source = str(raw.get("source", "")).strip()
        excluded = [
            str(value).upper() for value in raw.get("excluded_public_ids", [])
        ]
        if (
            component_id not in by_component
            or not PUBLIC_ID.fullmatch(public_id)
            or public_id in public_ids
            or relationship not in ALIAS_RELATIONSHIPS
            or not evidence
            or not source.startswith("https://github.com/")
            or any(not PUBLIC_ID.fullmatch(value) for value in excluded)
            or public_id in excluded
        ):
            raise SystemExit(f"malformed or duplicate alias amendment: {public_id}")
        row = by_component[component_id]
        row["public_ids"] = sorted(
            [*row["public_ids"], public_id],
            key=lambda value: (not value.startswith("CVE-"), value),
        )
        row["evidence"] = [
            *row["evidence"],
            {
                "kind": "public_id_alias_amendment",
                "public_id": public_id,
                "relationship": relationship,
                "evidence": evidence,
                "source": source,
                "excluded_public_ids": excluded,
            },
        ]
        public_ids.add(public_id)
    return len(amendments)


def main() -> int:
    args = _args()
    payload = json.loads(args.supplement.read_text(encoding="utf-8"))
    if (
        payload.get("schema_version") != 1
        or payload.get("artifact_kind") != "strict_atomic_ai_causal_supplement"
    ):
        raise SystemExit("invalid supplement header")
    base = payload.get("base_ledger")
    rows = payload.get("adjudications")
    if not isinstance(base, dict) or not isinstance(rows, list) or not rows:
        raise SystemExit("supplement lacks base ledger or adjudications")
    base_path = Path(str(base.get("path", "")))
    base_rows = _jsonl(base_path)
    if (
        _sha256(base_path) != base.get("sha256")
        or len(base_rows) != base.get("semantic_component_count")
        or sum(len(row["public_ids"]) for row in base_rows)
        != base.get("public_id_count")
    ):
        raise SystemExit("frozen base ledger does not match supplement")

    base_ledger = [
        {**row, "component_id": row.get("class_id", row["component_id"])}
        for row in base_rows
    ]
    alias_amendment_count = _apply_alias_amendments(
        base_ledger, payload.get("alias_amendments", [])
    )
    component_ids = {str(row["component_id"]) for row in base_ledger}
    public_ids = {value for row in base_ledger for value in row["public_ids"]}
    source_class_ids: set[str] = set()
    supplemental_ledger: list[dict[str, object]] = []
    for raw in rows:
        if not isinstance(raw, dict):
            raise SystemExit("malformed supplemental adjudication")
        component_id = str(raw.get("component_id", ""))
        primary_id = str(raw.get("primary_id", "")).upper()
        row_public_ids = [str(value).upper() for value in raw.get("public_ids", [])]
        row_class_ids = [str(value) for value in raw.get("source_class_ids", [])]
        contribution_kind = str(raw.get("contribution_kind", ""))
        mechanism = str(raw.get("mechanism", "")).strip()
        repo = Path(str(raw.get("repository_path", "")))
        if (
            not component_id
            or component_id in component_ids
            or not row_public_ids
            or primary_id not in row_public_ids
            or len(row_public_ids) != len(set(row_public_ids))
            or any(not PUBLIC_ID.fullmatch(value) for value in row_public_ids)
            or public_ids.intersection(row_public_ids)
            or not row_class_ids
            or source_class_ids.intersection(row_class_ids)
            or contribution_kind not in CONTRIBUTION_KINDS
            or not mechanism
            or not (repo / ".git").exists()
        ):
            raise SystemExit(f"malformed or duplicate supplemental row: {component_id}")
        edges = [
            _validate_edge(repo, component_id, edge)
            for edge in raw.get("accepted_edges", [])
        ]
        if not edges:
            raise SystemExit(f"supplemental row lacks accepted edges: {component_id}")
        component_ids.add(component_id)
        public_ids.update(row_public_ids)
        source_class_ids.update(row_class_ids)
        supplemental_ledger.append(
            {
                "component_id": component_id,
                "source_class_ids": row_class_ids,
                "primary_id": primary_id,
                "public_ids": row_public_ids,
                "evidence": [
                    {
                        "kind": "strict_supplemental_adjudication",
                        "repository_identity": raw["repository_identity"],
                        "repository_path": str(repo),
                        "contribution_kind": contribution_kind,
                        "mechanism": mechanism,
                        "accepted_edges": edges,
                        "advisory_sources": raw.get("advisory_sources", []),
                        "evidence_sources": raw.get("evidence_sources", []),
                    }
                ],
            }
        )

    ledger = base_ledger + supplemental_ledger
    minimum_public_id_count = int(payload.get("minimum_public_id_count", 150))
    if minimum_public_id_count < 1:
        raise SystemExit("minimum public ID count must be positive")
    summary = {
        "schema_version": 1,
        "artifact_kind": "strict_atomic_ai_causal_vulnerability_ledger_union",
        "claim_boundary": payload["claim_boundary"],
        "semantic_component_count": len(ledger),
        "public_id_count": sum(len(row["public_ids"]) for row in ledger),
        "cve_count": sum(
            value.startswith("CVE-") for row in ledger for value in row["public_ids"]
        ),
        "ghsa_count": sum(
            value.startswith("GHSA-") for row in ledger for value in row["public_ids"]
        ),
        "base_semantic_component_count": len(base_rows),
        "supplemental_semantic_component_count": len(supplemental_ledger),
        "alias_amendment_count": alias_amendment_count,
        "minimum_public_id_count": minimum_public_id_count,
        "minimum_met": (
            sum(len(row["public_ids"]) for row in ledger)
            >= minimum_public_id_count
        ),
        "inputs": {
            "base_ledger": {"path": str(base_path), "sha256": _sha256(base_path)},
            "supplement": {
                "path": str(args.supplement),
                "sha256": _sha256(args.supplement),
            },
        },
        "ledger_sha256": canonical_sha256(ledger),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    _atomic_jsonl(args.output_dir / "ledger.jsonl", ledger)
    _atomic_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
