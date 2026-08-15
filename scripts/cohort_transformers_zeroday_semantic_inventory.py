#!/usr/bin/env python3
"""Freeze a recall-first semantic inventory for the Transformers 0-day family.

This stage ranks every commit reachable from every local ref.  Path and semantic
signals only raise priority; neither a missing signal nor a model judgment can
remove a commit from the retained inventory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from cve_analyzer.provenance import scan_repo_ai_commit_index
from cohort_transformers_zeroday_squash_closure import (
    FULL_SHA,
    REPOSITORY_IDENTITY,
    _commit_metadata,
    _git,
    _load_jsonl,
)


EXPECTED_COMMIT_UNIVERSE_COUNT = 37_603
EXPECTED_SOURCE_V3_COUNT = 324
EXPECTED_SQUASH_MEMBER_COUNT = 179

RISK_PATHS: tuple[str, ...] = (
    "src/transformers/models/perceiver/",
    "src/transformers/models/deprecated/transfo_xl/",
    "src/transformers/models/transfo_xl/",
    "src/transformers/models/megatron_gpt2/",
    "src/transformers/models/sew/",
    "src/transformers/models/sew_d/",
    "src/transformers/models/hubert/",
    "src/transformers/models/x_clip/",
    "src/transformers/models/glm4/",
    "src/transformers/models/glm4_moe/",
    "src/transformers/models/glm4v/",
    "src/transformers/models/glm4v_moe/",
    "src/transformers/modeling_utils.py",
    "src/transformers/dynamic_module_utils.py",
    "src/transformers/utils/hub.py",
)

# POSIX ERE consumed by Git.  It deliberately includes broader loader and safe
# serialization signals: these are ranking signals, never exclusion predicates.
GIT_SEMANTIC_ERE = (
    r"pickle\.loads?\(|torch\.load\(|eval\(|weights_only|TRUST_REMOTE_CODE|"
    r"safetensors|from_pretrained|load_state_dict"
)

SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pickle_deserialization", re.compile(r"pickle\.loads?\(")),
    ("torch_deserialization", re.compile(r"torch\.load\(")),
    ("unsafe_weights_only", re.compile(r"weights_only\s*=\s*False")),
    ("safe_weights_only", re.compile(r"weights_only\s*=\s*True")),
    ("code_execution_eval", re.compile(r"\beval\(")),
    ("explicit_trust_guard", re.compile(r"TRUST_REMOTE_CODE")),
    ("safe_serialization", re.compile(r"safetensors", re.IGNORECASE)),
    ("loader_api", re.compile(r"from_pretrained|load_state_dict")),
)

EXACT_TRANSITIONS: tuple[dict[str, object], ...] = (
    {
        "sha": "2c58705dc23ce869e82b1a6ca225ad718916e8d5",
        "kind": "SAFE_TO_UNSAFE_REGRESSION",
        "cves": ["CVE-2025-14924"],
        "paths": [
            "src/transformers/models/megatron_gpt2/convert_megatron_gpt2_checkpoint.py"
        ],
        "before_required": ["weights_only=True"],
        "after_required": ["weights_only=False"],
        "claim": (
            "The commit changes the direct non-zip checkpoint load from "
            "weights_only=True to weights_only=False."
        ),
    },
    {
        "sha": "28eae8b4bdc66c0e841ce817f7faab5ef203ea68",
        "kind": "SAFE_OPTION_HARDENING",
        "cves": ["CVE-2025-14924", "CVE-2025-14929"],
        "paths": [
            "src/transformers/models/megatron_gpt2/convert_megatron_gpt2_checkpoint.py",
            "src/transformers/models/x_clip/convert_x_clip_original_pytorch_to_hf.py",
        ],
        "before_required": ["torch.load("],
        "after_required": ["weights_only=True"],
        "claim": (
            "The commit adds weights_only=True to the Megatron and X-CLIP "
            "checkpoint loads."
        ),
    },
    {
        "sha": "9ef804472b25c4f69c1eb213dea6f791615538a0",
        "kind": "EXPLICIT_OPT_IN_GUARD",
        "cves": ["CVE-2025-14920", "CVE-2025-14930"],
        "paths": [
            "src/transformers/models/perceiver/convert_perceiver_haiku_to_pytorch.py",
            "src/transformers/models/glm4v/convert_glm4v_mgt_weights_to_hf.py",
        ],
        "before_forbidden": ["TRUST_REMOTE_CODE"],
        "after_required": ["TRUST_REMOTE_CODE", "insecure"],
        "claim": (
            "The commit adds an explicit TRUST_REMOTE_CODE opt-in before "
            "unsafe Perceiver and GLM4V conversion loads."
        ),
    },
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--closure", type=Path, required=True)
    parser.add_argument("--commit-universe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain one JSON object")
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_inventory_digest(shas: set[str]) -> str:
    return _sha256_bytes("".join(f"{sha}\n" for sha in sorted(shas)).encode())


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise SystemExit(f"output already exists: {path}")
    encoded = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        handle.write(encoded)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def _git_sha_set(repository: Path, arguments: list[str]) -> set[str]:
    values = {line for line in _git(repository, arguments).splitlines() if line}
    if not all(FULL_SHA.fullmatch(value) for value in values):
        raise ValueError(f"Git returned malformed commit identities for {arguments[0]}")
    return values


def _all_reachable_commits(repository: Path) -> set[str]:
    return _git_sha_set(repository, ["rev-list", "--all"])


def _path_history(repository: Path) -> set[str]:
    return _git_sha_set(repository, ["log", "--all", "--format=%H", "--", *RISK_PATHS])


def _semantic_history(repository: Path) -> set[str]:
    return _git_sha_set(
        repository,
        [
            "log",
            "--all",
            "--format=%H",
            "-G",
            GIT_SEMANTIC_ERE,
            "--",
            *RISK_PATHS,
        ],
    )


def _risk_path_hits(changed_files: list[str]) -> list[str]:
    return [
        target
        for target in RISK_PATHS
        if any(path == target or path.startswith(target) for path in changed_files)
    ]


def _signal_changes(repository: Path, sha: str) -> list[dict[str, str]]:
    diff = _git(
        repository,
        [
            "show",
            "--format=",
            "--no-ext-diff",
            "--no-renames",
            "--unified=0",
            sha,
            "--",
            *RISK_PATHS,
        ],
    )
    changes: list[dict[str, str]] = []
    current_path = ""
    for line in diff.splitlines():
        if line.startswith("diff --git a/"):
            fields = line.split(" ", 3)
            if len(fields) >= 4 and fields[3].startswith("b/"):
                current_path = fields[3][2:]
            continue
        if line.startswith("+++ b/"):
            current_path = line[6:]
            continue
        if line.startswith("--- a/"):
            current_path = line[6:]
            continue
        if not line.startswith(("+", "-")) or line.startswith(("+++", "---")):
            continue
        categories = [name for name, pattern in SIGNAL_PATTERNS if pattern.search(line[1:])]
        if categories:
            changes.append(
                {
                    "sign": "added" if line.startswith("+") else "removed",
                    "path": current_path,
                    "categories": ",".join(categories),
                    "line": line[1:500],
                }
            )
    return changes


def _is_ancestor(repository: Path, ancestor: str, descendant: str) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(repository), "merge-base", "--is-ancestor", ancestor, descendant],
        capture_output=True,
        check=False,
        env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
        timeout=60,
    )
    if completed.returncode not in {0, 1}:
        raise ValueError(f"cannot test ancestry {ancestor} -> {descendant}")
    return completed.returncode == 0


def _source_candidate(
    repository: Path,
    row: Mapping[str, object],
    *,
    semantic_shas: set[str],
    affected_by_cve: Mapping[str, str],
    carrier_by_sha: Mapping[str, Mapping[str, object]],
    member_semantic_shas: set[str],
) -> dict[str, object]:
    sha = str(row["sha"])
    changed_files = [str(path) for path in row.get("changed_files", [])]
    carrier = carrier_by_sha.get(sha)
    source_members = (
        [str(value) for value in carrier.get("source_v3_ai_member_shas", [])]
        if carrier
        else []
    )
    return {
        **_commit_metadata(repository, sha),
        "source_matches": row.get("source_matches", []),
        "ai_evidence_contracts": row.get("ai_evidence_contracts", []),
        "frozen_observed_ai_routes": row.get("frozen_observed_ai_routes", []),
        "frozen_observed_ai_tools": row.get("frozen_observed_ai_tools", []),
        "risk_path_hits": _risk_path_hits(changed_files),
        "semantic_signal_hit": sha in semantic_shas,
        "ancestor_of_affected_cves": sorted(
            cve
            for cve, affected in affected_by_cve.items()
            if _is_ancestor(repository, sha, affected)
        ),
        "attribution_scope": (
            "SQUASH_CARRIER_REQUIRES_MEMBER_DECOMPOSITION"
            if carrier
            else "DIRECT_COMMIT_SOURCE_EVIDENCE"
        ),
        "carrier_source_member_shas": source_members,
        "carrier_source_members_with_semantic_signals": sorted(
            set(source_members) & member_semantic_shas
        ),
    }


def _file_at(repository: Path, revision: str, path: str) -> str:
    return _git(repository, ["show", f"{revision}:{path}"])


def _exact_transition(
    repository: Path,
    spec: Mapping[str, object],
    attribution_by_sha: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    sha = str(spec["sha"])
    parents = _git(repository, ["show", "-s", "--format=%P", sha]).split()
    if len(parents) != 1:
        raise ValueError(f"exact transition must have one parent: {sha}")
    before = "\n".join(
        _file_at(repository, parents[0], str(path)) for path in spec["paths"]
    )
    after = "\n".join(_file_at(repository, sha, str(path)) for path in spec["paths"])
    before_required = [str(value) for value in spec.get("before_required", [])]
    before_forbidden = [str(value) for value in spec.get("before_forbidden", [])]
    after_required = [str(value) for value in spec.get("after_required", [])]
    checks = {
        "before_required_present": all(value in before for value in before_required),
        "before_forbidden_absent": all(value not in before for value in before_forbidden),
        "after_required_present": all(value in after for value in after_required),
    }
    if not all(checks.values()):
        raise ValueError(f"exact transition contract failed for {sha}: {checks}")
    source = attribution_by_sha.get(sha)
    return {
        **_commit_metadata(repository, sha),
        "kind": spec["kind"],
        "cves": spec["cves"],
        "paths": spec["paths"],
        "claim": spec["claim"],
        "parent": parents[0],
        "checks": checks,
        "ai_evidence_observed": source is not None,
        "source_v3_ai_evidence": bool(
            source
            and "SOURCE_V3_EXPLICIT_ATTRIBUTION"
            in source.get("ai_evidence_contracts", [])
        ),
        "frozen_observed_ai_evidence": bool(
            source
            and "FROZEN_OBSERVED_AI_UNIT" in source.get("ai_evidence_contracts", [])
        ),
        "source_matches": source.get("source_matches", []) if source else [],
        "ai_evidence_contracts": source.get("ai_evidence_contracts", []) if source else [],
        "claim_boundary": (
            "This proves the local code transition. Exact CVE identity still "
            "depends on the public mechanism description and affected snapshot."
        ),
    }


def _build_inventory(
    repository: Path,
    closure: Mapping[str, object],
    universe_rows: list[dict[str, object]],
    *,
    closure_sha256: str,
    commit_universe_sha256: str,
) -> dict[str, object]:
    if closure.get("artifact_kind") != "transformers_zeroday_squash_member_closure":
        raise ValueError("unexpected closure artifact")
    repository_rows = [
        row for row in universe_rows if row.get("repository_identity") == REPOSITORY_IDENTITY
    ]
    universe_shas = {str(row["sha"]) for row in repository_rows}
    if len(universe_shas) != EXPECTED_COMMIT_UNIVERSE_COUNT:
        raise ValueError("frozen commit-universe count changed")

    all_ref_shas = _all_reachable_commits(repository)
    path_shas = _path_history(repository)
    semantic_shas = _semantic_history(repository)
    if not semantic_shas <= path_shas <= all_ref_shas:
        raise ValueError("semantic/path inventory escaped the all-ref commit closure")

    scan = scan_repo_ai_commit_index(repository, REPOSITORY_IDENTITY)
    if scan.get("complete") is not True:
        raise ValueError(f"Source-v3 scan is incomplete: {scan.get('error')}")
    scan_rows = scan.get("commits")
    if not isinstance(scan_rows, list) or len(scan_rows) != EXPECTED_SOURCE_V3_COUNT:
        raise ValueError("Source-v3 inventory count changed")
    source_by_sha = {}
    for row in scan_rows:
        if not isinstance(row, Mapping):
            continue
        source_by_sha[str(row["sha"])] = {
            **row,
            "ai_evidence_contracts": ["SOURCE_V3_EXPLICIT_ATTRIBUTION"],
        }
    source_shas = set(source_by_sha)
    if len(source_shas) != EXPECTED_SOURCE_V3_COUNT or not source_shas <= all_ref_shas:
        raise ValueError("Source-v3 candidates escaped the all-ref commit closure")
    closure_inputs = closure.get("inputs")
    if not isinstance(closure_inputs, Mapping):
        raise ValueError("closure inputs are malformed")
    if scan.get("refs_digest") != closure_inputs.get("source_v3_refs_digest"):
        raise ValueError("repository refs changed since the squash closure was frozen")

    member_rows = closure.get("member_candidates")
    pull_requests = closure.get("pull_requests")
    advisories = closure.get("advisories")
    if not all(isinstance(value, list) for value in (member_rows, pull_requests, advisories)):
        raise ValueError("closure member, PR, or advisory rows are malformed")
    member_shas = {
        str(row["sha"]) for row in member_rows if isinstance(row, Mapping)
    }
    if len(member_shas) != EXPECTED_SQUASH_MEMBER_COUNT:
        raise ValueError("squash-member inventory is not conserved")

    # A frozen inventory and a live all-ref walk are complementary.  Force every
    # identity from either side (plus recovered squash members) into the retained
    # union.  This preserves commits from deleted refs as well as newly fetched
    # refs.  Objects must still exist locally so later adjudication remains finite.
    retained_shas = universe_shas | all_ref_shas | member_shas | source_shas
    for sha in sorted(retained_shas - all_ref_shas):
        completed = subprocess.run(
            ["git", "-C", str(repository), "cat-file", "-e", f"{sha}^{{commit}}"],
            capture_output=True,
            check=False,
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
            timeout=60,
        )
        if completed.returncode != 0:
            raise ValueError(f"retained commit object is unavailable: {sha}")

    # Current `git log --all` cannot see commits whose refs disappeared.  Scan
    # those finite identities directly so ref churn cannot hide a semantic hit.
    direct_scan_shas = retained_shas - all_ref_shas
    for sha in sorted(direct_scan_shas):
        metadata = _commit_metadata(repository, sha)
        changed_files = [str(path) for path in metadata["changed_files"]]
        if _risk_path_hits(changed_files):
            path_shas.add(sha)
            if _signal_changes(repository, sha):
                semantic_shas.add(sha)
    carrier_by_sha = {
        str(row["landed"]): row
        for row in pull_requests
        if isinstance(row, Mapping) and row.get("landed")
    }
    affected_by_cve = {
        str(row["cve"]): str(row["resolved_affected_commit"])
        for row in advisories
        if isinstance(row, Mapping)
    }
    member_semantic_shas = member_shas & semantic_shas

    legacy_by_sha: dict[str, Mapping[str, object]] = {}
    for row in repository_rows:
        if row.get("observed_ai_unit") is not True:
            continue
        sha = str(row["sha"])
        metadata = _commit_metadata(repository, sha)
        legacy_by_sha[sha] = {
            "sha": sha,
            "changed_files": metadata["changed_files"],
            "source_matches": [],
            "ai_evidence_contracts": ["FROZEN_OBSERVED_AI_UNIT"],
            "frozen_observed_ai_routes": row.get("ai_routes", []),
            "frozen_observed_ai_tools": row.get("ai_tools", []),
        }
    legacy_shas = set(legacy_by_sha)
    attribution_by_sha: dict[str, Mapping[str, object]] = dict(legacy_by_sha)
    for sha, row in source_by_sha.items():
        if sha in attribution_by_sha:
            legacy = attribution_by_sha[sha]
            attribution_by_sha[sha] = {
                **legacy,
                **row,
                "ai_evidence_contracts": sorted(
                    {
                        *[str(value) for value in legacy.get("ai_evidence_contracts", [])],
                        *[str(value) for value in row.get("ai_evidence_contracts", [])],
                    }
                ),
                "frozen_observed_ai_routes": legacy.get(
                    "frozen_observed_ai_routes", []
                ),
                "frozen_observed_ai_tools": legacy.get("frozen_observed_ai_tools", []),
            }
        else:
            attribution_by_sha[sha] = row
    attribution_shas = set(attribution_by_sha)

    source_path_rows = [
        _source_candidate(
            repository,
            attribution_by_sha[sha],
            semantic_shas=semantic_shas,
            affected_by_cve=affected_by_cve,
            carrier_by_sha=carrier_by_sha,
            member_semantic_shas=member_semantic_shas,
        )
        for sha in sorted(attribution_shas & path_shas)
    ]
    semantic_rows = []
    signal_counts: Counter[str] = Counter()
    for sha in sorted(semantic_shas):
        metadata = _commit_metadata(repository, sha)
        signals = _signal_changes(repository, sha)
        signal_counts.update(
            category
            for signal in signals
            for category in str(signal["categories"]).split(",")
        )
        semantic_rows.append(
            {
                **metadata,
                "risk_path_hits": _risk_path_hits(
                    [str(path) for path in metadata["changed_files"]]
                ),
                "signal_changes": signals,
                "source_v3_ai_evidence": sha in source_by_sha,
                "frozen_observed_ai_evidence": sha in legacy_by_sha,
                "source_matches": source_by_sha.get(sha, {}).get("source_matches", []),
                "squash_member": sha in member_shas,
                "squash_carrier": sha in carrier_by_sha,
            }
        )

    transitions = [
        _exact_transition(repository, spec, attribution_by_sha)
        for spec in EXACT_TRANSITIONS
    ]
    semantic_source_shas = semantic_shas & source_shas
    attributed_semantic_shas = semantic_shas & attribution_shas
    source_path_shas = path_shas & source_shas
    attributed_path_shas = path_shas & attribution_shas
    return {
        "schema_version": 1,
        "artifact_kind": "transformers_zeroday_semantic_recall_inventory",
        "repository_identity": REPOSITORY_IDENTITY,
        "inputs": {
            "closure_sha256": closure_sha256,
            "commit_universe_sha256": commit_universe_sha256,
            "refs_digest": scan.get("refs_digest"),
            "matcher_contract": scan.get("matcher_contract"),
            "scan_predicate": scan.get("scan_predicate"),
            "risk_paths": list(RISK_PATHS),
            "semantic_git_ere": GIT_SEMANTIC_ERE,
        },
        "finite_inventory": {
            "retained_union_commit_count": len(retained_shas),
            "retained_union_commit_sha256": _sha_inventory_digest(retained_shas),
            "retained_union_commit_shas": sorted(retained_shas),
            "current_all_ref_commit_count": len(all_ref_shas),
            "current_all_ref_commit_sha256": _sha_inventory_digest(all_ref_shas),
            "frozen_commit_universe_count": len(universe_shas),
            "current_ref_not_frozen_count": len(all_ref_shas - universe_shas),
            "current_ref_not_frozen_shas": sorted(all_ref_shas - universe_shas),
            "frozen_not_current_ref_count": len(universe_shas - all_ref_shas),
            "frozen_not_current_ref_shas": sorted(universe_shas - all_ref_shas),
            "squash_member_count": len(member_shas),
            "source_v3_count": len(source_shas),
            "frozen_observed_ai_count": len(legacy_shas),
            "attribution_union_count": len(attribution_shas),
            "risk_path_history_count": len(path_shas),
            "semantic_history_count": len(semantic_shas),
        },
        "priority_lanes": {
            "exact_local_transition_count": len(transitions),
            "semantic_and_source_v3_count": len(semantic_source_shas),
            "semantic_and_source_v3_shas": sorted(semantic_source_shas),
            "semantic_and_any_ai_evidence_count": len(attributed_semantic_shas),
            "semantic_and_any_ai_evidence_shas": sorted(attributed_semantic_shas),
            "risk_path_and_source_v3_count": len(source_path_shas),
            "risk_path_and_source_v3_shas": sorted(source_path_shas),
            "risk_path_and_any_ai_evidence_count": len(attributed_path_shas),
            "risk_path_and_any_ai_evidence_shas": sorted(attributed_path_shas),
            "semantic_squash_member_count": len(member_semantic_shas),
            "semantic_squash_member_shas": sorted(member_semantic_shas),
            "semantic_source_squash_member_count": len(
                member_semantic_shas & attribution_shas
            ),
            "semantic_source_squash_member_shas": sorted(
                member_semantic_shas & attribution_shas
            ),
        },
        "source_path_candidates": source_path_rows,
        "semantic_candidates": semantic_rows,
        "semantic_signal_counts": dict(sorted(signal_counts.items())),
        "exact_local_transitions": transitions,
        "conservation": {
            "finite_union_commits_retained": len(retained_shas),
            "frozen_unreachable_commits_directly_scanned": len(direct_scan_shas),
            "path_signal_is_rank_only": True,
            "semantic_signal_is_rank_only": True,
            "missing_source_signal_is_not_human_proof": True,
            "squash_carrier_requires_member_decomposition": True,
            "hard_filter_count": 0,
            "passed": True,
        },
        "claim_boundary": (
            "Recall is exact only conditional on the frozen all-ref Git inventory "
            "and Source-v3's explicit-attribution contract. Semantic signals rank "
            "work; they do not prove a CVE or authorize deletion."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")
    closure_raw = args.closure.read_bytes()
    universe_raw = args.commit_universe.read_bytes()
    closure = _load_json(args.closure)
    universe_rows = _load_jsonl(args.commit_universe)
    try:
        value = _build_inventory(
            repository,
            closure,
            universe_rows,
            closure_sha256=_sha256_bytes(closure_raw),
            commit_universe_sha256=_sha256_bytes(universe_raw),
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    _atomic_json(args.output, value)
    finite = value["finite_inventory"]
    lanes = value["priority_lanes"]
    print("Transformers semantic recall inventory frozen")
    print(f"  retained union      : {finite['retained_union_commit_count']}")
    print(f"  current all-ref     : {finite['current_all_ref_commit_count']}")
    print(f"  semantic candidates: {finite['semantic_history_count']}")
    print(f"  Source-v3 candidates: {finite['source_v3_count']}")
    print(f"  semantic x source  : {lanes['semantic_and_source_v3_count']}")
    print(f"  hard filters       : {value['conservation']['hard_filter_count']}")
    print(f"  output             : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
