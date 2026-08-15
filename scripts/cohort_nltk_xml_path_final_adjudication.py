#!/usr/bin/env python3
"""Close NLTK CVE-2026-33236 without treating model negatives as proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path

from cohort_nltk_xml_path_causal_inventory import (
    AFFECTED_SHA,
    EARLIEST_PIPELINE_SHA,
    FIX_MEMBER_SHA,
    _git,
)


FINAL_VERDICT = (
    "NO_AI_CAUSAL_ROOT_OR_PATH_EXTENSION_RECOVERED_UNDER_FROZEN_"
    "OBSERVABLE_ATTRIBUTION_CONTRACT"
)
CODE_SCOPE_CONTRACTS: dict[str, dict[str, object]] = {
    "1f8eb13f385f0c49a32241d8dedc2c45b2cc22b6": {
        "scope": "md5_hexdigest",
        "required": ("MD-5", "MD5"),
        "reason": "docstring spelling only",
    },
    "3bc1214f7db0bc0d261196fac42c4dca74ce6d63": {
        "scope": "class Downloader",
        "required": ("stacklevel=2",),
        "reason": "warning stacklevel only",
    },
    "5fbbeb47edb1f93c022693765b4db018a514ff84": {
        "scope": "_unzip_iter",
        "required": ("os.makedirs(root, exist_ok=True)",),
        "reason": "ZIP extraction root creation only",
    },
    "cc4bec20672ae0e67d21db47a4bbe8418d239671": {
        "scope": "_unzip_iter",
        "required": ("continue",),
        "reason": "ZIP member error-flow continuation only",
    },
    "394eef88b0d5fd2d8571622f43cf7c3205b59355": {
        "scope": "_unzip_iter",
        "required": ("has_violations", "abs_prefix", "real_prefix"),
        "reason": "ZIP validation reporting refactor only",
    },
    "90712b608d9a8a8711016376223f9ba20bf5634d": {
        "scope": "_unzip_iter",
        "required": ("shutil.rmtree(root_abs)",),
        "reason": "ZIP extraction failure cleanup only",
    },
    "c88d8469d46b8743638dce75d07f67878bada9d1": {
        "scope": "_unzip_iter",
        "required": ("os.path.normcase", "os.path.realpath(os.path.join"),
        "reason": "ZIP containment normalization only",
    },
}
CONTEXT_ONLY_SHAS = frozenset(
    {
        "325b33e2ec4facbe6ada18d6e6d51d79c3bf9238",
        "a2d5d4b85b47bcda20e168cb8f2fb3f69f8112cb",
        "dce07f00f49588d0d3ea925111296afa1b930210",
    }
)
DATA_PATH_FOLLOWUPS = frozenset(
    {
        "5d69314100da999b0c9d73ee9e0088f983f40f49",
        "a051af54d98d016c6c8430fe0af4b8a17232a709",
        "edf8d495baa02e512d5906059d212344fa4728d8",
    }
)
CI_ACTIVATION_SHA = "13d6791c6890045421d7e85a1e092c9fd1c36c1d"
ACTIVATION_PATTERN = re.compile(
    r"nltk\.download|\bDownloader\b|_download_package|download_dir|"
    r"index\.xml|DEFAULT_URL|\bPackage\("
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--deepseek-aggregate", type=Path, required=True)
    parser.add_argument("--grok-aggregate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise ValueError(f"output already exists: {path}")
    encoded = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        handle.write(encoded)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def _changed_lines(diff: str) -> list[str]:
    return [
        line
        for line in diff.splitlines()
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    ]


def _activation_line_changes(diff: str) -> list[str]:
    return [
        line for line in _changed_lines(diff) if ACTIVATION_PATTERN.search(line[1:])
    ]


def _validate_model_aggregate(
    aggregate: Mapping[str, object],
    *,
    inventory_sha256: str,
    expected_shas: set[str],
) -> None:
    if aggregate.get("artifact_kind") != "nltk_xml_path_ai_review":
        raise ValueError("unexpected model-review artifact")
    if aggregate.get("inventory_sha256") != inventory_sha256:
        raise ValueError("model-review inventory digest mismatch")
    if aggregate.get("result_status") != "completed":
        raise ValueError("model review did not complete")
    if (
        set(str(value) for value in aggregate.get("candidate_shas", []))
        != expected_shas
    ):
        raise ValueError("model-review candidate coverage changed")
    if aggregate.get("blocked_candidate_shas") != []:
        raise ValueError("model review has blocked candidates")
    conservation = aggregate.get("conservation")
    if (
        not isinstance(conservation, Mapping)
        or conservation.get("exact_candidate_coverage") is not True
        or conservation.get("hard_filter_count") != 0
    ):
        raise ValueError("model review is not recall-conserving")


def _code_candidate_rows(
    repository: Path, candidates_by_sha: Mapping[str, Mapping[str, object]]
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    forbidden_scopes = ("_download_package", "class Package")
    for sha, contract in CODE_SCOPE_CONTRACTS.items():
        candidate = candidates_by_sha.get(sha)
        if candidate is None:
            raise ValueError(f"code candidate disappeared: {sha}")
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
                "nltk/downloader.py",
            ],
        )
        changed = _changed_lines(diff)
        required = tuple(str(value) for value in contract["required"])
        checks = {
            "expected_function_scope_present": str(contract["scope"]) in diff,
            "required_delta_snippets_present": all(
                any(snippet in line for line in changed) for snippet in required
            ),
            "xml_write_mechanism_scope_absent": all(
                scope not in diff for scope in forbidden_scopes
            ),
        }
        if not all(checks.values()):
            raise ValueError(f"code candidate contract changed for {sha}: {checks}")
        rows.append(
            {
                "sha": sha,
                "disposition": "RETAIN_UNRELATED_TO_XML_WRITE_MECHANISM",
                "reason": contract["reason"],
                "checks": checks,
                "candidate_retained": True,
            }
        )
    return rows


def _adjudicate(
    repository: Path,
    inventory: Mapping[str, object],
    deepseek: Mapping[str, object],
    grok: Mapping[str, object],
    *,
    inventory_sha256: str,
    deepseek_sha256: str,
    grok_sha256: str,
) -> dict[str, object]:
    if inventory.get("artifact_kind") != "nltk_xml_path_traversal_recall_inventory":
        raise ValueError("unexpected NLTK inventory")
    conservation = inventory.get("conservation")
    finite = inventory.get("finite_inventory")
    lanes = inventory.get("priority_lanes")
    candidates = inventory.get("ai_candidates")
    transitions = inventory.get("exact_local_transitions")
    if not all(
        isinstance(value, Mapping) for value in (conservation, finite, lanes)
    ) or not all(isinstance(value, list) for value in (candidates, transitions)):
        raise ValueError("NLTK inventory is malformed")
    if (
        conservation.get("passed") is not True
        or conservation.get("hard_filter_count") != 0
    ):
        raise ValueError("NLTK inventory is not recall-conserving")

    candidates_by_sha = {
        str(row["sha"]): row for row in candidates if isinstance(row, Mapping)
    }
    affected_shas = {
        sha
        for sha, row in candidates_by_sha.items()
        if row.get("ancestor_of_affected_state") is True
    }
    if len(affected_shas) != 48:
        raise ValueError("affected-state AI candidate count changed")
    _validate_model_aggregate(
        deepseek,
        inventory_sha256=inventory_sha256,
        expected_shas=affected_shas,
    )
    if deepseek.get("promoted_candidate_shas") != []:
        raise ValueError("DeepSeek review gained a promoted lead")

    deepseek_hypothesis_shas = {
        str(sha)
        for row in deepseek.get("cross_file_hypotheses", [])
        if isinstance(row, Mapping)
        for sha in row.get("candidate_shas", [])
    }
    affected_code_shas = {
        str(value) for value in lanes.get("affected_code_and_any_ai_candidate_shas", [])
    }
    expected_grok_shas = (
        deepseek_hypothesis_shas | affected_code_shas | DATA_PATH_FOLLOWUPS
    )
    if len(expected_grok_shas) != 18:
        raise ValueError("targeted Grok follow-up set changed")
    _validate_model_aggregate(
        grok,
        inventory_sha256=inventory_sha256,
        expected_shas=expected_grok_shas,
    )
    if grok.get("promoted_candidate_shas") != []:
        raise ValueError("Grok review gained a promoted lead")

    transition_by_sha = {
        str(row["sha"]): row for row in transitions if isinstance(row, Mapping)
    }
    origin = transition_by_sha.get(EARLIEST_PIPELINE_SHA)
    fix = transition_by_sha.get(FIX_MEMBER_SHA)
    if not isinstance(origin, Mapping) or not isinstance(fix, Mapping):
        raise ValueError("exact transition anchors are missing")
    origin_ai = origin.get("ai_evidence")
    fix_ai = fix.get("ai_evidence")
    if not isinstance(origin_ai, Mapping) or any(origin_ai.values()):
        raise ValueError("earliest pipeline gained observable AI evidence")
    if not isinstance(fix_ai, Mapping) or fix_ai.get("source_v3_explicit") is not True:
        raise ValueError("AI-authored fix evidence disappeared")

    code_rows = _code_candidate_rows(repository, candidates_by_sha)
    context_rows = []
    for sha in sorted(CONTEXT_ONLY_SHAS):
        row = candidates_by_sha.get(sha)
        if (
            not isinstance(row, Mapping)
            or row.get("code_path_hits") != []
            or not row.get("context_path_hits")
        ):
            raise ValueError(f"context-only candidate contract changed: {sha}")
        context_rows.append(
            {
                "sha": sha,
                "disposition": "RETAIN_TEST_ONLY_NO_RUNTIME_DELTA",
                "changed_files": row.get("changed_files", []),
                "candidate_retained": True,
            }
        )

    affected_source = _git(repository, ["show", f"{AFFECTED_SHA}:nltk/downloader.py"])
    write_index = affected_source.index('with open(filepath, "wb") as outfile:')
    unzip_index = affected_source.index(
        "for msg in _unzip_iter(filepath, zipdir, verbose=False):"
    )
    downstream_order = {
        "unsafe_filepath_write_precedes_unzip": write_index < unzip_index,
        "write_source_offset": write_index,
        "unzip_call_offset": unzip_index,
    }
    if downstream_order["unsafe_filepath_write_precedes_unzip"] is not True:
        raise ValueError("download/write ordering changed")

    fallback_shas = {
        sha
        for sha, row in candidates_by_sha.items()
        if row.get("ancestor_of_affected_state") is True
        and row.get("priority") == "P3_AI_ANCESTRY_FALLBACK"
    }
    if len(fallback_shas) != 38:
        raise ValueError("AI ancestry fallback count changed")
    activation_changes: dict[str, list[str]] = {}
    for sha in sorted(fallback_shas):
        diff = _git(
            repository,
            ["show", "--format=", "--no-ext-diff", "--no-renames", "--unified=0", sha],
        )
        hits = _activation_line_changes(diff)
        if hits:
            activation_changes[sha] = hits
    if set(activation_changes) != {CI_ACTIVATION_SHA}:
        raise ValueError("cross-file activation-token inventory changed")
    ci_hits = activation_changes[CI_ACTIVATION_SHA]
    if (
        len(ci_hits) != 2
        or not ci_hits[0].startswith("-")
        or not ci_hits[1].startswith("+")
        or "nltk.download('wordnet')" not in ci_hits[0]
        or "nltk.download('wordnet')" not in ci_hits[1]
    ):
        raise ValueError("CI downloader-call preservation contract changed")

    ai_squash_members = [
        sha
        for sha, row in candidates_by_sha.items()
        if row.get("squash_member") is True
    ]
    ai_squash_carriers = [
        sha
        for sha, row in candidates_by_sha.items()
        if row.get("squash_carrier") is True
    ]
    if ai_squash_members or ai_squash_carriers:
        raise ValueError("AI attribution gained a squash member or carrier")

    return {
        "schema_version": 1,
        "artifact_kind": "nltk_xml_path_final_adjudication",
        "repository_identity": inventory.get("repository_identity"),
        "advisory": inventory.get("advisory"),
        "inputs": {
            "inventory_sha256": inventory_sha256,
            "deepseek_aggregate_sha256": deepseek_sha256,
            "grok_aggregate_sha256": grok_sha256,
        },
        "finite_search": {
            "retained_union_commit_count": finite.get("retained_union_commit_count"),
            "observable_ai_candidate_count": finite.get("ai_candidate_union_count"),
            "affected_state_ai_ancestor_count": len(affected_shas),
            "affected_code_ai_ancestor_count": len(affected_code_shas),
            "affected_context_only_ai_ancestor_count": len(CONTEXT_ONLY_SHAS),
            "affected_ai_ancestry_fallback_count": len(fallback_shas),
            "squash_member_ai_candidate_count": 0,
            "squash_carrier_ai_candidate_count": 0,
            "hard_filter_count": 0,
        },
        "model_routing": {
            "deepseek_exact_coverage": "48/48",
            "deepseek_promoted_count": 0,
            "deepseek_usage": deepseek.get("usage", {}),
            "grok_targeted_exact_coverage": "18/18",
            "grok_promoted_count": 0,
            "grok_usage": grok.get("usage", {}),
            "negative_has_deletion_authority": False,
        },
        "deterministic_adjudication": {
            "earliest_complete_pipeline": origin,
            "ai_authored_fix_not_origin": fix,
            "affected_code_candidates": code_rows,
            "affected_context_only_candidates": context_rows,
            "unzip_is_downstream_of_unsafe_write": downstream_order,
            "cross_file_activation_token_changes": activation_changes,
            "cross_file_activation_conclusion": (
                "The only ancestry-fallback delta mentioning a downloader call "
                "splits one existing CI shell command into two commands while "
                "preserving nltk.download('wordnet'); it adds no production route."
            ),
        },
        "claim_grade_ai_true_positive_count": 0,
        "blocked_candidate_count": 0,
        "verdict": FINAL_VERDICT,
        "conservation": {
            "all_finite_inventory_commits_retained": True,
            "all_observable_ai_affected_ancestors_reviewed": True,
            "model_negatives_used_as_proof": False,
            "weak_regex_used_as_claim_grade_attribution": False,
            "hard_filter_count": 0,
            "passed": True,
        },
        "claim_boundary": (
            "The zero result is complete only for the retained Git-object union and "
            "observable attribution contracts. The exact 2008 transition proves the "
            "earliest local source-path-sink pipeline is not observably AI-authored; "
            "it cannot prove that an unmarked later commit received private AI help."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")
    try:
        value = _adjudicate(
            repository,
            _load_json(args.inventory),
            _load_json(args.deepseek_aggregate),
            _load_json(args.grok_aggregate),
            inventory_sha256=_sha256(args.inventory),
            deepseek_sha256=_sha256(args.deepseek_aggregate),
            grok_sha256=_sha256(args.grok_aggregate),
        )
        _atomic_json(args.output, value)
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    print("NLTK XML-path final adjudication frozen")
    print(
        f"  retained commits : {value['finite_search']['retained_union_commit_count']}"
    )
    print(
        f"  AI ancestors     : {value['finite_search']['affected_state_ai_ancestor_count']}"
    )
    print(f"  blocked          : {value['blocked_candidate_count']}")
    print(f"  claim-grade TPs  : {value['claim_grade_ai_true_positive_count']}")
    print(f"  verdict          : {value['verdict']}")
    print(f"  output           : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
