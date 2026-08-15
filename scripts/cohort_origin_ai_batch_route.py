#!/usr/bin/env python3
"""Route lossless origin packets through loopback CLIProxyAPI."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
import time
from collections import defaultdict
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import httpx

from cohort.origin_batch import (
    OriginBatchContractError,
    parse_batch_response,
    parse_edge_batch_response,
)
from cohort.root_adjudication import canonical_sha256
from cohort_ai_routing_pilot import (
    _commit_view,
    _is_loopback_api_base,
    _run_git,
    _usage_counts,
    _validate_response_provenance,
)
from cve_analyzer.llm_client import extract_response_text


DEFAULT_API_BASE = "http://127.0.0.1:8317/v1"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
SYSTEM_PROMPT = """\
You are a conservative security-history router. False positives are acceptable;
false negatives are expensive. A fix may repair a defect indirectly through an
added check, caller/callee guard, middleware, validation, initialization order,
or refactor. A candidate may be a real PR member recovered behind an
AI-attributed landed squash; do not reject it merely because its original SHA
is not a mainline ancestor. Use the explicit Git lineage to distinguish a
candidate's own delta from a defect introduced only by its child: a shared-path
ancestor is not automatically an atomic origin. When that distinction is
unclear, use possible or insufficient; mark unlikely only when the candidate is
clearly unrelated. Return only the exact JSON schema requested by the user.
"""
CAUSAL_DELTA_SYSTEM_PROMPT = """\
You are a second-pass, recall-first security-history router. The first pass was
intentionally broad; every candidate remains retained regardless of your answer.
Promote a candidate only when its own parent-to-candidate delta plausibly does
one of two things: introduces an independently triggerable defect, or activates
a pre-existing defect through a new runtime-reachable feature, source, sink,
default, caller, or input path that a listed fix repairs. Chronological ancestry,
shared files, shared subsystems, prerequisites, tests, documentation, empty
commits, carrier-only evidence, and unchanged perpetuation are not independent
causal deltas. Use possible when a concrete changed line supports such a delta
but the bounded evidence cannot settle the parent state. Use insufficient when
the needed candidate delta is absent or truncated. False negatives are still
expensive: do not reject a concrete new path merely because the underlying bug
predates it. Return only the exact JSON schema requested by the user.
"""
CONTRIBUTOR_RECALL_SYSTEM_PROMPT = """\
You are a recall-maximizing security-history contributor router. False positives
are acceptable and false negatives are costly; every candidate remains retained
regardless of your answer. Promote a candidate when its own parent-to-candidate
delta plausibly contributes to security-relevant behavior later repaired. The
candidate need not independently create the root defect. Eligible contributions
include the earliest vulnerable implementation; a new caller, input, UI action,
route, default, source, or sink; lifecycle or persistence changes that make a
vulnerable trigger execute reliably or automatically; a material rewrite or
extension of the exact security-sensitive sink/dataflow that preserves missing
authorization, validation, or escaping; and partial hardening that leaves or
moves the same unsafe path. Reject only when the shown delta demonstrates
unchanged context or is clearly unrelated. Tests, documentation, ancestry, and
carrier-only evidence are not contributions by themselves. If a later change is
only compatibility or availability work and does not plausibly enforce a
security boundary, do not promote it as a security repair; when that distinction
or the parent state is unresolved, use possible. Use insufficient when the needed
diff is absent or truncated. Return only the exact JSON schema requested by the
user.
"""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generated-dir", type=Path, required=True)
    parser.add_argument("--packet-dir", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--reasoning-effort",
        choices=("low", "medium", "high", "max", "model-controlled"),
        required=True,
    )
    parser.add_argument("--api-base", default=DEFAULT_API_BASE)
    parser.add_argument("--api-key-env", default="CLIPROXY_API_KEY")
    parser.add_argument(
        "--packets-per-group",
        type=int,
        default=0,
        help="route the first N packets per advisory/repository (0 = all)",
    )
    parser.add_argument("--max-packets", type=int, default=0)
    parser.add_argument(
        "--candidate-sha",
        action="append",
        default=[],
        help=(
            "route only the named candidate SHA; repeat for multiple candidates "
            "(all other inventory rows remain retained and deferred)"
        ),
    )
    parser.add_argument(
        "--candidate-signal",
        action="append",
        default=[],
        help=(
            "route only units carrying every named signal; repeat to require "
            "multiple signals (all other inventory rows remain retained and deferred)"
        ),
    )
    routing_gate = parser.add_mutually_exclusive_group()
    routing_gate.add_argument(
        "--causal-delta-gate",
        action="store_true",
        help=(
            "second-pass ranking: promote only an independently causal delta or "
            "new vulnerable runtime path; negatives remain retained"
        ),
    )
    routing_gate.add_argument(
        "--contributor-recall-gate",
        action="store_true",
        help=(
            "recall-first ranking: promote material activation, preservation, "
            "extension, and incomplete-hardening contributors; negatives remain "
            "retained"
        ),
    )
    parser.add_argument(
        "--edge-specific",
        action="store_true",
        help=(
            "require every promoted candidate to name the exact eligible fix "
            "aliases it relates to; preserves folded multi-fix prompts without "
            "copying one verdict onto unrelated fix edges"
        ),
    )
    parser.add_argument(
        "--require-label-neutral-input",
        action="store_true",
        help=(
            "fail closed unless the generated inventory removes adjudication "
            "labels, label-derived priority, and known-positive prompt signals"
        ),
    )
    parser.add_argument(
        "--isolate-candidates",
        action="store_true",
        help=(
            "give each retained candidate its own prompt so unrelated candidates "
            "cannot consume its shared-path evidence budget"
        ),
    )
    parser.add_argument("--candidate-diff-chars", type=int, default=2500)
    parser.add_argument("--fix-diff-chars", type=int, default=4000)
    parser.add_argument("--max-output-tokens", type=int, default=1800)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--transport-retries", type=int, default=2)
    parser.add_argument("--contract-retries", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain an object")
    return value


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise SystemExit(f"{path}:{line_number}: row is not an object")
                rows.append(row)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _atomic_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _select_packets(
    packets: list[dict[str, object]],
    *,
    packets_per_group: int,
    max_packets: int,
) -> list[dict[str, object]]:
    group_counts: defaultdict[tuple[str, str], int] = defaultdict(int)
    selected: list[dict[str, object]] = []
    for packet in sorted(packets, key=lambda row: int(row["sequence"])):
        group = (
            str(packet["advisory"]),
            str(packet["repository_identity"]),
        )
        group_counts[group] += 1
        if packets_per_group and group_counts[group] > packets_per_group:
            continue
        selected.append(packet)
        if max_packets and len(selected) >= max_packets:
            break
    return selected


def _filter_packets_by_candidate_sha(
    packets: list[dict[str, object]],
    units: list[dict[str, object]],
    candidate_shas: list[str],
) -> list[dict[str, object]]:
    """Return packet copies containing only explicitly requested candidate units."""
    if not candidate_shas:
        return packets

    requested = {sha.lower() for sha in candidate_shas}
    malformed = sorted(
        sha
        for sha in requested
        if len(sha) != 40 or any(ch not in "0123456789abcdef" for ch in sha)
    )
    if malformed:
        raise SystemExit(f"candidate SHA filter requires full 40-hex SHAs: {malformed}")

    unit_sha = {
        str(unit["unit_id"]): str(unit["candidate_sha"]).lower() for unit in units
    }
    found: set[str] = set()
    filtered: list[dict[str, object]] = []
    for packet in packets:
        retained_ids: list[object] = []
        for raw_unit_id in packet["candidate_unit_ids"]:
            unit_id = str(raw_unit_id)
            if unit_id not in unit_sha:
                raise SystemExit(f"packet references unknown candidate unit: {unit_id}")
            sha = unit_sha[unit_id]
            if sha in requested:
                retained_ids.append(raw_unit_id)
                found.add(sha)
        if retained_ids:
            retained_packet = dict(packet)
            retained_packet["candidate_unit_ids"] = retained_ids
            retained_packet["candidate_count"] = len(retained_ids)
            filtered.append(retained_packet)

    missing = sorted(requested - found)
    if missing:
        raise SystemExit(
            f"candidate SHA filter not present in packet inventory: {missing}"
        )
    return filtered


def _filter_packets_by_candidate_signal(
    packets: list[dict[str, object]],
    units: list[dict[str, object]],
    candidate_signals: list[str],
) -> list[dict[str, object]]:
    """Return packet copies containing only units with every requested signal."""
    requested = {signal.strip() for signal in candidate_signals if signal.strip()}
    if not requested:
        return packets

    unit_signals: dict[str, set[str]] = {}
    inventory_signals: set[str] = set()
    for unit in units:
        raw_signals = unit.get("signals")
        if not isinstance(raw_signals, list) or any(
            not isinstance(signal, str) for signal in raw_signals
        ):
            raise SystemExit("candidate unit signals are malformed")
        signals = set(raw_signals)
        unit_signals[str(unit["unit_id"])] = signals
        inventory_signals.update(signals)
    missing = sorted(requested - inventory_signals)
    if missing:
        raise SystemExit(
            f"candidate signal filter not present in packet inventory: {missing}"
        )

    filtered: list[dict[str, object]] = []
    for packet in packets:
        retained_ids = [
            raw_unit_id
            for raw_unit_id in packet["candidate_unit_ids"]
            if requested <= unit_signals.get(str(raw_unit_id), set())
        ]
        if retained_ids:
            retained_packet = dict(packet)
            retained_packet["candidate_unit_ids"] = retained_ids
            retained_packet["candidate_count"] = len(retained_ids)
            filtered.append(retained_packet)
    return filtered


_FORBIDDEN_LABEL_NEUTRAL_MARKERS = (
    "CONFIRMED_TRUE_POSITIVE",
    "candidate_confirmed_anywhere",
    "input_edge_status",
    "known_candidate_positive_control",
    "p5_already_confirmed_candidate_coverage",
)


def _validate_label_neutral_input(
    summary: Mapping[str, object], candidates: list[dict[str, object]]
) -> None:
    if summary.get("label_neutral") is not True:
        raise SystemExit("generated inventory is not marked label-neutral")
    for row in candidates:
        candidate_sha = str(row.get("sha") or "unknown")
        forbidden_fields = {
            "candidate_confirmed_anywhere",
            "input_edge_status",
            "priority_class",
        } & set(row)
        if forbidden_fields:
            raise SystemExit(
                f"label-neutral candidate {candidate_sha} exposes fields: "
                f"{sorted(forbidden_fields)}"
            )
        if int(row.get("priority_rank") or 0) != 1:
            raise SystemExit(
                f"label-neutral candidate {candidate_sha} has non-neutral priority"
            )
        signals = row.get("signals")
        if not isinstance(signals, list):
            raise SystemExit(
                f"label-neutral candidate {candidate_sha} has malformed signals"
            )
        leaked = [
            str(signal)
            for signal in signals
            if re.match(r"^p\d+_", str(signal))
            or any(
                marker.casefold() in str(signal).casefold()
                for marker in _FORBIDDEN_LABEL_NEUTRAL_MARKERS
            )
        ]
        if leaked:
            raise SystemExit(
                f"label-neutral candidate {candidate_sha} leaks signals: {leaked}"
            )


def _validate_prompt_label_neutrality(prompts: list[dict[str, object]]) -> None:
    serialized = json.dumps(prompts, sort_keys=True, ensure_ascii=False)
    leaked = [
        marker for marker in _FORBIDDEN_LABEL_NEUTRAL_MARKERS if marker in serialized
    ]
    if leaked:
        raise SystemExit(f"label-neutral prompts expose adjudication markers: {leaked}")


def _isolate_candidate_packets(
    packets: list[dict[str, object]],
    units: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Split packets losslessly so every candidate gets an independent budget."""

    unit_index = {str(unit["unit_id"]): unit for unit in units}
    isolated: list[dict[str, object]] = []
    expected_memberships: list[str] = []
    sequence = 0
    for packet in sorted(packets, key=lambda row: int(row["sequence"])):
        packet_fix_shas = [str(value) for value in packet["fix_shas"]]
        for raw_unit_id in packet["candidate_unit_ids"]:
            unit_id = str(raw_unit_id)
            if unit_id not in unit_index:
                raise SystemExit(f"packet references unknown candidate unit: {unit_id}")
            expected_memberships.append(unit_id)
            unit = unit_index[unit_id]
            eligible_fix_shas = {
                str(edge["fix_sha"])
                for edge in unit["fix_edges"]
                if isinstance(edge, Mapping) and edge.get("fix_sha")
            }
            fix_shas = [
                fix_sha
                for fix_sha in packet_fix_shas
                if fix_sha in eligible_fix_shas
            ]
            if set(fix_shas) != eligible_fix_shas:
                raise SystemExit(
                    f"candidate fixes escaped source packet: {unit_id}"
                )
            sequence += 1
            isolated.append(
                {
                    **packet,
                    "packet_id": f"{packet['packet_id']}--{unit_id}",
                    "sequence": sequence,
                    "source_packet_id": packet["packet_id"],
                    "source_sequence": packet["sequence"],
                    "candidate_unit_ids": [unit_id],
                    "candidate_shas": [unit["candidate_sha"]],
                    "candidate_count": 1,
                    "fix_shas": fix_shas,
                    "fix_edge_count": len(fix_shas),
                }
            )
    if len(expected_memberships) != len(set(expected_memberships)):
        raise SystemExit("candidate packet inventory contains duplicate membership")
    if [str(row["candidate_unit_ids"][0]) for row in isolated] != expected_memberships:
        raise SystemExit("isolated candidate conservation failed")
    return isolated


def _prompt(
    *,
    packet: Mapping[str, object],
    aliases: list[dict[str, object]],
    fix_views: list[dict[str, str]],
    candidate_views: list[dict[str, object]],
    causal_delta_gate: bool = False,
    contributor_recall_gate: bool = False,
    edge_specific: bool = False,
) -> str:
    fixes = []
    for index, view in enumerate(fix_views, start=1):
        fix_id = str(view.get("id") or f"F{index:02d}")
        fixes.append(
            f"""\
### Security fix {fix_id}
SHA: {view["sha"]}
Date: {view["date"]}
Subject: {view["subject"]}
```diff
{view["diff"]}
```"""
        )
    candidates = []
    alias_by_unit = {str(row["unit_id"]): str(row["id"]) for row in aliases}
    for view in candidate_views:
        alias = alias_by_unit[str(view["unit_id"])]
        candidates.append(
            f"""\
### Candidate {alias}
SHA: {view["sha"]}
Eligible fixes: {", ".join(str(value) for value in (view["fix_ids"] if edge_specific else view["fix_shas"]))}
Best structural rank: {view["rank"]}
Signals: {", ".join(str(value) for value in view["signals"])}
Carrier signals: {", ".join(str(value) for value in view["carrier_signals"]) or "none"}
Provenance: {view["provenance"]}
Lineage: {view["lineage"]}
Change stats: {view["change_stats"]}
Date: {view["date"]}
Subject: {view["subject"]}
```diff
{view["diff"]}
```"""
        )
    expected = ", ".join(str(row["id"]) for row in aliases)
    if contributor_recall_gate:
        decision_rule = (
            "For every candidate and eligible fix, decide whether the candidate's "
            "own parent-to-candidate delta likely or possibly contributes to the "
            "security-relevant path repaired by that fix. Count activation, new "
            "reachability or triggering, material sink/dataflow preservation, "
            "path extension, and incomplete hardening; independent root-cause "
            "introduction is not required."
        )
    elif causal_delta_gate:
        decision_rule = (
            "For every candidate, decide whether its own parent-to-candidate delta "
            "likely or possibly introduces an independently triggerable defect, or "
            "activates a new runtime-reachable path into a pre-existing defect, that "
            "an eligible fix repairs. Mere ancestry or unchanged perpetuation is "
            "unlikely."
        )
    else:
        decision_rule = (
            "For every candidate, decide whether any eligible fix likely or "
            "possibly repairs a defect introduced or materially perpetuated by it."
        )
    response_contract = (
        "For likely or possible, related_fixes must contain one or more eligible "
        "Fxx IDs. For unlikely it must be empty. For insufficient it may be empty "
        "or contain only the unresolved eligible Fxx IDs.\n\n"
        "Return JSON only, with no extra keys or prose:\n"
        '{"results":[{"id":"C01","causality":"likely|possible|unlikely|insufficient",'
        '"related_fixes":["F01"],"reason":"max 25 words"}]}'
        if edge_specific
        else (
            "Return JSON only, with no extra keys or prose:\n"
            '{"results":[{"id":"C01","causality":"likely|possible|unlikely|insufficient",'
            '"reason":"max 25 words"}]}'
        )
    )
    return f"""\
Repository: {packet["repository_identity"]}
Advisory: {packet["advisory"]}

## Later security fixes

{chr(10).join(fixes)}

## Earlier origin candidates

{chr(10).join(candidates)}

{decision_rule} You must return every ID exactly once: {expected}

{response_contract}
"""


def _candidate_provenance(unit: Mapping[str, object]) -> str:
    composite: set[tuple[int, str]] = set()
    for edge in unit.get("fix_edges", []):
        if not isinstance(edge, Mapping):
            continue
        evidence_rows = edge.get("relation_evidence", [])
        if not isinstance(evidence_rows, list):
            continue
        for evidence in evidence_rows:
            if not isinstance(evidence, Mapping):
                continue
            landed_sha = str(evidence.get("landed_sha") or "")
            raw_pr = evidence.get("relation_pr_number")
            if landed_sha and isinstance(raw_pr, int):
                composite.add((raw_pr, landed_sha))
    if not composite:
        return "mainline commit reachable from the pre-fix state"
    carriers = ", ".join(
        f"PR #{number} -> landed squash {sha}" for number, sha in sorted(composite)
    )
    member_signal = "yes" if unit.get("origin_observed_in_cohort") is True else "no"
    prefix = (
        "EMPTY TREE PR member" if unit.get("empty_commit") is True else "real PR member"
    )
    return (
        f"{prefix} ({carriers}); member-level AI signal={member_signal}; "
        "carrier-level AI exposure=yes"
    )


def _candidate_parent_shas(repo: Path, sha: str) -> list[str]:
    output = _run_git(repo, ["show", "--no-patch", "--format=%P", sha])
    return [
        value
        for value in output.strip().split()
        if len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    ]


def _selected_candidate_lineage(
    sha: str,
    *,
    parent_shas: Mapping[str, list[str]],
    alias_by_sha: Mapping[str, str],
) -> str:
    parents = parent_shas.get(sha, [])
    selected_parents = [
        f"{alias_by_sha[parent]}@{parent}"
        for parent in parents
        if parent in alias_by_sha
    ]
    selected_children = [
        f"{alias}@{child}"
        for child, alias in sorted(alias_by_sha.items(), key=lambda item: item[1])
        if sha in parent_shas.get(child, [])
    ]
    return (
        f"git-parents={','.join(parents) or 'none'}; "
        f"direct-parent-in-packet={','.join(selected_parents) or 'none'}; "
        f"direct-children-in-packet={','.join(selected_children) or 'none'}"
    )


def _priority_overlap_paths(
    paths: list[str],
    *,
    added_paths: set[str],
) -> list[str]:
    """Put production and newly introduced shared paths before ancillary evidence."""

    def ancillary(path: str) -> bool:
        lowered = path.lower()
        parts = set(lowered.split("/"))
        return bool(
            parts & {"doc", "docs", "test", "tests", "spec", "specs"}
        ) or lowered.endswith((".md", ".rst", ".txt"))

    return sorted(
        set(paths),
        key=lambda path: (
            ancillary(path),
            path not in added_paths,
            path,
        ),
    )


def _prepare_prompts(
    selected_packets: list[dict[str, object]],
    units: list[dict[str, object]],
    fixes: list[dict[str, object]],
    *,
    candidate_diff_chars: int,
    fix_diff_chars: int,
    causal_delta_gate: bool = False,
    contributor_recall_gate: bool = False,
    edge_specific: bool = False,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    unit_index = {str(row["unit_id"]): row for row in units}
    fix_index = {
        (
            str(row["advisory"]),
            str(row["repository_identity"]),
            str(row["fix_sha"]),
        ): row
        for row in fixes
    }
    view_cache: dict[tuple[str, str, int], tuple[str, str, str]] = {}
    added_path_cache: dict[tuple[str, str], set[str]] = {}
    changed_path_cache: dict[tuple[str, str], set[str]] = {}

    def view(repo: Path, sha: str, limit: int) -> tuple[str, str, str]:
        key = (str(repo), sha, limit)
        if key not in view_cache:
            view_cache[key] = _commit_view(repo, sha, limit)
        return view_cache[key]

    def added_paths(repo: Path, sha: str) -> set[str]:
        key = (str(repo), sha)
        if key not in added_path_cache:
            output = _run_git(
                repo,
                [
                    "diff-tree",
                    "--root",
                    "--no-commit-id",
                    "--name-only",
                    "--diff-filter=A",
                    "-r",
                    sha,
                ],
            )
            added_path_cache[key] = {
                line.strip() for line in output.splitlines() if line.strip()
            }
        return added_path_cache[key]

    def changed_paths(repo: Path, sha: str) -> set[str]:
        key = (str(repo), sha)
        if key not in changed_path_cache:
            output = _run_git(
                repo,
                [
                    "diff-tree",
                    "--root",
                    "--no-commit-id",
                    "--name-only",
                    "-r",
                    sha,
                ],
            )
            changed_path_cache[key] = {
                line.strip() for line in output.splitlines() if line.strip()
            }
        return changed_path_cache[key]

    items: list[dict[str, object]] = []
    prompts: list[dict[str, object]] = []
    for packet in selected_packets:
        advisory = str(packet["advisory"])
        identity = str(packet["repository_identity"])
        packet_units = [
            unit_index[str(value)] for value in packet["candidate_unit_ids"]
        ]
        fix_alias_by_sha = {
            str(fix_sha): f"F{index:02d}"
            for index, fix_sha in enumerate(packet["fix_shas"], start=1)
        }
        aliases = [
            {
                "id": f"C{index:02d}",
                "unit_id": unit["unit_id"],
                "candidate_sha": unit["candidate_sha"],
                "eligible_fix_ids": [
                    fix_alias_by_sha[str(edge["fix_sha"])]
                    for edge in unit["fix_edges"]
                ],
            }
            for index, unit in enumerate(packet_units, start=1)
        ]
        alias_by_sha = {
            str(alias["candidate_sha"]): str(alias["id"]) for alias in aliases
        }
        fix_rows = [
            fix_index[(advisory, identity, str(fix_sha))]
            for fix_sha in packet["fix_shas"]
        ]
        if any(row.get("status") != "RESOLVED" for row in fix_rows):
            raise SystemExit(f"packet has an unresolved fix: {packet['packet_id']}")
        repository_paths = {str(row.get("repository_path") or "") for row in fix_rows}
        if len(repository_paths) != 1:
            raise SystemExit(
                f"packet fixes disagree on repository path: {packet['packet_id']}"
            )
        repo = Path(next(iter(repository_paths)))
        if not repo.is_dir():
            raise SystemExit(f"packet repository unavailable: {repo}")
        fix_priority_paths: dict[str, list[str]] = {}
        for raw_fix_sha in packet["fix_shas"]:
            fix_sha = str(raw_fix_sha)
            overlap_files: list[str] = []
            candidate_added_paths: set[str] = set()
            fix_changed_paths = changed_paths(repo, fix_sha)
            for unit in packet_units:
                matching_edges = [
                    edge
                    for edge in unit["fix_edges"]
                    if isinstance(edge, Mapping)
                    and str(edge.get("fix_sha") or "") == fix_sha
                ]
                if not matching_edges:
                    continue
                overlap_files.extend(
                    str(path)
                    for edge in matching_edges
                    for path in edge.get("fix_file_overlap", [])
                )
                overlap_files.extend(
                    changed_paths(repo, str(unit["candidate_sha"]))
                    & fix_changed_paths
                )
                candidate_added_paths.update(
                    added_paths(repo, str(unit["candidate_sha"]))
                )
            fix_priority_paths[fix_sha] = _priority_overlap_paths(
                overlap_files,
                added_paths=candidate_added_paths,
            )

        fix_views: list[dict[str, str]] = []
        for fix_sha in packet["fix_shas"]:
            fix_sha = str(fix_sha)
            priority_paths = fix_priority_paths[fix_sha]
            if priority_paths:
                subject, date, diff = _commit_view(
                    repo,
                    fix_sha,
                    fix_diff_chars,
                    priority_paths=priority_paths,
                    priority_label="Candidate/fix shared-path fix evidence",
                )
            else:
                subject, date, diff = view(repo, fix_sha, fix_diff_chars)
            fix_views.append(
                {
                    "id": fix_alias_by_sha[fix_sha],
                    "sha": fix_sha,
                    "subject": subject,
                    "date": date,
                    "diff": diff,
                }
            )
        candidate_views: list[dict[str, object]] = []
        parent_shas = {
            str(unit["candidate_sha"]): _candidate_parent_shas(
                repo, str(unit["candidate_sha"])
            )
            for unit in packet_units
        }
        for unit in packet_units:
            candidate_sha = str(unit["candidate_sha"])
            carrier_signals = sorted(
                {
                    str(signal)
                    for edge in unit["fix_edges"]
                    if isinstance(edge, Mapping)
                    for signal in edge.get("landed_signals", [])
                }
            )
            overlap_files = sorted(
                {
                    str(path)
                    for edge in unit["fix_edges"]
                    if isinstance(edge, Mapping)
                    for path in edge.get("fix_file_overlap", [])
                }
            )
            eligible_fix_paths = set().union(
                *(
                    changed_paths(repo, str(edge["fix_sha"]))
                    for edge in unit["fix_edges"]
                    if isinstance(edge, Mapping) and edge.get("fix_sha")
                )
            )
            overlap_files = sorted(
                set(overlap_files)
                | (changed_paths(repo, candidate_sha) & eligible_fix_paths)
            )
            internal_blame_lines = sum(
                int(edge.get("squash_internal_blame_line_count") or 0)
                for edge in unit["fix_edges"]
                if isinstance(edge, Mapping)
            )
            internal_blame_paths = sorted(
                {
                    str(path)
                    for edge in unit["fix_edges"]
                    if isinstance(edge, Mapping)
                    for path in edge.get("squash_internal_blame_paths", [])
                }
            )
            priority_paths = _priority_overlap_paths(
                overlap_files,
                added_paths=added_paths(repo, candidate_sha),
            )
            if priority_paths:
                subject, date, diff = _commit_view(
                    repo,
                    candidate_sha,
                    candidate_diff_chars,
                    priority_paths=priority_paths,
                    priority_label="Candidate/fix shared-path candidate evidence",
                )
            else:
                subject, date, diff = view(repo, candidate_sha, candidate_diff_chars)
            change_stats = (
                "EMPTY TREE; this PR member contributes no content delta"
                if unit.get("empty_commit") is True
                else (
                    f"+{int(unit.get('additions') or 0)}/"
                    f"-{int(unit.get('deletions') or 0)}, "
                    f"files={len(unit.get('changed_files') or [])}, "
                    f"exact-fix-file-overlap={','.join(overlap_files) or 'none'}, "
                    f"squash-internal-fix-context-lines={internal_blame_lines}, "
                    "squash-internal-paths="
                    f"{','.join(internal_blame_paths) or 'none'}"
                )
            )
            candidate_views.append(
                {
                    "unit_id": unit["unit_id"],
                    "sha": candidate_sha,
                    "fix_shas": [edge["fix_sha"] for edge in unit["fix_edges"]],
                    "fix_ids": [
                        fix_alias_by_sha[str(edge["fix_sha"])]
                        for edge in unit["fix_edges"]
                    ],
                    "rank": unit["best_priority_rank"],
                    "signals": unit["signals"],
                    "carrier_signals": carrier_signals,
                    "change_stats": change_stats,
                    "provenance": _candidate_provenance(unit),
                    "lineage": _selected_candidate_lineage(
                        candidate_sha,
                        parent_shas=parent_shas,
                        alias_by_sha=alias_by_sha,
                    ),
                    "subject": subject,
                    "date": date,
                    "diff": diff,
                }
            )
        if contributor_recall_gate:
            system_prompt = CONTRIBUTOR_RECALL_SYSTEM_PROMPT
            routing_mode = "contributor_recall"
        elif causal_delta_gate:
            system_prompt = CAUSAL_DELTA_SYSTEM_PROMPT
            routing_mode = "causal_delta"
        else:
            system_prompt = SYSTEM_PROMPT
            routing_mode = "broad"
        user_prompt = _prompt(
            packet=packet,
            aliases=aliases,
            fix_views=fix_views,
            candidate_views=candidate_views,
            causal_delta_gate=causal_delta_gate,
            contributor_recall_gate=contributor_recall_gate,
            edge_specific=edge_specific,
        )
        item = {
            "packet_id": packet["packet_id"],
            "sequence": packet["sequence"],
            "advisory": advisory,
            "repository_identity": identity,
            "aliases": aliases,
            "candidate_count": len(aliases),
            "fix_shas": packet["fix_shas"],
            "fix_aliases": [
                {"id": fix_alias_by_sha[str(fix_sha)], "fix_sha": str(fix_sha)}
                for fix_sha in packet["fix_shas"]
            ],
            "edge_specific": edge_specific,
            "routing_mode": routing_mode,
            "prompt_chars": len(system_prompt) + len(user_prompt),
            "estimated_input_tokens_chars_div_4": (
                len(system_prompt) + len(user_prompt) + 3
            )
            // 4,
        }
        items.append(item)
        prompts.append(
            {
                **item,
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
            }
        )
    return items, prompts


def _call_one_once(
    prompt: Mapping[str, object],
    *,
    api_base: str,
    api_key: str,
    model: str,
    reasoning_effort: str,
    max_output_tokens: int,
    timeout: float,
    responses_dir: Path,
) -> dict[str, object]:
    body: dict[str, object] = {
        "model": model,
        "messages": [
            {"role": "system", "content": str(prompt["system_prompt"])},
            {"role": "user", "content": str(prompt["user_prompt"])},
        ],
        "max_tokens": max_output_tokens,
    }
    if reasoning_effort != "model-controlled":
        body["reasoning_effort"] = reasoning_effort
    result: dict[str, object] = {
        "packet_id": prompt["packet_id"],
        "sequence": prompt["sequence"],
        "requested_model": model,
        "observed_model": "",
        "result_status": "transport_error",
        "finish_reason": "",
        "reason": "",
        "unit_results": [],
        "usage": {},
    }
    try:
        response = httpx.post(
            f"{api_base.rstrip('/')}/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=body,
            timeout=timeout,
        )
        response.raise_for_status()
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise ValueError("response_too_large")
        raw = response.json()
        if not isinstance(raw, dict):
            raise ValueError("response_not_object")
        _atomic_json(responses_dir / f"{int(prompt['sequence']):03d}.json", raw)
        valid, reason, observed_model = _validate_response_provenance(
            raw,
            backend="cliproxyapi",
            requested_model=model,
        )
        result["observed_model"] = observed_model
        choices = raw.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], Mapping):
            result["finish_reason"] = str(choices[0].get("finish_reason") or "")
        if not valid:
            result["result_status"] = "provenance_error"
            result["reason"] = reason
        else:
            aliases = prompt["aliases"]
            assert isinstance(aliases, list)
            expected = [str(alias["id"]) for alias in aliases]
            try:
                if prompt.get("edge_specific") is True:
                    expected_fix_aliases = {
                        str(alias["id"]): [
                            str(value)
                            for value in alias.get("eligible_fix_ids", [])
                        ]
                        for alias in aliases
                    }
                    parsed = parse_edge_batch_response(
                        extract_response_text(raw), expected_fix_aliases
                    )
                else:
                    parsed = parse_batch_response(extract_response_text(raw), expected)
            except OriginBatchContractError as exc:
                result["result_status"] = "parse_error"
                result["reason"] = (
                    f"{exc}:finish_reason={result['finish_reason'] or 'unknown'}"
                )
            else:
                alias_index = {str(alias["id"]): alias for alias in aliases}
                result["result_status"] = "completed"
                result["unit_results"] = [
                    {
                        "unit_id": alias_index[row["id"]]["unit_id"],
                        "candidate_sha": alias_index[row["id"]]["candidate_sha"],
                        **row,
                    }
                    for row in parsed
                ]
        usage = raw.get("usage")
        if isinstance(usage, Mapping):
            input_tokens, output_tokens = _usage_counts(usage)
            result["usage"] = {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "reported_cost": str(raw.get("cost") or ""),
            }
    except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
        result["reason"] = f"{type(exc).__name__}:{str(exc)[:200]}"
    return result


def _call_with_retries(
    prompt: Mapping[str, object],
    *,
    transport_retries: int,
    contract_retries: int,
    **kwargs: object,
) -> dict[str, object]:
    attempt_count = 0
    transport_failure_count = 0
    contract_failure_count = 0
    while True:
        attempt_count += 1
        result = _call_one_once(prompt, **kwargs)  # type: ignore[arg-type]
        reason = str(result.get("reason") or "")
        retryable = result.get("result_status") == "transport_error" and any(
            marker in reason
            for marker in (
                "429",
                "500",
                "502",
                "503",
                "504",
                "ConnectError",
                "ReadTimeout",
                "RemoteProtocolError",
            )
        )
        if retryable and transport_failure_count < transport_retries:
            transport_failure_count += 1
            time.sleep(min(2 ** (transport_failure_count - 1), 4))
            continue
        if (
            result.get("result_status") == "parse_error"
            and contract_failure_count < contract_retries
        ):
            contract_failure_count += 1
            continue
        result["attempt_count"] = attempt_count
        result["transport_retry_count"] = transport_failure_count
        result["contract_retry_count"] = contract_failure_count
        return result


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if (
        min(
            args.candidate_diff_chars,
            args.fix_diff_chars,
            args.max_output_tokens,
            args.workers,
        )
        < 1
        or min(
            args.packets_per_group,
            args.max_packets,
            args.transport_retries,
            args.contract_retries,
        )
        < 0
    ):
        raise SystemExit(
            "batch bounds must be non-negative and evidence bounds positive"
        )
    if not _is_loopback_api_base(args.api_base):
        raise SystemExit("batch routing requires a loopback CLIProxyAPI endpoint")
    api_key = os.environ.get(args.api_key_env, "")
    if not api_key:
        raise SystemExit(f"API key environment is empty: {args.api_key_env}")

    generated_summary = _load_json(args.generated_dir / "summary.json")
    candidates = _load_jsonl(args.generated_dir / "candidates.jsonl")
    fixes = _load_jsonl(args.generated_dir / "fixes.jsonl")
    packet_summary = _load_json(args.packet_dir / "summary.json")
    units = _load_jsonl(args.packet_dir / "candidate_units.jsonl")
    packets = _load_jsonl(args.packet_dir / "packets.jsonl")
    if canonical_sha256(candidates) != generated_summary.get("candidate_rows_sha256"):
        raise SystemExit("generated candidate digest mismatch")
    if canonical_sha256(fixes) != generated_summary.get("fix_rows_sha256"):
        raise SystemExit("generated fix digest mismatch")
    if canonical_sha256(generated_summary) != packet_summary.get(
        "parent_generation_sha256"
    ):
        raise SystemExit("packet parent generation mismatch")
    if canonical_sha256(units) != packet_summary.get("candidate_units_sha256"):
        raise SystemExit("candidate unit digest mismatch")
    if canonical_sha256(packets) != packet_summary.get("packets_sha256"):
        raise SystemExit("packet digest mismatch")
    if args.require_label_neutral_input:
        _validate_label_neutral_input(generated_summary, candidates)

    candidate_sha_filter = sorted({sha.lower() for sha in args.candidate_sha})
    candidate_signal_filter = sorted(
        {signal.strip() for signal in args.candidate_signal if signal.strip()}
    )
    candidate_filtered_packets = _filter_packets_by_candidate_sha(
        packets,
        units,
        candidate_sha_filter,
    )
    candidate_filtered_packets = _filter_packets_by_candidate_signal(
        candidate_filtered_packets,
        units,
        candidate_signal_filter,
    )
    if (
        candidate_sha_filter or candidate_signal_filter
    ) and not candidate_filtered_packets:
        raise SystemExit("combined candidate filters matched no packet")
    if args.isolate_candidates:
        candidate_filtered_packets = _isolate_candidate_packets(
            candidate_filtered_packets,
            units,
        )
    selected_packets = _select_packets(
        candidate_filtered_packets,
        packets_per_group=args.packets_per_group,
        max_packets=args.max_packets,
    )
    items, prompts = _prepare_prompts(
        selected_packets,
        units,
        fixes,
        candidate_diff_chars=args.candidate_diff_chars,
        fix_diff_chars=args.fix_diff_chars,
        causal_delta_gate=args.causal_delta_gate,
        contributor_recall_gate=args.contributor_recall_gate,
        edge_specific=args.edge_specific,
    )
    if args.require_label_neutral_input:
        _validate_prompt_label_neutrality(prompts)
    args.output_dir.mkdir(parents=True)
    responses_dir = args.output_dir / "responses"
    responses_dir.mkdir(mode=0o700)
    _atomic_jsonl(args.output_dir / "items.jsonl", items)
    _atomic_jsonl(args.output_dir / "prompts.jsonl", prompts)
    spec = {
        "schema_version": 1,
        "artifact_kind": "recall_safe_origin_ai_batch_route",
        "parent_generation_sha256": canonical_sha256(generated_summary),
        "candidate_inventory_sha256": canonical_sha256(candidates),
        "packet_inventory_sha256": canonical_sha256(packet_summary),
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "packets_per_group": args.packets_per_group,
        "max_packets": args.max_packets,
        "candidate_sha_filter": candidate_sha_filter,
        "candidate_signal_filter": candidate_signal_filter,
        "causal_delta_gate": args.causal_delta_gate,
        "contributor_recall_gate": args.contributor_recall_gate,
        "label_neutral_input_required": args.require_label_neutral_input,
        "routing_mode": (
            "contributor_recall"
            if args.contributor_recall_gate
            else "causal_delta"
            if args.causal_delta_gate
            else "broad"
        ),
        "edge_specific": args.edge_specific,
        "isolate_candidates": args.isolate_candidates,
        "selected_packet_count": len(selected_packets),
        "selected_candidate_unit_count": sum(
            int(row["candidate_count"]) for row in items
        ),
        "total_packet_count": len(packets),
        "total_candidate_unit_count": len(units),
        "candidate_diff_chars": args.candidate_diff_chars,
        "fix_diff_chars": args.fix_diff_chars,
        "max_output_tokens": args.max_output_tokens,
        "workers": args.workers,
        "transport_retries": args.transport_retries,
        "contract_retries": args.contract_retries,
        "estimated_input_tokens_chars_div_4": sum(
            int(row["estimated_input_tokens_chars_div_4"]) for row in items
        ),
        "items_sha256": canonical_sha256(items),
        "prompts_sha256": canonical_sha256(prompts),
        "negative_disposition": "DEFER_not_delete",
        "missing_or_invalid_packet_disposition": "BLOCKED_all_members",
    }
    _atomic_json(args.output_dir / "spec.json", spec)

    results: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                _call_with_retries,
                prompt,
                transport_retries=args.transport_retries,
                contract_retries=args.contract_retries,
                api_base=args.api_base,
                api_key=api_key,
                model=args.model,
                reasoning_effort=args.reasoning_effort,
                max_output_tokens=args.max_output_tokens,
                timeout=args.timeout,
                responses_dir=responses_dir,
            ): prompt
            for prompt in prompts
        }
        for completed_count, future in enumerate(as_completed(futures), start=1):
            result = future.result()
            results.append(result)
            print(
                f"  [{completed_count}/{len(prompts)}] "
                f"packet {result['sequence']} {result['result_status']}",
                flush=True,
            )
    results.sort(key=lambda row: int(row["sequence"]))
    _atomic_jsonl(args.output_dir / "results.jsonl", results)

    unit_by_key = {
        (
            str(row["advisory"]),
            str(row["repository_identity"]),
            str(row["candidate_sha"]),
        ): row
        for row in units
    }
    selected_unit_to_packet = {
        str(unit_id): str(packet["packet_id"])
        for packet in selected_packets
        for unit_id in packet["candidate_unit_ids"]
    }
    result_by_packet = {str(row["packet_id"]): row for row in results}
    item_by_packet = {str(row["packet_id"]): row for row in items}
    unit_result_index: dict[str, dict[str, object]] = {}
    for result in results:
        for raw in result.get("unit_results", []):
            assert isinstance(raw, dict)
            unit_result_index[str(raw["unit_id"])] = raw

    routes: list[dict[str, object]] = []
    for candidate in candidates:
        unit = unit_by_key[
            (
                str(candidate["advisory"]),
                str(candidate["repository_identity"]),
                str(candidate["sha"]),
            )
        ]
        unit_id = str(unit["unit_id"])
        packet_id = selected_unit_to_packet.get(unit_id)
        unit_causality = ""
        model_related_fix_ids: list[str] = []
        model_related_fix_shas: list[str] = []
        edge_specific_match = False
        if packet_id is None:
            disposition = "DEFER"
            causality = ""
            unit_signals = {str(signal) for signal in unit.get("signals", [])}
            outside_target = bool(
                candidate_sha_filter
                and str(candidate["sha"]).lower() not in candidate_sha_filter
            ) or bool(
                candidate_signal_filter
                and not set(candidate_signal_filter) <= unit_signals
            )
            if outside_target:
                reason = "outside_targeted_candidate_filter"
            else:
                reason = "outside_batch_routing_budget"
        else:
            packet_result = result_by_packet[packet_id]
            if packet_result["result_status"] != "completed":
                disposition = "BLOCKED"
                causality = ""
                reason = str(packet_result["reason"])
            else:
                unit_result = unit_result_index[unit_id]
                unit_causality = str(unit_result["causality"])
                causality = unit_causality
                reason = str(unit_result["reason"])
                if args.edge_specific:
                    raw_related = unit_result.get("related_fixes", [])
                    if not isinstance(raw_related, list):
                        raise SystemExit("edge-specific result lost related fixes")
                    model_related_fix_ids = [str(value) for value in raw_related]
                    item = item_by_packet[packet_id]
                    raw_fix_aliases = item.get("fix_aliases", [])
                    if not isinstance(raw_fix_aliases, list):
                        raise SystemExit("edge-specific item lost fix aliases")
                    fix_sha_by_alias = {
                        str(row["id"]): str(row["fix_sha"])
                        for row in raw_fix_aliases
                        if isinstance(row, Mapping)
                    }
                    fix_alias_by_sha = {
                        value: key for key, value in fix_sha_by_alias.items()
                    }
                    candidate_fix_sha = str(candidate["fix_sha"])
                    candidate_fix_alias = fix_alias_by_sha.get(candidate_fix_sha)
                    if candidate_fix_alias is None:
                        raise SystemExit(
                            "candidate fix is absent from edge-specific packet"
                        )
                    model_related_fix_shas = [
                        fix_sha_by_alias[value] for value in model_related_fix_ids
                    ]
                    edge_specific_match = (
                        candidate_fix_alias in model_related_fix_ids
                    )
                    if unit_causality == "insufficient":
                        disposition = "BLOCKED"
                    elif (
                        unit_causality in {"likely", "possible"}
                        and edge_specific_match
                    ):
                        disposition = "PROMOTE"
                    else:
                        disposition = "DEFER"
                        if unit_causality in {"likely", "possible"}:
                            causality = ""
                            reason = (
                                "candidate_promoted_for_other_fix_edges; "
                                f"unit_reason={reason}"
                            )
                elif causality in {"likely", "possible"}:
                    disposition = "PROMOTE"
                elif causality == "insufficient":
                    disposition = "BLOCKED"
                else:
                    disposition = "DEFER"
        routes.append(
            {
                "repository_identity": candidate["repository_identity"],
                "advisory": candidate["advisory"],
                "fix_sha": candidate["fix_sha"],
                "candidate_sha": candidate["sha"],
                "input_priority_rank": candidate["priority_rank"],
                "model": args.model,
                "disposition": disposition,
                "causality": causality,
                "unit_causality": unit_causality,
                "reason": reason,
                "edge_specific_routing": args.edge_specific,
                "edge_specific_match": edge_specific_match,
                "model_related_fix_ids": model_related_fix_ids,
                "model_related_fix_shas": model_related_fix_shas,
                "retained": True,
            }
        )
    if len(routes) != len(candidates):
        raise SystemExit("batch routes did not conserve candidate/fix pairs")
    _atomic_jsonl(args.output_dir / "routes.jsonl", routes)
    input_tokens = sum(
        int(row.get("usage", {}).get("input_tokens", 0))
        for row in results
        if isinstance(row.get("usage"), Mapping)
    )
    output_tokens = sum(
        int(row.get("usage", {}).get("output_tokens", 0))
        for row in results
        if isinstance(row.get("usage"), Mapping)
    )
    execution = {
        "schema_version": 1,
        "artifact_kind": "recall_safe_origin_ai_batch_route_execution",
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "routing_mode": spec["routing_mode"],
        "contributor_recall_gate": args.contributor_recall_gate,
        "label_neutral_input_required": args.require_label_neutral_input,
        "edge_specific": args.edge_specific,
        "selected_packet_count": len(results),
        "physical_model_calls": sum(int(row["attempt_count"]) for row in results),
        "parsed_count": sum(row["result_status"] == "completed" for row in results),
        "transport_or_parse_blocked_count": sum(
            row["result_status"] != "completed" for row in results
        ),
        "promoted_count": sum(row["disposition"] == "PROMOTE" for row in routes),
        "promoted_candidate_unit_count": len(
            {
                str(row["candidate_sha"])
                for row in routes
                if row["disposition"] == "PROMOTE"
            }
        ),
        "deferred_count": sum(row["disposition"] == "DEFER" for row in routes),
        "blocked_count": sum(row["disposition"] == "BLOCKED" for row in routes),
        "inventory_count": len(routes),
        "all_candidates_retained": all(row["retained"] is True for row in routes),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "results_sha256": canonical_sha256(results),
        "routes_sha256": canonical_sha256(routes),
    }
    _atomic_json(args.output_dir / "execution.json", execution)
    print("origin AI batch route frozen")
    print(f"  packets    : {len(results)}")
    print(f"  calls      : {execution['physical_model_calls']}")
    print(f"  units      : {spec['selected_candidate_unit_count']}")
    print(f"  parsed     : {execution['parsed_count']}")
    print(f"  tokens     : {input_tokens:,} in / {output_tokens:,} out")
    print(f"  retained   : {execution['all_candidates_retained']}")
    print(f"  output     : {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
