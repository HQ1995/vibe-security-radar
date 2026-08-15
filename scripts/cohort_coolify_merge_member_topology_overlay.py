#!/usr/bin/env python3
"""Rank exact merge-member reversals without shrinking the recall universe.

The merge-member expansion conserves every candidate/member combination in
compressed bitsets.  This overlay joins its finite exact-reversal queue to the
complete Git-topology partition, separates atomic fixes from nested merges, and
selects one scheduling representative per observed-AI candidate.  No pair is
deleted and model labels never affect membership or rank.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from pathlib import Path


class MergeMemberTopologyError(ValueError):
    """An input artifact is malformed or violates lossless conservation."""


_SECURITY_RE = re.compile(
    r"\b(auth(?:orization|entication)?|permission|token|secret|credential|"
    r"webhook|hmac|inject(?:ion)?|escape|sanitize|scope|idor|xss|csrf|"
    r"path traversal|sudo|public network|private key)\b",
    re.IGNORECASE,
)
_GUARD_RE = re.compile(
    r"\b(validat(?:e|ion)|guard|check|restrict|prevent|deny|allow|filter|"
    r"locked|unique|policy|rule|safe|unsafe|null|empty|missing|required)\b",
    re.IGNORECASE,
)
_RUNTIME_RE = re.compile(
    r"\b(crash|freeze|timeout|restart|deploy|docker|proxy|traefik|database|"
    r"migration|queue|job|scheduler|lock|race|restore|backup|network|shell|"
    r"command|environment|parser|status|health|log)\b",
    re.IGNORECASE,
)
_UI_RE = re.compile(
    r"\b(ui|ux|view|modal|sidebar|button|layout|style|css|icon|color|"
    r"loading|scroll|navigation|dropdown|form)\b",
    re.IGNORECASE,
)
_SUBJECT_STOP_WORDS = frozenset(
    {
        "add",
        "and",
        "feat",
        "fix",
        "for",
        "from",
        "handle",
        "improve",
        "refactor",
        "resolve",
        "the",
        "use",
        "with",
    }
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--merge-member-dir", type=Path, required=True)
    parser.add_argument("--topology-closure-dir", type=Path, required=True)
    parser.add_argument("--census-dir", type=Path, required=True)
    parser.add_argument("--split-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MergeMemberTopologyError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise MergeMemberTopologyError(f"{path} must contain an object")
    return value


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise MergeMemberTopologyError(
                        f"{path}:{line_number} must contain an object"
                    )
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise MergeMemberTopologyError(f"cannot load {path}: {exc}") from exc
    return rows


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _atomic_jsonl(path: Path, rows: Iterable[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            for row in rows:
                stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
                stream.write("\n")
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _expected_digest(summary: Mapping[str, object], artifact: str) -> str | None:
    raw = summary.get("output_artifacts")
    if not isinstance(raw, Mapping):
        return None
    value = raw.get(artifact)
    if not isinstance(value, Mapping):
        return None
    digest = value.get("sha256")
    return str(digest) if digest else None


def _pair_relation(
    candidate_sha: str,
    commit_sha: str,
    *,
    ai_index: Mapping[str, int],
    topology_by_sha: Mapping[str, Mapping[str, object]],
) -> str:
    if candidate_sha not in ai_index:
        raise MergeMemberTopologyError(f"candidate absent from AI index: {candidate_sha}")
    row = topology_by_sha.get(commit_sha)
    if row is None:
        raise MergeMemberTopologyError(f"commit absent from topology: {commit_sha}")
    bit = 1 << ai_index[candidate_sha]
    fields = (
        ("strict_ai_ancestor_bitset_hex", "CANDIDATE_STRICT_ANCESTOR"),
        ("fix_precedes_ai_bitset_hex", "COMMIT_STRICT_ANCESTOR"),
        ("identity_bitset_hex", "IDENTITY"),
        ("incomparable_residual_bitset_hex", "INCOMPARABLE"),
    )
    matches = [
        label
        for field, label in fields
        if int(str(row.get(field) or "0"), 16) & bit
    ]
    if len(matches) != 1:
        raise MergeMemberTopologyError(
            f"topology partition is not singular for {candidate_sha}..{commit_sha}"
        )
    return matches[0]


def _subject(metadata: Mapping[str, object]) -> str:
    value = metadata.get("subject")
    return str(value) if value else ""


def _subject_tokens(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9]+", value.lower())
        if len(token) > 2 and token not in _SUBJECT_STOP_WORDS
    }


def _authored_gap_days(candidate: object, member: object) -> float | None:
    if not isinstance(candidate, str) or not isinstance(member, str):
        return None
    try:
        gap = (datetime.fromisoformat(member) - datetime.fromisoformat(candidate)).total_seconds()
    except ValueError:
        return None
    return gap / 86_400 if gap >= 0 else None


def _semantic_lanes(
    row: Mapping[str, object],
    *,
    candidate_subject: str,
    member_subject: str,
) -> list[str]:
    raw_sample = row.get("exact_reversal_sample")
    sample = raw_sample if isinstance(raw_sample, list) else []
    paths = " ".join(
        str(value.get("path") or "") for value in sample if isinstance(value, Mapping)
    )
    excerpts = " ".join(
        str(value.get("content_excerpt") or "")
        for value in sample
        if isinstance(value, Mapping)
    )
    text = f"{candidate_subject}\n{member_subject}\n{paths}\n{excerpts}"
    lanes: list[str] = []
    if member_subject.lower().startswith("revert"):
        lanes.append("EXPLICIT_REVERT")
    if _SECURITY_RE.search(text):
        lanes.append("SECURITY_OR_AUTHORIZATION")
    if _GUARD_RE.search(text) or any(
        value.get("control_like") is True
        for value in sample
        if isinstance(value, Mapping)
    ):
        lanes.append("GUARD_OR_VALIDATION_CHANGE")
    if _RUNTIME_RE.search(text):
        lanes.append("RUNTIME_OR_RELIABILITY")
    if _UI_RE.search(text):
        lanes.append("UI_OR_INTERACTION")
    return lanes or ["GENERAL_SEMANTIC_CHANGE"]


def _priority_score(row: Mapping[str, object]) -> int:
    topology = str(row["member_topology_class"])
    score = {
        "T0_DIRECT_MEMBER_AFTER_CANDIDATE": 8_000,
        "T1_MEMBER_LANDED_ON_CANDIDATE_FIRST_PARENT": 6_000,
        "T2_LATER_CARRIER_WITHOUT_FIRST_PARENT_ALIGNMENT": 4_000,
        "T3_INCOMPARABLE_CARRIER_RESCUE": 2_000,
        "T4_ALL_CARRIERS_PRECEDE_OR_EQUAL_CANDIDATE": 500,
        "T5_IDENTITY_MEMBER": 0,
    }[topology]
    if row.get("member_kind") == "atomic_or_root":
        score += 5_000
    lanes = set(row["semantic_lanes"])
    if "EXPLICIT_REVERT" in lanes:
        score += 2_500
    if str(row.get("member_fix_subject") or "").lower().startswith("fix"):
        score += 1_200
    if "SECURITY_OR_AUTHORIZATION" in lanes:
        score += 1_000
    if "GUARD_OR_VALIDATION_CHANGE" in lanes:
        score += 900
    score += min(int(row.get("control_like_reversal_count") or 0), 8) * 100
    score += min(int(row.get("exact_reversal_line_count") or 0), 12) * 30
    score -= min(int(row.get("generated_reversal_count") or 0), 4) * 300
    if int(row.get("exact_reversal_line_count") or 0) > 100:
        score -= 500
    overlap_count = int(row.get("subject_token_overlap_count") or 0)
    score += min(overlap_count, 4) * 250
    gap_days = row.get("authored_gap_days")
    if isinstance(gap_days, (int, float)):
        if gap_days <= 1:
            score += 800
        elif gap_days <= 7:
            score += 500
        elif gap_days <= 30:
            score += 300
        elif gap_days <= 90:
            score += 100
    member_fanout = int(row.get("member_exact_candidate_fanout") or 0)
    candidate_fanout = int(row.get("candidate_exact_member_count") or 0)
    score += 500 if member_fanout == 1 else 250 if member_fanout <= 3 else 100 if member_fanout <= 10 else 0
    score += 500 if candidate_fanout == 1 else 250 if candidate_fanout <= 3 else 100 if candidate_fanout <= 8 else 0
    return score


def build_overlay(
    *,
    exact_rows: Sequence[Mapping[str, object]],
    inventory_rows: Sequence[Mapping[str, object]],
    ai_shas: Sequence[str],
    topology_rows: Sequence[Mapping[str, object]],
    commit_rows: Sequence[Mapping[str, object]],
    split_id: str,
    repository_identity: str,
    compressed_pair_count: int,
) -> dict[str, object]:
    if not split_id.strip() or not exact_rows:
        raise MergeMemberTopologyError("split_id and exact rows are required")
    if list(ai_shas) != sorted(set(ai_shas)):
        raise MergeMemberTopologyError("AI SHAs must be sorted and unique")
    ai_index = {sha: index for index, sha in enumerate(ai_shas)}
    topology_by_sha = {str(row.get("sha") or ""): row for row in topology_rows}
    metadata_by_sha = {str(row.get("sha") or ""): row for row in commit_rows}
    inventory_by_merge = {
        str(row.get("merge_sha") or ""): row for row in inventory_rows
    }
    if len(topology_by_sha) != len(topology_rows):
        raise MergeMemberTopologyError("duplicate topology rows")

    enriched: list[dict[str, object]] = []
    topology_counts: Counter[str] = Counter()
    relation_counts: Counter[str] = Counter()
    lane_pair_counts: Counter[str] = Counter()
    for raw in exact_rows:
        row = dict(raw)
        candidate = str(row.get("candidate_sha") or "")
        member = str(row.get("member_fix_sha") or "")
        if candidate not in metadata_by_sha or member not in metadata_by_sha:
            raise MergeMemberTopologyError("exact pair metadata is incomplete")
        relation = _pair_relation(
            candidate,
            member,
            ai_index=ai_index,
            topology_by_sha=topology_by_sha,
        )
        raw_carriers = row.get("merge_carrier_shas")
        if not isinstance(raw_carriers, list) or not raw_carriers:
            raise MergeMemberTopologyError("exact pair has no merge carrier")
        carrier_relations: Counter[str] = Counter()
        first_parent_relations: Counter[str] = Counter()
        alignment_sample: list[dict[str, str]] = []
        for raw_carrier in raw_carriers:
            carrier = str(raw_carrier)
            inventory = inventory_by_merge.get(carrier)
            if inventory is None:
                raise MergeMemberTopologyError(f"carrier absent from inventory: {carrier}")
            first_parent = str(inventory.get("first_parent_sha") or "")
            carrier_relation = _pair_relation(
                candidate,
                carrier,
                ai_index=ai_index,
                topology_by_sha=topology_by_sha,
            )
            first_relation = _pair_relation(
                candidate,
                first_parent,
                ai_index=ai_index,
                topology_by_sha=topology_by_sha,
            )
            carrier_relations[carrier_relation] += 1
            first_parent_relations[first_relation] += 1
            if len(alignment_sample) < 12:
                alignment_sample.append(
                    {
                        "carrier_sha": carrier,
                        "first_parent_sha": first_parent,
                        "candidate_to_carrier_relation": carrier_relation,
                        "candidate_to_first_parent_relation": first_relation,
                    }
                )
        aligned = (
            first_parent_relations["CANDIDATE_STRICT_ANCESTOR"]
            + first_parent_relations["IDENTITY"]
        )
        later_carriers = carrier_relations["CANDIDATE_STRICT_ANCESTOR"]
        if relation == "CANDIDATE_STRICT_ANCESTOR":
            topology_class = "T0_DIRECT_MEMBER_AFTER_CANDIDATE"
        elif relation == "IDENTITY":
            topology_class = "T5_IDENTITY_MEMBER"
        elif aligned:
            topology_class = "T1_MEMBER_LANDED_ON_CANDIDATE_FIRST_PARENT"
        elif later_carriers:
            topology_class = "T2_LATER_CARRIER_WITHOUT_FIRST_PARENT_ALIGNMENT"
        elif carrier_relations["INCOMPARABLE"]:
            topology_class = "T3_INCOMPARABLE_CARRIER_RESCUE"
        else:
            topology_class = "T4_ALL_CARRIERS_PRECEDE_OR_EQUAL_CANDIDATE"

        candidate_metadata = metadata_by_sha[candidate]
        member_metadata = metadata_by_sha[member]
        candidate_subject = _subject(candidate_metadata)
        member_subject = _subject(member_metadata)
        candidate_tokens = _subject_tokens(candidate_subject)
        member_tokens = _subject_tokens(member_subject)
        shared_tokens = sorted(candidate_tokens & member_tokens)
        raw_sample = row.get("exact_reversal_sample")
        sample = raw_sample if isinstance(raw_sample, list) else []
        control_count = sum(
            value.get("control_like") is True
            for value in sample
            if isinstance(value, Mapping)
        )
        generated_count = sum(
            value.get("generated_or_machine_artifact") is True
            for value in sample
            if isinstance(value, Mapping)
        )
        row.update(
            {
                "candidate_subject": candidate_subject,
                "candidate_authored_at": candidate_metadata.get("authored_at"),
                "member_fix_subject": member_subject,
                "member_fix_authored_at": member_metadata.get("authored_at"),
                "authored_gap_days": _authored_gap_days(
                    candidate_metadata.get("authored_at"),
                    member_metadata.get("authored_at"),
                ),
                "subject_token_overlap_count": len(shared_tokens),
                "subject_token_overlap_tokens": shared_tokens,
                "candidate_to_member_relation": relation,
                "member_topology_class": topology_class,
                "candidate_aligned_first_parent_carrier_count": aligned,
                "candidate_later_carrier_count": later_carriers,
                "carrier_relation_counts": dict(sorted(carrier_relations.items())),
                "first_parent_relation_counts": dict(
                    sorted(first_parent_relations.items())
                ),
                "carrier_alignment_sample": alignment_sample,
                "carrier_alignment_sample_truncated": len(raw_carriers)
                > len(alignment_sample),
                "control_like_reversal_count": control_count,
                "generated_reversal_count": generated_count,
            }
        )
        lanes = _semantic_lanes(
            row,
            candidate_subject=candidate_subject,
            member_subject=member_subject,
        )
        row["semantic_lanes"] = lanes
        row["retained"] = True
        enriched.append(row)
        topology_counts[topology_class] += 1
        relation_counts[relation] += 1
        lane_pair_counts.update(lanes)

    candidate_pair_counts = Counter(str(row["candidate_sha"]) for row in enriched)
    member_candidate_sets: defaultdict[str, set[str]] = defaultdict(set)
    for row in enriched:
        member_candidate_sets[str(row["member_fix_sha"])].add(
            str(row["candidate_sha"])
        )
    for row in enriched:
        candidate = str(row["candidate_sha"])
        member = str(row["member_fix_sha"])
        row["candidate_exact_member_count"] = candidate_pair_counts[candidate]
        row["member_exact_candidate_fanout"] = len(member_candidate_sets[member])
        row["review_priority_score_v2"] = _priority_score(row)

    enriched.sort(
        key=lambda row: (
            -int(row["review_priority_score_v2"]),
            str(row["candidate_sha"]),
            str(row["member_fix_sha"]),
        )
    )
    for rank, row in enumerate(enriched, start=1):
        row["topology_review_rank"] = rank

    by_candidate: defaultdict[str, list[dict[str, object]]] = defaultdict(list)
    for row in enriched:
        by_candidate[str(row["candidate_sha"])].append(row)
    frontier: list[dict[str, object]] = []
    for candidate, rows in by_candidate.items():
        best = dict(rows[0])
        best["candidate_exact_pair_count"] = len(rows)
        best["candidate_atomic_exact_pair_count"] = sum(
            row.get("member_kind") == "atomic_or_root" for row in rows
        )
        best["candidate_nested_exact_pair_count"] = sum(
            row.get("member_kind") != "atomic_or_root" for row in rows
        )
        best["candidate_frontier_representative"] = True
        frontier.append(best)
    frontier.sort(
        key=lambda row: (
            -int(row["review_priority_score_v2"]),
            str(row["candidate_sha"]),
        )
    )
    lane_ranks: Counter[str] = Counter()
    for rank, row in enumerate(frontier, start=1):
        row["candidate_global_rank"] = rank
        primary = str(row["semantic_lanes"][0])
        lane_ranks[primary] += 1
        row["primary_lane"] = primary
        row["candidate_lane_rank"] = lane_ranks[primary]

    candidate_lane_counts = Counter(str(row["primary_lane"]) for row in frontier)
    if len(enriched) != len(exact_rows) or len(frontier) != len(by_candidate):
        raise MergeMemberTopologyError("overlay conservation failed")
    summary = {
        "schema_version": 1,
        "artifact_kind": "coolify_merge_member_topology_overlay",
        "split_id": split_id,
        "repository_identity": repository_identity,
        "compressed_candidate_member_pair_count_unchanged": compressed_pair_count,
        "input_exact_pair_count": len(exact_rows),
        "retained_exact_pair_count": len(enriched),
        "unique_exact_candidate_count": len(by_candidate),
        "candidate_frontier_count": len(frontier),
        "candidate_to_member_relation_counts": dict(sorted(relation_counts.items())),
        "member_topology_class_counts": dict(sorted(topology_counts.items())),
        "member_kind_counts": dict(
            sorted(Counter(str(row.get("member_kind")) for row in enriched).items())
        ),
        "semantic_lane_pair_counts": dict(sorted(lane_pair_counts.items())),
        "candidate_primary_lane_counts": dict(sorted(candidate_lane_counts.items())),
        "all_exact_pairs_conserved": len(enriched) == len(exact_rows),
        "all_exact_candidates_scheduled": len(frontier) == len(by_candidate),
        "hard_filter_count": 0,
        "model_labels_used_for_membership_or_rank": 0,
        "claim_boundary": (
            "Topology and exact reverse lines create a finite review schedule, not "
            "causal labels. Every exact pair remains retained, every candidate gets "
            "a frontier representative, and the larger compressed member universe "
            "is unchanged. Nested merges, broad refactors, common lines, and branch "
            "landings still require semantic adjudication."
        ),
    }
    return {"summary": summary, "exact_rows": enriched, "frontier": frontier}


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise SystemExit(f"output directory already exists: {output_dir}")
    merge_dir = args.merge_member_dir.resolve()
    topology_dir = args.topology_closure_dir.resolve()
    census_dir = args.census_dir.resolve()
    merge_summary_path = merge_dir / "summary.json"
    exact_path = merge_dir / "exact_member_review_queue.jsonl"
    inventory_path = merge_dir / "merge_member_inventory.jsonl"
    topology_summary_path = topology_dir / "summary.json"
    topology_index_path = topology_dir / "ai_index.json"
    topology_rows_path = topology_dir / "pair_partition.jsonl"
    commits_path = census_dir / "all_commits.jsonl"
    merge_summary = _load_json(merge_summary_path)
    topology_summary = _load_json(topology_summary_path)
    topology_index = _load_json(topology_index_path)
    if merge_summary.get("all_recoverable_member_pairs_compressed") is not True:
        raise SystemExit("merge-member input is not lossless")
    if merge_summary.get("hard_filter_count") != 0:
        raise SystemExit("merge-member input used a hard filter")
    for key, path in (
        ("exact_member_review_queue", exact_path),
        ("merge_member_inventory", inventory_path),
    ):
        if _expected_digest(merge_summary, key) != _sha256(path):
            raise SystemExit(f"merge-member {key} checksum drift")
    for key, path in (
        ("ai_index", topology_index_path),
        ("pair_partition", topology_rows_path),
    ):
        if _expected_digest(topology_summary, key) != _sha256(path):
            raise SystemExit(f"topology {key} checksum drift")
    raw_source = topology_summary.get("source_artifacts")
    expected_commits = (
        raw_source.get("all_commits", {}).get("sha256")
        if isinstance(raw_source, Mapping)
        and isinstance(raw_source.get("all_commits"), Mapping)
        else None
    )
    if expected_commits != _sha256(commits_path):
        raise SystemExit("census all-commit checksum drift")
    repository_identity = str(merge_summary.get("repository_identity") or "")
    if repository_identity != str(topology_summary.get("repository_identity") or ""):
        raise SystemExit("repository identity drift")
    raw_ai_shas = topology_index.get("ai_shas")
    if not isinstance(raw_ai_shas, list):
        raise SystemExit("topology AI index is malformed")
    payload = build_overlay(
        exact_rows=_load_jsonl(exact_path),
        inventory_rows=_load_jsonl(inventory_path),
        ai_shas=[str(value) for value in raw_ai_shas],
        topology_rows=_load_jsonl(topology_rows_path),
        commit_rows=_load_jsonl(commits_path),
        split_id=args.split_id,
        repository_identity=repository_identity,
        compressed_pair_count=int(
            merge_summary.get("compressed_unique_candidate_member_pair_count") or 0
        ),
    )
    exact_output = output_dir / "exact_member_topology_queue.jsonl"
    frontier_output = output_dir / "candidate_review_frontier.jsonl"
    summary_output = output_dir / "summary.json"
    _atomic_jsonl(exact_output, payload["exact_rows"])
    _atomic_jsonl(frontier_output, payload["frontier"])
    summary = dict(payload["summary"])
    summary["source_artifacts"] = {
        "merge_member_summary": {
            "path": str(merge_summary_path),
            "sha256": _sha256(merge_summary_path),
        },
        "topology_summary": {
            "path": str(topology_summary_path),
            "sha256": _sha256(topology_summary_path),
        },
    }
    summary["output_artifacts"] = {
        "exact_member_topology_queue": {
            "path": str(exact_output),
            "sha256": _sha256(exact_output),
        },
        "candidate_review_frontier": {
            "path": str(frontier_output),
            "sha256": _sha256(frontier_output),
        },
    }
    _atomic_json(summary_output, summary)
    print("Coolify merge-member topology overlay frozen")
    print(f"  exact pairs retained : {summary['retained_exact_pair_count']}")
    print(f"  candidate frontier   : {summary['candidate_frontier_count']}")
    print(f"  topology classes     : {summary['member_topology_class_counts']}")
    print(f"  output               : {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
