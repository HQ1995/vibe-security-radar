#!/usr/bin/env python3
"""Build a deduplicated ledger of mechanically bound AI-causal advisories."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path

from cohort.root_adjudication import canonical_sha256
from cohort_atomic_mechanism_review import _atomic_json, _atomic_jsonl, _jsonl


_PUBLIC_ID = re.compile(
    r"^(?:CVE-\d{4}-\d{4,}|GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4})$"
)
_REVIEW_VERDICTS = frozenset({"AI_CAUSAL", "NOT_AI_CAUSAL", "INCONCLUSIVE"})
_CLASS_STATUSES = frozenset({"PASS", "FAIL", "NEEDS_REVIEW", "BLOCKED"})
_ORIGIN_KINDS = frozenset(
    {"direct_commit", "squash_member", "upstream_atomic", "branch_copy"}
)
_ROUTING_KINDS = frozenset(
    {"repeated_model_mechanism_route", "cross_file_model_route"}
)
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_AI_MARKER = re.compile(
    r"(?:co[- ]?authored|generated with|claude|copilot|jules|rovo|codex|cursor|gemini|chatgpt|\[bot\])",
    re.IGNORECASE,
)


def _args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--alias-classes", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--witness", type=Path, action="append", default=[])
    parser.add_argument("--ranked-adjudications", type=Path)
    parser.add_argument("--class-adjudications", type=Path, required=True)
    parser.add_argument("--exclude-class", action="append", default=[])
    parser.add_argument("--review-support", type=int, default=2)
    parser.add_argument("--minimum-count", type=int, default=150)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _explicit_ai_signals(value: object) -> list[str]:
    """Return concrete AI-author/tool strings from an adjudication artifact."""

    signals: set[str] = set()
    if isinstance(value, Mapping):
        for child in value.values():
            signals.update(_explicit_ai_signals(child))
    elif isinstance(value, list):
        for child in value:
            signals.update(_explicit_ai_signals(child))
    elif isinstance(value, str) and _AI_MARKER.search(value):
        signals.add(value.strip())
    return sorted(signal for signal in signals if signal)


def _audit_record(path: Path, public_id: str) -> object:
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, list):
        matches = [
            row
            for row in value
            if isinstance(row, Mapping)
            and str(row.get("cve_id") or "").upper() == public_id
        ]
        if len(matches) != 1:
            raise SystemExit(f"audit record is not unique for {public_id}: {path}")
        return matches[0]
    return value


def _accepted_edges(value: object, class_id: str) -> list[dict[str, object]]:
    """Validate the exact causal edges admitted by a strict PASS."""

    if not isinstance(value, list) or not value:
        raise SystemExit(f"strict PASS lacks accepted edges: {class_id}")
    result: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for raw in value:
        if not isinstance(raw, Mapping):
            raise SystemExit(f"malformed accepted edge: {class_id}")
        candidate_sha = str(raw.get("candidate_sha") or "").lower()
        fix_sha = str(raw.get("fix_sha") or "").lower()
        origin_kind = str(raw.get("origin_kind") or "")
        ai_signal = str(raw.get("ai_signal") or "").strip()
        carrier_sha = str(raw.get("carrier_sha") or "").lower()
        if (
            not _SHA40.fullmatch(candidate_sha)
            or not _SHA40.fullmatch(fix_sha)
            or candidate_sha == fix_sha
            or origin_kind not in _ORIGIN_KINDS
            or not _AI_MARKER.search(ai_signal)
            or (carrier_sha and not _SHA40.fullmatch(carrier_sha))
            or carrier_sha == candidate_sha
            or (candidate_sha, fix_sha) in seen
        ):
            raise SystemExit(f"malformed accepted edge: {class_id}")
        edge: dict[str, object] = {
            "candidate_sha": candidate_sha,
            "fix_sha": fix_sha,
            "origin_kind": origin_kind,
            "ai_signal": ai_signal,
        }
        if carrier_sha:
            edge["carrier_sha"] = carrier_sha
        result.append(edge)
        seen.add((candidate_sha, fix_sha))
    return result


def _alias_index(path: Path) -> tuple[dict[str, list[str]], dict[str, str]]:
    members_by_class: dict[str, list[str]] = {}
    class_by_member: dict[str, str] = {}
    for row in _jsonl(path):
        class_id = str(row.get("class_id") or "")
        members = sorted({str(value).upper() for value in row.get("member_ids", [])})
        if not class_id or not members or class_id in members_by_class:
            raise SystemExit(f"malformed alias class: {class_id or '<missing>'}")
        members_by_class[class_id] = members
        for member in members:
            previous = class_by_member.setdefault(member, class_id)
            if previous != class_id:
                raise SystemExit(
                    f"public ID belongs to multiple alias classes: {member}"
                )
    return members_by_class, class_by_member


def review_edge_verdict_support(
    results_by_source: Mapping[str, Iterable[Mapping[str, object]]],
) -> dict[tuple[str, str, str], dict[str, set[str]]]:
    """Return every verdict source for each exact candidate/fix edge."""

    support: dict[tuple[str, str, str], dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )
    for source, rows in results_by_source.items():
        for row in rows:
            if row.get("status") != "COMPLETE":
                continue
            class_id = str(row.get("class_id") or "")
            for review in row.get("reviews", []):
                if not isinstance(review, Mapping):
                    continue
                verdict = str(review.get("verdict") or "")
                if verdict not in _REVIEW_VERDICTS:
                    continue
                key = (
                    class_id,
                    str(review.get("candidate_sha") or ""),
                    str(review.get("fix_sha") or ""),
                )
                if all(key):
                    support[key][verdict].add(source)
    return {key: dict(verdicts) for key, verdicts in support.items()}


def review_edge_support(
    results_by_source: Mapping[str, Iterable[Mapping[str, object]]],
) -> dict[tuple[str, str, str], set[str]]:
    """Compatibility view of positive sources; callers needing safety use all verdicts."""

    return {
        key: verdicts.get("AI_CAUSAL", set())
        for key, verdicts in review_edge_verdict_support(results_by_source).items()
        if verdicts.get("AI_CAUSAL")
    }


def _deepseek_review_support(
    campaign_dir: Path,
) -> tuple[dict[tuple[str, str, str], dict[str, set[str]]], dict[str, str]]:
    rows_by_source: dict[str, list[dict[str, object]]] = {}
    source_paths: dict[str, str] = {}
    for results_path in sorted(campaign_dir.glob("**/results.jsonl")):
        output_name = results_path.parent.name
        if "deepseek" not in output_name or "snapshot" in output_name:
            continue
        summary_path = results_path.with_name("summary.json")
        if not summary_path.is_file():
            continue
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        if (
            summary.get("model") != "deepseek-v4-flash"
            or summary.get("response_source") != "live_model_calls"
        ):
            continue
        source = _file_sha256(results_path)
        rows_by_source.setdefault(source, _jsonl(results_path))
        source_paths.setdefault(source, str(results_path))
    return review_edge_verdict_support(rows_by_source), source_paths


def _class_adjudications(
    path: Path, members_by_class: Mapping[str, list[str]]
) -> tuple[dict[str, dict[str, object]], Mapping[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, Mapping)
        or payload.get("schema_version") != 1
        or payload.get("artifact_kind")
        != "strict_atomic_ai_causal_class_adjudications"
    ):
        raise SystemExit("invalid strict class adjudication artifact")
    source_report = payload.get("source_report")
    if not isinstance(source_report, Mapping):
        raise SystemExit("strict class adjudications require a source report")
    report_path = Path(str(source_report.get("path") or ""))
    report_sha = str(source_report.get("sha256") or "")
    if not report_path.is_file() or _file_sha256(report_path) != report_sha:
        raise SystemExit("strict class adjudication source report does not match")
    rows = payload.get("adjudications")
    if not isinstance(rows, list):
        raise SystemExit("strict class adjudications require an adjudications list")
    result: dict[str, dict[str, object]] = {}
    seen_rows: set[int] = set()
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise SystemExit("malformed strict class adjudication")
        class_id = str(raw.get("class_id") or "")
        primary_id = str(raw.get("primary_id") or "").upper()
        status = str(raw.get("status") or "")
        reason = str(raw.get("reason") or "").strip()
        row_number = raw.get("row")
        if (
            class_id not in members_by_class
            or primary_id not in members_by_class[class_id]
            or status not in _CLASS_STATUSES
            or not reason
            or not isinstance(row_number, int)
            or isinstance(row_number, bool)
            or row_number < 1
            or class_id in result
            or row_number in seen_rows
        ):
            raise SystemExit(f"malformed strict class adjudication: {class_id}")
        accepted_edges = (
            _accepted_edges(raw.get("accepted_edges"), class_id)
            if status == "PASS"
            else []
        )
        if status != "PASS" and raw.get("accepted_edges"):
            raise SystemExit(f"non-PASS class has accepted edges: {class_id}")
        result[class_id] = {
            "class_id": class_id,
            "primary_id": primary_id,
            "status": status,
            "reason": reason,
            "row": row_number,
            "accepted_edges": accepted_edges,
        }
        seen_rows.add(row_number)
    return result, source_report


def _validated_packet_edges(
    campaign_dir: Path,
    required: set[tuple[str, str, str]],
) -> dict[tuple[str, str, str], dict[str, object]]:
    packet_ids: set[str] = set()
    # Restrict the expensive packet scan to IDs appearing in promoted reviews.
    for results_path in campaign_dir.glob("**/results.jsonl"):
        if (
            "deepseek" not in results_path.parent.name
            or "snapshot" in results_path.parent.name
        ):
            continue
        for row in _jsonl(results_path):
            class_id = str(row.get("class_id") or "")
            if any(key[0] == class_id for key in required):
                packet_id = str(row.get("packet_id") or "")
                if packet_id:
                    packet_ids.add(packet_id)

    validated: dict[tuple[str, str, str], dict[str, object]] = {}
    for packet_path in sorted(campaign_dir.glob("**/packets.jsonl")):
        for packet in _jsonl(packet_path):
            if str(packet.get("packet_id") or "") not in packet_ids:
                continue
            class_id = str(packet.get("class_id") or "")
            for candidate in packet.get("candidates", []):
                if not isinstance(candidate, Mapping):
                    continue
                key = (
                    class_id,
                    str(candidate.get("candidate_sha") or ""),
                    str(candidate.get("fix_sha") or ""),
                )
                if key not in required:
                    continue
                if (
                    candidate.get("atomicity") != "direct_commit_no_squash_inheritance"
                    or candidate.get("fix_source_evidence") != "public_exact"
                    or not candidate.get("ai_signal_types")
                    or not candidate.get("production_code_paths")
                ):
                    continue
                validated[key] = {
                    "packet_path": str(packet_path),
                    "packet_id": packet.get("packet_id"),
                    "member_ids": packet.get("member_ids", []),
                    "ai_signal_types": candidate.get("ai_signal_types", []),
                    "ai_tools": candidate.get("ai_tools", []),
                    "exact_blame_hit": candidate.get("exact_blame_hit") is True,
                }
    return validated


def _cross_file_evidence(campaign_dir: Path) -> dict[str, list[dict[str, object]]]:
    evidence: dict[str, list[dict[str, object]]] = defaultdict(list)
    for recall_dir in sorted(campaign_dir.glob("global-cross-file-deepseek-v*")):
        suffix = recall_dir.name.removeprefix("global-cross-file-deepseek-")
        strict_dir = campaign_dir / f"global-cross-file-strict-deepseek-{suffix}"
        base_dir = campaign_dir / f"global-cross-file-{suffix}"
        if (
            not (recall_dir / "routes.jsonl").is_file()
            or not (strict_dir / "routes.jsonl").is_file()
        ):
            continue
        units: dict[tuple[str, str, str], Mapping[str, object]] = {}
        for unit in _jsonl(base_dir / "packets" / "candidate_units.jsonl"):
            class_id = str(unit.get("advisory") or "")
            candidate_sha = str(unit.get("candidate_sha") or "")
            for edge in unit.get("fix_edges", []):
                if isinstance(edge, Mapping):
                    units[(class_id, candidate_sha, str(edge.get("fix_sha") or ""))] = (
                        unit
                    )
        recall = {
            (
                str(row.get("advisory") or ""),
                str(row.get("candidate_sha") or ""),
                str(row.get("fix_sha") or ""),
            )
            for row in _jsonl(recall_dir / "routes.jsonl")
            if row.get("disposition") == "PROMOTE"
        }
        for row in _jsonl(strict_dir / "routes.jsonl"):
            key = (
                str(row.get("advisory") or ""),
                str(row.get("candidate_sha") or ""),
                str(row.get("fix_sha") or ""),
            )
            unit = units.get(key)
            if (
                key not in recall
                or row.get("disposition") != "PROMOTE"
                or row.get("causality") != "likely"
                or not unit
                or unit.get("merge_topology") != "direct"
                or not unit.get("signal_types")
            ):
                continue
            evidence[key[0]].append(
                {
                    "kind": "cross_file_model_route",
                    "candidate_sha": key[1],
                    "fix_sha": key[2],
                    "ai_signal_types": unit.get("signal_types", []),
                    "ai_tools": unit.get("tools", []),
                    "recall_routes": str(recall_dir / "routes.jsonl"),
                    "strict_routes": str(strict_dir / "routes.jsonl"),
                    "reason": row.get("reason", ""),
                }
            )
    return evidence


def _resolve_public_ids(
    ids: Iterable[object], class_by_member: Mapping[str, str]
) -> str:
    classes = {
        class_by_member[value]
        for raw in ids
        if (value := str(raw).upper()) in class_by_member
        and _PUBLIC_ID.fullmatch(value)
    }
    if len(classes) != 1:
        raise SystemExit(
            f"public IDs do not resolve to one alias class: {sorted(classes)}"
        )
    return classes.pop()


def build(
    args: argparse.Namespace,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    members_by_class, class_by_member = _alias_index(args.alias_classes)
    evidence: dict[str, list[dict[str, object]]] = defaultdict(list)

    audit = json.loads(args.audit.read_text(encoding="utf-8"))
    audit_exclusions: dict[str, str] = {}
    for row in audit.get("adjudications", []):
        public_id = str(row.get("cve_id") or "").upper()
        label = str(row.get("label") or "")
        if not _PUBLIC_ID.fullmatch(public_id):
            continue
        class_id = _resolve_public_ids([public_id], class_by_member)
        if label in {"NOT_AI_CAUSAL", "INCONCLUSIVE"}:
            audit_exclusions[class_id] = label
            continue
        if label != "AI_CAUSAL":
            continue
        record_path = Path(str(row.get("source") or ""))
        if not record_path.is_file():
            raise SystemExit(f"audited positive record is missing: {record_path}")
        ai_signals = _explicit_ai_signals(_audit_record(record_path, public_id))
        if not ai_signals:
            raise SystemExit(f"audited positive lacks explicit AI signal: {public_id}")
        evidence[class_id].append(
            {
                "kind": "audited_positive",
                "source": str(args.audit),
                "record": str(record_path),
                "record_sha256": _file_sha256(record_path),
                "ai_signal_types": ["audited_commit_ai_attribution"],
                "ai_signal_evidence": ai_signals,
            }
        )

    for witness_path in args.witness:
        witness = json.loads(witness_path.read_text(encoding="utf-8"))
        if witness.get("verdict") != "AI_CAUSAL":
            continue
        ai_signals = _explicit_ai_signals(witness)
        if not ai_signals:
            raise SystemExit(f"differential witness lacks explicit AI signal: {witness_path}")
        class_id = _resolve_public_ids(witness.get("public_ids", []), class_by_member)
        evidence[class_id].append(
            {
                "kind": "differential_witness",
                "source": str(witness_path),
                "candidate_sha": witness.get("introduced_commit"),
                "fix_sha": witness.get("code_fix_commit"),
                "ai_signal_types": ["witnessed_commit_ai_attribution"],
                "ai_signal_evidence": ai_signals,
            }
        )

    if args.ranked_adjudications:
        ranked = json.loads(args.ranked_adjudications.read_text(encoding="utf-8"))
        for row in ranked.get("adjudications", []):
            if row.get("verdict") != "AI_CAUSAL":
                continue
            ai_signals = _explicit_ai_signals(row)
            if not ai_signals:
                raise SystemExit(
                    "ranked adjudication lacks explicit AI signal: "
                    f"{row.get('case_key')}"
                )
            class_id = str(row.get("alias_class_id") or "")
            if class_id not in members_by_class:
                class_id = _resolve_public_ids(
                    row.get("public_ids", []), class_by_member
                )
            evidence[class_id].append(
                {
                    "kind": "ranked_counterreview",
                    "source": str(args.ranked_adjudications),
                    "case_key": row.get("case_key"),
                    "ai_signal_types": ["counterreviewed_commit_ai_attribution"],
                    "ai_signal_evidence": ai_signals,
                }
            )

    verdict_support, source_paths = _deepseek_review_support(args.campaign_dir)
    routed_edges = {
        key
        for key, verdicts in verdict_support.items()
        if len(verdicts.get("AI_CAUSAL", set())) >= args.review_support
    }
    mixed_edges = {
        key
        for key in routed_edges
        if verdict_support[key].get("NOT_AI_CAUSAL")
        or verdict_support[key].get("INCONCLUSIVE")
    }
    conflict_free_edges = routed_edges - mixed_edges
    packet_evidence = _validated_packet_edges(args.campaign_dir, routed_edges)
    missing_packets = routed_edges - packet_evidence.keys()
    if missing_packets:
        raise SystemExit(
            f"promoted review edges lack mechanical packet evidence: {len(missing_packets)}"
        )
    for key in sorted(routed_edges):
        class_id, candidate_sha, fix_sha = key
        verdicts = verdict_support[key]
        evidence[class_id].append(
            {
                "kind": "repeated_model_mechanism_route",
                "candidate_sha": candidate_sha,
                "fix_sha": fix_sha,
                "review_sources": sorted(
                    source_paths[source]
                    for sources in verdicts.values()
                    for source in sources
                ),
                "verdict_source_counts": {
                    verdict: len(sources)
                    for verdict, sources in sorted(verdicts.items())
                },
                "mixed_verdicts": key in mixed_edges,
                **packet_evidence[key],
            }
        )

    for class_id, rows in _cross_file_evidence(args.campaign_dir).items():
        evidence[class_id].extend(rows)

    adjudications, adjudication_report = _class_adjudications(
        args.class_adjudications, members_by_class
    )
    manual_excluded = set(args.exclude_class)
    if manual_excluded - members_by_class.keys():
        raise SystemExit(
            "excluded unknown alias classes: "
            f"{sorted(manual_excluded - members_by_class.keys())}"
        )
    unknown_classes = set(evidence) - members_by_class.keys()
    if unknown_classes:
        raise SystemExit(
            f"evidence references unknown alias classes: {sorted(unknown_classes)}"
        )
    eligible_classes = {
        class_id
        for class_id in evidence
        if any(_PUBLIC_ID.fullmatch(value) for value in members_by_class[class_id])
    }
    missing_adjudications = (
        eligible_classes - manual_excluded - set(audit_exclusions) - set(adjudications)
    )
    if missing_adjudications:
        raise SystemExit(
            "strict ledger evidence lacks class adjudications: "
            f"{sorted(missing_adjudications)}"
        )
    confirmed_classes = {
        class_id
        for class_id, row in adjudications.items()
        if row["status"] == "PASS"
    }
    conflicts = confirmed_classes & set(audit_exclusions)
    if conflicts:
        raise SystemExit(
            "strict PASS conflicts with prior NOT/INCONCLUSIVE audit: "
            f"{sorted(conflicts)}"
        )
    missing_evidence = confirmed_classes - eligible_classes
    if missing_evidence:
        raise SystemExit(
            f"strict PASS lacks candidate evidence: {sorted(missing_evidence)}"
        )
    for class_id in confirmed_classes:
        row = adjudications[class_id]
        evidence[class_id].append(
            {
                "kind": "strict_class_adjudication",
                "source": str(args.class_adjudications),
                "source_report": dict(adjudication_report),
                "row": row["row"],
                "reason": row["reason"],
                "accepted_edges": row["accepted_edges"],
            }
        )
    excluded = manual_excluded | set(audit_exclusions) | (
        set(adjudications) - confirmed_classes
    )

    ledger: list[dict[str, object]] = []
    for class_id in sorted(set(evidence) - excluded):
        public_ids = [
            value for value in members_by_class[class_id] if _PUBLIC_ID.fullmatch(value)
        ]
        if not public_ids:
            continue
        primary = min(
            public_ids, key=lambda value: (not value.startswith("CVE-"), value)
        )
        ledger.append(
            {
                "class_id": class_id,
                "primary_id": primary,
                "public_ids": public_ids,
                "evidence": [
                    item
                    for item in evidence[class_id]
                    if item.get("kind") not in _ROUTING_KINDS
                ],
            }
        )

    evidence_counts = Counter(
        item["kind"] for row in ledger for item in row["evidence"]
    )
    summary: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "strict_atomic_ai_causal_vulnerability_ledger",
        "claim_boundary": (
            "One alias component per vulnerability. Model reviews and cross-file gates are routing "
            "evidence only; publication requires a fail-closed strict class adjudication grounded in "
            "the candidate parent delta, exact advisory mechanism, fix reversal, and commit-level AI "
            "signal. Squash or merge carriers never transfer attribution to members."
        ),
        "positive_alias_class_count": len(ledger),
        "minimum_count": args.minimum_count,
        "minimum_met": len(ledger) >= args.minimum_count,
        "public_id_count": sum(len(row["public_ids"]) for row in ledger),
        "cve_count": sum(
            value.startswith("CVE-") for row in ledger for value in row["public_ids"]
        ),
        "ghsa_count": sum(
            value.startswith("GHSA-") for row in ledger for value in row["public_ids"]
        ),
        "excluded_class_ids": sorted(excluded),
        "manual_excluded_class_ids": sorted(manual_excluded),
        "audit_exclusions": dict(sorted(audit_exclusions.items())),
        "class_adjudication_counts": dict(
            sorted(Counter(row["status"] for row in adjudications.values()).items())
        ),
        "evidence_counts": dict(sorted(evidence_counts.items())),
        "routed_model_edge_count": len(routed_edges),
        "mixed_model_edge_count": len(mixed_edges),
        "conflict_free_model_edge_count": len(conflict_free_edges),
        "inputs": {
            "alias_classes": {
                "path": str(args.alias_classes),
                "sha256": _file_sha256(args.alias_classes),
            },
            "audit": {"path": str(args.audit), "sha256": _file_sha256(args.audit)},
            "witnesses": [
                {"path": str(path), "sha256": _file_sha256(path)}
                for path in args.witness
            ],
            "ranked_adjudications": (
                {
                    "path": str(args.ranked_adjudications),
                    "sha256": _file_sha256(args.ranked_adjudications),
                }
                if args.ranked_adjudications
                else None
            ),
            "class_adjudications": {
                "path": str(args.class_adjudications),
                "sha256": _file_sha256(args.class_adjudications),
            },
        },
        "ledger_sha256": canonical_sha256(ledger),
    }
    return ledger, summary


def main(argv: list[str] | None = None) -> int:
    args = _args(argv)
    if args.review_support < 2:
        raise SystemExit("review support must be at least 2")
    ledger, summary = build(args)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    _atomic_jsonl(args.output_dir / "ledger.jsonl", ledger)
    _atomic_json(args.output_dir / "summary.json", summary)
    _atomic_jsonl(
        args.output_dir / "excluded.jsonl",
        (
            {
                "class_id": value,
                "reason": (
                    "manual_counterreview"
                    if value in summary["manual_excluded_class_ids"]
                    else summary["audit_exclusions"].get(
                        value,
                        "strict_class_adjudication_not_pass",
                    )
                ),
            }
            for value in summary["excluded_class_ids"]
        ),
    )
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["minimum_met"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
