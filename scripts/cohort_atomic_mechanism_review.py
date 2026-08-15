#!/usr/bin/env python3
"""Prepare and review public-exact advisory packets for atomic AI causality."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import time
import zipfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import httpx

from cohort.root_adjudication import canonical_sha256
from cohort_ai_routing_pilot import (
    _commit_view,
    _is_loopback_api_base,
    _usage_counts,
    _validate_response_provenance,
)
from cve_analyzer.llm_client import extract_response_text


DEFAULT_API_BASE = "http://127.0.0.1:8317/v1"
DEFAULT_CVELIST_DIR = Path.home() / ".cache/cve-analyzer/cvelistV5/cves"
DEFAULT_GHSA_DIR = Path.home() / ".cache/cve-analyzer/advisory-database/advisories"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_CODE_PATH_RE = re.compile(
    r"\.(?:bash|c|cc|cpp|cs|go|h|hpp|html|java|js|json|jsx|kt|php|py|rb|rs|sh|sql|svelte|swift|toml|ts|tsx|vue|xml|yaml|yml)$",
    re.IGNORECASE,
)
_NON_PRODUCTION_PATH_RE = re.compile(
    r"(?:^|/)(?:__tests__|docs?|test|tests)(?:/|$)|"
    r"\.(?:spec|test)\.|"
    r"(?:^|/)(?:changelog|readme)(?:\.[^/]*)?$|"
    r"(?:^|/)(?:package-lock\.json|pnpm-lock\.ya?ml)$",
    re.IGNORECASE,
)
_FEATURE_SUBJECT_RE = re.compile(
    r"^(?:add|build|create|feat|implement|initial|introduce|support)(?:[(: !]|$)",
    re.IGNORECASE,
)
_VERDICTS = {"AI_CAUSAL", "NOT_AI_CAUSAL", "INCONCLUSIVE"}
_MAX_ATTEMPTS = 6
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}

SYSTEM_PROMPT = """\
You are a strict software-security provenance reviewer. The supplied Git and
advisory evidence mechanically establishes a public exact fix, ancestry, and an
explicit AI signal on each atomic candidate commit. Those facts do not establish
causality by themselves.

Use AI_CAUSAL only when the candidate's own parent-to-candidate delta introduces
or materially extends a concrete vulnerable behavior that the exact later fix
repairs. A new caller, route, input path, unsafe default, incomplete hardening,
or vulnerable feature extension can qualify when the shown code establishes the
chain. Shared files, chronology, tests, docs, blame context, and an AI trailer
alone never qualify. OSV routing fallback is not origin evidence and may be stale;
prefer CVEList/GHSA wording when present. Use NOT_AI_CAUSAL only when the evidence
affirmatively shows an incidental or unrelated change. Use INCONCLUSIVE whenever unseen history,
truncated code, or ambiguous semantics are needed. Review every pair independently
and return only the requested JSON object.
"""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--same-file-candidates", type=Path, required=True)
    prepare.add_argument("--exact-blame-candidates", type=Path, required=True)
    prepare.add_argument("--atomic-ai-units", type=Path, required=True)
    prepare.add_argument("--cvelist-dir", type=Path, default=DEFAULT_CVELIST_DIR)
    prepare.add_argument("--ghsa-dir", type=Path, default=DEFAULT_GHSA_DIR)
    prepare.add_argument("--osv-zip", type=Path)
    prepare.add_argument("--repository-path", type=Path, required=True)
    prepare.add_argument("--max-candidates-per-class", type=int, default=2)
    prepare.add_argument(
        "--candidate-order",
        choices=("exact-recent", "feature-first"),
        default="exact-recent",
    )
    prepare.add_argument("--diff-chars", type=int, default=12_000)
    prepare.add_argument("--details-chars", type=int, default=10_000)
    prepare.add_argument("--output-dir", type=Path, required=True)

    review = subparsers.add_parser("review")
    review.add_argument("--packet-dir", type=Path, required=True)
    review.add_argument("--model", required=True)
    review.add_argument(
        "--reasoning-effort",
        choices=("low", "medium", "high", "max", "model-controlled"),
        required=True,
    )
    review.add_argument("--api-base", default=DEFAULT_API_BASE)
    review.add_argument("--api-key-env", default="CLIPROXY_API_KEY")
    review.add_argument("--workers", type=int, default=4)
    review.add_argument("--max-output-tokens", type=int, default=5000)
    review.add_argument("--timeout", type=float, default=300)
    review.add_argument("--class-id", action="append", default=[])
    review.add_argument(
        "--input-responses-dir",
        type=Path,
        help="reparse preserved raw responses instead of calling the model",
    )
    review.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise SystemExit(f"{path}:{line_number} is not an object")
            rows.append(row)
    return rows


def _load_packets(packet_dir: Path) -> list[dict[str, object]]:
    """Load one packet set or the repository-partitioned sets beneath it."""

    summaries = [packet_dir / "summary.json"]
    if not (packet_dir / "packets.jsonl").is_file():
        summaries = sorted(packet_dir.glob("*/summary.json"))
    if not summaries:
        raise SystemExit("packet directory has no packet sets")
    packets: list[dict[str, object]] = []
    for summary_path in summaries:
        packet_path = summary_path.with_name("packets.jsonl")
        if not packet_path.is_file():
            raise SystemExit(f"packet file is missing: {packet_path}")
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        rows = _jsonl(packet_path)
        if canonical_sha256(rows) != summary.get("packets_sha256"):
            raise SystemExit(f"packet digest mismatch: {packet_path}")
        packets.extend(rows)
    return packets


def _filter_packets(
    packets: list[dict[str, object]], class_ids: Iterable[str]
) -> list[dict[str, object]]:
    wanted = set(class_ids)
    if not wanted:
        return packets
    selected = [row for row in packets if str(row.get("class_id") or "") in wanted]
    missing = wanted - {str(row.get("class_id") or "") for row in selected}
    if missing:
        raise SystemExit(f"requested classes have no packets: {sorted(missing)}")
    return selected


def _atomic_json(path: Path, value: object) -> None:
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


def _atomic_jsonl(path: Path, rows: Iterable[Mapping[str, object]]) -> None:
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


def _is_code_path(path: str) -> bool:
    return bool(_CODE_PATH_RE.search(path)) and not _NON_PRODUCTION_PATH_RE.search(path)


def select_candidates(
    rows: Iterable[Mapping[str, object]],
    *,
    exact_keys: set[tuple[str, str, str]],
    units: Mapping[str, Mapping[str, object]],
    max_per_class: int,
    candidate_order: str = "exact-recent",
) -> dict[str, list[dict[str, object]]]:
    """Select direct atomic candidates, preferring exact blame and recent code overlap."""

    grouped: defaultdict[str, list[dict[str, object]]] = defaultdict(list)
    for raw in rows:
        candidate_sha = str(raw.get("candidate_sha") or "")
        class_id = str(raw.get("class_id") or "")
        fix_sha = str(raw.get("fix_sha") or "")
        relation = str(raw.get("relation") or "")
        unit = units.get(candidate_sha)
        unit_topology = str(unit.get("merge_topology") or "") if unit else ""
        code_paths = sorted(
            path
            for path in {str(value) for value in raw.get("overlapping_files", [])}
            if _is_code_path(path)
        )
        if (
            relation not in {
                "reachable_ancestor",
                "pull_request_member_landed_as_squash_then_reachable_ancestor",
            }
            or (
                relation.startswith("pull_request_member_")
                and (
                    not raw.get("landed_squash_sha")
                    or not raw.get("origin_relation_id")
                )
            )
            or unit is None
            or (
                relation == "reachable_ancestor"
                and unit_topology != "direct"
            )
            or (
                relation.startswith("pull_request_member_")
                and unit_topology not in {"direct", "pull_request_member"}
            )
            or not unit.get("signal_types")
            or not code_paths
        ):
            continue
        row = dict(raw)
        row["production_code_paths"] = code_paths
        row["exact_blame_hit"] = (class_id, fix_sha, candidate_sha) in exact_keys
        row["candidate_authored_date"] = str(unit.get("authored_date") or "")
        row["atomicity"] = (
            "resolved_pull_request_member_commit_no_carrier_inheritance"
            if relation.startswith("pull_request_member_")
            else "direct_commit_no_squash_inheritance"
        )
        row["feature_introduction"] = bool(
            _FEATURE_SUBJECT_RE.match(str(unit.get("message") or "").partition("\n")[0])
        )
        grouped[class_id].append(row)

    selected: dict[str, list[dict[str, object]]] = {}
    for class_id, candidates in grouped.items():
        if candidate_order == "feature-first":
            candidates.sort(
                key=lambda row: (
                    row["feature_introduction"] is not True,
                    row["exact_blame_hit"] is not True,
                    str(row["candidate_authored_date"]),
                    str(row["candidate_sha"]),
                    str(row["fix_sha"]),
                )
            )
        else:
            candidates.sort(
                key=lambda row: (
                    row["exact_blame_hit"] is True,
                    len(row["production_code_paths"]),
                    str(row["candidate_authored_date"]),
                    str(row["candidate_sha"]),
                    str(row["fix_sha"]),
                ),
                reverse=True,
            )
        selected[class_id] = candidates[:max_per_class]
    return selected


def _osv_records(
    path: Path, public_ids: Iterable[str] | None = None
) -> dict[str, dict[str, object]]:
    wanted = {value.upper() for value in public_ids or ()}
    by_id: dict[str, dict[str, object]] = {}
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if not name.endswith(".json") or (
                wanted and Path(name).stem.upper() not in wanted
            ):
                continue
            record = json.loads(archive.read(name))
            if not isinstance(record, dict):
                continue
            ids = [record.get("id"), *record.get("aliases", [])]
            for public_id in ids:
                if isinstance(public_id, str) and public_id:
                    by_id[public_id.upper()] = record
    return by_id


def _cvelist_record(root: Path, public_id: str) -> dict[str, object] | None:
    match = re.fullmatch(r"CVE-(\d{4})-(\d+)", public_id.upper())
    if match is None:
        return None
    year, number = match.groups()
    group = "0xxx" if len(number) <= 3 else f"{number[:-3]}xxx"
    path = root / year / group / f"CVE-{year}-{number}.json"
    if not path.is_file():
        return None
    record = json.loads(path.read_text(encoding="utf-8"))
    cna = record.get("containers", {}).get("cna", {})
    descriptions = cna.get("descriptions", [])
    description = next(
        (
            str(row.get("value") or "")
            for row in descriptions
            if str(row.get("lang") or "").startswith("en")
        ),
        str(descriptions[0].get("value") or "") if descriptions else "",
    )
    cwes = sorted(
        {
            str(item.get("cweId"))
            for problem in cna.get("problemTypes", [])
            for item in problem.get("descriptions", [])
            if item.get("cweId")
        }
    )
    return {
        "id": public_id.upper(),
        "aliases": [],
        "summary": str(cna.get("title") or ""),
        "details": description,
        "severity": None,
        "cwe_ids": cwes,
        "references": [
            str(row.get("url")) for row in cna.get("references", []) if row.get("url")
        ],
        "source": "cvelist_cna",
        "active": str(record.get("cveMetadata", {}).get("state") or "").upper()
        == "PUBLISHED",
    }


def _ghsa_record(root: Path, public_id: str) -> dict[str, object] | None:
    if not public_id.upper().startswith("GHSA-"):
        return None
    name = "GHSA-" + public_id[5:].lower()
    matches = [
        path
        for subdir in ("github-reviewed", "unreviewed")
        for path in (root / subdir).glob(f"*/*/{name}/{name}.json")
    ]
    if not matches:
        return None
    path = matches[0]
    record = json.loads(path.read_text(encoding="utf-8"))
    return {
        "id": str(record.get("id") or public_id).upper(),
        "aliases": [str(value).upper() for value in record.get("aliases", [])],
        "summary": str(record.get("summary") or ""),
        "details": str(record.get("details") or ""),
        "severity": record.get("database_specific", {}).get("severity"),
        "cwe_ids": record.get("database_specific", {}).get("cwe_ids", []),
        "references": [
            str(row.get("url")) for row in record.get("references", []) if row.get("url")
        ],
        "source": (
            "github_advisory_database_reviewed"
            if "github-reviewed" in path.parts
            else "github_advisory_database_unreviewed"
        ),
        "active": not bool(record.get("withdrawn")),
    }


def _first_party_records(
    cvelist_dir: Path, ghsa_dir: Path, public_ids: Iterable[str]
) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for public_id in sorted({value.upper() for value in public_ids}):
        record = _cvelist_record(cvelist_dir, public_id) or _ghsa_record(
            ghsa_dir, public_id
        )
        if record is not None:
            records[public_id] = record
    return records


def _advisory_records(
    member_ids: Iterable[str],
    first_party_by_id: Mapping[str, Mapping[str, object]],
    osv_by_id: Mapping[str, Mapping[str, object]],
) -> tuple[list[dict[str, object]], str, str | None]:
    ids = [value.upper() for value in member_ids]
    first_party = {
        (str(record.get("source") or ""), str(record.get("id") or public_id)): dict(
            record
        )
        for public_id in ids
        if (record := first_party_by_id.get(public_id)) is not None
    }
    active = [record for record in first_party.values() if record.get("active")]
    if active:
        return active, "first_party", None
    if first_party:
        return [], "inactive_first_party", "first_party_record_inactive"

    fallback: dict[str, dict[str, object]] = {}
    for public_id in ids:
        raw = osv_by_id.get(public_id)
        if raw is None:
            continue
        record_id = str(raw.get("id") or public_id).upper()
        fallback[record_id] = {
            "id": record_id,
            "aliases": [str(value).upper() for value in raw.get("aliases", [])],
            "summary": str(raw.get("summary") or ""),
            "details": str(raw.get("details") or ""),
            "severity": raw.get("database_specific", {}).get("severity"),
            "cwe_ids": raw.get("database_specific", {}).get("cwe_ids", []),
            "references": [
                str(row.get("url"))
                for row in raw.get("references", [])
                if row.get("url")
            ],
            "source": "osv_routing_fallback",
            "active": not bool(raw.get("withdrawn")),
        }
    if fallback:
        return list(fallback.values()), "osv_routing_fallback", None
    return [], "missing_first_party", None


def _packet_id(class_id: str) -> str:
    return "atomic-review-" + hashlib.sha256(class_id.encode()).hexdigest()


def _packet_fix_context(
    exact: Mapping[str, object], *, limit: int = 24
) -> tuple[list[dict[str, object]], bool]:
    rows = [
        dict(row)
        for row in exact.get("squash_internal_fix_context", [])
        if isinstance(row, Mapping)
        and row.get("match_quality") == "exact_line"
        and row.get("match_ambiguity") == 1
    ]
    return rows[:limit], len(rows) > limit


def _prepare(args: argparse.Namespace) -> int:
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if min(args.max_candidates_per_class, args.diff_chars, args.details_chars) < 1:
        raise SystemExit("preparation bounds must be positive")
    if not (args.repository_path / ".git").is_dir():
        raise SystemExit("repository-path is not a Git checkout")

    rows = _jsonl(args.same_file_candidates)
    exact_rows = _jsonl(args.exact_blame_candidates)
    exact_by_key = {
        (str(row["class_id"]), str(row["fix_sha"]), str(row["candidate_sha"])): row
        for row in exact_rows
    }
    units = {str(row["sha"]): row for row in _jsonl(args.atomic_ai_units)}
    selected = select_candidates(
        rows,
        exact_keys=set(exact_by_key),
        units=units,
        max_per_class=args.max_candidates_per_class,
        candidate_order=args.candidate_order,
    )
    public_ids = {
        str(value)
        for candidates in selected.values()
        for candidate in candidates
        for value in candidate.get("member_ids", [])
    }
    first_party_by_id = _first_party_records(
        args.cvelist_dir, args.ghsa_dir, public_ids
    )
    osv_by_id = _osv_records(args.osv_zip, public_ids) if args.osv_zip else {}
    packets: list[dict[str, object]] = []
    excluded: list[dict[str, object]] = []
    for class_id in sorted(selected):
        first = selected[class_id][0]
        member_ids = [str(value).upper() for value in first.get("member_ids", [])]
        active, advisory_source_status, inactive_reason = _advisory_records(
            member_ids, first_party_by_id, osv_by_id
        )
        if inactive_reason:
            excluded.append(
                {
                    "class_id": class_id,
                    "member_ids": member_ids,
                    "reason": inactive_reason,
                }
            )
            continue
        advisory_evidence = [
            {
                "id": row.get("id"),
                "aliases": row.get("aliases", []),
                "summary": row.get("summary", ""),
                "details": str(row.get("details") or "")[: args.details_chars],
                "severity": row.get("severity"),
                "cwe_ids": row.get("cwe_ids", []),
                "references": row.get("references", []),
                "source": row.get("source"),
            }
            for row in sorted(active, key=lambda value: str(value.get("id") or ""))
        ]
        candidate_evidence: list[dict[str, object]] = []
        for candidate in selected[class_id]:
            candidate_sha = str(candidate["candidate_sha"])
            fix_sha = str(candidate["fix_sha"])
            paths = [str(value) for value in candidate["production_code_paths"]]
            unit = units[candidate_sha]
            candidate_subject, candidate_date, candidate_diff = _commit_view(
                args.repository_path,
                candidate_sha,
                args.diff_chars,
                priority_paths=paths,
                priority_label="Shared production-path candidate evidence",
            )
            fix_subject, fix_date, fix_diff = _commit_view(
                args.repository_path,
                fix_sha,
                args.diff_chars,
                priority_paths=paths,
                priority_label="Shared production-path public-exact fix evidence",
            )
            exact = exact_by_key.get((class_id, fix_sha, candidate_sha), {})
            fix_context, fix_context_truncated = _packet_fix_context(exact)
            candidate_evidence.append(
                {
                    "candidate_sha": candidate_sha,
                    "fix_sha": fix_sha,
                    "production_code_paths": paths,
                    "candidate_subject": candidate_subject,
                    "candidate_authored_date": candidate_date,
                    "candidate_diff": candidate_diff,
                    "fix_subject": fix_subject,
                    "fix_authored_date": fix_date,
                    "fix_diff": fix_diff,
                    "ai_signal_types": unit.get("signal_types", []),
                    "ai_tools": unit.get("tools", []),
                    "ai_attribution_message": str(unit.get("message") or "")[:4000],
                    "exact_blame_hit": bool(exact),
                    "blame_signals": exact.get("blame_signals", []),
                    "blamed_paths": exact.get("blamed_paths", []),
                    "squash_internal_fix_context": fix_context,
                    "fix_context_packet_truncated": fix_context_truncated,
                    "exact_unambiguous_line_count": exact.get(
                        "exact_unambiguous_line_count", 0
                    ),
                    "fix_context_match_qualities": exact.get(
                        "fix_context_match_qualities", []
                    ),
                    "fix_source_evidence": "public_exact",
                    "atomicity": candidate["atomicity"],
                }
            )
        packets.append(
            {
                "packet_id": _packet_id(class_id),
                "class_id": class_id,
                "analysis_subject": first["analysis_subject"],
                "member_ids": member_ids,
                "advisory_source_status": advisory_source_status,
                "advisories": advisory_evidence,
                "candidates": candidate_evidence,
                "claim_boundary": (
                    "model review cannot by itself promote this class; final promotion requires "
                    "a validated mechanism finding plus explicit atomic AI attribution"
                ),
            }
        )

    args.output_dir.mkdir(parents=True)
    _atomic_jsonl(args.output_dir / "packets.jsonl", packets)
    _atomic_jsonl(args.output_dir / "excluded.jsonl", excluded)
    summary = {
        "schema_version": 1,
        "artifact_kind": "atomic_ai_public_exact_mechanism_review_packets",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_same_file_candidate_count": len(rows),
        "eligible_production_code_class_count": len(selected),
        "packet_count": len(packets),
        "candidate_pair_count": sum(len(row["candidates"]) for row in packets),
        "excluded_class_count": len(excluded),
        "first_party_packet_count": sum(
            row["advisory_source_status"] == "first_party" for row in packets
        ),
        "osv_routing_fallback_packet_count": sum(
            row["advisory_source_status"] == "osv_routing_fallback"
            for row in packets
        ),
        "missing_first_party_packet_count": sum(
            row["advisory_source_status"] == "missing_first_party" for row in packets
        ),
        "max_candidates_per_class": args.max_candidates_per_class,
        "candidate_order": args.candidate_order,
        "packets_sha256": canonical_sha256(packets),
        "excluded_sha256": canonical_sha256(excluded),
        "claim_boundary": (
            "packets are evidence for review, not positive labels; CVEList/GHSA text is "
            "preferred and OSV is routing-only fallback"
        ),
    }
    _atomic_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, sort_keys=True))
    return 0


def _prompt(packet: Mapping[str, object]) -> str:
    expected = [
        {"candidate_sha": row["candidate_sha"], "fix_sha": row["fix_sha"]}
        for row in packet["candidates"]
        if isinstance(row, Mapping)
    ]
    schema = {
        "class_id": packet["class_id"],
        "reviews": [
            {
                "candidate_sha": "exact supplied SHA",
                "fix_sha": "exact supplied SHA",
                "verdict": "AI_CAUSAL|NOT_AI_CAUSAL|INCONCLUSIVE",
                "confidence": "number from 0 through 1",
                "mechanism": "specific candidate-to-vulnerability-to-fix chain",
                "decisive_evidence": ["exact facts from the packet"],
                "missing_evidence": ["specific unresolved facts"],
            }
        ],
    }
    return (
        f"Review class {packet['class_id']} and every candidate/fix pair exactly once. "
        "Do not copy a verdict between distinct aliases or fixes. The advisory text may "
        "describe a fix but not an origin. Expected pairs: "
        f"{json.dumps(expected, sort_keys=True)}\n\n"
        f"EVIDENCE:\n{json.dumps(packet, indent=2, sort_keys=True)}\n\n"
        f"RETURN_SCHEMA:\n{json.dumps(schema, indent=2, sort_keys=True)}"
    )


def parse_review(text: str, packet: Mapping[str, object]) -> dict[str, object]:
    cleaned = text.strip()
    fenced = re.findall(
        r"```(?:json)?\s*(.*?)\s*```", cleaned, re.IGNORECASE | re.DOTALL
    )
    if fenced:
        if len(fenced) != 1:
            raise ValueError("review contains multiple fenced blocks")
        cleaned = fenced[0]
    value = json.loads(cleaned)
    if not isinstance(value, dict) or set(value) != {"class_id", "reviews"}:
        raise ValueError("review object keys are invalid")
    if value["class_id"] != packet["class_id"] or not isinstance(
        value["reviews"], list
    ):
        raise ValueError("review class or rows are invalid")
    expected = {
        (str(row["candidate_sha"]), str(row["fix_sha"]))
        for row in packet["candidates"]
        if isinstance(row, Mapping)
    }
    seen: set[tuple[str, str]] = set()
    normalized: list[dict[str, object]] = []
    required = {
        "candidate_sha",
        "fix_sha",
        "verdict",
        "confidence",
        "mechanism",
        "decisive_evidence",
        "missing_evidence",
    }
    for raw in value["reviews"]:
        if not isinstance(raw, dict) or set(raw) != required:
            raise ValueError("candidate review keys are invalid")
        key = (str(raw["candidate_sha"]), str(raw["fix_sha"]))
        confidence = raw["confidence"]
        if (
            key not in expected
            or key in seen
            or raw["verdict"] not in _VERDICTS
            or not isinstance(confidence, (int, float))
            or isinstance(confidence, bool)
            or not 0 <= float(confidence) <= 1
            or not isinstance(raw["mechanism"], str)
            or not isinstance(raw["decisive_evidence"], list)
            or not isinstance(raw["missing_evidence"], list)
        ):
            raise ValueError("candidate review values are invalid")
        seen.add(key)
        normalized.append(raw)
    if seen != expected:
        raise ValueError("review does not cover every candidate/fix pair")
    return {"class_id": value["class_id"], "reviews": normalized}


def _call(
    packet: Mapping[str, object],
    *,
    sequence: int,
    api_base: str,
    api_key: str,
    model: str,
    reasoning_effort: str,
    max_output_tokens: int,
    timeout: float,
    responses_dir: Path,
) -> dict[str, object]:
    result: dict[str, object] = {
        "sequence": sequence,
        "packet_id": packet["packet_id"],
        "class_id": packet["class_id"],
        "requested_model": model,
        "observed_model": "",
        "status": "BLOCKED",
        "reason": "",
        "reviews": [],
        "usage": {},
    }
    body: dict[str, object] = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _prompt(packet)},
        ],
        "max_tokens": max_output_tokens,
    }
    if reasoning_effort != "model-controlled":
        body["reasoning_effort"] = reasoning_effort
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            response = httpx.post(
                f"{api_base.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json=body,
                timeout=timeout,
            )
            response.raise_for_status()
            if len(response.content) > MAX_RESPONSE_BYTES:
                raise ValueError("response_too_large")
            raw = response.json()
            if not isinstance(raw, dict):
                raise ValueError("response_not_object")
            _atomic_json(responses_dir / f"{sequence:04d}-attempt-{attempt}.json", raw)
            valid, reason, observed = _validate_response_provenance(
                raw, backend="cliproxyapi", requested_model=model
            )
            result["observed_model"] = observed
            if not valid:
                raise ValueError(reason)
            parsed = parse_review(extract_response_text(raw), packet)
            result["status"] = "COMPLETE"
            result["reviews"] = parsed["reviews"]
            usage = raw.get("usage")
            if isinstance(usage, Mapping):
                input_tokens, output_tokens = _usage_counts(usage)
                result["usage"] = {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                }
            result["attempt_count"] = attempt
            return result
        except httpx.HTTPStatusError as exc:
            result["reason"] = f"{type(exc).__name__}:{str(exc)[:300]}"
            result["attempt_count"] = attempt
            if (
                exc.response.status_code not in _RETRYABLE_STATUS
                or attempt == _MAX_ATTEMPTS
            ):
                return result
            time.sleep(min(30, 5 * 2 ** (attempt - 1)))
        except httpx.HTTPError as exc:
            result["reason"] = f"{type(exc).__name__}:{str(exc)[:300]}"
            result["attempt_count"] = attempt
            if attempt == _MAX_ATTEMPTS:
                return result
            time.sleep(min(30, 5 * 2 ** (attempt - 1)))
        except (ValueError, json.JSONDecodeError) as exc:
            result["reason"] = f"{type(exc).__name__}:{str(exc)[:300]}"
            result["attempt_count"] = attempt
            if attempt >= 2:
                return result
    return result


def _replay_call(
    packet: Mapping[str, object],
    *,
    sequence: int,
    model: str,
    responses_dir: Path,
) -> dict[str, object]:
    result: dict[str, object] = {
        "sequence": sequence,
        "packet_id": packet["packet_id"],
        "class_id": packet["class_id"],
        "requested_model": model,
        "observed_model": "",
        "status": "BLOCKED",
        "reason": "raw_response_missing",
        "reviews": [],
        "usage": {},
    }
    for attempt in range(_MAX_ATTEMPTS, 0, -1):
        path = responses_dir / f"{sequence:04d}-attempt-{attempt}.json"
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > MAX_RESPONSE_BYTES:
                raise ValueError("response_too_large")
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("response_not_object")
            valid, reason, observed = _validate_response_provenance(
                raw, backend="cliproxyapi", requested_model=model
            )
            result["observed_model"] = observed
            if not valid:
                raise ValueError(reason)
            parsed = parse_review(extract_response_text(raw), packet)
            result["status"] = "COMPLETE"
            result["reason"] = ""
            result["reviews"] = parsed["reviews"]
            usage = raw.get("usage")
            if isinstance(usage, Mapping):
                input_tokens, output_tokens = _usage_counts(usage)
                result["usage"] = {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                }
            result["attempt_count"] = attempt
            return result
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            result["reason"] = f"{type(exc).__name__}:{str(exc)[:300]}"
            result["attempt_count"] = attempt
    return result


def _require_model(api_base: str, api_key: str, model: str, timeout: float) -> None:
    response = httpx.get(
        f"{api_base.rstrip('/')}/models",
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=min(timeout, 30),
    )
    response.raise_for_status()
    data = response.json().get("data", [])
    ids = [str(row.get("id") or "") for row in data if isinstance(row, Mapping)]
    if ids.count(model) != 1:
        raise SystemExit(f"CLIProxyAPI must expose model {model!r} exactly once")


def _review(args: argparse.Namespace) -> int:
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if min(args.workers, args.max_output_tokens, args.timeout) < 1:
        raise SystemExit("review bounds must be positive")
    replay = args.input_responses_dir is not None
    api_key = ""
    if replay:
        if not args.input_responses_dir.is_dir():
            raise SystemExit("input responses directory does not exist")
    else:
        if not _is_loopback_api_base(args.api_base):
            raise SystemExit("review requires a loopback CLIProxyAPI")
        api_key = os.environ.get(args.api_key_env, "").strip()
        if not api_key:
            raise SystemExit(f"API key environment is empty: {args.api_key_env}")
        _require_model(args.api_base, api_key, args.model, args.timeout)
    packets = _filter_packets(_load_packets(args.packet_dir), args.class_id)

    args.output_dir.mkdir(parents=True)
    responses_dir = args.input_responses_dir or (args.output_dir / "responses")
    if not replay:
        responses_dir.mkdir(mode=0o700)
    results: list[dict[str, object]] = []
    if replay:
        results = [
            _replay_call(
                packet,
                sequence=sequence,
                model=args.model,
                responses_dir=responses_dir,
            )
            for sequence, packet in enumerate(packets, start=1)
        ]
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(
                    _call,
                    packet,
                    sequence=sequence,
                    api_base=args.api_base,
                    api_key=api_key,
                    model=args.model,
                    reasoning_effort=args.reasoning_effort,
                    max_output_tokens=args.max_output_tokens,
                    timeout=args.timeout,
                    responses_dir=responses_dir,
                ): packet
                for sequence, packet in enumerate(packets, start=1)
            }
            for completed, future in enumerate(as_completed(futures), start=1):
                result = future.result()
                results.append(result)
                print(
                    f"[{completed}/{len(packets)}] {result['class_id']} {result['status']}",
                    flush=True,
                )
    results.sort(key=lambda row: int(row["sequence"]))
    _atomic_jsonl(args.output_dir / "results.jsonl", results)
    verdicts = Counter(
        str(review["verdict"])
        for result in results
        for review in result.get("reviews", [])
        if isinstance(review, Mapping)
    )
    positive_classes = {
        str(result["class_id"])
        for result in results
        if any(
            isinstance(review, Mapping) and review.get("verdict") == "AI_CAUSAL"
            for review in result.get("reviews", [])
        )
    }
    output_summary = {
        "schema_version": 1,
        "artifact_kind": "atomic_ai_mechanism_model_review",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "response_source": "preserved_raw_replay" if replay else "live_model_calls",
        "packet_count": len(packets),
        "complete_packet_count": sum(row["status"] == "COMPLETE" for row in results),
        "blocked_packet_count": sum(row["status"] != "COMPLETE" for row in results),
        "candidate_verdict_counts": dict(sorted(verdicts.items())),
        "model_positive_class_count": len(positive_classes),
        "model_positive_class_ids": sorted(positive_classes),
        "input_tokens": sum(
            int(row.get("usage", {}).get("input_tokens", 0))
            for row in results
            if isinstance(row.get("usage"), Mapping)
        ),
        "output_tokens": sum(
            int(row.get("usage", {}).get("output_tokens", 0))
            for row in results
            if isinstance(row.get("usage"), Mapping)
        ),
        "results_sha256": canonical_sha256(results),
        "claim_boundary": (
            "model positives are review findings, not final positives; independent review and "
            "mechanical atomic-attribution verification remain required"
        ),
    }
    _atomic_json(args.output_dir / "summary.json", output_summary)
    print(json.dumps(output_summary, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    return _prepare(args) if args.command == "prepare" else _review(args)


if __name__ == "__main__":
    raise SystemExit(main())
