#!/usr/bin/env python3
"""Fact gates for a causal-research record. These do not judge the AI role.

They refuse to land a closed verdict that is missing identity, BIC, or a
fix. They do not classify AI vs human — that stays a judgment call.

--strict adds the protocol checks that score a record against the current
audit contract (docs/DATA-SCHEMA.md): advisory disposition, BIC granularity
and squash decomposition evidence, flip condition, AI admissibility. A record
written under an older contract fails those; use it for batch QA, not for a
record that was never asked to carry the fields.

Usage:
  python3 scripts/audit_record_gates.py RECORD.jsonl
  python3 scripts/audit_record_gates.py --stdin  < one.json
  python3 scripts/audit_record_gates.py --strict --stdin < one.json
  python3 scripts/audit_record_gates.py --strict records/*.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CLOSED = {"NOT_AI", "AI_ROOT_CAUSE", "AI_CODE_FLAWED", "FALSE_POSITIVE"}
OPEN = {"EVIDENCE_GAP", "BLOCKED"}
SHA40 = re.compile(r"^[0-9a-f]{40}$")
OFFICIAL_ID = re.compile(r"^(GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}|CVE-\d{4}-\d{4,})$", re.I)

AI_VERDICTS = {"AI_ROOT_CAUSE", "AI_CODE_FLAWED", "AI_CAUSAL_CONTRIBUTOR"}
DISPOSITIONS = {"ACTIVE", "WITHDRAWN", "REJECTED", "DUPLICATE", "UNKNOWN"}
DEAD_DISPOSITIONS = {"WITHDRAWN", "REJECTED", "DUPLICATE"}
GRANULARITIES = {
    "ATOMIC",
    "SQUASH_DECOMPOSED",
    "AGGREGATE_MEMBERS_UNREACHABLE",
    "NON_GIT_BOUNDARY",
}
MARKER_STATES = {"PRESENT", "ABSENT", "UNKNOWN"}

# A disclosure claim, not a denial of one: "Generated with Claude Code",
# "Co-authored-by: Copilot". A nearby no/without/absent/missing guards the
# ordinary "checked - no AI trailer" sentence out of the match.
DISCLOSURE = re.compile(
    r"\b(?:generated[- ]with|generated[- ]by|co[- ]authored[- ]by|authored[- ]by"
    r"|written[- ]by|assisted[- ]by|produced[- ]by)\b[^\n]{0,60}?"
    r"\b(?:claude|copilot|cursor|codex|chatgpt|gpt-?[45]|gemini|devin|aider|windsurf)\b"
    r"|\[AI\]|\bClaude Code\b",
    re.I,
)
DENIAL = re.compile(
    r"\b(no|not|none|never|without|absent|missing|denies|denied|ruled out|found no"
    r"|lacks|lacking|zero|excluded|irrelevant|unknown|cannot|0)\b",
    re.I,
)
RESIDUAL = re.compile(
    r"\b(incomplete(?:ly)? (?:remediat|fix|patch)\w*|residual|remains unpatched"
    r"|still (?:ships|vulnerable|exploitable|unbounded)|not closed|unclosed"
    r"|partial(?:ly)? (?:fix|remediat|patch)\w*)\b",
    re.I,
)
JUDGMENT_KEYS = (
    "flaw_origin",
    "bug_semantics",
    "mechanism",
    "verdict_basis",
    "bic_note",
    "fix_note",
    "ai_evidence",
    "ai_marker",
    "fix_ai_marker",
    "evidence",
    "reasoning",
    "remaining_gap",
)


def judgment_text(record: dict) -> str:
    """The prose a verdict is argued from, as one string."""
    parts = []
    for key in JUDGMENT_KEYS:
        value = record.get(key)
        if value is None:
            continue
        parts.append(json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value)
    return "\n".join(parts)


def denied_around(text: str, start: int, end: int) -> bool:
    """True when the match sits in a denial or exclusion clause, not a claim."""
    return bool(
        DENIAL.search(text[max(0, start - 70) : start])
        or DENIAL.search(text[end : end + 40])
    )


def claimed_disclosure(text: str) -> str:
    """First AI-disclosure claim in text, skipping negated mentions."""
    for match in DISCLOSURE.finditer(text):
        if denied_around(text, match.start(), match.end()):
            continue
        return match.group(0)
    return ""

EXTERNAL_VCS = re.compile(
    r"\b(?:svn|subversion|cvs)\b.{0,400}\b(?:revision|changeset|r\d+)\b",
    re.I | re.S,
)


def official_ids(record: dict) -> list[str]:
    ids = []
    for item in record.get("advisory_ids") or []:
        text = str(item).strip()
        if OFFICIAL_ID.match(text):
            ids.append(text.upper())
    return ids


def check_record(record: dict) -> list[str]:
    """Return human-readable problems. Empty means the record may land."""
    cid = str(record.get("class_id") or "?")
    verdict = record.get("verdict")
    problems: list[str] = []

    if verdict not in CLOSED | OPEN:
        if verdict is not None:
            problems.append(f"{cid}: unknown verdict {verdict!r}")
        return problems

    if verdict in OPEN:
        if verdict == "EVIDENCE_GAP" and not (record.get("remaining_gap") or "").strip():
            problems.append(f"{cid}: EVIDENCE_GAP requires remaining_gap")
        return problems
    if verdict == "FALSE_POSITIVE":
        gap = " ".join(
            str(record.get(k) or "")
            for k in ("evidence", "reasoning", "remaining_gap")
        )
        if not re.search(r"\b(withdrawn|rejected|not a security issue|false positive)\b", gap, re.I):
            problems.append(f"{cid}: FALSE_POSITIVE requires withdrawn/rejected evidence")
        return problems

    if not official_ids(record):
        problems.append(f"{cid}: closed {verdict} requires a real GHSA/CVE in advisory_ids")

    intro = record.get("introducer_sha")
    provenance = " ".join(
        str(record.get(k) or "") for k in ("flaw_origin", "evidence", "reasoning")
    )
    external_vcs_bic = (
        verdict == "NOT_AI"
        and intro is None
        and record.get("introducer_parent") is None
        and record.get("introducer_parent_absent") is True
        and EXTERNAL_VCS.search(provenance)
    )
    if not (isinstance(intro, str) and SHA40.match(intro)) and not external_vcs_bic:
        problems.append(
            f"{cid}: closed {verdict} requires a 40-hex introducer_sha "
            "or a verified non-Git SVN/CVS BIC boundary"
        )

    fix = record.get("fix_sha") or record.get("direct_fix_sha")
    if not (isinstance(fix, str) and SHA40.match(fix)):
        unpatched_record = record.get("unpatched")
        potential_fix = (
            (unpatched_record or {}).get("potential_fix")
            if isinstance(unpatched_record, dict)
            else None
        )
        if not (
            isinstance(unpatched_record, dict)
            and unpatched_record.get("confirmed") is True
            and isinstance(potential_fix, dict)
            and str(potential_fix.get("approach") or "").strip()
            and str(potential_fix.get("rationale") or "").strip()
        ):
            problems.append(
                f"{cid}: closed {verdict} requires fix_sha, or an explicit "
                "unpatched record with potential_fix approach+rationale"
            )
    return problems


def check_jsonl(path: Path) -> list[str]:
    problems: list[str] = []
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        record = json.loads(line)
        for item in check_record(record):
            problems.append(f"{path}:{idx}: {item}")
    return problems


def check_record_strict(record: dict) -> list[str]:
    """Protocol-contract checks. Empty means the record carries the current fields."""
    cid = str(record.get("class_id") or "?")
    verdict = record.get("verdict")
    if verdict is None:
        return []
    problems: list[str] = []

    def need(key: str) -> str:
        value = record.get(key)
        return value.strip() if isinstance(value, str) else ""

    disposition = need("advisory_disposition").upper()
    if disposition not in DISPOSITIONS:
        problems.append(
            f"{cid}: strict: advisory_disposition must be one of "
            f"{sorted(DISPOSITIONS)} (Step 0 check)"
        )
    elif disposition in DEAD_DISPOSITIONS and verdict != "FALSE_POSITIVE":
        problems.append(
            f"{cid}: strict: advisory is {disposition} but verdict is {verdict}"
        )

    granularity = need("bic_granularity").upper()
    if verdict != "FALSE_POSITIVE":
        if granularity not in GRANULARITIES:
            problems.append(
                f"{cid}: strict: bic_granularity must be one of "
                f"{sorted(GRANULARITIES)}"
            )
        elif granularity == "SQUASH_DECOMPOSED":
            members = record.get("decomposed_shas") or []
            if not members or not all(
                isinstance(sha, str) and SHA40.match(sha) for sha in members
            ):
                problems.append(
                    f"{cid}: strict: SQUASH_DECOMPOSED requires 40-hex decomposed_shas"
                )
        elif granularity == "AGGREGATE_MEMBERS_UNREACHABLE":
            if len(need("decomposition_probe")) < 20:
                problems.append(
                    f"{cid}: strict: AGGREGATE_MEMBERS_UNREACHABLE requires "
                    "decomposition_probe with the command run and what it returned"
                )
        elif granularity == "NON_GIT_BOUNDARY":
            if record.get("introducer_sha") is not None:
                problems.append(
                    f"{cid}: strict: NON_GIT_BOUNDARY requires introducer_sha null"
                )
        elif granularity == "ATOMIC":
            landing = str(record.get("landing_commit") or "").lower()
            intro = str(record.get("introducer_sha") or "").lower()
            if landing and landing == intro:
                problems.append(
                    f"{cid}: strict: introducer_sha is its own landing commit, "
                    "so the BIC was not decomposed to an atomic change"
                )

    if verdict in CLOSED and not need("flip_condition"):
        problems.append(
            f"{cid}: strict: closed {verdict} requires flip_condition"
        )

    fix_marker = record.get("fix_ai_marker")
    state = (fix_marker or {}).get("state") if isinstance(fix_marker, dict) else None
    if str(state or "").upper() not in MARKER_STATES:
        problems.append(
            f"{cid}: strict: fix_ai_marker.state must be PRESENT/ABSENT/UNKNOWN"
        )

    ai_on_bic = record.get("ai_on_bic")
    if ai_on_bic is not None and not isinstance(ai_on_bic, bool):
        problems.append(
            f"{cid}: strict: ai_on_bic must be a JSON boolean, got {ai_on_bic!r}"
        )
    marker = record.get("ai_marker")
    bic_marker = (
        str((marker or {}).get("state") or "").upper()
        if isinstance(marker, dict)
        else ""
    )
    if verdict in AI_VERDICTS and ai_on_bic is not True and bic_marker != "PRESENT":
        problems.append(
            f"{cid}: strict: {verdict} needs ai_on_bic true or ai_marker PRESENT"
        )
    if verdict == "NOT_AI" and ai_on_bic is True:
        problems.append(f"{cid}: strict: NOT_AI contradicts ai_on_bic true")

    return problems


def review_signals(record: dict) -> list[str]:
    """Heuristic cues for a human re-read. Not gates: a hit is a question.

    A record can be complete and still contradict itself in prose. These two
    cues found the cases that decided the round21 protocol review: an AI
    disclosure the verdict does not reflect, and a closed verdict whose own
    evidence names an open surface.
    """
    cid = str(record.get("class_id") or "?")
    verdict = record.get("verdict")
    if verdict is None:
        return []
    text = judgment_text(record)
    signals = []
    disclosed = claimed_disclosure(text)
    if (
        disclosed
        and verdict not in AI_VERDICTS
        and not str(record.get("ai_admissibility") or "").strip()
    ):
        signals.append(
            f"{cid}: signal: evidence claims {disclosed!r} outside the BIC object "
            "and the record never says whether that evidence was admissible"
        )
    if verdict in CLOSED and not str(record.get("remaining_gap") or "").strip():
        for match in RESIDUAL.finditer(text):
            if denied_around(text, match.start(), match.end()):
                continue
            signals.append(
                f"{cid}: signal: evidence names a residual or incomplete surface "
                f"({match.group(0)!r}) while remaining_gap is empty"
            )
            break
    return signals


def check_path(path: Path, strict: bool = False) -> list[str]:
    if path.suffix == ".json":
        record = json.loads(path.read_text(encoding="utf-8"))
        problems = check_record(record)
        if strict:
            problems += check_record_strict(record)
        return [f"{path}: {item}" for item in problems]
    problems = check_jsonl(path)
    if strict:
        for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip():
                for item in check_record_strict(json.loads(line)):
                    problems.append(f"{path}:{idx}: {item}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument("--stdin", action="store_true")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="also check the current audit-contract fields (docs/DATA-SCHEMA.md)",
    )
    args = parser.parse_args()
    problems: list[str] = []
    if args.stdin:
        record = json.load(sys.stdin)
        problems.extend(check_record(record))
        if args.strict:
            problems.extend(check_record_strict(record))
    for path in args.paths:
        problems.extend(check_path(path, args.strict))
    for line in problems:
        print(line, file=sys.stderr)
    if problems:
        print(f"{len(problems)} gate failure(s)", file=sys.stderr)
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
