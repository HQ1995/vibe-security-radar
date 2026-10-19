#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

AI_VERDICTS = {"AI_ROOT_CAUSE", "AI_CODE_FLAWED"}
CLOSED = {"NOT_AI", "FALSE_POSITIVE"} | AI_VERDICTS
OPEN = {"EVIDENCE_GAP", "BLOCKED"}
SHA40 = re.compile(r"^[0-9a-f]{40}$")
OFFICIAL_ID = re.compile(r"^(GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}|CVE-\d{4}-\d{4,})$", re.I)

DISPOSITIONS = {"ACTIVE", "WITHDRAWN", "REJECTED", "DUPLICATE", "UNKNOWN"}
DEAD_DISPOSITIONS = {"WITHDRAWN", "REJECTED", "DUPLICATE"}
GRANULARITIES = {
    "ATOMIC",
    "SQUASH_DECOMPOSED",
    "AGGREGATE_MEMBERS_UNREACHABLE",
    "NON_GIT_BOUNDARY",
}
MARKER_STATES = {"PRESENT", "ABSENT", "UNKNOWN"}
FIX_MARKER_STATES = MARKER_STATES | {"ANNOTATION_ONLY"}
FIX_GRANULARITIES = {"ATOMIC", "CARRIER_BUNDLE", "UNRESOLVED", "NO_FIX_OBJECT"}
LANDING_BASIS = {
    "PROSE_CARRIER_ON_DEFAULT",
    "PROSE_CARRIER_NO_CONTENT_MATCH",
    "INTRODUCER_ON_DEFAULT",
    "NO_LANDING_NAMED",
}
FP_GROUNDS = {
    "ADVISORY_REJECTED_ALIAS",
    "ADVISORY_MISATTRIBUTED",
    "EVIDENCE_INSUFFICIENT",
    "MECHANISM_REFUTED",
}
CONTRACT_VERSION = re.compile(r"^(\d{4})-(\d{2})-(\d{2})\.(\d+)$")
IMPACT_CONTRACT = (2026, 10, 14, 1)
IMPACT_FIELDS = ("affected", "prerequisites", "effect")
IDENTITY_CLASSES = {
    "HUMAN",
    "HUMAN_GH_NOREPLY",
    "NAMED_NO_EMAIL",
    "AI_CODER_BOT",
    "PLACEHOLDER",
    "OBJECT_MISSING",
    "NO_OBJECT",
}
NAMED_IDENTITIES = {"HUMAN", "HUMAN_GH_NOREPLY"}
DISCLOSURE_STATES = {
    "CONVENTION_NOT_OBSERVED",
    "CONVENTION_PRESENT_UNUSED",
    "POLICY_MENTIONS_AI",
    "NO_DATE",
}
NOTE_MIN = 20

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
    parts = []
    for key in JUDGMENT_KEYS:
        value = record.get(key)
        if value is None:
            continue
        parts.append(json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value)
    return "\n".join(parts)


def denied_around(text: str, start: int, end: int) -> bool:
    return bool(
        DENIAL.search(text[max(0, start - 70) : start])
        or DENIAL.search(text[end : end + 40])
    )


def claimed_disclosure(text: str) -> str:
    for match in DISCLOSURE.finditer(text):
        if denied_around(text, match.start(), match.end()):
            continue
        return match.group(0)
    return ""


def residual_denied(record: dict) -> bool:
    triage = record.get("residual_triage")
    if not isinstance(triage, dict):
        return False
    return (
        str(triage.get("decision") or "").upper() == "NOT-RESIDUAL"
        and len(str(triage.get("basis") or "").strip()) >= NOTE_MIN
    )

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


def sha_list(value) -> list[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return []
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def check_record(record: dict) -> list[str]:
    cid = str(record.get("class_id") or "?")
    verdict = record.get("verdict")
    problems: list[str] = []

    if not isinstance(verdict, str) or verdict not in CLOSED | OPEN:
        problems.append(f"{cid}: missing or unknown verdict {verdict!r}")
        return problems

    if verdict in OPEN:
        if str(record.get("remaining_gap") or "").strip().lower() in {"", "none", "null", "n/a"}:
            problems.append(f"{cid}: {verdict} requires remaining_gap")
        if record.get("ai_marker") is None:
            problems.append(f"{cid}: {verdict} requires an ai_marker; use {{\"state\": \"UNKNOWN\"}} when no causal object is established")
        return problems
    if verdict == "FALSE_POSITIVE":
        if record.get("false_positive_ground") in FP_GROUNDS:
            if not (record.get("evidence") or record.get("reasoning")):
                problems.append(f"{cid}: FALSE_POSITIVE requires evidence for its ground")
            return problems
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


def check_record_strict(record: dict) -> list[str]:
    cid = str(record.get("class_id") or "?")
    verdict = record.get("verdict")
    if verdict is None:
        return []
    if not isinstance(verdict, str):
        return [f"{cid}: strict: verdict must be a string"]
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
    open_gap = (
        verdict in OPEN
        and need("remaining_gap").lower() not in {"", "none", "null", "n/a"}
        and bool(need("flip_condition"))
    )
    if verdict != "FALSE_POSITIVE":
        unknown_bic = (
            open_gap and record.get("introducer_sha") is None
            and "bic_granularity" in record and record["bic_granularity"] is None
        )
        if granularity not in GRANULARITIES and not unknown_bic:
            problems.append(
                f"{cid}: strict: bic_granularity must be one of "
                f"{sorted(GRANULARITIES)}"
            )
        elif granularity == "SQUASH_DECOMPOSED":
            members = sha_list(record.get("decomposed_shas"))
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

    if verdict != "FALSE_POSITIVE" and granularity in GRANULARITIES:
        landing = need("landing_commit").lower()
        basis = need("landing_basis").upper()
        note = need("landing_note")
        if basis and basis not in LANDING_BASIS:
            problems.append(
                f"{cid}: strict: landing_basis must be one of {sorted(LANDING_BASIS)}"
            )
        if granularity == "SQUASH_DECOMPOSED":
            if not SHA40.match(landing) and len(note) < NOTE_MIN:
                problems.append(
                    f"{cid}: strict: SQUASH_DECOMPOSED requires landing_commit (the "
                    "carrier) or landing_note saying why no carrier is resolvable"
                )
            elif basis == "PROSE_CARRIER_NO_CONTENT_MATCH" and len(note) < NOTE_MIN:
                problems.append(
                    f"{cid}: strict: the carrier is asserted, not content-matched - "
                    "landing_note must say what the carrier read showed"
                )
            elif landing in [sha.lower() for sha in sha_list(record.get("decomposed_shas"))] and len(note) < NOTE_MIN:
                problems.append(
                    f"{cid}: strict: the object that landed this content is listed as "
                    "its own member - landing_note must say why the sha is listed"
                )

    if verdict != "FALSE_POSITIVE":
        fix_granularity = need("fix_granularity").upper()
        unknown_fix = (
            open_gap and "fix_granularity" in record and record["fix_granularity"] is None
            and not any(record.get(k) for k in ("fix_sha", "direct_fix_sha", "atomic_repair_sha", "fix_shas"))
        )
        if fix_granularity not in FIX_GRANULARITIES and not unknown_fix:
            problems.append(
                f"{cid}: strict: fix_granularity must be one of "
                f"{sorted(FIX_GRANULARITIES)}"
            )
        repair = need("atomic_repair_sha").lower()
        if repair and not SHA40.match(repair):
            problems.append(f"{cid}: strict: atomic_repair_sha must be a 40-hex sha")
        others = record.get("fix_shas")
        if others is not None and (
            not isinstance(others, list)
            or not others
            or not all(isinstance(sha, str) and SHA40.match(sha) for sha in others)
        ):
            problems.append(
                f"{cid}: strict: fix_shas must list the other 40-hex landings of the "
                "same repair"
            )

    if verdict in CLOSED and not need("flip_condition"):
        problems.append(
            f"{cid}: strict: closed {verdict} requires flip_condition"
        )

    fix_marker = record.get("fix_ai_marker")
    state = (fix_marker or {}).get("state") if isinstance(fix_marker, dict) else None
    state = str(state or "").upper()
    if state not in FIX_MARKER_STATES:
        problems.append(
            f"{cid}: strict: fix_ai_marker.state must be one of "
            f"{sorted(FIX_MARKER_STATES)}"
        )
    if state == "PRESENT" and verdict not in AI_VERDICTS and not need("ai_admissibility"):
        problems.append(
            f"{cid}: strict: a PRESENT fix-side AI marker needs ai_admissibility "
            "(step 4: fix-side evidence never substitutes for BIC attribution)"
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
            f"{cid}: strict: {verdict} needs ai_on_bic true or ai_marker PRESENT on "
            "introducer_sha (the AI-attributed change is the BIC; record the human "
            "origin in flaw_origin, not as introducer_sha)"
        )
    if verdict == "NOT_AI" and ai_on_bic is True:
        problems.append(f"{cid}: strict: NOT_AI contradicts ai_on_bic true")

    if verdict == "NOT_AI":
        identity = need("identity_class").upper().replace("-", "_")
        if identity not in IDENTITY_CLASSES:
            problems.append(
                f"{cid}: strict: NOT_AI requires identity_class one of "
                f"{sorted(IDENTITY_CLASSES)}"
            )
        elif identity not in NAMED_IDENTITIES:
            problems.append(
                f"{cid}: strict: NOT_AI needs a recovered named identity on the BIC "
                f"object; {identity} is EVIDENCE_GAP (step 4)"
            )
        convention = need("disclosure_convention").upper()
        if convention not in DISCLOSURE_STATES:
            problems.append(
                f"{cid}: strict: NOT_AI requires the repo's disclosure convention at "
                f"the BIC date, one of {sorted(DISCLOSURE_STATES)}"
            )

    if verdict == "FALSE_POSITIVE" and need("false_positive_ground").upper() not in FP_GROUNDS:
        problems.append(
            f"{cid}: strict: FALSE_POSITIVE requires false_positive_ground one of "
            f"{sorted(FP_GROUNDS)}"
        )
    if verdict == "FALSE_POSITIVE":
        for field, marker_state in (("ai_marker", bic_marker), ("fix_ai_marker", state)):
            if marker_state == "PRESENT":
                problems.append(
                    f"{cid}: strict: FALSE_POSITIVE cannot bind PRESENT {field} to a null causal role; "
                    "retain observed markers in evidence"
                )
        if need("false_positive_ground").upper() == "EVIDENCE_INSUFFICIENT":
            problems.append(
                f"{cid}: strict: EVIDENCE_INSUFFICIENT is a legacy false-positive label; "
                "new records need affirmative MECHANISM_REFUTED evidence or an open verdict"
            )
        for key in ("introducer_sha", "bic_granularity", "fix_sha", "fix_granularity"):
            if key not in record or record[key] is not None:
                problems.append(f"{cid}: strict: FALSE_POSITIVE requires explicit {key}: null (not applicable)")
        for key in ("introducer_parent", "landing_commit", "decomposed_shas", "direct_fix_sha", "atomic_repair_sha", "fix_shas", "minimum_fix_set"):
            if record.get(key):
                problems.append(f"{cid}: strict: FALSE_POSITIVE cannot claim causal {key}; retain observed objects in evidence")
        if isinstance(record.get("unpatched"), dict) and record["unpatched"].get("confirmed") is True:
            problems.append(f"{cid}: strict: FALSE_POSITIVE cannot claim a confirmed unpatched defect")
        if record.get("ai_on_bic") is not None:
            problems.append(f"{cid}: strict: FALSE_POSITIVE has no BIC to attribute; omit ai_on_bic")
        ids = record.get("advisory_ids")
        keyed = ids[0] if isinstance(ids, list) and ids else None
        aliases = record.get("advisory_aliases")
        if not isinstance(keyed, str) or not OFFICIAL_ID.fullmatch(keyed):
            problems.append(f"{cid}: strict: FALSE_POSITIVE requires a keyed official advisory_ids entry")
        elif not any(
            isinstance(alias, dict)
            and str(alias.get("id") or "").upper() == keyed.upper()
            and str(alias.get("state") or "").upper() == disposition
            for alias in (aliases if isinstance(aliases, list) else [])
        ):
            problems.append(f"{cid}: strict: keyed advisory disposition must agree with advisory_aliases")
    if (
        verdict == "FALSE_POSITIVE"
        and need("false_positive_ground").upper() == "ADVISORY_REJECTED_ALIAS"
        and disposition not in DEAD_DISPOSITIONS
    ):
        problems.append(
            f"{cid}: strict: ADVISORY_REJECTED_ALIAS requires the keyed advisory "
            "to be REJECTED, WITHDRAWN or DUPLICATE; a live alias is not refuted by another alias"
        )

    aliases = record.get("advisory_aliases")
    if not isinstance(aliases, list) or not aliases:
        problems.append(
            f"{cid}: strict: advisory_aliases must list the consulted advisories "
            "with their state"
        )
    else:
        alias_states = {}
        for item in aliases:
            item = item if isinstance(item, dict) else {}
            if not OFFICIAL_ID.fullmatch(str(item.get("id") or "")) or str(
                item.get("state") or ""
            ).upper() not in DISPOSITIONS:
                problems.append(
                    f"{cid}: strict: every advisory_aliases entry needs an official id "
                    f"and a state in {sorted(DISPOSITIONS)}"
                )
                break
            alias_id, alias_state = item["id"].upper(), item["state"].upper()
            if alias_id in alias_states and alias_states[alias_id] != alias_state:
                problems.append(f"{cid}: strict: advisory_aliases has conflicting states for {alias_id}")
            alias_states[alias_id] = alias_state

    if verdict in CLOSED and not need("remaining_gap") and not residual_denied(record):
        text = judgment_text(record)
        for match in RESIDUAL.finditer(text):
            if denied_around(text, match.start(), match.end()):
                continue
            problems.append(
                f"{cid}: strict: evidence names a residual or incomplete surface "
                f"({match.group(0)!r}) while remaining_gap is empty"
            )
            break

    if verdict not in AI_VERDICTS and not need("ai_admissibility"):
        disclosed = claimed_disclosure(judgment_text(record))
        if disclosed:
            problems.append(
                f"{cid}: strict: evidence claims {disclosed!r} outside the BIC object "
                "and the record never says whether that evidence was admissible"
            )

    if verdict != "FALSE_POSITIVE" and contract_version(record) >= IMPACT_CONTRACT:
        impact = record.get("impact")
        missing = [
            key for key in IMPACT_FIELDS
            if not (isinstance(impact, dict) and isinstance(impact.get(key), str) and impact[key].strip())
        ]
        if missing:
            problems.append(
                f"{cid}: strict: contract records need a substantive "
                + ", ".join(f"impact.{key}" for key in missing) + " (step 2)"
            )

    return problems


def contract_version(record: dict) -> tuple[int, ...]:
    match = CONTRACT_VERSION.match(str(record.get("protocol_version") or "").strip())
    return tuple(int(part) for part in match.groups()) if match else (0,)


def review_signals(record: dict) -> list[str]:
    cid = str(record.get("class_id") or "?")
    verdict = record.get("verdict")
    if not isinstance(verdict, str):
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
    if (
        verdict in CLOSED
        and not str(record.get("remaining_gap") or "").strip()
        and not residual_denied(record)
    ):
        for match in RESIDUAL.finditer(text):
            if denied_around(text, match.start(), match.end()):
                continue
            signals.append(
                f"{cid}: signal: evidence names a residual or incomplete surface "
                f"({match.group(0)!r}) while remaining_gap is empty"
            )
            break
    return signals


def load_record(text: str) -> dict:
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    record = json.loads(text, object_pairs_hook=unique_pairs)
    if not isinstance(record, dict):
        raise ValueError("audit record must be a JSON object")
    return record


def check_git_evidence(record: dict, repo: Path) -> list[str]:
    cid = record.get("class_id", "?")
    problems = []
    objects = {}
    env = {**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1"}

    def read_commit(sha):
        if not isinstance(sha, str) or not SHA40.fullmatch(sha):
            problems.append(f"{cid}: git: expected a full commit SHA, got {sha!r}")
            return None
        if sha in objects:
            return objects[sha]
        try:
            proc = subprocess.run(
                ["git", "--no-replace-objects", "-C", str(repo), "cat-file", "--batch"],
                input=sha + "\n", capture_output=True, text=True, timeout=30, env=env,
            )
        except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
            problems.append(f"{cid}: git: cannot read {sha}: {exc}")
            objects[sha] = None
            return None
        header, _, body = proc.stdout.partition("\n")
        fields = header.split()
        if proc.returncode or len(fields) != 3:
            problems.append(f"{cid}: git: commit {sha} unavailable in {repo}; recover evidence or record the gap")
            objects[sha] = None
        elif fields[:2] != [sha, "commit"]:
            problems.append(f"{cid}: git: {sha} is not the named commit object")
            objects[sha] = None
        else:
            objects[sha] = body.removesuffix("\n")
        return objects[sha]

    intro = record.get("introducer_sha")
    if intro:
        raw = read_commit(intro)
        parent = record.get("introducer_parent")
        if raw is not None and parent:
            parents = re.findall(r"^parent ([0-9a-f]{40})$", raw.partition("\n\n")[0], re.M)
            if parent not in parents:
                problems.append(f"{cid}: git: introducer_parent is not a parent of {intro}")

    for field in ("ai_marker", "fix_ai_marker"):
        marker = record.get(field)
        required = field == "ai_marker" and record.get("ai_on_bic") is True
        if not isinstance(marker, dict):
            if required:
                problems.append(f"{cid}: git: ai_on_bic requires an ai_marker with sha and quote")
            continue
        if str(marker.get("state", "")).upper() != "PRESENT" and not required:
            continue
        sha = marker.get("sha")
        targets = [intro] if field == "ai_marker" else [
            record.get(k) for k in ("fix_sha", "direct_fix_sha", "atomic_repair_sha")
        ] + sha_list(record.get("fix_shas"))
        if not sha or sha not in targets:
            problems.append(f"{cid}: git: {field}.sha must name its {'BIC' if field == 'ai_marker' else 'fix'} object")
            continue
        quote = marker.get("quote")
        if not isinstance(quote, str) or not quote.strip():
            problems.append(f"{cid}: git: {field} requires an exact quote")
            continue
        source = marker.get("source", "commit")
        if source == "first_party":
            if not re.match(r"^https?://", str(marker.get("url") or "")) or not record.get("ai_admissibility"):
                problems.append(f"{cid}: git: first_party marker needs url and ai_admissibility; verify the saved source separately")
            continue
        if source != "commit":
            problems.append(f"{cid}: git: {field}.source must be commit or first_party")
            continue
        raw = read_commit(sha)
        if raw is not None:
            headers, _, message = raw.partition("\n\n")
            identity = "\n".join(line for line in headers.splitlines() if line.startswith(("author ", "committer ")))
            if quote not in identity and quote not in message:
                problems.append(f"{cid}: git: {field} quote is absent from commit {sha}")
    return problems


def check_text(text: str, strict: bool = False, repo: Path | None = None) -> list[str]:
    try:
        record = load_record(text)
    except ValueError as exc:
        return [str(exc)]
    problems = check_record(record)
    if strict:
        problems += check_record_strict(record)
    if repo is not None:
        problems += check_git_evidence(record, repo)
    return problems


def check_path(path: Path, strict: bool = False, repo: Path | None = None) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [f"{path}: {exc}"]
    return [f"{path}: {item}" for item in check_text(text, strict, repo)]


def main() -> int:
    parser = argparse.ArgumentParser(description='Fact gates for a causal-research record')
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument("--stdin", action="store_true")
    parser.add_argument("--repo", type=Path, help="verify commit marker quotes and parent links in this local clone (no fetch)")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="also check the current audit-contract fields (radar-audit references/record.md)",
    )
    args = parser.parse_args()
    if not args.stdin and not args.paths:
        parser.error("supply record paths or --stdin")
    problems: list[str] = []
    if args.stdin:
        problems.extend(check_text(sys.stdin.read(), args.strict, args.repo))
    for path in args.paths:
        problems.extend(check_path(path, args.strict, args.repo))
    for line in problems:
        print(line, file=sys.stderr)
    if problems:
        print(f"{len(problems)} gate failure(s)", file=sys.stderr)
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
