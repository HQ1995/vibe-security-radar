#!/usr/bin/env python3
"""Fail a site publish if public cases are missing dates, diffs, or identity.

A hole is a research task, not a skip. Fill the commit, advisory range, or
product repository, then republish. site_preflight_allowlist.json is only for
residuals that remain after that work, with a first-party reason.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_cache import load as cache_load, save as cache_save, fresh as cache_fresh

VERIFY_CACHE_ACTIVE = True

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = ROOT / "web/src/generated/research-data.json"
ALLOWLIST = ROOT / "scripts/site_preflight_allowlist.json"
FIX_OBJECT_WITNESS = ROOT / "scripts/published-fix-object-witness.json"
PUBLICATION_ADJUDICATIONS = ROOT / "scripts/publication_adjudications.json"
EVIDENCE_FETCH_OVERRIDES = ROOT / "scripts/evidence_fetch_overrides.json"
PUBLICATION_OVERRIDES = ROOT / "scripts/tp_publication_overrides.json"
EVIDENCE_REQUIRED_ROLES = ROOT / "scripts/code-evidence-required-roles.json"
GENERATED_CODE_EVIDENCE = ROOT / "scripts/generated-code-evidence.json"
GHSA_RE = re.compile(r"^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$", re.I)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\u3000-\u303f]")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$", re.I)
COMMIT_URL_RE = re.compile(
    r"^https://github\.com/(?P<repository>[^/]+/[^/]+)/commit/"
    r"(?P<sha>[0-9a-f]{40})(?:[/?#].*)?$",
    re.I,
)
OFFLINE_WITNESS_VERIFICATION_METHOD = "GitHub REST git/commits exact-SHA match"
LIVE_WITNESS_VERIFICATION_METHOD = (
    "GitHub commit HTML final-path and og:url exact-SHA match"
)
PUBLICATION_STATUSES = ("confirmed", "qualified", "provisional")
HUNK_ROLES = ("candidate", "fix", "before_after")
# The published case is a projection of the ledger row. Every key here is
# reader-facing or consumed by these checks; anything else is internal
# metadata that must not reach the site.
PUBLIC_CASE_KEYS = frozenset(
    {
        "case_id",
        "aliases",
        "repository",
        "repository_metadata",
        "contribution_class",
        "candidate_set",
        "candidate_sources",
        "carrier_set",
        "candidate_fix_edges",
        "minimum_fix_set",
        "publication_status",
        "publication_issues",
        "advisory_url",
        "gates",
        "vulnerable_release",
        "fixed_release",
        "published_at",
        "severity",
        "cwes",
        "description",
        "references",
        "mechanism",
        "cause_category",
        "ai_provenance",
        "fix_authorship",
        "code_evidence",
        "unpatched",
        "ir_chain",
    }
)
PUBLIC_EVIDENCE_KEYS = frozenset(
    {
        "display_hunks",
        "steps",
        "summary",
        "required_anchors",
        "mechanism",
        "candidate_url",
        "fix_url",
        "candidate_patch_sha256",
        "fix_patch_sha256",
        "advisory_url",
        "fix_marker",
        "fix_files",
        "fix_patch_files",
        "candidate_patch_files",
        "annotation_mode",
        "unavailable_reason",
    }
)


def project_public_case(case: dict) -> dict:
    """Reduce a built case to the public payload the site may serve.

    The publisher calls this, and evaluate() rejects anything outside the same
    key set, so the projection and its gate cannot drift apart.
    """
    case["aliases"] = [
        item
        for item in case.get("aliases") or []
        if GHSA_RE.match(str(item)) or CVE_RE.match(str(item))
    ]
    for key in set(case) - PUBLIC_CASE_KEYS:
        del case[key]
    evidence = case.get("code_evidence")
    if isinstance(evidence, dict):
        for key in set(evidence) - PUBLIC_EVIDENCE_KEYS:
            del evidence[key]
    return case


ANNOTATION_PREFIX_RE = re.compile(
    r"^(?:AI introduced this behavior|AI removed a constraint|The fix adds):\s*",
    re.I,
)


def strip_annotation_prefix(value: object) -> str:
    return ANNOTATION_PREFIX_RE.sub("", str(value or "").strip()).strip()
INTERNAL_PROSE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:cand|fix|sink|source|guard)=|ai=\['|/tmp/|"
    r"class_id|decomposed_shas|bug_semantics|introduced_with_feature|"
    r"alias-[0-9a-f]{6,}|phantom\s+sha|fetch_error|"
    r"traceback \(most recent call last\)",
    re.I,
)
HUNK_HEADER_RE = re.compile(
    r"^@@ -\d+(?:,(?P<old>\d+))? \+\d+(?:,(?P<new>\d+))? @@"
)
AUDIT_IDENTIFIER_RE = re.compile(
    r"\balias-[a-z0-9]+\b|"
    r"\b(?=[0-9a-f]{7,40}\b)(?=[0-9a-f]*\d)[0-9a-f]{7,40}\b|"
    r"\b(?:BIC|carrier|(?:AI|CAUSAL|EVIDENCE|PARTIALLY|UNANALYZED|NOT|FALSE)_[A-Z0-9_]+)\b",
    re.I,
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def official_ids(case: dict) -> list[str]:
    values = [case.get("case_id"), *(case.get("aliases") or [])]
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "")
        if (GHSA_RE.match(text) or CVE_RE.match(text)) and text.upper() not in seen:
            seen.add(text.upper())
            out.append(text)
    return out


def has_hunks(case: dict) -> bool:
    evidence = case.get("code_evidence") or {}
    return bool(display_hunks(evidence))


_TABLE_RULE_RE = re.compile(r"^\|[\s:|-]+\|$")
_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")


def strip_markdown(text: object) -> str:
    """Plain reader text: the site renders prose through this same transform."""
    lines: list[str] = []
    for line in str(text or "").split("\n"):
        value = line.strip()
        if _TABLE_RULE_RE.fullmatch(value):
            continue
        if value.startswith("|") and value.endswith("|") and "|" in value[1:-1]:
            lines.append(": ".join(cell.strip() for cell in value[1:-1].split("|")))
            continue
        lines.append(value)
    out = "\n".join(lines)
    out = re.sub(r"^#{1,6}\s+", "", out, flags=re.M)
    out = re.sub(r"```[\s\S]*?```", " ", out)
    out = re.sub(r"`([^`]+)`", r"\1", out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"\1", out)
    out = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", out)
    out = _LINK_RE.sub(r"\1", out)
    out = re.sub(r"^\s*[-*+]\s+", "· ", out, flags=re.M)
    return re.sub(r"\n{3,}", "\n\n", out).strip()


def reader_prose(value: object) -> bool:
    """True for reader-facing prose, false for an internal audit dump.

    Publish gates copy with this so the shipped payload carries no internal
    notes; the site then renders what publish ships and needs no second filter.
    """
    text = str(value or "").strip()
    if len(text) < 24 or INTERNAL_PROSE_RE.search(text):
        return False
    words = text.split()
    if len(words) < 5:
        return False
    if text.count("/") >= 4 and len(words) < 12 and not re.search(r"[.!?]\s", text):
        return False
    return bool(re.search(r"[a-z]", text, re.I))


def public_explanation(value: object) -> bool:
    """Reader prose short enough to use as a diff fallback blurb."""
    return reader_prose(value) and len(str(value or "").strip()) <= 360


def annotation_context(case: dict) -> tuple[str, ...]:
    evidence = case.get("code_evidence") or {}
    return tuple(
        str(value).strip()
        for value in (
            evidence.get("summary"),
            evidence.get("mechanism"),
            case.get("mechanism"),
            case.get("description"),
        )
        if str(value or "").strip()
    )


def public_cjk_paths(value: object, path: str = "") -> list[str]:
    """Paths of reader-facing strings that carry CJK characters.

    Quoted upstream `code` is verbatim evidence, not our copy: a vulnerable
    repository may legitimately contain non-English comments, and stripping
    them would publish a diff that never existed. Every other field is ours and
    must be English.
    """
    if isinstance(value, dict):
        return [
            hit
            for key, item in value.items()
            if key != "code"
            for hit in public_cjk_paths(item, f"{path}.{key}" if path else str(key))
        ]
    if isinstance(value, list):
        return [
            hit
            for index, item in enumerate(value)
            for hit in public_cjk_paths(item, f"{path}[{index}]")
        ]
    if isinstance(value, str) and CJK_RE.search(value):
        return [path or "<root>"]
    return []


def is_pseudo_annotation(value: object, context: tuple[str, ...]) -> bool:
    text = str(value or "").strip()
    return bool(text) and (not strip_annotation_prefix(text) or text in context)


_CODE_COMMENT_RE = re.compile(r"^(?:/{2,}|#+|/\*+|\*|--|<!--)")
_PROSE_WORD_RE = re.compile(r"[A-Za-z]{3,}")


def usable_hunk_annotation(value: object) -> str:
    """Return the value with its boilerplate lead-in removed when it still
    carries a reader-facing explanation; else empty.

    A bare code token — the diff line repeated as its own note — explains
    nothing the reader cannot already see, so it is dropped as noise.
    """
    text = strip_annotation_prefix(value)
    if not text or len(text) < 8 or INTERNAL_PROSE_RE.search(text):
        return ""
    wrapped = re.fullmatch(r"`([\s\S]*)`", text)
    body = (wrapped.group(1) if wrapped else text).strip()
    if not _CODE_COMMENT_RE.match(body) and len(_PROSE_WORD_RE.findall(body)) < 4:
        return ""
    return text


def valid_unified_hunks(value: object) -> bool:
    """Accept GitHub-style hunks that may concatenate multiple @@ blocks.

    Diffs produced by trim_patch can join several block headers into one
    string and truncate it at a line limit, so trailing lines of a block can
    be missing. Only over-counting a block is corruption (added lines would
    shift the diff); under-counting is harmless truncation.
    """
    seen_any = False
    blocks = str(value or "").strip().split("@@ -")[1:]
    for block in blocks:
        body = "@@ -" + block
        header_match = HUNK_HEADER_RE.match(body)
        if not header_match:
            continue
        seen_any = True
        old_count = new_count = 0
        for line in body.splitlines()[1:]:
            if line.startswith(" "):
                old_count += 1
                new_count += 1
            elif line.startswith("-"):
                old_count += 1
            elif line.startswith("+"):
                new_count += 1
        expected_old = int(header_match.group("old") or 1)
        expected_new = int(header_match.group("new") or 1)
        if old_count > expected_old or new_count > expected_new:
            return False
    if seen_any:
        return True
    # Headerless body: trim_patch can drop the @@ header but keep the
    # body. The renderer line-splits and never counts, so accept a body
    # that is purely diff lines.
    body = str(value or "").strip()
    return bool(body) and any(
        line.startswith(("+", "-", " ")) for line in body.splitlines()
    )


def _diff_body(value: object) -> str:
    lines: list[str] = []
    for line in str(value or "").splitlines():
        if line.startswith(("@@", "diff --git ", "index ", "--- ", "+++ ")):
            continue
        lines.append(line[1:] if line[:1] in "+- " else line)
    return "\n".join(lines).strip()


def _same_hunk(left: dict, right: dict) -> bool:
    if left.get("file") != right.get("file"):
        return False
    left_body = _diff_body(left.get("code"))
    right_body = _diff_body(right.get("code"))
    return bool(
        left_body
        and right_body
        and (
            left_body == right_body
            or left_body in right_body
            or right_body in left_body
        )
    )


def comparison_hunk_role(evidence: dict, hunk: dict) -> str | None:
    matches = [
        role
        for role, collection in (
            ("candidate", "candidate_hunks"),
            ("fix", "fix_hunks"),
        )
        if any(_same_hunk(hunk, other) for other in evidence.get(collection) or [])
    ]
    if len(matches) == 1:
        return matches[0]
    lines = str(hunk.get("code") or "").splitlines()
    added = any(line.startswith("+") and not line.startswith("+++") for line in lines)
    removed = any(line.startswith("-") and not line.startswith("---") for line in lines)
    return "before_after" if not matches and added and removed else None


def _same_display_hunk(left: dict, right: dict) -> bool:
    return left.get("file") == right.get("file") and left.get("code") == right.get("code")


def display_role(hunk: dict, candidate: list[dict], fix: list[dict]) -> str:
    if hunk.get("role") == "candidate" or any(
        _same_display_hunk(hunk, other) for other in candidate
    ):
        return "candidate"
    if hunk.get("role") == "fix" or any(
        _same_display_hunk(hunk, other) for other in fix
    ):
        return "fix"
    return "before_after"


def display_hunks(evidence: dict) -> list[dict]:
    """The reader-facing hunk list.

    Published cases ship the resolved list, which publish writes once and every
    later filter edits; ledger rows and test fixtures still carry the raw
    candidate/fix/comparison collections, so derive from those only when the
    shipped list is absent.
    """
    shipped = evidence.get("display_hunks")
    if shipped:
        return [dict(hunk) for hunk in shipped]
    candidate = list(evidence.get("candidate_hunks") or [])
    fix = list(evidence.get("fix_hunks") or [])
    comparison = list(evidence.get("comparison_hunks") or [])
    selected = [dict(hunk) for hunk in (comparison or [*candidate, *fix])]
    if comparison:
        for role, hunks in (("candidate", candidate), ("fix", fix)):
            if any(display_role(hunk, candidate, fix) == role for hunk in selected):
                continue
            for hunk in hunks:
                if not any(_same_display_hunk(hunk, other) for other in selected):
                    selected.append(dict(hunk))
    seen: set[str] = set()
    for hunk in selected:
        hunk["role"] = display_role(hunk, candidate, fix)
        annotation = str(hunk.get("annotation") or "").strip()
        if annotation in seen:
            hunk["annotation"] = ""
        elif annotation:
            seen.add(annotation)
    return selected


def hunks_for_role(evidence: dict, role: str) -> list[dict]:
    """Hunks for one reader role: raw collections, or the shipped display list."""
    raw = evidence.get(f"{role}_hunks")
    if raw:
        return list(raw)
    return [hunk for hunk in display_hunks(evidence) if hunk.get("role") == role]


def has_reader_fallback(case: dict, role: str) -> bool:
    chain = case.get("ir_chain") or {}
    attempted = chain.get("attempted_remediation") or {}
    closure = chain.get("final_closure") or {}
    if role == "candidate":
        values = (*annotation_context(case), attempted.get("changed"), attempted.get("missed"))
        return any(public_explanation(value) for value in values)
    if role == "fix":
        if public_explanation(closure.get("closed")):
            return True
        return any(
            public_explanation(step.get("detail"))
            for step in ((case.get("code_evidence") or {}).get("steps") or [])
            if re.search(r"\bfix\b", str(step.get("title") or ""), re.I)
        )
    if role == "before_after":
        values = (
            *annotation_context(case),
            attempted.get("changed"),
            attempted.get("missed"),
            closure.get("closed"),
        )
        return any(public_explanation(value) for value in values)
    return False


def has_release(case: dict) -> bool:
    return bool(case.get("vulnerable_release") or case.get("fixed_release"))


def is_unpatched(case: dict) -> bool:
    record = case.get("unpatched")
    return isinstance(record, dict) and record.get("confirmed") is True


def unpatched_errors(case_id: str, case: dict) -> list[str]:
    record = case.get("unpatched")
    if record is None:
        return []
    if not isinstance(record, dict) or record.get("confirmed") is not True:
        return [f"{case_id}: unpatched record is present but not confirmed"]
    reason = str(record.get("reason") or "").strip()
    potential = record.get("potential_fix") if isinstance(record.get("potential_fix"), dict) else {}
    approach = str(potential.get("approach") or "").strip()
    rationale = str(potential.get("rationale") or "").strip()
    errors: list[str] = []
    if not reason:
        errors.append(f"{case_id}: unpatched record has no reason")
    if not approach or not rationale:
        errors.append(f"{case_id}: unpatched record has no potential_fix approach/rationale")
    if case.get("minimum_fix_set"):
        errors.append(f"{case_id}: unpatched case still has a fix set")
    if case.get("fixed_release"):
        errors.append(f"{case_id}: unpatched case still has a fixed release")
    evidence = case.get("code_evidence") or {}
    if any(
        evidence.get(field)
        for field in ("fix_url", "fix_marker", "fix_files", "fix_patch_sha256")
    ):
        errors.append(f"{case_id}: unpatched case still has fix evidence metadata")
    if any(hunk.get("role") == "fix" for hunk in display_hunks(evidence)):
        errors.append(f"{case_id}: unpatched case still has fix hunks")
    if any(
        re.search(r"\bfix\b", str(step.get("title") or ""), re.I)
        for step in evidence.get("steps") or []
    ):
        errors.append(f"{case_id}: unpatched case still has a fix step")
    return errors


def _sha_sets_match(left: object, right: object) -> bool:
    if (
        not isinstance(left, list)
        or not isinstance(right, list)
        or not left
        or not right
    ):
        return False
    values = [str(value) for value in (*left, *right)]
    return all(SHA40_RE.fullmatch(value) for value in values) and {
        str(value).lower() for value in left
    } == {str(value).lower() for value in right}


def ir_chain_errors(case_id: str, case: dict) -> list[str]:
    chain = case.get("ir_chain")
    if not isinstance(chain, dict):
        return []
    errors: list[str] = []
    original_sha = str(chain.get("original_sha") or "").strip()
    advisory_ids = chain.get("original_advisory_ids")
    if (
        not isinstance(advisory_ids, list)
        or not advisory_ids
        or not all(str(value or "").strip() for value in advisory_ids)
    ):
        errors.append(f"{case_id}: ir_chain has no original_advisory_ids")
    if original_sha and not SHA40_RE.fullmatch(original_sha):
        errors.append(f"{case_id}: ir_chain has invalid original_sha")
    elif not original_sha and not public_explanation(chain.get("unresolved_reason")):
        errors.append(
            f"{case_id}: ir_chain without original_sha needs unresolved_reason"
        )
    if original_sha:
        if chain.get("original_author_kind") not in {"AI", "HUMAN"}:
            errors.append(f"{case_id}: resolved ir_chain has no original_author_kind")
        if not str(chain.get("original_author_name") or "").strip():
            errors.append(f"{case_id}: resolved ir_chain has no original_author_name")
    elif chain.get("original_author_kind") != "UNKNOWN":
        errors.append(f"{case_id}: unresolved ir_chain author kind must be UNKNOWN")
    for field in ("original_mechanism", "original_sink", "residual_bypass"):
        if not str(chain.get(field) or "").strip():
            errors.append(f"{case_id}: ir_chain has no {field}")

    attempted = chain.get("attempted_remediation")
    if not isinstance(attempted, dict):
        errors.append(f"{case_id}: ir_chain has no attempted_remediation")
    else:
        if not attempted.get("candidate_shas"):
            errors.append(f"{case_id}: attempted_remediation has no candidate_shas")
        elif not all(
            SHA40_RE.fullmatch(str(value))
            for value in attempted.get("candidate_shas")
        ):
            errors.append(
                f"{case_id}: attempted_remediation has invalid candidate_shas"
            )
        elif not _sha_sets_match(
            attempted.get("candidate_shas"), case.get("candidate_set")
        ):
            errors.append(
                f"{case_id}: attempted_remediation candidate_shas do not match candidate_set"
            )
        for field in ("changed", "missed"):
            if not str(attempted.get(field) or "").strip():
                errors.append(f"{case_id}: attempted_remediation has no {field}")

    closure = chain.get("final_closure")
    if not isinstance(closure, dict):
        if not is_unpatched(case):
            errors.append(f"{case_id}: ir_chain has no final_closure")
    else:
        if not closure.get("minimum_fix_shas"):
            errors.append(f"{case_id}: final_closure has no minimum_fix_shas")
        elif not all(
            SHA40_RE.fullmatch(str(value))
            for value in closure.get("minimum_fix_shas")
        ):
            errors.append(f"{case_id}: final_closure has invalid minimum_fix_shas")
        elif not _sha_sets_match(
            closure.get("minimum_fix_shas"), case.get("minimum_fix_set")
        ):
            errors.append(
                f"{case_id}: final_closure minimum_fix_shas do not match minimum_fix_set"
            )
        if not str(closure.get("closed") or "").strip():
            errors.append(f"{case_id}: final_closure has no closed")
    return errors


def fix_object_witness_errors(cases: list[dict], witness: dict) -> list[str]:
    expected = {
        (str(case.get("case_id") or "").upper(), str(sha).lower())
        for case in cases
        for sha in case.get("minimum_fix_set") or []
    }
    records = witness.get("objects") if isinstance(witness, dict) else None
    if (
        not isinstance(witness, dict)
        or witness.get("schema_version") != 1
        or not isinstance(records, list)
    ):
        return ["published fix object witness has invalid schema"]
    errors: list[str] = []
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(witness.get("verified_at") or "")):
        errors.append("published fix object witness has invalid verified_at")
    if witness.get("verification_method") != OFFLINE_WITNESS_VERIFICATION_METHOD:
        errors.append("published fix object witness has invalid verification_method")
    if witness.get("live_verification_method") != LIVE_WITNESS_VERIFICATION_METHOD:
        errors.append(
            "published fix object witness has invalid live_verification_method"
        )
    objects_digest = hashlib.sha256(
        json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if witness.get("objects_sha256") != objects_digest:
        errors.append("published fix object witness objects digest does not match")
    keys: list[tuple[str, str]] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append(f"fix object witness[{index}] is not an object")
            continue
        key = (
            str(record.get("case_id") or "").upper(),
            str(record.get("sha") or "").lower(),
        )
        keys.append(key)
        if not key[0] or not SHA40_RE.fullmatch(key[1]):
            errors.append(f"fix object witness[{index}] has invalid case_id/sha")
        if not str(record.get("repository") or "").strip():
            errors.append(f"fix object witness[{index}] has no repository")
        if record.get("object_type") != "commit":
            errors.append(f"fix object witness[{index}] is not a commit")
    if keys != sorted(keys):
        errors.append("published fix object witness is not sorted by case_id/sha")
    if len(keys) != len(set(keys)):
        errors.append("published fix object witness has duplicate case_id/sha records")
    missing = sorted(expected - set(keys))
    stale = sorted(set(keys) - expected)
    if missing:
        errors.append(f"published fix object witness is missing {missing[:12]}")
    if stale:
        errors.append(f"published fix object witness has stale records {stale[:12]}")
    return errors


def github_commit_sha(repository: str, sha: str) -> str | None:
    path = f"/{repository}/commit/{sha}"
    request = Request(
        f"https://github.com{path}",
        headers={
            "Range": "bytes=0-98303",
            "User-Agent": "ai-slop-site-preflight",
        },
    )
    with urlopen(request, timeout=20) as response:
        final = urlparse(response.geturl())
        if (
            final.scheme != "https"
            or final.hostname != "github.com"
            or final.path.casefold() != path.casefold()
        ):
            return None
        head = response.read(98304).decode("utf-8", errors="strict")
    exact_meta = f'<meta property="og:url" content="{path}"'
    return sha.lower() if exact_meta.casefold() in head.casefold() else None


def live_fix_object_witness_errors(witness: dict) -> list[str]:
    """Revalidate each offline repo/SHA claim against GitHub's commit endpoint."""

    targets = sorted(
        {
            (
                str(record.get("repository") or "").strip(),
                str(record.get("sha") or "").lower(),
            )
            for record in witness.get("objects") or []
            if isinstance(record, dict)
            and str(record.get("repository") or "").strip()
            and SHA40_RE.fullmatch(str(record.get("sha") or ""))
        }
    )

    def verify(target: tuple[str, str]) -> tuple[str, str, str | None]:
        repository, sha = target
        for attempt in range(4):
            try:
                return repository, sha, github_commit_sha(repository, sha)
            except HTTPError as error:
                if error.code in (429, 502, 503) and attempt < 3:
                    time.sleep(2.0 * (2**attempt))
                    continue
                return repository, sha, None
            except (OSError, TimeoutError, UnicodeError, ValueError):
                return repository, sha, None

    force_online = not VERIFY_CACHE_ACTIVE or "--force-online" in (sys.argv[1:] if len(sys.argv) > 1 else [])
    cache = {} if force_online else cache_load()
    witness_cache = cache.get("fix_objects") or {}
    cached_ok: set[tuple[str, str]] = set()
    stale: list[tuple[str, str]] = []
    for target in targets:
        entry = witness_cache.get(f"{target[0]}@{target[1]}")
        if not force_online and cache_fresh(entry):
            cached_ok.add(target)
        else:
            stale.append(target)

    online: list[tuple[str, str, str | None]] = []
    if stale:
        with ThreadPoolExecutor(max_workers=min(12, len(stale))) as pool:
            online = list(pool.map(verify, stale))
        for repository, sha, actual in online:
            if actual == sha:
                witness_cache[f"{repository}@{sha}"] = {"verified_at": time.time()}
        cache["fix_objects"] = witness_cache
        cache_save(cache)

    results = online + [(r, s, s) for r, s in cached_ok]
    return [
        f"published fix object witness live check failed for {repository}@{sha}"
        for repository, sha, actual in results
        if actual != sha
    ]


def not_ai_publication_errors(cases: list[dict], adjudications: dict) -> list[str]:
    records = adjudications.get("adjudications") if isinstance(adjudications, dict) else None
    if (
        not isinstance(adjudications, dict)
        or adjudications.get("schema_version") != 1
        or not isinstance(records, list)
    ):
        return ["effective publication adjudications have invalid schema"]
    not_ai_ids = {
        str(value).upper()
        for record in records
        if isinstance(record, dict) and record.get("label") == "NOT_AI_CAUSAL"
        for value in (record.get("cve_id"), *(record.get("aliases") or []))
        if GHSA_RE.match(str(value or "")) or CVE_RE.match(str(value or ""))
    }
    errors: list[str] = []
    for case in cases:
        matched = sorted(
            {value.upper() for value in official_ids(case)} & not_ai_ids
        )
        if matched:
            errors.append(
                f"{case.get('case_id')}: published identity is adjudicated NOT_AI "
                f"via {matched}"
            )
    return errors


def evidence_role_allowlist_errors(
    cases: list[dict], overrides: dict, manifest: dict
) -> list[str]:
    roles = manifest.get("roles") if isinstance(manifest, dict) else None
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != 1
        or manifest.get("artifact_kind") != "code_evidence_required_roles"
        or not isinstance(roles, list)
        or any(not isinstance(value, str) for value in roles)
    ):
        return ["code evidence required-role manifest has invalid schema"]
    digest = hashlib.sha256("\n".join(roles).encode()).hexdigest()
    errors: list[str] = []
    if roles != sorted(set(roles)):
        errors.append("code evidence required-role manifest is not sorted and unique")
    if manifest.get("role_count") != len(roles):
        errors.append("code evidence required-role manifest count does not match")
    if manifest.get("roles_sha256") != digest:
        errors.append("code evidence required-role manifest digest does not match")
    if not isinstance(overrides, dict):
        return [*errors, "code evidence fetch overrides have invalid schema"]

    normalized_overrides = {
        str(key).upper(): value
        for key, value in overrides.items()
        if isinstance(value, dict)
    }
    cases_by_subject: dict[str, list[dict]] = {}
    for case in cases:
        for subject in official_ids(case):
            cases_by_subject.setdefault(subject.upper(), []).append(case)

    for required in roles:
        subject, separator, role = required.rpartition(":")
        if (
            not separator
            or role not in {"candidate", "fix"}
            or not (GHSA_RE.match(subject) or CVE_RE.match(subject))
        ):
            errors.append(f"invalid required code-evidence role {required!r}")
            continue
        matched_cases = cases_by_subject.get(subject.upper(), [])
        if not matched_cases:
            errors.append(
                f"required code-evidence role {required} has no published identity"
            )
            continue
        if len(matched_cases) != 1:
            errors.append(f"required code-evidence role {required} is identity-ambiguous")
            continue
        case = matched_cases[0]
        case_id = str(case.get("case_id") or subject)
        spec = normalized_overrides.get(subject.upper())
        allowed = spec.get(f"{role}_files") if isinstance(spec, dict) else None
        if (
            not isinstance(allowed, list)
            or not allowed
            or any(not str(path or "").strip() for path in allowed)
            or len(allowed) != len(set(allowed))
        ):
            errors.append(f"{case_id}: required {role} role has no file allowlist")
            continue
        allowed_paths = {str(path) for path in allowed}
        evidence = case.get("code_evidence") or {}
        source = COMMIT_URL_RE.fullmatch(
            str(evidence.get(f"{role}_url") or "").strip()
        )
        expected_repo = str(
            spec.get(f"{role}_repo")
            or spec.get("fetch_repo")
            or case.get("repository")
            or ""
        ).strip()
        set_field = "candidate_set" if role == "candidate" else "minimum_fix_set"
        expected_sha = str(
            spec.get(role) or ((case.get(set_field) or [""])[0])
        ).lower()
        if (
            not source
            or source.group("repository").lower() != expected_repo.lower()
            or source.group("sha").lower() != expected_sha
        ):
            errors.append(
                f"{case_id}: {role} source does not match its effective fetch override"
            )
        if role == "fix" and expected_sha not in {
            str(sha).lower() for sha in case.get("minimum_fix_set") or []
        }:
            errors.append(
                f"{case_id}: allowlisted fix does not belong to minimum_fix_set"
            )

        role_hunks = hunks_for_role(evidence, role)
        if not role_hunks:
            errors.append(f"{case_id}: required {role} role emitted no hunk")
        displayed_role_hunks = [
            hunk for hunk in display_hunks(evidence) if hunk.get("role") == role
        ]
        emitted_paths = {
            str(hunk.get("file") or "").strip() for hunk in role_hunks
        }
        displayed_paths = {
            str(hunk.get("file") or "").strip()
            for hunk in displayed_role_hunks
        }
        if not emitted_paths <= allowed_paths or not displayed_paths <= allowed_paths:
            errors.append(
                f"{case_id}: displayed {role} path exceeds its file allowlist"
            )
        patch_files = evidence.get(f"{role}_patch_files")
        if not isinstance(patch_files, list) or {
            str(path) for path in patch_files
        } != allowed_paths:
            errors.append(
                f"{case_id}: {role} allowlist is not present in fetched patches"
            )
        raw_anchors = spec.get(f"{role}_anchors")
        anchors = (
            [raw_anchors]
            if isinstance(raw_anchors, str) and raw_anchors.strip()
            else [
                str(anchor)
                for anchor in raw_anchors
                if isinstance(anchor, str) and anchor.strip()
            ]
            if isinstance(raw_anchors, list)
            else []
        )
        if anchors:
            emitted_code = "\n".join(
                str(hunk.get("code") or "") for hunk in role_hunks
            ).casefold()
            displayed_code = "\n".join(
                str(hunk.get("code") or "") for hunk in displayed_role_hunks
            ).casefold()
            if not any(anchor.casefold() in emitted_code for anchor in anchors):
                errors.append(f"{case_id}: required {role} anchor is not emitted")
            if not any(anchor.casefold() in displayed_code for anchor in anchors):
                errors.append(f"{case_id}: required {role} anchor is not displayed")
    return errors


def curated_steps_source_errors(cases: list[dict]) -> list[str]:
    """Check that curated steps in site data also exist in the data source."""
    if not GENERATED_CODE_EVIDENCE.exists():
        return []
    generated = load_json(GENERATED_CODE_EVIDENCE)
    generic_titles = {"ai change", "ai fix", "fix", "root cause", "change"}
    errors: list[str] = []
    for case in cases:
        case_id = str(case.get("case_id") or "")
        evidence = case.get("code_evidence") or {}
        steps = evidence.get("steps") or []
        if not steps:
            continue
        has_curated = any(
            str(step.get("title") or "").strip().lower() not in generic_titles
            for step in steps
        )
        if not has_curated:
            continue
        generated_entry = generated.get(case_id)
        if generated_entry is None:
            errors.append(
                f"{case_id}: curated steps in site data but no entry in generated-code-evidence.json"
            )
            continue
        generated_steps = generated_entry.get("steps") or []
        if not any(
            str(step.get("title") or "").strip().lower() not in generic_titles
            for step in generated_steps
        ):
            errors.append(
                f"{case_id}: curated steps in site data but generated-code-evidence.json has only generic steps"
            )
    return errors


def evaluate(
    payload: dict,
    allowlist: dict | None = None,
    fix_object_witness: dict | None = None,
    publication_adjudications: dict | None = None,
    evidence_fetch_overrides: dict | None = None,
    evidence_required_roles: dict | None = None,
    publication_overrides: dict | None = None,
) -> tuple[list[str], list[str], dict]:
    allowlist = allowlist or {}
    release_allow = {
        key.upper(): reason
        for key, reason in (allowlist.get("missing_release") or {}).items()
    }
    cases = payload.get("cases") or []
    publication_overrides = (
        publication_overrides
        if publication_overrides is not None
        else load_json(PUBLICATION_OVERRIDES)
        if PUBLICATION_OVERRIDES.exists()
        else {}
    )
    snapshot = payload.get("snapshot") or {}
    # The payload ships official advisory IDs only, so a case cannot look up
    # its own override by class_id; every declared extra GHSA counts as
    # verified and the seen_official check below still rejects cross-case
    # claims.
    declared_extra_ids = {
        str(item).upper()
        for spec in (publication_overrides.get("cases") or {}).values()
        if isinstance(spec, dict)
        for item in (spec.get("aliases_extra") or [])
    }
    errors: list[str] = []
    warnings: list[str] = []
    seen_official: dict[str, str] = {}
    dated = 0
    hunks = 0
    releases = 0
    status_counts = {status: 0 for status in PUBLICATION_STATUSES}
    unused_release_allow = set(release_allow)
    errors.extend(
        fix_object_witness_errors(
            cases,
            fix_object_witness
            if fix_object_witness is not None
            else load_json(FIX_OBJECT_WITNESS)
            if FIX_OBJECT_WITNESS.exists()
            else {},
        )
    )
    errors.extend(
        not_ai_publication_errors(
            cases,
            publication_adjudications
            if publication_adjudications is not None
            else load_json(PUBLICATION_ADJUDICATIONS)
            if PUBLICATION_ADJUDICATIONS.exists()
            else {},
        )
    )
    errors.extend(
        evidence_role_allowlist_errors(
            cases,
            evidence_fetch_overrides
            if evidence_fetch_overrides is not None
            else load_json(EVIDENCE_FETCH_OVERRIDES)
            if EVIDENCE_FETCH_OVERRIDES.exists()
            else {},
            evidence_required_roles
            if evidence_required_roles is not None
            else load_json(EVIDENCE_REQUIRED_ROLES)
            if EVIDENCE_REQUIRED_ROLES.exists()
            else {},
        )
    )
    errors.extend(
        curated_steps_source_errors(cases)
    )

    if snapshot.get("case_count") != len(cases):
        errors.append(
            f"snapshot.case_count={snapshot.get('case_count')} but cases={len(cases)}"
        )

    for case in cases:
        case_id = str(case.get("case_id") or "")
        key = case_id.upper()
        leaked = [
            str(item)
            for item in case.get("aliases") or []
            if not (GHSA_RE.match(str(item)) or CVE_RE.match(str(item)))
        ]
        leaked.extend(sorted(set(case) - PUBLIC_CASE_KEYS))
        leaked.extend(
            f"code_evidence.{name}"
            for name in sorted(
                set(case.get("code_evidence") or {}) - PUBLIC_EVIDENCE_KEYS
            )
        )
        if leaked:
            errors.append(
                f"{case_id}: internal identifiers in public payload: "
                + ", ".join(leaked)
            )
        for leak_path in public_cjk_paths(case):
            errors.append(f"{case_id}: CJK leaked into public fields at {leak_path}")
        status = str(case.get("publication_status") or "")
        if status not in status_counts:
            errors.append(f"{case_id}: invalid publication_status {status!r}")
        else:
            status_counts[status] += 1
        gates = case.get("gates") or {}
        failed_gates = sorted(
            name for name, value in gates.items() if value == "FAIL"
        )
        if failed_gates:
            errors.append(
                f"{case_id}: published case has FAIL gates: {', '.join(failed_gates)}"
            )
        evidence = case.get("code_evidence") or {}
        summary = str(evidence.get("summary") or "").strip()
        if (
            not public_explanation(summary)
            or AUDIT_IDENTIFIER_RE.search(summary)
            or "PR #" in summary
        ):
            errors.append(f"{case_id}: missing public reader summary")
        errors.extend(unpatched_errors(case_id, case))
        errors.extend(ir_chain_errors(case_id, case))
        unpatched = is_unpatched(case)
        context = annotation_context(case)
        for field in ("candidate_set", "minimum_fix_set"):
            values = case.get(field)
            if values and (
                not isinstance(values, list)
                or not all(SHA40_RE.fullmatch(str(value)) for value in values)
            ):
                errors.append(f"{case_id}: {field} must contain full 40-hex commit SHAs")
        candidates = {
            str(sha).lower() for sha in case.get("candidate_set") or []
        }
        fixes = {
            str(sha).lower() for sha in case.get("minimum_fix_set") or []
        }
        carriers = {
            str(sha).lower() for sha in case.get("carrier_set") or []
        }
        candidate_sources = case.get("candidate_sources")
        candidate_source_repositories: dict[str, str] = {}
        evidence_candidate_source = COMMIT_URL_RE.fullmatch(
            str(evidence.get("candidate_url") or "").strip()
        )
        if len(candidates) > 1 or candidate_sources is not None:
            if not isinstance(candidate_sources, list) or not candidate_sources:
                errors.append(
                    f"{case_id}: multi-candidate case has no candidate_sources"
                )
            else:
                for index, source in enumerate(candidate_sources):
                    sha = str((source or {}).get("sha") or "").lower()
                    repository = str(
                        (source or {}).get("repository") or ""
                    ).strip()
                    if not SHA40_RE.fullmatch(sha) or not re.fullmatch(
                        r"[^/\s]+/[^/\s]+", repository
                    ):
                        errors.append(
                            f"{case_id}: candidate_sources[{index}] is invalid"
                        )
                        continue
                    if sha in candidate_source_repositories:
                        errors.append(
                            f"{case_id}: candidate_sources repeats {sha}"
                        )
                    candidate_source_repositories[sha] = repository
                if set(candidate_source_repositories) != candidates:
                    errors.append(
                        f"{case_id}: candidate_sources do not cover candidate_set"
                    )
                allowed_source_repositories = {
                    str(case.get("repository") or "").lower()
                }
                if evidence_candidate_source:
                    allowed_source_repositories.add(
                        evidence_candidate_source.group("repository").lower()
                    )
                if any(
                    repository.lower() not in allowed_source_repositories
                    for repository in candidate_source_repositories.values()
                ):
                    errors.append(
                        f"{case_id}: candidate_sources contain an unbound repository"
                    )
        edges = case.get("candidate_fix_edges")
        if len(candidates) > 1 and carriers and not edges:
            errors.append(
                f"{case_id}: multi-candidate carrier topology has no candidate_fix_edges"
            )
        if edges is not None:
            edge_candidates: list[str] = []
            edge_carriers: set[str] = set()
            if not isinstance(edges, list) or not edges:
                errors.append(f"{case_id}: candidate_fix_edges is invalid")
            else:
                for index, edge in enumerate(edges):
                    candidate_sha = str(
                        (edge or {}).get("candidate_sha") or ""
                    ).lower()
                    carrier_sha = (edge or {}).get("carrier_sha")
                    fix_sha = str((edge or {}).get("fix_sha") or "").lower()
                    origin_kind = str((edge or {}).get("origin_kind") or "")
                    if candidate_sha not in candidates:
                        errors.append(
                            f"{case_id}: candidate_fix_edges[{index}] candidate is outside candidate_set"
                        )
                    edge_candidates.append(candidate_sha)
                    if carrier_sha is not None:
                        carrier = str(carrier_sha).lower()
                        edge_carriers.add(carrier)
                        if carrier not in carriers:
                            errors.append(
                                f"{case_id}: candidate_fix_edges[{index}] carrier is outside carrier_set"
                            )
                    elif (
                        origin_kind == "direct_commit"
                        and candidate_source_repositories.get(
                            candidate_sha, ""
                        ).lower()
                        != str(case.get("repository") or "").lower()
                    ):
                        errors.append(
                            f"{case_id}: direct candidate source is not in the case repository"
                        )
                    if fix_sha not in fixes:
                        errors.append(
                            f"{case_id}: candidate_fix_edges[{index}] fix is outside minimum_fix_set"
                        )
                    if not re.fullmatch(r"[a-z][a-z0-9_]*", origin_kind):
                        errors.append(
                            f"{case_id}: candidate_fix_edges[{index}] has invalid origin_kind"
                        )
                if len(edge_candidates) != len(set(edge_candidates)) or set(
                    edge_candidates
                ) != candidates:
                    errors.append(
                        f"{case_id}: candidate_fix_edges do not cover candidate_set exactly"
                    )
                if edge_carriers != carriers:
                    errors.append(
                        f"{case_id}: candidate_fix_edges do not cover carrier_set"
                    )
        security_fix_steps = [
            (index, step)
            for index, step in enumerate(evidence.get("steps") or [])
            if str(step.get("title") or "").strip().lower() == "security fix"
        ]
        fix_files = evidence.get("fix_files")
        for index, step in security_fix_steps:
            if (
                not isinstance(fix_files, list)
                or not fix_files
                or not all(str(path or "").strip() for path in fix_files)
            ):
                errors.append(f"{case_id}: Security fix step has no fix_files witness")
            if not public_explanation(step.get("detail")):
                errors.append(
                    f"{case_id}: Security fix step[{index}] detail is not public prose"
                )
            fix_url = str(evidence.get("fix_url") or "").strip()
            fix_match = COMMIT_URL_RE.fullmatch(fix_url)
            if not fix_match:
                errors.append(f"{case_id}: Security fix step has no full commit fix_url")
        raw_roles = [
            role
            for role in ("candidate_hunks", "fix_hunks", "comparison_hunks")
            if evidence.get(role)
        ]
        for role in raw_roles or ["display_hunks"]:
            for index, hunk in enumerate(evidence.get(role) or []):
                if not str(hunk.get("file") or "").strip():
                    errors.append(f"{case_id}: {role}[{index}] has no file")
                if not str(hunk.get("code") or "").strip():
                    errors.append(f"{case_id}: {role}[{index}] has no code")
                if role == "display_hunks":
                    if hunk.get("role") not in HUNK_ROLES:
                        errors.append(
                            f"{case_id}: display_hunks[{index}] has no resolved role"
                        )
                else:
                    expected_role = (
                        comparison_hunk_role(evidence, hunk)
                        if role == "comparison_hunks"
                        else role.removesuffix("_hunks")
                    )
                    if expected_role is None:
                        errors.append(
                            f"{case_id}: {role}[{index}] cannot map to candidate/fix "
                            "and is not a before/after diff"
                        )
                    elif hunk.get("role") != expected_role:
                        errors.append(
                            f"{case_id}: {role}[{index}] role {hunk.get('role')!r} "
                            f"does not match {expected_role!r}"
                        )
                if is_pseudo_annotation(hunk.get("annotation"), context):
                    errors.append(f"{case_id}: {role}[{index}] has a pseudo annotation")
                # A displayed hunk with no reader-facing note ships the diff
                # without the explanation, which is the failure this gate
                # exists to catch; scrubbing can blank an annotation silently.
                if not usable_hunk_annotation(hunk.get("annotation")):
                    errors.append(
                        f"{case_id}: {role}[{index}] has no reader-facing annotation"
                    )
        displayed = [
            ("display_hunks", index, hunk)
            for index, hunk in enumerate(display_hunks(evidence))
        ]
        annotation_mode = evidence.get("annotation_mode")
        if annotation_mode not in {None, "hunk_specific"}:
            errors.append(f"{case_id}: invalid code evidence annotation_mode")
        elif annotation_mode == "hunk_specific":
            if any(
                not valid_unified_hunks(hunk.get("code"))
                for _, _, hunk in displayed
            ):
                errors.append(
                    f"{case_id}: hunk-specific evidence contains an invalid unified diff"
                )
            required_anchors = evidence.get("required_anchors")
            if not isinstance(required_anchors, dict) or not required_anchors:
                errors.append(
                    f"{case_id}: hunk-specific evidence has no required anchors"
                )
            else:
                for anchor_role, anchors in required_anchors.items():
                    if (
                        anchor_role not in {"candidate", "fix"}
                        or not isinstance(anchors, list)
                        or any(not str(anchor or "").strip() for anchor in anchors)
                    ):
                        errors.append(
                            f"{case_id}: invalid {anchor_role} required anchors"
                        )
                        continue
                    if anchor_role not in {
                        str(hunk.get("role")) for _, _, hunk in displayed
                    }:
                        # Anchors only matter for roles that are displayed.
                        continue
                    role_code = "\n".join(
                        str(hunk.get("code") or "")
                        for _, _, hunk in displayed
                        if hunk.get("role") == anchor_role
                    ).casefold()
                    missing = [
                        str(anchor)
                        for anchor in anchors
                        if str(anchor).casefold() not in role_code
                    ]
                    if missing:
                        errors.append(
                            f"{case_id}: missing {anchor_role} anchors: "
                            + ", ".join(missing)
                        )
        displayed_roles = {
            str(hunk.get("role"))
            for _, _, hunk in displayed
            if hunk.get("role") in HUNK_ROLES
        }
        if security_fix_steps and isinstance(fix_files, list):
            witnessed_fix_files = {str(path).strip() for path in fix_files}
            displayed_fix_files = {
                str(hunk.get("file") or "").strip()
                for _, _, hunk in displayed
                if hunk.get("role") == "fix"
            }
            if not displayed_fix_files:
                errors.append(
                    f"{case_id}: Security fix minimum fix has no displayed "
                    "hunk in fix_files"
                )
            elif not displayed_fix_files <= witnessed_fix_files:
                errors.append(
                    f"{case_id}: displayed fix-role files exceed fix_files witness"
                )
        for hunk_role, source_field in (
            ("candidate", "candidate_url"),
            ("fix", "fix_url"),
        ):
            if hunk_role in displayed_roles and not COMMIT_URL_RE.fullmatch(
                str(evidence.get(source_field) or "").strip()
            ):
                errors.append(
                    f"{case_id}: displayed role {hunk_role!r} has no full commit "
                    f"{source_field}"
                )
        fix_url = str(evidence.get("fix_url") or "").strip()
        fix_source = COMMIT_URL_RE.fullmatch(fix_url)
        if fix_url and not fix_source and "fix" not in displayed_roles:
            errors.append(f"{case_id}: fix_url is not a full commit URL")
        if fix_source and fix_source.group("sha").lower() not in {
            str(sha).lower() for sha in case.get("minimum_fix_set") or []
        }:
            errors.append(f"{case_id}: fix_url does not match minimum_fix_set")
        candidate_source = COMMIT_URL_RE.fullmatch(
            str(evidence.get("candidate_url") or "").strip()
        )
        if (
            "candidate" in displayed_roles
            and candidate_source
            and candidate_source.group("sha").lower()
            not in {str(sha).lower() for sha in case.get("candidate_set") or []}
        ):
            errors.append(f"{case_id}: candidate_url does not match candidate_set")
        if candidate_source and candidate_source_repositories:
            source_sha = candidate_source.group("sha").lower()
            source_repo = candidate_source.group("repository").lower()
            if (
                candidate_source_repositories.get(source_sha, "").lower()
                != source_repo
            ):
                errors.append(
                    f"{case_id}: candidate_url does not match candidate_sources"
                )
        for hunk_role in displayed_roles:
            if not has_reader_fallback(case, hunk_role):
                errors.append(
                    f"{case_id}: displayed role {hunk_role!r} has no public context"
                )
        if status == "confirmed":
            if not gates or set(gates.values()) != {"PASS"}:
                errors.append(f"{case_id}: confirmed case does not have all PASS gates")
            if case.get("publication_issues"):
                errors.append(
                    f"{case_id}: confirmed case has publication issues "
                    f"{case.get('publication_issues')}"
                )
            for field in (
                "candidate_set",
                "minimum_fix_set",
                "vulnerable_release",
                "fixed_release",
                "advisory_url",
                "fix_authorship",
            ):
                if (
                    field in {"minimum_fix_set", "fixed_release", "fix_authorship"}
                    and unpatched
                ):
                    continue
                if not case.get(field):
                    errors.append(f"{case_id}: confirmed case has no {field}")
            for role in ("candidate", "fix"):
                if role == "fix" and unpatched:
                    continue
                if not hunks_for_role(evidence, role):
                    errors.append(f"{case_id}: confirmed case has no {role}_hunks")
        published = str(case.get("published_at") or "")
        if not DATE_RE.match(published):
            errors.append(f"{case_id}: missing published_at")
        else:
            dated += 1
        language = str(
            ((case.get("repository_metadata") or {}).get("language") or "").strip()
        )
        if not language:
            errors.append(f"{case_id}: missing repository language")
        if has_hunks(case):
            hunks += 1
            if str(evidence.get("unavailable_reason") or "").strip():
                errors.append(
                    f"{case_id}: code diff exists but unavailable_reason is set"
                )
        else:
            errors.append(f"{case_id}: no code comparison; add hunks")
        ids = official_ids(case)
        release_gate = (case.get("gates") or {}).get("release")
        if has_release(case) or (unpatched and case.get("vulnerable_release")):
            releases += 1
        elif ids and not unpatched:
            if key in release_allow:
                unused_release_allow.discard(key)
                warnings.append(f"{case_id}: no release range ({release_allow[key]})")
            elif release_gate not in {"NARROW", "UNKNOWN"}:
                errors.append(
                    f"{case_id}: official ID has no vulnerable/fixed release; fetch it or allowlist"
                )
        elif ids and unpatched and not case.get("vulnerable_release"):
            if key in release_allow:
                unused_release_allow.discard(key)
                warnings.append(f"{case_id}: no release range ({release_allow[key]})")
            else:
                errors.append(
                    f"{case_id}: unpatched official ID has no vulnerable release; fetch it or allowlist"
                )
        if case.get("contribution_class") == "AI_INCOMPLETE_REMEDIATION" and not case.get("ir_chain"):
            errors.append(f"{case_id}: incomplete remediation without ir_chain")
        if case.get("ir_chain") and case.get("contribution_class") != "AI_INCOMPLETE_REMEDIATION":
            errors.append(
                f"{case_id}: ir_chain present but class is {case.get('contribution_class')}"
            )
        ghsas = [item for item in ids if GHSA_RE.match(item)]
        if len(ghsas) > 1:
            unexpected = [
                item
                for item in ghsas
                if item.upper() != key and item.upper() not in declared_extra_ids
            ]
            if unexpected:
                errors.append(f"{case_id}: multiple GHSAs {ghsas}")
        for official in ids:
            owner = seen_official.get(official.upper())
            if owner and owner != case_id:
                errors.append(f"{official}: claimed by both {owner} and {case_id}")
            seen_official[official.upper()] = case_id
        if snapshot.get("unknown_publication_dates"):
            pass

    if unused_release_allow:
        errors.append(
            "stale missing_release allowlist: "
            + ", ".join(sorted(unused_release_allow)[:12])
        )
    if snapshot.get("unknown_publication_dates", 0) != len(cases) - dated:
        errors.append("snapshot unknown_publication_dates does not match cases")
    if snapshot.get("unknown_publication_dates", 0) != 0:
        errors.append("snapshot still reports unknown publication dates")
    expected_status_counts = {
        "confirmed": snapshot.get("confirmed_cases"),
        "qualified": snapshot.get("qualified_cases"),
        "provisional": snapshot.get("provisional_cases"),
    }
    if expected_status_counts != status_counts:
        errors.append(
            f"snapshot publication counts {expected_status_counts} "
            f"do not match cases {status_counts}"
        )
    census_total = sum(
        int(snapshot.get(field) or 0)
        for field in ("ledger_reviewed", "ledger_in_progress", "ledger_not_started")
    )
    if census_total != snapshot.get("ledger_total"):
        errors.append(
            f"ledger census totals {census_total} but ledger_total="
            f"{snapshot.get('ledger_total')}"
        )

    stats = {
        "cases": len(cases),
        "dated": dated,
        "diffs": hunks,
        "releases": releases,
        "languages": sum(
            1
            for case in cases
            if str(((case.get("repository_metadata") or {}).get("language") or "").strip())
        ),
        "publication_statuses": status_counts,
        "errors": len(errors),
        "warnings": len(warnings),
    }
    return errors, warnings, stats


def main(argv: list[str] | None = None) -> int:
    args = (argv or sys.argv)[1:]
    path_arg = next((arg for arg in args if not arg.startswith("--")), None)
    path = Path(path_arg) if path_arg else DEFAULT_DATA
    payload = load_json(path)
    allowlist = load_json(ALLOWLIST) if ALLOWLIST.exists() else {}
    witness = load_json(FIX_OBJECT_WITNESS) if FIX_OBJECT_WITNESS.exists() else {}
    errors, warnings, stats = evaluate(
        payload,
        allowlist,
        fix_object_witness=witness,
    )
    if "--verify-fix-objects-live" in args and not errors:
        errors.extend(live_fix_object_witness_errors(witness))
        stats["errors"] = len(errors)
    print(
        json.dumps(
            {
                "preflight": "FAIL" if errors else "OK",
                "cases": stats["cases"],
                "dated": f"{stats['dated']}/{stats['cases']}",
                "diffs": f"{stats['diffs']}/{stats['cases']}",
                "releases": f"{stats['releases']}/{stats['cases']}",
                "languages": f"{stats['languages']}/{stats['cases']}",
                "allowlisted": stats["warnings"],
                "errors": stats["errors"],
                "publication_statuses": stats["publication_statuses"],
            },
            sort_keys=True,
        )
    )
    verbose = os.environ.get("SITE_PREFLIGHT_VERBOSE") == "1"
    if verbose:
        for warning in warnings:
            print(f"warn: {warning}")
    if errors:
        print("preflight failed:")
        error_limit = len(errors) if verbose else 40
        for error in errors[:error_limit]:
            print(f"  {error}")
        if len(errors) > error_limit:
            print(f"  ... {len(errors) - error_limit} more")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
