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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = ROOT / "web/src/generated/research-data.json"
ALLOWLIST = ROOT / "scripts/site_preflight_allowlist.json"
FIX_OBJECT_WITNESS = ROOT / "scripts/published-fix-object-witness.json"
PUBLICATION_ADJUDICATIONS = ROOT / "scripts/publication_adjudications.json"
EVIDENCE_FETCH_OVERRIDES = ROOT / "scripts/evidence_fetch_overrides.json"
EVIDENCE_REQUIRED_ROLES = ROOT / "scripts/code-evidence-required-roles.json"
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
PSEUDO_ANNOTATION_RE = re.compile(
    r"^(?:AI introduced this behavior|AI removed a constraint|The fix adds):",
    re.I,
)
INTERNAL_PROSE_RE = re.compile(
    r"cand=|fix=|ai=\['|/tmp/|sink=|source=|guard=|class_id|"
    r"\\s\+|decomposed_shas|bug_semantics",
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
    return bool(
        evidence.get("comparison_hunks")
        or evidence.get("candidate_hunks")
        or evidence.get("fix_hunks")
    )


def public_explanation(value: object) -> bool:
    """Mirror the site's compact public-prose test for diff fallbacks."""
    text = str(value or "").strip()
    words = text.split()
    if not 24 <= len(text) <= 360 or len(words) < 5:
        return False
    if INTERNAL_PROSE_RE.search(text):
        return False
    if text.count("/") >= 4 and len(words) < 12 and not re.search(r"[.!?]\s", text):
        return False
    return bool(re.search(r"[a-z]", text, re.I))


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


def is_pseudo_annotation(value: object, context: tuple[str, ...]) -> bool:
    text = str(value or "").strip()
    return bool(text) and (bool(PSEUDO_ANNOTATION_RE.match(text)) or text in context)


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
    if evidence.get("fix_hunks") or any(
        hunk.get("role") == "fix"
        for hunk in evidence.get("comparison_hunks") or []
    ):
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
        try:
            return repository, sha, github_commit_sha(repository, sha)
        except (OSError, TimeoutError, UnicodeError, ValueError):
            return repository, sha, None

    with ThreadPoolExecutor(max_workers=min(12, len(targets) or 1)) as pool:
        results = list(pool.map(verify, targets))
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

        role_hunks = evidence.get(f"{role}_hunks") or []
        if not role_hunks:
            errors.append(f"{case_id}: required {role} role emitted no hunk")
        comparison_role_hunks = [
            hunk
            for hunk in evidence.get("comparison_hunks") or []
            if hunk.get("role") == role
        ]
        displayed_role_hunks = (
            comparison_role_hunks
            if evidence.get("comparison_hunks")
            else role_hunks
        )
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


def evaluate(
    payload: dict,
    allowlist: dict | None = None,
    fix_object_witness: dict | None = None,
    publication_adjudications: dict | None = None,
    evidence_fetch_overrides: dict | None = None,
    evidence_required_roles: dict | None = None,
) -> tuple[list[str], list[str], dict]:
    allowlist = allowlist or {}
    diff_allow = {
        key.upper(): reason
        for key, reason in (allowlist.get("missing_diff") or {}).items()
    }
    release_allow = {
        key.upper(): reason
        for key, reason in (allowlist.get("missing_release") or {}).items()
    }
    cases = payload.get("cases") or []
    snapshot = payload.get("snapshot") or {}
    errors: list[str] = []
    warnings: list[str] = []
    seen_official: dict[str, str] = {}
    dated = 0
    hunks = 0
    releases = 0
    status_counts = {status: 0 for status in PUBLICATION_STATUSES}
    unused_diff_allow = set(diff_allow)
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

    if snapshot.get("case_count") != len(cases):
        errors.append(
            f"snapshot.case_count={snapshot.get('case_count')} but cases={len(cases)}"
        )

    for case in cases:
        case_id = str(case.get("case_id") or "")
        key = case_id.upper()
        blob = json.dumps(case, ensure_ascii=False)
        if CJK_RE.search(blob):
            errors.append(f"{case_id}: CJK leaked into public fields")
        status = str(case.get("publication_status") or "")
        if status not in status_counts:
            errors.append(f"{case_id}: invalid publication_status {status!r}")
        else:
            status_counts[status] += 1
        evidence = case.get("code_evidence") or {}
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
        for role in ("candidate_hunks", "fix_hunks", "comparison_hunks"):
            for index, hunk in enumerate(evidence.get(role) or []):
                if not str(hunk.get("file") or "").strip():
                    errors.append(f"{case_id}: {role}[{index}] has no file")
                if not str(hunk.get("code") or "").strip():
                    errors.append(f"{case_id}: {role}[{index}] has no code")
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
                if str(hunk.get("annotation") or "").strip() and not public_explanation(
                    hunk.get("annotation")
                ):
                    errors.append(
                        f"{case_id}: {role}[{index}] annotation is not public prose"
                    )
        displayed = [
            ("comparison_hunks", index, hunk)
            for index, hunk in enumerate(evidence.get("comparison_hunks") or [])
        ] or [
            (role, index, hunk)
            for role in ("candidate_hunks", "fix_hunks")
            for index, hunk in enumerate(evidence.get(role) or [])
        ]
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
        displayed_annotations = [
            str(hunk.get("annotation") or "").strip()
            for _, _, hunk in displayed
            if str(hunk.get("annotation") or "").strip()
        ]
        if len(displayed_annotations) != len(set(displayed_annotations)):
            errors.append(f"{case_id}: displayed hunks repeat the same annotation")
        for hunk_role in displayed_roles:
            if not has_reader_fallback(case, hunk_role):
                errors.append(
                    f"{case_id}: displayed role {hunk_role!r} has no public context"
                )
        for role, index, hunk in displayed:
            annotation = hunk.get("annotation")
            if hunk.get("role") == "before_after" and (
                not public_explanation(annotation)
                or is_pseudo_annotation(annotation, context)
            ):
                errors.append(
                    f"{case_id}: {role}[{index}] before_after hunk has no "
                    "genuine annotation"
                )
        if status == "confirmed":
            gates = case.get("gates") or {}
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
            ):
                if field in {"minimum_fix_set", "fixed_release"} and unpatched:
                    continue
                if not case.get(field):
                    errors.append(f"{case_id}: confirmed case has no {field}")
            for role in ("candidate_hunks", "fix_hunks"):
                if role == "fix_hunks" and unpatched:
                    continue
                if not evidence.get(role):
                    errors.append(f"{case_id}: confirmed case has no {role}")
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
        elif key in diff_allow:
            unused_diff_allow.discard(key)
            warnings.append(f"{case_id}: no diff ({diff_allow[key]})")
            reason = str(evidence.get("unavailable_reason") or "").strip()
            expected_reason = str(diff_allow[key] or "").strip()
            if reason != expected_reason or not public_explanation(reason):
                errors.append(
                    f"{case_id}: missing_diff reason is not published verbatim as "
                    "code_evidence.unavailable_reason"
                )
        else:
            errors.append(
                f"{case_id}: no code comparison; add hunks or allowlist a reason"
            )
        ids = official_ids(case)
        if has_release(case) or (unpatched and case.get("vulnerable_release")):
            releases += 1
        elif ids and not unpatched:
            if key in release_allow:
                unused_release_allow.discard(key)
                warnings.append(f"{case_id}: no release range ({release_allow[key]})")
            else:
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
            errors.append(f"{case_id}: multiple GHSAs {ghsas}")
        for official in ids:
            owner = seen_official.get(official.upper())
            if owner and owner != case_id:
                errors.append(f"{official}: claimed by both {owner} and {case_id}")
            seen_official[official.upper()] = case_id
        if snapshot.get("unknown_publication_dates"):
            pass

    if unused_diff_allow:
        errors.append(
            "stale missing_diff allowlist: " + ", ".join(sorted(unused_diff_allow)[:12])
        )
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
        for error in errors[:40]:
            print(f"  {error}")
        if len(errors) > 40:
            print(f"  ... {len(errors) - 40} more")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
