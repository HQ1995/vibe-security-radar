#!/usr/bin/env python3
"""Publish confirmed True Positives from the canonical funnel ledger.

Reads AI_ROOT_CAUSE and AI_CODE_FLAWED rows from the research ledger and
writes web/src/generated/research-data.json. Existing site evidence is reused
when a public advisory ID matches; missing fields stay null rather than guessed.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
OUT = ROOT / "web/src/generated/research-data.json"
OVERRIDES = ROOT / "scripts/tp_publication_overrides.json"
IR_CHAINS = ROOT / "research/orchestrator-260814-irchains-sol/ir-chains.jsonl"
ADVISORY_DATES = ROOT / "scripts/first-party-advisory-dates.json"
ADVISORY_RELEASES = ROOT / "scripts/first-party-advisory-releases.json"
GENERATED_EVIDENCE = ROOT / "scripts/generated-code-evidence.json"
UNPATCHED_FIXES = ROOT / "scripts/unpatched-potential-fixes.json"
REPO_LANGUAGES = ROOT / "scripts/repo-language-map.json"
DATE_FALLBACK = (
    ROOT / "research/orchestrator-260814-ghsa200-canvas/sweep/ghsa-first-party-dates.json"
)

TP_STATUSES = {"AI_ROOT_CAUSE", "AI_CODE_FLAWED"}
# Inclusive GHSA/CVE publication window of the funnel ledger.
LEDGER_WINDOW_START = "2025-05-01"
LEDGER_WINDOW_END = "2026-08-26"
GHSA_RE = re.compile(r"GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}", re.I)
CVE_RE = re.compile(r"(?<![A-Z0-9])CVE-\d{4}-\d{4,7}(?![A-Z0-9])", re.I)
SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
COMMIT_URL_RE = re.compile(r"/commit/([0-9a-fA-F]{7,40})")
REPO_RE = re.compile(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", re.I)
CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\u3000-\u303f]")

FAMILY_PATTERNS = [
    ("claude_flow", re.compile(r"claude[- ]?flow", re.I)),
    ("copilot", re.compile(r"copilot", re.I)),
    ("cursor", re.compile(r"cursor", re.I)),
    ("openai_gpt_codex", re.compile(r"codex|gpt-|openai", re.I)),
    ("claude", re.compile(r"claude|anthropic", re.I)),
]
SCOPE_TO_CLASS = {
    "AI_ROOT_CAUSE": "AI_DIRECT_ROOT",
    "AI_NEW_ATTACK_SURFACE": "AI_NEW_SURFACE_CONTRIBUTOR",
    "AI_INCOMPLETE_FIX": "AI_INCOMPLETE_REMEDIATION",
    "AI_INCOMPLETE_FIX_COMMIT_ONLY": "AI_INCOMPLETE_REMEDIATION",
    "AI_WEAKENED_GUARD": "AI_CAUSAL_CONTRIBUTOR",
    "AI_CODE_FLAWED": "AI_CODE_FLAWED",
}
CAUSE_PATTERNS = [
    ("ssrf_network", re.compile(r"ssrf|server-side request|outbound (url|dial)|private (ip|address)", re.I)),
    ("injection", re.compile(r"xss|cross-site|injection|command|exec|sqli|ssti|rce|deserializ", re.I)),
    ("path_link", re.compile(r"travers|symlink|path (confin|bypass|escape)|link following", re.I)),
    ("auth_access", re.compile(r"auth|access control|permission|privilege|idor|tenant|session", re.I)),
    ("resource_abuse", re.compile(r"dos|denial|resource|unbounded|memory|overflow|exhaust", re.I)),
    ("validation_fail_open", re.compile(r"validat|fail[- ]open|saniti|bypass|denylist|allowlist", re.I)),
]
DEFAULT_GATES = {
    "identity": "UNKNOWN",
    "ai_hunk": "UNKNOWN",
    "topology": "UNKNOWN",
    "but_for": "UNKNOWN",
    "fix_reversal": "UNKNOWN",
    "release": "UNKNOWN",
    "uniqueness": "UNKNOWN",
}
PASS_GATES = {key: "PASS" for key in DEFAULT_GATES}
CAUSE_CATEGORIES = {
    "auth_access": {
        "label": "Authentication & access control",
        "definition": "Broken authentication, authorization, tenancy, or session handling.",
    },
    "injection": {
        "label": "Injection & unsafe execution",
        "definition": "Untrusted input reaches an interpreter, template, command, or query.",
    },
    "path_link": {
        "label": "Path & link handling",
        "definition": "Path traversal, symlink, or link-following flaws.",
    },
    "ssrf_network": {
        "label": "SSRF & network boundaries",
        "definition": "Server-side requests or outbound connections that escape intended bounds.",
    },
    "resource_abuse": {
        "label": "Resource abuse & availability",
        "definition": "Unbounded allocation, loops, or other denial-of-service conditions.",
    },
    "validation_fail_open": {
        "label": "Validation & fail-open logic",
        "definition": "Missing, inverted, or fail-open validation of a security-relevant check.",
    },
    "other_ambiguous": {
        "label": "Other / insufficient public mechanism detail",
        "definition": "The public advisory does not name a more specific mechanism class.",
    },
}
FAMILIES = {
    "claude": {"label": "Claude"},
    "claude_flow": {"label": "claude-flow"},
    "copilot": {"label": "GitHub Copilot"},
    "cursor": {"label": "Cursor"},
    "openai_gpt_codex": {"label": "ChatGPT/Codex"},
}


def unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        key = value.strip()
        if not key or key.lower() in seen:
            continue
        seen.add(key.lower())
        out.append(key)
    return out


def is_official_id(value: str | None) -> bool:
    text = str(value or "")
    return bool(GHSA_RE.match(text) or CVE_RE.match(text))


def drop_original_aliases(case: dict) -> dict:
    """Earlier advisories in an incomplete chain are not aliases of this case."""
    original = {
        str(item).upper()
        for item in ((case.get("ir_chain") or {}).get("original_advisory_ids") or [])
        if item
    }
    if not original:
        return case
    this = {str(case.get("case_id") or "").upper()}
    cves = [
        item
        for item in [case.get("case_id"), *(case.get("aliases") or [])]
        if item and CVE_RE.match(str(item))
    ]
    keep_cves = [item for item in cves if str(item).upper() not in original]
    if keep_cves:
        this.update(str(item).upper() for item in keep_cves)
    elif cves:
        this.add(str(cves[0]).upper())
    case["aliases"] = [
        item
        for item in (case.get("aliases") or [])
        if str(item).upper() in this or str(item).upper() not in original
    ]
    return case


def official_ids_of(case: dict) -> list[str]:
    return unique(
        [
            str(value).upper()
            for value in [case.get("case_id"), *(case.get("aliases") or [])]
            if is_official_id(str(value or ""))
        ]
    )


def sha_prefix(value: str) -> str:
    return value.lower()[:12]


def sha_overlap(left: list[str], right: list[str]) -> bool:
    tokens = [item.lower() for item in left if item] 
    others = [item.lower() for item in right if item]
    for one in tokens:
        for two in others:
            n = min(len(one), len(two), 40)
            if n >= 7 and one[:n] == two[:n]:
                return True
    return False


def sha_from_url(url: object) -> str | None:
    match = COMMIT_URL_RE.search(str(url or ""))
    return match.group(1) if match else None


def repo_matches(cached: dict, repo: str | None) -> bool:
    hit_repo = (cached.get("repository") or "").lower()
    return not (repo and hit_repo and hit_repo != repo.lower())


def detect_family(text: str | None) -> str | None:
    if not text:
        return None
    for family, pattern in FAMILY_PATTERNS:
        if pattern.search(text):
            return family
    return None


def cause_of(text: str | None) -> str:
    for key, pattern in CAUSE_PATTERNS:
        if pattern.search(text or ""):
            return key
    return "other_ambiguous"


def contribution_class(row: dict, rec: dict | None) -> str:
    scope = row.get("site_scope")
    if scope in SCOPE_TO_CLASS:
        return SCOPE_TO_CLASS[scope]
    if row.get("status") == "AI_CODE_FLAWED":
        return "AI_CODE_FLAWED"
    origin = str((rec or {}).get("flaw_origin") or "")
    if re.search(
        r"\b(?:incomplete|partial)\s+(?:fix|patch|remediation)\b"
        r"|\b(?:fix|patch|remediation)\b.{0,80}\b(?:missed|residual)\b"
        r"|\bbypass remained after\b",
        origin,
        re.I,
    ):
        return "AI_INCOMPLETE_REMEDIATION"
    if re.search(r"surface|reachable|prerequisite", origin, re.I):
        return "AI_NEW_SURFACE_CONTRIBUTOR"
    return "AI_DIRECT_ROOT"


def research_records(row: dict) -> list[dict]:
    records: list[dict] = []
    for key in (
        "causal_research",
        "round6_research",
        "round5_research",
        "round4_research",
        "round3_research",
    ):
        value = row.get(key)
        if isinstance(value, dict) and value:
            records.append(value)
    for key, value in row.items():
        if key.startswith("round") and key.endswith("_research") and key not in (
            "round3_research",
            "round4_research",
            "round5_research",
            "round6_research",
        ):
            if isinstance(value, dict) and value:
                records.append(value)
    for key in ("squash_audit", "partial_wave", "blocked535", "blocked106", "blocked_deepwave_research", "blocked_deepwave_refreshed"):
        value = row.get(key)
        if isinstance(value, list):
            records.extend(item for item in value if isinstance(item, dict))
        elif isinstance(value, dict) and value:
            records.append(value)
    status = row.get("status")
    ranked = sorted(
        records,
        key=lambda item: (
            0 if item.get("verdict") == status else 1,
            0 if item.get("introducer_sha") else 1,
            0 if item.get("case_id") else 1,
        ),
    )
    return ranked


def ids_from_text(text: str) -> tuple[list[str], list[str]]:
    return unique(GHSA_RE.findall(text or "")), unique(CVE_RE.findall(text or ""))


def collect_ids(row: dict, rec: dict | None) -> tuple[list[str], list[str]]:
    ghsas: list[str] = []
    cves: list[str] = []
    identity = row.get("advisory_identity") or {}
    for value in identity.get("member_ids") or []:
        g, c = ids_from_text(str(value))
        ghsas.extend(g)
        cves.extend(c)
    subject = identity.get("analysis_subject")
    if subject:
        g, c = ids_from_text(str(subject))
        ghsas.extend(g)
        cves.extend(c)
    if rec:
        for value in [rec.get("case_id"), *(rec.get("advisory_ids") or [])]:
            g, c = ids_from_text(str(value or ""))
            ghsas.extend(g)
            cves.extend(c)
        # Prose may mention sibling advisories in the same repo. Those are
        # not aliases of this case; CVEs are only taken when none is known yet.
        if not cves:
            for key in ("bug_semantics", "evidence", "reasoning", "flaw_origin"):
                _, c = ids_from_text(str(rec.get(key) or ""))
                cves.extend(c)
    ghsas, cves = unique(ghsas), unique(cves)
    # One GHSA is one advisory. Extra GHSAs in squash case_id strings are
    # sibling bugs, not aliases of this case.
    if len(ghsas) > 1:
        preferred = None
        if rec:
            primary, _ = ids_from_text(str(rec.get("case_id") or ""))
            if primary:
                preferred = primary[0]
        ghsas = [preferred or ghsas[0]]
    return ghsas, cves


def collect_shas(rec: dict | None, *keys: str) -> list[str]:
    if not rec:
        return []
    found: list[str] = []
    for key in keys:
        value = rec.get(key)
        if isinstance(value, str) and SHA_RE.match(value):
            found.append(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and SHA_RE.match(item):
                    found.append(item)
                elif isinstance(item, dict):
                    sha = item.get("sha") or item.get("introducer_sha")
                    if isinstance(sha, str) and SHA_RE.match(sha):
                        found.append(sha)
    return unique(found)


def repo_of(row: dict, rec: dict | None) -> str | None:
    for value in (row.get("repo"), (rec or {}).get("repo")):
        if isinstance(value, str) and "/" in value and " " not in value:
            cleaned = value.strip().removeprefix("https://github.com/").strip("/")
            if cleaned.count("/") == 1:
                return cleaned
    blob = json.dumps({"row": row.get("repo"), "rec": rec}, ensure_ascii=False)
    match = REPO_RE.search(blob)
    return match.group(1) if match else None


def first_text(*values: object) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def strip_cjk_tree(value):
    """Remove Chinese characters from published JSON, including hunks and names."""
    if isinstance(value, str):
        text = CJK_RE.sub("", value)
        text = re.sub(r" \(\)", "", text)
        text = re.sub(r"[ \t]+\n", "\n", text)
        text = re.sub(r" {2,}", " ", text)
        return text
    if isinstance(value, list):
        return [strip_cjk_tree(item) for item in value]
    if isinstance(value, dict):
        return {key: strip_cjk_tree(item) for key, item in value.items()}
    return value


def public_text(*values: object) -> str | None:
    """English reader-facing copy only. Internal Chinese audit notes stay off the site."""
    for value in values:
        if not isinstance(value, str):
            continue
        text = value.strip()
        if text and not CJK_RE.search(text):
            return text
    return None


def infer_hunk_file(hunk: dict) -> str | None:
    file = str(hunk.get("file") or "").strip()
    if file:
        return file
    code = str(hunk.get("code") or "")
    for pattern in (
        re.compile(r"^diff --git a/.+? b/(.+)$", re.M),
        re.compile(r"^\+\+\+ b/(.+)$", re.M),
        re.compile(r"^--- a/(.+)$", re.M),
    ):
        match = pattern.search(code)
        if match:
            return match.group(1).strip()
    return None


def trim_mid_sentence(text: str) -> str:
    """Cut a clipped annotation at its last sentence boundary, never mid-word.

    Marker-style strings (sink:/source:/key=value) have no sentence boundary and
    pass through untouched.
    """
    stripped = text.rstrip()
    if len(stripped) < 120 or stripped[-1:] in ".!?\"')":
        return text
    boundary = stripped.rfind(". ")
    if boundary < int(len(stripped) * 0.6):
        return text
    return stripped[: boundary + 1]


def scrub_evidence(evidence: dict | None) -> dict | None:
    if not isinstance(evidence, dict):
        return None
    cleaned = dict(evidence)
    cleaned["summary"] = public_text(evidence.get("summary"))
    marker = evidence.get("ai_marker")
    cleaned["ai_marker"] = public_text(marker) if CJK_RE.search(str(marker or "")) else marker
    steps = []
    for step in evidence.get("steps") or []:
        title = public_text(step.get("title")) or (
            "Change" if CJK_RE.search(str(step.get("title") or "")) else step.get("title")
        )
        steps.append(
            {
                **step,
                "title": title,
                "detail": public_text(step.get("detail")) or "",
            }
        )
    cleaned["steps"] = steps
    full_summary = (
        cleaned.get("summary")
        if len(str(cleaned.get("summary") or "")) > 180
        else (cleaned.get("mechanism") or cleaned.get("summary") or "")
    )
    fulltexts = load_json(ANNOTATION_FULLTEXTS) or {}
    for key in ("candidate_hunks", "fix_hunks", "comparison_hunks"):
        hunks = []
        for hunk in evidence.get(key) or []:
            item = dict(hunk)
            annotation = str(item.get("annotation") or "")
            if CJK_RE.search(annotation):
                item["annotation"] = ""
            elif fulltext := fulltexts.get(annotation):
                item["annotation"] = fulltext
            elif (
                len(annotation) == 180
                and (prose := ANNOTATION_PROSE.get(annotation[:100]))
                and prose.startswith(annotation[:100])
            ):
                item["annotation"] = prose
            elif (
                len(annotation) == 180
                and len(full_summary) > 180
                and full_summary.startswith(annotation[:100])
            ):
                item["annotation"] = full_summary
            else:
                trimmed = trim_mid_sentence(annotation)
                if trimmed != annotation:
                    item["annotation"] = trimmed
            item["file"] = infer_hunk_file(item)
            hunks.append(item)
        cleaned[key] = hunks
    return cleaned


def normalize_fix_authorship(value: object, fixes: list[str]) -> dict | None:
    if not isinstance(value, dict) or not fixes:
        return None
    records = [
        record
        for record in value.get("fixes") or []
        if isinstance(record, dict)
        and record.get("sha")
        and any(sha_overlap([str(record["sha"])], [sha]) for sha in fixes)
        and str((record.get("author") or {}).get("name") or "").strip()
    ]
    if len(records) != len(fixes):
        return None
    return {
        "classification": value.get("classification") or "no_ai_marker",
        "families": [
            family for family in value.get("families") or [] if str(family).strip()
        ],
        "fixes": records,
    }


def advisory_url_of(case: dict) -> str | None:
    override_url = str(case.get("advisory_url") or "").strip()
    if override_url:
        return override_url
    evidence_url = str(((case.get("code_evidence") or {}).get("advisory_url")) or "").strip()
    if evidence_url:
        return evidence_url
    ids = official_ids_of(case)
    ghsa = next((item for item in ids if GHSA_RE.match(item)), None)
    if ghsa:
        return f"https://github.com/advisories/{ghsa}"
    cve = next((item for item in ids if CVE_RE.match(item)), None)
    return f"https://www.cve.org/CVERecord?id={cve}" if cve else None


def publication_issues(case: dict) -> list[str]:
    evidence = case.get("code_evidence") or {}
    issues: list[str] = []
    unpatched = _is_unpatched(case)
    checks = (
        ("missing_candidate", case.get("candidate_set")),
        (
            "missing_ai_attribution",
            (case.get("ai_provenance") or {}).get("coverage") != "unresolved",
        ),
        # An unpatched finding is a complete result, not a missing fix.
        ("missing_fix", (case.get("minimum_fix_set") or unpatched)),
        ("missing_vulnerable_release", case.get("vulnerable_release")),
        # Unpatched findings have no fixed release by definition.
        ("missing_fixed_release", (case.get("fixed_release") or unpatched)),
    )
    issues.extend(name for name, value in checks if not value)
    for role in ("candidate_hunks", "fix_hunks"):
        # A confirmed case must carry both hunk sets (site_preflight contract);
        # their absence keeps the case qualified, never confirmed.
        # Unpatched findings legitimately have no fix hunks.
        if role == "fix_hunks" and unpatched:
            continue
        if not (evidence.get(role) or []):
            issues.append(f"missing_{role.removesuffix('_hunks')}")
        elif any(not str(hunk.get("file") or "").strip() for hunk in evidence.get(role) or []):
            issues.append(f"missing_{role.removesuffix('_hunks')}_file")
    return issues


def first_unpatched(
    case_id: str,
    aliases: list[str],
    class_id: str,
    unpatched_fixes: dict[str, dict],
) -> dict | None:
    for key in (case_id, *aliases, class_id):
        if key:
            record = unpatched_fixes.get(str(key).upper())
            if isinstance(record, dict):
                return record
    return None


def _is_unpatched(case: dict) -> bool:
    record = case.get("unpatched")
    if isinstance(record, dict) and record.get("confirmed") is True:
        return True
    blob = json.dumps(
        {
            "research_status": case.get("research_status"),
            "mechanism": case.get("mechanism"),
            "scope": case.get("scope_statement"),
            "description": case.get("description"),
            "references": case.get("references"),
        },
        ensure_ascii=False,
    ).lower()
    return bool(
        re.search(r"\bunpatched\b", blob)
        or re.search(r"\bno fix\b", blob)
        or re.search(r"\bno fix commit\b", blob)
        or re.search(r"\bno fixing commit\b", blob)
        or re.search(r"\bnever fixed\b", blob)
        or re.search(r"\bno fix released\b", blob)
        or re.search(r"\bno fix was ever released\b", blob)
        or re.search(r"\bvulnerability remains\b", blob)
    )


def publication_status(case: dict) -> str:
    gate_values = set((case.get("gates") or {}).values())
    if not gate_values or "UNKNOWN" in gate_values or not case.get("candidate_set"):
        return "provisional"
    if gate_values == {"PASS"} and not case.get("publication_issues"):
        return "confirmed"
    return "qualified"


def index_existing(existing: dict) -> tuple[dict[str, dict], dict[str, dict]]:
    """Index prior site cases by official ID and by this row's class_id only.

    Do not index alias-* leftovers as if they were advisory IDs. Looking up a
    class_id through another case's alias list is how sibling ledger rows
    stole a GHSA identity.
    """
    official: dict[str, dict] = {}
    by_class: dict[str, dict] = {}
    for case in existing.get("cases") or []:
        class_id = str(case.get("class_id") or "").upper()
        if class_id:
            by_class.setdefault(class_id, case)
        for key in [case.get("case_id"), *(case.get("aliases") or [])]:
            if is_official_id(str(key or "")):
                official.setdefault(str(key).upper(), case)
    return official, by_class


def merge_indexes(
    base: tuple[dict[str, dict], dict[str, dict]],
    extra: tuple[dict[str, dict], dict[str, dict]],
) -> tuple[dict[str, dict], dict[str, dict]]:
    official, by_class = ({**base[0]}, {**base[1]})
    for key, value in extra[0].items():
        official.setdefault(key, value)
    for key, value in extra[1].items():
        by_class.setdefault(key, value)
    return official, by_class


def find_cached(
    ghsas: list[str],
    cves: list[str],
    class_id: str,
    repo: str | None,
    official: dict[str, dict],
    by_class: dict[str, dict],
) -> tuple[dict | None, bool]:
    for key in unique([*ghsas, *cves]):
        hit = official.get(key.upper())
        if hit and repo_matches(hit, repo):
            return hit, True
    hit = by_class.get(class_id.upper())
    if hit and repo_matches(hit, repo):
        return hit, False
    return None, False


def public_shas(
    rec: dict | None,
    cached: dict | None,
    evidence: dict | None = None,
) -> tuple[list[str], list[str]]:
    """One SHA source for listing, diagram, and diffs.

    ``evidence`` (the code_evidence the case will publish) takes priority
    over cached evidence so re-generated comparison hunks stay consistent
    with the listing SHAs.
    """
    candidates = collect_shas(rec, "introducer_sha", "introducer", "introducer_shas")
    if not candidates and cached:
        candidates = list(cached.get("candidate_set") or [])
    fixes = collect_shas(rec, "direct_fix_sha", "fix_sha")
    if not fixes and cached:
        fixes = list(cached.get("minimum_fix_set") or [])
    chain = (cached or {}).get("ir_chain") or {}
    evidence = evidence or (cached or {}).get("code_evidence") or {}
    attempted = ((chain.get("attempted_remediation") or {}).get("candidate_shas") or [])
    final = ((chain.get("final_closure") or {}).get("minimum_fix_shas") or [])
    url_candidate = sha_from_url(evidence.get("candidate_url"))
    url_fix = sha_from_url(evidence.get("fix_url"))
    attempted_shas = [str(item) for item in attempted if SHA_RE.match(str(item))]
    final_shas = [str(item) for item in final if SHA_RE.match(str(item))]
    if attempted_shas:
        candidates = attempted_shas
    elif url_candidate:
        candidates = [url_candidate]
    if final_shas:
        fixes = final_shas
    elif url_fix:
        fixes = [url_fix]
    return unique(candidates), unique(fixes)


def case_quality(case: dict) -> tuple:
    gates = case.get("gates") or {}
    all_pass = bool(gates) and all(value == "PASS" for value in gates.values())
    public_id = str(case.get("case_id") or "")
    return (
        0 if case.get("ir_chain") else 1,
        0 if case.get("code_evidence") else 1,
        0 if all_pass else 1,
        0 if is_official_id(public_id) else 1,
        public_id.upper(),
    )


def merge_duplicate_identities(cases: list[dict]) -> list[dict]:
    """One official advisory ID is one public case (gate 07)."""
    parent = list(range(len(cases)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    buckets: dict[str, list[int]] = {}
    for index, case in enumerate(cases):
        for official_id in official_ids_of(case):
            buckets.setdefault(official_id, []).append(index)
    for indexes in buckets.values():
        for extra in indexes[1:]:
            union(indexes[0], extra)

    clusters: dict[int, list[dict]] = {}
    for index, case in enumerate(cases):
        clusters.setdefault(find(index), []).append(case)

    merged: list[dict] = []
    for group in clusters.values():
        if len(group) == 1:
            merged.append(group[0])
            continue
        winner = dict(min(group, key=case_quality))
        chain = next((item.get("ir_chain") for item in group if item.get("ir_chain")), None)
        evidence = next(
            (item.get("code_evidence") for item in group if item.get("code_evidence")),
            None,
        )
        if chain:
            winner["ir_chain"] = chain
            winner["contribution_class"] = "AI_INCOMPLETE_REMEDIATION"
        if evidence and not winner.get("code_evidence"):
            winner["code_evidence"] = evidence
        winner["candidate_set"], winner["minimum_fix_set"] = public_shas(None, winner)
        provenance = dict(winner.get("ai_provenance") or {})
        provenance["candidate_count"] = len(winner["candidate_set"])
        provenance["named_candidate_count"] = len(winner["candidate_set"])
        winner["ai_provenance"] = provenance
        ids = unique([item for case in group for item in official_ids_of(case)])
        ghsas = [item for item in ids if GHSA_RE.match(item)]
        cves = [item for item in ids if CVE_RE.match(item)]
        if ghsas:
            winner["case_id"] = ghsas[0]
        elif cves:
            winner["case_id"] = cves[0]
        winner["aliases"] = [
            item
            for item in unique(
                [*cves, *ghsas[:1], str(winner.get("class_id") or "")]
            )
            if item.upper() != winner["case_id"].upper()
        ]
        merged.append(drop_original_aliases(winner))
    return merged


def entity_alias_map() -> dict[str, str]:
    """GHSA <-> CVE equivalence map (one advisory, two spellings).

    Loaded from scripts/ghsa-cve-map.json (maintained from GitHub advisory
    API). Catches cross-type duplicates: one case publishing a GHSA while
    another publishes its CVE is the same vulnerability twice.
    """
    path = ROOT / "scripts/ghsa-cve-map.json"
    try:
        payload = json.loads(path.read_text())
    except (FileNotFoundError, ValueError):
        return {}
    out: dict[str, str] = {}
    for key, value in (payload.get("ghsa_to_cve") or {}).items():
        out[str(key).upper()] = str(value).upper()
    for key, value in (payload.get("cve_to_ghsa") or {}).items():
        out[str(key).upper()] = str(value).upper()
    return out


_ENTITY_ALIASES: dict[str, str] | None = None


def expand_entity_ids(official_ids: list[str]) -> list[str]:
    """Expand official IDs to the same-entity spelling (GHSA <-> CVE)."""
    global _ENTITY_ALIASES
    if _ENTITY_ALIASES is None:
        _ENTITY_ALIASES = entity_alias_map()
    out = list(official_ids)
    for oid in official_ids:
        twin = (_ENTITY_ALIASES or {}).get(str(oid).upper())
        if twin:
            out.append(twin)
    return out


def publication_errors(
    cases: list[dict],
    dates: dict[str, str] | None = None,
) -> list[str]:
    errors: list[str] = []
    seen: dict[str, str] = {}
    date_values = set((dates or {}).values())
    for case in cases:
        case_id = case["case_id"]
        if case.get("ir_chain") and case.get("contribution_class") != "AI_INCOMPLETE_REMEDIATION":
            errors.append(f"{case_id}: ir_chain present but class is {case.get('contribution_class')}")
        if case.get("contribution_class") == "AI_INCOMPLETE_REMEDIATION" and not case.get("ir_chain"):
            errors.append(f"{case_id}: incomplete remediation without ir_chain")
        chain = case.get("ir_chain") or {}
        attempted = ((chain.get("attempted_remediation") or {}).get("candidate_shas") or [])
        if attempted and case.get("candidate_set") and not sha_overlap(attempted, list(case["candidate_set"])):
            errors.append(f"{case_id}: listing SHA does not match incomplete-fix SHA")
        url_candidate = sha_from_url(((case.get("code_evidence") or {}).get("candidate_url")))
        if (
            not attempted
            and url_candidate
            and case.get("candidate_set")
            and not sha_overlap([url_candidate], list(case["candidate_set"]))
        ):
            errors.append(f"{case_id}: listing SHA does not match evidence commit")
        ghsas = [item for item in official_ids_of(case) if GHSA_RE.match(item)]
        if len(ghsas) > 1:
            errors.append(f"{case_id}: multiple GHSAs {ghsas}")
        for official_id in unique(expand_entity_ids(official_ids_of(case))):
            owner = seen.get(official_id)
            if owner and owner != case_id:
                errors.append(f"{official_id}: claimed by both {owner} and {case_id}")
            seen[official_id] = case_id
        if not case.get("published_at"):
            errors.append(f"{case_id}: missing published_at")
        elif date_values and case.get("published_at") not in date_values:
            errors.append(
                f"{case_id}: published_at {case.get('published_at')} not traceable "
                f"to the advisory date table (scripts/first-party-advisory-dates.json); "
                f"resolve the real advisory date (web search if the APIs miss it), "
                f"never substitute the introducer commit date"
            )
    return errors


def normalize_ir_chain(raw: dict | None) -> dict | None:
    if not isinstance(raw, dict) or not raw:
        return None
    bic = raw.get("original_introducing_commit") or {}
    original_sha = raw.get("original_sha")
    if not original_sha and isinstance(bic, dict):
        original_sha = bic.get("sha")
    original_name = raw.get("original_author_name")
    if not original_name and isinstance(bic, dict):
        original_name = bic.get("author_name")
    return {
        "original_advisory_ids": list(raw.get("original_advisory_ids") or []),
        "original_mechanism": raw.get("original_mechanism"),
        "original_sink": raw.get("original_sink"),
        "original_author_kind": raw.get("original_author_kind"),
        "original_author_name": original_name,
        "original_sha": original_sha,
        "attempted_remediation": raw.get("attempted_remediation"),
        "residual_bypass": raw.get("residual_bypass"),
        "final_closure": raw.get("final_closure"),
    }


def load_advisory_dates() -> dict[str, str]:
    dates: dict[str, str] = {}
    for path in (DATE_FALLBACK, ADVISORY_DATES):
        payload = load_json(path)
        if not isinstance(payload, dict):
            continue
        for key, value in payload.items():
            text = str(value or "")[:10]
            if key and len(text) >= 10 and text[4] == "-":
                dates[str(key).upper()] = text
    return dates


AI_CASE_SUMMARIES = ROOT / "research/gate-campaign-20260830/summaries-by-alias.json"
ANNOTATION_FULLTEXTS = ROOT / "research/gate-campaign-20260830/annotation-fulltext.json"
ROUND_ADJUDICATION = ROOT / "research/round9-top200-20260828/adjudication"


def ai_summary_overlay(case: dict) -> None:
    """Apply the generated one-line finding to a case's evidence summary in place."""
    summary = AI_SUMMARIES.get(str(case.get("case_id") or "").upper())
    if not summary:
        return
    evidence = case.get("code_evidence")
    if not isinstance(evidence, dict):
        evidence = {}
        case["code_evidence"] = evidence
    evidence["summary"] = summary
    mechanism = AI_SUMMARIES_MECHANISM.get(str(case.get("case_id") or "").upper())
    if mechanism and not CJK_RE.search(mechanism):
        evidence["mechanism"] = mechanism


def load_generated_evidence() -> dict[str, dict]:
    payload = load_json(GENERATED_EVIDENCE)
    if not isinstance(payload, dict):
        return {}
    evidence = {
        str(key).upper(): value
        for key, value in payload.items()
        if isinstance(value, dict)
        and (value.get("comparison_hunks") or value.get("candidate_hunks"))
    }
    return evidence


def _index_prose(value: object) -> None:
    """Index long prose strings by their 100-char prefix for annotation recovery."""
    if isinstance(value, dict):
        for item in value.values():
            _index_prose(item)
    elif isinstance(value, list):
        for item in value:
            _index_prose(item)
    elif isinstance(value, str) and len(value) > 200:
        ANNOTATION_PROSE[value[:100]] = value


def _load_summary_maps() -> None:
    global AI_SUMMARIES, AI_SUMMARIES_MECHANISM, ANNOTATION_PROSE
    overlay = load_json(AI_CASE_SUMMARIES) or {}
    AI_SUMMARIES = {}
    AI_SUMMARIES_MECHANISM = {}
    ANNOTATION_PROSE = {}
    for key, value in overlay.items():
        if not isinstance(value, dict):
            continue
        if value.get("summary"):
            AI_SUMMARIES[str(key).upper()] = str(value["summary"])
        if value.get("mechanism"):
            AI_SUMMARIES_MECHANISM[str(key).upper()] = str(value["mechanism"])
    for line in LEDGER.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            _index_prose(json.loads(line))
        except (json.JSONDecodeError, ValueError):
            continue
    for prose_path in sorted(ROUND_ADJUDICATION.glob("*.json")):
        try:
            _index_prose(json.loads(prose_path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, ValueError, OSError):
            continue
    for patch_path in sorted(ROOT.glob("research/*/finalize-patches.jsonl")):
        for line in patch_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                _index_prose(json.loads(line))
            except (json.JSONDecodeError, ValueError):
                continue
    for key, mechanism in AI_SUMMARIES_MECHANISM.items():
        prose = ANNOTATION_PROSE.get(mechanism[:100])
        if prose and prose.startswith(mechanism):
            AI_SUMMARIES_MECHANISM[key] = prose


AI_SUMMARIES: dict[str, str] = {}
AI_SUMMARIES_MECHANISM: dict[str, str] = {}
ANNOTATION_PROSE: dict[str, str] = {}

def load_repo_languages() -> dict[str, str]:
    payload = load_json(REPO_LANGUAGES)
    if not isinstance(payload, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in payload.items():
        if key and value:
            out[str(key).lower()] = str(value)
    return out


def load_advisory_releases() -> dict[str, dict]:
    payload = load_json(ADVISORY_RELEASES)
    if not isinstance(payload, dict):
        return {}
    out: dict[str, dict] = {}
    for key, value in payload.items():
        if isinstance(value, dict) and (value.get("vulnerable") or value.get("fixed")):
            out[str(key).upper()] = value
    return out


def load_unpatched_fixes() -> dict[str, dict]:
    payload = load_json(UNPATCHED_FIXES)
    if isinstance(payload, list):
        out: dict[str, dict] = {}
        for item in payload:
            if not isinstance(item, dict):
                continue
            record = item.get("unpatched")
            if not isinstance(record, dict):
                continue
            for cid in (item.get("case_id"), item.get("repo")):
                if cid:
                    out[str(cid).upper()] = record
        return out
    if not isinstance(payload, dict):
        return {}
    return {
        str(key).upper(): value
        for key, value in payload.items()
        if isinstance(value, dict)
    }




def release_from_advisory(value: object, kind: str) -> dict | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if SHA_RE.match(text):
        return {"kind": "git_sha", "sha": text, "version": text, "tag": None}
    return {"kind": kind, "version": text, "tag": None}


def first_party_date(*keys: object, dates: dict[str, str]) -> str | None:
    for key in keys:
        if isinstance(key, (list, tuple)):
            hit = first_party_date(*key, dates=dates)
            if hit:
                return hit
            continue
        text = str(key or "").strip()
        if not text:
            continue
        if re.match(r"^\d{4}-\d{2}-\d{2}", text):
            return text[:10]
        hit = dates.get(text.upper())
        if hit:
            return hit
        if len(text) >= 12:
            hit = dates.get(text.upper()[:12])
            if hit:
                return hit
    return None


def load_ir_chains(path: Path) -> dict[str, dict]:
    index: dict[str, dict] = {}
    if not path.exists():
        return index
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        case_id = str(raw.get("case_id") or "").upper()
        chain = normalize_ir_chain(raw)
        if case_id and chain:
            index[case_id] = chain
    return index


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, ValueError):
        return {}


def ledger_census() -> dict[str, int]:
    counts = {
        "AI_ROOT_CAUSE": 0,
        "AI_CODE_FLAWED": 0,
        "NOT_AI": 0,
        "BLOCKED": 0,
        "FALSE_POSITIVE": 0,
        "PARTIALLY_ANALYZED": 0,
        "UNANALYZED": 0,
    }
    total = 0
    for line in LEDGER.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        total += 1
        status = json.loads(line).get("status")
        if status in counts:
            counts[status] += 1
    closed = (
        counts["AI_ROOT_CAUSE"]
        + counts["AI_CODE_FLAWED"]
        + counts["NOT_AI"]
        + counts["BLOCKED"]
        + counts["FALSE_POSITIVE"]
    )
    in_progress = counts["PARTIALLY_ANALYZED"]
    not_started = counts["UNANALYZED"]
    return {
        "total": total,
        "reviewed": closed + in_progress,
        "in_progress": in_progress,
        "not_started": not_started,
        "closed": closed,
    }


def git_head_research_data() -> dict:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "show", "HEAD:web/src/generated/research-data.json"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return {}
    try:
        return json.loads(result.stdout)
    except ValueError:
        return {}


def apply_case_overrides(
    case: dict,
    row: dict,
    rec: dict | None,
    overrides: dict,
    chains: dict[str, dict],
) -> dict:
    class_id = str(row.get("class_id") or "")
    spec = (overrides.get("cases") or {}).get(class_id) or {}
    if spec.get("case_id"):
        previous = case["case_id"]
        case["case_id"] = str(spec["case_id"]).upper()
        case["aliases"] = unique([previous, *(case.get("aliases") or [])])
        case["aliases"] = [
            item for item in case["aliases"] if item.upper() != case["case_id"].upper()
        ]
    if spec.get("repository"):
        case["repository"] = spec["repository"]
        meta = dict(case.get("repository_metadata") or {})
        meta["full_name"] = spec["repository"]
        if spec.get("language"):
            meta["language"] = spec["language"]
        case["repository_metadata"] = meta
    elif spec.get("language"):
        meta = dict(case.get("repository_metadata") or {})
        meta["language"] = spec["language"]
        case["repository_metadata"] = meta
    if spec.get("advisory_url"):
        case["advisory_url"] = str(spec["advisory_url"])
    for field in (
        "severity",
        "cwes",
        "description",
        "references",
        "scope_statement",
        "fix_authorship",
    ):
        if field in spec:
            case[field] = spec[field]
    if spec.get("aliases_extra"):
        case["aliases"] = unique([*(case.get("aliases") or []), *spec["aliases_extra"]])
    if spec.get("drop_aliases"):
        dropped = {str(item).upper() for item in spec["drop_aliases"]}
        case["aliases"] = [
            item for item in (case.get("aliases") or []) if item.upper() not in dropped
        ]
    class_override = (overrides.get("class_overrides") or {}).get(class_id)
    if class_override:
        case["contribution_class"] = class_override
    chain = normalize_ir_chain(spec.get("ir_chain")) if spec.get("ir_chain") else None
    if not chain:
        chain = normalize_ir_chain(row.get("ir_chain"))
    if not chain:
        chain = chains.get(str(case.get("case_id") or "").upper())
    if chain and (
        spec.get("ir_chain")
        or case.get("contribution_class") == "AI_INCOMPLETE_REMEDIATION"
    ):
        case["ir_chain"] = chain
        case["contribution_class"] = "AI_INCOMPLETE_REMEDIATION"
    if spec.get("candidate_set"):
        case["candidate_set"] = list(spec["candidate_set"])
    if spec.get("minimum_fix_set"):
        case["minimum_fix_set"] = list(spec["minimum_fix_set"])
    if case.get("ir_chain") and not spec.get("candidate_set"):
        aligned_candidates, aligned_fixes = public_shas(rec, case)
        if aligned_candidates:
            case["candidate_set"] = aligned_candidates
        if aligned_fixes:
            case["minimum_fix_set"] = aligned_fixes
    provenance = dict(case.get("ai_provenance") or {})
    provenance["candidate_count"] = len(case.get("candidate_set") or [])
    provenance["named_candidate_count"] = len(case.get("candidate_set") or [])
    case["ai_provenance"] = provenance
    return drop_original_aliases(case)


def build_case(
    row: dict,
    official: dict[str, dict],
    by_class: dict[str, dict],
    overrides: dict,
    chains: dict[str, dict],
    dates: dict[str, str],
    releases: dict[str, dict],
    generated_evidence: dict[str, dict],
    unpatched_fixes: dict[str, dict],
    repo_languages: dict[str, str],
) -> dict:
    recs = research_records(row)
    rec = recs[0] if recs else None
    ghsas, cves = collect_ids(row, rec)
    case_id = (ghsas[0] if ghsas else cves[0] if cves else row["class_id"]).upper()
    aliases = unique([*ghsas, *cves, row["class_id"]])
    aliases = [item for item in aliases if item.upper() != case_id]
    repo = repo_of(row, rec)
    cached, official_hit = find_cached(
        ghsas, cves, row["class_id"], repo, official, by_class
    )
    if cached and official_hit:
        if GHSA_RE.match(str(cached.get("case_id") or "")):
            case_id = str(cached["case_id"]).upper()
        cached_cves = [
            alias
            for alias in [cached.get("case_id"), *(cached.get("aliases") or [])]
            if alias and CVE_RE.match(str(alias))
        ]
        cves = unique([*cves, *cached_cves])
        aliases = unique([*ghsas, *cves, row["class_id"]])
        aliases = [item for item in aliases if item.upper() != case_id]
    marker = first_text(
        (rec or {}).get("ai_marker"),
        ((cached or {}).get("code_evidence") or {}).get("ai_marker"),
    )
    family = detect_family(marker) or detect_family(
        json.dumps(rec or {}, ensure_ascii=False)
    )
    cached_evidence = (cached or {}).get("code_evidence") or {}
    mechanism = public_text(
        cached.get("mechanism") if cached else None,
        cached_evidence.get("summary"),
        (rec or {}).get("bug_semantics"),
        (rec or {}).get("flaw_origin"),
    )
    description = public_text(
        cached.get("description") if cached else None,
        cached_evidence.get("summary"),
        mechanism,
    )
    scope_statement = public_text(
        cached.get("scope_statement") if cached else None,
    )
    language = ((cached or {}).get("repository_metadata") or {}).get("language") or repo_languages.get((repo or "").lower()) or ""
    case_evidence = next(
        (
            generated_evidence.get(str(key).upper())
            for key in [case_id, *aliases, row.get("class_id")]
            if (generated_evidence.get(str(key).upper()) or {}).get("comparison_hunks")
        ),
        None,
    ) or (cached or {}).get("code_evidence")
    candidates, fixes = public_shas(rec, cached, case_evidence)
    gates = dict(PASS_GATES) if row.get("site_tier") == "ALL_GATES_PASS" else dict(
        row.get("gates")
        or (cached.get("gates") if cached and cached.get("gates") else None)
        or DEFAULT_GATES
    )
    derived_class = contribution_class(row, rec)
    contribution = (
        "AI_INCOMPLETE_REMEDIATION"
        if (cached or {}).get("ir_chain") or derived_class == "AI_INCOMPLETE_REMEDIATION"
        else derived_class
    )
    case = {
        "case_id": case_id,
        "class_id": row["class_id"],
        "aliases": aliases,
        "repository": repo,
        "repository_metadata": {
            "full_name": repo or ((cached or {}).get("repository_metadata") or {}).get("full_name") or "",
            "language": language,
            "archived": bool(((cached or {}).get("repository_metadata") or {}).get("archived")),
        },
        "contribution_class": contribution,
        "ledger_status": row["status"],
        "candidate_set": candidates,
        "carrier_set": list((cached or {}).get("carrier_set") or []),
        "minimum_fix_set": fixes,
        "gates": gates,
        "vulnerable_release": (cached or {}).get("vulnerable_release")
        or release_from_advisory(
            next(
                (
                    (releases.get(str(key).upper()) or {}).get("vulnerable")
                    for key in [case_id, *aliases]
                    if (releases.get(str(key).upper()) or {}).get("vulnerable")
                ),
                None,
            ),
            "advisory_range",
        ),
        "fixed_release": (cached or {}).get("fixed_release")
        or release_from_advisory(
            next(
                (
                    (releases.get(str(key).upper()) or {}).get("fixed")
                    for key in [case_id, *aliases]
                    if (releases.get(str(key).upper()) or {}).get("fixed")
                ),
                None,
            ),
            "advisory_version",
        ),
        "published_at": first_party_date(
            case_id,
            aliases,
            candidates,
            (cached or {}).get("published_at"),
            dates=dates,
        ),
        "severity": (cached or {}).get("severity"),
        "cwes": list((cached or {}).get("cwes") or []),
        "description": description,
        "references": list((cached or {}).get("references") or []),
        "mechanism_key": (cached or {}).get("mechanism_key"),
        "mechanism": mechanism,
        "scope_statement": scope_statement,
        "cause_category": (cached or {}).get("cause_category")
        or cause_of(
            first_text(
                (rec or {}).get("bug_semantics"),
                (rec or {}).get("flaw_origin"),
                (rec or {}).get("evidence"),
                mechanism,
            )
        ),
        "ai_provenance": {
            "family": family or ((cached or {}).get("ai_provenance") or {}).get("family"),
            "coverage": (
                "complete"
                if family or ((cached or {}).get("ai_provenance") or {}).get("coverage") == "complete"
                else "generic"
                if marker
                else "unresolved"
            ),
            "candidate_count": len(candidates),
            "named_candidate_count": len(candidates),
            "note": public_text(marker),
        },
        "fix_authorship": (cached or {}).get("fix_authorship"),
        "code_evidence": scrub_evidence(
            next(
                (
                    generated_evidence.get(str(key).upper())
                    for key in [case_id, *aliases, row.get("class_id")]
                    if (generated_evidence.get(str(key).upper()) or {}).get(
                        "comparison_hunks"
                    )
                ),
                None,
            )
            or (cached or {}).get("code_evidence")
        ),
        "ir_chain": (cached or {}).get("ir_chain"),
    }
    case["research_status"] = " ".join(
        str((rec or {}).get(key) or "") for key in ("remaining_gap", "evidence")
    ).strip() or None
    case["unpatched"] = first_unpatched(
        case_id, aliases, row.get("class_id"), unpatched_fixes
    )
    case = apply_case_overrides(case, row, rec, overrides, chains)
    case["fix_authorship"] = normalize_fix_authorship(
        case.get("fix_authorship"), list(case.get("minimum_fix_set") or [])
    )
    case["advisory_url"] = advisory_url_of(case)
    case["publication_issues"] = publication_issues(case)
    case["publication_status"] = publication_status(case)
    if not case.get("published_at"):
        case["published_at"] = first_party_date(
            case["case_id"],
            list(case.get("aliases") or []),
            list(case.get("candidate_set") or []),
            dates=dates,
        )
    return strip_cjk_tree(drop_original_aliases(case))

def main() -> None:
    _load_summary_maps()
    existing = git_head_research_data() or load_json(OUT)
    cache = merge_indexes(
        index_existing(existing),
        index_existing(load_json(ROOT / "web/src/generated/research-data.base84.json")),
    )
    overrides = load_json(OVERRIDES)
    chains = load_ir_chains(IR_CHAINS)
    dates = load_advisory_dates()
    releases = load_advisory_releases()
    generated_evidence = load_generated_evidence()
    unpatched_fixes = load_unpatched_fixes()
    repo_languages = load_repo_languages()
    drop_class_ids = {
        str(item).lower() for item in (overrides.get("drop_class_ids") or [])
    }
    cases: list[dict] = []
    for line in LEDGER.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("status") not in TP_STATUSES:
            continue
        if (row.get("site_publication") or {}).get("publish") is False:
            continue
        if str(row.get("class_id") or "").lower() in drop_class_ids:
            continue
        case = build_case(
            row,
            cache[0],
            cache[1],
            overrides,
            chains,
            dates,
            releases,
            generated_evidence,
            unpatched_fixes,
            repo_languages,
        )
        case["aliases"] = [
            item
            for item in case["aliases"]
            if item.upper() != case["case_id"].upper()
        ]
        cases.append(case)
    cases = merge_duplicate_identities(cases)
    for case in cases:
        ai_summary_overlay(case)

    root_cause = sum(1 for item in cases if item["ledger_status"] == "AI_ROOT_CAUSE")
    code_flawed = sum(1 for item in cases if item["ledger_status"] == "AI_CODE_FLAWED")
    cases.sort(
        key=lambda item: (
            item.get("published_at") or "",
            item["case_id"],
        ),
        reverse=True,
    )
    dated = sum(1 for item in cases if item.get("published_at"))
    census = ledger_census()
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "snapshot": {
            "status": "PUBLISHED",
            "case_set": "TP_FUNNEL",
            "case_count": len(cases),
            "ai_root_cause": root_cause,
            "ai_code_flawed": code_flawed,
            "ledger_total": census["total"],
            "ledger_reviewed": census["closed"],
            "ledger_in_progress": census["in_progress"],
            "ledger_not_started": census["not_started"],
            "confirmed_cases": sum(
                item["publication_status"] == "confirmed" for item in cases
            ),
            "qualified_cases": sum(
                item["publication_status"] == "qualified" for item in cases
            ),
            "provisional_cases": sum(
                item["publication_status"] == "provisional" for item in cases
            ),
            "exact_publication_dates": dated,
            "unknown_publication_dates": len(cases) - dated,
            "date_policy": "GHSA_OR_CVE_PUBLISHED_ONLY",
            "coverage_from": LEDGER_WINDOW_START,
            "coverage_to": LEDGER_WINDOW_END,
            "source_cutoff": LEDGER_WINDOW_END,
            "generated_at": generated_at,
            "ledger": "artifacts/funnel-account-20260817.jsonl",
        },
        "cause_categories": existing.get("cause_categories") or CAUSE_CATEGORIES,
        "ai_provenance_families": FAMILIES,
        "cases": cases,
    }

    ai_commit_census = load_json(
        ROOT / "research/ai-commit-census-current/ai-commit-census.json"
    )
    if ai_commit_census.get("total_commits"):
        window = ai_commit_census.get("window") or {}
        payload["ai_commit_census"] = {
            "window": {
                "since": str(window.get("since") or LEDGER_WINDOW_START),
                "until": str(window.get("until") or LEDGER_WINDOW_END),
            },
            "repos_scanned": ai_commit_census.get("repos_scanned") or 0,
            "repos_missing": ai_commit_census.get("repos_missing") or [],
            "total_commits": ai_commit_census.get("total_commits") or 0,
            "marked_ai_commits": ai_commit_census.get("marked_ai_commits") or 0,
            "families": {
                key: {
                    "marked": (value or {}).get("marked") or 0,
                    "trailer": (value or {}).get("trailer") or 0,
                    "author": (value or {}).get("author") or 0,
                    "text": (value or {}).get("text") or 0,
                }
                for key, value in (ai_commit_census.get("families") or {}).items()
            },
        }

    leaks = [
        case["case_id"]
        for case in cases
        if CJK_RE.search(json.dumps(case, ensure_ascii=False))
    ]
    if leaks:
        raise SystemExit(
            f"CJK leaked into public fields: {leaks[:12]} ({len(leaks)} total)"
        )
    identity_errors = publication_errors(cases, dates)
    if identity_errors:
        raise SystemExit(
            "publication invariants failed:\n" + "\n".join(identity_errors[:20])
        )

    staged = OUT.with_suffix(".json.staging")
    staged.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n")
    preflight = subprocess.run(
        [sys.executable, str(ROOT / "scripts/site_preflight.py"), str(staged)]
    )
    if preflight.returncode != 0:
        staged.unlink(missing_ok=True)
        raise SystemExit("site preflight failed; research-data.json was not updated")
    staged.replace(OUT)
    with_evidence = sum(1 for item in cases if item.get("code_evidence"))
    print(
        json.dumps(
            {
                "cases": len(cases),
                "ai_root_cause": root_cause,
                "ai_code_flawed": code_flawed,
                "dated": dated,
                "code_evidence": with_evidence,
                "out": str(OUT),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
