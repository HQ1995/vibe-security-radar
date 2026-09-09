#!/usr/bin/env python3
"""Publish confirmed True Positives from the Neon ledger.

Reads AI_ROOT_CAUSE and AI_CODE_FLAWED rows from Neon ledger_rows and
writes web/src/generated/research-data.json. The committed jsonl file is a
recovery export, not a default publish input: --from-export restores offline
and --prefer-export uses it only while its digest matches Neon.
Existing site evidence is reused when a public advisory ID matches; missing
fields stay null rather than guessed.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from site_preflight import (
    AUDIT_IDENTIFIER_RE,
    comparison_hunk_role,
    is_pseudo_annotation,
    public_explanation,
    usable_hunk_annotation,
)

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
OUT = ROOT / "web/src/generated/research-data.json"
OVERRIDES = ROOT / "scripts/tp_publication_overrides.json"
IR_CHAINS = ROOT / "research/orchestrator-260814-irchains-sol/ir-chains.jsonl"
IR_CHAIN_UPDATES = ROOT / "research/ir-chain-origin-rereview-20260830/ir-chain-updates.jsonl"
ADVISORY_DATES = ROOT / "scripts/first-party-advisory-dates.json"
GENERATED_EVIDENCE = ROOT / "scripts/generated-code-evidence.json"
UNPATCHED_FIXES = ROOT / "scripts/unpatched-potential-fixes.json"
SECURITY_FIX_CONTEXTS = ROOT / "scripts/security-fix-contexts.json"
RELEASE_FALLBACKS = ROOT / "scripts/release-fallbacks.json"
CURATION = ROOT / "scripts/publication-curation.json"

_DB_DISPLAY_CACHE: dict[str, dict] = {}
_DB_DISPLAY_UNAVAILABLE = False


def _db_display_kind(kind: str) -> dict:
    """Fetch one ledger_display kind from Neon, cached per process.

    Only the requested kind is fetched; the full table is ~2.4 MB and callers
    such as the postbuild ir-chain test need a single small kind. Overlay only:
    case rows come from ledger_rows and never fall back to jsonl, while a
    display miss falls back to committed research/ files at the call site.
    """
    global _DB_DISPLAY_UNAVAILABLE
    if kind not in _DB_DISPLAY_CACHE and not _DB_DISPLAY_UNAVAILABLE:
        if not os.environ.get("DATABASE_URL"):
            _DB_DISPLAY_UNAVAILABLE = True
        else:
            try:
                sys.path.insert(0, str(ROOT / "scripts"))
                from ledger_store import connect

                with connect(direct=True) as conn:
                    row = conn.execute(
                        "SELECT value_json FROM ledger_display WHERE kind = %s",
                        (kind,),
                    ).fetchone()
                if row is not None and isinstance(row[0], dict):
                    _DB_DISPLAY_CACHE[kind] = row[0]
            except Exception as exc:  # noqa: BLE001 - never break publication
                print(
                    f"ledger_display unavailable (falling back to files): {exc}",
                    file=sys.stderr,
                )
                _DB_DISPLAY_UNAVAILABLE = True
        _DB_DISPLAY_CACHE.setdefault(kind, {})
    return _DB_DISPLAY_CACHE.get(kind) or {}

TP_STATUSES = {"AI_ROOT_CAUSE", "AI_CODE_FLAWED"}

def _read_export_rows() -> list[dict]:
    rows = []
    for line in LEDGER.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rows.append(json.loads(line))
    return rows


def export_matches_neon() -> bool:
    """True when the local jsonl export equals the Neon snapshot digest.

    The digest is computed in the database, so the freshness probe costs one
    small query instead of a full-table transfer. A stale export must never be
    published; callers fall back to reading Neon ledger_rows.
    """
    if not LEDGER.exists():
        return False
    sys.path.insert(0, str(ROOT / "scripts"))
    from ledger_store import load_env, snapshot_sha256

    load_env()
    digest = hashlib.sha256(LEDGER.read_bytes()).hexdigest()
    return digest == snapshot_sha256()


def load_ledger_rows(*, from_export: bool = False) -> list[dict]:
    """Load ledger rows for publication.

    Neon ledger_rows is the default publish input. The jsonl file is a recovery
    export; pass from_export=True for offline restore, or gate it on
    export_matches_neon() to publish from the backup without row egress.
    """
    if from_export:
        return _read_export_rows()
    sys.path.insert(0, str(ROOT / "scripts"))
    from ledger_store import connect, load_env

    load_env()
    if not os.environ.get("DATABASE_URL") and not os.environ.get(
        "DATABASE_URL_UNPOOLED"
    ):
        raise SystemExit(
            "publish reads Neon ledger_rows; set DATABASE_URL. "
            "jsonl is export-only (pass --from-export for the backup)."
        )
    with connect(direct=bool(os.environ.get("DATABASE_URL_UNPOOLED"))) as conn:
        fetched = conn.execute(
            """
            SELECT raw_json FROM ledger_rows
            WHERE status IN ('AI_ROOT_CAUSE', 'AI_CODE_FLAWED')
            ORDER BY ordinal
            """
        ).fetchall()
    return [json.loads(raw) for (raw,) in fetched]

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

# Reader-facing category copy lives here so the payload is a pure function of
# its inputs; it used to be read back from the previous snapshot, which froze
# these definitions at whatever a legacy pipeline had published.
CAUSE_CATEGORIES = {
    "auth_access": {
        "definition": (
            "Missing, bypassed, or confused authentication, authorization, "
            "identity, ownership, tenant, or privilege boundaries."
        ),
        "label": "Authentication & access control",
    },
    "injection": {
        "definition": (
            "Untrusted data reaches command, shell, template, script, query, "
            "spreadsheet, HTML, or similar execution contexts without safe "
            "encoding or isolation."
        ),
        "label": "Injection & unsafe execution",
    },
    "other_ambiguous": {
        "definition": (
            "The canonical mechanism fields do not expose enough stable public "
            "detail for a more specific cause category."
        ),
        "label": "Other / insufficient public mechanism detail",
    },
    "path_link": {
        "definition": (
            "Unsafe path construction, filesystem scope checks, archive "
            "extraction, local file access, or symbolic-link handling."
        ),
        "label": "Path & link handling",
    },
    "resource_abuse": {
        "definition": (
            "Unbounded input, computation, memory, storage, retry, rate, or "
            "loop behavior enables denial of service or disproportionate "
            "resource use."
        ),
        "label": "Resource abuse & availability",
    },
    "ssrf_network": {
        "definition": (
            "Unsafe URL parsing, redirects, proxying, credential forwarding, or "
            "destination checks allow unintended network access or "
            "trust-boundary crossing."
        ),
        "label": "SSRF & network boundaries",
    },
    "validation_fail_open": {
        "definition": (
            "A security validator, denylist, signature, or schema check is "
            "incomplete, incorrectly ordered, or allows processing after "
            "validation cannot be established."
        ),
        "label": "Validation & fail-open logic",
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
    if "causal_research" in row:
        record = row["causal_research"]
        if not isinstance(record, dict) or not record:
            raise ValueError(f"{row.get('class_id')}: causal_research must be a nonempty object")
        if record.get("verdict") != row.get("status"):
            raise ValueError(f"{row.get('class_id')}: causal_research verdict must match status")
        return [record]
    records: list[dict] = []
    for key in (
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
        return CJK_RE.sub("", value)
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


def ledger_value(row: dict, key: str, fallback, clean=None):
    """The ledger owns a field when the key is present, even when it is empty.

    Presence, not truthiness, is the contract: a canonical empty value must not
    fall back to the committed curation snapshot, or a rejected mechanism comes
    back. Every canonical-vs-snapshot choice routes through here.
    """
    if key not in row:
        return fallback
    return clean(row[key]) if clean else row[key]


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


def scrub_evidence(
    evidence: dict | None, case_context: tuple[object, ...] = ()
) -> dict | None:
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
    annotation_context = tuple(
        str(value).strip()
        for value in (
            cleaned.get("summary"),
            cleaned.get("mechanism"),
            *case_context,
        )
        if str(value or "").strip()
    )
    for key in ("candidate_hunks", "fix_hunks", "comparison_hunks"):
        hunks = []
        for hunk in evidence.get(key) or []:
            item = dict(hunk)
            annotation = str(item.get("annotation") or "")
            if CJK_RE.search(annotation):
                annotation = ""
            elif (
                len(annotation) == 180
                and (prose := ANNOTATION_PROSE.get(annotation[:100]))
                and prose.startswith(annotation[:100])
            ):
                annotation = prose
            elif (
                len(annotation) == 180
                and len(full_summary) > 180
                and full_summary.startswith(annotation[:100])
            ):
                annotation = full_summary
            annotation = trim_mid_sentence(annotation)
            usable = usable_hunk_annotation(annotation)
            item["annotation"] = (
                ""
                if not usable or is_pseudo_annotation(usable, annotation_context)
                else usable
            )
            item["file"] = infer_hunk_file(item)
            if key == "candidate_hunks":
                item["role"] = "candidate"
            elif key == "fix_hunks":
                item["role"] = "fix"
            hunks.append(item)
        cleaned[key] = hunks
    for hunk in cleaned["comparison_hunks"]:
        hunk["role"] = comparison_hunk_role(cleaned, hunk)
    displayed = cleaned["comparison_hunks"] or [
        *cleaned["candidate_hunks"],
        *cleaned["fix_hunks"],
    ]
    seen_annotations: set[str] = set()
    for hunk in displayed:
        annotation = str(hunk.get("annotation") or "").strip()
        if annotation in seen_annotations:
            hunk["annotation"] = ""
        elif annotation:
            seen_annotations.add(annotation)
    return cleaned


def apply_security_fix_context(evidence: dict, context: object) -> None:
    if not isinstance(context, dict):
        return
    raw_fix_files = context.get("fix_files")
    fix_files = unique(
        [str(path).strip() for path in raw_fix_files if str(path).strip()]
        if isinstance(raw_fix_files, list)
        else []
    )
    evidence["steps"] = [
        step
        for step in evidence.get("steps") or []
        if str(step.get("title") or "").strip().lower()
        not in {"fix", "security fix"}
    ] + [
        {
            "title": "Security fix",
            "detail": str(context.get("detail") or "").strip(),
        }
    ]
    evidence["fix_url"] = str(context.get("fix_url") or "").strip()
    evidence["fix_files"] = fix_files
    allowed = set(fix_files)
    evidence["fix_hunks"] = [
        hunk
        for hunk in evidence.get("fix_hunks") or []
        if str(hunk.get("file") or "").strip() in allowed
    ]
    evidence["comparison_hunks"] = [
        hunk
        for hunk in evidence.get("comparison_hunks") or []
        if hunk.get("role") != "fix"
        or str(hunk.get("file") or "").strip() in allowed
    ]


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


_FIX_AI_FAMILY_MAP = (
    ("claude_flow", ("claude-flow", "claude flow")),
    ("copilot", ("copilot",)),
    ("cursor", ("cursor",)),
    ("google_jules", ("google_jules", "jules")),
    ("openai_gpt_codex", ("codex", "gpt", "openai")),
    ("claude", ("claude", "anthropic")),
)


def _fix_ai_families(marker_text: str) -> list[str]:
    tokens = [token.strip().lower() for token in str(marker_text or "").split(",")]
    families: list[str] = []
    for family, aliases in _FIX_AI_FAMILY_MAP:
        if any(token in aliases for token in tokens) and family not in families:
            families.append(family)
    return families


def derive_fix_authorship(rec: dict | None, fixes: list[str]) -> dict | None:
    if not isinstance(rec, dict) or not fixes:
        return None
    marker = rec.get("fix_ai_marker")
    if not isinstance(marker, dict):
        return None
    per_sha = marker.get("per_sha")
    if not isinstance(per_sha, dict):
        return None
    seen: list[dict] = []
    for sha in fixes:
        match = next(
            (
                per
                for key, per in per_sha.items()
                if isinstance(per, dict) and sha_overlap([str(key)], [sha])
            ),
            None,
        )
        if match is None:
            return None
        state = str(match.get("state") or "").upper()
        if state not in ("PRESENT", "ABSENT"):
            return None
        evidence = [str(item) for item in match.get("evidence") or []]
        blob = " ".join(evidence)
        author = re.search(r"author\s+(.*?)\s*<([^>]*)>", blob)
        name = (author.group(1) if author else "").strip()
        email = (author.group(2) if author else "").strip()
        if not name:
            return None
        marker_line = next(
            (line for line in evidence if re.search(r"AI marker\(s\)", line)),
            "",
        )
        families = _fix_ai_families(marker_line.split(":", 1)[-1])
        entry: dict = {
            "sha": sha,
            "classification": "ai_assisted" if state == "PRESENT" else "no_ai_marker",
            "author": {"name": name, "email": email},
        }
        if state == "PRESENT":
            entry["families"] = families
        seen.append(entry)
    classes = {entry["classification"] for entry in seen}
    classification = (
        "ai_assisted"
        if classes == {"ai_assisted"}
        else "no_ai_marker"
        if classes == {"no_ai_marker"}
        else "mixed"
    )
    families_out: list[str] = []
    for entry in seen:
        for family in entry.pop("families", []):
            if family not in families_out:
                families_out.append(family)
    return {"classification": classification, "families": families_out, "fixes": seen}


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
        # Fix authorship must be analyzed so the site can show who fixed it and whether they used AI.
        ("missing_fix_authorship", (case.get("fix_authorship") or unpatched)),
    )
    issues.extend(name for name, value in checks if not value)
    fallback = release_fallback(case)
    if fallback and (case.get("gates") or {}).get("release") != "PASS":
        issues.append(f"release_fallback:{fallback.get('reason')}")
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


def strip_unpatched_fix_claims(case: dict) -> None:
    record = case.get("unpatched")
    if not isinstance(record, dict) or record.get("confirmed") is not True:
        return
    case["minimum_fix_set"] = []
    case["fixed_release"] = None
    case["fix_authorship"] = None
    evidence = case.get("code_evidence")
    if not isinstance(evidence, dict):
        return
    evidence["comparison_hunks"] = [
        hunk
        for hunk in evidence.get("comparison_hunks") or []
        if (hunk.get("role") or comparison_hunk_role(evidence, hunk)) != "fix"
    ]
    evidence["fix_hunks"] = []
    evidence["steps"] = [
        step
        for step in evidence.get("steps") or []
        if not re.search(r"\bfix\b", str(step.get("title") or ""), re.I)
    ]
    for field in (
        "fix_files",
        "fix_marker",
        "fix_patch_files",
        "fix_patch_sha256",
        "fix_url",
    ):
        evidence.pop(field, None)


def release_fallback(case: dict) -> dict | None:
    """An explicit, reviewed fallback for a release gate that cannot close."""
    fallbacks = _release_fallbacks()
    for key in (case.get("case_id"), *(case.get("aliases") or [])):
        hit = fallbacks.get(str(key or "").upper())
        if isinstance(hit, dict) and str(hit.get("reason") or "").strip():
            return hit
    return None


def _release_fallbacks() -> dict[str, dict]:
    if not RELEASE_FALLBACKS.exists():
        return {}
    try:
        payload = json.loads(RELEASE_FALLBACKS.read_text())
    except ValueError:
        return {}
    if not isinstance(payload, dict):
        return {}
    return {str(k).upper(): v for k, v in payload.items() if isinstance(v, dict)}


def publication_status(case: dict) -> str:
    gate_values = set((case.get("gates") or {}).values())
    if not gate_values or "UNKNOWN" in gate_values or not case.get("candidate_set"):
        return "provisional"
    # release may be non-PASS when a reviewed fallback records that the gate
    # cannot close (no release channel / no fixed artifact / same version).
    unresolved = {
        name
        for name, value in (case.get("gates") or {}).items()
        if value != "PASS" and not (name == "release" and release_fallback(case))
    }
    if not unresolved and not case.get("publication_issues"):
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


def find_cached(
    ghsas: list[str],
    cves: list[str],
    class_id: str,
    repo: str | None,
    official: dict[str, dict],
    by_class: dict[str, dict],
    dropped_ids: set[str] | None = None,
) -> tuple[dict | None, bool]:
    for key in unique([*ghsas, *cves]):
        hit = official.get(key.upper())
        if hit and repo_matches(hit, repo):
            return hit, True
    hit = by_class.get(class_id.upper())
    if hit and dropped_ids and set(official_ids_of(hit)) & dropped_ids:
        hit = None
    if hit and repo_matches(hit, repo):
        return hit, False
    return None, False


def public_shas(
    rec: dict | None,
    cached: dict | None,
    evidence: dict | None = None,
    row: dict | None = None,
) -> tuple[list[str], list[str]]:
    """One SHA source for listing, diagram, and diffs.

    ``evidence`` (the code_evidence the case will publish) takes priority
    over cached evidence so re-generated comparison hunks stay consistent
    with the listing SHAs.
    """
    chain = ir_chain_of(row, (cached or {}).get("ir_chain")) or {}
    if (cached or {}).get("ir_chain") and (
        not chain or (row is not None and "ir_chain" in row)
    ):
        # A rejected legacy chain cannot re-enter through its cached SHA sets or URLs.
        cached = None
        if row is None or "code_evidence" not in row:
            evidence = None
    if row is not None and "candidate_set" in row:
        candidates = list(row.get("candidate_set") or [])
    else:
        candidates = collect_shas(rec, "introducer_sha", "introducer", "introducer_shas")
    if not candidates and cached and not (row is not None and "candidate_set" in row):
        candidates = list(cached.get("candidate_set") or [])
    if row is not None and "minimum_fix_set" in row:
        fixes = list(row.get("minimum_fix_set") or [])
    else:
        fixes = collect_shas(rec, "direct_fix_sha", "fix_sha")
    if not fixes and cached and not (row is not None and "minimum_fix_set" in row):
        fixes = list(cached.get("minimum_fix_set") or [])
    if row is not None and "code_evidence" in row:
        evidence = row.get("code_evidence")
    elif evidence is None:
        evidence = (cached or {}).get("code_evidence")
    evidence = evidence or {}
    attempted = ((chain.get("attempted_remediation") or {}).get("candidate_shas") or [])
    final = ((chain.get("final_closure") or {}).get("minimum_fix_shas") or [])
    url_candidate = sha_from_url(evidence.get("candidate_url"))
    url_fix = sha_from_url(evidence.get("fix_url"))
    attempted_shas = [str(item) for item in attempted if SHA_RE.match(str(item))]
    final_shas = [str(item) for item in final if SHA_RE.match(str(item))]
    row_candidates = row is not None and "candidate_set" in row
    row_fixes = row is not None and "minimum_fix_set" in row
    if attempted_shas and not row_candidates:
        candidates = attempted_shas
    elif url_candidate and not row_candidates and not sha_overlap([url_candidate], candidates):
        candidates = [url_candidate]
    if final_shas and not row_fixes:
        fixes = final_shas
    elif url_fix and not row_fixes and not sha_overlap([url_fix], fixes):
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
        winner["candidate_set"], winner["minimum_fix_set"] = public_shas(None, winner, row=winner)
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
    overrides: dict | None = None,
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
        if chain and not chain.get("original_sha") and not str(
            chain.get("unresolved_reason") or ""
        ).strip():
            errors.append(f"{case_id}: ir_chain without original_sha needs unresolved_reason")
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
            verified = {
                str(item).upper()
                for item in (
                    (((overrides or {}).get("cases") or {}).get(case.get("class_id")) or {}).get("aliases_extra")
                    or []
                )
            }
            unexpected = [
                item
                for item in ghsas
                if item.upper() != case_id.upper() and item.upper() not in verified
            ]
            if unexpected:
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
        "unresolved_reason": raw.get("unresolved_reason")
        or raw.get("original_introducing_commit_reason"),
        "attempted_remediation": raw.get("attempted_remediation"),
        "residual_bypass": raw.get("residual_bypass"),
        "final_closure": raw.get("final_closure"),
    }


def ir_chain_of(row: dict | None, fallback: dict | None) -> dict | None:
    if row is not None:
        if "ir_chain" in row:
            return normalize_ir_chain(row["ir_chain"])
        if "site_scope" in row and SCOPE_TO_CLASS.get(row["site_scope"]) != "AI_INCOMPLETE_REMEDIATION":
            return None
    return normalize_ir_chain(fallback)


def load_advisory_dates() -> dict[str, str]:
    """Advisory publish dates keyed by GHSA/CVE.

    Doubles as the date-traceability gate in publication_errors: every
    published_at must appear here. Never publish a commit date in its place.
    """
    dates: dict[str, str] = {}
    payload = load_json(ADVISORY_DATES)
    if not isinstance(payload, dict):
        return dates
    for key, value in payload.items():
        text = str(value or "")[:10]
        if key and len(text) >= 10 and text[4] == "-":
            dates[str(key).upper()] = text
    return dates


AI_CASE_SUMMARIES = ROOT / "research/gate-campaign-20260830/summaries-by-alias.json"


def ai_summary_overlay(case: dict, *, canonical: bool = False) -> bool:
    # Keep canonical reader copy only when it reads as public prose without audit
    # identifiers; pseudo-prose (path/SHA noise) falls through to the curated map.
    evidence = case.get("code_evidence")
    if canonical and isinstance(evidence, dict):
        canonical = public_text(evidence.get("summary"))
        if (
            canonical
            and public_explanation(canonical)
            and not AUDIT_IDENTIFIER_RE.search(canonical)
            and "PR #" not in canonical
        ):
            return True
    keys = [case.get("case_id"), *(case.get("aliases") or []), case.get("class_id")]
    summary = next(
        (
            AI_SUMMARIES.get(str(key or "").upper())
            for key in keys
            if AI_SUMMARIES.get(str(key or "").upper())
        ),
        None,
    )
    if (
        not summary
        or not public_explanation(summary)
        or AUDIT_IDENTIFIER_RE.search(summary)
        or "PR #" in summary
    ):
        return False
    if not isinstance(evidence, dict):
        evidence = {}
        case["code_evidence"] = evidence
    evidence["summary"] = summary
    mechanism = next(
        (
            AI_SUMMARIES_MECHANISM.get(str(key or "").upper())
            for key in keys
            if AI_SUMMARIES_MECHANISM.get(str(key or "").upper())
        ),
        None,
    )
    if (
        mechanism
        and not CJK_RE.search(mechanism)
        and public_explanation(mechanism)
        and not AUDIT_IDENTIFIER_RE.search(mechanism)
        and "PR #" not in mechanism
    ):
        evidence["mechanism"] = mechanism
        case["mechanism"] = mechanism
    return True


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


def _load_summary_maps(rows: list[dict]) -> None:
    global AI_SUMMARIES, AI_SUMMARIES_MECHANISM, ANNOTATION_PROSE
    overlay = _db_display_kind("ai_summaries")
    if not overlay:
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
    for row in rows:
        try:
            _index_prose(row)
        except (json.JSONDecodeError, ValueError):
            continue
    # Prose recovery for truncated hunk annotations indexes ledger rows only:
    # the round9 adjudication and finalize-patches files are local research
    # artifacts absent from CI, and they resolve no published annotation or
    # mechanism (verified output-identical against the committed site data).
    for key, mechanism in AI_SUMMARIES_MECHANISM.items():
        prose = ANNOTATION_PROSE.get(mechanism[:100])
        if prose and prose.startswith(mechanism):
            AI_SUMMARIES_MECHANISM[key] = prose


AI_SUMMARIES: dict[str, str] = {}
AI_SUMMARIES_MECHANISM: dict[str, str] = {}
ANNOTATION_PROSE: dict[str, str] = {}

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
    if str(path) == str(IR_CHAINS):
        db_chains = _db_display_kind("ir_chains")
        if db_chains:
            return {
                str(case_id).upper(): normalize_ir_chain(raw)
                for case_id, raw in db_chains.items()
                if normalize_ir_chain(raw)
            }
    elif str(path) == str(IR_CHAIN_UPDATES):
        db_updates = _db_display_kind("ir_chain_updates")
        if db_updates:
            return {
                str(case_id).upper(): normalize_ir_chain(raw)
                for case_id, raw in db_updates.items()
                if normalize_ir_chain(raw)
            }
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


def ledger_census(*, from_export: bool = False) -> dict[str, int]:
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
    if from_export:
        for row in _read_export_rows():
            total += 1
            status = row.get("status")
            if status in counts:
                counts[status] += 1
    else:
        sys.path.insert(0, str(ROOT / "scripts"))
        from ledger_store import load_env, snapshot_aggregates

        load_env()
        agg = snapshot_aggregates()
        raw_statuses = agg["statuses"] or {}
        if isinstance(raw_statuses, str):
            raw_statuses = json.loads(raw_statuses)
        statuses = {str(key): int(value) for key, value in dict(raw_statuses).items()}
        counts = {key: statuses.get(key, 0) for key in counts}
        total = int(agg["rows"])
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
        canonical_repo = str(row.get("repo") or "")
        override_repo = str(spec["repository"])
        repository = (
            override_repo
            if not canonical_repo or canonical_repo.casefold() == override_repo.casefold()
            else canonical_repo
        )
        case["repository"] = repository
        meta = dict(case.get("repository_metadata") or {})
        meta["full_name"] = repository
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
        "mechanism",
        "description",
        "references",
        "scope_statement",
        "fix_authorship",
        "vulnerable_release",
        "fixed_release",
        "candidate_sources",
        "candidate_fix_edges",
    ):
        # The case already holds the cleaned canonical value when the ledger
        # owns the field; only fill the gap the ledger leaves.
        if field in spec and field not in row:
            case[field] = spec[field]
    if spec.get("aliases_extra"):
        case["aliases"] = unique([*(case.get("aliases") or []), *spec["aliases_extra"]])
    if spec.get("drop_aliases"):
        dropped = {str(item).upper() for item in spec["drop_aliases"]}
        case["aliases"] = [
            item for item in (case.get("aliases") or []) if item.upper() not in dropped
        ]
    class_override = (overrides.get("class_overrides") or {}).get(class_id)
    if "site_scope" in row:
        case["contribution_class"] = contribution_class(row, rec)
    elif class_override:
        case["contribution_class"] = class_override
    case["ir_chain"] = ir_chain_of(row, case.get("ir_chain"))
    chain = ir_chain_of(row, spec.get("ir_chain"))
    indexed_chain = chains.get(str(case.get("case_id") or "").upper())
    if (
        "ir_chain" not in row
        and indexed_chain
        and indexed_chain.get("_publication_override")
    ):
        chain = {
            key: value
            for key, value in indexed_chain.items()
            if key != "_publication_override"
        }
    elif "ir_chain" not in row and chain and indexed_chain:
        chain = dict(chain)
        for field in (
            "original_author_kind",
            "original_author_name",
            "original_sha",
            "unresolved_reason",
        ):
            if not chain.get(field) or chain.get(field) == "UNKNOWN":
                chain[field] = indexed_chain.get(field)
    if not chain and "ir_chain" not in row:
        chain = indexed_chain
    if chain and "ir_chain" not in row and rec and rec.get("squash_decomposed"):
        introducer = str(rec.get("introducer_sha") or "")
        evidence_sha = sha_from_url((case.get("code_evidence") or {}).get("candidate_url"))
        if introducer and evidence_sha and sha_overlap([introducer], [evidence_sha]):
            chain = json.loads(json.dumps(chain))
            attempted = dict(chain.get("attempted_remediation") or {})
            attempted["candidate_shas"] = [introducer]
            chain["attempted_remediation"] = attempted
    chain = ir_chain_of(row, chain)
    if chain and (
        "ir_chain" in row
        or spec.get("ir_chain")
        or case.get("contribution_class") == "AI_INCOMPLETE_REMEDIATION"
    ):
        case["ir_chain"] = chain
        if "site_scope" not in row:
            case["contribution_class"] = "AI_INCOMPLETE_REMEDIATION"
    if "candidate_set" in spec and "candidate_set" not in row:
        case["candidate_set"] = list(spec.get("candidate_set") or [])
    if "carrier_set" in spec and "carrier_set" not in row:
        case["carrier_set"] = list(spec.get("carrier_set") or [])
    if "minimum_fix_set" in spec and "minimum_fix_set" not in row:
        case["minimum_fix_set"] = list(spec.get("minimum_fix_set") or [])
    if case.get("ir_chain"):
        aligned_candidates, aligned_fixes = public_shas(rec, case, row=row)
        if (
            aligned_candidates
            and "candidate_set" not in row
            and "candidate_set" not in spec
        ):
            case["candidate_set"] = aligned_candidates
        if (
            aligned_fixes
            and "minimum_fix_set" not in row
            and "minimum_fix_set" not in spec
        ):
            case["minimum_fix_set"] = aligned_fixes
    provenance = dict(case.get("ai_provenance") or {})
    provenance["candidate_count"] = len(case.get("candidate_set") or [])
    provenance["named_candidate_count"] = len(case.get("candidate_set") or [])
    case["ai_provenance"] = provenance
    return drop_original_aliases(case)


def build_case(
    row: dict,
    *,
    official: dict[str, dict] | None = None,
    by_class: dict[str, dict] | None = None,
    overrides: dict | None = None,
    chains: dict[str, dict] | None = None,
    dates: dict[str, str] | None = None,
    generated_evidence: dict[str, dict] | None = None,
    unpatched_fixes: dict[str, dict] | None = None,
) -> dict:
    # Keyword-only: these are eight overlay maps that used to be positional,
    # so a changed signature silently shifted every argument.
    official = official or {}
    by_class = by_class or {}
    overrides = overrides or {}
    chains = chains or {}
    dates = dates or {}
    generated_evidence = generated_evidence or {}
    unpatched_fixes = unpatched_fixes or {}
    recs = research_records(row)
    rec = recs[0] if recs else None
    ghsas, cves = collect_ids(row, rec)
    case_id = (ghsas[0] if ghsas else cves[0] if cves else row["class_id"]).upper()
    aliases = unique([*ghsas, *cves, row["class_id"]])
    aliases = [item for item in aliases if item.upper() != case_id]
    repo = repo_of(row, rec)
    class_spec = (overrides.get("cases") or {}).get(str(row["class_id"])) or {}
    dropped_ids = {
        str(value).upper() for value in class_spec.get("drop_aliases") or []
    }
    cached, official_hit = find_cached(
        ghsas,
        cves,
        row["class_id"],
        repo,
        official,
        by_class,
        dropped_ids,
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
    language = ((cached or {}).get("repository_metadata") or {}).get("language") or ""
    if "code_evidence" in row:
        case_evidence = row.get("code_evidence")
        if case_evidence is not None and not isinstance(case_evidence, dict):
            raise ValueError(f"{case_id}: ledger code_evidence must be an object or null")
    else:
        case_evidence = next(
            (
                generated_evidence.get(str(key).upper())
                for key in [case_id, *aliases, row.get("class_id")]
                if (generated_evidence.get(str(key).upper()) or {}).get(
                    "comparison_hunks"
                )
            ),
            None,
        ) or (cached or {}).get("code_evidence")
    if case_evidence and (cached or {}).get("code_evidence", {}).get("steps"):
        # ponytail: prefer cached reader-facing steps over generated commit
        # subjects so rebuilds do not erase curated annotations.
        generic = {"ai change", "ai fix", "fix", "root cause", "change"}
        has_curated = any(
            str(step.get("title") or "").strip().lower() not in generic
            for step in cached["code_evidence"]["steps"]
        )
        if has_curated:
            case_evidence = {**case_evidence, "steps": cached["code_evidence"]["steps"]}
    candidates, fixes = public_shas(rec, cached, case_evidence, row)
    ledger_gates = row.get("gates")
    if ledger_gates:
        if (
            set(ledger_gates) != set(DEFAULT_GATES)
            or not set(ledger_gates.values()) <= {"PASS", "NARROW", "NA", "UNKNOWN", "FAIL"}
            or not row.get("gates_source")
        ):
            raise ValueError(f"{case_id}: invalid or unsourced ledger gates")
        gates = dict(ledger_gates)
    else:
        gates = dict(DEFAULT_GATES)
    derived_class = contribution_class(row, rec)
    chain = ir_chain_of(row, (cached or {}).get("ir_chain"))
    contribution = (
        "AI_INCOMPLETE_REMEDIATION"
        if chain and "site_scope" not in row
        else derived_class
    )
    if "carrier_set" in row:
        carriers = unique(list(row.get("carrier_set") or []))
    elif rec and "carrier_set" in rec:
        carriers = unique(list(rec.get("carrier_set") or []))
    else:
        carriers = unique(
            [
                *([rec.get("carrier_sha")] if rec and rec.get("carrier_sha") else []),
                *((cached or {}).get("carrier_set") or []),
            ]
        )
    candidate_repo_match = REPO_RE.search(
        str((case_evidence or {}).get("candidate_url") or "")
    )
    candidate_source_repo = (
        candidate_repo_match.group(1) if candidate_repo_match else repo
    )
    candidate_sources = ledger_value(
        row,
        "candidate_sources",
        [
            {"sha": sha, "repository": candidate_source_repo}
            for sha in candidates
        ]
        if len(candidates) > 1
        else None,
    )
    candidate_fix_edges = ledger_value(
        row, "candidate_fix_edges", (rec or {}).get("candidate_fix_edges") or None
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
        "carrier_set": carriers,
        "minimum_fix_set": fixes,
        "gates": gates,
        "vulnerable_release": ledger_value(
            row, "vulnerable_release", (cached or {}).get("vulnerable_release")
        ),
        "fixed_release": ledger_value(
            row, "fixed_release", (cached or {}).get("fixed_release")
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
        "description": ledger_value(row, "description", description, clean=public_text),
        "references": list((cached or {}).get("references") or []),
        "mechanism_key": (cached or {}).get("mechanism_key"),
        "mechanism": ledger_value(row, "mechanism", mechanism, clean=public_text),
        "scope_statement": ledger_value(
            row, "scope_statement", scope_statement, clean=public_text
        ),
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
        # The ledger is the source of truth: a derived authorship wins over the
        # committed snapshot, which can hold a stale non-null value that would
        # otherwise shadow a corrected ledger row forever. The snapshot stays as
        # the fallback for rows the ledger cannot derive.
        "fix_authorship": derive_fix_authorship(rec, list(fixes)) or (cached or {}).get("fix_authorship"),
        "code_evidence": scrub_evidence(case_evidence, (mechanism, description)),
        "ir_chain": chain,
    }
    if candidate_sources:
        case["candidate_sources"] = candidate_sources
    if candidate_fix_edges:
        case["candidate_fix_edges"] = candidate_fix_edges
    case["research_status"] = " ".join(
        str((rec or {}).get(key) or "") for key in ("remaining_gap", "evidence")
    ).strip() or None
    case["unpatched"] = ledger_value(
        row,
        "unpatched",
        (rec or {}).get("unpatched")
        or first_unpatched(case_id, aliases, row.get("class_id"), unpatched_fixes),
    )
    case = apply_case_overrides(case, row, rec, overrides, chains)
    strip_unpatched_fix_claims(case)
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
    case.pop("research_status", None)
    return strip_cjk_tree(drop_original_aliases(case))

def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Publish TPs from Neon ledger_rows into research-data.json"
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--from-export",
        action="store_true",
        help="Read the jsonl recovery export instead of Neon (offline/backup only)",
    )
    source.add_argument(
        "--prefer-export",
        action="store_true",
        help=(
            "Publish from the jsonl export when its sha256 matches the Neon "
            "snapshot digest (one small probe); stale exports fall back to Neon"
        ),
    )
    args = parser.parse_args(argv)
    from_export = args.from_export
    if args.prefer_export:
        from_export = export_matches_neon()
        print(
            "prefer-export: jsonl "
            + (
                "matches the Neon snapshot; publishing without row egress"
                if from_export
                else "is stale; reading Neon ledger_rows"
            ),
            file=sys.stderr,
        )
    rows = load_ledger_rows(from_export=from_export)
    _load_summary_maps(rows)
    # Curated reader-facing values (severity, CWEs, references, release ranges,
    # curated steps, dates) have no source in ledger_rows. They live in the
    # committed curation file, never in the previous publish output: publish
    # stays a pure function of Neon rows plus committed inputs, so a bad run
    # cannot feed its own mistakes back in.
    existing = load_json(CURATION)
    cache = index_existing(existing)
    overrides = load_json(OVERRIDES)
    chains = load_ir_chains(IR_CHAINS)
    chain_updates = load_ir_chains(IR_CHAIN_UPDATES)
    for chain in chain_updates.values():
        chain["_publication_override"] = True
    chains.update(chain_updates)
    dates = load_advisory_dates()
    if not dates:
        # publication_errors only enforces date traceability when the table is
        # non-empty; fail closed here so a missing table cannot publish dates
        # nobody verified.
        raise SystemExit(f"missing advisory date table: {ADVISORY_DATES}")
    generated_evidence = load_generated_evidence()
    unpatched_fixes = load_unpatched_fixes()
    drop_class_ids = {
        str(item).lower() for item in (overrides.get("drop_class_ids") or [])
    }
    canonical_evidence_classes: set[str] = set()
    cases: list[dict] = []
    for row in rows:
        if row.get("status") not in TP_STATUSES:
            continue
        if (row.get("site_publication") or {}).get("publish") is False:
            continue
        if str(row.get("class_id") or "").lower() in drop_class_ids:
            continue
        if "code_evidence" in row:
            canonical_evidence_classes.add(str(row.get("class_id") or "").lower())
        case = build_case(
            row,
            official=cache[0],
            by_class=cache[1],
            overrides=overrides,
            chains=chains,
            dates=dates,
            generated_evidence=generated_evidence,
            unpatched_fixes=unpatched_fixes,
        )
        case["aliases"] = [
            item
            for item in case["aliases"]
            if item.upper() != case["case_id"].upper()
        ]
        cases.append(case)
    cases = merge_duplicate_identities(cases)
    security_fix_contexts = load_json(SECURITY_FIX_CONTEXTS) or {}
    for case in cases:
        if not ai_summary_overlay(
            case,
            canonical=str(case.get("class_id") or "").lower()
            in canonical_evidence_classes,
        ):
            raise SystemExit(
                f"{case['case_id']}: missing reader summary in {AI_CASE_SUMMARIES}"
            )
        # ponytail: scrub runs once in build_case with the record's own
        # mechanism/description; re-scrubbing here resolved nothing extra.
        evidence = case.get("code_evidence")
        if not isinstance(evidence, dict):
            evidence = {}
            case["code_evidence"] = evidence
        fix_context = security_fix_contexts.get(
            str(case.get("case_id") or "").upper()
        )
        if not (
            isinstance(case.get("unpatched"), dict)
            and case["unpatched"].get("confirmed") is True
        ):
            apply_security_fix_context(evidence, fix_context)
        if any(
            evidence.get(role)
            for role in ("comparison_hunks", "candidate_hunks", "fix_hunks")
        ):
            evidence.pop("unavailable_reason", None)

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
    census = ledger_census(from_export=from_export)
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
            "ledger": (
                "artifacts/funnel-account-20260817.jsonl"
                if from_export
                else "neon:ledger_rows"
            ),
        },
        "cause_categories": CAUSE_CATEGORIES,
        "ai_provenance_families": FAMILIES,
        "cases": cases,
    }

    ai_commit_census = _db_display_kind("ai_commit_census") or load_json(
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
    identity_errors = publication_errors(cases, dates, overrides)
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
