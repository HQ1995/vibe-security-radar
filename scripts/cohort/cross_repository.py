"""Conservative candidate closure across explicitly declared repository imports."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence


DECLARED_IMPORT_RELATION = "declared_cross_repository_import"
CROSS_REPOSITORY_CANDIDATE_RELATION = (
    "declared_cross_repository_import_then_reachable_ancestor"
)
DECLARED_SOURCE = "DECLARED"
AMBIGUOUS_SOURCE = "AMBIGUOUS"

_GITHUB_URL_RE = re.compile(
    r"https?://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/"
    r"(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?(?:[\s/#),;]|$)",
    re.IGNORECASE,
)
_FROM_SLUG_RE = re.compile(
    r"\b(?:import(?:ed|ing)?|sync(?:ed|ing)?|vendor(?:ed|ing)?|"
    r"port(?:ed|ing)?|cop(?:y|ied|ying)|fork(?:ed|ing)?|mirror(?:ed|ing)?)"
    r"(?:\s+[A-Za-z0-9_.-]+){0,6}\s+from\s+"
    r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)\b",
    re.IGNORECASE,
)
_UPSTREAM_SLUG_RE = re.compile(
    r"\b(?:upstream(?:\s+repository)?|source(?:\s+repository)?)\s*[:=]?\s+"
    r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)\b",
    re.IGNORECASE,
)
_PLUGIN_BY_RE = re.compile(
    r"\b(?P<repo>[A-Za-z0-9_.-]{2,})\s+plugin\s+by\s+"
    r"@(?P<owner>[A-Za-z0-9_.-]+)\b",
    re.IGNORECASE,
)
_URL_TRANSFER_CUE_RE = re.compile(
    r"(?:import(?:ed|ing)?|sync(?:ed|ing)?|vendor(?:ed|ing)?|"
    r"port(?:ed|ing)?|cop(?:y|ied|ying)|fork(?:ed|ing)?|mirror(?:ed|ing)?|"
    r"upstream|source(?:\s+repository)?|based\s+on|derived\s+from|"
    r"replace(?:d|s|ing)?(?:\s+\S+){0,5}\s+with)\b.{0,160}$",
    re.IGNORECASE | re.DOTALL,
)


class CrossRepositoryContractError(ValueError):
    """A declared-import relation or coverage artifact is malformed."""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256(prefix.encode("ascii"))
    for part in parts:
        digest.update(b"\0")
        digest.update(part.encode("utf-8"))
    return f"{prefix}-{digest.hexdigest()}"


def _identity(value: object, *, field: str) -> str:
    identity = str(value or "").strip().lower().removesuffix(".git")
    if not identity.startswith("github.com/") or identity.count("/") != 2:
        raise CrossRepositoryContractError(f"{field} is not a GitHub repository identity")
    if any(character in identity for character in "\x00\r\n"):
        raise CrossRepositoryContractError(f"{field} is malformed")
    return identity


def _full_sha(value: object, *, field: str) -> str:
    sha = str(value or "").strip().lower()
    if len(sha) != 40 or any(character not in "0123456789abcdef" for character in sha):
        raise CrossRepositoryContractError(f"{field} must be a full 40-hex SHA")
    return sha


def classify_import_source_mentions(message: str) -> list[dict[str, str]]:
    """Separate explicit sources from owner/repo-shaped ambiguous prose."""

    mentions: dict[tuple[str, str, str], dict[str, str]] = {}

    def add(
        match: re.Match[str],
        *,
        status: str,
        evidence_kind: str,
    ) -> None:
        owner = match.group("owner").strip(". ").lower()
        repo = match.group("repo").strip(". ").removesuffix(".git").lower()
        if not owner or not repo:
            return
        identity = f"github.com/{owner}/{repo}"
        mentions[(identity, status, evidence_kind)] = {
            "source_repository_identity": identity,
            "status": status,
            "evidence_kind": evidence_kind,
            "evidence_text": match.group(0).strip(),
        }

    for match in _GITHUB_URL_RE.finditer(message):
        context = message[max(0, match.start() - 160) : match.start()]
        if not _URL_TRANSFER_CUE_RE.search(context):
            continue
        add(match, status=DECLARED_SOURCE, evidence_kind="transfer_github_url")
    for match in _PLUGIN_BY_RE.finditer(message):
        add(match, status=DECLARED_SOURCE, evidence_kind="plugin_by_author")
    for pattern, evidence_kind in (
        (_FROM_SLUG_RE, "bare_transfer_slug"),
        (_UPSTREAM_SLUG_RE, "bare_repository_slug"),
    ):
        for match in pattern.finditer(message):
            add(match, status=AMBIGUOUS_SOURCE, evidence_kind=evidence_kind)

    explicitly_declared = {
        identity
        for identity, status, _kind in mentions
        if status == DECLARED_SOURCE
    }
    return [
        mentions[key]
        for key in sorted(mentions)
        if not (key[1] == AMBIGUOUS_SOURCE and key[0] in explicitly_declared)
    ]


def declared_import_sources(message: str) -> list[str]:
    """Extract only unambiguous transferred-code source declarations."""

    return sorted(
        {
            row["source_repository_identity"]
            for row in classify_import_source_mentions(message)
            if row["status"] == DECLARED_SOURCE
        }
    )


def _normalize_carriers(
    carriers: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    normalized: dict[tuple[str, str, str, str], dict[str, object]] = {}
    for raw in carriers:
        target = _identity(
            raw.get("target_repository_identity"), field="target repository"
        )
        source = _identity(
            raw.get("source_repository_identity"), field="source repository"
        )
        if source == target:
            raise CrossRepositoryContractError("declared import source equals target")
        import_sha = _full_sha(raw.get("import_sha"), field="import sha")
        fix_sha = _full_sha(raw.get("fix_sha"), field="fix sha")
        status = str(raw.get("fix_root_status") or "").strip().upper()
        reason = str(raw.get("fix_root_reason") or "").strip()
        if status not in {"RESOLVED", "BLOCKED"}:
            raise CrossRepositoryContractError("invalid fix-root status")
        if status == "BLOCKED" and not reason:
            raise CrossRepositoryContractError("blocked fix root requires a reason")
        key = (target, source, import_sha, fix_sha)
        row: dict[str, object] = {
            "target_repository_identity": target,
            "source_repository_identity": source,
            "import_sha": import_sha,
            "fix_sha": fix_sha,
            "fix_root_status": status,
            "fix_root_reason": reason,
        }
        if isinstance(raw.get("advisories"), list):
            row["advisories"] = list(raw["advisories"])
        normalized[key] = row
    return [normalized[key] for key in sorted(normalized)]


def build_declared_import_inventory(
    carriers: Sequence[Mapping[str, object]],
    source_commits_by_repository: Mapping[str, Sequence[Mapping[str, object]]],
    source_coverage_by_repository: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    """Retain every AI-attributed source commit for each declared import."""

    normalized = _normalize_carriers(carriers)
    root_keys = sorted(
        {
            (
                str(row["target_repository_identity"]),
                str(row["source_repository_identity"]),
                str(row["import_sha"]),
            )
            for row in normalized
        }
    )
    relations: list[dict[str, object]] = []
    roots: list[dict[str, object]] = []
    for target, source, import_sha in root_keys:
        coverage = source_coverage_by_repository.get(source)
        if coverage is None:
            status = "BLOCKED"
            reason = "source_repository_scan_missing"
            commits: list[Mapping[str, object]] = []
        elif coverage.get("complete") is not True:
            status = "BLOCKED"
            detail = str(coverage.get("reason") or "unspecified")
            reason = f"source_repository_scan_incomplete:{detail}"
            commits = []
        else:
            status = "RESOLVED"
            reason = ""
            commits = list(source_commits_by_repository.get(source, ()))
        unique_commits: dict[str, Mapping[str, object]] = {}
        for raw_commit in commits:
            sha = _full_sha(raw_commit.get("sha"), field="source commit sha")
            unique_commits[sha] = raw_commit
        for origin_sha in sorted(unique_commits):
            origin = unique_commits[origin_sha]
            relations.append(
                {
                    "relation_id": _stable_id(
                        "cross-relation", source, origin_sha, target, import_sha
                    ),
                    "origin_repository_identity": source,
                    "origin_sha": origin_sha,
                    "target_repository_identity": target,
                    "import_sha": import_sha,
                    "relation": DECLARED_IMPORT_RELATION,
                    "origin_unit": dict(origin),
                }
            )
        roots.append(
            {
                "root_id": _stable_id("cross-root", source, target, import_sha),
                "origin_repository_identity": source,
                "target_repository_identity": target,
                "import_sha": import_sha,
                "status": status,
                "reason": reason,
                "origin_candidate_count": len(unique_commits),
                "origin_candidates_sha256": _sha256_json(sorted(unique_commits)),
            }
        )
    relations.sort(key=lambda row: str(row["relation_id"]))
    roots.sort(key=lambda row: str(row["root_id"]))
    resolved = sum(root["status"] == "RESOLVED" for root in roots)
    blocked = sum(root["status"] == "BLOCKED" for root in roots)
    inventory: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "declared_cross_repository_import_inventory",
        "coverage_complete": blocked == 0,
        "relation_count": len(relations),
        "import_root_count": len(roots),
        "resolved_import_root_count": resolved,
        "blocked_import_root_count": blocked,
        "relations": relations,
        "import_roots": roots,
        "relations_sha256": _sha256_json(relations),
        "import_roots_sha256": _sha256_json(roots),
        "conservation": {
            "import_root_count": len(roots),
            "resolved_import_root_count": resolved,
            "blocked_import_root_count": blocked,
            "import_roots_conserved": len(roots) == resolved + blocked,
        },
        "claim_boundary": (
            "an explicit source declaration creates a recall-first upstream"
            " population containing every scanned AI-attributed source commit;"
            " timestamps and content similarity may rank but never exclude"
        ),
        "model_api_calls": 0,
        "model_input_tokens": 0,
        "model_output_tokens": 0,
        "model_cost_usd": 0.0,
    }
    inventory["inventory_sha256"] = _sha256_json(inventory)
    return inventory


def expand_declared_import_candidates(
    carriers: Sequence[Mapping[str, object]],
    relations: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Compose every upstream origin through its import carrier to each fix."""

    normalized = _normalize_carriers(carriers)
    by_import: dict[tuple[str, str, str], list[Mapping[str, object]]] = {}
    seen_relations: set[str] = set()
    for relation in relations:
        relation_id = str(relation.get("relation_id") or "")
        if not relation_id or relation_id in seen_relations:
            raise CrossRepositoryContractError("duplicate or missing relation id")
        seen_relations.add(relation_id)
        if relation.get("relation") != DECLARED_IMPORT_RELATION:
            raise CrossRepositoryContractError("unsupported cross-repository relation")
        source = _identity(
            relation.get("origin_repository_identity"), field="origin repository"
        )
        target = _identity(
            relation.get("target_repository_identity"), field="target repository"
        )
        import_sha = _full_sha(relation.get("import_sha"), field="import sha")
        _full_sha(relation.get("origin_sha"), field="origin sha")
        by_import.setdefault((target, source, import_sha), []).append(relation)

    edges: list[dict[str, object]] = []
    for carrier in normalized:
        target = str(carrier["target_repository_identity"])
        source = str(carrier["source_repository_identity"])
        import_sha = str(carrier["import_sha"])
        fix_sha = str(carrier["fix_sha"])
        for relation in by_import.get((target, source, import_sha), []):
            origin_sha = _full_sha(relation.get("origin_sha"), field="origin sha")
            edge: dict[str, object] = {
                "edge_id": _stable_id(
                    "cross-edge", source, origin_sha, target, import_sha, fix_sha
                ),
                "repository_identity": target,
                "origin_repository_identity": source,
                "candidate_sha": origin_sha,
                "import_sha": import_sha,
                "fix_sha": fix_sha,
                "relation": CROSS_REPOSITORY_CANDIDATE_RELATION,
                "relation_path": [DECLARED_IMPORT_RELATION, "reachable_ancestor"],
                "origin_relation_id": str(relation["relation_id"]),
                "root_coverage_status": str(carrier["fix_root_status"]),
                "root_coverage_reason": str(carrier["fix_root_reason"]),
                "initial_status": "DEFER",
                "initial_reason": "awaiting_screening",
            }
            if "advisories" in carrier:
                edge["advisories"] = list(carrier["advisories"])
            edges.append(edge)
    edges.sort(key=lambda row: str(row["edge_id"]))
    return edges
