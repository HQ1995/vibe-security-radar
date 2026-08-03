"""Recall-oriented cross-file security bridge shared by routing stages."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from pathlib import Path


SECURITY_SURFACE_PATH_PARTS = {
    "action",
    "actions",
    "api",
    "apis",
    "consumer",
    "consumers",
    "controller",
    "controllers",
    "endpoint",
    "endpoints",
    "graphql",
    "grpc",
    "handler",
    "handlers",
    "listener",
    "listeners",
    "middleware",
    "resolver",
    "resolvers",
    "rest",
    "route",
    "router",
    "routers",
    "routes",
    "rpc",
    "servlet",
    "servlets",
    "socket",
    "viewset",
    "viewsets",
    "webhook",
    "webhooks",
}

CANDIDATE_SURFACE_PATTERNS = (
    re.compile(
        r"(?im)^\+\s*@(?:[\w.]+\.)?"
        r"(?:api_route|get|post|put|patch|delete|options|head|route)\s*\("
    ),
    re.compile(r"(?im)^\+\s*@(?:get|post|put|patch|delete|request)mapping\b"),
    re.compile(
        r"(?im)^\+\s*(?:app|api|router|server)\."
        r"(?:get|post|put|patch|delete|options|head|route|use)\s*\("
    ),
    re.compile(r"(?im)^\+.*\b(?:handle|handlefunc|add_url_rule)\s*\("),
    re.compile(r"(?im)^\+\s*(?:re_)?path\s*\(\s*['\"]"),
    re.compile(r"(?im)^\+.*\b(?:query|mutation|resolver|rpc)\b.*[({:]"),
)

GLOBAL_GUARD_PATTERNS = (
    re.compile(r"(?im)^\+.*@(?:[\w.]+\.)?middleware\s*\("),
    re.compile(
        r"(?im)^\+.*\b(?:auth|authentication|authorization)[\w -]*"
        r"(?:filter|guard|interceptor|middleware)\b"
    ),
    re.compile(r"(?im)^\+.*\bsecurityfilterchain\b"),
    re.compile(r"(?im)^\+.*\bbefore_request\b"),
    re.compile(r"(?im)^\+.*\b(?:default[ _-]*deny|deny[ _-]*by[ _-]*default)\b"),
    re.compile(
        r"(?im)^\+.*\b(?:enforce|require)[^\n]{0,48}"
        r"\b(?:auth|authentication|authorization|permission)\b"
    ),
    re.compile(r"(?im)^\+.*\b(?:all|every)\s+(?:api\s+)?routes?\b"),
    re.compile(
        r"(?im)^\+.*\b(?:access[ _-]*control|authorize|permission[ _-]*check|"
        r"require[ _-]*role)\b"
    ),
)


def split_patch_hunks(patch: str) -> tuple[str, list[str]]:
    """Split a one-path git patch while retaining the file header for context."""

    header: list[str] = []
    hunks: list[list[str]] = []
    current: list[str] | None = None
    for line in patch.splitlines():
        if line.startswith("@@"):
            current = [line]
            hunks.append(current)
        elif current is None:
            header.append(line)
        else:
            current.append(line)
    return "\n".join(header).strip(), ["\n".join(hunk) for hunk in hunks]


def matching_hunk_evidence(
    patch: str,
    patterns: Sequence[re.Pattern[str]],
    *,
    limit: int,
) -> str:
    """Put security-relevant added hunks first instead of trusting file order."""

    header, hunks = split_patch_hunks(patch)
    ranked: list[tuple[int, int, str]] = []
    for index, hunk in enumerate(hunks):
        added = "\n".join(
            line
            for line in hunk.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
        score = sum(len(pattern.findall(added)) for pattern in patterns)
        if score:
            ranked.append((-score, index, hunk))
    if not ranked:
        return ""
    ordered = [hunk for _score, _index, hunk in sorted(ranked)]
    evidence = "\n".join(part for part in [header, *ordered] if part)
    if len(evidence) <= limit:
        return evidence
    marker = "\n...[security bridge evidence truncated]"
    return evidence[: max(0, limit - len(marker))] + marker


def is_security_surface_path(path: str) -> bool:
    parts = {
        part
        for part in re.split(r"[^a-z0-9]+", path.casefold())
        if part
    }
    return bool(parts & SECURITY_SURFACE_PATH_PARTS)


def patch_has_global_guard(patch: str) -> bool:
    return bool(matching_hunk_evidence(patch, GLOBAL_GUARD_PATTERNS, limit=1))


def cross_file_security_bridge(
    repo: Path,
    candidate_sha: str,
    fix_sha: str,
    candidate_paths: Sequence[str],
    fix_paths: Sequence[str],
    *,
    path_patch: Callable[..., str],
    limit: int,
    allow_lazy_fetch: bool = False,
) -> dict[str, object]:
    """Recover route-to-global-guard evidence that shared-path ranking cannot see."""

    fix_path_set = set(fix_paths)
    candidate_evidence: list[tuple[str, str]] = []
    for path in sorted(candidate_paths):
        # Path names are a cheap expansion signal, not a hard gate.  A route or
        # handler in an unusually named file must still be eligible by content.
        if path in fix_path_set:
            continue
        evidence = matching_hunk_evidence(
            path_patch(
                repo,
                candidate_sha,
                path,
                allow_lazy_fetch=allow_lazy_fetch,
            ),
            CANDIDATE_SURFACE_PATTERNS,
            limit=limit,
        )
        if evidence:
            candidate_evidence.append((path, evidence))

    fix_evidence: list[tuple[str, str]] = []
    if candidate_evidence:
        for path in sorted(fix_paths):
            evidence = matching_hunk_evidence(
                path_patch(
                    repo,
                    fix_sha,
                    path,
                    allow_lazy_fetch=allow_lazy_fetch,
                ),
                GLOBAL_GUARD_PATTERNS,
                limit=limit,
            )
            if evidence:
                fix_evidence.append((path, evidence))

    if not candidate_evidence or not fix_evidence:
        return {
            "applied": False,
            "candidate_paths": [],
            "fix_paths": [],
            "candidate_evidence": "",
            "fix_evidence": "",
        }

    def combine(rows: Sequence[tuple[str, str]]) -> str:
        combined = "\n".join(evidence for _path, evidence in rows)
        if len(combined) <= limit:
            return combined
        marker = "\n...[security bridge evidence truncated]"
        return combined[: max(0, limit - len(marker))] + marker

    return {
        "applied": True,
        "candidate_paths": [path for path, _evidence in candidate_evidence],
        "fix_paths": [path for path, _evidence in fix_evidence],
        "candidate_evidence": combine(candidate_evidence),
        "fix_evidence": combine(fix_evidence),
    }
