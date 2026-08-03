"""Recall-first fix-source union and repository-level fallback evidence.

The source layer is deliberately broader than an exact-fix parser.  Public
references, cached enriched selections, ranked search carriers, and local
commit-message carriers are all retained.  None of those signals is allowed
to remove a repository/advisory fallback candidate.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from cohort.relations import canonical_repository_identity
from cve_analyzer.git_ops import run_git
from cve_analyzer.models import (
    canonical_repository_identity as repository_identity_from_url,
)


PUBLIC_EXACT = "public_exact"
PUBLIC_VERSION_BOUNDARY = "public_version_boundary"
ENRICHED_SELECTED = "enriched_selected"
RANKED_SEARCH_CARRIER = "ranked_search_carrier"
REPOSITORY_REFERENCE_CARRIER = "repository_reference_carrier"
REPOSITORY_ADVISORY_FALLBACK = "repository_advisory_fallback"

_HEX = frozenset("0123456789abcdef")
_CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)
_GHSA_URL_RE = re.compile(
    r"^https?://github\.com/([^/]+)/([^/]+)/security/advisories/(GHSA-[0-9a-z-]+)",
    re.IGNORECASE,
)
_ISSUE_URL_RE = re.compile(
    r"^https?://github\.com/([^/]+)/([^/]+)/(issues|pull)/(\d+)(?:[/?#]|$)",
    re.IGNORECASE,
)
_UNIT_METADATA_KEYS = (
    "ai_ratio",
    "authored_date",
    "files_changed",
    "merge_topology",
    "n_ai_members",
    "n_members",
    "observed_repository_identity",
    "pr_number",
    "route",
    "squash_attribution_only",
    "tier",
    "tools",
)


class FixSourceContractError(ValueError):
    """A source or fallback row would violate the recall contract."""


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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256(prefix.encode("ascii"))
    for part in parts:
        digest.update(b"\0")
        digest.update(part.encode("utf-8"))
    return f"{prefix}-{digest.hexdigest()}"


def _valid_commit_ref(value: object) -> str:
    ref = str(value or "").strip().lower()
    if not 7 <= len(ref) <= 40 or any(character not in _HEX for character in ref):
        return ""
    return ref


def _canonical_url_identity(
    value: object,
    aliases: Mapping[str, str],
) -> str:
    observed = repository_identity_from_url(str(value or "").strip()).lower()
    if not observed:
        return ""
    try:
        return canonical_repository_identity(observed, aliases)
    except ValueError:
        return ""


def _source_observation(
    *,
    repository_identity: str,
    advisory: str,
    fix_ref: str,
    evidence_kind: str,
    source: str,
    source_path: str = "",
    source_sha256: str = "",
    published: str = "",
    detail: str = "",
    inherited_model: str = "",
    score: float | int | None = None,
    message: str = "",
) -> dict[str, object]:
    observation: dict[str, object] = {
        "observation_id": _stable_id(
            "fix-source",
            repository_identity,
            advisory,
            fix_ref,
            evidence_kind,
            source,
            detail,
        ),
        "repository_identity": repository_identity,
        "advisory": advisory,
        "fix_ref": fix_ref,
        "evidence_kind": evidence_kind,
        "source": source,
        "source_path": source_path,
        "source_sha256": source_sha256,
        "published": published,
        "detail": detail,
        "inherited_model": inherited_model,
    }
    if score is not None:
        observation["score"] = score
    if message:
        observation["message"] = message
    return observation


def public_fix_observations(
    references: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Project existing OSV rows into the unified source-observation schema."""

    observations: dict[str, dict[str, object]] = {}
    for raw in references:
        identity = str(raw.get("repository_identity") or "").strip().lower()
        advisory = str(raw.get("advisory") or "").strip()
        fix_ref = _valid_commit_ref(raw.get("fix_sha"))
        if not identity or not advisory or len(fix_ref) != 40:
            raise FixSourceContractError("public fix reference is malformed")
        reference_kind = str(raw.get("reference_kind") or "").strip()
        evidence_kind = (
            PUBLIC_VERSION_BOUNDARY
            if reference_kind == "converted_version_boundary"
            else PUBLIC_EXACT
        )
        observation = _source_observation(
            repository_identity=identity,
            advisory=advisory,
            fix_ref=fix_ref,
            evidence_kind=evidence_kind,
            source="osv_bulk",
            published=str(raw.get("published") or "").strip(),
            detail=reference_kind,
        )
        observations[str(observation["observation_id"])] = observation
    return [observations[key] for key in sorted(observations)]


def _cvelist_path(cvelist_dir: Path, advisory: str) -> Path | None:
    match = _CVE_RE.fullmatch(advisory)
    if match is None:
        return None
    year, sequence = match.groups()
    bucket = f"{sequence[:-3]}xxx"
    return cvelist_dir / year / bucket / f"CVE-{year}-{sequence}.json"


def _reference_urls(value: object) -> list[str]:
    urls: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key == "url" and isinstance(child, str) and child:
                urls.append(child)
            else:
                urls.extend(_reference_urls(child))
    elif isinstance(value, list):
        for child in value:
            urls.extend(_reference_urls(child))
    return urls


def _reference_anchors(
    advisory: str,
    repository_identity: str,
    urls: Iterable[str],
    aliases: Mapping[str, str],
) -> list[dict[str, str]]:
    anchors: dict[tuple[str, str, str], dict[str, str]] = {}

    def add(kind: str, value: str, source_url: str = "") -> None:
        key = (kind, value.lower(), source_url)
        anchors[key] = {
            "kind": kind,
            "value": value,
            "source_url": source_url,
        }

    add("advisory_id", advisory)
    for url in sorted(set(urls)):
        issue = _ISSUE_URL_RE.match(url)
        if issue is not None:
            identity = _canonical_url_identity(
                f"https://github.com/{issue.group(1)}/{issue.group(2)}",
                aliases,
            ).lower()
            if identity == repository_identity:
                add(f"github_{issue.group(3).lower()}", f"#{issue.group(4)}", url)
        ghsa = _GHSA_URL_RE.match(url)
        if ghsa is not None:
            identity = _canonical_url_identity(
                f"https://github.com/{ghsa.group(1)}/{ghsa.group(2)}",
                aliases,
            ).lower()
            if identity == repository_identity:
                add("ghsa_id", ghsa.group(3).upper(), url)
    return [anchors[key] for key in sorted(anchors)]


def load_description_search_sources(
    cache_dir: Path,
    cohort_repositories: set[str],
    aliases: Mapping[str, str],
    *,
    cvelist_dir: Path | None = None,
) -> dict[str, object]:
    """Load every visible cached source signal without trusting model rejection.

    A ``FOUND`` Phase-2 selection is tagged as enriched, never public.  Ranked
    candidates remain carriers even when the cached model said ``NOT_FOUND``.
    This function only projects source fields and never reads an audit ledger.
    """

    observations: dict[str, dict[str, object]] = {}
    associations: dict[tuple[str, str], dict[str, object]] = {}
    stats = Counter[str]()
    paths = sorted(cache_dir.glob("*.json")) if cache_dir.is_dir() else []
    for path in paths:
        stats["files_scanned"] += 1
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            stats["unreadable_files"] += 1
            continue
        if not isinstance(payload, dict):
            stats["unreadable_files"] += 1
            continue
        raw_input = payload.get("input")
        if not isinstance(raw_input, Mapping):
            stats["malformed_records"] += 1
            continue
        identity = _canonical_url_identity(raw_input.get("repo_url"), aliases)
        if not identity:
            stats["repository_identity_unresolved"] += 1
            continue
        if identity not in cohort_repositories:
            stats["outside_cohort"] += 1
            continue
        advisory = str(payload.get("cve_id") or "").strip()
        if not advisory:
            stats["malformed_records"] += 1
            continue
        source_hash = _sha256_file(path)
        source_path = str(path)
        model = str(payload.get("model") or "").strip()
        status = str(payload.get("status") or "").strip()
        cvelist_path = (
            _cvelist_path(cvelist_dir, advisory)
            if cvelist_dir is not None
            else None
        )
        urls: list[str] = []
        cvelist_hash = ""
        if cvelist_path is not None and cvelist_path.is_file():
            try:
                cvelist_payload = json.loads(cvelist_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                stats["unreadable_cvelist_records"] += 1
            else:
                urls = _reference_urls(cvelist_payload)
                cvelist_hash = _sha256_file(cvelist_path)
                stats["cvelist_records_loaded"] += 1
        association = {
            "association_id": _stable_id("advisory-repository", identity, advisory),
            "repository_identity": identity,
            "advisory": advisory,
            "description": str(raw_input.get("description") or "").strip(),
            "anchors": _reference_anchors(advisory, identity, urls, aliases),
            "source": "description_search_cache",
            "source_path": source_path,
            "source_sha256": source_hash,
            "cvelist_path": str(cvelist_path) if cvelist_path is not None else "",
            "cvelist_sha256": cvelist_hash,
            "cached_status": status,
            "inherited_model": model,
        }
        associations[(identity, advisory)] = association
        stats["associations_in_cohort"] += 1
        if model:
            stats["records_with_inherited_model_evidence"] += 1

        raw_phase2 = payload.get("phase2")
        phase2 = raw_phase2 if isinstance(raw_phase2, Mapping) else {}
        selected_ref = _valid_commit_ref(phase2.get("fix_sha"))
        if selected_ref:
            evidence_kind = (
                ENRICHED_SELECTED if status == "FOUND" else RANKED_SEARCH_CARRIER
            )
            source = (
                "description_search_phase2_selected"
                if status == "FOUND"
                else "description_search_phase2_unselected"
            )
            observation = _source_observation(
                repository_identity=identity,
                advisory=advisory,
                fix_ref=selected_ref,
                evidence_kind=evidence_kind,
                source=source,
                source_path=source_path,
                source_sha256=source_hash,
                detail=status,
                inherited_model=model,
            )
            observations[str(observation["observation_id"])] = observation
            stats[f"{evidence_kind}_observations"] += 1

        raw_search = payload.get("search")
        search = raw_search if isinstance(raw_search, Mapping) else {}
        raw_ranked = search.get("top_scored", [])
        if not isinstance(raw_ranked, list):
            stats["malformed_ranked_lists"] += 1
            raw_ranked = []
        for rank, raw in enumerate(raw_ranked, start=1):
            if not isinstance(raw, Mapping):
                stats["malformed_ranked_candidates"] += 1
                continue
            fix_ref = _valid_commit_ref(raw.get("sha"))
            if not fix_ref:
                stats["malformed_ranked_candidates"] += 1
                continue
            score = raw.get("score")
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                score = None
            observation = _source_observation(
                repository_identity=identity,
                advisory=advisory,
                fix_ref=fix_ref,
                evidence_kind=RANKED_SEARCH_CARRIER,
                source="description_search_ranked_candidate",
                source_path=source_path,
                source_sha256=source_hash,
                detail=f"rank:{rank}",
                inherited_model=model,
                score=score,
                message=str(raw.get("message") or "").strip(),
            )
            observations[str(observation["observation_id"])] = observation
            stats["ranked_search_carrier_observations"] += 1

    association_rows = [associations[key] for key in sorted(associations)]
    observation_rows = [observations[key] for key in sorted(observations)]
    stats["observation_count"] = len(observation_rows)
    stats["association_count"] = len(association_rows)
    return {
        "associations": association_rows,
        "observations": observation_rows,
        "stats": dict(sorted(stats.items())),
        "associations_sha256": _sha256_json(association_rows),
        "observations_sha256": _sha256_json(observation_rows),
    }


def scan_repository_reference_carriers(
    repositories: Mapping[str, Path],
    associations: Sequence[Mapping[str, object]],
    *,
    timeout: int,
    git_global_arguments_by_repository: Mapping[str, Sequence[str]] | None = None,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Retain every local commit whose message names a public reference anchor."""

    queries: dict[tuple[str, str], list[tuple[Mapping[str, object], Mapping[str, object]]]] = (
        defaultdict(list)
    )
    for association in associations:
        identity = str(association.get("repository_identity") or "").strip().lower()
        raw_anchors = association.get("anchors", [])
        if not isinstance(raw_anchors, list):
            raise FixSourceContractError("advisory association anchors are malformed")
        for anchor in raw_anchors:
            if not isinstance(anchor, Mapping):
                raise FixSourceContractError("advisory association anchor is malformed")
            value = str(anchor.get("value") or "").strip()
            if value:
                queries[(identity, value.lower())].append((association, anchor))

    observations: dict[str, dict[str, object]] = {}
    stats = Counter[str]()
    blocked_queries: list[dict[str, str]] = []
    for (identity, _normalized_anchor), targets in sorted(queries.items()):
        anchor_value = str(targets[0][1].get("value") or "")
        repo_path = repositories.get(identity)
        stats["queries"] += 1
        if repo_path is None:
            stats["blocked_queries"] += 1
            blocked_queries.append(
                {
                    "repository_identity": identity,
                    "anchor": anchor_value,
                    "reason": "no_local_clone",
                }
            )
            continue
        try:
            global_arguments = list(
                (git_global_arguments_by_repository or {}).get(identity, [])
            )
            completed = run_git(
                [
                    "git",
                    "-C",
                    str(repo_path),
                    *global_arguments,
                    "log",
                    "--all",
                    "--regexp-ignore-case",
                    "--fixed-strings",
                    f"--grep={anchor_value}",
                    "--format=%H",
                ],
                capture_output=True,
                encoding="ascii",
                errors="replace",
                timeout=timeout,
                no_lazy_fetch=True,
            )
        except Exception as exc:  # noqa: BLE001 - recorded, never interpreted as no
            stats["blocked_queries"] += 1
            blocked_queries.append(
                {
                    "repository_identity": identity,
                    "anchor": anchor_value,
                    "reason": f"git_log_exception:{type(exc).__name__}",
                }
            )
            continue
        if completed.returncode != 0:
            stats["blocked_queries"] += 1
            blocked_queries.append(
                {
                    "repository_identity": identity,
                    "anchor": anchor_value,
                    "reason": f"git_log_nonzero:{completed.returncode}",
                }
            )
            continue
        matches = sorted(
            {
                sha
                for line in str(completed.stdout or "").splitlines()
                if len(sha := line.strip().lower()) == 40
                and all(character in _HEX for character in sha)
            }
        )
        stats["matched_commits"] += len(matches)
        for association, anchor in targets:
            advisory = str(association.get("advisory") or "")
            detail = f"{anchor.get('kind', '')}:{anchor_value}"
            for fix_sha in matches:
                observation = _source_observation(
                    repository_identity=identity,
                    advisory=advisory,
                    fix_ref=fix_sha,
                    evidence_kind=REPOSITORY_REFERENCE_CARRIER,
                    source="local_commit_message_reference",
                    source_path=str(repo_path),
                    detail=detail,
                )
                observations[str(observation["observation_id"])] = observation
    rows = [observations[key] for key in sorted(observations)]
    stats["observation_count"] = len(rows)
    return rows, {
        **dict(sorted(stats.items())),
        "blocked": sorted(
            blocked_queries,
            key=lambda row: (row["repository_identity"], row["anchor"]),
        ),
        "observations_sha256": _sha256_json(rows),
    }


def resolve_source_observations(
    observations: Sequence[Mapping[str, object]],
    repositories: Mapping[str, Path],
    *,
    timeout: int,
) -> tuple[list[dict[str, object]], dict[str, list[dict[str, str]]], dict[str, object]]:
    """Resolve every source reference from local objects and conserve failures."""

    resolution_cache: dict[tuple[str, str], tuple[str, str]] = {}
    resolved_rows: list[dict[str, object]] = []
    fixes_by_repo: dict[str, list[dict[str, str]]] = defaultdict(list)
    stats = Counter[str]()
    for raw in observations:
        identity = str(raw.get("repository_identity") or "").strip().lower()
        advisory = str(raw.get("advisory") or "").strip()
        fix_ref = _valid_commit_ref(raw.get("fix_ref"))
        if not identity or not advisory or not fix_ref:
            raise FixSourceContractError("fix source observation is malformed")
        key = (identity, fix_ref)
        if key not in resolution_cache:
            repo_path = repositories.get(identity)
            if repo_path is None:
                resolution_cache[key] = ("", "no_local_clone")
            else:
                try:
                    completed = run_git(
                        [
                            "git",
                            "-C",
                            str(repo_path),
                            "rev-parse",
                            "--verify",
                            f"{fix_ref}^{{commit}}",
                        ],
                        capture_output=True,
                        encoding="ascii",
                        errors="replace",
                        timeout=timeout,
                        no_lazy_fetch=True,
                    )
                except Exception as exc:  # noqa: BLE001 - preserved as BLOCKED
                    resolution_cache[key] = (
                        "",
                        f"rev_parse_exception:{type(exc).__name__}",
                    )
                else:
                    sha = str(completed.stdout or "").strip().lower()
                    if (
                        completed.returncode == 0
                        and len(sha) == 40
                        and all(character in _HEX for character in sha)
                    ):
                        resolution_cache[key] = (sha, "")
                    else:
                        resolution_cache[key] = (
                            "",
                            "fix_object_unavailable_or_ambiguous",
                        )
        fix_sha, reason = resolution_cache[key]
        row = dict(raw)
        row["resolution_status"] = "RESOLVED" if fix_sha else "BLOCKED"
        row["resolution_reason"] = reason
        row["fix_sha"] = fix_sha
        resolved_rows.append(row)
        stats[row["resolution_status"].lower()] += 1
        stats[f"evidence_kind:{row.get('evidence_kind', '')}"] += 1
        fixes_by_repo[identity].append(
            {
                "advisory": advisory,
                "fix_sha": fix_sha or fix_ref,
                "published": str(raw.get("published") or ""),
                "source": f"{raw.get('evidence_kind', '')}:{raw.get('source', '')}",
            }
        )
    resolved_rows.sort(key=lambda row: str(row.get("observation_id") or ""))
    stats["observation_count"] = len(resolved_rows)
    stats["unique_reference_count"] = len(resolution_cache)
    return resolved_rows, dict(fixes_by_repo), {
        **dict(sorted(stats.items())),
        "observations_sha256": _sha256_json(resolved_rows),
    }


def build_repository_recall_floor(
    units_by_repository: Mapping[str, Sequence[Mapping[str, object]]],
    associations: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Pair every known advisory/repository with every observed cohort unit.

    These rows are not ancestry claims and intentionally have no ``fix_sha``.
    They are the source-independent recall floor used when every fix source is
    missing or wrong.
    """

    merged: dict[tuple[str, str], dict[str, object]] = {}
    for raw in associations:
        identity = str(raw.get("repository_identity") or "").strip().lower()
        advisory = str(raw.get("advisory") or "").strip()
        if identity not in units_by_repository or not advisory:
            continue
        key = (identity, advisory)
        row = merged.setdefault(
            key,
            {
                "association_id": _stable_id(
                    "advisory-repository", identity, advisory
                ),
                "repository_identity": identity,
                "advisory": advisory,
                "descriptions": [],
                "sources": [],
            },
        )
        description = str(raw.get("description") or "").strip()
        if description:
            row["descriptions"].append(description)
        source = str(raw.get("source") or "").strip()
        if source:
            row["sources"].append(source)

    association_rows: list[dict[str, object]] = []
    candidates: list[dict[str, object]] = []
    for key in sorted(merged):
        identity, advisory = key
        association = merged[key]
        association["descriptions"] = sorted(set(association["descriptions"]))
        association["sources"] = sorted(set(association["sources"]))
        association_rows.append(association)
        seen_units: set[str] = set()
        for raw_unit in units_by_repository[identity]:
            unit_identity = str(
                raw_unit.get("repository_identity") or ""
            ).strip().lower()
            sha = str(raw_unit.get("sha") or "").strip().lower()
            if unit_identity != identity or len(sha) != 40 or any(
                character not in _HEX for character in sha
            ):
                raise FixSourceContractError("repository recall-floor unit is malformed")
            if sha in seen_units:
                continue
            seen_units.add(sha)
            candidate: dict[str, object] = {
                "fallback_id": _stable_id(
                    "source-fallback", identity, advisory, sha
                ),
                "repository_identity": identity,
                "advisory": advisory,
                "candidate_sha": sha,
                "relation": REPOSITORY_ADVISORY_FALLBACK,
                "association_id": association["association_id"],
                "initial_status": "DEFER",
                "initial_reason": "fix_source_independent_recall_floor",
            }
            for field in _UNIT_METADATA_KEYS:
                if field in raw_unit:
                    candidate[field] = raw_unit[field]
            candidates.append(candidate)
    candidates.sort(key=lambda row: str(row["fallback_id"]))
    summary: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "forward_cohort_repository_advisory_recall_floor",
        "association_count": len(association_rows),
        "fallback_candidate_count": len(candidates),
        "association_sha256": _sha256_json(association_rows),
        "fallback_candidates_sha256": _sha256_json(candidates),
        "all_candidates_deferred": all(
            row["initial_status"] == "DEFER" for row in candidates
        ),
        "claim_boundary": (
            "each row is only a same-repository advisory fallback, not an ancestry"
            " or causal claim; it remains available when every fix source is absent"
            " or wrong"
        ),
    }
    summary["summary_sha256"] = _sha256_json(summary)
    return {
        "associations": association_rows,
        "candidates": candidates,
        "summary": summary,
    }


def associations_from_public_references(
    references: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Build repository/advisory intake rows from exact public references."""

    rows: dict[tuple[str, str], dict[str, object]] = {}
    for raw in references:
        identity = str(raw.get("repository_identity") or "").strip().lower()
        advisory = str(raw.get("advisory") or "").strip()
        if not identity or not advisory:
            raise FixSourceContractError("public advisory association is malformed")
        rows[(identity, advisory)] = {
            "association_id": _stable_id("advisory-repository", identity, advisory),
            "repository_identity": identity,
            "advisory": advisory,
            "description": "",
            "source": "osv_bulk",
        }
    return [rows[key] for key in sorted(rows)]


def evaluate_fix_source_recall(
    fixes: Sequence[Mapping[str, object]],
    observations: Sequence[Mapping[str, object]],
    fallback_candidates: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Evaluate source tiers against a sealed fix-only manifest.

    This evaluation runs after generation and needs no origin/relation field.
    A carrier hit counts only toward source-candidate recall, never public or
    enriched-selected exact coverage.
    """

    rows: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for raw_fix in fixes:
        identity = str(raw_fix.get("repository_identity") or "").strip().lower()
        advisory = str(raw_fix.get("advisory") or "").strip()
        fix_sha = _valid_commit_ref(raw_fix.get("fix_sha"))
        if not identity or not advisory or len(fix_sha) != 40:
            raise FixSourceContractError("sealed fix source target is malformed")
        key = (identity, advisory, fix_sha)
        if key in seen:
            raise FixSourceContractError("duplicate sealed fix source target")
        seen.add(key)
        matches = [
            observation
            for observation in observations
            if str(observation.get("repository_identity") or "").strip().lower()
            == identity
            and str(observation.get("advisory") or "").strip() == advisory
            and str(observation.get("fix_sha") or "").strip().lower() == fix_sha
            and observation.get("resolution_status") == "RESOLVED"
        ]
        kinds = sorted(
            {str(observation.get("evidence_kind") or "") for observation in matches}
        )
        public = PUBLIC_EXACT in kinds
        selected = ENRICHED_SELECTED in kinds
        carrier = any(
            kind in {RANKED_SEARCH_CARRIER, REPOSITORY_REFERENCE_CARRIER}
            for kind in kinds
        )
        fallback_matches = [
            candidate
            for candidate in fallback_candidates
            if str(candidate.get("repository_identity") or "").strip().lower()
            == identity
            and str(candidate.get("advisory") or "").strip() == advisory
            and candidate.get("relation") == REPOSITORY_ADVISORY_FALLBACK
        ]
        rows.append(
            {
                "repository_identity": identity,
                "advisory": advisory,
                "fix_sha": fix_sha,
                "public_exact_status": "PASS" if public else "MISS",
                "enriched_selected_union_status": (
                    "PASS" if public or selected else "MISS"
                ),
                "source_candidate_status": "PASS" if matches else "MISS",
                "carrier_match": carrier,
                "matching_evidence_kinds": kinds,
                "matching_observation_ids": sorted(
                    str(observation.get("observation_id") or "")
                    for observation in matches
                ),
                "repository_fallback_status": (
                    "PASS" if fallback_matches else "MISS"
                ),
                "repository_fallback_candidate_count": len(fallback_matches),
            }
        )
    rows.sort(
        key=lambda row: (
            str(row["repository_identity"]),
            str(row["advisory"]),
            str(row["fix_sha"]),
        )
    )
    total = len(rows)
    public_passes = sum(row["public_exact_status"] == "PASS" for row in rows)
    selected_passes = sum(
        row["enriched_selected_union_status"] == "PASS" for row in rows
    )
    source_passes = sum(row["source_candidate_status"] == "PASS" for row in rows)
    fallback_passes = sum(
        row["repository_fallback_status"] == "PASS" for row in rows
    )
    result: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "forward_cohort_fix_source_recall",
        "fix_obligation_count": total,
        "public_exact_pass_count": public_passes,
        "enriched_selected_union_pass_count": selected_passes,
        "source_candidate_pass_count": source_passes,
        "repository_fallback_pass_count": fallback_passes,
        "public_exact_recall": public_passes / total if total else 0.0,
        "enriched_selected_union_recall": selected_passes / total if total else 0.0,
        "source_candidate_recall": source_passes / total if total else 0.0,
        "repository_fallback_recall": fallback_passes / total if total else 0.0,
        "source_candidate_gate_passed": bool(rows) and source_passes == total,
        "repository_fallback_gate_passed": bool(rows) and fallback_passes == total,
        "fixes": rows,
        "fixes_sha256": _sha256_json(rows),
        "claim_boundary": (
            "public exact, cached enriched selection, and carrier candidate recall"
            " are separate metrics; carrier matches are not verified fixes; repository"
            " fallback proves only same-repository candidate retention, not ancestry or"
            " causality"
        ),
        "model_api_calls": 0,
        "model_input_tokens": 0,
        "model_output_tokens": 0,
        "model_cost_usd": 0.0,
    }
    result["result_sha256"] = _sha256_json(result)
    return result
