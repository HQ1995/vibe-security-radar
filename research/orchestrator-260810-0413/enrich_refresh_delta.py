#!/usr/bin/env python3
"""Enrich the frozen 46-row refresh delta without changing the population ledger."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tarfile
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUN = Path(__file__).resolve().parent
SOURCE_RUN = ROOT / "autoresearch/orchestrator-260809-2331"
SCAN = ROOT / "autoresearch/orchestrator-260809-0539/current-ai-scan/commits.jsonl"
PRODUCT_RE = re.compile(r"(?<![\w.-])([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?![\w.-])")
PUBLIC_ID_RE = re.compile(r"^(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}(?:-[0-9a-z]{4}){2})$", re.I)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "cve-analyzer/src")]

from cohort.advisories import commit_reference_rows_from_record  # noqa: E402
from cohort.commit_urls import parse_foreign_commit_url  # noqa: E402
from cohort.fix_sources import (  # noqa: E402
    resolve_commit_refs,
    scan_repository_reference_carriers,
)
from cohort.repos import clone_identity  # noqa: E402
from cve_analyzer.git_ops import (  # noqa: E402
    REPOSITORY_CACHE_ROOT_ENV,
    url_to_cache_dir,
)
from cve_analyzer.git_url import parse_commit_url, parse_pr_url, parse_repo_url  # noqa: E402


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def urls(value: object) -> list[str]:
    if isinstance(value, Mapping):
        return [
            item
            for key, child in value.items()
            for item in ([child] if key == "url" and isinstance(child, str) else urls(child))
        ]
    if isinstance(value, list):
        return [item for child in value for item in urls(child)]
    return []


def repository_identity(url: str) -> str:
    parsed = parse_repo_url(url)
    return "/".join(parsed).lower() if parsed else ""


def specific_anchor(value: object) -> str:
    token = str(value or "").strip()
    if PUBLIC_ID_RE.fullmatch(token) or UUID_RE.fullmatch(token):
        return token
    if (
        len(token) >= 8
        and token.count("-") >= 2
        and any(character.isdigit() for character in token)
        and "." not in token
    ):
        return token
    return ""


def record_text(record: Mapping[str, object]) -> tuple[str, list[str]]:
    cna = ((record.get("containers") or {}).get("cna") or {}) if isinstance(record.get("containers"), Mapping) else {}
    title = str(cna.get("title") or record.get("summary") or "")
    products = [
        str(row.get("product") or "")
        for row in cna.get("affected") or []
        if isinstance(row, Mapping)
    ]
    return title, products


def source_records(rows: list[dict]) -> dict[str, dict]:
    wanted = {member for row in rows for member in row["member_ids"]}
    subjects = {
        row["id"]: row
        for row in jsonl(SOURCE_RUN / "official-census/subjects.jsonl")
        if row["id"] in wanted
    }
    archives = {
        name: tarfile.open(ROOT / details["path"], "r:gz")
        for name, details in json.loads((RUN / "goal_contract.json").read_text())["source_archives"].items()
    }
    records: dict[str, dict] = {}
    try:
        for member_id in sorted(wanted):
            subject = subjects.get(member_id)
            if subject is None:
                raise RuntimeError(f"official subject missing: {member_id}")
            handle = archives[subject["source"]].extractfile(subject["path"])
            if handle is None:
                raise RuntimeError(f"official record missing: {subject['path']}")
            raw = handle.read()
            records[member_id] = {
                "payload": json.loads(raw),
                "evidence": {
                    "id": member_id,
                    "source": subject["source"],
                    "source_path": subject["path"],
                    "record_sha256": hashlib.sha256(raw).hexdigest(),
                },
            }
    finally:
        for archive in archives.values():
            archive.close()
    return records


def local_clone_paths(identities: set[str]) -> dict[str, list[Path]]:
    observed: dict[str, set[Path]] = defaultdict(set)
    for row in jsonl(SCAN):
        identity = str(row.get("repository_identity") or "").lower()
        if identity in identities:
            observed[identity].update(Path(path) for path in row.get("observed_in_clone_paths", []))

    prior_root = os.environ.get(REPOSITORY_CACHE_ROOT_ENV)
    try:
        for identity in identities:
            url = f"https://{identity}"
            for root in (str(ROOT / ".ai-slop/cache/cve-analyzer"), None):
                if root is None:
                    os.environ.pop(REPOSITORY_CACHE_ROOT_ENV, None)
                else:
                    os.environ[REPOSITORY_CACHE_ROOT_ENV] = root
                observed[identity].add(url_to_cache_dir(url))
    finally:
        if prior_root is None:
            os.environ.pop(REPOSITORY_CACHE_ROOT_ENV, None)
        else:
            os.environ[REPOSITORY_CACHE_ROOT_ENV] = prior_root

    return {
        identity: sorted(
            path
            for path in paths
            if (path / ".git").is_dir() and clone_identity(path) == identity
        )
        for identity, paths in observed.items()
    }


def main() -> int:
    input_rows = list(jsonl(RUN / "frozen-input.jsonl"))
    records = source_records(input_rows)
    associations: dict[tuple[str, str], dict] = {}
    fix_references: dict[tuple[str, str, str, str], dict] = {}

    def associate(class_id: str, advisory: str, identity: str, kind: str, value: str) -> None:
        if not identity:
            return
        row = associations.setdefault(
            (class_id, identity),
            {
                "class_id": class_id,
                "advisory": advisory,
                "repository_identity": identity,
                "evidence": [],
                "anchors": [],
            },
        )
        item = {"kind": kind, "value": value}
        if item not in row["evidence"]:
            row["evidence"].append(item)

    def add_fix(class_id: str, advisory: str, raw: Mapping[str, object], source_id: str) -> None:
        identity = str(raw.get("repository_identity") or "").lower()
        ref = str(raw.get("fix_sha") or "").lower()
        if identity and ref:
            fix_references[(class_id, identity, ref, str(raw.get("reference_kind") or ""))] = {
                "class_id": class_id,
                "advisory": advisory,
                "repository_identity": identity,
                "fix_ref": ref,
                "reference_kind": str(raw.get("reference_kind") or "commit_url"),
                "source_id": source_id,
            }
            associate(class_id, advisory, identity, "official_commit_reference", ref)

    for row in input_rows:
        class_id = row["class_id"]
        advisory = row["analysis_subject"]
        anchors = set(row["member_ids"])
        for member_id in row["member_ids"]:
            record = records[member_id]["payload"]
            if member_id.startswith("GHSA-"):
                for reference in commit_reference_rows_from_record(record):
                    add_fix(class_id, advisory, reference, member_id)
            record_urls = sorted(set(urls(record)))
            for url in record_urls:
                parsed_commit = parse_commit_url(url)
                foreign = parse_foreign_commit_url(url)
                if parsed_commit:
                    add_fix(
                        class_id,
                        advisory,
                        {
                            "repository_identity": f"{parsed_commit.host}/{parsed_commit.owner}/{parsed_commit.repo}".lower(),
                            "fix_sha": parsed_commit.sha,
                            "reference_kind": "commit_url",
                        },
                        member_id,
                    )
                elif foreign:
                    add_fix(
                        class_id,
                        advisory,
                        {"repository_identity": foreign[0], "fix_sha": foreign[1], "reference_kind": "commit_url"},
                        member_id,
                    )
                identity = repository_identity(url)
                associate(class_id, advisory, identity, "official_repository_url", url)
                parsed_pr = parse_pr_url(url)
                if parsed_pr:
                    anchors.add(f"#{parsed_pr.number}")
            title, products = record_text(record)
            for token in {match.group(1) for text in [title, *products] for match in PRODUCT_RE.finditer(text)}:
                identity = repository_identity(f"https://github.com/{token}")
                associate(class_id, advisory, identity, "official_product_token", token)
            cna = ((record.get("containers") or {}).get("cna") or {}) if isinstance(record.get("containers"), Mapping) else {}
            source = cna.get("source") or {}
            source_anchor = specific_anchor(source.get("advisory")) if isinstance(source, Mapping) else ""
            if source_anchor:
                anchors.add(source_anchor)
        for (cid, _identity), association in associations.items():
            if cid == class_id:
                association["anchors"] = [
                    {"kind": "official_reference_token", "value": value}
                    for value in sorted(anchors)
                ]

    identities = {identity for _class_id, identity in associations}
    clones = local_clone_paths(identities)

    carrier_rows: dict[str, dict] = {}
    blocked_history: dict[str, set[str]] = defaultdict(set)
    by_identity: dict[str, list[dict]] = defaultdict(list)
    for (_class_id, identity), association in associations.items():
        by_identity[identity].append(association)
    for identity, identity_associations in sorted(by_identity.items()):
        paths = clones.get(identity, [])
        if not paths:
            for association in identity_associations:
                blocked_history[association["class_id"]].add(f"no_local_clone:{identity}")
            continue
        for path in paths:
            found, stats = scan_repository_reference_carriers(
                {identity: path}, identity_associations, timeout=120
            )
            for item in found:
                carrier_rows[str(item["observation_id"])] = item
            for blocked in stats.get("blocked", []):
                for association in identity_associations:
                    blocked_history[association["class_id"]].add(
                        f"{blocked['reason']}:{identity}:{blocked['anchor']}"
                    )

    refs_by_identity: dict[str, set[str]] = defaultdict(set)
    for item in fix_references.values():
        refs_by_identity[item["repository_identity"]].add(item["fix_ref"])
    resolution: dict[tuple[str, str], tuple[str, str]] = {}
    for identity, refs in sorted(refs_by_identity.items()):
        paths = clones.get(identity, [])
        if not paths:
            resolution.update({(identity, ref): ("", "no_local_clone") for ref in refs})
            continue
        per_path = [resolve_commit_refs(path, refs, timeout=120) for path in paths]
        for ref in refs:
            resolved = next((result for values in per_path if (result := values[ref])[0]), None)
            resolution[(identity, ref)] = resolved or ("", ";".join(sorted({values[ref][1] for values in per_path})))

    carrier_by_class: dict[str, list[dict]] = defaultdict(list)
    class_by_advisory = {row["analysis_subject"]: row["class_id"] for row in input_rows}
    for item in carrier_rows.values():
        carrier_by_class[class_by_advisory[item["advisory"]]].append(item)
    fix_by_class: dict[str, list[dict]] = defaultdict(list)
    for item in fix_references.values():
        fix_sha, reason = resolution[(item["repository_identity"], item["fix_ref"])]
        fix_by_class[item["class_id"]].append(
            {**item, "fix_sha": fix_sha, "resolution_status": "RESOLVED" if fix_sha else "BLOCKED", "resolution_reason": reason}
        )

    overlay = []
    for row in input_rows:
        class_id = row["class_id"]
        class_associations = [value for (cid, _identity), value in associations.items() if cid == class_id]
        fixes = sorted(fix_by_class[class_id], key=lambda item: (item["repository_identity"], item["fix_ref"]))
        carriers = sorted(carrier_by_class[class_id], key=lambda item: str(item["observation_id"]))
        blocks = sorted(blocked_history[class_id])
        if fixes or carriers:
            status, next_action = "CANDIDATE_EVIDENCE", "ADJUDICATE_CAUSAL_EDGE"
        elif blocks:
            status, next_action = "BLOCKED", "RECOVER_REPOSITORY_HISTORY"
        else:
            status, next_action = "UNKNOWN", "RETAIN_UNKNOWN_FOR_BACKGROUND_AUDIT"
        overlay.append(
            {
                "class_id": class_id,
                "analysis_subject": row["analysis_subject"],
                "member_ids": row["member_ids"],
                "base_disposition": row["disposition"],
                "enrichment_status": status,
                "next_action": next_action,
                "official_records": [records[member]["evidence"] for member in row["member_ids"]],
                "repository_associations": sorted(class_associations, key=lambda item: item["repository_identity"]),
                "local_clone_paths": {
                    item["repository_identity"]: [str(path) for path in clones.get(item["repository_identity"], [])]
                    for item in class_associations
                },
                "fix_references": fixes,
                "history_carriers": carriers,
                "blocked_reasons": blocks,
            }
        )

    overlay_path = RUN / "enrichment-overlay.jsonl"
    with overlay_path.open("w", encoding="utf-8") as handle:
        for row in overlay:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    status_counts = Counter(row["enrichment_status"] for row in overlay)
    summary = {
        "schema_version": 1,
        "artifact_kind": "refresh_delta_official_reference_and_history_overlay",
        "input_rows": len(input_rows),
        "input_sha256": sha256(RUN / "frozen-input.jsonl"),
        "source_record_count": len(records),
        "repository_association_count": len(associations),
        "repositories_with_local_history": sum(bool(paths) for paths in clones.values()),
        "fix_reference_count": len(fix_references),
        "resolved_fix_reference_count": sum(bool(row["fix_sha"]) for rows in fix_by_class.values() for row in rows),
        "history_carrier_count": len(carrier_rows),
        "status_counts": dict(sorted(status_counts.items())),
        "overlay_sha256": sha256(overlay_path),
        "model_api_calls": 0,
        "model_cost_usd": 0.0,
        "claim_boundary": "candidate evidence routes adjudication only; UNKNOWN and BLOCKED are never negative, and no row is promoted to verified AI causality",
    }
    (RUN / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
