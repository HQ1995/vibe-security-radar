#!/usr/bin/env python3
"""Freeze the atomic squash-member closure for the Transformers 0-day family.

The artifact is deliberately recall-first.  Every recovered PR member remains a
candidate, even when Source v3 finds no explicit AI attribution.  Source matches
control which members may support a direct authorship claim; they never delete a
member from the structural candidate inventory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cve_analyzer.provenance import scan_repo_ai_commit_index


REPOSITORY_IDENTITY = "github.com/huggingface/transformers"
EXPECTED_BASELINE_AI_UNITS = 26
FULL_SHA = re.compile(r"[0-9a-f]{40}")

# These values were read from the merged PR metadata.  The locally fetched refs
# are checked against the exact heads, and the local commit graph is checked
# against the exact bases and member counts before an artifact is emitted.
PR_SPECS: tuple[dict[str, object], ...] = (
    {
        "number": 39598,
        "base": "5dba4bc7b2c1ef517ed44bba76bb70b59001c737",
        "head": "f2563b4631ab58410deb63af4d5b2008b1c100b3",
        "landed": "0fe03afeb82e1a435a75704d1f434c47e49a0bbb",
        "member_count": 3,
        "merged_at": "2025-07-23T12:43:12Z",
    },
    {
        "number": 40128,
        "base": "e5886f9194ab6e19a7187c72d0b42be17bbc09cd",
        "head": "d7d960e298c34c34422b2917ae6cd615c4ba2d39",
        "landed": "00b4dfb7860c13eaf12613b815f3b5ef2d22ce52",
        "member_count": 5,
        "merged_at": "2025-08-18T14:31:40Z",
    },
    {
        "number": 40389,
        "base": "40299134a8cdd0f8c9a2cafbeb4c91d8eb490b80",
        "head": "b74ee18135b4e6b2493dcccd8eb50943cc0a3ac1",
        "landed": "11e12a715a0e54bb82c5b5775b069e7befc6923c",
        "member_count": 1,
        "merged_at": "2025-08-25T11:56:30Z",
    },
    {
        "number": 41310,
        "base": "438343d93f08d6f1f7c67933aaadf014ce719b4c",
        "head": "e6d8087351cb6bb9c200c7f3e99e5f21264a7d5d",
        "landed": "2ccc6cae21faaf11631efa5fb9054687ae5dc931",
        "member_count": 167,
        "merged_at": "2025-10-03T16:29:52Z",
    },
    {
        "number": 42928,
        "base": "b712a97d09efb3e6058d364c4e4783356a0250c8",
        "head": "d1aae01e213833ee0ad71e61b4a41eb6dc85279b",
        "landed": "b62e5b3e4060c07b0e595f670135d85bb51673fe",
        "member_count": 1,
        "merged_at": "2025-12-18T17:55:31Z",
    },
    {
        "number": 43040,
        "base": "a7f29523361b2cc12e51c1f5133d95f122f6f45c",
        "head": "58a1ee7d6acf31ceec74a5b77c894c800b78a5e5",
        "landed": "3aa21543ddda64d24314f1a17d2e80ad8747a9af",
        "member_count": 1,
        "merged_at": "2026-01-08T00:41:28Z",
    },
    {
        "number": 43235,
        "base": "7f20ad0073ae6d2f6a799c1404448d579496b6c4",
        "head": "56815e0517a4eda8879efea43c9d03b7a542d508",
        "landed": "c0d2e26fcebfa816db1537773c012f6f9e20a361",
        "member_count": 1,
        "merged_at": "2026-01-13T01:11:49Z",
    },
)

# Frozen positive controls for the existing Source-v3 matcher.  A later matcher
# may discover more members, so this is an add-only subset requirement rather
# than an exact-set requirement.
EXPECTED_SOURCE_AI_MEMBERS = frozenset(
    {
        "4ce49539d85abe54b4011d5c55a0a1d6f66b5dad",
        "0023a9af404e64943fc0a36fa92ef87763744a7e",
        "b74ee18135b4e6b2493dcccd8eb50943cc0a3ac1",
        "469336dea69f906d43dfeb86670644b02fe7ed53",
        "d1aae01e213833ee0ad71e61b4a41eb6dc85279b",
        "58a1ee7d6acf31ceec74a5b77c894c800b78a5e5",
        "56815e0517a4eda8879efea43c9d03b7a542d508",
    }
)

ADVISORY_SPECS: tuple[dict[str, object], ...] = (
    {
        "cve": "CVE-2025-14920",
        "path": "cves/2025/14xxx/CVE-2025-14920.json",
        "affected": "9c8bd3fc1befe54f3efb9f385561eef49f060a70",
        "family": "Perceiver",
        "prefixes": ("src/transformers/models/perceiver/",),
        "reference": "https://www.zerodayinitiative.com/advisories/ZDI-25-1150/",
    },
    {
        "cve": "CVE-2025-14921",
        "path": "cves/2025/14xxx/CVE-2025-14921.json",
        "affected": "9c8bd3fc1befe54f3efb9f385561eef49f060a70",
        "family": "Transformer-XL",
        "prefixes": ("src/transformers/models/deprecated/transfo_xl/",),
        "reference": "https://www.zerodayinitiative.com/advisories/ZDI-25-1149/",
    },
    {
        "cve": "CVE-2025-14924",
        "path": "cves/2025/14xxx/CVE-2025-14924.json",
        "affected": "95faabf0a6cd845f4c5548697e288a79e424b096",
        "family": "megatron_gpt2",
        "prefixes": ("src/transformers/models/megatron_gpt2/",),
        "reference": "https://www.zerodayinitiative.com/advisories/ZDI-25-1141/",
    },
    {
        "cve": "CVE-2025-14926",
        "path": "cves/2025/14xxx/CVE-2025-14926.json",
        "affected": "4.57.0",
        "family": "SEW",
        "prefixes": ("src/transformers/models/sew/",),
        "reference": "https://www.zerodayinitiative.com/advisories/ZDI-25-1147/",
    },
    {
        "cve": "CVE-2025-14927",
        "path": "cves/2025/14xxx/CVE-2025-14927.json",
        "affected": "4.57.0",
        "family": "SEW-D",
        "prefixes": ("src/transformers/models/sew_d/",),
        "reference": "https://www.zerodayinitiative.com/advisories/ZDI-25-1148/",
    },
    {
        "cve": "CVE-2025-14928",
        "path": "cves/2025/14xxx/CVE-2025-14928.json",
        "affected": "4.57.0",
        "family": "HuBERT",
        "prefixes": ("src/transformers/models/hubert/",),
        "reference": "https://www.zerodayinitiative.com/advisories/ZDI-25-1146/",
    },
    {
        "cve": "CVE-2025-14929",
        "path": "cves/2025/14xxx/CVE-2025-14929.json",
        "affected": "d1c6310d6a02481d48d81607cba7840be04580d1",
        "family": "X-CLIP",
        "prefixes": ("src/transformers/models/x_clip/",),
        "reference": "https://www.zerodayinitiative.com/advisories/ZDI-25-1144/",
    },
    {
        "cve": "CVE-2025-14930",
        "path": "cves/2025/14xxx/CVE-2025-14930.json",
        "affected": "4.57.1",
        "family": "GLM4",
        "prefixes": ("src/transformers/models/glm4/",),
        "reference": "https://www.zerodayinitiative.com/advisories/ZDI-25-1145/",
    },
)

MISMATCH_SPEC = {
    "cve": "CVE-2025-4929",
    "path": "cves/2025/4xxx/CVE-2025-4929.json",
}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--commit-universe", type=Path, required=True)
    parser.add_argument("--cvelist-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return _sha256_bytes(encoded)


def _git(repository: Path, arguments: list[str], *, timeout: int = 120) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            check=False,
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"git {' '.join(arguments)} failed: {exc}") from exc
    if completed.returncode != 0:
        reason = completed.stderr.decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"git {' '.join(arguments)} failed: {reason}")
    return completed.stdout.decode("utf-8", errors="strict")


def _rev_parse(repository: Path, revision: str) -> str:
    value = _git(repository, ["rev-parse", revision]).strip()
    if not FULL_SHA.fullmatch(value):
        raise SystemExit(f"revision did not resolve to a full commit: {revision}")
    return value


def _patch_id(repository: Path, before: str, after: str) -> str:
    diff = subprocess.run(
        ["git", "-C", str(repository), "diff", "--full-index", "--binary", before, after],
        capture_output=True,
        check=False,
        env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
        timeout=120,
    )
    if diff.returncode != 0:
        raise SystemExit(f"cannot compute aggregate diff for {before}..{after}")
    patch = subprocess.run(
        ["git", "patch-id", "--stable"],
        input=diff.stdout,
        capture_output=True,
        check=False,
        env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
        timeout=120,
    )
    fields = patch.stdout.decode("utf-8", errors="strict").split()
    return fields[0] if patch.returncode == 0 and fields else ""


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise SystemExit(f"{path}:{line_number}: row is not an object")
                key = (str(value.get("repository_identity", "")), str(value.get("sha", "")))
                if not key[0] or not FULL_SHA.fullmatch(key[1]):
                    raise SystemExit(f"{path}:{line_number}: malformed commit identity")
                if key in seen:
                    raise SystemExit(f"{path}:{line_number}: duplicate commit identity {key}")
                seen.add(key)
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read commit universe {path}: {exc}") from exc
    return rows


def _load_cve(path: Path) -> tuple[dict[str, object], str]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read CVE record {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"CVE record is not an object: {path}")
    return value, _sha256_bytes(raw)


def _cna(record: dict[str, object]) -> dict[str, object]:
    containers = record.get("containers")
    if not isinstance(containers, dict) or not isinstance(containers.get("cna"), dict):
        raise SystemExit("CVE record has no CNA container")
    return containers["cna"]


def _english_description(cna: dict[str, object]) -> str:
    descriptions = cna.get("descriptions")
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en":
            return str(item.get("value", ""))
    return ""


def _affected_versions(cna: dict[str, object]) -> list[str]:
    result: list[str] = []
    affected = cna.get("affected")
    if not isinstance(affected, list):
        return result
    for product in affected:
        if not isinstance(product, dict):
            continue
        versions = product.get("versions")
        if not isinstance(versions, list):
            continue
        for version in versions:
            if isinstance(version, dict) and version.get("status") == "affected":
                result.append(str(version.get("version", "")))
    return sorted(value for value in result if value)


def _vendors_and_products(cna: dict[str, object]) -> tuple[list[str], list[str]]:
    vendors: set[str] = set()
    products: set[str] = set()
    affected = cna.get("affected")
    if isinstance(affected, list):
        for item in affected:
            if not isinstance(item, dict):
                continue
            if item.get("vendor"):
                vendors.add(str(item["vendor"]))
            if item.get("product"):
                products.add(str(item["product"]))
    return sorted(vendors), sorted(products)


def _references(cna: dict[str, object]) -> list[str]:
    raw = cna.get("references")
    if not isinstance(raw, list):
        return []
    return sorted(
        str(item["url"])
        for item in raw
        if isinstance(item, dict) and item.get("url")
    )


def _risk_hits(files: list[str], advisory_specs: tuple[dict[str, object], ...]) -> list[str]:
    hits: set[str] = set()
    for spec in advisory_specs:
        prefixes = spec["prefixes"]
        assert isinstance(prefixes, tuple)
        if any(path.startswith(prefix) for path in files for prefix in prefixes):
            hits.add(str(spec["cve"]))
    return sorted(hits)


def _affected_git_ref(value: str) -> str:
    """Map a CNA release value to the repository's explicit tag spelling."""
    return value if FULL_SHA.fullmatch(value) else f"v{value}"


def _commit_metadata(repository: Path, sha: str) -> dict[str, object]:
    value = _git(
        repository,
        ["show", "-s", "--format=%H%x00%P%x00%an%x00%ae%x00%aI%x00%s", sha],
    ).rstrip("\n")
    fields = value.split("\x00")
    if len(fields) != 6 or fields[0] != sha:
        raise SystemExit(f"unexpected commit metadata for {sha}")
    changed_files = sorted(
        {
            line.strip()
            for line in _git(
                repository,
                [
                    "diff-tree",
                    "--root",
                    "--no-commit-id",
                    "--name-only",
                    "-r",
                    sha,
                ],
            ).splitlines()
            if line.strip()
        }
    )
    return {
        "sha": fields[0],
        "parents": fields[1].split(),
        "author_name": fields[2],
        "author_email": fields[3],
        "authored_at": fields[4],
        "subject": fields[5],
        "changed_files": changed_files,
    }


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise SystemExit(f"output already exists: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _validate_advisories(
    repository: Path, cvelist_root: Path
) -> tuple[list[dict[str, object]], dict[str, object]]:
    advisories: list[dict[str, object]] = []
    for spec in ADVISORY_SPECS:
        record_path = cvelist_root / str(spec["path"])
        record, digest = _load_cve(record_path)
        metadata = record.get("cveMetadata")
        if not isinstance(metadata, dict) or metadata.get("cveId") != spec["cve"]:
            raise SystemExit(f"CVE identity mismatch in {record_path}")
        cna = _cna(record)
        versions = _affected_versions(cna)
        vendors, products = _vendors_and_products(cna)
        references = _references(cna)
        if spec["affected"] not in versions:
            raise SystemExit(f"{spec['cve']}: expected affected revision is absent")
        if "Hugging Face" not in vendors or "Transformers" not in products:
            raise SystemExit(f"{spec['cve']}: vendor/product no longer match Transformers")
        if spec["reference"] not in references:
            raise SystemExit(f"{spec['cve']}: expected ZDI reference is absent")
        affected_git_ref = _affected_git_ref(str(spec["affected"]))
        resolved = _rev_parse(repository, f"{affected_git_ref}^{{commit}}")
        prefixes = spec["prefixes"]
        assert isinstance(prefixes, tuple)
        presence = {
            prefix: bool(
                _git(repository, ["ls-tree", "-r", "--name-only", resolved, "--", prefix]).strip()
            )
            for prefix in prefixes
        }
        advisories.append(
            {
                "cve": spec["cve"],
                "title": str(cna.get("title", "")),
                "description": _english_description(cna),
                "family": spec["family"],
                "affected_versions": versions,
                "affected_revision": spec["affected"],
                "affected_git_ref": affected_git_ref,
                "resolved_affected_commit": resolved,
                "model_path_prefixes": list(prefixes),
                "model_path_presence_at_affected_revision": presence,
                "references": references,
                "cvelist_path": str(record_path),
                "cvelist_sha256": digest,
                "mechanism_mapping_status": (
                    "BLOCKED_EXACT_PUBLIC_MECHANISM_LINE_UNDISCLOSED"
                ),
            }
        )

    mismatch_path = cvelist_root / str(MISMATCH_SPEC["path"])
    mismatch_record, mismatch_digest = _load_cve(mismatch_path)
    metadata = mismatch_record.get("cveMetadata")
    if not isinstance(metadata, dict) or metadata.get("cveId") != MISMATCH_SPEC["cve"]:
        raise SystemExit(f"CVE identity mismatch in {mismatch_path}")
    mismatch_cna = _cna(mismatch_record)
    mismatch_vendors, mismatch_products = _vendors_and_products(mismatch_cna)
    normalized = " ".join([*mismatch_vendors, *mismatch_products]).lower()
    if "transformers" in normalized or "hugging face" in normalized:
        raise SystemExit("CVE-2025-4929 unexpectedly identifies Transformers")
    mismatch = {
        "cve": MISMATCH_SPEC["cve"],
        "status": "REPOSITORY_ASSOCIATION_MISMATCH",
        "title": str(mismatch_cna.get("title", "")),
        "vendors": mismatch_vendors,
        "products": mismatch_products,
        "cvelist_path": str(mismatch_path),
        "cvelist_sha256": mismatch_digest,
        "claim_boundary": (
            "This CVE record identifies Campcodes Online Shopping Portal, not "
            "Hugging Face Transformers; it must not consume Transformers review budget."
        ),
    }
    return advisories, mismatch


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    universe_rows = _load_jsonl(args.commit_universe)
    repository_rows = [
        row for row in universe_rows if row["repository_identity"] == REPOSITORY_IDENTITY
    ]
    baseline_ai_rows = [row for row in repository_rows if row.get("observed_ai_unit") is True]
    if len(baseline_ai_rows) != EXPECTED_BASELINE_AI_UNITS:
        raise SystemExit(
            "frozen Transformers observed-AI count changed: "
            f"{len(baseline_ai_rows)} != {EXPECTED_BASELINE_AI_UNITS}"
        )
    baseline_ai_shas = {str(row["sha"]) for row in baseline_ai_rows}
    carrier_shas = {str(spec["landed"]) for spec in PR_SPECS}
    if not carrier_shas <= baseline_ai_shas:
        raise SystemExit("not every squash carrier is retained in the frozen AI universe")

    scan = scan_repo_ai_commit_index(repository, REPOSITORY_IDENTITY)
    if scan.get("complete") is not True:
        raise SystemExit(f"Source-v3 scan is incomplete: {scan.get('error')}")
    scan_rows = scan.get("commits")
    if not isinstance(scan_rows, list):
        raise SystemExit("Source-v3 scan returned malformed commits")
    source_by_sha = {
        str(row["sha"]): row
        for row in scan_rows
        if isinstance(row, dict) and FULL_SHA.fullmatch(str(row.get("sha", "")))
    }

    pr_rows: list[dict[str, object]] = []
    member_rows: list[dict[str, object]] = []
    seen_members: set[str] = set()
    for spec in PR_SPECS:
        number = int(spec["number"])
        base = str(spec["base"])
        head = str(spec["head"])
        landed = str(spec["landed"])
        ref = f"refs/ai-slop/transformers/pr/{number}/head"
        if _rev_parse(repository, ref) != head:
            raise SystemExit(f"PR #{number}: fetched head ref changed")
        if _rev_parse(repository, f"{base}^{{commit}}") != base:
            raise SystemExit(f"PR #{number}: base commit is unavailable")
        if _git(repository, ["merge-base", base, head]).strip() != base:
            raise SystemExit(f"PR #{number}: base is not the exact merge base")
        members = _git(
            repository, ["rev-list", "--reverse", "--topo-order", f"{base}..{head}"]
        ).split()
        if len(members) != spec["member_count"] or members[-1] != head:
            raise SystemExit(f"PR #{number}: member closure does not match frozen metadata")
        overlap = seen_members.intersection(members)
        if overlap:
            raise SystemExit(f"PR #{number}: duplicate member objects: {sorted(overlap)}")
        seen_members.update(members)

        landed_metadata = _commit_metadata(repository, landed)
        if len(landed_metadata["parents"]) != 1:
            raise SystemExit(f"PR #{number}: landed carrier is not a one-parent squash")
        if not str(landed_metadata["subject"]).endswith(f"(#{number})"):
            raise SystemExit(f"PR #{number}: landed subject does not bind the PR")
        landed_parent = str(landed_metadata["parents"][0])
        head_patch_id = _patch_id(repository, base, head)
        landed_patch_id = _patch_id(repository, landed_parent, landed)

        source_members: list[str] = []
        structural_members: list[str] = []
        for sha in members:
            metadata = _commit_metadata(repository, sha)
            source_row = source_by_sha.get(sha)
            source_matches = source_row.get("source_matches", []) if source_row else []
            if not isinstance(source_matches, list):
                raise SystemExit(f"Source-v3 matches are malformed for {sha}")
            risk_hits = _risk_hits(
                list(metadata["changed_files"]),
                ADVISORY_SPECS,
            )
            if source_matches:
                source_members.append(sha)
            if risk_hits:
                structural_members.append(sha)
            member_rows.append(
                {
                    **metadata,
                    "pr_number": number,
                    "source_v3_ai_evidence": bool(source_matches),
                    "source_matches": source_matches,
                    "advisory_model_path_hits": risk_hits,
                    "retained": True,
                    "retention_lane": (
                        "source_attributed_squash_member"
                        if source_matches
                        else "structural_squash_member_fallback"
                    ),
                }
            )
        pr_rows.append(
            {
                **spec,
                "url": f"https://github.com/huggingface/transformers/pull/{number}",
                "fetched_ref": ref,
                "landed_parent": landed_parent,
                "member_shas": members,
                "source_v3_ai_member_shas": source_members,
                "advisory_model_path_member_shas": structural_members,
                "aggregate_head_patch_id": head_patch_id,
                "aggregate_landed_patch_id": landed_patch_id,
                "aggregate_patch_equivalent": head_patch_id == landed_patch_id,
            }
        )

    detected_source_members = {
        str(row["sha"]) for row in member_rows if row["source_v3_ai_evidence"] is True
    }
    if not EXPECTED_SOURCE_AI_MEMBERS <= detected_source_members:
        missing = sorted(EXPECTED_SOURCE_AI_MEMBERS - detected_source_members)
        raise SystemExit(f"Source-v3 lost frozen member controls: {missing}")
    if len(member_rows) != 179 or len(seen_members) != 179:
        raise SystemExit("squash member inventory is not the expected 179 unique objects")

    noncarrier_ai_rows: list[dict[str, object]] = []
    for row in baseline_ai_rows:
        sha = str(row["sha"])
        if sha in carrier_shas:
            continue
        metadata = _commit_metadata(repository, sha)
        source_row = source_by_sha.get(sha)
        source_matches = source_row.get("source_matches", []) if source_row else []
        if not isinstance(source_matches, list) or not source_matches:
            raise SystemExit(f"frozen non-carrier AI unit lost Source-v3 evidence: {sha}")
        noncarrier_ai_rows.append(
            {
                **metadata,
                "ai_routes": row.get("ai_routes", []),
                "ai_tools": row.get("ai_tools", []),
                "source_v3_ai_evidence": True,
                "source_matches": source_matches,
                "advisory_model_path_hits": _risk_hits(
                    list(metadata["changed_files"]), ADVISORY_SPECS
                ),
                "retained": True,
            }
        )

    advisories, association_mismatch = _validate_advisories(
        repository, args.cvelist_root.resolve()
    )
    direct_source_path_rows = [
        row
        for row in [*member_rows, *noncarrier_ai_rows]
        if row.get("source_v3_ai_evidence", True)
        and row["advisory_model_path_hits"]
    ]
    structural_path_rows = [row for row in member_rows if row["advisory_model_path_hits"]]
    carrier_fallbacks = [
        {
            "sha": str(spec["landed"]),
            "pr_number": int(spec["number"]),
            "retained": True,
            "role": "landing_carrier_not_atomic_member_authorship",
            "may_support_whole_diff_ai_authorship": False,
        }
        for spec in PR_SPECS
    ]

    payload: dict[str, Any] = {
        "schema_version": 1,
        "artifact_kind": "transformers_zeroday_squash_member_closure",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository_identity": REPOSITORY_IDENTITY,
        "inputs": {
            "commit_universe": str(args.commit_universe.resolve()),
            "commit_universe_sha256": _sha256_bytes(args.commit_universe.read_bytes()),
            "cvelist_root": str(args.cvelist_root.resolve()),
            "source_v3_refs_digest": scan.get("refs_digest"),
            "source_v3_matcher_contract": scan.get("matcher_contract"),
            "source_v3_scan_predicate": scan.get("scan_predicate"),
            "source_v3_complete": True,
            "source_v3_repository_match_count": scan.get("commit_count"),
        },
        "frozen_baseline": {
            "repository_commit_count": len(repository_rows),
            "observed_ai_unit_count": len(baseline_ai_rows),
            "observed_ai_shas": sorted(baseline_ai_shas),
            "noncarrier_observed_ai_count": len(noncarrier_ai_rows),
            "squash_carrier_count": len(carrier_fallbacks),
        },
        "squash_closure": {
            "status": "RESOLVED",
            "pr_count": len(pr_rows),
            "member_edge_count": len(member_rows),
            "unique_member_count": len(seen_members),
            "source_v3_ai_member_count": len(detected_source_members),
            "source_v3_ai_member_shas": sorted(detected_source_members),
            "expected_source_controls_all_recalled": True,
            "structural_model_path_member_count": len(structural_path_rows),
            "structural_model_path_member_shas": sorted(
                str(row["sha"]) for row in structural_path_rows
            ),
            "member_inventory_sha256": _canonical_sha256(member_rows),
        },
        "pull_requests": pr_rows,
        "member_candidates": member_rows,
        "noncarrier_observed_ai_candidates": noncarrier_ai_rows,
        "carrier_fallbacks": carrier_fallbacks,
        "advisories": advisories,
        "repository_association_mismatch": association_mismatch,
        "findings": {
            "direct_source_attributed_model_path_overlap_count": len(
                direct_source_path_rows
            ),
            "direct_source_attributed_model_path_overlaps": direct_source_path_rows,
            "structural_model_path_overlap_count": len(structural_path_rows),
            "structural_model_path_overlaps": structural_path_rows,
            "advisory_causal_status": (
                "DEFER_NO_DIRECT_SOURCE_ATTRIBUTED_PATH_OVERLAP_"
                "BLOCKED_EXACT_PUBLIC_MECHANISM_LINE_UNDISCLOSED"
            ),
            "deletion_authority": False,
            "model_review_may_only_add_candidates": True,
        },
        "conservation": {
            "baseline_ai_units_retained": len(baseline_ai_rows),
            "squash_members_retained": len(member_rows),
            "carrier_fallbacks_retained": len(carrier_fallbacks),
            "hard_filter_count": 0,
            "members_without_source_signal_are_still_retained": True,
        },
        "claim_boundary": (
            "The seven squash carriers are not atomic authorship units. Their 179 "
            "exact PR members are retained add-only; Source v3 currently supplies "
            "direct attribution evidence for a subset, while every other member "
            "remains a structural fallback candidate. No source-attributed atomic "
            "candidate directly overlaps the eight disclosed model-family paths. "
            "That is ranking evidence only: public 0-day reports do not disclose "
            "exact causal lines, so this artifact has no authority to delete or "
            "declare unrelated candidates."
        ),
    }
    _atomic_json(args.output, payload)

    print("Transformers squash-member closure frozen")
    print(f"  PRs                     : {len(pr_rows)}")
    print(f"  unique members          : {len(member_rows)}")
    print(f"  Source-v3 AI members    : {len(detected_source_members)}")
    print(f"  structural path members : {len(structural_path_rows)}")
    print(f"  direct AI path overlaps : {len(direct_source_path_rows)}")
    print("  hard filters             : 0")
    print(f"  output                   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
