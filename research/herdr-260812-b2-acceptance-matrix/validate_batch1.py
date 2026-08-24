#!/usr/bin/env python3
"""Freeze and structurally validate the twelve completed Batch 1 shards."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from datetime import datetime
from pathlib import Path


ROOT = Path("/home/hanqing/agents/ai-slop")
OUT = ROOT / "autoresearch/herdr-260812-b2-acceptance-matrix"
SHARDS = (
    "herdr-260812-repro-qa",
    "herdr-260812-negative-controls",
    "herdr-260812-systems-ecosystem",
    "herdr-260812-python-ecosystem",
    "herdr-260812-fresh-advisories",
    "herdr-260812-ledger-qa",
    "herdr-260812-coolify-tail",
    "herdr-260812-alias-qa",
    "herdr-260812-unknown-recovery",
    "herdr-260812-openclaw-tail",
    "herdr-260812-mcp-js-ecosystem",
    "herdr-260812-squash-lineage",
)
HASH_RE = re.compile(r"(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])", re.I)
PATH_TOKEN_RE = re.compile(r"`([^`]+)`|\]\(([^)]+)\)")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory(directory: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        stat = path.stat()
        rows.append(
            {
                "path": path.relative_to(directory).as_posix(),
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "sha256": sha256(path),
            }
        )
    return rows


def inventory_identity(rows: list[dict[str, object]]) -> str:
    stable_fields = [
        {"path": row["path"], "size": row["size"], "sha256": row["sha256"]}
        for row in rows
    ]
    payload = json.dumps(
        stable_fields, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def resolve_local(shard: Path, value: str) -> Path | None:
    if not value or value.startswith(("http://", "https://")):
        return None
    candidate = Path(value)
    choices = (
        candidate if candidate.is_absolute() else shard / candidate,
        candidate if candidate.is_absolute() else ROOT / candidate,
    )
    for choice in choices:
        try:
            resolved = choice.resolve()
        except OSError:
            continue
        if resolved.exists():
            return resolved
    return None


def declared_artifacts(shard: Path, result: dict[str, object]) -> list[dict[str, object]]:
    declarations: list[dict[str, object]] = []
    for field in ("artifact_map", "artifacts"):
        value = result.get(field)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    declarations.append({"field": field, "path": item})
        elif isinstance(value, dict):
            for key, item in value.items():
                if isinstance(item, str) and HASH_RE.fullmatch(item):
                    declarations.append(
                        {"field": field, "path": str(key), "sha256": item.lower()}
                    )
                elif isinstance(item, str):
                    declarations.append(
                        {"field": field, "name": str(key), "path": item}
                    )
    for declaration in declarations:
        path = resolve_local(shard, str(declaration["path"]))
        declaration["exists"] = path is not None
        declaration["resolved_path"] = str(path) if path else None
        if path and path.is_file():
            declaration["observed_sha256"] = sha256(path)
        expected = declaration.get("sha256")
        if expected:
            declaration["hash_matches"] = declaration.get("observed_sha256") == expected
    return declarations


def parse_structured_files(shard: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in sorted(shard.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".json", ".jsonl"}:
            continue
        row: dict[str, object] = {
            "path": path.relative_to(shard).as_posix(),
            "kind": path.suffix.lower().lstrip("."),
            "ok": True,
            "records": 0,
        }
        try:
            if path.suffix.lower() == ".json":
                json.loads(path.read_text(encoding="utf-8"))
                row["records"] = 1
            else:
                with path.open(encoding="utf-8") as handle:
                    for line_number, line in enumerate(handle, 1):
                        if not line.strip():
                            continue
                        json.loads(line)
                        row["records"] = int(row["records"]) + 1
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            row["ok"] = False
            row["error"] = f"{type(exc).__name__}: {exc}"
            if isinstance(exc, json.JSONDecodeError):
                row["error_line"] = exc.lineno
        rows.append(row)
    return rows


def report_hash_pairs(shard: Path, report: str) -> list[dict[str, object]]:
    pairs: list[dict[str, object]] = []
    for line_number, line in enumerate(report.splitlines(), 1):
        hashes = [match.lower() for match in HASH_RE.findall(line)]
        if not hashes:
            continue
        tokens = [a or b for a, b in PATH_TOKEN_RE.findall(line)]
        candidates: list[Path] = []
        for token in tokens:
            path = resolve_local(shard, token)
            if path and path.is_file() and path not in candidates:
                candidates.append(path)
        for path in candidates:
            observed = sha256(path)
            pairs.append(
                {
                    "line": line_number,
                    "path": str(path),
                    "declared_hashes": hashes,
                    "observed_sha256": observed,
                    "matches_one_declared_hash": observed in hashes,
                }
            )
    return pairs


def snapshot_terminal_files(shard: Path) -> None:
    destination = OUT / "snapshot" / shard.name
    destination.mkdir(parents=True, exist_ok=True)
    for path in sorted(shard.iterdir()):
        if path.is_file() and path.suffix.lower() in {
            ".json",
            ".jsonl",
            ".md",
            ".py",
            ".txt",
        }:
            shutil.copy2(path, destination / path.name)


def main() -> int:
    source_root = ROOT / "autoresearch"
    before: dict[str, list[dict[str, object]]] = {}
    for name in SHARDS:
        before[name] = inventory(source_root / name)

    for name in SHARDS:
        snapshot_terminal_files(source_root / name)

    after: dict[str, list[dict[str, object]]] = {}
    for name in SHARDS:
        after[name] = inventory(source_root / name)

    validations: list[dict[str, object]] = []
    for name in SHARDS:
        shard = source_root / name
        report_path = shard / "report.md"
        result_path = shard / "result.json"
        report = report_path.read_text(encoding="utf-8") if report_path.is_file() else ""
        result: dict[str, object] = {}
        result_error: str | None = None
        try:
            loaded = json.loads(result_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                result = loaded
            else:
                result_error = "result.json is not an object"
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            result_error = f"{type(exc).__name__}: {exc}"

        structured = parse_structured_files(shard)
        start = parse_time(result.get("started_at"))
        end = parse_time(result.get("ended_at"))
        output = result.get("output_dir")
        output_matches = False
        if isinstance(output, str):
            candidate = Path(output)
            if not candidate.is_absolute():
                candidate = ROOT / candidate
            output_matches = candidate.resolve() == shard.resolve()

        artifacts = declared_artifacts(shard, result)
        hash_pairs = report_hash_pairs(shard, report)
        validation = {
            "shard": name,
            "source_dir": str(shard),
            "required_artifacts": {
                "report_md": report_path.is_file(),
                "result_json": result_path.is_file(),
            },
            "source_snapshot": {
                "before_file_count": len(before[name]),
                "after_file_count": len(after[name]),
                "before_identity_sha256": inventory_identity(before[name]),
                "after_identity_sha256": inventory_identity(after[name]),
                "stable_during_snapshot": before[name] == after[name],
            },
            "result_parse_error": result_error,
            "result_contract": {
                "task_nonempty": bool(result.get("task")),
                "status": result.get("status"),
                "status_valid": result.get("status") in {"COMPLETE", "PARTIAL", "BLOCKED"},
                "timestamps_valid_and_ordered": bool(start and end and start <= end),
                "output_dir_matches": output_matches,
                "counts_object": isinstance(result.get("counts"), dict),
                "blockers_array": isinstance(result.get("blockers"), list),
                "claim_boundary_in_result": bool(result.get("claim_boundary")),
                "claim_boundary_in_report": bool(
                    re.search(r"^##+ .*claim boundary", report, re.I | re.M)
                ),
            },
            "declared_artifacts": artifacts,
            "structured_files": structured,
            "structured_file_count": len(structured),
            "structured_parse_failures": sum(not bool(row["ok"]) for row in structured),
            "report_hash_pairs": hash_pairs,
            "report_hash_pair_failures": sum(
                not bool(row["matches_one_declared_hash"]) for row in hash_pairs
            ),
            "report_sha256": sha256(report_path) if report_path.is_file() else None,
            "result_sha256": sha256(result_path) if result_path.is_file() else None,
        }
        validations.append(validation)

    manifest = {
        "schema_version": 1,
        "batch": "Batch 1 terminal shard outputs",
        "source_root": str(source_root),
        "shards": [
            {
                "shard": name,
                "identity_sha256": inventory_identity(before[name]),
                "files": before[name],
            }
            for name in SHARDS
        ],
    }
    (OUT / "input-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (OUT / "validation.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "shard_count": len(validations),
                "all_snapshots_stable": all(
                    row["source_snapshot"]["stable_during_snapshot"]
                    for row in validations
                ),
                "all_structured_files_parse": all(
                    row["structured_parse_failures"] == 0 for row in validations
                ),
                "rows": validations,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
