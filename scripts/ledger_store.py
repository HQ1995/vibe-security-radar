#!/usr/bin/env python3
"""Transactional Neon ledger, scan history, and deterministic GitHub exports."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from audit_envelope import violations

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
DEFAULT_HISTORY = ROOT / "artifacts/ledger-history"
EXPORT_MARKER_NAME = ".funnel-export-marker.json"
SCHEMA = ROOT / "scripts/ledger_schema.sql"
ENV_FILE = ROOT / ".env.local"
TERMINAL_STATUSES = {"NOT_AI", "AI_ROOT_CAUSE", "AI_CODE_FLAWED", "BLOCKED", "FALSE_POSITIVE"}
ALL_STATUSES = TERMINAL_STATUSES | {"UNANALYZED", "PARTIALLY_ANALYZED"}
HISTORY_CHUNK_BYTES = 50 * 1024 * 1024


def load_env() -> None:
    if not ENV_FILE.exists():
        return
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key, value.strip().strip('"').strip("'"))


def connect(*, direct: bool = False):
    load_env()
    pooled = os.environ.get("DATABASE_URL")
    unpooled = os.environ.get("DATABASE_URL_UNPOOLED")
    url = unpooled if direct else pooled or unpooled
    if not url:
        raise SystemExit("DATABASE_URL is required")
    try:
        import psycopg
    except ImportError as exc:
        raise SystemExit(
            "psycopg is required: python3 -m pip install --user "
            "--break-system-packages -r scripts/requirements-neon.txt"
        ) from exc
    return psycopg.connect(url, connect_timeout=20)


def read_jsonl(path: Path) -> list[tuple[str, dict]]:
    records = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        class_id = row.get("class_id")
        if not isinstance(class_id, str) or not class_id:
            raise SystemExit(f"{path}:{number}: class_id missing")
        records.append((line, row))
    if len({row["class_id"] for _, row in records}) != len(records):
        raise SystemExit(f"{path}: duplicate class_id")
    return records


def read_objects(path: Path) -> list[dict]:
    records = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise SystemExit(f"{path}:{number}: JSON object required")
        records.append(value)
    return records


def parse_metadata(value: str) -> dict:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise SystemExit("metadata must be a JSON object")
    return parsed


def raw_row(row: dict) -> str:
    return json.dumps(row, ensure_ascii=False)


def sha256(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def migrate() -> None:
    with connect(direct=True) as conn:
        conn.execute(SCHEMA.read_text(encoding="utf-8"))
    print("ledger schema is current")


def bootstrap(path: Path, actor: str) -> None:
    from psycopg.types.json import Jsonb

    records = read_jsonl(path)
    change_set = f"bootstrap-{uuid.uuid4()}"
    with connect(direct=True) as conn:
        conn.execute(SCHEMA.read_text(encoding="utf-8"))
        count = conn.execute("SELECT count(*) FROM ledger_rows").fetchone()[0]
        if count:
            raise SystemExit(f"ledger_rows is not empty ({count} rows); refusing bootstrap")
        conn.execute(
            """
            INSERT INTO ledger_change_sets(change_set_id, actor, description)
            VALUES (%s, %s, %s)
            """,
            (change_set, actor, f"Initial import from {path.name}"),
        )
        row_sql = """
            INSERT INTO ledger_rows(
                class_id, ordinal, status, repo, advisory_ids, raw_json,
                revision, change_set_id, updated_by
            ) VALUES (%s, %s, %s, %s, %s, %s, 1, %s, %s)
        """
        version_sql = """
            INSERT INTO ledger_versions(
                class_id, revision, change_set_id, operation,
                raw_json, checksum, actor
            ) VALUES (%s, 1, %s, 'IMPORT', %s, %s, %s)
        """
        with conn.cursor() as cursor:
            for start in range(0, len(records), 500):
                batch = records[start : start + 500]
                cursor.executemany(
                    row_sql,
                    [
                        (
                            row["class_id"],
                            start + offset,
                            row["status"],
                            row.get("repo"),
                            Jsonb(row.get("advisory_ids") or []),
                            raw,
                            change_set,
                            actor,
                        )
                        for offset, (raw, row) in enumerate(batch)
                    ],
                )
                cursor.executemany(
                    version_sql,
                    [
                        (
                            row["class_id"],
                            change_set,
                            raw,
                            sha256(raw),
                            actor,
                        )
                        for raw, row in batch
                    ],
                )
        conn.execute(
            "UPDATE ledger_change_sets SET committed_at = now() WHERE change_set_id = %s",
            (change_set,),
        )
    print(f"bootstrapped {len(records)} ledger rows in change set {change_set}")


def database_records() -> list[tuple[str, int, dict]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT raw_json, revision FROM ledger_rows ORDER BY ordinal"
        ).fetchall()
    return [(raw, revision, json.loads(raw)) for raw, revision in rows]


def snapshot_bytes() -> bytes:
    return "".join(f"{raw}\n" for raw, _, _ in database_records()).encode()


# Server-side equivalent of sha256(snapshot_bytes()): every raw_json joined with
# a trailing newline (the join adds a separator after every row, including the
# last), UTF-8 encoded, digested in the database. Verified byte-identical to
# snapshot_bytes() on the production ledger 2026-08-31 (sha256 b7837fd8...).
# Returns 64 bytes of egress instead of pulling the full table (~26 MB).
SNAPSHOT_SHA256_SQL = """
SELECT encode(
    sha256(convert_to(coalesce(
        string_agg(raw_json, E'\\n' ORDER BY ordinal) || E'\\n', ''
    ), 'UTF8')),
    'hex'
)
FROM ledger_rows
"""


def snapshot_sha256() -> str:
    """Snapshot digest computed in the database; no full-table transfer."""
    with connect() as conn:
        return conn.execute(SNAPSHOT_SHA256_SQL).fetchone()[0]


# Same aggregates check() used to compute by pulling every ledger row into
# Python. Keys/values must match the historical `check` output exactly:
# statuses is a status -> row-count map, cve/ghsa count rows whose
# advisory_ids contain a CVE*/GHSA* identifier.
SNAPSHOT_AGGREGATES_SQL = """
WITH status_counts AS (
    SELECT jsonb_object_agg(status, n) AS statuses
    FROM (SELECT status, count(*) AS n FROM ledger_rows GROUP BY status) s
),
cve AS (
    SELECT count(*) AS n FROM ledger_rows
    WHERE EXISTS (
        SELECT 1 FROM jsonb_array_elements_text(advisory_ids) AS a(value)
        WHERE a.value LIKE 'CVE%'
    )
),
ghsa AS (
    SELECT count(*) AS n FROM ledger_rows
    WHERE EXISTS (
        SELECT 1 FROM jsonb_array_elements_text(advisory_ids) AS a(value)
        WHERE a.value LIKE 'GHSA%'
    )
)
SELECT
    (SELECT count(*) FROM ledger_rows) AS rows,
    COALESCE((SELECT statuses FROM status_counts), '{}'::jsonb) AS statuses,
    (SELECT n FROM cve) AS cve,
    (SELECT n FROM ghsa) AS ghsa,
    encode(
        sha256(convert_to(coalesce(
            string_agg(raw_json, E'\\n' ORDER BY ordinal) || E'\\n', ''
        ), 'UTF8')),
        'hex'
    ) AS sha256
FROM ledger_rows
"""


def snapshot_aggregates() -> dict:
    """Row/status/advisory counts plus the snapshot digest, all server-side."""
    with connect() as conn:
        rows, statuses, cve, ghsa, digest = conn.execute(
            SNAPSHOT_AGGREGATES_SQL
        ).fetchone()
    return {
        "rows": rows,
        "statuses": statuses,
        "cve": cve,
        "ghsa": ghsa,
        "sha256": digest,
    }


def export_jsonl(path: Path, *, force: bool = False) -> None:
    # The ledger is append-mostly: between change sets the canonical JSONL is
    # byte-identical, so gate the full ~26 MB transfer on the snapshot digest
    # (64 bytes of egress) instead of re-exporting on every verification.
    digest = snapshot_sha256()
    if not force and path.exists() and sha256(path.read_bytes()) == digest:
        print(
            f"export skipped: {path} already matches snapshot sha256={digest} "
            "(use --force to re-export)"
        )
        return
    content = snapshot_bytes()
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(content)
    os.replace(tmp, path)
    print(f"exported {content.count(chr(10).encode())} rows to {path} sha256={sha256(content)}")


INCREMENTAL_ROWS_SQL = """
SELECT class_id, raw_json, revision, updated_at
FROM ledger_rows WHERE updated_at > %s ORDER BY ordinal
"""


def _marker_path(path: Path) -> Path:
    return path.with_name(EXPORT_MARKER_NAME)


def _max_updated_at() -> str:
    with connect() as conn:
        latest = conn.execute("SELECT max(updated_at) FROM ledger_rows").fetchone()[0]
    if latest is None:
        return ""
    return latest.isoformat()


def read_jsonl_map(path: Path) -> dict[str, tuple[str, dict]]:
    """class_id -> (raw line, row) for the full local jsonl; no egress."""
    return {row["class_id"]: (line, row) for line, row in read_jsonl(path)}


def _write_jsonl_map(path: Path, records: dict[str, tuple[str, dict]]) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        for raw, _row in records.values():
            handle.write(raw if raw.endswith(chr(10)) else raw + chr(10))
    os.replace(tmp, path)


def export_jsonl_incremental(path: Path, *, force: bool = False) -> bool:
    """Delta-export ledger_rows into the local jsonl, gated on updated_at.

    Returns True when the file was rewritten. A no-marker first run reuses the
    export_jsonl snapshot digest gate: an up-to-date local file costs only the
    64-byte sha256 probe, and only a stale file triggers a full transfer.
    """
    marker_path = _marker_path(path)
    cursor = None
    if marker_path.exists() and not force:
        try:
            cursor = json.loads(marker_path.read_text(encoding="utf-8"))["updated_at"]
        except (KeyError, json.JSONDecodeError):
            cursor = None
    if cursor:
        with connect() as conn:
            changed = conn.execute(INCREMENTAL_ROWS_SQL, (cursor,)).fetchall()
        if changed:
            local = read_jsonl_map(path)
            for class_id, raw, _revision, _updated_at in changed:
                local[class_id] = (raw + chr(10), json.loads(raw))
            _write_jsonl_map(path, local)
            max_updated = max(row[3] for row in changed)
            marker_path.write_text(
                json.dumps(
                    {"updated_at": max_updated.isoformat()},
                    indent=2,
                    sort_keys=True,
                )
                + chr(10),
                encoding="utf-8",
            )
            print(
                f"exported {len(changed)} incremental rows to {path} "
                f"sha256={sha256(path.read_bytes())}"
            )
            return True
        # No rows past the cursor. Confirm the local file still matches the
        # server-side digest (64-byte probe) before skipping; a miss falls
        # through to a full export below.
        if path.exists() and sha256(path.read_bytes()) == snapshot_sha256():
            return False
    digest = snapshot_sha256()
    if not force and path.exists() and sha256(path.read_bytes()) == digest:
        marker_path.write_text(
            json.dumps({"updated_at": _max_updated_at()}, indent=2, sort_keys=True)
            + chr(10),
            encoding="utf-8",
        )
        print(
            f"export primed: {path} already matches snapshot sha256={digest[:16]} "
            "; wrote marker, no transfer"
        )
        return False
    export_jsonl(path, force=True)
    marker_path.write_text(
        json.dumps({"updated_at": _max_updated_at()}, indent=2, sort_keys=True)
        + chr(10),
        encoding="utf-8",
    )
    return True


def get_row(class_id: str) -> None:
    with connect() as conn:
        found = conn.execute(
            """
            SELECT revision, change_set_id, raw_json
            FROM ledger_rows WHERE class_id = %s
            """,
            (class_id,),
        ).fetchone()
    if not found:
        raise SystemExit(f"class_id not found: {class_id}")
    revision, change_set, raw = found
    print(
        json.dumps(
            {"revision": revision, "change_set_id": change_set, "row": json.loads(raw)},
            ensure_ascii=False,
        )
    )


def validate_update(old: dict, new: dict) -> None:
    if new.get("class_id") != old.get("class_id"):
        raise ValueError("class_id cannot change")
    if new.get("status") not in ALL_STATUSES:
        raise ValueError(f"invalid status: {new.get('status')}")
    old_ids = old.get("advisory_ids")
    new_ids = new.get("advisory_ids")
    if not isinstance(old_ids, list) or not isinstance(new_ids, list):
        raise ValueError("advisory_ids must be a list")
    lost = sorted(set(map(str, old_ids)) - set(map(str, new_ids)))
    if lost:
        raise ValueError(f"advisory_ids cannot be removed: {lost}")
    envelope_errors = violations(new)
    if envelope_errors:
        raise ValueError("envelope gate: " + "; ".join(envelope_errors))


def read_patches(path: Path, *, require_assessments: bool) -> list[dict]:
    patches = read_objects(path)
    if not patches:
        raise SystemExit(f"{path}: no patches")
    class_ids = []
    for number, item in enumerate(patches, 1):
        if not isinstance(item.get("expected_revision"), int):
            raise SystemExit(f"{path}:{number}: expected_revision is required")
        if not isinstance(item.get("row"), dict):
            raise SystemExit(f"{path}:{number}: row is required")
        class_id = item["row"].get("class_id")
        if not isinstance(class_id, str) or not class_id:
            raise SystemExit(f"{path}:{number}: row.class_id is required")
        class_ids.append(class_id)
        ids = item.get("assessment_ids", [])
        if not isinstance(ids, list) or not all(isinstance(value, str) for value in ids):
            raise SystemExit(f"{path}:{number}: assessment_ids must be a string list")
        if require_assessments and not ids:
            raise SystemExit(f"{path}:{number}: finalize requires assessment_ids")
    if len(set(class_ids)) != len(class_ids):
        raise SystemExit(f"{path}: duplicate class_id patch")
    return sorted(patches, key=lambda item: item["row"]["class_id"])


def apply_updates(
    path: Path,
    actor: str,
    description: str,
    *,
    require_assessments: bool = False,
) -> None:
    from psycopg.types.json import Jsonb

    patches = read_patches(path, require_assessments=require_assessments)
    change_set = str(uuid.uuid4())
    all_assessments = sorted(
        {assessment for item in patches for assessment in item.get("assessment_ids", [])}
    )
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO ledger_change_sets(
                change_set_id, actor, description, source_assessment_ids
            ) VALUES (%s, %s, %s, %s)
            """,
            (change_set, actor, description, Jsonb(all_assessments)),
        )
        for item in patches:
            row = item["row"]
            class_id = row["class_id"]
            current = conn.execute(
                """
                SELECT revision, raw_json
                FROM ledger_rows WHERE class_id = %s FOR UPDATE
                """,
                (class_id,),
            ).fetchone()
            if not current:
                raise RuntimeError(f"class_id not found: {class_id}")
            expected = item["expected_revision"]
            if current[0] != expected:
                raise RuntimeError(
                    f"revision conflict for {class_id}: expected {expected}, current {current[0]}"
                )
            validate_update(json.loads(current[1]), row)
            assessment_ids = sorted(set(item.get("assessment_ids", [])))
            if assessment_ids:
                found = conn.execute(
                    """
                    SELECT assessment_id FROM case_assessments
                    WHERE class_id = %s AND assessment_id = ANY(%s)
                    """,
                    (class_id, assessment_ids),
                ).fetchall()
                if {value[0] for value in found} != set(assessment_ids):
                    raise ValueError(f"assessment_ids do not belong to {class_id}")
            revision = expected + 1
            raw = raw_row(row)
            conn.execute(
                """
                INSERT INTO ledger_versions(
                    class_id, revision, change_set_id, operation, raw_json,
                    checksum, source_assessment_ids, actor
                ) VALUES (%s, %s, %s, 'UPDATE', %s, %s, %s, %s)
                """,
                (
                    class_id,
                    revision,
                    change_set,
                    raw,
                    sha256(raw),
                    Jsonb(assessment_ids),
                    actor,
                ),
            )
            changed = conn.execute(
                """
                UPDATE ledger_rows SET
                    status = %s, repo = %s, advisory_ids = %s,
                    raw_json = %s, revision = %s, change_set_id = %s,
                    updated_at = now(), updated_by = %s
                WHERE class_id = %s AND revision = %s
                """,
                (
                    row["status"],
                    row.get("repo"),
                    Jsonb(row["advisory_ids"]),
                    raw,
                    revision,
                    change_set,
                    actor,
                    class_id,
                    expected,
                ),
            ).rowcount
            if changed != 1:
                raise RuntimeError(f"concurrent update for {class_id}")
        conn.execute(
            "UPDATE ledger_change_sets SET committed_at = now() WHERE change_set_id = %s",
            (change_set,),
        )
    print(f"applied {len(patches)} rows in change set {change_set}")
    export_jsonl_incremental(DEFAULT_LEDGER)


def start_run(args: argparse.Namespace) -> None:
    from psycopg.types.json import Jsonb

    prompt = args.prompt_file.read_text(encoding="utf-8")
    run_id = args.run_id or str(uuid.uuid4())
    source_hash = snapshot_sha256()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO scan_runs(
                run_id, model_provider, model_name, model_version,
                prompt_text, prompt_hash, scanner_version,
                source_snapshot_sha256, actor, metadata
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                run_id,
                args.model_provider,
                args.model_name,
                args.model_version,
                prompt,
                sha256(prompt),
                args.scanner_version,
                source_hash,
                args.actor,
                Jsonb(parse_metadata(args.metadata_json)),
            ),
        )
    print(json.dumps({"run_id": run_id, "source_snapshot_sha256": source_hash}))


def complete_run(run_id: str) -> None:
    with connect() as conn:
        changed = conn.execute(
            """
            UPDATE scan_runs SET completed_at = now()
            WHERE run_id = %s AND completed_at IS NULL
            """,
            (run_id,),
        ).rowcount
    if changed != 1:
        raise SystemExit(f"active run not found: {run_id}")
    print(f"completed scan run {run_id}")


def add_assessments(path: Path) -> None:
    from psycopg.types.json import Jsonb

    items = read_objects(path)
    if not items:
        raise SystemExit(f"{path}: no assessments")
    run_ids = []
    for number, item in enumerate(items, 1):
        if not isinstance(item.get("run_id"), str) or not item["run_id"]:
            raise ValueError(f"{path}:{number}: run_id required")
        run_ids.append(item["run_id"])
    inserted = []
    with connect() as conn:
        active_runs = {
            row[0]
            for row in conn.execute(
                "SELECT run_id FROM scan_runs WHERE completed_at IS NULL AND run_id = ANY(%s)",
                (sorted(set(run_ids)),),
            ).fetchall()
        }
        for number, item in enumerate(items, 1):
            run_id = item.get("run_id")
            class_id = item.get("class_id")
            revision = item.get("base_ledger_revision")
            if run_id not in active_runs:
                raise ValueError(f"{path}:{number}: active run not found: {run_id}")
            if not isinstance(class_id, str) or not isinstance(revision, int):
                raise ValueError(f"{path}:{number}: class_id and base_ledger_revision required")
            if not isinstance(item.get("reasoning"), str) or not item["reasoning"].strip():
                raise ValueError(f"{path}:{number}: reasoning required")
            if not isinstance(item.get("raw_output"), str):
                raise ValueError(f"{path}:{number}: raw_output required")
            if not isinstance(item.get("agent_id"), str) or not item["agent_id"]:
                raise ValueError(f"{path}:{number}: agent_id required")
            base = conn.execute(
                """
                SELECT checksum FROM ledger_versions
                WHERE class_id = %s AND revision = %s
                """,
                (class_id, revision),
            ).fetchone()
            if not base:
                raise ValueError(f"{path}:{number}: base ledger revision not found")
            supersedes = item.get("supersedes_assessment_id")
            if supersedes:
                previous = conn.execute(
                    """
                    SELECT 1 FROM case_assessments
                    WHERE assessment_id = %s AND class_id = %s
                    """,
                    (supersedes, class_id),
                ).fetchone()
                if not previous:
                    raise ValueError(f"{path}:{number}: invalid supersedes_assessment_id")
            confidence = item.get("confidence")
            if confidence is not None and not isinstance(confidence, (int, float)):
                raise ValueError(f"{path}:{number}: confidence must be numeric")
            assessment_id = item.get("assessment_id") or str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO case_assessments(
                    assessment_id, class_id, run_id, base_ledger_revision,
                    base_row_checksum, verdict, confidence, reasoning,
                    causal_chain, evidence, raw_output, agent_id, metadata,
                    supersedes_assessment_id
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    assessment_id,
                    class_id,
                    run_id,
                    revision,
                    base[0],
                    str(item.get("verdict") or "UNSPECIFIED"),
                    confidence,
                    item["reasoning"],
                    Jsonb(item.get("causal_chain") or {}),
                    Jsonb(item.get("evidence") or {}),
                    item["raw_output"],
                    item["agent_id"],
                    Jsonb(item.get("metadata") or {}),
                    supersedes,
                ),
            )
            inserted.append(assessment_id)
    print(json.dumps({"inserted": inserted}))


def case_history(class_id: str) -> None:
    with connect() as conn:
        versions = conn.execute(
            """
            SELECT revision, change_set_id, operation, raw_json, checksum,
                   source_assessment_ids, actor, created_at
            FROM ledger_versions WHERE class_id = %s ORDER BY revision
            """,
            (class_id,),
        ).fetchall()
        assessments = conn.execute(
            """
            SELECT a.assessment_id, a.run_id, a.base_ledger_revision,
                   a.base_row_checksum, a.verdict, a.confidence, a.reasoning,
                   a.causal_chain, a.evidence, a.raw_output, a.agent_id,
                   a.metadata, a.supersedes_assessment_id, a.created_at,
                   r.model_provider, r.model_name, r.model_version,
                   r.prompt_hash, r.scanner_version, r.source_snapshot_sha256
            FROM case_assessments a
            JOIN scan_runs r ON r.run_id = a.run_id
            WHERE a.class_id = %s ORDER BY a.created_at, a.assessment_id
            """,
            (class_id,),
        ).fetchall()
    if not versions:
        raise SystemExit(f"class_id not found: {class_id}")
    print(
        json.dumps(
            {
                "class_id": class_id,
                "versions": [
                    {
                        "revision": row[0],
                        "change_set_id": row[1],
                        "operation": row[2],
                        "row": json.loads(row[3]),
                        "checksum": row[4],
                        "source_assessment_ids": row[5],
                        "actor": row[6],
                        "created_at": iso(row[7]),
                    }
                    for row in versions
                ],
                "assessments": [
                    {
                        "assessment_id": row[0],
                        "run_id": row[1],
                        "base_ledger_revision": row[2],
                        "base_row_checksum": row[3],
                        "verdict": row[4],
                        "confidence": row[5],
                        "reasoning": row[6],
                        "causal_chain": row[7],
                        "evidence": row[8],
                        "raw_output": row[9],
                        "agent_id": row[10],
                        "metadata": row[11],
                        "supersedes_assessment_id": row[12],
                        "created_at": iso(row[13]),
                        "model_provider": row[14],
                        "model_name": row[15],
                        "model_version": row[16],
                        "prompt_hash": row[17],
                        "scanner_version": row[18],
                        "source_snapshot_sha256": row[19],
                    }
                    for row in assessments
                ],
            },
            ensure_ascii=False,
        )
    )


def iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        for record in records
    )
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def write_partitioned(directory: Path, records: list[tuple[str, dict]]) -> int:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for month, record in records:
        grouped[month].append(record)
    directory.mkdir(parents=True, exist_ok=True)
    for stale in directory.glob("*.jsonl"):
        stale.unlink()
    written = 0
    for month, monthly in sorted(grouped.items()):
        chunk: list[dict] = []
        size = 0
        index = 1
        for record in monthly:
            line_size = len(json.dumps(record, ensure_ascii=False, sort_keys=True).encode()) + 1
            if chunk and size + line_size > HISTORY_CHUNK_BYTES:
                write_jsonl(directory / f"{month}-{index:03d}.jsonl", chunk)
                written += len(chunk)
                index += 1
                chunk, size = [], 0
            chunk.append(record)
            size += line_size
        if chunk:
            write_jsonl(directory / f"{month}-{index:03d}.jsonl", chunk)
            written += len(chunk)
    return written


# Fingerprint for export_history skip logic: per-table row counts plus the
# max timestamps of every column later mutations touch (change-set commits,
# run completion). All history inserts stamp created_at with now(), and
# updates only ever advance committed_at/completed_at, so an unchanged
# fingerprint implies byte-identical export output.
HISTORY_FINGERPRINT_SQL = """
SELECT
    (SELECT count(*) FROM ledger_change_sets),
    (SELECT max(created_at) FROM ledger_change_sets),
    (SELECT max(committed_at) FROM ledger_change_sets),
    (SELECT count(*) FROM ledger_versions),
    (SELECT max(created_at) FROM ledger_versions),
    (SELECT count(*) FROM scan_runs),
    (SELECT max(started_at) FROM scan_runs),
    (SELECT max(completed_at) FROM scan_runs),
    (SELECT count(*) FROM case_assessments),
    (SELECT max(created_at) FROM case_assessments)
"""


def history_fingerprint() -> dict:
    with connect() as conn:
        row = conn.execute(HISTORY_FINGERPRINT_SQL).fetchone()
    keys = (
        "change_sets", "change_sets_created_to", "change_sets_committed_to",
        "versions", "versions_created_to",
        "scan_runs", "scan_runs_started_to", "scan_runs_completed_to",
        "assessments", "assessments_created_to",
    )
    return {
        key: iso(value) if hasattr(value, "isoformat") else value
        for key, value in zip(keys, row)
    }


def export_history(directory: Path, *, force: bool = False) -> None:
    # Four-table full fetch used to cost ~50 MB per invocation; gate the
    # transfer on a lightweight fingerprint instead (history is
    # append-mostly, so unchanged fingerprints mean identical output).
    current = history_fingerprint()
    marker_path = directory / ".export-fingerprint.json"
    if not force and marker_path.exists() and json.loads(marker_path.read_text()) == current:
        print(
            "history export skipped: fingerprint unchanged since last export "
            f"({json.dumps(current, sort_keys=True)}); use --force to re-export"
        )
        return
    with connect() as conn:
        change_sets = conn.execute(
            """
            SELECT change_set_id, actor, description, source_assessment_ids,
                   created_at, committed_at
            FROM ledger_change_sets ORDER BY created_at, change_set_id
            """
        ).fetchall()
        versions = conn.execute(
            """
            SELECT class_id, revision, change_set_id, operation, raw_json,
                   checksum, source_assessment_ids, actor, created_at
            FROM ledger_versions ORDER BY created_at, class_id, revision
            """
        ).fetchall()
        runs = conn.execute(
            """
            SELECT run_id, model_provider, model_name, model_version,
                   prompt_text, prompt_hash, scanner_version,
                   source_snapshot_sha256, actor, metadata,
                   started_at, completed_at
            FROM scan_runs ORDER BY started_at, run_id
            """
        ).fetchall()
        assessments = conn.execute(
            """
            SELECT assessment_id, class_id, run_id, base_ledger_revision,
                   base_row_checksum, verdict, confidence, reasoning,
                   causal_chain, evidence, raw_output, agent_id, metadata,
                   supersedes_assessment_id, created_at
            FROM case_assessments ORDER BY created_at, assessment_id
            """
        ).fetchall()
    write_jsonl(
        directory / "change-sets.jsonl",
        [
            {
                "change_set_id": row[0],
                "actor": row[1],
                "description": row[2],
                "source_assessment_ids": row[3],
                "created_at": iso(row[4]),
                "committed_at": iso(row[5]),
            }
            for row in change_sets
        ],
    )
    write_jsonl(
        directory / "scan-runs.jsonl",
        [
            {
                "run_id": row[0],
                "model_provider": row[1],
                "model_name": row[2],
                "model_version": row[3],
                "prompt_text": row[4],
                "prompt_hash": row[5],
                "scanner_version": row[6],
                "source_snapshot_sha256": row[7],
                "actor": row[8],
                "metadata": row[9],
                "started_at": iso(row[10]),
                "completed_at": iso(row[11]),
            }
            for row in runs
        ],
    )
    version_count = write_partitioned(
        directory / "versions",
        [
            (
                row[8].strftime("%Y-%m"),
                {
                    "class_id": row[0],
                    "revision": row[1],
                    "change_set_id": row[2],
                    "operation": row[3],
                    "row": json.loads(row[4]),
                    "checksum": row[5],
                    "source_assessment_ids": row[6],
                    "actor": row[7],
                    "created_at": iso(row[8]),
                },
            )
            for row in versions
        ],
    )
    assessment_count = write_partitioned(
        directory / "assessments",
        [
            (
                row[14].strftime("%Y-%m"),
                {
                    "assessment_id": row[0],
                    "class_id": row[1],
                    "run_id": row[2],
                    "base_ledger_revision": row[3],
                    "base_row_checksum": row[4],
                    "verdict": row[5],
                    "confidence": row[6],
                    "reasoning": row[7],
                    "causal_chain": row[8],
                    "evidence": row[9],
                    "raw_output": row[10],
                    "agent_id": row[11],
                    "metadata": row[12],
                    "supersedes_assessment_id": row[13],
                    "created_at": iso(row[14]),
                },
            )
            for row in assessments
        ],
    )
    print(
        f"exported history: {len(change_sets)} change sets, {version_count} versions, "
        f"{len(runs)} runs, {assessment_count} assessments"
    )
    marker_path.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")


def check(path: Path) -> None:
    # All aggregates and the snapshot digest are computed server-side; the
    # pre-optimization version pulled the full ledger table (~26 MB egress)
    # on every verification. Aggregates are egress-equivalent to the old
    # Python-side counting: status -> row-count map, CVE/GHSA row counts,
    # sha256 over raw_json rows joined with a trailing newline.
    agg = snapshot_aggregates()
    with connect() as conn:
        runs = conn.execute("SELECT count(*) FROM scan_runs").fetchone()[0]
        assessments = conn.execute("SELECT count(*) FROM case_assessments").fetchone()[0]
    local = path.read_bytes() if path.exists() else None
    print(
        json.dumps(
            {
                "rows": agg["rows"],
                "statuses": agg["statuses"],
                "cve": agg["cve"],
                "ghsa": agg["ghsa"],
                "scan_runs": runs,
                "assessments": assessments,
                "sha256": agg["sha256"],
                "jsonl_byte_identical": sha256(local) == agg["sha256"]
                if local is not None
                else None,
            }
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate")
    boot = sub.add_parser("bootstrap")
    boot.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    boot.add_argument("--actor", default="migration-20260828")
    exp = sub.add_parser("export")
    exp.add_argument("--out", type=Path, default=DEFAULT_LEDGER)
    exp.add_argument("--force", action="store_true")
    exp_inc = sub.add_parser("export-incremental")
    exp_inc.add_argument("--out", type=Path, default=DEFAULT_LEDGER)
    exp_inc.add_argument("--force", action="store_true")
    hist_export = sub.add_parser("export-history")
    hist_export.add_argument("--out", type=Path, default=DEFAULT_HISTORY)
    hist_export.add_argument("--force", action="store_true")
    get = sub.add_parser("get")
    get.add_argument("class_id")
    patch = sub.add_parser("apply")
    patch.add_argument("file", type=Path)
    patch.add_argument("--actor", required=True)
    patch.add_argument("--description", required=True)
    finalize = sub.add_parser("finalize")
    finalize.add_argument("file", type=Path)
    finalize.add_argument("--actor", required=True)
    finalize.add_argument("--description", required=True)
    run = sub.add_parser("run-start")
    run.add_argument("--run-id")
    run.add_argument("--model-provider", required=True)
    run.add_argument("--model-name", required=True)
    run.add_argument("--model-version", required=True)
    run.add_argument("--prompt-file", type=Path, required=True)
    run.add_argument("--scanner-version", required=True)
    run.add_argument("--actor", required=True)
    run.add_argument("--metadata-json", default="{}")
    done = sub.add_parser("run-complete")
    done.add_argument("run_id")
    assessment = sub.add_parser("assessment-add")
    assessment.add_argument("file", type=Path)
    history = sub.add_parser("history")
    history.add_argument("class_id")
    verify = sub.add_parser("check")
    verify.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "migrate":
        migrate()
    elif args.command == "bootstrap":
        bootstrap(args.ledger, args.actor)
    elif args.command == "export":
        export_jsonl(args.out, force=args.force)
    elif args.command == "export-incremental":
        export_jsonl_incremental(args.out, force=args.force)
    elif args.command == "export-history":
        export_history(args.out, force=args.force)
    elif args.command == "get":
        get_row(args.class_id)
    elif args.command == "apply":
        apply_updates(args.file, args.actor, args.description)
    elif args.command == "finalize":
        apply_updates(
            args.file,
            args.actor,
            args.description,
            require_assessments=True,
        )
    elif args.command == "run-start":
        start_run(args)
    elif args.command == "run-complete":
        complete_run(args.run_id)
    elif args.command == "assessment-add":
        add_assessments(args.file)
    elif args.command == "history":
        case_history(args.class_id)
    elif args.command == "check":
        check(args.ledger)
    return 0


if __name__ == "__main__":
    sys.exit(main())
