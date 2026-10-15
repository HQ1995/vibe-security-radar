#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from audit_envelope import violations

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
DEFAULT_HISTORY = ROOT / "artifacts/ledger-history"
EXPORT_MARKER_NAME = ".funnel-export-marker.json"
SCHEMA = ROOT / "scripts/ledger_schema.sql"
ENV_FILE = ROOT / ".env.local"
AI_STATUSES = {"AI_ROOT_CAUSE", "AI_CODE_FLAWED"}
TERMINAL_STATUSES = AI_STATUSES | {"NOT_AI", "BLOCKED", "FALSE_POSITIVE"}
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


def connect(*, direct: bool = False, write: bool = False):
    load_env()
    prefix = "DATABASE_URL_OWNER" if write else "DATABASE_URL"
    pooled = os.environ.get(prefix)
    unpooled = os.environ.get(prefix + "_UNPOOLED")
    url = unpooled if direct else pooled or unpooled
    if not url:
        kind = "owner" if write else "read-only"
        raise SystemExit(f"{prefix} (write={write}) is required for a {kind} connection")
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
    with connect(direct=True, write=True) as conn:
        conn.execute(SCHEMA.read_text(encoding="utf-8"))
    print("ledger schema is current")


def bootstrap(path: Path, actor: str) -> None:
    from psycopg.types.json import Jsonb

    records = read_jsonl(path)
    change_set = f"bootstrap-{uuid.uuid4()}"
    with connect(direct=True, write=True) as conn:
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
    with connect() as conn:
        return conn.execute(SNAPSHOT_SHA256_SQL).fetchone()[0]


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
    return {row["class_id"]: (line, row) for line, row in read_jsonl(path)}


def _write_jsonl_map(path: Path, records: dict[str, tuple[str, dict]]) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        for raw, _row in records.values():
            handle.write(raw if raw.endswith(chr(10)) else raw + chr(10))
    os.replace(tmp, path)


def export_jsonl_incremental(path: Path, *, force: bool = False) -> bool:
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
        if require_assessments and item["row"].get("status") in TERMINAL_STATUSES:
            accepted = item["row"].get("causal_research")
            if not isinstance(accepted, dict) or not accepted:
                raise SystemExit(f"{path}:{number}: finalize requires causal_research")
            if accepted.get("verdict") != item["row"]["status"]:
                raise SystemExit(f"{path}:{number}: causal_research verdict must match status")
    if len(set(class_ids)) != len(class_ids):
        raise SystemExit(f"{path}: duplicate class_id patch")
    return sorted(patches, key=lambda item: item["row"]["class_id"])


PUBLIC_INTAKE_ID = re.compile(
    r"(?:CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2})$",
    re.I,
)


def intake_public_ids(row: dict) -> set[str]:
    values = list(row.get("advisory_ids") or [])
    values.extend(row.get("advisory_aliases") or [])
    values.extend((row.get("advisory_identity") or {}).get("member_ids") or [])
    result = set()
    for value in values:
        value = value.get("id") if isinstance(value, dict) else value
        if isinstance(value, str) and PUBLIC_INTAKE_ID.fullmatch(value):
            result.add(value.upper())
    return result


def intake_class_id(ids: set[str]) -> str:
    normalized = sorted("GHSA-" + x[5:].lower() if x.startswith("GHSA-") else x
                        for x in ids)
    return "alias-" + sha256("\n".join(normalized) + "\n")[:24]


def validate_intake_row(row: dict, files: dict) -> None:
    cid = row.get("class_id")
    if not isinstance(cid, str) or not re.fullmatch(r"alias-[0-9a-f]{24}", cid):
        raise ValueError("intake class_id must be alias- followed by 24 lowercase hex digits")
    if row.get("status") != "UNANALYZED":
        raise ValueError(f"{cid}: intake accepts UNANALYZED only")
    ids = row.get("advisory_ids")
    if (not isinstance(ids, list) or not ids
            or any(not isinstance(v, str) or not PUBLIC_INTAKE_ID.fullmatch(v) for v in ids)
            or len({v.upper() for v in ids}) != len(ids)):
        raise ValueError(f"{cid}: advisory_ids must contain unique explicit CVE/GHSA IDs")
    known = intake_public_ids(row)
    provenance = row.get("source_intake")
    if not isinstance(provenance, dict):
        raise ValueError(f"{cid}: source_intake object required")
    window = provenance.get("window")
    try:
        dates = [re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.([0-9]+))?(?:[Zz]|[+-]00:00)", window[k]) for k in ("start", "end")]
        if any(match is None or len((match[1] or "").rstrip("0")) > 6 for match in dates):
            raise ValueError
        start, end = [datetime.fromisoformat(match[0].upper().replace("Z", "+00:00"))
                      for match in dates]
        if (start.tzinfo is None or end.tzinfo is None or start >= end
                or start.utcoffset().total_seconds() or end.utcoffset().total_seconds()):
            raise ValueError
    except (TypeError, KeyError, AttributeError, ValueError):
        raise ValueError(f"{cid}: source_intake.window requires ordered UTC start/end") from None
    if not re.fullmatch(r"[0-9a-f]{64}", str(provenance.get("delta_sha256", ""))):
        raise ValueError(f"{cid}: source_intake.delta_sha256 required")
    mapping = provenance.get("repository_mapping")
    if (not isinstance(mapping, dict) or not isinstance(row.get("repo"), str)
            or not row["repo"].strip() or mapping.get("repository") != row["repo"]
            or not isinstance(mapping.get("basis"), str) or not mapping["basis"].strip()):
        raise ValueError(f"{cid}: repository_mapping requires exact repository and nonempty basis")
    records = provenance.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError(f"{cid}: source_intake.records must be nonempty")

    def read_file(path):
        if not isinstance(path, str) or not path:
            raise ValueError(f"{cid}: source path required")
        if path not in files:
            files[path] = Path(path).read_bytes()
        return files[path]

    source_public_ids = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError(f"{cid}: source record object required")
        pointer = record.get("pointer")
        if (not isinstance(pointer, str) or not pointer.startswith("/")
                or re.search(r"~(?![01])", pointer)):
            raise ValueError(f"{cid}: source record JSON pointer required")
        if not re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256", ""))):
            raise ValueError(f"{cid}: source record sha256 required")
        path = record.get("path")
        raw = read_file(path)
        parsed_key = ("json", path)
        if parsed_key not in files:
            files[parsed_key] = json.loads(raw)
        value = files[parsed_key]
        try:
            for part in pointer[1:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                if isinstance(value, list):
                    if not re.fullmatch(r"0|[1-9]\d*", part):
                        raise ValueError
                    value = value[int(part)]
                else:
                    value = value[part]
        except (KeyError, IndexError, TypeError, ValueError):
            raise ValueError(f"{cid}: source pointer does not resolve: {pointer}") from None
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if sha256(canonical) != record["sha256"]:
            raise ValueError(f"{cid}: source object hash mismatch")
        if not isinstance(value, dict):
            raise ValueError(f"{cid}: source pointer must select an advisory object")
        if "ghsa_id" in value:
            if value.get("id") is not None:
                raise ValueError(f"{cid}: mixed GitHub and other source identity fields")
            for field, kind in (("ghsa_id", "GHSA"), ("cve_id", "CVE")):
                ident = value.get(field)
                if field == "cve_id" and ident is None:
                    continue
                if (not isinstance(ident, str) or not PUBLIC_INTAKE_ID.fullmatch(ident)
                        or not ident.upper().startswith(kind + "-")):
                    raise ValueError(f"{cid}: source {field} type/value mismatch")
            source_ids = [value["ghsa_id"], value.get("cve_id")]
        else:
            source_ids = [value.get("id"), value.get("cve_id")]
        identifiers = value.get("identifiers")
        identifiers = [] if identifiers is None else identifiers
        if not isinstance(identifiers, list):
            raise ValueError(f"{cid}: source identifiers must be a nullable array")
        for identifier in identifiers:
            ident = identifier.get("value") if isinstance(identifier, dict) else None
            if not isinstance(ident, str) or not PUBLIC_INTAKE_ID.fullmatch(ident):
                raise ValueError(f"{cid}: invalid source identifier")
            if "ghsa_id" in value:
                kind = identifier.get("type")
                if (kind not in ("CVE", "GHSA") or not ident.upper().startswith(kind + "-")
                        or (kind == "GHSA" and ident.upper() != str(value["ghsa_id"]).upper())):
                    raise ValueError(f"{cid}: source identifier type/value mismatch")
            source_ids.append(ident)
        source_ids = {v.upper() for v in source_ids
                      if isinstance(v, str) and PUBLIC_INTAKE_ID.fullmatch(v)}
        if not source_ids or not source_ids <= known:
            raise ValueError(f"{cid}: source advisory IDs missing from intake identity")
        source_public_ids.update(source_ids)

    prior_ids = set()
    if cid != intake_class_id(known) or not known <= source_public_ids:
        prior = provenance.get("prior_identity")
        if not isinstance(prior, dict) or type(prior.get("line")) is not int or prior["line"] < 1:
            raise ValueError(f"{cid}: non-derived class_id needs pinned prior_identity")
        content = read_file(prior.get("path"))
        if sha256(content) != prior.get("sha256"):
            raise ValueError(f"{cid}: prior identity file hash mismatch")
        try:
            previous = json.loads(content.splitlines()[prior["line"] - 1])
            prior_ids = intake_public_ids({
                "advisory_ids": previous.get("public_ids", previous.get("advisory_ids", [])),
                "advisory_aliases": [*previous.get("extra_aliases", []),
                                    *previous.get("ghsa_ids", []),
                                    *previous.get("advisory_aliases", [])],
                "advisory_identity": previous.get("advisory_identity", {}),
            })
        except (IndexError, TypeError, AttributeError):
            raise ValueError(f"{cid}: prior identity line is invalid") from None
        if previous.get("class_id") != cid or not prior_ids or not prior_ids <= known:
            raise ValueError(f"{cid}: prior identity does not justify this class/ID set")
    if not known <= source_public_ids | prior_ids:
        raise ValueError(f"{cid}: identity IDs not covered by source objects or pinned prior identity")


def foreign_active_claims(class_ids: set[str], actor: str, *, path: Path | None = None) -> list[dict]:
    import claims as claims_mod

    current = claims_mod.state(claims_mod.load(path or claims_mod.DEFAULT_CLAIMS))
    protected = {value.casefold() for value in class_ids}
    return [
        {
            "class_id": class_id,
            "slot": cur["slot"],
            "owner": cur["owner"],
            "lease_until": cur["lease_until"],
        }
        for (class_id, _slot), cur in sorted(current.items())
        if class_id.casefold() in protected and cur["claimed"] and cur.get("owner") != actor
    ]


def intake(path: Path, actor: str, description: str) -> dict:
    from psycopg.types.json import Jsonb

    if not actor.strip() or not description.strip():
        raise ValueError("intake actor and description must be nonempty")
    rows = read_objects(path)
    if not rows:
        raise ValueError("intake file is empty")
    files = {}
    for row in rows:
        validate_intake_row(row, files)
    class_ids = {row["class_id"] for row in rows}
    if len(class_ids) != len(rows):
        raise ValueError("duplicate class_id in intake")
    rows.sort(key=lambda row: row["class_id"])
    protected_ids = class_ids | {ident for row in rows for ident in intake_public_ids(row)}
    blockers = foreign_active_claims(protected_ids, actor)
    if blockers:
        raise ValueError("foreign active claims block intake: " + json.dumps(blockers, sort_keys=True))
    change_set = None
    inserted, skipped = [], []
    with connect(write=True) as conn:
        conn.execute("LOCK TABLE ledger_rows IN SHARE ROW EXCLUSIVE MODE")
        blockers = foreign_active_claims(protected_ids, actor)
        if blockers:
            raise ValueError("foreign active claims block intake: " + json.dumps(blockers, sort_keys=True))
        snapshot = DEFAULT_LEDGER.read_bytes()
        current_digest = conn.execute(SNAPSHOT_SHA256_SQL).fetchone()[0]
        if sha256(snapshot) != current_digest:
            raise ValueError("local ledger export does not match locked database snapshot; refresh export before intake")
        existing = {}
        owners = defaultdict(set)
        for line in snapshot.splitlines():
            if not line.strip():
                continue
            saved = json.loads(line)
            cid = saved["class_id"]
            if cid in existing:
                raise ValueError(f"duplicate class_id in verified export: {cid}")
            existing[cid] = saved
            for ident in intake_public_ids(saved):
                owners[ident].add(cid)
        next_ordinal = conn.execute(
            "SELECT COALESCE(MAX(ordinal), -1) + 1 FROM ledger_rows"
        ).fetchone()[0]
        pending = []
        for row in rows:
            cid = row["class_id"]
            for ident in sorted(intake_public_ids(row)):
                if owners[ident] - {cid}:
                    raise ValueError(f"advisory ID overlap: {ident} already belongs to {sorted(owners[ident])}")
                owners[ident].add(cid)
            if cid in existing:
                if existing[cid] != row:
                    raise ValueError(f"existing class_id has different payload: {cid}")
                skipped.append(cid)
            else:
                pending.append(row)
        if pending:
            change_set = str(uuid.uuid4())
            conn.execute("""
                INSERT INTO ledger_change_sets(change_set_id, actor, description)
                VALUES (%s, %s, %s)
            """, (change_set, actor, description))
            with conn.cursor() as cursor:
                for start in range(0, len(pending), 500):
                    batch = pending[start:start + 500]
                    encoded = [(row, raw_row(row)) for row in batch]
                    cursor.executemany("""
                        INSERT INTO ledger_rows(
                            class_id, ordinal, status, repo, advisory_ids, raw_json,
                            revision, change_set_id, updated_by
                        ) VALUES (%s, %s, %s, %s, %s, %s, 1, %s, %s)
                    """, [(row["class_id"], next_ordinal + start + offset, row["status"],
                           row["repo"], Jsonb(row["advisory_ids"]), raw, change_set, actor)
                          for offset, (row, raw) in enumerate(encoded)])
                    cursor.executemany("""
                        INSERT INTO ledger_versions(
                            class_id, revision, change_set_id, operation, raw_json, checksum, actor
                        ) VALUES (%s, 1, %s, 'IMPORT', %s, %s, %s)
                    """, [(row["class_id"], change_set, raw, sha256(raw), actor)
                          for row, raw in encoded])
            conn.execute("UPDATE ledger_change_sets SET committed_at = now() WHERE change_set_id = %s",
                         (change_set,))
            inserted = [row["class_id"] for row in pending]
    result = {"change_set_id": change_set, "inserted": inserted, "skipped_exact": skipped}
    print(json.dumps(result, sort_keys=True))
    export_jsonl_incremental(DEFAULT_LEDGER)
    return result


def apply_updates(
    path: Path,
    actor: str,
    description: str,
    *,
    require_assessments: bool = False,
) -> None:
    from psycopg.types.json import Jsonb

    patches = read_patches(path, require_assessments=require_assessments)
    blockers = foreign_active_claims({item["row"]["class_id"] for item in patches}, actor)
    if blockers:
        detail = "; ".join(
            f"{item['class_id']} slot {item['slot']} held by {item['owner']} until {item['lease_until']}"
            for item in blockers
        )
        raise SystemExit(
            f"claims block this write: {detail}"
            " (the holder must release the exact claim; expiry does not release occupancy)"
        )
    change_set = str(uuid.uuid4())
    all_assessments = sorted(
        {assessment for item in patches for assessment in item.get("assessment_ids", [])}
    )
    with connect(write=True) as conn:
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
    with connect(write=True) as conn:
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
    with connect(write=True) as conn:
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
    skipped = []
    with connect(write=True) as conn:
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
            stored = conn.execute(
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
                ON CONFLICT (assessment_id) DO NOTHING
                RETURNING assessment_id
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
            ).fetchone()
            if stored is None:
                skipped.append(assessment_id)
            else:
                inserted.append(assessment_id)
    print(json.dumps({"inserted": inserted, "skipped": skipped}))


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
    ingest = sub.add_parser("intake")
    ingest.add_argument("file", type=Path)
    ingest.add_argument("--actor", required=True)
    ingest.add_argument("--description", required=True)
    exp = sub.add_parser("export")
    exp.add_argument("--out", type=Path, default=DEFAULT_LEDGER)
    exp.add_argument("--force", action="store_true")
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
    elif args.command == "intake":
        intake(args.file, args.actor, args.description)
    elif args.command == "export":
        export_jsonl(args.out, force=args.force)
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
