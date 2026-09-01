#!/usr/bin/env python3
"""Build the effective publication corpus from base and fp211 adjudications."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import date
from pathlib import Path
from typing import Any

from cohort.publication_admission import evaluate_publication_admission


_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
_FP211_DIR = _REPO_ROOT / "research" / "orchestrator-260813-fp211-audit"
_DEFAULT_BASE = _SCRIPT_DIR / "audit_adjudications.json"
_DEFAULT_FINAL = _FP211_DIR / "final_mechanisms.jsonl"
_DEFAULT_MANIFEST = _FP211_DIR / "manifest.jsonl"
_DEFAULT_PUBLIC_CASES = _FP211_DIR / "public_cases.jsonl"
_DEFAULT_SUPERSESSIONS = _SCRIPT_DIR / "publication-adjudication-supersessions.json"
_DEFAULT_OUTPUT = _SCRIPT_DIR / "publication_adjudications.json"
_HELPER = _SCRIPT_DIR / "cohort" / "publication_admission.py"
_ALLOWED_LABELS = frozenset({"AI_CAUSAL", "NOT_AI_CAUSAL", "INCONCLUSIVE"})
_DECISIVE_NONCAUSAL_GATES = (
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
)


def verify_committed(output: Path) -> int:
    """Verify the committed publication corpus without reading research/ sources.

    The drift guard is the input_sha256 manifest recorded inside the committed
    artifact, not a live re-computation against git-tracked research/ files.
    Publication data lives in the DB/generated artifacts; research dumps are no
    longer a deploy-time input. This is the deploy-time gate.
    """

    try:
        payload = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print("publication adjudications unreadable: " + str(exc))
        return 2
    errors = []
    if not isinstance(payload, dict):
        errors.append("payload is not an object")
    if payload.get("schema_version") != 1:
        errors.append("schema_version != 1")
    rows = payload.get("adjudications")
    if not isinstance(rows, list) or not rows:
        errors.append("adjudications is not a non-empty array")
    else:
        bad_labels = []
        missing_ids = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if row.get("label") not in _ALLOWED_LABELS:
                bad_labels.append(row.get("label"))
            if not row.get("cve_id"):
                missing_ids.append(row.get("cve_id"))
        if bad_labels:
            errors.append("invalid labels: " + repr(sorted(set(bad_labels))[:10]))
        if missing_ids:
            errors.append(str(len(missing_ids)) + " rows missing cve_id")
    manifest = (payload.get("provenance") or {}).get("input_sha256") or {}
    for required in (
        "research/orchestrator-260813-fp211-audit/final_mechanisms.jsonl",
        "research/orchestrator-260813-fp211-audit/manifest.jsonl",
        "research/orchestrator-260813-fp211-audit/public_cases.jsonl",
    ):
        if not manifest.get(required):
            errors.append("input_sha256 missing " + required)
    if errors:
        print("publication adjudications failed closed: " + "; ".join(errors[:8]))
        return 2
    print(
        "publication adjudications verified (committed artifact, "
        + str(len(rows))
        + " rows): "
        + str(output)
    )
    return 0


class PublicationCorpusError(RuntimeError):
    """An input cannot safely produce the effective publication corpus."""


def _jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PublicationCorpusError(
                f"malformed JSONL row {path}:{line_number}: {exc}"
            ) from exc
        if not isinstance(row, dict):
            raise PublicationCorpusError(
                f"JSONL row must be an object: {path}:{line_number}"
            )
        rows.append(row)
    if not rows:
        raise PublicationCorpusError(f"JSONL input is empty: {path}")
    return rows


def _subjects(row: Mapping[str, object], *, canonical_field: str) -> set[str]:
    canonical = row.get(canonical_field)
    aliases = row.get("aliases", [])
    if (
        not isinstance(canonical, str)
        or not canonical.strip()
        or not isinstance(aliases, list)
        or any(not isinstance(alias, str) or not alias.strip() for alias in aliases)
    ):
        raise PublicationCorpusError(f"invalid public identity in {canonical!r}")
    values = [canonical, *aliases]
    normalized = {value.upper() for value in values}
    if len(normalized) != len(values):
        raise PublicationCorpusError(f"duplicate public identity in {canonical}")
    return normalized


def _rows_by_ordinal(
    rows: list[dict[str, Any]], source: str
) -> dict[int, dict[str, Any]]:
    indexed: dict[int, dict[str, Any]] = {}
    for row in rows:
        ordinal = row.get("ordinal")
        row_key = row.get("row_key")
        if (
            isinstance(ordinal, bool)
            or not isinstance(ordinal, int)
            or ordinal < 1
            or not isinstance(row_key, str)
            or not row_key
            or ordinal in indexed
        ):
            raise PublicationCorpusError(
                f"invalid or duplicate {source} ordinal: {ordinal!r}"
            )
        indexed[ordinal] = row
    return indexed


def _label(final: Mapping[str, object], admission: Mapping[str, object]) -> str:
    if admission.get("may_publish") is True:
        return "AI_CAUSAL"
    if final.get("verdict") == "FALSE_POSITIVE" and any(
        final.get(field) == "FAIL" for field in _DECISIVE_NONCAUSAL_GATES
    ):
        return "NOT_AI_CAUSAL"
    return "INCONCLUSIVE"


def _supersession_rows(payload: object) -> list[dict[str, Any]]:
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 1
        or payload.get("artifact_kind")
        != "publication_adjudication_supersessions"
    ):
        raise PublicationCorpusError(
            "publication supersessions require schema_version 1"
        )
    rows = payload.get("supersessions")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise PublicationCorpusError("publication supersessions must be an object array")
    return rows


def _apply_supersessions(
    adjudications: list[dict[str, Any]],
    payload: object,
    *,
    input_hashes: Mapping[str, str],
) -> list[dict[str, Any]]:
    """Replace a prior label only when the complete public identity collides."""

    rows = [deepcopy(row) for row in adjudications]
    subjects_by_index = [
        _subjects(row, canonical_field="cve_id") for row in rows
    ]
    superseded_indices: set[int] = set()
    for override in _supersession_rows(payload):
        subjects = _subjects(override, canonical_field="cve_id")
        collisions = [
            index
            for index, existing_subjects in enumerate(subjects_by_index)
            if subjects & existing_subjects
        ]
        if len(collisions) != 1:
            raise PublicationCorpusError(
                f"supersession must collide with exactly one identity: "
                f"{override.get('cve_id')!r}"
            )
        index = collisions[0]
        previous = rows[index]
        if (
            index in superseded_indices
            or subjects != subjects_by_index[index]
            or str(override.get("cve_id", "")).upper()
            != str(previous.get("cve_id", "")).upper()
        ):
            raise PublicationCorpusError(
                f"supersession identity must exactly match the prior row: "
                f"{override.get('cve_id')!r}"
            )
        label = override.get("label")
        source = override.get("source")
        audited = override.get("audited")
        reason = override.get("reason")
        supersedes = override.get("supersedes")
        if label not in _ALLOWED_LABELS or label == previous.get("label"):
            raise PublicationCorpusError(
                f"invalid supersession label for {override.get('cve_id')}"
            )
        if (
            not isinstance(source, str)
            or not source
            or source == previous.get("source")
            or source not in input_hashes
        ):
            raise PublicationCorpusError(
                f"supersession source is not hashed for {override.get('cve_id')}"
            )
        try:
            if (
                not isinstance(audited, str)
                or date.fromisoformat(audited).isoformat() != audited
            ):
                raise ValueError
        except ValueError as exc:
            raise PublicationCorpusError(
                f"invalid supersession audit date for {override.get('cve_id')}"
            ) from exc
        if not isinstance(reason, str) or len(reason.strip()) < 24:
            raise PublicationCorpusError(
                f"supersession reason is too short for {override.get('cve_id')}"
            )
        if (
            not isinstance(supersedes, dict)
            or supersedes.get("label") != previous.get("label")
            or supersedes.get("source") != previous.get("source")
        ):
            raise PublicationCorpusError(
                f"supersession does not name the prior decision for "
                f"{override.get('cve_id')}"
            )

        prior = {
            key: previous[key]
            for key in ("label", "source", "audited", "confidence")
            if key in previous
        }
        previous["label"] = label
        previous["source"] = source
        previous["audited"] = audited
        previous["supersession"] = {
            "reason": reason.strip(),
            "superseded": prior,
        }
        superseded_indices.add(index)
    return rows


def build_publication_corpus(
    base_payload: object,
    final_rows: list[dict[str, Any]],
    manifest_rows: list[dict[str, Any]],
    public_cases: list[dict[str, Any]],
    supersessions_payload: object,
    *,
    input_hashes: Mapping[str, str],
) -> dict[str, Any]:
    """Overlay every fp211 public case while retaining non-overlapping base rows."""

    if not isinstance(base_payload, dict) or base_payload.get("schema_version") != 1:
        raise PublicationCorpusError("base adjudications require schema_version 1")
    base_rows = base_payload.get("adjudications")
    if not isinstance(base_rows, list) or any(
        not isinstance(row, dict) for row in base_rows
    ):
        raise PublicationCorpusError("base adjudications must contain an object array")

    final_by_ordinal = _rows_by_ordinal(final_rows, "final mechanism")
    manifest_by_ordinal = _rows_by_ordinal(manifest_rows, "manifest")
    if set(final_by_ordinal) != set(manifest_by_ordinal):
        raise PublicationCorpusError(
            "fp211 final mechanisms and manifest do not join exactly"
        )
    for ordinal, final in final_by_ordinal.items():
        manifest = manifest_by_ordinal[ordinal]
        if final["row_key"] != manifest["row_key"]:
            raise PublicationCorpusError(f"fp211 row_key mismatch at ordinal {ordinal}")

    cases_by_ordinal: dict[int, list[dict[str, Any]]] = {}
    fp_case_subjects: set[str] = set()
    case_ids: set[str] = set()
    for case in public_cases:
        ordinal = case.get("ordinal")
        case_id = case.get("case_id")
        if not isinstance(ordinal, int) or ordinal not in final_by_ordinal:
            raise PublicationCorpusError(
                f"public case has unknown ordinal: {ordinal!r}"
            )
        final = final_by_ordinal[ordinal]
        manifest = manifest_by_ordinal[ordinal]
        if case.get("row_key") != final["row_key"]:
            raise PublicationCorpusError(
                f"public case row_key mismatch at ordinal {ordinal}"
            )
        for field, expected in (
            ("verdict", final.get("verdict")),
            ("confidence", final.get("confidence")),
            ("causal_class", final.get("causal_class")),
            ("source_tier", manifest.get("source_tier")),
        ):
            if case.get(field) != expected:
                raise PublicationCorpusError(
                    f"public case {field} mismatch at ordinal {ordinal}"
                )
        subjects = _subjects(case, canonical_field="case_id")
        if (
            fp_case_subjects & subjects
            or not isinstance(case_id, str)
            or case_id in case_ids
        ):
            raise PublicationCorpusError(
                f"duplicate fp211 public case identity: {case_id!r}"
            )
        fp_case_subjects.update(subjects)
        case_ids.add(case_id)
        cases_by_ordinal.setdefault(ordinal, []).append(case)

    if set(cases_by_ordinal) != set(final_by_ordinal):
        raise PublicationCorpusError("every fp211 mechanism must have a public case")

    removed_ids: set[str] = set()
    fp_source_subjects: set[str] = set()
    admissions: dict[int, dict[str, object]] = {}
    for ordinal, final in final_by_ordinal.items():
        manifest = manifest_by_ordinal[ordinal]
        source_ids = manifest.get("public_ids")
        if not isinstance(source_ids, list):
            raise PublicationCorpusError(
                f"manifest public_ids are invalid at ordinal {ordinal}"
            )
        admission = evaluate_publication_admission(
            final,
            source_public_ids=source_ids,
            source_tier=manifest.get("source_tier"),
        )
        if admission["errors"] or admission["public_ids_conserved"] is not True:
            raise PublicationCorpusError(
                f"fp211 admission is invalid at ordinal {ordinal}: {admission['errors']}"
            )
        for case in cases_by_ordinal[ordinal]:
            if case.get("causal_valid") is not admission["causal_valid"]:
                raise PublicationCorpusError(
                    f"public case admission flags mismatch at ordinal {ordinal}"
                )
        case_subjects = {
            subject
            for case in cases_by_ordinal[ordinal]
            for subject in _subjects(case, canonical_field="case_id")
        }
        kept = {str(value).upper() for value in final["public_ids_keep"]}
        removed = {str(value).upper() for value in final["public_ids_remove"]}
        if case_subjects != kept:
            raise PublicationCorpusError(
                f"public cases do not equal kept IDs at ordinal {ordinal}"
            )
        if fp_source_subjects & (kept | removed):
            raise PublicationCorpusError(
                f"fp211 source public IDs overlap at ordinal {ordinal}"
            )
        fp_source_subjects.update(kept | removed)
        removed_ids.update(removed)
        admissions[ordinal] = admission

    if removed_ids & fp_case_subjects:
        raise PublicationCorpusError(
            "removed fp211 public IDs leaked into public cases"
        )

    preserved_base: list[dict[str, Any]] = []
    replaced_base_count = 0
    base_subjects_seen: set[str] = set()
    for base in base_rows:
        label = base.get("label")
        subjects = _subjects(base, canonical_field="cve_id")
        if label not in _ALLOWED_LABELS:
            raise PublicationCorpusError(f"invalid base label for {base.get('cve_id')}")
        if base_subjects_seen & subjects:
            raise PublicationCorpusError(
                f"overlapping base identity at {base.get('cve_id')}"
            )
        base_subjects_seen.update(subjects)
        if subjects & fp_source_subjects:
            replaced_base_count += 1
        else:
            preserved_base.append(deepcopy(base))

    fp_rows: list[dict[str, Any]] = []
    for case in public_cases:
        ordinal = case["ordinal"]
        final = final_by_ordinal[ordinal]
        manifest = manifest_by_ordinal[ordinal]
        admission = admissions[ordinal]
        fp_rows.append(
            {
                "cve_id": case["case_id"],
                "label": _label(final, admission),
                "aliases": list(case.get("aliases", [])),
                "excluded_aliases": list(final["public_ids_remove"]),
                "source": "research/orchestrator-260813-fp211-audit/final_mechanisms.jsonl",
                "fp211": {
                    "ordinal": ordinal,
                    "row_key": final["row_key"],
                    "verdict": final["verdict"],
                    "confidence": final["confidence"],
                    "source_tier": manifest["source_tier"],
                    "admission": admission["admission"],
                    "reason": admission["reason"],
                    "gates": admission["gates"],
                },
            }
        )

    for row in fp_rows:
        subjects = _subjects(row, canonical_field="cve_id")
        excluded = {value.upper() for value in row["excluded_aliases"]}
        if subjects & excluded:
            raise PublicationCorpusError(
                f"fp211 kept and excluded aliases overlap at {row['cve_id']}"
            )

    adjudications = _apply_supersessions(
        [*preserved_base, *fp_rows],
        supersessions_payload,
        input_hashes=input_hashes,
    )
    labels = Counter(row["label"] for row in adjudications)
    canonical = json.dumps(
        adjudications, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return {
        "schema_version": 1,
        "artifact_kind": "effective_publication_adjudications",
        "publication_ready": False,
        "adjudications": adjudications,
        "summary": {
            "adjudication_count": len(adjudications),
            "labels": dict(sorted(labels.items())),
            "preserved_base_count": len(preserved_base),
            "replaced_base_count": replaced_base_count,
            "fp211_public_case_count": len(fp_rows),
            "fp211_mechanism_count": len(final_rows),
            "supersession_count": len(_supersession_rows(supersessions_payload)),
            "removed_public_ids": sorted(removed_ids),
        },
        "provenance": {
            "algorithm": "base-plus-fp211-public-cases-with-supersessions-v2",
            "builder": "scripts/build_publication_adjudications.py",
            "input_sha256": dict(sorted(input_hashes.items())),
            "adjudications_sha256": hashlib.sha256(canonical).hexdigest(),
        },
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _encoded(payload: object) -> bytes:
    return (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode()


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), 0o644)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=_DEFAULT_BASE)
    parser.add_argument("--final", type=Path, default=_DEFAULT_FINAL)
    parser.add_argument("--manifest", type=Path, default=_DEFAULT_MANIFEST)
    parser.add_argument("--public-cases", type=Path, default=_DEFAULT_PUBLIC_CASES)
    parser.add_argument("--supersessions", type=Path, default=_DEFAULT_SUPERSESSIONS)
    parser.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--verify-committed", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.verify_committed:
        return verify_committed(args.output)
    try:
        supersessions_payload = json.loads(
            args.supersessions.read_text(encoding="utf-8")
        )
        supersession_sources: dict[str, Path] = {}
        for row in _supersession_rows(supersessions_payload):
            source = row.get("source")
            if not isinstance(source, str) or not source:
                raise PublicationCorpusError("supersession source must be repo-relative")
            source_path = Path(source)
            if source_path.is_absolute() or ".." in source_path.parts:
                raise PublicationCorpusError(
                    f"supersession source must be repo-relative: {source!r}"
                )
            resolved = (_REPO_ROOT / source_path).resolve()
            if not resolved.is_relative_to(_REPO_ROOT.resolve()):
                raise PublicationCorpusError(
                    f"supersession source escapes the repository: {source!r}"
                )
            supersession_sources[source] = resolved

        inputs = {
            "scripts/audit_adjudications.json": _sha256(args.base),
            "research/orchestrator-260813-fp211-audit/final_mechanisms.jsonl": _sha256(
                args.final
            ),
            "research/orchestrator-260813-fp211-audit/manifest.jsonl": _sha256(
                args.manifest
            ),
            "research/orchestrator-260813-fp211-audit/public_cases.jsonl": _sha256(
                args.public_cases
            ),
            "scripts/build_publication_adjudications.py": _sha256(Path(__file__)),
            "scripts/cohort/publication_admission.py": _sha256(_HELPER),
            "scripts/publication-adjudication-supersessions.json": _sha256(
                args.supersessions
            ),
            **{
                source: _sha256(path)
                for source, path in sorted(supersession_sources.items())
            },
        }
        artifact = build_publication_corpus(
            json.loads(args.base.read_text(encoding="utf-8")),
            _jsonl(args.final),
            _jsonl(args.manifest),
            _jsonl(args.public_cases),
            supersessions_payload,
            input_hashes=inputs,
        )
        content = _encoded(artifact)
    except (OSError, UnicodeError, json.JSONDecodeError, PublicationCorpusError) as exc:
        print(f"publication adjudications failed closed: {exc}")
        return 2
    if args.check:
        try:
            current = args.output.read_bytes()
        except OSError:
            current = b""
        if current != content:
            print(f"publication adjudications are stale: {args.output}")
            return 2
        print(f"publication adjudications are current: {args.output}")
        return 0
    _atomic_write(args.output, content)
    print(
        f"wrote {len(artifact['adjudications'])} publication adjudications to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
