"""Write the published web data artifacts in the per-CVE layout.

On-disk layout under ``web/data/``::

    index.json       {"generated_at", "total", "ids": [...]} — manifest, ids in display order
    cves/<ID>.json   one CveEntry per file
    stats.json       aggregate statistics

Why per-CVE files instead of one monolithic ``cves.json``: the single file
was fully rewritten on every run (new ``generated_at`` plus any content
churn), so an incremental update of a handful of CVEs produced an
unreviewable thousand-line diff. One file per CVE makes data PRs
reviewable — added/removed CVEs appear as added/deleted files, and field
changes show up as small focused diffs inside the affected entry only.

Every file is validated against ``web_data.schema`` before it is written,
and writes are atomic (temp file + rename) so a failed run never leaves a
half-written artifact. Stale per-CVE files (entries that disappeared from
the dataset) and a legacy monolithic ``cves.json`` are removed.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from web_data.schema import (
    validate_cve_entry,
    validate_index_payload,
    validate_stats_payload,
)

#: Legacy monolithic artifact superseded by the per-CVE layout.
_LEGACY_CVES_JSON = "cves.json"


@dataclass
class WriteResult:
    """Summary of one write run, for the orchestrator's report."""

    index_path: Path
    stats_path: Path
    cves_dir: Path
    written: int
    removed_stale: int
    removed_legacy: bool


def _atomic_write_json(path: Path, payload: dict) -> None:
    """Write ``payload`` as JSON via a temp file + rename (never partial)."""
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path)


def write_web_data(
    entries: list[dict],
    stats: dict,
    output_dir: Path,
    *,
    generated_at: str,
) -> WriteResult:
    """Validate and write all published artifacts to ``output_dir``.

    ``entries`` must already be in final display order; the index manifest
    records that order. Raises SchemaValidationError before touching the
    filesystem if any entry, the index, or the stats payload drifts from
    the published contract.
    """
    # 1. Validate everything up front — no writes on a drifting payload.
    for entry in entries:
        validate_cve_entry(entry)
    index = {
        "generated_at": generated_at,
        "total": len(entries),
        "ids": [entry["id"] for entry in entries],
    }
    validate_index_payload(index)
    validate_stats_payload(stats)

    # 2. Write per-CVE files.
    cves_dir = output_dir / "cves"
    cves_dir.mkdir(parents=True, exist_ok=True)
    current_filenames: set[str] = set()
    for entry in entries:
        filename = f"{entry['id']}.json"
        current_filenames.add(filename)
        _atomic_write_json(cves_dir / filename, entry)

    # 3. Remove stale per-CVE files (entries that left the dataset).
    removed_stale = 0
    for existing in cves_dir.glob("*.json"):
        if existing.name not in current_filenames:
            existing.unlink()
            removed_stale += 1

    # 4. Write the manifest and stats.
    index_path = output_dir / "index.json"
    _atomic_write_json(index_path, index)
    stats_path = output_dir / "stats.json"
    _atomic_write_json(stats_path, stats)

    # 5. Remove the legacy monolith so the two layouts never coexist.
    removed_legacy = False
    legacy_path = output_dir / _LEGACY_CVES_JSON
    if legacy_path.exists():
        legacy_path.unlink()
        removed_legacy = True

    return WriteResult(
        index_path=index_path,
        stats_path=stats_path,
        cves_dir=cves_dir,
        written=len(entries),
        removed_stale=removed_stale,
        removed_legacy=removed_legacy,
    )
