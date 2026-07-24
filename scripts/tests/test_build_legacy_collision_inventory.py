from __future__ import annotations

import json
from pathlib import Path

import build_legacy_collision_inventory as builder


def _manifest(path: Path, repositories: list[str]) -> Path:
    payload = {
        "schema_version": 3,
        "inputs": {"population_policy": "formal_full"},
        "mapping": {"unique_normalized_repos": len(set(repositories))},
        "verification": {
            "all_remaining_ids_exactly_once": True,
            "alias_classes_exactly_once": True,
        },
        "batches": [{"repos": repositories}],
    }
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    return path


def test_inventory_records_cross_host_legacy_collisions_deterministically(
    tmp_path: Path,
) -> None:
    manifest = _manifest(
        tmp_path / "manifest.json",
        ["github.com/example/project", "gitlab.com/example/project"],
    )

    inventory, summary = builder.build_inventory(
        manifest, cache_root=tmp_path / "repos"
    )

    lines = inventory.decode().splitlines()
    assert len(lines) == 2
    assert all("legacy-origin-collision:" in line for line in lines)
    assert all("v2_" in line.split("\t")[1] for line in lines)
    assert summary["repository_count"] == 2
    assert summary["collision_path_count"] == 1
    assert summary["collision_repository_count"] == 2
    assert summary["inventory_line_count"] == 2


def test_inventory_is_empty_when_legacy_names_are_unique(tmp_path: Path) -> None:
    manifest = _manifest(
        tmp_path / "manifest.json",
        ["github.com/example/one", "gitlab.com/example/two"],
    )

    inventory, summary = builder.build_inventory(
        manifest, cache_root=tmp_path / "repos"
    )

    assert inventory == b""
    assert summary["collision_path_count"] == 0
    assert summary["inventory_line_count"] == 0
