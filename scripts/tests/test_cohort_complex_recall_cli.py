"""CLI boundary tests for the complex-causality recall gate."""

from __future__ import annotations

import json

import cohort_complex_recall as cli


TARGET = "github.com/example/target"
UPSTREAM = "github.com/example/upstream"
ORIGIN = "1" * 40
IMPORT = "2" * 40
FIX = "3" * 40


def _write_jsonl(path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_cli_requires_target_and_upstream_obligations(tmp_path) -> None:
    relation_dir = tmp_path / "relation"
    candidate_dir = tmp_path / "candidate"
    cross_dir = tmp_path / "cross"
    relation_dir.mkdir()
    candidate_dir.mkdir()
    cross_dir.mkdir()
    controls = tmp_path / "controls.json"
    aliases = tmp_path / "aliases.json"
    output = tmp_path / "recall.json"
    controls.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "controls": [
                    {
                        "advisory": "CVE-TEST-CROSS",
                        "dimensions": ["CROSS_REPOSITORY_ORIGIN"],
                        "source": "audit/cross.json",
                        "source_sha256": "a" * 64,
                        "target_repository_identity": TARGET,
                        "target_edges": [
                            {
                                "candidate_sha": IMPORT,
                                "fix_sha": FIX,
                                "expected_relation": "reachable_ancestor",
                            }
                        ],
                        "upstream_imports": [
                            {
                                "origin_repository_identity": UPSTREAM,
                                "origin_sha": ORIGIN,
                                "import_sha": IMPORT,
                                "expected_relation": (
                                    "declared_cross_repository_import"
                                ),
                            }
                        ],
                        "public_fixes": [FIX],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    aliases.write_text(
        json.dumps({"schema_version": 1, "aliases": []}),
        encoding="utf-8",
    )
    _write_jsonl(
        relation_dir / "candidates_expanded.jsonl",
        [
            {
                "edge_id": "edge-1",
                "repository_identity": TARGET,
                "candidate_sha": IMPORT,
                "fix_sha": FIX,
                "relation": "reachable_ancestor",
            }
        ],
    )
    _write_jsonl(
        cross_dir / "relations.jsonl",
        [
            {
                "relation_id": "relation-1",
                "origin_repository_identity": UPSTREAM,
                "origin_sha": ORIGIN,
                "target_repository_identity": TARGET,
                "import_sha": IMPORT,
                "relation": "declared_cross_repository_import",
            }
        ],
    )
    _write_jsonl(
        candidate_dir / "public_fix_references.jsonl",
        [
            {
                "repository_identity": TARGET,
                "advisory": "CVE-TEST-CROSS",
                "fix_sha": FIX,
            }
        ],
    )

    exit_code = cli.main(
        [
            "--relation-dir",
            str(relation_dir),
            "--candidate-dir",
            str(candidate_dir),
            "--cross-dir",
            str(cross_dir),
            "--controls",
            str(controls),
            "--repository-aliases",
            str(aliases),
            "--output",
            str(output),
        ]
    )

    result = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert result["target_obligation_pass_count"] == 1
    assert result["upstream_obligation_pass_count"] == 1
    assert result["relation_gate_passed"] is True
