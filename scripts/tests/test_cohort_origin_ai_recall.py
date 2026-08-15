"""Tests for recall-safe origin AI route comparison."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import cohort_origin_ai_recall as comparison
from cohort.root_adjudication import canonical_sha256


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


def _fixtures(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    generated = tmp_path / "generated"
    candidates = [
        {
            "advisory": "CVE-test",
            "repository_identity": "github.com/example/repo",
            "fix_sha": "f" * 40,
            "sha": sha * 40,
            "priority_rank": rank,
        }
        for rank, sha in enumerate(("a", "b", "c"), start=1)
    ]
    summary = {
        "candidate_rows_sha256": canonical_sha256(candidates),
        "split_id": "test-split",
    }
    _write_jsonl(generated / "candidates.jsonl", candidates)
    _write_json(generated / "summary.json", summary)
    controls = tmp_path / "controls.json"
    _write_json(
        controls,
        {
            "split_id": "test-split",
            "controls": [
                {
                    "advisory": "CVE-test",
                    "repository_identity": "github.com/example/repo",
                    "fix_sha": "f" * 40,
                    "atomic_origin_sha": "b" * 40,
                }
            ],
        },
    )

    def route(name: str, dispositions: tuple[str, str, str]) -> Path:
        directory = tmp_path / name
        rows = [
            {
                "advisory": candidate["advisory"],
                "repository_identity": candidate["repository_identity"],
                "fix_sha": candidate["fix_sha"],
                "candidate_sha": candidate["sha"],
                "input_priority_rank": candidate["priority_rank"],
                "disposition": disposition,
                "causality": "likely" if disposition == "PROMOTE" else "unlikely",
                "retained": True,
            }
            for candidate, disposition in zip(candidates, dispositions, strict=True)
        ]
        _write_jsonl(directory / "routes.jsonl", rows)
        _write_json(
            directory / "spec.json",
            {
                "parent_generation_sha256": canonical_sha256(summary),
                "candidate_inventory_sha256": canonical_sha256(candidates),
            },
        )
        _write_json(
            directory / "execution.json",
            {
                "model": name,
                "reasoning_effort": "low",
                "physical_model_calls": 3,
                "parsed_count": 3,
                "promoted_count": dispositions.count("PROMOTE"),
                "blocked_count": dispositions.count("BLOCKED"),
                "input_tokens": 30,
                "output_tokens": 3,
                "all_candidates_retained": True,
                "routes_sha256": canonical_sha256(rows),
            },
        )
        return directory

    narrow = route("narrow", ("DEFER", "PROMOTE", "DEFER"))
    broad = route("broad", ("BLOCKED", "PROMOTE", "PROMOTE"))
    return generated, controls, narrow, broad


def test_comparison_measures_reranking_and_consensus_first_ensemble(tmp_path: Path) -> None:
    generated, controls, narrow, broad = _fixtures(tmp_path)
    output = tmp_path / "comparison.json"

    assert comparison.main(
        [
            "--generated-dir",
            str(generated),
            "--controls",
            str(controls),
            "--route",
            f"narrow={narrow}",
            "--route",
            f"broad={broad}",
            "--output",
            str(output),
        ]
    ) == 0

    payload = json.loads(output.read_text(encoding="utf-8"))
    row = payload["rows"][0]
    assert row["base_rank"] == 2
    assert row["route_results"]["narrow"]["rank"] == 1
    assert row["route_results"]["broad"]["rank"] == 1
    assert row["ensemble_rank"] == 1
    assert payload["base"]["recall_at_candidate_budget"]["1"] == 0.0
    assert payload["ensemble"]["recall_at_candidate_budget"]["1"] == 1.0
    assert payload["candidate_conservation_gate"] is True


def test_comparison_fails_closed_when_a_route_drops_a_candidate(tmp_path: Path) -> None:
    generated, controls, narrow, _broad = _fixtures(tmp_path)
    routes_path = narrow / "routes.jsonl"
    rows = [
        json.loads(line)
        for line in routes_path.read_text(encoding="utf-8").splitlines()
    ][:-1]
    _write_jsonl(routes_path, rows)
    execution = json.loads((narrow / "execution.json").read_text(encoding="utf-8"))
    execution["routes_sha256"] = canonical_sha256(rows)
    _write_json(narrow / "execution.json", execution)

    with pytest.raises(SystemExit, match="does not conserve candidates"):
        comparison.main(
            [
                "--generated-dir",
                str(generated),
                "--controls",
                str(controls),
                "--route",
                f"narrow={narrow}",
                "--output",
                str(tmp_path / "comparison.json"),
            ]
        )
