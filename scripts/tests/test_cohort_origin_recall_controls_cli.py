"""Coverage-gate contract for blind origin generation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import cohort_origin_recall_controls as cli


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, fatal: bool) -> dict[str, object]:
    identity = "github.com/example/repo"
    fix_sha = "f" * 40
    repo = tmp_path / ("fatal-repo" if fatal else "gap-repo")
    (repo / ".git").mkdir(parents=True)
    manifest = tmp_path / ("fatal.json" if fatal else "gap.json")
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact_kind": "sealed_fix_manifest",
                "split_id": "test",
                "frozen_at": "2099-01-01T00:00:00Z",
                "fixes": [
                    {
                        "advisory": "CVE-2099-0001",
                        "repository_identity": identity,
                        "fix_sha": fix_sha,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    aliases = tmp_path / "aliases.json"
    aliases.write_text('{"aliases": []}', encoding="utf-8")
    monkeypatch.setattr(cli, "_explicit_repositories", lambda *_: {identity: repo})

    if fatal:
        def collect(*_: object, **__: object) -> dict[str, object]:
            raise SystemExit("fatal ancestry failure")
    else:
        def collect(*_: object, **__: object) -> dict[str, object]:
            return {
                **{name: set() for name in (
                    "copy_aware", "file_local", "add_context", "function_history",
                    "pickaxe_history", "file_history", "cross_file_surface",
                    "cross_file_bridge",
                )},
                "ancestors": {"a" * 40},
                "bridge_evidence": [],
                "coverage_gaps": [
                    {"lane": "affected_file_history", "operation": "git", "reason": "missing blob"}
                ],
                "add_only_hunk_count": 0,
                "guard_like_hunk_count": 0,
                "fix_has_global_guard": False,
                "pickaxe_token_count": 0,
                "pickaxe_query_count": 0,
            }

    monkeypatch.setattr(cli, "collect_origin_signals", collect)
    output = tmp_path / ("fatal-output" if fatal else "gap-output")
    cli._generate(
        argparse.Namespace(
            output_dir=output,
            repo_timeout=30,
            aliases=aliases,
            fix_manifest=manifest,
            repository_identity=None,
            repository_path=[],
        )
    )
    return json.loads((output / "summary.json").read_text(encoding="utf-8"))


def test_optional_signal_gaps_do_not_block_but_fatal_failures_do(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gap = _run(tmp_path, monkeypatch, fatal=False)
    assert gap["gate_status"] == "READY_FOR_SEPARATE_EVALUATION"
    assert gap["resolved_fix_count"] == gap["signal_gap_fix_count"] == 1
    assert gap["signal_gap_count"] == 1
    assert gap["blocked_fix_count"] == 0

    fatal = _run(tmp_path, monkeypatch, fatal=True)
    assert fatal["gate_status"] == "BLOCKED"
    assert fatal["blocked_fix_count"] == 1
