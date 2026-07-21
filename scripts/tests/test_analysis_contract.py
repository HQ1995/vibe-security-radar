from __future__ import annotations

from pathlib import Path

import pytest

import analysis_contract


def _contract_tree(root: Path) -> None:
    analyzer = root / "cve-analyzer"
    source = analyzer / "src/cve_analyzer"
    source.mkdir(parents=True)
    (analyzer / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    (analyzer / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (source / "ai_signatures.py").write_text("SIGNATURES = ['codex']\n", encoding="utf-8")
    (source / "pipeline.py").write_text("CONTRACT = 1\n", encoding="utf-8")


def test_epoch_changes_with_analyzer_semantics_and_signatures(tmp_path: Path) -> None:
    _contract_tree(tmp_path)
    first = analysis_contract.analysis_contract_epoch(tmp_path)

    pipeline = tmp_path / "cve-analyzer/src/cve_analyzer/pipeline.py"
    pipeline.write_text("CONTRACT = 2\n", encoding="utf-8")
    second = analysis_contract.analysis_contract_epoch(tmp_path)
    assert second["sha256"] != first["sha256"]

    signatures = tmp_path / "cve-analyzer/src/cve_analyzer/ai_signatures.py"
    signatures.write_text("SIGNATURES = ['codex', 'claude']\n", encoding="utf-8")
    third = analysis_contract.analysis_contract_epoch(tmp_path)
    assert third["sha256"] != second["sha256"]
    assert third["signature_sha256"] != second["signature_sha256"]


def test_epoch_excludes_source_snapshots_and_generated_plans(tmp_path: Path) -> None:
    _contract_tree(tmp_path)
    first = analysis_contract.analysis_contract_epoch(tmp_path)
    state = tmp_path / ".ai-slop/state/data-refresh"
    plans = tmp_path / ".ai-slop/plans"
    state.mkdir(parents=True)
    plans.mkdir(parents=True)
    (state / "source-delta-current.json").write_text("{}\n", encoding="utf-8")
    (plans / "campaign.json").write_text("{}\n", encoding="utf-8")
    second = analysis_contract.analysis_contract_epoch(tmp_path)
    assert second == first


def test_epoch_fails_closed_on_unsafe_or_missing_input(tmp_path: Path) -> None:
    _contract_tree(tmp_path)
    signatures = tmp_path / "cve-analyzer/src/cve_analyzer/ai_signatures.py"
    signatures.unlink()
    signatures.symlink_to(tmp_path / "outside.py")
    with pytest.raises(analysis_contract.AnalysisContractError, match="non-symlink"):
        analysis_contract.analysis_contract_epoch(tmp_path)
