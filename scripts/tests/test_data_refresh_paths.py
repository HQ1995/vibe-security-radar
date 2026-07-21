from __future__ import annotations

from pathlib import Path

import data_refresh_paths


def test_project_runtime_paths_are_repository_local(tmp_path: Path) -> None:
    assert data_refresh_paths.data_refresh_state_root(tmp_path) == (
        tmp_path / ".ai-slop/state/data-refresh"
    )
    assert data_refresh_paths.data_refresh_log_root(tmp_path) == (
        tmp_path / ".ai-slop/logs/data-refresh"
    )


def test_runtime_path_constants_are_relative() -> None:
    assert not data_refresh_paths.DATA_REFRESH_STATE_RELATIVE.is_absolute()
    assert not data_refresh_paths.DATA_REFRESH_LOG_RELATIVE.is_absolute()
