"""Publisher reads Neon; jsonl is export-only."""
from __future__ import annotations

import pytest

import publish_tp_ledger


def test_load_ledger_rows_requires_database_url(monkeypatch) -> None:
    monkeypatch.setattr("ledger_store.load_env", lambda: None)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL_UNPOOLED", raising=False)
    with pytest.raises(SystemExit, match="DATABASE_URL"):
        publish_tp_ledger.load_ledger_rows(from_export=False)


def test_from_export_reads_jsonl_backup() -> None:
    rows = publish_tp_ledger.load_ledger_rows(from_export=True)
    assert rows
    assert any(row.get("status") in publish_tp_ledger.TP_STATUSES for row in rows)
    census = publish_tp_ledger.ledger_census(from_export=True)
    assert census["total"] == len(rows)
    assert census["closed"] + census["in_progress"] + census["not_started"] == census["total"]
