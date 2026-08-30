from apply_zero_pct_gate_20260826 import classify_scan_row


def test_classify_unscanned() -> None:
    assert classify_scan_row(None) == "unscanned"
    assert classify_scan_row({"clone_ok": True, "scan_complete": True, "has_ai": False}) == "unscanned"


def test_classify_has_ai_even_without_all_refs() -> None:
    assert classify_scan_row({"has_ai": True, "clone_ok": True}) == "has_ai"


def test_classify_empty_repo_is_droppable() -> None:
    assert classify_scan_row(
        {
            "clone_ok": True,
            "scan_complete": False,
            "has_ai": False,
            "scan_error": "ProvenanceError:repository has no readable refs",
        }
    ) == "droppable"
    assert classify_scan_row({"clone_ok": False, "has_ai": False}) == "unknown"
    assert classify_scan_row(
        {"clone_ok": True, "scan_complete": False, "has_ai": False}
    ) == "unknown"


def test_classify_droppable_needs_all_refs() -> None:
    row = {
        "clone_ok": True,
        "scan_complete": True,
        "has_ai": False,
        "agent_configs": [],
        "committer_ai_count": 0,
        "droppable": True,
        "all_refs": True,
    }
    assert classify_scan_row(row) == "droppable"
    row["all_refs"] = False
    assert classify_scan_row(row) == "unscanned"


def test_classify_keep_config() -> None:
    assert classify_scan_row(
        {
            "clone_ok": True,
            "scan_complete": True,
            "has_ai": False,
            "agent_configs": ["AGENTS.md"],
            "committer_ai_count": 0,
            "all_refs": True,
        }
    ) == "keep_config"
