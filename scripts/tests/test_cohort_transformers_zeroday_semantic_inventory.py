"""Contracts for the Transformers all-ref semantic inventory."""

from __future__ import annotations

from pathlib import Path

import pytest

import cohort_transformers_zeroday_semantic_inventory as inventory


def test_signal_changes_only_records_changed_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    diff = """\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1 +1,2 @@
-value = torch.load(path, weights_only=True)
+value = torch.load(path, weights_only=False)
+guard = TRUST_REMOTE_CODE
 context = eval(not_a_changed_line)
"""
    monkeypatch.setattr(inventory, "_git", lambda *_args, **_kwargs: diff)

    rows = inventory._signal_changes(Path("repo"), "a" * 40)

    assert [row["sign"] for row in rows] == ["removed", "added", "added"]
    assert "safe_weights_only" in rows[0]["categories"]
    assert "unsafe_weights_only" in rows[1]["categories"]
    assert "explicit_trust_guard" in rows[2]["categories"]
    assert all("not_a_changed_line" not in row["line"] for row in rows)


def test_signal_changes_resets_path_for_each_file(monkeypatch: pytest.MonkeyPatch) -> None:
    diff = """\
diff --git a/one.py b/one.py
--- a/one.py
+++ b/one.py
@@ -1 +1 @@
-value = torch.load(path)
+value = torch.load(path, weights_only=True)
diff --git a/two.py b/two.py
--- a/two.py
+++ b/two.py
@@ -1 +1 @@
-flag = False
+flag = TRUST_REMOTE_CODE
"""
    monkeypatch.setattr(inventory, "_git", lambda *_args, **_kwargs: diff)

    rows = inventory._signal_changes(Path("repo"), "a" * 40)

    assert [row["path"] for row in rows] == ["one.py", "one.py", "two.py"]


def test_source_candidate_never_upgrades_carrier_to_direct_attribution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sha = "a" * 40
    member = "b" * 40
    monkeypatch.setattr(
        inventory,
        "_commit_metadata",
        lambda _repo, value: {
            "sha": value,
            "changed_files": ["src/transformers/modeling_utils.py"],
        },
    )
    monkeypatch.setattr(inventory, "_is_ancestor", lambda *_args: True)

    row = inventory._source_candidate(
        Path("repo"),
        {"sha": sha, "changed_files": ["src/transformers/modeling_utils.py"]},
        semantic_shas={sha},
        affected_by_cve={"CVE-test": "c" * 40},
        carrier_by_sha={sha: {"source_v3_ai_member_shas": [member]}},
        member_semantic_shas=set(),
    )

    assert row["attribution_scope"] == "SQUASH_CARRIER_REQUIRES_MEMBER_DECOMPOSITION"
    assert row["ancestor_of_affected_cves"] == ["CVE-test"]
    assert row["carrier_source_member_shas"] == [member]
    assert row["carrier_source_members_with_semantic_signals"] == []


def test_sha_inventory_digest_is_order_independent() -> None:
    left = inventory._sha_inventory_digest({"b" * 40, "a" * 40})
    right = inventory._sha_inventory_digest({"a" * 40, "b" * 40})

    assert left == right


def test_risk_paths_include_glm_aliases_and_global_loaders() -> None:
    assert "src/transformers/models/glm4v/" in inventory.RISK_PATHS
    assert "src/transformers/models/glm4v_moe/" in inventory.RISK_PATHS
    assert "src/transformers/modeling_utils.py" in inventory.RISK_PATHS
    assert "src/transformers/dynamic_module_utils.py" in inventory.RISK_PATHS
