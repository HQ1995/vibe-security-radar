"""Tests for the Coolify symbol-contract method-migration witness."""

from __future__ import annotations

import cohort_coolify_symbol_contract_method_migration_witness as witness


def _local_sync_source() -> str:
    return """<?php
class EditDomain {
    public function mount() { $this->syncData(false); }
    private function syncData(bool $toModel = false): void {}
    public function submit() {
        $this->syncData(true);
        $this->syncData(false);
        $this->syncData(false);
    }
}
"""


def _broken_trait_source() -> str:
    return """<?php
class EditDomain {
    use SynchronizesModelData;
    public function mount() { $this->syncFromModel(); }
    protected function getModelBindings(): array { return []; }
    public function submit() {
        $this->syncToModel();
        $this->syncData(false);
        $this->syncData(false);
    }
}
"""


def _repaired_trait_source() -> str:
    return """<?php
class EditDomain {
    use SynchronizesModelData;
    public function mount() { $this->syncFromModel(); }
    protected function getModelBindings(): array { return []; }
    public function submit() {
        $this->syncToModel();
        $this->syncFromModel();
        $this->syncFromModel();
    }
}
"""


def _trait_source() -> str:
    return """<?php
trait SynchronizesModelData {
    protected function syncToModel(): void {}
    protected function syncFromModel(): void {}
}
"""


def test_contract_requires_self_consistent_parent_partial_break_and_exact_repair() -> (
    None
):
    local = _local_sync_source()
    broken = _broken_trait_source()
    repaired = _repaired_trait_source()

    result = witness._evaluate_contract_versions(
        local,
        local,
        broken,
        broken,
        repaired,
        _trait_source(),
    )

    assert all(result["checks"].values())


def test_contract_rejects_candidate_that_migrates_every_call() -> None:
    local = _local_sync_source()
    repaired = _repaired_trait_source()
    result = witness._evaluate_contract_versions(
        local,
        local,
        repaired,
        repaired,
        repaired,
        _trait_source(),
    )

    assert (
        result["checks"]["candidate_migrates_two_calls_but_leaves_two_old_calls"]
        is False
    )


def test_contract_rejects_initial_call_author_without_matching_callee() -> None:
    local = _local_sync_source()
    broken = _broken_trait_source()
    result = witness._evaluate_contract_versions(
        broken,
        local,
        broken,
        broken,
        _repaired_trait_source(),
        _trait_source(),
    )

    assert (
        result["checks"][
            "initial_call_author_introduces_self_consistent_local_contract"
        ]
        is False
    )


def _delta(
    *,
    before_blob: str,
    after_blob: str,
    added: list[str] | None = None,
    removed: list[str] | None = None,
    empty: bool = False,
    digest: str = "a" * 64,
) -> dict[str, object]:
    return {
        "before_blob_oid": before_blob,
        "after_blob_oid": after_blob,
        "added_lines": added or [],
        "removed_lines": removed or [],
        "empty": empty,
        "diff_sha256": digest,
    }


def test_exact_fix_delta_rejects_extra_refactor_lines() -> None:
    broken_blob = "1" * 40
    fixed_blob = "2" * 40
    fix_delta = _delta(
        before_blob=broken_blob,
        after_blob=fixed_blob,
        added=[witness.MIGRATED_CALL, witness.MIGRATED_CALL],
        removed=[witness.STALE_CALL, witness.STALE_CALL],
    )
    carrier_first = dict(fix_delta)
    carrier_second = _delta(
        before_blob=fixed_blob,
        after_blob=fixed_blob,
        empty=True,
        digest="e" * 64,
    )

    checks = witness._evaluate_exact_fix_delta(
        fix_delta,
        [witness.SOURCE_PATH],
        carrier_first,
        carrier_second,
    )
    assert all(checks.values())

    fix_delta["added_lines"] = [
        witness.MIGRATED_CALL,
        witness.MIGRATED_CALL,
        "$this->unrelatedRefactor();",
    ]
    checks = witness._evaluate_exact_fix_delta(
        fix_delta,
        [witness.SOURCE_PATH],
        carrier_first,
        carrier_second,
    )
    assert checks["fix_adds_exactly_two_trait_calls"] is False
