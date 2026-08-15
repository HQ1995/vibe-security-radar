"""Tests for the Coolify concurrent-index migration contract witness."""

from __future__ import annotations

import cohort_coolify_concurrent_index_migration_transaction_contract_witness as witness


def _migration_source(property_declaration: str = "") -> str:
    return f"""<?php
return new class extends Migration
{{
{property_declaration}
    public function up(): void
    {{
        DB::statement('CREATE INDEX CONCURRENTLY first');
        DB::statement('CREATE INDEX CONCURRENTLY second');
    }}

    public function down(): void
    {{
        DB::statement('DROP INDEX CONCURRENTLY first');
        DB::statement('DROP INDEX CONCURRENTLY second');
    }}
}};
"""


def test_version_predicates_separate_preexisting_ddl_from_typed_contract_break() -> (
    None
):
    baseline = _migration_source()
    candidate = baseline.replace(
        "    public function up(): void",
        witness.CANDIDATE_OVERRIDE_BLOCK + "    public function up(): void",
    )
    repair = """<?php
return new class extends Migration
{
    public function up(): void
    {
        DB::commit();
        DB::unprepared('CREATE INDEX CONCURRENTLY first');
        DB::unprepared('CREATE INDEX CONCURRENTLY second');
        DB::beginTransaction();
    }

    public function down(): void
    {
        DB::commit();
        DB::unprepared('DROP INDEX CONCURRENTLY first');
        DB::unprepared('DROP INDEX CONCURRENTLY second');
        DB::beginTransaction();
    }
};
"""
    canonical = _migration_source("    public $withinTransaction = false;\n").replace(
        "DB::statement", "DB::unprepared"
    )

    checks = witness._evaluate_versions(
        baseline,
        candidate,
        candidate,
        repair,
        canonical,
    )

    assert all(checks.values())


def test_locked_framework_contract_requires_untyped_property_and_migrator_gate() -> (
    None
):
    package = {
        "name": "laravel/framework",
        "version": witness.FRAMEWORK_VERSION,
        "source_reference": witness.FRAMEWORK_REF,
    }
    sources = {
        "migration": "public $withinTransaction = true;",
        "migrator": """
supportsSchemaTransactions()
$migration->withinTransaction
$connection->transaction($callback)
""",
        "transactions": """
if ($this->transactionLevel() == 1)
$this->getPdo()->commit();
max(0, $this->transactions - 1)
if ($this->transactions == 0)
$this->getPdo()->beginTransaction();
$this->transactions++;
""",
    }

    assert all(witness._evaluate_framework_contract(package, sources).values())

    sources["migration"] = "public bool $withinTransaction = true;"
    checks = witness._evaluate_framework_contract(package, sources)
    assert checks["migration_base_property_is_untyped"] is False


def test_php_runtime_predicates_require_fatal_candidate_and_loading_repairs() -> None:
    runs = {
        "candidate_typed_override": {
            "exit_code": 255,
            "output": (
                "Type of CandidateMigration::$withinTransaction must not be defined"
            ),
        },
        "intermediate_no_override": {
            "exit_code": 0,
            "output": "intermediate_load_ok PHP=8.4",
        },
        "canonical_untyped_override": {
            "exit_code": 0,
            "output": "canonical_load_ok PHP=8.4",
        },
    }

    assert all(witness._evaluate_php_runtime(runs).values())
