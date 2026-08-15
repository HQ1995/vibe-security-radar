#!/usr/bin/env python3
"""Freeze Coolify AI origins repaired by sensitive-model default hardening."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git_blob,
    _is_ancestor,
)
from cohort_coolify_security_frontier_preservation_witness import _blame_line


WEBHOOK_SHA = "27879377a07a88d2070a2939b2856cd0273eac52"
CLOUD_INIT_SHA = "7061eacfa506f92a8868c531fa52533e3563adc6"
TELEGRAM_SHA = "9f46586d4aaa93f2b526d67833ba70ef58b9893e"
REPAIR_SHA = "81a3bb0f0769e5a765e77649d002ea6acf9a667f"

WEBHOOK_PATH = "app/Models/WebhookNotificationSettings.php"
CLOUD_INIT_PATH = "app/Models/CloudInitScript.php"
TELEGRAM_PATH = "app/Models/TelegramNotificationSettings.php"
TEST_PATH = "tests/Unit/Models/SensitiveFieldsHiddenTest.php"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _text_blob(repository: Path, revision: str, source_path: str) -> str:
    return _git_blob(repository, revision, source_path).decode("utf-8")


def _blob_record(repository: Path, revision: str, source_path: str) -> dict[str, str]:
    blob = _git_blob(repository, revision, source_path)
    return {
        "revision": revision,
        "path": source_path,
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def _property_array(source: str, name: str) -> str:
    match = re.search(
        rf"protected\s+\${re.escape(name)}\s*=\s*\[(.*?)\];",
        source,
        flags=re.DOTALL,
    )
    if match is None:
        return ""
    return match.group(1)


def _property_marker_line(source: str, name: str, marker: str) -> int:
    match = re.search(
        rf"protected\s+\${re.escape(name)}\s*=\s*\[(.*?)\];",
        source,
        flags=re.DOTALL,
    )
    if match is None:
        raise SystemExit(f"property array ${name} not found")
    relative = match.group(0).find(marker)
    if relative < 0:
        raise SystemExit(f"marker {marker!r} not found in ${name}")
    return source[: match.start() + relative].count("\n") + 1


def _nth_line(source: str, marker: str, occurrence: int = 1) -> int:
    matches = [
        index + 1
        for index, line in enumerate(source.splitlines())
        if marker in line
    ]
    if occurrence < 1 or len(matches) < occurrence:
        raise SystemExit(
            f"expected marker {marker!r} occurrence {occurrence}, found {matches}"
        )
    return matches[occurrence - 1]


def _evaluate_encrypted_sensitive_model_origin(
    source: str,
    field: str,
) -> dict[str, bool]:
    return {
        "sensitive_field_is_fillable": f"'{field}'" in _property_array(source, "fillable"),
        "sensitive_field_has_encrypted_cast": (
            f"'{field}' => 'encrypted'" in source
        ),
        "sensitive_field_is_not_hidden_by_default": (
            f"'{field}'" not in _property_array(source, "hidden")
        ),
    }


def _evaluate_telegram_candidate(
    parent_source: str,
    candidate_source: str,
) -> dict[str, bool]:
    parent_fillable = _property_array(parent_source, "fillable")
    candidate_fillable = _property_array(candidate_source, "fillable")
    candidate_casts = _property_array(candidate_source, "casts")
    return {
        "parent_uses_old_singular_fillable_name": (
            "'telegram_notifications_docker_cleanup_thread_id'" in parent_fillable
        ),
        "candidate_makes_actual_success_failure_fields_fillable": all(
            field in candidate_fillable
            for field in (
                "'telegram_notifications_docker_cleanup_success_thread_id'",
                "'telegram_notifications_docker_cleanup_failure_thread_id'",
            )
        ),
        "candidate_leaves_stale_singular_encrypted_cast": (
            "'telegram_notifications_docker_cleanup_thread_id' => 'encrypted'"
            in candidate_casts
        ),
        "candidate_omits_actual_success_failure_encrypted_casts": all(
            field not in candidate_casts
            for field in (
                "'telegram_notifications_docker_cleanup_success_thread_id' => 'encrypted'",
                "'telegram_notifications_docker_cleanup_failure_thread_id' => 'encrypted'",
            )
        ),
        "candidate_does_not_hide_telegram_identifiers": (
            _property_array(candidate_source, "hidden") == ""
        ),
    }


def _evaluate_repair(
    webhook_source: str,
    cloud_init_source: str,
    telegram_source: str,
    tests: str,
) -> dict[str, bool]:
    telegram_hidden = _property_array(telegram_source, "hidden")
    telegram_casts = _property_array(telegram_source, "casts")
    return {
        "repair_hides_webhook_url": (
            "'webhook_url'" in _property_array(webhook_source, "hidden")
        ),
        "repair_hides_cloud_init_script": (
            "'script'" in _property_array(cloud_init_source, "hidden")
        ),
        "repair_hides_telegram_success_failure_ids": all(
            field in telegram_hidden
            for field in (
                "'telegram_notifications_docker_cleanup_success_thread_id'",
                "'telegram_notifications_docker_cleanup_failure_thread_id'",
            )
        ),
        "repair_encrypts_actual_telegram_success_failure_ids": all(
            field in telegram_casts
            for field in (
                "'telegram_notifications_docker_cleanup_success_thread_id' => 'encrypted'",
                "'telegram_notifications_docker_cleanup_failure_thread_id' => 'encrypted'",
            )
        ),
        "repair_removes_stale_singular_telegram_cast": (
            "'telegram_notifications_docker_cleanup_thread_id' => 'encrypted'"
            not in telegram_casts
        ),
        "repair_tests_all_three_model_contracts": all(
            marker in tests
            for marker in (
                "CloudInitScript hides script content",
                "Webhook-style notification settings hide delivery endpoints",
                "TelegramNotificationSettings hides bot, chat, and thread identifiers",
                "TelegramNotificationSettings casts actual docker cleanup thread ids as encrypted",
            )
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    webhook_candidate = _text_blob(repository, WEBHOOK_SHA, WEBHOOK_PATH)
    cloud_init_candidate = _text_blob(repository, CLOUD_INIT_SHA, CLOUD_INIT_PATH)
    telegram_parent = _text_blob(repository, f"{TELEGRAM_SHA}^", TELEGRAM_PATH)
    telegram_candidate = _text_blob(repository, TELEGRAM_SHA, TELEGRAM_PATH)
    webhook_repair = _text_blob(repository, REPAIR_SHA, WEBHOOK_PATH)
    cloud_init_repair = _text_blob(repository, REPAIR_SHA, CLOUD_INIT_PATH)
    telegram_repair = _text_blob(repository, REPAIR_SHA, TELEGRAM_PATH)
    repair_tests = _text_blob(repository, REPAIR_SHA, TEST_PATH)

    candidate_evaluations = {
        WEBHOOK_SHA: _evaluate_encrypted_sensitive_model_origin(
            webhook_candidate, "webhook_url"
        ),
        CLOUD_INIT_SHA: _evaluate_encrypted_sensitive_model_origin(
            cloud_init_candidate, "script"
        ),
        TELEGRAM_SHA: _evaluate_telegram_candidate(
            telegram_parent, telegram_candidate
        ),
    }
    repair_evaluation = _evaluate_repair(
        webhook_repair,
        cloud_init_repair,
        telegram_repair,
        repair_tests,
    )
    candidate_metadata = {
        sha: _commit_metadata(repository, sha)
        for sha in (WEBHOOK_SHA, CLOUD_INIT_SHA, TELEGRAM_SHA)
    }
    ancestry = {
        sha: _is_ancestor(repository, sha, REPAIR_SHA)
        for sha in (WEBHOOK_SHA, CLOUD_INIT_SHA, TELEGRAM_SHA)
    }

    line_specs = {
        "webhook_candidate_fillable": (
            WEBHOOK_SHA,
            WEBHOOK_PATH,
            webhook_candidate,
            "fillable",
            "'webhook_url'",
            "AI webhook URL default-serialization origin",
        ),
        "cloud_init_candidate_fillable": (
            CLOUD_INIT_SHA,
            CLOUD_INIT_PATH,
            cloud_init_candidate,
            "fillable",
            "'script'",
            "AI cloud-init script default-serialization origin",
        ),
        "telegram_candidate_actual_fillable": (
            TELEGRAM_SHA,
            TELEGRAM_PATH,
            telegram_candidate,
            "fillable",
            "'telegram_notifications_docker_cleanup_success_thread_id'",
            "AI Telegram actual-schema fillable activation",
        ),
        "telegram_candidate_stale_cast": (
            TELEGRAM_SHA,
            TELEGRAM_PATH,
            telegram_candidate,
            "casts",
            "'telegram_notifications_docker_cleanup_thread_id'",
            "stale Telegram singular encrypted cast retained by AI",
        ),
        "repair_webhook_hidden": (
            REPAIR_SHA,
            WEBHOOK_PATH,
            webhook_repair,
            "hidden",
            "'webhook_url'",
            "repair webhook URL default hiding",
        ),
        "repair_cloud_init_hidden": (
            REPAIR_SHA,
            CLOUD_INIT_PATH,
            cloud_init_repair,
            "hidden",
            "'script'",
            "repair cloud-init script default hiding",
        ),
        "repair_telegram_actual_cast": (
            REPAIR_SHA,
            TELEGRAM_PATH,
            telegram_repair,
            "casts",
            "'telegram_notifications_docker_cleanup_success_thread_id'",
            "repair Telegram actual-schema encrypted cast",
        ),
    }
    line_origins = {
        key: _blame_line(
            repository,
            revision,
            source_path,
            _property_marker_line(source, property_name, marker),
            label,
        )
        for key, (
            revision,
            source_path,
            source,
            property_name,
            marker,
            label,
        ) in line_specs.items()
    }
    line_origins["repair_contract_test"] = _blame_line(
        repository,
        REPAIR_SHA,
        TEST_PATH,
        _nth_line(
            repair_tests,
            "TelegramNotificationSettings casts actual docker cleanup thread ids as encrypted",
        ),
        "repair Telegram encrypted-cast contract test",
    )
    expected_origins = {
        "webhook_candidate_fillable": WEBHOOK_SHA,
        "cloud_init_candidate_fillable": CLOUD_INIT_SHA,
        "telegram_candidate_actual_fillable": TELEGRAM_SHA,
        "repair_webhook_hidden": REPAIR_SHA,
        "repair_cloud_init_hidden": REPAIR_SHA,
        "repair_telegram_actual_cast": REPAIR_SHA,
        "repair_contract_test": REPAIR_SHA,
    }

    witness_passed = bool(
        all(
            metadata["explicit_claude_signal"] is True
            for metadata in candidate_metadata.values()
        )
        and all(ancestry.values())
        and all(
            all(evaluation.values())
            for evaluation in candidate_evaluations.values()
        )
        and all(repair_evaluation.values())
        and all(
            line_origins[key]["origin_sha"] == expected
            for key, expected in expected_origins.items()
        )
    )

    source_pairs = {
        (WEBHOOK_SHA, WEBHOOK_PATH),
        (CLOUD_INIT_SHA, CLOUD_INIT_PATH),
        (f"{TELEGRAM_SHA}^", TELEGRAM_PATH),
        (TELEGRAM_SHA, TELEGRAM_PATH),
        (REPAIR_SHA, WEBHOOK_PATH),
        (REPAIR_SHA, CLOUD_INIT_PATH),
        (REPAIR_SHA, TELEGRAM_PATH),
        (REPAIR_SHA, TEST_PATH),
    }
    edges = [
        {
            "candidate_sha": WEBHOOK_SHA,
            "fix_sha": REPAIR_SHA,
            "causal_adjudication": "CONFIRMED_AI_SENSITIVE_MODEL_DEFAULT_SERIALIZATION_ORIGIN",
            "mechanism_group": "api_sensitive_model_default_serialization",
            "field": "WebhookNotificationSettings.webhook_url",
        },
        {
            "candidate_sha": CLOUD_INIT_SHA,
            "fix_sha": REPAIR_SHA,
            "causal_adjudication": "CONFIRMED_AI_SENSITIVE_MODEL_DEFAULT_SERIALIZATION_ORIGIN",
            "mechanism_group": "api_sensitive_model_default_serialization",
            "field": "CloudInitScript.script",
        },
        {
            "candidate_sha": TELEGRAM_SHA,
            "fix_sha": REPAIR_SHA,
            "causal_adjudication": "CONFIRMED_AI_INCOMPLETE_TELEGRAM_FIELD_SCHEMA_SYNC",
            "mechanism_group": "telegram_docker_cleanup_thread_id_encryption",
            "field": "TelegramNotificationSettings.telegram_notifications_docker_cleanup_*_thread_id",
        },
    ]
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_sensitive_model_defaults_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "fix_sha": REPAIR_SHA,
        "candidate_metadata": candidate_metadata,
        "ancestry": ancestry,
        "candidate_evaluations": candidate_evaluations,
        "repair_evaluation": repair_evaluation,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, revision, source_path)
            for revision, source_path in sorted(source_pairs)
        ],
        "edges": edges,
        "witness_passed": witness_passed,
        "counting": {
            "candidate_fix_true_positive_edge_count": len(edges),
            "unique_ai_candidate_count_in_witness": len(
                {edge["candidate_sha"] for edge in edges}
            ),
            "mechanism_group_count": len(
                {edge["mechanism_group"] for edge in edges}
            ),
            "ledger_must_deduplicate_candidates_across_other_witnesses": True,
        },
        "claim_boundary": (
            "The webhook and cloud-init Claude commits introduced encrypted-at-rest "
            "sensitive fields without Eloquent default hiding; the repair explicitly "
            "adds those fields to $hidden and tests the model contract. This proves a "
            "latent default-serialization origin, not a demonstrated public endpoint "
            "leak. The Telegram Claude refactor made the actual docker-cleanup "
            "success/failure thread-id fields fillable while retaining the obsolete "
            "singular encrypted cast. The repair replaces that stale cast with the "
            "actual two fields, hides them, and adds an exact regression test. No "
            "exploit reproduction or unique advisory is asserted."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify sensitive-model defaults witness failed")

    print("Coolify sensitive-model defaults witness frozen")
    print(f"  edges : {len(edges)}")
    print(f"  repair: {REPAIR_SHA}")
    print(f"  output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
