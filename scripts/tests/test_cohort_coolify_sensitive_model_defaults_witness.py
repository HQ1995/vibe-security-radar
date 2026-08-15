"""Tests for sensitive-model default hardening witness predicates."""

from __future__ import annotations

from cohort_coolify_sensitive_model_defaults_witness import (
    _evaluate_encrypted_sensitive_model_origin,
    _evaluate_repair,
    _evaluate_telegram_candidate,
)


def test_encrypted_sensitive_origin_requires_fillable_but_unhidden_field() -> None:
    source = """
protected $fillable = ['script'];
protected function casts(): array { return ['script' => 'encrypted']; }
"""

    assert all(
        _evaluate_encrypted_sensitive_model_origin(source, "script").values()
    )


def test_telegram_candidate_detects_fillable_cast_schema_mismatch() -> None:
    parent = """
protected $fillable = ['telegram_notifications_docker_cleanup_thread_id'];
protected $casts = ['telegram_notifications_docker_cleanup_thread_id' => 'encrypted'];
"""
    candidate = """
protected $fillable = [
    'telegram_notifications_docker_cleanup_success_thread_id',
    'telegram_notifications_docker_cleanup_failure_thread_id',
];
protected $casts = ['telegram_notifications_docker_cleanup_thread_id' => 'encrypted'];
"""

    assert all(_evaluate_telegram_candidate(parent, candidate).values())


def test_repair_requires_hidden_fields_actual_casts_and_tests() -> None:
    webhook = "protected $hidden = ['webhook_url'];"
    cloud_init = "protected $hidden = ['script'];"
    telegram = """
protected $hidden = [
    'telegram_notifications_docker_cleanup_success_thread_id',
    'telegram_notifications_docker_cleanup_failure_thread_id',
];
protected $casts = [
    'telegram_notifications_docker_cleanup_success_thread_id' => 'encrypted',
    'telegram_notifications_docker_cleanup_failure_thread_id' => 'encrypted',
];
"""
    tests = "\n".join(
        (
            "CloudInitScript hides script content",
            "Webhook-style notification settings hide delivery endpoints",
            "TelegramNotificationSettings hides bot, chat, and thread identifiers",
            "TelegramNotificationSettings casts actual docker cleanup thread ids as encrypted",
        )
    )

    assert all(_evaluate_repair(webhook, cloud_init, telegram, tests).values())
