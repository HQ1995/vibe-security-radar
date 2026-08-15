"""Tests for the Coolify development Compose pull-policy witness."""

from __future__ import annotations

import cohort_coolify_dev_compose_pull_policy_witness as witness


BASE = """
services:
    postgres:
        image: postgres:15-alpine
        restart: always
    redis:
        image: redis:7-alpine
        environment:
            REDIS_PASSWORD: example
"""

DEVELOPMENT_ALWAYS = """
services:
  postgres:
    pull_policy: always
    environment:
      POSTGRES_DB: coolify
  redis:
    pull_policy: always
  vite:
    image: node:24-alpine
    pull_policy: always
  mailpit:
    image: axllent/mailpit:latest
    pull_policy: always
  minio:
    image: minio/minio:latest
    pull_policy: always
  coolify:
    image: coolify:dev
    pull_policy: never
    build:
      context: .
  soketi:
    image: coolify-realtime:dev
    pull_policy: never
    build:
      context: .
  testing-host:
    image: coolify-testing-host:dev
    pull_policy: never
    build:
      context: .
networks:
  coolify:
    name: coolify
"""


def test_service_parser_handles_indentation_and_ignores_nested_keys() -> None:
    base = witness._parse_service_directives(BASE)
    development = witness._parse_service_directives(DEVELOPMENT_ALWAYS)

    assert base["postgres"]["directives"] == {
        "image": "postgres:15-alpine",
        "restart": "always",
    }
    assert base["redis"]["directives"] == {
        "image": "redis:7-alpine",
        "environment": None,
    }
    assert development["postgres"]["line_numbers"]["pull_policy"] == 4
    assert "POSTGRES_DB" not in development["postgres"]["directives"]


def test_compose_merge_identifies_registry_dependencies_and_local_builds() -> None:
    records = witness._compose_service_records(BASE, DEVELOPMENT_ALWAYS)

    assert records["postgres"] == {
        "image": "postgres:15-alpine",
        "pull_policy": "always",
        "has_build": False,
        "development_pull_policy_line": 4,
    }
    assert records["vite"]["image"] == "node:24-alpine"
    assert records["coolify"]["has_build"] is True
    assert records["coolify"]["pull_policy"] == "never"


def test_policy_contract_distinguishes_bootstrappable_and_blocked_sources() -> None:
    allowed_records = witness._compose_service_records(BASE, DEVELOPMENT_ALWAYS)
    blocked_source = DEVELOPMENT_ALWAYS.replace(
        "pull_policy: always", "pull_policy: never"
    )
    blocked_records = witness._compose_service_records(BASE, blocked_source)

    allowed = witness._evaluate_policy(allowed_records)
    blocked = witness._evaluate_policy(blocked_records)

    assert allowed["external_dependency_count"] == 5
    assert allowed["all_external_images_match"] is True
    assert allowed["all_external_dependencies_lack_build"] is True
    assert allowed["all_external_pulls_enabled"] is True
    assert allowed["all_external_pulls_disabled"] is False
    assert blocked["all_external_pulls_enabled"] is False
    assert blocked["all_external_pulls_disabled"] is True


def test_parser_rejects_source_without_services_mapping() -> None:
    try:
        witness._parse_service_directives("networks:\n  coolify:\n")
    except ValueError as exc:
        assert "no services" in str(exc)
    else:
        raise AssertionError("missing services mapping should fail closed")
