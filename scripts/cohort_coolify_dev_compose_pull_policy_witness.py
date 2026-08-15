#!/usr/bin/env python3
"""Freeze the Coolify development Compose pull-policy regression witness."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git,
    _git_blob,
    _is_ancestor,
)
from cohort_coolify_sentinel_command_injection_witness import _blame_line
from cohort_coolify_sentinel_restart_activation_witness import _line_number


BASELINE_SHA = "58864b9b20d6a5ba09426c68a3ad6255a43cc1a1"
AI_REGRESSION_SHA = "251a10f5bb5659b7ef32431795ec7531d0c4cb4f"
DIRECT_REPAIR_SHA = "031d40440d56792e9ae2abe096c177867cee8ffc"
PR_CARRIER_SHA = "20408b9e674c2badf944b578c7ddaea8d372bf4d"

MAINLINE_PRE_CARRIER_SHA = "721680818e473853821962f3e59902715694828a"
MAINLINE_SECOND_PARENT_SHA = "b9c23ddc6f4927984861772f8fe784b33d712cd6"
MAINLINE_CARRIER_SHA = "ad26fe9c3c9ad282316e90e00af9aa40f0d582b8"

BASE_COMPOSE_PATH = "docker-compose.yml"
DEV_COMPOSE_PATH = "docker-compose.dev.yml"
CONTRIBUTING_PATH = "CONTRIBUTING.md"
COMPOSE_FIXTURE_PATH = "tests/Feature/ConvertContainerEnvsToArray.php"
APP_LAYOUT_PATH = "resources/views/layouts/app.blade.php"
SETTINGS_DROPDOWN_PATH = "resources/views/livewire/settings-dropdown.blade.php"

EXTERNAL_DEPENDENCY_IMAGES = {
    "postgres": "postgres:15-alpine",
    "redis": "redis:7-alpine",
    "vite": "node:24-alpine",
    "mailpit": "axllent/mailpit:latest",
    "minio": "minio/minio:latest",
}
LOCAL_BUILD_SERVICES = ("coolify", "soketi", "testing-host")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _text_blob(repository: Path, revision: str, source_path: str) -> str:
    return _git_blob(repository, revision, source_path).decode("utf-8")


def _blob_oid(repository: Path, revision: str, source_path: str) -> str:
    value = _git(
        repository,
        ["rev-parse", f"{revision}:{source_path}"],
        text=True,
    )
    assert isinstance(value, str)
    oid = value.strip()
    if len(oid) != 40:
        raise SystemExit(
            f"unexpected blob object id for {revision}:{source_path}: {oid!r}"
        )
    return oid


def _blob_record(repository: Path, revision: str, source_path: str) -> dict[str, str]:
    blob = _git_blob(repository, revision, source_path)
    return {
        "revision": revision,
        "path": source_path,
        "git_blob_oid": _blob_oid(repository, revision, source_path),
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def _changed_paths(repository: Path, before: str, after: str) -> list[str]:
    value = _git(
        repository,
        ["diff", "--name-only", before, after, "--"],
        text=True,
    )
    assert isinstance(value, str)
    return [line for line in value.splitlines() if line]


def _leading_spaces(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _parse_service_directives(source: str) -> dict[str, dict[str, object]]:
    """Parse direct service keys from the small Compose YAML subset we audit."""

    lines = source.splitlines()
    services_index = next(
        (index for index, line in enumerate(lines) if line.strip() == "services:"),
        None,
    )
    if services_index is None:
        raise ValueError("Compose source has no services mapping")

    service_headers: list[tuple[int, int, str]] = []
    service_indent: int | None = None
    header_pattern = re.compile(r"^([A-Za-z0-9_.-]+):\s*$")
    for index in range(services_index + 1, len(lines)):
        line = lines[index]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = _leading_spaces(line)
        if indent == 0:
            break
        match = header_pattern.fullmatch(stripped)
        if service_indent is None:
            if match is None:
                raise ValueError("first Compose services child is malformed")
            service_indent = indent
        if indent == service_indent and match is not None:
            service_headers.append((index, indent, match.group(1)))

    records: dict[str, dict[str, object]] = {}
    for header_index, header_indent, service_name in service_headers:
        following_headers = [
            index for index, _, _ in service_headers if index > header_index
        ]
        block_end = min(following_headers, default=len(lines))
        body = [
            (index, line)
            for index, line in enumerate(
                lines[header_index + 1 : block_end], start=header_index + 1
            )
            if line.strip() and not line.lstrip().startswith("#")
        ]
        body_indents = [
            _leading_spaces(line)
            for _, line in body
            if _leading_spaces(line) > header_indent
        ]
        if not body_indents:
            records[service_name] = {"directives": {}, "line_numbers": {}}
            continue
        direct_indent = min(body_indents)
        directives: dict[str, str | None] = {}
        line_numbers: dict[str, int] = {}
        for index, line in body:
            if _leading_spaces(line) != direct_indent or ":" not in line:
                continue
            key, value = line.strip().split(":", 1)
            directives[key] = value.strip().strip("\"'") or None
            line_numbers[key] = index + 1
        records[service_name] = {
            "directives": directives,
            "line_numbers": line_numbers,
        }
    return records


def _compose_service_records(
    base_source: str, development_source: str
) -> dict[str, dict[str, object]]:
    base = _parse_service_directives(base_source)
    development = _parse_service_directives(development_source)
    service_names = sorted(set(base) | set(development))
    records: dict[str, dict[str, object]] = {}
    for service_name in service_names:
        base_directives = base.get(service_name, {}).get("directives", {})
        development_directives = development.get(service_name, {}).get("directives", {})
        if not isinstance(base_directives, dict) or not isinstance(
            development_directives, dict
        ):
            raise ValueError(f"malformed service record: {service_name}")
        merged = {**base_directives, **development_directives}
        development_lines = development.get(service_name, {}).get("line_numbers", {})
        records[service_name] = {
            "image": merged.get("image"),
            "pull_policy": merged.get("pull_policy"),
            "has_build": "build" in merged,
            "development_pull_policy_line": (
                development_lines.get("pull_policy")
                if isinstance(development_lines, dict)
                else None
            ),
        }
    return records


def _evaluate_policy(
    service_records: dict[str, dict[str, object]],
) -> dict[str, object]:
    external_records = {
        service_name: {
            **service_records.get(service_name, {}),
            "expected_image": expected_image,
            "image_matches_expected": service_records.get(service_name, {}).get("image")
            == expected_image,
            "registry_image_without_build": (
                service_records.get(service_name, {}).get("image") == expected_image
                and service_records.get(service_name, {}).get("has_build") is False
            ),
            "automatic_pull_disabled": service_records.get(service_name, {}).get(
                "pull_policy"
            )
            == "never",
            "automatic_pull_enabled": service_records.get(service_name, {}).get(
                "pull_policy"
            )
            == "always",
        }
        for service_name, expected_image in EXTERNAL_DEPENDENCY_IMAGES.items()
    }
    return {
        "external_dependencies": external_records,
        "external_dependency_count": len(external_records),
        "all_external_images_match": all(
            row["image_matches_expected"] is True for row in external_records.values()
        ),
        "all_external_dependencies_lack_build": all(
            row["registry_image_without_build"] is True
            for row in external_records.values()
        ),
        "all_external_pulls_disabled": all(
            row["automatic_pull_disabled"] is True for row in external_records.values()
        ),
        "all_external_pulls_enabled": all(
            row["automatic_pull_enabled"] is True for row in external_records.values()
        ),
        "local_build_service_policies": {
            service_name: service_records.get(service_name, {}).get("pull_policy")
            for service_name in LOCAL_BUILD_SERVICES
        },
    }


def _policy_line_origins(
    repository: Path,
    revision: str,
    development_source: str,
    service_records: dict[str, dict[str, object]],
    label: str,
) -> dict[str, dict[str, object]]:
    origins: dict[str, dict[str, object]] = {}
    for service_name in EXTERNAL_DEPENDENCY_IMAGES:
        line = service_records[service_name]["development_pull_policy_line"]
        if not isinstance(line, int):
            raise SystemExit(
                f"missing pull_policy line for {service_name} at {revision}"
            )
        expected = str(service_records[service_name]["pull_policy"])
        if f"pull_policy: {expected}" not in development_source.splitlines()[line - 1]:
            raise SystemExit(f"pull_policy line mismatch for {service_name}")
        origins[service_name] = _blame_line(
            repository,
            revision,
            DEV_COMPOSE_PATH,
            line,
            f"{label}: {service_name} pull_policy={expected}",
        )
    return origins


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    revisions = {
        "baseline": BASELINE_SHA,
        "ai_regression": AI_REGRESSION_SHA,
        "direct_repair": DIRECT_REPAIR_SHA,
        "pr_carrier": PR_CARRIER_SHA,
        "mainline_carrier": MAINLINE_CARRIER_SHA,
    }
    metadata = {
        name: _commit_metadata(repository, revision)
        for name, revision in revisions.items()
    }
    compose_sources = {
        name: {
            "base": _text_blob(repository, revision, BASE_COMPOSE_PATH),
            "development": _text_blob(repository, revision, DEV_COMPOSE_PATH),
        }
        for name, revision in revisions.items()
    }
    service_records = {
        name: _compose_service_records(sources["base"], sources["development"])
        for name, sources in compose_sources.items()
    }
    policy_evaluations = {
        name: _evaluate_policy(records) for name, records in service_records.items()
    }

    contributing = _text_blob(repository, AI_REGRESSION_SHA, CONTRIBUTING_PATH)
    compose_fixture = _text_blob(repository, AI_REGRESSION_SHA, COMPOSE_FIXTURE_PATH)
    workflow_contract = {
        "development_setup_copies_env_template": (
            "Duplicate the `.env.development.example` file" in contributing
            and "rename the copy to `.env`" in contributing
        ),
        "development_start_uses_spin_up": "spin up" in contributing,
        "documented_reset_prunes_all_unused_images": (
            "docker image prune -a" in contributing
        ),
        "documented_reset_starts_development_again": (
            contributing.count("spin up") >= 2
        ),
        "runtime_fixture_records_base_and_development_compose_files": (
            "docker-compose.yml," in compose_fixture
            and "docker-compose.dev.yml" in compose_fixture
        ),
    }

    compose_blobs = {
        name: _blob_oid(repository, revision, DEV_COMPOSE_PATH)
        for name, revision in revisions.items()
    }
    ui_blobs = {
        source_path: {
            name: _blob_oid(repository, revision, source_path)
            for name, revision in revisions.items()
        }
        for source_path in (APP_LAYOUT_PATH, SETTINGS_DROPDOWN_PATH)
    }
    path_states = {
        "development_compose": compose_blobs,
        "ui_paths": ui_blobs,
        "candidate_changed_paths": _changed_paths(
            repository, BASELINE_SHA, AI_REGRESSION_SHA
        ),
        "repair_changed_paths": _changed_paths(
            repository, AI_REGRESSION_SHA, DIRECT_REPAIR_SHA
        ),
        "pr_carrier_first_parent_changed_paths": _changed_paths(
            repository, BASELINE_SHA, PR_CARRIER_SHA
        ),
    }

    candidate_policy_origins = _policy_line_origins(
        repository,
        AI_REGRESSION_SHA,
        compose_sources["ai_regression"]["development"],
        service_records["ai_regression"],
        "AI regression",
    )
    repair_policy_origins = _policy_line_origins(
        repository,
        DIRECT_REPAIR_SHA,
        compose_sources["direct_repair"]["development"],
        service_records["direct_repair"],
        "direct repair",
    )
    pr_layout = _text_blob(repository, PR_CARRIER_SHA, APP_LAYOUT_PATH)
    pr_settings = _text_blob(repository, PR_CARRIER_SHA, SETTINGS_DROPDOWN_PATH)
    line_origins = {
        "candidate_external_pull_policies": candidate_policy_origins,
        "repair_external_pull_policies": repair_policy_origins,
        "pr_carrier_mobile_navbar": _blame_line(
            repository,
            PR_CARRIER_SHA,
            APP_LAYOUT_PATH,
            _line_number(pr_layout, "bg-white/95 dark:bg-base/95"),
            "intended mobile-navbar change retained by PR carrier",
        ),
        "pr_carrier_preferences_icon": _blame_line(
            repository,
            PR_CARRIER_SHA,
            SETTINGS_DROPDOWN_PATH,
            _line_number(pr_settings, 'title="Preferences"'),
            "intended settings-icon change retained by PR carrier",
        ),
    }

    topology = {
        "candidate_is_direct_parent_of_repair": metadata["direct_repair"]["parents"]
        == [AI_REGRESSION_SHA],
        "pr_carrier_has_baseline_and_repair_parents": metadata["pr_carrier"]["parents"]
        == [BASELINE_SHA, DIRECT_REPAIR_SHA],
        "candidate_and_repair_precede_pr_carrier": _is_ancestor(
            repository, AI_REGRESSION_SHA, PR_CARRIER_SHA
        )
        and _is_ancestor(repository, DIRECT_REPAIR_SHA, PR_CARRIER_SHA),
        "pr_carrier_enters_mainline_only_through_second_parent": (
            not _is_ancestor(repository, PR_CARRIER_SHA, MAINLINE_PRE_CARRIER_SHA)
            and _is_ancestor(repository, PR_CARRIER_SHA, MAINLINE_SECOND_PARENT_SHA)
            and _is_ancestor(repository, PR_CARRIER_SHA, MAINLINE_CARRIER_SHA)
        ),
        "mainline_carrier_has_frozen_parent_order": metadata["mainline_carrier"][
            "parents"
        ]
        == [MAINLINE_PRE_CARRIER_SHA, MAINLINE_SECOND_PARENT_SHA],
    }

    candidate_paths = sorted(
        [DEV_COMPOSE_PATH, APP_LAYOUT_PATH, SETTINGS_DROPDOWN_PATH]
    )
    ui_paths = sorted([APP_LAYOUT_PATH, SETTINGS_DROPDOWN_PATH])
    path_checks = {
        "candidate_changes_compose_and_two_intended_ui_paths": sorted(
            path_states["candidate_changed_paths"]
        )
        == candidate_paths,
        "direct_repair_changes_only_development_compose": path_states[
            "repair_changed_paths"
        ]
        == [DEV_COMPOSE_PATH],
        "repair_restores_entire_compose_blob_to_baseline": (
            compose_blobs["direct_repair"] == compose_blobs["baseline"]
            and compose_blobs["ai_regression"] != compose_blobs["baseline"]
        ),
        "pr_and_mainline_carriers_never_receive_regressed_compose_blob": (
            compose_blobs["pr_carrier"] == compose_blobs["baseline"]
            and compose_blobs["mainline_carrier"] == compose_blobs["baseline"]
        ),
        "repair_preserves_candidate_ui_blobs": all(
            blobs["ai_regression"] == blobs["direct_repair"]
            for blobs in ui_blobs.values()
        ),
        "pr_carrier_retains_only_intended_ui_path_delta": (
            sorted(path_states["pr_carrier_first_parent_changed_paths"]) == ui_paths
            and all(
                blobs["pr_carrier"] == blobs["ai_regression"]
                for blobs in ui_blobs.values()
            )
        ),
    }

    baseline_policy = policy_evaluations["baseline"]
    candidate_policy = policy_evaluations["ai_regression"]
    repair_policy = policy_evaluations["direct_repair"]
    policy_checks = {
        "all_five_dependencies_are_registry_images_without_build": (
            baseline_policy["all_external_images_match"] is True
            and baseline_policy["all_external_dependencies_lack_build"] is True
        ),
        "baseline_allows_automatic_dependency_image_pulls": baseline_policy[
            "all_external_pulls_enabled"
        ]
        is True,
        "candidate_disables_all_five_dependency_image_pulls": candidate_policy[
            "all_external_pulls_disabled"
        ]
        is True,
        "repair_restores_all_five_dependency_image_pulls": repair_policy[
            "all_external_pulls_enabled"
        ]
        is True,
        "candidate_policy_lines_are_owned_by_candidate": all(
            row["origin_sha"] == AI_REGRESSION_SHA
            for row in candidate_policy_origins.values()
        ),
        "restored_policy_lines_are_owned_by_direct_repair": all(
            row["origin_sha"] == DIRECT_REPAIR_SHA
            for row in repair_policy_origins.values()
        ),
    }

    semantic_checks = {
        "candidate_and_repair_have_explicit_conductor_signal": (
            metadata["ai_regression"]["explicit_claude_signal"] is True
            and metadata["direct_repair"]["explicit_claude_signal"] is True
        ),
        "pr_subject_confirms_ui_only_intent": (
            "fix-mobile-navbar-bg" in str(metadata["pr_carrier"]["message"])
            and "mobile navbar" in str(metadata["pr_carrier"]["message"]).lower()
        ),
        "documented_fresh_reset_requires_reacquiring_images": all(
            workflow_contract.values()
        ),
        "candidate_owns_both_retained_ui_lines": (
            line_origins["pr_carrier_mobile_navbar"]["origin_sha"] == AI_REGRESSION_SHA
            and line_origins["pr_carrier_preferences_icon"]["origin_sha"]
            == AI_REGRESSION_SHA
        ),
    }

    check_groups = {
        "topology": topology,
        "path_selection": path_checks,
        "pull_policy_mechanism": policy_checks,
        "semantic_boundary": semantic_checks,
    }
    witness_passed = all(
        value is True for group in check_groups.values() for value in group.values()
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_dev_compose_pull_policy_regression_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_REGRESSION_SHA,
        "fix_sha": DIRECT_REPAIR_SHA,
        "pr_carrier_sha": PR_CARRIER_SHA,
        "mainline_carrier_sha": MAINLINE_CARRIER_SHA,
        "metadata": metadata,
        "topology": topology,
        "workflow_contract": workflow_contract,
        "path_states": path_states,
        "policy_evaluations": policy_evaluations,
        "line_origins": line_origins,
        "check_groups": check_groups,
        "source_blobs": [
            *(
                _blob_record(repository, revision, source_path)
                for revision in (BASELINE_SHA, AI_REGRESSION_SHA, DIRECT_REPAIR_SHA)
                for source_path in (BASE_COMPOSE_PATH, DEV_COMPOSE_PATH)
            ),
            _blob_record(repository, PR_CARRIER_SHA, DEV_COMPOSE_PATH),
            _blob_record(repository, MAINLINE_CARRIER_SHA, DEV_COMPOSE_PATH),
            *(
                _blob_record(repository, revision, source_path)
                for revision in (
                    BASELINE_SHA,
                    AI_REGRESSION_SHA,
                    DIRECT_REPAIR_SHA,
                    PR_CARRIER_SHA,
                )
                for source_path in (APP_LAYOUT_PATH, SETTINGS_DROPDOWN_PATH)
            ),
            _blob_record(repository, AI_REGRESSION_SHA, CONTRIBUTING_PATH),
            _blob_record(repository, AI_REGRESSION_SHA, COMPOSE_FIXTURE_PATH),
        ],
        "confirmed_edge": {
            "adjudication": "CONFIRMED_AI_DEV_COLD_START_IMAGE_PULL_REGRESSION",
            "candidate_sha": AI_REGRESSION_SHA,
            "fix_sha": DIRECT_REPAIR_SHA,
            "mechanism_group": "dev_compose_external_image_pull_policy_never",
        },
        "counting": {
            "candidate_level_true_positive_count": 1,
            "production_release_exposure_count": 0,
            "security_vulnerability_increment_not_asserted": True,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Conductor commit 251a10f changed five external development "
            "dependencies with registry images and no local build from pull_policy "
            "always to never. That makes the documented fresh-reset workflow, which "
            "prunes unused images and then runs spin up, unable to reacquire missing "
            "dependency images automatically. Its direct Conductor child 031d404 "
            "restores the complete development Compose blob while preserving both "
            "intended mobile-navbar UI changes. PR #6929 carries only those two UI "
            "paths; both the PR carrier and later mainline carrier retain the "
            "baseline Compose blob. This confirms one branch-local AI development "
            "cold-start regression and exact repair, not a production release or "
            "security-vulnerability exposure."
        ),
        "witness_passed": witness_passed,
    }
    _atomic_json(args.output, payload)
    print("Coolify development Compose pull-policy witness frozen")
    print(f"  candidate      : {AI_REGRESSION_SHA}")
    print(f"  direct repair  : {DIRECT_REPAIR_SHA}")
    print(f"  PR carrier     : {PR_CARRIER_SHA}")
    print(f"  witness passed : {witness_passed}")
    print(f"  output         : {args.output}")
    return 0 if witness_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
