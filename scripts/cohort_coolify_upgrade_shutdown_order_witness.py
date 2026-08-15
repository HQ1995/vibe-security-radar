#!/usr/bin/env python3
"""Freeze the Coolify AI upgrade shutdown-order regression witness."""

from __future__ import annotations

import argparse
import hashlib
import re
from datetime import datetime
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


BASELINE_SHA = "7dc93001e3e4d1a089a7dcac3120b4e68669582d"
AI_REGRESSION_SHA = "f3ccacb2da6da8b502bcb472bfb0bc6a7c776068"
DIRECT_REPAIR_SHA = "f4dbae180536f897185c7933f1904e8b9d39efff"
DETACHED_FIX_SHA = "1f7888f515da8d67ebad655c35e38ed544cc0543"
FIX_FOLLOWUP_SHA = "30ac4e079c9b8e23401ae7b6a3594f5c5e19e6a4"
PR_CARRIER_SHA = "a3bc59dae26e2dcaf5143418843011756d502e4a"
PR_FIRST_PARENT_SHA = "92326c09ea28af6abf427b32a256dbd997ad7133"
PR_SECOND_PARENT_SHA = FIX_FOLLOWUP_SHA
FIRST_CONTAINING_TAG = "v4.0.0-beta.455"
FIRST_CONTAINING_TAG_SHA = "b18d9a254bb492bfc5fbf1c1dd15670188256ab7"

UPGRADE_PATHS = ("scripts/upgrade.sh", "other/nightly/upgrade.sh")
BASE_COMPOSE_PATH = "docker-compose.yml"
PROD_COMPOSE_PATH = "docker-compose.prod.yml"
UPDATE_ACTION_PATH = "app/Actions/Server/UpdateCoolify.php"
REMOTE_HELPER_PATH = "bootstrap/helpers/remoteProcess.php"
PREPARE_TASK_PATH = "app/Actions/CoolifyTask/PrepareCoolifyTask.php"
COOLIFY_TASK_PATH = "app/Jobs/CoolifyTask.php"
RUN_REMOTE_PATH = "app/Actions/CoolifyTask/RunRemoteProcess.php"
DATABASE_CONFIG_PATH = "config/database.php"
QUEUE_CONFIG_PATH = "config/queue.php"

CONTROL_PLANE = "coolify"
DEPENDENCIES = ("coolify-db", "coolify-redis", "coolify-realtime")
EXPECTED_CONTAINERS = (CONTROL_PLANE, *DEPENDENCIES)


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


def _extract_stop_order(source: str) -> tuple[str, ...]:
    pattern = re.compile(
        r"^\s*for container in\s+([A-Za-z0-9_-]+(?:\s+[A-Za-z0-9_-]+)*)"
        r";\s*do\s*$",
        re.MULTILINE,
    )
    matches = pattern.findall(source)
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one container stop loop, found {len(matches)}"
        )
    order = tuple(matches[0].split())
    if len(order) != len(set(order)):
        raise ValueError(f"container stop order contains duplicates: {order}")
    if set(order) != set(EXPECTED_CONTAINERS):
        raise ValueError(f"unexpected container stop set: {order}")
    return order


def _evaluate_shutdown_order(order: tuple[str, ...]) -> dict[str, object]:
    if len(order) != len(set(order)) or set(order) != set(EXPECTED_CONTAINERS):
        raise ValueError(f"invalid shutdown order: {order}")

    running = set(EXPECTED_CONTAINERS)
    states: list[dict[str, object]] = []
    for step, stopped in enumerate(order, start=1):
        running.remove(stopped)
        unavailable_dependencies = sorted(set(DEPENDENCIES) - running)
        control_plane_running = CONTROL_PLANE in running
        contract_violated = control_plane_running and bool(unavailable_dependencies)
        states.append(
            {
                "step": step,
                "stopped": stopped,
                "running": sorted(running),
                "control_plane_running": control_plane_running,
                "unavailable_control_plane_dependencies": unavailable_dependencies,
                "control_plane_dependency_contract_violated": contract_violated,
            }
        )

    violations = [
        state
        for state in states
        if state["control_plane_dependency_contract_violated"] is True
    ]
    return {
        "order": list(order),
        "states": states,
        "violation_count": len(violations),
        "violation_steps": [state["step"] for state in violations],
        "stopped_before_control_plane": [
            container for container in order[: order.index(CONTROL_PLANE)]
        ],
        "dependency_safe": not violations,
    }


def _seconds_between(before: str, after: str) -> int:
    delta = datetime.fromisoformat(after) - datetime.fromisoformat(before)
    seconds = int(delta.total_seconds())
    if seconds < 0:
        raise ValueError(f"timestamps are reversed: {before} > {after}")
    return seconds


def _parse_containing_tags(source: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in source.splitlines():
        if not line:
            continue
        fields = line.split("\t", 1)
        if len(fields) != 2 or not all(fields):
            raise ValueError(f"malformed containing-tag row: {line!r}")
        rows.append({"created_at": fields[0], "tag": fields[1]})
    if not rows:
        raise ValueError("candidate is not contained by any tag")
    return rows


def _containing_tags(repository: Path, revision: str) -> list[dict[str, str]]:
    value = _git(
        repository,
        [
            "for-each-ref",
            f"--contains={revision}",
            "--sort=creatordate",
            "--format=%(creatordate:iso-strict)%09%(refname:strip=2)",
            "refs/tags",
        ],
        text=True,
    )
    assert isinstance(value, str)
    return _parse_containing_tags(value)


def _resolved_commit(repository: Path, revision: str) -> str:
    value = _git(repository, ["rev-parse", f"{revision}^{{commit}}"], text=True)
    assert isinstance(value, str)
    sha = value.strip()
    if len(sha) != 40:
        raise SystemExit(f"unexpected resolved commit for {revision}: {sha!r}")
    return sha


def _evaluate_runtime_contract(sources: dict[str, str]) -> dict[str, bool]:
    base_compose = sources[BASE_COMPOSE_PATH]
    prod_compose = sources[PROD_COMPOSE_PATH]
    update_action = sources[UPDATE_ACTION_PATH]
    remote_helper = sources[REMOTE_HELPER_PATH]
    prepare_task = sources[PREPARE_TASK_PATH]
    coolify_task = sources[COOLIFY_TASK_PATH]
    run_remote = sources[RUN_REMOTE_PATH]
    database_config = sources[DATABASE_CONFIG_PATH]
    queue_config = sources[QUEUE_CONFIG_PATH]

    return {
        "base_compose_declares_all_control_plane_dependencies": all(
            marker in base_compose
            for marker in (
                "depends_on:\n            - postgres\n            - redis\n            - soketi",
                "container_name: coolify-db",
                "container_name: coolify-redis",
                "container_name: coolify-realtime",
            )
        ),
        "production_compose_requires_all_dependencies_healthy": all(
            marker in prod_compose
            for marker in (
                "postgres:\n        condition: service_healthy",
                "redis:\n        condition: service_healthy",
                "soketi:\n        condition: service_healthy",
            )
        ),
        "database_defaults_to_coolify_db": (
            "env('DB_HOST', 'coolify-db')" in database_config
        ),
        "redis_defaults_to_coolify_redis": (
            database_config.count("env('REDIS_HOST', 'coolify-redis')") >= 2
        ),
        "queue_defaults_to_redis": (
            "env('QUEUE_CONNECTION', 'redis')" in queue_config
            and "'driver' => 'redis'" in queue_config
        ),
        "ui_update_runs_upgrade_script_via_remote_process": all(
            marker in update_action
            for marker in (
                "remote_process([",
                '"bash /data/coolify/source/upgrade.sh ',
            )
        ),
        "remote_process_resolves_prepare_task": (
            "return resolve(PrepareCoolifyTask::class" in remote_helper
        ),
        "prepare_task_dispatches_and_refreshes_activity": all(
            marker in prepare_task
            for marker in (
                "new CoolifyTask(",
                "dispatch($job);",
                "$this->activity->refresh();",
            )
        ),
        "coolify_task_is_redis_backed_queued_work": all(
            marker in coolify_task
            for marker in (
                "class CoolifyTask implements ShouldBeEncrypted, ShouldQueue",
                "$this->onQueue('high');",
                "resolve(RunRemoteProcess::class",
            )
        ),
        "remote_runner_waits_for_ssh_process": all(
            marker in run_remote
            for marker in (
                "Process::timeout($timeout)->start($this->getCommand()",
                "$processResult = $process->wait();",
            )
        ),
        "remote_runner_persists_output_and_completion_to_database": all(
            marker in run_remote
            for marker in (
                "DB::transaction(function ()",
                "$this->activity->save();",
            )
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    revisions = {
        "baseline": BASELINE_SHA,
        "ai_regression": AI_REGRESSION_SHA,
        "direct_repair": DIRECT_REPAIR_SHA,
        "detached_fix": DETACHED_FIX_SHA,
        "fix_followup": FIX_FOLLOWUP_SHA,
        "pr_carrier": PR_CARRIER_SHA,
        "first_containing_tag": FIRST_CONTAINING_TAG,
    }
    metadata = {
        name: _commit_metadata(repository, revision)
        for name, revision in revisions.items()
    }
    upgrade_sources = {
        name: {
            source_path: _text_blob(repository, revision, source_path)
            for source_path in UPGRADE_PATHS
        }
        for name, revision in revisions.items()
    }
    stop_orders = {
        name: {
            source_path: list(_extract_stop_order(source))
            for source_path, source in sources.items()
        }
        for name, sources in upgrade_sources.items()
    }
    shutdown_evaluations = {
        name: {
            source_path: _evaluate_shutdown_order(tuple(order))
            for source_path, order in paths.items()
        }
        for name, paths in stop_orders.items()
    }

    runtime_sources = {
        source_path: _text_blob(repository, AI_REGRESSION_SHA, source_path)
        for source_path in (
            BASE_COMPOSE_PATH,
            PROD_COMPOSE_PATH,
            UPDATE_ACTION_PATH,
            REMOTE_HELPER_PATH,
            PREPARE_TASK_PATH,
            COOLIFY_TASK_PATH,
            RUN_REMOTE_PATH,
            DATABASE_CONFIG_PATH,
            QUEUE_CONFIG_PATH,
        )
    }
    runtime_contract = _evaluate_runtime_contract(runtime_sources)

    line_origins: dict[str, dict[str, dict[str, object]]] = {}
    for name, revision in (
        ("candidate", AI_REGRESSION_SHA),
        ("repair", DIRECT_REPAIR_SHA),
        ("detached_fix", DETACHED_FIX_SHA),
    ):
        line_origins[name] = {}
        for source_path in UPGRADE_PATHS:
            source = upgrade_sources[
                {
                    "candidate": "ai_regression",
                    "repair": "direct_repair",
                    "detached_fix": "detached_fix",
                }[name]
            ][source_path]
            line_origins[name][source_path] = _blame_line(
                repository,
                revision,
                source_path,
                _line_number(source, "for container in"),
                f"{name} container stop order",
            )
    detached_nohup_origins = {
        source_path: _blame_line(
            repository,
            DETACHED_FIX_SHA,
            source_path,
            _line_number(upgrade_sources["detached_fix"][source_path], "nohup bash -c"),
            "detached fix nohup boundary",
        )
        for source_path in UPGRADE_PATHS
    }

    containing_tags = _containing_tags(repository, AI_REGRESSION_SHA)
    first_tag = containing_tags[0]
    first_tag_resolved_sha = _resolved_commit(repository, first_tag["tag"])

    candidate_to_repair_seconds = _seconds_between(
        str(metadata["ai_regression"]["authored_at"]),
        str(metadata["direct_repair"]["authored_at"]),
    )
    repair_to_detached_fix_seconds = _seconds_between(
        str(metadata["direct_repair"]["authored_at"]),
        str(metadata["detached_fix"]["authored_at"]),
    )

    upgrade_blob_oids = {
        name: {
            source_path: _blob_oid(repository, revision, source_path)
            for source_path in UPGRADE_PATHS
        }
        for name, revision in revisions.items()
    }
    path_states = {
        "candidate_changed_paths": _changed_paths(
            repository, BASELINE_SHA, AI_REGRESSION_SHA
        ),
        "repair_changed_paths": _changed_paths(
            repository, AI_REGRESSION_SHA, DIRECT_REPAIR_SHA
        ),
        "upgrade_blob_oids": upgrade_blob_oids,
    }

    topology_checks = {
        "candidate_has_frozen_baseline_parent": metadata["ai_regression"]["parents"]
        == [BASELINE_SHA],
        "repair_is_direct_child_of_candidate": metadata["direct_repair"]["parents"]
        == [AI_REGRESSION_SHA],
        "detached_fix_is_direct_child_of_repair": metadata["detached_fix"]["parents"]
        == [DIRECT_REPAIR_SHA],
        "candidate_bad_state_lasts_187_seconds": candidate_to_repair_seconds == 187,
        "detached_fix_follows_repair_after_121_seconds": (
            repair_to_detached_fix_seconds == 121
        ),
        "pr_carrier_has_frozen_parent_order": metadata["pr_carrier"]["parents"]
        == [PR_FIRST_PARENT_SHA, PR_SECOND_PARENT_SHA],
        "chain_enters_pr_only_through_second_parent": (
            not _is_ancestor(repository, AI_REGRESSION_SHA, PR_FIRST_PARENT_SHA)
            and not _is_ancestor(repository, DIRECT_REPAIR_SHA, PR_FIRST_PARENT_SHA)
            and not _is_ancestor(repository, DETACHED_FIX_SHA, PR_FIRST_PARENT_SHA)
            and _is_ancestor(repository, AI_REGRESSION_SHA, PR_SECOND_PARENT_SHA)
            and _is_ancestor(repository, DIRECT_REPAIR_SHA, PR_SECOND_PARENT_SHA)
            and _is_ancestor(repository, DETACHED_FIX_SHA, PR_SECOND_PARENT_SHA)
            and _is_ancestor(repository, FIX_FOLLOWUP_SHA, PR_CARRIER_SHA)
        ),
    }

    path_checks = {
        "candidate_changes_only_both_upgrade_scripts": sorted(
            path_states["candidate_changed_paths"]
        )
        == sorted(UPGRADE_PATHS),
        "repair_changes_only_both_upgrade_scripts": sorted(
            path_states["repair_changed_paths"]
        )
        == sorted(UPGRADE_PATHS),
        "repair_exactly_restores_both_baseline_blobs": all(
            upgrade_blob_oids["direct_repair"][source_path]
            == upgrade_blob_oids["baseline"][source_path]
            != upgrade_blob_oids["ai_regression"][source_path]
            for source_path in UPGRADE_PATHS
        ),
        "candidate_owns_both_bad_order_lines": all(
            row["origin_sha"] == AI_REGRESSION_SHA
            for row in line_origins["candidate"].values()
        ),
        "repair_owns_both_restored_order_lines": all(
            row["origin_sha"] == DIRECT_REPAIR_SHA
            for row in line_origins["repair"].values()
        ),
        "detached_fix_owns_both_fixed_order_and_nohup_lines": (
            all(
                row["origin_sha"] == DETACHED_FIX_SHA
                for row in line_origins["detached_fix"].values()
            )
            and all(
                row["origin_sha"] == DETACHED_FIX_SHA
                for row in detached_nohup_origins.values()
            )
        ),
    }

    safe_names = (
        "baseline",
        "direct_repair",
        "detached_fix",
        "fix_followup",
        "pr_carrier",
        "first_containing_tag",
    )
    mechanism_checks = {
        "baseline_stops_control_plane_before_dependencies": all(
            tuple(stop_orders["baseline"][source_path]) == EXPECTED_CONTAINERS
            for source_path in UPGRADE_PATHS
        ),
        "candidate_stops_all_dependencies_before_control_plane": all(
            tuple(stop_orders["ai_regression"][source_path])
            == (*DEPENDENCIES, CONTROL_PLANE)
            for source_path in UPGRADE_PATHS
        ),
        "candidate_creates_three_dependency_contract_violations_per_script": all(
            shutdown_evaluations["ai_regression"][source_path]["violation_count"] == 3
            and shutdown_evaluations["ai_regression"][source_path]["violation_steps"]
            == [1, 2, 3]
            for source_path in UPGRADE_PATHS
        ),
        "baseline_repair_and_later_fix_states_are_dependency_safe": all(
            shutdown_evaluations[name][source_path]["dependency_safe"] is True
            for name in safe_names
            for source_path in UPGRADE_PATHS
        ),
        "candidate_does_not_detach_before_eventually_stopping_control_plane": all(
            "nohup bash -c" not in upgrade_sources["ai_regression"][source_path]
            and stop_orders["ai_regression"][source_path][-1] == CONTROL_PLANE
            for source_path in UPGRADE_PATHS
        ),
        "actual_fix_detaches_and_preserves_dependency_safe_order": all(
            "nohup bash -c" in upgrade_sources["detached_fix"][source_path]
            and tuple(stop_orders["detached_fix"][source_path]) == EXPECTED_CONTAINERS
            for source_path in UPGRADE_PATHS
        ),
    }

    release_checks = {
        "first_candidate_containing_tag_is_frozen_beta_455": (
            first_tag["tag"] == FIRST_CONTAINING_TAG
            and first_tag_resolved_sha == FIRST_CONTAINING_TAG_SHA
        ),
        "first_tag_contains_candidate_repair_and_actual_fix": all(
            _is_ancestor(repository, revision, first_tag_resolved_sha)
            for revision in (AI_REGRESSION_SHA, DIRECT_REPAIR_SHA, DETACHED_FIX_SHA)
        ),
        "first_tag_contains_only_dependency_safe_detached_script_state": all(
            shutdown_evaluations["first_containing_tag"][source_path]["dependency_safe"]
            is True
            and "nohup bash -c" in upgrade_sources["first_containing_tag"][source_path]
            for source_path in UPGRADE_PATHS
        ),
    }

    semantic_checks = {
        "runtime_dependency_and_execution_contract_is_fully_present": all(
            runtime_contract.values()
        ),
        "candidate_repair_and_actual_fix_have_explicit_claude_signal": all(
            metadata[name]["explicit_claude_signal"] is True
            for name in ("ai_regression", "direct_repair", "detached_fix")
        ),
        "candidate_message_claims_dependency_first_ui_upgrade_fix": all(
            marker in str(metadata["ai_regression"]["message"]).lower()
            for marker in (
                "stop dependencies first",
                "stopping the main coolify container",
                "triggered from coolify ui",
            )
        ),
        "repair_message_explicitly_restores_original_order": (
            "revert container stop order to original"
            in str(metadata["direct_repair"]["message"]).lower()
        ),
        "actual_fix_message_identifies_ssh_disconnect_and_nohup": all(
            marker in str(metadata["detached_fix"]["message"]).lower()
            for marker in ("ssh connection is lost", "using nohup ensures")
        ),
    }

    check_groups = {
        "topology": topology_checks,
        "exact_path_repair": path_checks,
        "shutdown_order_mechanism": mechanism_checks,
        "runtime_and_claim_boundary": semantic_checks,
        "release_exposure": release_checks,
    }
    witness_passed = all(
        value is True for group in check_groups.values() for value in group.values()
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_upgrade_shutdown_order_regression_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_REGRESSION_SHA,
        "fix_sha": DIRECT_REPAIR_SHA,
        "actual_mechanism_fix_sha": DETACHED_FIX_SHA,
        "pr_carrier_sha": PR_CARRIER_SHA,
        "metadata": metadata,
        "timing": {
            "candidate_to_direct_repair_seconds": candidate_to_repair_seconds,
            "direct_repair_to_detached_fix_seconds": repair_to_detached_fix_seconds,
        },
        "topology": topology_checks,
        "path_states": path_states,
        "stop_orders": stop_orders,
        "shutdown_evaluations": shutdown_evaluations,
        "runtime_contract": runtime_contract,
        "line_origins": {
            **line_origins,
            "detached_fix_nohup": detached_nohup_origins,
        },
        "containing_tags": containing_tags,
        "first_containing_tag_resolved_sha": first_tag_resolved_sha,
        "check_groups": check_groups,
        "source_blobs": [
            *(
                _blob_record(repository, revision, source_path)
                for revision in revisions.values()
                for source_path in UPGRADE_PATHS
            ),
            *(
                _blob_record(repository, AI_REGRESSION_SHA, source_path)
                for source_path in runtime_sources
            ),
        ],
        "confirmed_edge": {
            "adjudication": ("CONFIRMED_AI_UPGRADE_DEPENDENCY_INVERTED_SHUTDOWN_ORDER"),
            "candidate_sha": AI_REGRESSION_SHA,
            "fix_sha": DIRECT_REPAIR_SHA,
            "mechanism_group": "upgrade_dependency_inverted_shutdown_order",
        },
        "counting": {
            "candidate_level_true_positive_count": 1,
            "tagged_bad_state_exposure_count": 0,
            "production_release_exposure_count": 0,
            "preexisting_ssh_disconnect_defect_origin_not_attributed_to_candidate": True,
            "manual_cdn_sync_during_187_second_window_unknown": True,
            "security_vulnerability_increment_not_asserted": True,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The AI-authored candidate f3ccacb changed both upgrade scripts from "
            "stopping the Coolify control-plane container before its declared "
            "PostgreSQL, Redis, and realtime dependencies to stopping all three "
            "dependencies while Coolify remained running. The frozen Compose and "
            "runtime call chain show that Coolify requires those services and that "
            "UI upgrades execute as queued SSH work whose progress and completion "
            "are persisted through Redis and PostgreSQL. The candidate therefore "
            "introduced three deterministic dependency-contract violation states "
            "per script, yet still stopped Coolify last without detaching and did "
            "not solve the pre-existing SSH-disconnect defect. Its direct AI-authored "
            "child f4dbae1 exactly restored both baseline blobs after 187 seconds; "
            "1f7888f then fixed the original problem with nohup while retaining the "
            "dependency-safe order. The first tag containing the candidate already "
            "contains the repair and detached fix. This confirms one branch-local "
            "AI shutdown-order regression, not origin of the earlier SSH defect, a "
            "tagged bad-state release, production exposure, or a security advisory."
        ),
        "witness_passed": witness_passed,
    }
    _atomic_json(args.output, payload)
    print("Coolify upgrade shutdown-order witness frozen")
    print(f"  candidate      : {AI_REGRESSION_SHA}")
    print(f"  direct repair  : {DIRECT_REPAIR_SHA}")
    print(f"  actual fix     : {DETACHED_FIX_SHA}")
    print(f"  first tag      : {first_tag['tag']}")
    print(f"  witness passed : {witness_passed}")
    print(f"  output         : {args.output}")
    return 0 if witness_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
