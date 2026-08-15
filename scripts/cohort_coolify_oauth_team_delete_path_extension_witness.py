#!/usr/bin/env python3
"""Freeze the Coolify OAuth team-deletion authorization path witness."""

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
    _php_method_region,
)


BASELINE_SHA = "366ff95893572d4a45221ef2628a5474bbccc041"
AI_PATH_EXTENSION_SHA = "b0d50669b1b8929b3c82ee4103fb3d1f2a1b0bf1"
SECURITY_REPAIR_SHA = "94dfd6a54ec274f525766a97892852fb275b3401"
NAVBAR_PATH = "app/Livewire/NavbarDeleteTeam.php"
HELPER_PATH = "bootstrap/helpers/shared.php"
MODAL_PATH = "resources/views/components/modal-confirmation.blade.php"
POLICY_PATH = "app/Policies/TeamPolicy.php"
REPAIR_TEST_PATH = "tests/Feature/NavbarDeleteTeamAuthorizationTest.php"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _evaluate_navbar(source: str) -> dict[str, bool]:
    method = _php_method_region(source, "delete")
    return {
        "delete_is_public_livewire_action": bool(
            re.search(r"public function delete\s*\(", method)
        ),
        "uses_direct_password_hash_check": "Hash::check($password" in method,
        "uses_oauth_aware_password_helper": (
            "verifyPasswordConfirmation($password, $this)" in method
        ),
        "deletes_current_team": bool(
            "$currentTeam = currentTeam();" in method
            and "$currentTeam->delete();" in method
        ),
        "has_team_delete_authorization": (
            "$this->authorize('delete', $currentTeam)" in method
        ),
    }


def _global_function_region(source: str, function_name: str) -> str:
    match = re.search(
        rf"^function {re.escape(function_name)}\s*\(", source, re.MULTILINE
    )
    if match is None:
        raise ValueError(f"function not found: {function_name}")
    next_match = re.search(r"^function \w+\s*\(", source[match.end() :], re.MULTILINE)
    end = len(source) if next_match is None else match.end() + next_match.start()
    return source[match.start() : end]


def _evaluate_helper(source: str) -> dict[str, bool]:
    skip = None
    verify = None
    try:
        skip = _global_function_region(source, "shouldSkipPasswordConfirmation")
        verify = _global_function_region(source, "verifyPasswordConfirmation")
    except ValueError:
        pass
    return {
        "oauth_skip_helper_present": skip is not None,
        "passwordless_user_triggers_skip": bool(
            skip is not None and "if (! Auth::user()?->hasPassword())" in skip
        ),
        "verification_returns_true_on_skip": bool(
            verify is not None
            and "if (shouldSkipPasswordConfirmation())" in verify
            and re.search(
                r"if\s*\(shouldSkipPasswordConfirmation\(\)\)\s*\{\s*return true;",
                verify,
                re.DOTALL,
            )
        ),
    }


def _evaluate_modal(source: str) -> dict[str, bool]:
    return {
        "modal_uses_oauth_skip": (
            "$skipPasswordConfirmation = shouldSkipPasswordConfirmation();" in source
        ),
        "modal_omits_password_step_on_skip": (
            "$confirmWithPassword && !$skipPasswordConfirmation" in source
        ),
        "modal_passes_empty_password_on_skip": (
            "params.push(this.confirmWithPassword ? this.password : '');" in source
        ),
    }


def _evaluate_policy(source: str) -> dict[str, bool]:
    method = _php_method_region(source, "delete")
    return {
        "delete_policy_requires_team_membership": (
            "teams->contains('id', $team->id)" in method
        ),
        "delete_policy_requires_admin_or_owner": (
            "$user->isAdmin() || $user->isOwner()" in method
        ),
    }


def _evaluate_repair_test(source: str) -> dict[str, bool]:
    return {
        "member_negative_case_present": (
            "test('member cannot delete team via navbar'" in source
        ),
        "member_invokes_livewire_delete": bool(
            re.search(
                r"actingAs\(\$this->member\).*?"
                r"Livewire::test\(NavbarDeleteTeam::class\).*?"
                r"->call\('delete', 'password'\)",
                source,
                re.DOTALL,
            )
        ),
        "team_survival_asserted": (
            "expect(Team::find($this->teamToDelete->id))->not->toBeNull();" in source
        ),
        "owner_positive_case_present": (
            "test('owner can delete team via navbar'" in source
        ),
    }


def _line_in_method(source: str, method_name: str, marker: str) -> int:
    lines = source.splitlines()
    starts = [
        index
        for index, line in enumerate(lines)
        if re.search(
            rf"(?:public|private|protected)?\s*function {re.escape(method_name)}\s*\(",
            line,
        )
    ]
    if len(starts) != 1:
        raise SystemExit(f"expected one method {method_name}, found {starts}")
    start = starts[0]
    end = next(
        (
            index
            for index, line in enumerate(lines[start + 1 :], start=start + 1)
            if re.search(r"(?:public|private|protected)?\s*function \w+\s*\(", line)
        ),
        len(lines),
    )
    matches = [
        index + 1
        for index, line in enumerate(lines[start:end], start=start)
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"expected one {marker!r} in {method_name}, found {matches}"
        )
    return matches[0]


def _line_number(source: str, marker: str) -> int:
    matches = [
        index + 1
        for index, line in enumerate(source.splitlines())
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one marker {marker!r}, found {matches}")
    return matches[0]


def _blame_line(
    repository: Path,
    revision: str,
    source_path: str,
    line: int,
    marker: str,
) -> dict[str, object]:
    value = _git(
        repository,
        [
            "blame",
            "--line-porcelain",
            "-L",
            f"{line},{line}",
            revision,
            "--",
            source_path,
        ],
        text=True,
    )
    assert isinstance(value, str)
    return {
        "path": source_path,
        "line": line,
        "marker": marker,
        "origin_sha": value.split(None, 1)[0].lstrip("^"),
    }


def _run(repository: Path, label: str, revision: str) -> dict[str, object]:
    blobs = {
        path: _git_blob(repository, revision, path)
        for path in (NAVBAR_PATH, HELPER_PATH, MODAL_PATH)
    }
    return {
        "label": label,
        "revision": revision,
        "blob_sha256": {
            path: hashlib.sha256(blob).hexdigest() for path, blob in blobs.items()
        },
        "evaluation": {
            "navbar": _evaluate_navbar(blobs[NAVBAR_PATH].decode("utf-8")),
            "helper": _evaluate_helper(blobs[HELPER_PATH].decode("utf-8")),
            "modal": _evaluate_modal(blobs[MODAL_PATH].decode("utf-8")),
        },
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    runs = [
        _run(repository, "baseline", BASELINE_SHA),
        _run(repository, "direct_ai_path_extension", AI_PATH_EXTENSION_SHA),
        _run(repository, "security_repair", SECURITY_REPAIR_SHA),
    ]
    evaluations = {str(run["label"]): run["evaluation"] for run in runs}
    candidate_navbar = _git_blob(
        repository, AI_PATH_EXTENSION_SHA, NAVBAR_PATH
    ).decode("utf-8")
    candidate_helper = _git_blob(
        repository, AI_PATH_EXTENSION_SHA, HELPER_PATH
    ).decode("utf-8")
    candidate_modal = _git_blob(
        repository, AI_PATH_EXTENSION_SHA, MODAL_PATH
    ).decode("utf-8")
    repair_navbar = _git_blob(
        repository, SECURITY_REPAIR_SHA, NAVBAR_PATH
    ).decode("utf-8")
    repair_policy_source = _git_blob(
        repository, SECURITY_REPAIR_SHA, POLICY_PATH
    ).decode("utf-8")
    repair_test_source = _git_blob(
        repository, SECURITY_REPAIR_SHA, REPAIR_TEST_PATH
    ).decode("utf-8")
    policy = _evaluate_policy(repair_policy_source)
    repair_test = _evaluate_repair_test(repair_test_source)
    line_origins = {
        "candidate_navbar_helper_call": _blame_line(
            repository,
            AI_PATH_EXTENSION_SHA,
            NAVBAR_PATH,
            _line_in_method(
                candidate_navbar,
                "delete",
                "verifyPasswordConfirmation($password, $this)",
            ),
            "verifyPasswordConfirmation($password, $this)",
        ),
        "candidate_passwordless_skip": _blame_line(
            repository,
            AI_PATH_EXTENSION_SHA,
            HELPER_PATH,
            _line_in_method(
                candidate_helper,
                "shouldSkipPasswordConfirmation",
                "if (! Auth::user()?->hasPassword())",
            ),
            "if (! Auth::user()?->hasPassword())",
        ),
        "candidate_modal_skip": _blame_line(
            repository,
            AI_PATH_EXTENSION_SHA,
            MODAL_PATH,
            _line_number(
                candidate_modal,
                "$skipPasswordConfirmation = shouldSkipPasswordConfirmation();",
            ),
            "$skipPasswordConfirmation = shouldSkipPasswordConfirmation();",
        ),
        "repair_team_delete_authorization": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            NAVBAR_PATH,
            _line_in_method(
                repair_navbar,
                "delete",
                "$this->authorize('delete', $currentTeam)",
            ),
            "$this->authorize('delete', $currentTeam)",
        ),
        "repair_member_regression_test": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            REPAIR_TEST_PATH,
            _line_number(
                repair_test_source,
                "test('member cannot delete team via navbar'",
            ),
            "test('member cannot delete team via navbar'",
        ),
    }
    metadata = _commit_metadata(repository, AI_PATH_EXTENSION_SHA)
    baseline = evaluations["baseline"]
    candidate = evaluations["direct_ai_path_extension"]
    repair = evaluations["security_repair"]
    witness_passed = bool(
        metadata["explicit_claude_signal"] is True
        and metadata["parents"] == [BASELINE_SHA]
        and _is_ancestor(repository, AI_PATH_EXTENSION_SHA, SECURITY_REPAIR_SHA)
        and baseline["navbar"]["uses_direct_password_hash_check"] is True
        and baseline["navbar"]["deletes_current_team"] is True
        and baseline["navbar"]["has_team_delete_authorization"] is False
        and baseline["helper"]["oauth_skip_helper_present"] is False
        and candidate["navbar"]["uses_oauth_aware_password_helper"] is True
        and candidate["navbar"]["deletes_current_team"] is True
        and candidate["navbar"]["has_team_delete_authorization"] is False
        and all(candidate["helper"].values())
        and all(candidate["modal"].values())
        and repair["navbar"]["has_team_delete_authorization"] is True
        and all(policy.values())
        and all(repair_test.values())
        and all(
            value["origin_sha"] == AI_PATH_EXTENSION_SHA
            for key, value in line_origins.items()
            if key.startswith("candidate_")
        )
        and all(
            value["origin_sha"] == SECURITY_REPAIR_SHA
            for key, value in line_origins.items()
            if key.startswith("repair_")
        )
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_oauth_team_delete_path_extension_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": AI_PATH_EXTENSION_SHA,
        "fix_sha": SECURITY_REPAIR_SHA,
        "candidate_metadata": metadata,
        "line_origins": line_origins,
        "runs": runs,
        "repair_policy": policy,
        "repair_test": repair_test,
        "witness_passed": witness_passed,
        "causal_adjudication": "CONFIRMED_DIRECT_AI_VULNERABLE_PATH_EXTENSION",
        "causal_role": "oauth_passwordless_user_extension_to_unguarded_team_delete",
        "counting": {
            "candidate_level_true_positive": True,
            "mechanism_level_true_positive": False,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The Claude delta explicitly makes destructive Livewire actions usable "
            "by passwordless OAuth users: both the modal and backend helper skip the "
            "password step. NavbarDeleteTeam then deletes currentTeam without a "
            "role authorization check. The later repair keeps the OAuth helper but "
            "adds authorize('delete', currentTeam), backs it with an admin/owner "
            "policy, and adds a member-negative Livewire regression test. Ordinary "
            "password users could already pass their own password before the AI "
            "change, so this is an affected-user path extension rather than the "
            "earliest team-deletion authorization mechanism root. This is a source "
            "and repair-test witness, not a locally executed OAuth exploit or a new "
            "advisory claim."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify OAuth team-delete path-extension witness frozen")
    print(
        "  baseline OAuth skip : "
        f"{baseline['helper']['oauth_skip_helper_present']}"
    )
    print(
        "  candidate OAuth skip: "
        f"{candidate['helper']['passwordless_user_triggers_skip']}"
    )
    print(
        "  repair authorization: "
        f"{repair['navbar']['has_team_delete_authorization']}"
    )
    print(f"  witness             : {'PASS' if witness_passed else 'FAIL'}")
    print(f"  output              : {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
