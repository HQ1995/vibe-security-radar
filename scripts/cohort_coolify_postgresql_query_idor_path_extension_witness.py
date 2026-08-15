#!/usr/bin/env python3
"""Freeze the Coolify PostgreSQL query-state IDOR path-extension witness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


BASELINE_SHA = "20c6f61858aff70e69fc4e47e1c9f243b833b4ce"
AI_PATH_EXTENSION_SHA = "679833a0a6a2799d2086e0965dade0703587c3c5"
SECURITY_REPAIR_SHA = "e36622fdfb60df2bb733c37d6f0f4f7ac8b61486"
SOURCE_PATH = "app/Livewire/Project/New/Select.php"
REPAIR_TEST_PATH = "tests/Feature/CrossTeamIdorServerProjectTest.php"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _git(repository: Path, arguments: list[str], *, text: bool = False) -> bytes | str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"git {' '.join(arguments)} failed: {exc}") from exc
    if completed.returncode != 0:
        reason = completed.stderr.decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"git {' '.join(arguments)} failed: {reason}")
    if text:
        return completed.stdout.decode("utf-8", errors="strict")
    return completed.stdout


def _git_blob(repository: Path, revision: str, source_path: str) -> bytes:
    value = _git(repository, ["show", f"{revision}:{source_path}"])
    assert isinstance(value, bytes)
    if not value:
        raise SystemExit(f"empty Git blob: {revision}:{source_path}")
    return value


def _explicit_claude_signal(author_name: str, author_email: str, message: str) -> bool:
    normalized = f"{author_name}\n{author_email}\n{message}".lower()
    return bool(
        re.search(r"co-authored-by:\s*claude\b", message, re.IGNORECASE)
        or "generated with [claude code]" in normalized
        or "noreply@anthropic.com" in normalized
        or message.strip().casefold()
        == "changes auto-committed by conductor"
    )


def _commit_metadata(repository: Path, revision: str) -> dict[str, object]:
    value = _git(
        repository,
        ["show", "-s", "--format=%H%x00%P%x00%an%x00%ae%x00%aI%x00%B", revision],
        text=True,
    )
    assert isinstance(value, str)
    fields = value.rstrip("\n").split("\x00", 5)
    if len(fields) != 6:
        raise SystemExit(f"unexpected commit metadata for {revision}")
    sha, parents, author_name, author_email, authored_at, message = fields
    return {
        "sha": sha,
        "parents": parents.split(),
        "author_name": author_name,
        "author_email": author_email,
        "authored_at": authored_at,
        "message": message.rstrip(),
        "explicit_claude_signal": _explicit_claude_signal(
            author_name, author_email, message
        ),
    }


def _is_ancestor(repository: Path, ancestor: str, descendant: str) -> bool:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "merge-base",
            "--is-ancestor",
            ancestor,
            descendant,
        ],
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode not in {0, 1}:
        reason = completed.stderr.decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"cannot check ancestry {ancestor}..{descendant}: {reason}")
    return completed.returncode == 0


def _php_method_region(source: str, method_name: str) -> str:
    start = re.search(
        rf"^\s*(?:public|private|protected) function {re.escape(method_name)}\s*\(",
        source,
        re.MULTILINE,
    )
    if start is None:
        raise ValueError(f"PHP method is absent: {method_name}")
    following = re.search(
        r"^\s*(?:public|private|protected) function \w+\s*\(",
        source[start.end() :],
        re.MULTILINE,
    )
    end = len(source) if following is None else start.end() + following.start()
    return source[start.start() : end]


def _evaluate_source(source: str) -> dict[str, object]:
    mount = _php_method_region(source, "mount")
    postgresql_redirect = _php_method_region(source, "setPostgresqlType")
    query_contract = {
        "type_read_from_request": "request()->query('type')" in mount,
        "server_id_read_from_request": "request()->query('server_id')" in mount,
        "destination_read_from_request": "request()->query('destination')" in mount,
        "postgresql_branch_requires_query_values": bool(
            re.search(
                r"if\s*\(\s*\$queryType\s*===\s*'postgresql'\s*&&\s*"
                r"\$queryServerId\s*!==\s*null\s*&&\s*\$queryDestination\s*\)",
                mount,
            )
        ),
        "server_id_is_url_state": bool(
            re.search(r"protected \$queryString\s*=\s*\[[^]]*'server_id'", source, re.DOTALL)
        ),
        "type_is_url_state": "'type' => ['except' => '']" in source,
        "destination_is_url_state": (
            "'destination_uuid' => ['except' => '', 'as' => 'destination']" in source
        ),
    }
    lookup_contract = {
        "unscoped_server_find": "Server::find($queryServerId)" in mount,
        "team_scoped_server_find": (
            "Server::ownedByCurrentTeam()->find($queryServerId)" in mount
        ),
        "unscoped_project_lookup": (
            "Project::whereUuid($projectUuid)->firstOrFail()" in mount
        ),
        "team_scoped_project_lookup": (
            "Project::ownedByCurrentTeam()->whereUuid($projectUuid)->firstOrFail()"
            in mount
        ),
    }
    transition_contract = {
        "query_values_copy_to_livewire_state": all(
            marker in mount
            for marker in (
                "$this->type = $queryType",
                "$this->server_id = $queryServerId",
                "$this->destination_uuid = $queryDestination",
            )
        ),
        "query_branch_enters_postgresql_version_selection": (
            "$this->current_step = 'select-postgresql-type'" in mount
        ),
        "preexisting_version_selection_redirect_propagates_ids": all(
            marker in postgresql_redirect
            for marker in (
                "'destination' => $this->destination_uuid",
                "'server_id' => $this->server_id",
                "'database_image' => $this->postgresql_type",
            )
        ),
    }
    query_path_shape = bool(
        all(query_contract.values())
        and transition_contract["query_values_copy_to_livewire_state"]
        and transition_contract["query_branch_enters_postgresql_version_selection"]
    )
    return {
        "query_contract": query_contract,
        "lookup_contract": lookup_contract,
        "transition_contract": transition_contract,
        "query_driven_unscoped_server_load_active": bool(
            query_path_shape and lookup_contract["unscoped_server_find"]
        ),
        "query_driven_server_load_team_scoped": bool(
            query_path_shape and lookup_contract["team_scoped_server_find"]
        ),
    }


def _execute_revision(
    repository: Path, *, label: str, revision: str
) -> dict[str, object]:
    blob = _git_blob(repository, revision, SOURCE_PATH)
    metadata = _commit_metadata(repository, revision)
    return {
        "label": label,
        "revision": revision,
        "resolved_commit": metadata["sha"],
        "blob_sha256": hashlib.sha256(blob).hexdigest(),
        "evaluation": _evaluate_source(blob.decode("utf-8", errors="strict")),
    }


def _line_number(source: str, marker: str) -> int:
    matches = [
        index + 1
        for index, line in enumerate(source.splitlines())
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one marker {marker!r}, found {matches}")
    return matches[0]


def _line_in_method(source: str, method_name: str, marker: str) -> int:
    lines = source.splitlines()
    method_starts = [
        index
        for index, line in enumerate(lines)
        if re.search(
            rf"(?:public|private|protected) function {re.escape(method_name)}\s*\(",
            line,
        )
    ]
    if len(method_starts) != 1:
        raise SystemExit(
            f"expected one method marker for {method_name}, found {method_starts}"
        )
    start = method_starts[0]
    end = next(
        (
            index
            for index, line in enumerate(lines[start + 1 :], start=start + 1)
            if re.search(r"(?:public|private|protected) function \w+\s*\(", line)
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


def _blame_line(
    repository: Path, revision: str, line: int, marker: str
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
            SOURCE_PATH,
        ],
        text=True,
    )
    assert isinstance(value, str)
    return {
        "path": SOURCE_PATH,
        "line": line,
        "marker": marker,
        "origin_sha": value.split(None, 1)[0].lstrip("^"),
    }


def _repair_test_contract(source: str) -> dict[str, bool]:
    return {
        "advisory_named": "GHSA-qfcc-2fm3-9q42" in source,
        "attacker_and_victim_teams_present": (
            "// Attacker: Team A" in source and "// Victim: Team B" in source
        ),
        "cross_team_server_case_present": (
            "loadDestinations cannot access server from another team" in source
        ),
        "victim_server_id_used": (
            "->set('selectedServerId', $this->serverB->id)" in source
        ),
        "own_team_server_positive_control_present": (
            "boarding mount can load own team server via selectedExistingServer"
            in source
        ),
    }


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise SystemExit(f"output already exists: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    runs = [
        _execute_revision(repository, label="baseline", revision=BASELINE_SHA),
        _execute_revision(
            repository,
            label="direct_ai_path_extension",
            revision=AI_PATH_EXTENSION_SHA,
        ),
        _execute_revision(
            repository,
            label="security_repair",
            revision=SECURITY_REPAIR_SHA,
        ),
    ]
    evaluations = {str(run["label"]): run["evaluation"] for run in runs}
    commits = {
        revision: _commit_metadata(repository, revision)
        for revision in (AI_PATH_EXTENSION_SHA, SECURITY_REPAIR_SHA)
    }
    ancestry = {
        "baseline_reaches_ai_path_extension": _is_ancestor(
            repository, BASELINE_SHA, AI_PATH_EXTENSION_SHA
        ),
        "ai_path_extension_reaches_security_repair": _is_ancestor(
            repository, AI_PATH_EXTENSION_SHA, SECURITY_REPAIR_SHA
        ),
    }
    candidate_source = _git_blob(
        repository, AI_PATH_EXTENSION_SHA, SOURCE_PATH
    ).decode("utf-8")
    repair_source = _git_blob(repository, SECURITY_REPAIR_SHA, SOURCE_PATH).decode(
        "utf-8"
    )
    candidate_markers = (
        ("request()->query('type')", None),
        ("request()->query('server_id')", None),
        ("request()->query('destination')", None),
        ("Server::find($queryServerId)", None),
        ("$this->current_step = 'select-postgresql-type'", "mount"),
    )
    repair_markers = (
        "Project::ownedByCurrentTeam()->whereUuid($projectUuid)->firstOrFail()",
        "Server::ownedByCurrentTeam()->find($queryServerId)",
    )
    line_origins = {
        **{
            f"candidate_{index}": _blame_line(
                repository,
                AI_PATH_EXTENSION_SHA,
                (
                    _line_in_method(candidate_source, method_name, marker)
                    if method_name is not None
                    else _line_number(candidate_source, marker)
                ),
                marker,
            )
            for index, (marker, method_name) in enumerate(candidate_markers, start=1)
        },
        **{
            f"repair_{index}": _blame_line(
                repository,
                SECURITY_REPAIR_SHA,
                _line_number(repair_source, marker),
                marker,
            )
            for index, marker in enumerate(repair_markers, start=1)
        },
    }
    repair_test = _repair_test_contract(
        _git_blob(repository, SECURITY_REPAIR_SHA, REPAIR_TEST_PATH).decode("utf-8")
    )
    baseline = evaluations["baseline"]
    candidate = evaluations["direct_ai_path_extension"]
    repair = evaluations["security_repair"]
    witness_passed = bool(
        commits[AI_PATH_EXTENSION_SHA]["explicit_claude_signal"] is True
        and commits[SECURITY_REPAIR_SHA]["explicit_claude_signal"] is True
        and commits[AI_PATH_EXTENSION_SHA]["parents"] == [BASELINE_SHA]
        and all(ancestry.values())
        and baseline["query_driven_unscoped_server_load_active"] is False
        and baseline["transition_contract"][
            "preexisting_version_selection_redirect_propagates_ids"
        ]
        is True
        and candidate["query_driven_unscoped_server_load_active"] is True
        and candidate["query_driven_server_load_team_scoped"] is False
        and repair["query_driven_unscoped_server_load_active"] is False
        and repair["query_driven_server_load_team_scoped"] is True
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
        "artifact_kind": "coolify_postgresql_query_idor_path_extension_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "advisory": "GHSA-qfcc-2fm3-9q42",
        "commit_metadata": commits,
        "ancestry": ancestry,
        "line_origins": line_origins,
        "repair_test_contract": repair_test,
        "runs": runs,
        "witness_passed": witness_passed,
        "causal_adjudication": "CONFIRMED_DIRECT_AI_VULNERABLE_PATH_EXTENSION",
        "causal_role": "query_state_to_unscoped_server_model_load",
        "counting": {
            "candidate_level_true_positive": True,
            "mechanism_level_true_positive": False,
            "cve_specific_causal_member": True,
            "unique_advisory_increment_not_asserted": True,
            "runtime_exploit_not_asserted": True,
            "reason": (
                "The AI delta adds a query-driven PostgreSQL branch that loads an "
                "attacker-selected server without team scope; the later GHSA repair "
                "changes that exact lookup to ownedByCurrentTeam."
            ),
        },
        "claim_boundary": (
            "This witness proves a directly Claude-attributed vulnerable source-path "
            "extension for GHSA-qfcc-2fm3-9q42: attacker-controlled query values enter "
            "a newly added PostgreSQL branch and an unscoped Server::find, and the "
            "later repair scopes that exact lookup. The version-selection redirect "
            "already existed in the parent, and the repair covers a broader family of "
            "server/project IDORs, so this commit is not the earliest mechanism root "
            "and does not add a unique advisory. The repair suite establishes the "
            "cross-team server threat model but does not contain a Select-specific "
            "regression case. This is a compositional source/test witness, not a "
            "locally executed Laravel exploit or proof of downstream code execution."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify PostgreSQL query IDOR path-extension witness frozen")
    print(
        "  baseline query/server path : "
        f"{baseline['query_driven_unscoped_server_load_active']}"
    )
    print(
        "  candidate query/server path: "
        f"{candidate['query_driven_unscoped_server_load_active']}"
    )
    print(
        "  repair path team-scoped    : "
        f"{repair['query_driven_server_load_team_scoped']}"
    )
    print(f"  repair test contract       : {all(repair_test.values())}")
    print(f"  witness                    : {'PASS' if witness_passed else 'FAIL'}")
    print(f"  output                     : {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
