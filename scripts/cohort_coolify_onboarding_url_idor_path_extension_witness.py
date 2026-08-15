#!/usr/bin/env python3
"""Freeze the Coolify onboarding URL-state IDOR path-extension witness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


BASELINE_SHA = "821aa6a5317f46c34934e5e89b6cbdf61f6c562d"
AI_PATH_EXTENSION_SHA = "7a008c859ad68332de72683ddb751e40a6487c38"
SECURITY_REPAIR_SHA = "e36622fdfb60df2bb733c37d6f0f4f7ac8b61486"
SOURCE_PATH = "app/Livewire/Boarding/Index.php"
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


def _url_bound(source: str, property_name: str) -> bool:
    return bool(
        re.search(
            rf"#\[\\Livewire\\Attributes\\Url\(keep:\s*true\)\]\s*"
            rf"public\s+\?int\s+\${re.escape(property_name)}\s*=\s*null\s*;",
            source,
        )
    )


def _lookup_contract(body: str, model: str, property_name: str) -> dict[str, bool]:
    target = rf"\$this->{re.escape(property_name)}"
    return {
        "unscoped_find": bool(
            re.search(rf"{model}::find\(\s*{target}\s*\)", body)
        ),
        "team_scoped_find": bool(
            re.search(
                rf"{model}::ownedByCurrentTeam\(\)->find\(\s*{target}\s*\)",
                body,
            )
        ),
    }


def _optional_method_lookup_contract(
    source: str,
    method_name: str,
    model: str,
    property_name: str,
) -> dict[str, bool]:
    try:
        body = _php_method_region(source, method_name)
    except ValueError:
        return {"unscoped_find": False, "team_scoped_find": False}
    return _lookup_contract(body, model, property_name)


def _evaluate_source(source: str) -> dict[str, object]:
    mount = _php_method_region(source, "mount")
    mount_server = _lookup_contract(
        mount, "Server", "selectedExistingServer"
    )
    mount_project = _lookup_contract(mount, "Project", "selectedProject")
    legacy_server = _optional_method_lookup_contract(
        source,
        "selectExistingServer",
        "Server",
        "selectedExistingServer",
    )
    legacy_project = _optional_method_lookup_contract(
        source,
        "selectExistingProject",
        "Project",
        "selectedProject",
    )
    server_url_bound = _url_bound(source, "selectedExistingServer")
    project_url_bound = _url_bound(source, "selectedProject")
    return {
        "url_state": {
            "selected_existing_server": server_url_bound,
            "selected_project": project_url_bound,
        },
        "mount_server_lookup": mount_server,
        "mount_project_lookup": mount_project,
        "preexisting_public_method_server_lookup": legacy_server,
        "preexisting_public_method_project_lookup": legacy_project,
        "url_mount_cross_team_path_active": bool(
            server_url_bound
            and project_url_bound
            and mount_server["unscoped_find"]
            and mount_project["unscoped_find"]
        ),
        "url_mount_cross_team_path_blocked": bool(
            server_url_bound
            and project_url_bound
            and mount_server["team_scoped_find"]
            and mount_project["team_scoped_find"]
        ),
        "underlying_unscoped_public_method_mechanism_present": bool(
            legacy_server["unscoped_find"] and legacy_project["unscoped_find"]
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


def _line_number(source: str, marker: str, *, occurrence: int = 1) -> int:
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


def _blame_line(
    repository: Path,
    revision: str,
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
        "server_mount_case_present": (
            "boarding mount cannot load server from another team via selectedExistingServer"
            in source
        ),
        "server_mount_uses_victim_id": (
            "'selectedExistingServer' => $this->serverB->id" in source
        ),
        "project_mount_case_present": (
            "boarding mount cannot load project from another team via selectedProject"
            in source
        ),
        "project_mount_uses_victim_id": (
            "'selectedProject' => $this->projectB->id" in source
        ),
        "cross_team_objects_remain_null": (
            source.count("->toBeNull();") >= 2
        ),
        "own_team_positive_controls_present": (
            "boarding mount can load own team server via selectedExistingServer"
            in source
            and "boarding selectExistingProject can load own team project" in source
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
    candidate_url_marker = "#[\\Livewire\\Attributes\\Url(keep: true)]"
    line_origins = {
        "candidate_first_url_binding": _blame_line(
            repository,
            AI_PATH_EXTENSION_SHA,
            _line_number(candidate_source, candidate_url_marker),
            candidate_url_marker,
        ),
        "candidate_mount_server_lookup": _blame_line(
            repository,
            AI_PATH_EXTENSION_SHA,
            _line_in_method(
                candidate_source,
                "mount",
                "Server::find($this->selectedExistingServer)",
            ),
            "Server::find($this->selectedExistingServer)",
        ),
        "candidate_mount_project_lookup": _blame_line(
            repository,
            AI_PATH_EXTENSION_SHA,
            _line_in_method(
                candidate_source,
                "mount",
                "Project::find($this->selectedProject)",
            ),
            "Project::find($this->selectedProject)",
        ),
        "repair_mount_server_scope": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            _line_in_method(
                repair_source,
                "mount",
                "Server::ownedByCurrentTeam()->find($this->selectedExistingServer)",
            ),
            "Server::ownedByCurrentTeam()->find($this->selectedExistingServer)",
        ),
        "repair_mount_project_scope": _blame_line(
            repository,
            SECURITY_REPAIR_SHA,
            _line_in_method(
                repair_source,
                "mount",
                "Project::ownedByCurrentTeam()->find($this->selectedProject)",
            ),
            "Project::ownedByCurrentTeam()->find($this->selectedProject)",
        ),
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
        and baseline["underlying_unscoped_public_method_mechanism_present"] is True
        and baseline["url_mount_cross_team_path_active"] is False
        and candidate["underlying_unscoped_public_method_mechanism_present"] is True
        and candidate["url_mount_cross_team_path_active"] is True
        and repair["url_mount_cross_team_path_active"] is False
        and repair["url_mount_cross_team_path_blocked"] is True
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
        "artifact_kind": "coolify_onboarding_url_idor_path_extension_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "advisory": "GHSA-qfcc-2fm3-9q42",
        "commit_metadata": commits,
        "ancestry": ancestry,
        "line_origins": line_origins,
        "repair_test_contract": repair_test,
        "runs": runs,
        "witness_passed": witness_passed,
        "causal_adjudication": "CONFIRMED_DIRECT_AI_VULNERABLE_PATH_EXTENSION",
        "causal_role": "url_state_mount_cross_team_object_loading_path",
        "counting": {
            "candidate_level_true_positive": True,
            "mechanism_level_true_positive": False,
            "cve_specific_causal_member": True,
            "unique_advisory_increment_not_asserted": True,
            "reason": (
                "The AI delta adds URL-persisted mount-time IDOR paths that the "
                "GHSA-labeled repair test closes, while callable unscoped lookup "
                "methods already existed in the parent."
            ),
        },
        "claim_boundary": (
            "The witness proves a directly Claude-attributed vulnerable-path "
            "extension for GHSA-qfcc-2fm3-9q42. The parent already exposed "
            "unscoped Livewire methods, so the AI commit is not the earliest "
            "mechanism root. Its own delta makes server and project IDs URL "
            "state and dereferences them during mount, adding independently "
            "triggerable cross-team loading paths. The later Claude-attributed "
            "repair scopes both mount lookups and supplies attacker-team versus "
            "victim-team regression tests. This is a compositional source/test "
            "witness, not a locally executed Laravel exploit and not a new "
            "unique-vulnerability count."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify onboarding URL IDOR path-extension witness frozen")
    print(f"  baseline URL/mount path : {baseline['url_mount_cross_team_path_active']}")
    print(f"  candidate URL/mount path: {candidate['url_mount_cross_team_path_active']}")
    print(f"  repair path blocked     : {repair['url_mount_cross_team_path_blocked']}")
    print(f"  repair test contract    : {all(repair_test.values())}")
    print(f"  witness                 : {'PASS' if witness_passed else 'FAIL'}")
    print(f"  output                  : {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
