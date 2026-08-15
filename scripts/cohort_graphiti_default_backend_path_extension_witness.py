#!/usr/bin/env python3
"""Prove a Graphiti squash member activated a vulnerable backend by default."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


PARENT_SHA = "d1bb8554a62a94e6827ebd96c437e766d5a2c89c"
CANDIDATE_SHA = "b9ac3efb69b2208e0c55a36cba80ce9b9a02d27e"
FIX_SHA = "7d65d5e77e89a199a62d737634eaa26dbb04d037"
TRIGGER_GROUP_ID = "main)|@name:*"
CONFIG_PATH = "mcp_server/config/config.yaml"
DRIVER_PATH = "graphiti_core/driver/falkordb_driver.py"
HELPERS_PATH = "graphiti_core/helpers.py"


class WitnessGroupIdValidationError(ValueError):
    """Stand-in base used while executing the revision's validation functions."""

    def __init__(self, group_id: str):
        super().__init__(
            f'group_id "{group_id}" must contain only alphanumeric characters, '
            "dashes, or underscores"
        )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _git_blob(repository: Path, revision: str, path: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), "show", f"{revision}:{path}"],
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"cannot read {revision}:{path}: {exc}") from exc
    if completed.returncode != 0 or not completed.stdout:
        reason = completed.stderr.decode("utf-8", errors="replace")[:300]
        raise SystemExit(f"cannot read {revision}:{path}: {reason}")
    return completed.stdout


def _database_provider(config_source: str) -> str:
    database_indent: int | None = None
    for line in config_source.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if stripped == "database:":
            database_indent = indent
            continue
        if database_indent is None:
            continue
        if indent <= database_indent:
            break
        match = re.match(r"provider:\s*[\"']?([^\"'\s#]+)", stripped)
        if match:
            return match.group(1).lower()
    raise SystemExit("database.provider is absent from config")


def _named_functions(source: str, names: set[str]) -> list[ast.FunctionDef]:
    tree = ast.parse(source)
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    found = {node.name for node in functions}
    if found != names:
        raise SystemExit(f"expected helper functions {sorted(names)}, found {sorted(found)}")
    return functions


def _driver_class(source: str, namespace: dict[str, object]) -> type:
    tree = ast.parse(source)
    driver = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "FalkorDriver"
        ),
        None,
    )
    if driver is None:
        raise SystemExit("FalkorDriver class is absent")
    wanted = {"sanitize", "build_fulltext_query"}
    methods = [
        node
        for node in driver.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    found = {node.name for node in methods}
    if found != wanted:
        raise SystemExit(f"expected driver methods {sorted(wanted)}, found {sorted(found)}")
    extracted = ast.ClassDef(
        name="WitnessFalkorDriver",
        bases=[],
        keywords=[],
        body=methods,
        decorator_list=[],
    )
    module = ast.fix_missing_locations(ast.Module(body=[extracted], type_ignores=[]))
    exec(compile(module, DRIVER_PATH, "exec"), namespace)  # noqa: S102
    value = namespace["WitnessFalkorDriver"]
    assert isinstance(value, type)
    return value


def _execute_builder(driver_source: str, helpers_source: str) -> dict[str, object]:
    namespace: dict[str, object] = {
        "STOPWORDS": set(),
        "re": re,
        "GroupIdValidationError": WitnessGroupIdValidationError,
        # Old revisions do not have the list validator and do not call it.
        "validate_group_ids": lambda _group_ids: True,
    }
    helper_tree = ast.parse(helpers_source)
    available = {
        node.name
        for node in helper_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    validation_names = {"validate_group_id", "validate_group_ids"}
    if validation_names <= available:
        functions = _named_functions(helpers_source, validation_names)
        module = ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[]))
        exec(compile(module, HELPERS_PATH, "exec"), namespace)  # noqa: S102

    driver_class = _driver_class(driver_source, namespace)
    driver = driver_class()
    try:
        query = driver.build_fulltext_query("needle", [TRIGGER_GROUP_ID])
    except WitnessGroupIdValidationError as exc:
        return {
            "outcome": "validation_rejected",
            "exception_type": type(exc).__name__,
            "exception_message": str(exc),
            "query": "",
            "injection_marker_emitted": False,
        }
    return {
        "outcome": "query_emitted",
        "exception_type": "",
        "exception_message": "",
        "query": query,
        "injection_marker_emitted": "|@name:*" in query,
    }


def _execute_revision(repository: Path, label: str, revision: str) -> dict[str, object]:
    config = _git_blob(repository, revision, CONFIG_PATH)
    driver = _git_blob(repository, revision, DRIVER_PATH)
    helpers = _git_blob(repository, revision, HELPERS_PATH)
    provider = _database_provider(config.decode("utf-8"))
    builder = _execute_builder(
        driver.decode("utf-8"), helpers.decode("utf-8")
    )
    return {
        "label": label,
        "revision": revision,
        "default_database_provider": provider,
        "default_reaches_falkordb_builder": provider == "falkordb",
        "builder": builder,
        "config_sha256": hashlib.sha256(config).hexdigest(),
        "driver_sha256": hashlib.sha256(driver).hexdigest(),
        "helpers_sha256": hashlib.sha256(helpers).hexdigest(),
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
        _execute_revision(repository, "parent", PARENT_SHA),
        _execute_revision(repository, "candidate", CANDIDATE_SHA),
        _execute_revision(repository, "fixed", FIX_SHA),
    ]
    parent, candidate, fixed = runs
    parent_builder = parent["builder"]
    candidate_builder = candidate["builder"]
    fixed_builder = fixed["builder"]
    assert isinstance(parent_builder, dict)
    assert isinstance(candidate_builder, dict)
    assert isinstance(fixed_builder, dict)
    witness_passed = bool(
        parent["default_database_provider"] == "kuzu"
        and parent["default_reaches_falkordb_builder"] is False
        and parent_builder["injection_marker_emitted"] is True
        and candidate["default_database_provider"] == "falkordb"
        and candidate["default_reaches_falkordb_builder"] is True
        and candidate_builder["injection_marker_emitted"] is True
        and fixed["default_database_provider"] == "falkordb"
        and fixed["default_reaches_falkordb_builder"] is True
        and fixed_builder["outcome"] == "validation_rejected"
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "graphiti_falkordb_default_path_activation_witness",
        "repository_identity": "github.com/getzep/graphiti",
        "parent_sha": PARENT_SHA,
        "candidate_sha": CANDIDATE_SHA,
        "fix_sha": FIX_SHA,
        "trigger_group_id": TRIGGER_GROUP_ID,
        "runs": runs,
        "witness_passed": witness_passed,
        "claim_boundary": (
            "The triplet proves a default-configuration path extension: the parent "
            "kept the already-vulnerable FalkorDB builder off the default MCP path, "
            "the candidate made FalkorDB the default, and the fix rejects the same "
            "malicious group id. It does not make the candidate the earliest origin "
            "of the FalkorDB builder or prove member-level AI authorship."
        ),
    }
    _atomic_json(args.output, payload)
    print("Graphiti default-backend path-extension witness frozen")
    print(f"  parent default    : {parent['default_database_provider']}")
    print(f"  candidate default : {candidate['default_database_provider']}")
    print(f"  candidate emits   : {candidate_builder['injection_marker_emitted']}")
    print(f"  fixed rejects     : {fixed_builder['outcome'] == 'validation_rejected'}")
    print(f"  witness           : {'PASS' if witness_passed else 'FAIL'}")
    print(f"  output            : {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
