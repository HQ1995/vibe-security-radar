#!/usr/bin/env python3
"""Freeze the mixed-origin ChurchCRM setup-password validation witness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


BASELINE_SHA = "38d47eaf752ac2d9591df96907b4aa1362380914"
LATENT_AI_SHA = "63796244339281018bb9e810077789628b508b23"
RAW_PASSWORD_SHA = "472ef7f27a4bfdba8abd4ac06173a533d45a3702"
PRE_ACTIVATION_AI_SHA = "4c7a1f1c1a22e4f0e6a6e43d7bef1f278e56f860"
ACTIVATION_SHA = "8f7ecc7e6e54098c7ba977990cf7a4a8ac1736e9"
LANDED_MERGE_SHA = "c6991bc66a14aee4daa9fcf7bfbfe6be38909417"
SECURITY_PR_INITIAL_SHA = "9fd426df1370af9718bfac1e9486c01b7151751f"
PERSISTENCE_REVISIONS = ("5.19.0", "7.0.5")

SETUP_PATH = "src/setup/routes/setup.php"
CONFIG_TEMPLATE_PATH = "src/Include/Config.php.example"
PASSWORD_PLACEHOLDER = "||DB_PASSWORD||"
WITNESS_MARKER = "$AI_SLOP_WITNESS='reachable';"
WITNESS_PASSWORD = f"test123'; {WITNESS_MARKER} //"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _git(
    repository: Path,
    arguments: list[str],
    *,
    text: bool = False,
) -> bytes | str:
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


def _git_blob(repository: Path, revision: str, path: str) -> bytes:
    value = _git(repository, ["show", f"{revision}:{path}"])
    assert isinstance(value, bytes)
    if not value:
        raise SystemExit(f"empty Git blob: {revision}:{path}")
    return value


def _commit_metadata(repository: Path, revision: str) -> dict[str, object]:
    value = _git(
        repository,
        [
            "show",
            "-s",
            "--format=%H%x00%P%x00%an%x00%ae%x00%aI%x00%B",
            revision,
        ],
        text=True,
    )
    assert isinstance(value, str)
    fields = value.rstrip("\n").split("\x00", 5)
    if len(fields) != 6:
        raise SystemExit(f"unexpected commit metadata for {revision}")
    sha, parents, author_name, author_email, authored_at, message = fields
    normalized = f"{author_name}\n{author_email}\n{message}".lower()
    return {
        "sha": sha,
        "parents": parents.split(),
        "author_name": author_name,
        "author_email": author_email,
        "authored_at": authored_at,
        "message": message.rstrip(),
        "direct_copilot_signal": bool(
            re.search(r"co-authored-by:\s*copilot\b", message, re.IGNORECASE)
            or "copilot@users.noreply.github.com" in normalized
            or "copilot-swe-agent[bot]" in normalized
        ),
    }


def _is_ancestor(repository: Path, ancestor: str, descendant: str) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(repository), "merge-base", "--is-ancestor", ancestor, descendant],
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode not in {0, 1}:
        reason = completed.stderr.decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"cannot check ancestry {ancestor}..{descendant}: {reason}")
    return completed.returncode == 0


def _function_body(source: str, name: str) -> str | None:
    match = re.search(
        rf"function\s+{re.escape(name)}\s*\([^)]*\)\s*\{{(?P<body>.*?)\n\}}",
        source,
        re.DOTALL,
    )
    return match.group("body") if match else None


def _password_validator(source: str) -> str:
    match = re.search(
        r"elseif\s*\(\s*!\s*(?P<name>is_valid_[a-zA-Z0-9_]+)"
        r"\(\s*\$setupData\['DB_PASSWORD'\]\s*\)\s*\)",
        source,
    )
    if match:
        return match.group("name")
    match = re.search(
        r"!\s*(?P<name>is_valid_[a-zA-Z0-9_]+)"
        r"\(\s*\$setupData\['DB_PASSWORD'\]\s*\)",
        source,
    )
    if not match:
        raise SystemExit("DB_PASSWORD route validator is absent")
    return match.group("name")


def _php_pattern(literal: str) -> tuple[str, int]:
    if len(literal) < 2:
        raise SystemExit(f"invalid PHP regex literal: {literal!r}")
    delimiter = literal[0]
    escaped = False
    closing = -1
    for index, character in enumerate(literal[1:], start=1):
        if character == delimiter and not escaped:
            closing = index
        if character == "\\" and not escaped:
            escaped = True
        else:
            escaped = False
    if closing < 1:
        raise SystemExit(f"unterminated PHP regex literal: {literal!r}")
    pattern = literal[1:closing].replace(r"\@", "@").replace(r"\/", "/")
    modifiers = literal[closing + 1 :]
    unsupported = set(modifiers) - {"i"}
    if unsupported:
        raise SystemExit(f"unsupported PHP regex modifiers: {sorted(unsupported)}")
    return pattern, re.IGNORECASE if "i" in modifiers else 0


def _validator_accepts(source: str, name: str, value: str) -> bool:
    body = _function_body(source, name)
    if body is None:
        raise SystemExit(f"selected validator function is absent: {name}")
    if re.search(r"return\s+strlen\s*\(\s*\$value\s*\)\s*>\s*0\s*;", body):
        return len(value) > 0
    match = re.search(
        r"return\s+preg_match\s*\(\s*'(?P<regex>(?:\\.|[^'])+)'"
        r"\s*,\s*\$value\s*\)\s*;",
        body,
    )
    if not match:
        raise SystemExit(f"unsupported validator body for {name}: {body.strip()!r}")
    pattern, flags = _php_pattern(match.group("regex"))
    return re.search(pattern, value, flags) is not None


def _password_assignment(source: str) -> str:
    if re.search(
        r"\$dbPassword\s*=\s*\$setupData\['DB_PASSWORD'\]\s*;", source
    ):
        return "raw"
    if re.search(
        r"\$dbPassword\s*=\s*sanitize_db_field"
        r"\(\s*\$setupData\['DB_PASSWORD'\]\s*\)\s*;",
        source,
    ):
        return "sanitize_db_field"
    raise SystemExit("DB_PASSWORD assignment is absent or unsupported")


def _evaluate_source(setup_source: str, template_source: str) -> dict[str, object]:
    validator = _password_validator(setup_source)
    selected_body = _function_body(setup_source, validator)
    selected_accepts = (
        _validator_accepts(setup_source, validator, WITNESS_PASSWORD)
        if selected_body is not None
        else False
    )
    helper_body = _function_body(setup_source, "is_valid_db_password")
    helper_accepts = (
        _validator_accepts(setup_source, "is_valid_db_password", WITNESS_PASSWORD)
        if helper_body is not None
        else False
    )
    assignment = _password_assignment(setup_source)
    replacement_present = bool(
        re.search(
            r"str_replace\s*\(\s*'\|\|DB_PASSWORD\|\|'\s*,"
            r"\s*\$dbPassword\s*,\s*\$template\s*\)",
            setup_source,
        )
    )
    placeholder_context_present = bool(
        re.search(
            r"\$sPASSWORD\s*=\s*'\|\|DB_PASSWORD\|\|'\s*;", template_source
        )
    )
    raw_reaches_template = bool(
        selected_accepts
        and assignment == "raw"
        and replacement_present
        and placeholder_context_present
    )
    rendered_template = (
        template_source.replace(PASSWORD_PLACEHOLDER, WITNESS_PASSWORD)
        if raw_reaches_template
        else ""
    )
    expected_statement = f"$sPASSWORD = 'test123'; {WITNESS_MARKER} //';"
    return {
        "selected_password_validator": validator,
        "selected_validator_present": selected_body is not None,
        "selected_validator_outcome": (
            "accepted"
            if selected_accepts
            else "rejected"
            if selected_body is not None
            else "missing_function_runtime_error"
        ),
        "selected_validator_accepts_witness": selected_accepts,
        "permissive_password_helper_present": helper_body is not None,
        "permissive_password_helper_accepts_witness": helper_accepts,
        "password_assignment": assignment,
        "template_replacement_present": replacement_present,
        "quoted_php_placeholder_context_present": placeholder_context_present,
        "raw_password_reaches_template": raw_reaches_template,
        "harmless_php_statement_emitted": expected_statement in rendered_template,
        "rendered_password_line": next(
            (
                line.strip()
                for line in rendered_template.splitlines()
                if WITNESS_MARKER in line
            ),
            "",
        ),
    }


def _execute_revision(
    repository: Path,
    *,
    label: str,
    revision: str,
) -> dict[str, object]:
    setup_blob = _git_blob(repository, revision, SETUP_PATH)
    template_blob = _git_blob(repository, revision, CONFIG_TEMPLATE_PATH)
    setup_source = setup_blob.decode("utf-8", errors="strict")
    template_source = template_blob.decode("utf-8", errors="strict")
    return {
        "label": label,
        "revision": revision,
        "resolved_commit": str(_commit_metadata(repository, revision)["sha"]),
        "setup_sha256": hashlib.sha256(setup_blob).hexdigest(),
        "config_template_sha256": hashlib.sha256(template_blob).hexdigest(),
        "evaluation": _evaluate_source(setup_source, template_source),
    }


def _line_number(source: str, marker: str) -> int:
    matches = [
        number
        for number, line in enumerate(source.splitlines(), start=1)
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one line containing {marker!r}, found {matches}")
    return matches[0]


def _blame_marker(
    repository: Path,
    revision: str,
    source: str,
    marker: str,
) -> dict[str, object]:
    line = _line_number(source, marker)
    value = _git(
        repository,
        ["blame", "--line-porcelain", "-L", f"{line},{line}", revision, "--", SETUP_PATH],
        text=True,
    )
    assert isinstance(value, str)
    sha = value.split(None, 1)[0].lstrip("^")
    return {"line": line, "marker": marker, "origin_sha": sha}


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

    revision_specs = [
        ("pre_helper_baseline", BASELINE_SHA),
        ("latent_ai_helper", LATENT_AI_SHA),
        ("pre_activation_ai_refactor", PRE_ACTIVATION_AI_SHA),
        ("human_runtime_activation", ACTIVATION_SHA),
        ("landed_security_pr", LANDED_MERGE_SHA),
        *((f"released_{revision}", revision) for revision in PERSISTENCE_REVISIONS),
    ]
    runs = [
        _execute_revision(repository, label=label, revision=revision)
        for label, revision in revision_specs
    ]
    evaluations = {
        str(run["label"]): run["evaluation"]
        for run in runs
    }
    assert all(isinstance(value, dict) for value in evaluations.values())

    commit_shas = (
        SECURITY_PR_INITIAL_SHA,
        LATENT_AI_SHA,
        RAW_PASSWORD_SHA,
        PRE_ACTIVATION_AI_SHA,
        ACTIVATION_SHA,
        LANDED_MERGE_SHA,
    )
    commits = {
        sha: _commit_metadata(repository, sha)
        for sha in commit_shas
    }
    activation_source = _git_blob(repository, ACTIVATION_SHA, SETUP_PATH).decode("utf-8")
    blame = {
        "permissive_helper_definition": _blame_marker(
            repository,
            ACTIVATION_SHA,
            activation_source,
            "function is_valid_db_password($value)",
        ),
        "runtime_validator_selection": _blame_marker(
            repository,
            ACTIVATION_SHA,
            activation_source,
            "} elseif (!is_valid_db_password($setupData['DB_PASSWORD'])) {",
        ),
        "raw_password_assignment": _blame_marker(
            repository,
            ACTIVATION_SHA,
            activation_source,
            "$dbPassword  = $setupData['DB_PASSWORD'];",
        ),
        "template_replacement_sink": _blame_marker(
            repository,
            ACTIVATION_SHA,
            activation_source,
            "$template = str_replace('||DB_PASSWORD||', $dbPassword, $template);",
        ),
    }

    baseline = evaluations["pre_helper_baseline"]
    latent = evaluations["latent_ai_helper"]
    pre_activation = evaluations["pre_activation_ai_refactor"]
    activation = evaluations["human_runtime_activation"]
    landed = evaluations["landed_security_pr"]
    released = [evaluations[f"released_{revision}"] for revision in PERSISTENCE_REVISIONS]
    witness_passed = bool(
        commits[LATENT_AI_SHA]["direct_copilot_signal"] is True
        and commits[PRE_ACTIVATION_AI_SHA]["direct_copilot_signal"] is True
        and commits[ACTIVATION_SHA]["direct_copilot_signal"] is False
        and _is_ancestor(repository, LATENT_AI_SHA, ACTIVATION_SHA)
        and _is_ancestor(repository, ACTIVATION_SHA, LANDED_MERGE_SHA)
        and baseline["permissive_password_helper_present"] is False
        and baseline["selected_validator_present"] is True
        and baseline["selected_validator_accepts_witness"] is False
        and latent["permissive_password_helper_present"] is True
        and latent["permissive_password_helper_accepts_witness"] is True
        and latent["selected_password_validator"] == "is_valid_db_field"
        and latent["selected_validator_present"] is False
        and latent["selected_validator_accepts_witness"] is False
        and pre_activation["password_assignment"] == "raw"
        and pre_activation["selected_password_validator"] == "is_valid_db_field"
        and pre_activation["selected_validator_present"] is False
        and pre_activation["selected_validator_accepts_witness"] is False
        and activation["selected_password_validator"] == "is_valid_db_password"
        and activation["harmless_php_statement_emitted"] is True
        and landed["harmless_php_statement_emitted"] is True
        and all(item["harmless_php_statement_emitted"] is True for item in released)
        and blame["permissive_helper_definition"]["origin_sha"] == LATENT_AI_SHA
        and blame["runtime_validator_selection"]["origin_sha"] == ACTIVATION_SHA
        and blame["raw_password_assignment"]["origin_sha"] == RAW_PASSWORD_SHA
        and blame["template_replacement_sink"]["origin_sha"] == SECURITY_PR_INITIAL_SHA
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": "churchcrm_setup_password_compositional_witness",
        "advisory": "CVE-2025-11938",
        "repository_identity": "github.com/churchcrm/crm",
        "witness_password": WITNESS_PASSWORD,
        "witness_is_harmless": True,
        "ancestry": {
            "latent_ai_helper_reaches_human_activation": _is_ancestor(
                repository, LATENT_AI_SHA, ACTIVATION_SHA
            ),
            "human_activation_reaches_landed_merge": _is_ancestor(
                repository, ACTIVATION_SHA, LANDED_MERGE_SHA
            ),
        },
        "commit_metadata": commits,
        "line_origins_at_activation": blame,
        "runs": runs,
        "witness_passed": witness_passed,
        "causal_adjudication": "CONFIRMED_COMPOSITIONAL_AI_CONTRIBUTOR",
        "causal_role": "latent_insecure_primitive_with_human_activation",
        "direct_ai_root_claim": False,
        "claim_boundary": (
            "The witness proves a mixed-origin causal chain. A directly Copilot-"
            "co-authored commit introduced the non-empty-only password validator "
            "while leaving the route pointed at the now-absent old validator. A "
            "later human commit repaired that broken dispatch by selecting the "
            "latent permissive helper on a raw-password path into a "
            "single-quoted PHP configuration template. The harmless payload then "
            "emits a second PHP assignment, and the same mechanism persists in the "
            "sampled releases. This is a compositional AI causal contribution, not "
            "an independent AI-authored root, not execution of an operating-system "
            "command, and not a claim that every deployment is remotely reachable."
        ),
    }
    _atomic_json(args.output, payload)
    print("ChurchCRM setup-password compositional witness frozen")
    print(f"  latent helper AI signal : {commits[LATENT_AI_SHA]['direct_copilot_signal']}")
    print(f"  latent route outcome    : {latent['selected_validator_outcome']}")
    print(f"  pre-activation outcome  : {pre_activation['selected_validator_outcome']}")
    print(f"  activation emits marker : {activation['harmless_php_statement_emitted']}")
    print(f"  releases emit marker    : {[item['harmless_php_statement_emitted'] for item in released]}")
    print(f"  witness                 : {'PASS' if witness_passed else 'FAIL'}")
    print(f"  output                  : {args.output}")
    return 0 if witness_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
