#!/usr/bin/env python3
"""Freeze the carrier-aware chronology for OpenC3 CVE-2025-28389.

Commit timestamps are not used to decide whether a mitigation was available on
main.  The certificate follows the exact release, PR, and merge-carrier graph,
while retaining every observed AI candidate for compositional review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping


REPOSITORY_IDENTITY = "github.com/openc3/cosmos"
ADVISORY_ID = "CVE-2025-28389"
EXPECTED_DESCRIPTION = (
    "Weak password requirements in OpenC3 COSMOS v6.0.0 allow attackers to "
    "bypass authentication via a brute force attack."
)
DISCLOSURE_URL = (
    "https://visionspace.com/openc3-cosmos-a-security-assessment-of-an-open-"
    "source-mission-framework/"
)

AFFECTED_TAG = "v6.0.0"
AFFECTED_SHA = "6e0d24067e57572254471e0460bcc10931740c40"
HARDENED_TAG = "v7.0.0"
HARDENED_TAG_SHA = "eb3e364e8f3d5a7ea68fd756625561192d0025f0"
AUTH_MODEL_PATH = "openc3/lib/openc3/models/auth_model.rb"
EXPECTED_OBSERVED_AI_UNITS = 55
EXPECTED_VISIBLE_COMMITS = 11_966

AUTH_UI_AI_SHA = "e74d15a132b2ddc49e90813dd85740c0f2330316"
AUTH_MAIN_LANDING_SHA = "6633a8e184cd5b41762c4015a2ccf8419d3c4f27"
RATE_MAIN_LANDING_SHA = "02086f8882076c97374bb43a664a2d5f3c4391ad"
REDIS_MAIN_LANDING_SHA = "a4adb142b832d6a843c3db2ed8f5381eae02d98c"

EXPECTED_GRAPH_BUCKET_COUNTS = {
    "main_before_auth_hardening_landing": 17,
    "release_branch_containing_auth_hardening": 9,
    "main_after_auth_hardening_before_rate_limit": 20,
    "rate_limit_branch_ancestry_not_on_main_prelanding": 9,
    "main_after_rate_limit_before_redis": 0,
    "redis_rate_limit_branch": 0,
    "main_after_redis_rate_limit": 0,
    "other_retained_ref": 0,
}

MITIGATION_SPECS: tuple[dict[str, object], ...] = (
    {
        "sha": "d2246e82760626b264d083fd5afd7684998e6df9",
        "role": "remove_plaintext_password_support_for_api",
        "mainline_available_at": AUTH_MAIN_LANDING_SHA,
        "changed_files": {
            "docs.openc3.com/docs/development/json-api.md",
            "openc3-cosmos-cmd-tlm-api/app/controllers/auth_controller.rb",
            "openc3-cosmos-cmd-tlm-api/spec/controllers/auth_controller_spec.rb",
            "openc3-cosmos-init/plugins/packages/openc3-vue-common/src/tools/base/Login.vue",
            AUTH_MODEL_PATH,
            "openc3/lib/openc3/utilities/authorization.rb",
            "openc3/spec/models/auth_model_spec.rb",
        },
    },
    {
        "sha": "f58189b638165585d0ee91a73d667eaad65fb463",
        "role": "prevent_plaintext_password_use_in_api",
        "mainline_available_at": AUTH_MAIN_LANDING_SHA,
        "changed_files": {
            "openc3-cosmos-cmd-tlm-api/app/controllers/auth_controller.rb",
            AUTH_MODEL_PATH,
            "openc3/lib/openc3/utilities/authorization.rb",
        },
    },
    {
        "sha": "55dc2740a7b75ea9cd0ef0df1eed6ae46a9677a5",
        "role": "switch_password_hashing_to_argon2id",
        "mainline_available_at": AUTH_MAIN_LANDING_SHA,
        "changed_files": {
            "openc3/Gemfile",
            AUTH_MODEL_PATH,
            "openc3/openc3.gemspec",
            "openc3/spec/models/auth_model_spec.rb",
        },
    },
    {
        "sha": "a0ce1a6fea3f38b017c5db6eec87db9e38d523de",
        "role": "add_api_rate_limiting",
        "mainline_available_at": RATE_MAIN_LANDING_SHA,
        "changed_files": {
            ".env",
            "openc3-cosmos-cmd-tlm-api/app/controllers/auth_controller.rb",
            "openc3-cosmos-cmd-tlm-api/spec/controllers/auth_controller_spec.rb",
            "openc3-cosmos-cmd-tlm-api/spec/spec_helper.rb",
            "openc3-cosmos-init/plugins/packages/openc3-vue-common/src/tools/base/Login.vue",
            "playwright/tests/auth.p.spec.ts",
        },
    },
    {
        "sha": "62fe3c0b3383d9fa6125e8126a68639c5a9acd70",
        "role": "track_bad_password_attempts_in_redis",
        "mainline_available_at": REDIS_MAIN_LANDING_SHA,
        "changed_files": {
            "openc3-cosmos-cmd-tlm-api/app/controllers/auth_controller.rb",
            "playwright/tests/auth.p.spec.ts",
        },
    },
)

EXPECTED_AUTH_UI_PATHS = {
    "openc3-cosmos-init/plugins/packages/openc3-vue-common/src/tools/base/Login.vue",
    "openc3-cosmos-init/plugins/packages/openc3-vue-common/src/tools/base/UserMenu.vue",
}

LOGIN_PATH = (
    "openc3-cosmos-init/plugins/packages/openc3-vue-common/src/tools/base/Login.vue"
)
USER_MENU_PATH = (
    "openc3-cosmos-init/plugins/packages/openc3-vue-common/src/tools/base/UserMenu.vue"
)
EXPECTED_LOGIN_DIFF_SHA256 = (
    "30f45f0210cde6adf1a6c9a17c8d90fd177fe25a260110cf9b5c20c0377143a2"
)
EXPECTED_USER_MENU_DIFF_SHA256 = (
    "60fffac653bcec79792153566c46f018afd21323cd7d8e720f44361996b09d94"
)

CARRIER_SPECS: tuple[dict[str, object], ...] = (
    {
        "label": "plaintext_api_pr_2588",
        "sha": "81ebb592efd5dbfce7fc5b443073f1a48ccc1bc4",
        "parents": (
            "4f2d26f934aca78ae7807d9b98c08b7e73b60e96",
            "435b45d1f46ff62a4e674b050cae2af833056fb3",
        ),
        "pr_number": 2588,
        "base": "4f2d26f934aca78ae7807d9b98c08b7e73b60e96",
        "head": "435b45d1f46ff62a4e674b050cae2af833056fb3",
        "member_count": 19,
    },
    {
        "label": "argon2_pr_2608",
        "sha": "43d4d2fe6b14349170676ca412092db5319d6c87",
        "parents": (
            "997156a922318c98af96d5897e337798550ef411",
            "72d576ab8c8ef79e86cd82824ffa1d9580de7cce",
        ),
        "pr_number": 2608,
        "base": "81ebb592efd5dbfce7fc5b443073f1a48ccc1bc4",
        "head": "72d576ab8c8ef79e86cd82824ffa1d9580de7cce",
        "member_count": 16,
    },
    {
        "label": "release_v7_to_main",
        "sha": AUTH_MAIN_LANDING_SHA,
        "parents": (
            "23c82630c775d2f00d0a0a9d7ef8c74c5f9e888e",
            "6c183eca42a54b689c5785dba602eca3b4db1dc4",
        ),
    },
    {
        "label": "rate_limit_pr_2884",
        "sha": RATE_MAIN_LANDING_SHA,
        "parents": (
            "31339bb4dd4690ec1326b09560eb186cbd2c0f05",
            "6fb2a125fc4f8ea11eeb17e06f3b0a66281b3147",
        ),
        "pr_number": 2884,
        "base": "de8694201f9614a8b4ddfdc37fd11dae30dc762a",
        "head": "6fb2a125fc4f8ea11eeb17e06f3b0a66281b3147",
        "member_count": 6,
    },
    {
        "label": "redis_rate_limit_pr_2921",
        "sha": REDIS_MAIN_LANDING_SHA,
        "parents": (
            "df83ae7b941e3804870582f4249f38c15d9e4c59",
            "62fe3c0b3383d9fa6125e8126a68639c5a9acd70",
        ),
        "pr_number": 2921,
        "base": "f9d0650b3796564634b84260b68e8c5d6da3b824",
        "head": "62fe3c0b3383d9fa6125e8126a68639c5a9acd70",
        "member_count": 1,
    },
)

FULL_SHA = re.compile(r"[0-9a-f]{40}")
AUTH_COMPONENT = re.compile(
    r"(?:^|[/_.-])"
    r"(auth(?:entication|orization)?|login|password|session|token|user[_-]?menu)"
    r"(?:$|[/_.-])",
    re.IGNORECASE,
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--commit-universe", type=Path, required=True)
    parser.add_argument("--cve-record", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git_bytes(repository: Path, arguments: list[str], *, timeout: int = 120) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            check=False,
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"git {' '.join(arguments)} failed: {exc}") from exc
    if completed.returncode != 0:
        reason = completed.stderr.decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"git {' '.join(arguments)} failed: {reason}")
    return completed.stdout


def _git(repository: Path, arguments: list[str], *, timeout: int = 120) -> str:
    return _git_bytes(repository, arguments, timeout=timeout).decode(
        "utf-8", errors="strict"
    )


def _rev_parse(repository: Path, revision: str) -> str:
    value = _git(repository, ["rev-parse", revision]).strip()
    if not FULL_SHA.fullmatch(value):
        raise SystemExit(f"revision did not resolve to a full commit: {revision}")
    return value


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
        env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
        timeout=120,
    )
    if completed.returncode not in {0, 1}:
        reason = completed.stderr.decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"cannot check ancestry {ancestor}..{descendant}: {reason}")
    return completed.returncode == 0


def _changed_files(repository: Path, revision: str) -> list[str]:
    return sorted(
        line
        for line in _git(
            repository,
            ["diff-tree", "--no-commit-id", "--name-only", "-r", revision],
        ).splitlines()
        if line
    )


def _commit_metadata(repository: Path, revision: str) -> dict[str, object]:
    raw = _git(
        repository,
        [
            "show",
            "-s",
            "--format=%H%x00%P%x00%an%x00%ae%x00%aI%x00%cI%x00%ct%x00%s",
            revision,
        ],
    )
    fields = raw.rstrip("\n").split("\x00", 7)
    if len(fields) != 8:
        raise SystemExit(f"unexpected commit metadata for {revision}")
    sha, parents, author, email, authored_at, committed_at, timestamp, subject = fields
    if not FULL_SHA.fullmatch(sha):
        raise SystemExit(f"unexpected commit identity for {revision}")
    return {
        "sha": sha,
        "parents": parents.split(),
        "author": author,
        "author_email": email,
        "authored_at": authored_at,
        "committed_at": committed_at,
        "committer_timestamp": int(timestamp),
        "subject": subject,
    }


def _load_commit_universe(path: Path) -> tuple[list[dict[str, object]], str]:
    rows: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    try:
        raw = path.read_bytes()
        for line_number, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise SystemExit(f"{path}:{line_number}: row is not an object")
            identity = str(value.get("repository_identity", ""))
            sha = str(value.get("sha", ""))
            if not identity or not FULL_SHA.fullmatch(sha):
                raise SystemExit(f"{path}:{line_number}: malformed commit identity")
            key = (identity, sha)
            if key in seen:
                raise SystemExit(
                    f"{path}:{line_number}: duplicate commit identity {key}"
                )
            seen.add(key)
            if identity == REPOSITORY_IDENTITY:
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read commit universe {path}: {exc}") from exc
    return rows, _sha256(raw)


def _load_cve(path: Path) -> tuple[dict[str, object], str]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read CVE record {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit("CVE record is not an object")
    metadata = value.get("cveMetadata")
    containers = value.get("containers")
    if not isinstance(metadata, Mapping) or metadata.get("cveId") != ADVISORY_ID:
        raise SystemExit(f"unexpected CVE identity: {metadata}")
    if not isinstance(containers, Mapping) or not isinstance(
        containers.get("cna"), Mapping
    ):
        raise SystemExit("CVE record has no CNA container")
    cna = containers["cna"]
    assert isinstance(cna, Mapping)
    descriptions = cna.get("descriptions")
    references = cna.get("references")
    if not isinstance(descriptions, list) or not isinstance(references, list):
        raise SystemExit("CVE descriptions or references are malformed")
    english = [
        str(row.get("value"))
        for row in descriptions
        if isinstance(row, Mapping) and row.get("lang") == "en"
    ]
    urls = sorted(
        str(row.get("url"))
        for row in references
        if isinstance(row, Mapping) and isinstance(row.get("url"), str)
    )
    if english != [EXPECTED_DESCRIPTION]:
        raise SystemExit(f"unexpected CVE description: {english}")
    if DISCLOSURE_URL not in urls:
        raise SystemExit("CVE record does not contain the expected disclosure URL")
    return {
        "cve": ADVISORY_ID,
        "description": english[0],
        "references": urls,
        "date_published": metadata.get("datePublished"),
        "date_updated": metadata.get("dateUpdated"),
    }, _sha256(raw)


def _is_auth_surface_path(file_name: str) -> bool:
    return bool(AUTH_COMPONENT.search(file_name))


def _auth_surface_hits(files: list[str]) -> list[str]:
    return sorted(file_name for file_name in files if _is_auth_surface_path(file_name))


def _source_probe(source: str) -> dict[str, object]:
    markers = {
        "minimum_length_constant": "MIN_TOKEN_LENGTH = 8",
        "minimum_length_enforcement": (
            'raise "token must be at least 8 characters" if token.length < MIN_TOKEN_LENGTH'
        ),
        "direct_password_verification": "return true if @@token_cache == token_hash",
        "sha2_hash": "Digest::SHA2.hexdigest token",
        "service_password_verification": "service_password == token",
    }
    lines = source.splitlines()
    observations: dict[str, object] = {}
    for name, marker in markers.items():
        matches = [index for index, line in enumerate(lines, start=1) if marker in line]
        if len(matches) != 1:
            raise SystemExit(f"affected source marker {name} occurred at {matches}")
        observations[name] = {"line": matches[0], "marker": marker}
    return {
        "path": AUTH_MODEL_PATH,
        "observations": observations,
        "interpretation": {
            "minimum_password_length": 8,
            "application_accepts_password_for_direct_verification": True,
            "stored_direct_password_representation": "unsalted_sha2_digest",
            "database_plaintext_storage_claimed": False,
            "boundary": (
                "The source proves an eight-character minimum, direct password "
                "verification, and an unsalted SHA-2 digest. The disclosure calls "
                "the accepted password clear text; this certificate does not "
                "reinterpret that as plaintext database storage."
            ),
        },
    }


def _blame_marker(
    repository: Path, revision: str, marker: Mapping[str, object]
) -> dict[str, object]:
    line = int(marker["line"])
    raw = _git(
        repository,
        [
            "blame",
            "--line-porcelain",
            "-L",
            f"{line},{line}",
            revision,
            "--",
            AUTH_MODEL_PATH,
        ],
    )
    rows = raw.splitlines()
    origin = rows[0].split()[0].lstrip("^")
    details: dict[str, str] = {}
    for row in rows[1:]:
        key, separator, value = row.partition(" ")
        if separator and key in {"author", "author-mail", "author-time", "summary"}:
            details[key.replace("-", "_")] = value
    return {"origin_sha": origin, **details}


def _graph_membership(repository: Path, sha: str) -> dict[str, object]:
    flags = {
        "on_main_before_auth_hardening_landing": _is_ancestor(
            repository, sha, f"{AUTH_MAIN_LANDING_SHA}^1"
        ),
        "in_release_branch_containing_auth_hardening": _is_ancestor(
            repository, sha, f"{AUTH_MAIN_LANDING_SHA}^2"
        ),
        "descends_from_auth_hardening_main_landing": _is_ancestor(
            repository, AUTH_MAIN_LANDING_SHA, sha
        ),
        "on_main_before_rate_limit_landing": _is_ancestor(
            repository, sha, f"{RATE_MAIN_LANDING_SHA}^1"
        ),
        "in_rate_limit_branch_ancestry": _is_ancestor(
            repository, sha, f"{RATE_MAIN_LANDING_SHA}^2"
        ),
        "descends_from_rate_limit_main_landing": _is_ancestor(
            repository, RATE_MAIN_LANDING_SHA, sha
        ),
        "on_main_before_redis_rate_limit_landing": _is_ancestor(
            repository, sha, f"{REDIS_MAIN_LANDING_SHA}^1"
        ),
        "in_redis_rate_limit_branch": _is_ancestor(
            repository, sha, f"{REDIS_MAIN_LANDING_SHA}^2"
        ),
        "descends_from_redis_rate_limit_main_landing": _is_ancestor(
            repository, REDIS_MAIN_LANDING_SHA, sha
        ),
        "on_frozen_main": _is_ancestor(repository, sha, "main"),
    }
    if flags["on_main_before_auth_hardening_landing"]:
        bucket = "main_before_auth_hardening_landing"
    elif flags["in_release_branch_containing_auth_hardening"]:
        bucket = "release_branch_containing_auth_hardening"
    elif (
        flags["descends_from_auth_hardening_main_landing"]
        and flags["on_main_before_rate_limit_landing"]
    ):
        bucket = "main_after_auth_hardening_before_rate_limit"
    elif flags["in_rate_limit_branch_ancestry"]:
        bucket = "rate_limit_branch_ancestry_not_on_main_prelanding"
    elif (
        flags["descends_from_rate_limit_main_landing"]
        and flags["on_main_before_redis_rate_limit_landing"]
    ):
        bucket = "main_after_rate_limit_before_redis"
    elif flags["in_redis_rate_limit_branch"]:
        bucket = "redis_rate_limit_branch"
    elif (
        flags["descends_from_redis_rate_limit_main_landing"] and flags["on_frozen_main"]
    ):
        bucket = "main_after_redis_rate_limit"
    else:
        bucket = "other_retained_ref"
    return {"bucket": bucket, "flags": flags}


def _priority_lane(bucket: str, auth_hits: list[str]) -> str:
    if auth_hits:
        return "P0_direct_auth_surface"
    lanes = {
        "main_before_auth_hardening_landing": "P1_vulnerable_main_cross_file",
        "release_branch_containing_auth_hardening": "P1_auth_hardening_carrier_composition",
        "main_after_auth_hardening_before_rate_limit": "P1_residual_bruteforce_window",
        "rate_limit_branch_ancestry_not_on_main_prelanding": "P1_rate_limit_carrier_composition",
        "main_after_rate_limit_before_redis": "P2_post_rate_pre_redis",
        "redis_rate_limit_branch": "P2_redis_carrier_composition",
        "main_after_redis_rate_limit": "P3_post_mitigation_path_extension",
        "other_retained_ref": "P4_retained_other_ref",
    }
    return lanes[bucket]


def _carrier_rows(repository: Path, observed_shas: set[str]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for spec in CARRIER_SPECS:
        sha = str(spec["sha"])
        metadata = _commit_metadata(repository, sha)
        expected_parents = [str(parent) for parent in spec["parents"]]
        if metadata["parents"] != expected_parents:
            raise SystemExit(f"carrier parents drifted for {sha}")
        row: dict[str, object] = {
            **metadata,
            "label": spec["label"],
            "observed_ai_unit": sha in observed_shas,
            "changed_files_against_first_parent": sorted(
                line
                for line in _git(
                    repository,
                    ["diff", "--name-only", f"{sha}^1", sha],
                ).splitlines()
                if line
            ),
        }
        if "pr_number" in spec:
            base = str(spec["base"])
            head = str(spec["head"])
            members = [
                line
                for line in _git(
                    repository,
                    ["rev-list", "--reverse", "--no-merges", f"{base}..{head}"],
                ).splitlines()
                if line
            ]
            if len(members) != int(spec["member_count"]):
                raise SystemExit(
                    f"carrier member count drifted for PR {spec['pr_number']}"
                )
            if not _is_ancestor(repository, head, sha):
                raise SystemExit(f"PR head is not retained by carrier {sha}")
            row.update(
                {
                    "pr_number": spec["pr_number"],
                    "base": base,
                    "head": head,
                    "member_count": len(members),
                    "member_shas": members,
                    "observed_ai_member_shas": sorted(set(members) & observed_shas),
                }
            )
        rows.append(row)
    return rows


def _script_block(source: bytes) -> bytes:
    match = re.search(rb"<script(?:\s[^>]*)?>.*?</script>", source, re.DOTALL)
    if not match:
        raise SystemExit("Vue source has no script block")
    return match.group(0)


def _auth_ui_delta(repository: Path) -> dict[str, object]:
    parent_login = _git_bytes(repository, ["show", f"{AUTH_UI_AI_SHA}^:{LOGIN_PATH}"])
    current_login = _git_bytes(repository, ["show", f"{AUTH_UI_AI_SHA}:{LOGIN_PATH}"])
    login_diff = _git_bytes(
        repository, ["diff", f"{AUTH_UI_AI_SHA}^", AUTH_UI_AI_SHA, "--", LOGIN_PATH]
    )
    menu_diff = _git_bytes(
        repository, ["diff", f"{AUTH_UI_AI_SHA}^", AUTH_UI_AI_SHA, "--", USER_MENU_PATH]
    )
    login_diff_sha = _sha256(login_diff)
    menu_diff_sha = _sha256(menu_diff)
    parent_script_sha = _sha256(_script_block(parent_login))
    current_script_sha = _sha256(_script_block(current_login))
    if login_diff_sha != EXPECTED_LOGIN_DIFF_SHA256:
        raise SystemExit("Login.vue AI delta drifted")
    if menu_diff_sha != EXPECTED_USER_MENU_DIFF_SHA256:
        raise SystemExit("UserMenu.vue AI delta drifted")
    if parent_script_sha != current_script_sha:
        raise SystemExit("Login.vue script logic changed unexpectedly")
    return {
        "sha": AUTH_UI_AI_SHA,
        "login_diff_sha256": login_diff_sha,
        "user_menu_diff_sha256": menu_diff_sha,
        "parent_login_script_sha256": parent_script_sha,
        "current_login_script_sha256": current_script_sha,
        "login_script_block_unchanged": True,
        "auth_hardening_main_landing_is_ancestor": _is_ancestor(
            repository, AUTH_MAIN_LANDING_SHA, AUTH_UI_AI_SHA
        ),
        "candidate_is_on_main_before_auth_hardening_landing": _is_ancestor(
            repository, AUTH_UI_AI_SHA, f"{AUTH_MAIN_LANDING_SHA}^1"
        ),
        "exact_delta_adjudication": "NO_PASSWORD_OR_AUTH_REQUEST_LOGIC_CHANGE",
        "boundary": (
            "Login.vue only reorders template attributes; its complete script block "
            "is byte-identical. UserMenu.vue renames a news-loop variable and adds "
            "an ESLint suppression. This rejects a direct password-logic regression "
            "for the exact commit but does not delete the candidate."
        ),
    }


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        handle.write(encoded)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir():
        raise SystemExit(f"repository is not a directory: {repository}")
    if args.output.exists():
        raise SystemExit(f"output already exists: {args.output}")

    cve, cve_sha256 = _load_cve(args.cve_record)
    universe, universe_sha256 = _load_commit_universe(args.commit_universe)
    if len(universe) != EXPECTED_VISIBLE_COMMITS:
        raise SystemExit(
            f"unexpected OpenC3 visible commit count: {len(universe)} "
            f"!= {EXPECTED_VISIBLE_COMMITS}"
        )
    observed_rows = [row for row in universe if row.get("observed_ai_unit") is True]
    if len(observed_rows) != EXPECTED_OBSERVED_AI_UNITS:
        raise SystemExit(
            f"unexpected OpenC3 AI-unit count: {len(observed_rows)} "
            f"!= {EXPECTED_OBSERVED_AI_UNITS}"
        )
    observed_shas = {str(row["sha"]) for row in observed_rows}
    if len(observed_shas) != EXPECTED_OBSERVED_AI_UNITS:
        raise SystemExit("observed AI-unit identities are not unique")
    expected_routes = {"assistant_direct", "assistant_squash", "security_autofix"}
    expected_tools = {"claude_code", "github_copilot"}
    routes = {str(item) for row in observed_rows for item in row.get("ai_routes", [])}
    tools = {str(item) for row in observed_rows for item in row.get("ai_tools", [])}
    if routes != expected_routes or tools != expected_tools:
        raise SystemExit(
            f"unexpected AI source inventory: routes={routes}, tools={tools}"
        )

    resolved_affected = _rev_parse(repository, f"{AFFECTED_TAG}^{{}}")
    if resolved_affected != AFFECTED_SHA:
        raise SystemExit(f"affected tag drifted: {resolved_affected}")
    affected_metadata = _commit_metadata(repository, AFFECTED_SHA)
    source_bytes = _git_bytes(repository, ["show", f"{AFFECTED_SHA}:{AUTH_MODEL_PATH}"])
    source = source_bytes.decode("utf-8", errors="strict")
    source_probe = _source_probe(source)

    resolved_hardened = _rev_parse(repository, f"{HARDENED_TAG}^{{}}")
    if resolved_hardened != HARDENED_TAG_SHA:
        raise SystemExit(f"hardened tag drifted: {resolved_hardened}")
    hardened_metadata = _commit_metadata(repository, HARDENED_TAG_SHA)

    mitigation_rows: list[dict[str, object]] = []
    for spec in MITIGATION_SPECS:
        sha = str(spec["sha"])
        metadata = _commit_metadata(repository, sha)
        files = _changed_files(repository, sha)
        expected_files = set(spec["changed_files"])
        if set(files) != expected_files:
            raise SystemExit(f"mitigation file set drifted for {sha}")
        mainline_available_at = str(spec["mainline_available_at"])
        if not _is_ancestor(repository, sha, mainline_available_at):
            raise SystemExit(f"mitigation {sha} is absent from its landing carrier")
        if sha in observed_shas:
            raise SystemExit(
                f"mitigation unexpectedly has observed AI attribution: {sha}"
            )
        mitigation_rows.append(
            {
                **metadata,
                "role": spec["role"],
                "mainline_available_at": mainline_available_at,
                "mainline_available_metadata": _commit_metadata(
                    repository, mainline_available_at
                ),
                "changed_files": files,
                "auth_surface_hits": _auth_surface_hits(files),
                "observed_ai_unit": False,
            }
        )
    carrier_rows = _carrier_rows(repository, observed_shas)
    if not _is_ancestor(repository, AUTH_MAIN_LANDING_SHA, HARDENED_TAG_SHA):
        raise SystemExit("auth-hardening main landing is absent from the hardened tag")
    if not _is_ancestor(repository, RATE_MAIN_LANDING_SHA, HARDENED_TAG_SHA):
        raise SystemExit("rate-limit main landing is absent from the hardened tag")
    if not _is_ancestor(repository, REDIS_MAIN_LANDING_SHA, HARDENED_TAG_SHA):
        raise SystemExit("Redis rate-limit landing is absent from the hardened tag")

    candidates: list[dict[str, object]] = []
    for row in sorted(
        observed_rows,
        key=lambda item: (int(item["committer_timestamp"]), str(item["sha"])),
    ):
        sha = str(row["sha"])
        metadata = _commit_metadata(repository, sha)
        if int(row["committer_timestamp"]) != int(metadata["committer_timestamp"]):
            raise SystemExit(f"commit-universe timestamp drifted for {sha}")
        files = _changed_files(repository, sha)
        hits = _auth_surface_hits(files)
        membership = _graph_membership(repository, sha)
        bucket = str(membership["bucket"])
        candidates.append(
            {
                **metadata,
                "ai_routes": sorted(str(item) for item in row.get("ai_routes", [])),
                "ai_tools": sorted(str(item) for item in row.get("ai_tools", [])),
                "changed_files": files,
                "auth_surface_hits": hits,
                "graph_membership": membership,
                "priority_lane": _priority_lane(bucket, hits),
                "exact_diff_bytes": len(
                    _git_bytes(repository, ["show", "--format=", "--no-ext-diff", sha])
                ),
                "retained": True,
            }
        )

    if any(_is_ancestor(repository, sha, AFFECTED_SHA) for sha in observed_shas):
        raise SystemExit("an observed AI unit is an ancestor of the affected release")

    bucket_counts = {bucket: 0 for bucket in EXPECTED_GRAPH_BUCKET_COUNTS}
    for row in candidates:
        membership = row["graph_membership"]
        assert isinstance(membership, Mapping)
        bucket = str(membership["bucket"])
        bucket_counts[bucket] += 1
    if bucket_counts != EXPECTED_GRAPH_BUCKET_COUNTS:
        raise SystemExit(f"carrier-aware AI buckets drifted: {bucket_counts}")

    auth_overlap = {
        str(row["sha"]): row["auth_surface_hits"]
        for row in candidates
        if row["auth_surface_hits"]
    }
    if set(auth_overlap) != {AUTH_UI_AI_SHA}:
        raise SystemExit(f"unexpected observed-AI auth path inventory: {auth_overlap}")
    if set(auth_overlap[AUTH_UI_AI_SHA]) != EXPECTED_AUTH_UI_PATHS:
        raise SystemExit("auth UI path inventory drifted")
    auth_ui_delta = _auth_ui_delta(repository)

    observations = source_probe["observations"]
    assert isinstance(observations, Mapping)
    line_origins = {
        name: _blame_marker(repository, AFFECTED_SHA, marker)
        for name, marker in observations.items()
        if isinstance(marker, Mapping)
    }
    for origin in line_origins.values():
        origin["observed_ai_unit"] = origin["origin_sha"] in observed_shas
    if any(origin["observed_ai_unit"] for origin in line_origins.values()):
        raise SystemExit(
            "an affected-source marker unexpectedly has an observed AI origin"
        )

    retained_shas = {str(row["sha"]) for row in candidates if row["retained"] is True}
    conservation_passed = retained_shas == observed_shas and len(candidates) == len(
        observed_shas
    )
    if not conservation_passed:
        raise SystemExit("candidate conservation failed")

    payload = {
        "schema_version": 2,
        "artifact_kind": "openc3_weak_password_carrier_chronology_certificate",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository_identity": REPOSITORY_IDENTITY,
        "advisory": cve,
        "input_provenance": {
            "commit_universe": str(args.commit_universe.resolve()),
            "commit_universe_sha256": universe_sha256,
            "cve_record": str(args.cve_record.resolve()),
            "cve_record_sha256": cve_sha256,
            "repository": str(repository),
            "frozen_boundary": (
                "All claims are conditional on the 11,966 visible Git commits and "
                "55 observed AI units in the supplied all-commit universe."
            ),
        },
        "affected_release": {
            "tag": AFFECTED_TAG,
            "resolved_commit": AFFECTED_SHA,
            "metadata": affected_metadata,
            "auth_model_sha256": _sha256(source_bytes),
            "source_probe": source_probe,
            "line_origins": line_origins,
        },
        "hardened_release_snapshot": {
            "tag": HARDENED_TAG,
            "resolved_commit": HARDENED_TAG_SHA,
            "metadata": hardened_metadata,
            "contains_auth_hardening_main_landing": True,
            "contains_rate_limit_main_landing": True,
            "contains_redis_rate_limit_main_landing": True,
            "boundary": (
                "The CNA record does not name this as the exact resolved version; "
                "the tag is recorded only as a local snapshot containing all three "
                "identified landing carriers."
            ),
        },
        "mitigation_chronology": mitigation_rows,
        "mitigation_carriers": carrier_rows,
        "graph_windows": {
            "auth_hardening_main_landing": AUTH_MAIN_LANDING_SHA,
            "rate_limit_main_landing": RATE_MAIN_LANDING_SHA,
            "redis_rate_limit_main_landing": REDIS_MAIN_LANDING_SHA,
            "observed_ai_bucket_counts": bucket_counts,
            "timestamp_cutoff_authority": False,
            "boundary": (
                "Author and committer dates do not establish when a branch-only "
                "fix became available on main. Candidate windows use exact parent "
                "and carrier ancestry."
            ),
        },
        "observed_ai_candidates": candidates,
        "priority_review_shas": sorted(observed_shas),
        "direct_auth_surface_review_shas": sorted(auth_overlap),
        "auth_ui_exact_delta": auth_ui_delta,
        "adjudication": {
            "original_condition_observed_ai_attribution": (
                "EXCLUDED_BY_AFFECTED_VERSION_CHRONOLOGY"
            ),
            "mitigation_carrier_closure": "RESOLVED",
            "commit_timestamp_cutoff": "INVALID_FOR_MAINLINE_AVAILABILITY",
            "direct_auth_surface_ai_delta": "NO_PASSWORD_OR_AUTH_REQUEST_LOGIC_CHANGE",
            "cross_file_or_compositional_ai_attribution": "BLOCKED_NOT_NEGATIVE",
            "confirmed_ai_causal_role": False,
            "deletion_authority": False,
            "claim_boundary": (
                "The affected v6.0.0 state predates every observed AI unit in the "
                "frozen inventory, excluding those units only as original introducers. "
                "Branch-authored mitigation dates are not mainline landing dates: 17 "
                "observed AI units are already on main before the auth-hardening merge, "
                "and all 55 belong to an explicit main or mitigation-carrier window. "
                "The sole direct auth-path AI delta has byte-identical Login.vue script "
                "logic, so it is not a direct password-logic regression. Cross-file and "
                "carrier composition remain blocked-not-negative, and all candidates "
                "remain retained for batched review."
            ),
        },
        "conservation": {
            "visible_commit_count": len(universe),
            "observed_ai_input_count": len(observed_shas),
            "retained_candidate_count": len(retained_shas),
            "unique_retained_candidate_count": len(retained_shas),
            "hard_filter_count": 0,
            "passed": conservation_passed,
        },
    }
    _atomic_json(args.output, payload)
    print("OpenC3 carrier-aware weak-password chronology frozen")
    print(f"  visible commits       : {len(universe)}")
    print(f"  observed AI units     : {len(observed_shas)}")
    print(f"  graph buckets         : {bucket_counts}")
    print(f"  auth-path AI overlap  : {sorted(auth_overlap)}")
    print("  hard filters          : 0")
    print(f"  output                : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
