#!/usr/bin/env python3
"""Run the incremental CVE refresh campaign safely and resumably.

The campaign contract is intentionally fixed: Luna with maximum reasoning,
32 analyzer workers, frozen local-source rechecks, and forced LLM verification.
Successful batches receive content-addressed completion markers. Failed or
interrupted batches remain pending and can be rerun.
"""

from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import hashlib
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

import analysis_contract
import build_source_delta as source_delta_builder
import data_refresh_paths
from cve_analyzer.git_ops import _run_argv_bounded
from cve_analyzer.llm_client import (
    DEFAULT_LLM_REQUEST_TIMEOUT_SECONDS as REQUEST_TIMEOUT_SECONDS,
)
from cve_analyzer.llm_client import (
    MAX_REASONING_OUTPUT_TOKENS_CEILING,
    MAX_REASONING_OUTPUT_TOKENS_FLOOR,
    resolve_litellm_config,
)
from cve_analyzer.models import (
    ANALYSIS_STAGE_NAMES,
    SIGNAL_CLASSIFICATION_METHODS,
    analysis_stage_receipts_are_valid,
)

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent

MODEL = "gpt-5.6-luna"
REASONING_EFFORT = "max"
FROZEN_LOCAL_SOURCES_ENV = "CVE_ANALYZER_FROZEN_LOCAL_SOURCES"
LLM_MODEL_OVERRIDE_ENV = "CVE_LLM_MODEL_OVERRIDE"
LLM_STRICT_MODEL_ENV = "CVE_LLM_STRICT_MODEL"
LLM_DISABLE_CACHE_ENV = "CVE_LLM_DISABLE_CACHE"
LLM_CONCURRENCY_ENV = "CVE_LLM_CONCURRENCY"
RESULT_DIR_ENV = "CVE_ANALYZER_RESULT_DIR"
API_CACHE_DIR_ENV = "CVE_ANALYZER_API_CACHE_DIR"
DERIVED_CACHE_ROOT_ENV = "CVE_ANALYZER_DERIVED_CACHE_ROOT"
CAMPAIGN_ID_ENV = "CVE_ANALYZER_CAMPAIGN_ID"
CAMPAIGN_BATCH_ENV = "CVE_ANALYZER_CAMPAIGN_BATCH"
CAMPAIGN_STARTED_AT_ENV = "CVE_ANALYZER_CAMPAIGN_STARTED_AT"
CAMPAIGN_SOURCE_ENV = "CVE_ANALYZER_SOURCE_SHA256"
CAMPAIGN_CONTRACT_ENV = "CVE_ANALYZER_CONTRACT_SHA256"
CAMPAIGN_LITELLM_TRANSPORT_ENV = "CVE_ANALYZER_LITELLM_TRANSPORT_SHA256"
CAMPAIGN_ALIAS_DELTA_ENV = "CVE_ANALYZER_ALIAS_CLASS_SOURCE_DELTA"
CAMPAIGN_ALIAS_MANIFEST_ENV = "CVE_ANALYZER_ALIAS_CLASS_MANIFEST_SHA256"
PILOT_BUDGET_LEDGER_ENV = "CVE_LLM_PILOT_BUDGET_LEDGER"
PILOT_ID_ENV = "CVE_LLM_PILOT_ID"
PINNED_REPOSITORY_IDENTITY_ENV = "CVE_ANALYZER_PINNED_REPOSITORY_IDENTITY"
PINNED_REPOSITORY_PATH_ENV = "CVE_ANALYZER_PINNED_REPOSITORY_PATH"
PINNED_REPOSITORY_ORIGIN_ENV = "CVE_ANALYZER_PINNED_REPOSITORY_ORIGIN"
PINNED_REPOSITORY_HEAD_ENV = "CVE_ANALYZER_PINNED_REPOSITORY_HEAD"
PINNED_REPOSITORY_TREE_ENV = "CVE_ANALYZER_PINNED_REPOSITORY_TREE"
WORKERS = 32
LLM_CONCURRENCY = 4
MIN_FREE_BYTES = 120 * 1024**3
BATCH_TIMEOUT_SECONDS = 12 * 60 * 60
BATCH_TERMINATION_GRACE_SECONDS = 10
RESULT_RECEIPT_WRITE_GRACE_NS = 250_000_000
MAX_RESULT_JSON_BYTES = 32 * 1024 * 1024
# Source acquisition imports this campaign limit to reject oversized NVD
# metadata before download. Keep one numeric definition in the source builder.
MAX_NVD_JSON_BYTES = source_delta_builder.MAX_NVD_JSON_BYTES
MARKER_SCHEMA_VERSION = 7
SOURCE_DELTA_SCHEMA_VERSION = 3
BATCH_MANIFEST_SCHEMA_VERSION = 3
SOURCE_SNAPSHOT_SCHEMA_VERSION = 2
CAMPAIGN_LOCK_KEY = "campaign-global"
SOURCE_GIT_QUERY_TIMEOUT_SECONDS = source_delta_builder.GIT_COMMAND_TIMEOUT_SECONDS
OPENCLAW_PILOT_CLASS_COUNT = 24
OPENCLAW_PILOT_GATE_CONTRACT_VERSION = 1
OPENCLAW_PILOT_TIMEOUT_SECONDS = 60 * 60
OPENCLAW_PILOT_MAX_ATTEMPTS = 72
OPENCLAW_PILOT_MAX_COST_MICROUSD = 25_000_000
OPENCLAW_SMOKE_TIMEOUT_SECONDS = BATCH_TIMEOUT_SECONDS
OPENCLAW_SMOKE_MAX_ATTEMPTS = OPENCLAW_PILOT_MAX_ATTEMPTS
OPENCLAW_SMOKE_MAX_COST_MICROUSD = OPENCLAW_PILOT_MAX_COST_MICROUSD
OPENCLAW_GIT_FETCH_TIMEOUT_SECONDS = 60 * 60
PILOT_MODEL_INFO_TIMEOUT_SECONDS = 30.0
PILOT_MODEL_INFO_MAX_BYTES = 4 * 1024 * 1024
_OPENCLAW_REPOSITORY_MARKER = "github.com/openclaw/openclaw"
_OPENCLAW_ORIGIN = "https://github.com/openclaw/openclaw"
_OPENCLAW_BRANCH = "main"
_OPENCLAW_REMOTE_TRACKING_REF = "refs/remotes/origin/main"
_OPENCLAW_FETCH_REFSPEC = "refs/heads/main:refs/remotes/origin/main"

_CVELIST_ORIGIN = "https://github.com/CVEProject/cvelistV5.git"
_GHSA_ORIGIN = "https://github.com/github/advisory-database.git"
_GEMNASIUM_ORIGIN = "https://gitlab.com/gitlab-org/advisories-community.git"
_REQUIRED_NVD_FEEDS = frozenset(
    {
        "nvdcve-2.0-2025.json.gz",
        "nvdcve-2.0-2026.json.gz",
    }
)
_SUBJECT_ID = re.compile(
    r"[A-Za-z][A-Za-z0-9._:+-]{0,198}-[A-Za-z0-9][A-Za-z0-9._:+-]{0,198}"
)


class RunnerError(RuntimeError):
    """A fail-closed campaign validation or execution error."""


class CampaignSignalInterrupt(BaseException):
    """A process signal converted into a catchable campaign interruption."""

    def __init__(self, signum: int) -> None:
        self.signum = signum
        self.signal_name = signal.Signals(signum).name
        super().__init__(self.signal_name)


@contextmanager
def _campaign_signal_handlers() -> Iterator[None]:
    """Convert shell disconnect/termination signals so children are reaped."""

    handled = (signal.SIGHUP, signal.SIGTERM)
    previous = {signum: signal.getsignal(signum) for signum in handled}

    def interrupt(signum: int, _frame: Any) -> None:
        raise CampaignSignalInterrupt(signum)

    try:
        for signum in handled:
            signal.signal(signum, interrupt)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


@dataclass(frozen=True)
class RunnerPaths:
    """All campaign inputs and durable output locations."""

    repo_root: Path
    analyzer_dir: Path
    grouped_dir: Path
    legacy_batch: Path
    collision_inventory: Path
    state_dir: Path
    log_dir: Path
    result_dir: Path
    cvelist_dir: Path
    ghsa_dir: Path
    gemnasium_dir: Path
    nvd_feeds_dir: Path
    osv_bulk_dir: Path
    osv_ecosystems_file: Path
    source_remote_receipt: Path

    @classmethod
    def defaults(cls, repo_root: Path = _REPO_ROOT) -> RunnerPaths:
        root = repo_root.resolve()
        refresh_state = data_refresh_paths.data_refresh_state_root(root)
        return cls(
            repo_root=root,
            analyzer_dir=root / "cve-analyzer",
            grouped_dir=refresh_state / "grouped-batches-v1",
            legacy_batch=refresh_state / "batches-v1" / "batch-001.txt",
            collision_inventory=refresh_state / "missing-required-repos.txt",
            state_dir=refresh_state / "refresh-runner-v1",
            log_dir=data_refresh_paths.data_refresh_log_root(root),
            result_dir=Path.home() / ".cache" / "cve-analyzer" / "results",
            cvelist_dir=Path.home() / ".cache" / "cve-analyzer" / "cvelistV5",
            ghsa_dir=Path.home() / ".cache" / "cve-analyzer" / "advisory-database",
            gemnasium_dir=Path.home() / ".cache" / "cve-analyzer" / "gemnasium-db",
            nvd_feeds_dir=Path.home() / ".cache" / "cve-analyzer" / "nvd-feeds",
            osv_bulk_dir=Path.home() / ".cache" / "cve-analyzer" / "osv-bulk",
            osv_ecosystems_file=(
                Path.home()
                / ".cache"
                / "cve-analyzer"
                / "osv-bulk"
                / source_delta_builder.OSV_ECOSYSTEMS_FILENAME
            ),
            source_remote_receipt=(refresh_state / "source-remote-check-now.json"),
        )


@dataclass(frozen=True)
class BatchSpec:
    """One immutable unit of campaign work."""

    key: str
    path: Path
    kind: str
    ids: tuple[str, ...]
    repos: frozenset[str]
    class_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class LegacyCollision:
    """One static legacy-cache ambiguity that requires runtime resolution."""

    request_url: str
    repo_identity: str
    expected_new_dir: Path
    legacy_dir: Path


@dataclass(frozen=True)
class SourceSnapshot:
    """Canonical, content-addressed view of every local advisory source."""

    sha256: str
    details: dict[str, Any]


@dataclass(frozen=True)
class CampaignExecution:
    """Content-addressed, isolated writable state for one fixed campaign."""

    campaign_id: str
    root: Path
    result_dir: Path
    api_cache_dir: Path
    derived_cache_root: Path
    source_snapshot_sha256: str
    contract_sha256: str
    litellm_transport_sha256: str
    litellm_transport: dict[str, Any]
    analyzer_contract_sha256: str = ""
    signature_sha256: str = ""
    alias_class_delta_path: str = ""
    alias_class_manifest_sha256: str = ""
    analysis_checkout: dict[str, Any] | None = None


@dataclass(frozen=True)
class PilotPricing:
    """Explicit worst-case pricing inputs for one release-ineligible pilot."""

    input_usd_per_million_tokens: str
    output_usd_per_million_tokens: str
    max_input_tokens: int
    max_output_tokens: int
    max_cost_microusd: int
    max_attempts: int = OPENCLAW_PILOT_MAX_ATTEMPTS


CommandRunner = Callable[..., int]
DiskFree = Callable[[Path], int]
CacheResolver = Callable[[str], Path]
BatchValidator = Callable[[BatchSpec, int], dict[str, Any]]
SourceSnapshotProvider = Callable[[RunnerPaths], SourceSnapshot]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _iso_timestamp_ns(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    delta = parsed.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return (
        delta.days * 86_400 + delta.seconds
    ) * 1_000_000_000 + delta.microseconds * 1_000


def _read_nonempty_lines(path: Path) -> tuple[str, ...]:
    try:
        lines = tuple(
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    except (OSError, UnicodeError) as exc:
        raise RunnerError(f"cannot read batch file {path}: {exc}") from exc
    if not lines:
        raise RunnerError(f"batch file is empty: {path}")
    return lines


def _confined_file(directory: Path, file_name: str) -> Path:
    if not file_name or Path(file_name).name != file_name:
        raise RunnerError(
            f"grouped manifest contains unsafe batch file name: {file_name!r}"
        )
    directory = directory.resolve()
    path = (directory / file_name).resolve()
    try:
        path.relative_to(directory)
    except ValueError as exc:
        raise RunnerError(
            f"grouped batch escapes its directory: {file_name!r}"
        ) from exc
    if not path.is_file():
        raise RunnerError(f"grouped batch file is missing: {path}")
    return path


def _load_grouped_batches(
    grouped_dir: Path,
) -> tuple[list[tuple[int, BatchSpec]], dict[str, Any]]:
    manifest_path = grouped_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RunnerError(
            f"cannot read grouped batch manifest {manifest_path}: {exc}"
        ) from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != BATCH_MANIFEST_SCHEMA_VERSION
    ):
        raise RunnerError(
            f"grouped batch manifest requires schema_version {BATCH_MANIFEST_SCHEMA_VERSION}"
        )

    verification = manifest.get("verification")
    inputs = manifest.get("inputs")
    formal_full = (
        isinstance(inputs, dict) and inputs.get("population_policy") == "formal_full"
    )
    required_proofs = (
        (
            "all_remaining_ids_exactly_once",
            "alias_classes_exactly_once",
            "shared_repositories_are_scheduling_affinity",
            "normal_batches_within_targets",
        )
        if formal_full
        else (
            "all_remaining_ids_exactly_once",
            "each_repo_owned_by_one_batch",
            "normal_batches_within_targets",
        )
    )
    if not isinstance(verification, dict) or any(
        verification.get(proof) is not True for proof in required_proofs
    ):
        raise RunnerError(
            "grouped batch manifest is missing required true verification proofs"
        )

    raw_batches = manifest.get("batches")
    if not isinstance(raw_batches, list) or not raw_batches:
        raise RunnerError(
            "grouped batch manifest must contain a non-empty batches array"
        )

    grouped: list[tuple[int, BatchSpec]] = []
    seen_numbers: set[int] = set()
    for raw in raw_batches:
        if not isinstance(raw, dict):
            raise RunnerError("every grouped batch manifest entry must be an object")
        number = raw.get("batch")
        if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
            raise RunnerError(f"invalid grouped batch number: {number!r}")
        if number in seen_numbers:
            raise RunnerError(f"duplicate grouped batch number: {number}")
        seen_numbers.add(number)

        expected_name = f"batch-{number:03d}.txt"
        file_name = raw.get("file")
        if file_name != expected_name:
            raise RunnerError(f"grouped batch {number} must use {expected_name}")
        path = _confined_file(grouped_dir, file_name)
        lines = _read_nonempty_lines(path)
        raw_ids = raw.get("ids")
        if not isinstance(raw_ids, list) or not all(
            isinstance(value, str) and value for value in raw_ids
        ):
            raise RunnerError(f"grouped batch {number} has invalid ids metadata")
        if tuple(raw_ids) != lines or raw.get("id_count") != len(lines):
            raise RunnerError(
                f"grouped batch {number} file does not match manifest ids"
            )
        if len(set(lines)) != len(lines):
            raise RunnerError(f"grouped batch {number} contains duplicate IDs")

        raw_repos = raw.get("repos")
        if not isinstance(raw_repos, list) or not all(
            isinstance(value, str) and value for value in raw_repos
        ):
            raise RunnerError(f"grouped batch {number} has invalid repos metadata")
        repos = frozenset(_normalize_repo(value) for value in raw_repos)
        if raw.get("repo_count") != len(repos):
            raise RunnerError(
                f"grouped batch {number} repo count does not match manifest"
            )
        kind = raw.get("kind")
        if not isinstance(kind, str) or not kind:
            raise RunnerError(f"grouped batch {number} has invalid kind")
        raw_class_ids = raw.get("class_ids", [])
        if not isinstance(raw_class_ids, list) or any(
            not isinstance(value, str) or not value for value in raw_class_ids
        ):
            raise RunnerError(f"grouped batch {number} has invalid class IDs")
        if formal_full and len(raw_class_ids) != len(lines):
            raise RunnerError(
                f"formal grouped batch {number} must bind one class per analysis subject"
            )

        grouped.append(
            (
                number,
                BatchSpec(
                    key=f"grouped-{number:03d}",
                    path=path,
                    kind=kind,
                    ids=lines,
                    repos=repos,
                    class_ids=tuple(raw_class_ids),
                ),
            )
        )

    if 1 not in seen_numbers:
        raise RunnerError("grouped campaign requires batch 001")
    return grouped, manifest


def _manifest_path_label(path: Path, repo_root: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return str(resolved)


def _validated_subject_sequence(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise RunnerError(f"source delta {label} must be an ID array")
    output: list[str] = []
    for subject in value:
        if (
            not isinstance(subject, str)
            or not _SUBJECT_ID.fullmatch(subject)
            or Path(subject).name != subject
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in subject)
        ):
            raise RunnerError(f"source delta {label} contains an unsafe ID")
        output.append(subject)
    if output != sorted(output) or len(output) != len(set(output)):
        raise RunnerError(f"source delta {label} must be sorted and contain unique IDs")
    return tuple(output)


def _id_sequence_sha256(values: Sequence[str]) -> str:
    data = ("\n".join(sorted(values)) + "\n").encode() if values else b""
    return hashlib.sha256(data).hexdigest()


def _validate_alias_class_manifest(
    manifest: object,
    *,
    production_ids: Sequence[str],
    candidate_ids: Sequence[str],
    source_snapshot_sha256: str,
) -> dict[str, dict[str, Any]]:
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise RunnerError("formal alias-class manifest is missing or malformed")
    classes = manifest.get("classes")
    if not isinstance(classes, list) or not classes:
        raise RunnerError("formal alias-class manifest has no classes")
    if (
        manifest.get("classes_sha256")
        != hashlib.sha256(_canonical_json_bytes(classes)).hexdigest()
    ):
        raise RunnerError("formal alias-class manifest digest is invalid")
    if manifest.get("source_snapshot_sha256") != source_snapshot_sha256:
        raise RunnerError("formal alias-class source snapshot binding is stale")

    member_owner: dict[str, str] = {}
    scheduled: dict[str, dict[str, Any]] = {}
    eligible_counts: Counter[str] = Counter()
    class_ids: set[str] = set()
    for class_record in classes:
        if not isinstance(class_record, dict):
            raise RunnerError("formal alias-class record is malformed")
        class_id = class_record.get("class_id")
        component_sha256 = class_record.get("component_sha256")
        members = class_record.get("all_member_ids")
        eligible = class_record.get("eligible_seed_ids")
        scheduled_seeds = class_record.get("scheduled_seed_ids")
        subject = class_record.get("analysis_subject")
        if (
            not isinstance(class_id, str)
            or not class_id
            or class_id in class_ids
            or not isinstance(component_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", component_sha256)
            or not isinstance(members, list)
            or not members
            or any(not isinstance(item, str) for item in members)
            or len(members) != len(set(members))
            or not isinstance(eligible, list)
            or any(not isinstance(item, str) for item in eligible)
            or not isinstance(scheduled_seeds, list)
            or any(not isinstance(item, str) for item in scheduled_seeds)
            or not isinstance(subject, str)
            or not subject
            or class_record.get("source_snapshot_sha256") != source_snapshot_sha256
        ):
            raise RunnerError("formal alias-class record is malformed")
        expected_component = hashlib.sha256(
            ("\n".join(sorted(members)) + "\n").encode()
        ).hexdigest()
        if component_sha256 != expected_component or not set(eligible).issubset(
            members
        ):
            raise RunnerError("formal alias-class component proof is invalid")
        if (
            scheduled_seeds != sorted(scheduled_seeds)
            or len(scheduled_seeds) != len(set(scheduled_seeds))
            or not set(scheduled_seeds).issubset(eligible)
        ):
            raise RunnerError(
                "formal scheduled seeds must form a sorted unique subset of their "
                "eligible alias class"
            )
        if not scheduled_seeds:
            raise RunnerError("formal alias class is unscheduled")
        if subject not in eligible:
            raise RunnerError(
                "formal analysis subject must belong to its eligible alias class"
            )
        class_ids.add(class_id)
        for member in members:
            previous = member_owner.setdefault(member, class_id)
            if previous != class_id:
                raise RunnerError("formal alias classes overlap")
        eligible_counts.update(eligible)
        if subject in scheduled:
            raise RunnerError("formal analysis subject is scheduled more than once")
        scheduled[subject] = class_record

    production_set = set(production_ids)
    if any(eligible_counts[item] != 1 for item in production_set):
        raise RunnerError(
            "formal alias classes do not cover production IDs exactly once"
        )
    if any(count != 1 for count in eligible_counts.values()):
        raise RunnerError("formal eligible IDs do not form an exact partition")
    if (
        manifest.get("class_count") != len(classes)
        or manifest.get("scheduled_class_count") != len(classes)
        or manifest.get("scheduled_analysis_subject_count") != len(classes)
        or manifest.get("eligible_seed_id_count") != len(eligible_counts)
        or manifest.get("all_eligible_seed_ids_exactly_once") is not True
        or len(candidate_ids) != len(classes)
    ):
        raise RunnerError("formal alias-class counts do not prove full scheduling")
    if set(scheduled) != set(candidate_ids):
        raise RunnerError("formal candidates do not match scheduled alias classes")
    if manifest.get("scheduled_classes_exactly_once") is not True or manifest.get(
        "scheduled_analysis_subject_count"
    ) != len(candidate_ids):
        raise RunnerError("formal alias-class scheduling proof is incomplete")
    return scheduled


def _nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _source_delta_paths(
    paths: RunnerPaths,
    *,
    delta_path: Path,
    candidate_path: Path,
    discovery_since: str,
    corpus_present: bool,
    population_policy: str = source_delta_builder.FORMAL_FULL_POLICY,
) -> source_delta_builder.BuildPaths:
    refresh_root = paths.grouped_dir.resolve().parent
    baseline = refresh_root / "source-before-final"
    corpus_path = refresh_root / "adjudicated-corpus-subjects.txt"
    return source_delta_builder.BuildPaths(
        repo_root=paths.repo_root.resolve(),
        baseline_dir=baseline,
        git_sources=(
            source_delta_builder.GitSource(
                "cvelistV5",
                paths.cvelist_dir,
                baseline / "cvelistV5.head",
                _CVELIST_ORIGIN,
            ),
            source_delta_builder.GitSource(
                "github-advisory-database",
                paths.ghsa_dir,
                baseline / "github-advisory-database.head",
                _GHSA_ORIGIN,
            ),
            source_delta_builder.GitSource(
                "gemnasium-db",
                paths.gemnasium_dir,
                baseline / "gemnasium-db.head",
                _GEMNASIUM_ORIGIN,
            ),
        ),
        nvd_dir=paths.nvd_feeds_dir,
        osv_dir=paths.osv_bulk_dir,
        osv_ecosystems_file=paths.osv_ecosystems_file,
        result_cache_dir=paths.result_dir,
        delta_output=delta_path,
        candidate_output=candidate_path,
        adjudicated_corpus_file=corpus_path if corpus_present else None,
        discovery_since=discovery_since,
        population_policy=population_policy,
    )


def _validate_source_delta_contract(
    paths: RunnerPaths,
    *,
    delta_path: Path,
    candidate_path: Path,
    candidate_ids: Sequence[str],
    recapture_current_inputs: bool = True,
    replay_semantics: bool = True,
) -> dict[str, Any]:
    """Verify the schema-3 completeness proof against every current input."""

    try:
        if delta_path.is_symlink() or not delta_path.is_file():
            raise RunnerError(f"source delta must be a regular file: {delta_path}")
        delta = json.loads(delta_path.read_text(encoding="utf-8"))
    except RunnerError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"cannot read source delta {delta_path}: {exc}") from exc
    if (
        not isinstance(delta, dict)
        or delta.get("schema_version") != SOURCE_DELTA_SCHEMA_VERSION
    ):
        raise RunnerError(
            f"source delta requires schema_version {SOURCE_DELTA_SCHEMA_VERSION}"
        )
    required_top_level = {
        "schema_version",
        "generated_at_utc",
        "source_snapshot_time",
        "purpose",
        "population_policy",
        "analyzer_contract",
        "input_snapshot_sha256",
        "input_snapshot",
        "baseline",
        "coverage",
        "git",
        "nvd",
        "osv",
        "production_discovery",
        "result_cache",
        "all_id_count",
        "all_ids",
        "candidate",
        "integrity_payload_sha256",
    }
    if set(delta) != required_top_level:
        raise RunnerError("source delta has an unexpected top-level contract")
    if _iso_timestamp_ns(delta.get("generated_at_utc")) is None or delta.get(
        "source_snapshot_time"
    ) != delta.get("generated_at_utc"):
        raise RunnerError("source delta has an invalid snapshot timestamp")

    integrity = delta.get("integrity_payload_sha256")
    unsigned = dict(delta)
    unsigned.pop("integrity_payload_sha256", None)
    expected_integrity = hashlib.sha256(
        (json.dumps(unsigned, indent=2, sort_keys=False) + "\n").encode()
    ).hexdigest()
    if integrity != expected_integrity:
        raise RunnerError("source delta integrity payload hash is invalid")

    production = delta.get("production_discovery")
    cache = delta.get("result_cache")
    candidate = delta.get("candidate")
    input_snapshot = delta.get("input_snapshot")
    coverage = delta.get("coverage")
    git_delta = delta.get("git")
    nvd_delta = delta.get("nvd")
    osv_delta = delta.get("osv")
    objects = {
        "production_discovery": production,
        "result_cache": cache,
        "candidate": candidate,
        "input_snapshot": input_snapshot,
        "coverage": coverage,
        "git": git_delta,
        "nvd": nvd_delta,
        "osv": osv_delta,
    }
    malformed = [name for name, value in objects.items() if not isinstance(value, dict)]
    if malformed:
        raise RunnerError(
            f"source delta object contract is malformed: {', '.join(malformed)}"
        )

    assert isinstance(production, dict)
    assert isinstance(cache, dict)
    assert isinstance(candidate, dict)
    assert isinstance(input_snapshot, dict)
    assert isinstance(coverage, dict)
    assert isinstance(git_delta, dict)
    assert isinstance(nvd_delta, dict)
    assert isinstance(osv_delta, dict)

    discovery_since = production.get("since")
    try:
        if not isinstance(discovery_since, str):
            raise ValueError
        parsed_since = datetime.strptime(discovery_since, "%Y-%m-%d")
        if parsed_since.strftime("%Y-%m-%d") != discovery_since:
            raise ValueError
    except ValueError as exc:
        raise RunnerError("source delta discovery cutoff is invalid") from exc
    required_discovery_values = {
        "scope": "local OSV blameable records plus local GHSA supplement",
        "include_ghsa": True,
        "repo_filter": None,
        "limit": None,
        "frozen_local_sources": True,
        "network_advisory_api_included": False,
        "alias_aware_cache_coverage": True,
    }
    for field, expected in required_discovery_values.items():
        if production.get(field) != expected:
            raise RunnerError(f"source delta production discovery mismatch for {field}")
    alias_components = production.get("alias_components")
    alias_class_manifest = production.get("alias_class_manifest")
    ghsa_inventory = production.get("ghsa_inventory")
    if (
        not isinstance(alias_components, dict)
        or alias_components.get("transitive") is not True
        or not isinstance(ghsa_inventory, dict)
        or ghsa_inventory.get("all_json_records_valid") is not True
        or production.get("ghsa_loaded_record_count")
        != ghsa_inventory.get("since_eligible_file_count")
    ):
        raise RunnerError("source delta alias or GHSA inventory proof is incomplete")

    sequence_contracts = (
        ("production_discovered", "production_discovered_ids"),
        ("cache_covered_discovered", "cache_covered_discovered_ids"),
        ("uncached_discovered", "uncached_discovered_ids"),
        ("uncached_osv", "uncached_osv_ids"),
        ("uncached_ghsa_supplement", "uncached_ghsa_supplement_ids"),
    )
    discovery_ids: dict[str, tuple[str, ...]] = {}
    for prefix, field in sequence_contracts:
        values = _validated_subject_sequence(production.get(field), field)
        if production.get(f"{prefix}_id_count") != len(values):
            raise RunnerError(f"source delta count mismatch for {field}")
        if production.get(f"{prefix}_ids_sha256") != _id_sequence_sha256(values):
            raise RunnerError(f"source delta hash mismatch for {field}")
        discovery_ids[prefix] = values

    all_discovered = set(discovery_ids["production_discovered"])
    covered = set(discovery_ids["cache_covered_discovered"])
    uncached = set(discovery_ids["uncached_discovered"])
    uncached_osv = set(discovery_ids["uncached_osv"])
    uncached_ghsa = set(discovery_ids["uncached_ghsa_supplement"])
    if covered & uncached or all_discovered != covered | uncached:
        raise RunnerError("source delta cache coverage is not an exact partition")
    if uncached_osv & uncached_ghsa or uncached != uncached_osv | uncached_ghsa:
        raise RunnerError("source delta uncached source split is not exact")
    osv_discovered_count = _nonnegative_int(production.get("osv_discovered_id_count"))
    ghsa_supplement_count = _nonnegative_int(production.get("ghsa_supplement_id_count"))
    if (
        osv_discovered_count is None
        or ghsa_supplement_count is None
        or osv_discovered_count + ghsa_supplement_count != len(all_discovered)
    ):
        raise RunnerError("source delta production source counts are inconsistent")

    population_policy = delta.get("population_policy")
    if population_policy not in {
        source_delta_builder.FORMAL_FULL_POLICY,
        source_delta_builder.INCREMENTAL_POLICY,
    }:
        raise RunnerError("source delta population policy is invalid")
    analyzer_contract_payload = delta.get("analyzer_contract")
    if not isinstance(analyzer_contract_payload, dict):
        raise RunnerError("source delta analyzer contract is malformed")
    try:
        current_analyzer_contract = analysis_contract.analysis_contract_epoch(
            paths.repo_root
        )
    except analysis_contract.AnalysisContractError as exc:
        raise RunnerError(f"cannot recapture analyzer contract epoch: {exc}") from exc
    if analyzer_contract_payload != current_analyzer_contract:
        raise RunnerError("source delta analyzer contract epoch is stale")

    cache_policy = cache.get("coverage_policy")
    known_nonterminal = (
        cache_policy.get("known_nonterminal_categories")
        if isinstance(cache_policy, dict)
        else None
    )
    eligible_result_count = _nonnegative_int(
        cache.get("coverage_eligible_result_count")
    )
    if (
        cache.get("all_json_results_schema_valid") is not True
        or not isinstance(cache_policy, dict)
        or cache_policy.get("production_max_age_days") is not None
        or cache_policy.get("infrastructure_and_unsupported_errors_eligible")
        is not False
        or cache_policy.get("scope") != "incremental_diagnostic_only"
        or cache_policy.get("formal_population_suppression_enabled") is not False
        or cache_policy.get("formal_current_epoch_stage_receipt_required") is not True
        or cache_policy.get("current_luna_max_receipt_required") is not False
        or not isinstance(known_nonterminal, list)
        or "no_ai_activity" not in known_nonterminal
        or eligible_result_count is None
        or eligible_result_count < len(covered)
    ):
        raise RunnerError("source delta result-cache coverage policy is unsafe")

    all_ids = _validated_subject_sequence(delta.get("all_ids"), "all_ids")
    if delta.get("all_id_count") != len(all_ids):
        raise RunnerError("source delta all_ids count is inconsistent")
    expected_git_names = {
        "cvelistV5": "cvelistV5",
        "github-advisory-database": "github-advisory-database",
        "gemnasium-db": "gemnasium-db",
    }
    if set(git_delta) != set(expected_git_names):
        raise RunnerError("source delta Git source inventory is incomplete")
    subject_union: set[str] = set()
    for name, entry in git_delta.items():
        if not isinstance(entry, dict):
            raise RunnerError(f"source delta Git entry is malformed: {name}")
        subjects = _validated_subject_sequence(entry.get("subject_ids"), f"git.{name}")
        if entry.get("subject_id_count") != len(subjects):
            raise RunnerError(f"source delta Git subject count mismatch: {name}")
        subject_union.update(subjects)

    snapshot_nvd = input_snapshot.get("nvd")
    snapshot_osv = input_snapshot.get("osv")
    snapshot_osv_names = input_snapshot.get("osv_archive_names")
    snapshot_osv_manifest = input_snapshot.get("osv_ecosystem_manifest")
    if not isinstance(snapshot_nvd, dict) or not isinstance(snapshot_osv, dict):
        raise RunnerError("source delta snapshot archive inventory is malformed")
    try:
        manifest_data = paths.osv_ecosystems_file.read_bytes()
        manifest_inventory = source_delta_builder.parse_osv_ecosystems_manifest(
            manifest_data
        )
    except (OSError, source_delta_builder.SourceDeltaError) as exc:
        raise RunnerError(
            f"source delta OSV ecosystem manifest is invalid: {exc}"
        ) from exc
    manifest_path_from_snapshot = Path(
        str(
            snapshot_osv_manifest.get("path", "")
            if isinstance(snapshot_osv_manifest, dict)
            else ""
        )
    )
    if not manifest_path_from_snapshot.is_absolute():
        manifest_path_from_snapshot = paths.repo_root / manifest_path_from_snapshot
    if (
        not isinstance(snapshot_osv_manifest, dict)
        or set(snapshot_osv_manifest)
        != {
            "path",
            "sha256",
            "size_bytes",
            "ecosystem_count",
            "ecosystems",
        }
        or snapshot_osv_manifest.get("sha256")
        != hashlib.sha256(manifest_data).hexdigest()
        or manifest_path_from_snapshot.resolve() != paths.osv_ecosystems_file.resolve()
        or snapshot_osv_manifest.get("size_bytes") != len(manifest_data)
        or snapshot_osv_manifest.get("ecosystem_count")
        != len(manifest_inventory.ecosystems)
        or snapshot_osv_manifest.get("ecosystems")
        != list(manifest_inventory.ecosystems)
        or not isinstance(snapshot_osv_names, list)
        or not snapshot_osv_names
        or any(not isinstance(name, str) for name in snapshot_osv_names)
        or tuple(snapshot_osv_names) != tuple(snapshot_osv)
        or tuple(snapshot_osv_names) != manifest_inventory.archive_names
    ):
        raise RunnerError(
            "source delta snapshot OSV archive filename inventory is malformed"
        )
    expected_nvd = {
        match.group(1): details
        for file_name, details in snapshot_nvd.items()
        if (match := re.fullmatch(r"nvdcve-2\.0-([0-9]{4})\.json\.gz", file_name))
    }
    if len(expected_nvd) != len(snapshot_nvd) or set(nvd_delta) != set(expected_nvd):
        raise RunnerError("source delta NVD inventory is incomplete")
    for name, entry in nvd_delta.items():
        if not isinstance(entry, dict):
            raise RunnerError(f"source delta NVD entry is malformed: {name}")
        subjects = _validated_subject_sequence(entry.get("subject_ids"), f"nvd.{name}")
        if entry.get("subject_id_count") != len(subjects) or entry.get(
            "current_sha256"
        ) != expected_nvd[name].get("sha256"):
            raise RunnerError(f"source delta NVD proof mismatch: {name}")
        subject_union.update(subjects)
    expected_osv = {Path(name).stem: details for name, details in snapshot_osv.items()}
    if set(osv_delta) != set(expected_osv):
        raise RunnerError("source delta OSV inventory is incomplete")
    for name, entry in osv_delta.items():
        if not isinstance(entry, dict):
            raise RunnerError(f"source delta OSV entry is malformed: {name}")
        subjects = _validated_subject_sequence(entry.get("subject_ids"), f"osv.{name}")
        if entry.get("subject_id_count") != len(subjects) or entry.get(
            "current_sha256"
        ) != expected_osv[name].get("sha256"):
            raise RunnerError(f"source delta OSV proof mismatch: {name}")
        subject_union.update(subjects)
    if tuple(sorted(subject_union)) != all_ids:
        raise RunnerError("source delta all_ids does not match source subject proofs")
    if (
        coverage.get("git_mirror_count") != len(git_delta)
        or coverage.get("nvd_feed_count") != len(nvd_delta)
        or coverage.get("current_osv_archive_count") != len(osv_delta)
    ):
        raise RunnerError("source delta coverage counts are inconsistent")

    refresh_root = paths.grouped_dir.resolve().parent
    baseline_candidate = refresh_root / "source-before-final/new-osv-candidates.txt"
    baseline_ids = _read_nonempty_lines(baseline_candidate)
    corpus_path = refresh_root / "adjudicated-corpus-subjects.txt"
    corpus_present = candidate.get("adjudicated_corpus_file") is not None
    if corpus_present != corpus_path.is_file():
        raise RunnerError("source delta adjudicated corpus presence has drifted")
    corpus_ids = _read_nonempty_lines(corpus_path) if corpus_present else ()
    raw_candidate_ids = tuple(
        dict.fromkeys(
            [
                *baseline_ids,
                *all_ids,
                *corpus_ids,
                *(
                    discovery_ids["production_discovered"]
                    if population_policy == source_delta_builder.FORMAL_FULL_POLICY
                    else discovery_ids["uncached_discovered"]
                ),
            ]
        )
    )
    baseline_duplicates = {
        subject: count for subject, count in Counter(baseline_ids).items() if count > 1
    }
    expected_candidate_values = {
        "baseline_file": _manifest_path_label(baseline_candidate, paths.repo_root),
        "baseline_sha256": file_sha256(baseline_candidate),
        "baseline_line_count": len(baseline_ids),
        "baseline_unique_id_count": len(set(baseline_ids)),
        "baseline_duplicate_line_count": len(baseline_ids) - len(set(baseline_ids)),
        "baseline_duplicates": baseline_duplicates,
        "delta_id_count": len(all_ids),
        "adjudicated_corpus_file": (
            _manifest_path_label(corpus_path, paths.repo_root)
            if corpus_present
            else None
        ),
        "adjudicated_corpus_sha256": file_sha256(corpus_path)
        if corpus_present
        else None,
        "adjudicated_corpus_id_count": len(corpus_ids),
        "adjudicated_corpus_forced_regardless_of_cache": True,
        "population_policy": population_policy,
        "formal_release_eligible": population_policy
        == source_delta_builder.FORMAL_FULL_POLICY,
        "historical_cache_suppresses_current_classes": population_policy
        == source_delta_builder.INCREMENTAL_POLICY,
        "raw_union_id_count": len(raw_candidate_ids),
        "raw_union_sha256": _id_sequence_sha256(raw_candidate_ids),
        "uncached_production_discovery_id_count": len(uncached),
        "uncached_production_discovery_added_id_count": len(
            uncached - set(baseline_ids) - set(all_ids) - set(corpus_ids)
        ),
        "output_file": _manifest_path_label(candidate_path, paths.repo_root),
        "output_id_count": len(candidate_ids),
        "output_sha256": file_sha256(candidate_path),
        "union_exact": True,
        "output_duplicate_id_count": 0,
        "output_analysis_class_count": len(candidate_ids),
    }
    if any(
        candidate.get(field) != value
        for field, value in expected_candidate_values.items()
    ):
        raise RunnerError("source delta candidate metadata is inconsistent")
    snapshot_sha256 = input_snapshot.get("sha256")
    if (
        not isinstance(snapshot_sha256, str)
        or delta.get("input_snapshot_sha256") != snapshot_sha256
    ):
        raise RunnerError("source delta input snapshot digest is inconsistent")
    guard_payload = dict(input_snapshot)
    guard_payload.pop("sha256", None)
    if (
        hashlib.sha256(_canonical_json_bytes(guard_payload)).hexdigest()
        != snapshot_sha256
    ):
        raise RunnerError("source delta input snapshot digest is invalid")
    try:
        advisory_snapshot_sha256 = source_delta_builder.advisory_source_snapshot_sha256(
            input_snapshot
        )
    except source_delta_builder.SourceDeltaError as exc:
        raise RunnerError(
            f"source delta advisory snapshot is malformed: {exc}"
        ) from exc
    scheduled_classes = _validate_alias_class_manifest(
        alias_class_manifest,
        production_ids=discovery_ids["production_discovered"],
        candidate_ids=candidate_ids,
        source_snapshot_sha256=advisory_snapshot_sha256,
    )
    if candidate.get("alias_class_manifest_sha256") != alias_class_manifest.get(
        "classes_sha256"
    ):
        raise RunnerError("source delta candidate alias-class digest is inconsistent")
    if set(candidate_ids) != set(scheduled_classes):
        raise RunnerError("source delta candidate alias-class union is not exact")

    build_paths = _source_delta_paths(
        paths,
        delta_path=delta_path,
        candidate_path=candidate_path,
        discovery_since=discovery_since,
        corpus_present=corpus_present,
        population_policy=population_policy,
    )
    current_guard = input_snapshot
    if replay_semantics:
        try:
            replayed = source_delta_builder.build_artifacts(
                build_paths,
                generated_at_utc=delta["generated_at_utc"],
            )
        except source_delta_builder.SourceDeltaError as exc:
            raise RunnerError(f"source delta semantic replay failed: {exc}") from exc
        current_guard = replayed.input_guard
        if (
            current_guard != input_snapshot
            or current_guard.get("result_cache") != cache
        ):
            raise RunnerError(
                "source delta inputs or result-cache inventory have drifted"
            )
        try:
            committed_delta_bytes = delta_path.read_bytes()
            committed_candidate_bytes = candidate_path.read_bytes()
        except OSError as exc:
            raise RunnerError(f"cannot read replayed source artifacts: {exc}") from exc
        if (
            replayed.delta_bytes != committed_delta_bytes
            or replayed.candidate_bytes != committed_candidate_bytes
        ):
            raise RunnerError(
                "source delta semantic replay does not match committed delta and candidate bytes"
            )
    elif recapture_current_inputs:
        try:
            current_guard = source_delta_builder.capture_input_guard(build_paths)
        except source_delta_builder.SourceDeltaError as exc:
            raise RunnerError(f"cannot recapture source delta inputs: {exc}") from exc

    if recapture_current_inputs and not replay_semantics:
        if (
            current_guard != input_snapshot
            or current_guard.get("result_cache") != cache
        ):
            raise RunnerError(
                "source delta inputs or result-cache inventory have drifted"
            )

    snapshot_git = input_snapshot.get("git")
    if not isinstance(snapshot_git, dict):
        raise RunnerError("source delta Git input snapshot is malformed")
    for name, entry in git_delta.items():
        current = snapshot_git.get(name)
        if (
            not isinstance(current, dict)
            or entry.get("after") != current.get("head")
            or entry.get("after_tree") != current.get("tree")
            or entry.get("origin") != current.get("origin")
        ):
            raise RunnerError(f"source delta Git proof mismatch: {name}")
    baseline = delta.get("baseline")
    if not isinstance(baseline, dict) or baseline != {
        "directory": _manifest_path_label(
            refresh_root / "source-before-final", paths.repo_root
        ),
        "sha256_manifest": current_guard["baseline"],
    }:
        raise RunnerError("source delta preserved baseline proof is inconsistent")
    return delta


def _validate_plan_inputs(
    paths: RunnerPaths,
    manifest: Mapping[str, Any],
    plan: Sequence[BatchSpec],
    *,
    recapture_delta_inputs: bool = True,
    replay_delta_semantics: bool = True,
) -> None:
    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict):
        raise RunnerError("grouped manifest has no inputs contract")
    refresh_root = paths.grouped_dir.resolve().parent
    candidate_path = refresh_root / "new-osv-candidates.txt"
    delta_path = refresh_root / "source-delta-current.json"
    expected_paths = {
        "candidate_file": _manifest_path_label(candidate_path, paths.repo_root),
        "excluded_file": _manifest_path_label(paths.legacy_batch, paths.repo_root),
        "delta_file": _manifest_path_label(delta_path, paths.repo_root),
        "osv_archive_dir": _manifest_path_label(
            paths.osv_bulk_dir,
            paths.repo_root,
        ),
    }
    for field, expected in expected_paths.items():
        if inputs.get(field) != expected:
            raise RunnerError(
                f"grouped manifest input path mismatch for {field}: "
                f"expected {expected!r}, got {inputs.get(field)!r}"
            )

    candidate_ids = _read_nonempty_lines(candidate_path)
    if len(candidate_ids) != len(set(candidate_ids)):
        raise RunnerError("current candidate file contains duplicate IDs")
    delta = _validate_source_delta_contract(
        paths,
        delta_path=delta_path,
        candidate_path=candidate_path,
        candidate_ids=candidate_ids,
        recapture_current_inputs=recapture_delta_inputs,
        replay_semantics=replay_delta_semantics,
    )
    if inputs.get("candidate_sha256") != file_sha256(candidate_path):
        raise RunnerError("grouped manifest candidate hash is stale")
    if inputs.get("excluded_sha256") != file_sha256(paths.legacy_batch):
        raise RunnerError("grouped manifest excluded batch hash is stale")
    if inputs.get("delta_sha256") != file_sha256(delta_path):
        raise RunnerError("grouped manifest source-delta hash is stale")
    if inputs.get("candidate_line_count") != len(candidate_ids) or inputs.get(
        "candidate_unique_id_count"
    ) != len(candidate_ids):
        raise RunnerError("grouped manifest candidate counts are stale")

    archives = inputs.get("archives")
    if not isinstance(archives, list):
        raise RunnerError("grouped manifest archive inventory is missing")
    manifest_archives: dict[str, Mapping[str, Any]] = {}
    for item in archives:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise RunnerError("grouped manifest archive inventory is malformed")
        name = item["name"]
        if name in manifest_archives:
            raise RunnerError(f"duplicate grouped manifest archive: {name}")
        manifest_archives[name] = item
    current_archives = {
        path.name: path
        for path in paths.osv_bulk_dir.glob("*.zip")
        if path.is_file() and not path.is_symlink()
    }
    if set(manifest_archives) != set(current_archives):
        raise RunnerError("grouped manifest OSV archive inventory is stale")
    for name, archive_path in sorted(current_archives.items()):
        item = manifest_archives[name]
        if item.get("size_bytes") != archive_path.stat().st_size or item.get(
            "sha256"
        ) != file_sha256(archive_path):
            raise RunnerError(f"grouped manifest OSV archive is stale: {name}")

    plan_ids = [subject_id for batch in plan for subject_id in batch.ids]
    duplicates = {
        subject_id: count
        for subject_id, count in Counter(plan_ids).items()
        if count > 1
    }
    if duplicates:
        raise RunnerError(
            f"campaign plan contains duplicate or overlapping IDs: "
            f"{dict(list(sorted(duplicates.items()))[:10])}"
        )
    candidate_set = set(candidate_ids)
    plan_set = set(plan_ids)
    if plan_set != candidate_set:
        missing = sorted(candidate_set - plan_set)
        unexpected = sorted(plan_set - candidate_set)
        raise RunnerError(
            "campaign plan does not exactly cover current candidates: "
            f"missing={missing[:10]}, unexpected={unexpected[:10]}"
        )
    population_policy = delta.get("population_policy")
    if inputs.get("population_policy") != population_policy:
        raise RunnerError("grouped manifest population policy is stale")
    if population_policy == source_delta_builder.FORMAL_FULL_POLICY:
        production = delta.get("production_discovery")
        alias_manifest = (
            production.get("alias_class_manifest")
            if isinstance(production, dict)
            else None
        )
        if not isinstance(alias_manifest, dict):
            raise RunnerError("formal campaign has no alias-class manifest")
        classes = alias_manifest.get("classes")
        assert isinstance(classes, list)
        subject_to_class = {
            item["analysis_subject"]: item["class_id"]
            for item in classes
            if isinstance(item, dict) and item.get("scheduled_seed_ids")
        }
        plan_classes = [subject_to_class.get(subject) for subject in plan_ids]
        if any(class_id is None for class_id in plan_classes) or len(
            set(plan_classes)
        ) != len(plan_classes):
            raise RunnerError("formal campaign classes are not covered exactly once")
        declared_classes = [class_id for batch in plan for class_id in batch.class_ids]
        expected_declared = [
            subject_to_class[subject]
            for batch in plan
            if batch.class_ids
            for subject in batch.ids
        ]
        if declared_classes != expected_declared:
            raise RunnerError("grouped manifest class IDs do not match source classes")
        if (
            inputs.get("alias_class_manifest_sha256")
            != alias_manifest.get("classes_sha256")
            or inputs.get("analyzer_contract_sha256")
            != delta["analyzer_contract"].get("sha256")
            or inputs.get("signature_sha256")
            != delta["analyzer_contract"].get("signature_sha256")
        ):
            raise RunnerError("grouped manifest formal contract binding is stale")


def load_plan(
    paths: RunnerPaths,
    *,
    recapture_delta_inputs: bool = True,
    replay_delta_semantics: bool = True,
) -> tuple[BatchSpec, ...]:
    """Load and validate the fixed campaign, including its execution order."""
    repo_root = paths.repo_root.resolve()
    if not repo_root.is_dir():
        raise RunnerError(f"repository root is missing: {repo_root}")
    if not paths.analyzer_dir.resolve().is_dir():
        raise RunnerError(
            f"analyzer project directory is missing: {paths.analyzer_dir}"
        )

    legacy_path = paths.legacy_batch.resolve()
    if not legacy_path.is_file():
        raise RunnerError(f"legacy first batch is missing: {legacy_path}")
    legacy_ids = _read_nonempty_lines(legacy_path)
    if len(legacy_ids) != len(set(legacy_ids)):
        raise RunnerError("legacy first batch contains duplicate IDs")
    legacy = BatchSpec(
        key="legacy-001",
        path=legacy_path,
        kind="legacy_resume",
        ids=legacy_ids,
        repos=frozenset(),
    )

    grouped, manifest = _load_grouped_batches(paths.grouped_dir.resolve())
    manifest_inputs = manifest.get("inputs")
    formal_full = (
        isinstance(manifest_inputs, dict)
        and manifest_inputs.get("population_policy")
        == source_delta_builder.FORMAL_FULL_POLICY
    )
    if formal_full:
        grouped_plan = tuple(batch for _number, batch in sorted(grouped))
        grouped_ids = {subject for batch in grouped_plan for subject in batch.ids}
        candidate_ids = set(
            _read_nonempty_lines(paths.grouped_dir.parent / "new-osv-candidates.txt")
        )
        if grouped_ids == candidate_ids:
            plan = grouped_plan
        elif grouped_ids | set(legacy.ids) == candidate_ids and not (
            grouped_ids & set(legacy.ids)
        ):
            plan = (legacy, *grouped_plan)
        else:
            raise RunnerError(
                "formal grouped and legacy batches do not form an exact candidate partition"
            )
    else:
        normal = [batch for number, batch in sorted(grouped) if number != 1]
        large = [batch for number, batch in grouped if number == 1]
        plan = (legacy, *normal, *large)
    _validate_plan_inputs(
        paths,
        manifest,
        plan,
        recapture_delta_inputs=recapture_delta_inputs,
        replay_delta_semantics=replay_delta_semantics,
    )
    return plan


def _normalize_repo(value: str) -> str:
    candidate = value.strip()
    parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
    host = (parsed.hostname or "").lower()
    path = parsed.path.rstrip("/")
    if path.lower().endswith(".git"):
        path = path[:-4]
    normalized = f"{host}{path}".lower()
    if not host or not path:
        raise RunnerError(f"invalid repository identity: {value!r}")
    return normalized


def load_legacy_collisions(path: Path) -> tuple[LegacyCollision, ...]:
    """Load host-qualified repo identities with ambiguous legacy cache paths."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise RunnerError(
            f"cannot read legacy collision inventory {path}: {exc}"
        ) from exc

    collisions: list[LegacyCollision] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) != 3:
            raise RunnerError(
                f"malformed collision inventory line {line_number}: expected 3 tab-separated fields"
            )
        if fields[2].startswith("legacy-origin-collision:"):
            expected_new_dir = Path(fields[1])
            legacy_dir = Path(fields[2].split(":", 1)[1])
            if not expected_new_dir.is_absolute() or not legacy_dir.is_absolute():
                raise RunnerError(
                    f"collision inventory line {line_number} requires absolute cache paths"
                )
            collisions.append(
                LegacyCollision(
                    request_url=fields[0],
                    repo_identity=_normalize_repo(fields[0]),
                    expected_new_dir=expected_new_dir,
                    legacy_dir=legacy_dir,
                )
            )
    return tuple(collisions)


def _default_cache_resolver(url: str) -> Path:
    """Resolve through the analyzer's production cache policy."""
    from cve_analyzer.git_ops import url_to_cache_dir

    return url_to_cache_dir(url)


def unresolved_legacy_collisions(
    collisions: Sequence[LegacyCollision],
    cache_resolver: CacheResolver,
) -> frozenset[str]:
    """Return collision identities that remain unsafe after runtime checks.

    A static inventory entry becomes safe only when the production resolver
    selects either the recorded host-qualified path or the current digest-backed
    v2 identity path.
    Resolver errors, aliases back to the legacy path, path drift, symlinks, and
    malformed inventory relationships all remain blocked.
    """
    unresolved: set[str] = set()
    for collision in collisions:
        try:
            resolved = Path(cache_resolver(collision.request_url)).absolute()
            expected = collision.expected_new_dir.absolute()
            legacy = collision.legacy_dir.absolute()
            host = collision.repo_identity.split("/", 1)[0].replace(":", "_")
            is_current_v2 = bool(
                re.fullmatch(
                    r"v2_[a-z0-9._-]+_[a-z0-9._-]+_[0-9a-f]{64}"
                    r"(?:\.recovery-[1-9][0-9]*)?",
                    resolved.name,
                )
            )
            matches_supported_identity = resolved == expected or is_current_v2
            is_independent = (
                matches_supported_identity
                and resolved != legacy
                and resolved.parent == legacy.parent
                and (is_current_v2 or expected.name.startswith(f"{host}_"))
                and not resolved.is_symlink()
            )
        except Exception:  # noqa: BLE001 - every resolver failure must fail closed
            is_independent = False
        if not is_independent:
            unresolved.add(collision.repo_identity)
    return frozenset(unresolved)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise RunnerError(f"cannot hash file {path}: {exc}") from exc
    return digest.hexdigest()


def _canonical_json_bytes(payload: Any) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RunnerError(f"source snapshot is not canonical JSON: {exc}") from exc
    return encoded


def _source_snapshot_from_details(details: dict[str, Any]) -> SourceSnapshot:
    canonical = _canonical_json_bytes(details)
    return SourceSnapshot(
        sha256=hashlib.sha256(canonical).hexdigest(),
        details=json.loads(canonical),
    )


def validate_source_snapshot_details(details: Mapping[str, Any]) -> None:
    """Validate the exact, portable schema of an archived source snapshot.

    This intentionally validates the snapshot value itself rather than opening
    the recorded absolute paths.  Live capture performs the filesystem, Git,
    archive, and remote-parity checks before constructing this value; release
    verification can therefore replay the exact schema without depending on
    source mirrors that may have advanced after the campaign.
    """

    top_level_fields = {
        "schema_version",
        "git_mirrors",
        "nvd_feeds",
        "osv_ecosystem_manifest",
        "osv_archives",
        "remote_cutoff",
    }
    if (
        not isinstance(details, Mapping)
        or set(details) != top_level_fields
        or details.get("schema_version") != SOURCE_SNAPSHOT_SCHEMA_VERSION
    ):
        raise RunnerError(
            "source snapshot requires the exact schema 2 top-level contract"
        )

    def require_sha256(value: object, label: str) -> str:
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise RunnerError(f"source snapshot {label} SHA-256 is invalid")
        return value

    def require_absolute_path(value: object, label: str) -> Path:
        if not isinstance(value, str) or not value or not Path(value).is_absolute():
            raise RunnerError(f"source snapshot {label} path is invalid")
        return Path(value)

    git_mirrors = details.get("git_mirrors")
    git_origins = {
        "cvelist_v5": _CVELIST_ORIGIN,
        "gemnasium_advisories": _GEMNASIUM_ORIGIN,
        "github_advisories": _GHSA_ORIGIN,
    }
    git_fields = {"clean", "head", "origin", "path", "tree"}
    if not isinstance(git_mirrors, Mapping) or set(git_mirrors) != set(git_origins):
        raise RunnerError("source snapshot Git mirror inventory is invalid")
    for name, expected_origin in git_origins.items():
        entry = git_mirrors[name]
        if (
            not isinstance(entry, Mapping)
            or set(entry) != git_fields
            or entry.get("clean") is not True
            or entry.get("origin") != expected_origin
            or not isinstance(entry.get("head"), str)
            or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", entry["head"]) is None
            or not isinstance(entry.get("tree"), str)
            or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", entry["tree"]) is None
        ):
            raise RunnerError(f"source snapshot Git mirror is malformed: {name}")
        require_absolute_path(entry.get("path"), f"Git mirror {name}")

    file_fields = {"name", "path", "sha256", "size_bytes"}

    def validate_file_inventory(
        value: object,
        *,
        label: str,
        name_pattern: str,
    ) -> list[Mapping[str, Any]]:
        if not isinstance(value, list) or not value:
            raise RunnerError(f"source snapshot {label} inventory is invalid")
        entries: list[Mapping[str, Any]] = []
        names: list[str] = []
        for raw_entry in value:
            if not isinstance(raw_entry, Mapping) or set(raw_entry) != file_fields:
                raise RunnerError(f"source snapshot {label} entry is malformed")
            name = raw_entry.get("name")
            size = raw_entry.get("size_bytes")
            if (
                not isinstance(name, str)
                or re.fullmatch(name_pattern, name) is None
                or isinstance(size, bool)
                or not isinstance(size, int)
                or size <= 0
            ):
                raise RunnerError(f"source snapshot {label} entry is malformed")
            path = require_absolute_path(raw_entry.get("path"), f"{label} {name}")
            if path.name != name:
                raise RunnerError(f"source snapshot {label} path/name mismatch")
            require_sha256(raw_entry.get("sha256"), f"{label} {name}")
            names.append(name)
            entries.append(raw_entry)
        if names != sorted(set(names), key=lambda item: (item.casefold(), item)):
            raise RunnerError(f"source snapshot {label} inventory is not canonical")
        return entries

    nvd_feeds = validate_file_inventory(
        details.get("nvd_feeds"),
        label="NVD feed",
        name_pattern=r"nvdcve-2\.0-[0-9]{4}\.json\.gz",
    )
    nvd_names = {entry["name"] for entry in nvd_feeds}
    if not _REQUIRED_NVD_FEEDS.issubset(nvd_names):
        raise RunnerError("source snapshot NVD feed inventory is incomplete")

    manifest = details.get("osv_ecosystem_manifest")
    manifest_fields = {
        *file_fields,
        "ecosystem_count",
        "ecosystems",
        "archive_names",
    }
    if not isinstance(manifest, Mapping) or set(manifest) != manifest_fields:
        raise RunnerError("source snapshot OSV ecosystem manifest is malformed")
    manifest_name = manifest.get("name")
    manifest_size = manifest.get("size_bytes")
    ecosystems = manifest.get("ecosystems")
    archive_names = manifest.get("archive_names")
    if (
        manifest_name != source_delta_builder.OSV_ECOSYSTEMS_FILENAME
        or isinstance(manifest_size, bool)
        or not isinstance(manifest_size, int)
        or manifest_size <= 0
        or not isinstance(ecosystems, list)
        or not ecosystems
        or any(not isinstance(item, str) or not item for item in ecosystems)
        or len(set(ecosystems)) != len(ecosystems)
        or manifest.get("ecosystem_count") != len(ecosystems)
        or not isinstance(archive_names, list)
        or not archive_names
        or any(
            not isinstance(item, str) or re.fullmatch(r"[^/\\\x00]+\.zip", item) is None
            for item in archive_names
        )
        or archive_names
        != sorted(set(archive_names), key=lambda item: (item.casefold(), item))
    ):
        raise RunnerError("source snapshot OSV ecosystem manifest is malformed")
    manifest_path = require_absolute_path(
        manifest.get("path"), "OSV ecosystem manifest"
    )
    if manifest_path.name != manifest_name:
        raise RunnerError("source snapshot OSV ecosystem manifest path/name mismatch")
    require_sha256(manifest.get("sha256"), "OSV ecosystem manifest")

    osv_archives = validate_file_inventory(
        details.get("osv_archives"),
        label="OSV archive",
        name_pattern=r"[^/\\\x00]+\.zip",
    )
    if [entry["name"] for entry in osv_archives] != archive_names:
        raise RunnerError(
            "source snapshot OSV archive inventory does not match its manifest"
        )
    if not isinstance(details.get("remote_cutoff"), Mapping):
        raise RunnerError("source snapshot remote cutoff is malformed")


def _validated_source_snapshot(snapshot: SourceSnapshot) -> SourceSnapshot:
    if not isinstance(snapshot, SourceSnapshot):
        raise RunnerError("source snapshot provider returned an invalid value")
    canonical = _source_snapshot_from_details(snapshot.details)
    if not re.fullmatch(r"[0-9a-f]{64}", snapshot.sha256):
        raise RunnerError("source snapshot provider returned an invalid SHA-256")
    if snapshot.sha256 != canonical.sha256:
        raise RunnerError(
            "source snapshot provider returned mismatched details and SHA-256"
        )
    validate_source_snapshot_details(canonical.details)
    return canonical


def _safe_source_directory(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise RunnerError(f"{label} source directory is missing: {path}") from exc
    except OSError as exc:
        raise RunnerError(
            f"cannot inspect {label} source directory {path}: {exc}"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise RunnerError(f"{label} source directory is a symlink: {path}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise RunnerError(f"{label} source path is not a directory: {path}")
    return path.resolve()


def _git_output(source_dir: Path, *arguments: str) -> str:
    try:
        command = source_delta_builder.safe_git_command(source_dir, arguments)
        environment = source_delta_builder.safe_git_environment()
    except source_delta_builder.SourceDeltaError as exc:
        raise RunnerError(
            f"cannot construct strict Git command for {source_dir}: {exc}"
        ) from exc
    try:
        completed = _run_argv_bounded(
            command,
            timeout=(
                source_delta_builder.GIT_FSCK_TIMEOUT_SECONDS
                if arguments and arguments[0] == "fsck"
                else SOURCE_GIT_QUERY_TIMEOUT_SECONDS
            ),
            max_stdout_bytes=source_delta_builder.MAX_GIT_STDOUT_BYTES,
            max_stderr_bytes=source_delta_builder.MAX_GIT_STDERR_BYTES,
            capture_output=True,
            env=environment,
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="strict",
            check=False,
        )
    except UnicodeDecodeError as exc:
        raise RunnerError(
            f"malformed Git source {source_dir}: non-UTF-8 Git output"
        ) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise RunnerError(f"cannot inspect Git source {source_dir}: {exc}") from exc
    if any(
        getattr(completed, attribute, False)
        for attribute in (
            "stdout_limit_exceeded",
            "stderr_limit_exceeded",
            "stdout_drain_incomplete",
            "stderr_drain_incomplete",
        )
    ):
        raise RunnerError(
            f"malformed Git source {source_dir}: Git output was incomplete or "
            "exceeded the bounded limit"
        )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()[:500]
        raise RunnerError(
            f"malformed Git source {source_dir}: git {' '.join(arguments)} failed"
            + (f": {stderr}" if stderr else "")
        )
    return completed.stdout.strip()


def _git_source_details(
    source_dir: Path,
    *,
    label: str,
    expected_origin: str,
    fsck_cache: source_delta_builder.SuccessfulGitFsckCache | None = None,
) -> dict[str, Any]:
    source_dir = _safe_source_directory(source_dir, f"{label} Git")
    try:
        source_delta_builder.validate_git_repository_safety(
            source_dir,
            f"{label} Git source",
            lambda arguments: _git_output(source_dir, *arguments),
            fsck_cache=fsck_cache,
        )
    except source_delta_builder.SourceDeltaError as exc:
        raise RunnerError(f"malformed Git source {source_dir}: {exc}") from exc
    origin = _git_output(source_dir, "remote", "get-url", "origin")
    if origin != expected_origin:
        raise RunnerError(
            f"Git source has unexpected origin for {label}: {origin!r}; "
            f"expected {expected_origin!r}"
        )

    head_before = _git_output(source_dir, "rev-parse", "HEAD")
    tree = _git_output(source_dir, "rev-parse", "HEAD^{tree}")
    status_output = _git_output(
        source_dir,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    head_after = _git_output(source_dir, "rev-parse", "HEAD")
    if head_before != head_after:
        raise RunnerError(f"Git source changed while being captured: {source_dir}")
    for field_name, value in (("HEAD", head_before), ("tree", tree)):
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value):
            raise RunnerError(
                f"malformed Git source {source_dir}: invalid {field_name} hash {value!r}"
            )
    if status_output:
        preview = status_output.splitlines()[0][:300]
        raise RunnerError(f"Git source is dirty: {source_dir}: {preview}")
    return {
        "clean": True,
        "head": head_before,
        "origin": origin,
        "path": str(source_dir),
        "tree": tree,
    }


def _openclaw_checkout_base_contract(
    cache_resolver: CacheResolver = _default_cache_resolver,
) -> dict[str, Any]:
    """Capture a clean, full OpenClaw checkout before remote-tip comparison."""

    try:
        checkout = Path(cache_resolver(_OPENCLAW_ORIGIN)).absolute()
    except Exception as exc:  # noqa: BLE001 - resolver failures must fail closed
        raise RunnerError(
            f"cannot resolve the OpenClaw analysis checkout: {exc}"
        ) from exc
    details = _git_source_details(
        checkout,
        label="OpenClaw analysis checkout",
        expected_origin=_OPENCLAW_ORIGIN,
    )
    checkout = Path(details["path"])
    top_level = _git_output(checkout, "rev-parse", "--show-toplevel")
    if Path(top_level).resolve() != checkout:
        raise RunnerError("OpenClaw analysis checkout is not the Git worktree root")
    branch = _git_output(checkout, "branch", "--show-current")
    if branch != _OPENCLAW_BRANCH:
        raise RunnerError(f"OpenClaw analysis checkout must be on {_OPENCLAW_BRANCH!r}")
    shallow = _git_output(checkout, "rev-parse", "--is-shallow-repository")
    if shallow != "false":
        raise RunnerError("OpenClaw analysis checkout must be a full clone")
    tracking_head = _git_output(
        checkout,
        "rev-parse",
        _OPENCLAW_REMOTE_TRACKING_REF,
    )
    return {
        "repository_identity": _OPENCLAW_REPOSITORY_MARKER,
        "origin": details["origin"],
        "branch": branch,
        "remote_tracking_ref": _OPENCLAW_REMOTE_TRACKING_REF,
        "head_sha": details["head"],
        "remote_tracking_sha": tracking_head,
        "tree_sha": details["tree"],
        "cache_path": details["path"],
        "clean": True,
        "full_clone": True,
        "head_matches_remote_tracking": details["head"] == tracking_head,
        "git_integrity": "fsck_full_strict",
    }


def _openclaw_checkout_contract(
    cache_resolver: CacheResolver = _default_cache_resolver,
) -> dict[str, Any]:
    """Capture the exact clean, full, current checkout used by the pilot."""

    contract = _openclaw_checkout_base_contract(cache_resolver)
    if contract["head_matches_remote_tracking"] is not True:
        raise RunnerError(
            "OpenClaw analysis checkout HEAD is stale relative to origin/main"
        )
    return contract


def _openclaw_network_git_output(checkout: Path, *arguments: str) -> str:
    """Run one bounded, non-interactive HTTPS Git operation for OpenClaw."""

    try:
        command = source_delta_builder.safe_git_command(checkout, arguments)
        completed = _run_argv_bounded(
            command,
            timeout=OPENCLAW_GIT_FETCH_TIMEOUT_SECONDS,
            max_stdout_bytes=source_delta_builder.MAX_GIT_STDERR_BYTES,
            max_stderr_bytes=source_delta_builder.MAX_GIT_STDERR_BYTES,
            capture_output=True,
            env=source_delta_builder.safe_git_environment(),
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="strict",
            check=False,
        )
    except UnicodeDecodeError as exc:
        raise RunnerError("OpenClaw remote returned non-UTF-8 Git output") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise RunnerError(f"OpenClaw remote Git operation failed: {exc}") from exc
    if any(
        getattr(completed, attribute, False)
        for attribute in (
            "stdout_limit_exceeded",
            "stderr_limit_exceeded",
            "stdout_drain_incomplete",
            "stderr_drain_incomplete",
        )
    ):
        raise RunnerError("OpenClaw remote Git output was incomplete or oversized")
    if completed.returncode != 0:
        stderr = completed.stderr.strip()[:500]
        raise RunnerError(
            "OpenClaw remote Git operation failed" + (f": {stderr}" if stderr else "")
        )
    return completed.stdout.strip()


def _fetch_openclaw_remote_tip(checkout: Path) -> str:
    """Fetch and prove one advertised origin/main tip without silent drift."""

    for _attempt in range(3):
        _openclaw_network_git_output(
            checkout,
            "-c",
            "fetch.fsckObjects=true",
            "-c",
            "transfer.fsckObjects=true",
            "fetch",
            "--prune",
            "origin",
            _OPENCLAW_FETCH_REFSPEC,
        )
        tracking_head = _git_output(
            checkout,
            "rev-parse",
            _OPENCLAW_REMOTE_TRACKING_REF,
        )
        advertised = _openclaw_network_git_output(
            checkout,
            "ls-remote",
            "--exit-code",
            "origin",
            "refs/heads/main",
        )
        rows = [line.split("\t") for line in advertised.splitlines() if line]
        if (
            len(rows) == 1
            and len(rows[0]) == 2
            and rows[0][1] == "refs/heads/main"
            and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", rows[0][0])
            and rows[0][0] == tracking_head
        ):
            return tracking_head
    raise RunnerError("OpenClaw origin/main changed while its remote tip was captured")


def _prepare_openclaw_checkout(
    cache_resolver: CacheResolver = _default_cache_resolver,
) -> dict[str, Any]:
    """Fetch, fast-forward, fsck, and bind the live OpenClaw default tip."""

    initial = _openclaw_checkout_base_contract(cache_resolver)
    checkout = Path(initial["cache_path"])
    remote_tip = _fetch_openclaw_remote_tip(checkout)
    head = _git_output(checkout, "rev-parse", "HEAD")
    try:
        _git_output(checkout, "merge-base", "--is-ancestor", head, remote_tip)
    except RunnerError as exc:
        raise RunnerError(
            "OpenClaw analysis checkout cannot fast-forward to origin/main"
        ) from exc
    _git_output(
        checkout,
        "merge",
        "--ff-only",
        "--no-edit",
        _OPENCLAW_REMOTE_TRACKING_REF,
    )
    prepared = _openclaw_checkout_contract(cache_resolver)
    if prepared["head_sha"] != remote_tip:
        raise RunnerError("OpenClaw checkout does not match the advertised remote tip")
    return {
        **prepared,
        "remote_tip_fetch_verified": True,
        "remote_tip_fetch_refspec": _OPENCLAW_FETCH_REFSPEC,
        "remote_tip_sha": remote_tip,
    }


def _revalidate_openclaw_checkout(expected: Mapping[str, Any]) -> None:
    current = _openclaw_checkout_contract()
    if any(current.get(key) != expected.get(key) for key in current):
        raise RunnerError("OpenClaw analysis checkout changed during pilot")


def _current_prepared_openclaw_checkout() -> dict[str, Any]:
    """Rebuild the durable post-fetch checkout identity without network mutation."""

    current = _openclaw_checkout_contract()
    return {
        **current,
        "remote_tip_fetch_verified": True,
        "remote_tip_fetch_refspec": _OPENCLAW_FETCH_REFSPEC,
        "remote_tip_sha": current["head_sha"],
    }


def _analysis_checkout_receipt_binding(
    contract: Mapping[str, Any],
) -> dict[str, str]:
    fields = {
        "repository_identity": contract.get("repository_identity"),
        "path": contract.get("cache_path"),
        "origin": contract.get("origin"),
        "head_sha": contract.get("head_sha"),
        "tree_sha": contract.get("tree_sha"),
    }
    remote_tip_sha = contract.get("remote_tip_sha")
    path = fields["path"]
    if (
        fields["repository_identity"] != _OPENCLAW_REPOSITORY_MARKER
        or fields["origin"] != _OPENCLAW_ORIGIN
        or not isinstance(path, str)
        or not Path(path).is_absolute()
        or any(
            not isinstance(fields[name], str)
            or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", fields[name]) is None
            for name in ("head_sha", "tree_sha")
        )
        or not isinstance(remote_tip_sha, str)
        or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", remote_tip_sha) is None
        or fields["head_sha"] != remote_tip_sha
    ):
        raise RunnerError("pilot analysis checkout receipt binding is invalid")
    return {name: str(value) for name, value in fields.items()}


def _stat_signature(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@lru_cache(maxsize=4096)
def _cached_file_sha256(
    path_text: str,
    _signature: tuple[int, int, int, int, int],
) -> str:
    return file_sha256(Path(path_text))


def _regular_source_file_details(path: Path, label: str) -> dict[str, Any]:
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise RunnerError(f"{label} is missing: {path}") from exc
    except OSError as exc:
        raise RunnerError(f"cannot inspect {label} {path}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode):
        raise RunnerError(f"{label} is a symlink: {path}")
    if not stat.S_ISREG(before.st_mode):
        raise RunnerError(f"{label} is not a regular file: {path}")
    if before.st_size <= 0:
        raise RunnerError(f"{label} is empty: {path}")

    signature = _stat_signature(before)
    digest = _cached_file_sha256(str(path.resolve()), signature)
    try:
        after = path.lstat()
    except OSError as exc:
        raise RunnerError(f"cannot recheck {label} {path}: {exc}") from exc
    if _stat_signature(after) != signature:
        raise RunnerError(f"{label} changed while being hashed: {path}")
    return {
        "name": path.name,
        "path": str(path.resolve()),
        "sha256": digest,
        "size_bytes": before.st_size,
    }


@lru_cache(maxsize=128)
def _validate_nvd_feed(path_text: str, sha256: str) -> None:
    path = Path(path_text)
    max_compressed_bytes = source_delta_builder.MAX_NVD_GZIP_BYTES
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RunnerError(f"cannot inspect NVD feed {path}: {exc}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > max_compressed_bytes
    ):
        raise RunnerError(
            f"malformed NVD feed {path}: compressed input must be a regular file "
            f"within 1..{max_compressed_bytes} bytes"
        )
    label = f"NVD feed {path}"
    try:
        source_delta_builder._load_nvd(  # noqa: SLF001
            path,
            label,
            expected_snapshot={
                "size_bytes": metadata.st_size,
                "sha256": sha256,
            },
        )
    except source_delta_builder.SourceDeltaError as exc:
        raise RunnerError(f"malformed NVD feed {path}: {exc}") from exc


@lru_cache(maxsize=1024)
def _validate_osv_archive(path_text: str, sha256: str) -> None:
    path = Path(path_text)
    started = time.monotonic()
    max_archive_bytes = source_delta_builder.MAX_OSV_ARCHIVE_BYTES
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RunnerError(f"cannot inspect OSV archive {path}: {exc}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > max_archive_bytes
    ):
        raise RunnerError(
            f"malformed OSV archive {path}: input must be a regular file within "
            f"1..{max_archive_bytes} bytes"
        )

    label = f"OSV archive {path}"
    try:
        archive, members = source_delta_builder._safe_zip_members(  # noqa: SLF001
            path,
            label,
            started_at=started,
            expected_size=metadata.st_size,
            expected_sha256=sha256,
        )
        try:
            source_delta_builder._scan_osv_records(  # noqa: SLF001
                archive,
                members,
                label,
                started_at=started,
            )
        finally:
            archive.close()
        source_delta_builder._check_osv_archive_deadline(  # noqa: SLF001
            started,
            label,
        )
    except source_delta_builder.SourceDeltaError as exc:
        raise RunnerError(f"malformed OSV archive {path}: {exc}") from exc


def _nvd_source_details(directory: Path) -> list[dict[str, Any]]:
    directory = _safe_source_directory(directory, "NVD feeds")
    candidates = sorted(directory.glob("*.json.gz"), key=lambda path: path.name)
    names = {path.name for path in candidates}
    missing = sorted(_REQUIRED_NVD_FEEDS - names)
    if missing:
        raise RunnerError(f"required NVD feed is missing: {', '.join(missing)}")

    details: list[dict[str, Any]] = []
    for path in candidates:
        if not re.fullmatch(r"nvdcve-2\.0-[0-9]{4}\.json\.gz", path.name):
            raise RunnerError(f"malformed NVD feed name: {path.name!r}")
        entry = _regular_source_file_details(path, "NVD feed")
        _validate_nvd_feed(entry["path"], entry["sha256"])
        details.append(entry)
    return details


def _osv_source_details(
    directory: Path,
    expected_archive_names: Sequence[str],
) -> list[dict[str, Any]]:
    directory = _safe_source_directory(directory, "OSV bulk")
    candidates = sorted(
        directory.glob("*.zip"),
        key=lambda path: (path.name.casefold(), path.name),
    )
    current_names = tuple(path.name for path in candidates)
    if current_names != tuple(expected_archive_names):
        missing = sorted(set(expected_archive_names) - set(current_names))
        unexpected = sorted(set(current_names) - set(expected_archive_names))
        raise RunnerError(
            "OSV bulk archive inventory does not match the ecosystem manifest: "
            f"missing={missing}, unexpected={unexpected}"
        )

    details: list[dict[str, Any]] = []
    for path in candidates:
        entry = _regular_source_file_details(path, "OSV archive")
        _validate_osv_archive(entry["path"], entry["sha256"])
        details.append(entry)
    return details


def _stable_json_source(
    path: Path,
    label: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read one regular JSON source and bind the parsed bytes to its digest."""

    details = _regular_source_file_details(path, label)
    try:
        content = path.read_bytes()
        payload = json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"cannot read {label} {path}: {exc}") from exc
    if hashlib.sha256(content).hexdigest() != details["sha256"]:
        raise RunnerError(f"{label} changed while being read: {path}")
    if not isinstance(payload, dict):
        raise RunnerError(f"{label} must contain a JSON object: {path}")
    return payload, details


def _valid_gcs_md5_proof(etag: object, encoded: object) -> bool:
    if not isinstance(etag, str) or not isinstance(encoded, str):
        return False
    match = re.fullmatch(r'"([0-9a-f]{32})"', etag)
    if match is None:
        return False
    try:
        digest = base64.b64decode(encoded, validate=True)
    except (TypeError, ValueError):
        return False
    return len(digest) == 16 and digest.hex() == match.group(1)


def _valid_gcs_crc32c(encoded: object) -> bool:
    if not isinstance(encoded, str):
        return False
    try:
        digest = base64.b64decode(encoded, validate=True)
    except (TypeError, ValueError):
        return False
    return len(digest) == 4


def _validated_remote_cutoff(
    paths: RunnerPaths,
    *,
    git_mirrors: dict[str, dict[str, Any]],
    nvd_feeds: Sequence[dict[str, Any]],
    osv_ecosystem_manifest: dict[str, Any],
    osv_archives: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    """Bind the schema-3 rolling-cutoff receipt to exact campaign inputs.

    The schema retains the historical ``remote_parity`` compatibility field.
    Its proof is per-source and content-addressed; this validator performs no
    live network claim and requires the receipt versions to equal local bytes.
    """

    payload, receipt_file = _stable_json_source(
        paths.source_remote_receipt,
        "source remote-parity receipt",
    )
    required_top_level = {
        "schema_version",
        "checked_at_utc",
        "git_sources",
        "nvd_feeds",
        "osv_ecosystem_manifest",
        "osv_archive_count",
        "osv_archives",
        "remote_parity",
    }
    if set(payload) != required_top_level or payload.get("schema_version") != 3:
        raise RunnerError(
            "source remote-parity receipt requires the exact schema 3 contract"
        )
    if payload.get("remote_parity") is not True:
        raise RunnerError("source remote-parity receipt does not prove remote parity")
    checked_at = payload.get("checked_at_utc")
    if _iso_timestamp_ns(checked_at) is None:
        raise RunnerError("source remote-parity receipt has an invalid checked_at_utc")

    git_name_map = {
        "cvelistV5": "cvelist_v5",
        "github-advisory-database": "github_advisories",
        "gemnasium-db": "gemnasium_advisories",
    }
    raw_git = payload.get("git_sources")
    if not isinstance(raw_git, list) or len(raw_git) != len(git_name_map):
        raise RunnerError("source remote-parity receipt has an invalid Git inventory")
    seen_git: set[str] = set()
    required_git_fields = {
        "branch",
        "head",
        "name",
        "origin",
        "path",
        "remote_head",
        "tree",
    }
    for entry in raw_git:
        if not isinstance(entry, dict) or set(entry) != required_git_fields:
            raise RunnerError("source remote-parity receipt has a malformed Git entry")
        name = entry.get("name")
        if name not in git_name_map or name in seen_git:
            raise RunnerError(
                "source remote-parity receipt has an unexpected Git source"
            )
        seen_git.add(name)
        local = git_mirrors[git_name_map[name]]
        if (
            not isinstance(entry.get("branch"), str)
            or not entry["branch"]
            or entry.get("head") != entry.get("remote_head")
            or entry.get("head") != local.get("head")
            or entry.get("tree") != local.get("tree")
            or entry.get("origin") != local.get("origin")
            or Path(str(entry.get("path", ""))).resolve()
            != Path(str(local.get("path", ""))).resolve()
        ):
            raise RunnerError(f"source remote-parity receipt Git mismatch for {name}")
    if seen_git != set(git_name_map):
        raise RunnerError("source remote-parity receipt Git inventory is incomplete")

    local_nvd = {entry["name"]: entry for entry in nvd_feeds}
    raw_nvd = payload.get("nvd_feeds")
    required_nvd_fields = {
        "feed_path",
        "feed_sha256",
        "feed_size",
        "meta_path",
        "meta_sha256",
        "remote_etag",
        "remote_last_modified",
        "remote_meta_sha256",
        "year",
    }
    if not isinstance(raw_nvd, list) or len(raw_nvd) != len(local_nvd):
        raise RunnerError("source remote-parity receipt has an invalid NVD inventory")
    seen_nvd: set[str] = set()
    for entry in raw_nvd:
        if not isinstance(entry, dict) or set(entry) != required_nvd_fields:
            raise RunnerError("source remote-parity receipt has a malformed NVD entry")
        year = entry.get("year")
        if isinstance(year, bool) or not isinstance(year, int):
            raise RunnerError("source remote-parity receipt has an invalid NVD year")
        name = f"nvdcve-2.0-{year}.json.gz"
        if name not in local_nvd or name in seen_nvd:
            raise RunnerError("source remote-parity receipt has an unexpected NVD feed")
        seen_nvd.add(name)
        local = local_nvd[name]
        meta_path = Path(str(entry.get("meta_path", "")))
        meta = _regular_source_file_details(meta_path, "NVD remote metadata")
        if (
            Path(str(entry.get("feed_path", ""))).resolve()
            != Path(local["path"]).resolve()
            or entry.get("feed_sha256") != local["sha256"]
            or entry.get("feed_size") != local["size_bytes"]
            or entry.get("meta_sha256") != meta["sha256"]
            or entry.get("remote_meta_sha256") != meta["sha256"]
            or not isinstance(entry.get("remote_etag"), str)
            or not entry["remote_etag"]
            or not isinstance(entry.get("remote_last_modified"), str)
            or not entry["remote_last_modified"]
        ):
            raise RunnerError(f"source remote-parity receipt NVD mismatch for {name}")
    if seen_nvd != set(local_nvd):
        raise RunnerError("source remote-parity receipt NVD inventory is incomplete")

    raw_manifest = payload.get("osv_ecosystem_manifest")
    required_manifest_fields = {
        "ecosystem_count",
        "ecosystems",
        "etag",
        "filename",
        "generation",
        "last_modified",
        "md5_base64",
        "path",
        "remote_size",
        "sha256",
        "size",
        "url",
    }
    if (
        not isinstance(raw_manifest, dict)
        or set(raw_manifest) != required_manifest_fields
    ):
        raise RunnerError(
            "source remote-parity receipt has a malformed OSV ecosystem manifest"
        )
    local_ecosystems = osv_ecosystem_manifest.get("ecosystems")
    local_archive_names = osv_ecosystem_manifest.get("archive_names")
    manifest_generation = raw_manifest.get("generation")
    if (
        raw_manifest.get("filename") != source_delta_builder.OSV_ECOSYSTEMS_FILENAME
        or raw_manifest.get("url")
        != "https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt"
        or Path(str(raw_manifest.get("path", ""))).resolve()
        != Path(str(osv_ecosystem_manifest.get("path", ""))).resolve()
        or raw_manifest.get("sha256") != osv_ecosystem_manifest.get("sha256")
        or raw_manifest.get("size") != osv_ecosystem_manifest.get("size_bytes")
        or raw_manifest.get("remote_size") != osv_ecosystem_manifest.get("size_bytes")
        or raw_manifest.get("ecosystem_count") != len(local_ecosystems or [])
        or raw_manifest.get("ecosystems") != local_ecosystems
        or not isinstance(manifest_generation, str)
        or not manifest_generation.isdigit()
        or not _valid_gcs_md5_proof(
            raw_manifest.get("etag"), raw_manifest.get("md5_base64")
        )
        or not isinstance(raw_manifest.get("last_modified"), str)
        or not raw_manifest["last_modified"]
        or not isinstance(local_archive_names, list)
    ):
        raise RunnerError(
            "source remote-parity receipt OSV ecosystem manifest mismatch"
        )

    local_osv = {entry["name"]: entry for entry in osv_archives}
    raw_osv = payload.get("osv_archives")
    required_osv_fields = {
        "etag",
        "crc32c_base64",
        "filename",
        "generation",
        "last_modified",
        "md5_base64",
        "path",
        "remote_size",
        "sha256",
        "size",
        "url",
    }
    if (
        payload.get("osv_archive_count") != len(local_osv)
        or not isinstance(raw_osv, list)
        or len(raw_osv) != len(local_osv)
    ):
        raise RunnerError("source remote-parity receipt has an invalid OSV inventory")
    seen_osv: set[str] = set()
    for entry in raw_osv:
        if not isinstance(entry, dict) or set(entry) != required_osv_fields:
            raise RunnerError("source remote-parity receipt has a malformed OSV entry")
        name = entry.get("filename")
        if name not in local_osv or name in seen_osv:
            raise RunnerError(
                "source remote-parity receipt has an unexpected OSV archive"
            )
        seen_osv.add(name)
        local = local_osv[name]
        generation = entry.get("generation")
        if (
            Path(str(entry.get("path", ""))).resolve() != Path(local["path"]).resolve()
            or entry.get("sha256") != local["sha256"]
            or entry.get("size") != local["size_bytes"]
            or entry.get("remote_size") != local["size_bytes"]
            or not isinstance(generation, str)
            or not generation.isdigit()
            or not _valid_gcs_md5_proof(entry.get("etag"), entry.get("md5_base64"))
            or not _valid_gcs_crc32c(entry.get("crc32c_base64"))
            or not isinstance(entry.get("last_modified"), str)
            or not entry["last_modified"]
            or not isinstance(entry.get("url"), str)
            or entry["url"]
            != (
                "https://storage.googleapis.com/osv-vulnerabilities/"
                + quote(str(name).removesuffix(".zip"), safe="")
                + "/all.zip"
            )
        ):
            raise RunnerError(f"source remote-parity receipt OSV mismatch for {name}")
    if seen_osv != set(local_osv):
        raise RunnerError("source remote-parity receipt OSV inventory is incomplete")

    return {
        "checked_at_utc": checked_at,
        "receipt_file": receipt_file,
        "remote_parity": True,
        "receipt": payload,
    }


def capture_source_snapshot(
    paths: RunnerPaths,
    *,
    fsck_cache: source_delta_builder.SuccessfulGitFsckCache | None = None,
) -> SourceSnapshot:
    """Capture and validate every local source consumed by the campaign."""
    git_mirrors = {
        "cvelist_v5": _git_source_details(
            paths.cvelist_dir,
            label="cvelistV5",
            expected_origin=_CVELIST_ORIGIN,
            fsck_cache=fsck_cache,
        ),
        "gemnasium_advisories": _git_source_details(
            paths.gemnasium_dir,
            label="Gemnasium advisories",
            expected_origin=_GEMNASIUM_ORIGIN,
            fsck_cache=fsck_cache,
        ),
        "github_advisories": _git_source_details(
            paths.ghsa_dir,
            label="GitHub advisories",
            expected_origin=_GHSA_ORIGIN,
            fsck_cache=fsck_cache,
        ),
    }
    nvd_feeds = _nvd_source_details(paths.nvd_feeds_dir)
    manifest_file = _regular_source_file_details(
        paths.osv_ecosystems_file,
        "OSV ecosystem manifest",
    )
    try:
        manifest_bytes = paths.osv_ecosystems_file.read_bytes()
        manifest_inventory = source_delta_builder.parse_osv_ecosystems_manifest(
            manifest_bytes
        )
    except (OSError, source_delta_builder.SourceDeltaError) as exc:
        raise RunnerError(f"invalid OSV ecosystem manifest: {exc}") from exc
    if hashlib.sha256(manifest_bytes).hexdigest() != manifest_file["sha256"]:
        raise RunnerError("OSV ecosystem manifest changed while being read")
    osv_ecosystem_manifest = {
        **manifest_file,
        "ecosystem_count": len(manifest_inventory.ecosystems),
        "ecosystems": list(manifest_inventory.ecosystems),
        "archive_names": list(manifest_inventory.archive_names),
    }
    osv_archives = _osv_source_details(
        paths.osv_bulk_dir,
        manifest_inventory.archive_names,
    )
    details = {
        "schema_version": SOURCE_SNAPSHOT_SCHEMA_VERSION,
        "git_mirrors": git_mirrors,
        "nvd_feeds": nvd_feeds,
        "osv_ecosystem_manifest": osv_ecosystem_manifest,
        "osv_archives": osv_archives,
        "remote_cutoff": _validated_remote_cutoff(
            paths,
            git_mirrors=git_mirrors,
            nvd_feeds=nvd_feeds,
            osv_ecosystem_manifest=osv_ecosystem_manifest,
            osv_archives=osv_archives,
        ),
    }
    return _source_snapshot_from_details(details)


def _contract_files(paths: RunnerPaths) -> tuple[tuple[str, Path], ...]:
    """Return every source/config input that defines refresh output semantics."""
    repo_root = paths.repo_root.resolve()
    refresh_root = paths.grouped_dir.parent
    corpus_file = refresh_root / "adjudicated-corpus-subjects.txt"
    required_files = (
        paths.analyzer_dir / "pyproject.toml",
        paths.analyzer_dir / "uv.lock",
        repo_root / "scripts" / "run_data_refresh.py",
        repo_root / "scripts" / "run_data_refresh.sh",
        repo_root / "scripts" / "refresh_source_inputs.py",
        repo_root / "scripts" / "build_source_delta.py",
        repo_root / "scripts" / "build_data_refresh_batches.py",
        repo_root / "scripts" / "analysis_contract.py",
        repo_root / "scripts" / "generate_web_data.py",
        paths.source_remote_receipt,
        paths.legacy_batch,
        paths.grouped_dir.parent / "new-osv-candidates.txt",
        paths.grouped_dir.parent / "source-delta-current.json",
        *((corpus_file,) if corpus_file.is_file() else ()),
    )
    required_trees = (
        paths.analyzer_dir / "src",
        repo_root / "scripts" / "web_data",
        paths.grouped_dir,
        refresh_root / "source-before-final",
    )

    contract_files: list[Path] = []
    for path in required_files:
        if not path.is_file() or path.is_symlink():
            raise RunnerError(f"required contract input is missing or unsafe: {path}")
        contract_files.append(path)

    for directory in required_trees:
        if not directory.is_dir() or directory.is_symlink():
            raise RunnerError(
                f"required contract input tree is missing or unsafe: {directory}"
            )
        tree_files = sorted(
            path
            for path in directory.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
        )
        if not tree_files:
            raise RunnerError(f"required contract input tree is empty: {directory}")
        contract_files.extend(tree_files)

    labeled: list[tuple[str, Path]] = []
    for path in contract_files:
        resolved = path.resolve()
        try:
            label = resolved.relative_to(repo_root).as_posix()
        except ValueError as exc:
            raise RunnerError(
                f"contract input escapes repository root: {path}"
            ) from exc
        labeled.append((label, resolved))
    return tuple(sorted(labeled))


def contract_sha256(paths: RunnerPaths) -> str:
    """Hash the analyzer, generator, dependency, and runner contract."""
    digest = hashlib.sha256()
    for label, path in _contract_files(paths):
        label_bytes = label.encode("utf-8")
        digest.update(len(label_bytes).to_bytes(8, "big"))
        digest.update(label_bytes)
        try:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as exc:
            raise RunnerError(f"cannot hash contract input {path}: {exc}") from exc
        digest.update(b"\x00")
    return digest.hexdigest()


def litellm_transport_contract(
    source_env: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], str]:
    """Return a non-secret, content-addressed LiteLLM transport contract."""

    source = os.environ if source_env is None else source_env
    try:
        config = resolve_litellm_config(source)
    except ValueError as exc:
        raise RunnerError(f"invalid LiteLLM campaign transport: {exc}") from exc
    if config is None:
        raise RunnerError("LiteLLM campaign transport is not configured")

    contract = {
        "schema_version": 1,
        "api_base_sha256": hashlib.sha256(config.api_base.encode("utf-8")).hexdigest(),
        "base_env_vars": list(config.base_env_vars),
        "key_env_vars": list(config.key_env_vars),
        # A strict campaign always takes the Responses-only path in
        # ``LlmClient._raw_call``.  Recording Chat Completions here would claim
        # a fallback that the campaign deliberately forbids.
        "api_modes": ["responses"],
        "api_key_configured": True,
        "max_concurrent_requests": LLM_CONCURRENCY,
        "request_timeout_seconds": REQUEST_TIMEOUT_SECONDS,
        "max_reasoning_output_tokens_floor": (MAX_REASONING_OUTPUT_TOKENS_FLOOR),
    }
    return contract, hashlib.sha256(_canonical_json_bytes(contract)).hexdigest()


def _alias_manifest_execution_binding(paths: RunnerPaths) -> tuple[str, str]:
    """Return the validated formal source-delta path and class-manifest digest."""
    delta_path = (paths.grouped_dir.parent / "source-delta-current.json").resolve()
    if not delta_path.is_file() or delta_path.is_symlink():
        return "", ""
    try:
        delta = json.loads(delta_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"cannot bind formal alias-class manifest: {exc}") from exc
    if not isinstance(delta, dict) or delta.get("population_policy") != (
        source_delta_builder.FORMAL_FULL_POLICY
    ):
        return "", ""
    production = delta.get("production_discovery")
    manifest = (
        production.get("alias_class_manifest") if isinstance(production, dict) else None
    )
    classes = manifest.get("classes") if isinstance(manifest, dict) else None
    digest = manifest.get("classes_sha256") if isinstance(manifest, dict) else None
    if (
        not isinstance(classes, list)
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or hashlib.sha256(_canonical_json_bytes(classes)).hexdigest() != digest
    ):
        raise RunnerError("formal alias-class manifest binding is invalid")
    return str(delta_path), digest


def campaign_execution(
    paths: RunnerPaths,
    source_snapshot: SourceSnapshot,
    contract_digest: str,
) -> CampaignExecution:
    """Derive isolated writable paths from the exact source and code contract."""
    if not re.fullmatch(r"[0-9a-f]{64}", source_snapshot.sha256):
        raise RunnerError("invalid source snapshot digest for campaign identity")
    if not re.fullmatch(r"[0-9a-f]{64}", contract_digest):
        raise RunnerError("invalid contract digest for campaign identity")
    transport, transport_digest = litellm_transport_contract()
    try:
        analyzer_epoch = analysis_contract.analysis_contract_epoch(paths.repo_root)
    except analysis_contract.AnalysisContractError as exc:
        raise RunnerError(f"cannot bind analyzer contract epoch: {exc}") from exc
    alias_delta_path, alias_manifest_sha256 = _alias_manifest_execution_binding(paths)
    identity_payload = {
        "schema_version": MARKER_SCHEMA_VERSION,
        "source_snapshot_sha256": source_snapshot.sha256,
        "contract_sha256": contract_digest,
        "analyzer_contract_sha256": analyzer_epoch["sha256"],
        "signature_sha256": analyzer_epoch["signature_sha256"],
        "alias_class_manifest_sha256": alias_manifest_sha256,
        "model": MODEL,
        "reasoning_effort": REASONING_EFFORT,
        "workers": WORKERS,
        "forced_verification": True,
        "result_cache_reads": False,
        "llm_cache_reads": False,
        "litellm_transport_sha256": transport_digest,
        "batch_timeout_seconds": BATCH_TIMEOUT_SECONDS,
    }
    campaign_id = hashlib.sha256(_canonical_json_bytes(identity_payload)).hexdigest()
    root = paths.state_dir.parent / "campaigns-v1" / campaign_id
    return CampaignExecution(
        campaign_id=campaign_id,
        root=root,
        result_dir=root / "results",
        api_cache_dir=root / "api-responses",
        derived_cache_root=root / "derived-cache",
        source_snapshot_sha256=source_snapshot.sha256,
        contract_sha256=contract_digest,
        litellm_transport_sha256=transport_digest,
        litellm_transport=transport,
        analyzer_contract_sha256=analyzer_epoch["sha256"],
        signature_sha256=analyzer_epoch["signature_sha256"],
        alias_class_delta_path=alias_delta_path,
        alias_class_manifest_sha256=alias_manifest_sha256,
    )


def _prepare_campaign_execution(campaign: CampaignExecution) -> None:
    try:
        campaign.root.mkdir(parents=True, exist_ok=True)
        if campaign.root.is_symlink() or not campaign.root.is_dir():
            raise RunnerError(
                f"campaign root must be a real directory: {campaign.root}"
            )
        for directory in (
            campaign.result_dir,
            campaign.api_cache_dir,
            campaign.derived_cache_root,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            if directory.is_symlink() or not directory.is_dir():
                raise RunnerError(
                    f"campaign writable path must be a real directory: {directory}"
                )
    except RunnerError:
        raise
    except OSError as exc:
        raise RunnerError(
            f"cannot prepare isolated campaign state {campaign.root}: {exc}"
        ) from exc


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
    )


def _validate_open_directory(
    metadata: os.stat_result,
    *,
    label: str,
) -> None:
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_nlink < 1:
        raise RunnerError(f"{label} is not a safe directory")


def _open_directory_component(
    parent_fd: int,
    name: str,
    *,
    label: str,
    create: bool,
) -> int:
    if name in {"", ".", ".."} or "/" in name or "\x00" in name:
        raise RunnerError(f"unsafe directory component for {label}: {name!r}")
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        if not create:
            raise
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        except OSError as exc:
            raise RunnerError(f"cannot create {label}: {exc}") from exc
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise RunnerError(f"cannot inspect created {label}: {exc}") from exc
    except OSError as exc:
        raise RunnerError(f"cannot inspect {label}: {exc}") from exc
    _validate_open_directory(before, label=label)

    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_open_directory(opened, label=label)
        _validate_open_directory(after, label=label)
        if not (
            _directory_identity(before)
            == _directory_identity(opened)
            == _directory_identity(after)
        ):
            raise RunnerError(f"{label} changed while being opened")
        return descriptor
    except RunnerError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.EMLINK}:
            raise RunnerError(f"{label} is not a safe directory") from exc
        raise RunnerError(f"cannot open {label}: {exc}") from exc


def _open_directory_chain(
    path: Path,
    *,
    label: str,
    create: bool,
    missing_ok: bool = False,
) -> int | None:
    """Open every directory component by dir-fd without following symlinks."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        current_fd = os.open(os.sep, flags)
    except OSError as exc:  # pragma: no cover - an unusable root is fatal
        raise RunnerError(f"cannot open filesystem root for {label}: {exc}") from exc
    try:
        for index, component in enumerate(absolute.parts[1:], start=1):
            component_label = (
                f"{label} component {os.sep.join(absolute.parts[: index + 1])}"
            )
            try:
                child_fd = _open_directory_component(
                    current_fd,
                    component,
                    label=component_label,
                    create=create,
                )
            except FileNotFoundError:
                if missing_ok:
                    os.close(current_fd)
                    return None
                raise RunnerError(f"{component_label} is missing") from None
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _open_lock_file_at(
    lock_directory_fd: int,
    file_name: str,
    *,
    label: str,
    writable: bool,
    create: bool,
    missing_ok: bool = False,
) -> int | None:
    if Path(file_name).name != file_name or file_name in {"", ".", ".."}:
        raise RunnerError(f"unsafe lock filename for {label}: {file_name!r}")
    try:
        before = os.stat(
            file_name,
            dir_fd=lock_directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        if not create:
            if missing_ok:
                return None
            raise RunnerError(f"{label} is missing") from None
        before = None
    except OSError as exc:
        raise RunnerError(f"cannot inspect {label}: {exc}") from exc
    if before is not None and (
        not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
    ):
        raise RunnerError(f"unsafe {label}")

    flags = (
        (os.O_RDWR if writable else os.O_RDONLY)
        | (os.O_CREAT if create else 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            file_name,
            flags,
            0o600,
            dir_fd=lock_directory_fd,
        )
        opened = os.fstat(descriptor)
        after = os.stat(
            file_name,
            dir_fd=lock_directory_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
            or (
                before is not None
                and (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            )
        ):
            raise RunnerError(f"{label} changed while being opened")
        return descriptor
    except RunnerError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.EMLINK}:
            raise RunnerError(f"unsafe {label}") from exc
        raise RunnerError(f"cannot open {label}: {exc}") from exc


def _revalidate_lock_file_at(
    lock_directory_fd: int,
    file_name: str,
    descriptor: int,
    *,
    label: str,
) -> None:
    """Prove the acquired lock still names the opened single-link inode."""

    try:
        opened = os.fstat(descriptor)
        current = os.stat(
            file_name,
            dir_fd=lock_directory_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise RunnerError(f"cannot revalidate {label}: {exc}") from exc
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or not stat.S_ISREG(current.st_mode)
        or current.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise RunnerError(f"{label} changed while acquiring its lock")


@contextmanager
def batch_singleton_lock(state_dir: Path, batch_key: str) -> Iterator[int]:
    """Hold a process-recoverable, fail-closed singleton lock for one batch.

    The lock file remains as diagnostic state. ``flock`` ownership lives on the
    open file description, so the kernel releases it after normal or abnormal
    process exit without stale-lock deletion races.
    """
    if not batch_key or Path(batch_key).name != batch_key:
        raise RunnerError(f"unsafe batch lock key: {batch_key!r}")
    lock_path = state_dir / "locks" / f"{batch_key}.lock"
    descriptor: int | None = None
    lock_directory_fd: int | None = None
    try:
        lock_directory_fd = _open_directory_chain(
            lock_path.parent,
            label="singleton lock directory",
            create=True,
        )
        assert lock_directory_fd is not None
        descriptor = _open_lock_file_at(
            lock_directory_fd,
            lock_path.name,
            label=f"singleton lock for {batch_key}: {lock_path}",
            writable=True,
            create=True,
        )
        assert descriptor is not None
    except RunnerError:
        if descriptor is not None:
            os.close(descriptor)
        if lock_directory_fd is not None:
            os.close(lock_directory_fd)
        raise
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if lock_directory_fd is not None:
            os.close(lock_directory_fd)
        raise RunnerError(f"cannot open singleton lock for {batch_key}: {exc}") from exc

    assert descriptor is not None
    acquired = False
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise RunnerError(
                    f"{batch_key} is already running in another refresh runner"
                ) from exc
            raise RunnerError(
                f"cannot acquire singleton lock for {batch_key}: {exc}"
            ) from exc
        assert lock_directory_fd is not None
        _revalidate_lock_file_at(
            lock_directory_fd,
            lock_path.name,
            descriptor,
            label=f"singleton lock for {batch_key}: {lock_path}",
        )

        metadata = json.dumps(
            {
                "batch": batch_key,
                "pid": os.getpid(),
                "acquired_at": _utc_now(),
            },
            sort_keys=True,
        ).encode("utf-8")
        try:
            os.ftruncate(descriptor, 0)
            os.write(descriptor, metadata + b"\n")
            os.fsync(descriptor)
            assert lock_directory_fd is not None
            os.fsync(lock_directory_fd)
        except OSError as exc:
            raise RunnerError(
                f"cannot record singleton lock for {batch_key}: {exc}"
            ) from exc
        # The campaign-wide descriptor is passed through the analyzer exec.
        # If the runner itself is killed without a Python ``finally`` (SIGKILL,
        # host OOM), the live analyzer therefore keeps the kernel flock and a
        # retry cannot concurrently write the same campaign directories.
        yield descriptor
    finally:
        if acquired:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
        assert lock_directory_fd is not None
        os.close(lock_directory_fd)


def build_command(
    batch: BatchSpec,
    *,
    analyzer_dir: Path | None = None,
) -> list[str]:
    """Build the immutable analyzer invocation for a batch."""
    analyzer_root = (
        (_REPO_ROOT / "cve-analyzer") if analyzer_dir is None else analyzer_dir
    ).resolve()
    return [
        sys.executable,
        "-I",
        str(analyzer_root / "src" / "cve_analyzer" / "cli.py"),
        "--no-cache",
        "batch",
        "--cve-list",
        str(batch.path),
        "--recheck",
        "--force-verify",
        "--workers",
        str(WORKERS),
        "--no-deep-discovery",
        "--llm-verify",
        "--llm-model",
        MODEL,
        "--verify-model",
        MODEL,
        "--coding-agent",
        "off",
    ]


def build_environment(
    base: Mapping[str, str] | None = None,
    *,
    campaign: CampaignExecution | None = None,
    batch_key: str = "",
    started_at: str = "",
) -> dict[str, str]:
    environment = dict(os.environ if base is None else base)
    # The launcher and child both execute the repository-bound virtualenv.
    # Remove Python path injection even for callers that bypass the shell
    # launcher; ``-I`` on the child provides a second, interpreter-enforced
    # boundary.
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["CVE_REASONING_EFFORT"] = REASONING_EFFORT
    environment[FROZEN_LOCAL_SOURCES_ENV] = "1"
    environment[LLM_MODEL_OVERRIDE_ENV] = MODEL
    environment[LLM_STRICT_MODEL_ENV] = "1"
    environment[LLM_DISABLE_CACHE_ENV] = "1"
    environment[LLM_CONCURRENCY_ENV] = str(LLM_CONCURRENCY)
    if campaign is not None:
        if not batch_key or not started_at:
            raise RunnerError(
                "campaign environment requires a batch key and start timestamp"
            )
        current_transport, current_transport_sha256 = litellm_transport_contract(
            environment
        )
        if (
            current_transport_sha256 != campaign.litellm_transport_sha256
            or current_transport != campaign.litellm_transport
        ):
            raise RunnerError("LiteLLM campaign transport changed after binding")
        environment[RESULT_DIR_ENV] = str(campaign.result_dir)
        environment[API_CACHE_DIR_ENV] = str(campaign.api_cache_dir)
        environment[DERIVED_CACHE_ROOT_ENV] = str(campaign.derived_cache_root)
        environment[CAMPAIGN_ID_ENV] = campaign.campaign_id
        environment[CAMPAIGN_BATCH_ENV] = batch_key
        environment[CAMPAIGN_STARTED_AT_ENV] = started_at
        environment[CAMPAIGN_SOURCE_ENV] = campaign.source_snapshot_sha256
        environment[CAMPAIGN_CONTRACT_ENV] = campaign.contract_sha256
        environment[CAMPAIGN_LITELLM_TRANSPORT_ENV] = campaign.litellm_transport_sha256
        if campaign.alias_class_delta_path or campaign.alias_class_manifest_sha256:
            if not (
                campaign.alias_class_delta_path and campaign.alias_class_manifest_sha256
            ):
                raise RunnerError("formal alias-class campaign binding is incomplete")
            environment[CAMPAIGN_ALIAS_DELTA_ENV] = campaign.alias_class_delta_path
            environment[CAMPAIGN_ALIAS_MANIFEST_ENV] = (
                campaign.alias_class_manifest_sha256
            )
        if campaign.analysis_checkout is not None:
            checkout = _analysis_checkout_receipt_binding(
                campaign.analysis_checkout
            )
            environment[PINNED_REPOSITORY_IDENTITY_ENV] = checkout[
                "repository_identity"
            ]
            environment[PINNED_REPOSITORY_PATH_ENV] = checkout["path"]
            environment[PINNED_REPOSITORY_ORIGIN_ENV] = checkout["origin"]
            environment[PINNED_REPOSITORY_HEAD_ENV] = checkout["head_sha"]
            environment[PINNED_REPOSITORY_TREE_ENV] = checkout["tree_sha"]
    return environment


_TERMINAL_RESULT_CATEGORIES = frozenset({"no_fix_commits"})
_TRANSIENT_RESULT_CATEGORIES = frozenset({"api_error", "clone_failed"})
_KNOWN_NONTERMINAL_RESULT_CATEGORIES = frozenset({"no_ai_activity"})
_INCOMPLETE_RESULT_CATEGORIES = frozenset(
    {"fix_commit_unavailable", "skipped_advisory"}
)


def _terminal_result_problem(payload: dict[str, Any]) -> str | None:
    error = payload.get("error", "")
    error_category = payload.get("error_category", "")
    if not isinstance(error, str):
        return "invalid error field"
    if not isinstance(error_category, str):
        return "invalid error_category"

    repo_activity = payload.get("repo_ai_activity", [])
    if not isinstance(repo_activity, list) or not all(
        isinstance(reason, str) for reason in repo_activity
    ):
        return "invalid repo_ai_activity"
    incomplete = [
        reason for reason in repo_activity if reason.startswith("incomplete:")
    ]
    if incomplete:
        return f"incomplete Tier-0 result: {', '.join(incomplete)}"

    if error_category in _TRANSIENT_RESULT_CATEGORIES:
        return f"transient result: {error_category}"
    if error_category in _INCOMPLETE_RESULT_CATEGORIES:
        return f"incomplete result category: {error_category}"
    if error_category in _KNOWN_NONTERMINAL_RESULT_CATEGORIES:
        return f"non-terminal result category: {error_category}"
    if error_category and error_category not in _TERMINAL_RESULT_CATEGORIES:
        return f"unsupported result category: {error_category}"
    if not error_category and error:
        return "unterminated error without a terminal error_category"
    return None


def _analysis_stage_receipt_proof(
    payload: Mapping[str, Any],
    *,
    class_record: Mapping[str, Any],
    campaign: CampaignExecution,
    result_sha256: str,
) -> tuple[str | None, dict[str, Any] | None]:
    """Validate D9 and bind analyzer outcomes to this exact class and epoch."""

    raw_receipts = payload.get("analysis_stage_receipts")
    if not isinstance(raw_receipts, dict) or not analysis_stage_receipts_are_valid(
        raw_receipts,
        require_all=True,
    ):
        return "missing or invalid complete analysis stage receipts", None

    outcomes = [raw_receipts[stage]["outcome"] for stage in ANALYSIS_STAGE_NAMES]
    if outcomes[0] != "resolved":
        return "source discovery stage did not resolve", None
    exhausted = False
    for stage, outcome in zip(ANALYSIS_STAGE_NAMES, outcomes, strict=True):
        if outcome in {"incomplete", "error"}:
            if (
                stage == "adjudication"
                and outcome == "incomplete"
                and raw_receipts[stage].get("reason")
                == "incomplete:independent_adjudication_required"
            ):
                continue
            return f"analysis stage is non-terminal: {stage}={outcome}", None
        if exhausted:
            if outcome != "not_applicable":
                return (
                    f"downstream analysis stage must be not_applicable: {stage}",
                    None,
                )
            continue
        if outcome == "not_applicable":
            return f"analysis stage is unexpectedly not_applicable: {stage}", None
        if outcome == "exhausted_no_match":
            exhausted = True

    for stage in ("fix_resolution", "bic_resolution"):
        stage_receipt = raw_receipts[stage]
        if stage_receipt["outcome"] != "exhausted_no_match":
            continue
        methods = stage_receipt.get("methods")
        configured_methods = stage_receipt.get("configured_methods")
        if not isinstance(methods, list) or not methods:
            return f"{stage} exhaustion has no method receipts", None
        if (
            not isinstance(configured_methods, list)
            or not configured_methods
            or any(
                not isinstance(method, str) or not method
                for method in configured_methods
            )
            or len(configured_methods) != len(set(configured_methods))
        ):
            return f"{stage} exhaustion has no configured-method inventory", None
        method_names: list[str] = []
        allowed_not_applicable_reasons = {
            "no_alias_class_manifest",
            "prior_strategy_resolved",
            "missing_advisory_repository_or_version",
            "no_reference_urls",
            "missing_repository_description_or_versions",
            "missing_repository_or_description",
            "no_reference_repositories",
        }
        for method in methods:
            if not isinstance(method, dict):
                return f"{stage} has a malformed method receipt", None
            method_name = method.get("method")
            if (
                not isinstance(method_name, str)
                or not method_name
                or method.get("outcome")
                not in {"resolved", "exhausted_no_match", "not_applicable"}
                or any(
                    not isinstance(method.get(field), str)
                    or re.fullmatch(r"[0-9a-f]{64}", method[field]) is None
                    for field in ("input_sha256", "output_sha256")
                )
            ):
                return f"{stage} has a malformed method receipt", None
            if (
                method.get("outcome") == "not_applicable"
                and method.get("prerequisite_reason")
                not in allowed_not_applicable_reasons
            ):
                return f"{stage} has an unproved not-applicable method", None
            method_names.append(method_name)
        if len(method_names) != len(set(method_names)):
            return f"{stage} repeats a configured method receipt", None
        if set(method_names) != set(configured_methods):
            return f"{stage} method receipts are incomplete", None

    signal_receipt = raw_receipts["signal_classification"]
    if signal_receipt["outcome"] == "exhausted_no_match":
        raw_bics = payload.get("bug_introducing_commits")
        if not isinstance(raw_bics, list) or not raw_bics:
            return "signal exhaustion has no causal subjects", None
        expected_subjects: set[tuple[str, str, str, str]] = set()
        for bic in raw_bics:
            commit = bic.get("commit") if isinstance(bic, dict) else None
            subject_key = (
                bic.get("repository_identity", "") if isinstance(bic, dict) else None,
                bic.get("fix_commit_sha") if isinstance(bic, dict) else None,
                commit.get("sha") if isinstance(commit, dict) else None,
                bic.get("blamed_file") if isinstance(bic, dict) else None,
            )
            if any(not isinstance(value, str) for value in subject_key):
                return "signal exhaustion has a malformed causal subject", None
            normalized_key = (
                subject_key[0],
                subject_key[1].lower(),
                subject_key[2].lower(),
                subject_key[3],
            )
            if normalized_key in expected_subjects:
                return "signal exhaustion repeats a causal subject", None
            expected_subjects.add(normalized_key)
        configured_signal_methods = signal_receipt.get("configured_methods")
        signal_methods = signal_receipt.get("methods")
        if configured_signal_methods != list(
            SIGNAL_CLASSIFICATION_METHODS
        ) or not isinstance(signal_methods, list):
            return "signal exhaustion configured methods are incomplete", None
        for method in signal_methods:
            subjects = method.get("subjects") if isinstance(method, dict) else None
            if not isinstance(subjects, list):
                return "signal exhaustion method subjects are malformed", None
            observed = {
                tuple(subject.get("subject_key", ()))
                for subject in subjects
                if isinstance(subject, dict)
            }
            if observed != expected_subjects:
                return "signal exhaustion does not cover every causal subject", None

    error_category = payload.get("error_category", "")
    if (
        error_category == "no_fix_commits"
        and raw_receipts["fix_resolution"].get("outcome") != "exhausted_no_match"
    ):
        return "no_fix_commits lacks exhaustive fix-resolution receipts", None

    class_id = class_record.get("class_id")
    component_sha256 = class_record.get("component_sha256")
    source_snapshot_sha256 = class_record.get("source_snapshot_sha256")
    source_evidence_sha256 = class_record.get("merged_source_evidence_sha256")
    if (
        not isinstance(class_id, str)
        or not isinstance(component_sha256, str)
        or not isinstance(source_snapshot_sha256, str)
        or not isinstance(source_evidence_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", component_sha256) is None
        or re.fullmatch(r"[0-9a-f]{64}", source_snapshot_sha256) is None
        or re.fullmatch(r"[0-9a-f]{64}", source_evidence_sha256) is None
        or re.fullmatch(r"[0-9a-f]{64}", campaign.analyzer_contract_sha256) is None
        or re.fullmatch(r"[0-9a-f]{64}", campaign.signature_sha256) is None
    ):
        return "alias-class receipt binding is malformed or stale", None

    repository_inputs: list[str] = []
    analysis_input = class_record.get("analysis_input")
    if isinstance(analysis_input, dict):
        git_ranges = analysis_input.get("git_ranges", [])
        if isinstance(git_ranges, list):
            repository_inputs = sorted(
                {
                    repo
                    for item in git_ranges
                    if isinstance(item, dict)
                    for repo in [item.get("repo")]
                    if isinstance(repo, str) and repo
                }
            )
    fix_inputs = [
        list(item)
        for item in sorted(
            {
                (
                    str(item.get("repository_identity") or item.get("repo_url") or ""),
                    str(item.get("sha") or ""),
                )
                for item in payload.get("fix_commits", [])
                if isinstance(item, dict)
            }
        )
    ]
    base_binding = {
        "class_id": class_id,
        "component_sha256": component_sha256,
        "source_class_snapshot_sha256": source_snapshot_sha256,
        "campaign_source_snapshot_sha256": campaign.source_snapshot_sha256,
        "source_evidence_sha256": source_evidence_sha256,
        "analyzer_contract_sha256": campaign.analyzer_contract_sha256,
        "signature_sha256": campaign.signature_sha256,
        "campaign_contract_sha256": campaign.contract_sha256,
        "campaign_id": campaign.campaign_id,
        "model_contract": {
            "requested_model": MODEL,
            "reasoning_effort": REASONING_EFFORT,
            "litellm_transport_sha256": campaign.litellm_transport_sha256,
        },
        "repository_inputs": repository_inputs,
        "fix_inputs": fix_inputs,
    }
    previous_output = hashlib.sha256(_canonical_json_bytes(base_binding)).hexdigest()
    bound_stages: dict[str, dict[str, Any]] = {}
    for stage in ANALYSIS_STAGE_NAMES:
        analyzer_receipt = raw_receipts[stage]
        stage_input = hashlib.sha256(
            _canonical_json_bytes(
                {
                    "binding": base_binding,
                    "previous_output_sha256": previous_output,
                    "stage": stage,
                }
            )
        ).hexdigest()
        stage_output = hashlib.sha256(
            _canonical_json_bytes(
                {
                    "input_sha256": stage_input,
                    "analyzer_receipt": analyzer_receipt,
                    "result_sha256": result_sha256,
                }
            )
        ).hexdigest()
        bound_stages[stage] = {
            "outcome": analyzer_receipt["outcome"],
            "input_sha256": stage_input,
            "output_sha256": stage_output,
            "analyzer_receipt": analyzer_receipt,
        }
        previous_output = stage_output
    return None, {
        "schema_version": 1,
        **base_binding,
        "result_sha256": result_sha256,
        "stages": bound_stages,
        "terminal_stage_output_sha256": previous_output,
    }


def _llm_provenance_problem(payload: dict[str, Any]) -> str | None:
    """Reject cached or downgraded LLM judgments in a fixed campaign result."""

    allowed_models = {MODEL, f"osv+{MODEL}"}

    def visit(value: object, path: str) -> str | None:
        if isinstance(value, dict):
            model = value.get("model")
            if isinstance(model, str) and model and model not in allowed_models:
                return (
                    f"LLM model provenance mismatch at {path}: "
                    f"expected {MODEL}, got {model}"
                )
            if path.endswith(".deep_verification"):
                if model not in allowed_models:
                    return f"LLM model provenance mismatch at {path}"
                effort = value.get("reasoning_effort")
                if effort != REASONING_EFFORT:
                    return (
                        "deep verification reasoning effort mismatch at "
                        f"{path}: expected {REASONING_EFFORT}, got {effort}"
                    )
            for key, item in value.items():
                problem = visit(item, f"{path}.{key}")
                if problem:
                    return problem
        elif isinstance(value, list):
            for index, item in enumerate(value):
                problem = visit(item, f"{path}[{index}]")
                if problem:
                    return problem
        return None

    return visit(payload, "$")


def _campaign_receipt_problem(
    payload: dict[str, Any],
    *,
    campaign: CampaignExecution,
    batch_key: str,
    started_at: str,
    started_at_ns: int,
    completed_at_ns: int,
    result_mtime_ns: int,
) -> str | None:
    receipt = payload.get("campaign_receipt")
    if not isinstance(receipt, dict):
        return "missing campaign receipt"
    expected = {
        "schema_version": 1,
        "campaign_id": campaign.campaign_id,
        "batch": batch_key,
        "started_at": started_at,
        "source_snapshot_sha256": campaign.source_snapshot_sha256,
        "contract_sha256": campaign.contract_sha256,
        "litellm_transport_sha256": campaign.litellm_transport_sha256,
        "requested_model": MODEL,
        "reasoning_effort": REASONING_EFFORT,
        "llm_cache_disabled": True,
        "status": "success",
        "failed_stages": [],
    }
    if campaign.analysis_checkout is not None:
        expected["analysis_checkout"] = _analysis_checkout_receipt_binding(
            campaign.analysis_checkout
        )
    for field, value in expected.items():
        if receipt.get(field) != value:
            return (
                f"campaign receipt mismatch for {field}: "
                f"expected {value!r}, got {receipt.get(field)!r}"
            )
    expected_fields = {
        *expected,
        "completed_at",
        "stages",
    }
    if set(receipt) != expected_fields:
        return "invalid campaign receipt fields"
    receipt_completed_at_ns = _iso_timestamp_ns(receipt.get("completed_at"))
    if (
        receipt_completed_at_ns is None
        or receipt_completed_at_ns < started_at_ns
        or receipt_completed_at_ns > completed_at_ns
    ):
        return "campaign receipt completion time is outside the batch window"
    if result_mtime_ns - receipt_completed_at_ns > RESULT_RECEIPT_WRITE_GRACE_NS:
        return "result mtime is later than its campaign receipt completion"
    stages = receipt.get("stages")
    if not isinstance(stages, dict) or set(stages) != {
        "phase_c_screening",
        "phase_d_deep_verification",
    }:
        return "invalid campaign receipt stages"
    for name, stage in stages.items():
        if not isinstance(stage, dict) or stage.get("status") not in {
            "success",
            "not_applicable",
        }:
            return f"campaign receipt stage failed: {name}"
    return None


def _result_entry_signature(metadata: os.stat_result) -> tuple[int, ...]:
    """Return every inode field needed to prove a stable result read."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _result_directory_inventory(
    descriptor: int,
    *,
    result_dir: Path,
) -> dict[str, tuple[int, ...]]:
    """Capture one no-follow directory inventory through its open descriptor."""

    try:
        names = os.listdir(descriptor)
    except OSError as exc:
        raise RunnerError(
            f"cannot enumerate batch result directory {result_dir}: {exc}"
        ) from exc
    if len(names) != len(set(names)):
        raise RunnerError(f"batch result directory has duplicate names: {result_dir}")

    inventory: dict[str, tuple[int, ...]] = {}
    for name in sorted(names):
        if not isinstance(name, str) or name in {"", ".", ".."}:
            raise RunnerError(f"batch result directory has an unsafe entry: {name!r}")
        try:
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as exc:
            raise RunnerError(
                f"cannot inspect batch result entry {result_dir / name}: {exc}"
            ) from exc
        inventory[name] = _result_entry_signature(metadata)
    return inventory


def _read_stable_batch_result(
    directory_fd: int,
    *,
    file_name: str,
    cve_id: str,
    initial_signature: tuple[int, ...],
) -> tuple[bytes, os.stat_result]:
    """Read one expected result by dir-fd without following or racing its name."""

    mode = initial_signature[2]
    link_count = initial_signature[3]
    size = initial_signature[4]
    if stat.S_ISLNK(mode):
        raise RunnerError(f"unsafe symlink result for {cve_id}")
    if not stat.S_ISREG(mode) or link_count != 1:
        raise RunnerError(f"unsafe non-regular result for {cve_id}")
    if size > MAX_RESULT_JSON_BYTES:
        raise RunnerError(
            f"oversized result for {cve_id}: {size} bytes exceeds "
            f"{MAX_RESULT_JSON_BYTES}-byte limit"
        )

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(file_name, flags, dir_fd=directory_fd)
        opened = os.fstat(descriptor)
        named_after_open = os.stat(
            file_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        opened_signature = _result_entry_signature(opened)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or initial_signature != opened_signature
            or opened_signature != _result_entry_signature(named_after_open)
        ):
            raise RunnerError(f"result changed while read for {cve_id}")
        if opened.st_size > MAX_RESULT_JSON_BYTES:
            raise RunnerError(
                f"oversized result for {cve_id}: {opened.st_size} bytes exceeds "
                f"{MAX_RESULT_JSON_BYTES}-byte limit"
            )

        content = bytearray()
        while True:
            remaining_with_sentinel = MAX_RESULT_JSON_BYTES + 1 - len(content)
            chunk = os.read(descriptor, min(1024 * 1024, remaining_with_sentinel))
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > MAX_RESULT_JSON_BYTES:
                raise RunnerError(
                    f"oversized result for {cve_id}: exceeds "
                    f"{MAX_RESULT_JSON_BYTES}-byte limit"
                )

        after = os.fstat(descriptor)
        named_after_read = os.stat(
            file_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            opened_signature != _result_entry_signature(after)
            or opened_signature != _result_entry_signature(named_after_read)
            or len(content) != after.st_size
        ):
            raise RunnerError(f"result changed while read for {cve_id}")
        return bytes(content), after
    except RunnerError:
        raise
    except FileNotFoundError as exc:
        raise RunnerError(f"result changed while read for {cve_id}") from exc
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.EMLINK}:
            raise RunnerError(f"unsafe symlink result for {cve_id}") from exc
        if exc.errno in {errno.EISDIR, errno.ENXIO, errno.ENOTDIR}:
            raise RunnerError(f"unsafe non-regular result for {cve_id}") from exc
        raise RunnerError(f"cannot read result for {cve_id}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def validate_batch_results(
    batch: BatchSpec,
    result_dir: Path,
    started_at_ns: int,
    *,
    completed_at_ns: int | None = None,
    started_at: str = "",
    campaign: CampaignExecution | None = None,
    allowed_result_ids: Sequence[str] | None = None,
    class_records: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Prove that every requested ID produced a fresh terminal result.

    A zero subprocess exit is only a transport-level success. Missing files,
    transient API/clone failures, stale output, and incomplete Tier-0 scans
    keep the batch pending so a completion marker can never hide recall loss.
    """
    if isinstance(started_at_ns, bool) or not isinstance(started_at_ns, int):
        raise TypeError("started_at_ns must be an integer")
    if started_at_ns < 0:
        raise ValueError("started_at_ns must be non-negative")
    if completed_at_ns is not None and (
        isinstance(completed_at_ns, bool)
        or not isinstance(completed_at_ns, int)
        or completed_at_ns < started_at_ns
    ):
        raise ValueError("completed_at_ns must be an integer at or after started_at_ns")
    if campaign is not None and (
        completed_at_ns is None or _iso_timestamp_ns(started_at) is None
    ):
        raise ValueError("campaign validation requires a bounded batch time window")

    problems: list[str] = []
    terminal_count = 0
    result_manifest: list[dict[str, Any]] = []
    class_receipts: list[dict[str, Any]] = []
    unique_ids = tuple(dict.fromkeys(batch.ids))
    if len(unique_ids) != len(batch.ids):
        duplicate_ids = sorted(
            cve_id for cve_id, count in Counter(batch.ids).items() if count > 1
        )
        problems.append(f"duplicate result IDs in batch: {duplicate_ids[:10]}")

    allowed_ids = tuple(
        dict.fromkeys(batch.ids if allowed_result_ids is None else allowed_result_ids)
    )
    if len(allowed_ids) != len(
        batch.ids if allowed_result_ids is None else allowed_result_ids
    ):
        problems.append("duplicate IDs in allowed result inventory")
    allowed_id_set = set(allowed_ids)
    if not set(unique_ids).issubset(allowed_id_set):
        problems.append("batch IDs are absent from the allowed result inventory")

    for cve_id in (*unique_ids, *allowed_ids):
        if not cve_id or Path(cve_id).name != cve_id:
            problems.append(f"unsafe result ID {cve_id!r}")
    if problems:
        preview = "; ".join(problems[:10])
        suffix = f"; plus {len(problems) - 10} more" if len(problems) > 10 else ""
        raise RunnerError(
            f"{batch.key} result validation failed ({len(problems)} issue(s)): "
            f"{preview}{suffix}"
        )

    expected_names = {f"{cve_id}.json": cve_id for cve_id in unique_ids}
    allowed_names = {f"{cve_id}.json": cve_id for cve_id in allowed_ids}
    directory_fd = _open_directory_chain(
        result_dir,
        label="batch result directory",
        create=False,
    )
    assert directory_fd is not None
    try:
        directory_before = _result_entry_signature(os.fstat(directory_fd))
        inventory_before = _result_directory_inventory(
            directory_fd,
            result_dir=result_dir,
        )
        actual_names = set(inventory_before)
        for name in sorted(actual_names - set(allowed_names)):
            problems.append(f"unexpected result file {name!r}")
        for name, cve_id in expected_names.items():
            if name not in actual_names:
                problems.append(f"missing result for {cve_id}")
        for name in sorted((actual_names & set(allowed_names)) - set(expected_names)):
            signature = inventory_before[name]
            mode = signature[2]
            if stat.S_ISLNK(mode):
                problems.append(f"unsafe symlink result for {allowed_names[name]}")
            elif not stat.S_ISREG(mode) or signature[3] != 1:
                problems.append(f"unsafe non-regular result for {allowed_names[name]}")
            elif signature[4] > MAX_RESULT_JSON_BYTES:
                problems.append(
                    f"oversized result for {allowed_names[name]}: "
                    f"{signature[4]} bytes exceeds {MAX_RESULT_JSON_BYTES}-byte limit"
                )

        for name, cve_id in expected_names.items():
            initial_signature = inventory_before.get(name)
            if initial_signature is None:
                continue
            try:
                content, stat_before = _read_stable_batch_result(
                    directory_fd,
                    file_name=name,
                    cve_id=cve_id,
                    initial_signature=initial_signature,
                )
            except RunnerError as exc:
                problems.append(str(exc))
                continue
            if stat_before.st_mtime_ns < started_at_ns:
                problems.append(f"stale result for {cve_id}")
                continue
            if (
                completed_at_ns is not None
                and stat_before.st_mtime_ns > completed_at_ns
            ):
                problems.append(f"future-dated result for {cve_id}")
                continue

            try:
                payload = json.loads(content.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                problems.append(f"invalid result for {cve_id}: {exc}")
                continue
            if not isinstance(payload, dict) or payload.get("cve_id") != cve_id:
                problems.append(f"result identity mismatch for {cve_id}")
                continue

            terminal_problem = _terminal_result_problem(payload)
            if terminal_problem:
                problems.append(f"{terminal_problem} for {cve_id}")
                continue
            provenance_problem = _llm_provenance_problem(payload)
            if provenance_problem:
                problems.append(f"{provenance_problem} for {cve_id}")
                continue
            if campaign is not None:
                receipt_problem = _campaign_receipt_problem(
                    payload,
                    campaign=campaign,
                    batch_key=batch.key,
                    started_at=started_at,
                    started_at_ns=started_at_ns,
                    completed_at_ns=completed_at_ns,
                    result_mtime_ns=stat_before.st_mtime_ns,
                )
                if receipt_problem:
                    problems.append(f"{receipt_problem} for {cve_id}")
                    continue
                if class_records is not None:
                    class_record = class_records.get(cve_id)
                    if class_record is None:
                        problems.append(f"missing alias-class binding for {cve_id}")
                        continue
                    result_sha256 = hashlib.sha256(content).hexdigest()
                    stage_problem, class_receipt = _analysis_stage_receipt_proof(
                        payload,
                        class_record=class_record,
                        campaign=campaign,
                        result_sha256=result_sha256,
                    )
                    if stage_problem:
                        problems.append(f"{stage_problem} for {cve_id}")
                        continue
                    assert class_receipt is not None
                    class_receipts.append(class_receipt)
            terminal_count += 1
            result_manifest.append(
                {
                    "subject_id": cve_id,
                    "size_bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            )

        try:
            inventory_after = _result_directory_inventory(
                directory_fd,
                result_dir=result_dir,
            )
            directory_after = _result_entry_signature(os.fstat(directory_fd))
            path_after = _result_entry_signature(
                os.stat(result_dir, follow_symlinks=False)
            )
        except (OSError, RunnerError) as exc:
            problems.append(f"cannot revalidate batch result directory: {exc}")
        else:
            if (
                inventory_after != inventory_before
                or directory_after != directory_before
                or path_after != directory_before
            ):
                problems.append("batch result directory changed while read")
    finally:
        os.close(directory_fd)

    if problems:
        preview = "; ".join(problems[:10])
        suffix = f"; plus {len(problems) - 10} more" if len(problems) > 10 else ""
        raise RunnerError(
            f"{batch.key} result validation failed ({len(problems)} issue(s)): {preview}{suffix}"
        )
    result_manifest.sort(key=lambda item: item["subject_id"])
    validation = {
        "result_count": len(unique_ids),
        "terminal_count": terminal_count,
        "result_manifest_sha256": hashlib.sha256(
            _canonical_json_bytes(result_manifest)
        ).hexdigest(),
    }
    if class_records is not None:
        class_receipts.sort(key=lambda item: item["class_id"])
        if len(class_receipts) != len(unique_ids) or len(
            {item["class_id"] for item in class_receipts}
        ) != len(unique_ids):
            raise RunnerError(f"{batch.key} class receipt proof is not exact-once")
        validation.update(
            {
                "class_receipt_count": len(class_receipts),
                "class_receipts_sha256": hashlib.sha256(
                    _canonical_json_bytes(class_receipts)
                ).hexdigest(),
                "class_receipts": class_receipts,
                "alias_classes_exactly_once": True,
            }
        )
    return validation


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate_process_group(
    process: subprocess.Popen[Any],
    *,
    log: Any,
    reason: str,
) -> None:
    """Best-effort terminate the child's new session and reap its leader."""

    process_group_id = process.pid
    log.write(f"\n=== {reason}; terminating process group ===\n")
    log.flush()
    try:
        os.killpg(process_group_id, signal.SIGTERM)
    except ProcessLookupError:
        pass

    deadline = time.monotonic() + BATCH_TERMINATION_GRACE_SECONDS
    while time.monotonic() < deadline:
        process.poll()
        if not _process_group_exists(process_group_id):
            break
        time.sleep(0.05)

    if _process_group_exists(process_group_id):
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            pass

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        log.write("batch process-group leader could not be reaped after SIGKILL\n")
        log.flush()


def _run_subprocess(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    log_path: Path,
    timeout_seconds: float = BATCH_TIMEOUT_SECONDS,
    inherited_fds: Sequence[int] = (),
) -> int:
    with log_path.open("a", encoding="utf-8") as log:
        process: subprocess.Popen[Any] | None = None
        try:
            managed_signals = {signal.SIGHUP, signal.SIGINT, signal.SIGTERM}
            previous_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK,
                managed_signals,
            )
            try:
                process = subprocess.Popen(
                    list(command),
                    cwd=cwd,
                    env=dict(env),
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    pass_fds=tuple(inherited_fds),
                    start_new_session=True,
                )
            finally:
                # A signal queued during Popen is delivered only after the
                # returned child has been assigned, so the outer handler can
                # always terminate and reap its new process group.
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            exit_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            assert process is not None
            _terminate_process_group(
                process,
                log=log,
                reason=f"batch deadline exceeded after {timeout_seconds} seconds",
            )
            raise
        except BaseException as exc:
            if process is None:
                raise
            interruption = type(exc).__name__
            if isinstance(exc, CampaignSignalInterrupt):
                interruption += f"({exc.signal_name})"
            _terminate_process_group(
                process,
                log=log,
                reason=f"batch interrupted by {interruption}",
            )
            raise

        # A successful leader exit is incomplete while a process in its
        # dedicated group is still alive: it can continue mutating results
        # after validation and marker creation.  Reap the group and fail this
        # attempt so the batch remains retryable.
        assert process is not None
        if _process_group_exists(process.pid):
            _terminate_process_group(
                process,
                log=log,
                reason="batch leader exited with lingering descendants",
            )
            raise subprocess.SubprocessError(
                "batch leader exited while its process group was still alive"
            )
        return exit_code


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.stem}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _regular_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file():
            raise RunnerError(f"{label} must be a regular file: {path}")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except RunnerError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"cannot read {label} {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RunnerError(f"{label} must be a JSON object: {path}")
    return payload


def _canonical_price(raw: str, label: str) -> tuple[str, Decimal]:
    try:
        value = Decimal(raw)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise RunnerError(f"{label} must be a decimal number") from exc
    if not value.is_finite() or value < 0:
        raise RunnerError(f"{label} must be finite and non-negative")
    canonical = format(value, "f")
    if "." in canonical:
        canonical = canonical.rstrip("0").rstrip(".")
    return canonical or "0", value


def _pilot_pricing_contract(pricing: PilotPricing) -> tuple[dict[str, Any], int]:
    input_text, input_price = _canonical_price(
        pricing.input_usd_per_million_tokens,
        "pilot input price",
    )
    output_text, output_price = _canonical_price(
        pricing.output_usd_per_million_tokens,
        "pilot output price",
    )
    if (
        isinstance(pricing.max_input_tokens, bool)
        or not isinstance(pricing.max_input_tokens, int)
        or pricing.max_input_tokens <= 0
        or isinstance(pricing.max_output_tokens, bool)
        or not isinstance(pricing.max_output_tokens, int)
        or pricing.max_output_tokens < MAX_REASONING_OUTPUT_TOKENS_CEILING
    ):
        raise RunnerError(
            "pilot token bounds must be positive and cover the maximum reasoning output"
        )
    if (
        isinstance(pricing.max_attempts, bool)
        or not isinstance(pricing.max_attempts, int)
        or not 1 <= pricing.max_attempts <= OPENCLAW_PILOT_MAX_ATTEMPTS
    ):
        raise RunnerError(
            f"pilot attempts must be between 1 and {OPENCLAW_PILOT_MAX_ATTEMPTS}"
        )
    if (
        isinstance(pricing.max_cost_microusd, bool)
        or not isinstance(pricing.max_cost_microusd, int)
        or not 1 <= pricing.max_cost_microusd <= OPENCLAW_PILOT_MAX_COST_MICROUSD
    ):
        raise RunnerError(
            "pilot cost ceiling must be positive and no greater than USD 25"
        )
    reservation = int(
        (
            Decimal(pricing.max_input_tokens) * input_price
            + Decimal(pricing.max_output_tokens) * output_price
        ).to_integral_value(rounding=ROUND_CEILING)
    )
    if reservation <= 0:
        raise RunnerError("pilot pricing must reserve a positive worst-case cost")
    if reservation > pricing.max_cost_microusd:
        raise RunnerError(
            "one pilot request reservation exceeds the total cost ceiling"
        )
    contract = {
        "model": MODEL,
        "input_usd_per_million_tokens": input_text,
        "output_usd_per_million_tokens": output_text,
        "max_input_tokens": pricing.max_input_tokens,
        "max_output_tokens": pricing.max_output_tokens,
    }
    return contract, reservation


def _pilot_pricing_attestation(
    pricing: PilotPricing,
    source_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Bind operator bounds to the live LiteLLM model-info contract."""

    try:
        config = resolve_litellm_config(
            os.environ if source_env is None else source_env
        )
    except ValueError as exc:
        raise RunnerError(f"invalid LiteLLM pricing transport: {exc}") from exc
    if config is None:
        raise RunnerError("LiteLLM pricing transport is not configured")
    api_root = (
        config.api_base[: -len("/v1")]
        if config.api_base.endswith("/v1")
        else config.api_base
    )
    endpoint = f"{api_root}/model/info"
    try:
        response = httpx.get(
            endpoint,
            headers={"Authorization": f"Bearer {config.api_key}"},
            timeout=PILOT_MODEL_INFO_TIMEOUT_SECONDS,
            follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        raise RunnerError(
            f"LiteLLM model-info query failed: {type(exc).__name__}"
        ) from exc
    if response.status_code != 200:
        raise RunnerError(
            f"LiteLLM model-info query returned HTTP {response.status_code}"
        )
    content = response.content
    if not content or len(content) > PILOT_MODEL_INFO_MAX_BYTES:
        raise RunnerError("LiteLLM model-info response is empty or oversized")
    try:
        payload = response.json()
    except (UnicodeError, ValueError) as exc:
        raise RunnerError("LiteLLM model-info response is malformed") from exc
    entries = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(entries, list):
        raise RunnerError("LiteLLM model-info response has no model inventory")

    matched: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        parameters = entry.get("litellm_params")
        model_info = entry.get("model_info")
        if not isinstance(parameters, dict) or not isinstance(model_info, dict):
            continue
        if entry.get("model_name") != MODEL:
            continue
        try:
            input_cost = Decimal(str(model_info["input_cost_per_token"]))
            output_cost = Decimal(str(model_info["output_cost_per_token"]))
            max_input = model_info["max_input_tokens"]
            max_output = model_info.get(
                "max_output_tokens", model_info.get("max_tokens")
            )
        except (KeyError, InvalidOperation, TypeError, ValueError) as exc:
            raise RunnerError("LiteLLM model-info pricing is malformed") from exc
        if (
            not input_cost.is_finite()
            or input_cost < 0
            or not output_cost.is_finite()
            or output_cost < 0
            or isinstance(max_input, bool)
            or not isinstance(max_input, int)
            or max_input <= 0
            or isinstance(max_output, bool)
            or not isinstance(max_output, int)
            or max_output <= 0
        ):
            raise RunnerError("LiteLLM model-info pricing is malformed")
        matched.append(
            {
                "model_name": entry.get("model_name"),
                "litellm_model": parameters.get("model"),
                "input_cost_per_token": format(input_cost, "f"),
                "output_cost_per_token": format(output_cost, "f"),
                "max_input_tokens": max_input,
                "max_output_tokens": max_output,
            }
        )
    if not matched:
        raise RunnerError(f"LiteLLM model-info has no exact {MODEL!r} contract")

    provider_input = max(
        Decimal(item["input_cost_per_token"]) for item in matched
    ) * Decimal(1_000_000)
    provider_output = max(
        Decimal(item["output_cost_per_token"]) for item in matched
    ) * Decimal(1_000_000)
    configured_input = _canonical_price(
        pricing.input_usd_per_million_tokens,
        "pilot input price",
    )[1]
    configured_output = _canonical_price(
        pricing.output_usd_per_million_tokens,
        "pilot output price",
    )[1]
    provider_max_input = min(item["max_input_tokens"] for item in matched)
    provider_max_output = min(item["max_output_tokens"] for item in matched)
    if configured_input < provider_input or configured_output < provider_output:
        raise RunnerError("pilot prices are below the live LiteLLM model contract")
    if (
        pricing.max_input_tokens > provider_max_input
        or pricing.max_output_tokens > provider_max_output
    ):
        raise RunnerError("pilot token bounds exceed the live LiteLLM model contract")

    provider_input_text = _canonical_price(
        format(provider_input, "f"),
        "provider input price",
    )[0]
    provider_output_text = _canonical_price(
        format(provider_output, "f"),
        "provider output price",
    )[0]
    matched.sort(key=_canonical_json_bytes)
    return {
        "schema_version": 1,
        "model": MODEL,
        "currency": "USD",
        "source_kind": "live_litellm_model_info",
        "effective_time": "queried_immediately_before_pilot_identity",
        "endpoint_sha256": hashlib.sha256(endpoint.encode("utf-8")).hexdigest(),
        "source_response_sha256": hashlib.sha256(content).hexdigest(),
        "matched_entry_count": len(matched),
        "matched_entries_sha256": hashlib.sha256(
            _canonical_json_bytes(matched)
        ).hexdigest(),
        "provider_input_usd_per_million_tokens": provider_input_text,
        "provider_output_usd_per_million_tokens": provider_output_text,
        "provider_max_input_tokens": provider_max_input,
        "provider_max_output_tokens": provider_max_output,
        "configured_prices_at_or_above_provider": True,
        "configured_token_bounds_within_provider": True,
    }


def _openclaw_pilot_selection(
    paths: RunnerPaths,
) -> tuple[
    tuple[BatchSpec, ...],
    dict[str, Any],
    dict[str, dict[str, Any]],
    int,
    int,
]:
    """Select exactly 24 OpenClaw classes from the validated formal manifest."""

    plan = tuple(load_plan(paths, recapture_delta_inputs=True))
    delta_path = paths.grouped_dir.parent / "source-delta-current.json"
    delta = _regular_json_object(delta_path, "formal source delta")
    if (
        delta.get("schema_version") != SOURCE_DELTA_SCHEMA_VERSION
        or delta.get("population_policy") != source_delta_builder.FORMAL_FULL_POLICY
    ):
        raise RunnerError("OpenClaw pilot requires a schema-3 formal source delta")
    production = delta.get("production_discovery")
    manifest = (
        production.get("alias_class_manifest") if isinstance(production, dict) else None
    )
    classes = manifest.get("classes") if isinstance(manifest, dict) else None
    manifest_sha256 = (
        manifest.get("classes_sha256") if isinstance(manifest, dict) else None
    )
    if (
        not isinstance(classes, list)
        or not isinstance(manifest_sha256, str)
        or hashlib.sha256(_canonical_json_bytes(classes)).hexdigest() != manifest_sha256
    ):
        raise RunnerError("OpenClaw pilot parent alias manifest is invalid")

    scheduled = _current_formal_class_records(paths)
    if scheduled is None:
        raise RunnerError("OpenClaw pilot requires scheduled formal alias classes")
    plan_subjects = tuple(subject for batch in plan for subject in batch.ids)
    if len(plan_subjects) != len(set(plan_subjects)) or set(plan_subjects) != set(
        scheduled
    ):
        raise RunnerError("formal batch plan and alias-class population disagree")

    openclaw_records = [
        record
        for record in scheduled.values()
        if _OPENCLAW_REPOSITORY_MARKER
        in _canonical_json_bytes(record.get("analysis_input", {}))
        .decode("utf-8")
        .casefold()
    ]
    if len(openclaw_records) < OPENCLAW_PILOT_CLASS_COUNT:
        raise RunnerError(
            "formal manifest has fewer than "
            f"{OPENCLAW_PILOT_CLASS_COUNT} OpenClaw alias classes"
        )
    ranked = sorted(
        openclaw_records,
        key=lambda item: (
            hashlib.sha256(
                f"{manifest_sha256}\0{item['class_id']}".encode("utf-8")
            ).hexdigest(),
            item["class_id"],
        ),
    )
    selected = ranked[:OPENCLAW_PILOT_CLASS_COUNT]
    selected_records: dict[str, dict[str, Any]] = {}
    selection_classes: list[dict[str, Any]] = []
    for record in selected:
        subject = record.get("analysis_subject")
        class_id = record.get("class_id")
        if (
            not isinstance(subject, str)
            or subject in selected_records
            or not isinstance(class_id, str)
        ):
            raise RunnerError("OpenClaw pilot selection is not exact-once")
        selected_records[subject] = record
        selection_classes.append(
            {
                "class_id": class_id,
                "component_sha256": record.get("component_sha256"),
                "analysis_subject": subject,
                "all_member_ids": record.get("all_member_ids"),
                "scheduled_seed_ids": record.get("scheduled_seed_ids"),
                "merged_source_evidence_sha256": record.get(
                    "merged_source_evidence_sha256"
                ),
                "class_record_sha256": hashlib.sha256(
                    _canonical_json_bytes(record)
                ).hexdigest(),
            }
        )
    if (
        len(selected_records) != OPENCLAW_PILOT_CLASS_COUNT
        or len({item["class_id"] for item in selection_classes})
        != OPENCLAW_PILOT_CLASS_COUNT
    ):
        raise RunnerError("OpenClaw pilot class selection is not exact-once")

    selection = {
        "schema_version": 1,
        "artifact_kind": "pilot",
        "formal_release_eligible": False,
        "selection_method": "sha256(parent_manifest_sha256 + NUL + class_id)",
        "parent_source_delta": _manifest_path_label(delta_path, paths.repo_root),
        "parent_source_delta_sha256": file_sha256(delta_path),
        "parent_alias_class_manifest_sha256": manifest_sha256,
        "parent_alias_class_count": manifest.get("class_count"),
        "parent_scheduled_class_count": manifest.get("scheduled_class_count"),
        "openclaw_class_count": len(openclaw_records),
        "selected_class_count": OPENCLAW_PILOT_CLASS_COUNT,
        "selected_classes_exactly_once": True,
        "classes": selection_classes,
    }
    return plan, selection, selected_records, len(openclaw_records), len(scheduled)


def _openclaw_smoke_selection(
    paths: RunnerPaths,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], int]:
    """Project every current OpenClaw alias class into one exact smoke batch."""

    _, pilot_selection, _, expected_openclaw_count, _ = _openclaw_pilot_selection(
        paths
    )
    scheduled = _current_formal_class_records(paths)
    if scheduled is None:
        raise RunnerError("OpenClaw smoke requires scheduled formal alias classes")
    records = sorted(
        (
            record
            for record in scheduled.values()
            if _OPENCLAW_REPOSITORY_MARKER
            in _canonical_json_bytes(record.get("analysis_input", {}))
            .decode("utf-8")
            .casefold()
        ),
        key=lambda item: item["class_id"],
    )
    selected_records: dict[str, dict[str, Any]] = {}
    selection_classes: list[dict[str, Any]] = []
    for record in records:
        subject = record.get("analysis_subject")
        class_id = record.get("class_id")
        if (
            not isinstance(subject, str)
            or subject in selected_records
            or not isinstance(class_id, str)
        ):
            raise RunnerError("OpenClaw smoke selection is not exact-once")
        selected_records[subject] = record
        selection_classes.append(
            {
                "class_id": class_id,
                "component_sha256": record.get("component_sha256"),
                "analysis_subject": subject,
                "all_member_ids": record.get("all_member_ids"),
                "scheduled_seed_ids": record.get("scheduled_seed_ids"),
                "merged_source_evidence_sha256": record.get(
                    "merged_source_evidence_sha256"
                ),
                "class_record_sha256": hashlib.sha256(
                    _canonical_json_bytes(record)
                ).hexdigest(),
            }
        )
    if (
        len(records) != expected_openclaw_count
        or not records
        or len(selected_records) != len(records)
        or len({item["class_id"] for item in selection_classes}) != len(records)
    ):
        raise RunnerError("OpenClaw smoke class population is not exact-once")
    selection = {
        "schema_version": 1,
        "artifact_kind": "openclaw_smoke",
        "formal_release_eligible": False,
        "selection_method": "all current OpenClaw alias classes by class_id",
        "parent_source_delta": pilot_selection["parent_source_delta"],
        "parent_source_delta_sha256": pilot_selection[
            "parent_source_delta_sha256"
        ],
        "parent_alias_class_manifest_sha256": pilot_selection[
            "parent_alias_class_manifest_sha256"
        ],
        "parent_alias_class_count": pilot_selection["parent_alias_class_count"],
        "parent_scheduled_class_count": pilot_selection[
            "parent_scheduled_class_count"
        ],
        "selected_class_count": len(records),
        "selected_classes_exactly_once": True,
        "classes": selection_classes,
    }
    return selection, selected_records, len(records)


def _pilot_budget_snapshot(
    path: Path,
    *,
    immutable: Mapping[str, Any],
) -> dict[str, Any]:
    payload = _regular_json_object(path, "pilot budget ledger")
    expected_fields = {
        "schema_version",
        "artifact_kind",
        "pilot_id",
        "selection_sha256",
        "pricing_contract_sha256",
        "pricing_contract",
        "deadline_epoch_seconds",
        "max_attempts",
        "max_cost_microusd",
        "reservation_microusd",
        "attempts_reserved",
        "attempts_completed",
        "reserved_cost_microusd",
        "spent_cost_microusd",
        "attempt_receipts",
        "budget_breached",
    }
    if set(payload) != expected_fields or any(
        payload.get(key) != value for key, value in immutable.items()
    ):
        raise RunnerError("pilot budget ledger identity changed")
    integer_fields = (
        "max_attempts",
        "max_cost_microusd",
        "reservation_microusd",
        "attempts_reserved",
        "attempts_completed",
        "reserved_cost_microusd",
        "spent_cost_microusd",
    )
    if any(
        isinstance(payload.get(field), bool)
        or not isinstance(payload.get(field), int)
        or payload[field] < 0
        for field in integer_fields
    ):
        raise RunnerError("pilot budget ledger counters are invalid")
    receipts = payload.get("attempt_receipts")
    deadline = payload.get("deadline_epoch_seconds")
    if (
        payload.get("budget_breached") is not False
        or not isinstance(receipts, list)
        or isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(float(deadline))
        or not 1 <= payload["max_attempts"] <= OPENCLAW_PILOT_MAX_ATTEMPTS
        or not 1
        <= payload["max_cost_microusd"]
        <= OPENCLAW_PILOT_MAX_COST_MICROUSD
        or payload["reservation_microusd"] <= 0
        or payload["attempts_completed"] > payload["attempts_reserved"]
        or payload["reserved_cost_microusd"]
        != payload["attempts_reserved"] * payload["reservation_microusd"]
        or payload["attempts_reserved"] > payload["max_attempts"]
        or payload["reserved_cost_microusd"] > payload["max_cost_microusd"]
        or payload["spent_cost_microusd"] > payload["reserved_cost_microusd"]
    ):
        raise RunnerError("pilot budget ledger bounds are invalid")
    known_spend = 0
    completed_attempts = 0
    for sequence, receipt in enumerate(receipts, start=1):
        if (
            not isinstance(receipt, dict)
            or receipt.get("sequence") != sequence
            or set(receipt)
            != {
                "sequence",
                "admitted_at_epoch_seconds",
                "completed_at_epoch_seconds",
                "status",
                "actual_cost_microusd",
                "input_tokens",
                "output_tokens",
            }
            or isinstance(receipt.get("admitted_at_epoch_seconds"), bool)
            or not isinstance(
                receipt.get("admitted_at_epoch_seconds"), (int, float)
            )
            or not math.isfinite(float(receipt["admitted_at_epoch_seconds"]))
        ):
            raise RunnerError("pilot attempt receipt sequence is invalid")
        status_value = receipt.get("status")
        completed_at = receipt.get("completed_at_epoch_seconds")
        actual = receipt.get("actual_cost_microusd")
        input_tokens = receipt.get("input_tokens")
        output_tokens = receipt.get("output_tokens")
        if status_value == "reserved":
            if any(
                value is not None
                for value in (completed_at, actual, input_tokens, output_tokens)
            ):
                raise RunnerError("pilot reserved attempt receipt is invalid")
            continue
        completed_attempts += 1
        if (
            not isinstance(status_value, str)
            or not status_value
            or isinstance(completed_at, bool)
            or not isinstance(completed_at, (int, float))
            or not math.isfinite(float(completed_at))
            or float(completed_at) < float(receipt["admitted_at_epoch_seconds"])
            or (
                actual is not None
                and (
                    isinstance(actual, bool)
                    or not isinstance(actual, int)
                    or actual < 0
                )
            )
            or any(
                value is not None
                and (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value < 0
                )
                for value in (input_tokens, output_tokens)
            )
            or len(
                {
                    actual is None,
                    input_tokens is None,
                    output_tokens is None,
                }
            )
            != 1
        ):
            raise RunnerError("pilot completed attempt receipt is invalid")
        known_spend += actual or 0
    if (
        len(receipts) != payload["attempts_reserved"]
        or completed_attempts != payload["attempts_completed"]
        or known_spend != payload["spent_cost_microusd"]
    ):
        raise RunnerError(
            "pilot attempt receipt counters or spend are inconsistent"
        )
    return payload


def _validate_budget_attempt_window(
    ledger: Mapping[str, Any],
    *,
    started_at_ns: int,
    completed_at_ns: int,
    deadline_ns: int,
) -> None:
    """Bind every admitted attempt to the completed execution window."""

    for receipt in ledger["attempt_receipts"]:
        admitted_at_ns = int(
            float(receipt["admitted_at_epoch_seconds"]) * 1_000_000_000
        )
        raw_completed_at = receipt["completed_at_epoch_seconds"]
        attempt_completed_at_ns = (
            None
            if raw_completed_at is None
            else int(float(raw_completed_at) * 1_000_000_000)
        )
        if (
            admitted_at_ns < started_at_ns
            or admitted_at_ns > completed_at_ns
            or admitted_at_ns > deadline_ns
            or (
                attempt_completed_at_ns is not None
                and (
                    attempt_completed_at_ns > completed_at_ns
                    or attempt_completed_at_ns > deadline_ns
                )
            )
        ):
            raise RunnerError("budget attempt falls outside its execution window")


def _prepare_pilot_artifacts(
    pilots_root: Path,
    *,
    pilot_id: str,
    selection_document: dict[str, Any],
    batch_bytes: bytes,
    initial_ledger: dict[str, Any],
    immutable_ledger: Mapping[str, Any],
) -> tuple[Path, dict[str, Any]]:
    pilot_root = pilots_root / pilot_id
    if pilot_root.exists():
        if pilot_root.is_symlink() or not pilot_root.is_dir():
            raise RunnerError("pilot artifact root is unsafe")
        if (
            _regular_json_object(pilot_root / "selection.json", "pilot selection")
            != selection_document
        ):
            raise RunnerError("persisted pilot selection changed")
        batch_path = pilot_root / "batch.txt"
        try:
            if batch_path.is_symlink() or batch_path.read_bytes() != batch_bytes:
                raise RunnerError("persisted pilot batch changed")
        except OSError as exc:
            raise RunnerError(f"cannot read persisted pilot batch: {exc}") from exc
        return pilot_root, _pilot_budget_snapshot(
            pilot_root / "budget-ledger.json",
            immutable=immutable_ledger,
        )

    pilots_root.mkdir(parents=True, exist_ok=True)
    if pilots_root.is_symlink() or not pilots_root.is_dir():
        raise RunnerError("pilot artifact parent is unsafe")
    staging_path: Path | None = None
    try:
        staging_path = Path(tempfile.mkdtemp(prefix=f".{pilot_id}.", dir=pilots_root))
        _atomic_write_json(staging_path / "selection.json", selection_document)
        batch_path = staging_path / "batch.txt"
        batch_path.write_bytes(batch_bytes)
        with batch_path.open("rb") as handle:
            os.fsync(handle.fileno())
        _atomic_write_json(staging_path / "budget-ledger.json", initial_ledger)
        os.chmod(staging_path / "budget-ledger.json", 0o600)
        directory_fd = os.open(staging_path, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        os.replace(staging_path, pilot_root)
        staging_path = None
        parent_fd = os.open(pilots_root, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if staging_path is not None:
            shutil.rmtree(staging_path, ignore_errors=True)
    return pilot_root, _pilot_budget_snapshot(
        pilot_root / "budget-ledger.json",
        immutable=immutable_ledger,
    )


def _nearest_rank(values: Sequence[float], percentile: int) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, (percentile * len(ordered) + 99) // 100 - 1)
    return ordered[index]


def _pilot_report(
    *,
    campaign: CampaignExecution,
    batch: BatchSpec,
    ledger: Mapping[str, Any],
    openclaw_class_count: int,
    population_class_count: int,
) -> dict[str, Any]:
    latencies: list[float] = []
    for subject in batch.ids:
        payload = _regular_json_object(
            campaign.result_dir / f"{subject}.json",
            f"pilot result {subject}",
        )
        receipt = payload.get("campaign_receipt")
        if not isinstance(receipt, dict):
            raise RunnerError(f"pilot result {subject} has no campaign receipt")
        started_ns = _iso_timestamp_ns(receipt.get("started_at"))
        completed_ns = _iso_timestamp_ns(receipt.get("completed_at"))
        if started_ns is None or completed_ns is None or completed_ns < started_ns:
            raise RunnerError(f"pilot result {subject} has an invalid time window")
        latencies.append((completed_ns - started_ns) / 1_000_000_000)

    attempt_receipts = ledger["attempt_receipts"]
    input_tokens = sum(item.get("input_tokens") or 0 for item in attempt_receipts)
    output_tokens = sum(item.get("output_tokens") or 0 for item in attempt_receipts)
    spent = ledger["spent_cost_microusd"]
    reserved = ledger["reserved_cost_microusd"]
    class_count = len(batch.ids)

    def project(value: int, target: int) -> int:
        return (value * target + class_count - 1) // class_count

    return {
        "class_count": class_count,
        "result_latency_seconds_p50": _nearest_rank(latencies, 50),
        "result_latency_seconds_p95": _nearest_rank(latencies, 95),
        "llm_attempt_count": ledger["attempts_reserved"],
        "llm_completed_attempt_count": ledger["attempts_completed"],
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "known_spend_microusd": spent,
        "reserved_cost_microusd": reserved,
        "unknown_or_failed_attempt_count": sum(
            item.get("actual_cost_microusd") is None for item in attempt_receipts
        ),
        "openclaw_population_class_count": openclaw_class_count,
        "all_population_class_count": population_class_count,
        "projected_openclaw_attempt_count": project(
            ledger["attempts_reserved"], openclaw_class_count
        ),
        "projected_openclaw_known_cost_floor_microusd": project(
            spent, openclaw_class_count
        ),
        "projected_openclaw_reservation_ceiling_microusd": project(
            reserved, openclaw_class_count
        ),
        "projected_all_population_known_cost_floor_microusd": project(
            spent, population_class_count
        ),
        "projected_all_population_reservation_ceiling_microusd": project(
            reserved, population_class_count
        ),
        "projection_uncertainty": (
            "known token-priced spend is the floor; permanent worst-case "
            "reservations are the fail-closed ceiling"
        ),
    }


def _openclaw_smoke_budget_contract(
    pilot_report: Mapping[str, Any],
    *,
    max_attempts: int,
    max_cost_microusd: int,
) -> dict[str, Any]:
    """Bind the pilot projection to one operator-recorded smoke budget."""

    projected_attempts = pilot_report.get("projected_openclaw_attempt_count")
    known_floor = pilot_report.get(
        "projected_openclaw_known_cost_floor_microusd"
    )
    reservation_ceiling = pilot_report.get(
        "projected_openclaw_reservation_ceiling_microusd"
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in (projected_attempts, known_floor, reservation_ceiling)
    ) or known_floor > reservation_ceiling:
        raise RunnerError("OpenClaw pilot projection is malformed")
    if (
        isinstance(max_attempts, bool)
        or not isinstance(max_attempts, int)
        or not 1 <= max_attempts <= OPENCLAW_SMOKE_MAX_ATTEMPTS
    ):
        raise RunnerError(
            "OpenClaw smoke attempt budget must be between 1 and "
            f"{OPENCLAW_SMOKE_MAX_ATTEMPTS}"
        )
    if (
        isinstance(max_cost_microusd, bool)
        or not isinstance(max_cost_microusd, int)
        or not 1 <= max_cost_microusd <= OPENCLAW_SMOKE_MAX_COST_MICROUSD
    ):
        raise RunnerError(
            "OpenClaw smoke cost budget must be positive and no greater than USD 25"
        )
    if reservation_ceiling > max_cost_microusd:
        raise RunnerError(
            "projected OpenClaw smoke cost exceeds the operator budget: "
            f"projection={reservation_ceiling}, budget={max_cost_microusd} microusd"
        )
    if projected_attempts > max_attempts:
        raise RunnerError(
            "projected OpenClaw smoke attempt count exceeds the operator budget: "
            f"projection={projected_attempts}, budget={max_attempts}"
        )
    return {
        "schema_version": 1,
        "operator_recorded": True,
        "max_attempts": max_attempts,
        "max_cost_microusd": max_cost_microusd,
        "projected_attempt_count": projected_attempts,
        "projected_known_cost_floor_microusd": known_floor,
        "projected_reservation_ceiling_microusd": reservation_ceiling,
        "projection_fits_operator_budget": True,
    }


def run_openclaw_pilot(
    paths: RunnerPaths,
    pricing: PilotPricing,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run or resume one content-addressed, release-ineligible OpenClaw pilot."""

    litellm_transport_contract()
    pilots_root = paths.state_dir.parent / "pilots-v1"
    if dry_run:
        analysis_checkout = {
            **_openclaw_checkout_base_contract(),
            "remote_tip_fetch_verified": False,
            "remote_tip_fetch_refspec": _OPENCLAW_FETCH_REFSPEC,
            "remote_tip_sha": None,
        }
    else:
        with batch_singleton_lock(
            pilots_root,
            "openclaw-checkout-refresh",
        ):
            analysis_checkout = _prepare_openclaw_checkout()
    plan, selection, selected_records, openclaw_count, population_count = (
        _openclaw_pilot_selection(paths)
    )
    del plan  # the exact subject partition was proved by the selection helper
    try:
        free_bytes = shutil.disk_usage(paths.repo_root).free
    except OSError as exc:
        raise RunnerError(f"cannot check pilot disk space: {exc}") from exc
    if free_bytes < MIN_FREE_BYTES:
        raise RunnerError("OpenClaw pilot does not meet the campaign disk floor")

    source_snapshot = _validated_source_snapshot(capture_source_snapshot(paths))
    contract_digest = contract_sha256(paths)
    base_campaign = campaign_execution(paths, source_snapshot, contract_digest)
    pricing_contract, reservation = _pilot_pricing_contract(pricing)
    pricing_sha256 = hashlib.sha256(_canonical_json_bytes(pricing_contract)).hexdigest()
    pricing_attestation = _pilot_pricing_attestation(pricing)
    pricing_attestation_sha256 = hashlib.sha256(
        _canonical_json_bytes(pricing_attestation)
    ).hexdigest()
    selection_sha256 = hashlib.sha256(_canonical_json_bytes(selection)).hexdigest()
    identity = {
        "schema_version": 1,
        "artifact_kind": "pilot",
        "formal_release_eligible": False,
        "gate_contract_version": OPENCLAW_PILOT_GATE_CONTRACT_VERSION,
        "selection_sha256": selection_sha256,
        "pricing_contract_sha256": pricing_sha256,
        "pricing_attestation_sha256": pricing_attestation_sha256,
        "source_snapshot_sha256": source_snapshot.sha256,
        "contract_sha256": contract_digest,
        "analyzer_contract_sha256": base_campaign.analyzer_contract_sha256,
        "signature_sha256": base_campaign.signature_sha256,
        "alias_class_manifest_sha256": base_campaign.alias_class_manifest_sha256,
        "analysis_checkout": analysis_checkout,
        "model": MODEL,
        "reasoning_effort": REASONING_EFFORT,
        "class_cap": OPENCLAW_PILOT_CLASS_COUNT,
        "wall_time_cap_seconds": OPENCLAW_PILOT_TIMEOUT_SECONDS,
        "llm_attempt_cap": pricing.max_attempts,
        "cost_cap_microusd": pricing.max_cost_microusd,
    }
    pilot_id = hashlib.sha256(_canonical_json_bytes(identity)).hexdigest()
    selection_document = {
        "schema_version": 1,
        "artifact_kind": "pilot",
        "formal_release_eligible": False,
        "pilot_id": pilot_id,
        "selection_sha256": selection_sha256,
        "identity": identity,
        "pricing_attestation": pricing_attestation,
        "selection": selection,
    }
    subjects = tuple(item["analysis_subject"] for item in selection["classes"])
    class_ids = tuple(item["class_id"] for item in selection["classes"])
    batch_bytes = ("\n".join(subjects) + "\n").encode("utf-8")
    if dry_run:
        return {
            "status": "dry_run",
            "artifact_kind": "pilot",
            "formal_release_eligible": False,
            "pilot_id": pilot_id,
            "selection_sha256": selection_sha256,
            "selected_class_count": len(subjects),
            "openclaw_population_class_count": openclaw_count,
            "all_population_class_count": population_count,
            "analysis_checkout": analysis_checkout,
            "pricing_attestation": pricing_attestation,
            "reservation_microusd_per_attempt": reservation,
            "maximum_admissible_attempts_by_cost": (
                pricing.max_cost_microusd // reservation
            ),
        }

    immutable_ledger = {
        "schema_version": 1,
        "artifact_kind": "pilot",
        "pilot_id": pilot_id,
        "selection_sha256": selection_sha256,
        "pricing_contract_sha256": pricing_sha256,
        "pricing_contract": pricing_contract,
        "max_attempts": pricing.max_attempts,
        "max_cost_microusd": pricing.max_cost_microusd,
        "reservation_microusd": reservation,
    }
    with batch_singleton_lock(pilots_root, pilot_id) as pilot_lock_fd:
        _revalidate_openclaw_checkout(analysis_checkout)
        pilot_root = pilots_root / pilot_id
        if pilot_root.exists():
            initial_deadline = None
        else:
            initial_deadline = time.time() + OPENCLAW_PILOT_TIMEOUT_SECONDS
        initial_ledger = {
            **immutable_ledger,
            "deadline_epoch_seconds": initial_deadline,
            "attempts_reserved": 0,
            "attempts_completed": 0,
            "reserved_cost_microusd": 0,
            "spent_cost_microusd": 0,
            "attempt_receipts": [],
            "budget_breached": False,
        }
        pilot_root, ledger = _prepare_pilot_artifacts(
            pilots_root,
            pilot_id=pilot_id,
            selection_document=selection_document,
            batch_bytes=batch_bytes,
            initial_ledger=initial_ledger,
            immutable_ledger=immutable_ledger,
        )
        deadline = float(ledger["deadline_epoch_seconds"])
        pilot_campaign = CampaignExecution(
            campaign_id=pilot_id,
            root=pilot_root / "campaign",
            result_dir=pilot_root / "campaign" / "results",
            api_cache_dir=pilot_root / "campaign" / "api-responses",
            derived_cache_root=pilot_root / "campaign" / "derived-cache",
            source_snapshot_sha256=base_campaign.source_snapshot_sha256,
            contract_sha256=base_campaign.contract_sha256,
            litellm_transport_sha256=base_campaign.litellm_transport_sha256,
            litellm_transport=base_campaign.litellm_transport,
            analyzer_contract_sha256=base_campaign.analyzer_contract_sha256,
            signature_sha256=base_campaign.signature_sha256,
            alias_class_delta_path=base_campaign.alias_class_delta_path,
            alias_class_manifest_sha256=(base_campaign.alias_class_manifest_sha256),
            analysis_checkout=analysis_checkout,
        )
        batch = BatchSpec(
            key=f"pilot-{pilot_id[:16]}",
            path=pilot_root / "batch.txt",
            kind="openclaw_pilot",
            ids=subjects,
            repos=frozenset({_OPENCLAW_REPOSITORY_MARKER}),
            class_ids=class_ids,
        )
        completion_path = pilot_root / "completion.json"
        if completion_path.exists():
            proof = _validated_openclaw_pilot_completion(paths, pilot_id)
            return {
                "status": "already_completed",
                "artifact_kind": "pilot",
                "formal_release_eligible": False,
                "pilot_id": pilot_id,
                "report": proof["report"],
                "attempts_reserved": proof["ledger"]["attempts_reserved"],
            }

        remaining = deadline - time.time()
        if remaining <= 0:
            raise RunnerError("OpenClaw pilot absolute deadline expired")
        _prepare_campaign_execution(pilot_campaign)
        started_at = _utc_now()
        started_at_ns = time.time_ns()
        environment = build_environment(
            campaign=pilot_campaign,
            batch_key=batch.key,
            started_at=started_at,
        )
        environment[PILOT_BUDGET_LEDGER_ENV] = str(
            (pilot_root / "budget-ledger.json").resolve()
        )
        environment[PILOT_ID_ENV] = pilot_id
        log_path = pilot_root / "pilot.log"
        command = build_command(batch, analyzer_dir=paths.analyzer_dir)
        try:
            exit_code = _run_subprocess(
                command,
                cwd=paths.analyzer_dir,
                env=environment,
                log_path=log_path,
                timeout_seconds=min(remaining, OPENCLAW_PILOT_TIMEOUT_SECONDS),
                inherited_fds=(pilot_lock_fd,),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RunnerError(
                f"OpenClaw pilot execution failed; see {log_path}: {exc}"
            ) from exc
        if exit_code != 0:
            raise RunnerError(f"OpenClaw pilot exited with {exit_code}; see {log_path}")
        child_completed_at_ns = time.time_ns()
        if time.time() > deadline:
            raise RunnerError("OpenClaw pilot completed after its absolute deadline")
        if capture_source_snapshot(paths) != source_snapshot:
            raise RunnerError("local source snapshot changed during OpenClaw pilot")
        if contract_sha256(paths) != contract_digest:
            raise RunnerError("analysis contract changed during OpenClaw pilot")
        _revalidate_openclaw_checkout(analysis_checkout)
        _, current_selection, _, _, _ = _openclaw_pilot_selection(paths)
        if hashlib.sha256(_canonical_json_bytes(current_selection)).hexdigest() != (
            selection_sha256
        ):
            raise RunnerError("OpenClaw pilot selection changed during execution")
        result_validation = validate_batch_results(
            batch,
            pilot_campaign.result_dir,
            started_at_ns,
            completed_at_ns=child_completed_at_ns,
            started_at=started_at,
            campaign=pilot_campaign,
            allowed_result_ids=subjects,
            class_records=selected_records,
        )
        ledger = _pilot_budget_snapshot(
            pilot_root / "budget-ledger.json",
            immutable=immutable_ledger,
        )
        report = _pilot_report(
            campaign=pilot_campaign,
            batch=batch,
            ledger=ledger,
            openclaw_class_count=openclaw_count,
            population_class_count=population_count,
        )
        completed_at = _utc_now()
        marker = {
            "schema_version": 1,
            "artifact_kind": "pilot",
            "formal_release_eligible": False,
            "pilot_id": pilot_id,
            "selection_sha256": selection_sha256,
            "pricing_contract_sha256": pricing_sha256,
            "pricing_attestation_sha256": pricing_attestation_sha256,
            "source_snapshot_sha256": source_snapshot.sha256,
            "contract_sha256": contract_digest,
            "alias_class_manifest_sha256": (base_campaign.alias_class_manifest_sha256),
            "analysis_checkout": analysis_checkout,
            "batch_sha256": hashlib.sha256(batch_bytes).hexdigest(),
            "command": command,
            "started_at": started_at,
            "completed_at": completed_at,
            "deadline_epoch_seconds": deadline,
            "result_validation": result_validation,
            "budget_ledger_sha256": file_sha256(pilot_root / "budget-ledger.json"),
            "report": report,
        }
        _atomic_write_json(completion_path, marker)
        return {
            "status": "completed",
            "artifact_kind": "pilot",
            "formal_release_eligible": False,
            "pilot_id": pilot_id,
            "report": report,
        }


def _validate_pilot_pricing_attestation(
    attestation: object,
    *,
    pricing_contract: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "model",
        "currency",
        "source_kind",
        "effective_time",
        "endpoint_sha256",
        "source_response_sha256",
        "matched_entry_count",
        "matched_entries_sha256",
        "provider_input_usd_per_million_tokens",
        "provider_output_usd_per_million_tokens",
        "provider_max_input_tokens",
        "provider_max_output_tokens",
        "configured_prices_at_or_above_provider",
        "configured_token_bounds_within_provider",
    }
    if (
        not isinstance(attestation, dict)
        or set(attestation) != fields
        or attestation.get("schema_version") != 1
        or attestation.get("model") != MODEL
        or attestation.get("currency") != "USD"
        or attestation.get("source_kind") != "live_litellm_model_info"
        or attestation.get("effective_time")
        != "queried_immediately_before_pilot_identity"
        or any(
            not isinstance(attestation.get(field), str)
            or re.fullmatch(r"[0-9a-f]{64}", attestation[field]) is None
            for field in (
                "endpoint_sha256",
                "source_response_sha256",
                "matched_entries_sha256",
            )
        )
        or isinstance(attestation.get("matched_entry_count"), bool)
        or not isinstance(attestation.get("matched_entry_count"), int)
        or attestation["matched_entry_count"] <= 0
        or attestation.get("configured_prices_at_or_above_provider") is not True
        or attestation.get("configured_token_bounds_within_provider") is not True
    ):
        raise RunnerError("pilot pricing attestation is malformed")
    try:
        provider_input = Decimal(
            str(attestation["provider_input_usd_per_million_tokens"])
        )
        provider_output = Decimal(
            str(attestation["provider_output_usd_per_million_tokens"])
        )
        configured_input = Decimal(
            str(pricing_contract["input_usd_per_million_tokens"])
        )
        configured_output = Decimal(
            str(pricing_contract["output_usd_per_million_tokens"])
        )
        provider_max_input = attestation["provider_max_input_tokens"]
        provider_max_output = attestation["provider_max_output_tokens"]
        configured_max_input = pricing_contract["max_input_tokens"]
        configured_max_output = pricing_contract["max_output_tokens"]
    except (KeyError, InvalidOperation, TypeError, ValueError) as exc:
        raise RunnerError("pilot pricing attestation is malformed") from exc
    if (
        any(
            not value.is_finite() or value < 0
            for value in (
                provider_input,
                provider_output,
                configured_input,
                configured_output,
            )
        )
        or configured_input < provider_input
        or configured_output < provider_output
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in (
                provider_max_input,
                provider_max_output,
                configured_max_input,
                configured_max_output,
            )
        )
        or configured_max_input > provider_max_input
        or configured_max_output > provider_max_output
    ):
        raise RunnerError("pilot pricing attestation does not cover its contract")
    return dict(attestation)


def _validated_openclaw_pilot_completion(
    paths: RunnerPaths,
    pilot_id: str,
) -> dict[str, Any]:
    """Replay one pilot completion against every current gate input."""

    if (
        not isinstance(pilot_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", pilot_id) is None
    ):
        raise RunnerError("OpenClaw pilot ID must be a lowercase SHA-256")
    pilot_root = paths.state_dir.parent / "pilots-v1" / pilot_id
    if pilot_root.is_symlink() or not pilot_root.is_dir():
        raise RunnerError(f"current OpenClaw pilot artifact is missing: {pilot_id}")
    selection_document = _regular_json_object(
        pilot_root / "selection.json", "pilot selection"
    )
    selection_fields = {
        "schema_version",
        "artifact_kind",
        "formal_release_eligible",
        "pilot_id",
        "selection_sha256",
        "identity",
        "pricing_attestation",
        "selection",
    }
    if (
        set(selection_document) != selection_fields
        or selection_document.get("schema_version") != 1
        or selection_document.get("artifact_kind") != "pilot"
        or selection_document.get("formal_release_eligible") is not False
        or selection_document.get("pilot_id") != pilot_id
    ):
        raise RunnerError("pilot selection document is malformed")
    identity = selection_document.get("identity")
    identity_fields = {
        "schema_version",
        "artifact_kind",
        "formal_release_eligible",
        "gate_contract_version",
        "selection_sha256",
        "pricing_contract_sha256",
        "pricing_attestation_sha256",
        "source_snapshot_sha256",
        "contract_sha256",
        "analyzer_contract_sha256",
        "signature_sha256",
        "alias_class_manifest_sha256",
        "analysis_checkout",
        "model",
        "reasoning_effort",
        "class_cap",
        "wall_time_cap_seconds",
        "llm_attempt_cap",
        "cost_cap_microusd",
    }
    if (
        not isinstance(identity, dict)
        or set(identity) != identity_fields
        or identity.get("schema_version") != 1
        or identity.get("artifact_kind") != "pilot"
        or identity.get("formal_release_eligible") is not False
        or identity.get("gate_contract_version")
        != OPENCLAW_PILOT_GATE_CONTRACT_VERSION
        or hashlib.sha256(_canonical_json_bytes(identity)).hexdigest() != pilot_id
        or identity.get("model") != MODEL
        or identity.get("reasoning_effort") != REASONING_EFFORT
        or identity.get("class_cap") != OPENCLAW_PILOT_CLASS_COUNT
        or identity.get("wall_time_cap_seconds") != OPENCLAW_PILOT_TIMEOUT_SECONDS
    ):
        raise RunnerError("pilot identity is malformed")

    _, current_selection, selected_records, openclaw_count, population_count = (
        _openclaw_pilot_selection(paths)
    )
    selection_sha256 = hashlib.sha256(
        _canonical_json_bytes(current_selection)
    ).hexdigest()
    if (
        selection_document.get("selection") != current_selection
        or selection_document.get("selection_sha256") != selection_sha256
        or identity.get("selection_sha256") != selection_sha256
    ):
        raise RunnerError("pilot selection is stale relative to the formal manifest")

    source_snapshot = _validated_source_snapshot(capture_source_snapshot(paths))
    contract_digest = contract_sha256(paths)
    base_campaign = campaign_execution(paths, source_snapshot, contract_digest)
    analysis_checkout = _current_prepared_openclaw_checkout()
    current_bindings = {
        "source_snapshot_sha256": source_snapshot.sha256,
        "contract_sha256": contract_digest,
        "analyzer_contract_sha256": base_campaign.analyzer_contract_sha256,
        "signature_sha256": base_campaign.signature_sha256,
        "alias_class_manifest_sha256": base_campaign.alias_class_manifest_sha256,
        "analysis_checkout": analysis_checkout,
    }
    if any(identity.get(field) != value for field, value in current_bindings.items()):
        raise RunnerError("pilot completion is stale relative to current campaign inputs")

    raw_ledger = _regular_json_object(
        pilot_root / "budget-ledger.json", "pilot budget ledger"
    )
    pricing_contract = raw_ledger.get("pricing_contract")
    if not isinstance(pricing_contract, dict):
        raise RunnerError("pilot pricing contract is missing")
    pricing_sha256 = hashlib.sha256(
        _canonical_json_bytes(pricing_contract)
    ).hexdigest()
    immutable_ledger = {
        "schema_version": 1,
        "artifact_kind": "pilot",
        "pilot_id": pilot_id,
        "selection_sha256": selection_sha256,
        "pricing_contract_sha256": pricing_sha256,
        "pricing_contract": pricing_contract,
        "max_attempts": identity.get("llm_attempt_cap"),
        "max_cost_microusd": identity.get("cost_cap_microusd"),
        "reservation_microusd": raw_ledger.get("reservation_microusd"),
    }
    ledger = _pilot_budget_snapshot(
        pilot_root / "budget-ledger.json",
        immutable=immutable_ledger,
    )
    try:
        replay_pricing = PilotPricing(
            input_usd_per_million_tokens=str(
                pricing_contract["input_usd_per_million_tokens"]
            ),
            output_usd_per_million_tokens=str(
                pricing_contract["output_usd_per_million_tokens"]
            ),
            max_input_tokens=pricing_contract["max_input_tokens"],
            max_output_tokens=pricing_contract["max_output_tokens"],
            max_cost_microusd=ledger["max_cost_microusd"],
            max_attempts=ledger["max_attempts"],
        )
    except KeyError as exc:
        raise RunnerError("pilot pricing contract is malformed") from exc
    replayed_contract, reservation = _pilot_pricing_contract(replay_pricing)
    if (
        replayed_contract != pricing_contract
        or reservation != ledger["reservation_microusd"]
        or identity.get("pricing_contract_sha256") != pricing_sha256
    ):
        raise RunnerError("pilot pricing contract binding is invalid")
    pricing_attestation = _validate_pilot_pricing_attestation(
        selection_document.get("pricing_attestation"),
        pricing_contract=pricing_contract,
    )
    pricing_attestation_sha256 = hashlib.sha256(
        _canonical_json_bytes(pricing_attestation)
    ).hexdigest()
    if identity.get("pricing_attestation_sha256") != pricing_attestation_sha256:
        raise RunnerError("pilot pricing attestation digest is invalid")

    completion_path = pilot_root / "completion.json"
    completion = _regular_json_object(completion_path, "pilot completion")
    completion_fields = {
        "schema_version",
        "artifact_kind",
        "formal_release_eligible",
        "pilot_id",
        "selection_sha256",
        "pricing_contract_sha256",
        "pricing_attestation_sha256",
        "source_snapshot_sha256",
        "contract_sha256",
        "alias_class_manifest_sha256",
        "analysis_checkout",
        "batch_sha256",
        "command",
        "started_at",
        "completed_at",
        "deadline_epoch_seconds",
        "result_validation",
        "budget_ledger_sha256",
        "report",
    }
    if (
        set(completion) != completion_fields
        or completion.get("schema_version") != 1
        or completion.get("artifact_kind") != "pilot"
        or completion.get("formal_release_eligible") is not False
        or completion.get("pilot_id") != pilot_id
        or completion.get("selection_sha256") != selection_sha256
        or completion.get("pricing_contract_sha256") != pricing_sha256
        or completion.get("pricing_attestation_sha256")
        != pricing_attestation_sha256
        or any(
            completion.get(field) != current_bindings[field]
            for field in (
                "source_snapshot_sha256",
                "contract_sha256",
                "alias_class_manifest_sha256",
                "analysis_checkout",
            )
        )
        or completion.get("deadline_epoch_seconds")
        != ledger["deadline_epoch_seconds"]
        or completion.get("budget_ledger_sha256")
        != file_sha256(pilot_root / "budget-ledger.json")
    ):
        raise RunnerError("pilot completion marker is invalid")
    subjects = tuple(
        item["analysis_subject"] for item in current_selection["classes"]
    )
    class_ids = tuple(item["class_id"] for item in current_selection["classes"])
    batch_bytes = ("\n".join(subjects) + "\n").encode("utf-8")
    batch = BatchSpec(
        key=f"pilot-{pilot_id[:16]}",
        path=pilot_root / "batch.txt",
        kind="openclaw_pilot",
        ids=subjects,
        repos=frozenset({_OPENCLAW_REPOSITORY_MARKER}),
        class_ids=class_ids,
    )
    pilot_campaign = CampaignExecution(
        campaign_id=pilot_id,
        root=pilot_root / "campaign",
        result_dir=pilot_root / "campaign" / "results",
        api_cache_dir=pilot_root / "campaign" / "api-responses",
        derived_cache_root=pilot_root / "campaign" / "derived-cache",
        source_snapshot_sha256=base_campaign.source_snapshot_sha256,
        contract_sha256=base_campaign.contract_sha256,
        litellm_transport_sha256=base_campaign.litellm_transport_sha256,
        litellm_transport=base_campaign.litellm_transport,
        analyzer_contract_sha256=base_campaign.analyzer_contract_sha256,
        signature_sha256=base_campaign.signature_sha256,
        alias_class_delta_path=base_campaign.alias_class_delta_path,
        alias_class_manifest_sha256=base_campaign.alias_class_manifest_sha256,
        analysis_checkout=analysis_checkout,
    )
    started_at = completion.get("started_at")
    started_ns = _iso_timestamp_ns(started_at)
    completed_ns = _iso_timestamp_ns(completion.get("completed_at"))
    deadline_ns = int(
        float(ledger["deadline_epoch_seconds"]) * 1_000_000_000
    )
    if (
        started_ns is None
        or completed_ns is None
        or completed_ns < started_ns
        or completed_ns > deadline_ns
        or deadline_ns - started_ns
        > OPENCLAW_PILOT_TIMEOUT_SECONDS * 1_000_000_000
        or completion.get("batch_sha256") != hashlib.sha256(batch_bytes).hexdigest()
        or completion.get("command")
        != build_command(batch, analyzer_dir=paths.analyzer_dir)
    ):
        raise RunnerError("pilot completion time or command binding is invalid")
    _validate_budget_attempt_window(
        ledger,
        started_at_ns=started_ns,
        completed_at_ns=completed_ns,
        deadline_ns=deadline_ns,
    )
    validation = validate_batch_results(
        batch,
        pilot_campaign.result_dir,
        started_ns,
        completed_at_ns=completed_ns,
        started_at=str(started_at),
        campaign=pilot_campaign,
        allowed_result_ids=subjects,
        class_records=selected_records,
    )
    report = _pilot_report(
        campaign=pilot_campaign,
        batch=batch,
        ledger=ledger,
        openclaw_class_count=openclaw_count,
        population_class_count=population_count,
    )
    if completion.get("result_validation") != validation or completion.get(
        "report"
    ) != report:
        raise RunnerError("pilot completion report does not replay exactly")
    return {
        "pilot_id": pilot_id,
        "pilot_root": pilot_root,
        "completion": completion,
        "completion_sha256": file_sha256(completion_path),
        "selection": current_selection,
        "selection_sha256": selection_sha256,
        "selected_records": selected_records,
        "source_snapshot": source_snapshot,
        "base_campaign": base_campaign,
        "analysis_checkout": analysis_checkout,
        "pricing_contract": pricing_contract,
        "pricing_contract_sha256": pricing_sha256,
        "pricing_attestation": pricing_attestation,
        "pricing_attestation_sha256": pricing_attestation_sha256,
        "ledger": ledger,
        "report": report,
    }


def _openclaw_smoke_batch(
    *,
    smoke_id: str,
    smoke_root: Path,
    selection: Mapping[str, Any],
) -> BatchSpec:
    classes = selection.get("classes")
    if not isinstance(classes, list) or not classes:
        raise RunnerError("OpenClaw smoke selection has no classes")
    subjects = tuple(item["analysis_subject"] for item in classes)
    class_ids = tuple(item["class_id"] for item in classes)
    if (
        len(subjects) != len(class_ids)
        or not subjects
        or len(subjects) != len(set(subjects))
        or len(class_ids) != len(set(class_ids))
        or selection.get("selected_class_count") != len(subjects)
        or selection.get("selected_classes_exactly_once") is not True
    ):
        raise RunnerError("OpenClaw smoke selection is not exact-once")
    return BatchSpec(
        key=f"openclaw-smoke-{smoke_id[:16]}",
        path=smoke_root / "batch.txt",
        kind="openclaw_full_smoke",
        ids=subjects,
        repos=frozenset({_OPENCLAW_REPOSITORY_MARKER}),
        class_ids=class_ids,
    )


def _terminal_class_record(
    *,
    subject: str,
    class_id: str,
    receipt: Mapping[str, Any] | None,
    problem: str | None,
) -> dict[str, Any]:
    stages = receipt.get("stages") if isinstance(receipt, Mapping) else None
    stage_outcomes = {
        stage: (
            stages[stage].get("outcome")
            if isinstance(stages, Mapping)
            and isinstance(stages.get(stage), Mapping)
            else None
        )
        for stage in ANALYSIS_STAGE_NAMES
    }
    return {
        "class_id": class_id,
        "analysis_subject": subject,
        "terminal": problem is None,
        "stages": stage_outcomes,
        "terminal_stage_output_sha256": (
            receipt.get("terminal_stage_output_sha256")
            if isinstance(receipt, Mapping)
            else None
        ),
        "problem": problem,
    }


def _openclaw_smoke_terminal_status(
    *,
    smoke_id: str,
    batch: BatchSpec,
    campaign: CampaignExecution,
    class_records: Mapping[str, Mapping[str, Any]],
    started_at: str,
    started_at_ns: int,
    completed_at: str,
    completed_at_ns: int,
    subprocess_exit_code: int | None,
    execution_error: BaseException | None,
) -> dict[str, Any]:
    """Record one terminal/incomplete verdict for every expected smoke class."""

    validation: dict[str, Any] | None = None
    validation_problem: str | None = None
    terminal_by_subject: dict[str, dict[str, Any]] = {}
    try:
        validation = validate_batch_results(
            batch,
            campaign.result_dir,
            started_at_ns,
            completed_at_ns=completed_at_ns,
            started_at=started_at,
            campaign=campaign,
            allowed_result_ids=batch.ids,
            class_records=class_records,
        )
    except (OSError, RunnerError) as exc:
        validation_problem = str(exc)[:2000]
    else:
        receipts = {
            receipt["class_id"]: receipt
            for receipt in validation.get("class_receipts", [])
            if isinstance(receipt, dict) and isinstance(receipt.get("class_id"), str)
        }
        for subject, class_id in zip(batch.ids, batch.class_ids, strict=True):
            terminal_by_subject[subject] = _terminal_class_record(
                subject=subject,
                class_id=class_id,
                receipt=receipts.get(class_id),
                problem=None,
            )

    if validation is None:
        for subject, class_id in zip(batch.ids, batch.class_ids, strict=True):
            single_batch = BatchSpec(
                key=batch.key,
                path=batch.path,
                kind=batch.kind,
                ids=(subject,),
                repos=batch.repos,
                class_ids=(class_id,),
            )
            try:
                single_validation = validate_batch_results(
                    single_batch,
                    campaign.result_dir,
                    started_at_ns,
                    completed_at_ns=completed_at_ns,
                    started_at=started_at,
                    campaign=campaign,
                    allowed_result_ids=batch.ids,
                    class_records=class_records,
                )
            except (OSError, RunnerError) as exc:
                terminal_by_subject[subject] = _terminal_class_record(
                    subject=subject,
                    class_id=class_id,
                    receipt=None,
                    problem=str(exc)[:2000],
                )
            else:
                receipt = single_validation["class_receipts"][0]
                terminal_by_subject[subject] = _terminal_class_record(
                    subject=subject,
                    class_id=class_id,
                    receipt=receipt,
                    problem=None,
                )

    classes = sorted(terminal_by_subject.values(), key=lambda item: item["class_id"])
    terminal_count = sum(item["terminal"] is True for item in classes)
    error_text = (
        None
        if execution_error is None
        else f"{type(execution_error).__name__}: {execution_error}"[:2000]
    )
    all_terminal = terminal_count == len(batch.ids) == len(classes)
    complete = (
        all_terminal
        and subprocess_exit_code == 0
        and execution_error is None
        and validation is not None
    )
    return {
        "schema_version": 1,
        "artifact_kind": "openclaw_smoke_status",
        "smoke_id": smoke_id,
        "started_at": started_at,
        "completed_at": completed_at,
        "subprocess_exit_code": subprocess_exit_code,
        "execution_error": error_text,
        "expected_class_count": len(batch.ids),
        "terminal_class_count": terminal_count,
        "incomplete_class_count": len(batch.ids) - terminal_count,
        "all_classes_terminal": all_terminal,
        "smoke_complete": complete,
        "validation_error": validation_problem,
        "result_validation": validation,
        "classes": classes,
    }


def _openclaw_smoke_context(
    paths: RunnerPaths,
    *,
    pilot_id: str,
    max_attempts: int,
    max_cost_microusd: int,
) -> dict[str, Any]:
    pilot = _validated_openclaw_pilot_completion(paths, pilot_id)
    selection, class_records, class_count = _openclaw_smoke_selection(paths)
    budget_contract = _openclaw_smoke_budget_contract(
        pilot["report"],
        max_attempts=max_attempts,
        max_cost_microusd=max_cost_microusd,
    )
    reservation = pilot["ledger"]["reservation_microusd"]
    if max_cost_microusd < reservation:
        raise RunnerError(
            "OpenClaw smoke budget cannot reserve one bounded LLM attempt"
        )
    selection_sha256 = hashlib.sha256(
        _canonical_json_bytes(selection)
    ).hexdigest()
    budget_contract_sha256 = hashlib.sha256(
        _canonical_json_bytes(budget_contract)
    ).hexdigest()
    identity = {
        "schema_version": 1,
        "artifact_kind": "openclaw_smoke",
        "formal_release_eligible": False,
        "pilot_id": pilot_id,
        "pilot_completion_sha256": pilot["completion_sha256"],
        "pilot_report_sha256": hashlib.sha256(
            _canonical_json_bytes(pilot["report"])
        ).hexdigest(),
        "selection_sha256": selection_sha256,
        "budget_contract_sha256": budget_contract_sha256,
        "source_snapshot_sha256": pilot["source_snapshot"].sha256,
        "contract_sha256": pilot["base_campaign"].contract_sha256,
        "analyzer_contract_sha256": pilot[
            "base_campaign"
        ].analyzer_contract_sha256,
        "signature_sha256": pilot["base_campaign"].signature_sha256,
        "alias_class_manifest_sha256": pilot[
            "base_campaign"
        ].alias_class_manifest_sha256,
        "analysis_checkout": pilot["analysis_checkout"],
        "pricing_contract_sha256": pilot["pricing_contract_sha256"],
        "pricing_attestation_sha256": pilot["pricing_attestation_sha256"],
        "model": MODEL,
        "reasoning_effort": REASONING_EFFORT,
        "class_count": class_count,
        "wall_time_cap_seconds": OPENCLAW_SMOKE_TIMEOUT_SECONDS,
        "max_attempts": max_attempts,
        "max_cost_microusd": max_cost_microusd,
    }
    smoke_id = hashlib.sha256(_canonical_json_bytes(identity)).hexdigest()
    smoke_root = paths.state_dir.parent / "openclaw-smokes-v1" / smoke_id
    selection_document = {
        "schema_version": 1,
        "artifact_kind": "openclaw_smoke",
        "formal_release_eligible": False,
        "smoke_id": smoke_id,
        "identity": identity,
        "selection": selection,
        "budget_contract": budget_contract,
    }
    return {
        "smoke_id": smoke_id,
        "smoke_root": smoke_root,
        "pilot": pilot,
        "selection": selection,
        "selection_sha256": selection_sha256,
        "selection_document": selection_document,
        "class_records": class_records,
        "class_count": class_count,
        "budget_contract": budget_contract,
        "budget_contract_sha256": budget_contract_sha256,
        "identity": identity,
        "identity_sha256": smoke_id,
        "reservation_microusd": reservation,
    }


def _validated_openclaw_smoke_completion(
    paths: RunnerPaths,
    smoke_id: str,
) -> dict[str, Any]:
    if (
        not isinstance(smoke_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", smoke_id) is None
    ):
        raise RunnerError("OpenClaw smoke ID must be a lowercase SHA-256")
    smoke_root = paths.state_dir.parent / "openclaw-smokes-v1" / smoke_id
    if smoke_root.is_symlink() or not smoke_root.is_dir():
        raise RunnerError(f"current OpenClaw smoke artifact is missing: {smoke_id}")
    selection_document = _regular_json_object(
        smoke_root / "selection.json", "OpenClaw smoke selection"
    )
    identity = selection_document.get("identity")
    if not isinstance(identity, dict):
        raise RunnerError("OpenClaw smoke identity is missing")
    context = _openclaw_smoke_context(
        paths,
        pilot_id=str(identity.get("pilot_id", "")),
        max_attempts=identity.get("max_attempts"),
        max_cost_microusd=identity.get("max_cost_microusd"),
    )
    if context["smoke_id"] != smoke_id or selection_document != context[
        "selection_document"
    ]:
        raise RunnerError("OpenClaw smoke identity is stale or malformed")

    pilot = context["pilot"]
    raw_ledger = _regular_json_object(
        smoke_root / "budget-ledger.json", "OpenClaw smoke budget ledger"
    )
    immutable_ledger = {
        "schema_version": 1,
        # The analyzer's process-locked admission primitive is deliberately
        # reused here; its on-disk schema names the primitive, while the smoke
        # identity and selection remain separate exact artifacts.
        "artifact_kind": "pilot",
        "pilot_id": smoke_id,
        "selection_sha256": context["selection_sha256"],
        "pricing_contract_sha256": pilot["pricing_contract_sha256"],
        "pricing_contract": pilot["pricing_contract"],
        "max_attempts": context["budget_contract"]["max_attempts"],
        "max_cost_microusd": context["budget_contract"]["max_cost_microusd"],
        "reservation_microusd": context["reservation_microusd"],
    }
    ledger = _pilot_budget_snapshot(
        smoke_root / "budget-ledger.json",
        immutable=immutable_ledger,
    )
    if raw_ledger != ledger:
        raise RunnerError("OpenClaw smoke budget ledger changed while validated")

    batch = _openclaw_smoke_batch(
        smoke_id=smoke_id,
        smoke_root=smoke_root,
        selection=context["selection"],
    )
    base_campaign = pilot["base_campaign"]
    smoke_campaign = CampaignExecution(
        campaign_id=smoke_id,
        root=smoke_root / "campaign",
        result_dir=smoke_root / "campaign" / "results",
        api_cache_dir=smoke_root / "campaign" / "api-responses",
        derived_cache_root=smoke_root / "campaign" / "derived-cache",
        source_snapshot_sha256=base_campaign.source_snapshot_sha256,
        contract_sha256=base_campaign.contract_sha256,
        litellm_transport_sha256=base_campaign.litellm_transport_sha256,
        litellm_transport=base_campaign.litellm_transport,
        analyzer_contract_sha256=base_campaign.analyzer_contract_sha256,
        signature_sha256=base_campaign.signature_sha256,
        alias_class_delta_path=base_campaign.alias_class_delta_path,
        alias_class_manifest_sha256=base_campaign.alias_class_manifest_sha256,
        analysis_checkout=pilot["analysis_checkout"],
    )
    completion_path = smoke_root / "completion.json"
    completion = _regular_json_object(completion_path, "OpenClaw smoke completion")
    completion_fields = {
        "schema_version",
        "artifact_kind",
        "formal_release_eligible",
        "smoke_id",
        "pilot_id",
        "identity_sha256",
        "selection_sha256",
        "budget_contract_sha256",
        "source_snapshot_sha256",
        "contract_sha256",
        "analyzer_contract_sha256",
        "signature_sha256",
        "alias_class_manifest_sha256",
        "analysis_checkout",
        "batch_sha256",
        "command",
        "started_at",
        "completed_at",
        "deadline_epoch_seconds",
        "result_validation",
        "budget_ledger_sha256",
        "terminal_status_sha256",
        "terminal_class_count",
        "all_classes_terminal",
    }
    expected_bindings = {
        "smoke_id": smoke_id,
        "pilot_id": pilot["pilot_id"],
        "identity_sha256": context["identity_sha256"],
        "selection_sha256": context["selection_sha256"],
        "budget_contract_sha256": context["budget_contract_sha256"],
        "source_snapshot_sha256": base_campaign.source_snapshot_sha256,
        "contract_sha256": base_campaign.contract_sha256,
        "analyzer_contract_sha256": base_campaign.analyzer_contract_sha256,
        "signature_sha256": base_campaign.signature_sha256,
        "alias_class_manifest_sha256": base_campaign.alias_class_manifest_sha256,
        "analysis_checkout": pilot["analysis_checkout"],
    }
    batch_bytes = ("\n".join(batch.ids) + "\n").encode("utf-8")
    started_at = completion.get("started_at")
    completed_at = completion.get("completed_at")
    started_at_ns = _iso_timestamp_ns(started_at)
    completed_at_ns = _iso_timestamp_ns(completed_at)
    deadline_ns = int(
        float(ledger["deadline_epoch_seconds"]) * 1_000_000_000
    )
    if (
        set(completion) != completion_fields
        or completion.get("schema_version") != 1
        or completion.get("artifact_kind") != "openclaw_smoke"
        or completion.get("formal_release_eligible") is not False
        or any(completion.get(field) != value for field, value in expected_bindings.items())
        or completion.get("batch_sha256") != hashlib.sha256(batch_bytes).hexdigest()
        or completion.get("command")
        != build_command(batch, analyzer_dir=paths.analyzer_dir)
        or completion.get("deadline_epoch_seconds")
        != ledger["deadline_epoch_seconds"]
        or completion.get("budget_ledger_sha256")
        != file_sha256(smoke_root / "budget-ledger.json")
        or completion.get("terminal_class_count") != context["class_count"]
        or completion.get("all_classes_terminal") is not True
        or started_at_ns is None
        or completed_at_ns is None
        or completed_at_ns < started_at_ns
        or completed_at_ns > deadline_ns
        or deadline_ns - started_at_ns
        > OPENCLAW_SMOKE_TIMEOUT_SECONDS * 1_000_000_000
    ):
        raise RunnerError("OpenClaw smoke completion marker is invalid")
    _validate_budget_attempt_window(
        ledger,
        started_at_ns=started_at_ns,
        completed_at_ns=completed_at_ns,
        deadline_ns=deadline_ns,
    )
    expected_status = _openclaw_smoke_terminal_status(
        smoke_id=smoke_id,
        batch=batch,
        campaign=smoke_campaign,
        class_records=context["class_records"],
        started_at=str(started_at),
        started_at_ns=started_at_ns,
        completed_at=str(completed_at),
        completed_at_ns=completed_at_ns,
        subprocess_exit_code=0,
        execution_error=None,
    )
    status_path = smoke_root / "status.json"
    status = _regular_json_object(status_path, "OpenClaw smoke status")
    if (
        status != expected_status
        or status.get("smoke_complete") is not True
        or completion.get("terminal_status_sha256") != file_sha256(status_path)
        or completion.get("result_validation") != status.get("result_validation")
    ):
        raise RunnerError("OpenClaw smoke terminal status does not replay exactly")
    return {
        "status": "ready",
        "smoke_id": smoke_id,
        "pilot_id": pilot["pilot_id"],
        "class_count": context["class_count"],
        "completion_sha256": file_sha256(completion_path),
        "budget_contract": context["budget_contract"],
        "terminal_status_sha256": file_sha256(status_path),
    }


def _write_current_openclaw_smoke_pointer(
    paths: RunnerPaths,
    proof: Mapping[str, Any],
) -> None:
    root = paths.state_dir.parent / "openclaw-smokes-v1"
    _atomic_write_json(
        root / "current.json",
        {
            "schema_version": 1,
            "smoke_id": proof["smoke_id"],
            "completion_sha256": proof["completion_sha256"],
        },
    )


def run_openclaw_smoke(
    paths: RunnerPaths,
    *,
    pilot_id: str,
    max_attempts: int,
    max_cost_microusd: int,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run or resume the exact full-OpenClaw gate under a projected budget."""

    litellm_transport_contract()
    context = _openclaw_smoke_context(
        paths,
        pilot_id=pilot_id,
        max_attempts=max_attempts,
        max_cost_microusd=max_cost_microusd,
    )
    if dry_run:
        return {
            "status": "dry_run",
            "artifact_kind": "openclaw_smoke",
            "formal_release_eligible": False,
            "gate_status": "pilot_projection_fits_operator_budget",
            "smoke_id": context["smoke_id"],
            "pilot_id": pilot_id,
            "selected_class_count": context["class_count"],
            "budget_contract": context["budget_contract"],
        }

    smokes_root = paths.state_dir.parent / "openclaw-smokes-v1"
    smoke_id = context["smoke_id"]
    with batch_singleton_lock(
        paths.state_dir,
        CAMPAIGN_LOCK_KEY,
    ) as campaign_lock_fd:
        with batch_singleton_lock(smokes_root, smoke_id) as smoke_lock_fd:
            locked_context = _openclaw_smoke_context(
                paths,
                pilot_id=pilot_id,
                max_attempts=max_attempts,
                max_cost_microusd=max_cost_microusd,
            )
            if (
                locked_context["smoke_id"] != smoke_id
                or locked_context["selection_document"]
                != context["selection_document"]
            ):
                raise RunnerError("OpenClaw smoke inputs changed before execution")
            context = locked_context
            pilot = context["pilot"]
            smoke_root = context["smoke_root"]
            if smoke_root.exists():
                initial_deadline = None
            else:
                initial_deadline = time.time() + OPENCLAW_SMOKE_TIMEOUT_SECONDS
            immutable_ledger = {
                "schema_version": 1,
                "artifact_kind": "pilot",
                "pilot_id": smoke_id,
                "selection_sha256": context["selection_sha256"],
                "pricing_contract_sha256": pilot["pricing_contract_sha256"],
                "pricing_contract": pilot["pricing_contract"],
                "max_attempts": max_attempts,
                "max_cost_microusd": max_cost_microusd,
                "reservation_microusd": context["reservation_microusd"],
            }
            initial_ledger = {
                **immutable_ledger,
                "deadline_epoch_seconds": initial_deadline,
                "attempts_reserved": 0,
                "attempts_completed": 0,
                "reserved_cost_microusd": 0,
                "spent_cost_microusd": 0,
                "attempt_receipts": [],
                "budget_breached": False,
            }
            batch = _openclaw_smoke_batch(
                smoke_id=smoke_id,
                smoke_root=smoke_root,
                selection=context["selection"],
            )
            batch_bytes = ("\n".join(batch.ids) + "\n").encode("utf-8")
            smoke_root, ledger = _prepare_pilot_artifacts(
                smokes_root,
                pilot_id=smoke_id,
                selection_document=context["selection_document"],
                batch_bytes=batch_bytes,
                initial_ledger=initial_ledger,
                immutable_ledger=immutable_ledger,
            )
            completion_path = smoke_root / "completion.json"
            if completion_path.exists():
                proof = _validated_openclaw_smoke_completion(paths, smoke_id)
                _write_current_openclaw_smoke_pointer(paths, proof)
                return {
                    **proof,
                    "status": "already_completed",
                    "artifact_kind": "openclaw_smoke",
                    "formal_release_eligible": False,
                }

            deadline = float(ledger["deadline_epoch_seconds"])
            remaining = deadline - time.time()
            if remaining <= 0:
                raise RunnerError("OpenClaw smoke absolute deadline expired")
            base_campaign = pilot["base_campaign"]
            smoke_campaign = CampaignExecution(
                campaign_id=smoke_id,
                root=smoke_root / "campaign",
                result_dir=smoke_root / "campaign" / "results",
                api_cache_dir=smoke_root / "campaign" / "api-responses",
                derived_cache_root=smoke_root / "campaign" / "derived-cache",
                source_snapshot_sha256=base_campaign.source_snapshot_sha256,
                contract_sha256=base_campaign.contract_sha256,
                litellm_transport_sha256=base_campaign.litellm_transport_sha256,
                litellm_transport=base_campaign.litellm_transport,
                analyzer_contract_sha256=base_campaign.analyzer_contract_sha256,
                signature_sha256=base_campaign.signature_sha256,
                alias_class_delta_path=base_campaign.alias_class_delta_path,
                alias_class_manifest_sha256=(
                    base_campaign.alias_class_manifest_sha256
                ),
                analysis_checkout=pilot["analysis_checkout"],
            )
            _prepare_campaign_execution(smoke_campaign)
            started_at = _utc_now()
            started_at_ns = time.time_ns()
            environment = build_environment(
                campaign=smoke_campaign,
                batch_key=batch.key,
                started_at=started_at,
            )
            environment[PILOT_BUDGET_LEDGER_ENV] = str(
                (smoke_root / "budget-ledger.json").resolve()
            )
            environment[PILOT_ID_ENV] = smoke_id
            log_path = smoke_root / "smoke.log"
            command = build_command(batch, analyzer_dir=paths.analyzer_dir)
            exit_code: int | None = None
            execution_error: BaseException | None = None
            try:
                exit_code = _run_subprocess(
                    command,
                    cwd=paths.analyzer_dir,
                    env=environment,
                    log_path=log_path,
                    timeout_seconds=min(remaining, OPENCLAW_SMOKE_TIMEOUT_SECONDS),
                    inherited_fds=(campaign_lock_fd, smoke_lock_fd),
                )
                if isinstance(exit_code, bool) or not isinstance(exit_code, int):
                    raise RunnerError(
                        "OpenClaw smoke command returned an invalid exit code"
                    )
                if exit_code != 0:
                    raise RunnerError(
                        f"OpenClaw smoke exited with {exit_code}; see {log_path}"
                    )
                if time.time() > deadline:
                    raise RunnerError(
                        "OpenClaw smoke completed after its absolute deadline"
                    )
                current_context = _openclaw_smoke_context(
                    paths,
                    pilot_id=pilot_id,
                    max_attempts=max_attempts,
                    max_cost_microusd=max_cost_microusd,
                )
                if current_context["smoke_id"] != smoke_id:
                    raise RunnerError(
                        "OpenClaw smoke inputs changed during execution"
                    )
            except BaseException as exc:  # preserve interrupts after durable status
                execution_error = exc

            completed_at_ns = time.time_ns()
            completed_at = _utc_now()
            terminal_status = _openclaw_smoke_terminal_status(
                smoke_id=smoke_id,
                batch=batch,
                campaign=smoke_campaign,
                class_records=context["class_records"],
                started_at=started_at,
                started_at_ns=started_at_ns,
                completed_at=completed_at,
                completed_at_ns=completed_at_ns,
                subprocess_exit_code=exit_code,
                execution_error=execution_error,
            )
            status_path = smoke_root / "status.json"
            _atomic_write_json(status_path, terminal_status)
            if execution_error is not None:
                if isinstance(execution_error, RunnerError):
                    raise execution_error
                if isinstance(execution_error, Exception):
                    raise RunnerError(
                        "OpenClaw smoke execution failed; inspect "
                        f"{status_path} and {log_path}"
                    ) from execution_error
                raise execution_error
            if terminal_status["smoke_complete"] is not True:
                raise RunnerError(
                    "OpenClaw smoke has incomplete classes; inspect "
                    f"{status_path}"
                )
            ledger = _pilot_budget_snapshot(
                smoke_root / "budget-ledger.json",
                immutable=immutable_ledger,
            )
            completion = {
                "schema_version": 1,
                "artifact_kind": "openclaw_smoke",
                "formal_release_eligible": False,
                "smoke_id": smoke_id,
                "pilot_id": pilot_id,
                "identity_sha256": context["identity_sha256"],
                "selection_sha256": context["selection_sha256"],
                "budget_contract_sha256": context["budget_contract_sha256"],
                "source_snapshot_sha256": base_campaign.source_snapshot_sha256,
                "contract_sha256": base_campaign.contract_sha256,
                "analyzer_contract_sha256": (
                    base_campaign.analyzer_contract_sha256
                ),
                "signature_sha256": base_campaign.signature_sha256,
                "alias_class_manifest_sha256": (
                    base_campaign.alias_class_manifest_sha256
                ),
                "analysis_checkout": pilot["analysis_checkout"],
                "batch_sha256": hashlib.sha256(batch_bytes).hexdigest(),
                "command": command,
                "started_at": started_at,
                "completed_at": completed_at,
                "deadline_epoch_seconds": deadline,
                "result_validation": terminal_status["result_validation"],
                "budget_ledger_sha256": file_sha256(
                    smoke_root / "budget-ledger.json"
                ),
                "terminal_status_sha256": file_sha256(status_path),
                "terminal_class_count": terminal_status["terminal_class_count"],
                "all_classes_terminal": True,
            }
            _atomic_write_json(completion_path, completion)
            proof = _validated_openclaw_smoke_completion(paths, smoke_id)
            _write_current_openclaw_smoke_pointer(paths, proof)
            return {
                **proof,
                "status": "completed",
                "artifact_kind": "openclaw_smoke",
                "formal_release_eligible": False,
            }


def _current_openclaw_smoke_gate_status(paths: RunnerPaths) -> dict[str, Any]:
    pointer_path = paths.state_dir.parent / "openclaw-smokes-v1" / "current.json"
    try:
        pointer = _regular_json_object(pointer_path, "current OpenClaw smoke pointer")
        if (
            set(pointer) != {"schema_version", "smoke_id", "completion_sha256"}
            or pointer.get("schema_version") != 1
            or not isinstance(pointer.get("smoke_id"), str)
            or re.fullmatch(r"[0-9a-f]{64}", pointer["smoke_id"]) is None
            or not isinstance(pointer.get("completion_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", pointer["completion_sha256"])
            is None
        ):
            raise RunnerError("current OpenClaw smoke pointer is malformed")
        proof = _validated_openclaw_smoke_completion(paths, pointer["smoke_id"])
        if proof["completion_sha256"] != pointer["completion_sha256"]:
            raise RunnerError("current OpenClaw smoke completion digest changed")
        return proof
    except (OSError, RunnerError) as exc:
        return {"status": "blocked", "reason": str(exc)[:2000]}


def _current_formal_class_records(
    paths: RunnerPaths,
) -> dict[str, dict[str, Any]] | None:
    delta_path = paths.grouped_dir.parent / "source-delta-current.json"
    try:
        delta = json.loads(delta_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"cannot load formal alias-class bindings: {exc}") from exc
    if not isinstance(delta, dict):
        raise RunnerError("source delta must be an object for class binding")
    if delta.get("population_policy") != source_delta_builder.FORMAL_FULL_POLICY:
        return None
    production = delta.get("production_discovery")
    manifest = (
        production.get("alias_class_manifest") if isinstance(production, dict) else None
    )
    classes = manifest.get("classes") if isinstance(manifest, dict) else None
    if not isinstance(classes, list):
        raise RunnerError("formal source delta has no alias-class records")
    output: dict[str, dict[str, Any]] = {}
    for item in classes:
        if not isinstance(item, dict) or not item.get("scheduled_seed_ids"):
            raise RunnerError("formal source delta contains an unscheduled alias class")
        subject = item.get("analysis_subject")
        if not isinstance(subject, str) or subject in output:
            raise RunnerError("formal source delta has duplicate analysis subjects")
        output[subject] = item
    return output


class RefreshRunner:
    """Execute validated batches with durable completion markers."""

    def __init__(
        self,
        paths: RunnerPaths,
        *,
        command_runner: CommandRunner = _run_subprocess,
        disk_free: DiskFree | None = None,
        cache_resolver: CacheResolver = _default_cache_resolver,
        batch_validator: BatchValidator | None = None,
        source_snapshot_provider: SourceSnapshotProvider = capture_source_snapshot,
        require_formal: bool = True,
    ) -> None:
        self.paths = paths
        self.plan = load_plan(paths)
        self._campaign_result_ids = tuple(
            subject_id for batch in self.plan for subject_id in batch.ids
        )
        self._formal_class_records = _current_formal_class_records(paths)
        if require_formal and self._formal_class_records is None:
            raise RunnerError(
                "formal campaign requires population_policy=formal_full; incremental plans are release-ineligible"
            )
        self._bound_batch_sha256 = {
            batch.key: file_sha256(batch.path) for batch in self.plan
        }
        try:
            self._bound_analyzer_contract_sha256 = (
                analysis_contract.analysis_contract_epoch(paths.repo_root)["sha256"]
            )
        except analysis_contract.AnalysisContractError as exc:
            raise RunnerError(f"cannot bind analyzer contract epoch: {exc}") from exc
        self._bound_contract_sha256 = contract_sha256(paths)
        self._assert_campaign_binding("during runner initialization")
        collision_inventory = load_legacy_collisions(paths.collision_inventory)
        self.collisions = unresolved_legacy_collisions(
            collision_inventory,
            cache_resolver,
        )
        self.command_runner = command_runner
        self.disk_free = disk_free or (lambda path: shutil.disk_usage(path).free)
        self.batch_validator = batch_validator
        self.source_snapshot_provider = source_snapshot_provider
        self._source_fsck_cache = (
            source_delta_builder.SuccessfulGitFsckCache()
            if source_snapshot_provider is capture_source_snapshot
            else None
        )

    def _assert_campaign_binding(
        self,
        phase: str,
        *,
        completion_withheld: bool = False,
        recapture_delta_inputs: bool = False,
    ) -> None:
        """Re-read the full plan and contract and reject all post-init drift."""

        suffix = "; completion withheld" if completion_withheld else ""
        try:
            current_analyzer_contract_sha256 = (
                analysis_contract.analysis_contract_epoch(self.paths.repo_root)[
                    "sha256"
                ]
            )
        except analysis_contract.AnalysisContractError as exc:
            raise RunnerError(
                f"campaign contract changed {phase}: {exc}{suffix}"
            ) from exc
        if current_analyzer_contract_sha256 != self._bound_analyzer_contract_sha256:
            raise RunnerError(f"campaign contract changed {phase}{suffix}")

        try:
            current_plan = load_plan(
                self.paths,
                recapture_delta_inputs=recapture_delta_inputs,
                # Initialization already cached the expensive semantic replay.
                # Subsequent bindings still hash the complete contract and can
                # recapture all mutable inputs without rescanning aliases.
                replay_delta_semantics=False,
            )
        except RunnerError as exc:
            raise RunnerError(f"campaign plan changed {phase}: {exc}{suffix}") from exc
        if current_plan != self.plan:
            raise RunnerError(f"campaign plan changed {phase}{suffix}")

        current_batch_sha256 = {
            batch.key: file_sha256(batch.path) for batch in current_plan
        }
        if current_batch_sha256 != self._bound_batch_sha256:
            raise RunnerError(f"campaign batch hash changed {phase}{suffix}")

        try:
            current_contract_sha256 = contract_sha256(self.paths)
        except RunnerError as exc:
            raise RunnerError(
                f"campaign contract changed {phase}: {exc}{suffix}"
            ) from exc
        if current_contract_sha256 != self._bound_contract_sha256:
            raise RunnerError(f"campaign contract changed {phase}{suffix}")

    def _marker_path(self, batch: BatchSpec) -> Path:
        return self.paths.state_dir / "completed" / f"{batch.key}.json"

    def _capture_source_snapshot(self) -> SourceSnapshot:
        try:
            if self._source_fsck_cache is not None:
                snapshot = capture_source_snapshot(
                    self.paths,
                    fsck_cache=self._source_fsck_cache,
                )
            else:
                snapshot = self.source_snapshot_provider(self.paths)
        except RunnerError:
            raise
        except Exception as exc:  # noqa: BLE001 - injected providers fail closed
            raise RunnerError(f"cannot capture local source snapshot: {exc}") from exc
        return _validated_source_snapshot(snapshot)

    def _marker_matches(self, batch: BatchSpec, command: Sequence[str]) -> bool:
        marker_path = self._marker_path(batch)
        if not marker_path.exists():
            return False
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RunnerError(
                f"cannot read completion marker {marker_path}: {exc}"
            ) from exc
        if not isinstance(marker, dict):
            raise RunnerError(f"completion marker is not an object: {marker_path}")
        schema_version = marker.get("schema_version")
        if isinstance(schema_version, int) and not isinstance(schema_version, bool):
            if 0 < schema_version < MARKER_SCHEMA_VERSION:
                return False
        if schema_version != MARKER_SCHEMA_VERSION:
            raise RunnerError(
                f"completion marker has unsupported schema: {marker_path}"
            )

        current_contract_sha256 = self._bound_contract_sha256
        if marker.get("contract_sha256") != current_contract_sha256:
            return False
        marker_source_details = marker.get("source_snapshot")
        marker_source_sha256 = marker.get("source_snapshot_sha256")
        if not isinstance(marker_source_details, dict) or not isinstance(
            marker_source_sha256,
            str,
        ):
            raise RunnerError(
                f"completion marker has invalid source snapshot: {marker_path}"
            )
        marker_source = _source_snapshot_from_details(marker_source_details)
        if marker_source.sha256 != marker_source_sha256:
            raise RunnerError(
                f"completion marker source snapshot digest is invalid: {marker_path}"
            )
        current_source = self._capture_source_snapshot()
        current_campaign = campaign_execution(
            self.paths,
            current_source,
            current_contract_sha256,
        )
        if marker_source != current_source:
            return False
        marker_started_at = marker.get("started_at")
        marker_started_at_ns = _iso_timestamp_ns(marker_started_at)
        marker_completed_at_ns = _iso_timestamp_ns(marker.get("completed_at"))
        if (
            marker_started_at_ns is None
            or marker_completed_at_ns is None
            or marker_completed_at_ns < marker_started_at_ns
        ):
            raise RunnerError(
                f"completion marker has an invalid time window: {marker_path}"
            )
        if self.batch_validator is None:
            try:
                expected_result_validation = validate_batch_results(
                    batch,
                    current_campaign.result_dir,
                    marker_started_at_ns,
                    completed_at_ns=marker_completed_at_ns,
                    started_at=marker_started_at,
                    campaign=current_campaign,
                    allowed_result_ids=self._campaign_result_ids,
                    class_records=self._formal_class_records,
                )
            except RunnerError:
                return False
        else:
            expected_result_validation = {
                "result_count": len(set(batch.ids)),
                "terminal_count": len(set(batch.ids)),
            }
        expected = {
            "schema_version": MARKER_SCHEMA_VERSION,
            "batch": batch.key,
            "batch_sha256": self._bound_batch_sha256[batch.key],
            "contract_sha256": current_contract_sha256,
            "analyzer_contract_sha256": current_campaign.analyzer_contract_sha256,
            "signature_sha256": current_campaign.signature_sha256,
            "alias_class_manifest_sha256": (
                current_campaign.alias_class_manifest_sha256
            ),
            "source_snapshot_sha256": current_source.sha256,
            "source_snapshot": current_source.details,
            "command": list(command),
            "reasoning_effort": REASONING_EFFORT,
            "campaign_id": current_campaign.campaign_id,
            "campaign_result_dir": str(current_campaign.result_dir),
            "campaign_api_cache_dir": str(current_campaign.api_cache_dir),
            "campaign_derived_cache_root": str(current_campaign.derived_cache_root),
            "litellm_transport_sha256": (current_campaign.litellm_transport_sha256),
            "litellm_transport": current_campaign.litellm_transport,
            "batch_timeout_seconds": BATCH_TIMEOUT_SECONDS,
            "result_validation": expected_result_validation,
        }
        if any(marker.get(key) != value for key, value in expected.items()):
            # A well-formed marker from another transport/campaign is stale,
            # just like a marker from another source or code contract.  It is
            # never accepted; rerunning replaces it with fresh exact evidence.
            return False
        return True

    def _check_disk(self, when: str) -> int:
        try:
            free_bytes = self.disk_free(self.paths.repo_root)
        except OSError as exc:
            raise RunnerError(
                f"cannot check free disk space {when} batch: {exc}"
            ) from exc
        if (
            isinstance(free_bytes, bool)
            or not isinstance(free_bytes, int)
            or free_bytes < 0
        ):
            raise RunnerError(
                f"disk checker returned invalid free-byte count: {free_bytes!r}"
            )
        if free_bytes < MIN_FREE_BYTES:
            free_gib = free_bytes / 1024**3
            raise RunnerError(
                f"disk floor {when} batch: {free_gib:.2f} GiB free; require at least {MIN_FREE_BYTES / 1024**3:.0f} GiB"
            )
        return free_bytes

    def _run_one(
        self,
        batch: BatchSpec,
        command: list[str],
        current_contract_sha256: str,
        campaign_lock_fd: int,
    ) -> None:
        free_before = self._check_disk("before")
        source_snapshot = self._capture_source_snapshot()
        campaign = campaign_execution(
            self.paths,
            source_snapshot,
            current_contract_sha256,
        )
        _prepare_campaign_execution(campaign)
        self.paths.log_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.paths.log_dir / f"{batch.key}.log"
        started_at = _utc_now()
        started_at_ns = time.time_ns()
        with log_path.open("a", encoding="utf-8") as log:
            log.write(
                f"\n=== refresh attempt batch={batch.key} started_at={started_at} "
                f"sha256={self._bound_batch_sha256[batch.key]} ===\n"
            )
            log.flush()

        self._assert_campaign_binding(f"before executing {batch.key}")

        try:
            exit_code = self.command_runner(
                command,
                cwd=self.paths.analyzer_dir,
                env=build_environment(
                    campaign=campaign,
                    batch_key=batch.key,
                    started_at=started_at,
                ),
                log_path=log_path,
                inherited_fds=(campaign_lock_fd,),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RunnerError(
                f"cannot execute {batch.key}; see {log_path}: {exc}"
            ) from exc

        source_snapshot_after = self._capture_source_snapshot()
        if source_snapshot_after != source_snapshot:
            raise RunnerError(
                f"local source snapshot changed while {batch.key} was running; completion withheld"
            )
        free_after = self._check_disk("after")
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            raise RunnerError(
                f"command runner returned invalid exit code for {batch.key}: {exit_code!r}"
            )
        if exit_code != 0:
            raise RunnerError(
                f"{batch.key} failed with exit code {exit_code}; see {log_path}"
            )
        child_completed_at_ns = time.time_ns()
        if self.batch_validator is None:
            result_validation = validate_batch_results(
                batch,
                campaign.result_dir,
                started_at_ns,
                completed_at_ns=child_completed_at_ns,
                started_at=started_at,
                campaign=campaign,
                allowed_result_ids=self._campaign_result_ids,
                class_records=self._formal_class_records,
            )
        else:
            result_validation = self.batch_validator(batch, started_at_ns)
        self._assert_campaign_binding(
            f"while {batch.key} was running",
            completion_withheld=True,
            recapture_delta_inputs=True,
        )

        completed_at = _utc_now()
        marker = {
            "schema_version": MARKER_SCHEMA_VERSION,
            "batch": batch.key,
            "kind": batch.kind,
            "batch_file": str(batch.path.relative_to(self.paths.repo_root.resolve())),
            "batch_sha256": self._bound_batch_sha256[batch.key],
            "contract_sha256": current_contract_sha256,
            "analyzer_contract_sha256": campaign.analyzer_contract_sha256,
            "signature_sha256": campaign.signature_sha256,
            "alias_class_manifest_sha256": campaign.alias_class_manifest_sha256,
            "source_snapshot_sha256": source_snapshot.sha256,
            "source_snapshot": source_snapshot.details,
            "id_line_count": len(batch.ids),
            "unique_id_count": len(set(batch.ids)),
            "command": command,
            "reasoning_effort": REASONING_EFFORT,
            "model": MODEL,
            "workers": WORKERS,
            "campaign_id": campaign.campaign_id,
            "campaign_result_dir": str(campaign.result_dir),
            "campaign_api_cache_dir": str(campaign.api_cache_dir),
            "campaign_derived_cache_root": str(campaign.derived_cache_root),
            "litellm_transport_sha256": campaign.litellm_transport_sha256,
            "litellm_transport": campaign.litellm_transport,
            "batch_timeout_seconds": BATCH_TIMEOUT_SECONDS,
            "free_bytes_before": free_before,
            "free_bytes_after": free_after,
            "log_file": str(log_path.relative_to(self.paths.repo_root.resolve())),
            "started_at": started_at,
            "completed_at": completed_at,
            "exit_code": exit_code,
            "result_validation": result_validation,
        }
        _atomic_write_json(self._marker_path(batch), marker)

    def run(
        self,
        *,
        dry_run: bool = False,
        batch_key: str | None = None,
        limit: int | None = None,
        skip_legacy_origin_collisions: bool = False,
    ) -> list[dict[str, Any]]:
        """Run pending batches in order and return stable status records."""
        # This is a pure configuration check and belongs in dry-run preflight as
        # well as execution.  A plan-only dry run must not report readiness when
        # the one permitted LLM transport is absent or ambiguous.
        litellm_transport_contract()
        smoke_gate = _current_openclaw_smoke_gate_status(self.paths)
        if smoke_gate.get("status") != "ready":
            raise RunnerError(
                "formal OpenClaw smoke gate is blocked: "
                f"{smoke_gate.get('reason', 'current completion is invalid')}"
            )
        if limit is not None and (
            isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0
        ):
            raise RunnerError("limit must be a positive integer")
        known_keys = {batch.key for batch in self.plan}
        if batch_key is not None and batch_key not in known_keys:
            raise RunnerError(
                f"unknown batch {batch_key!r}; expected one of: {', '.join(sorted(known_keys))}"
            )

        selected = [
            batch for batch in self.plan if batch_key is None or batch.key == batch_key
        ]

        def process_selected(
            campaign_lock_fd: int | None = None,
        ) -> list[dict[str, Any]]:
            report: list[dict[str, Any]] = []
            if dry_run:
                report.append(
                    {
                        "batch": "openclaw-smoke-gate",
                        "status": "gate_ready",
                        "smoke_id": smoke_gate["smoke_id"],
                        "class_count": smoke_gate["class_count"],
                    }
                )
            attempted = 0
            for batch in selected:
                self._assert_campaign_binding(
                    f"before processing {batch.key}",
                    recapture_delta_inputs=not dry_run,
                )
                command = build_command(batch, analyzer_dir=self.paths.analyzer_dir)
                if self._marker_matches(batch, command):
                    report.append({"batch": batch.key, "status": "already_completed"})
                    continue
                if limit is not None and attempted >= limit:
                    break

                risky_repos = sorted(batch.repos & self.collisions)
                if risky_repos:
                    if skip_legacy_origin_collisions:
                        report.append(
                            {"batch": batch.key, "status": "collision_skipped"}
                        )
                        continue
                    raise RunnerError(
                        f"{batch.key} intersects legacy-origin-collision repositories: "
                        f"{', '.join(risky_repos)}; rerun with "
                        "--skip-legacy-origin-collisions to omit this batch"
                    )

                if dry_run:
                    report.append({"batch": batch.key, "status": "dry_run"})
                    attempted += 1
                    continue

                with batch_singleton_lock(self.paths.state_dir, batch.key):
                    self._assert_campaign_binding(f"before locking in {batch.key}")
                    if self._marker_matches(batch, command):
                        report.append(
                            {"batch": batch.key, "status": "already_completed"}
                        )
                        continue
                    assert campaign_lock_fd is not None
                    self._run_one(
                        batch,
                        command,
                        self._bound_contract_sha256,
                        campaign_lock_fd,
                    )
                report.append({"batch": batch.key, "status": "completed"})
                attempted += 1
            return report

        # Dry runs stay side-effect free. Every executing invocation holds one
        # campaign-wide lock for its complete selected sequence: different
        # batches still share Git repository caches and must never run in
        # separate runner processes concurrently.
        if dry_run:
            self._assert_campaign_binding(
                "before dry-run validation",
                recapture_delta_inputs=True,
            )
            return process_selected()
        with batch_singleton_lock(
            self.paths.state_dir,
            CAMPAIGN_LOCK_KEY,
        ) as campaign_lock_fd:
            return process_selected(campaign_lock_fd)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the validated, resumable Luna-max incremental CVE refresh campaign."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and print work without executing batches",
    )
    parser.add_argument(
        "--batch",
        dest="batch_key",
        help="run one key, for example legacy-001 or grouped-002",
    )
    parser.add_argument(
        "--limit", type=int, help="maximum number of pending, safe batches to execute"
    )
    parser.add_argument(
        "--skip-legacy-origin-collisions",
        action="store_true",
        help="explicitly omit batches whose repo metadata intersects a legacy cache-origin collision",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=_REPO_ROOT,
        help=f"repository root (default: {_REPO_ROOT})",
    )
    parser.add_argument(
        "--openclaw-pilot",
        action="store_true",
        help="run the release-ineligible 24-class OpenClaw budget pilot",
    )
    parser.add_argument(
        "--openclaw-smoke",
        action="store_true",
        help="run every current OpenClaw alias class after a completed pilot",
    )
    parser.add_argument(
        "--pilot-id",
        help="completed current pilot SHA-256 required for --openclaw-smoke",
    )
    parser.add_argument(
        "--pilot-input-usd-per-million-tokens",
        help="exact input-token price required for --openclaw-pilot",
    )
    parser.add_argument(
        "--pilot-output-usd-per-million-tokens",
        help="exact output-token price required for --openclaw-pilot",
    )
    parser.add_argument(
        "--pilot-max-input-tokens",
        type=int,
        help="worst-case input-token bound for every pilot HTTP attempt",
    )
    parser.add_argument(
        "--pilot-max-output-tokens",
        type=int,
        help="worst-case output-token bound for every pilot HTTP attempt",
    )
    parser.add_argument(
        "--pilot-cost-ceiling-usd",
        help="hard pilot API-cost ceiling, at most 25 USD and precise to micro-USD",
    )
    parser.add_argument(
        "--pilot-max-attempts",
        type=int,
        help=f"hard HTTP-attempt cap (default/max: {OPENCLAW_PILOT_MAX_ATTEMPTS})",
    )
    parser.add_argument(
        "--smoke-cost-ceiling-usd",
        help="operator hard full-OpenClaw cost ceiling, at most 25 USD",
    )
    parser.add_argument(
        "--smoke-max-attempts",
        type=int,
        help=f"operator hard full-OpenClaw attempt cap (max: {OPENCLAW_SMOKE_MAX_ATTEMPTS})",
    )
    return parser


def _cost_ceiling_microusd(raw: str, *, label: str, maximum: int) -> int:
    _canonical, value = _canonical_price(raw, f"{label} cost ceiling")
    scaled = value * Decimal(1_000_000)
    integral = scaled.to_integral_value()
    if scaled != integral:
        raise RunnerError(f"{label} cost ceiling supports at most six decimal places")
    result = int(integral)
    if not 1 <= result <= maximum:
        raise RunnerError(
            f"{label} cost ceiling must be positive and no greater than USD 25"
        )
    return result


def _pilot_cost_ceiling_microusd(raw: str) -> int:
    return _cost_ceiling_microusd(
        raw,
        label="pilot",
        maximum=OPENCLAW_PILOT_MAX_COST_MICROUSD,
    )


def _smoke_cost_ceiling_microusd(raw: str) -> int:
    return _cost_ceiling_microusd(
        raw,
        label="smoke",
        maximum=OPENCLAW_SMOKE_MAX_COST_MICROUSD,
    )


def _pilot_pricing_from_args(args: argparse.Namespace) -> PilotPricing:
    required = {
        "--pilot-input-usd-per-million-tokens": (
            args.pilot_input_usd_per_million_tokens
        ),
        "--pilot-output-usd-per-million-tokens": (
            args.pilot_output_usd_per_million_tokens
        ),
        "--pilot-max-input-tokens": args.pilot_max_input_tokens,
        "--pilot-max-output-tokens": args.pilot_max_output_tokens,
        "--pilot-cost-ceiling-usd": args.pilot_cost_ceiling_usd,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        raise RunnerError(
            "OpenClaw pilot requires explicit pricing bounds: " + ", ".join(missing)
        )
    return PilotPricing(
        input_usd_per_million_tokens=str(args.pilot_input_usd_per_million_tokens),
        output_usd_per_million_tokens=str(args.pilot_output_usd_per_million_tokens),
        max_input_tokens=args.pilot_max_input_tokens,
        max_output_tokens=args.pilot_max_output_tokens,
        max_cost_microusd=_pilot_cost_ceiling_microusd(
            str(args.pilot_cost_ceiling_usd)
        ),
        max_attempts=(
            OPENCLAW_PILOT_MAX_ATTEMPTS
            if args.pilot_max_attempts is None
            else args.pilot_max_attempts
        ),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        with _campaign_signal_handlers():
            paths = RunnerPaths.defaults(args.repo_root)
            if args.openclaw_pilot and args.openclaw_smoke:
                raise RunnerError(
                    "--openclaw-pilot and --openclaw-smoke are mutually exclusive"
                )
            if args.openclaw_pilot:
                if (
                    args.batch_key is not None
                    or args.limit is not None
                    or args.skip_legacy_origin_collisions
                    or args.pilot_id is not None
                    or args.smoke_cost_ceiling_usd is not None
                    or args.smoke_max_attempts is not None
                ):
                    raise RunnerError(
                        "OpenClaw pilot cannot be combined with batch-selection options"
                    )
                results: Any = run_openclaw_pilot(
                    paths,
                    _pilot_pricing_from_args(args),
                    dry_run=args.dry_run,
                )
            elif args.openclaw_smoke:
                if (
                    args.batch_key is not None
                    or args.limit is not None
                    or args.skip_legacy_origin_collisions
                ):
                    raise RunnerError(
                        "OpenClaw smoke cannot be combined with batch-selection options"
                    )
                supplied_pilot_pricing = any(
                    value is not None
                    for value in (
                        args.pilot_input_usd_per_million_tokens,
                        args.pilot_output_usd_per_million_tokens,
                        args.pilot_max_input_tokens,
                        args.pilot_max_output_tokens,
                        args.pilot_cost_ceiling_usd,
                        args.pilot_max_attempts,
                    )
                )
                if supplied_pilot_pricing:
                    raise RunnerError(
                        "OpenClaw smoke replays pricing from --pilot-id; "
                        "pilot pricing options are not accepted"
                    )
                missing_smoke_options = [
                    name
                    for name, value in (
                        ("--pilot-id", args.pilot_id),
                        (
                            "--smoke-cost-ceiling-usd",
                            args.smoke_cost_ceiling_usd,
                        ),
                        ("--smoke-max-attempts", args.smoke_max_attempts),
                    )
                    if value is None
                ]
                if missing_smoke_options:
                    raise RunnerError(
                        "OpenClaw smoke requires explicit pilot and budget inputs: "
                        + ", ".join(missing_smoke_options)
                    )
                results = run_openclaw_smoke(
                    paths,
                    pilot_id=str(args.pilot_id),
                    max_attempts=args.smoke_max_attempts,
                    max_cost_microusd=_smoke_cost_ceiling_microusd(
                        str(args.smoke_cost_ceiling_usd)
                    ),
                    dry_run=args.dry_run,
                )
            else:
                supplied_pilot_options = (
                    any(
                        value is not None
                        for value in (
                            args.pilot_input_usd_per_million_tokens,
                            args.pilot_output_usd_per_million_tokens,
                            args.pilot_max_input_tokens,
                            args.pilot_max_output_tokens,
                            args.pilot_cost_ceiling_usd,
                            args.pilot_max_attempts,
                            args.pilot_id,
                            args.smoke_cost_ceiling_usd,
                            args.smoke_max_attempts,
                        )
                    )
                )
                if supplied_pilot_options:
                    raise RunnerError(
                        "pilot/smoke options require their matching OpenClaw mode"
                    )
                refresh = RefreshRunner(paths)
                results = refresh.run(
                    dry_run=args.dry_run,
                    batch_key=args.batch_key,
                    limit=args.limit,
                    skip_legacy_origin_collisions=(args.skip_legacy_origin_collisions),
                )
    except CampaignSignalInterrupt as exc:
        print(
            f"data refresh interrupted by {exc.signal_name}; child process group terminated",
            file=sys.stderr,
        )
        return 128 + exc.signum
    except RunnerError as exc:
        print(f"data refresh failed closed: {exc}", file=sys.stderr)
        return 2

    print(
        json.dumps(
            {
                "schema_version": 1,
                "dry_run": args.dry_run,
                "results": results,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
