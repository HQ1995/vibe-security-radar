"""Bind formal-release verification to exact trusted Git objects and bytes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Sequence


class VerifierContractError(RuntimeError):
    """Raised when verifier code cannot be tied to one immutable Git state."""


SCHEMA_VERSION = 1
TREE_SCOPES = (
    "scripts",
    "cve-analyzer/src/cve_analyzer",
    "web/scripts",
    "web/src",
)
FILE_SCOPES = (
    "cve-analyzer/pyproject.toml",
    "cve-analyzer/uv.lock",
    "web/package.json",
    "web/package-lock.json",
    "web/next.config.ts",
)
DEPENDENCY_LOCKS = (
    "cve-analyzer/pyproject.toml",
    "cve-analyzer/uv.lock",
    "web/package.json",
    "web/package-lock.json",
)
_OID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_SOURCE_SHADOW_SUFFIXES = frozenset(
    {
        ".cjs",
        ".dll",
        ".dylib",
        ".js",
        ".mjs",
        ".node",
        ".py",
        ".pyc",
        ".pyd",
        ".pyi",
        ".so",
        ".ts",
        ".tsx",
        ".wasm",
    }
)
_MAX_FILE_BYTES = 128 * 1024 * 1024
_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _git(
    repo_root: Path,
    arguments: Sequence[str],
    *,
    description: str,
    accepted_returncodes: frozenset[int] = frozenset({0}),
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VerifierContractError(f"cannot {description}: {exc}") from exc
    if result.returncode not in accepted_returncodes:
        detail = result.stderr.decode("utf-8", errors="replace")[:500].strip()
        raise VerifierContractError(
            f"cannot {description}: git exited {result.returncode}: {detail}"
        )
    return result


def _oid(value: bytes, *, label: str) -> str:
    try:
        decoded = value.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise VerifierContractError(f"{label} is not an ASCII Git object ID") from exc
    if _OID.fullmatch(decoded) is None:
        raise VerifierContractError(f"{label} is not a Git object ID")
    return decoded


def _safe_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", "..", ".git"} for part in path.parts)
    ):
        raise VerifierContractError(f"unsafe verifier path: {value!r}")
    return path


def _regular_bytes(repo_root: Path, relative: str) -> bytes:
    path = repo_root.joinpath(*_safe_relative_path(relative).parts)
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise VerifierContractError(
            f"cannot inspect verifier input {relative}: {exc}"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_FILE_BYTES:
        raise VerifierContractError(
            f"verifier input is not a bounded regular file: {relative}"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            chunks: list[bytes] = []
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    raise VerifierContractError(
                        f"verifier input ended during read: {relative}"
                    )
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise VerifierContractError(
            f"cannot read verifier input {relative}: {exc}"
        ) from exc
    if (
        after.st_dev != metadata.st_dev
        or after.st_ino != metadata.st_ino
        or after.st_size != metadata.st_size
        or after.st_mtime_ns != metadata.st_mtime_ns
    ):
        raise VerifierContractError(f"verifier input changed during read: {relative}")
    return content


def _scoped_git_entries(repo_root: Path, commit: str) -> list[tuple[str, str, str]]:
    scopes = [*TREE_SCOPES, *FILE_SCOPES]
    result = _git(
        repo_root,
        ["ls-tree", "-r", "-z", "--full-tree", commit, "--", *scopes],
        description="enumerate verifier Git inputs",
    )
    entries: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, raw_oid = metadata.split(b" ", 2)
            relative = raw_path.decode("utf-8", errors="strict")
            oid = raw_oid.decode("ascii", errors="strict")
            mode_text = mode.decode("ascii", errors="strict")
            type_text = object_type.decode("ascii", errors="strict")
        except (UnicodeDecodeError, ValueError) as exc:
            raise VerifierContractError("verifier Git tree entry is malformed") from exc
        _safe_relative_path(relative)
        if (
            relative in seen
            or mode_text not in {"100644", "100755"}
            or type_text != "blob"
            or _OID.fullmatch(oid) is None
        ):
            raise VerifierContractError(
                f"verifier Git tree contains an unsafe entry: {relative}"
            )
        seen.add(relative)
        entries.append((relative, mode_text, oid))
    entries.sort()
    for required in FILE_SCOPES:
        if required not in seen:
            raise VerifierContractError(
                f"required verifier dependency file is absent from Git: {required}"
            )
    return entries


def _require_clean_scopes(repo_root: Path, commit: str) -> None:
    scopes = [*TREE_SCOPES, *FILE_SCOPES]
    diff = _git(
        repo_root,
        ["diff", "--quiet", commit, "--", *scopes],
        description="compare verifier inputs with the bound commit",
        accepted_returncodes=frozenset({0, 1}),
    )
    if diff.returncode == 1:
        raise VerifierContractError("verifier inputs differ from the bound Git commit")
    untracked = _git(
        repo_root,
        ["ls-files", "--others", "-z", "--exclude-standard", "--", *TREE_SCOPES],
        description="inspect untracked verifier inputs",
    ).stdout
    if untracked:
        names = sorted(
            value.decode("utf-8", errors="replace")
            for value in untracked.split(b"\0")
            if value
        )
        raise VerifierContractError(
            f"untracked files shadow the verifier scope: {names[:10]}"
        )
    ignored = _git(
        repo_root,
        [
            "ls-files",
            "--others",
            "-z",
            "--ignored",
            "--exclude-standard",
            "--",
            *TREE_SCOPES,
        ],
        description="inspect ignored verifier inputs",
    ).stdout
    ignored_sources = sorted(
        name
        for raw in ignored.split(b"\0")
        if raw
        and (name := raw.decode("utf-8", errors="replace"))
        and PurePosixPath(name).suffix.lower() in _SOURCE_SHADOW_SUFFIXES
    )
    if ignored_sources:
        raise VerifierContractError(
            f"ignored source files shadow the verifier scope: {ignored_sources[:10]}"
        )


def build_verifier_contract(
    repo_root: Path,
    *,
    git_commit: str | None = None,
) -> dict[str, Any]:
    """Build and validate the exact verifier contract for one trusted commit."""

    try:
        root = Path(repo_root).resolve(strict=True)
    except OSError as exc:
        raise VerifierContractError(
            f"trusted verifier repository is unavailable: {exc}"
        ) from exc
    commit_expression = (
        "HEAD^{commit}" if git_commit is None else f"{git_commit}^{{commit}}"
    )
    commit = _oid(
        _git(
            root,
            ["rev-parse", "--verify", commit_expression],
            description="resolve verifier commit",
        ).stdout,
        label="verifier commit",
    )
    head = _oid(
        _git(
            root,
            ["rev-parse", "--verify", "HEAD^{commit}"],
            description="resolve verifier HEAD",
        ).stdout,
        label="verifier HEAD",
    )
    _git(
        root,
        ["merge-base", "--is-ancestor", commit, head],
        description="prove verifier commit ancestry",
    )
    root_tree = _oid(
        _git(
            root,
            ["rev-parse", "--verify", f"{commit}^{{tree}}"],
            description="resolve verifier root tree",
        ).stdout,
        label="verifier root tree",
    )
    _require_clean_scopes(root, commit)

    scoped_trees: list[dict[str, str]] = []
    for relative in TREE_SCOPES:
        tree_oid = _oid(
            _git(
                root,
                ["rev-parse", "--verify", f"{commit}:{relative}"],
                description=f"resolve verifier tree {relative}",
            ).stdout,
            label=f"verifier tree {relative}",
        )
        object_type = _git(
            root,
            ["cat-file", "-t", tree_oid],
            description=f"inspect verifier tree {relative}",
        ).stdout
        if object_type != b"tree\n":
            raise VerifierContractError(f"verifier scope is not a Git tree: {relative}")
        scoped_trees.append({"path": relative, "git_tree_oid": tree_oid})

    files: list[dict[str, Any]] = []
    total_bytes = 0
    contents: dict[str, bytes] = {}
    for relative, mode, blob_oid in _scoped_git_entries(root, commit):
        content = _regular_bytes(root, relative)
        committed = _git(
            root,
            ["cat-file", "blob", blob_oid],
            description=f"read verifier Git blob {relative}",
        ).stdout
        if content != committed:
            raise VerifierContractError(
                f"executed verifier bytes differ from Git blob: {relative}"
            )
        total_bytes += len(content)
        if total_bytes > _MAX_TOTAL_BYTES:
            raise VerifierContractError("verifier input manifest exceeds size bound")
        contents[relative] = content
        files.append(
            {
                "path": relative,
                "mode": mode,
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "git_blob_oid": blob_oid,
            }
        )

    lock_hashes = {
        relative: hashlib.sha256(contents[relative]).hexdigest()
        for relative in DEPENDENCY_LOCKS
    }
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "git_commit": commit,
        "git_tree": root_tree,
        "scoped_trees": scoped_trees,
        "scoped_trees_sha256": _canonical_sha256(scoped_trees),
        "files": files,
        "files_manifest_sha256": _canonical_sha256(files),
        "dependency_locks": lock_hashes,
        "dependency_lock_sha256": _canonical_sha256(lock_hashes),
    }
    payload["contract_sha256"] = _canonical_sha256(payload)
    return payload


def validate_verifier_contract(
    contract: object,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    """Replay one contract against trusted Git objects and actual source bytes."""

    if (
        not isinstance(contract, dict)
        or contract.get("schema_version") != SCHEMA_VERSION
    ):
        raise VerifierContractError("verifier contract schema is invalid")
    commit = contract.get("git_commit")
    if not isinstance(commit, str) or _OID.fullmatch(commit) is None:
        raise VerifierContractError("verifier contract commit is invalid")
    expected = build_verifier_contract(repo_root, git_commit=commit)
    if contract != expected:
        raise VerifierContractError(
            "verifier contract does not match trusted Git objects and execution bytes"
        )
    return expected
