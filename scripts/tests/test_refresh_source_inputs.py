"""Focused, network-free tests for the reproducible source refresh command."""

from __future__ import annotations

import gzip
import base64
import hashlib
import json
import os
import signal
import subprocess
import zipfile
from collections.abc import Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from email.message import Message
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

import build_source_delta
import refresh_source_inputs as refresh
import run_data_refresh as campaign_contract


_TEST_OSV_ECOSYSTEMS = ("GitHub Actions", "PyPI", "[EMPTY]")


def _git(*arguments: str, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"},
    )
    return completed.stdout.strip()


@dataclass
class GitFixture:
    mirror: refresh.GitMirror
    seed: Path
    remote: Path

    def advance(self, marker: str) -> str:
        source = self.seed / "source.json"
        source.write_text(json.dumps({"marker": marker}) + "\n", encoding="utf-8")
        _git("add", "source.json", cwd=self.seed)
        _git(
            "-c",
            "user.name=Source Refresh Test",
            "-c",
            "user.email=source-refresh@example.invalid",
            "commit",
            "-q",
            "-m",
            marker,
            cwd=self.seed,
        )
        _git("push", "-q", "origin", "main", cwd=self.seed)
        return _git("rev-parse", "HEAD", cwd=self.seed)


def _make_git_fixture(tmp_path: Path, name: str) -> GitFixture:
    remote = tmp_path / f"{name}.git"
    seed = tmp_path / f"{name}-seed"
    mirror_path = tmp_path / "cache" / name
    remote.parent.mkdir(parents=True, exist_ok=True)
    _git("init", "-q", "--bare", "--initial-branch=main", str(remote))
    _git("init", "-q", "--initial-branch=main", str(seed))
    (seed / "source.json").write_text('{"marker":"initial"}\n', encoding="utf-8")
    _git("add", "source.json", cwd=seed)
    _git(
        "-c",
        "user.name=Source Refresh Test",
        "-c",
        "user.email=source-refresh@example.invalid",
        "commit",
        "-q",
        "-m",
        "initial",
        cwd=seed,
    )
    _git("remote", "add", "origin", str(remote), cwd=seed)
    _git("push", "-q", "-u", "origin", "main", cwd=seed)
    mirror_path.parent.mkdir(parents=True, exist_ok=True)
    _git("clone", "-q", str(remote), str(mirror_path))
    return GitFixture(
        mirror=refresh.GitMirror(name, mirror_path, str(remote)),
        seed=seed,
        remote=remote,
    )


def _nvd_payload(year: int, version: int = 1) -> tuple[bytes, bytes]:
    raw = json.dumps(
        {"vulnerabilities": [{"cve": {"id": f"CVE-{year}-{version:04d}"}}]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    compressed = gzip.compress(raw, mtime=0)
    metadata = (
        f"lastModifiedDate: 2026-07-18T12:00:0{version}.000\n"
        f"size: {len(raw)}\n"
        f"gzSize: {len(compressed)}\n"
        f"sha256: {hashlib.sha256(raw).hexdigest()}\n"
    ).encode()
    return compressed, metadata


def _osv_payload(filename: str, version: int = 1) -> bytes:
    from io import BytesIO

    output = BytesIO()
    identifier = f"OSV-{filename.removesuffix('.zip').replace(' ', '-')}-{version}"
    info = zipfile.ZipInfo(f"{identifier}.json", date_time=(2026, 7, 18, 12, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(info, json.dumps({"id": identifier}, sort_keys=True))
    return output.getvalue()


@dataclass
class RemoteObject:
    body: bytes
    generation: str
    last_modified: str
    hash_override: str | None = None

    @property
    def etag(self) -> str:
        return f'"{hashlib.md5(self.body, usedforsecurity=False).hexdigest()}"'

    @property
    def gcs_hash(self) -> str:
        if self.hash_override is not None:
            return self.hash_override
        md5 = base64.b64encode(
            hashlib.md5(self.body, usedforsecurity=False).digest()
        ).decode("ascii")
        return f"crc32c=AAAAAA==,md5={md5}"


class FakeHttp:
    def __init__(self) -> None:
        self.nvd = {
            year: {
                "feed": _nvd_payload(year)[0],
                "meta": _nvd_payload(year)[1],
                "etag": f'"nvd-meta-{year}"',
                "last_modified": "Sat, 18 Jul 2026 12:00:00 GMT",
            }
            for year in refresh.NVD_YEARS
        }
        self.osv_manifest = RemoteObject(
            ("\n".join(_TEST_OSV_ECOSYSTEMS) + "\n").encode(),
            "1780000000000000",
            "Sat, 18 Jul 2026 12:00:00 GMT",
        )
        manifest_inventory = build_source_delta.parse_osv_ecosystems_manifest(
            self.osv_manifest.body
        )
        self.osv = {
            filename: RemoteObject(
                _osv_payload(filename),
                str(1_780_000_000_000_000 + index),
                "Sat, 18 Jul 2026 12:00:00 GMT",
            )
            for index, filename in enumerate(manifest_inventory.archive_names)
        }
        self.calls: list[tuple[str, str]] = []
        self.meta_overrides: dict[int, list[bytes]] = {}

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        max_bytes: int,
        allowed_hosts: frozenset[str],
        destination: Path | None = None,
        timeout_seconds: float = refresh.HTTP_TIMEOUT_SECONDS,
    ) -> refresh.HttpResult:
        del timeout_seconds
        self.calls.append((method, url))
        parsed = urlsplit(url)
        assert parsed.scheme == "https"
        assert parsed.hostname in allowed_hosts
        path = unquote(parsed.path)

        if parsed.hostname == "nvd.nist.gov":
            year = int(path.split("-")[-1].split(".")[0])
            if path.endswith(".meta"):
                overrides = self.meta_overrides.get(year)
                body = overrides.pop(0) if overrides else self.nvd[year]["meta"]
                response_headers = {
                    "content-length": str(len(body)),
                    "etag": str(self.nvd[year]["etag"]),
                    "last-modified": str(self.nvd[year]["last_modified"]),
                }
            else:
                body = self.nvd[year]["feed"]
                response_headers = {"content-length": str(len(body))}
        else:
            parts = path.strip("/").split("/")
            assert parts[0] == "osv-vulnerabilities"
            if parts[-1] == build_source_delta.OSV_ECOSYSTEMS_FILENAME:
                remote = self.osv_manifest
            else:
                assert parts[-1] == "all.zip"
                filename = f"{parts[1]}.zip"
                remote = self.osv[filename]
            body = remote.body
            response_headers = {
                "content-length": str(len(body)),
                "etag": remote.etag,
                "x-goog-hash": remote.gcs_hash,
                "last-modified": remote.last_modified,
                "x-goog-generation": remote.generation,
            }
            if method == "GET":
                assert headers.get("If-Match") == remote.etag

        assert len(body) <= max_bytes or method == "HEAD"
        if destination is not None:
            destination.write_bytes(body)
        return refresh.HttpResult(
            status=200,
            final_url=url,
            headers=response_headers,
            size=0 if method == "HEAD" else len(body),
            body=body if destination is None and method == "GET" else None,
        )


@pytest.fixture
def source_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp]:
    git_fixtures = [
        _make_git_fixture(tmp_path, "cvelistV5"),
        _make_git_fixture(tmp_path, "github-advisory-database"),
        _make_git_fixture(tmp_path, "gemnasium-db"),
    ]
    by_name = {fixture.mirror.name: fixture for fixture in git_fixtures}
    monkeypatch.setattr(
        campaign_contract,
        "_CVELIST_ORIGIN",
        by_name["cvelistV5"].mirror.expected_origin,
    )
    monkeypatch.setattr(
        campaign_contract,
        "_GHSA_ORIGIN",
        by_name["github-advisory-database"].mirror.expected_origin,
    )
    monkeypatch.setattr(
        campaign_contract,
        "_GEMNASIUM_ORIGIN",
        by_name["gemnasium-db"].mirror.expected_origin,
    )

    repo_root = tmp_path / "repo"
    state = repo_root / ".ai-slop" / "state" / "data-refresh"
    nvd_dir = tmp_path / "cache" / "nvd-feeds"
    osv_dir = tmp_path / "cache" / "osv-bulk"
    nvd_dir.mkdir(parents=True)
    osv_dir.mkdir(parents=True)
    paths = refresh.RefreshPaths(
        repo_root=repo_root,
        git_mirrors=tuple(fixture.mirror for fixture in git_fixtures),
        nvd_dir=nvd_dir,
        osv_dir=osv_dir,
        osv_ecosystems_file=osv_dir / build_source_delta.OSV_ECOSYSTEMS_FILENAME,
        receipt_path=state / "source-remote-check-now.json",
        runner_state_dir=state / "refresh-runner-v1",
    )
    return paths, git_fixtures, FakeHttp()


def _hash_files(paths: refresh.RefreshPaths) -> dict[str, str]:
    files = [
        *paths.nvd_dir.glob("*"),
        *paths.osv_dir.glob("*"),
        paths.receipt_path,
    ]
    return {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in files
        if path.is_file()
    }


def test_refresh_fast_forwards_all_sources_and_emits_valid_sorted_receipt(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
) -> None:
    paths, git_fixtures, http = source_fixture
    expected_heads = {
        fixture.mirror.name: fixture.advance("remote-update")
        for fixture in git_fixtures
    }

    result = refresh.SourceRefresher(paths, http=http).refresh()

    assert result["remote_parity"] is True
    assert result["git_source_count"] == 3
    assert result["nvd_feed_count"] == 2
    assert result["osv_archive_count"] == len(_TEST_OSV_ECOSYSTEMS)
    for fixture in git_fixtures:
        assert (
            _git("rev-parse", "HEAD", cwd=fixture.mirror.directory)
            == expected_heads[fixture.mirror.name]
        )
        assert not _git(
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            cwd=fixture.mirror.directory,
        )

    receipt = json.loads(paths.receipt_path.read_text(encoding="utf-8"))
    assert set(receipt) == {
        "schema_version",
        "checked_at_utc",
        "git_sources",
        "nvd_feeds",
        "osv_ecosystem_manifest",
        "osv_archive_count",
        "osv_archives",
        "remote_parity",
    }
    assert [item["name"] for item in receipt["git_sources"]] == sorted(expected_heads)
    assert [item["year"] for item in receipt["nvd_feeds"]] == [2025, 2026]
    assert [item["filename"] for item in receipt["osv_archives"]] == sorted(
        build_source_delta.parse_osv_ecosystems_manifest(
            http.osv_manifest.body
        ).archive_names,
        key=lambda name: (name.casefold(), name),
    )
    snapshot = refresh._validate_campaign_contract(
        paths,
        receipt_path=paths.receipt_path,
    )
    assert result["source_snapshot_sha256"] == snapshot.sha256
    http.calls.clear()
    check = refresh.SourceRefresher(paths, http=http).check()
    assert check["remote_parity"] is True
    assert check["receipt_valid"] is True
    assert check["receipt_current"] is True
    assert check["freshness_semantics"] == "sequential-live-check-v1"
    assert check["drift"] == []
    assert not any(
        method == "GET" and (url.endswith(".json.gz") or url.endswith("/all.zip"))
        for method, url in http.calls
    )


def _mark_mirror_incomplete(
    fixture: GitFixture,
    *,
    worktree_rewrite: str | None = None,
) -> None:
    mirror = fixture.mirror
    head = _git("rev-parse", "HEAD", cwd=mirror.directory)
    (mirror.directory / ".git/shallow").write_text(head + "\n", encoding="ascii")
    _git("config", "remote.origin.promisor", "true", cwd=mirror.directory)
    _git(
        "config",
        "remote.origin.partialclonefilter",
        "blob:none",
        cwd=mirror.directory,
    )
    (mirror.directory / ".git/objects/pack/fixture.promisor").write_bytes(b"")
    if worktree_rewrite is not None:
        _git("config", "extensions.worktreeConfig", "true", cwd=mirror.directory)
        _git("config", "core.sparseCheckout", "true", cwd=mirror.directory)
        (mirror.directory / ".git/info/sparse-checkout").write_text(
            "/source.json\n",
            encoding="utf-8",
        )
        (mirror.directory / ".git/config.worktree").write_text(
            f'[url "{worktree_rewrite}"]\n\tinsteadOf = {mirror.expected_origin}\n',
            encoding="utf-8",
        )


def test_refresh_replaces_shallow_promisor_and_worktree_config_mirror(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, git_fixtures, http = source_fixture
    target, attacker = git_fixtures[:2]
    _mark_mirror_incomplete(target, worktree_rewrite=str(attacker.remote))
    original_head = _git("rev-parse", "HEAD", cwd=target.mirror.directory)
    monkeypatch.setattr(refresh, "MIN_GIT_MIGRATION_FREE_BYTES", 0)

    result = refresh.SourceRefresher(paths, http=http).refresh()

    assert result["remote_parity"] is True
    assert _git("rev-parse", "HEAD", cwd=target.mirror.directory) == original_head
    assert not (target.mirror.directory / ".git/shallow").exists()
    assert not (target.mirror.directory / ".git/config.worktree").exists()
    assert refresh._git_materialization_markers(target.mirror) == ()
    assert refresh._git_state(target.mirror).head == original_head
    assert all(
        not path.exists() for path in refresh._git_migration_paths(target.mirror)
    )


def test_refresh_rolls_back_installed_full_clone_on_later_failure(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, git_fixtures, http = source_fixture
    target = git_fixtures[0]
    _mark_mirror_incomplete(target)
    original_head = _git("rev-parse", "HEAD", cwd=target.mirror.directory)
    monkeypatch.setattr(refresh, "MIN_GIT_MIGRATION_FREE_BYTES", 0)

    def fail_contract(*_args: object, **_kwargs: object) -> None:
        raise refresh.SourceRefreshError("forced post-install failure")

    monkeypatch.setattr(refresh, "_validate_campaign_contract", fail_contract)

    with pytest.raises(refresh.SourceRefreshError, match="forced post-install failure"):
        refresh.SourceRefresher(paths, http=http).refresh()

    assert _git("rev-parse", "HEAD", cwd=target.mirror.directory) == original_head
    assert (target.mirror.directory / ".git/shallow").is_file()
    assert refresh._git_materialization_markers(target.mirror)
    assert all(
        not path.exists() for path in refresh._git_migration_paths(target.mirror)
    )


def test_full_clone_binds_fetched_tip_when_remote_advances_during_fsck(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _paths, git_fixtures, _http = source_fixture
    target = git_fixtures[0]
    _mark_mirror_incomplete(target)
    original = refresh._git_state(
        target.mirror,
        allow_incomplete_storage=True,
    )
    fetched_tip = _git("rev-parse", "HEAD", cwd=target.seed)
    monkeypatch.setattr(refresh, "MIN_GIT_MIGRATION_FREE_BYTES", 0)
    original_run_git = refresh._run_git
    later_tip: str | None = None

    def advance_after_full_fsck(
        mirror: refresh.GitMirror,
        arguments: Sequence[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal later_tip
        result = original_run_git(mirror, arguments, **kwargs)
        if arguments and arguments[0] == "fsck" and later_tip is None:
            later_tip = target.advance("advanced-during-full-fsck")
        return result

    monkeypatch.setattr(refresh, "_run_git", advance_after_full_fsck)
    migration: refresh._StagedGitMigration | None = None
    try:
        migration = refresh._stage_full_git_mirror(
            target.mirror,
            original,
            fsck_cache=build_source_delta.SuccessfulGitFsckCache(),
        )

        assert later_tip is not None
        assert later_tip != fetched_tip
        assert migration.remote == refresh.RemoteGitState("main", fetched_tip)
        assert migration.staged_state.head == fetched_tip
    finally:
        if migration is not None:
            refresh._remove_migration_tree(
                migration.staged_path,
                "test full-clone stage",
            )


def test_full_clone_rejects_tracking_tip_changed_after_fsck(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _paths, git_fixtures, _http = source_fixture
    target = git_fixtures[0]
    _mark_mirror_incomplete(target)
    original = refresh._git_state(
        target.mirror,
        allow_incomplete_storage=True,
    )
    target.advance("clone-tip")
    monkeypatch.setattr(refresh, "MIN_GIT_MIGRATION_FREE_BYTES", 0)
    original_run_git = refresh._run_git
    changed = False

    def change_tracking_tip_after_fsck(
        mirror: refresh.GitMirror,
        arguments: Sequence[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal changed
        result = original_run_git(mirror, arguments, **kwargs)
        if arguments and arguments[0] == "fsck" and not changed:
            changed = True
            _git(
                "update-ref",
                "refs/remotes/origin/main",
                original.head,
                cwd=mirror.directory,
            )
        return result

    monkeypatch.setattr(refresh, "_run_git", change_tracking_tip_after_fsck)

    with pytest.raises(
        refresh.SourceRefreshError,
        match="metadata changed|checkout differs from fetched default tip",
    ):
        refresh._stage_full_git_mirror(
            target.mirror,
            original,
            fsck_cache=build_source_delta.SuccessfulGitFsckCache(),
        )

    assert changed is True
    assert all(
        not path.exists() for path in refresh._git_migration_paths(target.mirror)
    )


def test_exact_branch_fetch_accepts_validated_fast_forward_catch_up(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _paths, git_fixtures, _http = source_fixture
    target = git_fixtures[0]
    local = refresh._git_state(target.mirror)
    advertised = refresh.RemoteGitState("main", target.advance("advertised"))
    fetched_tip = target.advance("advanced-before-fetch")
    original_run_git = refresh._run_git
    fetch_arguments: list[str] = []

    def capture_fetch_arguments(
        mirror: refresh.GitMirror,
        arguments: Sequence[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        if "fetch" in arguments:
            fetch_arguments.extend(arguments)
        return original_run_git(mirror, arguments, **kwargs)

    monkeypatch.setattr(refresh, "_run_git", capture_fetch_arguments)

    captured = refresh._fetch_exact_remote_commit(
        target.mirror,
        local,
        advertised,
    )

    assert captured == refresh.RemoteGitState("main", fetched_tip)
    assert _git("rev-parse", "FETCH_HEAD", cwd=target.mirror.directory) == fetched_tip
    assert fetch_arguments[:5] == [
        "-c",
        "fetch.fsckObjects=true",
        "-c",
        "transfer.fsckObjects=true",
        "fetch",
    ]


def test_exact_branch_fetch_rejects_force_push_after_advertisement(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
) -> None:
    _paths, git_fixtures, _http = source_fixture
    target = git_fixtures[0]
    local = refresh._git_state(target.mirror)
    advertised = refresh.RemoteGitState("main", target.advance("advertised"))
    _git("fetch", "-q", "origin", "main", cwd=target.mirror.directory)
    _git("checkout", "-q", "--orphan", "replacement", cwd=target.seed)
    (target.seed / "source.json").write_text(
        '{"marker":"force-pushed"}\n',
        encoding="utf-8",
    )
    _git("add", "source.json", cwd=target.seed)
    _git(
        "-c",
        "user.name=Source Refresh Test",
        "-c",
        "user.email=source-refresh@example.invalid",
        "commit",
        "-q",
        "-m",
        "force-pushed",
        cwd=target.seed,
    )
    _git("push", "-q", "--force", "origin", "HEAD:main", cwd=target.seed)

    with pytest.raises(refresh.SourceRefreshError, match="not a fast-forward"):
        refresh._fetch_exact_remote_commit(
            target.mirror,
            local,
            advertised,
        )


def test_full_clone_timeout_cleans_stage_and_preserves_incomplete_mirror(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, git_fixtures, http = source_fixture
    target = git_fixtures[0]
    _mark_mirror_incomplete(target)
    original_head = _git("rev-parse", "HEAD", cwd=target.mirror.directory)
    monkeypatch.setattr(refresh, "MIN_GIT_MIGRATION_FREE_BYTES", 0)
    bounded = refresh._run_argv_bounded

    def interrupt_clone(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess:
        if "clone" in command:
            raise subprocess.TimeoutExpired(command, 1)
        return bounded(command, **kwargs)

    monkeypatch.setattr(refresh, "_run_argv_bounded", interrupt_clone)

    with pytest.raises(refresh.SourceRefreshError, match="Git command failed"):
        refresh.SourceRefresher(paths, http=http).refresh()

    assert _git("rev-parse", "HEAD", cwd=target.mirror.directory) == original_head
    assert (target.mirror.directory / ".git/shallow").is_file()
    assert all(
        not path.exists() for path in refresh._git_migration_paths(target.mirror)
    )


def test_next_refresh_recovers_crash_after_full_clone_directory_exchange(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _paths, git_fixtures, _http = source_fixture
    target = git_fixtures[0]
    _mark_mirror_incomplete(target)
    original = refresh._git_state(
        target.mirror,
        allow_incomplete_storage=True,
    )
    monkeypatch.setattr(refresh, "MIN_GIT_MIGRATION_FREE_BYTES", 0)
    refresh._stage_full_git_mirror(
        target.mirror,
        original,
        fsck_cache=build_source_delta.SuccessfulGitFsckCache(),
    )
    stage, backup, _garbage = refresh._git_migration_paths(target.mirror)
    os.replace(target.mirror.directory, backup)
    os.replace(stage, target.mirror.directory)

    refresh._recover_git_migration(target.mirror)

    assert (
        refresh._git_state(
            target.mirror,
            allow_incomplete_storage=True,
        )
        == original
    )
    assert (target.mirror.directory / ".git/shallow").is_file()
    assert all(
        not path.exists() for path in refresh._git_migration_paths(target.mirror)
    )


def test_migration_cache_reuses_fsck_across_stage_validation_and_owned_rename(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _paths, git_fixtures, _http = source_fixture
    target = git_fixtures[0]
    _mark_mirror_incomplete(target)
    original_state = refresh._git_state(
        target.mirror,
        allow_incomplete_storage=True,
    )
    monkeypatch.setattr(refresh, "MIN_GIT_MIGRATION_FREE_BYTES", 0)
    cache = build_source_delta.SuccessfulGitFsckCache()
    original_run_git = refresh._run_git
    fsck_calls = 0

    def counted_run_git(
        mirror: refresh.GitMirror,
        arguments: Sequence[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal fsck_calls
        if mirror.name == target.mirror.name and arguments and arguments[0] == "fsck":
            fsck_calls += 1
        return original_run_git(mirror, arguments, **kwargs)

    monkeypatch.setattr(refresh, "_run_git", counted_run_git)
    migration = refresh._stage_full_git_mirror(
        target.mirror,
        original_state,
        fsck_cache=cache,
    )
    transaction = refresh._GitMigrationTransaction(cache)
    transaction.track(migration)

    installed = transaction.install(migration)

    assert installed == migration.staged_state
    assert fsck_calls == 1
    transaction.rollback()


def test_check_is_read_only_and_reports_remote_git_drift(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
) -> None:
    paths, git_fixtures, http = source_fixture
    refresher = refresh.SourceRefresher(paths, http=http)
    refresher.refresh()
    before_files = _hash_files(paths)
    before_heads = {
        fixture.mirror.name: _git("rev-parse", "HEAD", cwd=fixture.mirror.directory)
        for fixture in git_fixtures
    }
    git_fixtures[0].advance("remote-drift")
    http.calls.clear()

    report = refresher.check()

    assert report["remote_parity"] is False
    assert report["source_remote_parity"] is False
    assert report["receipt_valid"] is True
    assert report["receipt_current"] is False
    assert any(item["source"] == "git:cvelistV5" for item in report["drift"])
    assert _hash_files(paths) == before_files
    assert {
        fixture.mirror.name: _git("rev-parse", "HEAD", cwd=fixture.mirror.directory)
        for fixture in git_fixtures
    } == before_heads
    assert not any(
        method == "GET" and (url.endswith(".json.gz") or url.endswith("/all.zip"))
        for method, url in http.calls
    )


def test_check_reports_a_stale_receipt_without_rewriting_it(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
) -> None:
    paths, _git_fixtures, http = source_fixture
    refresher = refresh.SourceRefresher(paths, http=http)
    refresher.refresh()
    receipt = json.loads(paths.receipt_path.read_text(encoding="utf-8"))
    receipt["nvd_feeds"][0]["feed_sha256"] = "0" * 64
    paths.receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    before = paths.receipt_path.read_bytes()

    report = refresher.check()

    assert report["source_remote_parity"] is True
    assert report["receipt_valid"] is False
    assert report["receipt_current"] is False
    assert report["drift"] == [
        {
            "source": "receipt",
            "reason": "remote-cutoff receipt is absent, unsafe, or stale",
        }
    ]
    assert paths.receipt_path.read_bytes() == before


def test_refresh_derives_added_and_removed_archives_from_changed_manifest(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
) -> None:
    paths, _git_fixtures, http = source_fixture
    refresher = refresh.SourceRefresher(paths, http=http)
    refresher.refresh()
    assert (paths.osv_dir / "[EMPTY].zip").is_file()

    ecosystems = ("GitHub Actions", "PyPI", "Wolfi")
    http.osv_manifest.body = ("\n".join(ecosystems) + "\n").encode()
    http.osv_manifest.generation = str(int(http.osv_manifest.generation) + 1)
    http.osv["Wolfi.zip"] = RemoteObject(
        _osv_payload("Wolfi.zip"),
        "1780000000009999",
        "Sat, 18 Jul 2026 13:00:00 GMT",
    )

    result = refresher.refresh()

    assert result["osv_archive_count"] == 3
    assert paths.osv_ecosystems_file.read_bytes() == http.osv_manifest.body
    assert (
        tuple(
            path.name
            for path in sorted(
                paths.osv_dir.glob("*.zip"),
                key=lambda path: (path.name.casefold(), path.name),
            )
        )
        == build_source_delta.parse_osv_ecosystems_manifest(
            http.osv_manifest.body
        ).archive_names
    )
    assert not (paths.osv_dir / "[EMPTY].zip").exists()


def test_manifest_change_between_get_and_second_head_fails_before_install(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, git_fixtures, http = source_fixture
    initial_heads = {
        fixture.mirror.name: _git("rev-parse", "HEAD", cwd=fixture.mirror.directory)
        for fixture in git_fixtures
    }
    original_request = http.request
    changed = False

    def racing_request(*args: object, **kwargs: object) -> refresh.HttpResult:
        nonlocal changed
        result = original_request(*args, **kwargs)
        method = str(args[0])
        url = str(args[1])
        if method == "GET" and url == refresh.OSV_ECOSYSTEMS_URL and not changed:
            changed = True
            http.osv_manifest.generation = str(int(http.osv_manifest.generation) + 1)
        return result

    monkeypatch.setattr(http, "request", racing_request)
    with pytest.raises(refresh.SourceRefreshError, match="manifest changed"):
        refresh.SourceRefresher(paths, http=http).refresh()

    assert not paths.receipt_path.exists()
    assert not list(paths.nvd_dir.iterdir())
    assert not list(paths.osv_dir.iterdir())
    assert {
        fixture.mirror.name: _git("rev-parse", "HEAD", cwd=fixture.mirror.directory)
        for fixture in git_fixtures
    } == initial_heads


def test_metadata_race_aborts_before_any_source_or_git_update(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
) -> None:
    paths, git_fixtures, http = source_fixture
    initial_heads = {
        fixture.mirror.name: _git("rev-parse", "HEAD", cwd=fixture.mirror.directory)
        for fixture in git_fixtures
    }
    for fixture in git_fixtures:
        fixture.advance("remote-update")
    _feed, changed_meta = _nvd_payload(2025, version=2)
    http.meta_overrides[2025] = [http.nvd[2025]["meta"], changed_meta]

    with pytest.raises(refresh.SourceRefreshError, match="changed during verification"):
        refresh.SourceRefresher(paths, http=http).refresh()

    assert not paths.receipt_path.exists()
    assert not list(paths.nvd_dir.iterdir())
    assert not list(paths.osv_dir.iterdir())
    assert {
        fixture.mirror.name: _git("rev-parse", "HEAD", cwd=fixture.mirror.directory)
        for fixture in git_fixtures
    } == initial_heads


def test_refresh_keeps_stable_earlier_source_when_unrelated_remote_advances(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, _git_fixtures, http = source_fixture
    original_2025_feed = bytes(http.nvd[2025]["feed"])
    original_request = http.request
    advanced = False

    def advance_2025_while_capturing_2026(
        *args: object,
        **kwargs: object,
    ) -> refresh.HttpResult:
        nonlocal advanced
        method = str(args[0])
        url = str(args[1])
        if method == "GET" and url.endswith("nvdcve-2.0-2026.meta") and not advanced:
            advanced = True
            feed, meta = _nvd_payload(2025, version=2)
            http.nvd[2025]["feed"] = feed
            http.nvd[2025]["meta"] = meta
            http.nvd[2025]["etag"] = '"nvd-meta-2025-v2"'
            http.nvd[2025]["last_modified"] = "Sat, 18 Jul 2026 13:00:00 GMT"
        return original_request(*args, **kwargs)

    monkeypatch.setattr(http, "request", advance_2025_while_capturing_2026)

    result = refresh.SourceRefresher(paths, http=http).refresh()

    assert advanced is True
    assert result["remote_parity"] is True
    assert result["cutoff_semantics"] == "rolling-source-capture-v1"
    assert (paths.nvd_dir / "nvdcve-2.0-2025.json.gz").read_bytes() == (
        original_2025_feed
    )
    assert http.nvd[2025]["feed"] != original_2025_feed
    report = refresh.SourceRefresher(paths, http=http).check()
    assert report["remote_parity"] is False
    assert report["receipt_valid"] is True
    assert report["receipt_current"] is False
    assert any(item["source"] == "nvd:2025" for item in report["drift"])


def test_contract_failure_rolls_back_files_receipt_and_git(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, git_fixtures, http = source_fixture
    refresher = refresh.SourceRefresher(paths, http=http)
    refresher.refresh()
    before_files = _hash_files(paths)
    before_heads = {
        fixture.mirror.name: _git("rev-parse", "HEAD", cwd=fixture.mirror.directory)
        for fixture in git_fixtures
    }
    for fixture in git_fixtures:
        fixture.advance("second-remote-update")
    for year in refresh.NVD_YEARS:
        feed, meta = _nvd_payload(year, version=2)
        http.nvd[year]["feed"] = feed
        http.nvd[year]["meta"] = meta
    for filename, remote in http.osv.items():
        remote.body = _osv_payload(filename, version=2)
        remote.generation = str(int(remote.generation) + 100)

    def reject_contract(*_args: object, **_kwargs: object) -> None:
        raise refresh.SourceRefreshError("injected contract failure")

    monkeypatch.setattr(refresh, "_validate_campaign_contract", reject_contract)
    with pytest.raises(refresh.SourceRefreshError, match="injected contract failure"):
        refresher.refresh()

    assert _hash_files(paths) == before_files
    assert {
        fixture.mirror.name: _git("rev-parse", "HEAD", cwd=fixture.mirror.directory)
        for fixture in git_fixtures
    } == before_heads


@pytest.mark.parametrize("signum", [signal.SIGHUP, signal.SIGTERM])
def test_signal_after_first_file_install_rolls_back_files_receipt_and_git(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    monkeypatch: pytest.MonkeyPatch,
    signum: int,
) -> None:
    paths, git_fixtures, http = source_fixture
    refresher = refresh.SourceRefresher(paths, http=http)
    refresher.refresh()
    before_files = _hash_files(paths)
    before_heads = {
        fixture.mirror.name: _git("rev-parse", "HEAD", cwd=fixture.mirror.directory)
        for fixture in git_fixtures
    }
    for fixture in git_fixtures:
        fixture.advance(f"signal-{signum}")
    for year in refresh.NVD_YEARS:
        feed, meta = _nvd_payload(year, version=2)
        http.nvd[year]["feed"] = feed
        http.nvd[year]["meta"] = meta

    real_install = refresh._FileTransaction.install
    delivered = False

    def install_then_signal(
        transaction: refresh._FileTransaction,
        staged: Path,
        destination: Path,
    ) -> None:
        nonlocal delivered
        real_install(transaction, staged, destination)
        if not delivered:
            delivered = True
            os.kill(os.getpid(), signum)

    monkeypatch.setattr(refresh._FileTransaction, "install", install_then_signal)
    with campaign_contract._campaign_signal_handlers():
        with pytest.raises(campaign_contract.CampaignSignalInterrupt):
            refresher.refresh()

    assert delivered is True
    assert _hash_files(paths) == before_files
    assert {
        fixture.mirror.name: _git("rev-parse", "HEAD", cwd=fixture.mirror.directory)
        for fixture in git_fixtures
    } == before_heads


def test_signal_during_obsolete_archive_unlink_uses_pre_registered_rollback(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, _git_fixtures, http = source_fixture
    refresher = refresh.SourceRefresher(paths, http=http)
    refresher.refresh()
    before_files = _hash_files(paths)
    obsolete = paths.osv_dir / "[EMPTY].zip"
    assert obsolete.is_file()

    http.osv_manifest.body = b"GitHub Actions\nPyPI\n"
    http.osv_manifest.generation = str(int(http.osv_manifest.generation) + 1)
    real_unlink = Path.unlink
    delivered = False

    def unlink_then_signal(path: Path, *args: object, **kwargs: object) -> None:
        nonlocal delivered
        real_unlink(path, *args, **kwargs)
        if path == obsolete and not delivered:
            delivered = True
            os.kill(os.getpid(), signal.SIGTERM)

    monkeypatch.setattr(Path, "unlink", unlink_then_signal)
    with campaign_contract._campaign_signal_handlers():
        with pytest.raises(campaign_contract.CampaignSignalInterrupt):
            refresher.refresh()

    assert delivered is True
    assert _hash_files(paths) == before_files


def test_read_only_campaign_lock_is_noncreating_and_rejects_active_writer(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "refresh-runner-v1"
    with refresh._read_only_campaign_lock(state_dir):
        pass
    assert not state_dir.exists()

    with campaign_contract.batch_singleton_lock(
        state_dir,
        campaign_contract.CAMPAIGN_LOCK_KEY,
    ):
        with pytest.raises(refresh.SourceRefreshError, match="currently active"):
            with refresh._read_only_campaign_lock(state_dir):
                pass


def test_read_only_campaign_lock_rejects_intermediate_symlink(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    redirected = tmp_path / "redirected"
    redirected.symlink_to(target, target_is_directory=True)

    with pytest.raises(refresh.SourceRefreshError, match="not a safe directory"):
        with refresh._read_only_campaign_lock(redirected / "refresh-runner-v1"):
            pass

    assert not (target / "refresh-runner-v1").exists()


def test_main_converts_campaign_signal_to_shell_exit_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = False

    @contextmanager
    def handlers() -> object:
        nonlocal entered
        entered = True
        yield

    class InterruptedRefresher:
        def __init__(self, _paths: refresh.RefreshPaths) -> None:
            pass

        def refresh(self) -> dict[str, object]:
            raise campaign_contract.CampaignSignalInterrupt(signal.SIGTERM)

        def check(self) -> dict[str, object]:  # pragma: no cover - mode contract
            raise AssertionError

    monkeypatch.setattr(campaign_contract, "_campaign_signal_handlers", handlers)
    monkeypatch.setattr(refresh, "SourceRefresher", InterruptedRefresher)
    monkeypatch.setattr(
        refresh.RefreshPaths,
        "defaults",
        classmethod(lambda cls: object()),
    )

    assert refresh.main([]) == 128 + signal.SIGTERM
    assert entered is True


def test_dirty_git_mirror_fails_before_http_downloads(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
) -> None:
    paths, git_fixtures, http = source_fixture
    (git_fixtures[1].mirror.directory / "untracked.txt").write_text(
        "dirty\n",
        encoding="utf-8",
    )

    with pytest.raises(refresh.SourceRefreshError, match="Git mirror is dirty"):
        refresh.SourceRefresher(paths, http=http).refresh()

    assert http.calls == []
    assert not paths.receipt_path.exists()


def test_git_state_ignores_ambient_repository_redirects(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _paths, git_fixtures, _http = source_fixture
    target = git_fixtures[0]
    redirected = git_fixtures[1]
    _git(
        "remote",
        "set-url",
        "origin",
        target.mirror.expected_origin,
        cwd=redirected.mirror.directory,
    )
    _git(
        "-c",
        "user.name=Source Refresh Test",
        "-c",
        "user.email=source-refresh@example.invalid",
        "commit",
        "--amend",
        "-q",
        "-m",
        "redirected fixture",
        cwd=redirected.mirror.directory,
    )
    target_head = _git("rev-parse", "HEAD", cwd=target.mirror.directory)
    redirected_head = _git("rev-parse", "HEAD", cwd=redirected.mirror.directory)
    assert target_head != redirected_head

    monkeypatch.setenv("GIT_DIR", str(redirected.mirror.directory / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(target.mirror.directory))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.filemode")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "false")

    state = refresh._git_state(target.mirror)

    assert state.head == target_head
    assert state.head != redirected_head


def test_git_commands_disable_fsmonitor_external_helper(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
) -> None:
    _paths, git_fixtures, _http = source_fixture
    mirror = git_fixtures[0].mirror
    sentinel = mirror.directory.parent / "fsmonitor-invoked"
    fsmonitor = mirror.directory.parent / "fsmonitor.sh"
    fsmonitor.write_text(
        f"#!/bin/sh\nprintf invoked > {sentinel}\n",
        encoding="utf-8",
    )
    fsmonitor.chmod(0o755)
    _git("config", "core.fsmonitor", str(fsmonitor), cwd=mirror.directory)

    refresh._run_git(mirror, ["status", "--porcelain=v1"])

    assert not sentinel.exists()
    with pytest.raises(refresh.SourceRefreshError, match="external Git config"):
        refresh._git_state(mirror)


def test_git_capture_uses_shared_real_inventory_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def bounded(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, "complete\n", "")

    monkeypatch.setattr(refresh, "_run_argv_bounded", bounded)
    mirror = refresh.GitMirror(
        "bounded",
        tmp_path,
        "https://example.invalid/advisories.git",
    )

    assert refresh._run_git(mirror, ["status"]).stdout == "complete\n"
    assert captured["max_stdout_bytes"] == build_source_delta.MAX_GIT_STDOUT_BYTES
    assert captured["max_stderr_bytes"] == build_source_delta.MAX_GIT_STDERR_BYTES
    assert int(captured["max_stdout_bytes"]) > 72_107_801


@pytest.mark.parametrize(
    "incomplete_flag",
    [
        "stdout_limit_exceeded",
        "stderr_limit_exceeded",
        "stdout_drain_incomplete",
        "stderr_drain_incomplete",
    ],
)
def test_git_capture_rejects_limits_and_incomplete_drains(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    incomplete_flag: str,
) -> None:
    def bounded(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.CompletedProcess(command, 0, "partial", "")
        setattr(result, incomplete_flag, True)
        return result

    monkeypatch.setattr(refresh, "_run_argv_bounded", bounded)
    mirror = refresh.GitMirror(
        "bounded",
        tmp_path,
        "https://example.invalid/advisories.git",
    )

    with pytest.raises(refresh.SourceRefreshError, match="output was incomplete"):
        refresh._run_git(mirror, ["status"])


def test_refresher_strict_state_never_uses_process_fsck_cache(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _paths, git_fixtures, _http = source_fixture
    mirror = git_fixtures[0].mirror
    original = refresh._run_git
    fsck_calls = 0

    def counted_run_git(
        target: refresh.GitMirror,
        arguments: Sequence[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal fsck_calls
        if arguments and arguments[0] == "fsck":
            fsck_calls += 1
        return original(target, arguments, **kwargs)

    monkeypatch.setattr(refresh, "_run_git", counted_run_git)

    refresh._git_state(mirror)
    refresh._git_state(mirror)
    assert fsck_calls == 2


def test_one_refresh_reuses_successful_fsck_for_unchanged_installed_sources(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, git_fixtures, http = source_fixture
    original = refresh._run_git
    fsck_calls = 0

    def counted_run_git(
        target: refresh.GitMirror,
        arguments: Sequence[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal fsck_calls
        if arguments and arguments[0] == "fsck":
            fsck_calls += 1
        return original(target, arguments, **kwargs)

    monkeypatch.setattr(refresh, "_run_git", counted_run_git)

    refresh.SourceRefresher(paths, http=http).refresh()

    assert fsck_calls == len(git_fixtures)


@pytest.mark.parametrize(
    "index_flag",
    ["--assume-unchanged", "--skip-worktree"],
)
def test_git_state_rejects_index_flags_that_hide_forged_worktree_bytes(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
    index_flag: str,
) -> None:
    _paths, git_fixtures, _http = source_fixture
    mirror = git_fixtures[0].mirror
    _git("update-index", index_flag, "source.json", cwd=mirror.directory)
    (mirror.directory / "source.json").write_text(
        '{"marker":"forged"}\n',
        encoding="utf-8",
    )
    assert (
        _git(
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            cwd=mirror.directory,
        )
        == ""
    )

    with pytest.raises(refresh.SourceRefreshError, match="index flags"):
        refresh._git_state(mirror)


def test_remote_discovery_rejects_worktree_config_url_rewrite(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
) -> None:
    _paths, git_fixtures, _http = source_fixture
    target = git_fixtures[0]
    attacker = git_fixtures[1]
    trusted_origin = "https://example.invalid/advisories.git"
    mirror = refresh.GitMirror(
        target.mirror.name,
        target.mirror.directory,
        trusted_origin,
    )
    _git("remote", "set-url", "origin", trusted_origin, cwd=mirror.directory)
    _git("config", "extensions.worktreeConfig", "true", cwd=mirror.directory)
    (mirror.directory / ".git/config.worktree").write_text(
        f'[url "file://{attacker.remote}"]\n\tinsteadOf = {trusted_origin}\n',
        encoding="utf-8",
    )
    attacker_head = _git("rev-parse", "refs/heads/main", cwd=attacker.remote)
    rewritten_head = _git("ls-remote", trusted_origin, "HEAD", cwd=mirror.directory)
    assert rewritten_head.split()[0] == attacker_head

    with pytest.raises(refresh.SourceRefreshError, match="worktree config"):
        refresh._remote_default(mirror)


def test_git_state_rejects_ignored_untracked_advisory_files(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
) -> None:
    _paths, git_fixtures, _http = source_fixture
    mirror = git_fixtures[0].mirror
    (mirror.directory / ".git/info/exclude").write_text(
        "ignored/\n",
        encoding="utf-8",
    )
    ignored = mirror.directory / "ignored/CVE-2026-9000.json"
    ignored.parent.mkdir()
    ignored.write_text('{"id":"CVE-2026-9000"}\n', encoding="utf-8")
    assert (
        _git(
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            cwd=mirror.directory,
        )
        == ""
    )

    with pytest.raises(refresh.SourceRefreshError, match="worktree differs"):
        refresh._git_state(mirror)


def test_fast_forward_disables_repository_hooks(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
) -> None:
    paths, git_fixtures, http = source_fixture
    fixture = git_fixtures[0]
    fixture.advance("hook-safe-update")
    sentinel = fixture.mirror.directory.parent / "post-merge-invoked"
    hook = fixture.mirror.directory / ".git/hooks/post-merge"
    hook.write_text(
        f"#!/bin/sh\nprintf invoked > {sentinel}\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)

    refresh.SourceRefresher(paths, http=http).refresh()

    assert not sentinel.exists()


def test_remote_commit_with_symlink_is_rejected_before_fast_forward(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
) -> None:
    paths, git_fixtures, http = source_fixture
    fixture = git_fixtures[0]
    link = fixture.seed / "unsafe-link"
    link.symlink_to("source.json")
    _git("add", "unsafe-link", cwd=fixture.seed)
    _git(
        "-c",
        "user.name=Source Refresh Test",
        "-c",
        "user.email=source-refresh@example.invalid",
        "commit",
        "-q",
        "-m",
        "symlink",
        cwd=fixture.seed,
    )
    _git("push", "-q", "origin", "main", cwd=fixture.seed)
    original = _git("rev-parse", "HEAD", cwd=fixture.mirror.directory)

    with pytest.raises(refresh.SourceRefreshError, match="contains a symlink"):
        refresh.SourceRefresher(paths, http=http).refresh()

    assert _git("rev-parse", "HEAD", cwd=fixture.mirror.directory) == original
    assert not paths.receipt_path.exists()


def test_malformed_osv_crc32c_metadata_fails_closed_before_source_install(
    source_fixture: tuple[refresh.RefreshPaths, list[GitFixture], FakeHttp],
) -> None:
    paths, git_fixtures, http = source_fixture
    filename = next(iter(http.osv))
    remote = http.osv[filename]
    valid_md5 = base64.b64encode(
        hashlib.md5(remote.body, usedforsecurity=False).digest()
    ).decode("ascii")
    remote.hash_override = f"crc32c=AA==,md5={valid_md5}"
    initial_heads = {
        fixture.mirror.name: _git("rev-parse", "HEAD", cwd=fixture.mirror.directory)
        for fixture in git_fixtures
    }

    with pytest.raises(refresh.SourceRefreshError, match="crc32c digest size"):
        refresh.SourceRefresher(paths, http=http).refresh()

    assert not paths.receipt_path.exists()
    assert not list(paths.nvd_dir.iterdir())
    assert not list(paths.osv_dir.iterdir())
    assert {
        fixture.mirror.name: _git("rev-parse", "HEAD", cwd=fixture.mirror.directory)
        for fixture in git_fixtures
    } == initial_heads


def test_repeated_gcs_hash_headers_are_preserved() -> None:
    headers = Message()
    headers.add_header("x-goog-hash", "crc32c=4waSgw==")
    headers.add_header("x-goog-hash", "md5=XrY7u+Ae7tCTyyK7j1rNww==")
    assert refresh._normalized_response_headers(headers)["x-goog-hash"] == (
        "crc32c=4waSgw==,md5=XrY7u+Ae7tCTyyK7j1rNww=="
    )


def test_head_content_length_describes_remote_object_without_a_response_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = "https://storage.googleapis.com/osv-vulnerabilities/Azure%20Linux/all.zip"

    class HeadResponse:
        status = 200

        def __init__(self) -> None:
            self.headers = Message()
            self.headers.add_header("Content-Length", "11076886")

        def __enter__(self) -> HeadResponse:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def geturl(self) -> str:
            return url

        def read(self, _size: int) -> bytes:
            raise AssertionError("HEAD must not read a response body")

    monkeypatch.setattr(refresh, "urlopen", lambda *_args, **_kwargs: HeadResponse())
    result = refresh.UrllibTransport().request(
        "HEAD",
        url,
        headers={},
        max_bytes=1,
        allowed_hosts=frozenset({"storage.googleapis.com"}),
    )
    assert result.size == 0
    assert result.body is None
    assert result.headers["content-length"] == "11076886"


def test_nvd_metadata_rejects_oversized_decompressed_json_before_download() -> None:
    _feed, metadata = _nvd_payload(2025)
    lines = metadata.decode("ascii").splitlines()
    oversized = (
        "\n".join(
            (
                f"size: {campaign_contract.MAX_NVD_JSON_BYTES + 1}"
                if line.startswith("size:")
                else line
            )
            for line in lines
        )
        + "\n"
    ).encode("ascii")

    with pytest.raises(refresh.SourceRefreshError, match="decompressed JSON bytes"):
        refresh._parse_nvd_metadata(oversized, 2025)
