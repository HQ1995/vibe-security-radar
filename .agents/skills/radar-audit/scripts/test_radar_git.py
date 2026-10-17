#!/usr/bin/env python3
import base64
import hashlib
import importlib.util
import io
import itertools
import json
import os
from pathlib import Path
import subprocess
import tarfile
import zipfile

import pytest

spec = importlib.util.spec_from_file_location("radar_git", Path(__file__).with_name("radar_git.py"))
rg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rg)

TICK = itertools.count()
GUARD = "export function act(page) {\n  return unguardedEvaluate(page);\n}\n"
BASE_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_AUTHOR_NAME": "Ada Human", "GIT_AUTHOR_EMAIL": "ada@example.org",
            "GIT_COMMITTER_NAME": "Ada Human", "GIT_COMMITTER_EMAIL": "ada@example.org"}


def g(repo, *args, input=None):
    n = next(TICK)
    when = f"2026-01-{1 + n // 24:02d}T{n % 24:02d}:00:00+0000"
    env = {**BASE_ENV, "GIT_AUTHOR_DATE": when, "GIT_COMMITTER_DATE": when}
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                          input=input, env=env).stdout.strip()


def init(tmp_path, name="repo"):
    repo = tmp_path / name
    repo.mkdir()
    g(repo, "init", "-q", "-b", "main")
    return repo


def commit(repo, files=None, message="change"):
    for path, text in (files or {}).items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    g(repo, "add", "-A")
    g(repo, "commit", "-q", "--allow-empty", "-m", message)
    return g(repo, "rev-parse", "HEAD")


def run(tmp_path, *argv):
    name = f"r{next(TICK)}"
    code = rg.main([*argv, "--out", str(tmp_path / "evidence"), "--name", name])
    receipt = json.loads((tmp_path / "evidence" / f"{name}.json").read_text())
    assert receipt["exit"] == code and receipt["schema"] == rg.SCHEMA and receipt["captured_utc"]
    return receipt


def test_commit_reports_identity_trailers_and_marker_leads(tmp_path):
    repo = init(tmp_path)
    sha = commit(repo, {"a.py": "x\n"}, "Add parser\n\nCo-authored-by: Claude <noreply@anthropic.com>")
    receipt = run(tmp_path, "commit", "--repo", str(repo), sha[:10])
    info = receipt["result"]["commits"][0]
    assert info["sha"] == sha and info["author"]["email"] == "ada@example.org"
    assert {"key": "Co-authored-by", "value": "Claude <noreply@anthropic.com>"} in info["trailers"]
    assert any("Claude" in lead["line"] for lead in info["marker_leads"])
    assert receipt["repository"]["is_shallow"] is False
    failed = run(tmp_path, "commit", "--repo", str(repo), "f" * 40)
    assert failed["exit"] == 1 and "not a commit" in failed["error"]


def test_parent_diff_shows_a_path_the_parent_lacks(tmp_path):
    repo = init(tmp_path)
    commit(repo, {"a.py": "x\n"})
    child = commit(repo, {"lib/bridge.js": "return arr[index];\n"})
    receipt = run(tmp_path, "parent-diff", "--repo", str(repo), "--path", "lib/bridge.js", child)
    path = receipt["result"]["comparisons"][0]["paths"][0]
    assert path["in_parent"] is False and path["in_child"] is True and path["changed"] is True
    assert "arr[index]" in (tmp_path / "evidence" / receipt["raw"]["path"]).read_text()


def test_landing_separates_members_merges_squashes_and_branches(tmp_path):
    repo = init(tmp_path)
    base = commit(repo, {"readme": "0\n"})
    g(repo, "switch", "-q", "-c", "feature")
    member = commit(repo, {"f.py": "check = False\n"}, "member")
    g(repo, "switch", "-q", "main")
    direct = commit(repo, {"other": "1\n"}, "direct")
    g(repo, "merge", "-q", "--no-ff", "-m", "merge feature", "feature")
    merge = g(repo, "rev-parse", "HEAD")
    g(repo, "switch", "-q", "-c", "feature2", base)
    squashed = commit(repo, {"g.py": "squash me\n"}, "squashed member")
    g(repo, "switch", "-q", "main")
    g(repo, "merge", "-q", "--squash", "feature2")
    g(repo, "commit", "-q", "-m", "squash feature2")
    squash = g(repo, "rev-parse", "HEAD")
    g(repo, "switch", "-q", "-c", "release", base)
    g(repo, "cherry-pick", member)
    picked = g(repo, "rev-parse", "HEAD")

    via_merge = run(tmp_path, "landing", "--repo", str(repo), "--branch", "main", member)["result"]["branches"][0]
    assert via_merge["on_first_parent"] is False
    assert via_merge["ancestry_landing"]["sha"] == merge and via_merge["ancestry_landing"]["first_parent_contains"] is False
    on_main = run(tmp_path, "landing", "--repo", str(repo), "--branch", "main", direct)["result"]["branches"][0]
    assert on_main["on_first_parent"] is True and on_main["ancestry_landing"] is None
    via_squash = run(tmp_path, "landing", "--repo", str(repo), "--branch", "main", "--path", "g.py",
                     squashed)["result"]["branches"][0]
    assert via_squash["ancestry_landing"] is None and via_squash["content_landing"][0]["landing"]["sha"] == squash
    both = run(tmp_path, "landing", "--repo", str(repo), "--branch", "main", "--branch", "release",
               "--path", "f.py", member)["result"]["branches"]
    assert both[1]["ancestry_landing"] is None and both[1]["content_landing"][0]["landing"]["sha"] == picked


def test_releases_report_boundaries_per_line_by_ancestry_and_content(tmp_path):
    repo = init(tmp_path)
    first = commit(repo, {"f.py": "open\n"})
    g(repo, "tag", "v1.0.0")
    fix = commit(repo, {"f.py": "open\nguard()\n"}, "fix")
    g(repo, "tag", "v1.1.0")
    commit(repo, {"g.py": "later\n"})
    g(repo, "tag", "-a", "v1.2.0-beta.1", "-m", "beta")
    g(repo, "switch", "-q", "-c", "old", first)
    commit(repo, {"h.py": "x\n"})
    g(repo, "tag", "v0.9.0")
    commit(repo, {"f.py": "open\nguard()\n"}, "backport")
    g(repo, "tag", "v0.9.1")
    result = run(tmp_path, "releases", "--repo", str(repo), "--commit", fix, "--path", "f.py",
                 "--pattern", r"guard\(\)", "--line-depth", "1")["result"]
    assert result["by_ancestry"]["1"] == {"tags": 3, "latest": "v1.2.0-beta.1", "first_with": "v1.1.0",
                                          "last_without": "v1.0.0", "unknown": [], "without_after_first": []}
    assert result["by_ancestry"]["0"]["first_with"] is None and result["by_ancestry"]["0"]["latest"] == "v0.9.1"
    assert result["by_content"]["0"] == {"tags": 2, "latest": "v0.9.1", "first_with": "v0.9.1",
                                         "last_without": "v0.9.0", "unknown": [], "without_after_first": []}
    assert {r["tag"]: r["prerelease"] for r in result["tags"]}["v1.2.0-beta.1"] is True
    assert result["pattern_check"]["parent_matches"] is False and "warning" not in result["pattern_check"]
    loose = run(tmp_path, "releases", "--repo", str(repo), "--commit", fix, "--path", "f.py",
                "--pattern", "open")["result"]["pattern_check"]
    assert loose["parent_matches"] is True and "isolate" in loose["warning"]


def test_carriers_keep_every_commit_of_a_shared_tree_moves_and_unreachable_objects(tmp_path):
    repo = init(tmp_path)
    commit(repo, {"readme": "0\n"})
    origin = commit(repo, {"src/guard.ts": GUARD}, "add guard")
    blob = g(repo, "rev-parse", f"{origin}:src/guard.ts")
    tree = g(repo, "rev-parse", f"{origin}^{{tree}}")
    twin = g(repo, "commit-tree", tree, "-p", f"{origin}^", "-m", "same tree, other commit")
    g(repo, "update-ref", "refs/pull/7/head", twin)
    dangling = g(repo, "commit-tree", tree, "-m", "pre-force-push\n\nCo-authored-by: Claude <noreply@anthropic.com>")
    after = commit(repo, {"src/other.ts": "x\n"}, "unrelated")
    (repo / "src" / "nav").mkdir()
    g(repo, "mv", "src/guard.ts", "src/nav/guard.ts")
    moved = commit(repo, message="move")
    edited = commit(repo, {"src/nav/guard.ts": GUARD + "// tidy\n"}, "edit")

    result = run(tmp_path, "carriers", "--repo", str(repo), "--blob", blob)["result"]
    found = {r["commit"] for r in result["carriers"]}
    assert found == {origin, twin, dangling, after, moved}
    assert result["paths"]["discovered"] == ["src/guard.ts", "src/nav/guard.ts"]
    assert set(result["commits_by_root_tree"][tree]) == {origin, twin, dangling}
    lost = next(r for r in result["carriers"] if r["commit"] == dangling)
    assert lost["reachable"] is False and lost["marker_leads"]
    assert result["universe"]["unreachable"] == 1 and result["completeness"]["complete_for_local_objects"] is True

    by_pattern = run(tmp_path, "carriers", "--repo", str(repo), "--blob", blob, "--pattern",
                     r"unguardedEvaluate\(page\)")["result"]
    assert edited in {r["commit"] for r in by_pattern["carriers"] if r["match"] == "pattern"}


def test_carriers_mark_a_shallow_clone_incomplete(tmp_path):
    repo = init(tmp_path)
    origin = commit(repo, {"src/guard.ts": GUARD})
    commit(repo, {"b": "1\n"})
    blob = g(repo, "rev-parse", f"{origin}:src/guard.ts")
    shallow = tmp_path / "shallow"
    g(tmp_path, "clone", "-q", "--depth", "1", f"file://{repo}", str(shallow))
    result = run(tmp_path, "carriers", "--repo", str(shallow), "--blob", blob)["result"]
    assert result["completeness"]["complete_for_local_objects"] is False
    assert any("shallow" in limit for limit in result["completeness"]["limits"])


def test_carriers_work_in_a_blobless_clone_without_fetching(tmp_path):
    repo = init(tmp_path)
    origin = commit(repo, {"src/guard.ts": GUARD, "big.txt": "data\n" * 100})
    later = commit(repo, {"big.txt": "other\n" * 100})
    blob = g(repo, "rev-parse", f"{origin}:src/guard.ts")
    g(repo, "config", "uploadpack.allowfilter", "true")
    partial = tmp_path / "partial.git"
    g(tmp_path, "clone", "-q", "--bare", "--filter=blob:none", f"file://{repo}", str(partial))
    receipt = run(tmp_path, "carriers", "--repo", str(partial), "--blob", blob)
    assert receipt["repository"]["partial_filter"] == "blob:none"
    assert {r["commit"] for r in receipt["result"]["carriers"]} == {origin, later}
    pattern = run(tmp_path, "carriers", "--repo", str(partial), "--path", "src/guard.ts", "--pattern", "unguarded")
    assert pattern["result"]["completeness"]["complete_for_local_objects"] is False
    assert pattern["result"]["unreadable_blobs"] == [blob]


def partial_clone(tmp_path, repo, name="partial.git"):
    g(repo, "config", "uploadpack.allowfilter", "true")
    g(repo, "config", "uploadpack.allowanysha1inwant", "true")
    target = tmp_path / name
    g(tmp_path, "clone", "-q", "--bare", "--filter=blob:none", f"file://{repo}", str(target))
    return target


def test_unreadable_versions_are_unknown_not_absent_and_fetch_is_opt_in(tmp_path, monkeypatch):
    repo = init(tmp_path)
    commit(repo, {"f.py": "open\n"})
    g(repo, "tag", "v1.0.0")
    fix = commit(repo, {"f.py": "open\nguard()\n"}, "fix")
    g(repo, "tag", "v1.1.0")
    commit(repo, {"g.py": "1\n"})
    g(repo, "tag", "v1.2.0")
    partial = partial_clone(tmp_path, repo)
    monkeypatch.setitem(rg.ENV, "GIT_NO_LAZY_FETCH", "1")
    monkeypatch.setattr(rg, "LOCAL", {})
    monkeypatch.setattr(rg, "FETCH_MISSING", False)
    blind = run(tmp_path, "releases", "--repo", str(partial), "--commit", fix, "--path", "f.py",
                "--pattern", r"guard\(\)", "--line-depth", "1")["result"]["by_content"]["1"]
    assert blind["first_with"] is None and blind["last_without"] is None
    assert blind["unknown"] == ["v1.0.0", "v1.1.0", "v1.2.0"]
    diff = run(tmp_path, "parent-diff", "--repo", str(partial), "--path", "f.py", fix)["result"]["comparisons"][0]
    assert diff["diff_unavailable"] is True and diff["paths"][0]["changed"] is True
    fetched = run(tmp_path, "releases", "--repo", str(partial), "--fetch-missing", "--commit", fix, "--path", "f.py",
                  "--pattern", r"guard\(\)", "--line-depth", "1")["result"]["by_content"]["1"]
    assert fetched["first_with"] == "v1.1.0" and fetched["last_without"] == "v1.0.0" and fetched["unknown"] == []
    shared = tmp_path / ".ai-slop" / "state" / "repos" / "product"
    shared.parent.mkdir(parents=True)
    g(tmp_path, "clone", "-q", "--bare", str(repo), str(shared))
    refused = run(tmp_path, "commit", "--repo", str(shared), "--fetch-missing", fix)
    assert refused["exit"] == 1 and "scratch clone" in refused["error"]


def test_github_queries_are_read_only_and_bind_pr_disclosures(tmp_path, monkeypatch):
    calls = []
    sha = "a" * 40

    def fake(argv, lines=False):
        calls.append(argv)
        path = argv[1] if argv[1] != "-X" else argv[3]
        if path.endswith("/pulls") and "/commits/" in path:
            return [{"number": 13719}]
        if path.endswith("/pulls/13719"):
            return {"title": "Fix gateway path", "state": "closed", "merged_at": "2026-02-12T00:00:00Z",
                    "merge_commit_sha": "b" * 40, "base": {"ref": "main"}, "head": {"ref": "codex/an-07"},
                    "user": {"login": "maintainer"}, "body": "AI-assisted: yes\nModel: GPT-5.3-Codex"}
        if path.endswith("/pulls/13719/commits"):
            return [{"sha": sha, "login": "maintainer", "author": {"name": "M"},
                     "message": "Guard raw path\n\nGenerated by staged fix workflow."}]
        if path.endswith("security-advisories"):
            return [{"ghsa_id": "GHSA-w8jc-g24h-crhw", "cve_id": None, "summary": "ls_remote residual",
                     "published_at": "2026-09-30T00:00:00Z", "withdrawn_at": None}]
        if path == "advisories":
            return []
        raise AssertionError(argv)

    monkeypatch.setattr(rg, "run_gh", fake)
    pr = run(tmp_path, "github", "pr", "--slug", "openclaw/openclaw", "--commit", sha)
    pull = pr["result"]["pulls"][0]
    assert pull["members"][0]["sha"] == sha and pull["merge_commit_sha"] == "b" * 40
    assert any("GPT-5.3-Codex" in lead["line"] for lead in pull["body_leads"])
    assert json.loads((tmp_path / "evidence" / pr["raw"]["path"]).read_text())["pulls/13719"]["head"]["ref"] == "codex/an-07"
    advisories = run(tmp_path, "github", "advisories", "--slug", "gitpython-developers/GitPython",
                     "--package", "pip:GitPython")
    assert advisories["result"]["repository_advisories"][0]["ghsa_id"] == "GHSA-w8jc-g24h-crhw"
    assert all(a[0] == "api" and "POST" not in a and "PATCH" not in a for a in calls)


def tarball(members, mode="w:gz"):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_artifact_verifies_digests_and_finds_members(tmp_path, monkeypatch):
    sdist = tarball({"pkg-1.0/server/key-server/app/config.py": b'cors_origins = ["*"]\n',
                     "pkg-1.0/README": b"hi\n"})
    wheel = io.BytesIO()
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("pkg/__init__.py", "")
    gem = tarball({"data.tar.gz": tarball({"lib/bsv/wallet_interface/wallet_client.rb":
                                           b"def acquire_certificate\n  store\nend\n"}),
                   "metadata.gz": b""}, mode="w")
    npm = tarball({"package/index.js": b"module.exports = 1\n"})
    urls = {
        "https://pypi.org/pypi/pkg/1.0/json": json.dumps({"urls": [
            {"filename": "pkg-1.0.tar.gz", "url": "https://files/pkg-1.0.tar.gz", "packagetype": "sdist",
             "digests": {"sha256": hashlib.sha256(sdist).hexdigest()}},
            {"filename": "pkg-1.0-py3-none-any.whl", "url": "https://files/pkg.whl", "packagetype": "bdist_wheel",
             "digests": {"sha256": "0" * 64}}]}).encode(),
        "https://files/pkg-1.0.tar.gz": sdist, "https://files/pkg.whl": wheel.getvalue(),
        "https://rubygems.org/api/v2/rubygems/bsv-sdk/versions/0.7.0.json":
            json.dumps({"sha": hashlib.sha256(gem).hexdigest(), "platform": "ruby"}).encode(),
        "https://rubygems.org/downloads/bsv-sdk-0.7.0.gem": gem,
        "https://registry.npmjs.org/@scope%2Flib/1.2.3": json.dumps({"dist": {
            "tarball": "https://registry/lib-1.2.3.tgz",
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(npm).digest()).decode()}}).encode(),
        "https://registry/lib-1.2.3.tgz": npm,
    }
    monkeypatch.setattr(rg, "FETCH", lambda url: urls[url])
    dest = tmp_path / "scratch" / "downloads"
    pypi = run(tmp_path, "artifact", "--registry", "pypi", "--package", "pkg", "--version", "1.0",
               "--dest", str(dest), "--glob", "*/server/*", "--pattern", r"cors_origins")["result"]
    sdist_row, wheel_row = pypi["versions"][0]["files"]
    assert sdist_row["digest_ok"] is True and wheel_row["digest_ok"] is False
    assert sdist_row["glob_matches"] == ["pkg-1.0/server/key-server/app/config.py"]
    assert sdist_row["pattern_matches"][0]["lines"] == [1] and (dest / "pkg-1.0.tar.gz").read_bytes() == sdist
    gem_row = run(tmp_path, "artifact", "--registry", "rubygems", "--package", "bsv-sdk", "--version", "0.7.0",
                  "--dest", str(dest), "--glob", "lib/bsv/wallet_interface/*")["result"]["versions"][0]["files"][0]
    assert gem_row["digest_ok"] and gem_row["glob_matches"] == ["lib/bsv/wallet_interface/wallet_client.rb"]
    npm_row = run(tmp_path, "artifact", "--registry", "npm", "--package", "@scope/lib", "--version", "1.2.3",
                  "--dest", str(dest))["result"]["versions"][0]["files"][0]
    assert npm_row["digest_ok"] and npm_row["members_total"] == 1
