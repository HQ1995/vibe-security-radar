"""Adversarial tests for the formal-release verifier trust contract."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from web_data import verifier_contract


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _git(repo_root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo_root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _commit(repo_root: Path, message: str, *paths: str) -> str:
    _git(repo_root, "add", "--", *paths)
    _git(
        repo_root,
        "-c",
        "user.name=Verifier Contract Test",
        "-c",
        "user.email=verifier@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "-m",
        message,
    )
    return _git(repo_root, "rev-parse", "HEAD")


def _repository(tmp_path: Path) -> Path:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    _git(repo_root, "init", "-q")
    files = {
        "scripts/release.py": "print('verify')\n",
        "cve-analyzer/src/cve_analyzer/__init__.py": '"""fixture"""\n',
        "cve-analyzer/pyproject.toml": "[project]\nname='fixture'\nversion='0'\n",
        "cve-analyzer/uv.lock": "version = 1\n",
        "web/scripts/verify.mjs": "export const fixture = true;\n",
        "web/src/index.ts": "export const fixture = true;\n",
        "web/package.json": '{"name":"fixture","version":"0.0.0"}\n',
        "web/package-lock.json": '{"lockfileVersion":3,"name":"fixture"}\n',
        "web/next.config.ts": "export default {};\n",
    }
    for relative, content in files.items():
        path = repo_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _commit(
        repo_root,
        "Bind verifier inputs",
        *verifier_contract.TREE_SCOPES,
        *verifier_contract.FILE_SCOPES,
    )
    return repo_root


def test_contract_replays_after_descendant_commit_outside_verifier_scope(
    tmp_path: Path,
) -> None:
    repo_root = _repository(tmp_path)
    contract = verifier_contract.build_verifier_contract(repo_root)
    (repo_root / "README.md").write_text("release notes\n", encoding="utf-8")
    _commit(repo_root, "Add release notes", "README.md")

    assert (
        verifier_contract.validate_verifier_contract(
            contract,
            repo_root=repo_root,
        )
        == contract
    )


def test_contract_rejects_descendant_commit_inside_verifier_scope(
    tmp_path: Path,
) -> None:
    repo_root = _repository(tmp_path)
    contract = verifier_contract.build_verifier_contract(repo_root)
    (repo_root / "web/src/index.ts").write_text(
        "export const fixture = false;\n",
        encoding="utf-8",
    )
    _commit(repo_root, "Change verifier source", "web/src/index.ts")

    with pytest.raises(
        verifier_contract.VerifierContractError,
        match="differ from the bound Git commit",
    ):
        verifier_contract.validate_verifier_contract(contract, repo_root=repo_root)


@pytest.mark.parametrize(
    "kind",
    ["tracked", "untracked", "ignored", "ignored_native"],
)
def test_contract_rejects_worktree_shadows(tmp_path: Path, kind: str) -> None:
    repo_root = _repository(tmp_path)
    if kind == "tracked":
        (repo_root / "scripts/release.py").write_text(
            "print('changed')\n",
            encoding="utf-8",
        )
        expected = "differ from the bound Git commit"
    elif kind == "untracked":
        (repo_root / "scripts/shadow.py").write_text("pass\n", encoding="utf-8")
        expected = "untracked files shadow"
    else:
        suffix = ".py" if kind == "ignored" else ".cpython-313-x86_64-linux-gnu.so"
        ignored_path = f"scripts/ignored{suffix}"
        (repo_root / ".gitignore").write_text(
            f"{ignored_path}\n",
            encoding="utf-8",
        )
        _commit(repo_root, "Ignore generated source", ".gitignore")
        (repo_root / ignored_path).write_bytes(b"native-or-source-shadow\n")
        expected = "ignored source files shadow"

    with pytest.raises(verifier_contract.VerifierContractError, match=expected):
        verifier_contract.build_verifier_contract(repo_root)


def test_contract_rejects_correlated_manifest_reseal(tmp_path: Path) -> None:
    repo_root = _repository(tmp_path)
    contract = verifier_contract.build_verifier_contract(repo_root)
    contract["files"][0]["sha256"] = "0" * 64
    contract["files_manifest_sha256"] = _canonical_sha256(contract["files"])
    preimage = dict(contract)
    preimage.pop("contract_sha256")
    contract["contract_sha256"] = _canonical_sha256(preimage)

    with pytest.raises(
        verifier_contract.VerifierContractError,
        match="does not match trusted Git objects",
    ):
        verifier_contract.validate_verifier_contract(contract, repo_root=repo_root)
