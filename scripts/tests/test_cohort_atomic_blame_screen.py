import subprocess
from pathlib import Path

from cohort_atomic_blame_screen import (
    _collect_all_fix_blame,
    collect_fix_blame,
    match_candidates,
)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        message,
    )
    return _git(repo, "rev-parse", "HEAD")


def test_collect_fix_blame_includes_typescript_method_owner(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    (repo / "README.md").write_text("seed\n", encoding="utf-8")
    _commit(repo, "seed")
    source = repo / "handler.ts"
    source.write_text(
        "export async function run(input: string) {\n"
        "  const one = 1;\n  const two = 2;\n  const three = 3;\n"
        "  const four = 4;\n  const five = 5;\n  const six = 6;\n"
        "  return execute(input);\n}\n",
        encoding="utf-8",
    )
    candidate = _commit(repo, "add handler")
    source.write_text(
        source.read_text(encoding="utf-8").replace(
            "  return execute(input);",
            "  if (!allowed(input)) throw new Error('blocked');\n  return execute(input);",
        ),
        encoding="utf-8",
    )
    fix = _commit(repo, "guard handler")

    result = collect_fix_blame(repo, fix, timeout=30)

    assert "method_signature_blame" in result["origins"][candidate]["signals"]


def test_match_candidates_keeps_direct_blame_separate_from_carrier_blame() -> None:
    fix = "f" * 40
    direct_sha = "a" * 40
    member_sha = "b" * 40
    carrier_sha = "c" * 40
    common = {"class_id": "alias-1", "fix_sha": fix}
    candidates = [
        {**common, "candidate_sha": direct_sha, "relation": "reachable_ancestor"},
        {
            **common,
            "candidate_sha": member_sha,
            "relation": "pull_request_member_landed_as_squash_then_reachable_ancestor",
            "landed_squash_sha": carrier_sha,
        },
    ]
    blame = {
        fix: {
            "status": "RESOLVED",
            "parent_sha": "d" * 40,
            "origins": {
                direct_sha: {"signals": ["deleted_line_blame"], "paths": ["src/a.ts"]},
                carrier_sha: {
                    "signals": ["guard_context_blame"],
                    "paths": ["src/a.ts"],
                },
            },
        }
    }

    direct, carrier = match_candidates(candidates, blame)

    assert [row["candidate_sha"] for row in direct] == [direct_sha]
    assert [row["candidate_sha"] for row in carrier] == [member_sha]
    assert "not yet tied" in carrier[0]["claim_boundary"]


def test_collect_all_fix_blame_accepts_empty_inventory(tmp_path: Path) -> None:
    assert (
        _collect_all_fix_blame(
            tmp_path,
            [],
            timeout=30,
            allow_lazy_fetch=False,
        )
        == {}
    )
