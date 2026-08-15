import json

from cohort_atomic_partition_inputs import _repositories, partition_inputs


def test_repositories_assigns_missing_slugs(tmp_path) -> None:
    path = tmp_path / "repositories.json"
    path.write_text(
        json.dumps(
            [
                {
                    "repository_identity": "github.com/a/a",
                    "repository_path": "/a",
                }
            ]
        ),
        encoding="utf-8",
    )

    assert _repositories(path)[0]["slug"] == "repo-1"


def test_partition_inputs_routes_each_row_once(tmp_path) -> None:
    repositories = [
        {"repository_identity": "github.com/a/a", "repository_path": "/a", "slug": "a"},
        {"repository_identity": "github.com/b/b", "repository_path": "/b", "slug": "b"},
    ]
    source = tmp_path / "source.jsonl"
    source.write_text(
        "\n".join(
            json.dumps({"repository_identity": identity, "value": value})
            for identity, value in (
                ("github.com/a/a", 1),
                ("github.com/c/c", 2),
                ("github.com/b/b", 3),
            )
        )
        + "\n",
        encoding="utf-8",
    )

    summary = partition_inputs(repositories, {"rows": source}, tmp_path / "out")

    assert summary["row_counts"] == {"a": {"rows": 1}, "b": {"rows": 1}}
    assert json.loads((tmp_path / "out/a/rows.jsonl").read_text())["value"] == 1
    assert json.loads((tmp_path / "out/b/rows.jsonl").read_text())["value"] == 3
