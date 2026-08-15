"""Regression tests for supplementary Web data loaders."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

import web_data.loader as loader
from web_data.loader import (
    build_alias_map,
    load_ghsa_published_dates,
    load_ghsa_severities,
)


@pytest.mark.parametrize("subdir", ["github-reviewed", "unreviewed"])
def test_ghsa_indexes_follow_current_advisory_database_layout(
    tmp_path,
    subdir: str,
) -> None:
    advisory_id = "GHSA-2345-6789-abcd"
    alias = "CVE-2026-12345"
    advisory_dir = tmp_path / subdir / "2026" / "07" / advisory_id
    advisory_dir.mkdir(parents=True)
    osv_bulk_dir = tmp_path / "osv-bulk"
    osv_bulk_dir.mkdir()
    (advisory_dir / f"{advisory_id}.json").write_text(
        json.dumps(
            {
                "id": advisory_id,
                "aliases": [alias],
                "published": "2026-07-18T04:05:06Z",
                "database_specific": {"severity": "MODERATE"},
            }
        ),
        encoding="utf-8",
    )

    assert load_ghsa_published_dates(str(tmp_path)) == {advisory_id: "2026-07-18"}
    assert load_ghsa_severities(str(tmp_path)) == {
        advisory_id: "MEDIUM",
        alias: "MEDIUM",
    }
    expected_aliases = {advisory_id, alias}
    assert build_alias_map(str(tmp_path), str(osv_bulk_dir)) == {
        advisory_id: expected_aliases,
        alias: expected_aliases,
    }


def test_ghsa_severity_index_skips_unreviewed_null_severity(tmp_path) -> None:
    advisory_id = "GHSA-3456-789a-bcde"
    advisory_dir = tmp_path / "unreviewed" / "2026" / "07" / advisory_id
    advisory_dir.mkdir(parents=True)
    (advisory_dir / f"{advisory_id}.json").write_text(
        json.dumps(
            {
                "id": advisory_id,
                "aliases": ["CVE-2026-54321"],
                "published": "2026-07-18T04:05:06Z",
                "database_specific": {"severity": None},
            }
        ),
        encoding="utf-8",
    )

    assert load_ghsa_severities(str(tmp_path)) == {}


def test_alias_map_includes_actual_cve_ghsa_pair_from_osv_bulk(tmp_path) -> None:
    """OSV-only aliases must prevent duplicate publication of one vulnerability."""
    ghsa_dir = tmp_path / "ghsa"
    osv_bulk_dir = tmp_path / "osv-bulk"
    osv_bulk_dir.mkdir()
    cve_id = "CVE-2026-32890"
    ghsa_id = "GHSA-qpmq-6wjc-w28q"
    with zipfile.ZipFile(osv_bulk_dir / "GIT.zip", "w") as archive:
        archive.writestr(
            f"{cve_id}.json",
            json.dumps({"id": cve_id, "aliases": [ghsa_id]}),
        )

    aliases = build_alias_map(str(ghsa_dir), str(osv_bulk_dir))

    expected = {cve_id, ghsa_id}
    assert aliases[cve_id] == expected
    assert aliases[ghsa_id] == expected


def test_alias_map_merges_ghsa_and_osv_groups_transitively(tmp_path) -> None:
    ghsa_id = "GHSA-2345-6789-abcd"
    cve_id = "CVE-2026-12345"
    osv_id = "OSV-2026-77"
    advisory_dir = tmp_path / "ghsa" / "github-reviewed" / "2026" / ghsa_id
    advisory_dir.mkdir(parents=True)
    (advisory_dir / f"{ghsa_id}.json").write_text(
        json.dumps({"id": ghsa_id, "aliases": [cve_id]}),
        encoding="utf-8",
    )
    osv_bulk_dir = tmp_path / "osv-bulk"
    osv_bulk_dir.mkdir()
    with zipfile.ZipFile(osv_bulk_dir / "GIT.zip", "w") as archive:
        archive.writestr(
            f"{osv_id}.json",
            json.dumps({"id": osv_id, "aliases": [cve_id]}),
        )

    aliases = build_alias_map(str(tmp_path / "ghsa"), str(osv_bulk_dir))

    expected = {ghsa_id, cve_id, osv_id}
    assert all(aliases[advisory_id] == expected for advisory_id in expected)


def test_alias_map_skips_malformed_osv_data_without_partial_links(
    tmp_path,
    caplog,
) -> None:
    osv_bulk_dir = tmp_path / "osv-bulk"
    osv_bulk_dir.mkdir()
    (osv_bulk_dir / "broken.zip").write_bytes(b"not a zip archive")
    with zipfile.ZipFile(osv_bulk_dir / "records.zip", "w") as archive:
        archive.writestr(
            "OSV-2026-bad.json",
            json.dumps(
                {
                    "id": "OSV-2026-bad",
                    "aliases": "GHSA-would-be-split-into-characters",
                }
            ),
        )
        archive.writestr("corrupt.json", "{bad json")
        archive.writestr(
            "OSV-2026-good.json",
            json.dumps({"id": "OSV-2026-good", "aliases": ["CVE-2026-10000"]}),
        )

    aliases = build_alias_map(str(tmp_path / "missing-ghsa"), str(osv_bulk_dir))

    assert "OSV-2026-bad" not in aliases
    assert aliases["OSV-2026-good"] == {"OSV-2026-good", "CVE-2026-10000"}
    assert "Skipping OSV bulk archive" in caplog.text
    assert "aliases must be strings" in caplog.text
    assert "Skipping OSV alias record" in caplog.text


def test_audit_labels_apply_to_declared_aliases(monkeypatch) -> None:
    entries = [
        {
            "cve_id": "CVE-2026-2581",
            "aliases": ["GHSA-phc3-fgpg-7m6h"],
            "label": "NOT_AI_CAUSAL",
        },
        {
            "cve_id": "CVE-2026-9999",
            "aliases": ["GHSA-aaaa-bbbb-cccc"],
            "label": "AI_CAUSAL",
        },
        {
            "cve_id": "CVE-2026-7777",
            "aliases": ["GHSA-dddd-eeee-ffff"],
            "label": "INCONCLUSIVE",
        },
    ]
    monkeypatch.setattr(loader, "_read_audit_adjudication_file", lambda: entries)
    monkeypatch.setattr(loader, "_read_audit_override_file", lambda: [])

    assert loader.load_audit_exclusions() == {
        "CVE-2026-2581",
        "GHSA-phc3-fgpg-7m6h",
        "CVE-2026-7777",
        "GHSA-dddd-eeee-ffff",
    }
    assert loader.load_audit_overrides() == {
        "CVE-2026-9999",
        "GHSA-aaaa-bbbb-cccc",
    }


def test_source_aliases_expand_audit_labels_before_filtering(monkeypatch) -> None:
    monkeypatch.setattr(
        loader,
        "_read_audit_adjudication_file",
        lambda: [
            {
                "cve_id": "GHSA-g353-mgv3-8pcj",
                "label": "NOT_AI_CAUSAL",
            },
            {
                "cve_id": "CVE-2026-9999",
                "label": "AI_CAUSAL",
            },
        ],
    )
    monkeypatch.setattr(loader, "_read_audit_override_file", lambda: [])
    alias_map = {
        "GHSA-g353-mgv3-8pcj": {
            "GHSA-g353-mgv3-8pcj",
            "CVE-2026-32974",
        },
        "CVE-2026-32974": {
            "GHSA-g353-mgv3-8pcj",
            "CVE-2026-32974",
        },
        "CVE-2026-9999": {"CVE-2026-9999", "GHSA-aaaa-bbbb-cccc"},
        "GHSA-aaaa-bbbb-cccc": {"CVE-2026-9999", "GHSA-aaaa-bbbb-cccc"},
    }

    assert loader.load_audit_exclusions(alias_map) == {
        "GHSA-g353-mgv3-8pcj",
        "CVE-2026-32974",
    }
    assert loader.load_adjudicated_positive_ids(alias_map) == {
        "CVE-2026-9999",
        "GHSA-aaaa-bbbb-cccc",
    }


def test_excluded_alias_tombstone_blocks_transitive_source_expansion() -> None:
    kept = "GHSA-aaaa-bbbb-cccc"
    bridge = "CVE-2026-1"
    removed = "GHSA-dddd-eeee-ffff"
    expanded = loader.expand_audit_adjudications(
        [
            {
                "cve_id": kept,
                "aliases": [],
                "excluded_aliases": [removed],
                "label": "INCONCLUSIVE",
            }
        ],
        {
            kept: {kept, bridge},
            bridge: {kept, bridge, removed},
            removed: {bridge, removed},
        },
    )

    assert expanded[0]["aliases"] == [bridge]
    assert expanded[0]["excluded_aliases"] == [removed]


def test_excluded_alias_tombstone_applies_across_adjudication_rows() -> None:
    removed = "GHSA-dddd-eeee-ffff"
    expanded = loader.expand_audit_adjudications(
        [
            {
                "cve_id": "GHSA-aaaa-bbbb-cccc",
                "excluded_aliases": [removed],
                "label": "INCONCLUSIVE",
            },
            {
                "cve_id": "CVE-2026-2",
                "label": "AI_CAUSAL",
            },
        ],
        {"CVE-2026-2": {"CVE-2026-2", removed}},
    )

    assert expanded[1]["aliases"] == []


def test_default_alias_expansion_does_not_resurrect_removed_fp211_ids() -> None:
    payload = json.loads(
        (Path(loader.__file__).resolve().parent.parent / "publication_adjudications.json")
        .read_text(encoding="utf-8")
    )
    removed = set(payload["summary"]["removed_public_ids"])
    expanded = loader.expand_audit_adjudications(
        loader._read_audit_adjudication_file(),
        loader.build_alias_map(),
    )
    subjects = {
        subject.upper()
        for row in expanded
        for subject in [row["cve_id"], *row.get("aliases", [])]
    }

    assert subjects.isdisjoint(removed)


def test_source_alias_label_conflict_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(
        loader,
        "_read_audit_adjudication_file",
        lambda: [
            {"cve_id": "CVE-2026-1", "label": "AI_CAUSAL"},
            {"cve_id": "GHSA-aaaa-bbbb-cccc", "label": "NOT_AI_CAUSAL"},
        ],
    )
    alias_group = {"CVE-2026-1", "GHSA-aaaa-bbbb-cccc"}

    with pytest.raises(ValueError, match="Conflicting audit adjudications"):
        loader.load_audit_exclusions(
            {subject_id: alias_group for subject_id in alias_group}
        )


def test_adjudication_details_extend_legacy_override_details(monkeypatch) -> None:
    exclusion = {
        "fix_commit_sha": "a" * 40,
        "commit_sha": "b" * 40,
        "blamed_file": "src/plugin-sdk/index.ts",
    }
    monkeypatch.setattr(
        loader,
        "_read_audit_override_file",
        lambda: [
            {
                "cve_id": "CVE-2026-28478",
                "reason": "Legacy audit narrative.",
                "tools": ["claude_code"],
            }
        ],
    )
    monkeypatch.setattr(
        loader,
        "_read_audit_adjudication_file",
        lambda: [
            {
                "cve_id": "CVE-2026-28478",
                "label": "AI_CAUSAL",
                "excluded_bic_subjects": [exclusion],
            }
        ],
    )

    detail = loader.load_audit_override_details()["CVE-2026-28478"]

    assert detail["reason"] == "Legacy audit narrative."
    assert detail["tools"] == ["claude_code"]
    assert detail["label"] == "AI_CAUSAL"
    assert detail["excluded_bic_subjects"] == [exclusion]


def _write_audit_adjudications(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    adjudications: list[dict],
) -> None:
    """Point the loader at a temporary adjudication corpus."""
    package_dir = tmp_path / "web_data"
    package_dir.mkdir()
    monkeypatch.setattr(loader, "__file__", str(package_dir / "loader.py"))
    (tmp_path / "publication_adjudications.json").write_text(
        json.dumps({"schema_version": 1, "adjudications": adjudications}),
        encoding="utf-8",
    )


def test_default_loader_consumes_effective_publication_corpus() -> None:
    rows = loader._read_audit_adjudication_file()
    labels = {
        subject.upper(): row["label"]
        for row in rows
        for subject in [row["cve_id"], *row.get("aliases", [])]
    }

    assert labels["CVE-2026-32247"] == "NOT_AI_CAUSAL"
    assert labels["CVE-2026-1979"] == "INCONCLUSIVE"
    assert labels["CVE-2026-25481"] == "INCONCLUSIVE"
    assert labels["GHSA-G353-MGV3-8PCJ"] == "INCONCLUSIVE"


def test_audit_adjudication_accepts_exact_bic_subject_exclusions(
    tmp_path,
    monkeypatch,
) -> None:
    exclusion = {
        "fix_commit_sha": "a" * 40,
        "commit_sha": "b" * 40,
        "blamed_file": "src/plugin-sdk/index.ts",
    }
    _write_audit_adjudications(
        tmp_path,
        monkeypatch,
        [
            {
                "cve_id": "CVE-2026-28478",
                "label": "AI_CAUSAL",
                "excluded_bic_subjects": [exclusion],
            }
        ],
    )

    assert loader._read_audit_adjudication_file()[0]["excluded_bic_subjects"] == [exclusion]


@pytest.mark.parametrize(
    ("label", "subjects"),
    [
        ("AI_CAUSAL", []),
        (
            "NOT_AI_CAUSAL",
            [
                {
                    "fix_commit_sha": "a" * 40,
                    "commit_sha": "b" * 40,
                    "blamed_file": "src/main.py",
                }
            ],
        ),
        (
            "AI_CAUSAL",
            [
                {
                    "commit_sha": "b" * 40,
                    "blamed_file": "src/main.py",
                }
            ],
        ),
        (
            "AI_CAUSAL",
            [
                {
                    "fix_commit_sha": "short",
                    "commit_sha": "b" * 40,
                    "blamed_file": "src/main.py",
                }
            ],
        ),
        (
            "AI_CAUSAL",
            [
                {
                    "fix_commit_sha": "a" * 40,
                    "commit_sha": "B" * 40,
                    "blamed_file": "src/main.py",
                }
            ],
        ),
        (
            "AI_CAUSAL",
            [
                {
                    "fix_commit_sha": "a" * 40,
                    "commit_sha": "b" * 40,
                    "blamed_file": "../src/main.py",
                }
            ],
        ),
        (
            "AI_CAUSAL",
            [
                {
                    "fix_commit_sha": "a" * 40,
                    "commit_sha": "b" * 40,
                    "blamed_file": "",
                }
            ],
        ),
        (
            "AI_CAUSAL",
            [
                {
                    "fix_commit_sha": "a" * 40,
                    "commit_sha": "b" * 40,
                    "blamed_file": "src/main.py",
                    "reason": "extra keys make the exact subject ambiguous",
                }
            ],
        ),
    ],
)
def test_audit_adjudication_rejects_malformed_bic_subject_exclusions(
    tmp_path,
    monkeypatch,
    label: str,
    subjects: list[dict],
) -> None:
    _write_audit_adjudications(
        tmp_path,
        monkeypatch,
        [
            {
                "cve_id": "CVE-2026-28478",
                "label": label,
                "excluded_bic_subjects": subjects,
            }
        ],
    )

    with pytest.raises(ValueError, match="excluded BIC subjects"):
        loader._read_audit_adjudication_file()


def test_audit_adjudication_rejects_duplicate_bic_subject_exclusions(
    tmp_path,
    monkeypatch,
) -> None:
    exclusion = {
        "fix_commit_sha": "a" * 40,
        "commit_sha": "b" * 40,
        "blamed_file": "src/main.py",
    }
    _write_audit_adjudications(
        tmp_path,
        monkeypatch,
        [
            {
                "cve_id": "CVE-2026-28478",
                "label": "AI_CAUSAL",
                "excluded_bic_subjects": [exclusion, dict(exclusion)],
            }
        ],
    )

    with pytest.raises(ValueError, match="Duplicate excluded BIC subject"):
        loader._read_audit_adjudication_file()
