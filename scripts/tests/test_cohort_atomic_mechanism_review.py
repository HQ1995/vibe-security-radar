import json
import time
import zipfile

import httpx
import pytest

from cohort_atomic_mechanism_review import (
    _advisory_records,
    _call,
    _filter_packets,
    _first_party_records,
    _is_code_path,
    _load_packets,
    _osv_records,
    _packet_fix_context,
    _replay_call,
    parse_review,
    select_candidates,
)
from cohort.root_adjudication import canonical_sha256


def test_selection_requires_production_code_and_prefers_exact_blame() -> None:
    direct = "a" * 40
    exact = "b" * 40
    squash = "c" * 40
    common = {
        "class_id": "alias-1",
        "fix_sha": "f" * 40,
        "relation": "reachable_ancestor",
    }
    units = {
        direct: {
            "merge_topology": "direct",
            "signal_types": ["co_author_trailer"],
            "authored_date": "2026-02-02T00:00:00Z",
        },
        exact: {
            "merge_topology": "direct",
            "signal_types": ["co_author_trailer"],
            "authored_date": "2026-01-01T00:00:00Z",
        },
        squash: {
            "merge_topology": "squash",
            "signal_types": ["co_author_trailer"],
            "authored_date": "2026-03-01T00:00:00Z",
        },
    }
    rows = [
        {**common, "candidate_sha": direct, "overlapping_files": ["src/a.ts"]},
        {**common, "candidate_sha": exact, "overlapping_files": ["src/b.ts"]},
        {**common, "candidate_sha": squash, "overlapping_files": ["src/c.ts"]},
        {**common, "candidate_sha": direct, "overlapping_files": ["docs/a.md"]},
    ]

    selected = select_candidates(
        rows,
        exact_keys={("alias-1", "f" * 40, exact)},
        units=units,
        max_per_class=2,
    )

    assert [row["candidate_sha"] for row in selected["alias-1"]] == [exact, direct]

    units[direct]["message"] = "feat: add vulnerable route"
    units[exact]["message"] = "refactor: move helper"
    feature_first = select_candidates(
        rows,
        exact_keys={("alias-1", "f" * 40, exact)},
        units=units,
        max_per_class=1,
        candidate_order="feature-first",
    )
    assert feature_first["alias-1"][0]["candidate_sha"] == direct


def test_selection_accepts_resolved_atomic_squash_member_not_carrier() -> None:
    member = "a" * 40
    carrier = "b" * 40
    common = {
        "class_id": "alias-1",
        "fix_sha": "f" * 40,
        "overlapping_files": ["src/a.ts"],
    }
    rows = [
        {
            **common,
            "candidate_sha": member,
            "relation": "pull_request_member_landed_as_squash_then_reachable_ancestor",
            "landed_squash_sha": carrier,
            "origin_relation_id": "cohort-relation-1",
        },
        {
            **common,
            "candidate_sha": carrier,
            "relation": "reachable_ancestor",
        },
    ]
    units = {
        member: {
            "merge_topology": "pull_request_member",
            "signal_types": ["co_author_trailer"],
            "authored_date": "2026-01-01T00:00:00Z",
        },
        carrier: {
            "merge_topology": "squash",
            "signal_types": ["co_author_trailer"],
            "authored_date": "2026-01-02T00:00:00Z",
        },
    }

    selected = select_candidates(
        rows,
        exact_keys=set(),
        units=units,
        max_per_class=2,
    )

    assert [row["candidate_sha"] for row in selected["alias-1"]] == [member]
    assert selected["alias-1"][0]["atomicity"] == (
        "resolved_pull_request_member_commit_no_carrier_inheritance"
    )


def test_packet_fix_context_keeps_only_bounded_unambiguous_exact_lines() -> None:
    exact = {
        "squash_internal_fix_context": [
            {"match_quality": "exact_line", "match_ambiguity": 1, "line": value}
            for value in range(3)
        ]
        + [
            {"match_quality": "exact_line", "match_ambiguity": 2, "line": 4},
            {
                "match_quality": "token_signature_fail_open",
                "match_ambiguity": 1,
                "line": 5,
            },
        ]
    }

    rows, truncated = _packet_fix_context(exact, limit=2)

    assert [row["line"] for row in rows] == [0, 1]
    assert truncated is True


def test_global_packet_inputs_accept_common_code_and_all_osv_packages(tmp_path) -> None:
    assert _is_code_path("src/Auth.cs")
    assert _is_code_path("app/guard.vue")
    assert _is_code_path("config/security.yaml")
    assert not _is_code_path("docs/example.ts")
    assert not _is_code_path("package-lock.json")

    archive_path = tmp_path / "osv.zip"
    record = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "aliases": ["CVE-2026-12345"],
        "affected": [{"package": {"name": "not-openclaw"}}],
    }
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("record.json", json.dumps(record))

    indexed = _osv_records(archive_path)

    assert indexed["GHSA-XXXX-YYYY-ZZZZ"] == record
    assert indexed["CVE-2026-12345"] == record
    assert _osv_records(archive_path, ["GHSA-missing"]) == {}


def test_first_party_advisories_precede_osv_without_transitive_aliases(tmp_path) -> None:
    cvelist = tmp_path / "cves"
    cve_path = cvelist / "2026" / "12xxx" / "CVE-2026-12345.json"
    cve_path.parent.mkdir(parents=True)
    cve_path.write_text(
        json.dumps(
            {
                "cveMetadata": {"state": "PUBLISHED"},
                "containers": {
                    "cna": {
                        "title": "First-party title",
                        "descriptions": [{"lang": "en", "value": "Exact mechanism"}],
                        "problemTypes": [
                            {"descriptions": [{"cweId": "CWE-918"}]}
                        ],
                        "references": [{"url": "https://example.test/fix"}],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    ghsa = tmp_path / "advisories"
    ghsa_path = (
        ghsa
        / "github-reviewed"
        / "2026"
        / "08"
        / "GHSA-abcd-1234-wxyz"
        / "GHSA-abcd-1234-wxyz.json"
    )
    ghsa_path.parent.mkdir(parents=True)
    ghsa_path.write_text(
        json.dumps(
            {
                "id": "GHSA-abcd-1234-wxyz",
                "aliases": ["CVE-2026-99999"],
                "summary": "GHSA title",
                "details": "GHSA mechanism",
                "references": [],
            }
        ),
        encoding="utf-8",
    )

    first_party = _first_party_records(
        cvelist,
        ghsa,
        ["CVE-2026-12345", "GHSA-ABCD-1234-WXYZ", "CVE-2026-99999"],
    )
    records, source, reason = _advisory_records(
        ["CVE-2026-12345"],
        first_party,
        {"CVE-2026-12345": {"id": "OSV-stale", "details": "stale"}},
    )

    assert source == "first_party"
    assert reason is None
    assert records[0]["details"] == "Exact mechanism"
    assert first_party["GHSA-ABCD-1234-WXYZ"]["source"] == (
        "github_advisory_database_reviewed"
    )
    assert "CVE-2026-99999" not in first_party

    records, source, reason = _advisory_records(["GHSA-missing"], {}, {})
    assert (records, source, reason) == ([], "missing_first_party", None)

    records, source, reason = _advisory_records(
        ["GHSA-missing"],
        {},
        {"GHSA-MISSING": {"id": "GHSA-missing", "details": "routing only"}},
    )
    assert source == "osv_routing_fallback"
    assert reason is None
    assert records[0]["source"] == "osv_routing_fallback"

    assert _advisory_records(
        ["CVE-2026-12345"],
        {"CVE-2026-12345": {"id": "CVE-2026-12345", "active": False}},
        {},
    ) == ([], "inactive_first_party", "first_party_record_inactive")


def test_load_packets_accepts_repository_partitions(tmp_path) -> None:
    expected = []
    for slug in ("one", "two"):
        packet_dir = tmp_path / slug
        packet_dir.mkdir()
        rows = [{"packet_id": slug, "class_id": f"alias-{slug}"}]
        expected.extend(rows)
        (packet_dir / "packets.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )
        (packet_dir / "summary.json").write_text(
            json.dumps({"packets_sha256": canonical_sha256(rows)}), encoding="utf-8"
        )

    assert _load_packets(tmp_path) == expected


def test_filter_packets_selects_requested_classes() -> None:
    packets = [
        {"packet_id": "one", "class_id": "alias-one"},
        {"packet_id": "two", "class_id": "alias-two"},
    ]

    assert _filter_packets(packets, ["alias-two"]) == [packets[1]]
    with pytest.raises(SystemExit, match="alias-missing"):
        _filter_packets(packets, ["alias-missing"])


def test_review_parser_requires_every_exact_pair() -> None:
    packet = {
        "class_id": "alias-1",
        "candidates": [{"candidate_sha": "a" * 40, "fix_sha": "f" * 40}],
    }
    review = {
        "class_id": "alias-1",
        "reviews": [
            {
                "candidate_sha": "a" * 40,
                "fix_sha": "f" * 40,
                "verdict": "AI_CAUSAL",
                "confidence": 0.9,
                "mechanism": "candidate adds unsafe path fixed later",
                "decisive_evidence": ["candidate and fix touch the same guard"],
                "missing_evidence": [],
            }
        ],
    }

    assert (
        parse_review(json.dumps(review), packet)["reviews"][0]["verdict"] == "AI_CAUSAL"
    )
    wrapped = f"Analysis before the answer.\n```json\n{json.dumps(review)}\n```"
    assert parse_review(wrapped, packet)["reviews"][0]["verdict"] == "AI_CAUSAL"
    review["reviews"] = []
    with pytest.raises(ValueError, match="every candidate"):
        parse_review(json.dumps(review), packet)


def test_replay_recovers_json_after_model_analysis(tmp_path) -> None:
    packet = {
        "packet_id": "packet-1",
        "class_id": "alias-1",
        "candidates": [{"candidate_sha": "a" * 40, "fix_sha": "f" * 40}],
    }
    review = {
        "class_id": "alias-1",
        "reviews": [
            {
                "candidate_sha": "a" * 40,
                "fix_sha": "f" * 40,
                "verdict": "AI_CAUSAL",
                "confidence": 0.9,
                "mechanism": "candidate adds the unsafe path",
                "decisive_evidence": ["exact delta"],
                "missing_evidence": [],
            }
        ],
    }
    raw = {
        "model": "claude-sonnet-4-6",
        "choices": [
            {"message": {"content": f"Analysis.\n```json\n{json.dumps(review)}\n```"}}
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20},
    }
    (tmp_path / "0001-attempt-1.json").write_text(json.dumps(raw), encoding="utf-8")

    result = _replay_call(
        packet,
        sequence=1,
        model="claude-sonnet-4-6",
        responses_dir=tmp_path,
    )

    assert result["status"] == "COMPLETE"
    assert result["reviews"][0]["verdict"] == "AI_CAUSAL"


@pytest.mark.parametrize("status_code", [500, 503])
def test_live_call_backs_off_after_retryable_server_error(
    tmp_path, monkeypatch, status_code
) -> None:
    packet = {
        "packet_id": "packet-1",
        "class_id": "alias-1",
        "candidates": [{"candidate_sha": "a" * 40, "fix_sha": "f" * 40}],
    }
    review = {
        "class_id": "alias-1",
        "reviews": [
            {
                "candidate_sha": "a" * 40,
                "fix_sha": "f" * 40,
                "verdict": "AI_CAUSAL",
                "confidence": 0.9,
                "mechanism": "candidate adds the unsafe path",
                "decisive_evidence": ["exact delta"],
                "missing_evidence": [],
            }
        ],
    }
    request = httpx.Request("POST", "http://127.0.0.1:8317/v1/chat/completions")
    responses = [
        httpx.Response(status_code, request=request),
        httpx.Response(
            200,
            request=request,
            json={
                "model": "deepseek-v4-flash",
                "choices": [{"message": {"content": json.dumps(review)}}],
            },
        ),
    ]
    sleeps = []
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: responses.pop(0))
    monkeypatch.setattr(time, "sleep", sleeps.append)

    result = _call(
        packet,
        sequence=1,
        api_base="http://127.0.0.1:8317/v1",
        api_key="test",
        model="deepseek-v4-flash",
        reasoning_effort="model-controlled",
        max_output_tokens=16000,
        timeout=30,
        responses_dir=tmp_path,
    )

    assert result["status"] == "COMPLETE"
    assert result["attempt_count"] == 2
    assert sleeps == [5]
