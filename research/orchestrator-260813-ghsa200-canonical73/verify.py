#!/usr/bin/env python3
"""Distinct structural, Git, and semantic verifiers. Fail-fast. Clean stderr on success."""

from __future__ import annotations

import os
import subprocess
from collections import Counter
from pathlib import Path

import build


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
GATES = build.GATES
HAN = build.HAN
SHA_RE = build.SHA_RE
GHSA_RE = build.GHSA_RE
EXCLUDE_NARROW = build.EXCLUDE_NARROW
EXCLUDE_F38V = build.EXCLUDE_F38V
EXCLUDE_4FXP = build.EXCLUDE_4FXP
CASE_Q855 = build.CASE_Q855
B3_KEEP = build.B3_KEEP
PRIOR_STRICT = build.PRIOR_STRICT
STRICT_COUNT = build.STRICT_COUNT
FILEBROWSER_NEG = build.FILEBROWSER_NEG
FILEBROWSER_POS = build.FILEBROWSER_POS
ORD200 = build.ORD200


def load_rows() -> list[dict]:
    return build.load_jsonl(HERE / "ledger.jsonl")


def by_kind(rows: list[dict], kind: str) -> list[dict]:
    return [row for row in rows if row["record_kind"] == kind]


def git_run(repo: str, *args: str) -> int:
    env = os.environ.copy()
    env["GIT_NO_LAZY_FETCH"] = "1"
    proc = subprocess.run(
        [
            "git",
            "--no-optional-locks",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            "-C",
            repo,
            *args,
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert proc.stderr == "", proc.stderr
    return proc.returncode


def verify_structural() -> dict:
    pins = build.pin_frozen()
    outputs = build.build_outputs()
    for path, expected in outputs.items():
        assert path.is_file() and path.read_text() == expected, path.name
    rows = load_rows()
    text = (HERE / "ledger.jsonl").read_text()
    assert not HAN.search(text)
    assert not HAN.search((HERE / "summary.json").read_text())
    assert not HAN.search((HERE / "report.md").read_text())
    summary = build.load_json(HERE / "summary.json")
    manifest = build.load_json(HERE / "manifest.json")

    hyp = by_kind(rows, "PRESERVED_HYPOTHESIS")
    pub = by_kind(rows, "PRESERVED_PUBLIC_CASE")
    counted = by_kind(rows, "STRICT_RELEASED_CASE")
    appends = by_kind(rows, "APPEND_IDENTITY")
    auth = by_kind(rows, "PACKET_AUTHORITY")
    edges = by_kind(rows, "SUPERSEDES_EDGE")
    assert len(hyp) == 211
    assert len(pub) == 212
    assert len(counted) == STRICT_COUNT
    assert len(appends) == 4
    assert len(auth) == len(build.PACKET_AUTHORITY)
    assert [row["ordinal"] for row in hyp] == list(range(1, 212))
    assert len({row["row_key"] for row in hyp}) == 211
    assert len({row["case_id"] for row in pub}) == 212
    assert all(GHSA_RE.fullmatch(row["case_id"]) for row in pub)
    assert all(row["counted"] is False for row in hyp + pub + appends + auth + edges)
    assert all(row["counted"] is True for row in counted)
    assert all(row["source_layer"] is True for row in hyp + pub)
    assert {row["case_id"] for row in appends} == {
        "GHSA-6P9M-Q3JP-47H4",
        "GHSA-G39V-CVJH-8FPF",
        "GHSA-PF93-J98V-25PV",
        CASE_Q855,
    }
    source_ids = {row["case_id"] for row in pub}
    for row in appends:
        assert row["case_id"] not in source_ids
        assert row["row_key"].startswith("ghsa200-next:")
        assert row["ordinal"] >= 212
        assert all(row[field] == "PASS" for field in GATES)

    for row in counted:
        for field in GATES:
            assert row[field] == "PASS", (row["case_id"], field, row[field])
            assert row[field] is not None and row[field] != "NA"
        for field in ("candidate_set", "carrier_set", "minimum_fix_set"):
            assert row[field] == sorted(set(row[field]))
            assert all(SHA_RE.fullmatch(item) for item in row[field])
        assert "candidate_fix_edges" not in row
        assert row["edge_authority"] == "candidate_set/carrier_set/minimum_fix_set"
        assert GHSA_RE.fullmatch(row["case_id"])
        aliases = row["aliases"]
        assert row["case_id"] not in aliases
        assert not any(GHSA_RE.fullmatch(item) and item != row["case_id"] for item in aliases)
        assert row["mechanism_key"]
        assert row["mechanism_fingerprint"]
        assert row["counting_unit"] == "first-party GHSA case"

    assert summary["counts"]["strict_released_first_party_ghsa"] == STRICT_COUNT
    assert summary["canonical_strict_count"] == STRICT_COUNT
    assert summary["checkpoint"]["prior_strict_count"] == PRIOR_STRICT
    assert summary["checkpoint"]["uncorrected_count_not_terminal"] == 73
    assert summary["checkpoint"]["corrected_strict_count"] == STRICT_COUNT
    assert summary["counts"]["corrected_baseline_47"] == 47
    assert summary["counts"]["fp211_released_admitted_raw"] == 48
    assert summary["counts"]["q855_keep"] == 1
    assert summary["integration_ready"] is False
    assert summary["publication_ready"] is False
    assert summary["status"] == "HOLD"
    assert summary["public_200_claim_supported"] is False
    assert summary["causal_admission"] is False
    assert summary["conservation"]["fp211_hypotheses"] == 211
    assert summary["conservation"]["fp211_source_ghsa_cases"] == 212
    assert summary["conservation"]["cve_aliases_counted"] is False
    assert manifest["strict_released_first_party_ghsa"] == STRICT_COUNT
    assert manifest["integration_ready"] is False
    assert manifest["publication_ready"] is False
    assert summary["ledger_sha256"] == build.sha256_file(HERE / "ledger.jsonl")
    assert manifest["outputs"]["ledger.jsonl_sha256"] == summary["ledger_sha256"]
    assert manifest["hash_roles"]["frozen"]["netnew22_cases"]["sha256"] == pins["netnew22_cases"]["sha256"]
    assert manifest["hash_roles"]["frozen"]["actual_gogs_cases"]["sha256"] == pins["actual_gogs_cases"]["sha256"]
    assert manifest["hash_roles"]["frozen"]["b3_cases"]["sha256"] == pins["b3_cases"]["sha256"]
    assert manifest["hash_roles"]["frozen"]["directroot_cases"]["sha256"] == pins["directroot_cases"]["sha256"]
    assert manifest["hash_roles"]["frozen"]["directroot_result"]["sha256"] == pins["directroot_result"]["sha256"]
    assert manifest["hash_roles"]["frozen"]["q855_cases"]["sha256"] == pins["q855_cases"]["sha256"]
    assert manifest["hash_roles"]["frozen"]["q855_result"]["sha256"] == pins["q855_result"]["sha256"]
    assert manifest["hash_roles"]["frozen"]["canonical71_ledger"]["sha256"] == pins["canonical71_ledger"]["sha256"]
    assert Counter(row["admission_source"] for row in counted) == Counter(
        {
            "fp211_released_publication_admitted": 47,
            "netnew22_redteam_keep": 21,
            "actual_gogs_redteam_keep": 2,
            "b3_redteam_keep": 2,
            "q855_redteam_keep": 1,
        }
    )
    return summary


def verify_git() -> None:
    rows = load_rows()
    counted = by_kind(rows, "STRICT_RELEASED_CASE")
    replay = [row for row in counted if row["overlay_state"] == "KEEP"]
    assert len(replay) == 26
    for row in replay:
        repo = build.CLONES[row["repository"]]
        assert Path(repo).is_dir(), row["repository"]
        vuln = row["vulnerable_release"]["tag"]
        fixed = row["fixed_release"]["tag"]
        for cand in row["candidate_set"]:
            assert git_run(repo, "merge-base", "--is-ancestor", cand, vuln) == 0, (
                row["case_id"],
                cand,
                vuln,
            )
        for fix in row["minimum_fix_set"]:
            assert git_run(repo, "merge-base", "--is-ancestor", fix, vuln) == 1, (
                row["case_id"],
                fix,
                vuln,
            )
            assert git_run(repo, "merge-base", "--is-ancestor", fix, fixed) == 0, (
                row["case_id"],
                fix,
                fixed,
            )
        if row["case_id"] == CASE_Q855:
            also = row["fixed_release"]["also_fixed_tag"]
            assert row["vulnerable_release"]["tag"] == "v7.5.0"
            assert row["fixed_release"]["tag"] == "v7.7.0"
            assert also == "v7.10.0"
            for fix in row["minimum_fix_set"]:
                assert git_run(repo, "merge-base", "--is-ancestor", fix, also) == 0, (
                    row["case_id"],
                    fix,
                    also,
                )


def verify_semantic() -> None:
    rows = load_rows()
    hyp = by_kind(rows, "PRESERVED_HYPOTHESIS")
    pub = by_kind(rows, "PRESERVED_PUBLIC_CASE")
    counted = by_kind(rows, "STRICT_RELEASED_CASE")
    by_key = {row["row_key"]: row for row in hyp}
    negative = by_key[FILEBROWSER_NEG]
    positive = by_key[FILEBROWSER_POS]
    assert negative["ordinal"] == 165
    assert positive["ordinal"] == 166
    assert negative["fp211_verdict"] == "FALSE_POSITIVE"
    assert positive["fp211_verdict"] == "CONFIRM"
    assert negative["fp211_candidate_set"] == positive["fp211_candidate_set"]
    assert negative["fp211_minimum_fix_set"] == positive["fp211_minimum_fix_set"]
    assert negative["row_key"] != positive["row_key"]

    dual = [row for row in pub if row["ordinal"] == 200]
    assert {row["case_id"] for row in dual} == set(ORD200)
    assert len(dual) == 2
    assert dual[0]["row_key"] == dual[1]["row_key"]
    assert not any(row["case_id"] in ORD200 for row in counted)

    counted_ids = [row["case_id"] for row in counted]
    assert EXCLUDE_NARROW not in counted_ids
    assert EXCLUDE_F38V not in counted_ids
    assert EXCLUDE_4FXP not in counted_ids
    assert CASE_Q855 in counted_ids
    assert counted_ids.count(CASE_Q855) == 1
    assert set(B3_KEEP) <= set(counted_ids)
    narrow_hyp = next(row for row in hyp if EXCLUDE_NARROW in " ".join(row["public_ids"]))
    assert narrow_hyp["overlay_state"] == "NARROW"
    assert narrow_hyp["gates"]["but_for_gate"] == "NARROW"
    f38v_hyp = next(row for row in hyp if EXCLUDE_F38V in " ".join(row["public_ids"]))
    assert f38v_hyp["overlay_state"] == "NARROW"
    assert f38v_hyp["gates"]["but_for_gate"] == "NARROW"
    four_hyp = next(row for row in hyp if EXCLUDE_4FXP in " ".join(row.get("public_ids") or []) or EXCLUDE_4FXP in " ".join(row.get("declared_public_ids") or []))
    assert four_hyp["overlay_state"] == "NARROW"
    assert four_hyp["gates"]["identity_gate"] == "NARROW"
    assert four_hyp["released_publication_admitted"] is True
    assert four_hyp["authority_packet"] == "autoresearch/herdr-260813-ghsa200-final-candidate-review-codex"
    assert four_hyp["failed_gate"] == "identity_gate"
    assert "final-candidate-review-codex NARROW identity_gate supersedes counted membership" in four_hyp["authority_lineage"]
    assert not any(row["record_kind"] == "STRICT_RELEASED_CASE" and row["case_id"] == EXCLUDE_4FXP for row in rows)

    assert len(counted_ids) == len(set(counted_ids)) == STRICT_COUNT
    fps = [row["mechanism_fingerprint"] for row in counted]
    assert len(fps) == len(set(fps))
    cve_aliases = [item for row in counted for item in row["aliases"] if item.startswith("CVE-")]
    assert not any(item in counted_ids for item in cve_aliases)
    assert "more than 200" not in (HERE / "report.md").read_text().lower()
    report = (HERE / "report.md").read_text()
    assert "worker-only PASS" in report
    assert "canonical strict count 73" in report
    assert CASE_Q855 in report
    assert EXCLUDE_F38V in report
    assert EXCLUDE_4FXP in report
    assert "Pending B3" not in report

    sha_index: dict[str, list[str]] = {}
    for row in counted:
        for sha in row["candidate_set"] + row["minimum_fix_set"]:
            sha_index.setdefault(sha, []).append(row["case_id"])
    assert len({row["case_id"] for row in counted}) == STRICT_COUNT

    b3 = "autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh"
    assert b3 in {row["packet"] for row in by_kind(rows, "PACKET_AUTHORITY")}
    assert any(row.get("to_packet") == b3 for row in by_kind(rows, "SUPERSEDES_EDGE"))
    q855_pkt = "autoresearch/herdr-260813-ghsa200-q855-redteam-grok46-medium"
    dr_pkt = "autoresearch/herdr-260813-ghsa200-directroot-mining-grok46-xhigh"
    assert q855_pkt in {row["packet"] for row in by_kind(rows, "PACKET_AUTHORITY")}
    assert dr_pkt in {row["packet"] for row in by_kind(rows, "PACKET_AUTHORITY")}
    assert any(row.get("to_packet") == q855_pkt for row in by_kind(rows, "SUPERSEDES_EDGE"))
    q855_edge = next(row for row in by_kind(rows, "SUPERSEDES_EDGE") if row["case_id"] == CASE_Q855)
    assert q855_edge["from_packet"] == dr_pkt
    assert q855_edge["to_verdict"] == "KEEP"
    assert q855_edge["applies_to_counted_set"] is True
    assert not any(row["admission_source"] == "worker_pass" for row in counted)

    four_edge = next(
        row
        for row in by_kind(rows, "SUPERSEDES_EDGE")
        if row["case_id"] == EXCLUDE_4FXP
    )
    assert four_edge["to_verdict"] == "NARROW"
    assert four_edge["failed_gate"] == "identity_gate"
    assert four_edge["applies_to_counted_set"] is True
    assert four_edge["from_verdict"] == "fp211_released_publication_admitted"


def verify() -> tuple[dict, list[dict]]:
    summary = verify_structural()
    verify_git()
    verify_semantic()
    return summary, by_kind(load_rows(), "STRICT_RELEASED_CASE")


def main() -> None:
    summary, counted = verify()
    print(
        "PASS: canonical73 HOLD structural+git+semantic; "
        f"counted={len(counted)}; publication=HOLD"
    )
    assert summary["counts"]["strict_released_first_party_ghsa"] == len(counted) == STRICT_COUNT
    assert summary["canonical_strict_count"] == STRICT_COUNT


if __name__ == "__main__":
    main()
