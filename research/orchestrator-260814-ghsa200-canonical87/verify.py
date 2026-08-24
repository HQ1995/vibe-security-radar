#!/usr/bin/env python3
"""Distinct structural, Git, and semantic verifiers. Fail-fast. Clean stderr on success."""

from __future__ import annotations

import subprocess
from pathlib import Path

import build


HERE = Path(__file__).resolve().parent
GATES = build.GATES
HAN = build.HAN
SHA_RE = build.SHA_RE
GHSA_RE = build.GHSA_RE
PRIOR_STRICT = build.PRIOR_STRICT
STRICT_COUNT = build.STRICT_COUNT
CASE_V52W = build.CASE_V52W
CASE_FRVJ = build.CASE_FRVJ
CAND_V52W = build.CAND_V52W
PARENT_V52W = build.PARENT_V52W
CARR_V52W = build.CARR_V52W
FIX_V52W = build.FIX_V52W
FIX_PARENT_V52W = build.FIX_PARENT_V52W
REST_164 = build.REST_164
CASE_PIMCORE = build.CASE_PIMCORE
CASE_HHJV = build.CASE_HHJV
CASE_73HC = build.CASE_73HC
CASE_282G = build.CASE_282G
CASE_45Q4 = build.CASE_45Q4
CASE_954P = build.CASE_954P
FILEBROWSER_NEG = build.FILEBROWSER_NEG
FILEBROWSER_POS = build.FILEBROWSER_POS
ORD200 = build.ORD200
GIT = (
    "/usr/bin/git",
    "--no-optional-locks",
    "-c",
    "gc.auto=0",
    "-c",
    "maintenance.auto=false",
)
CLONE = str(
    Path("/home")
    / "hanqing"
    / ".cache"
    / "cve-analyzer"
    / "repos"
    / "github.com_kozou-dev_kozou"
)
FILE = "packages/mcp/src/startHttpServer.ts"


def load_rows() -> list[dict]:
    return build.load_jsonl(HERE / "ledger.jsonl")


def by_kind(rows: list[dict], kind: str) -> list[dict]:
    return [row for row in rows if row["record_kind"] == kind]


def gitx(*args: str) -> str:
    proc = subprocess.run(
        [*GIT, "-C", CLONE, *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def verify_structural() -> dict:
    pins = build.pin_inputs()
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
    cap = build.load_capsule_v52w()
    neg = build.load_negative()
    prior = build.load_json(build.ROOT / build.P_C86_SUM)
    prior_rows = build.load_jsonl(build.ROOT / build.P_C86_LEDGER)
    prior_text = (build.ROOT / build.P_C86_LEDGER).read_text()
    assert text.startswith(prior_text if prior_text.endswith("\n") else prior_text + "\n")
    assert len(prior_rows) == build.BASE_LEDGER_RECORDS
    assert len(rows) == build.LEDGER_RECORDS
    assert [line for line in prior_text.splitlines() if line.strip()] == text.splitlines()[
        : build.BASE_LEDGER_RECORDS
    ]

    counted = by_kind(rows, "STRICT_RELEASED_CASE")
    hyp = by_kind(rows, "PRESERVED_HYPOTHESIS")
    pub = by_kind(rows, "PRESERVED_PUBLIC_CASE")
    assert len(hyp) == 211
    assert len(pub) == 212
    assert len(counted) == STRICT_COUNT
    assert all(row["counted"] is True for row in counted)
    prior_counted = [row for row in prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert prior_counted == counted[:PRIOR_STRICT]
    assert [row["case_id"] for row in counted[PRIOR_STRICT:]] == [CASE_V52W]
    row87 = counted[86]
    assert row87["ordinal"] == 87
    assert row87["case_id"] == CASE_V52W
    assert row87["candidate_set"] == [CAND_V52W]
    assert row87["carrier_set"] == [CARR_V52W]
    assert row87["minimum_fix_set"] == [FIX_V52W]
    assert row87["aliases"] == []
    assert row87["n_parents"] == 1
    assert row87["authorship_transfer"] is False
    assert row87["leader_strict_case_accepted"] is True
    assert row87["contribution_class"] == "AI_DIRECT_ROOT"
    assert row87["counted_bundled_issues"] == [1, 2]
    assert row87["excluded_bundled_issues"] == [3, 4]
    assert "causal_admission" not in row87
    assert row87["in_fp211_212"] is False
    assert row87["action"] == "APPEND"

    for row in counted:
        for field in GATES:
            assert row[field] == "PASS", (row["case_id"], field, row[field])
        for field in ("candidate_set", "carrier_set", "minimum_fix_set"):
            assert row[field] == sorted(set(row[field]))
            assert all(SHA_RE.fullmatch(item) for item in row[field])
        assert "candidate_fix_edges" not in row
        assert GHSA_RE.fullmatch(row["case_id"])
        assert row["case_id"] not in row["aliases"]
        assert row["counting_unit"] == "first-party GHSA case"

    assert summary["causal_admission"] is False
    assert summary["publication_ready"] is False
    assert summary["integration_ready"] is False
    assert summary["status"] == "HOLD"
    assert summary["public_200_claim_supported"] is False
    assert summary["canonical_strict_count"] == STRICT_COUNT
    prior_append = list(prior["conservation"]["append_identities"])
    assert summary["conservation"]["prior_append_identities"] == prior_append
    assert len(prior_append) == 16
    assert summary["conservation"]["new_append_identities"] == [CASE_V52W]
    assert summary["conservation"]["append_identities"] == prior_append + [CASE_V52W]
    assert len(summary["conservation"]["append_identities"]) == 17
    assert summary["conservation"]["new_identities_append"] is True
    assert summary["conservation"]["appended_strict_rows"] == 1
    auth = manifest["packet_authority"]
    assert auth[-1]["packet"] == build.P_HOSTILE
    assert auth[-1]["role"] == "redteam"
    assert auth[-1]["authority_rank"] == 45
    assert len(auth) == 24
    assert summary["strict_released_case_ids"][:PRIOR_STRICT] == prior["strict_released_case_ids"]
    assert summary["strict_released_case_ids"][PRIOR_STRICT:] == [CASE_V52W]
    assert CASE_V52W not in prior["strict_released_case_ids"]
    assert summary["ledger_sha256"] == build.sha256_file(HERE / "ledger.jsonl")
    assert pins["canonical86_ledger"]["sha256"] == "3150a7925cc31645b00862595d553db49ec5e07076d87e6c42beec401a647ee7"
    assert {row["case_id"] for row in neg["controls"]} == {
        CASE_PIMCORE,
        CASE_HHJV,
        CASE_73HC,
        CASE_282G,
        CASE_45Q4,
        CASE_954P,
    }
    assert cap["leader_strict_case_accepted"] is True
    assert counted[85]["case_id"] == CASE_FRVJ
    return summary


def verify_git() -> None:
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    row87 = counted[86]
    cap = build.load_capsule_v52w()
    assert gitx("rev-parse", f"{CAND_V52W}^") == PARENT_V52W
    assert gitx("rev-parse", f"{CARR_V52W}^") == PARENT_V52W
    assert gitx("rev-parse", f"{FIX_V52W}^") == FIX_PARENT_V52W
    parents = gitx("rev-list", "--parents", "-n", "1", CAND_V52W).split()
    assert parents[0] == CAND_V52W
    assert parents[1:] == [PARENT_V52W]
    subprocess.run([*GIT, "-C", CLONE, "merge-base", "--is-ancestor", PARENT_V52W, CAND_V52W], check=True)
    subprocess.run([*GIT, "-C", CLONE, "merge-base", "--is-ancestor", CARR_V52W, FIX_V52W], check=True)
    subprocess.run([*GIT, "-C", CLONE, "merge-base", "--is-ancestor", CARR_V52W, build.PEEL_180], check=True)
    miss = subprocess.run([*GIT, "-C", CLONE, "merge-base", "--is-ancestor", CAND_V52W, FIX_V52W])
    assert miss.returncode == 1
    assert gitx("rev-parse", f"{CAND_V52W}^{{tree}}") == gitx("rev-parse", f"{CARR_V52W}^{{tree}}")
    assert gitx("rev-parse", f"{CAND_V52W}:{FILE}") == build.BLOB_INTRO
    missing = subprocess.run(
        [*GIT, "-C", CLONE, "cat-file", "-e", f"{PARENT_V52W}:{FILE}"],
        capture_output=True,
        text=True,
    )
    assert missing.returncode != 0
    cand_src = gitx("show", f"{CAND_V52W}:{FILE}")
    assert "allowedHosts" not in cand_src
    assert "maxBodyBytes" not in cand_src
    assert "async function readJsonBody" in cand_src
    fix_src = gitx("show", f"{FIX_V52W}:{FILE}")
    assert "allowedHosts" in fix_src
    assert "maxBodyBytes" in fix_src
    assert gitx("rev-parse", "v1.8.0^{commit}") == build.PEEL_180
    assert gitx("rev-parse", "v1.8.1^{commit}") == build.PEEL_181
    assert gitx("rev-parse", f"v1.8.0:{FILE}") == build.BLOB_180
    assert gitx("rev-parse", f"v1.8.1:{FILE}") == build.BLOB_181
    assert gitx("rev-parse", f"{FIX_V52W}:{FILE}") == build.BLOB_181
    vuln_src = gitx("show", f"v1.8.0:{FILE}")
    assert "allowedHosts" not in vuln_src
    assert "maxBodyBytes" not in vuln_src
    msg = gitx("log", "-1", "--format=%B", CAND_V52W)
    assert "Co-Authored-By: Claude Opus 4.7" in msg
    assert "startHttpServer" in msg
    names = gitx("diff", "--name-only", PARENT_V52W, CAND_V52W)
    assert FILE in names.splitlines()
    assert row87["candidate_set"][0] == cap["object_shas"]["counted_candidate"] == CAND_V52W
    assert row87["carrier_set"][0] == cap["object_shas"]["mainline_carrier"] == CARR_V52W
    assert row87["minimum_fix_set"][0] == cap["object_shas"]["minimum_fix"] == FIX_V52W
    assert row87["candidate_parent"] == PARENT_V52W
    assert row87["carrier_parent"] == PARENT_V52W
    assert row87["fix_parent"] == FIX_PARENT_V52W
    assert REST_164 not in row87["candidate_set"] + row87["carrier_set"] + row87["minimum_fix_set"]
    assert row87["vulnerable_release"]["tarball_sha256"] == build.NPM_180
    assert row87["fixed_release"]["tarball_sha256"] == build.NPM_181
    assert row87["vulnerable_release"]["contains_allowed_hosts"] is False
    assert row87["fixed_release"]["contains_allowed_hosts"] is True


def verify_semantic() -> None:
    rows = load_rows()
    hyp = by_kind(rows, "PRESERVED_HYPOTHESIS")
    pub = by_kind(rows, "PRESERVED_PUBLIC_CASE")
    counted = by_kind(rows, "STRICT_RELEASED_CASE")
    by_key = {row["row_key"]: row for row in hyp}
    assert by_key[FILEBROWSER_NEG]["ordinal"] == 165
    assert by_key[FILEBROWSER_POS]["ordinal"] == 166
    dual = [row for row in pub if row["ordinal"] == 200]
    assert {row["case_id"] for row in dual} == set(ORD200)

    counted_ids = [row["case_id"] for row in counted]
    for banned in (
        CASE_PIMCORE,
        CASE_HHJV,
        CASE_73HC,
        CASE_282G,
        CASE_45Q4,
        CASE_954P,
    ):
        assert banned not in counted_ids
    assert counted_ids.count(CASE_V52W) == 1
    assert counted_ids[-1] == CASE_V52W
    assert counted_ids[-2] == CASE_FRVJ
    assert len(counted_ids) == len(set(counted_ids)) == STRICT_COUNT
    fps = [row["mechanism_fingerprint"] for row in counted]
    assert len(fps) == len(set(fps)) == STRICT_COUNT
    mechs = [row["mechanism_key"] for row in counted]
    assert len(mechs) == len(set(mechs)) == STRICT_COUNT
    assert build.MECH_FP_V52W in fps
    assert build.MECH_KEY_V52W in mechs
    neg = build.load_negative()
    for ctrl in neg["controls"]:
        assert ctrl["case_id"] not in counted_ids
        assert ctrl["verdict"] == "REJECT"
    summary = build.load_json(HERE / "summary.json")
    report = (HERE / "report.md").read_text()
    assert "more than 200" not in report.lower()
    assert "Causal admission is false" in report
    assert "canonical strict count 87" in report
    assert counted[86]["admission_source"] == "v52w_hostile_redteam_keep"
    assert not any(row["admission_source"] == "worker_pass" for row in counted)
    for name in ("ledger.jsonl", "summary.json", "manifest.json", "report.md", "v52w_acceptance.json"):
        blob = (HERE / name).read_text()
        assert "/home/hanqing/.cache" not in blob
        build.assert_no_leak(blob)
        for line in blob.splitlines():
            assert line == line.rstrip(), name
    for name in ("summary.json", "manifest.json", "report.md", "v52w_acceptance.json"):
        blob = (HERE / name).read_text()
        assert "pages/ghsa/" not in blob
        assert "pages/GHSA" not in blob
    for row in counted[PRIOR_STRICT:]:
        assert not any("pages/ghsa/" in item for item in row["first_party_source_refs"])
        assert "clone_path" not in row
        assert "clone" not in row
    assert summary["counts"]["keep_v52w"] == 1
    assert "bundled_issue_3_readonly" in summary["excluded"]
    assert "bundled_issue_4_compose_bind" in summary["excluded"]
    assert "rest_body_164" in summary["excluded"]


def verify() -> tuple[dict, list[dict]]:
    summary = verify_structural()
    verify_git()
    verify_semantic()
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    return summary, counted


def main() -> None:
    summary, counted = verify()
    print(
        "PASS: canonical87 HOLD structural+git+semantic; "
        f"counted={len(counted)}; publication=HOLD"
    )
    assert summary["counts"]["strict_released_first_party_ghsa"] == len(counted) == STRICT_COUNT
    assert summary["integration_ready"] is False
    assert summary["publication_ready"] is False
    assert summary["causal_admission"] is False
    assert summary["public_200_claim_supported"] is False
    assert counted[-1]["case_id"] == CASE_V52W


if __name__ == "__main__":
    main()
