#!/usr/bin/env python3
"""Distinct structural, Git, and semantic verifiers. Fail-fast. Clean stderr on success."""

from __future__ import annotations

import subprocess
from pathlib import Path

import build


HERE = Path(__file__).resolve().parent
GATES = build.GATES
REMEDIATION_GATE = build.REMEDIATION_GATE
HAN = build.HAN
SHA_RE = build.SHA_RE
GHSA_RE = build.GHSA_RE
PRIOR_STRICT = build.PRIOR_STRICT
STRICT_COUNT = build.STRICT_COUNT
CASE_FRVJ = build.CASE_FRVJ
CASE_R2WG = build.CASE_R2WG
ALIAS_FRVJ = build.ALIAS_FRVJ
CAND_FRVJ = build.CAND_FRVJ
PARENT_FRVJ = build.PARENT_FRVJ
FIX_FRVJ = build.FIX_FRVJ
FIX_PARENT_FRVJ = build.FIX_PARENT_FRVJ
CASE_PIMCORE = build.CASE_PIMCORE
CASE_HHJV = build.CASE_HHJV
CASE_73HC = build.CASE_73HC
CASE_282G = build.CASE_282G
CASE_45Q4 = build.CASE_45Q4
CASE_954P = build.CASE_954P
CASE_8359 = build.CASE_8359
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
    / "open-webui_open-webui"
)
FILE = "backend/open_webui/routers/terminals.py"


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
    cap = build.load_capsule_frvj()
    neg = build.load_negative()
    prior = build.load_json(build.ROOT / build.P_C85_SUM)
    prior_rows = build.load_jsonl(build.ROOT / build.P_C85_LEDGER)
    prior_text = (build.ROOT / build.P_C85_LEDGER).read_text()
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
    assert [row["case_id"] for row in counted[PRIOR_STRICT:]] == [CASE_FRVJ]
    row86 = counted[85]
    assert row86["ordinal"] == 86
    assert row86["case_id"] == CASE_FRVJ
    assert row86["candidate_set"] == [CAND_FRVJ]
    assert row86["carrier_set"] == []
    assert row86["minimum_fix_set"] == [FIX_FRVJ]
    assert row86["aliases"] == [ALIAS_FRVJ]
    assert row86["n_parents"] == 1
    assert row86["authorship_transfer"] is False
    assert row86["leader_strict_case_accepted"] is True
    assert row86["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    assert row86[REMEDIATION_GATE] == "PASS"
    assert row86["distinct_from_r2wg"] is True
    assert "causal_admission" not in row86
    assert row86["in_fp211_212"] is False
    assert row86["action"] == "APPEND"

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
    assert len(prior_append) == 15
    assert summary["conservation"]["new_append_identities"] == [CASE_FRVJ]
    assert summary["conservation"]["append_identities"] == prior_append + [CASE_FRVJ]
    assert len(summary["conservation"]["append_identities"]) == 16
    assert summary["conservation"]["new_identities_append"] is True
    assert summary["conservation"]["appended_strict_rows"] == 1
    auth = manifest["packet_authority"]
    assert auth[-2]["packet"] == build.P_WORKER
    assert auth[-2]["role"] == "worker"
    assert auth[-1]["packet"] == build.P_HOSTILE
    assert auth[-1]["role"] == "redteam"
    assert auth[-1]["authority_rank"] == 44
    assert len(auth) == 23
    assert summary["strict_released_case_ids"][:PRIOR_STRICT] == prior["strict_released_case_ids"]
    assert summary["strict_released_case_ids"][PRIOR_STRICT:] == [CASE_FRVJ]
    assert CASE_FRVJ not in prior["strict_released_case_ids"]
    assert summary["ledger_sha256"] == build.sha256_file(HERE / "ledger.jsonl")
    assert pins["canonical85_ledger"]["sha256"] == "2927924603a76a2565d9c244c3b79f70d4693c127f1bc6fcc63e8099172ba568"
    assert {row["case_id"] for row in neg["controls"]} == {
        CASE_PIMCORE,
        CASE_HHJV,
        CASE_73HC,
        CASE_282G,
        CASE_45Q4,
        CASE_954P,
    }
    assert cap["leader_strict_case_accepted"] is True
    assert counted[84]["case_id"] == CASE_8359
    return summary


def verify_git() -> None:
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    row86 = counted[85]
    cap = build.load_capsule_frvj()
    assert gitx("rev-parse", f"{CAND_FRVJ}^") == PARENT_FRVJ
    assert gitx("rev-parse", f"{FIX_FRVJ}^") == FIX_PARENT_FRVJ
    parents = gitx("rev-list", "--parents", "-n", "1", CAND_FRVJ).split()
    assert parents[0] == CAND_FRVJ
    assert parents[1:] == [PARENT_FRVJ]
    subprocess.run([*GIT, "-C", CLONE, "merge-base", "--is-ancestor", PARENT_FRVJ, CAND_FRVJ], check=True)
    subprocess.run([*GIT, "-C", CLONE, "merge-base", "--is-ancestor", CAND_FRVJ, FIX_FRVJ], check=True)
    names = gitx("diff", "--name-only", PARENT_FRVJ, CAND_FRVJ)
    assert names == FILE
    cand_diff = gitx("diff", PARENT_FRVJ, CAND_FRVJ, "--", FILE)
    assert "for _ in range(8):" in cand_diff
    assert "decoded = unquote(path)" in cand_diff
    fix_diff = gitx("diff", FIX_PARENT_FRVJ, FIX_FRVJ, "--", FILE)
    assert "if unquote(decoded) != decoded:" in fix_diff
    msg = gitx("log", "-1", "--format=%B", CAND_FRVJ)
    assert "Co-authored-by: Claude Opus 4.7" in msg
    assert row86["candidate_set"][0] == cap["object_shas"]["counted_candidate"] == CAND_FRVJ
    assert row86["minimum_fix_set"][0] == cap["object_shas"]["minimum_fix"] == FIX_FRVJ
    assert row86["carrier_set"] == []
    assert row86["candidate_parent"] == PARENT_FRVJ
    assert row86["fix_parent"] == FIX_PARENT_FRVJ
    assert row86["vulnerable_release"]["sha256"] == build.WHEEL_096
    assert row86["fixed_release"]["sha256"] == build.WHEEL_010
    assert row86["vulnerable_release"]["contains_fail_closed"] is False
    assert row86["fixed_release"]["contains_fail_closed"] is True


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
        CASE_R2WG,
        ALIAS_FRVJ,
    ):
        assert banned not in counted_ids
    assert counted_ids.count(CASE_FRVJ) == 1
    assert counted_ids[-1] == CASE_FRVJ
    assert len(counted_ids) == len(set(counted_ids)) == STRICT_COUNT
    fps = [row["mechanism_fingerprint"] for row in counted]
    assert len(fps) == len(set(fps)) == STRICT_COUNT
    mechs = [row["mechanism_key"] for row in counted]
    assert len(mechs) == len(set(mechs)) == STRICT_COUNT
    assert build.MECH_FP_FRVJ in fps
    assert build.MECH_KEY_FRVJ in mechs
    cve_aliases = [item for row in counted for item in row["aliases"] if item.startswith("CVE-")]
    assert ALIAS_FRVJ in cve_aliases
    assert ALIAS_FRVJ not in counted_ids
    neg = build.load_negative()
    for ctrl in neg["controls"]:
        assert ctrl["case_id"] not in counted_ids
        assert ctrl["verdict"] == "REJECT"
    summary = build.load_json(HERE / "summary.json")
    report = (HERE / "report.md").read_text()
    assert "more than 200" not in report.lower()
    assert "Causal admission is false" in report
    assert "canonical strict count 86" in report
    assert counted[85]["admission_source"] == "frvj_hostile2_redteam_keep"
    assert not any(row["admission_source"] == "worker_pass" for row in counted)
    for name in ("ledger.jsonl", "summary.json", "manifest.json", "report.md", "frvj_acceptance.json"):
        blob = (HERE / name).read_text()
        assert "/home/hanqing/.cache" not in blob
        build.assert_no_leak(blob)
        for line in blob.splitlines():
            assert line == line.rstrip(), name
    for name in ("summary.json", "manifest.json", "report.md", "frvj_acceptance.json"):
        blob = (HERE / name).read_text()
        assert "pages/ghsa/" not in blob
        assert "pages/GHSA" not in blob
    for row in counted[PRIOR_STRICT:]:
        assert not any("pages/ghsa/" in item for item in row["first_party_source_refs"])
    for row in counted[PRIOR_STRICT:]:
        assert "clone_path" not in row
        assert "clone" not in row
    assert summary["counts"]["keep_frvj"] == 1


def verify() -> tuple[dict, list[dict]]:
    summary = verify_structural()
    verify_git()
    verify_semantic()
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    return summary, counted


def main() -> None:
    summary, counted = verify()
    print(
        "PASS: canonical86 HOLD structural+git+semantic; "
        f"counted={len(counted)}; publication=HOLD"
    )
    assert summary["counts"]["strict_released_first_party_ghsa"] == len(counted) == STRICT_COUNT
    assert summary["integration_ready"] is False
    assert summary["publication_ready"] is False
    assert summary["causal_admission"] is False
    assert summary["public_200_claim_supported"] is False
    assert counted[-1]["case_id"] == CASE_FRVJ


if __name__ == "__main__":
    main()
