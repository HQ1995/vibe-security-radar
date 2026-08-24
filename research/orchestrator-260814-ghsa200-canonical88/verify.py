#!/usr/bin/env python3
"""Distinct structural, Git, and semantic verifiers. Fail-fast. Clean stderr on success."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

import build


HERE = Path(__file__).resolve().parent
GATES = build.GATES
HAN = build.HAN
SHA_RE = build.SHA_RE
GHSA_RE = build.GHSA_RE
PRIOR_STRICT = build.PRIOR_STRICT
STRICT_COUNT = build.STRICT_COUNT
CASE_8RW6 = build.CASE_8RW6
CASE_V52W = build.CASE_V52W
CASE_FRVJ = build.CASE_FRVJ
CAND_8RW6 = build.CAND_8RW6
PARENT_8RW6 = build.PARENT_8RW6
FIX_8RW6 = build.FIX_8RW6
FIX_PARENT_8RW6 = build.FIX_PARENT_8RW6
HUMAN_DOC = build.HUMAN_DOC
CASE_PIMCORE = build.CASE_PIMCORE
CASE_HHJV = build.CASE_HHJV
CASE_73HC = build.CASE_73HC
CASE_282G = build.CASE_282G
CASE_45Q4 = build.CASE_45Q4
CASE_954P = build.CASE_954P
CASE_C8JX = build.CASE_C8JX
CASE_FPXG = build.CASE_FPXG
CASE_6G9V = build.CASE_6G9V
CASE_9722 = build.CASE_9722
FILEBROWSER_NEG = build.FILEBROWSER_NEG
FILEBROWSER_POS = build.FILEBROWSER_POS
ORD200 = build.ORD200
FILE = build.FILE
OUTF = build.OUTF
RED = build.RED
GIT = (
    "/usr/bin/git",
    "--no-optional-locks",
    "-c",
    "gc.auto=0",
    "-c",
    "maintenance.auto=false",
)
GIT_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp",
    "LC_ALL": "C",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_NO_LAZY_FETCH": "1",
}
CLONE = str(
    Path("/home")
    / "hanqing"
    / ".cache"
    / "cve-analyzer"
    / "repos"
    / "surrealdb_surrealdb"
)
UA = "ai-slop-canonical88"


def load_rows() -> list[dict]:
    return build.load_jsonl(HERE / "ledger.jsonl")


def by_kind(rows: list[dict], kind: str) -> list[dict]:
    return [row for row in rows if row["record_kind"] == kind]


def gitx(*args: str, repo: str = CLONE) -> str:
    proc = subprocess.run(
        [*GIT, "-C", repo, *args],
        capture_output=True,
        text=True,
        check=True,
        env=GIT_ENV,
    )
    return proc.stdout.strip()


def git_ok(*args: str, repo: str = CLONE) -> subprocess.CompletedProcess:
    return subprocess.run(
        [*GIT, "-C", repo, *args],
        capture_output=True,
        text=True,
        env=GIT_ENV,
    )


def ls_tree_blob(repo: str, rev: str, rel: str) -> str:
    out = gitx("ls-tree", rev, "--", rel, repo=repo)
    if not out:
        return ""
    return out.split()[2]


def fetch_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


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
    cap = build.load_capsule_8rw6()
    neg = build.load_negative()
    prior = build.load_json(build.ROOT / build.P_C87_SUM)
    prior_rows = build.load_jsonl(build.ROOT / build.P_C87_LEDGER)
    prior_text = (build.ROOT / build.P_C87_LEDGER).read_text()
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
    assert [row["case_id"] for row in counted[PRIOR_STRICT:]] == [CASE_8RW6]
    row88 = counted[87]
    assert row88["ordinal"] == 88
    assert row88["case_id"] == CASE_8RW6
    assert row88["candidate_set"] == [CAND_8RW6]
    assert row88["carrier_set"] == []
    assert row88["minimum_fix_set"] == [FIX_8RW6]
    assert row88["aliases"] == []
    assert row88["n_parents"] == 1
    assert row88["authorship_transfer"] is False
    assert row88["leader_strict_case_accepted"] is True
    assert row88["contribution_class"] == "AI_NEW_SURFACE_CONTRIBUTOR"
    assert row88["whole_ghsa_direct_root"] is False
    assert row88["human_pluck_doc_siblings_excluded"] is True
    assert row88["production_default_planner"] == "best-effort"
    assert row88["record_id_reuses_pipeline_filter"] is True
    assert "causal_admission" not in row88
    assert row88["in_fp211_212"] is False
    assert row88["action"] == "APPEND"

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
    assert len(prior_append) == 17
    assert summary["conservation"]["new_append_identities"] == [CASE_8RW6]
    assert summary["conservation"]["append_identities"] == prior_append + [CASE_8RW6]
    assert len(summary["conservation"]["append_identities"]) == 18
    assert summary["conservation"]["new_identities_append"] is True
    assert summary["conservation"]["appended_strict_rows"] == 1
    auth = manifest["packet_authority"]
    assert auth[-1]["packet"] == build.P_HOSTILE
    assert auth[-1]["role"] == "redteam"
    assert auth[-1]["authority_rank"] == 46
    assert len(auth) == 25
    assert summary["strict_released_case_ids"][:PRIOR_STRICT] == prior["strict_released_case_ids"]
    assert summary["strict_released_case_ids"][PRIOR_STRICT:] == [CASE_8RW6]
    assert CASE_8RW6 not in prior["strict_released_case_ids"]
    assert summary["ledger_sha256"] == build.sha256_file(HERE / "ledger.jsonl")
    assert pins["canonical87_ledger"]["sha256"] == "b6dc7e781017e60a94725696b5a08b229a5cb026ffd098e6306e9a8941f9fdbe"
    assert {row["case_id"] for row in neg["controls"]} == {
        CASE_PIMCORE,
        CASE_HHJV,
        CASE_73HC,
        CASE_282G,
        CASE_45Q4,
        CASE_954P,
    }
    assert cap["leader_strict_case_accepted"] is True
    assert counted[86]["case_id"] == CASE_V52W
    return summary


def verify_git() -> None:
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    row88 = counted[87]
    cap = build.load_capsule_8rw6()
    assert gitx("rev-parse", f"{CAND_8RW6}^") == PARENT_8RW6
    assert gitx("rev-parse", f"{FIX_8RW6}^") == FIX_PARENT_8RW6
    parents = gitx("rev-list", "--parents", "-n", "1", CAND_8RW6).split()
    assert parents[0] == CAND_8RW6
    assert parents[1:] == [PARENT_8RW6]
    subprocess.run(
        [*GIT, "-C", CLONE, "merge-base", "--is-ancestor", PARENT_8RW6, CAND_8RW6],
        check=True,
        env=GIT_ENV,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [*GIT, "-C", CLONE, "merge-base", "--is-ancestor", CAND_8RW6, FIX_8RW6],
        check=True,
        env=GIT_ENV,
        capture_output=True,
        text=True,
    )
    names = gitx("diff", "--name-only", PARENT_8RW6, CAND_8RW6)
    assert FILE in names.splitlines()
    assert OUTF not in names.splitlines()
    assert RED not in names.splitlines()
    assert ls_tree_blob(CLONE, CAND_8RW6, FILE) == build.BLOB_CAND
    assert ls_tree_blob(CLONE, PARENT_8RW6, FILE) == build.BLOB_PARENT
    assert ls_tree_blob(CLONE, FIX_8RW6, FILE) == build.BLOB_314
    assert ls_tree_blob(CLONE, FIX_PARENT_8RW6, FILE) == build.BLOB_313
    assert ls_tree_blob(CLONE, PARENT_8RW6, OUTF) == ""
    assert ls_tree_blob(CLONE, CAND_8RW6, OUTF) == ""
    msg = gitx("log", "-1", "--format=%B", CAND_8RW6)
    assert "Co-authored-by: Claude Opus 4.7 (1M context) <noreply@anthropic.com>" in msg
    fix_msg = gitx("log", "-1", "--format=%B", FIX_8RW6)
    assert "Claude" not in fix_msg
    assert "Copilot" not in fix_msg
    tags = gitx("tag")
    assert "v3.1.3" not in tags.splitlines()
    assert "v3.1.4" not in tags.splitlines()

    remote = subprocess.run(
        [
            *GIT,
            "ls-remote",
            "https://github.com/surrealdb/surrealdb.git",
            "refs/tags/v3.1.3",
            "refs/tags/v3.1.4",
        ],
        capture_output=True,
        text=True,
        check=True,
        env=GIT_ENV,
    ).stdout
    assert f"{build.PEEL_313}\trefs/tags/v3.1.3" in remote
    assert f"{build.PEEL_314}\trefs/tags/v3.1.4" in remote

    tmp = tempfile.mkdtemp(prefix="canonical88-8rw6-")
    try:
        clone = str(Path(tmp) / "clone")
        subprocess.run([*GIT, "init", "-q", clone], check=True, env=GIT_ENV, capture_output=True, text=True)
        subprocess.run(
            [*GIT, "-C", clone, "remote", "add", "origin", "https://github.com/surrealdb/surrealdb.git"],
            check=True,
            env=GIT_ENV,
            capture_output=True,
            text=True,
        )
        alt = Path(clone) / ".git" / "objects" / "info" / "alternates"
        assert not alt.exists()
        subprocess.run(
            [
                *GIT,
                "-C",
                clone,
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-recurse-submodules",
                "--filter=blob:none",
                "--depth=1",
                "origin",
                "refs/tags/v3.1.3:refs/tags/v3.1.3",
                "refs/tags/v3.1.4:refs/tags/v3.1.4",
                f"{FIX_8RW6}:refs/heads/fix",
                f"{FIX_PARENT_8RW6}:refs/heads/fixparent",
            ],
            check=True,
            env=GIT_ENV,
            capture_output=True,
            text=True,
        )
        assert gitx("rev-parse", "v3.1.3^{commit}", repo=clone) == build.PEEL_313
        assert gitx("rev-parse", "v3.1.4^{commit}", repo=clone) == build.PEEL_314
        assert gitx("rev-parse", "v3.1.4^{commit}", repo=clone) != FIX_8RW6
        assert ls_tree_blob(clone, "v3.1.3", FILE) == build.BLOB_313
        assert ls_tree_blob(clone, "v3.1.4", FILE) == build.BLOB_314
        assert ls_tree_blob(clone, "v3.1.3", OUTF) == build.BLOB_313_OUT
        assert ls_tree_blob(clone, "v3.1.4", OUTF) == build.BLOB_314_OUT
        assert ls_tree_blob(clone, "v3.1.3", RED) == build.BLOB_313_RED
        assert ls_tree_blob(clone, "v3.1.4", RED) == build.BLOB_314_RED
        assert ls_tree_blob(clone, "fix", FILE) == build.BLOB_314
        assert ls_tree_blob(clone, "fixparent", FILE) == build.BLOB_313
        cmpf = json.loads(
            fetch_bytes(
                f"https://api.github.com/repos/surrealdb/surrealdb/compare/{FIX_8RW6}...v3.1.4"
            )
        )
        assert cmpf["status"] == "diverged"
        cmpc = json.loads(
            fetch_bytes(
                f"https://api.github.com/repos/surrealdb/surrealdb/compare/{CAND_8RW6}...v3.1.3"
            )
        )
        assert cmpc["status"] == "ahead"
        assert cmpc["behind_by"] == 0
        assert cmpc["merge_base_commit"]["sha"] == CAND_8RW6

        parent_fn = (build.ROOT / build.P_HOSTILE / "diffs/parent.filter_fields.rs").read_text()
        cand_fn = (build.ROOT / build.P_HOSTILE / "diffs/cand.filter_fields.rs").read_text()
        fix_fn = (build.ROOT / build.P_HOSTILE / "diffs/fix.filter_fields.rs").read_text()
        for ver, want_sha, want_fn, has_rev in (
            ("3.1.3", build.CRATE_313, cand_fn, False),
            ("3.1.4", build.CRATE_314, fix_fn, True),
        ):
            crate = Path(tmp) / f"surrealdb-core-{ver}.crate"
            crate.write_bytes(
                fetch_bytes(
                    f"https://static.crates.io/crates/surrealdb-core/surrealdb-core-{ver}.crate"
                )
            )
            assert hashlib.sha256(crate.read_bytes()).hexdigest() == want_sha
            with tarfile.open(crate, "r:gz") as tf:
                inner = f"surrealdb-core-{ver}/src/exec/operators/scan/pipeline.rs"
                data = tf.extractfile(inner).read()
            extracted = build.extract_filter_fields(data.decode("utf-8"))
            assert extracted == want_fn
            assert ("into_iter().rev()" in extracted) is has_rev
        assert "obj.remove" in parent_fn
        assert "value.cut" not in parent_fn
        assert "for path in original.each(&idiom.0)" in cand_fn
        assert "into_iter().rev()" not in cand_fn
        assert "into_iter().rev()" in fix_fn
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    facts_git = build.load_json(build.ROOT / build.P_HOSTILE / "facts/git.json")
    assert facts_git["production_default_planner"] == "best-effort"
    assert facts_git["record_id_reuses_pipeline_filter"] is True
    assert facts_git["pluck_already_had_each_forward_cut"] is True
    assert facts_git["candidate_does_not_touch_pluck_output_reduce"] is True
    facts_rel = build.load_json(build.ROOT / build.P_HOSTILE / "facts/releases.json")
    assert facts_rel["fix_sha_not_ancestor_of_v3_1_4"] is True
    assert facts_rel["fix_bytes_present_on_v3_1_4"] is True
    assert row88["candidate_set"][0] == cap["object_shas"]["counted_candidate"] == CAND_8RW6
    assert row88["minimum_fix_set"][0] == cap["object_shas"]["minimum_fix"] == FIX_8RW6
    assert row88["carrier_set"] == []
    assert row88["candidate_parent"] == PARENT_8RW6
    assert row88["fix_parent"] == FIX_PARENT_8RW6
    assert HUMAN_DOC not in row88["candidate_set"] + row88["minimum_fix_set"]
    assert row88["vulnerable_release"]["crates_io_surrealdb_core_checksum"] == build.CRATE_313
    assert row88["fixed_release"]["crates_io_surrealdb_core_checksum"] == build.CRATE_314
    assert row88["vulnerable_release"]["pipeline_has_forward_each_cut"] is True
    assert row88["fixed_release"]["contains_fix_sha_as_ancestor"] is False
    assert row88["fixed_release"]["contains_fix_bytes"] is True


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
        CASE_C8JX,
        CASE_FPXG,
        CASE_6G9V,
        CASE_9722,
    ):
        assert banned not in counted_ids
    assert counted_ids.count(CASE_8RW6) == 1
    assert counted_ids[-1] == CASE_8RW6
    assert counted_ids[-2] == CASE_V52W
    assert len(counted_ids) == len(set(counted_ids)) == STRICT_COUNT
    fps = [row["mechanism_fingerprint"] for row in counted]
    assert len(fps) == len(set(fps)) == STRICT_COUNT
    mechs = [row["mechanism_key"] for row in counted]
    assert len(mechs) == len(set(mechs)) == STRICT_COUNT
    assert build.MECH_FP_8RW6 in fps
    assert build.MECH_KEY_8RW6 in mechs
    neg = build.load_negative()
    for ctrl in neg["controls"]:
        assert ctrl["case_id"] not in counted_ids
        assert ctrl["verdict"] == "REJECT"
    summary = build.load_json(HERE / "summary.json")
    report = (HERE / "report.md").read_text()
    assert "more than 200" not in report.lower()
    assert "Causal admission is false" in report
    assert "canonical strict count 88" in report
    assert counted[87]["admission_source"] == "8rw6_hostile_redteam_keep"
    assert not any(row["admission_source"] == "worker_pass" for row in counted)
    for name in ("ledger.jsonl", "summary.json", "manifest.json", "report.md", "8rw6_acceptance.json"):
        blob = (HERE / name).read_text()
        assert "/home/hanqing/.cache" not in blob
        build.assert_no_leak(blob)
        for line in blob.splitlines():
            assert line == line.rstrip(), name
    for name in ("summary.json", "manifest.json", "report.md", "8rw6_acceptance.json"):
        blob = (HERE / name).read_text()
        assert "pages/ghsa/" not in blob
        assert "pages/GHSA" not in blob
    for row in counted[PRIOR_STRICT:]:
        assert not any("pages/ghsa/" in item for item in row["first_party_source_refs"])
        assert "clone_path" not in row
        assert "clone" not in row
    assert summary["counts"]["keep_8rw6"] == 1
    assert "whole_ghsa_direct_root_8rw6" in summary["excluded"]
    assert "human_pluck_select_8rw6" in summary["excluded"]
    assert "human_doc_output_reduce_8rw6" in summary["excluded"]


def verify() -> tuple[dict, list[dict]]:
    summary = verify_structural()
    verify_git()
    verify_semantic()
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    return summary, counted


def main() -> None:
    summary, counted = verify()
    print(
        "PASS: canonical88 HOLD structural+git+semantic; "
        f"counted={len(counted)}; publication=HOLD"
    )
    assert summary["counts"]["strict_released_first_party_ghsa"] == len(counted) == STRICT_COUNT
    assert summary["integration_ready"] is False
    assert summary["publication_ready"] is False
    assert summary["causal_admission"] is False
    assert summary["public_200_claim_supported"] is False
    assert counted[-1]["case_id"] == CASE_8RW6


if __name__ == "__main__":
    main()
