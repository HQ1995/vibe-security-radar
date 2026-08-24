#!/usr/bin/env zsh
set -euo pipefail

# Fail-fast read-only offline replay.
# Do not fetch, clone, commit, push, or rerun ranking.
# Success produces no stderr (empty-stderr self-check).

export GIT_OPTIONAL_LOCKS=0

ROOT=/home/hanqing/agents/ai-slop
cd "$ROOT"

OWNED=autoresearch/herdr-260814-ghsa200-directroot-batch17-grok46-xhigh
FIRST=autoresearch/herdr-260813-ghsa200-directroot-mining-grok46-xhigh
ADB=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database

hash_file() {
  sha256sum -- "$1" | awk '{print $1}'
}

[[ -f "$OWNED/result.json" ]]
[[ -f "$OWNED/cases.jsonl" ]]
[[ -f "$OWNED/report.md" ]]
[[ -f "$OWNED/replay.sh" ]]
[[ -f "$OWNED/work/selected-30.jsonl" ]]
[[ -f "$FIRST/work/selected-30.jsonl" ]]
[[ -f "$FIRST/work/rank-hits.jsonl" ]]
[[ -d "$ADB/.git" ]]

[[ "$(hash_file autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md)" == "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-ghsa200-leader/baseline.json)" == "d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl)" == "e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl)" == "1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl)" == "0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh/result.json)" == "c50b878583f3b09f37d7c88638ea179e75cf6b0ccf2e4ade689f2d673f7b0829" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh/cases.jsonl)" == "d4d3c96ba0a60214971ab88f3de7adce1edfc27f39a388906600aad91b5c1889" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-commitfirst-gn/ai-commit-scans.jsonl)" == "a6d7ca1584dbeb1596c57643092df0178001925efe0de60ca3eee5f72182481a" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-commitfirst-af/ai-commits.jsonl)" == "9659e93e82df4428df361507c6728ac83988211b0282ffbc3c12e3aba529d6d0" ]]
[[ "$(hash_file /home/hanqing/.cache/ghsa200-worker-clones/commit-oz/work/ai_mine.jsonl)" == "047bbb068b09194a59a934117fec1448563e073147bf2e005d53f427bdc8c18a" ]]
[[ "$(hash_file "$FIRST/work/selected-30.jsonl")" == "908f64f5f00195dae78574e86e9379f0b65cdd34c92ed1217c18702e35c59365" ]]
[[ "$(hash_file "$FIRST/work/rank-hits.jsonl")" == "7247f2cd6d3835385eb96a1acad945702b15cd8a618b0465bf73551de0af7e49" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-canonical72-dedupe-grok46-medium/result.json)" == "fb3b97c7b5d207119cc22d255ba48cbda568d56c8fffb447fb0e58ac8878f4fb" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json)" == "699f6160b6ecb9c9ce2cdae257c9a12dbdf4f7ef8a925196fcfd4fcf0b1140d8" ]]
[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$ADB" rev-parse HEAD)" == "a42c436870111aa3f221257c9d56126a93173ccc" ]]
[[ "$(hash_file "$OWNED/work/selected-30.jsonl")" == "a35fe8a5135737df2920c26d5a0f1c9e00afca6300dc0d07664848d15c2ff1cd" ]]
[[ "$(hash_file autoresearch/herdr-260814-ghsa200-directroot-batch15-grok46-high/work/selected-30.jsonl)" == "743e0e1b9d738e087cfb42dadb252d3aeb82b7b19b069146c9e5c608c9f651e5" ]]
[[ "$(hash_file autoresearch/herdr-260814-ghsa200-directroot-batch16-grok46-medium/work/selected-30.jsonl)" == "0bd6962152df1f674afa4257eb396b94db29234f75c6b6a6409e58a1249dad00" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-directroot-batch3-grok46-xhigh/work/selected-30.jsonl)" == "$(hash_file autoresearch/herdr-260814-ghsa200-directroot-batch3-grok46-xhigh/work/selected-30.jsonl)" ]]

python3 - "$OWNED" "$FIRST" <<'PY'
import hashlib, json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
first = Path(sys.argv[2])
han = re.compile(r"[\u3400-\u9fff]")
for name in ("cases.jsonl", "report.md", "replay.sh", "result.json"):
    text = (owned / name).read_text(encoding="utf-8")
    assert text, name
    assert not han.search(text), name

res = json.loads((owned / "result.json").read_text())
for name, digest in res["artifact_hashes"].items():
    got = hashlib.sha256((owned / name).read_bytes()).hexdigest()
    assert got == digest, (name, got, digest)

assert res["status"] == "TERMINAL"
assert res["hold"] is True
assert res["publication_status"] == "HOLD"
assert res["causal_admission"] is False
assert res["worker_pass_is_proposal_only"] is True
assert res["hard_terminal_checkpoint"] is True
assert res["discovery_stopped"] is True
assert res["analysis_stopped"] is True
assert res["final_round_checkpoint"]["final_round"] is True
assert res["final_round_checkpoint"]["expansion_stopped"] is True
assert res["final_round_checkpoint"]["no_further_candidates_inspected"] is True
assert res["final_round_checkpoint"]["assigned"] == 30
assert res["final_round_checkpoint"]["reviewed"] == 30
assert res["final_round_checkpoint"]["unreviewed"] == 320
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 30
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 0
assert res["counts"]["assigned"] == 30
assert res["counts"]["reviewed"] == 30
assert res["counts"]["unreviewed"] == 320
assert res["counts"]["countable_pass"] == 0
assert res["proposed_pass_ids"] == []
assert res["claim_boundary"]["more_than_200_claim_supported_by_this_review"] is False
assert set(res["dispositions"]) == {"PASS", "REJECT", "NARROW", "UNKNOWN", "BLOCKED"}

cons = res["conservation"]
assert cons["assigned"] == 30
assert cons["reviewed"] == 30
assert cons["unreviewed"] == 320
assert cons["incoming_unreviewed_hits"] == 350
assert cons["prior_directroot_reviewed"] == 480
assert cons["prior_directroot_reviewed"] + cons["deep_reviewed"] + cons["unreviewed_hits"] + cons["rank_misses"] == cons["rank_pool"]
assert cons["assigned_equals_reviewed"] is True
assert cons["selected_equals_ranked_481_to_510"] is True
assert 480 + 30 + 320 + 2643 == 3473
assert cons["stale_260813_batch3_counted_once"] is True

assigned = ["GHSA-JJ6Q-RRRF-H66H", "GHSA-XH72-V6V9-MWHC", "GHSA-9CP7-J3F8-P5JX", "GHSA-GJM7-HW8F-73RQ", "GHSA-QRP5-GFW2-GXV4", "GHSA-8M29-FPQ5-89JJ", "GHSA-3F6H-2HRP-W5WX", "GHSA-FVCV-3M26-PCQX", "GHSA-GHM9-CR32-G9QJ", "GHSA-4X48-CGF9-Q33F", "GHSA-V2WJ-Q39Q-566R", "GHSA-WWFP-W96M-C6X8", "GHSA-3JR7-6HQP-X679", "GHSA-525J-HQQ2-66R4", "GHSA-CHFM-XGC4-47RJ", "GHSA-3G92-F9CH-QJCM", "GHSA-5GFJ-64GH-MGMW", "GHSA-3P68-RC4W-QGX5", "GHSA-HVC7-763R-4F3H", "GHSA-38C5-483C-4QQP", "GHSA-CMXV-58FP-FM3G", "GHSA-FVX6-PJ3R-5Q4Q", "GHSA-49CG-279W-M73X", "GHSA-8H88-GXP3-J7PG", "GHSA-28XX-PPPM-VQFF", "GHSA-7R9J-R86Q-7G45", "GHSA-XW59-HVM2-8PJ6", "GHSA-88GM-J2WX-58H6", "GHSA-G87C-R2JP-293W", "GHSA-89GG-P5R5-Q6R4"]
cases = [json.loads(line) for line in (owned / "cases.jsonl").read_text().splitlines() if line.strip()]
assert len(cases) == 30
ids = [c["case_id"] for c in cases]
assert ids == assigned
assert ids == res["selection"]["selected_ids"]
sel_file = [json.loads(l)["ghsa_id"] for l in (owned / "work/selected-30.jsonl").read_text().splitlines() if l.strip()]
assert ids == sel_file
assert all(c["worker_verdict"] == "REJECT" for c in cases)
assert all(c["countable"] is False for c in cases)
assert all(c["causal_admission"] is False for c in cases)
assert all(c["english_only"] is True for c in cases)

gates = ["identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
for row in cases:
    failed = [g for g in gates if row[g] != "PASS"]
    assert failed, row["case_id"]
    assert row["identity_gate"] == "PASS"

def load_ids(path, key):
    p = Path(path)
    if not p.exists():
        return set()
    out = set()
    for line in p.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        val = row.get(key) or row.get("case_id") or row.get("ghsa_id")
        if isinstance(val, str) and val.upper().startswith("GHSA-"):
            out.add(val.upper())
    return out

c73 = set(json.loads(Path("autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json").read_text())["strict_released_case_ids"])
assert not (set(ids) & c73)
stale_b3 = load_ids("autoresearch/herdr-260813-ghsa200-directroot-batch3-grok46-xhigh/work/selected-30.jsonl", "ghsa_id")
formal_b3 = load_ids("autoresearch/herdr-260814-ghsa200-directroot-batch3-grok46-xhigh/work/selected-30.jsonl", "ghsa_id")
assert stale_b3 == formal_b3
prior_dirs = [
    first / "work/selected-30.jsonl",
    Path("autoresearch/herdr-260813-ghsa200-directroot-batch2-grok46-xhigh/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260813-ghsa200-directroot-batch3-grok46-xhigh/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch3-grok46-xhigh/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch4-grok46-high/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch5-grok46-medium/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch6-grok46-low/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch7-grok46-low/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch8-grok46-medium/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch9-grok46-low/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch10-grok46-high/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch11-grok46-medium/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch12-grok46-high/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch13-grok46-low/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch14-grok46-medium/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch15-grok46-high/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch16-grok46-medium/work/selected-30.jsonl"),
]
for p in prior_dirs:
    prior = load_ids(p, "ghsa_id")
    assert not (set(ids) & prior), str(p)

remain = [line.strip() for line in (owned / "work/unreviewed-hit-ids.txt").read_text().splitlines() if line.strip()]
assert len(remain) == 320
assert len(set(remain)) == 320
assert not (set(ids) & set(remain))

hits = {json.loads(l)["ghsa_id"].upper() for l in (first / "work/rank-hits.jsonl").read_text().splitlines() if l.strip()}
assert set(ids) <= hits
assert [c["original_rank"] for c in cases] == list(range(481, 510 + 1))
assert res["selection"]["selected_original_ranks"] == list(range(481, 510 + 1))
assert res["frozen_input_hashes"]["CONTRACT.md"] == res["current_input_hashes"]["CONTRACT.md"]
assert res["did_not_edit_tracked_or_canonical"] is True
assert res["did_not_commit_or_push"] is True

for i in ids:
    assert (owned / "work/pages" / f"{i.lower()}.json").is_file()

ckpt = json.loads((owned / "work/checkpoint.json").read_text())
assert ckpt["assigned"] == 30
assert ckpt["reviewed"] == 30
assert ckpt["unreviewed"] == 320
assert ckpt["reviewed_ids"] == ids
assert ckpt["expansion_stopped"] is True
PY

echo OK
