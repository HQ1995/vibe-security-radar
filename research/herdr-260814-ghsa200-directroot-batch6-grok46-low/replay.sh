#!/usr/bin/env zsh
set -euo pipefail

# Fail-fast read-only offline replay.
# Do not fetch, clone, commit, push, or rerun ranking.

export GIT_OPTIONAL_LOCKS=0

ROOT=/home/hanqing/agents/ai-slop
cd "$ROOT"

OWNED=autoresearch/herdr-260814-ghsa200-directroot-batch6-grok46-low
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
[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$ADB" rev-parse HEAD)" == "a42c436870111aa3f221257c9d56126a93173ccc" ]]

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
assert res["final_round_checkpoint"]["unreviewed"] == 740
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 30
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 0
assert res["counts"]["assigned"] == 30
assert res["counts"]["reviewed"] == 30
assert res["counts"]["unreviewed"] == 740
assert res["proposed_pass_ids"] == []
assert res["claim_boundary"]["more_than_200_claim_supported_by_this_review"] is False
assert set(res["dispositions"]) == {"PASS", "REJECT", "NARROW", "UNKNOWN", "BLOCKED"}

cons = res["conservation"]
assert cons["assigned"] == 30
assert cons["reviewed"] == 30
assert cons["unreviewed"] == 740
assert cons["incoming_unreviewed_hits"] == 770
assert cons["first60_deep_reviewed"] + cons["deep_reviewed"] + cons["unreviewed_hits"] + cons["rank_misses"] == cons["rank_pool"]
assert cons["assigned_equals_reviewed"] is True

assigned = [
    "GHSA-G5H5-M4HM-XJRR","GHSA-6PR9-RP53-2PMC","GHSA-C54G-XJWJ-8G82","GHSA-CG7W-RG45-PC59","GHSA-248M-82V9-Q6G6",
    "GHSA-9GGV-8W38-R7PM","GHSA-W6J9-VW59-27WV","GHSA-4565-R4X7-HG8J","GHSA-XXHQ-69MF-W8CR","GHSA-J93G-RP6M-J32M",
    "GHSA-QRPV-Q767-XQQ2","GHSA-2P9H-RQJW-GM92","GHSA-246W-JGMQ-88FG","GHSA-GX2M-MCC2-R4P3","GHSA-C65F-X25W-62JV",
    "GHSA-PJJW-68HJ-V9MW","GHSA-5GJC-GRVM-M88J","GHSA-FH32-73R9-RGH5","GHSA-5R8F-96GM-5J6G","GHSA-JJ6C-8H6C-HPPX",
    "GHSA-HPPC-G8H3-XHP3","GHSA-HV99-MXM5-Q397","GHSA-HR8G-2Q7X-3F4W","GHSA-3J8V-CGW4-2G6Q","GHSA-JF25-7968-H2H5",
    "GHSA-XRWR-FCW6-FMQ8","GHSA-CJW9-GHJ4-FWXF","GHSA-2XCP-X87W-Q377","GHSA-CWQ8-6F96-G3Q4","GHSA-P9FF-H696-F583",
]
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
    assert "PASS" not in (None,)

first_sel = [json.loads(l)["ghsa_id"] for l in (first / "work/selected-30.jsonl").read_text().splitlines() if l.strip()]
b2 = [json.loads(l)["ghsa_id"] for l in Path("autoresearch/herdr-260813-ghsa200-directroot-batch2-grok46-xhigh/work/selected-30.jsonl").read_text().splitlines() if l.strip()]
assert not (set(ids) & set(first_sel))
assert not (set(ids) & set(b2))
assert "GHSA-Q855-8RH5-JFGQ" not in ids

remain = [line.strip() for line in (owned / "work/unreviewed-hit-ids.txt").read_text().splitlines() if line.strip()]
assert len(remain) == 740
assert len(set(remain)) == 740
assert not (set(ids) & set(remain))
assert 60 + 30 + 740 + 2643 == 3473

c65 = next(c for c in cases if c["case_id"] == "GHSA-C65F-X25W-62JV")
assert c65["ai_hunk_gate"] == "PASS"
assert c65["release_gate"] == "FAIL"
assert c65["contribution_class"] == "WEAK_PACKAGE_MAPPING"

hits = {json.loads(l)["ghsa_id"] for l in (first / "work/rank-hits.jsonl").read_text().splitlines() if l.strip()}
assert set(ids) <= hits

for i in ids:
    assert (owned / "work/pages" / f"{i.lower()}.json").is_file()

ckpt = json.loads((owned / "work/checkpoint.json").read_text())
assert ckpt["assigned"] == 30
assert ckpt["reviewed"] == 30
assert ckpt["unreviewed"] == 740
assert ckpt["reviewed_ids"] == ids
assert ckpt["expansion_stopped"] is True
PY

echo OK
