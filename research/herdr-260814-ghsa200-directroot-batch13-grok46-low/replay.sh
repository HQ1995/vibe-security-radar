#!/usr/bin/env zsh
set -euo pipefail

# Fail-fast read-only offline replay.
# Do not fetch, clone, commit, push, or rerun ranking.

export GIT_OPTIONAL_LOCKS=0

ROOT=/home/hanqing/agents/ai-slop
cd "$ROOT"

OWNED=autoresearch/herdr-260814-ghsa200-directroot-batch13-grok46-low
FIRST=autoresearch/herdr-260813-ghsa200-directroot-mining-grok46-xhigh
B11=autoresearch/herdr-260814-ghsa200-directroot-batch11-grok46-medium
B12=autoresearch/herdr-260814-ghsa200-directroot-batch12-grok46-high
ADB=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database
AX=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/axios__axios
EK=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/lf-edge__ekuiper
MCP=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/modelcontextprotocol__servers

hash_file() {
  sha256sum -- "$1" | awk '{print $1}'
}

[[ -f "$OWNED/result.json" ]]
[[ -f "$OWNED/cases.jsonl" ]]
[[ -f "$OWNED/report.md" ]]
[[ -f "$OWNED/replay.sh" ]]
[[ -f "$OWNED/work/selected-30.jsonl" ]]
[[ -f "$FIRST/work/rank-hits.jsonl" ]]
[[ -d "$ADB/.git" ]]
[[ -d "$AX/.git" ]] || [[ -f "$AX/HEAD" ]]
[[ -d "$EK/.git" ]]
[[ -d "$MCP/.git" ]]

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
[[ "$(hash_file "$OWNED/work/selected-30.jsonl")" == "f9c82a6c083e7af42656aea2a4f2a09f58aa8203f3bbdf2b71753fda65faf997" ]]
[[ "$(hash_file "$B11/work/selected-30.jsonl")" == "fb65eed161857dddfcc404c4a765812364abdf16d34e19783eae3fbf9a5aa456" ]]
[[ "$(hash_file "$B12/work/selected-30.jsonl")" == "02b8be6ad3b328b156e36cbcafad6ed1261a4c09aed305864511466e209ac759" ]]
[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$ADB" rev-parse HEAD)" == "a42c436870111aa3f221257c9d56126a93173ccc" ]]
[[ "$(hash_file scripts/publication_adjudications.json)" == "9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f" ]]

AX_AI=860e03396a536e9b926dacb6570732489c9d7012
AX_FIX=28c721588c7a77e7503d0a434e016f852c597b57
EK_AI=f47289ab810b7f58ed76eb88a91a1fbbdc883e1f
EK_FIX=72c4918744934deebf04e324ae66933ec089ebd3
MCP_AI=4e31b9d66e9cb7fb7ba1cc332ee91c8ec0513df6

git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$AX" cat-file -t "$AX_AI" >/dev/null
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$AX" cat-file -t "$AX_FIX" >/dev/null
[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$AX" rev-list --parents -n 1 "$AX_AI" | awk '{print NF-1}')" == "1" ]]
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$AX" log -1 --format=%b "$AX_AI" | grep -q "Co-authored-by: Copilot"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$EK" cat-file -t "$EK_AI" >/dev/null
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$EK" cat-file -t "$EK_FIX" >/dev/null
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$EK" log -1 --format=%b "$EK_AI" | grep -q "github-advanced-security"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$MCP" cat-file -t "$MCP_AI" >/dev/null
[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$MCP" show "${MCP_AI}:src/filesystem/index.ts" | grep -c 'Server error:')" == "1" ]]

python3 - <<'PY'
import json
from pathlib import Path

root = Path("/home/hanqing/agents/ai-slop")
owned = root / "autoresearch/herdr-260814-ghsa200-directroot-batch13-grok46-low"
first = root / "autoresearch/herdr-260813-ghsa200-directroot-mining-grok46-xhigh"
res = json.loads((owned / "result.json").read_text())
assert res["status"] == "TERMINAL"
assert res["english_only"] is True
assert res["publication_status"] == "HOLD"
assert res["worker_pass_is_proposal_only"] is True
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 30
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 0
assert res["counts"]["assigned"] == 30
assert res["counts"]["reviewed"] == 30
assert res["counts"]["unreviewed"] == 440
assert res["proposed_pass_ids"] == []
assert res["claim_boundary"]["more_than_200_claim_supported_by_this_review"] is False
assert set(res["dispositions"]) == {"PASS", "REJECT", "NARROW", "UNKNOWN", "BLOCKED"}

cons = res["conservation"]
assert cons["assigned"] == 30
assert cons["reviewed"] == 30
assert cons["unreviewed"] == 440
assert cons["incoming_unreviewed_hits"] == 470
assert cons["prior_directroot_reviewed"] == 360
assert cons["prior_directroot_reviewed"] + cons["deep_reviewed"] + cons["unreviewed_hits"] + cons["rank_misses"] == cons["rank_pool"]
assert cons["assigned_equals_reviewed"] is True

assigned = [
    "GHSA-9C54-GXH7-PPJC","GHSA-MV7P-34FV-4874","GHSA-565G-HWWR-4PP3","GHSA-F4CF-9RVR-2RCX","GHSA-2267-XQCF-GW2M",
    "GHSA-C6XV-RCVW-V685","GHSA-XRQC-7XGX-C9VH","GHSA-WPQC-H9WP-CHMQ","GHSA-8FR4-5Q9J-M8GM","GHSA-W832-GG5G-X44M",
    "GHSA-J4G7-V4M4-77PX","GHSA-H238-5MWF-8XW8","GHSA-6QV9-48XG-FC7F","GHSA-Q66Q-FX2P-7W4M","GHSA-HC55-P739-J48W",
    "GHSA-526J-MV3P-F4VV","GHSA-QP7J-X725-G67F","GHSA-GM8Q-M8MV-JJ5M","GHSA-2W46-VQ8H-98VH","GHSA-43FC-JF86-J433",
    "GHSA-RF4G-89H5-CRCR","GHSA-6V48-FCQ6-FF23","GHSA-G34W-4XQQ-H79M","GHSA-V6C6-VQQG-W888","GHSA-W5CR-2QHR-JQC5",
    "GHSA-PGVM-WXW2-HRV9","GHSA-WH94-P5M6-MR7J","GHSA-5XFQ-5MR7-426Q","GHSA-H9G4-589H-68XV","GHSA-M82Q-59GV-MCR9",
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

def load_ids(path, key):
    return {json.loads(l)[key].upper() for l in Path(path).read_text().splitlines() if l.strip()}

first_sel = load_ids(first / "work/selected-30.jsonl", "ghsa_id")
b2 = load_ids("autoresearch/herdr-260813-ghsa200-directroot-batch2-grok46-xhigh/work/selected-30.jsonl", "ghsa_id")
b3 = load_ids("autoresearch/herdr-260814-ghsa200-directroot-batch3-grok46-xhigh/work/selected-30.jsonl", "ghsa_id")
b4 = load_ids("autoresearch/herdr-260814-ghsa200-directroot-batch4-grok46-high/work/selected-30.jsonl", "ghsa_id")
b5 = load_ids("autoresearch/herdr-260814-ghsa200-directroot-batch5-grok46-medium/work/selected-30.jsonl", "ghsa_id")
b6 = load_ids("autoresearch/herdr-260814-ghsa200-directroot-batch6-grok46-low/work/selected-30.jsonl", "ghsa_id")
b7 = load_ids("autoresearch/herdr-260814-ghsa200-directroot-batch7-grok46-low/work/selected-30.jsonl", "ghsa_id")
b8 = load_ids("autoresearch/herdr-260814-ghsa200-directroot-batch8-grok46-medium/work/selected-30.jsonl", "ghsa_id")
b9 = load_ids("autoresearch/herdr-260814-ghsa200-directroot-batch9-grok46-low/work/selected-30.jsonl", "ghsa_id")
b10 = load_ids("autoresearch/herdr-260814-ghsa200-directroot-batch10-grok46-high/work/selected-30.jsonl", "ghsa_id")
b11 = load_ids("autoresearch/herdr-260814-ghsa200-directroot-batch11-grok46-medium/work/selected-30.jsonl", "ghsa_id")
b12 = load_ids("autoresearch/herdr-260814-ghsa200-directroot-batch12-grok46-high/work/selected-30.jsonl", "ghsa_id")
c73 = set(json.loads(Path("autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json").read_text())["strict_released_case_ids"])
for s in (first_sel, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, c73):
    assert not (set(ids) & s)

remain = [line.strip() for line in (owned / "work/unreviewed-hit-ids.txt").read_text().splitlines() if line.strip()]
assert len(remain) == 440
assert len(set(remain)) == 440
assert not (set(ids) & set(remain))
assert 360 + 30 + 440 + 2643 == 3473

hits = {json.loads(l)["ghsa_id"].upper() for l in (first / "work/rank-hits.jsonl").read_text().splitlines() if l.strip()}
assert set(ids) <= hits
assert [c["original_rank"] for c in cases] == list(range(361, 391))

for i in ids:
    assert (owned / "work/pages" / f"{i.lower()}.json").is_file()

ckpt = json.loads((owned / "work/checkpoint.json").read_text())
assert ckpt["assigned"] == 30
assert ckpt["reviewed"] == 30
assert ckpt["unreviewed"] == 440
assert ckpt["reviewed_ids"] == ids
assert ckpt["expansion_stopped"] is True
PY

echo OK
