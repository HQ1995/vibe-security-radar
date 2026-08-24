#!/usr/bin/env zsh
set -euo pipefail

# Fail-fast read-only offline replay.
# Do not fetch, clone, commit, push, or rerun ranking.

export GIT_OPTIONAL_LOCKS=0

ROOT=/home/hanqing/agents/ai-slop
cd "$ROOT"

OWNED=autoresearch/herdr-260814-ghsa200-directroot-batch9-grok46-low
FIRST=autoresearch/herdr-260813-ghsa200-directroot-mining-grok46-xhigh
B8=autoresearch/herdr-260814-ghsa200-directroot-batch8-grok46-medium
ADB=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database
GP=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gopacket__gopacket
NG=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/asymmetric-effort__NogginLessDom

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
[[ -d "$GP/.git" ]]
[[ -f "$NG/HEAD" ]]
[[ -d "$NG/objects" ]]

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
[[ "$(hash_file "$OWNED/work/selected-30.jsonl")" == "dd6cadd958addee4f558824c416ce0c0f547e3282abd6fa902fe55cefa14edae" ]]
[[ "$(hash_file "$B8/work/selected-30.jsonl")" == "950307abeceef4d0315e36d5551f362bdd0c18629d79bdb818611da164bd1b1c" ]]
[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$ADB" rev-parse HEAD)" == "a42c436870111aa3f221257c9d56126a93173ccc" ]]
[[ "$(hash_file scripts/publication_adjudications.json)" == "9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f" ]]

DIAMETER_AI=fe11a243b3365bf877ddd91f9ba37206c25d96df
DIAMETER_FIX=145859d0eaee1a6f5925ffb93851c976449c3311
SNAP_AI=ed0124d37f548be12f2ff91b48ce7e33380d0ab4
SNAP_FIX=785e6ac6e124d1a89b3ccf40bbd75fc8e4cb215d
REDOS_AI=f8ee181be67344f12aeb30ec39e5ab611c65b826
REDOS_FIX=25a3cbac665fae5663f8b71c073b80c3152dbe7b
V021=7cd241350fb7669b006fed46b81436925d1bb55c
V022=00dc8ad39071140d1d76c03d93c6e10f19e51138

git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" cat-file -t "$DIAMETER_AI" >/dev/null
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" cat-file -t "$DIAMETER_FIX" >/dev/null
[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" rev-list --parents -n 1 "$DIAMETER_AI" | awk '{print NF-1}')" == "1" ]]
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" log -1 --format=%b "$DIAMETER_AI" | grep -q "Co-authored-by: Copilot"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" merge-base --is-ancestor "$DIAMETER_AI" v1.6.0
if git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" merge-base --is-ancestor "$DIAMETER_FIX" v1.6.0; then
  echo "diameter fix must not be ancestor of v1.6.0" >&2
  exit 1
fi
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" merge-base --is-ancestor "$DIAMETER_FIX" v1.6.1
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" blame -l -w -L56,57 "$DIAMETER_FIX"^ -- layers/diameter_avp_decoders.go | grep -q "$DIAMETER_AI"

git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$NG" cat-file -t "$SNAP_AI" >/dev/null
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$NG" cat-file -t "$REDOS_AI" >/dev/null
[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$NG" rev-list --parents -n 1 "$SNAP_AI" | awk '{print NF-1}')" == "1" ]]
[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$NG" rev-list --parents -n 1 "$REDOS_AI" | awk '{print NF-1}')" == "1" ]]
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$NG" log -1 --format=%b "$SNAP_AI" | grep -q "Co-Authored-By: Claude Opus 4.6"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$NG" log -1 --format=%b "$REDOS_AI" | grep -q "Co-Authored-By: Claude Opus 4.6"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$NG" merge-base --is-ancestor "$SNAP_AI" "$V021"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$NG" merge-base --is-ancestor "$REDOS_AI" "$V021"
if git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$NG" merge-base --is-ancestor "$SNAP_FIX" "$V021"; then
  echo "snapshot fix must not be ancestor of 0.0.21" >&2
  exit 1
fi
if git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$NG" merge-base --is-ancestor "$REDOS_FIX" "$V021"; then
  echo "redos fix must not be ancestor of 0.0.21" >&2
  exit 1
fi
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$NG" merge-base --is-ancestor "$SNAP_FIX" "$V022"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$NG" merge-base --is-ancestor "$REDOS_FIX" "$V022"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$NG" show "${V021}:package.json" | grep -q '"version": "0.0.21"'
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$NG" show "${V022}:package.json" | grep -q '"version": "0.0.22"'
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$NG" blame -l -w -L732,732 "$SNAP_FIX"^ -- src/assertions/snapshots.ts | grep -q "$SNAP_AI"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$NG" blame -l -w -L286,286 "$REDOS_FIX"^ -- src/dom/html-elements.ts | grep -q "$REDOS_AI"

python3 - "$OWNED" "$FIRST" "$B8" <<'PY'
import hashlib, json, re, sys
from pathlib import Path

owned, first, b8 = map(Path, sys.argv[1:4])
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
assert res["final_round_checkpoint"]["unreviewed"] == 560
assert res["counts"]["PASS"] == 3
assert res["counts"]["REJECT"] == 27
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 0
assert res["counts"]["assigned"] == 30
assert res["counts"]["reviewed"] == 30
assert res["counts"]["unreviewed"] == 560
assert res["counts"]["countable_pass"] == 0
assert res["counts"]["proposed_acceptances"] == 3
assert res["proposed_acceptances_are_uncounted"] is True
assert res["claim_boundary"]["more_than_200_claim_supported_by_this_review"] is False
assert set(res["dispositions"]) == {"PASS", "REJECT", "NARROW", "UNKNOWN", "BLOCKED"}

cons = res["conservation"]
assert cons["assigned"] == 30
assert cons["reviewed"] == 30
assert cons["unreviewed"] == 560
assert cons["incoming_unreviewed_hits"] == 590
assert cons["prior_directroot_reviewed"] == 240
assert cons["prior_directroot_reviewed"] + cons["deep_reviewed"] + cons["unreviewed_hits"] + cons["rank_misses"] == cons["rank_pool"]
assert cons["assigned_equals_reviewed"] is True
assert cons["rank_pool"] == 3473
assert cons["hits"] == 830
assert cons["rank_misses"] == 2643

assigned = ["GHSA-GCG5-86JR-F7JG","GHSA-GG2G-P7XC-QQMM","GHSA-482J-2PQ6-Q5W4","GHSA-GFM2-XM6C-37QC","GHSA-P64J-F4X9-WQ66","GHSA-M77W-P5JJ-XMHG","GHSA-MJ4X-VF5C-5XG8","GHSA-RQV2-M695-F8J4","GHSA-2RC4-7JC6-QFFH","GHSA-3775-99MW-8RP4","GHSA-WPXJ-44W3-2J6X","GHSA-93RG-2XM5-2P9V","GHSA-GW2X-Q739-QHCR","GHSA-333V-68XH-8MMQ","GHSA-2MMV-7RRP-G8XH","GHSA-CV78-6M8Q-PH82","GHSA-H4RM-MM56-XF63","GHSA-F283-GHQC-FG79","GHSA-CWJ3-VQPP-PMXR","GHSA-X4HG-HFWF-P9MW","GHSA-322X-V876-G883","GHSA-RJVX-X5H2-6PX5","GHSA-5QJJ-4XWW-7PHC","GHSA-RGV6-XP99-6MGJ","GHSA-W6P7-2FXX-4F44","GHSA-H8FP-F39C-Q6MH","GHSA-6HM7-3PWJ-22RM","GHSA-7RW5-9F7Q-XJ36","GHSA-HVRM-45R6-MJFJ","GHSA-6R28-9PPF-4HJ5"]
cases = [json.loads(line) for line in (owned / "cases.jsonl").read_text().splitlines() if line.strip()]
assert len(cases) == 30
ids = [c["case_id"] for c in cases]
assert ids == assigned
assert ids == res["selection"]["selected_ids"]
sel_file = [json.loads(l)["ghsa_id"] for l in (owned / "work/selected-30.jsonl").read_text().splitlines() if l.strip()]
assert ids == sel_file
assert all(c["countable"] is False for c in cases)
assert all(c["causal_admission"] is False for c in cases)
assert all(c["english_only"] is True for c in cases)
assert [c["original_rank"] for c in cases] == list(range(241, 271))

gates = ["identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
pass_rows = [c for c in cases if c["worker_verdict"] == "PASS"]
reject_rows = [c for c in cases if c["worker_verdict"] == "REJECT"]
assert len(pass_rows) == 3
assert len(reject_rows) == 27
assert [c["case_id"] for c in pass_rows] == res["proposed_pass_ids"]
for row in pass_rows:
    assert all(row[g] == "PASS" for g in gates), row["case_id"]
    assert row["failing_gates"] == []
    assert row["countable_proposal"] is True
    assert row["contribution_class"] == "AI_DIRECT_ROOT"
for row in reject_rows:
    failed = [g for g in gates if row[g] != "PASS"]
    assert failed, row["case_id"]
    assert row["identity_gate"] == "PASS"

def load_ids(path, key):
    p = Path(path)
    if not p.exists():
        return set()
    out = set()
    for l in p.read_text().splitlines():
        if not l.strip():
            continue
        row = json.loads(l)
        val = row.get(key)
        if isinstance(val, str) and val.upper().startswith("GHSA-"):
            out.add(val.upper())
    return out

first_sel = load_ids(first / "work/selected-30.jsonl", "ghsa_id")
b8 = load_ids(b8 / "work/selected-30.jsonl", "ghsa_id")
c73 = set(json.loads(Path("autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json").read_text())["strict_released_case_ids"])
assert not (set(ids) & first_sel)
assert not (set(ids) & b8)
assert not (set(ids) & c73)
assert "GHSA-Q855-8RH5-JFGQ" not in ids
assert "GHSA-JF73-858C-54PG" not in ids

remain = [line.strip() for line in (owned / "work/unreviewed-hit-ids.txt").read_text().splitlines() if line.strip()]
assert len(remain) == 560
assert len(set(remain)) == 560
assert not (set(ids) & set(remain))
assert 240 + 30 + 560 + 2643 == 3473

hits = {json.loads(l)["ghsa_id"].upper() for l in (first / "work/rank-hits.jsonl").read_text().splitlines() if l.strip()}
assert set(ids) <= hits

for i in ids:
    assert (owned / "work/pages" / f"{i.lower()}.json").is_file()

ckpt = json.loads((owned / "work/checkpoint.json").read_text())
assert ckpt["assigned"] == 30
assert ckpt["reviewed"] == 30
assert ckpt["unreviewed"] == 560
assert ckpt["reviewed_ids"] == ids
assert ckpt["expansion_stopped"] is True
assert res["current_overlap_check"]["selected_ids_in_live_adjudications"] == []
PY

echo OK
