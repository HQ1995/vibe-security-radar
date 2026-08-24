#!/usr/bin/env zsh
set -euo pipefail

# Fail-fast read-only offline replay.
# Do not fetch, clone, commit, push, or rerun ranking.

export GIT_OPTIONAL_LOCKS=0

ROOT=/home/hanqing/agents/ai-slop
cd "$ROOT"

OWNED=autoresearch/herdr-260814-ghsa200-directroot-batch11-grok46-medium
FIRST=autoresearch/herdr-260813-ghsa200-directroot-mining-grok46-xhigh
ADB=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database
LCLONE=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/langroid__langroid

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
[[ -d "$LCLONE/.git" ]]

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
[[ "$(hash_file "$OWNED/work/selected-30.jsonl")" == "fb65eed161857dddfcc404c4a765812364abdf16d34e19783eae3fbf9a5aa456" ]]
[[ "$(hash_file autoresearch/herdr-260814-ghsa200-directroot-batch9-grok46-low/work/selected-30.jsonl)" == "dd6cadd958addee4f558824c416ce0c0f547e3282abd6fa902fe55cefa14edae" ]]
[[ "$(hash_file autoresearch/herdr-260814-ghsa200-directroot-batch10-grok46-high/work/selected-30.jsonl)" == "c477cdb217efd4353ddfd7ea8e3e154c5a03d3051fcabfb6f601d46a5fe392b9" ]]

# Langroid incomplete-remediation replay
[[ "$(git --no-optional-locks -c gc.auto=0 -C "$LCLONE" rev-list --parents -n 1 60933b4860a8952894b31caa0dd3f9dcba512c8e | awk '{print NF-1}')" == "1" ]]
git --no-optional-locks -c gc.auto=0 -C "$LCLONE" merge-base --is-ancestor 60933b4860a8952894b31caa0dd3f9dcba512c8e 00b7dd7b79c5d03c94be284cf3459d98195ebfba
git --no-optional-locks -c gc.auto=0 -C "$LCLONE" merge-base --is-ancestor 60933b4860a8952894b31caa0dd3f9dcba512c8e fee670d502ed6d82b8414388bd137a315830331f
git --no-optional-locks -c gc.auto=0 -C "$LCLONE" merge-base --is-ancestor 00b7dd7b79c5d03c94be284cf3459d98195ebfba fee670d502ed6d82b8414388bd137a315830331f && exit 1 || true
git --no-optional-locks -c gc.auto=0 -C "$LCLONE" merge-base --is-ancestor 00b7dd7b79c5d03c94be284cf3459d98195ebfba 84d2aff0af173d75417fc37fc629be97177098f3
git --no-optional-locks -c gc.auto=0 -C "$LCLONE" log -1 --format=%B 60933b4860a8952894b31caa0dd3f9dcba512c8e | grep -F "Co-authored-by: Claude <noreply@anthropic.com>" >/dev/null
git --no-optional-locks -c gc.auto=0 -C "$LCLONE" show fee670d502ed6d82b8414388bd137a315830331f:pyproject.toml | grep -F 'version = "0.63.0"' >/dev/null
git --no-optional-locks -c gc.auto=0 -C "$LCLONE" show 84d2aff0af173d75417fc37fc629be97177098f3:pyproject.toml | grep -F 'version = "0.64.0"' >/dev/null

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
assert res["final_round_checkpoint"]["unreviewed"] == 500
assert res["counts"]["PASS"] == 1
assert res["counts"]["REJECT"] == 29
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 0
assert res["counts"]["assigned"] == 30
assert res["counts"]["reviewed"] == 30
assert res["counts"]["unreviewed"] == 500
assert res["counts"]["countable_pass"] == 0
assert res["proposed_pass_ids"] == ["GHSA-PMCH-G965-GRMR"]
assert res["claim_boundary"]["more_than_200_claim_supported_by_this_review"] is False
assert set(res["dispositions"]) == {"PASS", "REJECT", "NARROW", "UNKNOWN", "BLOCKED"}

cons = res["conservation"]
assert cons["assigned"] == 30
assert cons["reviewed"] == 30
assert cons["unreviewed"] == 500
assert cons["incoming_unreviewed_hits"] == 530
assert cons["prior_directroot_reviewed"] + cons["deep_reviewed"] + cons["unreviewed_hits"] + cons["rank_misses"] == cons["rank_pool"]
assert cons["assigned_equals_reviewed"] is True
assert cons["selected_equals_ranked_301_to_330"] is True
assert 300 + 30 + 500 + 2643 == 3473

assigned = ["GHSA-F75J-4CW6-RMX4","GHSA-4M82-P8CX-F94J","GHSA-HP74-GM6M-2QM5","GHSA-Q8WF-6R8G-63CH","GHSA-55H5-XMCQ-C37V","GHSA-9H85-G7W3-RH49","GHSA-866W-XMHQ-WJ7X","GHSA-H95V-H523-3MW8","GHSA-FMH4-WCC4-5JM3","GHSA-392P-2Q2V-4372","GHSA-5578-W22F-PFX9","GHSA-2XGG-R2WC-C5R2","GHSA-6QC9-MQVW-JG7X","GHSA-HG5R-VQ93-9FV6","GHSA-7488-6R32-C95Q","GHSA-JM28-2WCR-QF3H","GHSA-2CF7-HPWF-47H9","GHSA-824W-X939-6CMC","GHSA-V73X-HX65-6PF4","GHSA-683J-3FF6-HH2X","GHSA-9MQ6-MQJJ-C2C5","GHSA-X77V-Q46J-393G","GHSA-PMCH-G965-GRMR","GHSA-RJWR-M7QX-3FJR","GHSA-2X35-3FW4-9JR4","GHSA-3WP3-XXJ9-5JQQ","GHSA-G9G6-QHRC-P3QC","GHSA-6WCC-39RP-HH9P","GHSA-6C6R-5XR4-CR5M","GHSA-GF29-4F56-R2JF"]
cases = [json.loads(line) for line in (owned / "cases.jsonl").read_text().splitlines() if line.strip()]
assert len(cases) == 30
ids = [c["case_id"] for c in cases]
assert ids == assigned
assert ids == res["selection"]["selected_ids"]
sel_file = [json.loads(l)["ghsa_id"] for l in (owned / "work/selected-30.jsonl").read_text().splitlines() if l.strip()]
assert ids == sel_file
assert [c["worker_verdict"] for c in cases].count("PASS") == 1
assert [c["worker_verdict"] for c in cases].count("REJECT") == 29
assert all(c["countable"] is False for c in cases)
assert all(c["causal_admission"] is False for c in cases)
assert all(c["english_only"] is True for c in cases)
pass_row = next(c for c in cases if c["worker_verdict"] == "PASS")
assert pass_row["case_id"] == "GHSA-PMCH-G965-GRMR"
assert pass_row["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
assert pass_row["countable_proposal"] is True
gates = ["identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
for g in gates:
    assert pass_row[g] == "PASS", g
for row in cases:
    if row["worker_verdict"] != "PASS":
        failed = [g for g in gates if row[g] != "PASS"]
        assert failed, row["case_id"]
    assert row["identity_gate"] == "PASS"

first_sel = [json.loads(l)["ghsa_id"] for l in (first / "work/selected-30.jsonl").read_text().splitlines() if l.strip()]
assert not (set(ids) & set(first_sel))

c73 = json.loads(Path("autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json").read_text())["strict_released_case_ids"]
assert not (set(ids) & set(c73))

prior_dirs = [
    "autoresearch/herdr-260813-ghsa200-directroot-batch2-grok46-xhigh/work/selected-30.jsonl",
    "autoresearch/herdr-260813-ghsa200-directroot-batch3-grok46-xhigh/work/selected-30.jsonl",
    "autoresearch/herdr-260814-ghsa200-directroot-batch3-grok46-xhigh/work/selected-30.jsonl",
    "autoresearch/herdr-260814-ghsa200-directroot-batch4-grok46-high/work/selected-30.jsonl",
    "autoresearch/herdr-260814-ghsa200-directroot-batch5-grok46-medium/work/selected-30.jsonl",
    "autoresearch/herdr-260814-ghsa200-directroot-batch6-grok46-low/work/selected-30.jsonl",
    "autoresearch/herdr-260814-ghsa200-directroot-batch7-grok46-low/work/selected-30.jsonl",
    "autoresearch/herdr-260814-ghsa200-directroot-batch8-grok46-medium/work/selected-30.jsonl",
    "autoresearch/herdr-260814-ghsa200-directroot-batch9-grok46-low/work/selected-30.jsonl",
    "autoresearch/herdr-260814-ghsa200-directroot-batch10-grok46-high/work/selected-30.jsonl",
]
for p in prior_dirs:
    path = Path(p)
    if not path.exists():
        continue
    prior = [json.loads(l)["ghsa_id"] for l in path.read_text().splitlines() if l.strip()]
    assert not (set(ids) & set(prior)), p

remain = [line.strip() for line in (owned / "work/unreviewed-hit-ids.txt").read_text().splitlines() if line.strip()]
assert len(remain) == 500
assert len(set(remain)) == 500
assert not (set(ids) & set(remain))

hits = {json.loads(l)["ghsa_id"] for l in (first / "work/rank-hits.jsonl").read_text().splitlines() if l.strip()}
assert set(ids) <= hits

for i in ids:
    assert (owned / "work/pages" / f"{i.lower()}.json").is_file()

assert res["selection"]["selected_original_ranks"] == list(range(301, 331))
assert res["frozen_input_hashes"]["CONTRACT.md"] == res["current_input_hashes"]["CONTRACT.md"]
assert res["did_not_edit_tracked_or_canonical"] is True
assert res["did_not_commit_or_push"] is True
PY

echo OK
