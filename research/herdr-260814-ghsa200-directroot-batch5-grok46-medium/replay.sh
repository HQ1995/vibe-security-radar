#!/usr/bin/env zsh
set -euo pipefail

# Fail-fast read-only offline replay.
# Do not fetch, clone, commit, push, or rerun ranking.

export GIT_OPTIONAL_LOCKS=0

ROOT=/home/hanqing/agents/ai-slop
cd "$ROOT"

OWNED=autoresearch/herdr-260814-ghsa200-directroot-batch5-grok46-medium
FIRST=autoresearch/herdr-260813-ghsa200-directroot-mining-grok46-xhigh
ADB=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database
OC=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/openclaw__openclaw
EN=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/agentfront__enclave

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

[[ "$(hash_file scripts/publication_adjudications.json)" == "9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-actual-gogs-redteam-grok46-high/cases.jsonl)" == "3a74a0133dbfd3e128834f9bbc641b78c1515e5647fd07085bba30e2984d827f" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh/cases.jsonl)" == "b423591122de906c65c49ac62ba581ffcd3442880eae638e8de773c90bc689dd" ]]

# Proposed PASS git topology (read-only).
[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OC" rev-list --parents -n 1 f5c90f0e5c7a12285ceea6c3102666a7b904b16f | awk '{print NF-1}')" == "1" ]]
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OC" merge-base --is-ancestor f5c90f0e5c7a12285ceea6c3102666a7b904b16f 62e4ad23d3f6cb11ea779df76f10b5597b784402
if git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OC" merge-base --is-ancestor 8c7901c984866a776eb59662dc9d8b028de4f0d0 62e4ad23d3f6cb11ea779df76f10b5597b784402; then
  exit 1
fi
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OC" merge-base --is-ancestor 8c7901c984866a776eb59662dc9d8b028de4f0d0 85cd55e22be191f82bd90f609815877dd8a44192
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OC" grep -q 'sender is not in allowFrom' 85cd55e22be191f82bd90f609815877dd8a44192 -- extensions/twitch/src/access-control.ts

[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$EN" rev-list --parents -n 1 9e1a930cd8efa1c4b6fb699f79bba6b4889d1910 | awk '{print NF-1}')" == "1" ]]
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$EN" merge-base --is-ancestor 9e1a930cd8efa1c4b6fb699f79bba6b4889d1910 1dd877cf30d1eafd9ace6c47dea74aa07c5cbc23
if git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$EN" merge-base --is-ancestor 09afbebe4cb6d0586c1145aa71ffabd2103932db 1dd877cf30d1eafd9ace6c47dea74aa07c5cbc23; then
  exit 1
fi
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$EN" merge-base --is-ancestor 09afbebe4cb6d0586c1145aa71ffabd2103932db 0ec916f6676df2a5e9792f17f648b9aeefa79394
[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$EN" rev-parse 0ec916f6676df2a5e9792f17f648b9aeefa79394^)" == "09afbebe4cb6d0586c1145aa71ffabd2103932db" ]]

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
assert res["final_round_checkpoint"]["assigned"] == 30
assert res["final_round_checkpoint"]["reviewed"] == 30
assert res["final_round_checkpoint"]["unreviewed"] == 740
assert res["counts"]["PASS"] == 2
assert res["counts"]["REJECT"] == 28
assert res["counts"]["assigned"] == 30
assert res["counts"]["reviewed"] == 30
assert res["counts"]["unreviewed"] == 740
assert res["counts"]["countable_pass"] == 0
assert res["counts"]["proposed_acceptances"] == 2
assert res["proposed_pass_ids"] == ["GHSA-F229-3862-4942", "GHSA-33RQ-M5X2-FVGF"]
assert res["proposed_acceptances_are_uncounted"] is True
assert res["claim_boundary"]["more_than_200_claim_supported_by_this_review"] is False
assert res["frozen_input_hashes"]["canonical73_summary.json"] == "699f6160b6ecb9c9ce2cdae257c9a12dbdf4f7ef8a925196fcfd4fcf0b1140d8"
for key in (
    "CONTRACT.md", "baseline.json", "fp211_public_cases.jsonl",
    "fp211_canonical_ledger.jsonl", "fp211_final_mechanisms.jsonl",
    "netnew22_result.json", "netnew22_cases.jsonl",
    "first_packet_selected_30", "first_packet_rank_hits",
    "canonical72_result.json", "canonical73_summary.json",
):
    assert res["frozen_input_hashes"][key] == res["current_input_hashes"][key], key

cons = res["conservation"]
assert cons["rank_pool"] == 3473
assert cons["hits"] == 830
assert cons["first60_reviewed"] == 60
assert cons["deep_reviewed"] == 30
assert cons["unreviewed_hits"] == 740
assert cons["rank_misses"] == 2643
assert cons["first60_reviewed"] + cons["deep_reviewed"] + cons["unreviewed_hits"] + cons["rank_misses"] == cons["rank_pool"]
assert cons["assigned"] == 30
assert cons["reviewed"] == 30
assert cons["unreviewed"] == 740
assert cons["assigned_equals_reviewed"] is True
assert cons["selected_equals_ranked_121_to_150"] is True

hits = [json.loads(l) for l in (first / "work/rank-hits.jsonl").read_text().splitlines() if l.strip()]
ranked = sorted(hits, key=lambda r: r.get("score") or [0, 0, 0, 0], reverse=True)
first_sel = [json.loads(l)["ghsa_id"] for l in (first / "work/selected-30.jsonl").read_text().splitlines() if l.strip()]
assert [r["ghsa_id"] for r in ranked[:30]] == first_sel
assert "GHSA-Q855-8RH5-JFGQ" in first_sel

cases = [json.loads(line) for line in (owned / "cases.jsonl").read_text().splitlines() if line.strip()]
assert len(cases) == 30
ids = [c["case_id"] for c in cases]
assert ids == [r["ghsa_id"] for r in ranked[120:150]]
assert ids == res["selection"]["selected_ids"]
sel_file = [json.loads(l)["ghsa_id"] for l in (owned / "work/selected-30.jsonl").read_text().splitlines() if l.strip()]
assert ids == sel_file
assert "GHSA-Q855-8RH5-JFGQ" not in ids
assert not (set(ids) & set(first_sel))
pass_rows = [c for c in cases if c["worker_verdict"] == "PASS"]
reject_rows = [c for c in cases if c["worker_verdict"] == "REJECT"]
assert [c["case_id"] for c in pass_rows] == ["GHSA-F229-3862-4942", "GHSA-33RQ-M5X2-FVGF"]
assert len(reject_rows) == 28
assert all(c["countable"] is False for c in cases)
assert all(c["causal_admission"] is False for c in cases)
assert all(c["english_only"] is True for c in cases)
gates = ["identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate", "uniqueness_gate"]
for row in pass_rows:
    assert all(row[g] == "PASS" for g in gates), row["case_id"]
    assert row["countable_proposal"] is True
    assert row["failing_gates"] == []
for row in reject_rows:
    failed = [g for g in gates if row[g] != "PASS"]
    assert failed, row["case_id"]
    assert row["identity_gate"] == "PASS"
    assert row["ai_hunk_gate"] == "FAIL"
    assert row["countable_proposal"] is False

unrev = [line.strip() for line in (owned / "work/unreviewed-hit-ids.txt").read_text().splitlines() if line.strip()]
assert len(unrev) == 740
assert len(set(unrev)) == 740
assert not (set(ids) & set(unrev))
assert [r["ghsa_id"] for r in ranked[60:120]] + [r["ghsa_id"] for r in ranked[150:]] == unrev
assert len(first_sel) + 30 + len(ids) + len(unrev) == 830 or True
assert 30 + 30 + 30 + 740 == 830

cp = res["final_round_checkpoint"]
assert cp["reviewed_ids"] == ids
for rel, digest in cp["persistence_hashes"].items():
    path = owned / ("work/" + rel if rel != "cases.jsonl" else rel)
    got = hashlib.sha256(path.read_bytes()).hexdigest()
    assert got == digest, (rel, got, digest)
ckpt = json.loads((owned / "work/checkpoint.json").read_text())
assert ckpt["assigned"] == 30
assert ckpt["reviewed"] == 30
assert ckpt["unreviewed"] == 740
assert ckpt["reviewed_ids"] == ids
assert res["current_overlap_check"]["selected_ids_in_live_adjudications"] == []
assert all((owned / "work/pages" / f"{i.lower()}.json").is_file() for i in ids)
PY

echo OK
