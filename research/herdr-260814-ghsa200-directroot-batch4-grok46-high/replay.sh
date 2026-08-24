#!/usr/bin/env zsh
set -euo pipefail

# Fail-fast read-only offline replay.
# Do not fetch, clone, commit, push, or rerun ranking.

export GIT_OPTIONAL_LOCKS=0

ROOT=/home/hanqing/agents/ai-slop
cd "$ROOT"

OWNED=autoresearch/herdr-260814-ghsa200-directroot-batch4-grok46-high
FIRST=autoresearch/herdr-260813-ghsa200-directroot-mining-grok46-xhigh
BATCH2=autoresearch/herdr-260813-ghsa200-directroot-batch2-grok46-xhigh
BATCH3=autoresearch/herdr-260813-ghsa200-directroot-batch3-grok46-xhigh
ADB=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database
SP=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/asymmetric-effort__specifyjs

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
[[ -f "$SP/HEAD" ]]
[[ -d "$SP/objects" ]]

# Frozen conservation inputs. Replay fails if these bytes move.
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
[[ "$(hash_file "$BATCH2/work/selected-30.jsonl")" == "05ff6f4b3a0de2d61be00bbcbd3adda9587e9897303b3fc595948dd4071e189e" ]]
[[ "$(hash_file "$BATCH3/work/selected-30.jsonl")" == "cc9357feda897f591a4ce0e6a060d8da724c85aa0a6ecce5d9add9c487249a1c" ]]
[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$ADB" rev-parse HEAD)" == "a42c436870111aa3f221257c9d56126a93173ccc" ]]

# Current overlap pins. These do not re-select the reviewed set.
[[ "$(hash_file scripts/publication_adjudications.json)" == "9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-actual-gogs-redteam-grok46-high/cases.jsonl)" == "3a74a0133dbfd3e128834f9bbc641b78c1515e5647fd07085bba30e2984d827f" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh/cases.jsonl)" == "b423591122de906c65c49ac62ba581ffcd3442880eae638e8de773c90bc689dd" ]]

# Proposed PASS git proofs (offline, local objects only).
SAST=caa8fbfa4d7d99e02dca3ee0df642b30a5d856cc
HTTPS=30f9b76f848b681e2806ac6ebcebebb055af3999
FIX=25d1fb491d99479efdf501f5f75e0bb80c908f0a
V135=a84103e7dc3e3283279058d8f7e5a3c01a79fa3d
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" cat-file -t "$SAST" >/dev/null
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" cat-file -t "$HTTPS" >/dev/null
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" cat-file -t "$FIX" >/dev/null
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" cat-file -t "$V135" >/dev/null
[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" rev-list --parents -n 1 "$SAST" | awk '{print NF-1}')" == "1" ]]
[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" rev-list --parents -n 1 "$HTTPS" | awk '{print NF-1}')" == "1" ]]
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" log -1 --format=%b "$SAST" | grep -q "Co-Authored-By: Claude Opus 4.6"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" log -1 --format=%b "$HTTPS" | grep -q "Co-Authored-By: Claude Opus 4.6"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" merge-base --is-ancestor "$SAST" "$V135"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" merge-base --is-ancestor "$HTTPS" "$V135"
if git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" merge-base --is-ancestor "$FIX" "$V135"; then
  echo "fix must not be ancestor of v0.2.135" >&2
  exit 1
fi
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" merge-base --is-ancestor "$FIX" "$FIX"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" show "${V135}:core/package.json" | grep -q '"name": "@asymmetric-effort/specifyjs"'
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" show "${V135}:core/package.json" | grep -q '"version": "0.2.135"'
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" show "${FIX}:core/package.json" | grep -q '"version": "0.2.136"'
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" blame -l -w -L70,74 "$V135" -- core/src/client/graphql.ts | grep -q "$SAST"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" blame -l -w -L307,310 "$V135" -- core/src/server/render-to-string.ts | grep -q "$SAST"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" blame -l -w -L44,44 "$V135" -- core/src/shared/secure-fetch.ts | grep -q "$HTTPS"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" blame -l -w -L73,73 "$V135" -- core/src/shared/secure-fetch.ts | grep -q "$HTTPS"
git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$SP" blame -l -w -L33,33 "$V135" -- core/src/shared/secure-fetch.ts | grep -q "$HTTPS"

python3 - "$OWNED" "$FIRST" "$BATCH2" "$BATCH3" <<'PY'
import hashlib, json, re, sys
from pathlib import Path

owned, first, batch2, batch3 = map(Path, sys.argv[1:5])
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
assert res["final_round_checkpoint"]["unreviewed"] == 710
assert res["final_round_checkpoint"]["assigned_equals_reviewed"] is True
assert res["final_round_checkpoint"]["queue_exhausted"] is False
assert res["counts"]["PASS"] == 5
assert res["counts"]["REJECT"] == 25
assert res["counts"]["assigned"] == 30
assert res["counts"]["reviewed"] == 30
assert res["counts"]["unreviewed"] == 710
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 0
assert res["counts"]["countable_pass"] == 0
assert res["counts"]["proposed_acceptances"] == 5
assert res["proposed_acceptances_are_uncounted"] is True
assert res["claim_boundary"]["more_than_200_claim_supported_by_this_review"] is False
assert res["claim_boundary"]["canonical_ledger_edited"] is False
assert res["did_not_edit_first_packet"] is True
assert res["unreviewed_stream"]["same_id_first_party"] == 0
assert res["unreviewed_stream"]["alias_other_ghsa"] == 684
assert res["frozen_input_hashes"]["CONTRACT.md"] == "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"
assert res["frozen_input_hashes"]["canonical73_summary.json"] == "699f6160b6ecb9c9ce2cdae257c9a12dbdf4f7ef8a925196fcfd4fcf0b1140d8"
assert res["frozen_input_hashes"]["batch3_selected_30"] == "cc9357feda897f591a4ce0e6a060d8da724c85aa0a6ecce5d9add9c487249a1c"
for key in (
    "CONTRACT.md",
    "baseline.json",
    "fp211_public_cases.jsonl",
    "fp211_canonical_ledger.jsonl",
    "fp211_final_mechanisms.jsonl",
    "netnew22_result.json",
    "netnew22_cases.jsonl",
    "first_packet_selected_30",
    "first_packet_rank_hits",
    "canonical72_result.json",
    "canonical73_summary.json",
    "batch2_selected_30",
    "batch3_selected_30",
):
    assert res["frozen_input_hashes"][key] == res["current_input_hashes"][key], key

cons = res["conservation"]
assert cons["rank_pool"] == 3473
assert cons["hits"] == 830
assert cons["batch1_deep_reviewed"] == 30
assert cons["batch2_deep_reviewed"] == 30
assert cons["batch3_deep_reviewed"] == 30
assert cons["deep_reviewed"] == 30
assert cons["unreviewed_hits"] == 710
assert cons["rank_misses"] == 2643
assert cons["batch1_deep_reviewed"] + cons["batch2_deep_reviewed"] + cons["batch3_deep_reviewed"] + cons["deep_reviewed"] + cons["unreviewed_hits"] + cons["rank_misses"] == cons["rank_pool"]
assert cons["assigned"] == 30
assert cons["reviewed"] == 30
assert cons["unreviewed"] == 710
assert cons["assigned_equals_reviewed"] is True
assert cons["selected_equals_ranked_91_to_120"] is True

hits = [json.loads(l) for l in (first / "work/rank-hits.jsonl").read_text().splitlines() if l.strip()]
ranked = sorted(hits, key=lambda r: r.get("score") or [0, 0, 0, 0], reverse=True)
b1 = [json.loads(l)["ghsa_id"] for l in (first / "work/selected-30.jsonl").read_text().splitlines() if l.strip()]
b2 = [json.loads(l)["ghsa_id"] for l in (batch2 / "work/selected-30.jsonl").read_text().splitlines() if l.strip()]
b3 = [json.loads(l)["ghsa_id"] for l in (batch3 / "work/selected-30.jsonl").read_text().splitlines() if l.strip()]
assert [r["ghsa_id"] for r in ranked[:30]] == b1
assert [r["ghsa_id"] for r in ranked[30:60]] == b2
assert [r["ghsa_id"] for r in ranked[60:90]] == b3
assert [r["ghsa_id"] for r in ranked[90:120]] == [json.loads(l)["ghsa_id"] for l in (owned / "work/selected-30.jsonl").read_text().splitlines() if l.strip()]

cases = [json.loads(line) for line in (owned / "cases.jsonl").read_text().splitlines() if line.strip()]
assert len(cases) == 30
ids = [c["case_id"] for c in cases]
assert len(set(ids)) == 30
assert ids == [r["ghsa_id"] for r in ranked[90:120]]
assert ids == res["selection"]["selected_ids"]
assert "GHSA-Q855-8RH5-JFGQ" not in ids
assert not (set(ids) & set(b1) & set(b2) & set(b3))
assert not (set(ids) & set(b1))
assert not (set(ids) & set(b2))
assert not (set(ids) & set(b3))
excl = json.loads((owned / "work/exclusion.json").read_text())
assert excl["counts"]["canonical73"] == 73
assert not (set(ids) & set(excl["canonical73"]))
assert not (set(ids) & set(excl["discovery_exclude"]))
pass_rows = [c for c in cases if c["worker_verdict"] == "PASS"]
reject_rows = [c for c in cases if c["worker_verdict"] == "REJECT"]
assert len(pass_rows) == 5
assert len(reject_rows) == 25
assert [c["case_id"] for c in pass_rows] == res["proposed_pass_ids"]
assert all(c["countable"] is False for c in cases)
assert all(c["causal_admission"] is False for c in cases)
assert all(c["english_only"] is True for c in cases)
assert all(c["countable_proposal"] is True for c in pass_rows)
assert all(c["countable_proposal"] is False for c in reject_rows)
assert all(c["contribution_class"] == "AI_INCOMPLETE_REMEDIATION" for c in pass_rows)
gates = [
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
]
for row in pass_rows:
    assert all(row[g] == "PASS" for g in gates), row["case_id"]
    assert row["failing_gates"] == []
for row in reject_rows:
    failed = [g for g in gates if row[g] != "PASS"]
    assert failed, row["case_id"]
    assert row["identity_gate"] == "PASS"

unrev = [line.strip() for line in (owned / "work/unreviewed-hit-ids.txt").read_text().splitlines() if line.strip()]
assert len(unrev) == 710
assert len(set(unrev)) == 710
assert not (set(ids) & set(unrev))
assert [r["ghsa_id"] for r in ranked[120:]] == unrev
assert len(b1) + len(b2) + len(b3) + len(ids) + len(unrev) == 830

cp = res["final_round_checkpoint"]
assert cp["reviewed_ids"] == ids
for rel, digest in cp["persistence_hashes"].items():
    path = owned / ("work/" + rel if rel != "cases.jsonl" else rel)
    got = hashlib.sha256(path.read_bytes()).hexdigest()
    assert got == digest, (rel, got, digest)
ckpt = json.loads((owned / "work/checkpoint.json").read_text())
assert ckpt["assigned"] == 30
assert ckpt["reviewed"] == 30
assert ckpt["unreviewed"] == 710
assert ckpt["reviewed_ids"] == ids
assert ckpt["expansion_stopped"] is True
assert res["current_overlap_check"]["selected_ids_in_live_adjudications"] == []
assert all((owned / "work/pages" / f"{i.lower()}.json").is_file() for i in ids)
assert set(res["dispositions"].keys()) == {"PASS", "REJECT", "NARROW", "UNKNOWN", "BLOCKED"}
assert res["dispositions"]["PASS"] == [c["case_id"] for c in pass_rows]
assert res["dispositions"]["REJECT"] == [c["case_id"] for c in reject_rows]
assert res["dispositions"]["NARROW"] == []
assert res["dispositions"]["UNKNOWN"] == []
assert res["dispositions"]["BLOCKED"] == []
PY

echo OK
