#!/usr/bin/env zsh
set -euo pipefail

# Fail-fast read-only offline replay.
# Do not fetch, clone, commit, push, or rerun ranking.

export GIT_OPTIONAL_LOCKS=0

ROOT=/home/hanqing/agents/ai-slop
cd "$ROOT"

OWNED=autoresearch/herdr-260813-ghsa200-directroot-mining-grok46-xhigh
CLONE=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/homeassistant-ai__ha-mcp
ADB=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database
WHEELS=/home/hanqing/.cache/ghsa200-worker-clones/directroot-mining/pypi
AI=9783f346795be919bffda8a6475ae716a9e3580c
FIX=9f5b085ad4a7b38b067c9da0dc5b45462c4d796e
PARENT=8ba80aee1e942651e34d64a5c501a98d6c49adb6
GIT=(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

hash_file() {
  sha256sum -- "$1" | awk '{print $1}'
}

[[ -f "$OWNED/result.json" ]]
[[ -f "$OWNED/cases.jsonl" ]]
[[ -f "$OWNED/report.md" ]]
[[ -f "$OWNED/replay.sh" ]]
[[ -d "$CLONE/.git" ]]
[[ -d "$ADB/.git" ]]
[[ -f "$WHEELS/ha_mcp-7.5.0-py3-none-any.whl" ]]
[[ -f "$WHEELS/ha_mcp-7.7.0-py3-none-any.whl" ]]

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
[[ "$(hash_file "$OWNED/work/pages/ghsa-q855-8rh5-jfgq.json")" == "fa423727d9fe61f903e744547f85e41dd1020ac79473b8d807c023dbda9a0346" ]]
[[ "$("${GIT[@]}" -C "$ADB" rev-parse HEAD)" == "a42c436870111aa3f221257c9d56126a93173ccc" ]]

# Current overlap / pending-proposal identity pins. These do not re-select the reviewed set.
[[ "$(hash_file scripts/publication_adjudications.json)" == "9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-actual-gogs-redteam-grok46-high/cases.jsonl)" == "3a74a0133dbfd3e128834f9bbc641b78c1515e5647fd07085bba30e2984d827f" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh/cases.jsonl)" == "b423591122de906c65c49ac62ba581ffcd3442880eae638e8de773c90bc689dd" ]]
[[ "$(hash_file "$WHEELS/ha_mcp-7.5.0-py3-none-any.whl")" == "a94521373161d1202907190d64a75716c4d664aa133b00067718f9c9e0700538" ]]
[[ "$(hash_file "$WHEELS/ha_mcp-7.7.0-py3-none-any.whl")" == "7fb6fa548779da9c946afef19919eb75bcd60e1ef9f7cc8f793e4e05576cba89" ]]

python3 - "$OWNED" <<'PY'
import hashlib, json, re, sys, zipfile
from pathlib import Path

owned = Path(sys.argv[1])
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
assert res["counts"]["PASS"] == 1
assert res["counts"]["REJECT"] == 29
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 0
assert res["counts"]["countable_pass"] == 0
assert res["counts"]["proposed_acceptances"] == 1
assert res["proposed_pass_ids"] == ["GHSA-Q855-8RH5-JFGQ"]
assert res["proposed_acceptances_are_uncounted"] is True
assert res["claim_boundary"]["more_than_200_claim_supported_by_this_review"] is False
assert res["claim_boundary"]["canonical_ledger_edited"] is False
assert res["unreviewed_stream"]["same_id_first_party"] == 0
assert res["unreviewed_stream"]["alias_other_ghsa"] == 684
assert res["frozen_input_hashes"]["CONTRACT.md"] == "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"
assert res["frozen_input_hashes"]["baseline.json"] == "d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132"
assert res["frozen_input_hashes"]["fp211_public_cases.jsonl"] == "e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257"
assert res["frozen_input_hashes"]["fp211_canonical_ledger.jsonl"] == "1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6"
assert res["frozen_input_hashes"]["fp211_final_mechanisms.jsonl"] == "0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2"
assert res["frozen_input_hashes"]["netnew22_result.json"] == "c50b878583f3b09f37d7c88638ea179e75cf6b0ccf2e4ade689f2d673f7b0829"
assert res["frozen_input_hashes"]["netnew22_cases.jsonl"] == "d4d3c96ba0a60214971ab88f3de7adce1edfc27f39a388906600aad91b5c1889"
assert res["frozen_input_hashes"]["gn_ai_commit_scans.jsonl"] == "a6d7ca1584dbeb1596c57643092df0178001925efe0de60ca3eee5f72182481a"
assert res["frozen_input_hashes"]["af_ai_commits.jsonl"] == "9659e93e82df4428df361507c6728ac83988211b0282ffbc3c12e3aba529d6d0"
assert res["frozen_input_hashes"]["oz_ai_mine.jsonl"] == "047bbb068b09194a59a934117fec1448563e073147bf2e005d53f427bdc8c18a"
assert res["frozen_input_hashes"]["advisory_database_head"] == "a42c436870111aa3f221257c9d56126a93173ccc"
assert res["current_overlap_check"]["publication_adjudications"] == "9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f"
for key in (
    "CONTRACT.md",
    "baseline.json",
    "fp211_public_cases.jsonl",
    "fp211_canonical_ledger.jsonl",
    "fp211_final_mechanisms.jsonl",
    "netnew22_result.json",
    "netnew22_cases.jsonl",
):
    assert res["frozen_input_hashes"][key] == res["current_input_hashes"][key], key

cons = res["conservation"]
assert cons["reviewed_2025_2026"] == 12817
assert cons["window_first_party_active"] == 8757
assert cons["with_commit_refs"] == 4652
assert cons["eligible_after_exclude"] == 4507
assert cons["rank_pool"] == 3473
assert cons["hits"] == 830
assert cons["deep_reviewed"] == 30
assert cons["unreviewed_hits"] == 800
assert cons["rank_misses"] == 2643
assert cons["skipped_no_ai_or_clone"] == 1034
assert cons["no_ai_commits"] == 1025
assert cons["clone_missing"] == 9
assert cons["deep_reviewed"] + cons["unreviewed_hits"] + cons["rank_misses"] == cons["rank_pool"]
assert cons["rank_pool"] + cons["skipped_no_ai_or_clone"] == cons["eligible_after_exclude"]
assert cons["no_ai_commits"] + cons["clone_missing"] == cons["skipped_no_ai_or_clone"]
assert cons["reviewed_plus_unreviewed_hits_plus_misses_equals_rank_pool"] is True
assert cons["rank_pool_plus_skipped_equals_eligible"] is True
assert cons["skipped_parts_equal"] is True

rank = json.loads((owned / "work/rank-summary.json").read_text())
assert rank["reviewed_rows"] == 12817
assert rank["rank_pool"] == 3473
assert rank["hits"] == 830
assert rank["selected_count"] == 30

excl = json.loads((owned / "work/exclusion.json").read_text())
assert excl["counts"]["baseline_48"] == 48
assert excl["counts"]["netred_keep_21"] == 21
assert excl["counts"]["pending_actual_b3_gogs"] == 5
assert excl["counts"]["fp211_public_case_ids"] == 212
assert excl["counts"]["discovery_exclude"] == 215
assert len(excl["baseline_48"]) == 48
assert len(excl["netred_keep_21"]) == 21
assert len(excl["pending_actual_b3_gogs"]) == 5

unrev_meta = json.loads((owned / "work/unreviewed-conservation.json").read_text())
assert unrev_meta["same_id_first_party"] == 0
assert unrev_meta["alias_other_ghsa"] == 684
assert unrev_meta["fp_url_hits"] == 684

cases = [json.loads(line) for line in (owned / "cases.jsonl").read_text().splitlines() if line.strip()]
assert len(cases) == 30
ids = [c["case_id"] for c in cases]
assert len(set(ids)) == 30
assert ids == rank["selected"]
assert ids == res["selection"]["selected_ids"]
pass_rows = [c for c in cases if c["worker_verdict"] == "PASS"]
reject_rows = [c for c in cases if c["worker_verdict"] == "REJECT"]
assert [c["case_id"] for c in pass_rows] == ["GHSA-Q855-8RH5-JFGQ"]
assert len(reject_rows) == 29
assert all(c["worker_verdict"] in {"PASS", "REJECT"} for c in cases)
assert all(c["countable"] is False for c in cases)
assert all(c["causal_admission"] is False for c in cases)
assert all(c["english_only"] is True for c in cases)

gates = [
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
]
p = pass_rows[0]
assert all(p[g] == "PASS" for g in gates)
assert p["failing_gates"] == []
assert p["contribution_class"] == "AI_DIRECT_ROOT"
assert p["countable_proposal"] is True
assert p["worker_pass_is_proposal_only"] is True
assert p["candidate_set"] == ["9783f346795be919bffda8a6475ae716a9e3580c"]
assert p["minimum_fix_set"] == ["9f5b085ad4a7b38b067c9da0dc5b45462c4d796e"]
assert p["carrier_set"] == []
assert p["vulnerable_release_evidence"]["git_tag"] == "v7.5.0"
assert p["fixed_release_evidence"]["git_tag"] == "v7.7.0"
assert p["vulnerable_release_evidence"]["settings_ui_git_hash_object"] == "46d32362fbed4d0706bf70601cbfbbf2dfc69b08"
assert p["fixed_release_evidence"]["settings_ui_git_hash_object"] == "36479aaa873cba5d0cad41d21327f01646c7bb72"
assert p["vulnerable_release_evidence"]["wheel_member_git_hash_object"] == p["vulnerable_release_evidence"]["settings_ui_git_hash_object"]
assert p["fixed_release_evidence"]["wheel_member_git_hash_object"] == p["fixed_release_evidence"]["settings_ui_git_hash_object"]
for row in reject_rows:
    failed = [g for g in gates if row[g] != "PASS"]
    assert failed, row["case_id"]
    assert row["countable_proposal"] is False

exclude = set(excl["baseline_48"]) | set(excl["netred_keep_21"]) | set(excl["pending_actual_b3_gogs"])
assert not (set(ids) & exclude)
unrev = [line.strip() for line in (owned / "work/unreviewed-hit-ids.txt").read_text().splitlines() if line.strip()]
assert len(unrev) == 800
assert len(set(unrev)) == 800
assert not (set(ids) & set(unrev))

page = json.loads((owned / "work/pages/ghsa-q855-8rh5-jfgq.json").read_text())
assert page["id"].lower() == "ghsa-q855-8rh5-jfgq"
assert page.get("withdrawn") in (None, "")
assert page["database_specific"]["github_reviewed"] is True
assert any(
    "github.com/homeassistant-ai/ha-mcp/security/advisories/GHSA-q855-8rh5-jfgq" in (ref.get("url") or "")
    for ref in page.get("references", [])
)

def git_blob_hash(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

wheels = Path("/home/hanqing/.cache/ghsa200-worker-clones/directroot-mining/pypi")
with zipfile.ZipFile(wheels / "ha_mcp-7.5.0-py3-none-any.whl") as zf:
    data = zf.read("ha_mcp/settings_ui.py")
assert git_blob_hash(data) == "46d32362fbed4d0706bf70601cbfbbf2dfc69b08"
assert b"SUPERVISOR_INGRESS" not in data
with zipfile.ZipFile(wheels / "ha_mcp-7.7.0-py3-none-any.whl") as zf:
    data = zf.read("ha_mcp/settings_ui.py")
assert git_blob_hash(data) == "36479aaa873cba5d0cad41d21327f01646c7bb72"
assert b"SUPERVISOR_INGRESS" in data
assert b"_ingress_only" in data
PY

# Git proofs for the single PASS proposal. Expected-negative checks keep stderr clean.
[[ "$("${GIT[@]}" -C "$CLONE" rev-list --parents -n 1 "$AI")" == "$AI $PARENT" ]]
if "${GIT[@]}" -C "$CLONE" cat-file -e "${AI}^:src/ha_mcp/settings_ui.py" 2>/dev/null; then
  exit 1
fi
"${GIT[@]}" -C "$CLONE" cat-file -e "${AI}:src/ha_mcp/settings_ui.py"
"${GIT[@]}" -C "$CLONE" merge-base --is-ancestor "$AI" v7.5.0
if "${GIT[@]}" -C "$CLONE" merge-base --is-ancestor "$FIX" v7.5.0; then
  exit 1
fi
"${GIT[@]}" -C "$CLONE" merge-base --is-ancestor "$FIX" v7.7.0
[[ "$("${GIT[@]}" -C "$CLONE" rev-parse v7.5.0:src/ha_mcp/settings_ui.py)" == "46d32362fbed4d0706bf70601cbfbbf2dfc69b08" ]]
[[ "$("${GIT[@]}" -C "$CLONE" rev-parse v7.7.0:src/ha_mcp/settings_ui.py)" == "36479aaa873cba5d0cad41d21327f01646c7bb72" ]]
v750_blame=$("${GIT[@]}" -C "$CLONE" blame -l -L968,968 v7.5.0 -- src/ha_mcp/settings_ui.py)
[[ "$v750_blame" == "$AI "* ]]
v770_blame=$("${GIT[@]}" -C "$CLONE" blame -l -L3135,3135 v7.7.0 -- src/ha_mcp/settings_ui.py)
[[ "$v770_blame" == "$FIX "* ]]
ai_body=$("${GIT[@]}" -C "$CLONE" log -1 --format=%B "$AI")
[[ "$ai_body" == *"noreply@anthropic.com"* ]]
[[ "$ai_body" == *"Claude Opus 4.6"* ]]

echo OK
