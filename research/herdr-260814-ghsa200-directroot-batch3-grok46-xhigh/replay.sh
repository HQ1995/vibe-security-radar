#!/usr/bin/env zsh
set -euo pipefail

# Fail-fast read-only offline replay.
# Do not fetch, clone, commit, push, or rerun ranking.

export GIT_OPTIONAL_LOCKS=0

ROOT=/home/hanqing/agents/ai-slop
cd "$ROOT"

OWNED=autoresearch/herdr-260814-ghsa200-directroot-batch3-grok46-xhigh
FIRST=autoresearch/herdr-260813-ghsa200-directroot-mining-grok46-xhigh
BATCH2=autoresearch/herdr-260813-ghsa200-directroot-batch2-grok46-xhigh
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
[[ -f "$BATCH2/work/selected-30.jsonl" ]]
[[ -d "$ADB/.git" ]]

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
[[ "$(hash_file "$BATCH2/work/selected-30.jsonl")" == "05ff6f4b3a0de2d61be00bbcbd3adda9587e9897303b3fc595948dd4071e189e" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json)" == "699f6160b6ecb9c9ce2cdae257c9a12dbdf4f7ef8a925196fcfd4fcf0b1140d8" ]]
[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$ADB" rev-parse HEAD)" == "a42c436870111aa3f221257c9d56126a93173ccc" ]]

# Current overlap pins. These do not re-select the reviewed set.
[[ "$(hash_file scripts/publication_adjudications.json)" == "9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-actual-gogs-redteam-grok46-high/cases.jsonl)" == "3a74a0133dbfd3e128834f9bbc641b78c1515e5647fd07085bba30e2984d827f" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh/cases.jsonl)" == "b423591122de906c65c49ac62ba581ffcd3442880eae638e8de773c90bc689dd" ]]

python3 - "$OWNED" "$FIRST" "$BATCH2" <<'PY'
import hashlib, json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
first = Path(sys.argv[2])
batch2 = Path(sys.argv[3])
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
assert res["final_round_checkpoint"]["assigned_equals_reviewed"] is True
assert res["final_round_checkpoint"]["queue_exhausted"] is False
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 30
assert res["counts"]["assigned"] == 30
assert res["counts"]["reviewed"] == 30
assert res["counts"]["unreviewed"] == 740
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 0
assert res["counts"]["countable_pass"] == 0
assert res["counts"]["proposed_acceptances"] == 0
assert res["proposed_pass_ids"] == []
assert res["proposed_acceptances_are_uncounted"] is True
assert res["claim_boundary"]["more_than_200_claim_supported_by_this_review"] is False
assert res["claim_boundary"]["canonical_ledger_edited"] is False
assert res["unreviewed_stream"]["same_id_first_party"] == 0
assert res["unreviewed_stream"]["alias_other_ghsa"] == 684
assert res["frozen_input_hashes"]["CONTRACT.md"] == res["current_input_hashes"]["CONTRACT.md"]
assert res["frozen_input_hashes"]["first_packet_selected_30"] == res["current_input_hashes"]["first_packet_selected_30"]
assert res["frozen_input_hashes"]["first_packet_rank_hits"] == res["current_input_hashes"]["first_packet_rank_hits"]
assert res["frozen_input_hashes"]["batch2_selected_30"] == res["current_input_hashes"]["batch2_selected_30"]
assert res["frozen_input_hashes"]["canonical73_summary.json"] == res["current_input_hashes"]["canonical73_summary.json"]

cons = res["conservation"]
assert cons["reviewed_2025_2026"] == 12817
assert cons["window_first_party_active"] == 8757
assert cons["with_commit_refs"] == 4652
assert cons["eligible_after_exclude"] == 4507
assert cons["rank_pool"] == 3473
assert cons["hits"] == 830
assert cons["batch1_deep_reviewed"] == 30
assert cons["batch2_deep_reviewed"] == 30
assert cons["deep_reviewed"] == 30
assert cons["unreviewed_hits"] == 740
assert cons["rank_misses"] == 2643
assert cons["skipped_no_ai_or_clone"] == 1034
assert cons["no_ai_commits"] == 1025
assert cons["clone_missing"] == 9
assert cons["batch1_deep_reviewed"] + cons["batch2_deep_reviewed"] + cons["deep_reviewed"] + cons["unreviewed_hits"] + cons["rank_misses"] == cons["rank_pool"]
assert cons["rank_pool"] + cons["skipped_no_ai_or_clone"] == cons["eligible_after_exclude"]
assert cons["assigned"] == 30
assert cons["reviewed"] == 30
assert cons["unreviewed"] == 740
assert cons["assigned_equals_reviewed"] is True
assert cons["selected_equals_ranked_61_to_90"] is True
assert cons["equation"] == "assigned=reviewed=30; 30+30+30+740+2643=3473"

hits = [json.loads(l) for l in (first / "work/rank-hits.jsonl").read_text().splitlines() if l.strip()]
ranked = sorted(hits, key=lambda r: r.get("score") or [0, 0, 0, 0], reverse=True)
first_sel = [json.loads(l)["ghsa_id"] for l in (first / "work/selected-30.jsonl").read_text().splitlines() if l.strip()]
batch2_sel = [json.loads(l)["ghsa_id"] for l in (batch2 / "work/selected-30.jsonl").read_text().splitlines() if l.strip()]
assert [r["ghsa_id"] for r in ranked[:30]] == first_sel
assert [r["ghsa_id"] for r in ranked[30:60]] == batch2_sel
canon73 = json.loads(Path("autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json").read_text())["strict_released_case_ids"]
assert "GHSA-Q855-8RH5-JFGQ" in first_sel
assert "GHSA-Q855-8RH5-JFGQ" in canon73

assigned = [
    "GHSA-W5C7-9QQW-6645",
    "GHSA-G2F5-GJR4-QJVM",
    "GHSA-29JH-8CFQ-RR8X",
    "GHSA-5WX6-MG75-V57R",
    "GHSA-CMW6-HCPP-C6JP",
    "GHSA-4GGG-H7PH-26QR",
    "GHSA-V529-VHWC-WFC5",
    "GHSA-75HX-XJ24-MQRW",
    "GHSA-538C-55JV-C5G9",
    "GHSA-8F24-V5VV-GM5J",
    "GHSA-G374-MGGX-P6XC",
    "GHSA-CJ4V-437J-JQ4C",
    "GHSA-WPPH-CJGR-7C39",
    "GHSA-VQX8-9XXW-F2M7",
    "GHSA-WW6V-V748-X7G9",
    "GHSA-MFG5-7Q5G-F37J",
    "GHSA-H656-5VCF-CM23",
    "GHSA-Q938-GHWV-8GVC",
    "GHSA-62F6-MRCJ-V8H5",
    "GHSA-56PX-HM34-XQJ5",
    "GHSA-3R9X-F23J-GC73",
    "GHSA-X3QM-P8HR-3C3H",
    "GHSA-3V85-FQVH-7RXF",
    "GHSA-JXX9-PX88-PJ69",
    "GHSA-M69W-P7M4-585J",
    "GHSA-QJVR-435C-5FJH",
    "GHSA-RJ4G-RQGH-RX9H",
    "GHSA-V6QF-75PR-P96M",
    "GHSA-562R-8445-54R2",
    "GHSA-XW57-23P8-9WC5",
]
assert assigned == [r["ghsa_id"] for r in ranked[60:90]]

cases = [json.loads(line) for line in (owned / "cases.jsonl").read_text().splitlines() if line.strip()]
assert len(cases) == 30
ids = [c["case_id"] for c in cases]
assert len(set(ids)) == 30
assert ids == assigned
assert ids == res["selection"]["selected_ids"]
sel_file = [json.loads(l)["ghsa_id"] for l in (owned / "work/selected-30.jsonl").read_text().splitlines() if l.strip()]
assert ids == sel_file
assert "GHSA-Q855-8RH5-JFGQ" not in ids
assert not (set(ids) & set(first_sel))
assert not (set(ids) & set(batch2_sel))
assert not (set(ids) & set(canon73))
assert all(c["worker_verdict"] == "REJECT" for c in cases)
assert all(c["countable"] is False for c in cases)
assert all(c["causal_admission"] is False for c in cases)
assert all(c["english_only"] is True for c in cases)
assert all(c["countable_proposal"] is False for c in cases)
assert all(c["identity_gate"] == "PASS" for c in cases)
assert all(c["ai_hunk_gate"] == "FAIL" for c in cases)
assert all(c["uniqueness_gate"] == "PASS" for c in cases)
gates = ["identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
for row in cases:
    failed = [g for g in gates if row[g] != "PASS"]
    assert failed, row["case_id"]
    assert row["failing_gates"] == failed

unrev_meta = json.loads((owned / "work/unreviewed-conservation.json").read_text())
assert unrev_meta["same_id_first_party"] == 0
assert unrev_meta["alias_other_ghsa"] == 684

unrev = [line.strip() for line in (owned / "work/unreviewed-hit-ids.txt").read_text().splitlines() if line.strip()]
assert len(unrev) == 740
assert len(set(unrev)) == 740
assert not (set(ids) & set(unrev))
assert not (set(first_sel) & set(unrev))
assert not (set(batch2_sel) & set(unrev))
assert [r["ghsa_id"] for r in ranked[90:]] == unrev
assert len(first_sel) + len(batch2_sel) + len(ids) + len(unrev) == 830

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
assert ckpt["expansion_stopped"] is True
assert res["current_overlap_check"]["selected_ids_in_live_adjudications"] == []
assert all((owned / "work/pages" / f"{i.lower()}.json").is_file() for i in ids)
assert all((owned / "work/packets" / f"{n:02d}-{i}.md").is_file() for n, i in enumerate(ids, 1))
PY

echo OK
