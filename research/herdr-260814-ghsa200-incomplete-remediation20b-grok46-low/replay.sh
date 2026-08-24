#!/usr/bin/env bash
set -euo pipefail
ROOT="/home/hanqing/agents/ai-slop"
OWNED="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20b-grok46-low"
ADV="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database"
SIB="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20-grok46-low"
hash_file() { sha256sum "$1" | awk '{print $1}'; }
[[ "$(git -C "$ADV" rev-parse HEAD)" == "a42c436870111aa3f221257c9d56126a93173ccc" ]]
[[ "$(hash_file "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md")" == "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3" ]]
[[ "$(hash_file "$ROOT/autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json")" == "699f6160b6ecb9c9ce2cdae257c9a12dbdf4f7ef8a925196fcfd4fcf0b1140d8" ]]
[[ "$(hash_file "$SIB/work/selected-20.jsonl")" == "3d0e65cd3866eb4d45d70d9222c364f31e4950b04c0ce7b0bf19c3371c888dba" ]]
[[ "$(hash_file "$OWNED/work/selected-20.jsonl")" == "0f74281db331aa95b76b0e208e743e38a626ca8ff2fe20c4031165b2330fb92b" ]]
python3 - <<'PY'
import json
from pathlib import Path
owned=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-incomplete-remediation20b-grok46-low")
sib=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-incomplete-remediation20-grok46-low")
sel=[json.loads(l)["ghsa_id"] for l in (owned/"work/selected-20.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l)["case_id"] for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
assert sel==cases and len(sel)==20
sib20=[json.loads(l)["ghsa_id"] for l in (sib/"work/selected-20.jsonl").read_text().splitlines() if l.strip()]
assert set(sel).isdisjoint(sib20)
rows=[json.loads(l) for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
assert all(r["worker_verdict"]!="PASS" for r in rows)
causal=["ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
blocked=[r for r in rows if r["worker_verdict"]=="BLOCKED"]
assert len(blocked)==4
assert {r["reject_class"] for r in blocked}=={"NO_LOCAL_CLONE","UNAVAILABLE_PRIMARY_EVIDENCE"}
for r in blocked:
    assert r["countable"] is False
    assert r["publication_status"]=="HOLD"
    assert r["identity_gate"]=="PASS" and r["gates"]["identity_gate"]=="PASS"
    assert r["remediation_patch_delta"]=="BLOCKED"
    for g in causal:
        assert r[g]=="BLOCKED" and r["gates"][g]=="BLOCKED"
        assert r[g]!="FAIL"
rej=[r for r in rows if r["worker_verdict"]=="REJECT"]
assert len(rej)==16
result=json.loads((owned/"result.json").read_text())
assert result["unreviewed_n"]==208
assert result["counts"]["PASS"]==0
assert result["publication_status"]=="HOLD"
print("freeze_and_cases_ok")
PY
git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/navidrome__navidrome log -1 --format='%an' 09ae41a2da66264c60ef307882362d2e2d8d8b89 | grep -qx 'Deluan'
git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/minio__minio log -1 --format='%an' 8c70975283f9f4ce80f331a25c7475a36279e519 | grep -qx 'Harshavardhana'
git -C /home/hanqing/.cache/cve-analyzer/repos/phpoffice_phpspreadsheet log -1 --format='%an' 45052f88e04c735d56457a8ffcdc40b2635a028e | grep -qx 'oleibman'
git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/laravel__framework log -1 --format='%an' a4f7a8f9b83e21882abeef78c3174c66b0f4a26b | grep -qx 'Mior Muhammad Zaki'
echo replay_ok
