#!/usr/bin/env bash
set -euo pipefail
ROOT="/home/hanqing/agents/ai-slop"
OWNED="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20i-grok46-low"
ADV="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database"
SIB20="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20-grok46-low"
SIB20B="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20b-grok46-low"
SIB20C="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20c-grok46-low"
SIB20D="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20d-grok46-low"
SIB20E="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20e-grok46-low"
SIB20F="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20f-grok46-low"
SIB20G="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20g-grok46-low"
SIB20H="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20h-grok46-low"
hash_file() { sha256sum "$1" | awk '{print $1}'; }
[[ "$(git -C "$ADV" rev-parse HEAD)" == "a42c436870111aa3f221257c9d56126a93173ccc" ]]
[[ "$(hash_file "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md")" == "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3" ]]
[[ "$(hash_file "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json")" == "dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c" ]]
[[ "$(hash_file "$SIB20/work/selected-20.jsonl")" == "3d0e65cd3866eb4d45d70d9222c364f31e4950b04c0ce7b0bf19c3371c888dba" ]]
[[ "$(hash_file "$SIB20B/work/selected-20.jsonl")" == "0f74281db331aa95b76b0e208e743e38a626ca8ff2fe20c4031165b2330fb92b" ]]
[[ "$(hash_file "$SIB20C/work/selected-20.jsonl")" == "c4f91e54b68b28295d20ff1d468576ea9f2ca4874642b6e1df258cdace3fed6c" ]]
[[ "$(hash_file "$SIB20D/work/selected-20.jsonl")" == "6270cc030886583d088f0ab074cfe91f341412a07fa55b9c7896f54eccddb8bd" ]]
[[ "$(hash_file "$SIB20E/work/selected-20.jsonl")" == "a07fdd1d44c92a2c4b2bffcb66927500319fd99a11dbebedefa342b649b1afc3" ]]
[[ "$(hash_file "$SIB20F/work/selected-20.jsonl")" == "53bf2ff055fa14d381f4dac699a1e1a0d5f09867bda9ae6bac08205914abbd92" ]]
[[ "$(hash_file "$SIB20G/work/selected-20.jsonl")" == "6559d200404a07b32f32f4b60b85ac8abeb8d965e940538f9873bf927fed4a20" ]]
[[ "$(hash_file "$SIB20H/work/selected-20.jsonl")" == "a3fe5f00950225db235d5698c21677da4c83d42b0d117d66eef9fa144a9b933d" ]]
[[ "$(hash_file "$OWNED/work/selected-20.jsonl")" == "e7e23c15eb7d29d77bb1f0d6e0289ddd3a4e293d5fe7dccf5b7b19bf47441002" ]]
python3 - <<'PY'
import json
from pathlib import Path
owned=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-incomplete-remediation20i-grok46-low")
sib20h=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-incomplete-remediation20h-grok46-low")
sel=[json.loads(l)["ghsa_id"] for l in (owned/"work/selected-20.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l)["case_id"] for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
assert sel==cases and len(sel)==20
s20h=[json.loads(l)["ghsa_id"] for l in (sib20h/"work/selected-20.jsonl").read_text().splitlines() if l.strip()]
assert set(sel).isdisjoint(s20h)
prior20h=json.loads((sib20h/"work/freeze.json").read_text())["unreviewed_keyword_ids"][:20]
assert sel==prior20h
rows=[json.loads(l) for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
assert all(r["worker_verdict"]!="PASS" for r in rows)
causal=["ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
blocked=[r for r in rows if r["worker_verdict"]=="BLOCKED"]
assert len(blocked)==11
assert {r["reject_class"] for r in blocked}=={"NO_LOCAL_CLONE","MISSING_CITED_FIX"}
for r in blocked:
    assert r["countable"] is False
    assert r["publication_status"]=="HOLD"
    assert r["identity_gate"]=="PASS" and r["gates"]["identity_gate"]=="PASS"
    assert r["remediation_patch_delta"]=="BLOCKED"
    for g in causal:
        assert r[g]=="BLOCKED" and r["gates"][g]=="BLOCKED"
        assert r[g]!="FAIL"
rej=[r for r in rows if r["worker_verdict"]=="REJECT"]
assert len(rej)==9
result=json.loads((owned/"result.json").read_text())
assert result["unreviewed_n"]==68
assert result["counts"]["PASS"]==0
assert result["publication_status"]=="HOLD"
print("freeze_and_cases_ok")
PY
git -C /home/hanqing/.cache/cve-analyzer/repos/snowflakedb_snowflake-connector-python log -1 --format='%an' f3f9b666518d29c31a49384bbaa9a65889e72056 | grep -qx 'Jakub Szczerbiński'
git -C /home/hanqing/.cache/cve-analyzer/repos/cometbft_cometbft log -1 --format='%an' 0ee80cd609c7ae9fe856bdd1c6d38553fdae90ce | grep -qx 'Anton Kaliaev'
git -C /home/hanqing/.cache/cve-analyzer/repos/octokit_request-error.js log -1 --format='%an' d558320874a4bc8d356babf1079e6f0056a59b9e | grep -qx 'DayShift'
git -C /home/hanqing/.cache/cve-analyzer/repos/9001_copyparty log -1 --format='%an' 438ea6ccb06f39d7cbb4b6ee7ad44606e21a63dd | grep -qx 'ed'
git -C /home/hanqing/.cache/cve-analyzer/repos/rack_rack log -1 --format='%an' 803aa221e8302719715e224f4476e438f2531a53 | grep -qx 'Samuel Williams'
git -C /home/hanqing/.cache/cve-analyzer/repos/rack_rack log -1 --format='%an' 50caab74fa01ee8f5dbdee7bb2782126d20c6583 | grep -qx 'Samuel Williams'
git -C /home/hanqing/.cache/cve-analyzer/repos/mockoon_mockoon log -1 --format='%an' c7f6e23e87dc3b8cc44e5802af046200a797bd2e | grep -qx 'Guillaume'
git -C /home/hanqing/.cache/cve-analyzer/repos/pimcore_pimcore log -1 --format='%an' 19a8520895484e68fd254773e32476565d91deea | grep -qx 'JiaJia Ji'
git -C /home/hanqing/.cache/cve-analyzer/repos/cosmos_cosmos-sdk log -1 --format='%an' cbd69fb1f4fac418c1f8c6253f5f91fb1263776a | grep -qx 'Alexander Peters'
echo replay_ok
