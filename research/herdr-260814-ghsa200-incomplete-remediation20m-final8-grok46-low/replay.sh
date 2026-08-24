#!/usr/bin/env bash
set -euo pipefail
ROOT="/home/hanqing/agents/ai-slop"
OWNED="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20m-final8-grok46-low"
ADV="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database"
SIB20="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20-grok46-low"
SIB20B="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20b-grok46-low"
SIB20C="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20c-grok46-low"
SIB20D="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20d-grok46-low"
SIB20E="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20e-grok46-low"
SIB20F="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20f-grok46-low"
SIB20G="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20g-grok46-low"
SIB20H="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20h-grok46-low"
SIB20I="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20i-grok46-low"
SIB20J="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20j-grok46-low"
SIB20K="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20k-grok46-low"
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
[[ "$(hash_file "$SIB20I/work/selected-20.jsonl")" == "e7e23c15eb7d29d77bb1f0d6e0289ddd3a4e293d5fe7dccf5b7b19bf47441002" ]]
[[ "$(hash_file "$SIB20J/work/selected-20.jsonl")" == "ccf1d374787a0464016502fb55f706a808172c9fd24e5dd744c02c68f93bab6e" ]]
[[ "$(hash_file "$SIB20K/work/selected-20.jsonl")" == "c24e10d3aa8ba6f1d5e1ead021f696fac88e3225f855ad33867ac03cf77cfc3d" ]]
[[ "$(hash_file "$SIB20K/work/freeze.json")" == "0d717e4996ebb54690dd701b3fb8a5d875a795c0ac186747e29075183fc9d0ee" ]]
[[ "$(hash_file "$OWNED/work/selected-8.jsonl")" == "33d8ace133a97deecb052d299a7e6a1d19e4a7d09a073e01f4e816852cdb9206" ]]
python3 - <<'PY'
import json
from pathlib import Path
owned=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-incomplete-remediation20m-final8-grok46-low")
sib20k=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-incomplete-remediation20k-grok46-low")
sel=[json.loads(l)["ghsa_id"] for l in (owned/"work/selected-8.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l)["case_id"] for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
assert sel==cases and len(sel)==8
expected=["GHSA-PJ3V-9CM8-GVJ8","GHSA-8H6M-WV39-239M","GHSA-PJR6-JX7R-J4R6","GHSA-6Q9C-M9FR-865M","GHSA-5XH2-23CC-5JC6","GHSA-JR5F-V2JV-69X6","GHSA-76G3-38JV-WXH4","GHSA-8P83-CPFG-FJ3G"]
assert sel==expected
prior=json.loads((sib20k/"work/freeze.json").read_text())["unreviewed_keyword_ids"]
assert len(prior)==28
assert sel==prior[20:28]
s20k=[json.loads(l)["ghsa_id"] for l in (sib20k/"work/selected-20.jsonl").read_text().splitlines() if l.strip()]
assert set(sel).isdisjoint(s20k)
rows=[json.loads(l) for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
assert all(r["worker_verdict"]!="PASS" for r in rows)
causal=["ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
blocked=[r for r in rows if r["worker_verdict"]=="BLOCKED"]
assert len(blocked)==2
assert {r["reject_class"] for r in blocked}=={"NO_LOCAL_CLONE"}
for r in blocked:
    assert r["countable"] is False
    assert r["publication_status"]=="HOLD"
    assert r["identity_gate"]=="PASS" and r["gates"]["identity_gate"]=="PASS"
    assert r["remediation_patch_delta"]=="BLOCKED"
    for g in causal:
        assert r[g]=="BLOCKED" and r["gates"][g]=="BLOCKED"
        assert r[g]!="FAIL"
rej=[r for r in rows if r["worker_verdict"]=="REJECT"]
assert len(rej)==6
result=json.loads((owned/"result.json").read_text())
assert result["unreviewed_n"]==0
assert result["counts"]["PASS"]==0
assert result["publication_status"]=="HOLD"
assert result["conservation"]["identity"]=="48 = 20 + 20 + 8"
assert result["conservation"]["reserved_for_20l_not_inspected"] is True
print("freeze_and_cases_ok")
PY
git -C /home/hanqing/.cache/cve-analyzer/repos/trpc_trpc log -1 --format='%an' 9beb26c636d44852e0f407f3d7a82ad54df65b4d | grep -qx 'Luke Childs'
git -C /home/hanqing/.cache/cve-analyzer/repos/rancher_rancher log -1 --format='%an' 7f16b596120dd382ce6e9ed0baf83bc23f633054 | grep -qx 'Jonathan Crowther'
git -C /home/hanqing/.cache/cve-analyzer/repos/auth0_nextjs-auth0 log -1 --format='%an' a4f061aed02ffa132feca8adfbd11704df17e1c3 | grep -qx 'Frederik Prijck'
git -C /home/hanqing/.cache/cve-analyzer/repos/safedep_vet log -1 --format='%an' 0ae3560ba11846375812377299fe078d45cc3d48 | grep -qx 'Arunanshu Biswas'
git -C /home/hanqing/.cache/cve-analyzer/repos/axios_axios log -1 --format='%an' fb8eec214ce7744b5ca787f2c3b8339b2f54b00f | grep -qx 'Fasoro-Joseph Alexander'
git -C /home/hanqing/.cache/cve-analyzer/repos/axios_axios log -1 --format='%an' 02c3c69ced0f8fd86407c23203835892313d7fde | grep -qx 'Gabe Mendoza'
git -C /home/hanqing/.cache/cve-analyzer/repos/rancher_rancher log -1 --format='%an' 08f4cff3fc174bffa90f3996df1962ddc739ac55 | grep -qx 'Jonathan Crowther'
echo replay_ok
