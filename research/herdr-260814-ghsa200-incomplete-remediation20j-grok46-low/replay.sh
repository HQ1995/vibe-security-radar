#!/usr/bin/env bash
set -euo pipefail
ROOT="/home/hanqing/agents/ai-slop"
OWNED="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20j-grok46-low"
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
[[ "$(hash_file "$OWNED/work/selected-20.jsonl")" == "ccf1d374787a0464016502fb55f706a808172c9fd24e5dd744c02c68f93bab6e" ]]
python3 - <<'PY'
import json
from pathlib import Path
owned=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-incomplete-remediation20j-grok46-low")
sib20i=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-incomplete-remediation20i-grok46-low")
sel=[json.loads(l)["ghsa_id"] for l in (owned/"work/selected-20.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l)["case_id"] for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
assert sel==cases and len(sel)==20
s20i=[json.loads(l)["ghsa_id"] for l in (sib20i/"work/selected-20.jsonl").read_text().splitlines() if l.strip()]
assert set(sel).isdisjoint(s20i)
prior20i=json.loads((sib20i/"work/freeze.json").read_text())["unreviewed_keyword_ids"][:20]
assert sel==prior20i
rows=[json.loads(l) for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
assert all(r["worker_verdict"]!="PASS" for r in rows)
causal=["ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
blocked=[r for r in rows if r["worker_verdict"]=="BLOCKED"]
assert len(blocked)==7
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
assert len(rej)==13
result=json.loads((owned/"result.json").read_text())
assert result["unreviewed_n"]==48
assert result["counts"]["PASS"]==0
assert result["publication_status"]=="HOLD"
print("freeze_and_cases_ok")
PY
git -C /home/hanqing/.cache/cve-analyzer/repos/directus_directus log -1 --format='%an' 2e893f9c576d5a02506272fe2c0bcc12e6c58768 | grep -qx 'ian'
git -C /home/hanqing/.cache/cve-analyzer/repos/sveltejs_kit log -1 --format='%an' d3300c6a67908590266c363dba7b0835d9a194cf | grep -qx 'Rich Harris'
git -C /home/hanqing/.cache/cve-analyzer/repos/vllm-project_vllm log -1 --format='%an' cb84e45ac75b42ba6795145923e8eb323bb825ad | grep -qx 'Russell Bryant'
git -C /home/hanqing/.cache/cve-analyzer/repos/yeswiki_yeswiki log -1 --format='%an' 0d4efc880a727599fa4f6d7a64cc967afe475530 | grep -qx 'Florian Schmitt'
git -C /home/hanqing/.cache/cve-analyzer/repos/linode_terraform-provider-linode log -1 --format='%an' 43a925d826b999f0355de3dc7330c55f496824c0 | grep -qx 'Zhiwei Liang'
git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/h44z__wg-portal log -1 --format='%an' 62dbdfe0f96045d46e121d509fc181fbb7936895 | grep -qx 'Christoph Haas'
git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/h44z__wg-portal log -1 --format='%an' 62e7f9d8b9ca64f39a8e2aff1851bd5ee04ad016 | grep -qx 'Dan Berg'
git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/kubewarden__kubewarden-controller log -1 --format='%an' 51a88dfbb4c090ce0f76a22d98106518e0824d0b | grep -qx 'Flavio Castelli'
git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/kubewarden__kubewarden-controller log -1 --format='%an' 8124039b5f0c955d0ee8c8ca12d4415282f02d2c | grep -qx 'Flavio Castelli'
git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/netty__netty log -1 --format='%an' 87f40725155b2f89adfde68c7732f97c153676c4 | grep -qx 'Norman Maurer'
git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/hickory-dns__hickory-dns log -1 --format='%an' e118c6eec569f4340421f86ee0686714010c63e9 | grep -qx 'David Cook'
git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/home-assistant__core log -1 --format='%an' 8c6547f1b64f4a3d9f10090b97383353c9367892 | grep -qx 'vexofp'
git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/getformwork__formwork log -1 --format='%an' d9f0c1feb3b9855d5bdc8bb189c0aaab2792e7ca | grep -qx 'Giuseppe Criscione'
git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/keycloak__keycloak log -1 --format='%an' 5aa2b4c75bb474303ab807017582bc01a9f7e378 | grep -qx 'Pedro Igor'
echo replay_ok
