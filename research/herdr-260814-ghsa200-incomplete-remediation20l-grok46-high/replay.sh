#!/usr/bin/env bash
set -euo pipefail
ROOT="/home/hanqing/agents/ai-slop"
OWNED="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20l-grok46-high"
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
[[ "$(hash_file "$OWNED/work/selected-20.jsonl")" == "58f0c8b701202ed3a3d9ffb7f4d94b69c94e718b665dae57fe23ba9ea0fa08c8" ]]
python3 - <<'PY'
import json
from pathlib import Path
owned=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-incomplete-remediation20l-grok46-high")
sib20k=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-incomplete-remediation20k-grok46-low")
sel=[json.loads(l)["ghsa_id"] for l in (owned/"work/selected-20.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l)["case_id"] for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
assert sel==cases and len(sel)==20
s20k=[json.loads(l)["ghsa_id"] for l in (sib20k/"work/selected-20.jsonl").read_text().splitlines() if l.strip()]
assert set(sel).isdisjoint(s20k)
prior20k=json.loads((sib20k/"work/freeze.json").read_text())["unreviewed_keyword_ids"]
assert sel==prior20k[:20]
assert len(prior20k)==28
rows=[json.loads(l) for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
assert all(r["worker_verdict"]!="PASS" for r in rows)
assert all(ord(ch)<128 for line in (owned/"cases.jsonl").read_text().splitlines() for ch in line)
causal=["ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
blocked=[r for r in rows if r["worker_verdict"]=="BLOCKED"]
assert len(blocked)==7
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
assert len(rej)==13
result=json.loads((owned/"result.json").read_text())
assert result["unreviewed_n"]==8
assert result["conservation"]["identity"]=="28 = 20 + 8"
assert result["counts"]["PASS"]==0
assert result["publication_status"]=="HOLD"
assert result["more_than_200_claim"] is False
freeze=json.loads((owned/"work/freeze.json").read_text())
assert freeze["unreviewed_n"]==8
assert freeze["leader_verified_zero_overlap_with_true_final_directroot_queue"] is True
assert freeze["overlap_selected_vs_true_final_directroot_queue"]==[]
print("freeze_and_cases_ok")
PY
git -C /home/hanqing/.cache/cve-analyzer/repos/flarum_framework log -1 --format='%an' a05aaea3ee1e0a8b870935183193cd6052f1d402 | grep -qx 'Simon'
git -C /home/hanqing/.cache/cve-analyzer/repos/expr-lang_expr log -1 --format='%an' 0d19441454426d2f58edb22c31f3ba5f99c7a26e | grep -qx 'Ville Vesilehto'
git -C /home/hanqing/.cache/cve-analyzer/repos/youki-dev_youki log -1 --format='%an' 747e342d2026fbf3a395db3e2a491ebef00082f1 | grep -qx 'Yashodhan'
git -C /home/hanqing/.cache/cve-analyzer/repos/mccutchen_go-httpbin log -1 --format='%an' 0decfd1a2e88d85ca6bfb8a92421653f647cbc04 | grep -qx 'Will McCutchen'
git -C /home/hanqing/.cache/cve-analyzer/repos/frappe_frappe log -1 --format='%an' d14520edafdc8560f0bba4a26d27946c037a5cee | grep -qx 'Akhil Narang'
git -C /home/hanqing/.cache/cve-analyzer/repos/frappe_frappe log -1 --format='%an' 27f13437db161a173137d91cd07d0f9287d7c556 | grep -qx 'Akhil Narang'
git -C /home/hanqing/.cache/cve-analyzer/repos/frappe_frappe log -1 --format='%an' fb1b776a16036271caf39435729239018decb4c0 | grep -qx 'Akhil Narang'
git -C /home/hanqing/.cache/cve-analyzer/repos/frappe_frappe log -1 --format='%an' b2a6285dc4833c556800603eb3093341ffaac216 | grep -qx 'Akhil Narang'
git -C /home/hanqing/.cache/cve-analyzer/repos/directus_directus log -1 --format='%an' 42d8adf3f47e77d37662b4d4780783ca01fd9d33 | grep -qx 'Brainslug'
git -C /home/hanqing/.cache/cve-analyzer/repos/bentoml_bentoml log -1 --format='%an' b35f4f4fcc53a8c3fe8ed9c18a013fe0a728e194 | grep -qx 'Frost Ming'
git -C /home/hanqing/.cache/cve-analyzer/repos/apollographql_router log -1 --format='%an' ab6675a63174715ea6ff50881fc957831d4e9564 | grep -qx 'Sachin D. Shinde'
git -C /home/hanqing/.cache/cve-analyzer/repos/pytorch_pytorch log -1 --format='%an' 0eda02a94c754e2256ff1701bcc03c40ece2bbef | grep -qx 'Mikayla Gawarecki'
git -C /home/hanqing/.cache/cve-analyzer/repos/pytorch_pytorch log -1 --format='%an' 8d4b8a920a2172523deb95bf20e8e52d50649c04 | grep -qx 'pytorchbot'
git -C /home/hanqing/.cache/cve-analyzer/repos/cilium_cilium log -1 --format='%an' e8543eef05126e9ba8a845dc74e96f4e30f6dba9 | grep -qx 'Julian Wiedmann'
git -C /home/hanqing/.cache/cve-analyzer/repos/sparklemotion_nokogiri log -1 --format='%an' 5b9bc1c60a67f43930431f64ffe38b0807836948 | grep -qx 'Mike Dalessio'
echo replay_ok
