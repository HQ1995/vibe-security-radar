#!/usr/bin/env bash
set -euo pipefail
ROOT="/home/hanqing/agents/ai-slop"
OWNED="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20k-grok46-low"
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
[[ "$(hash_file "$OWNED/work/selected-20.jsonl")" == "c24e10d3aa8ba6f1d5e1ead021f696fac88e3225f855ad33867ac03cf77cfc3d" ]]
python3 - <<'PY'
import json
from pathlib import Path
owned=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-incomplete-remediation20k-grok46-low")
sib20j=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-incomplete-remediation20j-grok46-low")
sel=[json.loads(l)["ghsa_id"] for l in (owned/"work/selected-20.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l)["case_id"] for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
assert sel==cases and len(sel)==20
s20j=[json.loads(l)["ghsa_id"] for l in (sib20j/"work/selected-20.jsonl").read_text().splitlines() if l.strip()]
assert set(sel).isdisjoint(s20j)
prior20j=json.loads((sib20j/"work/freeze.json").read_text())["unreviewed_keyword_ids"][:20]
assert sel==prior20j
rows=[json.loads(l) for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
assert all(r["worker_verdict"]!="PASS" for r in rows)
causal=["ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
blocked=[r for r in rows if r["worker_verdict"]=="BLOCKED"]
assert len(blocked)==10
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
assert len(rej)==10
result=json.loads((owned/"result.json").read_text())
assert result["unreviewed_n"]==28
assert result["counts"]["PASS"]==0
assert result["publication_status"]=="HOLD"
print("freeze_and_cases_ok")
PY
git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/mmaitre314__picklescan log -1 --format='%an' 62e76cfdf9aaaa3d0a26b78f7a93710406482274 | grep -qx 'Matthieu Maitre'
git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/nats-io__nats-server log -1 --format='%an' 3e7e4645a24e829a36b4210f2d7c34dea7f7a424 | grep -qx 'Neil Twigg'
git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/HumanSignal__label-studio log -1 --format='%an' ea2462bf042bbf370b79445d02a205fbe547b505 | grep -qx 'Nick Skriabin'
git -C /home/hanqing/.cache/cve-analyzer/repos/denoland_deno log -1 --format='%an' c380447de7849aee6614bee90e5625f9e2b9adc3 | grep -qx 'Espen Hovlandsdal'
git -C /home/hanqing/.cache/cve-analyzer/repos/typo3_typo3 log -1 --format='%an' a4abf48d254685f43383e6e7f80d48aebaea56af | grep -qx 'Benjamin Franzke'
git -C /home/hanqing/.cache/cve-analyzer/repos/codeigniter4_codeigniter4 log -1 --format='%an' 5f8aa24280fb09947897d6b322bf1f0e038b13b6 | grep -qx 'Michal Sniatala'
git -C /home/hanqing/.cache/cve-analyzer/repos/edgelesssys_contrast log -1 --format='%an' 3f974deb75adc2fef6192e8a163ddfd95837d1b7 | grep -qx 'Markus Rudy'
git -C /home/hanqing/.cache/cve-analyzer/repos/indutny_elliptic log -1 --format='%an' 04cb6f54ce552b3ebde6be06d6050419e1c7333e | grep -qx 'Nikita Skovoroda'
git -C /home/hanqing/.cache/cve-analyzer/repos/sparklemotion_nokogiri log -1 --format='%an' dde7ed1478744e6769ddd54c2d499f79509bf68b | grep -qx 'Mike Dalessio'
git -C /home/hanqing/.cache/cve-analyzer/repos/fleetdm_fleet log -1 --format='%an' 718c95e47ad010ad6b8ceb3f3460e921fbfc53bb | grep -qx 'Luke Heath'
git -C /home/hanqing/.cache/cve-analyzer/repos/fleetdm_fleet log -1 --format='%an' fc96cc4e91047250afb12f65ad70e90b30a7fb1c | grep -qx 'Lucas Manuel Rodriguez'
echo replay_ok
