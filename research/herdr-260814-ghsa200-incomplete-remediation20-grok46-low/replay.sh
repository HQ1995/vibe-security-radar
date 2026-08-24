#!/usr/bin/env bash
set -euo pipefail
ROOT="/home/hanqing/agents/ai-slop"
OWNED="$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20-grok46-low"
ADV="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database"
hash_file() { sha256sum "$1" | awk '{print $1}'; }
[[ "$(git -C "$ADV" rev-parse HEAD)" == "a42c436870111aa3f221257c9d56126a93173ccc" ]]
[[ "$(hash_file "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md")" == "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3" ]]
[[ "$(hash_file "$ROOT/autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json")" == "699f6160b6ecb9c9ce2cdae257c9a12dbdf4f7ef8a925196fcfd4fcf0b1140d8" ]]
[[ "$(hash_file "$OWNED/work/selected-20.jsonl")" == "3d0e65cd3866eb4d45d70d9222c364f31e4950b04c0ce7b0bf19c3371c888dba" ]]
python3 - <<'PY'
import json
from pathlib import Path
owned=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-incomplete-remediation20-grok46-low")
sel=[json.loads(l)["ghsa_id"] for l in (owned/"work/selected-20.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l)["case_id"] for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
assert sel==cases and len(sel)==20
rows=[json.loads(l) for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
assert all(r["worker_verdict"]!="PASS" for r in rows)
causal=["ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
blocked=[r for r in rows if r["worker_verdict"]=="BLOCKED"]
assert len(blocked)==4
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
assert len(rej)==16
print("freeze_and_cases_ok")
PY
git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/jupyterlab__jupyterlab-git log -1 --format='%an' 2e8fd94b9b76df82f6e85b79673a0c693b145529 | grep -qx 'rahrad123'
git -C /home/hanqing/.cache/cve-analyzer/repos/qhkm_zeptoclaw log -1 --format='%B' 51bc07a02484ddfd2ec9c7f382dc43f829a9df86 | grep -q 'Claude Sonnet 4.6'
git -C /home/hanqing/.cache/cve-analyzer/repos/qhkm_zeptoclaw diff v0.7.5 v0.7.6 -- src/channels/email_channel.rs | grep -q 'parsed From header'
git -C /home/hanqing/.cache/cve-analyzer/repos/alchemyplatform_aa-sdk log -1 --format='%s' b65bafdb9eec3a009df2cbabf09a35a76550e9d0 | grep -q 'allowlist'
echo replay_ok
