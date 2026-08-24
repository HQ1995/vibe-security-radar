#!/usr/bin/env zsh
set -euo pipefail
cd /home/hanqing/agents/ai-slop

hash_file() {
  sha256sum -- "$1" | awk '{print $1}'
}

[[ "$(hash_file autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md)" == "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-ghsa200-leader/baseline.json)" == "d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl)" == "1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl)" == "e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-commitfirst-gn/assigned.jsonl)" == "89cf34362e3f1cc36d91595ddab808eeefc477c0756a924b705d581207149a73" ]]

[[ "$(hash_file scripts/publication_adjudications.json)" == "9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh/cases.jsonl)" == "d4d3c96ba0a60214971ab88f3de7adce1edfc27f39a388906600aad91b5c1889" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-actual-gogs-redteam-grok46-high/cases.jsonl)" == "3a74a0133dbfd3e128834f9bbc641b78c1515e5647fd07085bba30e2984d827f" ]]

INS=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/modelcontextprotocol__inspector
GITEA=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/go-gitea__gitea

git --no-optional-locks -c gc.auto=0 -C "$INS" merge-base --is-ancestor 50df0e1ec488f3983740b4d28d2a968f12eb8979 fdae89ecbfec8fda5d166277ab77398e6d3c06c9

body="$(git --no-optional-locks -c gc.auto=0 -C "$GITEA" log -1 --format=%B 33923a4d7c3c0d25d40373447088d234b4a1387b)"
[[ "$body" == *"Co-authored-by: Claude (Opus 4.7)"* ]]

python3 - <<'PY'
import json
from pathlib import Path
p=Path("autoresearch/herdr-260813-ghsa200-remediation-mining-grok46-low/cases.jsonl")
rows=[json.loads(l) for l in p.read_text().splitlines() if l.strip()]
assert len(rows)==30
assert all(r.get("worker_verdict")=="REJECT" for r in rows)
assert all(r.get("countable") is False for r in rows)
ids=[r["case_id"] for r in rows]
assert len(ids)==len(set(ids))
banned={"GHSA-7GH7-258J-4MPQ","GHSA-6P9M-Q3JP-47H4","GHSA-XQJM-27PC-RVWM"}
assert not (set(ids)&banned)
r=json.loads(Path("autoresearch/herdr-260813-ghsa200-remediation-mining-grok46-low/result.json").read_text())
assert r["counts"]["PASS"]==0
assert r["publication_status"]=="HOLD"
assert r["more_than_200_claim"] is False
PY
