#!/usr/bin/env zsh
set -euo pipefail
OWN=/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-cf2-af-new-surface-grok46-low
AF=/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-commitfirst-af
CACHE=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos
TAGFILE="$OWN/work/ls-remote-tags.txt"
mkdir -p "$OWN/work"
trap 'rm -f "$TAGFILE"' EXIT
fail=0
check_hash() {
  local want="$1" target_path="$2"
  local got
  got=$(sha256sum "$target_path" | awk '{print $1}')
  if [[ "$got" != "$want" ]]; then
    echo "HASH_FAIL $target_path"
    fail=1
  fi
}
check_hash cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3 /home/hanqing/agents/ai-slop/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
check_hash 70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f /home/hanqing/agents/ai-slop/docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md
check_hash 47209f841a5cb793ae6146b4247990fd2af1d4e50d3d881e0b53904f850bbd0c /home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json
check_hash 0b9cd2daae23e33faf3f2ceed46bba4802e2f9b0ef9c739f0bce7e6f4a16f687 /home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl
check_hash 8398ac0cabc3399e5bf86897c44af841d8f0727c09c9369a0ddaa0377d6798eb "$AF/inventory-novel-af.jsonl"
check_hash 9659e93e82df4428df361507c6728ac83988211b0282ffbc3c12e3aba529d6d0 "$AF/ai-commits.jsonl"
check_hash 765e7766eb9a4d65555c4fb52e8846505330d5f56054feb813393a82b50abcb3 "$AF/repo-scan-status.jsonl"

git --git-dir "$CACHE/flytohub__flyto-core" cat-file -t 68af171dcf42b89fb5d3f5f3f60c2ae25f91e5ce | grep -qx commit
git --git-dir "$CACHE/flytohub__flyto-core" cat-file -t d5f89d71303e3c1e6418d347c5c55fcd173cc8cc | grep -qx commit
git --git-dir "$CACHE/Budibase__budibase" cat-file -t 700ff33db7470d4d2dd9674e9e29dc5e6392daa4 | grep -qx commit
git --git-dir "$CACHE/delmaredigital__payload-puck" cat-file -t f9536974e65fe510d3b7df0a26d272bb8ad5905f | grep -qx commit
git --git-dir "$CACHE/Aarondoran__servify-express" cat-file -t c26113f0ec02569b0fa67b4c93184c98f6a5b7c5 | grep -qx commit
git --git-dir "$CACHE/Budibase__budibase" cat-file -t e37242a18893ed042c7f400207024d5351b53a80 | grep -qx commit

git --git-dir "$CACHE/flytohub__flyto-core" merge-base --is-ancestor 68af171dcf42b89fb5d3f5f3f60c2ae25f91e5ce d5f89d71303e3c1e6418d347c5c55fcd173cc8cc
parents=$(git --git-dir "$CACHE/flytohub__flyto-core" rev-list --parents -n 1 68af171dcf42b89fb5d3f5f3f60c2ae25f91e5ce | awk '{print NF}')
[[ "$parents" == "2" ]]

GIT_TERMINAL_PROMPT=0 git ls-remote --tags https://github.com/flytohub/flyto-core.git > "$TAGFILE"
grep -q '50d0d327a1278c8cec9495ba5f6f010dd67ef19c[[:space:]]*refs/tags/v2.26.4\^{}' "$TAGFILE"
grep -q '2471c6e774102fcca21c61eb66cae057c0f0cecf[[:space:]]*refs/tags/v2.26.6\^{}' "$TAGFILE"
grep -q '9449def37907190798b5d677b716526b09ae7302[[:space:]]*refs/tags/v2.26.7\^{}' "$TAGFILE"

python3 - <<'PY'
import json
from pathlib import Path
own=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-cf2-af-new-surface-grok46-low")
cases=[json.loads(l) for l in (own/"cases.jsonl").read_text().splitlines() if l.strip()]
assign=[json.loads(l) for l in (own/"assignment.jsonl").read_text().splitlines() if l.strip()]
res=json.loads((own/"result.json").read_text())
assert len(cases)==6 and len(assign)==6
assert len(cases)==res["counts"]["reviewed"]==res["counts"]["assigned"]
assert sum(1 for c in cases if c["worker_verdict"]=="REJECT")==6
assert res["PASS_PROPOSAL_ids"]==[]
assert res["conservation"]["assigned_equals_reviewed"] is True
for p in [own/"assignment.jsonl", own/"cases.jsonl", own/"result.json", own/"report.md", own/"replay.zsh"]:
    p.read_bytes().decode("ascii")
print("CONSERVATION_OK")
PY

if [[ $fail -ne 0 ]]; then
  echo REPLAY_FAIL
  exit 1
fi
echo REPLAY_OK
