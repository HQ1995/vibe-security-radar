#!/usr/bin/env bash
# Clone assigned repos under the batch2 cache only. Do not use /tmp.
set -euo pipefail
CACHE="/home/hanqing/.cache/ghsa200-worker-clones/delta-even-batch2"
mkdir -p "$CACHE"
export GIT_OPTIONAL_LOCKS=0

clone_one() {
  local spec="$1"
  local dest="$CACHE/${spec//\//__}"
  if [ -d "$dest/.git" ]; then
    echo "exists $spec"
    git -C "$dest" config gc.auto 0 >/dev/null 2>&1 || true
    git -C "$dest" config maintenance.auto false >/dev/null 2>&1 || true
    return 0
  fi
  echo "clone $spec"
  if git clone --filter=blob:none --single-branch "https://github.com/${spec}.git" "$dest"; then
    git -C "$dest" config gc.auto 0
    git -C "$dest" config maintenance.auto false
    echo "ok $spec"
  else
    echo "FAIL $spec"
    return 1
  fi
}

# Read unique repos from advisory packets
python3 - <<'PY'
import json
from pathlib import Path
p=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-delta-even-batch2/advisory_packets.jsonl")
repos=sorted({json.loads(l)["repository"] for l in p.read_text().splitlines() if l.strip()})
Path("/home/hanqing/.cache/ghsa200-worker-clones/delta-even-batch2/repo_list.txt").write_text("\n".join(repos)+"\n")
print(len(repos))
PY

fail=0
# sequential is safer for disk; still reasonably fast with blob:none
while IFS= read -r spec; do
  [ -z "$spec" ] && continue
  clone_one "$spec" || fail=$((fail+1))
done < /home/hanqing/.cache/ghsa200-worker-clones/delta-even-batch2/repo_list.txt
echo "clone_failures=$fail"
