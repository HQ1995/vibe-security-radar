#!/usr/bin/env zsh
# Fail-closed zsh replay for herdr-260814-ghsa200-unreviewed-commitref20-grok46-medium.
# English only. Do not print credentials or environment values.
# Do not clone, commit, push, or modify shared caches.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# PASS is a proposal only. This script does not admit any row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-unreviewed-commitref20-grok46-medium
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database
git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

require_dir() {
  if [[ ! -d $1 ]]; then
    printf 'missing directory: %s\n' "$1" >&2
    exit 1
  fi
}
require_file() {
  if [[ ! -f $1 ]]; then
    printf 'missing file: %s\n' "$1" >&2
    exit 1
  fi
}
expect_hash() {
  local target=$1 expected=$2
  local got
  got=$(/usr/bin/sha256sum "$target" | /usr/bin/awk '{print $1}')
  if [[ $got != "$expected" ]]; then
    printf 'hash mismatch %s\n expected %s\n got      %s\n' "$target" "$expected" "$got" >&2
    exit 1
  fi
}

require_dir "$OWNED"
require_dir "$ADV"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/work/freeze.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/notes/freeze.txt"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/ledger.jsonl" \
  58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" \
  d436f47f82297eb0d9363ad0f3876adc639b1f61e9b23c7f9d613545741e106e

head=$("${git_cmd[@]}" -C "$ADV" rev-parse HEAD)
if [[ $head != a42c436870111aa3f221257c9d56126a93173ccc ]]; then
  printf 'advisory HEAD mismatch %s\n' "$head" >&2
  exit 1
fi

/usr/bin/python3 - <<'PY'
import json
from pathlib import Path
root = Path("/home/hanqing/agents/ai-slop")
owned = root / "autoresearch/herdr-260814-ghsa200-unreviewed-commitref20-grok46-medium"
sel = [json.loads(l) for l in (owned/"selected.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned/"result.json").read_text())
uni = json.loads((owned/"work/uniqueness.json").read_text())
fr = json.loads((owned/"work/freeze.json").read_text())
assert len(sel) == 20
assert len(cases) == 20
assert [r["ghsa_id"] for r in sel] == [c["case_id"] for c in cases]
assert all(c["worker_verdict"] == "REJECT" for c in cases)
assert all(c["identity_gate"] == "FAIL" for c in cases)
assert all(c["uniqueness_gate"] == "PASS" for c in cases)
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 20
assert res["claim_boundary"]["packet_delta"] == 0
assert res["current_leader_accepted_count"] == 82
assert res["analysis_stopped"] is True
assert uni["canonical82_overlap"] == []
assert uni["packet_delta"] == 0
assert fr["padding"] is False
assert fr["frozen_n"] == 20
assert "425G" not in "".join(r["ghsa_id"] for r in sel)
assert "HC8V" not in "".join(r["ghsa_id"] for r in sel)
c82 = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json").read_text())
assert c82["canonical_strict_count"] == 82
strict = {x.upper() for x in c82["strict_released_case_ids"]}
assert not strict.intersection({r["ghsa_id"] for r in sel})
print("replay asserts ok")
PY

printf 'replay ok\n'
