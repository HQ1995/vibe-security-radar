#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-fresh-remediation-wave2-grok46-medium.
# English ASCII. Do not print credentials. Do not clone, commit, or push.
# Worker PASS is a proposal only. Packet delta is 0. Canonical85 stays 85.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-fresh-remediation-wave2-grok46-medium
CANON=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database

expect_hash() {
  local target=$1 expected=$2
  local got
  got=$(/usr/bin/sha256sum "$target" | /usr/bin/awk '{print $1}')
  if [[ $got != "$expected" ]]; then
    printf 'hash mismatch %s\n expected %s\n got      %s\n' "$target" "$expected" "$got" >&2
    exit 1
  fi
}

head_got=$(/usr/bin/git --no-optional-locks -C "$ADV" rev-parse HEAD)
if [[ $head_got != a42c436870111aa3f221257c9d56126a93173ccc ]]; then
  printf 'advisory HEAD mismatch got %s\n' "$head_got" >&2
  exit 1
fi

python3 - <<'PY'
import json, re
from pathlib import Path
root = Path("/home/hanqing/agents/ai-slop")
owned = root / "autoresearch/herdr-260814-fresh-remediation-wave2-grok46-medium"
canon = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
assert canon["canonical_strict_count"] == 85
excl = {ln.strip() for ln in (owned / "work/exclusion_ids.txt").read_text().splitlines() if ln.strip()}
assert len(excl) == 1211
assert strict <= excl
res = json.loads((owned / "result.json").read_text())
assert res["packet_delta"] == 0
assert res["current_leader_accepted_count"] == 85
assert res["publication_status"] == "HOLD"
assert res["pass_proposals"] == []
assert res["causal_admission"] is False
assert res["canonical_ledger_edited"] is False
assert res["did_not_pad"] is True
assert res["counts"]["ai_prior_hits"] == 0
sel = [json.loads(l) for l in (owned / "selection.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
ids = [c["case_id"] for c in cases]
assert ids == [s["ghsa_id"] for s in sel]
assert len(ids) == 11
assert len(set(ids)) == 11
assert set(ids).isdisjoint(strict)
assert set(ids).isdisjoint(excl)
assert res["conservation"]["equation"] == "11=10+1+0+0"
SEVEN = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
from collections import Counter
vc = Counter(c["worker_verdict"] for c in cases)
assert dict(vc) == {"REJECT": 10, "UNKNOWN": 1}
assert [c["worker_verdict"] for c in cases if c["case_id"]=="GHSA-48P8-G2FX-3WWM"] == ["UNKNOWN"]
for c in cases:
    for ch in json.dumps(c, ensure_ascii=True):
        assert ord(ch) < 128
    g = c["gates"]
    for k in SEVEN:
        v = g[k]
        if v == "FAIL":
            assert k in c["failing_gates"], (c["case_id"], k)
        else:
            assert k not in c["failing_gates"], (c["case_id"], k)
        if v == "UNKNOWN":
            assert k in c["unclosed_gates"], (c["case_id"], k)
        else:
            assert k not in c["unclosed_gates"], (c["case_id"], k)
    assert c["countable"] is False
    assert c["packet_delta"] == 0
    assert c["in_canonical85"] is False
print("REPLAY_OK reviewed=11 PASS_proposal=0 REJECT=10 NARROW=0 UNKNOWN=1 BLOCKED=0 packet_delta=0 current_leader_accepted_count=85")
PY
