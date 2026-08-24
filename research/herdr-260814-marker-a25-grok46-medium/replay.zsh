#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-marker-a25-grok46-medium.
# English ASCII. Do not print credentials. Do not clone, commit, or push.
# Worker PASS is a proposal only. Packet delta is 0. Canonical85 stays 85.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-marker-a25-grok46-medium
CANON=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85
CAND=$ROOT/autoresearch/herdr-260814-fresh-marker-prefilter-grok46-low/candidates.jsonl
GP=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gitpython-developers__GitPython
AR=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/argoproj__argo-workflows

expect_hash() {
  local target=$1 expected=$2
  local got
  got=$(/usr/bin/sha256sum "$target" | /usr/bin/awk '{print $1}')
  if [[ $got != "$expected" ]]; then
    printf 'hash mismatch %s\n expected %s\n got      %s\n' "$target" "$expected" "$got" >&2
    exit 1
  fi
}

expect_hash "$CANON/ledger.jsonl" 2927924603a76a2565d9c244c3b79f70d4693c127f1bc6fcc63e8099172ba568
expect_hash "$CANON/summary.json" 47209f841a5cb793ae6146b4247990fd2af1d4e50d3d881e0b53904f850bbd0c
expect_hash "$CANON/manifest.json" 5781078c8b286a454b647c84447fa8c9ff4dc2068f3c45acb45acddb50167abd
expect_hash "$CAND" d2fca17de6592ebea84f38c49f791dc516a0be6e47b56912de91343a71f798b0
expect_hash "$OWNED/cases.jsonl" 412902561828b4644664351297cc00b133550a30f7f2816002589f87bd0b0eda
expect_hash "$OWNED/report.md" d22e46253f9aed21e60a9368ddbaaf23bcb7b64a6a8a3e5deaae1d5edd2aef2b
expect_hash "$OWNED/result.json" 5c4a559f223bbe490ca80d2362cdcc73192e09a4007c492885acb5883c661c24

python3 - <<'PY'
import json
from pathlib import Path
from collections import Counter
root = Path("/home/hanqing/agents/ai-slop")
owned = root / "autoresearch/herdr-260814-marker-a25-grok46-medium"
canon = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json").read_text())
assert canon["canonical_strict_count"] == 85
strict = set(canon["strict_released_case_ids"])
assert len(strict) == 85
cands = []
for i, line in enumerate((root / "autoresearch/herdr-260814-fresh-marker-prefilter-grok46-low/candidates.jsonl").read_text().splitlines(), 1):
    if i > 25:
        break
    cands.append(json.loads(line))
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned / "result.json").read_text())
assert len(cases) == 25
assert len(cands) == 25
assert [c["case_id"] for c in cases] == [c["case_id"] for c in cands]
assert len(set(c["case_id"] for c in cases)) == 25
assert res["packet_delta"] == 0
assert res["canonical_strict_count_untouched"] == 85
assert res["publication_status"] == "HOLD"
assert res["pass_proposals"] == []
assert res["causal_admission"] is False
assert res["canonical_ledger_edited"] is False
assert res["conservation"]["equation"] == "25=25+0"
assert res["conservation"]["assigned"] == 25
assert res["conservation"]["reviewed"] == 25
assert res["conservation"]["unreviewed"] == 0
SEVEN = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
vc = Counter(c["worker_verdict"] for c in cases)
assert vc.get("PASS_PROPOSAL", 0) == 0
assert vc["REJECT"] == 21
assert vc["UNKNOWN"] == 4
assert set(vc) == {"REJECT", "UNKNOWN"}
for c in cases:
    assert c["case_id"] not in strict
    assert c["worker_verdict"] in ("PASS_PROPOSAL", "REJECT", "UNKNOWN")
    assert c["countable"] is False
    assert c["countable_proposal"] is False
    assert c["authorship_transfer_from_member_to_carrier"] is False
    assert c["packet_delta"] == 0
    g = c["gates"]
    if c["worker_verdict"] == "PASS_PROPOSAL":
        assert all(g[k] == "PASS" for k in SEVEN)
    for k in SEVEN:
        if g[k] == "FAIL":
            assert k in c["failing_gates"]
        else:
            assert k not in c["failing_gates"]
        if g[k] == "UNKNOWN":
            assert k in c["unclosed_gates"]
        else:
            assert k not in c["unclosed_gates"]
    blob = json.dumps(c)
    assert all(ord(ch) < 128 for ch in blob)
assert cases[0]["case_id"] == "GHSA-48P8-G2FX-3WWM"
assert cases[0]["worker_verdict"] == "UNKNOWN"
assert cases[0]["routed_role"] == "closer_carrier_merge_from_fork"
assert cases[1]["worker_verdict"] == "REJECT"
assert cases[1]["uniqueness_gate"] == "FAIL"
print("PASS conservation and gate accounting")
PY

/usr/bin/git --no-optional-locks -c gc.auto=0 -C "$AR" log -1 --format=%s 277e9cef0ad16d7eaaab253573d0695951a65dbd | /usr/bin/grep -F "Merge commit from fork" >/dev/null
/usr/bin/git --no-optional-locks -c gc.auto=0 -C "$GP" log -1 --format=%an 701ce32fe5ba8cb622c0e0342a376a6beb47d738 | /usr/bin/grep -F "GPT 5.6" >/dev/null
/usr/bin/git --no-optional-locks -c gc.auto=0 -C "$GP" log -1 --format=%s 96a888f4d782cb2f80452148e48e60ce4af6d541 | /usr/bin/grep -F "joined short-option" >/dev/null

printf 'PASS replay\n'
