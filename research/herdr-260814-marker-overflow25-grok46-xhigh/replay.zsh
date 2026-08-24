#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-marker-overflow25-grok46-xhigh.
# English ASCII. Do not print credentials. Do not clone, commit, or push.
# Worker PASS is a proposal only. Packet delta is 0. Canonical85 stays 85.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-marker-overflow25-grok46-xhigh
CANON=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85
git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0)

expect_hash() {
  local target=$1 expected=$2
  local got
  got=$(/usr/bin/sha256sum "$target" | /usr/bin/awk '{print $1}')
  if [[ $got != "$expected" ]]; then
    printf 'hash mismatch %s\n expected %s\n got      %s\n' "$target" "$expected" "$got" >&2
    exit 1
  fi
}

python3 - <<'PY'
import json, re
from collections import Counter
from pathlib import Path
root = Path("/home/hanqing/agents/ai-slop")
owned = root / "autoresearch/herdr-260814-marker-overflow25-grok46-xhigh"
canon = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json").read_text())
strict = set(canon["strict_released_case_ids"])
assert canon["canonical_strict_count"] == 85
assert len(strict) == 85
assert "GHSA-3775-99MW-8RP4" not in strict
assert "GHSA-7VF8-2CR6-54MF" not in strict
res = json.loads((owned / "result.json").read_text())
assert res["packet_delta"] == 0
assert res["current_leader_accepted_count"] == 85
assert res["publication_status"] == "HOLD"
assert res["pass_proposals"] == []
assert res["causal_admission"] is False
assert res["canonical_ledger_edited"] is False
assert res["did_not_pad"] is True
sel = [json.loads(l) for l in (owned / "selection.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
ids = [c["case_id"] for c in cases]
assert ids == [s["case_id"] for s in sel]
assert ids == res["conservation"]["reviewed_case_ids"]
assert len(cases) == 25
assert len(set(ids)) == 25
assert res["conservation"]["equation"] == "54=0+2+52; 52=35+17; 35=25+10; 25=25+0"
assert "GHSA-3775-99MW-8RP4" not in ids
assert "GHSA-7VF8-2CR6-54MF" not in ids
assert set(ids).isdisjoint(strict)
SEVEN = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
vc = Counter(c["worker_verdict"] for c in cases)
assert dict(vc) == {"REJECT": 25}
p64 = next(c for c in cases if c["case_id"] == "GHSA-P64J-F4X9-WQ66")
rgj = next(c for c in cases if c["case_id"] == "GHSA-RGJ7-VG8V-J4WR")
assert p64["candidate_set"] == rgj["candidate_set"]
assert rgj["reject_class"] == "SHARED_SHA_WRONG_MECHANISM"
assert p64["uniqueness_gate"] == "PASS" and rgj["uniqueness_gate"] == "PASS"
for c in cases:
    g = c["gates"]
    failing = c["failing_gates"]
    unclosed = c["unclosed_gates"]
    for k in SEVEN:
        v = g[k]
        assert v in ("PASS", "FAIL", "UNKNOWN"), (c["case_id"], k, v)
        if v == "FAIL":
            assert k in failing
        else:
            assert k not in failing
        if v == "UNKNOWN":
            assert k in unclosed
        else:
            assert k not in unclosed
    assert c["worker_verdict"] == "REJECT"
    assert failing
    assert c["countable"] is False
    assert c["countable_proposal"] is False
    assert all(s["exact_atomic_ai_marker"] for s in sel)
    assert c["authorship_transfer_from_member_to_carrier"] is False
for p in (owned / "result.json", owned / "cases.jsonl", owned / "report.md", owned / "selection.jsonl", owned / "replay.zsh"):
    raw = p.read_text()
    if re.search(r"[^\x09\x0a\x0d\x20-\x7e]", raw):
        raise SystemExit("non-ascii " + str(p))
print("conservation and ASCII ok")
PY

expect_hash "$CANON/ledger.jsonl" "2927924603a76a2565d9c244c3b79f70d4693c127f1bc6fcc63e8099172ba568"
expect_hash "$CANON/summary.json" "47209f841a5cb793ae6146b4247990fd2af1d4e50d3d881e0b53904f850bbd0c"
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"
expect_hash "$ROOT/autoresearch/herdr-260814-fresh-marker-prefilter-grok46-low/unknown.jsonl" "d3c2c4f17c5af91866d0bff295819590eb3019a1c8b7851fddb2c8cae5cb3df7"

ECH0=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/lin-snow__Ech0
COSMOS=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/OpenC3__cosmos
OC=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/openclaw__openclaw
P64=a7e8b8e84bd1e3db090dfb720f2c6c433356b442
DENY=9957a9fa460c0c0cf5cdbf6a5931bbdd025246a5
ALLOW=e6efccbd148ba0e3361c5891027f2373aa140d42
HUMAN=dd9d9c1c609dcb4579f9e57bd7b5c879d0146b53
AILOC=14baadda2c456f3cf749f1f97e8678746a34a7f4

if [[ ! -d $ECH0/.git && ! -e $ECH0/HEAD ]]; then
  printf 'missing Ech0 clone\n' >&2
  exit 1
fi
body=$("${git_cmd[@]}" -C "$ECH0" log -1 --format=%B "$P64")
printf '%s\n' "$body" | /usr/bin/grep -F 'Claude Opus 4.7' >/dev/null
sha1=$("${git_cmd[@]}" -C "$ECH0" rev-parse "$P64")
if [[ $sha1 != "$P64" ]]; then
  printf 'unexpected p64 sha\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$COSMOS" merge-base --is-ancestor "$DENY" "$ALLOW"
if "${git_cmd[@]}" -C "$COSMOS" merge-base --is-ancestor "$ALLOW" "$DENY"; then
  printf 'allowlist should not be ancestor of denylist\n' >&2
  exit 1
fi
dbody=$("${git_cmd[@]}" -C "$COSMOS" log -1 --format=%B "$DENY")
printf '%s\n' "$dbody" | /usr/bin/grep -F 'Claude Opus 4.6' >/dev/null
"${git_cmd[@]}" -C "$OC" merge-base --is-ancestor "$HUMAN" "$AILOC"
if "${git_cmd[@]}" -C "$OC" merge-base --is-ancestor "$AILOC" "$HUMAN"; then
  printf 'AI localRoots should not be ancestor of human sandbox closer\n' >&2
  exit 1
fi

printf 'replay ok\n'
