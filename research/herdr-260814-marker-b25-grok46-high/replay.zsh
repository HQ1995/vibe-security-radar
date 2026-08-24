#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-marker-b25-grok46-high.
# English ASCII. Do not print credentials. Do not clone, commit, or push.
# Worker PASS is a proposal only. Packet delta is 0. Canonical85 stays 85.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-marker-b25-grok46-high
CANON=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85
CAND=$ROOT/autoresearch/herdr-260814-fresh-marker-prefilter-grok46-low/candidates.jsonl
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
from pathlib import Path
root = Path("/home/hanqing/agents/ai-slop")
owned = root / "autoresearch/herdr-260814-marker-b25-grok46-high"
canon = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json").read_text())
strict = set(canon["strict_released_case_ids"])
assert canon["canonical_strict_count"] == 85
assert len(strict) == 85
cands = [json.loads(l) for l in (root / "autoresearch/herdr-260814-fresh-marker-prefilter-grok46-low/candidates.jsonl").read_text().splitlines() if l.strip()]
assert len(cands) == 50
assigned = cands[25:50]
assert len(assigned) == 25
res = json.loads((owned / "result.json").read_text())
assert res["packet_delta"] == 0
assert res["canonical_strict_count"] == 85
assert res["publication_status"] == "HOLD"
assert res["pass_proposals"] == []
assert res["causal_admission"] is False
assert res["canonical_ledger_edited"] is False
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
ids = [c["case_id"] for c in cases]
assert ids == [a["case_id"] for a in assigned]
assert ids == res["conservation"]["reviewed_case_ids"]
assert [c["ordinal"] for c in cases] == list(range(26, 51))
assert len(cases) == 25
assert len(set(ids)) == 25
assert res["conservation"]["equation"] == "25=25+0"
assert set(ids).isdisjoint(strict)
SEVEN = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
from collections import Counter
vc = Counter(c["worker_verdict"] for c in cases)
assert dict(vc) == {"REJECT": 25}
for c in cases:
    assert c["worker_verdict"] in ("PASS_PROPOSAL", "REJECT", "UNKNOWN")
    assert c["routed_sha_role"] in ("origin", "security-attempt", "carrier", "closer", "unrelated")
    assert c["squash_trailer_transfer"] is False
    assert c["ai_closer_as_origin"] is False
    assert c["missing_gate_inference"] is False
    assert c["countable"] is False
    assert c["countable_proposal"] is False
    g = c["gates"]
    failing = c["failing_gates"]
    unclosed = c["unclosed_gates"]
    for k in SEVEN:
        v = g[k]
        if v == "FAIL":
            assert k in failing, (c["case_id"], k)
        else:
            assert k not in failing, (c["case_id"], k)
        if v == "UNKNOWN":
            assert k in unclosed, (c["case_id"], k)
        else:
            assert k not in unclosed, (c["case_id"], k)
    if c["worker_verdict"] == "PASS_PROPOSAL":
        assert all(g[k] == "PASS" for k in SEVEN)
        assert failing == [] and unclosed == []
    elif c["worker_verdict"] == "REJECT":
        assert failing, c["case_id"]
    elif c["worker_verdict"] == "UNKNOWN":
        assert failing == [] and unclosed, c["case_id"]
    else:
        raise SystemExit("unexpected verdict " + c["case_id"])
    assert g["ai_hunk_gate"] == "FAIL"
    assert g["identity_gate"] == "PASS"
    assert g["uniqueness_gate"] == "PASS"
    assert c["routed_sha_role"] == "closer"
for p in (owned / "result.json", owned / "cases.jsonl", owned / "report.md", owned / "replay.zsh"):
    raw = p.read_text()
    if re.search(r"[^\x09\x0a\x0d\x20-\x7e]", raw):
        raise SystemExit("non-ascii " + str(p))
print("conservation and ASCII ok")
PY

expect_hash "$CANON/ledger.jsonl" "2927924603a76a2565d9c244c3b79f70d4693c127f1bc6fcc63e8099172ba568"
expect_hash "$CANON/summary.json" "47209f841a5cb793ae6146b4247990fd2af1d4e50d3d881e0b53904f850bbd0c"
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"
expect_hash "$CAND" "d2fca17de6592ebea84f38c49f791dc516a0be6e47b56912de91343a71f798b0"
expect_hash "$OWNED/cases.jsonl" "2bc4ef6f17d8f5439b49fbb66239f84e37debbc57c5a0da2c1fbc3f703ab721c"
expect_hash "$OWNED/report.md" "40b69c4b3483d1ec497e08fde9169a135355447aa62eed40e887220cedf97fd1"
expect_hash "$OWNED/result.json" "6ac92f13dac3bd3d20df67ffd9bcd28acb3f8632b83c24a5aa12b52a9cfec4d2"

LR=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/HKUDS__LightRAG
if [[ -d $LR/.git || -e $LR/HEAD ]]; then
  body=$("${git_cmd[@]}" -C "$LR" log -1 --format=%B f7819aa3a49a9d8d92eed8251d82d6ebcafa8cba)
  printf '%s\n' "$body" | /usr/bin/grep -F 'GHSA-f4vv' >/dev/null
  auth=$("${git_cmd[@]}" -C "$LR" log -1 --format=%ae 09567a4c983f580050db63569dd477122c058c3d)
  if [[ $auth != noreply@anthropic.com ]]; then
    printf 'unexpected 6X6H author email %s\n' "$auth" >&2
    exit 1
  fi
  "${git_cmd[@]}" -C "$LR" merge-base --is-ancestor 09567a4c983f580050db63569dd477122c058c3d df68d75f9dc29dd340ffb6794b48f48c4fdc9a2d
fi

JL=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/jline__jline3
if [[ -d $JL/.git || -e $JL/HEAD ]]; then
  par=$("${git_cmd[@]}" -C "$JL" log -1 --format=%P 733eb353dca7b0ea0252e724445b6defa29c393e)
  if [[ $par != 934f09e6128cee33c2b13d42b6e859c1ee2d194b ]]; then
    printf 'unexpected 2R2C parent %s\n' "$par" >&2
    exit 1
  fi
fi

AP=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/microsoft__apm
if [[ -d $AP/.git || -e $AP/HEAD ]]; then
  par=$("${git_cmd[@]}" -C "$AP" log -1 --format=%P 77d1dda8303c8d7ccb6148788a6274fdece98499)
  if [[ $par != f85b9f54ad303159f9c448268eb7005c319fe02a ]]; then
    printf 'unexpected MQ5J parent %s\n' "$par" >&2
    exit 1
  fi
fi

printf 'replay ok\n'
