#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-cf3-release6-grok46-low.
# English only. No credentials. No clone/commit/push. Shared caches read-only.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-cf3-release6-grok46-low
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical86/ledger.jsonl
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical86/summary.json

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

OC=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw
CRM=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/churchcrm
GP=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/gitpython
PR=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/praisonai

expect_eq() {
  if [[ $1 != "$2" ]]; then
    printf 'mismatch %s expected=%s got=%s\n' "$3" "$2" "$1" >&2
    exit 1
  fi
}

expect_hash() {
  local got
  got=$(/usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}')
  expect_eq "$got" "$2" "$1"
}

gitx() {
  local repo=$1
  shift
  local errf
  errf=$(mktemp /tmp/cf3-giterr.XXXXXX)
  set +e
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
  if [[ -s $errf ]]; then
    /usr/bin/grep -vE 'unable to normalize alternate object path|lazy fetching disabled' "$errf" >&2 || true
  fi
  rm -f "$errf"
  return $rc
}

anc() {
  gitx "$1" merge-base --is-ancestor "$2" "$3"
}

not_anc() {
  if gitx "$1" merge-base --is-ancestor "$2" "$3"; then
    printf 'unexpected ancestor %s of %s\n' "$2" "$3" >&2
    exit 1
  fi
}

require_file() {
  if [[ ! -f $1 ]]; then
    printf 'missing %s\n' "$1" >&2
    exit 1
  fi
}

require_dir() {
  if [[ ! -d $1 ]]; then
    printf 'missing %s\n' "$1" >&2
    exit 1
  fi
}

require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/result.json"
require_file "$OWNED/report.md"
require_file "$LEDGER"
require_file "$CONTRACT"
require_dir "$OC"
require_dir "$CRM"
require_dir "$GP"
require_dir "$PR"

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 3150a7925cc31645b00862595d553db49ec5e07076d87e6c42beec401a647ee7
expect_hash "$SUMMARY" 74efef286737bcbd852bf1887ffa34b30224f7902f96a2c45455ba399a4d739c

n_assign=$(/usr/bin/wc -l < "$OWNED/assignment.jsonl")
n_cases=$(/usr/bin/wc -l < "$OWNED/cases.jsonl")
expect_eq "${n_assign// /}" 6 assign_rows
expect_eq "${n_cases// /}" 6 case_rows

/usr/bin/python3 - "$OWNED/assignment.jsonl" "$OWNED/cases.jsonl" "$OWNED/result.json" "$LEDGER" <<'PY'
import json,sys
from pathlib import Path
assign=[json.loads(l) for l in Path(sys.argv[1]).read_text().splitlines() if l.strip()]
cases=[json.loads(l) for l in Path(sys.argv[2]).read_text().splitlines() if l.strip()]
res=json.loads(Path(sys.argv[3]).read_text())
assert len(assign)==6 and len(cases)==6
ids=[r["case_id"] for r in assign]
expect=["GHSA-2X93-H3HG-2XFP","GHSA-9C3V-684M-579C","GHSA-F2FQ-4RMP-9X8C","GHSA-F38V-77QJ-H4JQ","GHSA-V396-V7Q4-X2QJ","GHSA-WP73-F3GG-W4VR"]
assert ids==expect
assert [r["case_id"] for r in cases]==expect
assert res["conservation"]["equation"]=="6=6+0"
assert res["conservation"]["holds"] is True
assert res["counts"]["PASS_PROPOSAL"]==0
assert res["counts"]["REJECT"]==1
assert res["counts"]["NARROW"]==5
assert res["counts"]["UNKNOWN"]==0
assert res["per_case"]["GHSA-F2FQ-4RMP-9X8C"]=="REJECT"
assert cases[2]["not_ai"] is False
assert cases[2]["strict_released_class"]=="UNRELEASED_AI_MEMBER"
counted=set()
for line in Path(sys.argv[4]).read_text().splitlines():
    o=json.loads(line)
    if o.get("counted") is True and o.get("case_id"):
        counted.add(o["case_id"])
assert len(counted)==86
for cid in expect:
    assert cid not in counted
print("conservation_uniqueness_ok")
PY

# 2X93
CAND=b75ad800a59009fc47eaa3471410f69046150e59
FIX=06047005ef7dedda5ea655f52117e8aaa1cca373
gitx "$OC" log -1 --format=%s "$CAND" | /usr/bin/grep -F '[AI]' >/dev/null
anc "$OC" "$CAND" "$FIX"
VULN=$(gitx "$OC" rev-parse 'v2026.5.22^{commit}')
FIXED=$(gitx "$OC" rev-parse 'v2026.5.26^{commit}')
expect_eq "$VULN" a374c3a5bfd5225ce319bce3865aab6216309c4f 2x93_vuln
expect_eq "$FIXED" 10ad3aa16068baa84a1bd9ac4f7d42ae725cedb7 2x93_fix
anc "$OC" "$CAND" "$VULN"
not_anc "$OC" "$FIX" "$VULN"
anc "$OC" "$FIX" "$FIXED"

# 9C3V
CAND=47eb2d48d43452afc4b0160e40a2630e4a38a0ff
FIX=3c6259ebb70c76523a7b3fb7cfdac2e40a7f7449
gitx "$OC" log -1 --format=%s "$CAND" | /usr/bin/grep -F 'streamable' >/dev/null
gitx "$OC" diff --name-only "$CAND^" "$CAND" | /usr/bin/grep -F 'src/agents/mcp-transport.ts' >/dev/null
if gitx "$OC" diff --name-only "$CAND^" "$CAND" | /usr/bin/grep -F 'sse' >/dev/null; then
  printf '9C3V candidate unexpectedly lists sse file\n' >&2
  exit 1
fi
anc "$OC" "$CAND" "$FIX"
VULN=$(gitx "$OC" rev-parse 'v2026.6.1^{commit}')
FIXED=$(gitx "$OC" rev-parse 'v2026.6.5^{commit}')
anc "$OC" "$CAND" "$VULN"
not_anc "$OC" "$FIX" "$VULN"
anc "$OC" "$FIX" "$FIXED"

# WP73
CAND=6c918ca85fc6256a309ca0a737d7729059b34e1e
FIX=797bcd5bdb28cd8bab4f5385f4515467e42bfcfd
if gitx "$OC" diff --name-only "$CAND^" "$CAND" | /usr/bin/grep -i clickclack >/dev/null; then
  printf 'WP73 candidate has ClickClack files\n' >&2
  exit 1
fi
gitx "$OC" diff --name-only "$FIX^" "$FIX" | /usr/bin/grep -i clickclack >/dev/null
anc "$OC" "$CAND" "$FIX"
VULN=$(gitx "$OC" rev-parse 'v2026.5.18^{commit}')
FIXED=$(gitx "$OC" rev-parse 'v2026.6.5^{commit}')
anc "$OC" "$CAND" "$VULN"
not_anc "$OC" "$FIX" "$VULN"
anc "$OC" "$FIX" "$FIXED"

# F2FQ unreleased member
MEM=cbea916e77e2d8cbe34f04efdd00792e3af27e2c
FIX=07be35d7fdaae872f2f6ff404779368f201fe8b5
gitx "$CRM" log -1 --format=%B "$MEM" | /usr/bin/grep -F 'Claude Haiku 4.5' >/dev/null
TAGS=$("${git_cmd[@]}" -C "$CRM" tag --contains "$MEM" 2>/dev/null || true)
if [[ -n ${TAGS} ]]; then
  printf 'F2FQ member unexpectedly tagged\n' >&2
  exit 1
fi
not_anc "$CRM" "$MEM" "$(gitx "$CRM" rev-parse '7.5.1^{commit}')"
anc "$CRM" "$FIX" "$(gitx "$CRM" rev-parse '7.6.0^{commit}')"
expect_eq "$(gitx "$CRM" rev-parse "${MEM}:src/api/routes/public/public-user.php")" 74e9d89029ffd307d5ddd45054da4e2a1957a43f f2fq_member_blob
expect_eq "$(gitx "$CRM" rev-parse '7.5.1:src/api/routes/public/public-user.php')" 25e8219b790c0d309a88f9bd1285bb6dc43e99b6 f2fq_751_blob

# V396 cmd.py untouched by candidate
CAND=c9a26789d88b18f8b4620f37307df2976292d2a0
FIX=56806080c1348749b07daa4a2024ce47b3cad285
gitx "$GP" log -1 --format='%an <%ae>' "$CAND" | /usr/bin/grep -F 'codex@openai.com' >/dev/null
expect_eq "$(gitx "$GP" rev-parse "${CAND}:git/cmd.py")" "$(gitx "$GP" rev-parse "${CAND}^:git/cmd.py")" v396_cmd_unchanged
anc "$GP" "$CAND" "$FIX"
VULN=$(gitx "$GP" rev-parse '3.1.50^{commit}')
FIXED=$(gitx "$GP" rev-parse '3.1.51^{commit}')
anc "$GP" "$CAND" "$VULN"
not_anc "$GP" "$FIX" "$VULN"
anc "$GP" "$FIX" "$FIXED"

# F38V no git tags for cand/fix
CAND=179cab02dbec0c1e9b601507a65908e079876004
FIX=e0fb8e7dd1ee6759c18ed07f436c21dbd9c20747
gitx "$PR" log -1 --format=%B "$CAND" | /usr/bin/grep -F 'cursoragent@cursor.com' >/dev/null
anc "$PR" "$CAND" "$FIX"
T1=$("${git_cmd[@]}" -C "$PR" tag --contains "$CAND" 2>/dev/null || true)
T2=$("${git_cmd[@]}" -C "$PR" tag --contains "$FIX" 2>/dev/null || true)
if [[ -n ${T1} || -n ${T2} ]]; then
  printf 'F38V unexpectedly tagged in clone\n' >&2
  exit 1
fi
gitx "$PR" show "${CAND}:src/praisonai-platform/pyproject.toml" | /usr/bin/grep -F '0.1.2' >/dev/null
gitx "$PR" show "${FIX}:src/praisonai-platform/pyproject.toml" | /usr/bin/grep -F '0.1.4' >/dev/null

printf 'REPLAY_OK reviewed=6 PASS_proposal=0 NARROW=5 REJECT=1 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=86\n'
