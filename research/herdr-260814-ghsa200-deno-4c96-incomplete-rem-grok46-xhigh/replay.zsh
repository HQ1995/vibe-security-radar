#!/usr/bin/env zsh
# Fail-fast self-contained replay for GHSA-4C96 REJECT.
# English only. Do not print credentials. Do not call gh. Do not use network.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# REJECT is terminal. Packet delta is 0. This script does not admit GHSA-4C96.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export PYTHONDONTWRITEBYTECODE=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-deno-4c96-incomplete-rem-grok46-xhigh
DENO=/home/hanqing/.cache/cve-analyzer/repos/denoland_deno
TMP_DECLARED=/tmp/ghsa200-deno-4c96
git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

PRIOR=9132ad958c83a0d0b199de12b69b877f63edab4c
RESIDUAL=a29b955a86990be8795778a456b38cc09086575b
CLOSER=b4d4a5bc2192e4dcb3ae16319273d9ffa883c7d1
AI43=43deeb2cdbbb8687bf6e9136f4809c6ce32fa1ff
V268=7ab62a769be154c0926fe8be640d48674eb79614
V270=fb4db333c37ec1242a6f80738510d214018fea53
V271=1df618d969894353731981a17784816167ad82fb
V272=83e374686079a2f067115e60ad91ec38f4f6118b
BLOB_V270=3c7661a8c0bf41b74d53e42ddccf737d33a74993
BLOB_V272=b3bda553f593007a327aa8352f24cbcc9fe69242
FILE=ext/node/polyfills/internal/child_process.ts

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
g() {
  "${git_cmd[@]}" -C "$1" "${@:2}"
}
assert_ancestor() {
  g "$1" merge-base --is-ancestor "$2" "$3"
}
assert_not_ancestor() {
  if g "$1" merge-base --is-ancestor "$2" "$3"; then
    printf 'unexpected ancestor: %s is ancestor of %s\n' "$2" "$3" >&2
    exit 1
  fi
}

if [[ -e $TMP_DECLARED ]]; then
  printf 'declared temp path must be absent: %s\n' "$TMP_DECLARED" >&2
  exit 1
fi
require_dir "$OWNED"
require_dir "$DENO/.git"
require_file "$OWNED/case.json"
require_file "$OWNED/report.md"
require_file "$OWNED/summary.json"
require_file "$OWNED/adjudication.jsonl"
require_file "$OWNED/facts/identity.json"
require_file "$OWNED/facts/git.json"
require_file "$OWNED/facts/gates.json"
require_file "$OWNED/facts/uniqueness.json"
require_file "$OWNED/diffs/prior-9132ad95.message.txt"
require_file "$OWNED/diffs/closer-b4d4a5bc.quoting.diff.txt"
require_file "$OWNED/diffs/ai-43deeb2c.message.txt"
require_file "$OWNED/sha256.txt"
if [[ -e $OWNED/selected.jsonl ]]; then
  printf 'selected.jsonl must be absent unless all seven PASS\n' >&2
  exit 1
fi

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06

python3 -B - "$OWNED" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" <<'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
case = json.loads((owned / "case.json").read_text())
summary = json.loads((owned / "summary.json").read_text())
gates = json.loads((owned / "facts/gates.json").read_text())
ident = json.loads((owned / "facts/identity.json").read_text())
gitf = json.loads((owned / "facts/git.json").read_text())
uniq = json.loads((owned / "facts/uniqueness.json").read_text())
adj = [json.loads(l) for l in (owned / "adjudication.jsonl").read_text().splitlines() if l.strip()]
report = (owned / "report.md").read_text()
replay = (owned / "replay.zsh").read_text()

assert case["verdict"] == "REJECT"
assert case["countable"] is False
assert case["countable_proposal"] is False
assert case["causal_admission"] is False
assert case["packet_delta"] == 0
assert case["canonical_strict_count"] == 84
assert case["identity_gate"] == "PASS"
assert case["ai_hunk_gate"] == "FAIL"
assert case["topology_gate"] == "PASS"
assert case["but_for_gate"] == "FAIL"
assert case["fix_reversal_gate"] == "FAIL"
assert case["release_gate"] == "PASS"
assert case["uniqueness_gate"] == "PASS"
assert case["candidate_set"] == []
assert case["failing_gates"] == ["ai_hunk_gate", "but_for_gate"]
assert summary["REJECT"] == 1
assert summary["PASS"] == 0
assert summary["packet_delta"] == 0
assert summary["current_leader_accepted_count"] == 84
assert gates["all_seven_pass"] is False
assert gates["verdict"] == "REJECT"
assert ident["withdrawn"] is False
assert ident["aliases"] == ["CVE-2026-32260"]
assert ident["global_advisory_role"] == "routing_only"
assert gitf["landed_security_commits_ai_marker_in_git_message"] is False
assert gitf["gh_pr_commit_lists"] == "routing_only_discarded"
assert gitf["ai_routing_sha_43de"]["v2_7_2_ancestor"] is False
assert gitf["v2_7_0_equals_v2_7_1_file"] is True
assert uniq["in_canonical84_strict"] is False
assert uniq["canonical84_strict_count"] == 84
assert len(adj) == 1
assert adj[0]["worker_verdict"] == "REJECT"
assert "REJECT" in report
assert "Canonical84 stays 84" in report
assert "gh lists discarded" in report
assert "git_cmd is a zsh array" in replay
assert "Do not name a local 'path'" in replay
assert "Do not call gh" in replay
assert not re.search(r"(?m)^(?:[^#\n]*)\bgh\s+(?:api|pr|auth)\b", replay)

c84 = json.loads(Path(sys.argv[2]).read_text())
ids = {x.upper() for x in c84["strict_released_case_ids"]}
assert len(c84["strict_released_case_ids"]) == 84
assert c84["canonical_strict_count"] == 84
assert "GHSA-4C96-W8V2-P28J" not in ids
assert "GHSA-HMH4-3XVX-Q5HR" not in ids

msg43 = (owned / "diffs/ai-43deeb2c.message.txt").read_text()
assert "Co-authored-by: Claude Opus 4.6 (1M context) <noreply@anthropic.com>" in msg43
assert "timeout" in msg43 and "killSignal" in msg43 and "pid" in msg43
q1 = (owned / "diffs/v2.7.1.quoting-snippet.txt").read_text()
q2 = (owned / "diffs/v2.7.2.quoting-snippet.txt").read_text()
assert "$[A-Za-z_]" in q1
assert "unsafeInDoubleQuotes" not in q1
assert "unsafeInDoubleQuotes" in q2
d = (owned / "diffs/closer-b4d4a5bc.quoting.diff.txt").read_text()
assert "unsafeInDoubleQuotes" in d
assert "hasShellVarRef" in d
pmsg = (owned / "diffs/prior-9132ad95.message.txt").read_text()
assert "escape more shell args (#31999)" in pmsg
assert "Co-authored-by" not in pmsg
assert "Assisted-by" not in pmsg
assert "Claude" not in pmsg

han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(
    r"ghp_" + r"[A-Za-z0-9]{20,}|"
    r"github" + r"_pat_[A-Za-z0-9_]+|"
    r"sk" + r"_live_|"
    r"xox[baprs]-|"
    r"AKIA" + r"[0-9A-Z]{16}|"
    r"BEGIN" + r" PRIVATE"
)
for p in sorted(owned.rglob("*")):
    if not p.is_file():
        continue
    if p.name == "sha256.txt":
        text = p.read_text(encoding="utf-8")
    else:
        text = p.read_text(encoding="utf-8")
    assert text.isascii(), p
    assert not han.search(text), p
    assert not secret.search(text), p
    assert text.endswith("\n"), p
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (str(p), line)
    if p.suffix == ".json":
        json.loads(text)
print("conservation assigned=1 reviewed=1 REJECT=1 PASS=0 NARROW=0 UNKNOWN=0 BLOCKED=0 current_leader_accepted_count=84 packet_delta=0")
PY

[[ "$(g "$DENO" rev-parse 'v2.6.8^{commit}')" == "$V268" ]]
[[ "$(g "$DENO" rev-parse 'v2.7.0^{commit}')" == "$V270" ]]
[[ "$(g "$DENO" rev-parse 'v2.7.1^{commit}')" == "$V271" ]]
[[ "$(g "$DENO" rev-parse 'v2.7.2^{commit}')" == "$V272" ]]
[[ "$(g "$DENO" rev-parse "v2.7.0:${FILE}")" == "$BLOB_V270" ]]
[[ "$(g "$DENO" rev-parse "v2.7.1:${FILE}")" == "$BLOB_V270" ]]
[[ "$(g "$DENO" rev-parse "v2.7.2:${FILE}")" == "$BLOB_V272" ]]
[[ "$(g "$DENO" rev-parse "${CLOSER}:${FILE}")" == "$BLOB_V272" ]]
[[ "$(g "$DENO" log -1 --format='%ae' "$PRIOR")" == "fraifelipe@gmail.com" ]]
[[ "$(g "$DENO" log -1 --format='%ae' "$RESIDUAL")" == "fraifelipe@gmail.com" ]]
[[ "$(g "$DENO" log -1 --format='%ae' "$CLOSER")" == "fraifelipe@gmail.com" ]]
[[ "$(g "$DENO" log -1 --format='%ae' "$AI43")" == "biwanczuk@gmail.com" ]]
[[ "$(g "$DENO" log -1 --format='%P' "$PRIOR")" == "b51441cc1bf99a0ccc66ff706a1887ee0a933d46" ]]
[[ "$(g "$DENO" log -1 --format='%P' "$CLOSER")" == "9c81a2306081a63be4cdbb94b24a2437d0956945" ]]

prior_body=$(g "$DENO" log -1 --format='%B' "$PRIOR")
printf '%s\n' "$prior_body" | grep -F 'escape more shell args (#31999)' >/dev/null
if printf '%s\n' "$prior_body" | grep -Ei 'copilot|claude|assisted-by|co-authored-by' >/dev/null; then
  printf 'prior unexpectedly had AI marker\n' >&2
  exit 1
fi
closer_body=$(g "$DENO" log -1 --format='%B' "$CLOSER")
if printf '%s\n' "$closer_body" | grep -Ei 'copilot|claude|assisted-by|co-authored-by' >/dev/null; then
  printf 'closer unexpectedly had AI marker\n' >&2
  exit 1
fi
ai_body=$(g "$DENO" log -1 --format='%B' "$AI43")
printf '%s\n' "$ai_body" | grep -F 'Co-authored-by: Claude Opus 4.6 (1M context) <noreply@anthropic.com>' >/dev/null
printf '%s\n' "$ai_body" | grep -F 'timeout' >/dev/null

assert_ancestor "$DENO" "$PRIOR" v2.6.8
assert_not_ancestor "$DENO" "$PRIOR" v2.6.7
assert_ancestor "$DENO" "$RESIDUAL" v2.7.0
assert_not_ancestor "$DENO" "$RESIDUAL" v2.6.8
assert_ancestor "$DENO" "$CLOSER" v2.7.2
assert_not_ancestor "$DENO" "$CLOSER" v2.7.1
assert_not_ancestor "$DENO" "$AI43" v2.7.0
assert_not_ancestor "$DENO" "$AI43" v2.7.1
assert_not_ancestor "$DENO" "$AI43" v2.7.2

fp270=$(g "$DENO" rev-list --first-parent v2.7.0)
printf '%s\n' "$fp270" | grep -Fx "$RESIDUAL" >/dev/null
fp272=$(g "$DENO" rev-list --first-parent v2.7.2)
printf '%s\n' "$fp272" | grep -Fx "$CLOSER" >/dev/null
printf '%s\n' "$fp272" | grep -Fx "$PRIOR" >/dev/null
if printf '%s\n' "$fp272" | grep -Fx "$AI43" >/dev/null; then
  printf '43de unexpectedly on first-parent of v2.7.2\n' >&2
  exit 1
fi

v271q=$(g "$DENO" show "v2.7.1:${FILE}")
printf '%s\n' "$v271q" | grep -F '$[A-Za-z_]' >/dev/null
if printf '%s\n' "$v271q" | grep -F 'unsafeInDoubleQuotes' >/dev/null; then
  printf 'v2.7.1 unexpectedly had unsafeInDoubleQuotes\n' >&2
  exit 1
fi
v272q=$(g "$DENO" show "v2.7.2:${FILE}")
printf '%s\n' "$v272q" | grep -F 'unsafeInDoubleQuotes' >/dev/null

if g "$DENO" cat-file -t 0393fdcd14a3987f6863d5fb6d7f149d27548671 >/dev/null 2>&1; then
  printf 'unexpected local object 0393fdcd; packet must not newly attribute it\n' >&2
  exit 1
fi

found=$(/usr/bin/find "$OWNED" \( -name '__pycache__' -o -name '*.pyc' -o -name '*.pyo' \) -print)
if [[ -n $found ]]; then
  printf 'bytecode present:\n%s\n' "$found" >&2
  exit 1
fi

cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"
printf 'REPLAY_OK reviewed=1 REJECT=1 PASS=0 NARROW=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=84\n'
