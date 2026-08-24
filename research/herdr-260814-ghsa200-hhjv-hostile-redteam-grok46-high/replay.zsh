#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-hhjv-hostile-redteam-grok46-high.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# REJECT is the verdict. Packet delta is 0. This script does not admit GHSA-HHJV.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-hhjv-hostile-redteam-grok46-high
ZT=/home/hanqing/.cache/cve-analyzer/repos/qhkm_zeptoclaw

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

CAND=8f1c1db4f3e6d9e0beb16dc69bf07b10f12276cc
PARENT=5dad36b962af6258bb059b30bd1b4b5bac3e7442
FIX=68916c3e4f3af107f11940b27854fc7ef517058b
M1=92396b576d1ec8a39600ad510930d3e1a21484e7
M2=e7c1a68d5e7cd99ba0edc32f7d376f00246b6c76
V061=ad14ed8d4e6f982af272523f4accc107b191fb18
V062=f052aa21f298559729aa19b770da988f00a193df
FILE=src/tools/android/actions.rs
BLOB_M1=52b8f8aefb3769b8ab54df95af50b826f1429313
BLOB_SQ=c1b86011dede6ae50bd58043ce149f3d5440608b
BLOB_FIX=e544f53b405e75991d7d2ff766f6182de2df4057

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
  local repo=$1
  shift
  local errf=$OWNED/work/.giterr
  mkdir -p "$OWNED/work"
  set +e
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
  if [[ -s $errf ]]; then
    grep -vF 'unable to normalize alternate object path' "$errf" >&2 || true
  fi
  rm -f "$errf"
  return $rc
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

require_dir "$OWNED"
require_dir "$ZT/.git"
require_file "$OWNED/case.json"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/facts/gates.json"
require_file "$OWNED/facts/git.json"
require_file "$OWNED/facts/identity.json"
require_file "$OWNED/facts/crates.json"
require_file "$OWNED/facts/uniqueness.json"
require_file "$OWNED/diffs/device_shell.m1.rs.txt"
require_file "$OWNED/diffs/device_shell.squash.rs.txt"
require_file "$OWNED/diffs/m1.message.txt"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/ledger.jsonl" \
  58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" \
  d436f47f82297eb0d9363ad0f3876adc639b1f61e9b23c7f9d613545741e106e
expect_hash "$OWNED/case.json" \
  23e9c6fc47171c2add46b6c3da16bc1a23dd54f6dbc476757c4f744108a181de
expect_hash "$OWNED/report.md" \
  d938a4f9b5ba5498ebe2088310b850616c927666d75c83e77c0dbf3bd43ca94f
expect_hash "$OWNED/facts/crates.json" \
  dc7c661334bb2620f8ca7c7d8686054a225f31cf551548c8f24a785c42d65b1f
expect_hash "$OWNED/facts/gates.json" \
  1099877734fa1a261871b3344cc9ef4d893079de6c3ccd5016e50f3687dd4e93
expect_hash "$OWNED/facts/git.json" \
  7820d383b30d64999f79cbf40d8cad3cb706de06d46c3f3b35f85b1abefa35ae
expect_hash "$OWNED/facts/identity.json" \
  10acb738ddca3354595b67613464a07d6ddd5241da2eda1a00f03a9d19f5eb5d
expect_hash "$OWNED/facts/uniqueness.json" \
  01529707bbd9d4263ed7c193cbb6b64d563fc705c11a1bccea63dbbeed73e9b1
expect_hash "$OWNED/diffs/device_shell.m1.rs.txt" \
  c17d795752964fac55d24f44d2bebc574dc65db11adc4f967cf4d46db7370942
expect_hash "$OWNED/diffs/device_shell.squash.rs.txt" \
  c17d795752964fac55d24f44d2bebc574dc65db11adc4f967cf4d46db7370942
expect_hash "$OWNED/diffs/device_shell.v061.rs.txt" \
  c17d795752964fac55d24f44d2bebc574dc65db11adc4f967cf4d46db7370942
expect_hash "$OWNED/diffs/device_shell.crate061.rs.txt" \
  c17d795752964fac55d24f44d2bebc574dc65db11adc4f967cf4d46db7370942
expect_hash "$OWNED/diffs/features.crate061.toml.txt" \
  77d44cc2b94a56b10ae69a3145fbc7731b30caae3a67fdd52d58f6e05df278df
expect_hash "$OWNED/diffs/features.crate062.toml.txt" \
  a20f32b5710657aa6f80bc9852ba8142b1fb8635f86598f2c5d2d982e02001aa
expect_hash "$OWNED/diffs/m1.message.txt" \
  41ff4bee52e47e7ed722c678fea153d1e68a820b121274f0043b27887c0364df

[[ "$(g "$ROOT" rev-parse 6800d2127c19532160cc88880115ae28cc446aa5)" == 6800d2127c19532160cc88880115ae28cc446aa5 ]]

python3 - "$OWNED" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
case = json.loads((owned / "case.json").read_text())
res = json.loads((owned / "result.json").read_text())
gates = json.loads((owned / "facts/gates.json").read_text())
uniq = json.loads((owned / "facts/uniqueness.json").read_text())
ident = json.loads((owned / "facts/identity.json").read_text())
gitf = json.loads((owned / "facts/git.json").read_text())
crates = json.loads((owned / "facts/crates.json").read_text())
report = (owned / "report.md").read_text()
replay = (owned / "replay.zsh").read_text()

assert case["verdict"] == "REJECT"
assert case["countable"] is False
assert case["countable_proposal"] is False
assert case["causal_admission"] is False
assert case["packet_delta"] == 0
assert case["current_leader_accepted_count"] == 82
assert case["identity_gate"] == "PASS"
assert case["ai_hunk_gate"] == "FAIL"
assert case["topology_gate"] == "FAIL"
assert case["but_for_gate"] == "FAIL"
assert case["fix_reversal_gate"] == "PASS"
assert case["release_gate"] == "PASS"
assert case["uniqueness_gate"] == "PASS"
assert case["failing_gates"] == ["ai_hunk_gate", "topology_gate", "but_for_gate"]
assert case["authorship_transfer_from_member_to_carrier"] is True
assert gates["verdict"] == "REJECT"
assert gates["all_seven_pass"] is False
assert res["verdicts"]["KEEP"] == 0
assert res["verdicts"]["REJECT"] == 1
assert res["packet_delta"] == 0
assert res["current_leader_accepted_count"] == 82
assert res["causal_admission"] is False
assert res["canonical_count_updated"] is False
assert ident["github_reviewed"] is True
assert ident["withdrawn"] is False
assert ident["aliases"] == []
assert gitf["human_member"]["ai_marker"] is False
assert gitf["ai_member"]["ai_marker"] is True
assert gitf["human_member"]["ancestor_of_v0_6_1"] is False
assert gitf["squash"]["device_shell_fn_equals_human_member"] is True
assert crates["feature_gating_voids_advisory_range"] is False
assert crates["v0_6_1"]["yanked"] is False
assert crates["v0_6_2"]["yanked"] is False
assert uniq["in_canonical82_strict"] is False
assert uniq["packet_delta"] == 0
assert uniq["shared_fix_does_not_merge_cases"] is True
assert "REJECT" in report
assert "Packet delta 0" in report
assert "does not rebuild canonical82" in report
assert "KEEP proposal 0" in report

han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(
    r"ghp_" + r"[A-Za-z0-9]{20,}|"
    r"github" + r"_pat_[A-Za-z0-9_]+|"
    r"sk" + r"_live_|"
    r"xox[baprs]-|"
    r"AKIA" + r"[0-9A-Z]{16}|"
    r"BEGIN" + r" PRIVATE"
)
for name in (
    "case.json",
    "report.md",
    "replay.zsh",
    "result.json",
    "facts/identity.json",
    "facts/git.json",
    "facts/crates.json",
    "facts/uniqueness.json",
    "facts/gates.json",
):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    assert text.endswith("\n"), name
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (name, line)
    if name.endswith(".json"):
        json.loads(text)

c82 = json.loads(Path(sys.argv[2]).read_text())
ids82 = {x.upper() for x in c82["strict_released_case_ids"]}
assert len(c82["strict_released_case_ids"]) == 82
assert c82["canonical_strict_count"] == 82
assert "GHSA-HHJV-JQ77-CMVX" not in ids82
assert "GHSA-5WP8-Q9MX-8JX8" not in ids82
assert "GHSA-46Q5-G3J9-WX5C" in ids82
assert uniq["canonical82_strict_count"] == 82

m1 = (owned / "diffs/device_shell.m1.rs.txt").read_text()
sq = (owned / "diffs/device_shell.squash.rs.txt").read_text()
v61 = (owned / "diffs/device_shell.v061.rs.txt").read_text()
c61 = (owned / "diffs/device_shell.crate061.rs.txt").read_text()
assert m1 == sq == v61 == c61
assert '"rm -rf"' in m1
assert "pub async fn device_shell" in m1
assert "lower.contains(pattern)" in m1
fix = (owned / "diffs/device_shell.fix.rs.txt").read_text()
assert "fn rm_invocation_args" in fix
assert "is_rm_recursive_force" in fix
assert '"rm -rf"' not in fix
msg = (owned / "diffs/m1.message.txt").read_text()
assert "Co-authored-by" not in msg
assert "Claude" not in msg
assert "Generated with" not in msg
print("conservation assigned=1 reviewed=1 unreviewed=0 KEEP_proposal=0 REJECT=1 NARROW=0 UNKNOWN=0 BLOCKED=0 current_leader_accepted_count=82 packet_delta=0")
PY

[[ "$(g "$ZT" log -1 --format='%P' "$CAND")" == "$PARENT" ]]
[[ "$(g "$ZT" log -1 --format='%P' "$M1")" == "$PARENT" ]]
[[ "$(g "$ZT" log -1 --format='%P' "$M2")" == "$M1" ]]
[[ "$(g "$ZT" rev-parse "${M1}:${FILE}")" == "$BLOB_M1" ]]
[[ "$(g "$ZT" rev-parse "${M2}:${FILE}")" == "$BLOB_SQ" ]]
[[ "$(g "$ZT" rev-parse "${CAND}:${FILE}")" == "$BLOB_SQ" ]]
[[ "$(g "$ZT" rev-parse "${V061}:${FILE}")" == "$BLOB_SQ" ]]
[[ "$(g "$ZT" rev-parse "${FIX}:${FILE}")" == "$BLOB_FIX" ]]
[[ "$(g "$ZT" rev-parse "${V062}:${FILE}")" == "$BLOB_FIX" ]]
parent_file=$(g "$ZT" ls-tree --name-only "$PARENT" -- "$FILE")
if [[ -n $parent_file ]]; then
  printf 'AI parent unexpectedly has android actions.rs\n' >&2
  exit 1
fi

m1body=$(g "$ZT" log -1 --format='%B' "$M1")
if printf '%s\n' "$m1body" | grep -E 'Co-authored-by:|Claude|Generated with' >/dev/null; then
  printf 'human member unexpectedly has AI marker\n' >&2
  exit 1
fi
m2body=$(g "$ZT" log -1 --format='%B' "$M2")
printf '%s\n' "$m2body" | grep -F 'Co-authored-by: Claude Opus 4.6 <noreply@anthropic.com>' >/dev/null
sqbody=$(g "$ZT" log -1 --format='%B' "$CAND")
printf '%s\n' "$sqbody" | grep -F 'Co-authored-by: Claude Opus 4.6 <noreply@anthropic.com>' >/dev/null

m1fn=$(g "$ZT" show "${M1}:${FILE}")
printf '%s\n' "$m1fn" | grep -F 'pub async fn device_shell' >/dev/null
printf '%s\n' "$m1fn" | grep -F '"rm -rf"' >/dev/null
printf '%s\n' "$m1fn" | grep -F 'lower.contains(pattern)' >/dev/null
diffout=$(g "$ZT" diff "$M1" "$M2" -- "$FILE")
if printf '%s\n' "$diffout" | grep -E '^[+-].*"rm -rf"|^[+-].*let blocked' | grep -vE '^\+\+\+|^---' >/dev/null; then
  printf 'AI member unexpectedly touches rm blocklist\n' >&2
  exit 1
fi

assert_not_ancestor "$ZT" "$M1" "$CAND"
assert_not_ancestor "$ZT" "$M2" "$CAND"
assert_not_ancestor "$ZT" "$M1" "$V061"
assert_not_ancestor "$ZT" "$M2" "$V061"
assert_ancestor "$ZT" "$CAND" "$V061"
assert_not_ancestor "$ZT" "$FIX" "$V061"
assert_ancestor "$ZT" "$FIX" "$V062"
[[ "$(g "$ZT" rev-parse 'v0.6.1^{commit}')" == "$V061" ]]
[[ "$(g "$ZT" rev-parse 'v0.6.2^{commit}')" == "$V062" ]]

fixfiles=$(g "$ZT" diff-tree --no-commit-id --name-only -r "$FIX")
printf '%s\n' "$fixfiles" | grep -Fx "$FILE" >/dev/null
printf '%s\n' "$fixfiles" | grep -Fx 'src/security/shell.rs' >/dev/null
fixfn=$(g "$ZT" show "${FIX}:${FILE}")
printf '%s\n' "$fixfn" | grep -F 'fn rm_invocation_args' >/dev/null
printf '%s\n' "$fixfn" | grep -F 'is_rm_recursive_force' >/dev/null
if printf '%s\n' "$fixfn" | grep -F '"rm -rf"' >/dev/null; then
  printf 'fix still has literal rm -rf blocklist entry\n' >&2
  exit 1
fi

host=$(g "$ZT" ls-tree -r --name-only "$PARENT")
printf '%s\n' "$host" | grep -Fx 'src/security/shell.rs' >/dev/null
if printf '%s\n' "$host" | grep -i android >/dev/null; then
  printf 'parent unexpectedly has android paths\n' >&2
  exit 1
fi

printf 'REPLAY_OK reviewed=1 KEEP_proposal=0 REJECT=1 NARROW=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=82\n'
