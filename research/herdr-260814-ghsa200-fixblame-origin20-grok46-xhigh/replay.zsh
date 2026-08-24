#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Current leader-accepted count is 82. Packet delta is 0.
# PASS is a proposal only. This script does not admit GHSA-HHJV.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export TMPDIR=/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/work

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh
ZT=/home/hanqing/.cache/cve-analyzer/repos/qhkm_zeptoclaw
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

g() {
  local repo=$1
  shift
  local errf=$OWNED/work/.giterr
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
    printf 'unexpected ancestor: %s is ancestor of %s in %s\n' "$2" "$3" "$1" >&2
    exit 1
  fi
}

require_dir "$OWNED"
require_dir "$ZT/.git"
require_dir "$ADV/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/exclusion.json"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/ledger.jsonl" \
  58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" \
  d436f47f82297eb0d9363ad0f3876adc639b1f61e9b23c7f9d613545741e106e
expect_hash "$OWNED/selected.jsonl" \
  344761d2c9c683ee6bf2b451f79b70b9e0b12802f037f972e8b159dc9b20f43e
expect_hash "$OWNED/cases.jsonl" \
  f1aa5870c6acbc0128d1c6971a95a0f3a4e609fc5bea6cbc4541fd870a2a35b0
expect_hash "$OWNED/report.md" \
  952af469809a0e28f33851e682445889faaa6818faac3ff98d42f95d90200917
expect_hash "$OWNED/work/uniqueness.json" \
  d2e0160b7d9cdc9deba768a94f4e97c3e327f3a396a7a87c6a4bc81b65d21325
expect_hash "$OWNED/work/exclusion.json" \
  1bf4eb4121ab222579efa008d95ceb020e9ec443c0c450a809d2e93ae2b0fe0a
expect_hash "$OWNED/work/pages/GHSA-HHJV-JQ77-CMVX.json" \
  8ff3c8485814b1720f8dc2d11bd2975f26456a2a635d73dc1b3e5cfb626f17f8
expect_hash "$OWNED/work/pages/repo-advisory/qhkm__zeptoclaw__GHSA-HHJV-JQ77-CMVX.json" \
  1f6c256142a0804eebd71e2ea6659071ff4710c1187498e40a2830e3b774dbfe
expect_hash "$OWNED/work/pages/crates/zeptoclaw-0.6.1.json" \
  f05f30f70880b4f6c8ccb199edcfe754cebae8d16daf707abcbf8233eb7cb8f2
expect_hash "$OWNED/work/pages/crates/zeptoclaw-0.6.2.json" \
  ca8dee4cb5b3ca9e0b372fd18e44aa353f519b22fead32ce827fe99b04ba3006

[[ "$(g "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]
[[ "$(g "$ROOT" rev-parse 6800d2127c19532160cc88880115ae28cc446aa5)" == 6800d2127c19532160cc88880115ae28cc446aa5 ]]

python3 - "$OWNED" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned / "result.json").read_text())
uniq = json.loads((owned / "work/uniqueness.json").read_text())
report = (owned / "report.md").read_text()
replay = (owned / "replay.zsh").read_text()
assert len(rows) == 14, len(rows)
assert len(sel) == 14, len(sel)
want = [r["ghsa_id"] for r in sel]
assert want == sorted(want)
assert [r["case_id"] for r in rows] == want
assert res["counts"]["PASS"] == 1
assert res["counts"]["REJECT"] == 13
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 0
assert res["current_leader_accepted_count"] == 82
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["pass_proposals"] == ["GHSA-HHJV-JQ77-CMVX"]
assert res["did_not_pad"] is True
assert res["not_directroot_queue_pass"] is True
assert "Start count is not rebuilt" in report
assert "Current leader-accepted count 82" in report
assert "Packet delta 0" in report
assert uniq["canonical82_strict_count"] == 82
assert uniq["packet_delta"] == 0
assert uniq["assigned_in_canonical82_strict"] == []
by = {r["case_id"]: r for r in rows}
assert by["GHSA-HHJV-JQ77-CMVX"]["worker_verdict"] == "PASS"
assert by["GHSA-HHJV-JQ77-CMVX"]["countable_proposal"] is True
assert by["GHSA-HHJV-JQ77-CMVX"]["causal_admission"] is False
assert by["GHSA-HHJV-JQ77-CMVX"]["identity_gate"] == "PASS"
assert by["GHSA-HHJV-JQ77-CMVX"]["ai_hunk_gate"] == "PASS"
assert by["GHSA-HHJV-JQ77-CMVX"]["topology_gate"] == "PASS"
assert by["GHSA-HHJV-JQ77-CMVX"]["but_for_gate"] == "PASS"
assert by["GHSA-HHJV-JQ77-CMVX"]["fix_reversal_gate"] == "PASS"
assert by["GHSA-HHJV-JQ77-CMVX"]["release_gate"] == "PASS"
assert by["GHSA-HHJV-JQ77-CMVX"]["uniqueness_gate"] == "PASS"
for cid, rec in by.items():
    if cid != "GHSA-HHJV-JQ77-CMVX":
        assert rec["worker_verdict"] == "REJECT", cid
        assert rec["countable_proposal"] is False, cid
        assert rec["ai_hunk_gate"] == "FAIL", cid
        assert rec["but_for_gate"] == "FAIL", cid
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(
    r"ghp_" + r"[A-Za-z0-9]{20,}|"
    r"github" + r"_pat_[A-Za-z0-9_]+|"
    r"sk" + r"_live_|"
    r"xox[baprs]-|"
    r"AKIA" + r"[0-9A-Z]{16}|"
    r"BEGIN" + r" PRIVATE"
)
for name in ("cases.jsonl", "selected.jsonl", "report.md", "replay.zsh", "result.json", "work/uniqueness.json", "work/exclusion.json"):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    assert text.endswith("\n"), name
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (name, line)
c82 = json.loads(Path(sys.argv[2]).read_text())
ids82 = {x.upper() for x in c82["strict_released_case_ids"]}
assert len(c82["strict_released_case_ids"]) == 82
assert c82["canonical_strict_count"] == 82
assert c82["ledger_sha256"] == "58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23"
for i in want:
    assert i not in ids82, i
assert "GHSA-HHJV-JQ77-CMVX" not in ids82
assert "GHSA-5WP8-Q9MX-8JX8" not in ids82
gpage = json.loads((owned / "work/pages/GHSA-HHJV-JQ77-CMVX.json").read_text())
assert gpage["id"].upper() == "GHSA-HHJV-JQ77-CMVX"
assert gpage.get("withdrawn") in (None, "")
assert (gpage.get("database_specific") or {}).get("github_reviewed") is True
radv = json.loads((owned / "work/pages/repo-advisory/qhkm__zeptoclaw__GHSA-HHJV-JQ77-CMVX.json").read_text())
assert radv.get("state") == "published"
assert radv.get("withdrawn_at") in (None, "")
c61 = json.loads((owned / "work/pages/crates/zeptoclaw-0.6.1.json").read_text())
c62 = json.loads((owned / "work/pages/crates/zeptoclaw-0.6.2.json").read_text())
assert c61["version"]["num"] == "0.6.1"
assert c61["version"]["yanked"] is False
assert c62["version"]["num"] == "0.6.2"
assert c62["version"]["yanked"] is False
r61 = json.loads((owned / "work/pages/github-releases/zeptoclaw_v0.6.1.json").read_text())
r62 = json.loads((owned / "work/pages/github-releases/zeptoclaw_v0.6.2.json").read_text())
assert r61["prerelease"] is False and r61["draft"] is False
assert r62["prerelease"] is False and r62["draft"] is False
print("conservation assigned=14 reviewed=14 unreviewed=0 PASS_proposal=1 REJECT=13 NARROW=0 UNKNOWN=0 BLOCKED=0 current_leader_accepted_count=82 packet_delta=0")
PY

CAND=8f1c1db4f3e6d9e0beb16dc69bf07b10f12276cc
CAND_PARENT=5dad36b962af6258bb059b30bd1b4b5bac3e7442
FIX=68916c3e4f3af107f11940b27854fc7ef517058b
V061=ad14ed8d4e6f982af272523f4accc107b191fb18
V062=f052aa21f298559729aa19b770da988f00a193df

body=$(g "$ZT" log -1 --format='%B' "$CAND")
printf '%s\n' "$body" | grep -F 'Co-authored-by: Claude Opus 4.6 <noreply@anthropic.com>' >/dev/null
pc=$(g "$ZT" log -1 --format='%P' "$CAND")
[[ $pc == "$CAND_PARENT" ]]
[[ "$(g "$ZT" rev-parse 'v0.6.1^{commit}')" == "$V061" ]]
[[ "$(g "$ZT" rev-parse 'v0.6.2^{commit}')" == "$V062" ]]
assert_ancestor "$ZT" "$CAND" "$V061"
assert_not_ancestor "$ZT" "$FIX" "$V061"
assert_ancestor "$ZT" "$CAND" "$V062"
assert_ancestor "$ZT" "$FIX" "$V062"
if g "$ZT" cat-file -e "${CAND_PARENT}:src/tools/android/actions.rs" 2>/dev/null; then
  printf 'AI parent unexpectedly has android actions.rs\n' >&2
  exit 1
fi
ai_shell=$(g "$ZT" show "${CAND}:src/tools/android/actions.rs")
printf '%s\n' "$ai_shell" | grep -F 'pub async fn device_shell' >/dev/null
printf '%s\n' "$ai_shell" | grep -F '"rm -rf"' >/dev/null
printf '%s\n' "$ai_shell" | grep -F 'lower.contains(pattern)' >/dev/null
fix_shell=$(g "$ZT" show "${FIX}:src/tools/android/actions.rs")
printf '%s\n' "$fix_shell" | grep -F 'fn rm_invocation_args' >/dev/null
printf '%s\n' "$fix_shell" | grep -F 'is_rm_recursive_force' >/dev/null
if printf '%s\n' "$fix_shell" | grep -F '"rm -rf"' >/dev/null; then
  printf 'fix still has literal rm -rf blocklist entry\n' >&2
  exit 1
fi
v61_shell=$(g "$ZT" show "${V061}:src/tools/android/actions.rs")
printf '%s\n' "$v61_shell" | grep -F '"rm -rf"' >/dev/null
v62_shell=$(g "$ZT" show "${V062}:src/tools/android/actions.rs")
printf '%s\n' "$v62_shell" | grep -F 'fn rm_invocation_args' >/dev/null

printf 'REPLAY_OK reviewed=14 PASS_proposal=1 REJECT=13 NARROW=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=82\n'
