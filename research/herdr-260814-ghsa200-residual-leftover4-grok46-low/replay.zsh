#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-residual-leftover4-grok46-low.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Current leader-accepted count is 82. Packet delta is 0.
# PASS is a proposal only. This script does not admit GHSA-CHFM or GHSA-JXX9.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export TMPDIR=/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-residual-leftover4-grok46-low/work

ROOT=/home/hanqing/agents/ai-slop
OWNED=/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-residual-leftover4-grok46-low
OC=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw
N8N=/home/hanqing/.cache/ghsa200-worker-clones/baseline-increm-odd/clones/n8n-mcp
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
require_dir "$OC/.git"
require_dir "$N8N/.git"
require_dir "$ADV/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/work/uniqueness.json"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/ledger.jsonl" 58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" d436f47f82297eb0d9363ad0f3876adc639b1f61e9b23c7f9d613545741e106e
expect_hash "$OWNED/selected.jsonl" d0451fc097b0da1aae3befba159facdcbbf322ce3610addc6f0649b1bab0610a
expect_hash "$OWNED/cases.jsonl" 0f2f23102e899bf81aa427706895b531e47971f76a7895012bf025bf8d5403bb
expect_hash "$OWNED/report.md" c7dcd2acfdac65cc8514c81db4874b85c4b4dccb54f9bbc32e066d239570f824
expect_hash "$OWNED/work/uniqueness.json" 19f1fc038d6c135e713cb38ff2c531456df98049eb6488d0ee89335819e7472c

[[ "$(g "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]
[[ "$(g "$ROOT" rev-parse 6800d2127c19532160cc88880115ae28cc446aa5)" == 6800d2127c19532160cc88880115ae28cc446aa5 ]]

python3 - "$OWNED" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" << 'PY'
import json, re, sys
from pathlib import Path
owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned / "result.json").read_text())
uniq = json.loads((owned / "work/uniqueness.json").read_text())
report = (owned / "report.md").read_text()
replay = (owned / "replay.zsh").read_text()
assert len(rows) == 4, len(rows)
assert len(sel) == 4, len(sel)
want = [r["ghsa_id"] for r in sel]
assert want == ['GHSA-X9CF-3W63-RPQ9', 'GHSA-V3QC-WRWX-J3PW', 'GHSA-CHFM-XGC4-47RJ', 'GHSA-JXX9-PX88-PJ69']
assert [r["case_id"] for r in rows] == want
assert res["counts"]["PASS"] == 2
assert res["counts"]["REJECT"] == 2
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 0
assert res["current_leader_accepted_count"] == 82
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["conservation"]["equation"] == "4=4+0"
assert res["did_not_pad"] is True
assert res["pass_proposals"] == ["GHSA-CHFM-XGC4-47RJ", "GHSA-JXX9-PX88-PJ69"]
assert "Current leader-accepted count 82" in report
assert "Packet delta 0" in report
assert uniq["canonical82_strict_count"] == 82
assert uniq["packet_delta"] == 0
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(
    r"ghp_" + r"[A-Za-z0-9]{20,}|"
    r"github" + r"_pat_[A-Za-z0-9_]+|"
    r"sk" + r"_live_|"
    r"xox[baprs]-|"
    r"AKIA" + r"[0-9A-Z]{16}|"
    r"BEGIN" + r" PRIVATE"
)
for name in ("cases.jsonl", "selected.jsonl", "report.md", "replay.zsh", "result.json", "work/uniqueness.json"):
    text = (owned / name).read_text(encoding="utf-8")
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    assert text.endswith("\n"), name
c82 = json.loads(Path(sys.argv[2]).read_text())
ids82 = {x.upper() for x in c82["strict_released_case_ids"]}
assert len(ids82) == 82
for i in want:
    assert i not in ids82, i
by = {r["case_id"]: r for r in rows}
for cid in ("GHSA-CHFM-XGC4-47RJ", "GHSA-JXX9-PX88-PJ69"):
    rec = by[cid]
    assert rec["worker_verdict"] == "PASS"
    assert rec["countable_proposal"] is True
    assert rec["causal_admission"] is False
    assert rec["contribution_class"] == "AI_DIRECT_ROOT"
    for gname in ("identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate", "uniqueness_gate"):
        assert rec[gname] == "PASS", (cid, gname)
    assert rec["remediation_patch_delta_gate"] == "FAIL"
for cid in ("GHSA-X9CF-3W63-RPQ9", "GHSA-V3QC-WRWX-J3PW"):
    rec = by[cid]
    assert rec["worker_verdict"] == "REJECT"
    assert rec["countable_proposal"] is False
print("conservation assigned=4 reviewed=4 unreviewed=0 PASS_proposal=2 REJECT=2 NARROW=0 UNKNOWN=0 BLOCKED=0 current_leader_accepted_count=82 packet_delta=0")
PY

# X9CF: AI subject is image injection
[[ "$(g "$OC" log -1 --format='%s' 8d74578ceb0c3b913555dff6265821eb0fc09749)" == "feat: native image injection for vision-capable models" ]]
pc=$(g "$OC" log -1 --format='%P' 8d74578ceb0c3b913555dff6265821eb0fc09749)
[[ $pc == f7123ec30af8c96bb2cb4da198e19bc03312ba16 ]]

# V3QC: restart deferral
[[ "$(g "$OC" log -1 --format='%s' ab4a08a82accc36ca8cb223c6f9a31eb8e6f72d5)" == "fix: defer gateway restart until all replies are sent (#12970)" ]]

# CHFM topology and trees
CAND=8c852d86f759bc769dfdb070ce568b91c30f2b67
CAND_PARENT=6cbd2d36f85ab47649687eb013630c28987edaad
FIX=5cca38084074fb5095aa11b6a59820d63e4937c9
V328=f9b1079283a8ee25a7cee77c8f8225d5c813bc30
V331=213a704b71f4996dc82a583288ee53785215f627
body=$(g "$OC" log -1 --format='%B' "$CAND")
printf '%s\n' "$body" | grep -F 'Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>' >/dev/null
pc=$(g "$OC" log -1 --format='%P' "$CAND")
[[ $pc == "$CAND_PARENT" ]]
[[ "$(g "$OC" rev-parse 'v2026.3.28^{commit}')" == "$V328" ]]
[[ "$(g "$OC" rev-parse 'v2026.3.31^{commit}')" == "$V331" ]]
assert_ancestor "$OC" "$CAND" "$V328"
assert_not_ancestor "$OC" "$FIX" "$V328"
assert_ancestor "$OC" "$CAND" "$FIX"
assert_ancestor "$OC" "$FIX" "$V331"
v328=$(g "$OC" show "${V328}:extensions/msteams/src/monitor-handler/message-handler.ts")
printf '%s\n' "$v328" | grep -F 'const formatted = formatThreadContext(allMessages, activity.id);' >/dev/null
if printf '%s\n' "$v328" | grep -F 'threadMessages' >/dev/null; then
  printf 'v2026.3.28 already filtered threadMessages\n' >&2
  exit 1
fi
v331=$(g "$OC" show "${V331}:extensions/msteams/src/monitor-handler/message-handler.ts")
printf '%s\n' "$v331" | grep -F 'resolveMSTeamsAllowlistMatch' >/dev/null
printf '%s\n' "$v331" | grep -F 'threadMessages' >/dev/null

# JXX9 topology and tags
ATT=f237fad1e84fbeef388c552c265e61a640352c92
ATT_PARENT=424f8ae1ff1b840a2646b84d594e4f6057128dff
FIXJ=853015d0897be7cf2d9d4726de195c938e4395ab
V2511=b7ad528466bdef4e7b2c38eff833b0b7d476cc44
body=$(g "$N8N" log -1 --format='%B' "$ATT")
printf '%s\n' "$body" | grep -F 'Co-Authored-By: Claude <noreply@anthropic.com>' >/dev/null
pc=$(g "$N8N" log -1 --format='%P' "$ATT")
[[ $pc == "$ATT_PARENT" ]]
pcf=$(g "$N8N" log -1 --format='%P' "$FIXJ")
[[ $pcf == "$V2511" ]]
[[ "$(g "$N8N" rev-parse 'v2.51.1^{commit}')" == "$V2511" ]]
[[ "$(g "$N8N" rev-parse 'v2.51.2^{commit}')" == "$FIXJ" ]]
assert_ancestor "$N8N" "$ATT" "$V2511"
assert_not_ancestor "$N8N" "$FIXJ" "$V2511"
assert_ancestor "$N8N" "$ATT" "$FIXJ"
fb=$(g "$N8N" show "${ATT}:src/mcp/handlers-n8n-manager.ts")
printf '%s\n' "$fb" | grep -F 'Falling back to environment configuration for n8n API client' >/dev/null
fx=$(g "$N8N" show "${FIXJ}:src/mcp/handlers-n8n-manager.ts")
printf '%s\n' "$fx" | grep -F "process.env.ENABLE_MULTI_TENANT === 'true'" >/dev/null
printf '%s\n' "$fx" | grep -F 'must result in no client' >/dev/null

printf 'REPLAY_OK reviewed=4 PASS_proposal=2 REJECT=2 NARROW=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=82\n'
