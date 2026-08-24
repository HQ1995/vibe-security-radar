#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-chfm-jxx9-hostile-redteam-grok46-high.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# REJECT is the verdict. Packet delta is 0. This script does not admit GHSA-CHFM or GHSA-JXX9.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-chfm-jxx9-hostile-redteam-grok46-high
OC=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw
N8N=/home/hanqing/.cache/ghsa200-worker-clones/baseline-increm-odd/clones/n8n-mcp
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database
SRC=$ROOT/autoresearch/herdr-260814-ghsa200-residual-leftover4-grok46-low

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

CAND_CHFM=8c852d86f759bc769dfdb070ce568b91c30f2b67
PARENT_CHFM=6cbd2d36f85ab47649687eb013630c28987edaad
FIX_CHFM=5cca38084074fb5095aa11b6a59820d63e4937c9
M1=9f40ec891132372673b82cdda039db51a57e20c1
V328=f9b1079283a8ee25a7cee77c8f8225d5c813bc30
V331=213a704b71f4996dc82a583288ee53785215f627
MH=extensions/msteams/src/monitor-handler/message-handler.ts
GT=extensions/msteams/src/graph-thread.ts

CAND_J=f237fad1e84fbeef388c552c265e61a640352c92
PARENT_J=424f8ae1ff1b840a2646b84d594e4f6057128dff
FIX_J=853015d0897be7cf2d9d4726de195c938e4395ab
MERGE212=c5aebc14504ecb60a8f9dbfc36f5e6e33d0b8e95
V2511=b7ad528466bdef4e7b2c38eff833b0b7d476cc44
HN=src/mcp/handlers-n8n-manager.ts
BLOB_HN_PARENT=502a664edd63844a27f1f434e18c39fd0adb2dfe

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
require_dir "$OC/.git"
require_dir "$N8N/.git"
require_dir "$ADV/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/case.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/facts/gates.json"
require_file "$OWNED/facts/git.json"
require_file "$OWNED/facts/identity.json"
require_file "$OWNED/facts/uniqueness.json"
require_file "$OWNED/releases/npm.json"
require_file "$OWNED/diffs/chfm.m1.message.txt"
require_file "$OWNED/diffs/chfm.m1.mh.hunk.diff.txt"
require_file "$OWNED/diffs/jxx9.cand.files.txt"
require_file "$OWNED/diffs/jxx9.npm2511.no_refuse.txt"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/ledger.jsonl" \
  58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" \
  d436f47f82297eb0d9363ad0f3876adc639b1f61e9b23c7f9d613545741e106e
expect_hash "$SRC/selected.jsonl" \
  d0451fc097b0da1aae3befba159facdcbbf322ce3610addc6f0649b1bab0610a
expect_hash "$SRC/cases.jsonl" \
  0f2f23102e899bf81aa427706895b531e47971f76a7895012bf025bf8d5403bb
expect_hash "$SRC/result.json" \
  2ff65355600bee4830f342e73e6be415d1971eef44315143f6cbbf8bb9bd985a
expect_hash "$OWNED/cases.jsonl" \
  6760e03bfd63fff4cd9373b15574d8297d6e1245a8c40f90f9d1184a0bd0e6aa
expect_hash "$OWNED/case.jsonl" \
  6760e03bfd63fff4cd9373b15574d8297d6e1245a8c40f90f9d1184a0bd0e6aa
expect_hash "$OWNED/report.md" \
  9ee1e2e45052978563f386cffd1bea6a9ebdaf2331c30e4e890b5ef6f30d46a0
expect_hash "$OWNED/facts/identity.json" \
  a2dd75b6218b983d8a55fd9c607d79dce11ad611ac7cad63c303a7efad3b7eb8
expect_hash "$OWNED/facts/git.json" \
  08f63bcb8a68b79b2535dcd5b7b01af9726c1f022bfd5feb25343b1c39a44c01
expect_hash "$OWNED/facts/uniqueness.json" \
  6de3848f294f68c17e57e3b75ac31a7a9fce7e73c17dec1d649ea1fa91812be1
expect_hash "$OWNED/facts/gates.json" \
  1dc7f1b60923f21d46ecbbf0801a9381cf47b0cea3bc809bd93e662eab846778
expect_hash "$OWNED/releases/npm.json" \
  306ba7547b91c6823db2bc7094168f802c2364e4416ebe421c2ca8942041f45f
expect_hash "$OWNED/diffs/chfm.m1.message.txt" \
  a499e61de608380ca46a82bd87b965afb3d5a617330a93cbe81e3fc19aa9c842
expect_hash "$OWNED/diffs/chfm.m1.mh.hunk.diff.txt" \
  8209699c50347f446374f5ba8f8fd559a7d8b26966842aa528b38e58b6bd4599
expect_hash "$OWNED/diffs/chfm.npm328.unfiltered.js.txt" \
  4188ec6ca40d38d670e9db3e6cc261056904847ec478d0ca5fa46faa218dd718
expect_hash "$OWNED/diffs/chfm.npm331.filtered.js.txt" \
  f3f5433da56ae0b1b4dcf8787a6a82516e4cc5bcc2ad5df5d96608469de9fd85
expect_hash "$OWNED/diffs/jxx9.cand.files.txt" \
  b8ad2bc5dab5d6d8c60e852ccbb87b609074719b22cf31568674cd20e3d24e94
expect_hash "$OWNED/diffs/jxx9.npm2511.no_refuse.txt" \
  2254400f0e116ce60c37eda311835f44acd9169e6f0f7abdc3884ab169333125

[[ "$(g "$ROOT" rev-parse 6800d2127c19532160cc88880115ae28cc446aa5)" == 6800d2127c19532160cc88880115ae28cc446aa5 ]]
[[ "$(g "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]

python3 - "$OWNED" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
case_copy = [json.loads(l) for l in (owned / "case.jsonl").read_text().splitlines() if l.strip()]
assert rows == case_copy
assert [r["case_id"] for r in rows] == ["GHSA-CHFM-XGC4-47RJ", "GHSA-JXX9-PX88-PJ69"]
res = json.loads((owned / "result.json").read_text())
gates = json.loads((owned / "facts/gates.json").read_text())
uniq = json.loads((owned / "facts/uniqueness.json").read_text())
ident = json.loads((owned / "facts/identity.json").read_text())
gitf = json.loads((owned / "facts/git.json").read_text())
npm = json.loads((owned / "releases/npm.json").read_text())
report = (owned / "report.md").read_text()

assert len(rows) == 2
for rec in rows:
    assert rec["verdict"] == "REJECT"
    assert rec["countable"] is False
    assert rec["countable_proposal"] is False
    assert rec["causal_admission"] is False
    assert rec["packet_delta"] == 0
    assert rec["current_leader_accepted_count"] == 82
    assert rec["leader_logical_count"] == 84
    assert rec["committed_canonical_baseline"] == 82
    assert rec["identity_gate"] == "PASS"
    assert rec["ai_hunk_gate"] == "FAIL"
    assert rec["topology_gate"] == "FAIL"
    assert rec["but_for_gate"] == "FAIL"
    assert rec["fix_reversal_gate"] == "PASS"
    assert rec["release_gate"] == "PASS"
    assert rec["uniqueness_gate"] == "PASS"
    assert rec["remediation_patch_delta_gate"] == "NOT_APPLICABLE"
    assert rec["failing_gates"] == ["ai_hunk_gate", "topology_gate", "but_for_gate"]

assert rows[0]["authorship_transfer_from_member_to_carrier"] is True
assert rows[0]["human_member"].startswith("9f40ec89")
assert "handlers-n8n-manager.ts" not in (owned / "diffs/jxx9.cand.files.txt").read_text()
assert gates["all_seven_pass"] is False
assert gates["remediation_patch_delta_gate"] == "NOT_APPLICABLE"
assert res["verdicts"]["KEEP"] == 0
assert res["verdicts"]["REJECT"] == 2
assert res["packet_delta"] == 0
assert res["current_leader_accepted_count"] == 82
assert res["leader_logical_count"] == 84
assert res["causal_admission"] is False
assert res["canonical_count_updated"] is False
assert res["conservation"]["equation"] == "2=2+0"
assert ident["cases"]["GHSA-CHFM-XGC4-47RJ"]["github_reviewed"] is True
assert ident["cases"]["GHSA-CHFM-XGC4-47RJ"]["withdrawn"] is False
assert ident["cases"]["GHSA-JXX9-PX88-PJ69"]["github_reviewed"] is True
assert ident["cases"]["GHSA-JXX9-PX88-PJ69"]["withdrawn"] is False
assert gitf["GHSA-CHFM-XGC4-47RJ"]["pr_members"][0]["ai_marker"] is False
assert gitf["GHSA-CHFM-XGC4-47RJ"]["pr_members"][0]["authors_unfiltered_thread_history"] is True
assert gitf["GHSA-JXX9-PX88-PJ69"]["candidate_files_do_not_include_handlers_n8n_manager"] is True
assert gitf["GHSA-JXX9-PX88-PJ69"]["candidate_first_parent_ancestor_of_v2.51.1"] is False
assert uniq["canonical82_strict_count"] == 82
assert uniq["packet_delta"] == 0
assert uniq["GHSA-JXX9-PX88-PJ69"]["shared_sha_does_not_merge_cases"] is True
assert npm["openclaw"]["2026.3.28"]["contains_unfiltered_graph_thread"] is True
assert npm["openclaw"]["2026.3.31"]["contains_allowlist_filter_on_thread"] is True
assert npm["n8n-mcp"]["2.51.1"]["has_refuse_fallback"] is False
assert npm["n8n-mcp"]["2.51.2"]["has_refuse_fallback"] is True
assert "REJECT both" in report
assert "Packet delta 0" in report
assert "does not rebuild canonical82" in report
assert "KEEP proposal 0" in report
assert "leader logical count 84" in report.lower() or "Leader logical count 84" in report

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
    "cases.jsonl",
    "case.jsonl",
    "report.md",
    "replay.zsh",
    "result.json",
    "facts/identity.json",
    "facts/git.json",
    "facts/uniqueness.json",
    "facts/gates.json",
    "releases/npm.json",
):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    assert text.endswith("\n"), name
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (name, line)
    if name.endswith(".json") or name.endswith(".jsonl"):
        if name.endswith(".jsonl"):
            for line in text.splitlines():
                if line.strip():
                    json.loads(line)
        else:
            json.loads(text)

c82 = json.loads(Path(sys.argv[2]).read_text())
ids82 = {x.upper() for x in c82["strict_released_case_ids"]}
assert len(c82["strict_released_case_ids"]) == 82
assert c82["canonical_strict_count"] == 82
assert "GHSA-CHFM-XGC4-47RJ" not in ids82
assert "GHSA-JXX9-PX88-PJ69" not in ids82
assert "GHSA-4GGG-H7PH-26QR" not in ids82
assert "GHSA-56C3-VFP2-5QQJ" in ids82

m1 = (owned / "diffs/chfm.m1.message.txt").read_text()
assert "Co-Authored-By" not in m1 and "Co-authored-by" not in m1
assert "Claude" not in m1
assert "Generated with" not in m1
mh = (owned / "diffs/chfm.m1.mh.hunk.diff.txt").read_text()
assert "formatThreadContext(allMessages, activity.id)" in mh
assert "resolveMSTeamsAllowlistMatch" not in mh
sq = (owned / "diffs/chfm.squash.message.txt").read_text()
assert "Co-Authored-By: Claude Opus 4.6" in sq or "Co-authored-by: Claude Opus 4.6" in sq
u328 = (owned / "diffs/chfm.npm328.unfiltered.js.txt").read_text()
assert "formatThreadContext(parentMsg ? [parentMsg, ...replies] : replies, activity.id)" in u328
assert "resolveMSTeamsAllowlistMatch" not in u328
u331 = (owned / "diffs/chfm.npm331.filtered.js.txt").read_text()
assert "allMessages.filter" in u331
assert "resolveMSTeamsAllowlistMatch" in u331
nr = (owned / "diffs/jxx9.npm2511.no_refuse.txt").read_text()
assert "has_Refusing=False" in nr
assert "has_headers_required=False" in nr
assert "has_Falling_back=True" in nr
print("conservation assigned=2 reviewed=2 unreviewed=0 KEEP_proposal=0 REJECT=2 NARROW=0 UNKNOWN=0 BLOCKED=0 current_leader_accepted_count=82 packet_delta=0")
PY

# CHFM topology
[[ "$(g "$OC" log -1 --format='%P' "$CAND_CHFM")" == "$PARENT_CHFM" ]]
[[ "$(g "$OC" log -1 --format='%P' "$FIX_CHFM")" == "$(g "$OC" rev-parse "${FIX_CHFM}^")" ]]
body=$(g "$OC" log -1 --format='%B' "$CAND_CHFM")
printf '%s\n' "$body" | grep -F 'Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>' >/dev/null
[[ "$(g "$OC" rev-parse 'v2026.3.28^{commit}')" == "$V328" ]]
[[ "$(g "$OC" rev-parse 'v2026.3.31^{commit}')" == "$V331" ]]
assert_ancestor "$OC" "$CAND_CHFM" "$V328"
assert_not_ancestor "$OC" "$FIX_CHFM" "$V328"
assert_ancestor "$OC" "$FIX_CHFM" "$V331"
parent_gt=$(g "$OC" ls-tree --name-only "$PARENT_CHFM" -- "$GT")
if [[ -n $parent_gt ]]; then
  printf 'parent unexpectedly has graph-thread.ts\n' >&2
  exit 1
fi
set +e
"${git_cmd[@]}" -C "$OC" cat-file -e "${M1}^{commit}" >/dev/null 2>&1
m1_present=$?
set -e
if [[ $m1_present -eq 0 ]]; then
  printf 'unmarked member unexpectedly present in clone\n' >&2
  exit 1
fi
m1msg=$(cat "$OWNED/diffs/chfm.m1.message.txt")
if printf '%s\n' "$m1msg" | grep -E 'Co-authored-by:|Co-Authored-By:|Claude|Generated with' >/dev/null; then
  printf 'unmarked member unexpectedly has AI marker\n' >&2
  exit 1
fi
v328=$(g "$OC" show "${V328}:${MH}")
printf '%s\n' "$v328" | grep -F 'formatThreadContext(allMessages, activity.id)' >/dev/null
v331=$(g "$OC" show "${V331}:${MH}")
printf '%s\n' "$v331" | grep -F 'resolveMSTeamsAllowlistMatch' >/dev/null
printf '%s\n' "$v331" | grep -F 'threadMessages' >/dev/null

# JXX9 topology and hunk
[[ "$(g "$N8N" log -1 --format='%P' "$CAND_J")" == "$PARENT_J" ]]
[[ "$(g "$N8N" rev-parse "${PARENT_J}:${HN}")" == "$BLOB_HN_PARENT" ]]
[[ "$(g "$N8N" rev-parse "${CAND_J}:${HN}")" == "$BLOB_HN_PARENT" ]]
[[ "$(g "$N8N" log -1 --format='%s' "$FIX_J")" == "Merge commit from fork" ]]
[[ "$(g "$N8N" rev-parse 'v2.51.1^{commit}')" == "$V2511" ]]
[[ "$(g "$N8N" rev-parse 'v2.51.2^{commit}')" == "$FIX_J" ]]
assert_ancestor "$N8N" "$CAND_J" "$V2511"
assert_not_ancestor "$N8N" "$FIX_J" "$V2511"
assert_ancestor "$N8N" "$MERGE212" "$V2511"
fp=$(g "$N8N" log --first-parent --format='%H' "$V2511")
if printf '%s\n' "$fp" | grep -Fx "$CAND_J" >/dev/null; then
  printf 'f237 unexpectedly on first-parent chain of v2.51.1\n' >&2
  exit 1
fi
printf '%s\n' "$fp" | grep -Fx "$MERGE212" >/dev/null
parent_hn=$(g "$N8N" show "${PARENT_J}:${HN}")
printf '%s\n' "$parent_hn" | grep -F 'Falling back to environment configuration for n8n API client' >/dev/null
if printf '%s\n' "$parent_hn" | grep -F 'ENABLE_MULTI_TENANT' >/dev/null; then
  printf 'parent unexpectedly has ENABLE_MULTI_TENANT in handlers\n' >&2
  exit 1
fi
cand_files=$(g "$N8N" diff-tree --no-commit-id --name-only -r "$CAND_J")
if printf '%s\n' "$cand_files" | grep -Fx "$HN" >/dev/null; then
  printf 'candidate unexpectedly modifies handlers-n8n-manager.ts\n' >&2
  exit 1
fi
printf '%s\n' "$cand_files" | grep -Fx 'src/http-server-single-session.ts' >/dev/null
v2511hn=$(g "$N8N" show "${V2511}:${HN}")
printf '%s\n' "$v2511hn" | grep -F 'Falling back to environment configuration for n8n API client' >/dev/null
if printf '%s\n' "$v2511hn" | grep -F 'Refusing env-credential fallback' >/dev/null; then
  printf 'v2.51.1 unexpectedly refuses env fallback\n' >&2
  exit 1
fi
fixhn=$(g "$N8N" show "${FIX_J}:${HN}")
printf '%s\n' "$fixhn" | grep -F 'Refusing env-credential fallback' >/dev/null

printf 'REPLAY_OK reviewed=2 KEEP_proposal=0 REJECT=2 NARROW=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=82\n'
