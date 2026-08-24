#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-hc8v-hostile-redteam-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# KEEP is a proposal only. Packet delta is 0. This script does not admit GHSA-HC8V.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-hc8v-hostile-redteam-grok46-xhigh
GG=/home/hanqing/.cache/cve-analyzer/repos/go-git_go-git

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

CAND=d83871ed0314f604e417f40733f762acfdcbc35c
PARENT=c6d8721af933337e0ef616eba1920b195da27f67
FIX=008a78f2dd86f52544ddff8b8e8ddeecdf3f7aab
ORIG=a0e1969181c482fad64a016167bb95d0eba80eef
MERGE2081=6381631cf5c3c8c1ec1d908c907a3ed930d85b96
MERGE2100=b1fab6cb0d33be2e084565bf04bb9222c8d1f419
V191=3c3be601aa6c0fd0d536c0d1e4f898b4c60e65fe
V192=3eeb238da61eb9c7a324f3ee04f990ce89175642
MOVING=2263fb5f022dde90b1c2845f028d3e37e161f2b8
BLOB_ORIG=6804d21d9e8029ea9b5d9a8956561b75415e31e0
BLOB_CAND=3b8e28d7baca3324d442284560a9c82675795d1d
BLOB_V191=9bc2fd97dc9b41432807f030870a4237765b8999
BLOB_FIX=cf16de746a8479096fae8f84a0d8d2347f2b355c
FILE=worktree_fs.go

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
require_dir "$GG/.git"
require_file "$OWNED/case.json"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/facts/gates.json"
require_file "$OWNED/facts/git.json"
require_file "$OWNED/facts/identity.json"
require_file "$OWNED/facts/releases.json"
require_file "$OWNED/facts/uniqueness.json"
require_file "$OWNED/facts/prs.json"
require_file "$OWNED/diffs/candidate.worktree_fs.go.txt"
require_file "$OWNED/diffs/fix.validNoLeadingSymlink.fn.go.txt"
require_file "$OWNED/work/tarballs/v5.19.1.tar.gz"
require_file "$OWNED/work/tarballs/v5.19.2.tar.gz"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/ledger.jsonl" \
  58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" \
  d436f47f82297eb0d9363ad0f3876adc639b1f61e9b23c7f9d613545741e106e
expect_hash "$OWNED/case.json" \
  0b9bdbbcffabdf43b0f69fc6f273489396d2fabd8b9dfc31956683d5c435df37
expect_hash "$OWNED/report.md" \
  d60c5f8650a2bfb00661832218271f30a46885d71458da7a409e7d1309f30025
expect_hash "$OWNED/facts/identity.json" \
  d923b3da8c13063abde3134ff00c0379e805727a41a3522771f9c8a729e42c70
expect_hash "$OWNED/facts/git.json" \
  787f48051a0515df2bd01053ffe16d8fd2125f1909afc4c4ce6355f1e21030b7
expect_hash "$OWNED/facts/prs.json" \
  e339acdb7d852e6ba706a8377d9977d93928efdbcf036ff5a1d4b9f9ea464819
expect_hash "$OWNED/facts/releases.json" \
  0a5428b1d9df12904f71dfbd5f90a2e325919f35613b3b120f3a546017d31107
expect_hash "$OWNED/facts/uniqueness.json" \
  056684a5b00972e381025f395195c1c987fbe080584b298ba1efc4b48403563b
expect_hash "$OWNED/facts/gates.json" \
  5de7461049dc89a86bc98afa3e64ad6cb8a84f006e46fab9705025fb2d87390b
expect_hash "$OWNED/diffs/candidate.message.txt" \
  8f30d6e99bdc588a27d15edf5fcdc60ee4d592bd67a71cdb600601ae7ec6d693
expect_hash "$OWNED/diffs/orig2081.message.txt" \
  2e67da1e809e972bfb2a926c21994a3dc293005820a6737133a4d4cf8199eef0
expect_hash "$OWNED/diffs/fix.message.txt" \
  078ec9e1eaccd506bf779f4021b267f8bfdd45daad36c6cc026da8d42a064eb5
expect_hash "$OWNED/diffs/candidate.worktree_fs.go.txt" \
  4dcb8cb88ef4138c51448b2c8630f7762d88dca439f9a0ddcdd21c13627fbf7d
expect_hash "$OWNED/diffs/orig2081.worktree_fs.go.txt" \
  105c12f514cbe162d982c5bfbdd3727e9d27a003f0d474c2766f9da102ee8931
expect_hash "$OWNED/diffs/v5191.worktree_fs.go.txt" \
  bd304bf7a2b0836f14964bc36c23cebd15c57cef1c6293a410d199ab124ae528
expect_hash "$OWNED/diffs/fix.worktree_fs.go.txt" \
  11d7a155bf28b8e86fc2e5833eb363ede45c13a941006199e813e4d03594cb46
expect_hash "$OWNED/diffs/tarball.v5191.worktree_fs.go.txt" \
  bd304bf7a2b0836f14964bc36c23cebd15c57cef1c6293a410d199ab124ae528
expect_hash "$OWNED/diffs/tarball.v5192.worktree_fs.go.txt" \
  11d7a155bf28b8e86fc2e5833eb363ede45c13a941006199e813e4d03594cb46
expect_hash "$OWNED/diffs/orig2081-vs-candidate.worktree_fs.diff.txt" \
  80ffe47f5f663b888c61b57e56c72c57c0b3959ab3d2f4c40938f0d7c0616835
expect_hash "$OWNED/diffs/candidate.repository.diff.txt" \
  6e09de210fda735868d350336003598df960d29ef8b7b5eda6c03e4d635f7384
expect_hash "$OWNED/diffs/fix.validWritePath.fn.go.txt" \
  e53055e0dbc81a1e966781f1130591bd77d3b72236b9cc2b57fd90da9a68a166
expect_hash "$OWNED/diffs/fix.validNoLeadingSymlink.fn.go.txt" \
  0ebd2e620f3b82abf897b671a2b7a52cd52e4b7ba57581096d1fb478091d15fd
expect_hash "$OWNED/diffs/fix.TestWorktreeFilesystemRejectsSymlinkTraversal.go.txt" \
  58734f47fbf37dc9708c57498ed893b01ff7e80021d72f8e835ed5b6eb98612e
expect_hash "$OWNED/work/tarballs/v5.19.1.tar.gz" \
  91b44587081b94cee4c379f7eaad28e660384f77c334da57cf53551e7e710596
expect_hash "$OWNED/work/tarballs/v5.19.2.tar.gz" \
  6c4524af67065f3b28708c3a3aa0931c43aa17c0cddd5762a38717e1286e8ed8
expect_hash "$OWNED/work/pages/github/git-ref-tags-v5.19.1.json" \
  f118dd9d42a1f6fb4b5c6b57c3b8fe0ce6e7e38f6abe1c32b84c1eea88deddc8
expect_hash "$OWNED/work/pages/github/git-ref-tags-v5.19.2.json" \
  44a78144a0cec3335ff02929507ec6e6ca270eeab8856f73bf6d89b8dd26c88c
expect_hash "$OWNED/work/pages/github/compare-fix-to-v5192.json" \
  ce097d5d616ab3be43d56236c09d87f06e10012cabc5b6dacccc9c9bfbbf2370
expect_hash "$OWNED/work/pages/github/compare-cand-to-v5191.json" \
  11b411d2450a4bbd4b0ebfc2467548bd76027810852c62be696e526225f9bad2
expect_hash "$OWNED/work/pages/ghsa/GHSA-hc8v-wwc9-vgxm.json" \
  752f55af64bf7f3409c09458bead3a2ccd10b0825e918cfd33c44cd038a86236

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
rels = json.loads((owned / "facts/releases.json").read_text())
prs = json.loads((owned / "facts/prs.json").read_text())
report = (owned / "report.md").read_text()
replay = (owned / "replay.zsh").read_text()

assert case["verdict"] == "KEEP"
assert case["countable"] is False
assert case["countable_proposal"] is True
assert case["causal_admission"] is False
assert case["packet_delta"] == 0
assert case["current_leader_accepted_count"] == 82
assert case["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
assert case["identity_gate"] == "PASS"
assert case["ai_hunk_gate"] == "PASS"
assert case["topology_gate"] == "PASS"
assert case["but_for_gate"] == "PASS"
assert case["fix_reversal_gate"] == "PASS"
assert case["release_gate"] == "PASS"
assert case["uniqueness_gate"] == "PASS"
assert case["remediation_patch_delta_gate"] == "PASS"
assert case["failing_gates"] == []
assert case["authorship_transfer_from_human_2081"] is False
assert case["authorship_transfer_from_member_to_carrier"] is False
assert case["candidate_set"] == ["d83871ed0314f604e417f40733f762acfdcbc35c"]
assert case["carrier_set"] == ["b1fab6cb0d33be2e084565bf04bb9222c8d1f419"]
assert case["candidate_on_release_first_parent"] is False
assert case["carrier_on_release_first_parent"] is True
assert case["candidate_any_parent"] is True
assert gates["verdict"] == "KEEP"
assert gates["all_seven_pass"] is True
assert gates["remediation_patch_delta_gate"] == "PASS"
assert res["verdicts"]["KEEP"] == 1
assert res["verdicts"]["REJECT"] == 0
assert res["packet_delta"] == 0
assert res["current_leader_accepted_count"] == 82
assert res["causal_admission"] is False
assert res["canonical_count_updated"] is False
assert ident["github_reviewed"] is True
assert ident["withdrawn"] is False
assert ident["aliases"] == ["CVE-2026-71556"]
assert gitf["human_2081_origin"] is False
assert gitf["parent_has_worktreeFilesystem"] is False
assert gitf["candidate_creates_worktree_fs"] is True
assert gitf["candidate_has_validNoLeadingSymlink"] is False
assert gitf["candidate_any_parent"] is True
assert gitf["candidate_on_release_first_parent"] is False
assert gitf["carrier_on_release_first_parent"] is True
assert gitf["carrier_set"] == ["b1fab6cb0d33be2e084565bf04bb9222c8d1f419"]
assert gitf["moving_branch_contains_fix"] is False
assert rels["do_not_trust_moving_branch"] is True
assert rels["v5_19_1"]["draft"] is False
assert rels["v5_19_1"]["prerelease"] is False
assert rels["v5_19_2"]["worktree_fs_equals_fix_blob"] is True
assert prs["pr2081"]["first_commit_ai_marker"] is True
assert prs["pr2100"]["squash"] is False
assert prs["pr2100"]["first_commit_on_release_first_parent"] is False
assert prs["pr2100"]["merge_on_release_first_parent"] is True
assert prs["pr2100"]["first_commit_any_parent_of_v5_19_1"] is True
assert uniq["in_canonical82_strict"] is False
assert uniq["packet_delta"] == 0
assert uniq["distinct_from"]["GHSA-3R9X-F23J-GC73"]["same_repository"] is False
assert uniq["distinct_from"]["GHSA-CMW6-HCPP-C6JP"]["same_mechanism"] is False
assert "KEEP" in report
assert "Packet delta 0" in report
assert "does not rebuild canonical82" in report
assert "KEEP proposal 1" in report
assert "carrier_set=[b1fab6cb]" in report
assert "candidate_on_release_first_parent=false" in report
assert "git_cmd is a zsh array" in replay
assert "Do not name a local 'path'" in replay

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
    "facts/prs.json",
    "facts/releases.json",
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
assert "GHSA-HC8V-WWC9-VGXM" not in ids82
assert "GHSA-3R9X-F23J-GC73" not in ids82
assert "GHSA-CMW6-HCPP-C6JP" not in ids82
assert uniq["canonical82_strict_count"] == 82

cand = (owned / "diffs/candidate.worktree_fs.go.txt").read_text()
orig = (owned / "diffs/orig2081.worktree_fs.go.txt").read_text()
v191 = (owned / "diffs/v5191.worktree_fs.go.txt").read_text()
fix = (owned / "diffs/fix.worktree_fs.go.txt").read_text()
tb1 = (owned / "diffs/tarball.v5191.worktree_fs.go.txt").read_text()
tb2 = (owned / "diffs/tarball.v5192.worktree_fs.go.txt").read_text()
assert v191 == tb1
assert fix == tb2
assert "type worktreeFilesystem struct" in cand
assert "validPath(filename)" in cand
assert "validNoLeadingSymlink" not in cand
assert "validWritePath" not in cand
assert "github.com/go-git/go-billy/v6" in orig
assert "github.com/go-git/go-billy/v5" in cand
assert "sfs.validPath(filename)" in v191
assert "validNoLeadingSymlink" not in v191
assert "validWritePath" not in v191
assert "func (sfs *worktreeFilesystem) validWritePath" in fix
assert "func (sfs *worktreeFilesystem) validNoLeadingSymlink" in fix
assert 'leading component %q is a symlink' in fix
assert "sfs.validWritePath(filename)" in (owned / "diffs/fix.worktree_fs.Create.go.txt").read_text()
msg = (owned / "diffs/candidate.message.txt").read_text()
assert "Assisted-by: Claude Opus 4.6 <noreply@anthropic.com>" in msg
assert "Backport of #2081" in msg
omsg = (owned / "diffs/orig2081.message.txt").read_text()
assert "Assisted-by: Claude Opus 4.6 <noreply@anthropic.com>" in omsg
fmsg = (owned / "diffs/fix.message.txt").read_text()
assert "Assisted-by: Claude Opus 4.8 <noreply@anthropic.com>" in fmsg
assert "validNoLeadingSymlink" in fmsg
test = (owned / "diffs/fix.TestWorktreeFilesystemRejectsSymlinkTraversal.go.txt").read_text()
assert "func TestWorktreeFilesystemRejectsSymlinkTraversal" in test
assert "validPath alone would allow it" in test
parent_fn = (owned / "diffs/parent.validPath.fn.go.txt").read_text()
assert "func validPath(paths ...string) error" in parent_fn
assert "worktreeFilesystem" not in parent_fn
gpage = json.loads((owned / "work/pages/ghsa/GHSA-hc8v-wwc9-vgxm.json").read_text())
assert gpage["id"].lower() == "ghsa-hc8v-wwc9-vgxm"
assert gpage["database_specific"]["github_reviewed"] is True
assert gpage.get("withdrawn") in (None, False)
g3 = json.loads((owned / "work/pages/ghsa/GHSA-3r9x-f23j-gc73.json").read_text())
g6 = json.loads((owned / "work/pages/ghsa/GHSA-cmw6-hcpp-c6jp.json").read_text())
assert g3["affected"][0]["package"]["name"] == "onnx"
assert g6["affected"][0]["package"]["name"] == "onnx"
cref = json.loads((owned / "work/pages/github/git-ref-tags-v5.19.1.json").read_text())
assert cref["object"]["sha"] == "3c3be601aa6c0fd0d536c0d1e4f898b4c60e65fe"
assert cref["object"]["type"] == "commit"
fref = json.loads((owned / "work/pages/github/git-ref-tags-v5.19.2.json").read_text())
assert fref["object"]["sha"] == "3eeb238da61eb9c7a324f3ee04f990ce89175642"
cmpf = json.loads((owned / "work/pages/github/compare-fix-to-v5192.json").read_text())
assert cmpf["status"] == "ahead"
assert cmpf["behind_by"] == 0
assert cmpf["merge_base"] == "008a78f2dd86f52544ddff8b8e8ddeecdf3f7aab"
print("conservation assigned=1 reviewed=1 unreviewed=0 KEEP_proposal=1 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=0 current_leader_accepted_count=82 packet_delta=0")
PY

[[ "$(g "$GG" log -1 --format='%P' "$CAND")" == "$PARENT" ]]
[[ "$(g "$GG" log -1 --format='%P' "$FIX")" == 4a0e66d555de5f9a30c31e2df64f445f42bd01e7 ]]
[[ "$(g "$GG" rev-parse "${ORIG}:${FILE}")" == "$BLOB_ORIG" ]]
[[ "$(g "$GG" rev-parse "${CAND}:${FILE}")" == "$BLOB_CAND" ]]
[[ "$(g "$GG" rev-parse "${V191}:${FILE}")" == "$BLOB_V191" ]]
[[ "$(g "$GG" rev-parse "${FIX}:${FILE}")" == "$BLOB_FIX" ]]
[[ "$(g "$GG" rev-parse 'v5.19.1^{commit}')" == "$V191" ]]

parent_file=$(g "$GG" ls-tree --name-only "$PARENT" -- "$FILE")
if [[ -n $parent_file ]]; then
  printf 'parent unexpectedly has worktree_fs.go\n' >&2
  exit 1
fi

candbody=$(g "$GG" log -1 --format='%B' "$CAND")
printf '%s\n' "$candbody" | grep -F 'Assisted-by: Claude Opus 4.6 <noreply@anthropic.com>' >/dev/null
printf '%s\n' "$candbody" | grep -F 'Backport of #2081' >/dev/null
origbody=$(g "$GG" log -1 --format='%B' "$ORIG")
printf '%s\n' "$origbody" | grep -F 'Assisted-by: Claude Opus 4.6 <noreply@anthropic.com>' >/dev/null
fixbody=$(g "$GG" log -1 --format='%B' "$FIX")
printf '%s\n' "$fixbody" | grep -F 'Assisted-by: Claude Opus 4.8 <noreply@anthropic.com>' >/dev/null

assert_ancestor "$GG" "$CAND" "$V191"
assert_not_ancestor "$GG" "$FIX" "$V191"
assert_ancestor "$GG" "$CAND" "$FIX"
assert_ancestor "$GG" "$ORIG" "$MERGE2081"
assert_not_ancestor "$GG" "$ORIG" "$CAND"
assert_not_ancestor "$GG" "$ORIG" "$V191"
assert_ancestor "$GG" "$CAND" "$MERGE2100"
assert_ancestor "$GG" "$MERGE2100" "$V191"
assert_ancestor "$GG" "$CAND" "$MOVING"
assert_not_ancestor "$GG" "$FIX" "$MOVING"

fp=$(g "$GG" rev-list --first-parent "$V191")
if printf '%s\n' "$fp" | grep -Fx "$CAND" >/dev/null; then
  printf 'candidate unexpectedly on first-parent of v5.19.1\n' >&2
  exit 1
fi
printf '%s\n' "$fp" | grep -Fx "$MERGE2100" >/dev/null

cand_fs=$(g "$GG" show "${CAND}:${FILE}")
printf '%s\n' "$cand_fs" | grep -F 'type worktreeFilesystem struct' >/dev/null
printf '%s\n' "$cand_fs" | grep -F 'validPath' >/dev/null
if printf '%s\n' "$cand_fs" | grep -F 'validNoLeadingSymlink' >/dev/null; then
  printf 'candidate unexpectedly had validNoLeadingSymlink\n' >&2
  exit 1
fi
v191_fs=$(g "$GG" show "${V191}:${FILE}")
printf '%s\n' "$v191_fs" | grep -F 'sfs.validPath(filename)' >/dev/null
if printf '%s\n' "$v191_fs" | grep -F 'validNoLeadingSymlink' >/dev/null; then
  printf 'v5.19.1 unexpectedly had validNoLeadingSymlink\n' >&2
  exit 1
fi
fix_fs=$(g "$GG" show "${FIX}:${FILE}")
printf '%s\n' "$fix_fs" | grep -F 'validWritePath' >/dev/null
printf '%s\n' "$fix_fs" | grep -F 'validNoLeadingSymlink' >/dev/null
printf '%s\n' "$fix_fs" | grep -F 'leading component %q is a symlink' >/dev/null
got=$(g "$GG" show "${FIX}:${FILE}" | /usr/bin/sha256sum | /usr/bin/awk '{print $1}')
[[ $got == 11d7a155bf28b8e86fc2e5833eb363ede45c13a941006199e813e4d03594cb46 ]]

parent_hits=$(g "$GG" grep -n worktreeFilesystem "$PARENT" -- '*.go' || true)
if [[ -n $parent_hits ]]; then
  printf 'parent unexpectedly has worktreeFilesystem\n' >&2
  exit 1
fi
g "$GG" grep -F 'func validPath' "$PARENT" -- worktree.go >/dev/null

repo_diff=$(g "$GG" diff "$PARENT" "$CAND" -- repository.go)
printf '%s\n' "$repo_diff" | grep -F 'Filesystem: newWorktreeFilesystem(r.wt)' >/dev/null

[[ "$(g "$GG" log -1 --format='%s' "$MERGE2081")" == "Merge pull request #2081 from pjbgf/worktree-fs" ]]
[[ "$(g "$GG" log -1 --format='%s' "$MERGE2100")" == "Merge pull request #2100 from hiddeco/v5/worktree-fs" ]]
[[ "$(g "$GG" rev-parse "$MERGE2100^1")" == "$PARENT" ]]
[[ "$(g "$GG" rev-parse origin/releases/v5.x)" == "$MOVING" ]]

printf 'REPLAY_OK reviewed=1 KEEP_proposal=1 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=82\n'
