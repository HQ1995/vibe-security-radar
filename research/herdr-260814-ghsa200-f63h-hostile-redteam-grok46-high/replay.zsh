#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-f63h-hostile-redteam-grok46-high.
# English only. Do not print credentials. Do not clone, commit, push, or fetch.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# REJECT is the verdict. Packet delta is 0. This script does not admit GHSA-F63H.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-f63h-hostile-redteam-grok46-high
AB=/home/hanqing/.cache/cve-analyzer/repos/astrbotdevs_astrbot

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

CAND=a404436f2cddf6b7e49d7e9c60dc240748d0767d
CAND_PARENT=bcb12a071732c694e37a42fcea419ef866b9d127
ORIGIN=f7a716af43f238e75c50251422666539265c4ef3
ORIGIN_PARENT=a708901e7feda4c5c274ddbdd055aa7bf02dca28
FIX=aaec41e5054569ceaa1113593a34da7568e2d211
FIX_PARENT=9f8ce247266e1ab2a2075845cd50fc0b59e94cdb
V4235=9f8ce247266e1ab2a2075845cd50fc0b59e94cdb
V4236=09ab45fcb545a692c9b27877efc84731c246bfd1
FILE=astrbot/dashboard/routes/chat.py
M_COPILOT=ea615cb3858188a265b25b8ffb101e3c10e41149
M_JOIN=590e7f3e1e6df546e860485ddab79142d31525eb
M_FILENAME=7a669119884041a3a751c7f8c8eb6442e67709c1
BLOB_PARENT_CAND=a7c0e3a573a51888cc532f67c0af1f9780444975
BLOB_CAND=495854b1b5ab46a6de64772b80a6d0f089318b56
BLOB_V4235=d4174ffb5855d572ba464331f1e99a809db5d97b
BLOB_FIX=458deb23167329b46b7361c87fa9cd76a4d687fb
BLOB_V4236=dea3cca3dfc6ef29539a8a740b0444b77cc46dcd

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
require_dir "$AB/.git"
require_file "$OWNED/adjudication.json"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/facts/gates.json"
require_file "$OWNED/facts/git.json"
require_file "$OWNED/facts/identity.json"
require_file "$OWNED/facts/uniqueness.json"
require_file "$OWNED/releases/pypi.json"
require_file "$OWNED/diffs/m.file_filename.diff.txt"
require_file "$OWNED/diffs/m.copilot_autofix.files.txt"
require_file "$OWNED/diffs/post_file.v4235.py.txt"
require_file "$OWNED/diffs/post_file.v4236.py.txt"
require_file "$OWNED/work/packages/astrbot-4.23.5-py3-none-any.whl"
require_file "$OWNED/work/packages/astrbot-4.23.6-py3-none-any.whl"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$OWNED/adjudication.json" \
  ab71f67d85f720996f87279d21318bfd78fd4c0274a237b898e59199992a894f
expect_hash "$OWNED/report.md" \
  5e312e50964c3cb2d86191bc2237a0fbdfc2d53616e1ae85100fb497bbb24842
expect_hash "$OWNED/result.json" \
  a93baf861d972687ca242eb6336befbf24a107cc39c9278b52ca5459c7f03318
expect_hash "$OWNED/facts/gates.json" \
  719016fb770676ae395e089c18763b215bbaac98ffb9d58b0de60ac0c440934a
expect_hash "$OWNED/facts/git.json" \
  6841822d3272fcdf31f21617523d5327166f97dec2319a4a284e6add6cdc7965
expect_hash "$OWNED/facts/identity.json" \
  d2e248e1956fc74fdabed923e5013c3f34a233f312d7de5e9936f5c6ef6d8794
expect_hash "$OWNED/facts/uniqueness.json" \
  ca2258c07ba618f2a9c017ee3f2fdae45636a61a00e9d9ba1c54fe7df46adde1
expect_hash "$OWNED/releases/pypi.json" \
  9ab15f18292c3570bddb700438b2ffc5fd07211660d87966fa6d57527e42b3ad
expect_hash "$OWNED/diffs/post_file.v4235.py.txt" \
  c923a1273d840dce317c34b3b5f337427016b147db6567e7ea0c4db47fe042a0
expect_hash "$OWNED/diffs/post_file.cand.py.txt" \
  c923a1273d840dce317c34b3b5f337427016b147db6567e7ea0c4db47fe042a0
expect_hash "$OWNED/diffs/post_file.pypi4235.py.txt" \
  c923a1273d840dce317c34b3b5f337427016b147db6567e7ea0c4db47fe042a0
expect_hash "$OWNED/diffs/post_file.v4236.py.txt" \
  3631fd9c61041efa561249609e567ac40f33be5c108c9831d21041c385ec9ae8
expect_hash "$OWNED/diffs/post_file.fix.py.txt" \
  3631fd9c61041efa561249609e567ac40f33be5c108c9831d21041c385ec9ae8
expect_hash "$OWNED/diffs/post_file.pypi4236.py.txt" \
  3631fd9c61041efa561249609e567ac40f33be5c108c9831d21041c385ec9ae8
expect_hash "$OWNED/diffs/m.file_filename.diff.txt" \
  f4af92183e3e5c2efd170daca81417a5b86fd42b29bcbcf045d4c1309882342d
expect_hash "$OWNED/diffs/m.copilot_autofix.files.txt" \
  68d671c4983e18c0f20bba34f9775fda4e59d512916eab0da7781c251f47377f
expect_hash "$OWNED/work/packages/astrbot-4.23.5-py3-none-any.whl" \
  f0927cfffdc7e24dd45a20ec3818a8a40d98c08d6aadd6fd62a41b4148d4ff4b
expect_hash "$OWNED/work/packages/astrbot-4.23.6-py3-none-any.whl" \
  9dc253d0306b1f011e899336b5d959c7ec17047acbee3cd80f14d4ea5f555b22
expect_hash "$OWNED/work/pages/ghsa/GHSA-f63h-wc26-pmvc.advisory-database.json" \
  5b07d3177bd30320c035374e4b68d319078f383d002655308a36a9c2de734874

[[ "$(g "$ROOT" rev-parse ca034f064fd696201c81baae7392c14f0d501d2b)" == ca034f064fd696201c81baae7392c14f0d501d2b ]]

python3 - "$OWNED" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
adj = json.loads((owned / "adjudication.json").read_text())
res = json.loads((owned / "result.json").read_text())
gates = json.loads((owned / "facts/gates.json").read_text())
uniq = json.loads((owned / "facts/uniqueness.json").read_text())
ident = json.loads((owned / "facts/identity.json").read_text())
gitf = json.loads((owned / "facts/git.json").read_text())
pypi = json.loads((owned / "releases/pypi.json").read_text())
report = (owned / "report.md").read_text()
replay = (owned / "replay.zsh").read_text()

assert adj["verdict"] == "REJECT"
assert adj["countable"] is False
assert adj["countable_proposal"] is False
assert adj["causal_admission"] is False
assert adj["packet_delta"] == 0
assert adj["current_leader_accepted_count"] == 84
assert adj["identity_gate"] == "PASS"
assert adj["ai_hunk_gate"] == "FAIL"
assert adj["topology_gate"] == "FAIL"
assert adj["but_for_gate"] == "FAIL"
assert adj["fix_reversal_gate"] == "PASS"
assert adj["release_gate"] == "PASS"
assert adj["uniqueness_gate"] == "PASS"
assert adj["failing_gates"] == ["ai_hunk_gate", "topology_gate", "but_for_gate"]
assert adj["authorship_transfer_from_member_to_carrier"] is True
assert gates["verdict"] == "REJECT"
assert gates["all_seven_pass"] is False
assert gates["remediation_patch_delta_gate"] == "NOT_APPLICABLE"
assert res["verdicts"]["KEEP"] == 0
assert res["verdicts"]["REJECT"] == 1
assert res["packet_delta"] == 0
assert res["current_leader_accepted_count"] == 84
assert res["causal_admission"] is False
assert res["canonical_count_updated"] is False
assert ident["github_reviewed"] is True
assert ident["withdrawn"] is False
assert ident["aliases"] == ["CVE-2026-8754"]
assert ident["repo_advisory_http"] == 404
assert gitf["origin_ai_marker"] is False
assert gitf["candidate_ai_marker"] is True
assert gitf["copilot_autofix_member"]["touches_chat_py"] is False
assert gitf["human_filename_member"]["ai_marker"] is False
assert gitf["human_join_rename_member"]["ai_marker"] is False
assert gitf["parent_cand_has_unsanitized_imgs_dir_join"] is True
assert gitf["members_missing_from_first_party_clone"] is True
assert gitf["authorship_transfer_from_member_to_carrier"] is True
assert pypi["v4_23_5"]["yanked"] is False
assert pypi["v4_23_6"]["yanked"] is False
assert pypi["v4_23_5"]["contains_unsanitized_join"] is True
assert pypi["v4_23_6"]["contains_sanitize"] is True
assert uniq["in_canonical84_strict"] is False
assert uniq["packet_delta"] == 0
assert uniq["canonical84_strict_count"] == 84
assert "REJECT" in report
assert "Packet delta 0" in report
assert "does not rebuild canonical84" in report
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
    "adjudication.json",
    "report.md",
    "replay.zsh",
    "result.json",
    "facts/identity.json",
    "facts/git.json",
    "facts/uniqueness.json",
    "facts/gates.json",
    "facts/falsify.json",
    "releases/pypi.json",
    "releases/github.json",
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

c84 = json.loads(Path(sys.argv[2]).read_text())
ids84 = {x.upper() for x in c84["strict_released_case_ids"]}
assert len(c84["strict_released_case_ids"]) == 84
assert c84["canonical_strict_count"] == 84
assert "GHSA-F63H-WC26-PMVC" not in ids84
assert "GHSA-425G-FJHQ-5H92" in ids84
assert "GHSA-HC8V-WWC9-VGXM" in ids84
assert uniq["canonical84_strict_count"] == 84

v35 = (owned / "diffs/post_file.v4235.py.txt").read_text()
cand = (owned / "diffs/post_file.cand.py.txt").read_text()
p35 = (owned / "diffs/post_file.pypi4235.py.txt").read_text()
assert v35 == cand == p35
assert "filename = file.filename or" in v35
assert "os.path.join(self.attachments_dir, filename)" in v35
assert "_sanitize_upload_filename" not in v35
parent = (owned / "diffs/post_file.parent_cand.py.txt").read_text()
assert "os.path.join(self.imgs_dir, filename)" in parent
assert "filename = file.filename or" in parent
fix = (owned / "diffs/post_file.fix.py.txt").read_text()
v36 = (owned / "diffs/post_file.v4236.py.txt").read_text()
p36 = (owned / "diffs/post_file.pypi4236.py.txt").read_text()
assert fix == v36 == p36
assert "def _sanitize_upload_filename" in fix
assert "is_relative_to" in fix
assert "os.path.join(self.attachments_dir, filename)" not in fix
fn = (owned / "diffs/m.file_filename.diff.txt").read_text()
assert "-        filename = f\"{uuid.uuid4()!s}\"" in fn
assert "+        filename = file.filename or f\"{uuid.uuid4()!s}\"" in fn
cop = (owned / "diffs/m.copilot_autofix.files.txt").read_text()
assert "astrbot/dashboard/server.py" in cop
assert "chat.py" not in cop.split("FILES ", 1)[1].splitlines()[0]
assert "Co-authored-by: Copilot Autofix powered by AI" in cop
omsg = (owned / "diffs/origin.message.txt").read_text()
assert "Co-authored-by" not in omsg
assert "Copilot" not in omsg
assert "Claude" not in omsg
print("conservation assigned=1 reviewed=1 unreviewed=0 KEEP_proposal=0 REJECT=1 NARROW=0 UNKNOWN=0 BLOCKED=0 current_leader_accepted_count=84 packet_delta=0")
PY

[[ "$(g "$AB" log -1 --format='%P' "$CAND")" == "$CAND_PARENT" ]]
[[ "$(g "$AB" log -1 --format='%P' "$ORIGIN")" == "$ORIGIN_PARENT" ]]
[[ "$(g "$AB" log -1 --format='%P' "$FIX")" == "$FIX_PARENT" ]]
[[ "$(g "$AB" rev-parse "${CAND_PARENT}:${FILE}")" == "$BLOB_PARENT_CAND" ]]
[[ "$(g "$AB" rev-parse "${CAND}:${FILE}")" == "$BLOB_CAND" ]]
[[ "$(g "$AB" rev-parse "${V4235}:${FILE}")" == "$BLOB_V4235" ]]
[[ "$(g "$AB" rev-parse "${FIX}:${FILE}")" == "$BLOB_FIX" ]]
[[ "$(g "$AB" rev-parse "${V4236}:${FILE}")" == "$BLOB_V4236" ]]
[[ "$(g "$AB" rev-parse 'v4.23.5^{commit}')" == "$V4235" ]]
[[ "$(g "$AB" rev-parse 'v4.23.6^{commit}')" == "$V4236" ]]
[[ "$FIX_PARENT" == "$V4235" ]]

if "${git_cmd[@]}" -C "$AB" cat-file -e "${M_COPILOT}^{commit}" 2>/dev/null; then
  printf 'copilot member unexpectedly present in first-party clone\n' >&2
  exit 1
fi
if "${git_cmd[@]}" -C "$AB" cat-file -e "${M_JOIN}^{commit}" 2>/dev/null; then
  printf 'join member unexpectedly present in first-party clone\n' >&2
  exit 1
fi
if "${git_cmd[@]}" -C "$AB" cat-file -e "${M_FILENAME}^{commit}" 2>/dev/null; then
  printf 'filename member unexpectedly present in first-party clone\n' >&2
  exit 1
fi

candbody=$(g "$AB" log -1 --format='%B' "$CAND")
printf '%s\n' "$candbody" | grep -F 'Co-authored-by: Copilot Autofix powered by AI <62310815+github-advanced-security[bot]@users.noreply.github.com>' >/dev/null
printf '%s\n' "$candbody" | grep -F 'feat: refactor attachment directory handling in ChatRoute' >/dev/null
origbody=$(g "$AB" log -1 --format='%B' "$ORIGIN")
if printf '%s\n' "$origbody" | grep -E 'Co-authored-by:|Copilot|Claude|aider' >/dev/null; then
  printf 'origin squash unexpectedly has AI marker\n' >&2
  exit 1
fi
fixbody=$(g "$AB" log -1 --format='%B' "$FIX")
printf '%s\n' "$fixbody" | grep -F 'fix: prevent path traversal in file uploads (#7751)' >/dev/null
if printf '%s\n' "$fixbody" | grep -E 'Copilot|Claude|aider' >/dev/null; then
  printf 'fix unexpectedly has AI marker\n' >&2
  exit 1
fi

parentfn=$(g "$AB" show "${CAND_PARENT}:${FILE}")
printf '%s\n' "$parentfn" | grep -F 'filename = file.filename or f"{uuid.uuid4()!s}"' >/dev/null
printf '%s\n' "$parentfn" | grep -F 'path = os.path.join(self.imgs_dir, filename)' >/dev/null
candfn=$(g "$AB" show "${CAND}:${FILE}")
printf '%s\n' "$candfn" | grep -F 'filename = file.filename or f"{uuid.uuid4()!s}"' >/dev/null
printf '%s\n' "$candfn" | grep -F 'path = os.path.join(self.attachments_dir, filename)' >/dev/null
if printf '%s\n' "$candfn" | grep -F '_sanitize_upload_filename' >/dev/null; then
  printf 'candidate unexpectedly has sanitizer\n' >&2
  exit 1
fi
v35=$(g "$AB" show "${V4235}:${FILE}")
printf '%s\n' "$v35" | grep -F 'path = os.path.join(self.attachments_dir, filename)' >/dev/null
if printf '%s\n' "$v35" | grep -F '_sanitize_upload_filename' >/dev/null; then
  printf 'v4.23.5 unexpectedly has sanitizer\n' >&2
  exit 1
fi
v36=$(g "$AB" show "${V4236}:${FILE}")
printf '%s\n' "$v36" | grep -F 'def _sanitize_upload_filename' >/dev/null
printf '%s\n' "$v36" | grep -F 'is_relative_to' >/dev/null
if printf '%s\n' "$v36" | grep -F 'path = os.path.join(self.attachments_dir, filename)' >/dev/null; then
  printf 'v4.23.6 still has unsanitized join\n' >&2
  exit 1
fi
fixfn=$(g "$AB" show "${FIX}:${FILE}")
printf '%s\n' "$fixfn" | grep -F 'def _sanitize_upload_filename' >/dev/null
printf '%s\n' "$fixfn" | grep -F 'filename = _sanitize_upload_filename(file.filename)' >/dev/null

blame_join=$(g "$AB" blame -L 349,349 "$V4235" -- "$FILE")
printf '%s\n' "$blame_join" | grep -F 'a404436f2c' >/dev/null
blame_fn=$(g "$AB" blame -L 336,336 "$V4235" -- "$FILE")
printf '%s\n' "$blame_fn" | grep -F 'f7a716af43' >/dev/null

assert_ancestor "$AB" "$CAND" "$V4235"
assert_ancestor "$AB" "$ORIGIN" "$V4235"
assert_not_ancestor "$AB" "$FIX" "$V4235"
assert_ancestor "$AB" "$FIX" "$V4236"
assert_ancestor "$AB" "$CAND" "$V4236"

g "$AB" rev-list --first-parent "$V4235" | grep -Fx "$CAND" >/dev/null

orig_parent=$(g "$AB" show "${ORIGIN_PARENT}:${FILE}")
printf '%s\n' "$orig_parent" | grep -F 'path = os.path.join(self.imgs_dir, filename)' >/dev/null
if printf '%s\n' "$orig_parent" | grep -F 'filename = file.filename or' >/dev/null; then
  printf 'origin parent unexpectedly already uses file.filename\n' >&2
  exit 1
fi
printf '%s\n' "$orig_parent" | grep -F 'filename = f"{uuid.uuid4()!s}"' >/dev/null

printf 'REPLAY_OK reviewed=1 KEEP_proposal=0 REJECT=1 NARROW=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=84\n'
