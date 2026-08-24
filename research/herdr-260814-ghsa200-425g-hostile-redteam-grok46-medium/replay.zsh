#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-425g-hostile-redteam-grok46-medium.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# KEEP is a proposal. Packet delta is 0. This script does not admit GHSA-425G.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-425g-hostile-redteam-grok46-medium
OE=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/jahlives__openssl_encrypt
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

CAND=a3d7f417be601a15865e8817086644d9451cdb73
PARENT=c9c932afbe0f6f0036f0f4913070c3be14e759d7
FIX=6e7f938dcb7928faf5fd12bb5559f6dae2944124
DUP=6ad5d5ca79a0c7db6b6ae542192fc3cfa2ae4925
EARLY=f5e9c3096a97167470c4098b48b7ad3262fa2468
MERGE=bb8915d2673d448b7b89ef484d7fef464f9c6684
FILE=openssl_encrypt/modules/json_validator.py
BLOB_CAND=19ec65fadd73ad42da0078c4d03bef99ba96c5b2
BLOB_FIX=691e13f72bed0c51e55e863d2c3588426f848db1

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

gitx() {
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
  gitx "$1" merge-base --is-ancestor "$2" "$3"
}

assert_not_ancestor() {
  if gitx "$1" merge-base --is-ancestor "$2" "$3"; then
    printf 'unexpected ancestor: %s is ancestor of %s\n' "$2" "$3" >&2
    exit 1
  fi
}

require_dir "$OWNED"
require_dir "$OE/.git"
require_dir "$ADV/.git"
require_file "$OWNED/case.json"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/facts/gates.json"
require_file "$OWNED/facts/git.json"
require_file "$OWNED/facts/identity.json"
require_file "$OWNED/facts/pypi.json"
require_file "$OWNED/facts/uniqueness.json"
require_file "$OWNED/diffs/failopen.cand.py.txt"
require_file "$OWNED/diffs/failopen.pypi135.py.txt"
require_file "$OWNED/diffs/cand.message.txt"
require_file "$OWNED/work/releases/pypi/openssl_encrypt-1.3.5-py3-none-any.whl"
require_file "$OWNED/work/releases/pypi/openssl_encrypt-1.4.0-py3-none-any.whl"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/ledger.jsonl" \
  58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" \
  d436f47f82297eb0d9363ad0f3876adc639b1f61e9b23c7f9d613545741e106e
expect_hash "$OWNED/case.json" \
  d86e3dfd98274a6768d234386e9775c7d64144602952cec73dbe45d303787c93
expect_hash "$OWNED/report.md" \
  e43c59604d5aca07fe9bc7bbc1e47ade9a76eb1707e08da4a2a11742507cc23f
expect_hash "$OWNED/facts/identity.json" \
  a2d90a377e8f79783801dee8f9026d99f6119514c299afba85cf55ecb574c2fe
expect_hash "$OWNED/facts/git.json" \
  01fdc5e7024ae3f326fa710f5c526c6f5a7c567de4fce49439d35c23457c3424
expect_hash "$OWNED/facts/pypi.json" \
  156d05db336dfaf25a0d7f8f949df2d02ca32d4d51c72fce7842bb354993522d
expect_hash "$OWNED/facts/gates.json" \
  a621fb1c48be984adc63cf05e279eff9dacc049f38523da75b58a51b4386b271
expect_hash "$OWNED/facts/uniqueness.json" \
  66b4a4aa20ceea6ac67a17eceea1dd0e878e936b998cb0a66af582a4001f6edc
expect_hash "$OWNED/diffs/failopen.cand.py.txt" \
  6ba97efe0f4980516e7fb473ac67c51e35c63db02150551a17c784e601fe31ed
expect_hash "$OWNED/diffs/failopen.pypi135.py.txt" \
  6ba97efe0f4980516e7fb473ac67c51e35c63db02150551a17c784e601fe31ed
expect_hash "$OWNED/diffs/failopen.pypi140.py.txt" \
  5dbb283c0925d1df2a475e2532cf1d9b9fa8ae1224f26ca3c60d161762a897a7
expect_hash "$OWNED/diffs/failopen.fix.py.txt" \
  5dbb283c0925d1df2a475e2532cf1d9b9fa8ae1224f26ca3c60d161762a897a7
expect_hash "$OWNED/diffs/json_validator.pypi1.3.5.wheel.py.txt" \
  9feefe8538a4a281649db01134f8870785a33dd5c4728b3155b0216e20d8cc19
expect_hash "$OWNED/diffs/json_validator.pypi1.4.0.wheel.py.txt" \
  7da15d0cadd24250f5f01988b582723977dccee27e52be1f82b5cd8cd750f48f
expect_hash "$OWNED/work/releases/pypi/openssl_encrypt-1.3.5-py3-none-any.whl" \
  c8d7a129da8459cfaf4f09722cb1cd1fd3a6c9393aed847cf0571f937ff740d3
expect_hash "$OWNED/work/releases/pypi/openssl_encrypt-1.3.5.tar.gz" \
  3a8d8c2943ef4abd39ecb364a037f3aaa99921e59a4fd4b9450c42d536244fb6
expect_hash "$OWNED/work/releases/pypi/openssl_encrypt-1.4.0-py3-none-any.whl" \
  6f819ae67dc22ce06f204ff40b14daf19047263fbf3d9614214de6ee5cf6ab60
expect_hash "$OWNED/work/releases/pypi/openssl_encrypt-1.4.0.tar.gz" \
  77a024c126ec6757703bd5e74da8c3af34683537b6e3f31585d9c3cf4497ca4f
expect_hash "$OWNED/work/pages/ghsa/GHSA-425g-fjhq-5h92.advisory-database.json" \
  a2e4eaab027dfc2988731b2416413202475a04d0797cf934d8b79cc102ba6750

[[ "$(gitx "$ROOT" rev-parse 6800d2127c19532160cc88880115ae28cc446aa5)" == 6800d2127c19532160cc88880115ae28cc446aa5 ]]
[[ "$(gitx "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]

python3 - "$OWNED" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" << 'PY'
import json, re, sys, zipfile, tarfile, hashlib
from pathlib import Path

owned = Path(sys.argv[1])
case = json.loads((owned / "case.json").read_text())
res = json.loads((owned / "result.json").read_text())
gates = json.loads((owned / "facts/gates.json").read_text())
uniq = json.loads((owned / "facts/uniqueness.json").read_text())
ident = json.loads((owned / "facts/identity.json").read_text())
gitf = json.loads((owned / "facts/git.json").read_text())
pypi = json.loads((owned / "facts/pypi.json").read_text())
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
assert case["authorship_transfer_from_member_to_carrier"] is False
assert case["candidate_set"] == ["a3d7f417be601a15865e8817086644d9451cdb73"]
assert case["carrier_set"] == ["bb8915d2673d448b7b89ef484d7fef464f9c6684"]
assert case["lineage_evidence_not_counted"] == ["6ad5d5ca79a0c7db6b6ae542192fc3cfa2ae4925"]
assert "6ad5d5ca79a0c7db6b6ae542192fc3cfa2ae4925" not in case["candidate_set"]
assert "bb8915d2673d448b7b89ef484d7fef464f9c6684" not in case["candidate_set"]
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
assert ident["aliases"] == []
assert ident["package"] == "openssl-encrypt"
assert gitf["candidate_parent_count"] == 1
assert gitf["candidate_is_merge"] is False
assert gitf["parent_has_json_validator"] is False
assert gitf["human_unmarked_member_found"] is False
assert gitf["associated_github_pulls_a3d7"] == []
assert gitf["candidate_ancestor_of_fix_any_parent"] is True
assert gitf["candidate_on_first_parent_of_fix"] is False
assert gitf["merge_bb8915_on_first_parent_of_fix"] is True
assert gitf["carrier"] == "bb8915d2673d448b7b89ef484d7fef464f9c6684"
assert gitf["duplicate_atomic_ai"]["separately_counted"] is False
assert gitf["duplicate_atomic_ai"]["role"] == "lineage_evidence_not_counted_candidate"
assert gitf["lineage_evidence_not_counted"] == ["6ad5d5ca79a0c7db6b6ae542192fc3cfa2ae4925"]
assert res["keep_cases"][0]["carrier"] == "bb8915d2673d448b7b89ef484d7fef464f9c6684"
assert "lineage evidence" in report
assert "not a separately counted candidate" in report
assert "carrier_set" in report
assert pypi["jsonschema_in_1_3_5_requires_dist"] is False
assert pypi["jsonschema_in_1_4_0_requires_dist"] is True
assert pypi["missing_jsonschema_branch_reachable_in_1_3_5"] is True
assert pypi["vulnerable"]["yanked"] is False
assert pypi["fixed"]["yanked"] is False
assert pypi["fixed"]["wheel_equals_git_fix_blob"] is True
assert uniq["in_canonical82_strict"] is False
assert uniq["packet_delta"] == 0
assert uniq["canonical82_strict_count"] == 82
assert uniq["duplicate_atomic_6ad5d5ca_separately_counted"] is False
assert "KEEP proposal" in report
assert "Packet delta 0" in report
assert "does not rebuild canonical82" in report

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
    "facts/pypi.json",
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
assert "GHSA-425G-FJHQ-5H92" not in ids82

fo135 = (owned / "diffs/failopen.pypi135.py.txt").read_text()
fo140 = (owned / "diffs/failopen.pypi140.py.txt").read_text()
focand = (owned / "diffs/failopen.cand.py.txt").read_text()
fofix = (owned / "diffs/failopen.fix.py.txt").read_text()
assert focand == fo135
assert fofix == fo140
assert "if not JSONSCHEMA_AVAILABLE:" in fo135
assert "            return" in fo135
assert "Cannot validate against schema" in fo135
assert "raise JSONValidationError" not in fo135
assert "raise JSONValidationError" in fo140
assert "            return" not in fo140
assert "Schema validation unavailable" in fo140
msg = (owned / "diffs/cand.message.txt").read_text()
assert "Co-Authored-By: Claude <noreply@anthropic.com>" in msg
assert "secure JSON validator" in msg
fixmsg = (owned / "diffs/fix.message.txt").read_text()
assert "GHSA-425g-fjhq-5h92" in fixmsg
assert "Raise error when jsonschema unavailable" in fixmsg

rel = owned / "work/releases/pypi"
z = zipfile.ZipFile(rel / "openssl_encrypt-1.3.5-py3-none-any.whl")
raw135 = z.read("openssl_encrypt/modules/json_validator.py")
meta135 = z.read("openssl_encrypt-1.3.5.dist-info/METADATA").decode("utf-8", "replace")
assert b"if not JSONSCHEMA_AVAILABLE:" in raw135
assert b"Cannot validate against schema" in raw135
assert b"            return" in raw135
assert b"Schema validation unavailable" not in raw135
assert "Requires-Dist: jsonschema" not in meta135
z2 = zipfile.ZipFile(rel / "openssl_encrypt-1.4.0-py3-none-any.whl")
raw140 = z2.read("openssl_encrypt/modules/json_validator.py")
meta140 = z2.read("openssl_encrypt-1.4.0.dist-info/METADATA").decode("utf-8", "replace")
assert b"Schema validation unavailable: jsonschema library not installed" in raw140
assert b"raise JSONValidationError" in raw140
assert b"Cannot validate against schema" in raw140
assert "Requires-Dist: jsonschema==4.25.1" in meta140
assert hashlib.sha256(raw135).hexdigest() == "9feefe8538a4a281649db01134f8870785a33dd5c4728b3155b0216e20d8cc19"
assert hashlib.sha256(raw140).hexdigest() == "7da15d0cadd24250f5f01988b582723977dccee27e52be1f82b5cd8cd750f48f"
t = tarfile.open(rel / "openssl_encrypt-1.3.5.tar.gz", "r:gz")
s135 = t.extractfile("openssl_encrypt-1.3.5/openssl_encrypt/modules/json_validator.py").read()
assert s135 == raw135
t2 = tarfile.open(rel / "openssl_encrypt-1.4.0.tar.gz", "r:gz")
s140 = t2.extractfile("openssl_encrypt-1.4.0/openssl_encrypt/modules/json_validator.py").read()
assert s140 == raw140

print("conservation assigned=1 reviewed=1 unreviewed=0 KEEP_proposal=1 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=0 current_leader_accepted_count=82 packet_delta=0")
PY

[[ "$(gitx "$OE" log -1 --format='%P' "$CAND")" == "$PARENT" ]]
[[ "$(gitx "$OE" rev-parse "${CAND}:${FILE}")" == "$BLOB_CAND" ]]
[[ "$(gitx "$OE" rev-parse "${DUP}:${FILE}")" == "$BLOB_CAND" ]]
[[ "$(gitx "$OE" rev-parse "${EARLY}:${FILE}")" == "$BLOB_CAND" ]]
[[ "$(gitx "$OE" rev-parse "${FIX}:${FILE}")" == "$BLOB_FIX" ]]
parent_file=$(gitx "$OE" ls-tree --name-only "$PARENT" -- "$FILE")
if [[ -n $parent_file ]]; then
  printf 'parent unexpectedly has json_validator.py\n' >&2
  exit 1
fi

candbody=$(gitx "$OE" log -1 --format='%B' "$CAND")
printf '%s\n' "$candbody" | grep -F 'Co-Authored-By: Claude <noreply@anthropic.com>' >/dev/null
printf '%s\n' "$candbody" | grep -F 'secure JSON validator module' >/dev/null
dupbody=$(gitx "$OE" log -1 --format='%B' "$DUP")
printf '%s\n' "$dupbody" | grep -F 'Co-Authored-By: Claude <noreply@anthropic.com>' >/dev/null
fixbody=$(gitx "$OE" log -1 --format='%B' "$FIX")
printf '%s\n' "$fixbody" | grep -F 'GHSA-425g-fjhq-5h92' >/dev/null

candfile=$(gitx "$OE" show "${CAND}:${FILE}")
printf '%s\n' "$candfile" | grep -F 'if not JSONSCHEMA_AVAILABLE:' >/dev/null
printf '%s\n' "$candfile" | grep -F 'jsonschema library not available' >/dev/null
fixfile=$(gitx "$OE" show "${FIX}:${FILE}")
printf '%s\n' "$fixfile" | grep -F 'Schema validation unavailable: jsonschema library not installed' >/dev/null
printf '%s\n' "$fixfile" | grep -F 'raise JSONValidationError' >/dev/null

assert_ancestor "$OE" "$PARENT" "$CAND"
assert_ancestor "$OE" "$CAND" "$FIX"
assert_ancestor "$OE" "$DUP" "$FIX"
assert_ancestor "$OE" "$MERGE" "$FIX"
assert_not_ancestor "$OE" "$CAND" "$MERGE"

if gitx "$OE" rev-list --first-parent "$FIX" | grep -F -x "$CAND" >/dev/null; then
  printf 'candidate unexpectedly on first-parent of fix\n' >&2
  exit 1
fi
gitx "$OE" rev-list --first-parent "$FIX" | grep -F -x "$MERGE" >/dev/null

fixfiles=$(gitx "$OE" diff-tree --no-commit-id --name-only -r "$FIX")
printf '%s\n' "$fixfiles" | grep -Fx "$FILE" >/dev/null

wheel140_blob=$(gitx "$OE" hash-object "$OWNED/diffs/json_validator.pypi1.4.0.wheel.py.txt")
[[ $wheel140_blob == "$BLOB_FIX" ]]

printf 'REPLAY_OK reviewed=1 KEEP_proposal=1 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=82\n'
