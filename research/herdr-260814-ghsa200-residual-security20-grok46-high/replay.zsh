#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-residual-security20-grok46-high.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Current leader-accepted count is 82. Packet delta is 0.
# PASS is a proposal only. This script does not admit GHSA-HC8V or GHSA-425G.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export TMPDIR=/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-residual-security20-grok46-high/work

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-residual-security20-grok46-high
N8N=/home/hanqing/.cache/ghsa200-worker-clones/baseline-increm-odd/clones/n8n-mcp
OC=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw
SIP=/home/hanqing/.cache/ghsa200-worker-clones/redbase/clones/sipsorcery
ONNX=/home/hanqing/.cache/cve-analyzer/repos/onnx_onnx
LIT=/home/hanqing/.cache/cve-analyzer/repos/berriai_litellm
STU=/home/hanqing/.cache/cve-analyzer/repos/withstudiocms_studiocms
GG=/home/hanqing/.cache/cve-analyzer/repos/go-git_go-git
OE=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/jahlives__openssl_encrypt
EL=/home/hanqing/.cache/cve-analyzer/repos/electron_electron
ENC=/home/hanqing/.cache/cve-analyzer/repos/agentfront_enclave
APM=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/microsoft__apm
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
require_dir "$N8N/.git"
require_dir "$OC/.git"
require_dir "$SIP/.git"
require_dir "$ONNX/.git"
require_dir "$LIT/.git"
require_dir "$STU/.git"
require_dir "$GG/.git"
require_dir "$OE/.git"
require_dir "$EL/.git"
require_dir "$ENC/.git"
require_dir "$APM/.git"
require_dir "$ADV/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/work/uniqueness.json"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/ledger.jsonl" \
  58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" \
  d436f47f82297eb0d9363ad0f3876adc639b1f61e9b23c7f9d613545741e106e
expect_hash "$OWNED/selected.jsonl" \
  f179f86d9097f71a0d632b2ea572dba0d1f6b1bb16743a332f331f66af6aba3f
expect_hash "$OWNED/cases.jsonl" \
  39ea2048d8ee655c6136d5c1a51518a82a4ae8b648ba00334c9458a41482af51
expect_hash "$OWNED/report.md" \
  830d24f3edd900b332adf77ca8465a2f4d25b098c8be04975a66db084491bf85
expect_hash "$OWNED/work/uniqueness.json" \
  75d1c21b4cbfaa5d84077639b349a91a91d5cc1e42e49f5c84f29009ecb198cb
expect_hash "$OWNED/work/pages/ghsa/GHSA-hc8v-wwc9-vgxm.json" \
  752f55af64bf7f3409c09458bead3a2ccd10b0825e918cfd33c44cd038a86236
expect_hash "$OWNED/work/pages/ghsa/GHSA-425g-fjhq-5h92.json" \
  a2e4eaab027dfc2988731b2416413202475a04d0797cf934d8b79cc102ba6750
expect_hash "$OWNED/work/releases/go-git/inspect.json" \
  bdff0e6cc1ecae88a00fb9fbace78f48085faa7954b12eae8c89ed9bd1fd7648
expect_hash "$OWNED/work/releases/pypi/inspect.json" \
  d57a5aa80d80673527c1519289796594c0e7f8d884c62d0ef14d1d6d99912c30
expect_hash "$OWNED/work/pages/github/go-git-releases-compact.json" \
  b2246ed35cb9504388c3578451bc99a118e135acbaf82deee85464b8a1a0c624
expect_hash "$OWNED/work/releases/go-git/v5.19.1.tar.gz" \
  91b44587081b94cee4c379f7eaad28e660384f77c334da57cf53551e7e710596
expect_hash "$OWNED/work/releases/go-git/v5.19.2.tar.gz" \
  6c4524af67065f3b28708c3a3aa0931c43aa17c0cddd5762a38717e1286e8ed8
expect_hash "$OWNED/work/releases/pypi/openssl_encrypt-1.3.5-py3-none-any.whl" \
  c8d7a129da8459cfaf4f09722cb1cd1fd3a6c9393aed847cf0571f937ff740d3
expect_hash "$OWNED/work/releases/pypi/openssl_encrypt-1.4.0-py3-none-any.whl" \
  6f819ae67dc22ce06f204ff40b14daf19047263fbf3d9614214de6ee5cf6ab60

[[ "$(g "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]
[[ "$(g "$ROOT" rev-parse 6800d2127c19532160cc88880115ae28cc446aa5)" == 6800d2127c19532160cc88880115ae28cc446aa5 ]]

python3 - "$OWNED" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" << 'PY'
import json, re, sys, tarfile, zipfile, hashlib
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned / "result.json").read_text())
uniq = json.loads((owned / "work/uniqueness.json").read_text())
report = (owned / "report.md").read_text()
replay = (owned / "replay.zsh").read_text()
assert len(rows) == 20, len(rows)
assert len(sel) == 20, len(sel)
want = [r["ghsa_id"] for r in sel]
assert [r["case_id"] for r in rows] == want
assert res["counts"]["PASS"] == 2
assert res["counts"]["REJECT"] == 18
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 0
assert res["current_leader_accepted_count"] == 82
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["pass_proposals"] == ["GHSA-HC8V-WWC9-VGXM", "GHSA-425G-FJHQ-5H92"]
assert res["did_not_pad"] is True
assert res["did_not_backfill"] is True
assert res["did_not_inspect_fixblame_outcomes"] is True
assert "Start count is not rebuilt" in report
assert "Current leader-accepted count 82" in report
assert "Packet delta 0" in report
assert uniq["canonical82_strict_count"] == 82
assert uniq["packet_delta"] == 0
assert uniq["assigned_in_canonical82_strict"] == []
assert uniq["selected_sha256"] == "f179f86d9097f71a0d632b2ea572dba0d1f6b1bb16743a332f331f66af6aba3f"
by = {r["case_id"]: r for r in rows}
for cid in ("GHSA-HC8V-WWC9-VGXM", "GHSA-425G-FJHQ-5H92"):
    rec = by[cid]
    assert rec["worker_verdict"] == "PASS", cid
    assert rec["countable_proposal"] is True, cid
    assert rec["causal_admission"] is False, cid
    assert rec["contribution_class"] == "AI_INCOMPLETE_REMEDIATION", cid
    for gname in (
        "identity_gate",
        "ai_hunk_gate",
        "topology_gate",
        "but_for_gate",
        "fix_reversal_gate",
        "release_gate",
        "uniqueness_gate",
        "remediation_patch_delta_gate",
    ):
        assert rec[gname] == "PASS", (cid, gname, rec[gname])
for cid, rec in by.items():
    if cid not in ("GHSA-HC8V-WWC9-VGXM", "GHSA-425G-FJHQ-5H92"):
        assert rec["worker_verdict"] == "REJECT", cid
        assert rec["countable_proposal"] is False, cid
        assert rec["remediation_patch_delta_gate"] == "FAIL", cid
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
    "selected.jsonl",
    "report.md",
    "replay.zsh",
    "result.json",
    "work/uniqueness.json",
):
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
gpage = json.loads((owned / "work/pages/ghsa/GHSA-hc8v-wwc9-vgxm.json").read_text())
assert gpage["id"].upper() == "GHSA-HC8V-WWC9-VGXM"
assert gpage.get("withdrawn") in (None, "")
assert (gpage.get("database_specific") or {}).get("github_reviewed") is True
g425 = json.loads((owned / "work/pages/ghsa/GHSA-425g-fjhq-5h92.json").read_text())
assert g425["id"].upper() == "GHSA-425G-FJHQ-5H92"
assert g425.get("withdrawn") in (None, "")
rels = json.loads((owned / "work/pages/github/go-git-releases-compact.json").read_text())
bytag = {r["tag_name"]: r for r in rels}
assert bytag["v5.19.1"]["draft"] is False and bytag["v5.19.1"]["prerelease"] is False
assert bytag["v5.19.2"]["draft"] is False and bytag["v5.19.2"]["prerelease"] is False
insp = json.loads((owned / "work/releases/go-git/inspect.json").read_text())
inspb = {x["tag"]: x for x in insp}
assert inspb["v5.19.1"]["has_validPath_only_wrapper"] is True
assert inspb["v5.19.1"]["has_validNoLeadingSymlink"] is False
assert inspb["v5.19.2"]["has_validWritePath"] is True
assert inspb["v5.19.2"]["has_validNoLeadingSymlink"] is True
with tarfile.open(owned / "work/releases/go-git/v5.19.2.tar.gz", "r:gz") as t:
    name = next(n for n in t.getnames() if n.endswith("worktree_fs.go"))
    blob = t.extractfile(name).read()
assert hashlib.sha256(blob).hexdigest() == "11d7a155bf28b8e86fc2e5833eb363ede45c13a941006199e813e4d03594cb46"
pypi = json.loads((owned / "work/releases/pypi/inspect.json").read_text())
pby = {x["version"]: x for x in pypi}
assert pby["1.3.5"]["yanked"] is False
assert pby["1.4.0"]["yanked"] is False
w135 = zipfile.ZipFile(owned / "work/releases/pypi/openssl_encrypt-1.3.5-py3-none-any.whl").read(
    "openssl_encrypt/modules/json_validator.py"
).decode()
assert "print(" in w135
assert "Cannot validate against schema" in w135
assert "return" in w135
w140 = zipfile.ZipFile(owned / "work/releases/pypi/openssl_encrypt-1.4.0-py3-none-any.whl").read(
    "openssl_encrypt/modules/json_validator.py"
).decode()
assert "Schema validation unavailable: jsonschema library not installed." in w140
print("conservation assigned=20 reviewed=20 unreviewed=0 PASS_proposal=2 REJECT=18 NARROW=0 UNKNOWN=0 BLOCKED=0 current_leader_accepted_count=82 packet_delta=0")
PY

# F3RG: hostname-only sanitizer is pre-AI
blame=$(g "$N8N" blame -L 342,342 6cf6fef653fcd6d598f2f356aac4754931c7329f^ -- src/telemetry/workflow-sanitizer.ts)
printf '%s\n' "$blame" | grep -F '5960d282' >/dev/null
printf '%s\n' "$blame" | grep -F "urlParts[2] = '[domain]'" >/dev/null

# CWJ3: path denylist predates the AI attempt
g "$OC" grep -F PROTECTED_GATEWAY_CONFIG_PATHS 29f206243b2d636e10ebf794a27d937d63f04b49^ -- src/agents/tools/gateway-tool.ts >/dev/null
body=$(g "$OC" show 29f206243b2d636e10ebf794a27d937d63f04b49 -- src/agents/tools/gateway-tool.ts)
printf '%s\n' "$body" | grep -F 'collectEnabledInsecureOrDangerousFlags' >/dev/null

# 28GM squash subject
[[ "$(g "$SIP" log -1 --format='%s' aebe49c58ff01857fa800e1ae323b0503eda4fb7)" == "Consolidating all projects into a single repo (#1524)" ]]

# onnx: no tags contain attempt or fix
[[ -z "$(g "$ONNX" tag --contains 2e46bc2badc0b319f3254ae5b298fa1c3538b705)" ]]
[[ -z "$(g "$ONNX" tag --contains 4755f8053928dce18a61db8fec71b69c74f786cb)" ]]

# 9PF5 human author
[[ "$(g "$EL" log -1 --format='%an' 842290c50fc1db230abb1194079a1ddb1d1972ac)" == "trop[bot]" ]]

# HC8V topology and shipped wrapper
CAND=d83871ed0314f604e417f40733f762acfdcbc35c
CAND_PARENT=c6d8721af933337e0ef616eba1920b195da27f67
FIX=008a78f2dd86f52544ddff8b8e8ddeecdf3f7aab
V191=3c3be601aa6c0fd0d536c0d1e4f898b4c60e65fe
body=$(g "$GG" log -1 --format='%B' "$CAND")
printf '%s\n' "$body" | grep -F 'Assisted-by: Claude Opus 4.6 <noreply@anthropic.com>' >/dev/null
pc=$(g "$GG" log -1 --format='%P' "$CAND")
[[ $pc == "$CAND_PARENT" ]]
[[ "$(g "$GG" rev-parse 'v5.19.1^{commit}')" == "$V191" ]]
assert_ancestor "$GG" "$CAND" "$V191"
assert_not_ancestor "$GG" "$FIX" "$V191"
assert_ancestor "$GG" "$CAND" "$FIX"
ai_fs=$(g "$GG" show "${CAND}:worktree_fs.go")
printf '%s\n' "$ai_fs" | grep -F 'type worktreeFilesystem struct' >/dev/null
printf '%s\n' "$ai_fs" | grep -F 'validPath' >/dev/null
if printf '%s\n' "$ai_fs" | grep -F 'validNoLeadingSymlink' >/dev/null; then
  printf 'AI attempt already had validNoLeadingSymlink\n' >&2
  exit 1
fi
v191_fs=$(g "$GG" show "${V191}:worktree_fs.go")
printf '%s\n' "$v191_fs" | grep -F 'sfs.validPath(filename)' >/dev/null
if printf '%s\n' "$v191_fs" | grep -F 'validNoLeadingSymlink' >/dev/null; then
  printf 'v5.19.1 already had validNoLeadingSymlink\n' >&2
  exit 1
fi
fix_fs=$(g "$GG" show "${FIX}:worktree_fs.go")
printf '%s\n' "$fix_fs" | grep -F 'validWritePath' >/dev/null
printf '%s\n' "$fix_fs" | grep -F 'validNoLeadingSymlink' >/dev/null
got=$(g "$GG" show "${FIX}:worktree_fs.go" | /usr/bin/sha256sum | /usr/bin/awk '{print $1}')
[[ $got == 11d7a155bf28b8e86fc2e5833eb363ede45c13a941006199e813e4d03594cb46 ]]

# 425G topology and skip/raise
ATT=a3d7f417be601a15865e8817086644d9451cdb73
ATT_PARENT=c9c932afbe0f6f0036f0f4913070c3be14e759d7
FIX425=6e7f938dcb7928faf5fd12bb5559f6dae2944124
body=$(g "$OE" log -1 --format='%B' "$ATT")
printf '%s\n' "$body" | grep -F 'Co-Authored-By: Claude <noreply@anthropic.com>' >/dev/null
pc=$(g "$OE" log -1 --format='%P' "$ATT")
[[ $pc == "$ATT_PARENT" ]]
assert_ancestor "$OE" "$ATT" "$FIX425"
att_py=$(g "$OE" show "${ATT}:openssl_encrypt/modules/json_validator.py")
printf '%s\n' "$att_py" | grep -F 'jsonschema library not available' >/dev/null
printf '%s\n' "$att_py" | grep -F '            return' >/dev/null
fix_py=$(g "$OE" show "${FIX425}:openssl_encrypt/modules/json_validator.py")
printf '%s\n' "$fix_py" | grep -F 'Schema validation unavailable: jsonschema library not installed.' >/dev/null
[[ "$(g "$OE" show "${FIX425}:openssl_encrypt/modules/json_validator.py" | /usr/bin/wc -c)" -gt 1000 ]]

printf 'REPLAY_OK reviewed=20 PASS_proposal=2 REJECT=18 NARROW=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=82\n'
