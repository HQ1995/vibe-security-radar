#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-fp211-confirm11-closure-grok46-medium.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# PASS is a proposal only. This script does not admit any row into canonical81.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fp211-confirm11-closure-grok46-medium
F=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/fission
GP=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/gitpython
P=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/praisonai
H=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/hermes-webui
K=/home/hanqing/.cache/ghsa200-worker-clones/delta-even-batch2/microsoft__kiota
W=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/wacrm
PR=/home/hanqing/.cache/ghsa200-worker-clones/baseline-increm-even/clones/prospero-flow-crm
V=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/vitest-dev__vitest
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

assert_ancestor() {
  "${git_cmd[@]}" -C "$1" merge-base --is-ancestor "$2" "$3"
}

assert_not_ancestor() {
  if "${git_cmd[@]}" -C "$1" merge-base --is-ancestor "$2" "$3"; then
    printf 'unexpected ancestor: %s is ancestor of %s in %s\n' "$2" "$3" "$1" >&2
    exit 1
  fi
}

require_dir "$OWNED"
require_dir "$F/.git"
require_dir "$GP/.git"
require_dir "$P/.git"
require_dir "$H/.git"
require_dir "$K/.git"
require_dir "$W/.git"
require_dir "$PR/.git"
require_dir "$V/.git"
require_dir "$ADV/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected-11.jsonl"
require_file "$OWNED/report.md"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/ledger.jsonl" \
  3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9
expect_hash "$OWNED/selected-11.jsonl" \
  34afa134a216056c304269bcacad64e5b13f2a4546474e22e305fff4d37638d5
expect_hash "$OWNED/cases.jsonl" \
  065104a9a80b216ef0cca62062c1d0d0eba16ac4b005456da4270f0da9c29879
expect_hash "$OWNED/report.md" \
  e43f7924eb293a5807526c4e5fcd3ba611433663f7f2c8636c151091ecd4cf82
expect_hash "$OWNED/work/uniqueness.json" \
  b6f70a05606be09221f3706ad9ef4816e747dac69a5f291bf408e5dda3d7d41a

[[ "$("${git_cmd[@]}" -C "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]

python3 - "$OWNED" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected-11.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 11, len(rows)
assert len(sel) == 11, len(sel)
want = [
    "GHSA-4FXP-2M36-QV64",
    "GHSA-4MR5-G6F9-CFRH",
    "GHSA-94P4-4CQ8-9G67",
    "GHSA-G8MR-85JM-7XHM",
    "GHSA-M63V-2G9W-2W6V",
    "GHSA-P52P-4VMG-4VQ3",
    "GHSA-P538-C434-8V24",
    "GHSA-P5RM-JG5C-8C77",
    "GHSA-QF5V-M7P4-95RP",
    "GHSA-X2W7-XR2G-QHJR",
    "GHSA-X8QQ-M4QC-RPJ5",
]
assert [r["case_id"] for r in rows] == want
assert [r["case_id"] for r in sel] == want
assert all(r["fp211_verdict"] == "CONFIRM" for r in sel)
assert all(r["record_kind"] == "PRESERVED_HYPOTHESIS" for r in sel)
assert all(r["not_in_canonical81_strict"] is True for r in sel)
by = {r["case_id"]: r for r in rows}
assert by["GHSA-QF5V-M7P4-95RP"]["worker_verdict"] == "PASS"
assert by["GHSA-QF5V-M7P4-95RP"]["countable_proposal"] is True
assert by["GHSA-QF5V-M7P4-95RP"]["causal_admission"] is False
assert all(by[i]["worker_verdict"] == "NARROW" for i in want if i != "GHSA-QF5V-M7P4-95RP")
assert all(r["publication_status"] == "HOLD" for r in rows)
assert all(r["worker_pass_is_proposal_only"] is True for r in rows)
assert by["GHSA-4FXP-2M36-QV64"]["identity_gate"] == "NARROW"
assert by["GHSA-4MR5-G6F9-CFRH"]["but_for_gate"] == "NARROW"
assert by["GHSA-94P4-4CQ8-9G67"]["but_for_gate"] == "NARROW"
assert by["GHSA-G8MR-85JM-7XHM"]["release_gate"] == "NARROW"
assert by["GHSA-M63V-2G9W-2W6V"]["release_gate"] == "NARROW"
assert by["GHSA-P52P-4VMG-4VQ3"]["identity_gate"] == "NARROW"
assert by["GHSA-P538-C434-8V24"]["but_for_gate"] == "NARROW"
assert by["GHSA-P5RM-JG5C-8C77"]["release_gate"] == "NARROW"
assert all(by["GHSA-QF5V-M7P4-95RP"]["gates"][g] == "PASS" for g in [
    "identity_gate","ai_hunk_gate","topology_gate","but_for_gate",
    "fix_reversal_gate","release_gate","uniqueness_gate"])
assert by["GHSA-QF5V-M7P4-95RP"]["remediation_patch_delta_gate"] == "PASS"
assert by["GHSA-X2W7-XR2G-QHJR"]["identity_gate"] == "NARROW"
assert by["GHSA-X8QQ-M4QC-RPJ5"]["identity_gate"] == "NARROW"
assert by["GHSA-4FXP-2M36-QV64"]["repository"] == "Roskus/prospero-flow-crm"
assert by["GHSA-X8QQ-M4QC-RPJ5"]["repository"] == "Roskus/prospero-flow-crm"
assert by["GHSA-QF5V-M7P4-95RP"]["repository"] == "fission/fission"
assert by["GHSA-M63V-2G9W-2W6V"]["repository"] == "fission/fission"
keys = {r["mechanism_key"] for r in rows}
assert len(keys) == 11
han = re.compile(r"[\u3400-\u9fff]")
for name in ("cases.jsonl", "selected-11.jsonl", "report.md", "replay.sh", "result.json"):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert text.isascii(), name
    assert not han.search(text), name
    assert text.endswith("\n"), name
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (name, line)
c81 = json.loads(Path(sys.argv[2]).read_text())
cids = {x.upper() for x in c81["strict_released_case_ids"]}
assert len(c81["strict_released_case_ids"]) == 81
for i in want:
    assert i not in cids
g4 = json.loads((owned / "work/pages/ghsa/GHSA-4fxp-2m36-qv64.json").read_text())
assert g4["type"] == "unreviewed"
assert g4.get("vulnerabilities") in ([], None) or g4["vulnerabilities"] == []
assert not g4.get("repository_advisory_url")
rq = json.loads((owned / "work/pages/ghsa/GHSA-qf5v-m7p4-95rp.json").read_text())
assert rq["ghsa_id"].lower() == "ghsa-qf5v-m7p4-95rp"
assert rq.get("type") == "reviewed"
assert rq.get("withdrawn_at") is None
rr = json.loads((owned / "work/pages/repo-advisory/fission__fission__GHSA-qf5v-m7p4-95rp.json").read_text())
assert rr["state"] == "published" and rr["withdrawn_at"] is None
info = json.loads((owned / "work/pages/goproxy/fission_v1.24.0.info.json").read_text())
assert info["Version"] == "v1.24.0"
assert info["Origin"]["Hash"] == "ce617120c41b9e4a51d577f81b441238264e88fd"
rel = json.loads((owned / "work/pages/github-releases/fission_v1.24.0.json").read_text())
assert rel["prerelease"] is True and rel["draft"] is False
rel25 = json.loads((owned / "work/pages/github-releases/fission_v1.25.0.json").read_text())
assert rel25["prerelease"] is False and rel25["draft"] is False
print("conservation assigned=11 reviewed=11 unreviewed=0 PASS_proposal=1 NARROW=10 REJECT=0 UNKNOWN=0 BLOCKED=0")
PY

C4FXP=52e5e1938ba7db9191ab75fc6f81d92cf667dd4d
F4FXP=86a7d6557bd111518a221f4575ad6e36087e19d3
C4MR5=3cd664bf7b7db5f774c1e7e3123a1a24c68ba700
F4MR5=179cab02dbec0c1e9b601507a65908e079876004
C94P4=8ac5a30519b6f4af85398b9b9d7064ff4d452da2
F94P4=863417457a0633db7ea5aed4fd01e0b291a41162
CG8MR=af88b1f5d82844a4761ea9a977156c98e2b14ca8
FG8MR=385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7
PEEL324=c666d149a4516761bae92ca56ce1336d2fd352c3
PEEL325=2cbad0a923c48c6144266df3cd25f93547cb5221
MEM63=2db76f65dbfe4f657b4a4efb506ed63b24623e92
CARF=e484df8460bb4e8026e24210120602aa7f181f64
FM63=695d3e97e3a20463ab7c8c081843e69e65e952e5
FQF5=2569b42bfadbcb7d78b55a00a60f77937e522699
PEEL124=ce617120c41b9e4a51d577f81b441238264e88fd
PEEL125=ae970aaa9bc76ec93d748bdaf03fd7523b6b6a62
MH=b8b62722ec2f6b3cd394737ab409c35650f29ca6
CH=1126e541325d401538f6a272a9c024c37d47ae08
FH=f2ef2851d389cf7a41308dcf0180d7cfbe446379
CP538=701ce32fe5ba8cb622c0e0342a376a6beb47d738
FP538=38553b6fddc7f6a667cdb45a6762343a08fc72b2
MK=f51f4971ea3459cd410b363b34e156a116b530f4
CK=de3d18d9fe31ced4ac749728d3a2f94811f59268
FK=430008e9d700b3fe80f206c672415cfbd8e830e7
CW=4afa9bea32cd4538af19cbba45a874dbb614be8d
FW=b4f18537bbf6787d18a9abafce53c557ac36f475
BOUND=73041bfa6420f5e1ecbfa1dd4fa847d8529320f5
CX8A=56ea64c80fd36840fe3c84d0c6a6a38296a8f111
FX8=9a859c4de3d49674916773d346c60d89ad7febe0

# GHSA-4FXP
body=$("${git_cmd[@]}" -C "$PR" log -1 --format='%B' "$C4FXP")
printf '%s\n' "$body" | grep -F 'Co-authored-by: Claude Sonnet 4.6 <noreply@anthropic.com>' >/dev/null
assert_ancestor "$PR" "$C4FXP" "v4.6.0"
assert_not_ancestor "$PR" "$F4FXP" "v4.6.0"
assert_ancestor "$PR" "$F4FXP" "v5.5.3"
blob_c=$("${git_cmd[@]}" -C "$PR" rev-parse "${C4FXP}:app/Http/Controllers/Permission/PermissionSaveController.php")
blob_v=$("${git_cmd[@]}" -C "$PR" rev-parse "v4.6.0:app/Http/Controllers/Permission/PermissionSaveController.php")
[[ $blob_c == "$blob_v" ]]
[[ $blob_c == f0da620c7b4f2a3708979a684eb2d4eba35db9a6 ]]

# GHSA-4MR5
an=$("${git_cmd[@]}" -C "$P" log -1 --format='%an' "$C4MR5")
[[ $an == 'claude[bot]' ]]
blob_ai=$("${git_cmd[@]}" -C "$P" rev-parse "${C4MR5}:src/praisonai-agents/praisonaiagents/tools/python_tools.py")
blob_r=$("${git_cmd[@]}" -C "$P" rev-parse "v4.6.39:src/praisonai-agents/praisonaiagents/tools/python_tools.py")
[[ $blob_ai == fcaf2927ff446e3a2bf4a0bb0c685ca6d9eaac38 ]]
[[ $blob_r == c4ba5d9763f8dc05da26179f43172d9091a5116f ]]
[[ $blob_ai != "$blob_r" ]]
assert_ancestor "$P" "$C4MR5" "v4.6.39"
assert_not_ancestor "$P" "$F4MR5" "v4.6.39"
assert_ancestor "$P" "$F4MR5" "v4.6.40"

# GHSA-94P4
sv=$("${git_cmd[@]}" -C "$GP" log -1 --format='%an %ae' "$C94P4")
[[ $sv == 'GPT 5.6 codex@openai.com' ]]
cmd_p=$("${git_cmd[@]}" -C "$GP" rev-parse "${C94P4}^:git/remote.py")
cmd_c=$("${git_cmd[@]}" -C "$GP" rev-parse "${C94P4}:git/remote.py")
[[ $cmd_p == "$cmd_c" ]]
assert_ancestor "$GP" "$C94P4" "3.1.52"
assert_not_ancestor "$GP" "$F94P4" "3.1.52"
assert_ancestor "$GP" "$F94P4" "3.1.55"

# GHSA-G8MR
s=$("${git_cmd[@]}" -C "$V" log -1 --format='%b' "$CG8MR")
printf '%s\n' "$s" | grep -F 'Co-authored-by: Codex <noreply@openai.com>' >/dev/null
assert_not_ancestor "$V" "$CG8MR" "$PEEL324"
assert_ancestor "$V" "$CG8MR" "$PEEL325"
assert_ancestor "$V" "$FG8MR" "$PEEL325"
rpc_c=$("${git_cmd[@]}" -C "$V" rev-parse "${CG8MR}:packages/browser/src/node/rpc.ts")
rpc_4=$("${git_cmd[@]}" -C "$V" rev-parse "${PEEL324}:packages/browser/src/node/rpc.ts")
rpc_5=$("${git_cmd[@]}" -C "$V" rev-parse "${PEEL325}:packages/browser/src/node/rpc.ts")
rpc_f=$("${git_cmd[@]}" -C "$V" rev-parse "${FG8MR}:packages/browser/src/node/rpc.ts")
[[ $rpc_c != "$rpc_4" ]]
[[ $rpc_5 == "$rpc_f" ]]
[[ $rpc_c == 358ac355f89983297c18932c68e5aea7d78020ea ]]
[[ $rpc_f == 72818584f0669b58db74b6e093e04173c083293e ]]

# GHSA-M63V / QF5V
body_car=$("${git_cmd[@]}" -C "$F" log -1 --format='%B' "$CARF")
printf '%s\n' "$body_car" | grep -F 'Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>' >/dev/null
pc=$("${git_cmd[@]}" -C "$F" log -1 --format='%P' "$CARF")
[[ $pc == 8fa799417c77ce8a0189d9858bfe11ece29b84a6 ]]
mp=$("${git_cmd[@]}" -C "$F" log -1 --format='%P' "$MEM63")
[[ $mp == "$pc" ]]
member_tags=$("${git_cmd[@]}" -C "$F" tag --contains "$MEM63")
if [[ -n $member_tags ]]; then
  printf 'fission member unexpectedly contained in tags\n' >&2
  exit 1
fi
assert_not_ancestor "$F" "$MEM63" "v1.24.0"
assert_ancestor "$F" "$CARF" "v1.24.0"
assert_ancestor "$F" "$FM63" "v1.24.0"
assert_not_ancestor "$F" "$FQF5" "v1.24.0"
assert_ancestor "$F" "$FQF5" "v1.25.0"
peel124=$("${git_cmd[@]}" -C "$F" rev-parse 'v1.24.0^{commit}')
peel125=$("${git_cmd[@]}" -C "$F" rev-parse 'v1.25.0^{commit}')
[[ $peel124 == "$PEEL124" ]]
[[ $peel125 == "$PEEL125" ]]
blob_car=$("${git_cmd[@]}" -C "$F" rev-parse "${CARF}:pkg/apis/core/v1/podspec_safety.go")
blob_m63=$("${git_cmd[@]}" -C "$F" rev-parse "${FM63}:pkg/apis/core/v1/podspec_safety.go")
blob_124=$("${git_cmd[@]}" -C "$F" rev-parse "v1.24.0:pkg/apis/core/v1/podspec_safety.go")
blob_125=$("${git_cmd[@]}" -C "$F" rev-parse "v1.25.0:pkg/apis/core/v1/podspec_safety.go")
blob_fix=$("${git_cmd[@]}" -C "$F" rev-parse "${FQF5}:pkg/apis/core/v1/podspec_safety.go")
[[ $blob_124 == "$blob_m63" ]]
[[ $blob_124 == 1d7219e7f592cc6ea631866328820475617141bd ]]
[[ $blob_125 == "$blob_fix" ]]
[[ $blob_car != "$blob_124" ]]
if "${git_cmd[@]}" -C "$F" cat-file -e 'v1.23.0:pkg/apis/core/v1/podspec_safety.go' 2>/dev/null; then
  printf 'v1.23.0 unexpectedly has podspec_safety.go\n' >&2
  exit 1
fi
src124=$("${git_cmd[@]}" -C "$F" show 'v1.24.0:pkg/apis/core/v1/podspec_safety.go')
printf '%s\n' "$src124" | grep -F 'var dangerousCapabilities' >/dev/null
if printf '%s\n' "$src124" | grep -F 'SYS_TIME' >/dev/null; then
  printf 'v1.24.0 denylist unexpectedly mentions SYS_TIME\n' >&2
  exit 1
fi
src125=$("${git_cmd[@]}" -C "$F" show 'v1.25.0:pkg/apis/core/v1/podspec_safety.go')
printf '%s\n' "$src125" | grep -F 'var allowedCapabilities' >/dev/null
printf '%s\n' "$src125" | grep -F 'SYS_TIME' >/dev/null
blame=$("${git_cmd[@]}" -C "$F" blame -L 17,24 v1.24.0 -- pkg/apis/core/v1/podspec_safety.go)
printf '%s\n' "$blame" | grep -F 'e484df846' >/dev/null

# GHSA-P52P
body_m=$("${git_cmd[@]}" -C "$H" log -1 --format='%B' "$MH")
printf '%s\n' "$body_m" | grep -F 'Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>' >/dev/null
hp=$("${git_cmd[@]}" -C "$H" log -1 --format='%P' "$CH")
[[ $hp == $'5dceb2993cc0a6bc42697a30d370425db482609a f2ef2851d389cf7a41308dcf0180d7cfbe446379' ]]
assert_ancestor "$H" "$MH" "v0.51.357"
assert_not_ancestor "$H" "$FH" "v0.51.357"
assert_ancestor "$H" "$FH" "v0.51.358"
blob_mem=$("${git_cmd[@]}" -C "$H" rev-parse "${MH}:api/config.py")
blob_357=$("${git_cmd[@]}" -C "$H" rev-parse "v0.51.357:api/config.py")
[[ $blob_mem != "$blob_357" ]]

# GHSA-P538
sv2=$("${git_cmd[@]}" -C "$GP" log -1 --format='%an %ae' "$CP538")
[[ $sv2 == 'GPT 5.6 codex@openai.com' ]]
fixan=$("${git_cmd[@]}" -C "$GP" log -1 --format='%an' "$FP538")
[[ $fixan == 'Sebastian Thiel' ]]
assert_ancestor "$GP" "$CP538" "3.1.51"
assert_not_ancestor "$GP" "$FP538" "3.1.51"
assert_ancestor "$GP" "$FP538" "3.1.56"

# GHSA-P5RM
bodyk=$("${git_cmd[@]}" -C "$K" log -1 --format='%B' "$MK")
printf '%s\n' "$bodyk" | grep -F 'Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>' >/dev/null
assert_not_ancestor "$K" "$MK" "v1.33.0"
assert_not_ancestor "$K" "$CK" "v1.33.0"
assert_not_ancestor "$K" "$MK" "v1.34.0"
assert_ancestor "$K" "$CK" "v1.34.0"
assert_ancestor "$K" "$FK" "v1.34.0"
bmem=$("${git_cmd[@]}" -C "$K" rev-parse "${MK}:src/Kiota.Builder/OpenApiExtensions/OpenApiAiCapabilitiesExtension.cs")
bcar=$("${git_cmd[@]}" -C "$K" rev-parse "${CK}:src/Kiota.Builder/OpenApiExtensions/OpenApiAiCapabilitiesExtension.cs")
b133=$("${git_cmd[@]}" -C "$K" rev-parse "v1.33.0:src/Kiota.Builder/OpenApiExtensions/OpenApiAiCapabilitiesExtension.cs")
b134=$("${git_cmd[@]}" -C "$K" rev-parse "v1.34.0:src/Kiota.Builder/OpenApiExtensions/OpenApiAiCapabilitiesExtension.cs")
bfix=$("${git_cmd[@]}" -C "$K" rev-parse "${FK}:src/Kiota.Builder/OpenApiExtensions/OpenApiAiCapabilitiesExtension.cs")
[[ $bmem == "$bcar" ]]
[[ $bmem != "$b133" ]]
[[ $b134 == "$bfix" ]]

# GHSA-X2W7
bodyw=$("${git_cmd[@]}" -C "$W" log -1 --format='%B' "$CW")
printf '%s\n' "$bodyw" | grep -F 'Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>' >/dev/null
wtags=$("${git_cmd[@]}" -C "$W" tag)
if [[ -n $wtags ]]; then
  printf 'wacrm unexpectedly has tags\n' >&2
  exit 1
fi
assert_ancestor "$W" "$CW" "$BOUND"
assert_ancestor "$W" "$FW" "$BOUND"

# GHSA-X8QQ
bodyx=$("${git_cmd[@]}" -C "$PR" log -1 --format='%B' "$CX8A")
printf '%s\n' "$bodyx" | grep -F 'Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>' >/dev/null
if "${git_cmd[@]}" -C "$PR" cat-file -e 'v4.6.0:app/Http/Controllers/Api/Order/OrderReadController.php' 2>/dev/null; then
  printf 'v4.6.0 unexpectedly has OrderReadController\n' >&2
  exit 1
fi
assert_ancestor "$PR" "$CX8A" "v5.5.3"
assert_ancestor "$PR" "$FX8" "v5.5.3"
bxo=$("${git_cmd[@]}" -C "$PR" rev-parse "${CX8A}:app/Http/Controllers/Api/Order/OrderReadController.php")
bxf=$("${git_cmd[@]}" -C "$PR" rev-parse "${FX8}:app/Http/Controllers/Api/Order/OrderReadController.php")
bx553=$("${git_cmd[@]}" -C "$PR" rev-parse "v5.5.3:app/Http/Controllers/Api/Order/OrderReadController.php")
[[ $bx553 == "$bxf" ]]
[[ $bxo != "$bxf" ]]

python3 - "$F" "$GP" "$H" "$P" << 'PY'
import re, subprocess, sys
pat = re.compile(
    r"Co-authored-by:.*(Claude|Cursor Agent|Copilot|ChatGPT|OpenAI|Anthropic)|"
    r"Generated with Claude|noreply@anthropic|codex@openai.com|\[AI\]",
    re.I,
)
git = ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]
# Human rewrite 9ef539 must not be the counted AI origin. P538 closer is GPT-trailed; authorship of count is still a sibling completion.
scans = [
    (sys.argv[4], "9ef5391c832be926e86ee3a491970bc9dc7d1b5c"),
]
for repo, sha in scans:
    rec = subprocess.check_output(
        git + ["-C", repo, "log", "-1", "--format=%H%x1f%an%x1f%s%x1f%b", sha],
        text=True,
        errors="replace",
    )
    assert not pat.search(rec), (sha, rec[:200])
p538 = subprocess.check_output(
    git + ["-C", sys.argv[2], "log", "-1", "--format=%an%x1f%b", "38553b6fddc7f6a667cdb45a6762343a08fc72b2"],
    text=True,
    errors="replace",
)
assert p538.startswith("Sebastian Thiel")
assert "Co-authored-by: GPT 5.6 <codex@openai.com>" in p538
print("human_rewrite_and_p538_author_scan_ok")
PY

printf 'REPLAY_OK reviewed=11 PASS_proposal=1 NARROW=10 REJECT=0 UNKNOWN=0 BLOCKED=0\n'
