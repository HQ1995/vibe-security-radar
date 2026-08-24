#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-nearpass-twogate12-grok46-medium.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# PASS is a proposal only. This script does not admit any row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-nearpass-twogate12-grok46-medium
MY=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/mysti
CB=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/codexbar
ZC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/zeptoclaw
CY=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/coolify
BB=/home/hanqing/.cache/cve-analyzer/repos/maziggy_bambuddy
OC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/openclaw
MS=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/misp
AP=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/apm
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

# Drop broken-alternate warnings from clone objects/info/alternates.
# Keep all other git stderr, including fatal path misses used as failures.
gitx() {
  local repo=$1
  shift
  local errfile rc
  errfile=$(/usr/bin/mktemp)
  set +e
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errfile"
  rc=$?
  set -e
  /usr/bin/grep -vF -- 'unable to normalize alternate object path:' "$errfile" >&2 || true
  /usr/bin/rm -f "$errfile"
  return $rc
}

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
  gitx "$1" merge-base --is-ancestor "$2" "$3"
}

assert_not_ancestor() {
  if gitx "$1" merge-base --is-ancestor "$2" "$3"; then
    printf 'unexpected ancestor: %s is ancestor of %s in %s\n' "$2" "$3" "$1" >&2
    exit 1
  fi
}

require_dir "$OWNED"
require_dir "$MY/.git"
require_dir "$CB/.git"
require_dir "$ZC/.git"
require_dir "$CY/.git"
require_dir "$BB/.git"
require_dir "$OC/.git"
require_dir "$MS/.git"
require_dir "$AP/.git"
require_dir "$ADV/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected-12.jsonl"
require_file "$OWNED/report.md"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/ledger.jsonl" \
  3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9
expect_hash "$OWNED/selected-12.jsonl" \
  c4257548b392033594b015bc505b7ae107f537db9b771f3cb1cdada7ec28328a
expect_hash "$OWNED/cases.jsonl" \
  c2e72b9c4f190b371085706f7f5f2479483cb203fe4a9b717645b4ecc6aae964
expect_hash "$OWNED/report.md" \
  d5bd4af7f624558137811afa3cdbfda34b75d8ddef7a5020e317111286485c36
expect_hash "$OWNED/work/uniqueness.json" \
  e63120319c472e7c2a3cfbd43547cd124b596b36611197a93f0e532e7f9ac35c
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/ledger.jsonl" \
  58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" \
  d436f47f82297eb0d9363ad0f3876adc639b1f61e9b23c7f9d613545741e106e
expect_hash "$OWNED/work/git/probes.json" \
  ff9aab0fb2bd0a70b0bcbfd04f9f45c86340d21283470a62910afe385d0cfb8b
expect_hash "$OWNED/work/pages/ghsa/GHSA-FWPR-59HH-GR98.json" \
  02e55d12550a54c4a6cf5950acd9ee80088e788b435c70e4c177f47a03071119
expect_hash "$OWNED/work/pages/ghsa/GHSA-42M6-XH7C-6XM4.json" \
  c02d8369b7a9924b052d7d8a63a38a2750a6cf7ccde3d55e89bbfec15dfdb3ce
expect_hash "$OWNED/work/pages/repo-advisory/coollabsio__coolify__GHSA-Q9J6-XCVX-PX63.json" \
  a43adedfe433382daf9ea81be1f0d6b0529bc024637ed7f2097134fcc6d4ed21
expect_hash "$OWNED/work/pages/repo-advisory/coollabsio__coolify__GHSA-4MPW-WCJ4-V9PP.json" \
  6206157d93d18a0bc6124f1bc02d1969bd2c5d59df732ed214e698061226a2b4
expect_hash "$OWNED/work/pages/repo-advisory/openclaw__openclaw__GHSA-HFF7-CCV5-52F8.json" \
  fea3b58103cc80a5d016b45e3f3928e8fabbf5cb11f3150cf2e90f1531fdfd9b
expect_hash "$OWNED/work/pages/ghsa/GHSA-3636-3MQQ-Q7X9.json" \
  f0e7b9e74fac7a3a3772d2a140ace064b98f652f35350a077132e0db5a007cc8

[[ "$(gitx "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]

python3 - "$OWNED" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected-12.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 12, len(rows)
assert len(sel) == 12, len(sel)
want = [
    "GHSA-FWPR-59HH-GR98",
    "GHSA-42M6-XH7C-6XM4",
    "GHSA-2M67-CXXQ-C3H8",
    "GHSA-Q9J6-XCVX-PX63",
    "GHSA-4MPW-WCJ4-V9PP",
    "GHSA-GC24-PX2R-5QMF",
    "GHSA-HFF7-CCV5-52F8",
    "GHSA-Q447-RJ3R-2CGH",
    "GHSA-C339-W3CQ-2RJR",
    "GHSA-Q6QF-4P5J-R25G",
    "GHSA-3636-3MQQ-Q7X9",
    "GHSA-Q5PP-GVJG-H7V4",
]
assert [r["case_id"] for r in rows] == want
assert [r["case_id"] for r in sel] == want
assert [r["ordinal"] for r in sel] == [5, 22, 24, 34, 35, 37, 40, 47, 55, 60, 61, 70]
assert all(r["fp211_nonpass_count"] == 2 for r in sel)
assert all(r["causal_admission"] is False for r in rows)
assert all(r["countable"] is False for r in rows)
assert all(r["countable_proposal"] is False for r in rows)
assert all(r["publication_status"] == "HOLD" for r in rows)
assert all(r["worker_pass_is_proposal_only"] is True for r in rows)
assert all(r["uniqueness_gate"] == "PASS" for r in rows)
by = {r["case_id"]: r for r in rows}
assert by["GHSA-4MPW-WCJ4-V9PP"]["verdict"] == "UNKNOWN"
assert by["GHSA-4MPW-WCJ4-V9PP"]["ai_hunk_gate"] == "UNKNOWN"
assert sum(1 for r in rows if r["verdict"] == "NARROW") == 11
assert sum(1 for r in rows if r["verdict"] == "PASS") == 0
assert by["GHSA-FWPR-59HH-GR98"]["identity_gate"] == "NARROW"
assert by["GHSA-FWPR-59HH-GR98"]["release_gate"] == "NARROW"
assert by["GHSA-42M6-XH7C-6XM4"]["ai_hunk_gate"] == "NARROW"
assert by["GHSA-2M67-CXXQ-C3H8"]["release_gate"] == "NARROW"
assert by["GHSA-Q9J6-XCVX-PX63"]["but_for_gate"] == "NARROW"
assert by["GHSA-GC24-PX2R-5QMF"]["identity_gate"] == "NARROW"
assert by["GHSA-HFF7-CCV5-52F8"]["but_for_gate"] == "NARROW"
assert by["GHSA-Q447-RJ3R-2CGH"]["but_for_gate"] == "NARROW"
assert by["GHSA-C339-W3CQ-2RJR"]["but_for_gate"] == "NARROW"
assert by["GHSA-Q6QF-4P5J-R25G"]["but_for_gate"] == "NARROW"
assert by["GHSA-3636-3MQQ-Q7X9"]["identity_gate"] == "NARROW"
assert by["GHSA-Q5PP-GVJG-H7V4"]["but_for_gate"] == "NARROW"
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(r"ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}")
for name in ("cases.jsonl", "selected-12.jsonl", "report.md", "replay.zsh"):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    assert text.endswith("\n"), name
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (name, line)
c81 = json.loads(Path(sys.argv[2]).read_text())
cids = {x.upper() for x in c81["strict_released_case_ids"]}
assert len(c81["strict_released_case_ids"]) == 81
for i in want:
    assert i not in cids
c82 = json.loads(Path(sys.argv[3]).read_text())
c82ids = {x.upper() for x in c82["strict_released_case_ids"]}
assert len(c82["strict_released_case_ids"]) == 82
assert c82["canonical_strict_count"] == 82
for i in want:
    assert i not in c82ids
uni = json.loads((owned / "work/uniqueness.json").read_text())
assert uni["canonical81_overlap"] == []
assert uni["canonical82_overlap"] == []
assert uni["start_count"] == 81
assert uni["current_leader_accepted_count"] == 82
assert uni["packet_delta"] == 0
assert uni["canonical81_strict_count"] == 81
assert uni["canonical82_strict_count"] == 82
fw = json.loads((owned / "work/pages/ghsa/GHSA-FWPR-59HH-GR98.json").read_text())
assert fw["type"] == "unreviewed"
g42 = json.loads((owned / "work/pages/ghsa/GHSA-42M6-XH7C-6XM4.json").read_text())
assert g42["type"] == "unreviewed"
r4 = json.loads((owned / "work/pages/repo-advisory/coollabsio__coolify__GHSA-4MPW-WCJ4-V9PP.json").read_text())
assert r4["state"] == "published" and r4["withdrawn_at"] is None
g36 = json.loads((owned / "work/pages/ghsa/GHSA-3636-3MQQ-Q7X9.json").read_text())
assert g36["type"] == "unreviewed"
print("conservation assigned=12 reviewed=12 unreviewed=0 PASS_proposal=0 NARROW=11 REJECT=0 UNKNOWN=1 BLOCKED=0")
PY

# FWPR
CFWPR=bce0d2ba7904c056c576cf94db817635421d1f41
FFWPR=6d709229b5199f6769fb3cf763e5122dcc43c079
gitx "$MY" cat-file -e "${CFWPR}"'^{commit}'
body=$(gitx "$MY" log -1 --format='%B' "$CFWPR")
printf '%s\n' "$body" | grep -F 'Co-Authored-By: Claude Opus 4.6' >/dev/null
peel40=$(gitx "$MY" rev-parse 'v0.4.0^{commit}')
[[ $peel40 == "$CFWPR" ]]
assert_not_ancestor "$MY" "$FFWPR" "v0.4.0"
tagsfix=$(gitx "$MY" tag --contains "$FFWPR")
[[ -z $tagsfix ]]

# 42M6
C42=8348c85cd8d43affa0c9d83be20ff42d895fe1dc
F42=08c171b6b487654a0eb188494fa24bd1c4272a2e
gitx "$CB" cat-file -e "${C42}"'^{commit}'
if gitx "$CB" cat-file -e "${C42}:Sources/CodexBarCore/ProviderHTTPClient.swift" 2>/dev/null; then
  printf '42m6 candidate unexpectedly has ProviderHTTPClient.swift\n' >&2
  exit 1
fi
H42=$(gitx "$CB" rev-parse f62bb8c8d564)
gitx "$CB" cat-file -e "${H42}:Sources/CodexBarCore/ProviderHTTPClient.swift"
assert_ancestor "$CB" "$C42" "$H42"
assert_not_ancestor "$CB" "$F42" "v0.32.0"
assert_ancestor "$CB" "$F42" "v0.33.0"

# 2M67
C2M=fe70dcd422adbd1e95c90b097489380bf84c4c55
K2M=51bc07a02484ddfd2ec9c7f382dc43f829a9df86
F2M=f50c17e11ae3e2d40c96730abac41974ef2ee2a8
gitx "$ZC" cat-file -e "${C2M}"'^{commit}'
body2=$(gitx "$ZC" log -1 --format='%B' "$C2M")
printf '%s\n' "$body2" | grep -F 'Co-Authored-By: Claude Sonnet 4.6' >/dev/null
assert_not_ancestor "$ZC" "$C2M" "v0.7.5"
assert_ancestor "$ZC" "$K2M" "v0.7.5"
assert_ancestor "$ZC" "$F2M" "v0.7.5"
bm=$(gitx "$ZC" rev-parse "${C2M}:src/tools/pdf_read.rs")
bk=$(gitx "$ZC" rev-parse "${K2M}:src/tools/pdf_read.rs")
b75=$(gitx "$ZC" rev-parse "v0.7.5:src/tools/pdf_read.rs")
if [[ $bm == "$bk" || $bm == "$b75" ]]; then
  printf 'zeptoclaw pdf_read blobs unexpectedly equal\n' >&2
  exit 1
fi
pfix=$(gitx "$ZC" rev-parse "${F2M}:src/security/path.rs")
p75=$(gitx "$ZC" rev-parse "v0.7.5:src/security/path.rs")
[[ $pfix == "$p75" ]]

# Q9J6
CQ9=bbb2aa9ad4e0c14517d32272b5e6d83318fde493
FQ9=f267a28cb2badc7e712c4592af4d79d090fe5063
gitx "$CY" cat-file -e "${CQ9}"'^{commit}'
parent_gl=$(gitx "$CY" show "${CQ9}"'^:app/Livewire/Project/Shared/GetLogs.php')
printf '%s\n' "$parent_gl" | grep -F '{$this->container}' >/dev/null
assert_ancestor "$CY" "$CQ9" "v4.0.0-beta.461"
assert_not_ancestor "$CY" "$FQ9" "v4.0.0-beta.461"
assert_ancestor "$CY" "$FQ9" "v4.0.0-beta.471"

# 4MPW
C4M=473c32270d72252ee6753afc35c3ea4360d169e0
body4=$(gitx "$CY" log -1 --format='%B' "$C4M")
printf '%s\n' "$body4" | grep -F 'Changes auto-committed by Conductor' >/dev/null
if printf '%s\n' "$body4" | grep -Ei 'Co-Authored-By: Claude|Co-authored-by: Copilot'; then
  printf '4mpw unexpectedly has Claude/Copilot trailer\n' >&2
  exit 1
fi
assert_ancestor "$CY" "$C4M" "v4.0.0-beta.461"

# GC24
CGC=a7319f0e7087cee59f1aa658c52c6408f1fb71e8
FGC=c31f2968889c855f1ffacb700c2c9970deb2a6fb
gitx "$BB" cat-file -e "${CGC}"'^{commit}'
bodyg=$(gitx "$BB" log -1 --format='%B' "$CGC")
printf '%s\n' "$bodyg" | grep -F 'Co-Authored-By: Claude Opus 4.5' >/dev/null
cand_pr=$(gitx "$BB" show "${CGC}:backend/app/api/routes/printers.py")
parent_pr=$(gitx "$BB" show "${CGC}"'^:backend/app/api/routes/printers.py')
printf '%s\n' "$cand_pr" | grep -F 'simulate-print-complete' >/dev/null
if printf '%s\n' "$parent_pr" | grep -F 'simulate-print-complete'; then
  printf 'gc24 parent unexpectedly has simulate-print-complete\n' >&2
  exit 1
fi
assert_ancestor "$BB" "$CGC" "v0.1.6"
assert_not_ancestor "$BB" "$FGC" "v0.1.6"
assert_ancestor "$BB" "$FGC" "v0.1.7"

# HFF7
CH=f4b03599f0fb9c2f76e8dbe5fde13948d68dbc3f
FH=356d61aacfa5b0f1d5830716ec59d70682a3e7b8
gitx "$OC" cat-file -e "${CH}"'^{commit}'
parent_h=$(gitx "$OC" show "${CH}"'^:src/gateway/openai-http.ts')
printf '%s\n' "$parent_h" | grep -F 'authorizeGatewayConnect' >/dev/null
assert_ancestor "$OC" "$CH" "v2026.2.19"
assert_not_ancestor "$OC" "$FH" "v2026.2.19"
assert_ancestor "$OC" "$FH" "v2026.2.21"

# Q447
CQ=b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517
KQ=5c2cb6c591e4b63c2df0549ad2202403256e2a96
FQ=3cbcba10cf30c2ffb898f0d8c7dfb929f15f8930
gitx "$OC" cat-file -e "${CQ}"'^{commit}'
assert_not_ancestor "$OC" "$CQ" "$KQ"
assert_not_ancestor "$OC" "$CQ" "v2026.2.12"
assert_ancestor "$OC" "$KQ" "v2026.2.12"
assert_not_ancestor "$OC" "$FQ" "v2026.2.12"
assert_ancestor "$OC" "$FQ" "v2026.2.13"
bmq=$(gitx "$OC" rev-parse "${CQ}:extensions/feishu/src/monitor.ts")
bkq=$(gitx "$OC" rev-parse "${KQ}:extensions/feishu/src/monitor.ts")
[[ $bmq == "$bkq" ]]

# C339
CC3=acff543e09ae5c7f8da78e5a092ebb1e57f24dc0
FC3=0fed553207383f384b93cba24d28122065fa67d5
parent_c=$(gitx "$CY" show "${CC3}"'^:app/Livewire/Settings/Updates.php')
cand_c=$(gitx "$CY" show "${CC3}:app/Livewire/Settings/Updates.php")
fix_c=$(gitx "$CY" show "${FC3}:app/Livewire/Settings/Updates.php")
printf '%s\n' "$parent_c" | grep -F 'findOrFail' >/dev/null
if printf '%s\n' "$parent_c" | grep -F 'isInstanceAdmin'; then
  printf 'c339 parent unexpectedly has isInstanceAdmin\n' >&2
  exit 1
fi
printf '%s\n' "$cand_c" | grep -F 'isCloud' >/dev/null
printf '%s\n' "$fix_c" | grep -F 'isInstanceAdmin' >/dev/null
assert_ancestor "$CY" "$CC3" "v4.0.0-beta.461"
assert_not_ancestor "$CY" "$FC3" "v4.0.0-beta.461"
assert_ancestor "$CY" "$FC3" "v4.0.0-beta.471"

# Q6QF
CQ6=8d74578ceb0c3b913555dff6265821eb0fc09749
FQ6=dd9d9c1c609dcb4579f9e57bd7b5c879d0146b53
parent_q=$(gitx "$OC" show "${CQ6}"'^:src/agents/tools/image-tool.ts')
cand_q=$(gitx "$OC" show "${CQ6}:src/agents/tools/image-tool.ts")
fix_q=$(gitx "$OC" show "${FQ6}:src/agents/tools/image-tool.ts")
if printf '%s\n' "$parent_q" | grep -F 'workspaceOnly'; then
  printf 'q6qf parent unexpectedly has workspaceOnly\n' >&2
  exit 1
fi
if printf '%s\n' "$cand_q" | grep -F 'workspaceOnly'; then
  printf 'q6qf candidate unexpectedly has workspaceOnly\n' >&2
  exit 1
fi
printf '%s\n' "$fix_q" | grep -F 'workspaceOnly' >/dev/null
assert_ancestor "$OC" "$CQ6" "v2026.2.22"
assert_not_ancestor "$OC" "$FQ6" "v2026.2.22"
assert_ancestor "$OC" "$FQ6" "v2026.2.23"

# 3636
C36=47bf71cc78d13c06e1eaa4d9842e6f94ddce4bea
F36=8aa2bb6d1af6e8c57c8d8437cf203acb8bce7a53
D36=d3adfe1a097dd4b403364e9af34e208660eeec1a
body36=$(gitx "$MS" log -1 --format='%B' "$C36")
printf '%s\n' "$body36" | grep -F 'Co-Authored-By: Claude Opus 4.7' >/dev/null
assert_ancestor "$MS" "$D36" "v2.5.39"
assert_not_ancestor "$MS" "$F36" "v2.5.39"
assert_ancestor "$MS" "$F36" "v2.5.40"

# Q5PP
CQ5=810d87b2af77b05a3b82cc6e076b053835d6adc3
FQ5=f85b9f54ad303159f9c448268eb7005c319fe02a
parent5=$(gitx "$AP" show "${CQ5}"'^:src/apm_cli/integration/agent_integrator.py')
cand5=$(gitx "$AP" show "${CQ5}:src/apm_cli/integration/agent_integrator.py")
printf '%s\n' "$parent5" | grep -F 'find_agent_files' >/dev/null
if printf '%s\n' "$parent5" | grep -F 'integrate_package_agents_claude'; then
  printf 'q5pp parent unexpectedly has integrate_package_agents_claude\n' >&2
  exit 1
fi
printf '%s\n' "$cand5" | grep -F 'integrate_package_agents_claude' >/dev/null
assert_ancestor "$AP" "$CQ5" "v0.12.4"
assert_not_ancestor "$AP" "$FQ5" "v0.12.4"
assert_ancestor "$AP" "$FQ5" "v0.13.0"

printf 'REPLAY_OK reviewed=12 PASS_proposal=0 NARROW=11 REJECT=0 UNKNOWN=1 BLOCKED=0\n'
