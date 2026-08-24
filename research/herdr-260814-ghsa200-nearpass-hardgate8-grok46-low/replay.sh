#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-nearpass-hardgate8-grok46-low.
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
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-nearpass-hardgate8-grok46-low
OC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/openclaw
CC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/churchcrm
CH=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/claude-hud
ZC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/zeptoclaw
SC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/solidcam-gppl-ide
IC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/ironclaw
LR=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/langroid
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
require_dir "$OC/.git"
require_dir "$CC/.git"
require_dir "$CH/.git"
require_dir "$ZC/.git"
require_dir "$SC/.git"
require_dir "$IC/.git"
require_dir "$LR/.git"
require_dir "$ADV/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected-8.jsonl"
require_file "$OWNED/report.md"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/ledger.jsonl" \
  3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9
expect_hash "$OWNED/selected-8.jsonl" \
  e6700f5736322f8b43a2c947ad259254fc19a89642507542fb7625cf084567ac
expect_hash "$OWNED/cases.jsonl" \
  c44bfc2b09e19598e06d22ac46bbd9a0cfa3d3cbed7c35825c28796d6e747c70
expect_hash "$OWNED/report.md" \
  86d92d7a3c014badcf96811f55c665731bd9cffd7b92a15c12390f8f361f097e
expect_hash "$OWNED/work/uniqueness.json" \
  0096530edc3ba75480448cf077f967df3e681dd88eb226983002c302fce26eae
expect_hash "$OWNED/work/pages/ghsa/GHSA-2QRV-RC5X-2G2H.json" \
  f8a7ef05e5cacda4e0b6ad07a78153e167a6e20af500cb22ceb169e15a1cc30a
expect_hash "$OWNED/work/pages/ghsa/GHSA-3J8Q-FWPJ-F8J5.json" \
  2218b50c8a811e2f609d256cc18fa9a5c1ecabca78a58f10ea7977e8a8392684
expect_hash "$OWNED/work/pages/repo-advisory/openclaw__openclaw__GHSA-2QRV-RC5X-2G2H.json" \
  de253d38b424e7c65475f54abacb7214055f38fe2ad7865281cb24bbebcfeb91
expect_hash "$OWNED/work/pages/repo-advisory/claude-hud__claude-hud__GHSA-4524-X6PC-RR9X.json" \
  3a32eab6ffbfd1cf2684b1a409bf40db46e46c5eaff44de656e499df05d92730
expect_hash "$OWNED/work/pages/repo-advisory/nearai__ironclaw__GHSA-CW23-QWR7-C655.json" \
  790eded25807b4eba5072a42f10b85b0dfc1712aaadb2e4b4fb39d0e3026223f
expect_hash "$OWNED/work/pages/npm/openclaw.wanted.json" \
  e2ed6a4f788510f4391f8013fc29a58a4df59999e767877558046dc9da534924
expect_hash "$OWNED/work/pages/pypi/langroid.wanted.json" \
  b3155b6727ed9e65d4b4a2f95dcc284b936bb06724a030a830c5024aea4a4820
expect_hash "$OWNED/work/pages/crates/zeptoclaw.wanted.json" \
  f8a865da3a72b33ec0a35923c0de775ac72c6640ec57ac55b65b333ebfd409f7

[[ "$("${git_cmd[@]}" -C "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]

python3 - "$OWNED" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected-8.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 8, len(rows)
assert len(sel) == 8, len(sel)
want = [
    "GHSA-2QRV-RC5X-2G2H",
    "GHSA-3J8Q-FWPJ-F8J5",
    "GHSA-4524-X6PC-RR9X",
    "GHSA-5WP8-Q9MX-8JX8",
    "GHSA-92VG-F4FQ-FXM9",
    "GHSA-CW23-QWR7-C655",
    "GHSA-F7FH-QG34-X2XH",
    "GHSA-X34R-63HX-W57F",
]
assert [r["case_id"] for r in rows] == want
assert all("GHSA-" in " ".join(r.get("declared_public_ids") or []) or True for r in sel)
sel_ids = []
for r in sel:
    ids = [x.upper() for x in (r.get("declared_public_ids") or [])]
    hit = [i for i in want if i in ids]
    assert len(hit) == 1, ids
    sel_ids.append(hit[0])
assert sel_ids == want
assert all(r["worker_verdict"] == "NARROW" for r in rows)
assert all(r["verdict"] == "NARROW" for r in rows)
assert all(r["causal_admission"] is False for r in rows)
assert all(r["countable"] is False for r in rows)
assert all(r["countable_proposal"] is False for r in rows)
assert all(r["publication_status"] == "HOLD" for r in rows)
assert all(r["worker_pass_is_proposal_only"] is True for r in rows)
assert all(r["uniqueness_gate"] == "PASS" for r in rows)
by = {r["case_id"]: r for r in rows}
assert by["GHSA-2QRV-RC5X-2G2H"]["identity_gate"] == "PASS"
assert by["GHSA-2QRV-RC5X-2G2H"]["topology_gate"] == "NARROW"
assert by["GHSA-3J8Q-FWPJ-F8J5"]["identity_gate"] == "NARROW"
assert by["GHSA-4524-X6PC-RR9X"]["fix_reversal_gate"] == "NARROW"
assert by["GHSA-4524-X6PC-RR9X"]["identity_gate"] == "NARROW"
assert by["GHSA-5WP8-Q9MX-8JX8"]["topology_gate"] == "NARROW"
assert by["GHSA-92VG-F4FQ-FXM9"]["ai_hunk_gate"] == "NARROW"
assert by["GHSA-CW23-QWR7-C655"]["topology_gate"] == "NARROW"
assert by["GHSA-F7FH-QG34-X2XH"]["identity_gate"] == "NARROW"
assert by["GHSA-X34R-63HX-W57F"]["topology_gate"] == "NARROW"
assert by["GHSA-2QRV-RC5X-2G2H"]["repository"] == "openclaw/openclaw"
assert by["GHSA-3J8Q-FWPJ-F8J5"]["repository"] == "ChurchCRM/CRM"
assert by["GHSA-4524-X6PC-RR9X"]["repository"] == "claude-hud/claude-hud"
assert by["GHSA-5WP8-Q9MX-8JX8"]["repository"] == "qhkm/zeptoclaw"
assert by["GHSA-92VG-F4FQ-FXM9"]["repository"] == "anzory/solidcam-gppl-ide"
assert by["GHSA-CW23-QWR7-C655"]["repository"] == "nearai/ironclaw"
assert by["GHSA-F7FH-QG34-X2XH"]["repository"] == "openclaw/openclaw"
assert by["GHSA-X34R-63HX-W57F"]["repository"] == "langroid/langroid"
keys = {r["mechanism_key"] for r in rows}
assert len(keys) == 8
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(r"ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}")
for name in ("cases.jsonl", "selected-8.jsonl", "report.md", "replay.sh"):
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
g3 = json.loads((owned / "work/pages/ghsa/GHSA-3J8Q-FWPJ-F8J5.json").read_text())
assert g3["message"] == "Not Found"
r3 = json.loads((owned / "work/pages/repo-advisory/ChurchCRM__CRM__GHSA-3J8Q-FWPJ-F8J5.json").read_text())
assert r3["state"] == "published" and r3["withdrawn_at"] is None
r4524 = json.loads((owned / "work/pages/repo-advisory/claude-hud__claude-hud__GHSA-4524-X6PC-RR9X.json").read_text())
assert r4524["message"] == "Not Found"
g4524 = json.loads((owned / "work/pages/ghsa/GHSA-4524-X6PC-RR9X.json").read_text())
assert g4524.get("vulnerabilities") == []
rcw = json.loads((owned / "work/pages/repo-advisory/nearai__ironclaw__GHSA-CW23-QWR7-C655.json").read_text())
assert rcw["message"] == "Not Found"
r2 = json.loads((owned / "work/pages/repo-advisory/openclaw__openclaw__GHSA-2QRV-RC5X-2G2H.json").read_text())
assert r2["state"] == "published" and r2["withdrawn_at"] is None
npm = json.loads((owned / "work/pages/npm/openclaw.wanted.json").read_text())
for v in ("2026.4.1", "2026.4.2", "2026.4.5"):
    assert npm["wanted"][v]["in_versions"] is True
    assert npm["wanted"][v]["dist_tarball"]
pypi = json.loads((owned / "work/pages/pypi/langroid.wanted.json").read_text())
assert pypi["wanted"]["0.59.31"]["n_files"] == 2
assert pypi["wanted"]["0.59.32"]["n_files"] == 2
assert pypi["wanted"]["0.59.31"]["yanked"] == [False, False]
print("conservation assigned=8 reviewed=8 unreviewed=0 PASS_proposal=0 NARROW=8 REJECT=0 UNKNOWN=0 BLOCKED=0")
PY

C2QRV=fc1b156dc4105bdbcdc24d4c25d4f5af25cfd7bb
K2QRV=f4cc93dc7da7359c35130bbbb244d3fac695740f
F2QRV=53c29df2a9eb242a70d0ff29f3d1e67c8d6801f0
C3J8Q=b3edc22580116beb6bc8463d1876f2a7c9b96a28
F3J8Q=83c19611701b96300872390071440151360dfb48
C4524=26a3e984e442382f83297b545626f7293f4379b4
F4524=234d9aad919b51326a43bcf90b45ae35c23afc30
M5WP8=3c4368da0ab48c1091858d3f9503c378a209997f
K5WP8=1712debbea60af6adf4a8a5939a43f7ef9a1ac16
F5WP8=68916c3e4f3af107f11940b27854fc7ef517058b
C92VG=d1944bca6e984665fb98f5ea824c6c370fd618d6
F92VG=9d0ba808afd143ede448026a5dc681bfdc5c138d
MCW23=b20880c12837df41d7f49de6a33ebe4562b27c5b
KCW23=b58b421535e593b165393846a4c37d74283060ad
FCW23=a1d7c3ba428ed575900469b207fb5668725f9a71
CF7FH=75602014dbc5088b80e9b236146dfe5fdcc59e20
FF7FH=bc356cc8c2beaa747c71dd86cceab8f804699665
MX34R=b1c45e3fc0f3578a5dea9844c0216044321ae1c8
KX34R=0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6
FX34R=30abbc1a854dee22fbd2f8b2f575dfdabdb603ea

# GHSA-2QRV
"${git_cmd[@]}" -C "$OC" cat-file -e "${C2QRV}"'^{commit}'
body2=$("${git_cmd[@]}" -C "$OC" log -1 --format='%B' "$C2QRV")
printf '%s\n' "$body2" | grep -F 'Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>' >/dev/null
files2=$("${git_cmd[@]}" -C "$OC" diff-tree --no-commit-id --name-only -r "$C2QRV")
if printf '%s\n' "$files2" | grep -F 'src/channels/plugins/catalog.ts' >/dev/null; then
  printf '2qrv member unexpectedly edits catalog.ts\n' >&2
  exit 1
fi
blob_c=$("${git_cmd[@]}" -C "$OC" rev-parse "${C2QRV}:src/channels/plugins/catalog.ts")
blob_p=$("${git_cmd[@]}" -C "$OC" rev-parse "${C2QRV}"'^:src/channels/plugins/catalog.ts')
[[ $blob_c == "$blob_p" ]]
assert_not_ancestor "$OC" "$C2QRV" "$K2QRV"
peel41=$("${git_cmd[@]}" -C "$OC" rev-parse 'v2026.4.1^{commit}')
peel42=$("${git_cmd[@]}" -C "$OC" rev-parse 'v2026.4.2^{commit}')
[[ $peel41 == da64a978e5814567f7797cc34fbe29b61b7eae7a ]]
[[ $peel42 == d74a12264aa5fb0598605e8f04e1864b7239ddd5 ]]
assert_not_ancestor "$OC" "$C2QRV" "v2026.4.1"
assert_ancestor "$OC" "$K2QRV" "v2026.4.1"
assert_not_ancestor "$OC" "$F2QRV" "v2026.4.1"
assert_ancestor "$OC" "$F2QRV" "v2026.4.2"
pkg41=$("${git_cmd[@]}" -C "$OC" show 'v2026.4.1:package.json' | python3 -c 'import sys,json; print(json.load(sys.stdin)["version"])')
pkg42=$("${git_cmd[@]}" -C "$OC" show 'v2026.4.2:package.json' | python3 -c 'import sys,json; print(json.load(sys.stdin)["version"])')
[[ $pkg41 == 2026.4.1 ]]
[[ $pkg42 == 2026.4.2 ]]

# GHSA-3J8Q
"${git_cmd[@]}" -C "$CC" cat-file -e "${C3J8Q}"'^{commit}'
body3=$("${git_cmd[@]}" -C "$CC" log -1 --format='%B' "$C3J8Q")
printf '%s\n' "$body3" | grep -F 'Co-authored-by: Claude Sonnet 4.6 <noreply@anthropic.com>' >/dev/null
fbody3=$("${git_cmd[@]}" -C "$CC" log -1 --format='%B' "$F3J8Q")
printf '%s\n' "$fbody3" | grep -F 'GHSA-jjcj-h3cm-p7x7' >/dev/null
peel733=$("${git_cmd[@]}" -C "$CC" rev-parse '7.3.3^{commit}')
peel740=$("${git_cmd[@]}" -C "$CC" rev-parse '7.4.0^{commit}')
[[ $peel733 == da7ffe51e09dfab869750d6f56e94e03960346d1 ]]
[[ $peel740 == 66a731a1cf9b56e96b9a27de1bcb16364bbd986a ]]
assert_ancestor "$CC" "$C3J8Q" "7.3.3"
assert_not_ancestor "$CC" "$F3J8Q" "7.3.3"
assert_ancestor "$CC" "$F3J8Q" "7.4.0"

# GHSA-4524
"${git_cmd[@]}" -C "$CH" cat-file -e "${C4524}"'^{commit}'
body4=$("${git_cmd[@]}" -C "$CH" log -1 --format='%B' "$C4524")
printf '%s\n' "$body4" | grep -F 'Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>' >/dev/null
fsubj4=$("${git_cmd[@]}" -C "$CH" log -1 --format='%s' "$F4524")
[[ $fsubj4 == 'fix(security): harden links and Windows version lookup (#487)' ]]
assert_ancestor "$CH" "$C4524" "v0.0.12"
assert_not_ancestor "$CH" "$F4524" "v0.0.12"
assert_ancestor "$CH" "$F4524" "v0.1.0"
t12=$("${git_cmd[@]}" -C "$CH" show 'v0.0.12:src/transcript.ts')
t10=$("${git_cmd[@]}" -C "$CH" show 'v0.1.0:src/transcript.ts')
printf '%s\n' "$t12" | grep -F 'createReadStream' >/dev/null
printf '%s\n' "$t10" | grep -F 'createReadStream' >/dev/null
if printf '%s\n' "$t10" | grep -F 'allowlist' >/dev/null; then
  printf 'v0.1.0 unexpectedly has transcript allowlist\n' >&2
  exit 1
fi

# GHSA-5WP8
"${git_cmd[@]}" -C "$ZC" cat-file -e "${M5WP8}"'^{commit}'
body5=$("${git_cmd[@]}" -C "$ZC" log -1 --format='%B' "$M5WP8")
printf '%s\n' "$body5" | grep -F 'Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>' >/dev/null
assert_not_ancestor "$ZC" "$M5WP8" "$K5WP8"
assert_not_ancestor "$ZC" "$M5WP8" "v0.6.1"
assert_ancestor "$ZC" "$K5WP8" "v0.6.1"
assert_not_ancestor "$ZC" "$F5WP8" "v0.6.1"
assert_ancestor "$ZC" "$F5WP8" "v0.6.2"
bm=$("${git_cmd[@]}" -C "$ZC" rev-parse "${M5WP8}:src/security/shell.rs")
bk=$("${git_cmd[@]}" -C "$ZC" rev-parse "${K5WP8}:src/security/shell.rs")
b61=$("${git_cmd[@]}" -C "$ZC" rev-parse "v0.6.1:src/security/shell.rs")
if [[ $bm == "$bk" || $bm == "$b61" || $bk == "$b61" ]]; then
  printf 'zeptoclaw shell.rs blobs unexpectedly equal\n' >&2
  exit 1
fi

# GHSA-92VG
"${git_cmd[@]}" -C "$SC" cat-file -e "${C92VG}"'^{commit}'
files9=$("${git_cmd[@]}" -C "$SC" diff-tree --no-commit-id --name-only -r "$C92VG")
printf '%s\n' "$files9" | grep -F 'server/SolidCAM.GPPL.Server.exe' >/dev/null
if printf '%s\n' "$files9" | grep -Ei 'vmid|xdocument|\.cs$' >/dev/null; then
  printf 'solidcam candidate unexpectedly has parser source\n' >&2
  exit 1
fi
peel100=$("${git_cmd[@]}" -C "$SC" rev-parse 'v1.0.0^{commit}')
peel102=$("${git_cmd[@]}" -C "$SC" rev-parse 'v1.0.2^{commit}')
[[ $peel100 == "$C92VG" ]]
[[ $peel102 == "$F92VG" ]]

# GHSA-CW23
"${git_cmd[@]}" -C "$IC" cat-file -e "${MCW23}"'^{commit}'
bodyc=$("${git_cmd[@]}" -C "$IC" log -1 --format='%B' "$MCW23")
printf '%s\n' "$bodyc" | grep -F 'Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>' >/dev/null
assert_not_ancestor "$IC" "$MCW23" "$KCW23"
assert_not_ancestor "$IC" "$MCW23" "ironclaw-v0.29.1"
assert_ancestor "$IC" "$KCW23" "ironclaw-v0.29.1"
assert_not_ancestor "$IC" "$FCW23" "ironclaw-v0.29.1"
assert_ancestor "$IC" "$FCW23" "ironclaw-v1.0.0"
sm=$("${git_cmd[@]}" -C "$IC" rev-parse "${MCW23}:src/tools/builtin/shell.rs")
sk=$("${git_cmd[@]}" -C "$IC" rev-parse "${KCW23}:src/tools/builtin/shell.rs")
s29=$("${git_cmd[@]}" -C "$IC" rev-parse "ironclaw-v0.29.1:src/tools/builtin/shell.rs")
if [[ $sm == "$sk" || $sm == "$s29" || $sk == "$s29" ]]; then
  printf 'ironclaw shell.rs blobs unexpectedly equal\n' >&2
  exit 1
fi

# GHSA-F7FH
"${git_cmd[@]}" -C "$OC" cat-file -e "${CF7FH}"'^{commit}'
bodyf=$("${git_cmd[@]}" -C "$OC" log -1 --format='%B' "$CF7FH")
printf '%s\n' "$bodyf" | grep -F 'Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>' >/dev/null
parent_cdp=$("${git_cmd[@]}" -C "$OC" show "${CF7FH}"'^:src/browser/cdp.ts')
cand_cdp=$("${git_cmd[@]}" -C "$OC" show "${CF7FH}:src/browser/cdp.ts")
printf '%s\n' "$parent_cdp" | grep -F '/json/version' >/dev/null
printf '%s\n' "$cand_cdp" | grep -F 'isWebSocketUrl' >/dev/null
if printf '%s\n' "$parent_cdp" | grep -F 'isWebSocketUrl' >/dev/null; then
  printf 'f7fh parent unexpectedly already has isWebSocketUrl\n' >&2
  exit 1
fi
peel45=$("${git_cmd[@]}" -C "$OC" rev-parse 'v2026.4.5^{commit}')
[[ $peel45 == 3e72c0352dde84a0bcb3aabafa99c2d4b12d1c46 ]]
assert_ancestor "$OC" "$CF7FH" "v2026.4.1"
assert_not_ancestor "$OC" "$FF7FH" "v2026.4.1"
assert_ancestor "$OC" "$FF7FH" "v2026.4.5"
fixdiff=$("${git_cmd[@]}" -C "$OC" diff "${FF7FH}"'^' "$FF7FH" -- extensions/browser/src/browser/cdp.ts)
printf '%s\n' "$fixdiff" | grep -F 'assertCdpEndpointAllowed' >/dev/null

# GHSA-X34R
"${git_cmd[@]}" -C "$LR" cat-file -e "${MX34R}"'^{commit}'
bodyx=$("${git_cmd[@]}" -C "$LR" log -1 --format='%B' "$MX34R")
printf '%s\n' "$bodyx" | grep -F 'Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>' >/dev/null
filesx=$("${git_cmd[@]}" -C "$LR" diff-tree --no-commit-id --name-only -r "$MX34R")
[[ $filesx == 'langroid/agent/special/table_chat_agent.py' ]]
pm=$("${git_cmd[@]}" -C "$LR" rev-parse "${MX34R}:langroid/utils/pandas_utils.py")
pp=$("${git_cmd[@]}" -C "$LR" rev-parse "${MX34R}"'^:langroid/utils/pandas_utils.py')
[[ $pm == "$pp" ]]
assert_not_ancestor "$LR" "$MX34R" "$KX34R"
assert_not_ancestor "$LR" "$MX34R" "0.59.31"
assert_ancestor "$LR" "$KX34R" "0.59.31"
assert_not_ancestor "$LR" "$FX34R" "0.59.31"
assert_ancestor "$LR" "$FX34R" "0.59.32"
p31=$("${git_cmd[@]}" -C "$LR" show '0.59.31:langroid/utils/pandas_utils.py')
p32=$("${git_cmd[@]}" -C "$LR" show '0.59.32:langroid/utils/pandas_utils.py')
if printf '%s\n' "$p31" | grep -F 'visit_Attribute' >/dev/null; then
  printf '0.59.31 unexpectedly already has visit_Attribute\n' >&2
  exit 1
fi
printf '%s\n' "$p32" | grep -F 'visit_Attribute' >/dev/null

printf 'REPLAY_OK reviewed=8 PASS_proposal=0 NARROW=8 REJECT=0 UNKNOWN=0 BLOCKED=0\n'
