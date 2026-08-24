#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-nearpass-release5-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# PASS is a proposal only. This script does not admit any row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-nearpass-release5-grok46-xhigh
OC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/openclaw
GP=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/gitpython
CC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/churchcrm
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database

C2X93=b75ad800a59009fc47eaa3471410f69046150e59
F2X93=06047005ef7dedda5ea655f52117e8aaa1cca373
C9C3V=47eb2d48d43452afc4b0160e40a2630e4a38a0ff
F9C3V=3c6259ebb70c76523a7b3fb7cfdac2e40a7f7449
CWP73=6c918ca85fc6256a309ca0a737d7729059b34e1e
FWP73=797bcd5bdb28cd8bab4f5385f4515467e42bfcfd
CV396=c9a26789d88b18f8b4620f37307df2976292d2a0
HV396=142195888e713542189533a52cdfc333f05c3af6
FV396=56806080c1348749b07daa4a2024ce47b3cad285
MF2FQ=cbea916e77e2d8cbe34f04efdd00792e3af27e2c
CF2FQ=1bfc187ac41238a2488d58f06361d7377d3cdf11
FF2FQ=07be35d7fdaae872f2f6ff404779368f201fe8b5
UF2FQ=32599b3d5975f95a5dfa09847855bfdd085b07fb

PEEL_522=a374c3a5bfd5225ce319bce3865aab6216309c4f
PEEL_526=10ad3aa16068baa84a1bd9ac4f7d42ae725cedb7
PEEL_61=2e08f0f4221f522b60423ed6ffd83427942b28de
PEEL_65=5181e4f7c82bd373cb215a5619b0fa03c13862b7
PEEL_BETA=9c7e67b0f8247dbd81b6610bc1bd9a1a4d4a1256
PEEL_3150=5a294a6fc7ed5dc0946d4b576257bf926178f269
PEEL_3151=7b0764d309334b0f27f503d7fa1a395cbd165de0
PEEL_751=9ee9c00c6ea99582a7d65b5d1d8c6197b51a77a8
PEEL_760=9b5993c0918ce45522e57f28114929ac75a29b9b

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
require_dir "$GP/.git"
require_dir "$CC/.git"
require_dir "$ADV/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected-5.jsonl"
require_file "$OWNED/report.md"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/ledger.jsonl" \
  3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9
expect_hash "$OWNED/selected-5.jsonl" \
  e755f022b603d628c6452330ba142dcb714d043f5b27cf6833d5f0977676a3bf
expect_hash "$OWNED/cases.jsonl" \
  944770da6bb59078e7bd020d436e381f3b60357aa94cbbb974d1bf77f645d186
expect_hash "$OWNED/report.md" \
  295f7b7b4d4edc464db926d97c1dd0ca01466e63f87648684be81a45950ebe0c
expect_hash "$OWNED/work/uniqueness.json" \
  ca49d7036f81ff3ef06f7f337c71ed8766a323fad63a4a4c2cc80580d91ac806
expect_hash "$OWNED/work/pages/npm/openclaw.wanted.json" \
  bcbc284c3927d763c6ee4ad3d5159551c91e2e2912070f1670f24ea58c2480c1
expect_hash "$OWNED/work/pages/pypi/GitPython.wanted.json" \
  68b58bd2fdd51dbe5a63edc104ab00523e0ab7f594427be84c36c2f56e2e0901
expect_hash "$OWNED/work/pages/ghsa/GHSA-2x93-h3hg-2xfp.json" \
  2218b50c8a811e2f609d256cc18fa9a5c1ecabca78a58f10ea7977e8a8392684
expect_hash "$OWNED/work/pages/ghsa/GHSA-9c3v-684m-579c.json" \
  fc57c220cf9348b0ae80a8284a3c1aef2a16726d4ae17599f02413bcb1600ad0
expect_hash "$OWNED/work/pages/ghsa/GHSA-f2fq-4rmp-9x8c.json" \
  2218b50c8a811e2f609d256cc18fa9a5c1ecabca78a58f10ea7977e8a8392684
expect_hash "$OWNED/work/pages/ghsa/GHSA-v396-v7q4-x2qj.json" \
  074df4b416de8c8e627e1f8971c6d364dbf49568717155f0af6175010eb3291b
expect_hash "$OWNED/work/pages/ghsa/GHSA-wp73-f3gg-w4vr.json" \
  2218b50c8a811e2f609d256cc18fa9a5c1ecabca78a58f10ea7977e8a8392684
expect_hash "$OWNED/work/pages/repo-advisory/openclaw__openclaw__GHSA-2x93-h3hg-2xfp.json" \
  854776ca719788e0ce94d3cc49726f484c9f6758a2a9689654e59a47fe416210
expect_hash "$OWNED/work/pages/repo-advisory/openclaw__openclaw__GHSA-9c3v-684m-579c.json" \
  cc5002e81af4b7e300e31c66f97da80e91c17c86e136f24a34daf89c47062b94
expect_hash "$OWNED/work/pages/repo-advisory/openclaw__openclaw__GHSA-wp73-f3gg-w4vr.json" \
  a5eaf2c0327fbc8c7607684208010e81dad8d6698ef1ede420a3d2b74f979743
expect_hash "$OWNED/work/pages/repo-advisory/ChurchCRM__CRM__GHSA-f2fq-4rmp-9x8c.json" \
  f447b081d4462570c10798f454880211865656c7c0deb58a449b7450fea19dd9
expect_hash "$OWNED/work/pages/repo-advisory/gitpython-developers__GitPython__GHSA-v396-v7q4-x2qj.json" \
  47b418d3693b1aca5ee1ef0eccc83577210d78819e1b84401b25c2bb0d504e83

[[ "$("${git_cmd[@]}" -C "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]

python3 - "$OWNED" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected-5.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 5, len(rows)
assert len(sel) == 5, len(sel)
want = [
    "GHSA-2X93-H3HG-2XFP",
    "GHSA-9C3V-684M-579C",
    "GHSA-F2FQ-4RMP-9X8C",
    "GHSA-V396-V7Q4-X2QJ",
    "GHSA-WP73-F3GG-W4VR",
]
assert [r["case_id"] for r in rows] == want
assert [r["case_id"] for r in sel] == want
assert all(r["worker_verdict"] == "NARROW" for r in rows)
assert all(r["verdict"] == "NARROW" for r in rows)
assert all(r["causal_admission"] is False for r in rows)
assert all(r["countable"] is False for r in rows)
assert all(r["countable_proposal"] is False for r in rows)
assert all(r["publication_status"] == "HOLD" for r in rows)
assert all(r["worker_pass_is_proposal_only"] is True for r in rows)
assert all(r["identity_gate"] == "PASS" and r["gates"]["identity_gate"] == "PASS" for r in rows)
assert all(r["uniqueness_gate"] == "PASS" and r["gates"]["uniqueness_gate"] == "PASS" for r in rows)
assert all(r["ai_hunk_gate"] == "PASS" for r in rows)
assert all(r["contribution_class"] == "AI_INCOMPLETE_REMEDIATION" for r in rows)
by = {r["case_id"]: r for r in rows}
assert by["GHSA-2X93-H3HG-2XFP"]["release_gate"] == "PASS"
assert by["GHSA-9C3V-684M-579C"]["release_gate"] == "PASS"
assert by["GHSA-V396-V7Q4-X2QJ"]["release_gate"] == "PASS"
assert by["GHSA-F2FQ-4RMP-9X8C"]["release_gate"] == "NARROW"
assert by["GHSA-WP73-F3GG-W4VR"]["release_gate"] == "NARROW"
assert by["GHSA-2X93-H3HG-2XFP"]["but_for_gate"] == "NARROW"
assert by["GHSA-9C3V-684M-579C"]["but_for_gate"] == "NARROW"
assert by["GHSA-V396-V7Q4-X2QJ"]["but_for_gate"] == "NARROW"
assert by["GHSA-WP73-F3GG-W4VR"]["but_for_gate"] == "NARROW"
assert by["GHSA-F2FQ-4RMP-9X8C"]["topology_gate"] == "NARROW"
assert by["GHSA-2X93-H3HG-2XFP"]["repository"] == "openclaw/openclaw"
assert by["GHSA-9C3V-684M-579C"]["repository"] == "openclaw/openclaw"
assert by["GHSA-WP73-F3GG-W4VR"]["repository"] == "openclaw/openclaw"
assert by["GHSA-F2FQ-4RMP-9X8C"]["repository"] == "ChurchCRM/CRM"
assert by["GHSA-V396-V7Q4-X2QJ"]["repository"] == "gitpython-developers/GitPython"
keys = {r["mechanism_key"] for r in rows}
assert len(keys) == 5
han = re.compile(r"[\u3400-\u9fff]")
for name in ("cases.jsonl", "selected-5.jsonl", "report.md", "replay.sh"):
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
g404 = json.loads((owned / "work/pages/ghsa/GHSA-2x93-h3hg-2xfp.json").read_text())
assert g404["message"] == "Not Found"
g9 = json.loads((owned / "work/pages/ghsa/GHSA-9c3v-684m-579c.json").read_text())
assert g9["ghsa_id"].lower() == "ghsa-9c3v-684m-579c"
assert g9.get("withdrawn_at") is None
r2 = json.loads((owned / "work/pages/repo-advisory/openclaw__openclaw__GHSA-2x93-h3hg-2xfp.json").read_text())
assert r2["state"] == "published" and r2["withdrawn_at"] is None
rf = json.loads((owned / "work/pages/repo-advisory/ChurchCRM__CRM__GHSA-f2fq-4rmp-9x8c.json").read_text())
assert rf["state"] == "published" and rf["withdrawn_at"] is None
npm = json.loads((owned / "work/pages/npm/openclaw.wanted.json").read_text())
for v in ("2026.4.14", "2026.5.22", "2026.5.26", "2026.6.1", "2026.6.5", "2026.5.10-beta.1"):
    assert npm["wanted"][v]["in_versions"] is True
    assert npm["wanted"][v]["dist_tarball"]
pypi = json.loads((owned / "work/pages/pypi/GitPython.wanted.json").read_text())
assert pypi["wanted"]["3.1.50"]["n_files"] == 2
assert pypi["wanted"]["3.1.51"]["n_files"] == 2
assert pypi["wanted"]["3.1.50"]["yanked"] == [False, False]
print("conservation assigned=5 reviewed=5 unreviewed=0 PASS_proposal=0 NARROW=5 REJECT=0 UNKNOWN=0 BLOCKED=0")
PY

# GHSA-2X93
"${git_cmd[@]}" -C "$OC" cat-file -e "$C2X93^{commit}"
csubj=$("${git_cmd[@]}" -C "$OC" log -1 --format='%s' "$C2X93")
[[ $csubj == 'fix(browser): enforce SSRF policy on snapshot, screenshot, and tab routes [AI] (#66040)' ]]
cpc=$("${git_cmd[@]}" -C "$OC" log -1 --format='%P' "$C2X93")
[[ $cpc == 55a3c8ea07aef2b0f7833b2a954d8a425d32cb7d ]]
fsubj=$("${git_cmd[@]}" -C "$OC" log -1 --format='%an %s' "$F2X93")
[[ $fsubj == 'Agustin Rivera fix(browser): validate current tab before snapshots (#78526)' ]]
peel522=$("${git_cmd[@]}" -C "$OC" rev-parse 'v2026.5.22^{commit}')
peel526=$("${git_cmd[@]}" -C "$OC" rev-parse 'v2026.5.26^{commit}')
[[ $peel522 == "$PEEL_522" ]]
[[ $peel526 == "$PEEL_526" ]]
pkg522=$("${git_cmd[@]}" -C "$OC" show 'v2026.5.22:package.json' | python3 -c 'import sys,json; print(json.load(sys.stdin)["version"])')
pkg526=$("${git_cmd[@]}" -C "$OC" show 'v2026.5.26:package.json' | python3 -c 'import sys,json; print(json.load(sys.stdin)["version"])')
[[ $pkg522 == 2026.5.22 ]]
[[ $pkg526 == 2026.5.26 ]]
assert_ancestor "$OC" "$C2X93" "v2026.5.22"
assert_not_ancestor "$OC" "$F2X93" "v2026.5.22"
assert_ancestor "$OC" "$F2X93" "v2026.5.26"
assert_ancestor "$OC" "$C2X93" "v2026.4.14"
"${git_cmd[@]}" -C "$OC" cat-file -e "${C2X93}^:extensions/browser/src/browser/routes/agent.snapshot.ts"

# GHSA-9C3V
"${git_cmd[@]}" -C "$OC" cat-file -e "$C9C3V^{commit}"
s9=$("${git_cmd[@]}" -C "$OC" log -1 --format='%s' "$C9C3V")
[[ $s9 == 'Scrub streamable MCP redirect headers [AI] (#80906)' ]]
peel61=$("${git_cmd[@]}" -C "$OC" rev-parse 'v2026.6.1^{commit}')
peel65=$("${git_cmd[@]}" -C "$OC" rev-parse 'v2026.6.5^{commit}')
[[ $peel61 == "$PEEL_61" ]]
[[ $peel65 == "$PEEL_65" ]]
assert_ancestor "$OC" "$C9C3V" "v2026.6.1"
assert_not_ancestor "$OC" "$F9C3V" "v2026.6.1"
assert_ancestor "$OC" "$F9C3V" "v2026.6.5"
parent_sse=$("${git_cmd[@]}" -C "$OC" show "${C9C3V}^:src/agents/mcp-transport.ts")
cand_sse=$("${git_cmd[@]}" -C "$OC" show "${C9C3V}:src/agents/mcp-transport.ts")
printf '%s\n' "$parent_sse" | grep -F 'new SSEClientTransport' >/dev/null
printf '%s\n' "$cand_sse" | grep -F 'STREAMABLE_HTTP_MAX_REDIRECTS' >/dev/null
printf '%s\n' "$cand_sse" | grep -F 'new SSEClientTransport' >/dev/null

# GHSA-WP73
"${git_cmd[@]}" -C "$OC" cat-file -e "$CWP73^{commit}"
sw=$("${git_cmd[@]}" -C "$OC" log -1 --format='%s' "$CWP73")
[[ $sw == 'Inherit tool restrictions for delegated sessions [AI] (#80979)' ]]
peel_beta=$("${git_cmd[@]}" -C "$OC" rev-parse 'v2026.5.10-beta.1^{commit}')
[[ $peel_beta == "$PEEL_BETA" ]]
assert_not_ancestor "$OC" "$CWP73" "v2026.5.10-beta.1"
assert_ancestor "$OC" "$CWP73" "v2026.6.1"
assert_not_ancestor "$OC" "$FWP73" "v2026.6.1"
assert_ancestor "$OC" "$FWP73" "v2026.6.5"
files_w=$("${git_cmd[@]}" -C "$OC" diff-tree --no-commit-id --name-only -r "$CWP73")
if printf '%s\n' "$files_w" | grep -qi clickclack; then
  printf 'wp73 candidate unexpectedly edits clickclack\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$OC" cat-file -e "${CWP73}:extensions/clickclack/src/inbound.ts"
in_cand=$("${git_cmd[@]}" -C "$OC" show "${CWP73}:extensions/clickclack/src/inbound.ts")
if printf '%s\n' "$in_cand" | grep -F 'toolsAllow' >/dev/null; then
  printf 'wp73 candidate inbound already has toolsAllow\n' >&2
  exit 1
fi
in_fix=$("${git_cmd[@]}" -C "$OC" show "${FWP73}:extensions/clickclack/src/inbound.ts")
printf '%s\n' "$in_fix" | grep -F 'toolsAllow: params.account.toolsAllow' >/dev/null

# GHSA-V396
"${git_cmd[@]}" -C "$GP" cat-file -e "$CV396^{commit}"
sv=$("${git_cmd[@]}" -C "$GP" log -1 --format='%an %ae %s' "$CV396")
[[ $sv == 'GPT 5.4 codex@openai.com Make sure that multi-options are checked after splitting them with `shlex`' ]]
cmd_p=$("${git_cmd[@]}" -C "$GP" rev-parse "${CV396}^:git/cmd.py")
cmd_c=$("${git_cmd[@]}" -C "$GP" rev-parse "${CV396}:git/cmd.py")
[[ $cmd_p == "$cmd_c" ]]
cand_check=$("${git_cmd[@]}" -C "$GP" show "${CV396}:git/cmd.py")
printf '%s\n' "$cand_check" | grep -F 'option.startswith(unsafe_option)' >/dev/null
human_an=$("${git_cmd[@]}" -C "$GP" log -1 --format='%an <%ae>' "$HV396")
[[ $human_an == 'w <w@mac.lan>' ]]
hbody=$("${git_cmd[@]}" -C "$GP" log -1 --format='%B' "$HV396")
if printf '%s\n' "$hbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT|codex@openai'; then
  printf 'human matcher unexpectedly has AI marker\n' >&2
  exit 1
fi
peel3150=$("${git_cmd[@]}" -C "$GP" rev-parse '3.1.50^{commit}')
peel3151=$("${git_cmd[@]}" -C "$GP" rev-parse '3.1.51^{commit}')
[[ $peel3150 == "$PEEL_3150" ]]
[[ $peel3151 == "$PEEL_3151" ]]
assert_ancestor "$GP" "$CV396" "3.1.50"
assert_ancestor "$GP" "$HV396" "3.1.50"
assert_not_ancestor "$GP" "$FV396" "3.1.50"
assert_ancestor "$GP" "$FV396" "3.1.51"
assert_ancestor "$GP" "$CV396" "3.1.47"
tag3150_cmd=$("${git_cmd[@]}" -C "$GP" show '3.1.50:git/cmd.py')
printf '%s\n' "$tag3150_cmd" | grep -F '_canonicalize_option_name' >/dev/null
if printf '%s\n' "$tag3150_cmd" | grep -F 'option.startswith(unsafe_option)' >/dev/null; then
  printf '3.1.50 unexpectedly still uses startswith matcher\n' >&2
  exit 1
fi
fix_check=$("${git_cmd[@]}" -C "$GP" show "${FV396}:git/cmd.py")
printf '%s\n' "$fix_check" | grep -F 'unsafe_short_options' >/dev/null

# GHSA-F2FQ
"${git_cmd[@]}" -C "$CC" cat-file -e "$MF2FQ^{commit}"
mbody=$("${git_cmd[@]}" -C "$CC" log -1 --format='%B' "$MF2FQ")
printf '%s\n' "$mbody" | grep -F 'Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>' >/dev/null
cbody=$("${git_cmd[@]}" -C "$CC" log -1 --format='%B' "$CF2FQ")
if printf '%s\n' "$cbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT|codex@openai'; then
  printf 'churchcrm carrier unexpectedly has AI marker\n' >&2
  exit 1
fi
mp=$("${git_cmd[@]}" -C "$CC" log -1 --format='%P' "$MF2FQ")
cp=$("${git_cmd[@]}" -C "$CC" log -1 --format='%P' "$CF2FQ")
[[ $mp == 1b29acf2500fd15c84b399830ef6c5e861e8800c ]]
[[ $cp == 1b29acf2500fd15c84b399830ef6c5e861e8800c ]]
assert_not_ancestor "$CC" "$MF2FQ" "$CF2FQ"
member_tags=$("${git_cmd[@]}" -C "$CC" tag --contains "$MF2FQ")
if [[ -n $member_tags ]]; then
  printf 'churchcrm member unexpectedly contained in tags\n' >&2
  exit 1
fi
peel751=$("${git_cmd[@]}" -C "$CC" rev-parse '7.5.1^{commit}')
peel760=$("${git_cmd[@]}" -C "$CC" rev-parse '7.6.0^{commit}')
[[ $peel751 == "$PEEL_751" ]]
[[ $peel760 == "$PEEL_760" ]]
assert_ancestor "$CC" "$CF2FQ" "7.5.1"
assert_not_ancestor "$CC" "$MF2FQ" "7.5.1"
assert_not_ancestor "$CC" "$FF2FQ" "7.5.1"
assert_ancestor "$CC" "$FF2FQ" "7.6.0"
assert_not_ancestor "$CC" "$UF2FQ" "7.6.0"
blob_m=$("${git_cmd[@]}" -C "$CC" rev-parse "${MF2FQ}:src/api/routes/public/public-user.php")
blob_c=$("${git_cmd[@]}" -C "$CC" rev-parse "${CF2FQ}:src/api/routes/public/public-user.php")
blob_751=$("${git_cmd[@]}" -C "$CC" rev-parse "7.5.1:src/api/routes/public/public-user.php")
[[ $blob_m == 74e9d89029ffd307d5ddd45054da4e2a1957a43f ]]
[[ $blob_c == abf31119e42922898d9748866eb1dd9bd4eb59a8 ]]
[[ $blob_751 == 25e8219b790c0d309a88f9bd1285bb6dc43e99b6 ]]
if [[ $blob_m == "$blob_c" || $blob_m == "$blob_751" || $blob_c == "$blob_751" ]]; then
  printf 'churchcrm public-user blobs unexpectedly equal\n' >&2
  exit 1
fi
src751=$("${git_cmd[@]}" -C "$CC" show '7.5.1:src/api/routes/public/public-user.php')
src760=$("${git_cmd[@]}" -C "$CC" show '7.6.0:src/api/routes/public/public-user.php')
printf '%s\n' "$src751" | grep -F 'API login: invalid 2FA code' >/dev/null
if printf '%s\n' "$src751" | grep -F 'Count OTP failures toward account lockout' >/dev/null; then
  printf '7.5.1 unexpectedly already counts OTP failures\n' >&2
  exit 1
fi
printf '%s\n' "$src760" | grep -F 'Count OTP failures toward account lockout' >/dev/null

python3 - "$OC" "$GP" "$CC" << 'PY'
import re, subprocess, sys
pat = re.compile(
    r"Co-authored-by:.*(Claude|Cursor Agent|Copilot|ChatGPT|OpenAI|Anthropic)|"
    r"Generated with Claude|noreply@anthropic|codex@openai.com|\[AI\]",
    re.I,
)
git = ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]
# Closers that must not be the counted AI origin.
scans = [
    (sys.argv[1], "06047005ef7dedda5ea655f52117e8aaa1cca373"),
    (sys.argv[1], "3c6259ebb70c76523a7b3fb7cfdac2e40a7f7449"),
    (sys.argv[1], "797bcd5bdb28cd8bab4f5385f4515467e42bfcfd"),
    (sys.argv[2], "142195888e713542189533a52cdfc333f05c3af6"),
    (sys.argv[3], "1bfc187ac41238a2488d58f06361d7377d3cdf11"),
    (sys.argv[3], "07be35d7fdaae872f2f6ff404779368f201fe8b5"),
]
for repo, sha in scans:
    rec = subprocess.check_output(
        git + ["-C", repo, "log", "-1", "--format=%H%x1f%an%x1f%s%x1f%b", sha],
        text=True,
        errors="replace",
    )
    assert not pat.search(rec), (sha, rec[:200])
print("closer_ai_trailer_scan_empty")
PY

printf 'REPLAY_OK reviewed=5 PASS_proposal=0 NARROW=5 REJECT=0 UNKNOWN=0 BLOCKED=0\n'
