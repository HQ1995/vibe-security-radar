#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-increm20f-blocked7-recovery-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# PASS is a proposal only. This script does not admit any row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-increm20f-blocked7-recovery-grok46-xhigh
CACHE=/home/hanqing/.cache/ghsa200-worker-clones/recovery20f-260814
XC=$CACHE/node-saml__xml-crypto
FV=$CACHE/DavidOsipov__PostQuantum-Feldman-VSS
CZ=$CACHE/corazawaf__coraza
BG=$CACHE/beego__beego
WF=$CACHE/canonical__get-workflow-version-action
AP=$CACHE/api-platform__core
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database

XC_V3=28f92218ecbb8dcbd238afa4efbbd50302aa9aed
XC_V2=886dc63a8b4bb5ae1db9f41c7854b171eb83aa98
XC_V6=8ac6118ee7978b46aa56b82cbcaa5fca58c93a07
XC_V320=777e15779b6002df0f2c65376baaea88621048f7
XC_V321=92bbddf6b986ab1bfeda6841339161dd599aa31a
XC_V215=701616302d6f0ec752646632203b3dab717751c0
XC_V216=5d260884f48e6bc3050a7d14be13c79a5e9acdec
XC_V600=0ed7ab2681af7e13defa055f5670bad9adad927b
XC_V601=d80e5b77ade2f72225a2f324d5b54d20f4f4e396
XC_BLOB_V320=ac3dd51fefce994c02f9b7364c203a1ee7f1571b
XC_BLOB_V321=190ddc755839ab750434cd8978d07a9fd9ee50fd
XC_BLOB_V600=e5d80af70c596e7637d8e9d484fa75c547b5289f
XC_BLOB_V601=4f6d11ec8f51836811a6bcd7ef4e87dd3bc59653
XC_FILE_V3=lib/signed-xml.js
XC_FILE_V6=src/signed-xml.ts

FV_076=40ffb4b3a7342229b116285453463569184f3488
FV_080B2=36d6fb742bd3008848bc5b7eb0588dd034f4b07e
FV_MEM=9d814d0bded6654d9998644185b6e08b750bdc06

CZ_FIX=4722c9ad0d502abd56b8d6733c6b47eb4111742d
CZ_PARENT=8b612f4e6e18c606e371110227bc7669dc714cab
CZ_V332=f4de57c3a4fc05a7ad1f09f9fdc4b9b2b7d22cb3
CZ_FILE=internal/corazawaf/transaction.go
CZ_BLOB_P=8264c7e6731209018dbb14187ab712ad788248a1
CZ_BLOB_F=67ecfab05e42ef2dad8ee7d00c95ad192f5973a1

BG_FIX=939bb18c66406466715ddadd25dd9ffa6f169e25
BG_PARENT=1f40a88b0ccc861dee094371aeeb29a3f70a2ee6
BG_V235=5e9c913b47dce0155e05637d4e195b87d3cdf75f
BG_V236=5fa33bc11b947d0ddd0f68eb0cb8903741900f00
BG_FILE=server/web/templatefunc.go
BG_BLOB_P=f7cce06a3f6481625d2d3439ff3c75f8c95e4f2e
BG_BLOB_F=ba2cc543a51e9df7773b08a3bcc349c6e6b61559

WF_FIX=88281a62e96e1c0ef4df30352ae0668a9f3e3369
WF_PARENT=a5d53b08d254a157ea441c9819ea5002ffc12edc
WF_FILE=get_workflow_version/main.py
WF_BLOB_P=8d22fd9669100499ef9a85fdf24447e877deb881
WF_BLOB_F=07f0eb118f96bc8cda4f001d55054a81c3adddb9

AP_557=55712452b4f630978537bdb2a07dc958202336bb
AP_607=60747cc8c2fb855798c923b5537888f8d0969568
AP_V3416=64c6e1092cf988ba619907b3e4cce8a229ce4fae
AP_V3417=c5fb664d17ed9ae919394514ea69a5039d2ad9ab
AP_V4021=4acec639046f6539d3fc00abb833ba2c3a3292cf
AP_V4022=8de9bf87f20a31f74102247cb8d75583797c6593
AP_V414=c636d980a70de9fd274fafcbfe9ea3cfbb8d4e9a
AP_V415=2a765275d5df404def9fdb630f61d6fd035185b1
AP_FILE=src/GraphQl/Resolver/Factory/ResolverFactory.php
AP_BLOB_P=c7ba03283ee64a36b5e81a610b551346fab2344b
AP_BLOB_F=1aca8b41babd5ba7d0cd8eea5ea6c698ad733e50

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
require_dir "$XC/.git"
require_dir "$FV/.git"
require_dir "$CZ/.git"
require_dir "$BG/.git"
require_dir "$WF/.git"
require_dir "$AP/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/baseline.json" \
  d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/ledger.jsonl" \
  3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20f-grok46-low/cases.jsonl" \
  a73cd687ae297db41c830537e88826bed56578528e9fce1f3816c9fb55701d51
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20f-grok46-low/result.json" \
  810da7b6e1b8c233a5d346596913f52de529260acc01dec84793c26187710dc6
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20f-grok46-low/work/freeze.json" \
  f57ecbed9f8fd140648f64dc1fd4af3191f2484c51e89511f04edd980ccdf6c7
expect_hash "$OWNED/cases.jsonl" \
  bcafe94970b7170457119c4771951a3ca3484133a3cfff284104c726a7973ab1
expect_hash "$OWNED/report.md" \
  7cabea54a3733faae99ac3fc400288f340533fa5507eb1e9b97e57d5a5950fa7
expect_hash "$OWNED/work/pages/advisory/GHSA-9p8x-f768-wp2g.json" \
  be8d0d9afb07f30a5b8f1488fbb2ea37ca20817ab6937d66fc860f9f3eaf8499
expect_hash "$OWNED/work/pages/advisory/GHSA-x3m8-899r-f7c3.json" \
  a3125c23f8f1e7d1d1816d89259ebc3e13c1f2ef349c63f3a0c38332d7dde8c1
expect_hash "$OWNED/work/pages/advisory/GHSA-v432-7f47-9g94.json" \
  d8eac7daba2c6ff7fa28bbeae2af06e8e7b8265692e1bb32981be73f39b6aff6
expect_hash "$OWNED/work/pages/advisory/GHSA-q9f5-625g-xm39.json" \
  a521dd344dcedcad379d59d8b2127a2fdf65b8c41ada6992f133dbeeb92d5bdd
expect_hash "$OWNED/work/pages/advisory/GHSA-2j42-h78h-q4fg.json" \
  ee559e28b8b3871c0e9b09a7dfce58a7de3773c045fcba8ad717e83ae94b69fc
expect_hash "$OWNED/work/pages/advisory/GHSA-26wh-cc3r-w6pj.json" \
  e0f87838430c713658175b4ac45174bb2182549f3f5efbd05e8b4865a4ee7766
expect_hash "$OWNED/work/pages/advisory/GHSA-cg3c-245w-728m.json" \
  df5713a03a425f8ba66a4aa98dd3021255adf0ed107990a2773d8a8444929fd4
expect_hash "$OWNED/work/pages/ghsa/GHSA-9p8x-f768-wp2g.json" \
  99e0a3daeda1c336719b7785fa7b29abb710a747f009497ba580a270d0d2cf0a
expect_hash "$OWNED/work/pages/ghsa/GHSA-x3m8-899r-f7c3.json" \
  aadcc2615ecaef40022c41705202805fc815fe4838ae37230092fd5c6a26e3c9
expect_hash "$OWNED/work/pages/ghsa/GHSA-v432-7f47-9g94.json" \
  80224a51a63078b6d184879bb6e695e9028582355248d7ee687d86e39bb24a57
expect_hash "$OWNED/work/pages/ghsa/GHSA-q9f5-625g-xm39.json" \
  5b0bd8ce9fbcf9b1e66f9705307e3554235d037cc58e169ba7f930c96a88c1f0
expect_hash "$OWNED/work/pages/ghsa/GHSA-2j42-h78h-q4fg.json" \
  3fa8f9dac5ff1af6f377fbe6bea61fe9df258e67ab60406014daf1bd4015b923
expect_hash "$OWNED/work/pages/ghsa/GHSA-26wh-cc3r-w6pj.json" \
  9de311dd6d313810753a5d856c309a7132500d4667f2b133083714744a56417a
expect_hash "$OWNED/work/pages/ghsa/GHSA-cg3c-245w-728m.json" \
  e70338a0765e17554ccc0447ee9ad94255c0355dcedfffa8d54ccaab75fa0527

[[ "$("${git_cmd[@]}" -C "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]

python3 - "$OWNED" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  "$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20f-grok46-low/cases.jsonl" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 7, len(rows)
want = [
    "GHSA-9P8X-F768-WP2G",
    "GHSA-X3M8-899R-F7C3",
    "GHSA-V432-7F47-9G94",
    "GHSA-Q9F5-625G-XM39",
    "GHSA-2J42-H78H-Q4FG",
    "GHSA-26WH-CC3R-W6PJ",
    "GHSA-CG3C-245W-728M",
]
assert [r["case_id"] for r in rows] == want
src = [json.loads(l) for l in Path(sys.argv[3]).read_text().splitlines() if l.strip()]
src_ids = [r["case_id"] for r in src if r["case_id"] in set(want)]
assert src_ids == want
assert all(r.get("worker_verdict") == "BLOCKED" for r in src if r["case_id"] in set(want))
for r in rows:
    assert r["verdict"] == "REJECT"
    assert r["worker_verdict"] == "REJECT"
    assert r["causal_admission"] is False
    assert r["countable"] is False
    assert r["countable_proposal"] is False
    assert r["publication_status"] == "HOLD"
    assert r["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    assert r["identity_gate"] == "PASS" and r["gates"]["identity_gate"] == "PASS"
    assert r["uniqueness_gate"] == "PASS" and r["gates"]["uniqueness_gate"] == "PASS"
    assert r["ai_hunk_gate"] == "FAIL"
    assert r["remediation_patch_delta"] == "FAIL"
    for g in ("topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate"):
        assert r[g] == "FAIL" and r["gates"][g] == "FAIL"
        assert r[g] != "BLOCKED"
    assert r["verdict"] != "PASS"
    assert r["verdict"] != "KEEP"
han = re.compile(r"[\u3400-\u9fff]")
for name in ("cases.jsonl", "report.md", "replay.sh"):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert not han.search(text), name
c81 = json.loads(Path(sys.argv[2]).read_text())
cids = {x.upper() for x in c81["strict_released_case_ids"]}
assert len(c81["strict_released_case_ids"]) == 81
for i in want:
    assert i not in cids
adv9 = json.loads((owned / "work/pages/advisory/GHSA-9p8x-f768-wp2g.json").read_text())
assert adv9["id"] == "GHSA-9p8x-f768-wp2g"
assert adv9["affected"][0]["package"]["name"] == "xml-crypto"
g9 = json.loads((owned / "work/pages/ghsa/GHSA-9p8x-f768-wp2g.json").read_text())
assert g9["ghsa_id"] == "GHSA-9p8x-f768-wp2g"
assert g9["withdrawn_at"] is None
assert g9["source_code_location"] == "https://github.com/node-saml/xml-crypto"
gx = json.loads((owned / "work/pages/ghsa/GHSA-x3m8-899r-f7c3.json").read_text())
assert gx["source_code_location"] == "https://github.com/node-saml/xml-crypto"
assert gx["cve_id"] == "CVE-2025-29775"
assert g9["cve_id"] == "CVE-2025-29774"
gv = json.loads((owned / "work/pages/ghsa/GHSA-v432-7f47-9g94.json").read_text())
assert gv["source_code_location"] == "https://github.com/DavidOsipov/PostQuantum-Feldman-VSS"
assert gv["withdrawn_at"] is None
fp = gv["vulnerabilities"][0]["first_patched_version"]
if isinstance(fp, dict):
    fp = fp.get("identifier")
assert fp == "0.7.7b0"
gq = json.loads((owned / "work/pages/ghsa/GHSA-q9f5-625g-xm39.json").read_text())
assert gq["source_code_location"] == "https://github.com/corazawaf/coraza"
gb = json.loads((owned / "work/pages/ghsa/GHSA-2j42-h78h-q4fg.json").read_text())
assert gb["source_code_location"] == "https://github.com/beego/beego"
gw = json.loads((owned / "work/pages/ghsa/GHSA-26wh-cc3r-w6pj.json").read_text())
assert gw["source_code_location"] == "https://github.com/canonical/get-workflow-version-action"
gc = json.loads((owned / "work/pages/ghsa/GHSA-cg3c-245w-728m.json").read_text())
assert gc["source_code_location"] == "https://github.com/api-platform/core"
print("conservation assigned=7 reviewed=7 unreviewed=0 PASS_proposal=0 NARROW=0 REJECT=7 UNKNOWN=0 BLOCKED=0")
PY

# xml-crypto v3
"${git_cmd[@]}" -C "$XC" cat-file -e "$XC_V3^{commit}"
got_xparent=$("${git_cmd[@]}" -C "$XC" rev-parse "${XC_V3}^")
[[ $got_xparent == "$XC_V320" ]]
xauthor=$("${git_cmd[@]}" -C "$XC" log -1 --format='%an' "$XC_V3")
[[ $xauthor == 'Matt Dzwonczyk' ]]
xsubj=$("${git_cmd[@]}" -C "$XC" log -1 --format='%s' "$XC_V3")
[[ $xsubj == 'Merge commit from fork' ]]
xbody=$("${git_cmd[@]}" -C "$XC" log -1 --format='%B' "$XC_V3")
if printf '%s\n' "$xbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'xml-crypto v3 closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel320=$("${git_cmd[@]}" -C "$XC" rev-parse 'v3.2.0^{commit}')
peel321=$("${git_cmd[@]}" -C "$XC" rev-parse 'v3.2.1^{commit}')
[[ $peel320 == "$XC_V320" ]]
[[ $peel321 == "$XC_V321" ]]
assert_ancestor "$XC" "$XC_V3" "v3.2.1"
assert_not_ancestor "$XC" "$XC_V3" "v3.2.0"
xblob_p=$("${git_cmd[@]}" -C "$XC" rev-parse "v3.2.0:${XC_FILE_V3}")
xblob_f=$("${git_cmd[@]}" -C "$XC" rev-parse "v3.2.1:${XC_FILE_V3}")
xblob_c=$("${git_cmd[@]}" -C "$XC" rev-parse "${XC_V3}:${XC_FILE_V3}")
[[ $xblob_p == "$XC_BLOB_V320" ]]
[[ $xblob_f == "$XC_BLOB_V321" ]]
[[ $xblob_c == "$XC_BLOB_V321" ]]

# xml-crypto v2 / v6
"${git_cmd[@]}" -C "$XC" cat-file -e "$XC_V2^{commit}"
"${git_cmd[@]}" -C "$XC" cat-file -e "$XC_V6^{commit}"
v2author=$("${git_cmd[@]}" -C "$XC" log -1 --format='%an' "$XC_V2")
[[ $v2author == 'Matt Dzwonczyk' ]]
v6author=$("${git_cmd[@]}" -C "$XC" log -1 --format='%an' "$XC_V6")
[[ $v6author == 'ahacker1' ]]
v6body=$("${git_cmd[@]}" -C "$XC" log -1 --format='%B' "$XC_V6")
if printf '%s\n' "$v6body" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'xml-crypto v6 closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel216=$("${git_cmd[@]}" -C "$XC" rev-parse 'v2.1.6^{commit}')
peel215=$("${git_cmd[@]}" -C "$XC" rev-parse 'v2.1.5^{commit}')
peel601=$("${git_cmd[@]}" -C "$XC" rev-parse 'v6.0.1^{commit}')
peel600=$("${git_cmd[@]}" -C "$XC" rev-parse 'v6.0.0^{commit}')
[[ $peel216 == "$XC_V216" ]]
[[ $peel215 == "$XC_V215" ]]
[[ $peel601 == "$XC_V601" ]]
[[ $peel600 == "$XC_V600" ]]
assert_ancestor "$XC" "$XC_V2" "v2.1.6"
assert_not_ancestor "$XC" "$XC_V2" "v2.1.5"
assert_ancestor "$XC" "$XC_V6" "v6.0.1"
assert_not_ancestor "$XC" "$XC_V6" "v6.0.0"
v6blob_p=$("${git_cmd[@]}" -C "$XC" rev-parse "v6.0.0:${XC_FILE_V6}")
v6blob_f=$("${git_cmd[@]}" -C "$XC" rev-parse "v6.0.1:${XC_FILE_V6}")
[[ $v6blob_p == "$XC_BLOB_V600" ]]
[[ $v6blob_f == "$XC_BLOB_V601" ]]

# feldman
"${git_cmd[@]}" -C "$FV" cat-file -e "$FV_076^{commit}"
"${git_cmd[@]}" -C "$FV" cat-file -e "$FV_080B2^{commit}"
"${git_cmd[@]}" -C "$FV" cat-file -e "$FV_MEM^{commit}"
peel076=$("${git_cmd[@]}" -C "$FV" rev-parse 'v0.7.6-beta^{commit}')
peel080=$("${git_cmd[@]}" -C "$FV" rev-parse 'v0.8.0b2^{commit}')
[[ $peel076 == "$FV_076" ]]
[[ $peel080 == "$FV_080B2" ]]
if "${git_cmd[@]}" -C "$FV" grep -q MemoryMonitor v0.7.6-beta -- '*.py'; then
  printf 'feldman v0.7.6-beta unexpectedly has MemoryMonitor\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$FV" grep -q MemoryMonitor v0.8.0b2 -- '*.py'
fauthor=$("${git_cmd[@]}" -C "$FV" log -1 --format='%an' "$FV_MEM")
[[ $fauthor == 'DavidOsipov' ]]
fbody=$("${git_cmd[@]}" -C "$FV" log -1 --format='%B' "$FV_MEM")
if printf '%s\n' "$fbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'feldman MemoryMonitor intro unexpectedly has AI marker\n' >&2
  exit 1
fi
printf '%s\n' "$fbody" | grep -F 'Signed-off-by: DavidOsipov' >/dev/null

# coraza
"${git_cmd[@]}" -C "$CZ" cat-file -e "$CZ_FIX^{commit}"
got_cparent=$("${git_cmd[@]}" -C "$CZ" rev-parse "${CZ_FIX}^")
[[ $got_cparent == "$CZ_PARENT" ]]
cauthor=$("${git_cmd[@]}" -C "$CZ" log -1 --format='%an' "$CZ_FIX")
[[ $cauthor == 'blotus' ]]
csubj=$("${git_cmd[@]}" -C "$CZ" log -1 --format='%s' "$CZ_FIX")
[[ $csubj == 'Merge commit from fork' ]]
cbody=$("${git_cmd[@]}" -C "$CZ" log -1 --format='%B' "$CZ_FIX")
if printf '%s\n' "$cbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'coraza closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel332=$("${git_cmd[@]}" -C "$CZ" rev-parse 'v3.3.2^{commit}')
peel333=$("${git_cmd[@]}" -C "$CZ" rev-parse 'v3.3.3^{commit}')
[[ $peel332 == "$CZ_V332" ]]
[[ $peel333 == "$CZ_FIX" ]]
assert_ancestor "$CZ" "$CZ_FIX" "v3.3.3"
assert_not_ancestor "$CZ" "$CZ_FIX" "v3.3.2"
cblob_p=$("${git_cmd[@]}" -C "$CZ" rev-parse "${CZ_PARENT}:${CZ_FILE}")
cblob_f=$("${git_cmd[@]}" -C "$CZ" rev-parse "${CZ_FIX}:${CZ_FILE}")
cblob_332=$("${git_cmd[@]}" -C "$CZ" rev-parse "v3.3.2:${CZ_FILE}")
cblob_333=$("${git_cmd[@]}" -C "$CZ" rev-parse "v3.3.3:${CZ_FILE}")
[[ $cblob_p == "$CZ_BLOB_P" ]]
[[ $cblob_f == "$CZ_BLOB_F" ]]
[[ $cblob_332 == "$CZ_BLOB_P" ]]
[[ $cblob_333 == "$CZ_BLOB_F" ]]

# beego
"${git_cmd[@]}" -C "$BG" cat-file -e "$BG_FIX^{commit}"
got_bparent=$("${git_cmd[@]}" -C "$BG" rev-parse "${BG_FIX}^")
[[ $got_bparent == "$BG_PARENT" ]]
bauthor=$("${git_cmd[@]}" -C "$BG" log -1 --format='%an' "$BG_FIX")
[[ $bauthor == 'Ville Vesilehto' ]]
bsubj=$("${git_cmd[@]}" -C "$BG" log -1 --format='%s' "$BG_FIX")
[[ $bsubj == 'fix: add proper HTML escaping in renderFormField' ]]
bbody=$("${git_cmd[@]}" -C "$BG" log -1 --format='%B' "$BG_FIX")
if printf '%s\n' "$bbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'beego closer unexpectedly has AI marker\n' >&2
  exit 1
fi
printf '%s\n' "$bbody" | grep -F 'Signed-off-by: Ville Vesilehto' >/dev/null
peel235=$("${git_cmd[@]}" -C "$BG" rev-parse 'v2.3.5^{commit}')
peel236=$("${git_cmd[@]}" -C "$BG" rev-parse 'v2.3.6^{commit}')
[[ $peel235 == "$BG_V235" ]]
[[ $peel236 == "$BG_V236" ]]
assert_ancestor "$BG" "$BG_FIX" "v2.3.6"
assert_not_ancestor "$BG" "$BG_FIX" "v2.3.5"
bblob_p=$("${git_cmd[@]}" -C "$BG" rev-parse "${BG_PARENT}:${BG_FILE}")
bblob_f=$("${git_cmd[@]}" -C "$BG" rev-parse "${BG_FIX}:${BG_FILE}")
bblob_235=$("${git_cmd[@]}" -C "$BG" rev-parse "v2.3.5:${BG_FILE}")
bblob_236=$("${git_cmd[@]}" -C "$BG" rev-parse "v2.3.6:${BG_FILE}")
[[ $bblob_p == "$BG_BLOB_P" ]]
[[ $bblob_f == "$BG_BLOB_F" ]]
[[ $bblob_235 == "$BG_BLOB_P" ]]
[[ $bblob_236 == "$BG_BLOB_F" ]]

# workflow
"${git_cmd[@]}" -C "$WF" cat-file -e "$WF_FIX^{commit}"
got_wparent=$("${git_cmd[@]}" -C "$WF" rev-parse "${WF_FIX}^")
[[ $got_wparent == "$WF_PARENT" ]]
wauthor=$("${git_cmd[@]}" -C "$WF" log -1 --format='%an' "$WF_FIX")
[[ $wauthor == 'Carl Csaposs' ]]
wsubj=$("${git_cmd[@]}" -C "$WF" log -1 --format='%s' "$WF_FIX")
[[ $wsubj == 'Remove GitHub token from exception output' ]]
wbody=$("${git_cmd[@]}" -C "$WF" log -1 --format='%B' "$WF_FIX")
if printf '%s\n' "$wbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'workflow closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel100=$("${git_cmd[@]}" -C "$WF" rev-parse 'v1.0.0^{commit}')
peel101=$("${git_cmd[@]}" -C "$WF" rev-parse 'v1.0.1^{commit}')
[[ $peel100 == "$WF_PARENT" ]]
[[ $peel101 == "$WF_FIX" ]]
assert_ancestor "$WF" "$WF_FIX" "v1.0.1"
assert_not_ancestor "$WF" "$WF_FIX" "v1.0.0"
wblob_p=$("${git_cmd[@]}" -C "$WF" rev-parse "v1.0.0:${WF_FILE}")
wblob_f=$("${git_cmd[@]}" -C "$WF" rev-parse "v1.0.1:${WF_FILE}")
[[ $wblob_p == "$WF_BLOB_P" ]]
[[ $wblob_f == "$WF_BLOB_F" ]]
wfix_src=$("${git_cmd[@]}" -C "$WF" show "${WF_FIX}:${WF_FILE}")
printf '%s\n' "$wfix_src" | grep -F 'pretty_exceptions_show_locals=False' >/dev/null

# api-platform
"${git_cmd[@]}" -C "$AP" cat-file -e "$AP_557^{commit}"
"${git_cmd[@]}" -C "$AP" cat-file -e "$AP_607^{commit}"
aauthor=$("${git_cmd[@]}" -C "$AP" log -1 --format='%an' "$AP_557")
[[ $aauthor == 'Antoine Bluchet' ]]
asubj=$("${git_cmd[@]}" -C "$AP" log -1 --format='%s' "$AP_557")
[[ $asubj == 'fix(graphql): access to unauthorized resource using node Relay' ]]
abody=$("${git_cmd[@]}" -C "$AP" log -1 --format='%B' "$AP_557")
if printf '%s\n' "$abody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'api-platform 557 unexpectedly has AI marker\n' >&2
  exit 1
fi
a6author=$("${git_cmd[@]}" -C "$AP" log -1 --format='%an' "$AP_607")
[[ $a6author == 'Antoine Bluchet' ]]
peel3416=$("${git_cmd[@]}" -C "$AP" rev-parse 'v3.4.16^{commit}')
peel3417=$("${git_cmd[@]}" -C "$AP" rev-parse 'v3.4.17^{commit}')
peel4021=$("${git_cmd[@]}" -C "$AP" rev-parse 'v4.0.21^{commit}')
peel4022=$("${git_cmd[@]}" -C "$AP" rev-parse 'v4.0.22^{commit}')
peel414=$("${git_cmd[@]}" -C "$AP" rev-parse 'v4.1.4^{commit}')
peel415=$("${git_cmd[@]}" -C "$AP" rev-parse 'v4.1.5^{commit}')
[[ $peel3416 == "$AP_V3416" ]]
[[ $peel3417 == "$AP_V3417" ]]
[[ $peel4021 == "$AP_V4021" ]]
[[ $peel4022 == "$AP_V4022" ]]
[[ $peel414 == "$AP_V414" ]]
[[ $peel415 == "$AP_V415" ]]
assert_ancestor "$AP" "$AP_557" "v3.4.17"
assert_not_ancestor "$AP" "$AP_557" "v3.4.16"
assert_ancestor "$AP" "$AP_607" "v4.0.22"
assert_not_ancestor "$AP" "$AP_607" "v4.0.21"
assert_ancestor "$AP" "$AP_607" "v4.1.5"
assert_not_ancestor "$AP" "$AP_607" "v4.1.4"
ablob_557=$("${git_cmd[@]}" -C "$AP" rev-parse "${AP_557}:${AP_FILE}")
ablob_607=$("${git_cmd[@]}" -C "$AP" rev-parse "${AP_607}:${AP_FILE}")
ablob_3416=$("${git_cmd[@]}" -C "$AP" rev-parse "v3.4.16:${AP_FILE}")
ablob_3417=$("${git_cmd[@]}" -C "$AP" rev-parse "v3.4.17:${AP_FILE}")
ablob_4021=$("${git_cmd[@]}" -C "$AP" rev-parse "v4.0.21:${AP_FILE}")
ablob_4022=$("${git_cmd[@]}" -C "$AP" rev-parse "v4.0.22:${AP_FILE}")
ablob_414=$("${git_cmd[@]}" -C "$AP" rev-parse "v4.1.4:${AP_FILE}")
ablob_415=$("${git_cmd[@]}" -C "$AP" rev-parse "v4.1.5:${AP_FILE}")
[[ $ablob_557 == "$AP_BLOB_F" ]]
[[ $ablob_607 == "$AP_BLOB_F" ]]
[[ $ablob_3416 == "$AP_BLOB_P" ]]
[[ $ablob_3417 == "$AP_BLOB_F" ]]
[[ $ablob_4021 == "$AP_BLOB_P" ]]
[[ $ablob_4022 == "$AP_BLOB_F" ]]
[[ $ablob_414 == "$AP_BLOB_P" ]]
[[ $ablob_415 == "$AP_BLOB_F" ]]

python3 - "$XC" "$FV" "$CZ" "$BG" "$WF" "$AP" \
  "$XC_V3" "$XC_V2" "$XC_V6" "$FV_MEM" "$CZ_FIX" "$BG_FIX" "$WF_FIX" "$AP_557" "$AP_607" << 'PY'
import re, subprocess, sys

repos = sys.argv[1:7]
protected = sys.argv[7:]
pat = re.compile(
    r"Co-authored-by:.*(Claude|Cursor|Copilot|GPT|OpenAI|Gemini|Codex|Anthropic)|"
    r"Generated with Claude|Generated with Copilot|noreply@anthropic|chatgpt|claude\.ai",
    re.I,
)
git = ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]
empty_ok = {
    repos[0],  # xml-crypto
    repos[1],  # feldman
    repos[3],  # beego
    repos[4],  # workflow
}
for repo in repos:
    out = subprocess.check_output(
        git + ["-C", repo, "log", "--all", "--format=%H%x1f%an%x1f%s%x1f%b%x1e"],
        text=True,
        errors="replace",
    )
    hits = []
    for rec in out.split("\x1e"):
        if pat.search(rec):
            hits.append(rec.split("\x1f", 1)[0][:40].strip())
    if repo in empty_ok:
        assert hits == [], (repo, hits[:5])
    for sha in protected:
        probe = subprocess.run(git + ["-C", repo, "cat-file", "-e", sha + "^{commit}"], capture_output=True)
        if probe.returncode != 0:
            continue
        meta = subprocess.check_output(git + ["-C", repo, "log", "-1", "--format=%B", sha], text=True, errors="replace")
        assert not pat.search(meta), (repo, sha)
print("ai_trailer_scan_cited_rems_clean empty_repos=4")
PY

printf 'REPLAY_OK reviewed=7 PASS_proposal=0 NARROW=0 REJECT=7 UNKNOWN=0 BLOCKED=0\n'
