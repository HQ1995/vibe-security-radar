#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-increm20c-blocked6-recovery-grok46-xhigh.
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
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-increm20c-blocked6-recovery-grok46-xhigh
CACHE=/home/hanqing/.cache/ghsa200-worker-clones/recovery20c-260814
CRUD=$CACHE/Guichaguri__crud-query-parser
BASE=$CACHE/cryptocoinjs__base-x
ORML=$CACHE/open-web3-stack__open-runtime-module-library
IBC=$CACHE/cosmos__ibc-go
LS3=$CACHE/Robothy__local-s3
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database

CRUD_VAL=cace89104e26c07bfe84f19702351d0d25c81493
CRUD_010=4dbc1bd6bfbd83c79a35884a9d53c03025d5758e
CRUD_003=a0460104efa0712eb0a4b3f968c41cbd51b6bb66

BASE_MERGE=e4cb9b0b563ba36718acd7006f35fa4b3ac43c05
BASE_MEMBER=831716afd2d6e9f1c1e28cdf84ccb1eb17692e43
BASE_500=125c2030a069588701bea4a5981cb93cd403105e
BASE_501=b7b0cec52bf60d993957902e8e7c96906ac39c7c

ORML_FIX=6720fcd92f44e5f204741b04fdef3b67b0fcf6bc
ORML_LIB=rewards/src/lib.rs
ORML_BLOB_PARENT=85e127d1b8c33a959c11ec0d9ed182f0e6e16bda
ORML_BLOB_FIX=ab33f86836bc80eeef77ea44bead47a7ccec5574
ORML_121=59e37340e16b6bd23e6d70febff8bb297aa428f4

IBC_FIX=59987d52d959dc5876ffd4f307c9b33a52a43748
IBC_PARENT=91dda01659676dfc15339a196b0750b6c808af93
IBC_GO=modules/apps/transfer/ibc_module.go
IBC_BLOB_PARENT=2f91fb49a8fdb0c2ec30a0c511d5739df69a310e
IBC_BLOB_FIX=2325bdf7fb9c6548e0163aef3c970436540b9dea
IBC_BP=9869b3c6f7eb05a935b1eb33611c5406f68438a5

LS3_FIX=d6ed756ceb30c1eb9d4263321ac683d734f8836f
LS3_PARENT=009901882be8b543e85b67c5ec2e9f30d83d62ef
LS3_XML=local-s3-rest/src/main/java/com/robothy/s3/rest/utils/XmlUtils.java
LS3_JAVA=local-s3-rest/src/main/java/com/robothy/s3/rest/LocalS3.java
LS3_BLOB_PARENT=67aab78b4c9874e9eb51bf9ad0482acf72dae28a
LS3_BLOB_FIX=e937b98bd33df6593e1ea02c29ea49ba951b5acd
LS3_JAVA_PARENT=b1b1c136126f7542297ab01340f81f2bce03d7b0
LS3_JAVA_FIX=f0d2c4e610105810d2c15d3325ba70317f24ac08
LS3_120=45cb60cec18c16e14e728d801414b484a591a97d
LS3_121=ac5983447db7a1385b81958dc4cb49faa9222a72

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
require_dir "$CRUD/.git"
require_dir "$BASE/.git"
require_dir "$ORML/.git"
require_dir "$IBC/.git"
require_dir "$LS3/.git"
if [[ -e $CACHE/macropay-solutions__laravel-crud-wizard-free/.git ]]; then
  printf 'laravel clone unexpectedly exists\n' >&2
  exit 1
fi
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/ledger.jsonl" \
  3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20c-grok46-low/cases.jsonl" \
  c10467a160a2c01ec70e4531f5ac315057923d864f642037eaea53398b358cbd
expect_hash "$OWNED/cases.jsonl" \
  b284de1bb37699f3c210277fffd858efd3365adbec899b679b804bbc5546ac16
expect_hash "$OWNED/report.md" \
  fd89cdf2abb36b5151fbd29843a674ea1f5dd10837cb9c8e08d84a26b2c77768
expect_hash "$OWNED/work/pages/advisory/GHSA-3wgq-h4fr-cwg5.json" \
  a769c1d7614eedd99f088ffe16dd9f523415d71291ae7c1ab21236cd9140cf46
expect_hash "$OWNED/work/pages/advisory/GHSA-9r25-rp3p-h2w4.json" \
  882c3f550ccb8a885e75f4e5e0a251cb98e0f5dfb689391fc72c3fa4b5ff52a3
expect_hash "$OWNED/work/pages/advisory/GHSA-xq7p-g2vc-g82p.json" \
  582ad9c72202d5ad5ba37680245526517cc8a8bc0b0049313790af7d052d0a4b
expect_hash "$OWNED/work/pages/advisory/GHSA-5v93-9mqw-p9mh.json" \
  36635c3829c64188d6568403a5fe57c3bfd8224af76635392d94d0f7c3ac186e
expect_hash "$OWNED/work/pages/advisory/GHSA-jg6f-48ff-5xrw.json" \
  8c2dd19236df5654899b253e3939a3c7941d3eb97fa48a576b9e57ddb98810a1
expect_hash "$OWNED/work/pages/advisory/GHSA-2466-4485-4pxj.json" \
  df512713908ef5f270860d07264062ba554331d58492cbdd51297606aba78890
expect_hash "$OWNED/work/pages/ghsa/GHSA-3wgq-h4fr-cwg5.json" \
  1f99e137a8a5837864ea81c0e3727f9daf96425cdcf55320003ae253e1982d14
expect_hash "$OWNED/work/pages/ghsa/GHSA-9r25-rp3p-h2w4.json" \
  d526e5fa0ab69a164c030919b97a6efdd7b2887f2777676f5321bd3ec9c7fa5d
expect_hash "$OWNED/work/pages/ghsa/GHSA-xq7p-g2vc-g82p.json" \
  abeb92ec934e31294c4c16a786c972dc36a7edcab9e94a7af28f8ed4493f797e
expect_hash "$OWNED/work/pages/ghsa/GHSA-5v93-9mqw-p9mh.json" \
  74fe7632de07856774d35ef4164778f251903243fe437b394d9ad9020aa332cf
expect_hash "$OWNED/work/pages/ghsa/GHSA-jg6f-48ff-5xrw.json" \
  4520b32ee709786f0fb3f343170aec55b29cd6120139a074e202d5d594a1738e
expect_hash "$OWNED/work/pages/ghsa/GHSA-2466-4485-4pxj.json" \
  107dea0b778c6f3ca7164a7c6e2a76d0d385f816314d9ee8249c923515f57cab

[[ "$("${git_cmd[@]}" -C "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]

SRC20C_CASES=$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20c-grok46-low/cases.jsonl
python3 - "$OWNED" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  "$SRC20C_CASES" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 6, len(rows)
want = [
    "GHSA-3WGQ-H4FR-CWG5",
    "GHSA-9R25-RP3P-H2W4",
    "GHSA-XQ7P-G2VC-G82P",
    "GHSA-5V93-9MQW-P9MH",
    "GHSA-JG6F-48FF-5XRW",
    "GHSA-2466-4485-4PXJ",
]
assert [r["case_id"] for r in rows] == want
src = [json.loads(l) for l in Path(sys.argv[3]).read_text().splitlines() if l.strip()]
src_ids = [r["case_id"] for r in src if r["case_id"] in set(want)]
assert src_ids == want
assert all(r.get("worker_verdict") == "BLOCKED" for r in src if r["case_id"] in set(want))
blocked = [r for r in rows if r["worker_verdict"] == "BLOCKED"]
rej = [r for r in rows if r["worker_verdict"] == "REJECT"]
assert len(blocked) == 1 and blocked[0]["case_id"] == "GHSA-3WGQ-H4FR-CWG5"
assert len(rej) == 5
assert all(r["worker_verdict"] != "PASS" for r in rows)
for r in rows:
    assert r["causal_admission"] is False
    assert r["countable"] is False
    assert r["publication_status"] == "HOLD"
    assert r["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    assert r["identity_gate"] == "PASS" and r["gates"]["identity_gate"] == "PASS"
    assert r["uniqueness_gate"] == "PASS" and r["gates"]["uniqueness_gate"] == "PASS"
causal = ["ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate"]
b = blocked[0]
assert b["remediation_patch_delta"] == "BLOCKED"
for g in causal:
    assert b[g] == "BLOCKED" and b["gates"][g] == "BLOCKED"
    assert b[g] != "FAIL"
for r in rej:
    assert r["ai_hunk_gate"] == "FAIL"
    assert r["remediation_patch_delta"] == "FAIL"
    for g in causal:
        assert r[g] == "FAIL" and r["gates"][g] == "FAIL"
        assert r[g] != "BLOCKED"
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
g3 = json.loads((owned / "work/pages/ghsa/GHSA-3wgq-h4fr-cwg5.json").read_text())
assert g3["ghsa_id"] == "GHSA-3wgq-h4fr-cwg5"
assert g3["withdrawn_at"] is None
assert g3["source_code_location"] == "https://github.com/macropay-solutions/laravel-crud-wizard-free"
g9 = json.loads((owned / "work/pages/ghsa/GHSA-9r25-rp3p-h2w4.json").read_text())
assert g9["cve_id"] == "CVE-2025-32020"
g_x = json.loads((owned / "work/pages/ghsa/GHSA-xq7p-g2vc-g82p.json").read_text())
assert g_x["cve_id"] == "CVE-2025-27611"
g5 = json.loads((owned / "work/pages/ghsa/GHSA-5v93-9mqw-p9mh.json").read_text())
assert g5["source_code_location"] == "https://github.com/open-web3-stack/open-runtime-module-library"
gj = json.loads((owned / "work/pages/ghsa/GHSA-jg6f-48ff-5xrw.json").read_text())
assert gj["source_code_location"] == "https://github.com/cosmos/ibc-go"
gl = json.loads((owned / "work/pages/ghsa/GHSA-2466-4485-4pxj.json").read_text())
assert gl["source_code_location"] == "https://github.com/Robothy/local-s3"
fp = gl["vulnerabilities"][0]["first_patched_version"]
if isinstance(fp, dict):
    fp = fp.get("identifier")
assert fp == "1.21"
print("conservation assigned=6 reviewed=6 unreviewed=0 PASS_proposal=0 NARROW=0 REJECT=5 UNKNOWN=0 BLOCKED=1")
PY

# crud-query-parser
"${git_cmd[@]}" -C "$CRUD" cat-file -e "$CRUD_VAL^{commit}"
cauthor=$("${git_cmd[@]}" -C "$CRUD" log -1 --format='%an' "$CRUD_VAL")
[[ $cauthor == 'Guilherme Chaguri' ]]
csubj=$("${git_cmd[@]}" -C "$CRUD" log -1 --format='%s' "$CRUD_VAL")
[[ $csubj == 'feat(typeorm): added field validation' ]]
cbody=$("${git_cmd[@]}" -C "$CRUD" log -1 --format='%B' "$CRUD_VAL")
if printf '%s\n' "$cbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'crud validator unexpectedly has AI marker\n' >&2
  exit 1
fi
peel010=$("${git_cmd[@]}" -C "$CRUD" rev-parse '0.1.0^{commit}')
[[ $peel010 == "$CRUD_010" ]]
assert_ancestor "$CRUD" "$CRUD_VAL" "0.1.0"
assert_not_ancestor "$CRUD" "$CRUD_VAL" "$CRUD_003"

# base-x
"${git_cmd[@]}" -C "$BASE" cat-file -e "$BASE_MERGE^{commit}"
bauthor=$("${git_cmd[@]}" -C "$BASE" log -1 --format='%an' "$BASE_MERGE")
[[ $bauthor == 'Kirill Fomichev' ]]
mauthor=$("${git_cmd[@]}" -C "$BASE" log -1 --format='%an' "$BASE_MEMBER")
[[ $mauthor == 'Steven Luscher' ]]
msubj=$("${git_cmd[@]}" -C "$BASE" log -1 --format='%s' "$BASE_MEMBER")
[[ $msubj == 'Prohibit char codes that would overflow the `BASE_MAP`' ]]
mbody=$("${git_cmd[@]}" -C "$BASE" log -1 --format='%B' "$BASE_MEMBER")
if printf '%s\n' "$mbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'base-x member unexpectedly has AI marker\n' >&2
  exit 1
fi
peel500=$("${git_cmd[@]}" -C "$BASE" rev-parse 'v5.0.0^{commit}')
peel501=$("${git_cmd[@]}" -C "$BASE" rev-parse 'v5.0.1^{commit}')
[[ $peel500 == "$BASE_500" ]]
[[ $peel501 == "$BASE_501" ]]
assert_ancestor "$BASE" "$BASE_MERGE" "v5.0.1"
assert_not_ancestor "$BASE" "$BASE_MERGE" "v5.0.0"

# orml
"${git_cmd[@]}" -C "$ORML" cat-file -e "$ORML_FIX^{commit}"
oauthor=$("${git_cmd[@]}" -C "$ORML" log -1 --format='%an' "$ORML_FIX")
[[ $oauthor == 'zjb0807' ]]
osubj=$("${git_cmd[@]}" -C "$ORML" log -1 --format='%s' "$ORML_FIX")
[[ $osubj == 'update saturating calculation (#1016)' ]]
obody=$("${git_cmd[@]}" -C "$ORML" log -1 --format='%B' "$ORML_FIX")
if printf '%s\n' "$obody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'orml closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel121=$("${git_cmd[@]}" -C "$ORML" rev-parse 'v1.2.1^{commit}')
[[ $peel121 == "$ORML_121" ]]
assert_ancestor "$ORML" "$ORML_FIX" "v1.2.1"
assert_not_ancestor "$ORML" "$ORML_FIX" "v1.0.1"
oblob_p=$("${git_cmd[@]}" -C "$ORML" rev-parse "${ORML_FIX}^:${ORML_LIB}")
oblob_f=$("${git_cmd[@]}" -C "$ORML" rev-parse "${ORML_FIX}:${ORML_LIB}")
oblob_121=$("${git_cmd[@]}" -C "$ORML" rev-parse "v1.2.1:${ORML_LIB}")
[[ $oblob_p == "$ORML_BLOB_PARENT" ]]
[[ $oblob_f == "$ORML_BLOB_FIX" ]]
[[ $oblob_121 == "$ORML_BLOB_FIX" ]]
oparent_src=$("${git_cmd[@]}" -C "$ORML" show "${ORML_FIX}^:${ORML_LIB}")
printf '%s\n' "$oparent_src" | grep -F 'as_u128()' >/dev/null
ofix_src=$("${git_cmd[@]}" -C "$ORML" show "${ORML_FIX}:${ORML_LIB}")
printf '%s\n' "$ofix_src" | grep -F 'saturated_into::<u128>()' >/dev/null

# ibc-go
"${git_cmd[@]}" -C "$IBC" cat-file -e "$IBC_FIX^{commit}"
got_iparent=$("${git_cmd[@]}" -C "$IBC" rev-parse "${IBC_FIX}^")
[[ $got_iparent == "$IBC_PARENT" ]]
iauthor=$("${git_cmd[@]}" -C "$IBC" log -1 --format='%an' "$IBC_FIX")
[[ $iauthor == 'Gjermund Garaba' ]]
isubj=$("${git_cmd[@]}" -C "$IBC" log -1 --format='%s' "$IBC_FIX")
[[ $isubj == 'fix: remove packet data remarshaling (#8065)' ]]
ibody=$("${git_cmd[@]}" -C "$IBC" log -1 --format='%B' "$IBC_FIX")
if printf '%s\n' "$ibody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'ibc closer unexpectedly has AI marker\n' >&2
  exit 1
fi
bauthor=$("${git_cmd[@]}" -C "$IBC" log -1 --format='%an' "$IBC_BP")
[[ $bauthor == 'Gjermund Garaba' ]]
peel860=$("${git_cmd[@]}" -C "$IBC" rev-parse 'v8.6.0^{commit}')
peel861=$("${git_cmd[@]}" -C "$IBC" rev-parse 'v8.6.1^{commit}')
[[ $peel860 == "$IBC_PARENT" ]]
[[ $peel861 == "$IBC_FIX" ]]
assert_ancestor "$IBC" "$IBC_FIX" "v8.6.1"
assert_not_ancestor "$IBC" "$IBC_FIX" "v8.6.0"
assert_not_ancestor "$IBC" "bf74b47a41eaca1304d92632623aa80034e0222c" "v8.6.1"
ibblob_p=$("${git_cmd[@]}" -C "$IBC" rev-parse "v8.6.0:${IBC_GO}")
ibblob_f=$("${git_cmd[@]}" -C "$IBC" rev-parse "v8.6.1:${IBC_GO}")
[[ $ibblob_p == "$IBC_BLOB_PARENT" ]]
[[ $ibblob_f == "$IBC_BLOB_FIX" ]]

# local-s3
"${git_cmd[@]}" -C "$LS3" cat-file -e "$LS3_FIX^{commit}"
got_lparent=$("${git_cmd[@]}" -C "$LS3" rev-parse "${LS3_FIX}^")
[[ $got_lparent == "$LS3_PARENT" ]]
lauthor=$("${git_cmd[@]}" -C "$LS3" log -1 --format='%an' "$LS3_FIX")
[[ $lauthor == 'Luo' ]]
lsubj=$("${git_cmd[@]}" -C "$LS3" log -1 --format='%s' "$LS3_FIX")
[[ $lsubj == 'fix XML External Entity (XXE) Injection (#172)' ]]
lbody=$("${git_cmd[@]}" -C "$LS3" log -1 --format='%B' "$LS3_FIX")
if printf '%s\n' "$lbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'locals3 closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel120=$("${git_cmd[@]}" -C "$LS3" rev-parse '1.20^{commit}')
peel121=$("${git_cmd[@]}" -C "$LS3" rev-parse '1.21^{commit}')
[[ $peel120 == "$LS3_120" ]]
[[ $peel121 == "$LS3_121" ]]
assert_ancestor "$LS3" "$LS3_FIX" "1.21"
assert_not_ancestor "$LS3" "$LS3_FIX" "1.20"
lblob_p=$("${git_cmd[@]}" -C "$LS3" rev-parse "${LS3_PARENT}:${LS3_XML}")
lblob_f=$("${git_cmd[@]}" -C "$LS3" rev-parse "${LS3_FIX}:${LS3_XML}")
lblob_120=$("${git_cmd[@]}" -C "$LS3" rev-parse "1.20:${LS3_XML}")
lblob_121=$("${git_cmd[@]}" -C "$LS3" rev-parse "1.21:${LS3_XML}")
[[ $lblob_p == "$LS3_BLOB_PARENT" ]]
[[ $lblob_f == "$LS3_BLOB_FIX" ]]
[[ $lblob_120 == "$LS3_BLOB_PARENT" ]]
[[ $lblob_121 == "$LS3_BLOB_FIX" ]]
jblob_120=$("${git_cmd[@]}" -C "$LS3" rev-parse "1.20:${LS3_JAVA}")
jblob_121=$("${git_cmd[@]}" -C "$LS3" rev-parse "1.21:${LS3_JAVA}")
[[ $jblob_120 == "$LS3_JAVA_PARENT" ]]
[[ $jblob_121 == "$LS3_JAVA_FIX" ]]
lfix_src=$("${git_cmd[@]}" -C "$LS3" show "${LS3_FIX}:${LS3_XML}")
printf '%s\n' "$lfix_src" | grep -F 'XMLInputFactory.SUPPORT_DTD' >/dev/null
lparent_src=$("${git_cmd[@]}" -C "$LS3" show "${LS3_PARENT}:${LS3_XML}")
if printf '%s\n' "$lparent_src" | grep -F 'SUPPORT_DTD' >/dev/null; then
  printf 'locals3 parent unexpectedly disables DTD\n' >&2
  exit 1
fi

python3 - "$CRUD" "$BASE" "$ORML" "$LS3" "$IBC" << 'PY'
import re, subprocess, sys

repos = sys.argv[1:5]
ibc = sys.argv[5]
pat = re.compile(
    r"Co-authored-by:.*(Claude|Cursor|Copilot|GPT|OpenAI|Gemini|Codex|Anthropic)|"
    r"Generated with Claude|Generated with Copilot|noreply@anthropic|chatgpt|claude\.ai|"
    r"Made-with: Cursor",
    re.I,
)
git = ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]
for repo in repos:
    out = subprocess.check_output(git + ["-C", repo, "log", "--all", "--format=%H%x1f%an%x1f%s%x1f%b%x1e"], text=True)
    hits = []
    for rec in out.split("\x1e"):
        if pat.search(rec):
            hits.append(rec.split("\x1f", 1)[0][:40])
    assert hits == [], (repo, hits[:5])
out = subprocess.check_output(git + ["-C", ibc, "log", "v8.6.1", "--format=%H%x1f%an%x1f%s%x1f%b%x1e"], text=True)
hits = []
for rec in out.split("\x1e"):
    if pat.search(rec):
        hits.append(rec.split("\x1f", 1)[0][:40])
assert hits == [], ("ibc-v8.6.1", hits[:5])
print("ai_trailer_scan_empty_on_relevant_history")
PY

printf 'REPLAY_OK reviewed=6 PASS_proposal=0 NARROW=0 REJECT=5 UNKNOWN=0 BLOCKED=1\n'
