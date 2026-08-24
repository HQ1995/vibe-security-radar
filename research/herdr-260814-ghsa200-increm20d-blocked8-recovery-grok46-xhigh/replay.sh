#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-increm20d-blocked8-recovery-grok46-xhigh.
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
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-increm20d-blocked8-recovery-grok46-xhigh
CACHE=/home/hanqing/.cache/ghsa200-worker-clones/recovery20d-260814
ZIP=$CACHE/zip-rs__zip2
TM=$CACHE/informalsystems__tendermint-rs
YT=$CACHE/dirkf__youtube-dl
FH=$CACHE/HL7__fhir-ig-publisher
CQ=$CACHE/github__codeql-action
LS3=$CACHE/Robothy__local-s3
TS=$CACHE/OmenApps__django-tomselect
LN=$CACHE/lnbits__lnbits
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database

ZIP_FIX=a2e062f37066c3b12860a32eb1cb44856cfb7afe
ZIP_IN=0199ac2cb8e9a5d7e645e53d51838655d8e15148
ZIP_PARENT=c6ba2012352c1b7ba6340d38207538c71aacc797
ZIP_READ_V223=39686012dbee95375a1e1e8233ff89c1ba20ecde
ZIP_READ_V230=abcb063ba92fc144593d5a866c136d179793e65e
ZIP_V223=57cb3a8eefce0d697986f96e2a2f45c55063d1ae
ZIP_V230=6eab5f5cc64cf051f2712428745ca2fea088097c

TM_FIX=1aabcfe6a3c0678db22097543f7f7a662f0db34b
TM_PARENT=cb664165b4b9925436c2320f13e66bb8c657c6e1
TM_VOTE_P=8feba60f2be18621287a7cc778ddd84b21931845
TM_VOTE_F=703b8830db30420fccd30caaeb90ca410eecb317
TM_V403=c7025490235ccfae3757a543607baf2d1109123a
TM_FILE=light-client-verifier/src/operations/voting_power.rs

YT_CITED=d42a222ed541b96649396ef00e19552aef0f09ec
YT_DIRKF=46521096433aceaa41b4caa845bed22ca6f377ce
YT_PATCHID=355665f1b2029339fc483e7024b8ecd50656e74b

FH_FIX=3560de2f486d688a3ddcf4aa54d8bdacea380c3d
FH_PRIOR=e5db459f3995bbf9dfd558f9f40020fb4df79d33
FH_173=a923509a20e150a2a9a10fda9719998eba896692
FH_174=9a619c4c6cebb3cb3566f079c8f4324dbd05cb90
FH_1622=33e2566af5b442c6565664e1152763ce0f8caac3

CQ_FIX=519de26711ecad48bde264c51e414658a82ef3fa
CQ_PARENT=7e4b683a3d062a0853420133e3b340e23c59a1e8
CQ_BLOB_P=5594b818aaf14f4474f71ac71d29f17e8dc8dc4d
CQ_BLOB_F=a15277a7b83a520264995cfd8fb93121173b468a
CQ_V3282=d68b2d4edb4189fd2a5366ac14e72027bd4b37dd
CQ_V3283=dd196fa9ce80b6bacc74ca1c32bd5b0ba22efca7
CQ_FILE=src/debug-artifacts.ts

LS3_FIX=d6ed756ceb30c1eb9d4263321ac683d734f8836f
LS3_PARENT=009901882be8b543e85b67c5ec2e9f30d83d62ef
LS3_XML=local-s3-rest/src/main/java/com/robothy/s3/rest/utils/XmlUtils.java
LS3_BLOB_P=67aab78b4c9874e9eb51bf9ad0482acf72dae28a
LS3_BLOB_F=e937b98bd33df6593e1ea02c29ea49ba951b5acd
LS3_120=45cb60cec18c16e14e728d801414b484a591a97d
LS3_121=ac5983447db7a1385b81958dc4cb49faa9222a72

TS_FIX=0990ed36c8874f9d42fa9deff7734bf8dcd46d40
TS_MERGE=b6817c43eca3c41e28fd59d9cceb6c80af67be79
TS_UTILS=src/django_tomselect/utils.py
TS_BLOB_F=942c74952333f024db52e961d7ba012fff1c2181
TS_532=238b7a995145bf23e11f52ed1f3e5989b38fb385
TS_533=839b4befb02906b9bf556bad3dabe2648141be3a

LN_LAST=51c9d294cdb40c777b1048bbee267b49cdaf7a34
LN_HUMAN=bfa23568e3c84e863df14be25eb6f3f1b7cb2fc2
LN_V100=57148484348ca33f170ab85f00debe67cc3b265f

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
require_dir "$ZIP/.git"
require_dir "$TM/.git"
require_dir "$YT/.git"
require_dir "$FH/.git"
require_dir "$CQ/.git"
require_dir "$LS3/.git"
require_dir "$TS/.git"
require_dir "$LN/.git"
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
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20d-grok46-low/cases.jsonl" \
  f7b6f42a1c2b77b9d0b729afa7a009a79af326e888d5866736f5551a2b8227b2
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20d-grok46-low/result.json" \
  80a345b2aaa3d1c11739f2a13182da8e3c2423963b9524f1d8ae59fdab32488c
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20d-grok46-low/work/freeze.json" \
  6750d024df074bd64548c513b6e5762aa0902a5bb871fe51b254987f68cb1cc2
expect_hash "$OWNED/cases.jsonl" \
  593e24cdb3c112bc24ae9c77658e1c90d57af02ddb7d4ade097523a28fbeb4f0
expect_hash "$OWNED/report.md" \
  e807396274e0052b3f6c76576c5b665388450e60d972294b33942d3aed0c219b
expect_hash "$OWNED/work/pages/advisory/GHSA-94vh-gphv-8pm8.json" \
  582d3f5d2e7516915e62f8df46ca82ed623f403a9bc069e461fa52969fc335cf
expect_hash "$OWNED/work/pages/advisory/GHSA-6jrf-4jv4-r9mw.json" \
  615a1afd61e55a23c6f5120a34c9313e793a7a45bd51965256f24570feafa83d
expect_hash "$OWNED/work/pages/advisory/GHSA-22fp-mf44-f2mq.json" \
  585637d275ccb9c1e585133a7f59b6e3fa7b675f5d538d0bedc1ab5b23af727d
expect_hash "$OWNED/work/pages/advisory/GHSA-8c3x-hq82-gjcm.json" \
  041b80620a33655bb0bc77c7aeaded68026e52054200e7a73074b22665851f43
expect_hash "$OWNED/work/pages/advisory/GHSA-vqf5-2xx6-9wfm.json" \
  b9d256c66c0db6156c44dee2eee2fb3fc6434b4f6ecdc4b250bea8739076239c
expect_hash "$OWNED/work/pages/advisory/GHSA-g6wm-2v64-wq36.json" \
  0cc979986bee1ec25f05843f1bae1b3b5a6b1b241f83414ace04ef049debcda5
expect_hash "$OWNED/work/pages/advisory/GHSA-785h-76cm-cpmf.json" \
  271787099be0f255decb8787903357837519ded49234e39b7036d3d3b84febaf
expect_hash "$OWNED/work/pages/advisory/GHSA-qp8j-p87f-c8cc.json" \
  ac88505c7a6f7f4b6ffc6586c71cca3113fb604a805ae927dd50298d05cd6069
expect_hash "$OWNED/work/pages/ghsa/GHSA-94vh-gphv-8pm8.json" \
  2af0bce32c006ac6ff652cf3d3bba9080f43143f4797c1c1b1a39b137d656b74
expect_hash "$OWNED/work/pages/ghsa/GHSA-6jrf-4jv4-r9mw.json" \
  c0c87323dd36591475bf4d298a04d0a4157b0fcf5a39c52e9412e04b6a4baa8f
expect_hash "$OWNED/work/pages/ghsa/GHSA-22fp-mf44-f2mq.json" \
  ef3c4438a51f32cc3f01cb034d334e4326eab96aaa7d5954adfc8e4975890344
expect_hash "$OWNED/work/pages/ghsa/GHSA-8c3x-hq82-gjcm.json" \
  9936e3c302fc41c7693c6403bee9414a44f4d7b1bfac1e0d624f50fce272f071
expect_hash "$OWNED/work/pages/ghsa/GHSA-vqf5-2xx6-9wfm.json" \
  73ffae1b25b842a1850c331364ba4e942b2ad144b0a757a467b54b0f61c6f07d
expect_hash "$OWNED/work/pages/ghsa/GHSA-g6wm-2v64-wq36.json" \
  fb87621707c97b9edf6b36e24e94b563f619563ec3b5f90b53c8a1c71382b366
expect_hash "$OWNED/work/pages/ghsa/GHSA-785h-76cm-cpmf.json" \
  3edde36dddcd771d6233bb3dfe842fd6c10c0cbe87dc802008d81863e0f49d5b
expect_hash "$OWNED/work/pages/ghsa/GHSA-qp8j-p87f-c8cc.json" \
  f0bdeb869d3d6e8e4598633f2d854e0065accce4df197b7b880a3f145f23fb58

[[ "$("${git_cmd[@]}" -C "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]

python3 - "$OWNED" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  "$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20d-grok46-low/cases.jsonl" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 8, len(rows)
want = [
    "GHSA-94VH-GPHV-8PM8",
    "GHSA-6JRF-4JV4-R9MW",
    "GHSA-22FP-MF44-F2MQ",
    "GHSA-8C3X-HQ82-GJCM",
    "GHSA-VQF5-2XX6-9WFM",
    "GHSA-G6WM-2V64-WQ36",
    "GHSA-785H-76CM-CPMF",
    "GHSA-QP8J-P87F-C8CC",
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
adv94 = json.loads((owned / "work/pages/advisory/GHSA-94vh-gphv-8pm8.json").read_text())
assert adv94["id"] == "GHSA-94vh-gphv-8pm8"
assert adv94["affected"][0]["package"]["name"] == "zip"
g94 = json.loads((owned / "work/pages/ghsa/GHSA-94vh-gphv-8pm8.json").read_text())
assert g94["ghsa_id"] == "GHSA-94vh-gphv-8pm8"
assert g94["withdrawn_at"] is None
assert g94["source_code_location"] == "https://github.com/zip-rs/zip2"
g6 = json.loads((owned / "work/pages/ghsa/GHSA-6jrf-4jv4-r9mw.json").read_text())
assert g6["source_code_location"] == "https://github.com/informalsystems/tendermint-rs"
g22 = json.loads((owned / "work/pages/ghsa/GHSA-22fp-mf44-f2mq.json").read_text())
assert g22["source_code_location"] == "https://github.com/dirkf/youtube-dl"
assert g22["vulnerabilities"][0]["first_patched_version"] is None
g8 = json.loads((owned / "work/pages/ghsa/GHSA-8c3x-hq82-gjcm.json").read_text())
assert g8["source_code_location"] == "https://github.com/HL7/fhir-ig-publisher"
gv = json.loads((owned / "work/pages/ghsa/GHSA-vqf5-2xx6-9wfm.json").read_text())
assert gv["source_code_location"] == "https://github.com/github/codeql-action"
gg = json.loads((owned / "work/pages/ghsa/GHSA-g6wm-2v64-wq36.json").read_text())
assert gg["source_code_location"] == "https://github.com/Robothy/local-s3"
fp = gg["vulnerabilities"][0]["first_patched_version"]
if isinstance(fp, dict):
    fp = fp.get("identifier")
assert fp == "1.21"
gt = json.loads((owned / "work/pages/ghsa/GHSA-785h-76cm-cpmf.json").read_text())
assert gt["source_code_location"] == "https://github.com/OmenApps/django-tomselect"
gq = json.loads((owned / "work/pages/ghsa/GHSA-qp8j-p87f-c8cc.json").read_text())
assert gq["source_code_location"] == "https://github.com/lnbits/lnbits"
assert gq["vulnerabilities"][0]["first_patched_version"] is None
print("conservation assigned=8 reviewed=8 unreviewed=0 PASS_proposal=0 NARROW=0 REJECT=8 UNKNOWN=0 BLOCKED=0")
PY

# zip2
"${git_cmd[@]}" -C "$ZIP" cat-file -e "$ZIP_FIX^{commit}"
"${git_cmd[@]}" -C "$ZIP" cat-file -e "$ZIP_IN^{commit}"
nparents=$("${git_cmd[@]}" -C "$ZIP" rev-list --parents -n 1 "$ZIP_FIX")
[[ $nparents == "$ZIP_FIX $ZIP_PARENT $ZIP_IN" ]]
zauthor=$("${git_cmd[@]}" -C "$ZIP" log -1 --format='%an' "$ZIP_FIX")
[[ $zauthor == 'Chris Hennick' ]]
zsubj=$("${git_cmd[@]}" -C "$ZIP" log -1 --format='%s' "$ZIP_FIX")
[[ $zsubj == 'Merge commit from fork' ]]
zbody=$("${git_cmd[@]}" -C "$ZIP" log -1 --format='%B' "$ZIP_FIX")
if printf '%s\n' "$zbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'zip2 closer unexpectedly has AI marker\n' >&2
  exit 1
fi
ibody=$("${git_cmd[@]}" -C "$ZIP" log -1 --format='%B' "$ZIP_IN")
printf '%s\n' "$ibody" | grep -F 'Signed-off-by: eternal-flame-AD' >/dev/null
iauthor=$("${git_cmd[@]}" -C "$ZIP" log -1 --format='%an' "$ZIP_IN")
[[ $iauthor == 'eternal-flame-AD' ]]
peel223=$("${git_cmd[@]}" -C "$ZIP" rev-parse 'v2.2.3^{commit}')
peel230=$("${git_cmd[@]}" -C "$ZIP" rev-parse 'v2.3.0^{commit}')
[[ $peel223 == "$ZIP_V223" ]]
[[ $peel230 == "$ZIP_V230" ]]
assert_ancestor "$ZIP" "$ZIP_FIX" "v2.3.0"
assert_not_ancestor "$ZIP" "$ZIP_FIX" "v2.2.3"
zblob_223=$("${git_cmd[@]}" -C "$ZIP" rev-parse "v2.2.3:src/read.rs")
zblob_230=$("${git_cmd[@]}" -C "$ZIP" rev-parse "v2.3.0:src/read.rs")
[[ $zblob_223 == "$ZIP_READ_V223" ]]
[[ $zblob_230 == "$ZIP_READ_V230" ]]
if "${git_cmd[@]}" -C "$ZIP" cat-file -e 'v2.2.3:src/path.rs' 2>/dev/null; then
  printf 'zip2 v2.2.3 unexpectedly has src/path.rs\n' >&2
  exit 1
fi

# tendermint
"${git_cmd[@]}" -C "$TM" cat-file -e "$TM_FIX^{commit}"
got_tparent=$("${git_cmd[@]}" -C "$TM" rev-parse "${TM_FIX}^")
[[ $got_tparent == "$TM_PARENT" ]]
tauthor=$("${git_cmd[@]}" -C "$TM" log -1 --format='%an' "$TM_FIX")
[[ $tauthor == 'Anton Kaliaev' ]]
tbody=$("${git_cmd[@]}" -C "$TM" log -1 --format='%B' "$TM_FIX")
if printf '%s\n' "$tbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'tendermint closer unexpectedly has AI marker\n' >&2
  exit 1
fi
printf '%s\n' "$tbody" | grep -F 'GHSA-6jrf-4jv4-r9mw' >/dev/null
peel402=$("${git_cmd[@]}" -C "$TM" rev-parse 'v0.40.2^{commit}')
peel403=$("${git_cmd[@]}" -C "$TM" rev-parse 'v0.40.3^{commit}')
[[ $peel402 == "$TM_PARENT" ]]
[[ $peel403 == "$TM_V403" ]]
assert_ancestor "$TM" "$TM_FIX" "v0.40.3"
assert_not_ancestor "$TM" "$TM_FIX" "v0.40.2"
tblob_p=$("${git_cmd[@]}" -C "$TM" rev-parse "v0.40.2:${TM_FILE}")
tblob_f=$("${git_cmd[@]}" -C "$TM" rev-parse "${TM_FIX}:${TM_FILE}")
tblob_403=$("${git_cmd[@]}" -C "$TM" rev-parse "v0.40.3:${TM_FILE}")
[[ $tblob_p == "$TM_VOTE_P" ]]
[[ $tblob_f == "$TM_VOTE_F" ]]
[[ $tblob_403 == "$TM_VOTE_F" ]]

# youtube-dl
"${git_cmd[@]}" -C "$YT" cat-file -e "$YT_CITED^{commit}"
"${git_cmd[@]}" -C "$YT" cat-file -e "$YT_DIRKF^{commit}"
yauthor=$("${git_cmd[@]}" -C "$YT" log -1 --format='%an' "$YT_DIRKF")
[[ $yauthor == 'dirkf' ]]
ybody=$("${git_cmd[@]}" -C "$YT" log -1 --format='%B' "$YT_DIRKF")
if printf '%s\n' "$ybody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'youtube-dl rem unexpectedly has AI marker\n' >&2
  exit 1
fi
assert_ancestor "$YT" "$YT_DIRKF" "HEAD"
pid1=$("${git_cmd[@]}" -C "$YT" show "$YT_CITED" | "${git_cmd[@]}" patch-id --stable | /usr/bin/awk '{print $1}')
pid2=$("${git_cmd[@]}" -C "$YT" show "$YT_DIRKF" | "${git_cmd[@]}" patch-id --stable | /usr/bin/awk '{print $1}')
[[ $pid1 == "$YT_PATCHID" ]]
[[ $pid2 == "$YT_PATCHID" ]]

# fhir
"${git_cmd[@]}" -C "$FH" cat-file -e "$FH_FIX^{commit}"
"${git_cmd[@]}" -C "$FH" cat-file -e "$FH_PRIOR^{commit}"
fauthor=$("${git_cmd[@]}" -C "$FH" log -1 --format='%an' "$FH_FIX")
[[ $fauthor == 'dotasek' ]]
fbody=$("${git_cmd[@]}" -C "$FH" log -1 --format='%B' "$FH_FIX")
if printf '%s\n' "$fbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'fhir closer unexpectedly has AI marker\n' >&2
  exit 1
fi
pauthor=$("${git_cmd[@]}" -C "$FH" log -1 --format='%an' "$FH_PRIOR")
[[ $pauthor == 'dotasek' ]]
pbody=$("${git_cmd[@]}" -C "$FH" log -1 --format='%B' "$FH_PRIOR")
printf '%s\n' "$pbody" | grep -F 'Fix XXE issue' >/dev/null
peel173=$("${git_cmd[@]}" -C "$FH" rev-parse '1.7.3^{commit}')
peel174=$("${git_cmd[@]}" -C "$FH" rev-parse '1.7.4^{commit}')
peel1622=$("${git_cmd[@]}" -C "$FH" rev-parse '1.6.22^{commit}')
[[ $peel173 == "$FH_173" ]]
[[ $peel174 == "$FH_174" ]]
[[ $peel1622 == "$FH_1622" ]]
assert_ancestor "$FH" "$FH_FIX" "1.7.4"
assert_not_ancestor "$FH" "$FH_FIX" "1.7.3"
assert_ancestor "$FH" "$FH_PRIOR" "1.6.22"

# codeql
"${git_cmd[@]}" -C "$CQ" cat-file -e "$CQ_FIX^{commit}"
got_cparent=$("${git_cmd[@]}" -C "$CQ" rev-parse "${CQ_FIX}^")
[[ $got_cparent == "$CQ_PARENT" ]]
cauthor=$("${git_cmd[@]}" -C "$CQ" log -1 --format='%an' "$CQ_FIX")
[[ $cauthor == 'Angela P Wen' ]]
csubj=$("${git_cmd[@]}" -C "$CQ" log -1 --format='%s' "$CQ_FIX")
[[ $csubj == 'Temporarily disable uploading debug artifacts' ]]
cbody=$("${git_cmd[@]}" -C "$CQ" log -1 --format='%B' "$CQ_FIX")
if printf '%s\n' "$cbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'codeql closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel3282=$("${git_cmd[@]}" -C "$CQ" rev-parse 'v3.28.2^{commit}')
peel3283=$("${git_cmd[@]}" -C "$CQ" rev-parse 'v3.28.3^{commit}')
[[ $peel3282 == "$CQ_V3282" ]]
[[ $peel3283 == "$CQ_V3283" ]]
assert_ancestor "$CQ" "$CQ_FIX" "v3.28.3"
assert_not_ancestor "$CQ" "$CQ_FIX" "v3.28.2"
cblob_p=$("${git_cmd[@]}" -C "$CQ" rev-parse "${CQ_PARENT}:${CQ_FILE}")
cblob_f=$("${git_cmd[@]}" -C "$CQ" rev-parse "${CQ_FIX}:${CQ_FILE}")
cblob_3282=$("${git_cmd[@]}" -C "$CQ" rev-parse "v3.28.2:${CQ_FILE}")
cblob_3283=$("${git_cmd[@]}" -C "$CQ" rev-parse "v3.28.3:${CQ_FILE}")
[[ $cblob_p == "$CQ_BLOB_P" ]]
[[ $cblob_f == "$CQ_BLOB_F" ]]
[[ $cblob_3282 == "$CQ_BLOB_P" ]]
[[ $cblob_3283 == "$CQ_BLOB_F" ]]

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
[[ $lblob_p == "$LS3_BLOB_P" ]]
[[ $lblob_f == "$LS3_BLOB_F" ]]
[[ $lblob_120 == "$LS3_BLOB_P" ]]
[[ $lblob_121 == "$LS3_BLOB_F" ]]
lfix_src=$("${git_cmd[@]}" -C "$LS3" show "${LS3_FIX}:${LS3_XML}")
printf '%s\n' "$lfix_src" | grep -F 'XMLInputFactory.SUPPORT_DTD' >/dev/null
lparent_src=$("${git_cmd[@]}" -C "$LS3" show "${LS3_PARENT}:${LS3_XML}")
if printf '%s\n' "$lparent_src" | grep -F 'SUPPORT_DTD' >/dev/null; then
  printf 'locals3 parent unexpectedly disables DTD\n' >&2
  exit 1
fi
namerev=$("${git_cmd[@]}" -C "$LS3" name-rev --tags --name-only "$LS3_FIX")
[[ $namerev == '1.21~3' ]]

# tomselect
"${git_cmd[@]}" -C "$TS" cat-file -e "$TS_FIX^{commit}"
tsauthor=$("${git_cmd[@]}" -C "$TS" log -1 --format='%an' "$TS_FIX")
[[ $tsauthor == 'jacklinke' ]]
tssubj=$("${git_cmd[@]}" -C "$TS" log -1 --format='%s' "$TS_FIX")
[[ $tssubj == 'Escape and sanitize all variables and data passed to js' ]]
tsbody=$("${git_cmd[@]}" -C "$TS" log -1 --format='%B' "$TS_FIX")
if printf '%s\n' "$tsbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'tomselect closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel532=$("${git_cmd[@]}" -C "$TS" rev-parse '2025.3.2^{commit}')
peel533=$("${git_cmd[@]}" -C "$TS" rev-parse '2025.3.3^{commit}')
[[ $peel532 == "$TS_532" ]]
[[ $peel533 == "$TS_533" ]]
assert_ancestor "$TS" "$TS_FIX" "2025.3.3"
assert_not_ancestor "$TS" "$TS_FIX" "2025.3.2"
if "${git_cmd[@]}" -C "$TS" cat-file -e "2025.3.2:${TS_UTILS}" 2>/dev/null; then
  printf 'tomselect 2025.3.2 unexpectedly has utils.py\n' >&2
  exit 1
fi
tsblob=$("${git_cmd[@]}" -C "$TS" rev-parse "${TS_FIX}:${TS_UTILS}")
tsblob533=$("${git_cmd[@]}" -C "$TS" rev-parse "2025.3.3:${TS_UTILS}")
[[ $tsblob == "$TS_BLOB_F" ]]
[[ $tsblob533 == "$TS_BLOB_F" ]]
nparents_m=$("${git_cmd[@]}" -C "$TS" rev-list --parents -n 1 "$TS_MERGE")
[[ $nparents_m == "$TS_MERGE $TS_532 $TS_FIX" ]]

# lnbits
"${git_cmd[@]}" -C "$LN" cat-file -e "$LN_LAST^{commit}"
"${git_cmd[@]}" -C "$LN" cat-file -e "$LN_HUMAN^{commit}"
peel_ln=$("${git_cmd[@]}" -C "$LN" rev-parse 'v0.12.12^{commit}')
[[ $peel_ln == "$LN_LAST" ]]
peel_v100=$("${git_cmd[@]}" -C "$LN" rev-parse 'v1.0.0^{commit}')
[[ $peel_v100 == "$LN_V100" ]]
assert_not_ancestor "$LN" "$LN_HUMAN" "v0.12.12"
assert_ancestor "$LN" "$LN_HUMAN" "v1.0.0"
lnauthor=$("${git_cmd[@]}" -C "$LN" log -1 --format='%an' "$LN_HUMAN")
[[ $lnauthor == 'Vlad Stan' ]]
lnbody=$("${git_cmd[@]}" -C "$LN" log -1 --format='%B' "$LN_HUMAN")
if printf '%s\n' "$lnbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'lnbits callback rem unexpectedly has AI marker\n' >&2
  exit 1
fi

python3 - "$ZIP" "$TM" "$YT" "$FH" "$CQ" "$LS3" "$TS" "$LN" \
  "$ZIP_FIX" "$ZIP_IN" "$TM_FIX" "$YT_DIRKF" "$FH_FIX" "$FH_PRIOR" "$CQ_FIX" "$LS3_FIX" "$TS_FIX" "$LN_HUMAN" << 'PY'
import re, subprocess, sys

repos = sys.argv[1:9]
protected = sys.argv[9:]
pat = re.compile(
    r"Co-authored-by:.*(Claude|Cursor|Copilot|GPT|OpenAI|Gemini|Codex|Anthropic)|"
    r"Generated with Claude|Generated with Copilot|noreply@anthropic|chatgpt|claude\.ai",
    re.I,
)
git = ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]
empty_ok = {
    repos[1],  # tendermint
    repos[2],  # youtube-dl
    repos[5],  # local-s3
    repos[6],  # tomselect
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

printf 'REPLAY_OK reviewed=8 PASS_proposal=0 NARROW=0 REJECT=8 UNKNOWN=0 BLOCKED=0\n'
