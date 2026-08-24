#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-increm20i-blocked11-recovery-grok46-xhigh.
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
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-increm20i-blocked11-recovery-grok46-xhigh
CACHE=/home/hanqing/.cache/ghsa200-worker-clones/recovery20i-260814
SRC20I=$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20i-grok46-low
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database

CDF=$CACHE/pimcore__customer-data-framework
S3=$CACHE/oxyno-zeta__s3-proxy
REDAXO=$CACHE/redaxo__redaxo
REDAXO_CORE=$CACHE/redaxo__core
HORCRUX=$CACHE/strangelove-ventures__horcrux
VELA=$CACHE/go-vela__server
CHEQD=$CACHE/cheqd__cheqd-node
IBC=$CACHE/cosmos__ibc-go
HTML=$CACHE/jitbit__HtmlSanitizer
VLLM=$CACHE/vllm-project__vllm
SUR=$CACHE/surrealdb__surrealdb

CDF_FIX=a49b322bb870e4b30c6f3d5456b516bf296f3bea
CDF_SEG=src/CustomerList/Filter/CustomerSegment.php
CDF_BLOB_PARENT=3bf9fcadd5c9f67743558a78f2610e53670203f8
CDF_420=4ec3748325cf42cab8df2a8ff4d8653338eddb1a
CDF_421=8da6d00cff036ee5ec6f5595e8b99a704e9ee12c

S3_FIX=c611c741ed4872ea3f46232be23bb830f96f9564
S3_TPL=pkg/s3-proxy/utils/templateutils/template.go
S3_FOLDER=templates/folder-list.tpl
S3_BLOB_PARENT=9a294d6691b8fd8c0ca8e8372df7c357197d2344
S3_BLOB_FIX=377ed8be532eeb81ec9b35aeaf9e88379c4bf6ee
S3_FOLDER_BLOB=feead67da42b39c08bbbb25ac1e2de04e88d5735
S3_4180=890f6e202892139764532a95c13d5eb6f95a432d

REDAXO_FIX=44df786f12e42facdecc4bda62169c73c3c1cb6e
REDAXO_API=redaxo/src/core/lib/api_function.php
REDAXO_BLOB_PARENT=98266a3e3b8f8f7c50ce6994e7e8f465fb30f1d2
REDAXO_BLOB_FIX=01592d5fe5d8293e88282dd52b8ccde7da97e298
REDAXO_5182=fdd41fcc9acb3cddb80b3f4098c820709193f457
REDAXO_5183=aa9ad0f744c77f93f01f873bc15a5cbcf458855b
REDAXO_CSRF=c490c7880373b6fd0687a7607041ee7404964dca

HORCRUX_FIX=fb49be9baed30942b81b42da2b4f7040a2a83c02
HORCRUX_INTRO=34c4db1d43221b20e34511d7fff7734e4743525e
HORCRUX_SS=signer/sign_state.go
HORCRUX_BLOB_PARENT=f6c55eb089da88595ae485f1a07858d9f4b6486e
HORCRUX_BLOB_FIX=b780607524cbcb195c07f5765f712b593020884b
HORCRUX_331=735808bd5b97c3665d07c2ea77c1d5e69a8d64cd
HORCRUX_310=03f565d67bb5394a4b3017a1adb00561d5297724

VELA_FIX=20c5a6cb0173c5bdda8b6f0ae093bac9ea72658f
VELA_BACKPORT=67c1892e2464dc54b8d2588815dfb7819222500b
VELA_CORS=257886e5a3eea518548387885894e239668584f5
VELA_COPILOT=65953f2b1a543bdd2424fb4daad8c906d7905745
VELA_WH=api/webhook/post.go
VELA_BLOB_PARENT=e5f64488910bffac3a74adaf0db6857a683ef5ec
VELA_BLOB_FIX=2fec135ec62f768eea8f699eff7b45dd6d25028d
VELA_262=ff7c877f9ac113691dbd930af5b15ded5b0c3e63
VELA_263=15195c5a0eb8c3d662c6c4fa8299b94ad351e3eb

CHEQD_33CR=7a6075b9b44001b19f0fc7573eeeca594863a3ec
CHEQD_H2RP=5a58b08dfb8dfc24631fb85b641cb75e9178d07f
CHEQD_IBC_SHA=59987d52d959dc5876ffd4f307c9b33a52a43748
CHEQD_316=c061371089fdf75f0f723325d6c2dfd35a71c942
CHEQD_317=3374ba2d70f3583dc0eb3e6951baa14d36f0684b
CHEQD_318=ae5e5e7fcd2f08439efcd153c34ce6fde4b51c66

IBC_FIX8=17b2240cb206f1403534594302f4e33785add4f0
IBC_FIX7=a5b5b929831859be62c5f7dc94970efa868cc84b
IBC_PRIOR8=59987d52d959dc5876ffd4f307c9b33a52a43748
IBC_PRIOR7=9869b3c6f7eb05a935b1eb33611c5406f68438a5
IBC_PKT=modules/core/04-channel/keeper/packet.go
IBC_BLOB_PARENT=698dc952a3590959a6c775e63bc850dcb6e68dc2
IBC_BLOB_FIX8=84b50411c00318cd76daa78a218e772565b6fd97
IBC_BLOB_PARENT7=827f324d9accdeb109814b64ef2505d4d5b01968
IBC_BLOB_FIX7=5856be49ae7a328fd7e4ecbeb8ca57fcb972f0fd
IBC_860=91dda01659676dfc15339a196b0750b6c808af93
IBC_870=53eaba19375dab0145509af101dbce193284ec5d
IBC_790=37ab926637aab78892aed61952fbb4b49da48ccd
IBC_710=4632144de1f563f26406e2185e977a06a60a35b7

HTML_FIX=af6d2a78877e7277cd01c825b7fb50edb5956963
HTML_JS=HtmlSanitizer.js
HTML_BLOB_PARENT=6ca8ea83890f4944b4503f91e24f767373bba8a2
HTML_202=ace3c2e2c915149581fbee95a49493a56914d9e9
HTML_203=67d23a1bd2f8a2dd66939449a89f307b2f0acac1

VLLM_FIX=776dcec8fe51860d7580001de86216406629df0f
VLLM_OUT=vllm/model_executor/guided_decoding/outlines_logits_processors.py
VLLM_BLOB_PARENT=a05267d921d1affc7dc1edef9bfc8a69715e1aee
VLLM_BLOB_FIX=8b2a0f4cfe64b75d9e2230e45e2cd420eb1add77
VLLM_073=ed6e9075d31e32c8548b480a47d1ffb77da1f54c
VLLM_080=966f933ee1cd7c9a41db60de5c7ff98657005251

SUR_FIX=3be0366bb9356f41e376797ffe80902820fa9f3e
SUR_L21=d1d41efca2279989799de4ee98ab65a926833a44
SUR_L22=b86f6ac5cdb4831c0ee1ed9004293c860c4a7337
SUR_EXP=core/src/kvs/export.rs
SUR_BLOB_PARENT=3a5b1bd1ec90ee68df14b5863999b6ded9cd94f1
SUR_BLOB_FIX=317239b2d6282dc2ee03fc318e82f0c3753942ab
SUR_204=f43a062c1ad7d346f1e2454ebd23d0ea6094db98
SUR_205=a83e960ee5513a3e39c88f312fabba83f8e15322

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
require_dir "$CDF/.git"
require_dir "$S3/.git"
require_dir "$REDAXO/.git"
require_dir "$REDAXO_CORE/.git"
require_dir "$HORCRUX/.git"
require_dir "$VELA/.git"
require_dir "$CHEQD/.git"
require_dir "$IBC/.git"
require_dir "$HTML/.git"
require_dir "$VLLM/.git"
require_dir "$SUR/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/ledger.jsonl" \
  3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9
expect_hash "$SRC20I/cases.jsonl" \
  6b09bda420bf5a167b9e259b80a01a8de8c37da5c4a3aa52d8a6d32090e36395
expect_hash "$SRC20I/work/selected-20.jsonl" \
  e7e23c15eb7d29d77bb1f0d6e0289ddd3a4e293d5fe7dccf5b7b19bf47441002
expect_hash "$OWNED/cases.jsonl" \
  7eb7886b9fb9818bedd79e860a9ef411740d3e2eabf8af5717251967e4678de8
expect_hash "$OWNED/report.md" \
  5d0436d7a0a855ef55356282c32aaed8b7697bad10f01a7a764bf87df63f6d74
expect_hash "$OWNED/work/pages/advisory/GHSA-q53r-9hh9-w277.json" \
  39c4f8aa4872189d851693c15ab4183e56ad13b61954642f810e179d8dc63fd1
expect_hash "$OWNED/work/pages/advisory/GHSA-pp9m-qf39-hxjc.json" \
  cf9eb32c011cf84485cffb9f0f9953715217b53a3749f3a4a4770752f592d83d
expect_hash "$OWNED/work/pages/advisory/GHSA-8366-xmgf-334f.json" \
  2501f756d1b6d5775a120833e10d015f5769cc35d653acb8218285ec4211ac67
expect_hash "$OWNED/work/pages/advisory/GHSA-6wxf-7784-62fp.json" \
  f8798ad072e66aff1a2f1b8cdc93eff3b93721eaf7b84a616c37e0c16b284687
expect_hash "$OWNED/work/pages/advisory/GHSA-9m63-33q3-xq5x.json" \
  9e22245487e6397c9d1958397f445153456b774b0f89a953aadf3ae3bcf0d91a
expect_hash "$OWNED/work/pages/advisory/GHSA-33cr-m232-xqch.json" \
  3dcf9c86247bb3a094d11efe15107a1729a5ad9748e8b3755e8dbcabd67ac485
expect_hash "$OWNED/work/pages/advisory/GHSA-4wf3-5qj9-368v.json" \
  5f37a3e7877c483f685a42dde521b079d0424f35850bb64ccd4319b050e79d27
expect_hash "$OWNED/work/pages/advisory/GHSA-h2rp-8vpx-q9r4.json" \
  d065c28d5295ebc7c5b4fff443c9c5ee5bab1e7a0a6120ba2e6669393c742c96
expect_hash "$OWNED/work/pages/advisory/GHSA-vhv4-fh94-jm5x.json" \
  0832cbb3291093f2486b620e1c73a9fb73eb10308028a6044a071cf5eb126008
expect_hash "$OWNED/work/pages/advisory/GHSA-mgrm-fgjv-mhv8.json" \
  7912efa9f68c85e9dd49026278b16adcbc1ea1c184ec8d770270b06dd4f08d44
expect_hash "$OWNED/work/pages/advisory/GHSA-ccj3-5p93-8p42.json" \
  e3feb9d70b113d263bdd385bba7eddaeb751d0bcbc5c2eeafc5bc913bb0a95a9
expect_hash "$OWNED/work/pages/ghsa/GHSA-q53r-9hh9-w277.json" \
  2cc626516270b4870bb4bdec74a6df7d36daf6d5aa465e982c1551bf0bb99993
expect_hash "$OWNED/work/pages/ghsa/GHSA-pp9m-qf39-hxjc.json" \
  ce01dea0f9b701240b48e80df1b728c91a87d80ef2de2d8c41ec27a43b88e136
expect_hash "$OWNED/work/pages/ghsa/GHSA-8366-xmgf-334f.json" \
  18cf0761dec3fdcde4b56b457dfccacd54131ca8d7703f161359fa2064674c1a
expect_hash "$OWNED/work/pages/ghsa/GHSA-6wxf-7784-62fp.json" \
  29f6e7108ab048fd028bfa8e4d5f4e6594c9cd22dc3e51d69179ea3b2bd52305
expect_hash "$OWNED/work/pages/ghsa/GHSA-9m63-33q3-xq5x.json" \
  e83f40b427ba11c9be56735f491de18e6887c378c52e3a4ad6c53e8d12c4f0cb
expect_hash "$OWNED/work/pages/ghsa/GHSA-33cr-m232-xqch.json" \
  2d0e1c8e1af53291382dabb22e5346c19a778d9943486d7d5cdf2811382e5b3a
expect_hash "$OWNED/work/pages/ghsa/GHSA-4wf3-5qj9-368v.json" \
  63121c0bdbe842a3d3a3fd58a6158ddb2b93f31a2cd919fda0ed2b0e3cfe3da9
expect_hash "$OWNED/work/pages/ghsa/GHSA-h2rp-8vpx-q9r4.json" \
  f543ac1181d44b74e2473ec6f705caf268ab6f18d84fb2b6b90ec7d64ccd8605
expect_hash "$OWNED/work/pages/ghsa/GHSA-vhv4-fh94-jm5x.json" \
  f58ff5b7790500d23958a3229d845b7ba41c89e89362a49f46523662f87910ba
expect_hash "$OWNED/work/pages/ghsa/GHSA-mgrm-fgjv-mhv8.json" \
  cd6fe458ed402147c11aabe1305d9012d6fd71d5745c3a2f44434f2b4859c6f9
expect_hash "$OWNED/work/pages/ghsa/GHSA-ccj3-5p93-8p42.json" \
  9b6afb6c09518a6e5103a171d00cb385f4a921f2e2f6a9a07eac26d4f73e85e4

[[ "$("${git_cmd[@]}" -C "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]
[[ "$("${git_cmd[@]}" -C "$REDAXO" rev-parse HEAD)" == "$("${git_cmd[@]}" -C "$REDAXO_CORE" rev-parse HEAD)" ]]

python3 - "$OWNED" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  "$SRC20I/cases.jsonl" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 11, len(rows)
want = [
    "GHSA-Q53R-9HH9-W277",
    "GHSA-PP9M-QF39-HXJC",
    "GHSA-8366-XMGF-334F",
    "GHSA-6WXF-7784-62FP",
    "GHSA-9M63-33Q3-XQ5X",
    "GHSA-33CR-M232-XQCH",
    "GHSA-4WF3-5QJ9-368V",
    "GHSA-H2RP-8VPX-Q9R4",
    "GHSA-VHV4-FH94-JM5X",
    "GHSA-MGRM-FGJV-MHV8",
    "GHSA-CCJ3-5P93-8P42",
]
assert [r["case_id"] for r in rows] == want
src = [json.loads(l) for l in Path(sys.argv[3]).read_text().splitlines() if l.strip()]
src_ids = [r["case_id"] for r in src if r["case_id"] in set(want)]
assert src_ids == want
assert all(r.get("worker_verdict") == "BLOCKED" for r in src if r["case_id"] in set(want))
assert all(r["worker_verdict"] == "REJECT" for r in rows)
assert all(r["worker_verdict"] != "PASS" for r in rows)
reject = {r["case_id"]: r["reject_class"] for r in rows}
assert reject["GHSA-4WF3-5QJ9-368V"] == "HUMAN_INCOMPLETE_PRIOR_NOT_AI"
for i in want:
    if i != "GHSA-4WF3-5QJ9-368V":
        assert reject[i] == "ORIGIN_NOT_INCOMPLETE_REMEDIATION", (i, reject[i])
r33 = next(r for r in rows if r["case_id"] == "GHSA-33CR-M232-XQCH")
rh2 = next(r for r in rows if r["case_id"] == "GHSA-H2RP-8VPX-Q9R4")
assert r33["repository"] == rh2["repository"] == "cheqd/cheqd-node"
assert r33["minimum_fix_set"] != rh2["minimum_fix_set"]
assert r33["mechanism_key"] != rh2["mechanism_key"]
for r in rows:
    assert r["causal_admission"] is False
    assert r["countable"] is False
    assert r["publication_status"] == "HOLD"
    assert r["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    assert r["identity_gate"] == "PASS" and r["gates"]["identity_gate"] == "PASS"
    assert r["uniqueness_gate"] == "PASS" and r["gates"]["uniqueness_gate"] == "PASS"
    assert r["ai_hunk_gate"] == "FAIL"
    assert r["remediation_patch_delta"] == "FAIL"
    for g in ["ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate"]:
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
g_q = json.loads((owned / "work/pages/ghsa/GHSA-q53r-9hh9-w277.json").read_text())
assert g_q["ghsa_id"] == "GHSA-q53r-9hh9-w277"
assert g_q["withdrawn_at"] is None
assert g_q["cve_id"] == "CVE-2024-11956"
assert g_q["source_code_location"] == "https://github.com/pimcore/pimcore"
g_p = json.loads((owned / "work/pages/ghsa/GHSA-pp9m-qf39-hxjc.json").read_text())
assert g_p["cve_id"] == "CVE-2025-27088"
g_r = json.loads((owned / "work/pages/ghsa/GHSA-8366-xmgf-334f.json").read_text())
assert g_r["source_code_location"] == "https://github.com/redaxo/redaxo"
g_h = json.loads((owned / "work/pages/ghsa/GHSA-6wxf-7784-62fp.json").read_text())
assert g_h["cve_id"] is None
g_v = json.loads((owned / "work/pages/ghsa/GHSA-9m63-33q3-xq5x.json").read_text())
assert g_v["cve_id"] == "CVE-2025-27616"
g_33 = json.loads((owned / "work/pages/ghsa/GHSA-33cr-m232-xqch.json").read_text())
assert g_33["source_code_location"] == "https://github.com/cheqd/cheqd-node"
assert g_33["cve_id"] is None
g_4 = json.loads((owned / "work/pages/ghsa/GHSA-4wf3-5qj9-368v.json").read_text())
assert g_4["source_code_location"] == "https://github.com/cosmos/ibc-go"
g_h2 = json.loads((owned / "work/pages/ghsa/GHSA-h2rp-8vpx-q9r4.json").read_text())
assert g_h2["source_code_location"] == "https://github.com/cheqd/cheqd-node"
g_html = json.loads((owned / "work/pages/ghsa/GHSA-vhv4-fh94-jm5x.json").read_text())
assert g_html["cve_id"] == "CVE-2025-29771"
g_m = json.loads((owned / "work/pages/ghsa/GHSA-mgrm-fgjv-mhv8.json").read_text())
assert g_m["cve_id"] == "CVE-2025-29770"
g_c = json.loads((owned / "work/pages/ghsa/GHSA-ccj3-5p93-8p42.json").read_text())
assert g_c["cve_id"] is None
print("conservation assigned=11 reviewed=11 unreviewed=0 PASS_proposal=0 NARROW=0 REJECT=11 UNKNOWN=0 BLOCKED=0")
PY

# pimcore/customer-data-framework (GHSA-Q53R)
"${git_cmd[@]}" -C "$CDF" cat-file -e "$CDF_FIX^{commit}"
cauthor=$("${git_cmd[@]}" -C "$CDF" log -1 --format='%an' "$CDF_FIX")
[[ $cauthor == 'Matthias Schuhmayer' ]]
csubj=$("${git_cmd[@]}" -C "$CDF" log -1 --format='%s' "$CDF_FIX")
[[ $csubj == '[Bug]: Use parameters for joins in Customer Segment (#549)' ]]
cbody=$("${git_cmd[@]}" -C "$CDF" log -1 --format='%B' "$CDF_FIX")
if printf '%s\n' "$cbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'cdf closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel420=$("${git_cmd[@]}" -C "$CDF" rev-parse 'v4.2.0^{commit}')
peel421=$("${git_cmd[@]}" -C "$CDF" rev-parse 'v4.2.1^{commit}')
[[ $peel420 == "$CDF_420" ]]
[[ $peel421 == "$CDF_421" ]]
assert_ancestor "$CDF" "$CDF_FIX" "v4.2.1"
assert_not_ancestor "$CDF" "$CDF_FIX" "v4.2.0"
cblob_p=$("${git_cmd[@]}" -C "$CDF" rev-parse "${CDF_FIX}^:${CDF_SEG}")
cblob_420=$("${git_cmd[@]}" -C "$CDF" rev-parse "v4.2.0:${CDF_SEG}")
[[ $cblob_p == "$CDF_BLOB_PARENT" ]]
[[ $cblob_420 == "$CDF_BLOB_PARENT" ]]
csrc=$("${git_cmd[@]}" -C "$CDF" show "${CDF_FIX}:${CDF_SEG}")
printf '%s\n' "$csrc" | grep -F 'setParameter' >/dev/null

# oxyno-zeta/s3-proxy (GHSA-PP9M)
"${git_cmd[@]}" -C "$S3" cat-file -e "$S3_FIX^{commit}"
sauthor=$("${git_cmd[@]}" -C "$S3" log -1 --format='%an' "$S3_FIX")
[[ $sauthor == 'Havrileck Alexandre' ]]
ssubj=$("${git_cmd[@]}" -C "$S3" log -1 --format='%s' "$S3_FIX")
[[ $ssubj == 'fix: Sanitize all http request fields to avoid XSS injection in templates' ]]
sbody=$("${git_cmd[@]}" -C "$S3" log -1 --format='%B' "$S3_FIX")
if printf '%s\n' "$sbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 's3-proxy closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel4180=$("${git_cmd[@]}" -C "$S3" rev-parse 'v4.18.0^{commit}')
peel4181=$("${git_cmd[@]}" -C "$S3" rev-parse 'v4.18.1^{commit}')
[[ $peel4180 == "$S3_4180" ]]
[[ $peel4181 == "$S3_FIX" ]]
assert_ancestor "$S3" "$S3_FIX" "v4.18.1"
assert_not_ancestor "$S3" "$S3_FIX" "v4.18.0"
sblob_p=$("${git_cmd[@]}" -C "$S3" rev-parse "v4.18.0:${S3_TPL}")
sblob_f=$("${git_cmd[@]}" -C "$S3" rev-parse "v4.18.1:${S3_TPL}")
sblob_folder0=$("${git_cmd[@]}" -C "$S3" rev-parse "v4.18.0:${S3_FOLDER}")
sblob_folder1=$("${git_cmd[@]}" -C "$S3" rev-parse "v4.18.1:${S3_FOLDER}")
[[ $sblob_p == "$S3_BLOB_PARENT" ]]
[[ $sblob_f == "$S3_BLOB_FIX" ]]
[[ $sblob_folder0 == "$S3_FOLDER_BLOB" ]]
[[ $sblob_folder1 == "$S3_FOLDER_BLOB" ]]
ssrc=$("${git_cmd[@]}" -C "$S3" show "${S3_FIX}:${S3_TPL}")
printf '%s\n' "$ssrc" | grep -F 'LightSanitizedRequest' >/dev/null

# redaxo/redaxo (GHSA-8366)
"${git_cmd[@]}" -C "$REDAXO" cat-file -e "$REDAXO_FIX^{commit}"
rauthor=$("${git_cmd[@]}" -C "$REDAXO" log -1 --format='%an' "$REDAXO_FIX")
[[ $rauthor == 'Gregor Harlan' ]]
rsubj=$("${git_cmd[@]}" -C "$REDAXO" log -1 --format='%s' "$REDAXO_FIX")
[[ $rsubj == 'API-Functions: Bei Reboot Result in Session zwischenspeichern (#6260)' ]]
rbody=$("${git_cmd[@]}" -C "$REDAXO" log -1 --format='%B' "$REDAXO_FIX")
if printf '%s\n' "$rbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'redaxo closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel5182=$("${git_cmd[@]}" -C "$REDAXO" rev-parse '5.18.2^{commit}')
peel5183=$("${git_cmd[@]}" -C "$REDAXO" rev-parse '5.18.3^{commit}')
[[ $peel5182 == "$REDAXO_5182" ]]
[[ $peel5183 == "$REDAXO_5183" ]]
assert_ancestor "$REDAXO" "$REDAXO_FIX" "5.18.3"
assert_not_ancestor "$REDAXO" "$REDAXO_FIX" "5.18.2"
assert_not_ancestor "$REDAXO" "$REDAXO_CSRF" "5.18.3"
rblob_p=$("${git_cmd[@]}" -C "$REDAXO" rev-parse "5.18.2:${REDAXO_API}")
rblob_f=$("${git_cmd[@]}" -C "$REDAXO" rev-parse "5.18.3:${REDAXO_API}")
[[ $rblob_p == "$REDAXO_BLOB_PARENT" ]]
[[ $rblob_f == "$REDAXO_BLOB_FIX" ]]
rsrc=$("${git_cmd[@]}" -C "$REDAXO" show "${REDAXO_FIX}:${REDAXO_API}")
printf '%s\n' "$rsrc" | grep -F 'rex_set_session' >/dev/null

# strangelove-ventures/horcrux (GHSA-6WXF)
"${git_cmd[@]}" -C "$HORCRUX" cat-file -e "$HORCRUX_FIX^{commit}"
hauthor=$("${git_cmd[@]}" -C "$HORCRUX" log -1 --format='%an' "$HORCRUX_FIX")
[[ $hauthor == 'Andrew Gouin' ]]
hsubj=$("${git_cmd[@]}" -C "$HORCRUX" log -1 --format='%s' "$HORCRUX_FIX")
[[ $hsubj == 'single lock for read and write (#297)' ]]
hbody=$("${git_cmd[@]}" -C "$HORCRUX" log -1 --format='%B' "$HORCRUX_FIX")
if printf '%s\n' "$hbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'horcrux closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel331=$("${git_cmd[@]}" -C "$HORCRUX" rev-parse 'v3.3.1^{commit}')
peel332=$("${git_cmd[@]}" -C "$HORCRUX" rev-parse 'v3.3.2^{commit}')
peel310=$("${git_cmd[@]}" -C "$HORCRUX" rev-parse 'v3.1.0^{commit}')
[[ $peel331 == "$HORCRUX_331" ]]
[[ $peel332 == "$HORCRUX_FIX" ]]
[[ $peel310 == "$HORCRUX_310" ]]
assert_ancestor "$HORCRUX" "$HORCRUX_INTRO" "v3.1.0"
assert_ancestor "$HORCRUX" "$HORCRUX_FIX" "v3.3.2"
assert_not_ancestor "$HORCRUX" "$HORCRUX_FIX" "v3.3.1"
hxblob_p=$("${git_cmd[@]}" -C "$HORCRUX" rev-parse "v3.3.1:${HORCRUX_SS}")
hxblob_f=$("${git_cmd[@]}" -C "$HORCRUX" rev-parse "v3.3.2:${HORCRUX_SS}")
[[ $hxblob_p == "$HORCRUX_BLOB_PARENT" ]]
[[ $hxblob_f == "$HORCRUX_BLOB_FIX" ]]

# go-vela/server (GHSA-9M63)
"${git_cmd[@]}" -C "$VELA" cat-file -e "$VELA_FIX^{commit}"
vauthor=$("${git_cmd[@]}" -C "$VELA" log -1 --format='%an' "$VELA_FIX")
[[ $vauthor == 'Easton Crupper' ]]
vsubj=$("${git_cmd[@]}" -C "$VELA" log -1 --format='%s' "$VELA_FIX")
[[ $vsubj == 'Merge commit from fork' ]]
vbody=$("${git_cmd[@]}" -C "$VELA" log -1 --format='%B' "$VELA_FIX")
printf '%s\n' "$vbody" | grep -F 'verify repository and installation events' >/dev/null
if printf '%s\n' "$vbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'vela closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel262=$("${git_cmd[@]}" -C "$VELA" rev-parse 'v0.26.2^{commit}')
peel263=$("${git_cmd[@]}" -C "$VELA" rev-parse 'v0.26.3^{commit}')
peel253=$("${git_cmd[@]}" -C "$VELA" rev-parse 'v0.25.3^{commit}')
[[ $peel262 == "$VELA_262" ]]
[[ $peel263 == "$VELA_263" ]]
[[ $peel253 == "$VELA_BACKPORT" ]]
assert_ancestor "$VELA" "$VELA_FIX" "v0.26.3"
assert_not_ancestor "$VELA" "$VELA_FIX" "v0.26.2"
assert_ancestor "$VELA" "$VELA_BACKPORT" "v0.25.3"
assert_not_ancestor "$VELA" "$VELA_COPILOT" "v0.26.3"
assert_not_ancestor "$VELA" "$VELA_COPILOT" "v0.25.3"
cors_files=$("${git_cmd[@]}" -C "$VELA" diff-tree --no-commit-id --name-only -r "$VELA_CORS")
if printf '%s\n' "$cors_files" | grep -F 'api/webhook/post.go' >/dev/null; then
  printf 'cited CORS SHA unexpectedly touches webhook post.go\n' >&2
  exit 1
fi
vblob_p=$("${git_cmd[@]}" -C "$VELA" rev-parse "v0.26.2:${VELA_WH}")
vblob_f=$("${git_cmd[@]}" -C "$VELA" rev-parse "v0.26.3:${VELA_WH}")
[[ $vblob_p == "$VELA_BLOB_PARENT" ]]
[[ $vblob_f == "$VELA_BLOB_FIX" ]]

# cheqd/cheqd-node (GHSA-33CR and GHSA-H2RP remain distinct)
"${git_cmd[@]}" -C "$CHEQD" cat-file -e "$CHEQD_33CR^{commit}"
"${git_cmd[@]}" -C "$CHEQD" cat-file -e "$CHEQD_H2RP^{commit}"
if "${git_cmd[@]}" -C "$CHEQD" cat-file -e "$CHEQD_IBC_SHA^{commit}" 2>/dev/null; then
  printf 'ibc-go SHA unexpectedly present in cheqd-node\n' >&2
  exit 1
fi
t33=$("${git_cmd[@]}" -C "$CHEQD" log -1 --format='%an' "$CHEQD_33CR")
[[ $t33 == 'Tasos Derisiotis' ]]
t33s=$("${git_cmd[@]}" -C "$CHEQD" log -1 --format='%s' "$CHEQD_33CR")
[[ $t33s == 'build: Bump ibc-go to latest recommended (patches https://github.com/cosmos/ibc-go/security/advisories/GHSA-jg6f-48ff-5xrw)' ]]
th2=$("${git_cmd[@]}" -C "$CHEQD" log -1 --format='%an' "$CHEQD_H2RP")
[[ $th2 == 'Tasos Derisiotis' ]]
th2s=$("${git_cmd[@]}" -C "$CHEQD" log -1 --format='%s' "$CHEQD_H2RP")
[[ $th2s == 'build: Bump `cosmos-sdk` + `ibc-go` to latest release lines (v0.47.17 + v7.10.0)' ]]
peel316=$("${git_cmd[@]}" -C "$CHEQD" rev-parse 'v3.1.6^{commit}')
peel317=$("${git_cmd[@]}" -C "$CHEQD" rev-parse 'v3.1.7^{commit}')
peel318=$("${git_cmd[@]}" -C "$CHEQD" rev-parse 'v3.1.8^{commit}')
[[ $peel316 == "$CHEQD_316" ]]
[[ $peel317 == "$CHEQD_317" ]]
[[ $peel318 == "$CHEQD_318" ]]
assert_ancestor "$CHEQD" "$CHEQD_33CR" "v3.1.7"
assert_not_ancestor "$CHEQD" "$CHEQD_33CR" "v3.1.6"
assert_ancestor "$CHEQD" "$CHEQD_H2RP" "v3.1.8"
assert_not_ancestor "$CHEQD" "$CHEQD_H2RP" "v3.1.7"
p33=$("${git_cmd[@]}" -C "$CHEQD" log -1 --format='%P' "$CHEQD_33CR")
[[ $p33 == "$CHEQD_316" ]]

# cosmos/ibc-go (GHSA-4WF3)
"${git_cmd[@]}" -C "$IBC" cat-file -e "$IBC_FIX8^{commit}"
"${git_cmd[@]}" -C "$IBC" cat-file -e "$IBC_FIX7^{commit}"
iauthor=$("${git_cmd[@]}" -C "$IBC" log -1 --format='%an' "$IBC_FIX8")
[[ $iauthor == 'Gjermund Garaba' ]]
isubj=$("${git_cmd[@]}" -C "$IBC" log -1 --format='%s' "$IBC_FIX8")
[[ $isubj == 'Merge commit from fork' ]]
ibody=$("${git_cmd[@]}" -C "$IBC" log -1 --format='%B' "$IBC_FIX8")
printf '%s\n' "$ibody" | grep -F 'Aditya Sripal' >/dev/null
if printf '%s\n' "$ibody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'ibc-go closer unexpectedly has AI marker\n' >&2
  exit 1
fi
iprior=$("${git_cmd[@]}" -C "$IBC" log -1 --format='%an %s' "$IBC_PRIOR8")
[[ $iprior == 'Gjermund Garaba fix: remove packet data remarshaling (#8065)' ]]
peel860=$("${git_cmd[@]}" -C "$IBC" rev-parse 'v8.6.0^{commit}')
peel861=$("${git_cmd[@]}" -C "$IBC" rev-parse 'v8.6.1^{commit}')
peel870=$("${git_cmd[@]}" -C "$IBC" rev-parse 'v8.7.0^{commit}')
peel790=$("${git_cmd[@]}" -C "$IBC" rev-parse 'v7.9.0^{commit}')
peel791=$("${git_cmd[@]}" -C "$IBC" rev-parse 'v7.9.1^{commit}')
peel710=$("${git_cmd[@]}" -C "$IBC" rev-parse 'v7.10.0^{commit}')
[[ $peel860 == "$IBC_860" ]]
[[ $peel861 == "$IBC_PRIOR8" ]]
[[ $peel870 == "$IBC_870" ]]
[[ $peel790 == "$IBC_790" ]]
[[ $peel791 == "$IBC_PRIOR7" ]]
[[ $peel710 == "$IBC_710" ]]
iparent=$("${git_cmd[@]}" -C "$IBC" log -1 --format='%P' "$IBC_FIX8")
[[ $iparent == "$IBC_PRIOR8" ]]
assert_not_ancestor "$IBC" "$IBC_PRIOR8" "v8.6.0"
assert_ancestor "$IBC" "$IBC_PRIOR8" "v8.6.1"
assert_not_ancestor "$IBC" "$IBC_FIX8" "v8.6.1"
assert_ancestor "$IBC" "$IBC_FIX8" "v8.7.0"
assert_not_ancestor "$IBC" "$IBC_PRIOR7" "v7.9.0"
assert_ancestor "$IBC" "$IBC_PRIOR7" "v7.9.1"
assert_not_ancestor "$IBC" "$IBC_FIX7" "v7.9.1"
assert_ancestor "$IBC" "$IBC_FIX7" "v7.10.0"
iblob_860=$("${git_cmd[@]}" -C "$IBC" rev-parse "v8.6.0:${IBC_PKT}")
iblob_861=$("${git_cmd[@]}" -C "$IBC" rev-parse "v8.6.1:${IBC_PKT}")
iblob_870=$("${git_cmd[@]}" -C "$IBC" rev-parse "v8.7.0:${IBC_PKT}")
iblob_790=$("${git_cmd[@]}" -C "$IBC" rev-parse "v7.9.0:${IBC_PKT}")
iblob_710=$("${git_cmd[@]}" -C "$IBC" rev-parse "v7.10.0:${IBC_PKT}")
[[ $iblob_860 == "$IBC_BLOB_PARENT" ]]
[[ $iblob_861 == "$IBC_BLOB_PARENT" ]]
[[ $iblob_870 == "$IBC_BLOB_FIX8" ]]
[[ $iblob_790 == "$IBC_BLOB_PARENT7" ]]
[[ $iblob_710 == "$IBC_BLOB_FIX7" ]]

# jitbit/HtmlSanitizer (GHSA-VHV4)
"${git_cmd[@]}" -C "$HTML" cat-file -e "$HTML_FIX^{commit}"
jauthor=$("${git_cmd[@]}" -C "$HTML" log -1 --format='%an' "$HTML_FIX")
[[ $jauthor == 'Alexander Yumashev' ]]
jsubj=$("${git_cmd[@]}" -C "$HTML" log -1 --format='%s' "$HTML_FIX")
[[ $jsubj == 'Removed <br> beautification, introduces attack vector' ]]
jbody=$("${git_cmd[@]}" -C "$HTML" log -1 --format='%B' "$HTML_FIX")
if printf '%s\n' "$jbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'htmlsanitizer closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel202=$("${git_cmd[@]}" -C "$HTML" rev-parse '2.0.2^{commit}')
peel203=$("${git_cmd[@]}" -C "$HTML" rev-parse '2.0.3^{commit}')
[[ $peel202 == "$HTML_202" ]]
[[ $peel203 == "$HTML_203" ]]
assert_ancestor "$HTML" "$HTML_FIX" "2.0.3"
assert_not_ancestor "$HTML" "$HTML_FIX" "2.0.2"
jblob_p=$("${git_cmd[@]}" -C "$HTML" rev-parse "2.0.2:${HTML_JS}")
[[ $jblob_p == "$HTML_BLOB_PARENT" ]]
jparent_src=$("${git_cmd[@]}" -C "$HTML" show "2.0.2:${HTML_JS}")
printf '%s\n' "$jparent_src" | grep -F '.replace(/<br[^>]*>(\S)/g, "<br>\n$1")' >/dev/null
jfix_src=$("${git_cmd[@]}" -C "$HTML" show "${HTML_FIX}:${HTML_JS}")
if printf '%s\n' "$jfix_src" | grep -F '.replace(/<br[^>]*>(\S)/g, "<br>\n$1")' >/dev/null; then
  printf 'htmlsanitizer closer still has br beautify replace\n' >&2
  exit 1
fi

# vllm-project/vllm (GHSA-MGRM)
"${git_cmd[@]}" -C "$VLLM" cat-file -e "$VLLM_FIX^{commit}"
mauthor=$("${git_cmd[@]}" -C "$VLLM" log -1 --format='%an' "$VLLM_FIX")
[[ $mauthor == 'Russell Bryant' ]]
msubj=$("${git_cmd[@]}" -C "$VLLM" log -1 --format='%s' "$VLLM_FIX")
[[ $msubj == 'Disable outlines cache by default (#14837)' ]]
mbody=$("${git_cmd[@]}" -C "$VLLM" log -1 --format='%B' "$VLLM_FIX")
if printf '%s\n' "$mbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'vllm closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel073=$("${git_cmd[@]}" -C "$VLLM" rev-parse 'v0.7.3^{commit}')
peel080=$("${git_cmd[@]}" -C "$VLLM" rev-parse 'v0.8.0^{commit}')
[[ $peel073 == "$VLLM_073" ]]
[[ $peel080 == "$VLLM_080" ]]
assert_ancestor "$VLLM" "$VLLM_FIX" "v0.8.0"
assert_not_ancestor "$VLLM" "$VLLM_FIX" "v0.7.3"
mblob_p=$("${git_cmd[@]}" -C "$VLLM" rev-parse "v0.7.3:${VLLM_OUT}")
mblob_f=$("${git_cmd[@]}" -C "$VLLM" rev-parse "v0.8.0:${VLLM_OUT}")
[[ $mblob_p == "$VLLM_BLOB_PARENT" ]]
[[ $mblob_f == "$VLLM_BLOB_FIX" ]]
msrc=$("${git_cmd[@]}" -C "$VLLM" show "${VLLM_FIX}:${VLLM_OUT}")
printf '%s\n' "$msrc" | grep -F 'VLLM_V0_USE_OUTLINES_CACHE' >/dev/null

# surrealdb/surrealdb (GHSA-CCJ3)
"${git_cmd[@]}" -C "$SUR" cat-file -e "$SUR_FIX^{commit}"
uauthor=$("${git_cmd[@]}" -C "$SUR" log -1 --format='%an' "$SUR_FIX")
[[ $uauthor == 'Mees Delzenne' ]]
usubj=$("${git_cmd[@]}" -C "$SUR" log -1 --format='%s' "$SUR_FIX")
[[ $usubj == 'Fix import injection security bug' ]]
ubody=$("${git_cmd[@]}" -C "$SUR" log -1 --format='%B' "$SUR_FIX")
if printf '%s\n' "$ubody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'surrealdb closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel204=$("${git_cmd[@]}" -C "$SUR" rev-parse 'v2.0.4^{commit}')
peel205=$("${git_cmd[@]}" -C "$SUR" rev-parse 'v2.0.5^{commit}')
[[ $peel204 == "$SUR_204" ]]
[[ $peel205 == "$SUR_205" ]]
assert_ancestor "$SUR" "$SUR_FIX" "v2.0.5"
assert_not_ancestor "$SUR" "$SUR_FIX" "v2.0.4"
assert_ancestor "$SUR" "$SUR_L21" "v2.1.5"
assert_ancestor "$SUR" "$SUR_L22" "v2.2.2"
l21s=$("${git_cmd[@]}" -C "$SUR" log -1 --format='%an %s' "$SUR_L21")
l22s=$("${git_cmd[@]}" -C "$SUR" log -1 --format='%an %s' "$SUR_L22")
[[ $l21s == 'Mees Delzenne Fix import injection security bug' ]]
[[ $l22s == 'Mees Delzenne Fix import injection security bug' ]]
ublob_p=$("${git_cmd[@]}" -C "$SUR" rev-parse "v2.0.4:${SUR_EXP}")
ublob_f=$("${git_cmd[@]}" -C "$SUR" rev-parse "v2.0.5:${SUR_EXP}")
[[ $ublob_p == "$SUR_BLOB_PARENT" ]]
[[ $ublob_f == "$SUR_BLOB_FIX" ]]
ufiles=$("${git_cmd[@]}" -C "$SUR" diff-tree --no-commit-id --name-only -r "$SUR_FIX")
printf '%s\n' "$ufiles" | grep -F 'core/src/kvs/export.rs' >/dev/null
printf '%s\n' "$ufiles" | grep -F 'core/src/sql/escape.rs' >/dev/null

python3 - "$CDF" "$S3" "$REDAXO" "$HORCRUX" "$VELA" "$CHEQD" "$IBC" "$HTML" "$VLLM" "$SUR" << 'PY'
import re, subprocess, sys

pat = re.compile(
    r"Co-authored-by:.*(Claude|Cursor Agent|Copilot|ChatGPT|OpenAI|Anthropic)|"
    r"Generated with Claude|Generated with Copilot|noreply@anthropic|"
    r"Made-with: Cursor|chatgpt|claude\.ai",
    re.I,
)
git = ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]
scans = [
    (sys.argv[1], ["--all"]),
    (sys.argv[2], ["--all"]),
    (sys.argv[3], ["5.18.3"]),
    (sys.argv[4], ["--all"]),
    (sys.argv[5], ["v0.26.3"]),
    (sys.argv[5], ["v0.25.3"]),
    (sys.argv[6], ["--all"]),
    (sys.argv[7], ["v8.7.0"]),
    (sys.argv[7], ["v7.10.0"]),
    (sys.argv[8], ["--all"]),
    (sys.argv[9], ["v0.8.0"]),
    (sys.argv[10], ["v2.0.5"]),
    (sys.argv[10], ["v2.2.2"]),
]
for repo, rev in scans:
    out = subprocess.check_output(
        git + ["-C", repo, "log"] + rev + ["--format=%H%x1f%an%x1f%s%x1f%b%x1e"],
        text=True,
        errors="replace",
    )
    hits = []
    for rec in out.split("\x1e"):
        if pat.search(rec):
            hits.append(rec.split("\x1f", 1)[0][:40])
    assert hits == [], (repo, rev, hits[:5])
print("ai_trailer_scan_empty_on_relevant_history")
PY

printf 'REPLAY_OK reviewed=11 PASS_proposal=0 NARROW=0 REJECT=11 UNKNOWN=0 BLOCKED=0\n'
