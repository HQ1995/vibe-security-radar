#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-increm20e-blocked9-recovery-grok46-xhigh.
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
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-increm20e-blocked9-recovery-grok46-xhigh
CACHE=/home/hanqing/.cache/ghsa200-worker-clones/recovery20e-260814
SNAP=$CACHE/canonical__snapd
CDK=$CACHE/aws__aws-cdk
RP=$CACHE/zopefoundation__RestrictedPython
AE=$CACHE/lmfit__asteval
CMS=$CACHE/opensource-workshop__connect-cms
LUC=$CACHE/instaclustr__cassandra-lucene-index
OPC=$CACHE/OPCFoundation__UA-.NETStandard
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database

SNAP_FIX=68ee9c6aa916ab87dbfd9a26030690f2cabf1e14
SNAP_PARENT=84106089df82cd9a9785f4cd1be6b27c60f92769
SNAP_CTL=overlord/hookstate/ctlcmd/ctlcmd.go
SNAP_BLOB_PARENT=b663420a3fb6008203c64db546b54d2507cb67c2
SNAP_BLOB_FIX=a4a717fd4da3c9480be4fce363adf9d41416d9b6
SNAP_2631=3ba5d67ca332f9fcb408ad0ad3cc70b3d67869ca
SNAP_264=98a40cf5b5f26308e6f608d5c10c0e154251569b

CDK_FIX=3e4f3773bfa48b75bf0adc7d53d46bbec7714a9e
CDK_OIDC='packages/@aws-cdk/custom-resource-handlers/lib/aws-iam/oidc-handler/external.ts'
CDK_BLOB_PARENT=1051a0c594831f950c4ebb8d3f69d47b770e5112
CDK_BLOB_FIX=840f462eb19556ad54160bbbf1a3afac6e0b09a8
CDK_2176=899965d6147829b8f8ac52ac8c1350de50d7b6d0
CDK_2177=b396961272695cd70ac183fdaf842ffb48f5d91f

RP_FIX=48a92c5bb617a647cffd0dadd4d5cfe626bcdb2f
RP_TRANS=src/RestrictedPython/transformer.py
RP_BLOB_PARENT=2034205204981f032aa681aeef3c66bc7f95cb2e
RP_BLOB_FIX=7fd301648f53517405bcc4681e4f5f842bac3a69
RP_74=7e5234545d9efcc02dd47b74ae14610fb516bc9a
RP_80=67d6d95794f5196295ad1f9af8811f938fc9fdc2

AE_MERGE=45bb47533f7abb5479618ae7f6a809215700dcb2
AE_MEMBER=babca619c10defdfcb5cd26c76de2ca5904cfac0
AE_105=8d7326df8015cf6a57506b1c2c167a1c3763e090
AE_106=40c31962bbdfe1012aacca1892a8d9263a67258e

CMS_FIX=cb64bfae4ee5028c95600a299abcc59a04e6159f
CMS_INTRO=105bf1c63a6722fa90db5e58e63176ca8da107ed
CMS_SEARCH=app/Plugins/User/Searchs/SearchsPlugin.php
CMS_BLOB_PARENT=94fca6757d82e32a253d2ea91099cafb6103bfe8
CMS_183=3be87176d2e38ec28e1fbef03ef9745b9a7e8f0c
CMS_184=5bd616c8b4f78672c35a6ba53b8ab3f3518d01a3

LUC_40=44ab4b639c9354a6335f40b1cf6178c745c6e101
LUC_41=94380b165bd3e597d3e22e47f8cc674ec7c7bf7f
LUC_HANDLER=plugin/src/main/scala/com/stratio/cassandra/lucene/IndexQueryHandler.scala
LUC_BLOB_40P=c54415ec2e19e2abb0ebbcd66bf0d9638ddc246d
LUC_BLOB_40=4a881e2a11e32c13d8dc8db1c0af8dae7c3203b5
LUC_BLOB_41P=cff6214a7cdb49010f7ab7ad736485e1be99670c
LUC_4180=b9e9244bb1ef37cd1bce59ae9b66253a7ce01b10
LUC_4181=68203d6ac1734ca617d8c22d8dc051102dc34026

OPC_H958=3543d0292556691f681e39145e2de4526b90487d
OPC_HTTPS=d0e89a3bf140efced967ad3482d8dd9c9c936c9f
OPC_TCP=Stack/Opc.Ua.Core/Stack/Tcp/TcpTransportListener.cs
OPC_HTTP=Stack/Opc.Ua.Bindings.Https/Stack/Https/HttpsTransportListener.cs
OPC_BLOB_TCP=27c51eb71760d13c7413bfc4e79cf80124cbe7e1
OPC_BLOB_HTTPS=7149e0483d1db956d7767def0d527354912392ac
OPC_158=f5d00d934cd1c0679e5f3cc6423ae60fa2046968
OPC_118=c4f0f735642a132652e821fc8f07c837bb11e2c4

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
require_dir "$SNAP/.git"
require_dir "$CDK/.git"
require_dir "$RP/.git"
require_dir "$AE/.git"
require_dir "$CMS/.git"
require_dir "$LUC/.git"
require_dir "$OPC/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/ledger.jsonl" \
  3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20e-grok46-low/cases.jsonl" \
  6fdcbb10380a24d6515eb32c8126d29d35b1822b25fe9cb57e87f5d83cf2b879
expect_hash "$OWNED/cases.jsonl" \
  52c93030a96afa3c2f3e3fa475c6c66da97f3f0240803827c71b3fef128820bb
expect_hash "$OWNED/report.md" \
  280e9c7c221c46e0c464a2a12b2710f8ffe26a6fe32ec373fb4e105977bda42d
expect_hash "$OWNED/work/pages/advisory/GHSA-p9v8-q5m4-pf46.json" \
  ae0288942166eaa7b258a26538629d72056870837e6682241f888a183689edb1
expect_hash "$OWNED/work/pages/advisory/GHSA-v4mq-x674-ff73.json" \
  a73c6d2a5e0c182e54e0194de6144fb4a5bba86461dc9df3059e7a96f290be6c
expect_hash "$OWNED/work/pages/advisory/GHSA-gmj9-h825-chq2.json" \
  83091616e4b2462c74fc84afe0b97ac97c510baafa940e8c1088a71f8e53f6bf
expect_hash "$OWNED/work/pages/advisory/GHSA-vp47-9734-prjw.json" \
  124a5de81e7b31f23f1b61c04423d655b9898374ff5b19df66cc104c3887f396
expect_hash "$OWNED/work/pages/advisory/GHSA-3wwr-3g9f-9gc7.json" \
  9ecaaac91246e6b5838f7e699aa00696e98c355967d567f619cfe8c0b24edd8e
expect_hash "$OWNED/work/pages/advisory/GHSA-2237-5r9w-vm8j.json" \
  8c8a4393d53872f78a0ae434043fa1c4f73aef32916b33e359879043000628a9
expect_hash "$OWNED/work/pages/advisory/GHSA-mrqp-q7vx-v2cx.json" \
  dea5bac8ac94d9a092ae88e1a3d64c5df929eb1a2ea01c4f981d1f33f4209e38
expect_hash "$OWNED/work/pages/advisory/GHSA-4rcc-7pg7-f57f.json" \
  3d32f943a4a9030996dc0a1e2a47b59a6847ed463986f108a2093c607648dc24
expect_hash "$OWNED/work/pages/advisory/GHSA-h958-fxgg-g7w3.json" \
  538b2bc654695205335e842171e8f0c2ed1c9e146241536ad7db259b0d040017
expect_hash "$OWNED/work/pages/ghsa/GHSA-p9v8-q5m4-pf46.json" \
  a1366616e53a7a79f477b89edffac0f083cb6db88d653c4b475db049334b63f4
expect_hash "$OWNED/work/pages/ghsa/GHSA-v4mq-x674-ff73.json" \
  cfa67f4874ef5b1f2416f000fe147685b4e502b3cad8f31421194302a82f6e2d
expect_hash "$OWNED/work/pages/ghsa/GHSA-gmj9-h825-chq2.json" \
  0800a2ef1d43bee03ad1a77b189d2d9ed7c93ec28b050893033f2f4b3253b70a
expect_hash "$OWNED/work/pages/ghsa/GHSA-vp47-9734-prjw.json" \
  cb0569075a4fc316700b82417329e4821baae8efc0c54ff9922e5894a85243da
expect_hash "$OWNED/work/pages/ghsa/GHSA-3wwr-3g9f-9gc7.json" \
  95f058f89895c7244f38b78183f77f183cff7f010c34169316161acda4468b08
expect_hash "$OWNED/work/pages/ghsa/GHSA-2237-5r9w-vm8j.json" \
  2e55ca27a75e5f062d51450549b3e49684c13aac886bd70811ac42e7c0ebf56c
expect_hash "$OWNED/work/pages/ghsa/GHSA-mrqp-q7vx-v2cx.json" \
  a75ca3d2e302c5504bd2da088ba1b893e49dee7f5801d5a6d68d531c11e65fb0
expect_hash "$OWNED/work/pages/ghsa/GHSA-4rcc-7pg7-f57f.json" \
  bec21ca5c49108cd2fc6198e0ee3d7282750746a1094b091472cc38b91bf4cea
expect_hash "$OWNED/work/pages/ghsa/GHSA-h958-fxgg-g7w3.json" \
  e223adfebe4a1683898f0685d349bb45177e8a9fd90ea2af802d3319d03eef22

[[ "$("${git_cmd[@]}" -C "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]

SRC20E_CASES=$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20e-grok46-low/cases.jsonl
python3 - "$OWNED" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  "$SRC20E_CASES" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 9, len(rows)
want = [
    "GHSA-P9V8-Q5M4-PF46",
    "GHSA-V4MQ-X674-FF73",
    "GHSA-GMJ9-H825-CHQ2",
    "GHSA-VP47-9734-PRJW",
    "GHSA-3WWR-3G9F-9GC7",
    "GHSA-2237-5R9W-VM8J",
    "GHSA-MRQP-Q7VX-V2CX",
    "GHSA-4RCC-7PG7-F57F",
    "GHSA-H958-FXGG-G7W3",
]
assert [r["case_id"] for r in rows] == want
src = [json.loads(l) for l in Path(sys.argv[3]).read_text().splitlines() if l.strip()]
src_ids = [r["case_id"] for r in src if r["case_id"] in set(want)]
assert src_ids == want
assert all(r.get("worker_verdict") == "BLOCKED" for r in src if r["case_id"] in set(want))
assert all(r["worker_verdict"] == "REJECT" for r in rows)
assert all(r["worker_verdict"] != "PASS" for r in rows)
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
g_snap = json.loads((owned / "work/pages/ghsa/GHSA-p9v8-q5m4-pf46.json").read_text())
assert g_snap["ghsa_id"] == "GHSA-p9v8-q5m4-pf46"
assert g_snap["withdrawn_at"] is None
assert g_snap["source_code_location"] == "https://github.com/canonical/snapd"
g_cdk = json.loads((owned / "work/pages/ghsa/GHSA-v4mq-x674-ff73.json").read_text())
assert g_cdk["cve_id"] == "CVE-2025-23206"
g_rp = json.loads((owned / "work/pages/ghsa/GHSA-gmj9-h825-chq2.json").read_text())
assert g_rp["source_code_location"] == "https://github.com/zopefoundation/RestrictedPython"
g_vp = json.loads((owned / "work/pages/ghsa/GHSA-vp47-9734-prjw.json").read_text())
assert g_vp["cve_id"] is None
g_3w = json.loads((owned / "work/pages/ghsa/GHSA-3wwr-3g9f-9gc7.json").read_text())
assert g_3w["cve_id"] == "CVE-2025-24359"
g_cms = json.loads((owned / "work/pages/ghsa/GHSA-2237-5r9w-vm8j.json").read_text())
assert g_cms["source_code_location"] == "https://github.com/opensource-workshop/connect-cms"
g_luc = json.loads((owned / "work/pages/ghsa/GHSA-mrqp-q7vx-v2cx.json").read_text())
assert g_luc["cve_id"] == "CVE-2025-26511"
g_4r = json.loads((owned / "work/pages/ghsa/GHSA-4rcc-7pg7-f57f.json").read_text())
assert g_4r["cve_id"] == "CVE-2024-42513"
g_h9 = json.loads((owned / "work/pages/ghsa/GHSA-h958-fxgg-g7w3.json").read_text())
assert g_h9["cve_id"] == "CVE-2024-42512"
print("conservation assigned=9 reviewed=9 unreviewed=0 PASS_proposal=0 NARROW=0 REJECT=9 UNKNOWN=0 BLOCKED=0")
PY

# snapd
"${git_cmd[@]}" -C "$SNAP" cat-file -e "$SNAP_FIX^{commit}"
sauthor=$("${git_cmd[@]}" -C "$SNAP" log -1 --format='%an' "$SNAP_FIX")
[[ $sauthor == 'Zygmunt Bazyli Krynicki' ]]
ssubj=$("${git_cmd[@]}" -C "$SNAP" log -1 --format='%s' "$SNAP_FIX")
[[ $ssubj == 'Merge pull request from GHSA-p9v8-q5m4-pf46' ]]
sbody=$("${git_cmd[@]}" -C "$SNAP" log -1 --format='%B' "$SNAP_FIX")
if printf '%s\n' "$sbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'snapd closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel2631=$("${git_cmd[@]}" -C "$SNAP" rev-parse '2.63.1^{commit}')
peel264=$("${git_cmd[@]}" -C "$SNAP" rev-parse '2.64^{commit}')
[[ $peel2631 == "$SNAP_2631" ]]
[[ $peel264 == "$SNAP_264" ]]
assert_ancestor "$SNAP" "$SNAP_FIX" "2.64"
assert_not_ancestor "$SNAP" "$SNAP_FIX" "2.63.1"
sblob_p=$("${git_cmd[@]}" -C "$SNAP" rev-parse "${SNAP_FIX}^:${SNAP_CTL}")
sblob_f=$("${git_cmd[@]}" -C "$SNAP" rev-parse "${SNAP_FIX}:${SNAP_CTL}")
sblob_2631=$("${git_cmd[@]}" -C "$SNAP" rev-parse "2.63.1:${SNAP_CTL}")
sblob_264=$("${git_cmd[@]}" -C "$SNAP" rev-parse "2.64:${SNAP_CTL}")
[[ $sblob_p == "$SNAP_BLOB_PARENT" ]]
[[ $sblob_f == "$SNAP_BLOB_FIX" ]]
[[ $sblob_2631 == "$SNAP_BLOB_PARENT" ]]
[[ $sblob_264 == "$SNAP_BLOB_FIX" ]]
sfix_src=$("${git_cmd[@]}" -C "$SNAP" show "${SNAP_FIX}:${SNAP_CTL}")
printf '%s\n' "$sfix_src" | grep -F 'if arg == "--"' >/dev/null

# aws-cdk
"${git_cmd[@]}" -C "$CDK" cat-file -e "$CDK_FIX^{commit}"
cauthor=$("${git_cmd[@]}" -C "$CDK" log -1 --format='%an' "$CDK_FIX")
[[ $cauthor == 'GZ' ]]
csubj=$("${git_cmd[@]}" -C "$CDK" log -1 --format='%s' "$CDK_FIX")
[[ $csubj == 'fix(custom-resource-handlers): do not allow unauthorized connection for iam OIDC connection (under feature flag) (#32921)' ]]
cbody=$("${git_cmd[@]}" -C "$CDK" log -1 --format='%B' "$CDK_FIX")
if printf '%s\n' "$cbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'aws-cdk closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel2176=$("${git_cmd[@]}" -C "$CDK" rev-parse 'v2.176.0^{commit}')
peel2177=$("${git_cmd[@]}" -C "$CDK" rev-parse 'v2.177.0^{commit}')
[[ $peel2176 == "$CDK_2176" ]]
[[ $peel2177 == "$CDK_2177" ]]
assert_ancestor "$CDK" "$CDK_FIX" "v2.177.0"
assert_not_ancestor "$CDK" "$CDK_FIX" "v2.176.0"
cblob_p=$("${git_cmd[@]}" -C "$CDK" rev-parse "${CDK_FIX}^:${CDK_OIDC}")
cblob_f=$("${git_cmd[@]}" -C "$CDK" rev-parse "${CDK_FIX}:${CDK_OIDC}")
cblob_176=$("${git_cmd[@]}" -C "$CDK" rev-parse "v2.176.0:${CDK_OIDC}")
cblob_177=$("${git_cmd[@]}" -C "$CDK" rev-parse "v2.177.0:${CDK_OIDC}")
[[ $cblob_p == "$CDK_BLOB_PARENT" ]]
[[ $cblob_f == "$CDK_BLOB_FIX" ]]
[[ $cblob_176 == "$CDK_BLOB_PARENT" ]]
[[ $cblob_177 == "$CDK_BLOB_FIX" ]]
cparent_src=$("${git_cmd[@]}" -C "$CDK" show "${CDK_FIX}^:${CDK_OIDC}")
printf '%s\n' "$cparent_src" | grep -F 'rejectUnauthorized: false' >/dev/null

# RestrictedPython
"${git_cmd[@]}" -C "$RP" cat-file -e "$RP_FIX^{commit}"
rauthor=$("${git_cmd[@]}" -C "$RP" log -1 --format='%an' "$RP_FIX")
[[ $rauthor == 'Michael Howitz' ]]
rsubj=$("${git_cmd[@]}" -C "$RP" log -1 --format='%s' "$RP_FIX")
[[ $rsubj == 'Merge commit from fork' ]]
rbody=$("${git_cmd[@]}" -C "$RP" log -1 --format='%B' "$RP_FIX")
if printf '%s\n' "$rbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'RestrictedPython closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel74=$("${git_cmd[@]}" -C "$RP" rev-parse '7.4^{commit}')
peel80=$("${git_cmd[@]}" -C "$RP" rev-parse '8.0^{commit}')
[[ $peel74 == "$RP_74" ]]
[[ $peel80 == "$RP_80" ]]
assert_ancestor "$RP" "$RP_FIX" "8.0"
assert_not_ancestor "$RP" "$RP_FIX" "7.4"
rblob_p=$("${git_cmd[@]}" -C "$RP" rev-parse "${RP_FIX}^:${RP_TRANS}")
rblob_f=$("${git_cmd[@]}" -C "$RP" rev-parse "${RP_FIX}:${RP_TRANS}")
rblob_74=$("${git_cmd[@]}" -C "$RP" rev-parse "7.4:${RP_TRANS}")
rblob_80=$("${git_cmd[@]}" -C "$RP" rev-parse "8.0:${RP_TRANS}")
[[ $rblob_p == "$RP_BLOB_PARENT" ]]
[[ $rblob_f == "$RP_BLOB_FIX" ]]
[[ $rblob_74 == "$RP_BLOB_PARENT" ]]
[[ $rblob_80 == "$RP_BLOB_FIX" ]]
rfix_src=$("${git_cmd[@]}" -C "$RP" show "${RP_FIX}:${RP_TRANS}")
printf '%s\n' "$rfix_src" | grep -F 'self.not_allowed(node)' >/dev/null

# asteval
"${git_cmd[@]}" -C "$AE" cat-file -e "$AE_MERGE^{commit}"
"${git_cmd[@]}" -C "$AE" cat-file -e "$AE_MEMBER^{commit}"
mauthor=$("${git_cmd[@]}" -C "$AE" log -1 --format='%an' "$AE_MERGE")
[[ $mauthor == 'Matt Newville' ]]
wauthor=$("${git_cmd[@]}" -C "$AE" log -1 --format='%an' "$AE_MEMBER")
[[ $wauthor == 'William Khem Marquez' ]]
wsubj=$("${git_cmd[@]}" -C "$AE" log -1 --format='%s' "$AE_MEMBER")
[[ $wsubj == 'Implement safe_getattr and safe_format functions; fix bugs in UNSAFE_ATTRS and UNSAFE_ATTRS_DTYPES usage' ]]
wbody=$("${git_cmd[@]}" -C "$AE" log -1 --format='%B' "$AE_MEMBER")
if printf '%s\n' "$wbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'asteval member unexpectedly has AI marker\n' >&2
  exit 1
fi
peel105=$("${git_cmd[@]}" -C "$AE" rev-parse '1.0.5^{commit}')
peel106=$("${git_cmd[@]}" -C "$AE" rev-parse '1.0.6^{commit}')
[[ $peel105 == "$AE_105" ]]
[[ $peel106 == "$AE_106" ]]
assert_ancestor "$AE" "$AE_MERGE" "1.0.6"
assert_ancestor "$AE" "$AE_MEMBER" "1.0.6"
assert_not_ancestor "$AE" "$AE_MERGE" "1.0.5"
assert_not_ancestor "$AE" "$AE_MEMBER" "1.0.5"
wsrc=$("${git_cmd[@]}" -C "$AE" show "${AE_MEMBER}:asteval/asteval.py")
printf '%s\n' "$wsrc" | grep -F 'safe_getattr' >/dev/null
printf '%s\n' "$wsrc" | grep -F 'safe_format' >/dev/null

# connect-cms
"${git_cmd[@]}" -C "$CMS" cat-file -e "$CMS_FIX^{commit}"
kauthor=$("${git_cmd[@]}" -C "$CMS" log -1 --format='%an' "$CMS_FIX")
[[ $kauthor == 'gakigaki' ]]
ksubj=$("${git_cmd[@]}" -C "$CMS" log -1 --format='%s' "$CMS_FIX")
[[ $ksubj == 'Fix: GHSA-2237-5r9w-vm8j' ]]
kbody=$("${git_cmd[@]}" -C "$CMS" log -1 --format='%B' "$CMS_FIX")
if printf '%s\n' "$kbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'connect-cms closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel183=$("${git_cmd[@]}" -C "$CMS" rev-parse 'v1.8.3^{commit}')
peel184=$("${git_cmd[@]}" -C "$CMS" rev-parse 'v1.8.4^{commit}')
[[ $peel183 == "$CMS_183" ]]
[[ $peel184 == "$CMS_184" ]]
assert_ancestor "$CMS" "$CMS_FIX" "v1.8.4"
assert_not_ancestor "$CMS" "$CMS_FIX" "v1.8.3"
assert_ancestor "$CMS" "$CMS_INTRO" "v1.8.0"
assert_not_ancestor "$CMS" "d5ed251f4debe4c03588136f618dd069d4346a8f" "v1.8.4"
kblob_p=$("${git_cmd[@]}" -C "$CMS" rev-parse "${CMS_FIX}^:${CMS_SEARCH}")
kblob_183=$("${git_cmd[@]}" -C "$CMS" rev-parse "v1.8.3:${CMS_SEARCH}")
[[ $kblob_p == "$CMS_BLOB_PARENT" ]]
[[ $kblob_183 == "$CMS_BLOB_PARENT" ]]
kfix_src=$("${git_cmd[@]}" -C "$CMS" show "${CMS_FIX}:${CMS_SEARCH}")
printf '%s\n' "$kfix_src" | grep -F 'fetchSearchablePageIds' >/dev/null

# cassandra-lucene-index
"${git_cmd[@]}" -C "$LUC" cat-file -e "$LUC_40^{commit}"
"${git_cmd[@]}" -C "$LUC" cat-file -e "$LUC_41^{commit}"
l40a=$("${git_cmd[@]}" -C "$LUC" log -1 --format='%an' "$LUC_40")
[[ $l40a == 'Jackson Fleming' ]]
l41a=$("${git_cmd[@]}" -C "$LUC" log -1 --format='%an' "$LUC_41")
[[ $l41a == 'Jackson Fleming' ]]
l40body=$("${git_cmd[@]}" -C "$LUC" log -1 --format='%B' "$LUC_40")
if printf '%s\n' "$l40body" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'cassandra 4.0 closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel4017=$("${git_cmd[@]}" -C "$LUC" rev-parse 'cassandra-4.0.17-1.0.0^{commit}')
peel4180=$("${git_cmd[@]}" -C "$LUC" rev-parse 'cassandra-4.1.8-1.0.0^{commit}')
peel4181=$("${git_cmd[@]}" -C "$LUC" rev-parse 'cassandra-4.1.8-1.0.1^{commit}')
[[ $peel4017 == "$LUC_40" ]]
[[ $peel4180 == "$LUC_4180" ]]
[[ $peel4181 == "$LUC_4181" ]]
assert_ancestor "$LUC" "$LUC_40" "cassandra-4.0.17-1.0.0"
assert_ancestor "$LUC" "$LUC_41" "cassandra-4.1.8-1.0.1"
assert_not_ancestor "$LUC" "$LUC_41" "cassandra-4.1.8-1.0.0"
lblob_40p=$("${git_cmd[@]}" -C "$LUC" rev-parse "${LUC_40}^:${LUC_HANDLER}")
lblob_40=$("${git_cmd[@]}" -C "$LUC" rev-parse "${LUC_40}:${LUC_HANDLER}")
lblob_41p=$("${git_cmd[@]}" -C "$LUC" rev-parse "${LUC_41}^:${LUC_HANDLER}")
lblob_4180=$("${git_cmd[@]}" -C "$LUC" rev-parse "cassandra-4.1.8-1.0.0:${LUC_HANDLER}")
[[ $lblob_40p == "$LUC_BLOB_40P" ]]
[[ $lblob_40 == "$LUC_BLOB_40" ]]
[[ $lblob_41p == "$LUC_BLOB_41P" ]]
[[ $lblob_4180 == "$LUC_BLOB_41P" ]]
l40src=$("${git_cmd[@]}" -C "$LUC" show "${LUC_40}:${LUC_HANDLER}")
printf '%s\n' "$l40src" | grep -F 'statement.authorize' >/dev/null
l4180src=$("${git_cmd[@]}" -C "$LUC" show "cassandra-4.1.8-1.0.0:${LUC_HANDLER}")
if printf '%s\n' "$l4180src" | grep -F 'statement.authorize' >/dev/null; then
  printf 'cassandra 4.1.8-1.0.0 unexpectedly has authorize\n' >&2
  exit 1
fi
l4181src=$("${git_cmd[@]}" -C "$LUC" show "cassandra-4.1.8-1.0.1:${LUC_HANDLER}")
printf '%s\n' "$l4181src" | grep -F 'statement.authorize' >/dev/null

# OPC UA
"${git_cmd[@]}" -C "$OPC" cat-file -e "$OPC_H958^{commit}"
"${git_cmd[@]}" -C "$OPC" cat-file -e "$OPC_HTTPS^{commit}"
hauthor=$("${git_cmd[@]}" -C "$OPC" log -1 --format='%an' "$OPC_H958")
[[ $hauthor == 'Suciu Mircea Adrian' ]]
hsubj=$("${git_cmd[@]}" -C "$OPC" log -1 --format='%s' "$OPC_H958")
[[ $hsubj == 'Added a minimal rogue client detection mechanism at the transport level (#2850)' ]]
xauthor=$("${git_cmd[@]}" -C "$OPC" log -1 --format='%an' "$OPC_HTTPS")
[[ $xauthor == 'Suciu Mircea Adrian' ]]
xsubj=$("${git_cmd[@]}" -C "$OPC" log -1 --format='%s' "$OPC_HTTPS")
[[ $xsubj == 'Support mutual TLS on server https endpoints (#2849)' ]]
hbody=$("${git_cmd[@]}" -C "$OPC" log -1 --format='%B' "$OPC_H958")
xbody=$("${git_cmd[@]}" -C "$OPC" log -1 --format='%B' "$OPC_HTTPS")
if printf '%s\n' "$hbody$xbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'opcua closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel158=$("${git_cmd[@]}" -C "$OPC" rev-parse '1.5.374.158^{commit}')
peel118=$("${git_cmd[@]}" -C "$OPC" rev-parse '1.5.374.118^{commit}')
[[ $peel158 == "$OPC_158" ]]
[[ $peel118 == "$OPC_118" ]]
assert_ancestor "$OPC" "$OPC_H958" "1.5.374.158"
assert_ancestor "$OPC" "$OPC_HTTPS" "1.5.374.158"
assert_not_ancestor "$OPC" "$OPC_H958" "1.5.374.118"
assert_not_ancestor "$OPC" "$OPC_HTTPS" "1.5.374.118"
assert_not_ancestor "$OPC" "b995f3e74afadbdb89d1a48127c34de95e6da988" "1.5.374.158"
oblob_tcp=$("${git_cmd[@]}" -C "$OPC" rev-parse "${OPC_H958}:${OPC_TCP}")
oblob_158t=$("${git_cmd[@]}" -C "$OPC" rev-parse "1.5.374.158:${OPC_TCP}")
oblob_https=$("${git_cmd[@]}" -C "$OPC" rev-parse "${OPC_HTTPS}:${OPC_HTTP}")
oblob_158h=$("${git_cmd[@]}" -C "$OPC" rev-parse "1.5.374.158:${OPC_HTTP}")
[[ $oblob_tcp == "$OPC_BLOB_TCP" ]]
[[ $oblob_158t == "$OPC_BLOB_TCP" ]]
[[ $oblob_https == "$OPC_BLOB_HTTPS" ]]
[[ $oblob_158h == "$OPC_BLOB_HTTPS" ]]

python3 - "$SNAP" "$CDK" "$RP" "$AE" "$CMS" "$LUC" "$OPC" << 'PY'
import re, subprocess, sys

repos_rev = [
    (sys.argv[1], "2.64"),
    (sys.argv[2], "v2.177.0"),
    (sys.argv[3], "8.0"),
    (sys.argv[4], "1.0.6"),
    (sys.argv[5], "v1.8.4"),
]
luc = sys.argv[6]
opc = sys.argv[7]
pat = re.compile(
    r"Co-authored-by:.*(Claude|Cursor Agent|Copilot|ChatGPT|OpenAI|Anthropic)|"
    r"Generated with Claude|Generated with Copilot|noreply@anthropic|"
    r"Made-with: Cursor|chatgpt|claude\.ai",
    re.I,
)
git = ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]
for repo, rev in repos_rev:
    out = subprocess.check_output(git + ["-C", repo, "log", rev, "--format=%H%x1f%an%x1f%s%x1f%b%x1e"], text=True)
    hits = []
    for rec in out.split("\x1e"):
        if pat.search(rec):
            hits.append(rec.split("\x1f", 1)[0][:40])
    assert hits == [], (repo, rev, hits[:5])
out = subprocess.check_output(git + ["-C", luc, "log", "--all", "--format=%H%x1f%an%x1f%s%x1f%b%x1e"], text=True)
hits = []
for rec in out.split("\x1e"):
    if pat.search(rec):
        hits.append(rec.split("\x1f", 1)[0][:40])
assert hits == [], ("lucene", hits[:5])
out = subprocess.check_output(git + ["-C", opc, "log", "1.5.374.158", "--format=%H%x1f%an%x1f%s%x1f%b%x1e"], text=True)
hits = []
for rec in out.split("\x1e"):
    if pat.search(rec):
        hits.append(rec.split("\x1f", 1)[0][:40])
assert hits == [], ("opc-1.5.374.158", hits[:5])
print("ai_trailer_scan_empty_on_relevant_history")
PY

printf 'REPLAY_OK reviewed=9 PASS_proposal=0 NARROW=0 REJECT=9 UNKNOWN=0 BLOCKED=0\n'
