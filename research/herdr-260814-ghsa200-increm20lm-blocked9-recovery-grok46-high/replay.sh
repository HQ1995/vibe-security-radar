#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-increm20lm-blocked9-recovery-grok46-high.
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
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-increm20lm-blocked9-recovery-grok46-high
CACHE=/home/hanqing/.cache/ghsa200-worker-clones/recovery20lm-260814
RAT=$CACHE/ratify-project__ratify
BMO=$CACHE/metal3-io__baremetal-operator
PAY=$CACHE/Sylius__PayPalPlugin
TUF=$CACHE/awslabs__tough
JHI=$CACHE/jhipster__generator-jhipster-entity-audit
APO=$CACHE/apollographql__apollo-rs
MIN=$CACHE/minio__operator
STR=$CACHE/strawberry-graphql__strawberry
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database

RAT_FIX12=0ec0c08490e3d672ae64b1a220c90d5484f1c93f
RAT_FIX13=84c7c48fa76bb9a1c9583635d1e90bc25b1a546c
RAT_AZURE=pkg/common/oras/authprovider/azure/azureidentity.go
RAT_BLOB_12P=9e5ee0111b7f04f8992d81e2f33d2bfc5afa0fd2
RAT_BLOB_12=6f366e409b2c058d6012f811221f3ec4bef5a48f
RAT_BLOB_13P=0a5a00e5ced325521128db26564714d584dda6a1
RAT_BLOB_13=e1e231cc72402f5c853be0e78b456879a5fc41ef
RAT_122=0f2a6ad4a9c884d5bfc69d3e2b527f611d4a79fa
RAT_123=7d1ed86966904fadf0d5f03b403480fe5514f922
RAT_131=e57c9a90b30cc30f82e12fd86832c65bf8b56d4d
RAT_132=2d8921018a7368bef3b33a0ffca294f91c89429d

BMO_FIX=19f8443b1fe182f76dd81b43122e8dd102f8b94c
BMO_MEMBER=84798044692b910263b1f50bf001814badec7ee5
BMO_09=bcda0f0f25bdaa0cbb6fb681b1d8eb85ccf61637
BMO_08=ea8528e73bf9d72db5a149918bc7667f107d9e87
BMO_VAL=apis/metal3.io/v1alpha1/bmceventsubscription_validation.go
BMO_BLOB_P=1aefae1b32ce6aeee153685921334e66b1d5c40a
BMO_BLOB_F=e4e8c209dead4efc1a2279d1c726876c54c75638
BMO_080=c2b5a557641bc273367635124047d6c958aa15f7
BMO_090=65af31a3209d9e654999a789dcccbbe372145131

PAY_FIX=5613df827a6d4fc50862229295976200a68e97aa
PAY_PROC=src/Processor/PayPalOrderCompleteProcessor.php
PAY_BLOB_P=5eaaaf2223e4c5a22ddc63b9a069ea8a198fbece
PAY_BLOB_F=9ee7d786ac92b745eb3609597ccb56d70ac96cc2
PAY_161=31e71b0457e5d887a6c19f8cfabb8b16125ec406

TUF_CYCLE=c5ee1718e630fdedc5676bf71b5bef10e4c7f91c
TUF_TS=9b400e1c8b7d6b9ab8009104fa7fe5884db05f18
TUF_019=e8f453e7c502ea2bbcbb8f76d38fa2674c895342
TUF_020=596c2a046a3e5da841090a1c216bf65960dbc840

JHI_FIX=eb00a2442d054b31ba7d8fc403ed5acb362f05c4
JHI_DEP=e21e83135d10c77d92203c89cb0b0063914e8fe0
JHI_RES=generators/spring-boot-javers/templates/src/main/java/_package_/web/rest/JaversEntityAuditResource.java.ejs
JHI_BLOB_P=c46237081c3af82a82f70ff8dfc0e6841f92b935
JHI_BLOB_F=f852640c18eff4775dd100b503f37a6aeb7bac94
JHI_590=3f40be969cf5c71afc24d950170d46278fd95d5e
JHI_591=0ff1137fc89ce6b1ff59855a2d454682f113fda2

APO_FIX=35f280cb5bdc2276ddf000b8d81dfef9d30170f6
APO_FRAG=crates/apollo-compiler/src/validation/fragment.rs
APO_BLOB_P=f554a00362e50f74dd283241292978584c05de89
APO_BLOB_F=f6e7117c7a0c3e971850f6a87c686784d2c1b551
APO_126=1a138ced46811d47b98cf83b6f71fa2ee944c74e
APO_127=f20ac42562f63a21bd3b3477af0d7ca4fa8a97ed

MIN_FIX=d586294d526bf0d8e6097225114655f68b0adcc5
MIN_STS=pkg/controller/sts.go
MIN_BLOB_P=9507095b0d00ee22e403fa71dc8a2aef4d488b3e
MIN_BLOB_F=9cea54ab2de584fff1e5cc78529d649d2ff94070
MIN_701=e97863ae76fbd76ee424565e1110d6c7039f8fca
MIN_710=00378303a987610ffa42321a11a89d718622c6a0

STR_FIX=526eb82b70451c0e59d5a71ae9b7396f59974bd8
STR_FIELDS=strawberry/relay/fields.py
STR_BLOB_P=347fd22169028d02fc400f80665bdf0531ba1902
STR_BLOB_F=3e0c77e240f667013f407307d808e43ba7a8a06f
STR_256=25e660ed34b6e820fd2efd6290101edc3d4aff22
STR_257=1e0e1efe4b103f933fccc81961ec65db490d0058

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
require_dir "$RAT/.git"
require_dir "$BMO/.git"
require_dir "$PAY/.git"
require_dir "$TUF/.git"
require_dir "$JHI/.git"
require_dir "$APO/.git"
require_dir "$MIN/.git"
require_dir "$STR/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/ledger.jsonl" \
  3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20l-grok46-high/cases.jsonl" \
  483c87e317973ca853998ecac9f7fba6d33e03a4c76ae5b29e2a8c46f151d951
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20m-final8-grok46-low/cases.jsonl" \
  a4b6c9106c43e5ffaf0dee96c3d1367424d5e719cc2bb6e78c20799f4db687c5
expect_hash "$OWNED/work/freeze.json" \
  e625fad3c74fc1b1e5ea9f68c1a532fe5aaf495e92fc542fcc2f4166185d86f1
expect_hash "$OWNED/cases.jsonl" \
  26defefc6c38e171cccac2985f78804718255644f83cc0c05abfd19fbf4ab084
expect_hash "$OWNED/report.md" \
  90eb7f1edc9c23c72bb6b697f8fd21d1ad88664cda7a6014d47f41e7a7fd2235
expect_hash "$OWNED/work/pages/advisory/GHSA-44f7-5fj5-h4px.json" \
  5b1183f7ea91278d9d77b83415dee24077f3602305f8a43428be57fe96c85bc0
expect_hash "$OWNED/work/pages/advisory/GHSA-c98h-7hp9-v9hq.json" \
  15a65623ff7cca74fbe60d617711efd81bb309e45c753cb90622e318ff17b9b4
expect_hash "$OWNED/work/pages/advisory/GHSA-hxg4-65p5-9w37.json" \
  0b42d224f8ecbb40caa3179d9406d356c90204e62bdf7c5f7a82d1a0ecab59c2
expect_hash "$OWNED/work/pages/advisory/GHSA-j8x2-777p-23fc.json" \
  d7bbf360a866672258921a508d5cffcbdf686081da3da1a8850b91ae4759e4fc
expect_hash "$OWNED/work/pages/advisory/GHSA-7rmp-3g9f-cvq8.json" \
  28827ac19236c3489bbe89306ee6b2a470abd15dad00106ce028f4d727a722d9
expect_hash "$OWNED/work/pages/advisory/GHSA-7mpv-9xg6-5r79.json" \
  f675def2032afcf773b0dfe556131271c5896412842bd00dc51acb41e7c4d544
expect_hash "$OWNED/work/pages/advisory/GHSA-7m6v-q233-q9j9.json" \
  0bb73983a54975864498a89750920d48fde3919ae67b44178e501e7f127b729a
expect_hash "$OWNED/work/pages/advisory/GHSA-5xh2-23cc-5jc6.json" \
  771c3ab60774e47eb3acd1f3ebca507758314be01f65561115cba29b3193f6c0
expect_hash "$OWNED/work/pages/advisory/GHSA-76g3-38jv-wxh4.json" \
  db567e310b874c56a3bb85f773d9a6793e304e590d4acf767d0c3296338fc84a
expect_hash "$OWNED/work/pages/ghsa/GHSA-44f7-5fj5-h4px.json" \
  a3ea5635dfcd1d56bc86d2ffe5267c67473456f8d1190fec73819185a8a2c5e4
expect_hash "$OWNED/work/pages/ghsa/GHSA-c98h-7hp9-v9hq.json" \
  f9b4e5d4abc9646565e00628550e6f91632d79b16a907782fe9d0181a09e7b62
expect_hash "$OWNED/work/pages/ghsa/GHSA-hxg4-65p5-9w37.json" \
  4944a0d4aed9210b988da30b3f0b7d367084000095848555f899abeae32aba93
expect_hash "$OWNED/work/pages/ghsa/GHSA-j8x2-777p-23fc.json" \
  e0f1a5b1f0dcc6516b46fffe2d4f230b01b64ef9017b78dca1f93a7007d2870e
expect_hash "$OWNED/work/pages/ghsa/GHSA-7rmp-3g9f-cvq8.json" \
  36724193acaba100f9013b876215f55961d16f49a0df0198b0cc1e282affa9dc
expect_hash "$OWNED/work/pages/ghsa/GHSA-7mpv-9xg6-5r79.json" \
  4e558082f34ad97915c7be61329143f61b3122018ed9ac8d5665729904f57268
expect_hash "$OWNED/work/pages/ghsa/GHSA-7m6v-q233-q9j9.json" \
  3066052190a923b35effa9c94dd2626d823539fcdb5cfb0f84b15aa3eb258e6f
expect_hash "$OWNED/work/pages/ghsa/GHSA-5xh2-23cc-5jc6.json" \
  db2365c12f9fe480179a38cd4f7f520693fc6b69fb1dcb81b226c75ea6b1aecb
expect_hash "$OWNED/work/pages/ghsa/GHSA-76g3-38jv-wxh4.json" \
  e1ae0f1d1afd8b64b8e3881204e2d503965330b6a587b4a23b1340b1b4ef4d60

[[ "$("${git_cmd[@]}" -C "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]

SRC20L=$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20l-grok46-high/cases.jsonl
SRC20M=$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20m-final8-grok46-low/cases.jsonl
python3 - "$OWNED" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  "$SRC20L" "$SRC20M" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 9, len(rows)
want = [
    "GHSA-44F7-5FJ5-H4PX",
    "GHSA-C98H-7HP9-V9HQ",
    "GHSA-HXG4-65P5-9W37",
    "GHSA-J8X2-777P-23FC",
    "GHSA-7RMP-3G9F-CVQ8",
    "GHSA-7MPV-9XG6-5R79",
    "GHSA-7M6V-Q233-Q9J9",
    "GHSA-5XH2-23CC-5JC6",
    "GHSA-76G3-38JV-WXH4",
]
assert [r["case_id"] for r in rows] == want
src_l = [json.loads(l) for l in Path(sys.argv[3]).read_text().splitlines() if l.strip()]
src_m = [json.loads(l) for l in Path(sys.argv[4]).read_text().splitlines() if l.strip()]
from_l = [r["case_id"] for r in src_l if r["case_id"] in set(want)]
from_m = [r["case_id"] for r in src_m if r["case_id"] in set(want)]
assert from_l == want[:7]
assert from_m == want[7:]
assert all(r.get("worker_verdict") == "BLOCKED" for r in src_l if r["case_id"] in set(want[:7]))
assert all(r.get("worker_verdict") == "BLOCKED" for r in src_m if r["case_id"] in set(want[7:]))
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
assert rows[3]["repository"] == rows[8]["repository"] == "awslabs/tough"
assert rows[3]["mechanism_key"] != rows[8]["mechanism_key"]
assert rows[3]["minimum_fix_set"] != rows[8]["minimum_fix_set"]
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
g_rat = json.loads((owned / "work/pages/ghsa/GHSA-44f7-5fj5-h4px.json").read_text())
assert g_rat["ghsa_id"] == "GHSA-44f7-5fj5-h4px"
assert g_rat["withdrawn_at"] is None
assert g_rat["source_code_location"] == "https://github.com/ratify-project/ratify"
assert g_rat["cve_id"] == "CVE-2025-27403"
g_bmo = json.loads((owned / "work/pages/ghsa/GHSA-c98h-7hp9-v9hq.json").read_text())
assert g_bmo["source_code_location"] == "https://github.com/metal3-io/baremetal-operator"
g_pay = json.loads((owned / "work/pages/ghsa/GHSA-hxg4-65p5-9w37.json").read_text())
assert g_pay["cve_id"] == "CVE-2025-30152"
g_j8 = json.loads((owned / "work/pages/ghsa/GHSA-j8x2-777p-23fc.json").read_text())
assert g_j8["cve_id"] is None
assert g_j8["source_code_location"] == "https://github.com/awslabs/tough"
g_jhi = json.loads((owned / "work/pages/ghsa/GHSA-7rmp-3g9f-cvq8.json").read_text())
assert g_jhi["cve_id"] == "CVE-2025-31119"
g_apo = json.loads((owned / "work/pages/ghsa/GHSA-7mpv-9xg6-5r79.json").read_text())
assert g_apo["source_code_location"] == "https://github.com/apollographql/apollo-rs"
g_min = json.loads((owned / "work/pages/ghsa/GHSA-7m6v-q233-q9j9.json").read_text())
assert g_min["cve_id"] == "CVE-2025-32963"
g_str = json.loads((owned / "work/pages/ghsa/GHSA-5xh2-23cc-5jc6.json").read_text())
assert g_str["cve_id"] == "CVE-2025-22151"
g_76 = json.loads((owned / "work/pages/ghsa/GHSA-76g3-38jv-wxh4.json").read_text())
assert g_76["cve_id"] == "CVE-2025-2888"
assert g_76["source_code_location"] == "https://github.com/awslabs/tough"
print("conservation assigned=9 reviewed=9 unreviewed=0 PASS_proposal=0 NARROW=0 REJECT=9 UNKNOWN=0 BLOCKED=0")
PY

# ratify
"${git_cmd[@]}" -C "$RAT" cat-file -e "$RAT_FIX12^{commit}"
"${git_cmd[@]}" -C "$RAT" cat-file -e "$RAT_FIX13^{commit}"
rauthor=$("${git_cmd[@]}" -C "$RAT" log -1 --format='%an' "$RAT_FIX12")
[[ $rauthor == 'Binbin Li' ]]
rsubj=$("${git_cmd[@]}" -C "$RAT" log -1 --format='%s' "$RAT_FIX12")
[[ $rsubj == 'fix: enforce host checking before exchanging a refresh token (#2069) (#2072)' ]]
rbody=$("${git_cmd[@]}" -C "$RAT" log -1 --format='%B' "$RAT_FIX12")
rbody13=$("${git_cmd[@]}" -C "$RAT" log -1 --format='%B' "$RAT_FIX13")
if printf '%s\n' "$rbody$rbody13" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'ratify closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel122=$("${git_cmd[@]}" -C "$RAT" rev-parse 'v1.2.2^{commit}')
peel123=$("${git_cmd[@]}" -C "$RAT" rev-parse 'v1.2.3^{commit}')
peel131=$("${git_cmd[@]}" -C "$RAT" rev-parse 'v1.3.1^{commit}')
peel132=$("${git_cmd[@]}" -C "$RAT" rev-parse 'v1.3.2^{commit}')
[[ $peel122 == "$RAT_122" ]]
[[ $peel123 == "$RAT_123" ]]
[[ $peel131 == "$RAT_131" ]]
[[ $peel132 == "$RAT_132" ]]
assert_ancestor "$RAT" "$RAT_FIX12" "v1.2.3"
assert_not_ancestor "$RAT" "$RAT_FIX12" "v1.2.2"
assert_ancestor "$RAT" "$RAT_FIX13" "v1.3.2"
assert_not_ancestor "$RAT" "$RAT_FIX13" "v1.3.1"
rblob_p=$("${git_cmd[@]}" -C "$RAT" rev-parse "${RAT_FIX12}^:${RAT_AZURE}")
rblob_f=$("${git_cmd[@]}" -C "$RAT" rev-parse "${RAT_FIX12}:${RAT_AZURE}")
rblob_122=$("${git_cmd[@]}" -C "$RAT" rev-parse "v1.2.2:${RAT_AZURE}")
rblob_123=$("${git_cmd[@]}" -C "$RAT" rev-parse "v1.2.3:${RAT_AZURE}")
rblob_131=$("${git_cmd[@]}" -C "$RAT" rev-parse "v1.3.1:${RAT_AZURE}")
rblob_132=$("${git_cmd[@]}" -C "$RAT" rev-parse "v1.3.2:${RAT_AZURE}")
[[ $rblob_p == "$RAT_BLOB_12P" ]]
[[ $rblob_f == "$RAT_BLOB_12" ]]
[[ $rblob_122 == "$RAT_BLOB_12P" ]]
[[ $rblob_123 == "$RAT_BLOB_12" ]]
[[ $rblob_131 == "$RAT_BLOB_13P" ]]
[[ $rblob_132 == "$RAT_BLOB_13" ]]
rfix_src=$("${git_cmd[@]}" -C "$RAT" show "${RAT_FIX12}:pkg/common/oras/authprovider/azure/helper.go")
printf '%s\n' "$rfix_src" | grep -F 'parseEndpoints' >/dev/null

# baremetal-operator
"${git_cmd[@]}" -C "$BMO" cat-file -e "$BMO_FIX^{commit}"
"${git_cmd[@]}" -C "$BMO" cat-file -e "$BMO_MEMBER^{commit}"
bauthor=$("${git_cmd[@]}" -C "$BMO" log -1 --format='%an' "$BMO_FIX")
[[ $bauthor == 'Tuomo Tanskanen' ]]
mauthor=$("${git_cmd[@]}" -C "$BMO" log -1 --format='%an' "$BMO_MEMBER")
[[ $mauthor == 'Lennart Jern' ]]
msubj=$("${git_cmd[@]}" -C "$BMO" log -1 --format='%s' "$BMO_MEMBER")
[[ $msubj == 'Only accept HTTPHeadersRef in same namespace' ]]
mbody=$("${git_cmd[@]}" -C "$BMO" log -1 --format='%B' "$BMO_MEMBER")
if printf '%s\n' "$mbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'bmo member unexpectedly has AI marker\n' >&2
  exit 1
fi
peel080=$("${git_cmd[@]}" -C "$BMO" rev-parse 'v0.8.0^{commit}')
peel081=$("${git_cmd[@]}" -C "$BMO" rev-parse 'v0.8.1^{commit}')
peel090=$("${git_cmd[@]}" -C "$BMO" rev-parse 'v0.9.0^{commit}')
peel091=$("${git_cmd[@]}" -C "$BMO" rev-parse 'v0.9.1^{commit}')
[[ $peel080 == "$BMO_080" ]]
[[ $peel081 == "$BMO_08" ]]
[[ $peel090 == "$BMO_090" ]]
[[ $peel091 == "$BMO_09" ]]
assert_ancestor "$BMO" "$BMO_08" "v0.8.1"
assert_not_ancestor "$BMO" "$BMO_FIX" "v0.8.0"
assert_ancestor "$BMO" "$BMO_09" "v0.9.1"
assert_not_ancestor "$BMO" "$BMO_FIX" "v0.9.0"
bblob_p=$("${git_cmd[@]}" -C "$BMO" rev-parse "${BMO_FIX}^:${BMO_VAL}")
bblob_f=$("${git_cmd[@]}" -C "$BMO" rev-parse "${BMO_FIX}:${BMO_VAL}")
bblob_090=$("${git_cmd[@]}" -C "$BMO" rev-parse "v0.9.0:${BMO_VAL}")
bblob_091=$("${git_cmd[@]}" -C "$BMO" rev-parse "v0.9.1:${BMO_VAL}")
bblob_080=$("${git_cmd[@]}" -C "$BMO" rev-parse "v0.8.0:${BMO_VAL}")
bblob_081=$("${git_cmd[@]}" -C "$BMO" rev-parse "v0.8.1:${BMO_VAL}")
[[ $bblob_p == "$BMO_BLOB_P" ]]
[[ $bblob_f == "$BMO_BLOB_F" ]]
[[ $bblob_090 == "$BMO_BLOB_P" ]]
[[ $bblob_091 == "$BMO_BLOB_F" ]]
[[ $bblob_080 == "$BMO_BLOB_P" ]]
[[ $bblob_081 == "$BMO_BLOB_F" ]]

# PayPalPlugin
"${git_cmd[@]}" -C "$PAY" cat-file -e "$PAY_FIX^{commit}"
pauthor=$("${git_cmd[@]}" -C "$PAY" log -1 --format='%an' "$PAY_FIX")
[[ $pauthor == 'Grzegorz Sadowski' ]]
psubj=$("${git_cmd[@]}" -C "$PAY" log -1 --format='%s' "$PAY_FIX")
[[ $psubj == '[Bug] Fix issue after paypal checkout (#355)' ]]
pbody=$("${git_cmd[@]}" -C "$PAY" log -1 --format='%B' "$PAY_FIX")
if printf '%s\n' "$pbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'paypal closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel161=$("${git_cmd[@]}" -C "$PAY" rev-parse 'v1.6.1^{commit}')
peel162=$("${git_cmd[@]}" -C "$PAY" rev-parse 'v1.6.2^{commit}')
[[ $peel161 == "$PAY_161" ]]
[[ $peel162 == "$PAY_FIX" ]]
assert_ancestor "$PAY" "$PAY_FIX" "v1.6.2"
assert_not_ancestor "$PAY" "$PAY_FIX" "v1.6.1"
pblob_p=$("${git_cmd[@]}" -C "$PAY" rev-parse "${PAY_FIX}^:${PAY_PROC}")
pblob_f=$("${git_cmd[@]}" -C "$PAY" rev-parse "${PAY_FIX}:${PAY_PROC}")
pblob_161=$("${git_cmd[@]}" -C "$PAY" rev-parse "v1.6.1:${PAY_PROC}")
pblob_162=$("${git_cmd[@]}" -C "$PAY" rev-parse "v1.6.2:${PAY_PROC}")
[[ $pblob_p == "$PAY_BLOB_P" ]]
[[ $pblob_f == "$PAY_BLOB_F" ]]
[[ $pblob_161 == "$PAY_BLOB_P" ]]
[[ $pblob_162 == "$PAY_BLOB_F" ]]
pfix_src=$("${git_cmd[@]}" -C "$PAY" show "${PAY_FIX}:${PAY_PROC}")
printf '%s\n' "$pfix_src" | grep -F 'function verify' >/dev/null

# tough cycle + timestamp (distinct)
"${git_cmd[@]}" -C "$TUF" cat-file -e "$TUF_CYCLE^{commit}"
"${git_cmd[@]}" -C "$TUF" cat-file -e "$TUF_TS^{commit}"
cauthor=$("${git_cmd[@]}" -C "$TUF" log -1 --format='%an' "$TUF_CYCLE")
[[ $cauthor == 'Martin Harriman' ]]
csubj=$("${git_cmd[@]}" -C "$TUF" log -1 --format='%s' "$TUF_CYCLE")
[[ $csubj == 'tough: detect cyclic (or redundant) delegations' ]]
tauthor=$("${git_cmd[@]}" -C "$TUF" log -1 --format='%an' "$TUF_TS")
[[ $tauthor == 'Martin Harriman' ]]
tsubj=$("${git_cmd[@]}" -C "$TUF" log -1 --format='%s' "$TUF_TS")
[[ $tsubj == 'tough: detect rollback in timestamp metafiles' ]]
cbody=$("${git_cmd[@]}" -C "$TUF" log -1 --format='%B' "$TUF_CYCLE")
tbody=$("${git_cmd[@]}" -C "$TUF" log -1 --format='%B' "$TUF_TS")
if printf '%s\n' "$cbody$tbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'tough closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel019=$("${git_cmd[@]}" -C "$TUF" rev-parse 'tough-v0.19.0^{commit}')
peel020=$("${git_cmd[@]}" -C "$TUF" rev-parse 'tough-v0.20.0^{commit}')
[[ $peel019 == "$TUF_019" ]]
[[ $peel020 == "$TUF_020" ]]
assert_ancestor "$TUF" "$TUF_CYCLE" "tough-v0.20.0"
assert_not_ancestor "$TUF" "$TUF_CYCLE" "tough-v0.19.0"
assert_ancestor "$TUF" "$TUF_TS" "tough-v0.20.0"
assert_not_ancestor "$TUF" "$TUF_TS" "tough-v0.19.0"
[[ "$TUF_CYCLE" != "$TUF_TS" ]]
cycle_files=$("${git_cmd[@]}" -C "$TUF" diff-tree --no-commit-id --name-only -r "$TUF_CYCLE")
printf '%s\n' "$cycle_files" | grep -Fx 'tough/src/lib.rs' >/dev/null
ts_files=$("${git_cmd[@]}" -C "$TUF" diff-tree --no-commit-id --name-only -r "$TUF_TS")
printf '%s\n' "$ts_files" | grep -Fx 'tough/src/error.rs' >/dev/null

# jhipster
"${git_cmd[@]}" -C "$JHI" cat-file -e "$JHI_FIX^{commit}"
"${git_cmd[@]}" -C "$JHI" cat-file -e "$JHI_DEP^{commit}"
jauthor=$("${git_cmd[@]}" -C "$JHI" log -1 --format='%an' "$JHI_FIX")
[[ $jauthor == 'Marcelo Shima' ]]
jsubj=$("${git_cmd[@]}" -C "$JHI" log -1 --format='%s' "$JHI_FIX")
[[ $jsubj == 'Adjust custom audit api (#301)' ]]
dauthor=$("${git_cmd[@]}" -C "$JHI" log -1 --format='%an' "$JHI_DEP")
[[ $dauthor == 'dependabot[bot]' ]]
jbody=$("${git_cmd[@]}" -C "$JHI" log -1 --format='%B' "$JHI_FIX")
if printf '%s\n' "$jbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'jhipster closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel590=$("${git_cmd[@]}" -C "$JHI" rev-parse 'v5.9.0^{commit}')
peel591=$("${git_cmd[@]}" -C "$JHI" rev-parse 'v5.9.1^{commit}')
[[ $peel590 == "$JHI_590" ]]
[[ $peel591 == "$JHI_591" ]]
assert_ancestor "$JHI" "$JHI_FIX" "v5.9.1"
assert_not_ancestor "$JHI" "$JHI_FIX" "v5.9.0"
jblob_p=$("${git_cmd[@]}" -C "$JHI" rev-parse "${JHI_FIX}^:${JHI_RES}")
jblob_f=$("${git_cmd[@]}" -C "$JHI" rev-parse "${JHI_FIX}:${JHI_RES}")
jblob_590=$("${git_cmd[@]}" -C "$JHI" rev-parse "v5.9.0:${JHI_RES}")
jblob_591=$("${git_cmd[@]}" -C "$JHI" rev-parse "v5.9.1:${JHI_RES}")
[[ $jblob_p == "$JHI_BLOB_P" ]]
[[ $jblob_f == "$JHI_BLOB_F" ]]
[[ $jblob_590 == "$JHI_BLOB_P" ]]
[[ $jblob_591 == "$JHI_BLOB_F" ]]
jfix_src=$("${git_cmd[@]}" -C "$JHI" show "${JHI_FIX}:${JHI_RES}")
printf '%s\n' "$jfix_src" | grep -F 'AuditedEntity' >/dev/null
jpar_src=$("${git_cmd[@]}" -C "$JHI" show "${JHI_FIX}^:${JHI_RES}")
printf '%s\n' "$jpar_src" | grep -F 'Class.forName' >/dev/null

# apollo-rs
"${git_cmd[@]}" -C "$APO" cat-file -e "$APO_FIX^{commit}"
aauthor=$("${git_cmd[@]}" -C "$APO" log -1 --format='%an' "$APO_FIX")
[[ $aauthor == 'Sachin D. Shinde' ]]
asubj=$("${git_cmd[@]}" -C "$APO" log -1 --format='%s' "$APO_FIX")
[[ $asubj == 'Avoid reprocessing named fragments (#952)' ]]
abody=$("${git_cmd[@]}" -C "$APO" log -1 --format='%B' "$APO_FIX")
if printf '%s\n' "$abody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'apollo closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel126=$("${git_cmd[@]}" -C "$APO" rev-parse 'apollo-compiler@1.26.0^{commit}')
peel127=$("${git_cmd[@]}" -C "$APO" rev-parse 'apollo-compiler@1.27.0^{commit}')
[[ $peel126 == "$APO_126" ]]
[[ $peel127 == "$APO_127" ]]
assert_ancestor "$APO" "$APO_FIX" "apollo-compiler@1.27.0"
assert_not_ancestor "$APO" "$APO_FIX" "apollo-compiler@1.26.0"
ablob_p=$("${git_cmd[@]}" -C "$APO" rev-parse "${APO_FIX}^:${APO_FRAG}")
ablob_f=$("${git_cmd[@]}" -C "$APO" rev-parse "${APO_FIX}:${APO_FRAG}")
ablob_126=$("${git_cmd[@]}" -C "$APO" rev-parse "apollo-compiler@1.26.0:${APO_FRAG}")
ablob_127=$("${git_cmd[@]}" -C "$APO" rev-parse "apollo-compiler@1.27.0:${APO_FRAG}")
[[ $ablob_p == "$APO_BLOB_P" ]]
[[ $ablob_f == "$APO_BLOB_F" ]]
[[ $ablob_126 == "$APO_BLOB_P" ]]
[[ $ablob_127 == "$APO_BLOB_F" ]]

# minio operator
"${git_cmd[@]}" -C "$MIN" cat-file -e "$MIN_FIX^{commit}"
nauthor=$("${git_cmd[@]}" -C "$MIN" log -1 --format='%an' "$MIN_FIX")
[[ $nauthor == 'Pedro Juarez' ]]
nsubj=$("${git_cmd[@]}" -C "$MIN" log -1 --format='%s' "$MIN_FIX")
[[ $nsubj == 'Security fix: Use audience `sts.min.io` to invoke TokenReview. (#2418)' ]]
nbody=$("${git_cmd[@]}" -C "$MIN" log -1 --format='%B' "$MIN_FIX")
if printf '%s\n' "$nbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'minio closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel701=$("${git_cmd[@]}" -C "$MIN" rev-parse 'v7.0.1^{commit}')
peel710=$("${git_cmd[@]}" -C "$MIN" rev-parse 'v7.1.0^{commit}')
[[ $peel701 == "$MIN_701" ]]
[[ $peel710 == "$MIN_710" ]]
assert_ancestor "$MIN" "$MIN_FIX" "v7.1.0"
assert_not_ancestor "$MIN" "$MIN_FIX" "v7.0.1"
nblob_p=$("${git_cmd[@]}" -C "$MIN" rev-parse "${MIN_FIX}^:${MIN_STS}")
nblob_f=$("${git_cmd[@]}" -C "$MIN" rev-parse "${MIN_FIX}:${MIN_STS}")
nblob_701=$("${git_cmd[@]}" -C "$MIN" rev-parse "v7.0.1:${MIN_STS}")
nblob_710=$("${git_cmd[@]}" -C "$MIN" rev-parse "v7.1.0:${MIN_STS}")
[[ $nblob_p == "$MIN_BLOB_P" ]]
[[ $nblob_f == "$MIN_BLOB_F" ]]
[[ $nblob_701 == "$MIN_BLOB_P" ]]
[[ $nblob_710 == "$MIN_BLOB_F" ]]
nfix_src=$("${git_cmd[@]}" -C "$MIN" show "${MIN_FIX}:${MIN_STS}")
printf '%s\n' "$nfix_src" | grep -F 'TokenReviewAudience = "sts.min.io"' >/dev/null

# strawberry
"${git_cmd[@]}" -C "$STR" cat-file -e "$STR_FIX^{commit}"
sauthor=$("${git_cmd[@]}" -C "$STR" log -1 --format='%an' "$STR_FIX")
[[ $sauthor == 'Thiago Bellini Ribeiro' ]]
ssubj=$("${git_cmd[@]}" -C "$STR" log -1 --format='%s' "$STR_FIX")
[[ $ssubj == 'fix: Prevent a possible security issue when resolving a relay node with multiple possibilities (#3749)' ]]
sbody=$("${git_cmd[@]}" -C "$STR" log -1 --format='%B' "$STR_FIX")
if printf '%s\n' "$sbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'strawberry closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel256=$("${git_cmd[@]}" -C "$STR" rev-parse '0.256.1^{commit}')
peel257=$("${git_cmd[@]}" -C "$STR" rev-parse '0.257.0^{commit}')
[[ $peel256 == "$STR_256" ]]
[[ $peel257 == "$STR_257" ]]
assert_ancestor "$STR" "$STR_FIX" "0.257.0"
assert_not_ancestor "$STR" "$STR_FIX" "0.256.1"
sblob_p=$("${git_cmd[@]}" -C "$STR" rev-parse "${STR_FIX}^:${STR_FIELDS}")
sblob_f=$("${git_cmd[@]}" -C "$STR" rev-parse "${STR_FIX}:${STR_FIELDS}")
sblob_256=$("${git_cmd[@]}" -C "$STR" rev-parse "0.256.1:${STR_FIELDS}")
sblob_257=$("${git_cmd[@]}" -C "$STR" rev-parse "0.257.0:${STR_FIELDS}")
[[ $sblob_p == "$STR_BLOB_P" ]]
[[ $sblob_f == "$STR_BLOB_F" ]]
[[ $sblob_256 == "$STR_BLOB_P" ]]
[[ $sblob_257 == "$STR_BLOB_F" ]]

python3 - "$RAT" "$BMO" "$PAY" "$TUF" "$JHI" "$APO" "$MIN" "$STR" << 'PY'
import re, subprocess, sys

pat = re.compile(
    r"Co-authored-by:.*(Claude|Cursor Agent|Copilot|ChatGPT|OpenAI|Anthropic)|"
    r"Generated with Claude|Generated with Copilot|noreply@anthropic|"
    r"Made-with: Cursor|chatgpt|claude\.ai",
    re.I,
)
git = ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]
jobs = [
    (sys.argv[1], "v1.3.2"),
    (sys.argv[2], "v0.9.1"),
    (sys.argv[3], "v1.6.2"),
    (sys.argv[5], "v5.9.1"),
    (sys.argv[6], "apollo-compiler@1.27.0"),
    (sys.argv[7], "v7.1.0"),
    (sys.argv[8], "0.257.0"),
]
for repo, rev in jobs:
    out = subprocess.check_output(git + ["-C", repo, "log", rev, "--format=%H%x1f%an%x1f%s%x1f%b%x1e"], text=True)
    hits = []
    for rec in out.split("\x1e"):
        if pat.search(rec):
            hits.append(rec.split("\x1f", 1)[0][:40])
    assert hits == [], (repo, rev, hits[:5])
tuf = sys.argv[4]
out = subprocess.check_output(git + ["-C", tuf, "log", "--all", "--format=%H%x1f%an%x1f%s%x1f%b%x1e"], text=True)
hits = []
for rec in out.split("\x1e"):
    if pat.search(rec):
        hits.append(rec.split("\x1f", 1)[0][:40])
assert hits == [], ("tough", hits[:5])
print("ai_trailer_scan_empty_on_relevant_history")
PY

printf 'REPLAY_OK reviewed=9 PASS_proposal=0 NARROW=0 REJECT=9 UNKNOWN=0 BLOCKED=0\n'
