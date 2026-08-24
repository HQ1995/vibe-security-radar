#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-contributor-butfor11-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Evidence start is pinned to canonical81. Current leader-accepted count is 82.
# Packet delta is 0. PASS is a proposal only. This script admits none.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=0
export TMPDIR=/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-contributor-butfor11-grok46-xhigh/work

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-contributor-butfor11-grok46-xhigh
HE=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/hermes-webui
SH=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/sharpcompress
GL=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/gitlab-mcp
TI=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/titra
DY=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/dynatrace-mcp
OC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/openclaw
FI=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/fission
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

g() {
  local repo=$1
  shift
  local errf=$OWNED/work/.giterr
  set +e
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
  if [[ -s $errf ]]; then
    grep -vF 'unable to normalize alternate object path' "$errf" >&2 || true
  fi
  rm -f "$errf"
  return $rc
}

assert_ancestor() {
  g "$1" merge-base --is-ancestor "$2" "$3"
}

assert_not_ancestor() {
  if g "$1" merge-base --is-ancestor "$2" "$3"; then
    printf 'unexpected ancestor: %s is ancestor of %s in %s\n' "$2" "$3" "$1" >&2
    exit 1
  fi
}

require_dir "$OWNED"
require_dir "$HE/.git"
require_dir "$SH/.git"
require_dir "$GL/.git"
require_dir "$TI/.git"
require_dir "$DY/.git"
require_dir "$OC/.git"
require_dir "$FI/.git"
require_dir "$ADV/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected-11.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/work/uniqueness.json"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/ledger.jsonl" \
  3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/ledger.jsonl" \
  58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" \
  d436f47f82297eb0d9363ad0f3876adc639b1f61e9b23c7f9d613545741e106e
expect_hash "$OWNED/selected-11.jsonl" \
  b19aeef24cf7cf559f7dfd69d0def03fd4d6e7be2bdd5f6cf15a5ded63ef48f6
expect_hash "$OWNED/cases.jsonl" \
  54ee3c1b64d8f99d24b937fd8c8b6399f259b8d1df25ee9da59ca27c3be49cfa
expect_hash "$OWNED/report.md" \
  a0a768aaa9052ad0347877798c39e3a757b804e42808f127723b856f5138da5b
expect_hash "$OWNED/work/uniqueness.json" \
  138f8f37159b9cad8e32e2217ba916f97880aa37a3cc2d6c4f143e7ac00376eb
expect_hash "$OWNED/work/pages/ghsa/GHSA-5WQV-FHMR-PJGH.json" \
  4b585bb4626721be7186c110a0ebc37729128ebf6b53beba058feeeca8d31980
expect_hash "$OWNED/work/pages/repo-advisory/nesquena__hermes-webui__GHSA-5WQV-FHMR-PJGH.json" \
  f2e7217d5c8cc204ab24e1b474f365c353c7ebff4714daf287490f0a75e7ba6d
expect_hash "$OWNED/work/pages/ghsa/GHSA-6C8G-7P36-R338.json" \
  c1d9117a7655660fcb568de25f1b03851e822c40cfc430cea963dbc5ab5aef5e
expect_hash "$OWNED/work/pages/repo-advisory/adamhathcock__sharpcompress__GHSA-6C8G-7P36-R338.json" \
  e55a2e560521f0e17bc6be561d6f5023576f7fbcb36de602ef643e9920e597e6
expect_hash "$OWNED/work/pages/repo-advisory/zereight__gitlab-mcp__GHSA-7C3W-FXGH-FRC7.json" \
  e0e107ee3276b0bbbd93e1820bb12c99538138f1936a230192e2c79394b599bc
expect_hash "$OWNED/work/pages/repo-advisory/openclaw__openclaw__GHSA-7JX6-764P-FGG9.json" \
  2ff551d26433d2890d6a7835480af72e6e505d16cb60ef05a7084f65475c377e
expect_hash "$OWNED/work/pages/ghsa/GHSA-H2VW-PH2C-JVWF.json" \
  2a6406c7c5604f23bfef0f55b0d47ef211f177d28bd61c3aa62c6832c9a8c32d
expect_hash "$OWNED/work/pages/repo-advisory/kromitgmbh__titra__GHSA-PQGX-6WG3-GMVR.json" \
  e9bb7a103b5f9167e4f49c34a91ca7d13b1b5d5945d32f43e1f4458a833ee033
expect_hash "$OWNED/work/pages/ghsa/GHSA-PQH8-P93P-2RX7.json" \
  1ca58ee17296251e4fcbb7c3e8185729b10ed2a86fa7d959fb050d0c7b085a10
expect_hash "$OWNED/work/pages/ghsa/GHSA-R5JH-Q2MW-GCX4.json" \
  74a1d1707dbe568215056633922e29ad99527b3febfad66aa8946e0ca1047053
expect_hash "$OWNED/work/pages/ghsa/GHSA-W85G-3H6X-4XH2.json" \
  38b85e3aa528d3b93cb96925596444009fd84f499ce18333a1030d3432260524
expect_hash "$OWNED/work/pages/ghsa/GHSA-XMXX-7P24-H892.json" \
  f7a5d379d2f9c3d52d178c25fbcb1d30ec1c13dd84406ce1f51ed7f3131727ea
expect_hash "$OWNED/work/pages/ghsa/GHSA-XQ94-R468-QWGJ.json" \
  dc08ed81dd553b6d3e71934b25f059eb47086c655a142409abc03c67f20ab6bc
expect_hash "$OWNED/work/pages/npm/openclaw.wanted.json" \
  8e2e5d8a1dd884bfe11eab5be541ba5f34ffdbd252fe4dd7304593b2de5d6314
expect_hash "$OWNED/work/pages/npm/gitlab-mcp.wanted.json" \
  80e89aa039d5dc50dde83c5bfc0888e67d489b5c2745819b83f0e653d2896253
expect_hash "$OWNED/work/pages/npm/dynatrace.wanted.json" \
  0ea55d95d672783c371b45d4e35f6b645b8ca44823df07f371d209eed44055e4

[[ "$(g "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]
[[ "$(g "$ROOT" rev-parse 6800d2127c19532160cc88880115ae28cc446aa5)" == 6800d2127c19532160cc88880115ae28cc446aa5 ]]

python3 - "$OWNED" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected-11.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned / "result.json").read_text())
uniq = json.loads((owned / "work/uniqueness.json").read_text())
report = (owned / "report.md").read_text()
replay = (owned / "replay.sh").read_text()
assert len(rows) == 11, len(rows)
assert len(sel) == 11, len(sel)
want = [
    "GHSA-5WQV-FHMR-PJGH",
    "GHSA-6C8G-7P36-R338",
    "GHSA-7C3W-FXGH-FRC7",
    "GHSA-7JX6-764P-FGG9",
    "GHSA-H2VW-PH2C-JVWF",
    "GHSA-PQGX-6WG3-GMVR",
    "GHSA-PQH8-P93P-2RX7",
    "GHSA-R5JH-Q2MW-GCX4",
    "GHSA-W85G-3H6X-4XH2",
    "GHSA-XMXX-7P24-H892",
    "GHSA-XQ94-R468-QWGJ",
]
assert [r["case_id"] for r in rows] == want
assert [r["case_id"] for r in sel] == want
assert all(r["record_kind"] == "PRESERVED_HYPOTHESIS" for r in sel)
assert all(r["fp211_verdict"] == "NARROW" for r in sel)
assert all(r["not_in_canonical81_strict"] is True for r in sel)
assert all(r["verdict"] == "NARROW" for r in rows)
assert all(r["worker_verdict"] == "NARROW" for r in rows)
assert all(r["countable_proposal"] is False for r in rows)
assert all(r["causal_admission"] is False for r in rows)
assert all(r["publication_status"] == "HOLD" for r in rows)
assert res["counts"]["PASS"] == 0
assert res["counts"]["NARROW"] == 11
assert res["counts"]["REJECT"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 0
assert res["start_count"] == 81
assert res["current_leader_accepted_count"] == 82
assert res["packet_delta"] == 0
assert res["leader_accepted"]["start_count"] == 81
assert res["leader_accepted"]["current_leader_accepted_count"] == 82
assert res["leader_accepted"]["packet_delta"] == 0
assert res["leader_accepted"]["ledger_sha256"] == "58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23"
assert res["leader_accepted"]["commit"] == "6800d2127c19532160cc88880115ae28cc446aa5"
assert res["canonical_count_updated"] is False
assert res["pass_proposals"] == []
forbidden = "stays" + " 81"
assert forbidden not in report
assert forbidden not in replay
assert forbidden not in json.dumps(res)
assert "canonical_strict_count_untouched" not in res
assert "Start count 81" in report
assert "Current leader-accepted count 82" in report
assert "Packet delta 0" in report
assert uniq["start_count"] == 81
assert uniq["current_leader_accepted_count"] == 82
assert uniq["packet_delta"] == 0
assert uniq["assigned_in_canonical81_strict"] == []
assert uniq["assigned_in_canonical82_strict"] == []
assert uniq["assigned_fingerprints_unique"] is True
fps = [r["mechanism_fingerprint"] for r in rows]
assert len(set(fps)) == 11
assert uniq["fingerprints"] == {r["case_id"]: r["mechanism_fingerprint"] for r in rows}
by = {r["case_id"]: r for r in rows}
assert by["GHSA-5WQV-FHMR-PJGH"]["identity_gate"] == "NARROW"
assert by["GHSA-5WQV-FHMR-PJGH"]["but_for_gate"] == "NARROW"
assert by["GHSA-5WQV-FHMR-PJGH"]["fix_reversal_gate"] == "NARROW"
assert by["GHSA-6C8G-7P36-R338"]["but_for_gate"] == "NARROW"
assert by["GHSA-7C3W-FXGH-FRC7"]["but_for_gate"] == "NARROW"
assert by["GHSA-7JX6-764P-FGG9"]["but_for_gate"] == "NARROW"
assert by["GHSA-7JX6-764P-FGG9"]["remediation_patch_delta_gate"] == "NARROW"
assert by["GHSA-H2VW-PH2C-JVWF"]["but_for_gate"] == "NARROW"
assert by["GHSA-PQGX-6WG3-GMVR"]["but_for_gate"] == "NARROW"
assert by["GHSA-PQH8-P93P-2RX7"]["but_for_gate"] == "NARROW"
assert by["GHSA-R5JH-Q2MW-GCX4"]["but_for_gate"] == "NARROW"
assert by["GHSA-W85G-3H6X-4XH2"]["but_for_gate"] == "NARROW"
assert by["GHSA-XMXX-7P24-H892"]["but_for_gate"] == "NARROW"
assert by["GHSA-XQ94-R468-QWGJ"]["but_for_gate"] == "NARROW"
assert by["GHSA-XQ94-R468-QWGJ"]["fix_reversal_gate"] == "NARROW"
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(
    r"ghp_" + r"[A-Za-z0-9]{20,}|"
    r"github" + r"_pat_[A-Za-z0-9_]+|"
    r"sk" + r"_live_|"
    r"xox[baprs]-|"
    r"AKIA" + r"[0-9A-Z]{16}|"
    r"BEGIN" + r" PRIVATE"
)
for name in ("cases.jsonl", "selected-11.jsonl", "report.md", "replay.sh", "result.json", "work/uniqueness.json"):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    assert text.endswith("\n"), name
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (name, line)
c81 = json.loads(Path(sys.argv[2]).read_text())
c82 = json.loads(Path(sys.argv[3]).read_text())
ids81 = {x.upper() for x in c81["strict_released_case_ids"]}
ids82 = {x.upper() for x in c82["strict_released_case_ids"]}
assert len(c81["strict_released_case_ids"]) == 81
assert len(c82["strict_released_case_ids"]) == 82
assert c82["canonical_strict_count"] == 82
assert c82["ledger_sha256"] == "58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23"
for i in want:
    assert i not in ids81, i
    assert i not in ids82, i
assert "GHSA-QF5V-M7P4-95RP" in ids82
assert "GHSA-QF5V-M7P4-95RP" not in want
g5 = json.loads((owned / "work/pages/ghsa/GHSA-5WQV-FHMR-PJGH.json").read_text())
assert g5["type"] == "unreviewed"
assert g5["vulnerabilities"] == []
assert not g5.get("source_code_location")
assert g5.get("repository_advisory_url") in (None, "")
r5 = json.loads((owned / "work/pages/repo-advisory/nesquena__hermes-webui__GHSA-5WQV-FHMR-PJGH.json").read_text())
assert r5.get("status") == "404" or r5.get("message") == "Not Found"
npm_gl = json.loads((owned / "work/pages/npm/gitlab-mcp.wanted.json").read_text())
assert npm_gl["wanted"]["2.1.18"]["gitHead"] == "74a8c834424ff557ad8bc6f225e4dc5acf80aa13"
assert npm_gl["wanted"]["2.1.31"]["in_versions"] is False
assert npm_gl["wanted"]["2.1.32"]["in_versions"] is False
assert npm_gl["wanted"]["2.1.30"]["gitHead"] == "cff3ebeec272d7cc609d9b3cab57f52cb15fae96"
assert npm_gl["wanted"]["2.1.38"]["gitHead"] == "f8d1d7f0b2afa35a1d891ee3643fce1c2cbcf7db"
rel24 = json.loads((owned / "work/pages/github-releases/fission_v1.24.0.json").read_text())
assert rel24["prerelease"] is True
rel25 = json.loads((owned / "work/pages/github-releases/fission_v1.25.0.json").read_text())
assert rel25["prerelease"] is False
print("conservation assigned=11 reviewed=11 unreviewed=0 PASS_proposal=0 NARROW=11 REJECT=0 UNKNOWN=0 BLOCKED=0 start_count=81 current_leader_accepted_count=82 packet_delta=0")
PY

C5WQV=ee672df463e285791e4466e6132297e5feb4a1df
P5WQV=465b97a9f5e5b7bd733eaab6fe251d73e815df6e
F5WQV=2a3baa71b81ca92da8ece8616a09f15894beec71
PEEL442=4d90577e25d5537cb07290eca3fb8abff3bab316
C6C8G=8b95e0a76d6b387533175730e2895ccd16772d07
P6C8G=3f9986c13c973f5e9b8e08da8bfb5e8259044a44
F6C8G=2021a06626d0555a4d69471386e763ca5f5d5dfb
PEEL474=5758b08236b275b926bc2c3d97604a96d21546c0
PEEL480=6e59c7d7bbf8c19a8a92c3c382599906684bb93d
C7C3W=c156ac7675207e3dbc0c6a4b3ed6931dc96513c2
P7C3W=dc16faa9e2a186ffd4b4a96fc1a9cd2b94f9236a
F7C3W=e2a81a047ab8750fa5bfa1763b5d85e5616f3994
PEEL218=74a8c834424ff557ad8bc6f225e4dc5acf80aa13
PEEL230=cff3ebeec272d7cc609d9b3cab57f52cb15fae96
PEEL238=f8d1d7f0b2afa35a1d891ee3643fce1c2cbcf7db
PEEL232=84c7ddfaddc0d04e5bdb39d35a80e75014881535
C7JX6=6e498a1f628873b16aaeeecfbc3dc249b9a1d8bf
P7JX6=2ec1a27c9fba56ac30e4a8b35a89343029be9492
F7JX6=08a73dbe4b09e6a15db591649ddec81b48c59584
PEEL526=10ad3aa16068baa84a1bd9ac4f7d42ae725cedb7
PEEL527=27ae826f65256c7fbd1d78475fca87b674a53e7b
CH2VW=7d7f5d85b4ff0bf9a135ced8022d8860a1979a06
PH2VW=49d962a82f67203994c39cc577b39aa47632fef4
FH2VW=2f06696579a1ab0cb5bbbbb6a900414a6b2e3cd1
PEEL401=da64a978e5814567f7797cc34fbe29b61b7eae7a
PEEL405=3e72c0352dde84a0bcb3aabafa99c2d4b12d1c46
PEEL420=115f05d5952adeaa8043311c24c4b8a3803481ba
MPQGX=40331e610075e7c9a076873cc5b3655362d136db
CPQGX=67c7b7663219c9e28fce487b1803706b333c2a4f
PPQGX=62fe0533d792ca72794af098cd6b1d3301514ff7
FPQGX=2e2ac5cbeed47a76720b21c7fde0214a242e065e
PEEL9948=433d1092e6e0a584a617cae61f45a88a1eed3e0d
CPQH8=66ff2a7c8bedc23939d6d70ab4c3bdce53673843
PPQH8=c11191125271e676109e78fef32df4a61bfa4ce6
FPQH8=15d3546c0618ffbaeaeca477337e08e92f2151bc
PEEL120=1c192a0427bb348b0843779207f556052d6c28e7
PEEL211=9a5f6f86d186f1168645e24673c73bc56a94dda8
MR5JH=0d851525a35ba517dda7fe892333df5d0919dffc
CR5JH=5a3d68a349b001302b1acb6e838f05283160548d
PR5JH=c4125e170a222a4bf1539a5c4167533e35612588
FR5JH=8298e33ea7457702f893eae11077987cf905edb4
PEEL124=ce617120c41b9e4a51d577f81b441238264e88fd
PEEL125=ae970aaa9bc76ec93d748bdaf03fd7523b6b6a62
CW85G=8d74578ceb0c3b913555dff6265821eb0fc09749
PW85G=f7123ec30af8c96bb2cb4da198e19bc03312ba16
FW85G=0ed4f8a72bb140045962e97ab01c94c076b758a4
PEEL328=f9b1079283a8ee25a7cee77c8f8225d5c813bc30
PEEL331=213a704b71f4996dc82a583288ee53785215f627
CXMXX=f4b03599f0fb9c2f76e8dbe5fde13948d68dbc3f
PXMXX=7f6e87e9180b9f236aa88b90936be8f6f7988bc2
FXMXX=acd4e0a32f12e1ad85f3130f63b42443ce90f094
PEEL414=323493fa1b6adc1e10b9954a68d5eaa5a6ef1170
PEEL415=041266a6699cac3baef8ef39db41fa26f29f9db3
CXQ94=75602014dbc5088b80e9b236146dfe5fdcc59e20
PXQ94=3cf75f760c0f89adbad9415b3d5fdb5b83f2dd82
FXQ94=121c452d666d4749744dc2089287d0227aae2ed3
PEEL308=3caab9260cb0a0064e6a37b2de3bedc8a547e599
PEEL410=44e5b62c27e088128e32e209c146de346c3ea7e6

# GHSA-5WQV
body=$(g "$HE" log -1 --format='%B' "$C5WQV")
printf '%s\n' "$body" | grep -F 'Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>' >/dev/null
pc=$(g "$HE" log -1 --format='%P' "$C5WQV")
[[ $pc == "$P5WQV" ]]
assert_ancestor "$HE" "$C5WQV" "$PEEL442"
assert_not_ancestor "$HE" "$F5WQV" "$PEEL442"
assert_ancestor "$HE" "$F5WQV" "v0.51.443"
[[ "$(g "$HE" rev-parse 'v0.51.443^{commit}')" == "$F5WQV" ]]
parent_routes=$(g "$HE" show "${P5WQV}:api/routes.py")
printf '%s\n' "$parent_routes" | grep -F '/api/session' >/dev/null

# GHSA-6C8G
an=$(g "$SH" log -1 --format='%an %ae' "$C6C8G")
[[ $an == 'copilot-swe-agent[bot] 198982749+Copilot@users.noreply.github.com' ]]
assert_ancestor "$SH" "$C6C8G" "$PEEL474"
assert_not_ancestor "$SH" "$F6C8G" "$PEEL474"
assert_ancestor "$SH" "$F6C8G" "$PEEL480"
parent_ext=$(g "$SH" show "${P6C8G}:src/SharpCompress/Archives/IArchiveExtensions.cs")
printf '%s\n' "$parent_ext" | grep -F 'WriteToDirectory' >/dev/null
printf '%s\n' "$parent_ext" | grep -F 'Path.Combine' >/dev/null

# GHSA-7C3W
bodyg=$(g "$GL" log -1 --format='%B' "$C7C3W")
printf '%s\n' "$bodyg" | grep -F 'Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>' >/dev/null
assert_ancestor "$GL" "$C7C3W" "$PEEL218"
assert_not_ancestor "$GL" "$F7C3W" "$PEEL218"
assert_not_ancestor "$GL" "$F7C3W" "$PEEL230"
assert_ancestor "$GL" "$F7C3W" "$PEEL238"
assert_ancestor "$GL" "$F7C3W" "$PEEL232"
[[ "$(g "$GL" rev-parse 'v2.1.18^{commit}')" == "$PEEL218" ]]
parent_idx=$(g "$GL" show "${P7C3W}:index.ts")
printf '%s\n' "$parent_idx" | grep -F '/jobs/${jobId}/trace' >/dev/null

# GHSA-7JX6
subj=$(g "$OC" log -1 --format='%s' "$C7JX6")
printf '%s\n' "$subj" | grep -F '[AI]' >/dev/null
assert_ancestor "$OC" "$C7JX6" "$PEEL526"
assert_not_ancestor "$OC" "$F7JX6" "$PEEL526"
assert_ancestor "$OC" "$F7JX6" "$PEEL527"
if g "$OC" cat-file -e "${P7JX6}:extensions/qqbot/src/exec-approvals.ts" 2>/dev/null; then
  parent_qq=$(g "$OC" show "${P7JX6}:extensions/qqbot/src/exec-approvals.ts")
  if printf '%s\n' "$parent_qq" | grep -F 'authorizeQQBotApprovalAction' >/dev/null; then
    printf 'parent unexpectedly has authorizeQQBotApprovalAction\n' >&2
    exit 1
  fi
fi
cand_qq=$(g "$OC" show "${C7JX6}:extensions/qqbot/src/exec-approvals.ts")
printf '%s\n' "$cand_qq" | grep -F 'authorizeQQBotApprovalAction' >/dev/null

# GHSA-H2VW
bodyh=$(g "$OC" log -1 --format='%B' "$CH2VW")
printf '%s\n' "$bodyh" | grep -F 'Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>' >/dev/null
assert_not_ancestor "$OC" "$CH2VW" "$PEEL401"
parent_vlm=$(g "$OC" show "${PH2VW}:src/agents/minimax-vlm.ts")
printf '%s\n' "$parent_vlm" | grep -F 'MINIMAX_API_HOST' >/dev/null
vlm401=$(g "$OC" show "${PEEL401}:src/agents/minimax-vlm.ts")
printf '%s\n' "$vlm401" | grep -F 'MINIMAX_API_HOST' >/dev/null
if g "$OC" cat-file -e "${PEEL401}:extensions/minimax/speech-provider.ts" 2>/dev/null; then
  printf 'v2026.4.1 unexpectedly has MiniMax TTS speech-provider\n' >&2
  exit 1
fi
assert_ancestor "$OC" "$CH2VW" "$PEEL405"
assert_not_ancestor "$OC" "$FH2VW" "$PEEL405"
assert_ancestor "$OC" "$FH2VW" "$PEEL420"

# GHSA-PQGX
assert_not_ancestor "$TI" "$MPQGX" "$CPQGX"
assert_not_ancestor "$TI" "$MPQGX" "$PEEL9948"
assert_ancestor "$TI" "$CPQGX" "$PEEL9948"
assert_not_ancestor "$TI" "$FPQGX" "$PEEL9948"
assert_ancestor "$TI" "$FPQGX" "0.99.49"
[[ "$(g "$TI" rev-parse '0.99.49^{commit}')" == "$FPQGX" ]]
an_car=$(g "$TI" log -1 --format='%an %ae' "$CPQGX")
[[ $an_car == 'Copilot 198982749+Copilot@users.noreply.github.com' ]]
parent_vm=$(g "$TI" show "${PPQGX}:imports/api/timecards/server/methods.js")
printf '%s\n' "$parent_vm" | grep -F 'vm.run' >/dev/null
printf '%s\n' "$parent_vm" | grep -F 'timeEntryRule' >/dev/null

# GHSA-PQH8
an_d=$(g "$DY" log -1 --format='%an %ae' "$CPQH8")
[[ $an_d == 'copilot-swe-agent[bot] 198982749+Copilot@users.noreply.github.com' ]]
assert_ancestor "$DY" "$CPQH8" "$PEEL120"
assert_not_ancestor "$DY" "$FPQH8" "$PEEL120"
assert_ancestor "$DY" "$FPQH8" "$PEEL211"
[[ "$(g "$DY" rev-parse 'v1.2.0^{commit}')" == "$PEEL120" ]]
[[ "$(g "$DY" rev-parse 'v2.1.1^{commit}')" == "$PEEL211" ]]
parent_prob=$(g "$DY" show "${PPQH8}:src/capabilities/list-problems.ts")
printf '%s\n' "$parent_prob" | grep -F 'now()-${timeframe}' >/dev/null

# GHSA-R5JH
assert_not_ancestor "$FI" "$MR5JH" "$CR5JH"
assert_not_ancestor "$FI" "$MR5JH" "$PEEL124"
assert_ancestor "$FI" "$CR5JH" "$PEEL124"
assert_not_ancestor "$FI" "$FR5JH" "$PEEL124"
assert_ancestor "$FI" "$FR5JH" "$PEEL125"
[[ "$(g "$FI" rev-parse 'v1.24.0^{commit}')" == "$PEEL124" ]]
[[ "$(g "$FI" rev-parse 'v1.25.0^{commit}')" == "$PEEL125" ]]
body_car=$(g "$FI" log -1 --format='%B' "$CR5JH")
printf '%s\n' "$body_car" | grep -F 'Co-Authored-By: Claude Opus 4.7' >/dev/null
parent_utils=$(g "$FI" show "${PR5JH}:pkg/utils/utils.go")
printf '%s\n' "$parent_utils" | grep -F 'SanitizeFilePath' >/dev/null
printf '%s\n' "$parent_utils" | grep -F 'HasPrefix' >/dev/null

# GHSA-W85G
bodyw=$(g "$OC" log -1 --format='%B' "$CW85G")
printf '%s\n' "$bodyw" | grep -F 'Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>' >/dev/null
assert_ancestor "$OC" "$CW85G" "$PEEL328"
assert_not_ancestor "$OC" "$FW85G" "$PEEL328"
assert_ancestor "$OC" "$FW85G" "$PEEL331"
parent_img=$(g "$OC" show "${PW85G}:src/media/image-ops.ts")
printf '%s\n' "$parent_img" | grep -F 'sips' >/dev/null
if printf '%s\n' "$parent_img" | grep -F 'limitInputPixels' >/dev/null; then
  printf 'parent image-ops unexpectedly has limitInputPixels\n' >&2
  exit 1
fi

# GHSA-XMXX
bodyx=$(g "$OC" log -1 --format='%B' "$CXMXX")
printf '%s\n' "$bodyx" | grep -F 'Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>' >/dev/null
assert_ancestor "$OC" "$CXMXX" "$PEEL414"
assert_not_ancestor "$OC" "$FXMXX" "$PEEL414"
assert_ancestor "$OC" "$FXMXX" "$PEEL415"
parent_http=$(g "$OC" show "${PXMXX}:src/gateway/server-http.ts")
printf '%s\n' "$parent_http" | grep -F 'resolvedAuth' >/dev/null

# GHSA-XQ94
bodyq=$(g "$OC" log -1 --format='%B' "$CXQ94")
printf '%s\n' "$bodyq" | grep -F 'Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>' >/dev/null
assert_ancestor "$OC" "$CXQ94" "$PEEL308"
assert_not_ancestor "$OC" "$FXQ94" "$PEEL308"
assert_ancestor "$OC" "$FXQ94" "$PEEL410"
parent_cdp=$(g "$OC" show "${PXQ94}:src/browser/cdp.ts")
printf '%s\n' "$parent_cdp" | grep -F '/json/version' >/dev/null

printf 'REPLAY_OK reviewed=11 PASS_proposal=0 NARROW=11 REJECT=0 UNKNOWN=0 BLOCKED=0\n'
