#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-fp211-unseen-twogate5-grok46-high.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Canonical baseline is 84. Packet delta is 0. Terminal NARROW. Zero PASS proposals.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export TMPDIR=/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unseen-twogate5-grok46-high/work

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fp211-unseen-twogate5-grok46-high
O=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw
C=/home/hanqing/.cache/cve-analyzer/repos/churchcrm_crm

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
  /usr/bin/timeout 30 "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
  if [[ $rc -eq 124 ]]; then
    printf 'git timeout: %s\n' "$*" >&2
    rm -f "$errf"
    exit 1
  fi
  if [[ -s $errf ]]; then
    if grep -Eiq 'bad object|not found|does not exist|did not exist|needed a single revision|promisor|partial clone|could not get object|unable to read' "$errf"; then
      if ! grep -Eiq 'path .* does not exist' "$errf"; then
        printf 'missing git object (fail closed): %s\n' "$(cat "$errf")" >&2
        rm -f "$errf"
        exit 1
      fi
    fi
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

expect_blob() {
  local repo=$1 rev=$2 file=$3 want=$4
  local got
  got=$(g "$repo" rev-parse "$rev:$file")
  if [[ $got != "$want" ]]; then
    printf 'blob mismatch %s:%s\n expected %s\n got %s\n' "$rev" "$file" "$want" "$got" >&2
    exit 1
  fi
}

assert_missing_path() {
  local repo=$1 rev=$2 file=$3
  if g "$repo" rev-parse "$rev:$file"; then
    printf 'unexpected path present: %s:%s\n' "$rev" "$file" >&2
    exit 1
  fi
}

require_dir "$OWNED"
require_dir "$O/.git"
require_dir "$C/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/compact_facts.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/pages/repo-advisory/GHSA-37MF-VQ43-5QP9.json"
require_file "$OWNED/work/pages/repo-advisory/GHSA-3FP5-V549-9V66.json"
require_file "$OWNED/work/pages/repo-advisory/GHSA-QJPC-QF9M-XWMR.json"
require_file "$OWNED/work/pages/repo-advisory/GHSA-J4CX-JVQ7-79VM.json"
require_file "$OWNED/work/pages/repo-advisory/GHSA-JX5R-P82P-2P8M.json"
require_file "$OWNED/notes/releases/github_releases.json"
require_file "$OWNED/notes/releases/npm_openclaw.json"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$OWNED/selected.jsonl" \
  38fb2bfa436c4acb7fc6022acc0e3768885beeef7371ac7a62b164663e9c06e4
expect_hash "$OWNED/cases.jsonl" \
  c50397515c0fbdf65fa92e473ab4bc20928ea5cf26b29fb38eac04093cbb8f66
expect_hash "$OWNED/report.md" \
  51847aa18d2b3fd15ac096c229570d96f8073f1247d2e388e4ef68ccca1a5302
expect_hash "$OWNED/compact_facts.json" \
  a986aafd941154b5f45fc18ef1e271e89f0b71999b2ee29241a64648856e1d95
expect_hash "$OWNED/work/uniqueness.json" \
  a2cc3b55eb80099d93c06591d3495af2dd82036d7eb3615d02e64e32ebc5a475

python3 - "$OWNED" <<'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
order = [
    "GHSA-37MF-VQ43-5QP9",
    "GHSA-3FP5-V549-9V66",
    "GHSA-QJPC-QF9M-XWMR",
    "GHSA-J4CX-JVQ7-79VM",
    "GHSA-JX5R-P82P-2P8M",
]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l]
if len(sel) != 5 or len(cases) != 5:
    raise SystemExit("conservation fail: selected/cases not 5")
if [o["case_id"] for o in sel] != order:
    raise SystemExit("selected order mismatch")
if [c["case_id"] for c in cases] != order:
    raise SystemExit("cases order mismatch")
if [o["ordinal"] for o in sel] != [187, 189, 194, 196, 201]:
    raise SystemExit("ordinal order mismatch")
if [o["row_key"] for o in sel] != [
    "posthold:F06",
    "posthold:F08",
    "posthold:F13",
    "posthold:F15",
    "posthold:G03",
]:
    raise SystemExit("row_key order mismatch")
for c in cases:
    if c["verdict"] != "NARROW":
        raise SystemExit("unexpected verdict " + c["case_id"])
    if c.get("countable_proposal") is True:
        raise SystemExit("countable proposal leaked")
    if c.get("packet_delta") != 0:
        raise SystemExit("case packet_delta")
res = json.loads((owned / "result.json").read_text())
if res["terminal_status"] != "NARROW":
    raise SystemExit("terminal_status")
if res["packet_delta"] != 0:
    raise SystemExit("packet_delta")
if res["canonical_strict_count_untouched"] != 84:
    raise SystemExit("canonical84")
if res["counts"]["PASS"] != 0 or res["counts"]["NARROW"] != 5:
    raise SystemExit("counts")
if res["conservation"]["equation"] != "5=5+0":
    raise SystemExit("equation")
uni = json.loads((owned / "work/uniqueness.json").read_text())
if uni["assigned_in_counted"]:
    raise SystemExit("assigned leaked into counted")
if uni["canonical_strict_count"] != 84:
    raise SystemExit("uni count")
if len(uni["excluded_unseen_twogate8"]) != 8:
    raise SystemExit("twogate8 exclusion count")
cf = json.loads((owned / "compact_facts.json").read_text())
if cf["churchcrm_37mf"]["member_ancestor_of_carrier"] is not False:
    raise SystemExit("37mf member must not be carrier ancestor")
if cf["churchcrm_jx5r"]["member_ancestor_of_carrier"] is not False:
    raise SystemExit("jx5r member must not be carrier ancestor")
if cf["openclaw_qjpc"]["connect_policy_parent_equals_cand"] is not True:
    raise SystemExit("qjpc connect-policy must be unchanged")
if cf["openclaw_j4cx"]["export_parent_equals_cand"] is not True:
    raise SystemExit("j4cx export must be unchanged")
if cf["openclaw_3fp5"]["cand_has_unwrapFlock"] is not False:
    raise SystemExit("3fp5 candidate must lack unwrapFlock")
if cf["openclaw_3fp5"]["fix_has_unwrapFlock"] is not True:
    raise SystemExit("3fp5 fix must add unwrapFlock")
for ghsa, summary in (
    ("GHSA-37MF-VQ43-5QP9", "Authenticated Remote Code Execution"),
    ("GHSA-3FP5-V549-9V66", "flock wrapper could bypass durable exec approval binding"),
    ("GHSA-QJPC-QF9M-XWMR", "Trusted-proxy Control UI WebSocket accepted client-declared scopes before pairing"),
    ("GHSA-J4CX-JVQ7-79VM", "Trajectory export could skip broad credential redaction"),
    ("GHSA-JX5R-P82P-2P8M", "CSRF via legacy GET-delete pages"),
):
    o = json.loads((owned / "work/pages/repo-advisory" / f"{ghsa}.json").read_text())
    if o.get("state") != "published":
        raise SystemExit("repo advisory not published " + ghsa)
    if summary not in (o.get("summary") or ""):
        raise SystemExit("summary mismatch " + ghsa)
print("CONSERVATION_OK 5=5+0")
PY

# ChurchCRM 37MF: member not in tags; blobs three-way unequal
assert_not_ancestor "$C" 095bf81b318c892258a9874e63ebb017b971443d 7.3.3
assert_not_ancestor "$C" 095bf81b318c892258a9874e63ebb017b971443d de417ffa845a8f6c68905740b34478537543bc05
assert_ancestor "$C" de417ffa845a8f6c68905740b34478537543bc05 7.3.0
assert_ancestor "$C" de417ffa845a8f6c68905740b34478537543bc05 7.3.3
assert_ancestor "$C" 1b4e2c708f9f4d8afd458febc6958cec21da2922 7.4.0
assert_not_ancestor "$C" 1b4e2c708f9f4d8afd458febc6958cec21da2922 7.3.3
expect_blob "$C" 095bf81b318c892258a9874e63ebb017b971443d src/ChurchCRM/Plugin/PluginInstaller.php b79ef3586b2664133248fd72840b9d3d89aa9e9d
expect_blob "$C" de417ffa845a8f6c68905740b34478537543bc05 src/ChurchCRM/Plugin/PluginInstaller.php bd4e0ec0c2ef32820b11799e83ea1114a891d616
expect_blob "$C" 7.3.0 src/ChurchCRM/Plugin/PluginInstaller.php bd4e0ec0c2ef32820b11799e83ea1114a891d616
expect_blob "$C" 7.3.3 src/ChurchCRM/Plugin/PluginInstaller.php 332bdd42f008d2c41e70022705b194928c0f2313
expect_blob "$C" 7.4.0 src/ChurchCRM/Plugin/PluginInstaller.php c6157e53d9d0571d70b7f41889ef7ead7063b751
expect_blob "$C" 1b4e2c708f9f4d8afd458febc6958cec21da2922 src/ChurchCRM/Plugin/PluginInstaller.php c6157e53d9d0571d70b7f41889ef7ead7063b751

# ChurchCRM JX5R
assert_not_ancestor "$C" 6ef78813e04987da217bbb081706715c1ecb19e9 7.2.2
assert_not_ancestor "$C" 6ef78813e04987da217bbb081706715c1ecb19e9 ede1bfb08633e6d1157744e99d176e258fc58aba
assert_ancestor "$C" ede1bfb08633e6d1157744e99d176e258fc58aba 7.2.2
assert_ancestor "$C" f1c11f9fefa3d0fe37373f10a0c659087684c36d 7.4.3
assert_not_ancestor "$C" f1c11f9fefa3d0fe37373f10a0c659087684c36d 7.2.2
expect_blob "$C" 6ef78813e04987da217bbb081706715c1ecb19e9 src/FundRaiserDelete.php 80acd007ed48460a20595a93b61355e4fbc1715e
expect_blob "$C" ede1bfb08633e6d1157744e99d176e258fc58aba src/FundRaiserDelete.php 80acd007ed48460a20595a93b61355e4fbc1715e
expect_blob "$C" 7.2.2 src/FundRaiserDelete.php 2963cd58d9da5114b30460829a97facb0606e69d
set +e
/usr/bin/timeout 30 "${git_cmd[@]}" -C "$C" rev-parse --verify '7.3.2^{commit}' >/dev/null 2>"$OWNED/work/.giterr"
tag32_rc=$?
set -e
if [[ $tag32_rc -eq 0 ]]; then
  printf 'unexpected tag 7.3.2\n' >&2
  rm -f "$OWNED/work/.giterr"
  exit 1
fi
rm -f "$OWNED/work/.giterr"

# OpenClaw 3FP5
assert_ancestor "$O" 8e41c118fa80c186ac40676e87bfecf988101ecb v2026.6.6
assert_ancestor "$O" 8e41c118fa80c186ac40676e87bfecf988101ecb v2026.6.8
assert_not_ancestor "$O" 55d1324c7d0d2146b16aaef9572b7177a710f881 v2026.6.6
assert_ancestor "$O" 55d1324c7d0d2146b16aaef9572b7177a710f881 v2026.6.9
expect_blob "$O" 8e41c118fa80c186ac40676e87bfecf988101ecb src/infra/dispatch-wrapper-resolution.ts fc93552fc5a02174098dfe5f2493e2220fafe38b
expect_blob "$O" v2026.6.9 src/infra/dispatch-wrapper-resolution.ts 1a7981d2dea3c370c8b6ea2e4f35b5c657f8300a
expect_blob "$O" 55d1324c7d0d2146b16aaef9572b7177a710f881 src/infra/dispatch-wrapper-resolution.ts 1a7981d2dea3c370c8b6ea2e4f35b5c657f8300a

# OpenClaw QJPC: connect-policy unchanged by candidate
expect_blob "$O" 0e702f106313c1c63a32a6e7b3dbb5e96e620656^ src/gateway/server/ws-connection/connect-policy.ts 27284609174b8c9ef60580b1bbdbaa5cbf01feaa
expect_blob "$O" 0e702f106313c1c63a32a6e7b3dbb5e96e620656 src/gateway/server/ws-connection/connect-policy.ts 27284609174b8c9ef60580b1bbdbaa5cbf01feaa
assert_ancestor "$O" 0e702f106313c1c63a32a6e7b3dbb5e96e620656 v2026.5.12
assert_not_ancestor "$O" 96fba91b3a51d6e536f03a4077ef8a11a132578d v2026.5.12
assert_ancestor "$O" 96fba91b3a51d6e536f03a4077ef8a11a132578d v2026.5.18
expect_blob "$O" 96fba91b3a51d6e536f03a4077ef8a11a132578d src/gateway/server/ws-connection/connect-policy.ts 6a7c03c04ca52feb4e954d23cd3628f3a382307c

# OpenClaw J4CX: export.ts unchanged by candidate
expect_blob "$O" 17ceca86d698c104df48149ba85f8dfab3ea622c^ src/trajectory/export.ts fbbd7e1b6cc1a244325b687498cbabb9e1c839c1
expect_blob "$O" 17ceca86d698c104df48149ba85f8dfab3ea622c src/trajectory/export.ts fbbd7e1b6cc1a244325b687498cbabb9e1c839c1
assert_ancestor "$O" 17ceca86d698c104df48149ba85f8dfab3ea622c v2026.5.28
assert_not_ancestor "$O" 19fb9f12993d6974e86cc10f25c5b7c9af230171 v2026.5.28
assert_ancestor "$O" 19fb9f12993d6974e86cc10f25c5b7c9af230171 v2026.6.1
expect_blob "$O" v2026.6.1 src/trajectory/export.ts 30a9d5c816f51c816761685c0a35f75dc946e68e

python3 - "$OWNED" <<'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
rel = json.loads((owned / "notes/releases/github_releases.json").read_text())
for name, tag in (
    ("churchcrm_7.2.2.json", "7.2.2"),
    ("churchcrm_7.3.0.json", "7.3.0"),
    ("churchcrm_7.3.3.json", "7.3.3"),
    ("churchcrm_7.4.0.json", "7.4.0"),
    ("churchcrm_7.4.3.json", "7.4.3"),
    ("openclaw_v2026.6.1.json", "v2026.6.1"),
    ("openclaw_v2026.6.6.json", "v2026.6.6"),
    ("openclaw_v2026.6.9.json", "v2026.6.9"),
):
    o = rel[name]
    if o["tag_name"] != tag or o["draft"] or o["prerelease"]:
        raise SystemExit("release " + name)
if rel["churchcrm_7.3.2.json"].get("git_tag_exists") is not False:
    raise SystemExit("7.3.2 must be absent")
if rel["openclaw_v2026.5.12.json"].get("independent_fetch_status") != 403:
    raise SystemExit("v2026.5.12 fetch status")
npm = json.loads((owned / "notes/releases/npm_openclaw.json").read_text())
if npm["2026.6.6"]["gitHead"] is not None:
    raise SystemExit("npm 2026.6.6 gitHead unexpectedly set")
if npm["2026.6.9"]["shasum"] != "e2af4589183eea25d5720a5029d5c315d7b0fc4d":
    raise SystemExit("npm 2026.6.9 shasum")
print("RELEASES_OK")
PY

python3 - "$OWNED" <<'PY'
from pathlib import Path
import sys
owned = Path(sys.argv[1])
for p in owned.rglob('*'):
    if p.is_file() and any(x in p.name.lower() for x in ('credential', '.env', 'secret')):
        raise SystemExit('hygiene name ' + str(p))
check = [
    owned / 'selected.jsonl',
    owned / 'cases.jsonl',
    owned / 'report.md',
    owned / 'result.json',
    owned / 'replay.zsh',
    owned / 'compact_facts.json',
    owned / 'work/uniqueness.json',
]
needles = ('gh' + 'p_', 'github' + '_pat_', 'AKI' + 'A')
for p in check:
    text = p.read_text()
    if any('\u4e00' <= ch <= '\u9fff' for ch in text):
        raise SystemExit('han ' + p.name)
    for ln in text.splitlines():
        if ln.endswith(' ') or ln.endswith('\t'):
            raise SystemExit('trailing whitespace ' + p.name)
    if p.name == 'replay.zsh':
        continue
    for needle in needles:
        if needle in text:
            raise SystemExit('secret string ' + p.name)
print("HYGIENE_OK")
PY

printf 'REPLAY_OK reviewed=5 PASS_proposal=0 NARROW=5 REJECT=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 canonical=84\n'
