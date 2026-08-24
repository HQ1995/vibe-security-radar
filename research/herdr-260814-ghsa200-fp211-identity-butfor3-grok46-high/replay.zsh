#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-fp211-identity-butfor3-grok46-high.
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
export TMPDIR=/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-identity-butfor3-grok46-high/work

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fp211-identity-butfor3-grok46-high
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

expect_blob() {
  local repo=$1 rev=$2 file=$3 want=$4
  local got
  got=$(g "$repo" rev-parse "$rev:$file")
  if [[ $got != "$want" ]]; then
    printf 'blob mismatch %s:%s\n expected %s\n got %s\n' "$rev" "$file" "$want" "$got" >&2
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
require_file "$OWNED/work/pages/raw/parent_gv.js"
require_file "$OWNED/work/pages/raw/member_gv.js"
require_file "$OWNED/work/pages/raw/parent_gr.js"
require_file "$OWNED/work/pages/raw/member_gr.js"
require_file "$OWNED/work/pages/raw/t751_gv.js"
require_file "$OWNED/work/pages/raw/t760_gv.js"
require_file "$OWNED/work/pages/repo-advisory/GHSA-2Q7J-2VHX-56G8.json"
require_file "$OWNED/work/pages/repo-advisory/GHSA-MFMP-Q643-VJ39.json"
require_file "$OWNED/work/pages/repo-advisory/GHSA-M649-24Q9-Q6R4.json"
require_file "$OWNED/work/pages/ghsa/GHSA-2Q7J-2VHX-56G8.json"
require_file "$OWNED/notes/releases/github_releases.json"
require_file "$OWNED/work/pages/npm/openclaw_feishu_summary.json"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$OWNED/selected.jsonl" \
  5ff6bc1f5752c4592c3d1c2c408eec39090e44bdbb71919c6d9e37388d5c8363
expect_hash "$OWNED/cases.jsonl" \
  67954c11a8c89266695b6875db184a76c0f8cbc3185f65641522cd717d03d429
expect_hash "$OWNED/report.md" \
  6e853cbb3bd736a91c07a1696a61d5dece53e4f8c0d691770df611d84f6170dc
expect_hash "$OWNED/compact_facts.json" \
  1b58ab2c1b24b07b7b5480a4c5ed39f50b7212cc08123380f9f700cacef84fd4
expect_hash "$OWNED/work/uniqueness.json" \
  6c6abbf71c38c8ceb452603e91dc5a562dcc72fdba92749237e92b3d2e88acc7

python3 - "$OWNED" <<'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
order = [
    "GHSA-2Q7J-2VHX-56G8",
    "GHSA-MFMP-Q643-VJ39",
    "GHSA-M649-24Q9-Q6R4",
]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l]
if len(sel) != 3 or len(cases) != 3:
    raise SystemExit("conservation fail: selected/cases not 3")
if [o["case_id"] for o in sel] != order:
    raise SystemExit("selected order mismatch")
if [c["case_id"] for c in cases] != order:
    raise SystemExit("cases order mismatch")
if [o["ordinal"] for o in sel] != [125, 183, 184]:
    raise SystemExit("ordinal order mismatch")
if [o["row_key"] for o in sel] != [
    "post:openclaw-feishu-tool-gate@canonical",
    "posthold:F02",
    "posthold:F03",
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
if res["counts"]["PASS"] != 0 or res["counts"]["NARROW"] != 3:
    raise SystemExit("counts")
if res["conservation"]["equation"] != "3=3+0":
    raise SystemExit("equation")
uni = json.loads((owned / "work/uniqueness.json").read_text())
if uni["assigned_in_counted"]:
    raise SystemExit("assigned leaked into counted")
if uni["canonical_strict_count"] != 84:
    raise SystemExit("uni count")
cf = json.loads((owned / "compact_facts.json").read_text())
if cf["openclaw"]["tool_account_ts_at_candidate"] is not False:
    raise SystemExit("tool-account present at candidate")
if cf["churchcrm"]["member_ancestor_of_carrier"] is not False:
    raise SystemExit("member must not be carrier ancestor")
# identity objects
for ghsa, summary in (
    ("GHSA-2Q7J-2VHX-56G8", "Feishu tools could ignore per-account disablement"),
    ("GHSA-MFMP-Q643-VJ39", "Incomplete client-side fix"),
    ("GHSA-M649-24Q9-Q6R4", "Stored XSS in the group member table"),
):
    o = json.loads((owned / "work/pages/repo-advisory" / f"{ghsa}.json").read_text())
    if o.get("state") != "published":
        raise SystemExit("repo advisory not published " + ghsa)
    if summary not in (o.get("summary") or ""):
        raise SystemExit("summary mismatch " + ghsa)
    g = json.loads((owned / "work/pages/ghsa" / f"{ghsa}.json").read_text())
    if g.get("status") != "404" and g.get("message") != "Not Found":
        raise SystemExit("expected global 404 " + ghsa)
# ChurchCRM parent vs member tokens from frozen raw files
parent = (owned / "work/pages/raw/parent_gv.js").read_text()
member = (owned / "work/pages/raw/member_gv.js").read_text()
parent_gr = (owned / "work/pages/raw/parent_gr.js").read_text()
member_gr = (owned / "work/pages/raw/member_gr.js").read_text()
if "buildRolePills" in parent:
    raise SystemExit("parent already has buildRolePills")
if "buildRolePills" not in member:
    raise SystemExit("member missing buildRolePills")
if parent.count("tel:") != 0 or member.count("tel:") < 1:
    raise SystemExit("tel counts")
if parent.count("mailto:") != 0 or member.count("mailto:") < 1:
    raise SystemExit("mailto counts")
if parent.count("data-name") < 1 or member.count("data-name") < 1:
    raise SystemExit("data-name must preexist")
if parent_gr != member_gr:
    raise SystemExit("GroupRoles.js must be unchanged by the member")
if "OptionName" not in parent_gr:
    raise SystemExit("parent GroupRoles missing OptionName")
t751 = (owned / "work/pages/raw/t751_gv.js").read_text()
t760 = (owned / "work/pages/raw/t760_gv.js").read_text()
if "escapeAttribute" in t751:
    raise SystemExit("7.5.1 should lack escapeAttribute")
if "escapeAttribute" not in t760:
    raise SystemExit("7.6.0 should use escapeAttribute")
print("CONSERVATION_OK 3=3+0")
PY

# OpenClaw 2Q7J
assert_ancestor "$O" 5f6e1c19bd18ea45addd3afedf2f88cc3064f3f6 v2026.2.6
assert_ancestor "$O" 5f6e1c19bd18ea45addd3afedf2f88cc3064f3f6 v2026.6.6
assert_not_ancestor "$O" d4f11d3005a56abc709ebc8e715972593ebed96e v2026.6.6
assert_ancestor "$O" d4f11d3005a56abc709ebc8e715972593ebed96e v2026.6.9
expect_blob "$O" 7e005acd3c02f0cd26445c2c443f0b03c4dafbe5 extensions/feishu/src/perm.ts 22184dbe9f33703e826dc2ce6424a009463999e5
expect_blob "$O" 5f6e1c19bd18ea45addd3afedf2f88cc3064f3f6 extensions/feishu/src/perm.ts f11fb9882ecd980640d19351fa49306cf56d4780
expect_blob "$O" v2026.2.6 extensions/feishu/src/perm.ts f11fb9882ecd980640d19351fa49306cf56d4780
expect_blob "$O" d4f11d3005a56abc709ebc8e715972593ebed96e extensions/feishu/src/perm.ts 50b27f833c1714f44f05e997824eb3f34ae373a2
expect_blob "$O" v2026.6.9 extensions/feishu/src/perm.ts 50b27f833c1714f44f05e997824eb3f34ae373a2

# ChurchCRM shared origin: member not in tags; carrier is; blobs three-way unequal
assert_not_ancestor "$C" 0ea20d01050cd25b30bca1418bb821fbd3bcb7ab 7.4.2
assert_not_ancestor "$C" 0ea20d01050cd25b30bca1418bb821fbd3bcb7ab 80a3e620a4aa046c2644937a5a2fa799a2e750d6
assert_ancestor "$C" 80a3e620a4aa046c2644937a5a2fa799a2e750d6 7.4.2
assert_ancestor "$C" 330d0d6a2e6995f017d5943bd3b4806d713b181c 7.4.3
assert_not_ancestor "$C" 330d0d6a2e6995f017d5943bd3b4806d713b181c 7.4.2
assert_not_ancestor "$C" 3b8b474519272e0d6bb2a7f07c4f1202d2a02bf4 7.4.3
assert_not_ancestor "$C" 367dd18e4b017a5bc893e1fab1ce55cc34647f08 7.4.3
assert_not_ancestor "$C" 0ea20d01050cd25b30bca1418bb821fbd3bcb7ab 7.5.1
assert_not_ancestor "$C" 5631bb084da530732dbef5aa2f3f71c67c739298 7.6.0
assert_ancestor "$C" ae2b73550452056cc45a65a4165340ae17c2c3e5 7.6.0
expect_blob "$C" 0ea20d01050cd25b30bca1418bb821fbd3bcb7ab src/skin/js/GroupView.js 6d1eae1066039f7e0b32b870cf4c82ddc3b3d815
expect_blob "$C" 80a3e620a4aa046c2644937a5a2fa799a2e750d6 src/skin/js/GroupView.js 23fb4f55f25d6e1e881163891152fe2a3cb6ccaa
expect_blob "$C" 7.4.2 src/skin/js/GroupView.js 1cb473c551a7625ef1c35f9e3d8d449853b54c1a
expect_blob "$C" 7.4.3 src/skin/js/GroupView.js 116f1bffe566960053ee9aff479dfa3c02e8d9a7
expect_blob "$C" 330d0d6a2e6995f017d5943bd3b4806d713b181c src/skin/js/GroupView.js 116f1bffe566960053ee9aff479dfa3c02e8d9a7
expect_blob "$C" 0ea20d01050cd25b30bca1418bb821fbd3bcb7ab src/skin/js/GroupRoles.js 62dfbce14ca2bd0f7ff7a0e5f69152ef289ea2b0
expect_blob "$C" 442cf6ebfeb6e95a992c0084353ba7741d873e71 src/skin/js/GroupRoles.js 62dfbce14ca2bd0f7ff7a0e5f69152ef289ea2b0
expect_blob "$C" 7.6.0 src/skin/js/GroupView.js 041a9794dc64be0b0c3931edba027ca7a1030a47
expect_blob "$C" ae2b73550452056cc45a65a4165340ae17c2c3e5 src/skin/js/GroupView.js 041a9794dc64be0b0c3931edba027ca7a1030a47
expect_blob "$C" 5631bb084da530732dbef5aa2f3f71c67c739298 src/skin/js/GroupView.js 9a48ea502fa4ae8283bf9dcea5c81243eca0405c

# releases not drafts
python3 - "$OWNED" <<'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
rel = json.loads((owned / "notes/releases/github_releases.json").read_text())
for name, tag in (
    ("openclaw_v2026.6.6.json", "v2026.6.6"),
    ("openclaw_v2026.6.9.json", "v2026.6.9"),
    ("churchcrm_7.4.2.json", "7.4.2"),
    ("churchcrm_7.4.3.json", "7.4.3"),
    ("churchcrm_7.5.1.json", "7.5.1"),
    ("churchcrm_7.6.0.json", "7.6.0"),
):
    o = rel[name]
    if o["tag_name"] != tag or o["draft"] or o["prerelease"]:
        raise SystemExit("release " + name)
npm = json.loads((owned / "work/pages/npm/openclaw_feishu_summary.json").read_text())
if npm["2026.6.6"]["gitHead"] != "8c802aa683510c7f7503597b54c3021733245e59":
    raise SystemExit("npm 2026.6.6 gitHead")
if npm["2026.6.9"]["gitHead"] != "c645ec4555c017931de0e35ad9847dffae2741ef":
    raise SystemExit("npm 2026.6.9 gitHead")
print("RELEASES_OK")
PY

# hygiene: English packet files, no credentials, no Han, no trailing whitespace
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

printf 'REPLAY_OK reviewed=3 PASS_proposal=0 NARROW=3 REJECT=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 canonical=84\n'
