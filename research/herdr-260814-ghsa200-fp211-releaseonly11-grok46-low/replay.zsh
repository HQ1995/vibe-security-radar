#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-fp211-releaseonly11-grok46-low.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Canonical baseline is 82. Packet delta is 0. Terminal NARROW. Zero PASS proposals.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export TMPDIR=/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-releaseonly11-grok46-low/work

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fp211-releaseonly11-grok46-low
F=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/fission
K=/home/hanqing/.cache/ghsa200-worker-clones/delta-even-batch2/microsoft__kiota
W=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/wacrm
PR=/home/hanqing/.cache/ghsa200-worker-clones/baseline-increm-even/clones/prospero-flow-crm
V=/home/hanqing/.cache/cve-analyzer/repos/vitest-dev_vitest
P=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/praisonai
GP=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/gitpython
C=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/churchcrm
O=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw

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
require_dir "$F/.git"
require_dir "$K/.git"
require_dir "$W/.git"
require_dir "$PR/.git"
require_dir "$V/.git"
require_dir "$P/.git"
require_dir "$GP/.git"
require_dir "$C/.git"
require_dir "$O/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/compact_facts.json"
require_file "$OWNED/work/uniqueness.json"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/ledger.jsonl" \
  58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" \
  d436f47f82297eb0d9363ad0f3876adc639b1f61e9b23c7f9d613545741e106e
expect_hash "$OWNED/selected.jsonl" \
  6ce3f21ccf8ba06e5052c39db24975af0181110d684f7a318aa4185ee3d89076
expect_hash "$OWNED/cases.jsonl" \
  a1b9912498203dc1cab78e46946657d3dbd89c83605e3532936400aee8f11344
expect_hash "$OWNED/report.md" \
  e98fc650be5f54684abf85051b69d724afbb12bde4f16583576edfac1f5eaac6
expect_hash "$OWNED/compact_facts.json" \
  231e8ad8e1c35a874684d3a576e4cf59a7bb9ce432e36f9e1487408b0a9e5167
expect_hash "$OWNED/work/uniqueness.json" \
  58fe560ddb534d196ce2cd3deb70862fef3a7dd1f30f268f914cf9be3caa109d

python3 - "$OWNED" <<'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
order = [
    "GHSA-M63V-2G9W-2W6V",
    "GHSA-P5RM-JG5C-8C77",
    "GHSA-X2W7-XR2G-QHJR",
    "GHSA-X8QQ-M4QC-RPJ5",
    "GHSA-G8MR-85JM-7XHM",
    "GHSA-F38V-77QJ-H4JQ",
    "GHSA-V396-V7Q4-X2QJ",
    "GHSA-F2FQ-4RMP-9X8C",
    "GHSA-2X93-H3HG-2XFP",
    "GHSA-9C3V-684M-579C",
    "GHSA-WP73-F3GG-W4VR",
]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l]
if len(sel) != 11 or len(cases) != 11:
    raise SystemExit("conservation fail: selected/cases not 11")
sel_ids = []
for o in sel:
    ids = o.get("public_ids_keep") or []
    gh = [x for x in ids if str(x).startswith("GHSA-")][0]
    sel_ids.append(gh)
if sel_ids != order:
    raise SystemExit("selected order mismatch")
if [c["case_id"] for c in cases] != order:
    raise SystemExit("cases order mismatch")
if [o["ordinal"] for o in sel] != [132, 136, 152, 155, 157, 169, 170, 186, 192, 195, 197]:
    raise SystemExit("ordinal order mismatch")
for c in cases:
    if c["verdict"] != "NARROW":
        raise SystemExit("unexpected verdict " + c["case_id"])
    if c["release_gate"] != "NARROW":
        raise SystemExit("release_gate not NARROW " + c["case_id"])
    if c.get("countable_proposal") is True:
        raise SystemExit("countable proposal leaked")
res = json.loads((owned / "result.json").read_text())
if res["terminal_status"] != "NARROW":
    raise SystemExit("terminal_status")
if res["packet_delta"] != 0:
    raise SystemExit("packet_delta")
if res["canonical_strict_count_untouched"] != 82:
    raise SystemExit("canonical82")
if res["counts"]["PASS"] != 0 or res["counts"]["NARROW"] != 11:
    raise SystemExit("counts")
if res["conservation"]["equation"] != "11=11+0":
    raise SystemExit("equation")
uni = json.loads((owned / "work/uniqueness.json").read_text())
if uni["assigned_in_counted"]:
    raise SystemExit("assigned leaked into counted")
if not uni["excluded_in_counted"]["GHSA-XW8C-RRVX-F7XQ"]:
    raise SystemExit("XW8C should remain counted")
if uni["pending_425G_HC8V_in_counted"]:
    raise SystemExit("pending counted")
print("CONSERVATION_OK 11=11+0")
PY

# M63V: member not in tags; v1.24.0 equals closer blob
assert_not_ancestor "$F" 2db76f65dbfe4f657b4a4efb506ed63b24623e92 v1.24.0
assert_ancestor "$F" e484df8460bb4e8026e24210120602aa7f181f64 v1.24.0
assert_ancestor "$F" 695d3e97e3a20463ab7c8c081843e69e65e952e5 v1.24.0
expect_blob "$F" 2db76f65dbfe4f657b4a4efb506ed63b24623e92 pkg/apis/core/v1/podspec_safety.go af473d2601a9299a035166c4d4bf67927abc50df
expect_blob "$F" e484df8460bb4e8026e24210120602aa7f181f64 pkg/apis/core/v1/podspec_safety.go 330fccee042945fac9ccfcdb3d62f52036e63b5e
expect_blob "$F" v1.24.0 pkg/apis/core/v1/podspec_safety.go 1d7219e7f592cc6ea631866328820475617141bd
python3 - <<'PY'
import json
from pathlib import Path
p=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-releaseonly11-grok46-low/work/pages/goproxy/fission_v1.24.0.info.json")
o=json.loads(p.read_text())
if o["Origin"]["Hash"] != "ce617120c41b9e4a51d577f81b441238264e88fd":
    raise SystemExit("goproxy origin hash")
print("GOPROXY_V124_OK")
PY

# P5RM
assert_not_ancestor "$K" f51f4971ea3459cd410b363b34e156a116b530f4 v1.33.0
assert_not_ancestor "$K" f51f4971ea3459cd410b363b34e156a116b530f4 v1.34.0
assert_ancestor "$K" de3d18d9fe31ced4ac749728d3a2f94811f59268 v1.34.0
assert_ancestor "$K" 430008e9d700b3fe80f206c672415cfbd8e830e7 v1.34.0
expect_blob "$K" f51f4971ea3459cd410b363b34e156a116b530f4 src/Kiota.Builder/OpenApiExtensions/OpenApiAiCapabilitiesExtension.cs 782a03f5a90908d179e6b2ddc971762ce2818cd3
expect_blob "$K" v1.33.0 src/Kiota.Builder/OpenApiExtensions/OpenApiAiCapabilitiesExtension.cs 1391bf0c317ededff61d42336eb20cc168c584f5
expect_blob "$K" v1.34.0 src/Kiota.Builder/OpenApiExtensions/OpenApiAiCapabilitiesExtension.cs 1b62b65383747873569474fbcf4d2895976ad405

# X2W7 no tags
tagcount=$(g "$W" tag | wc -l | awk '{print $1}')
if [[ $tagcount != 0 ]]; then
  printf 'wacrm unexpected tags %s\n' "$tagcount" >&2
  exit 1
fi

# X8QQ
assert_not_ancestor "$PR" 56ea64c80fd36840fe3c84d0c6a6a38296a8f111 v4.6.0
assert_ancestor "$PR" 56ea64c80fd36840fe3c84d0c6a6a38296a8f111 v5.5.3
assert_ancestor "$PR" 9a859c4de3d49674916773d346c60d89ad7febe0 v5.5.3

# G8MR
assert_not_ancestor "$V" af88b1f5d82844a4761ea9a977156c98e2b14ca8 v3.2.4
assert_ancestor "$V" af88b1f5d82844a4761ea9a977156c98e2b14ca8 v3.2.5
assert_ancestor "$V" 385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7 v3.2.5
expect_blob "$V" v3.2.4 packages/browser/src/node/rpc.ts 7619c5f0fc4b66ea0992e61e357331c6280e4a29
expect_blob "$V" v3.2.5 packages/browser/src/node/rpc.ts 72818584f0669b58db74b6e093e04173c083293e
expect_blob "$V" af88b1f5d82844a4761ea9a977156c98e2b14ca8 packages/browser/src/node/rpc.ts 358ac355f89983297c18932c68e5aea7d78020ea

# V396
assert_ancestor "$GP" c9a26789d88b18f8b4620f37307df2976292d2a0 3.1.50
assert_not_ancestor "$GP" 56806080c1348749b07daa4a2024ce47b3cad285 3.1.50
assert_ancestor "$GP" 56806080c1348749b07daa4a2024ce47b3cad285 3.1.51

# F2FQ
assert_not_ancestor "$C" cbea916e77e2d8cbe34f04efdd00792e3af27e2c 7.5.1
assert_ancestor "$C" 1bfc187ac41238a2488d58f06361d7377d3cdf11 7.5.1
assert_ancestor "$C" 07be35d7fdaae872f2f6ff404779368f201fe8b5 7.6.0
expect_blob "$C" cbea916e77e2d8cbe34f04efdd00792e3af27e2c src/api/routes/public/public-user.php 74e9d89029ffd307d5ddd45054da4e2a1957a43f
expect_blob "$C" 7.5.1 src/api/routes/public/public-user.php 25e8219b790c0d309a88f9bd1285bb6dc43e99b6
expect_blob "$C" 7.6.0 src/api/routes/public/public-user.php c31ac1761c6d7762bd27c5dd8f4efed7d3437fc0

# openclaw windows exist but named mechanism fails
assert_ancestor "$O" b75ad800a59009fc47eaa3471410f69046150e59 v2026.5.22
assert_not_ancestor "$O" 06047005ef7dedda5ea655f52117e8aaa1cca373 v2026.5.22
assert_ancestor "$O" 06047005ef7dedda5ea655f52117e8aaa1cca373 v2026.5.26
assert_ancestor "$O" 47eb2d48d43452afc4b0160e40a2630e4a38a0ff v2026.6.1
assert_not_ancestor "$O" 3c6259ebb70c76523a7b3fb7cfdac2e40a7f7449 v2026.6.1
assert_ancestor "$O" 6c918ca85fc6256a309ca0a737d7729059b34e1e v2026.5.18
assert_not_ancestor "$O" 797bcd5bdb28cd8bab4f5385f4515467e42bfcfd v2026.5.18

# registry caches exist
require_file "$OWNED/work/pages/pypi/GitPython.json"
require_file "$OWNED/work/pages/pypi/praisonai-platform.json"
require_file "$OWNED/work/pages/npm/_vitest_browser.json"
require_file "$OWNED/work/pages/nuget/microsoft.openapi.kiota.index.json"

python3 - "$OWNED" <<'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
gp = json.loads((owned / "work/pages/pypi/GitPython.json").read_text())
assert "3.1.50" in gp["releases"] and "3.1.51" in gp["releases"]
pp = json.loads((owned / "work/pages/pypi/praisonai-platform.json").read_text())
assert "0.1.4" in pp["releases"] and "0.1.6" in pp["releases"] and "0.1.5" not in pp["releases"]
npm = json.loads((owned / "work/pages/npm/_vitest_browser.json").read_text())
assert "3.2.4" in npm["versions"] and "3.2.5" in npm["versions"]
nu = json.loads((owned / "work/pages/nuget/microsoft.openapi.kiota.index.json").read_text())
assert "1.33.0" in nu["versions"] and "1.34.0" in nu["versions"]
print("REGISTRY_OK")
PY

# hygiene: no credential files in owned
if find "$OWNED" -iname '*credential*' -o -iname '.env' -o -iname '*secret*' | grep -q .; then
  printf 'hygiene fail\n' >&2
  exit 1
fi

printf 'REPLAY_OK reviewed=11 PASS_proposal=0 NARROW=11 REJECT=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 canonical=82\n'
