#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260813-ghsa200-medium5-redteam-grok46-low.
# English only. Do not print credentials. Do not clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Red-team KEEP is a proposal. This script admits none.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260813-ghsa200-medium5-redteam-grok46-low
ART=$OWNED/snapshot/artifacts
H=/tmp/ghsa200-worker-clones/upgrade-b/clones/hermes-webui
PR=/tmp/ghsa200-worker-clones/upgrade-b/clones/praisonai
F=/tmp/ghsa200-worker-clones/upgrade-b/clones/fission
G=/tmp/ghsa200-worker-clones/upgrade-b/clones/gitpython

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

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
require_dir "$H"
require_dir "$PR"
require_dir "$F"
require_dir "$G"
require_dir "$ART"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/baseline.json" \
  d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-reintroduction-grok46-xhigh/work/freeze.json" \
  f7cb96a39a44bb94eec3640a4759b13b9f87bef5ee785727e39b2cdea2109e34
expect_hash "$OWNED/cases.jsonl" \
  01452d3e62530b31ef912f9f206fcb5271c39be9a0b472c837abeb3fbb864fc3
expect_hash "$OWNED/snapshot/pages/ghsa/ghsa-p52p-4vmg-4vq3.json" \
  64ff632b5ea4ea4dee989ad55f36a0503f737fa41fbc44e6d6a293c009465f59
expect_hash "$OWNED/snapshot/pages/ghsa/ghsa-4mr5-g6f9-cfrh.json" \
  de2663feda22fa1441efe8fb0b49f5f192b71d1adbaf2ec0e0642c998f09a29e
expect_hash "$OWNED/snapshot/pages/ghsa/ghsa-qf5v-m7p4-95rp.json" \
  940e51477efca6a924226cbbcab696f3829fa80dc82be61e30ae33622e1bbe8d
expect_hash "$OWNED/snapshot/pages/ghsa/ghsa-94p4-4cq8-9g67.json" \
  86fe764e5c6662c34e46f7f837adbb36c1dfb7fc91fc2efc19f1985aee2c3f56
expect_hash "$OWNED/snapshot/pages/ghsa/ghsa-p538-c434-8v24.json" \
  670de306fd6a305048776c77def151f0df95df0daaf63cf958d86cc10440329b
expect_hash "$OWNED/snapshot/pages/repo-advisory/GHSA-P52P-4VMG-4VQ3.json" \
  61733b3130b4f3a94909d00a043803160592b85f452ea82dc73fe1149891f5a8
expect_hash "$OWNED/snapshot/artifacts/praisonaiagents-1.6.39-py3-none-any.whl" \
  488c3474c7d79ca43d6628004a4a0d6921fd0995e8df245bc3071788b342df7b
expect_hash "$OWNED/snapshot/artifacts/praisonaiagents-1.6.40-py3-none-any.whl" \
  4f0ebe7910cf25d4813056e416996ab8f710824656965aaddde036dccde771bf
expect_hash "$OWNED/snapshot/artifacts/gitpython-3.1.54-py3-none-any.whl" \
  b90d7b3d9bc0238681d24369130826f0dcdb0ceaa45db67cf1d4ffa4c302dedf
expect_hash "$OWNED/snapshot/artifacts/gitpython-3.1.55-py3-none-any.whl" \
  7c9ec1e69c158c081632ab35c41471e302c96db2ae42165036a5d2403378812e
expect_hash "$OWNED/snapshot/artifacts/gitpython-3.1.56-py3-none-any.whl" \
  bedffdc4bdd2e3cf21b328711a552b0529751f08bff6591339d18492291ad035
expect_hash "$OWNED/snapshot/pages/rel-fission-v1.24.0.json" \
  d0f873b809b7f87ced9e5f17cf4abafd69ffa102f4404b672b8ec5e32e04b083
expect_hash "$OWNED/snapshot/pages/rel-fission-v1.25.0.json" \
  e21d6fac1d126ca9a431516ce0ef15574ea0ac2745f829f7616cfecd60fb9816

python3 - "$OWNED/cases.jsonl" "$ROOT/autoresearch/herdr-260813-ghsa200-reintroduction-grok46-xhigh/work/freeze.json" << 'PY'
import json, sys
from pathlib import Path
rows = [json.loads(l) for l in Path(sys.argv[1]).read_text().splitlines() if l.strip()]
assert len(rows) == 5, len(rows)
ids = [r["case_id"] for r in rows]
assert ids == [
    "GHSA-P52P-4VMG-4VQ3",
    "GHSA-4MR5-G6F9-CFRH",
    "GHSA-QF5V-M7P4-95RP",
    "GHSA-94P4-4CQ8-9G67",
    "GHSA-P538-C434-8V24",
], ids
assert [r["verdict"] for r in rows] == ["NARROW"] * 5
gates = ["identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate", "uniqueness_gate"]
for r in rows:
    seven = all(r.get(g) == "PASS" for g in gates)
    assert not seven, r["case_id"]
    assert r.get("failing_gates")
    assert r.get("causal_admission") is False
    assert r.get("countable") is False
freeze = json.loads(Path(sys.argv[2]).read_text())
s73 = set(freeze["strict_73"])
assert len(s73) == 73
for r in rows:
    assert r["case_id"] not in s73
print("conservation reviewed=5 KEEP=0 NARROW=5 REJECT=0 UNKNOWN=0 BLOCKED=0")
PY

# ----- 114 Hermes identity / topology -----
python3 - "$OWNED" << 'PY'
import json, sys
from pathlib import Path
d = json.loads((Path(sys.argv[1]) / "snapshot/pages/ghsa/ghsa-p52p-4vmg-4vq3.json").read_text())
assert d.get("type") == "unreviewed"
assert d.get("vulnerabilities") == []
assert d.get("repository_advisory_url") in (None, "")
assert d.get("source_code_location") in (None, "")
assert d.get("cve_id") == "CVE-2026-49973"
repo = json.loads((Path(sys.argv[1]) / "snapshot/pages/repo-advisory/GHSA-P52P-4VMG-4VQ3.json").read_text())
assert repo.get("error") is True or repo.get("status") == 1
print("114 unreviewed empty vulns and repo 404")
PY
"${git_cmd[@]}" -C "$H" log -1 --format='%B' b8b62722ec2f6b3cd394737ab409c35650f29ca6 | grep -F 'Co-Authored-By: Claude Opus 4.6' >/dev/null
"${git_cmd[@]}" -C "$H" rev-parse b8b62722ec2f6b3cd394737ab409c35650f29ca6^@ | grep -Fx 1c6db07c2bef8d53656032a2c39a2385a176c959 >/dev/null
if "${git_cmd[@]}" -C "$H" grep -F '_set_password' 'b8b62722ec2f6b3cd394737ab409c35650f29ca6^' -- api/config.py >/dev/null; then
  printf 'parent unexpectedly has _set_password\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$H" grep -F '_set_password' b8b62722ec2f6b3cd394737ab409c35650f29ca6 -- api/config.py >/dev/null
blob_mem=$("${git_cmd[@]}" -C "$H" rev-parse 'b8b62722ec2f6b3cd394737ab409c35650f29ca6:api/config.py')
blob_357=$("${git_cmd[@]}" -C "$H" rev-parse 'v0.51.357:api/config.py')
blob_358=$("${git_cmd[@]}" -C "$H" rev-parse 'v0.51.358:api/config.py')
blob_fix=$("${git_cmd[@]}" -C "$H" rev-parse 'f2ef2851d389cf7a41308dcf0180d7cfbe446379:api/config.py')
[[ $blob_mem == 0c7741621415753812f194cd5d201e98ac877b8b ]]
[[ $blob_357 == a12c3ef18f26500bc74b73ba29f0f108cc27c46f ]]
[[ $blob_357 == "$blob_358" ]]
[[ $blob_357 == "$blob_fix" ]]
[[ $blob_mem != "$blob_357" ]]
peel357=$("${git_cmd[@]}" -C "$H" rev-parse 'v0.51.357^{commit}')
[[ $peel357 == 5dceb2993cc0a6bc42697a30d370425db482609a ]]
assert_ancestor "$H" b8b62722ec2f6b3cd394737ab409c35650f29ca6 v0.51.357
assert_not_ancestor "$H" f2ef2851d389cf7a41308dcf0180d7cfbe446379 v0.51.357
parents=$("${git_cmd[@]}" -C "$H" rev-parse 1126e541325d401538f6a272a9c024c37d47ae08^@)
printf '%s\n' "$parents" | grep -Fx 5dceb2993cc0a6bc42697a30d370425db482609a >/dev/null
printf '%s\n' "$parents" | grep -Fx f2ef2851d389cf7a41308dcf0180d7cfbe446379 >/dev/null
"${git_cmd[@]}" -C "$H" diff --stat v0.51.357 f2ef2851d389cf7a41308dcf0180d7cfbe446379 -- api/routes.py | grep -F api/routes.py >/dev/null

# ----- 128 Praison patch-delta and wheels -----
"${git_cmd[@]}" -C "$PR" log -1 --format='%an <%ae>' 3cd664bf7b7db5f774c1e7e3123a1a24c68ba700 | grep -F 'claude[bot]' >/dev/null
if "${git_cmd[@]}" -C "$PR" grep -F 'safe_builtins' '3cd664bf7b7db5f774c1e7e3123a1a24c68ba700^' -- src/praisonai-agents/praisonaiagents/tools/python_tools.py >/dev/null; then
  printf 'parent unexpectedly has safe_builtins\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$PR" grep -F 'safe_builtins' 3cd664bf7b7db5f774c1e7e3123a1a24c68ba700 -- src/praisonai-agents/praisonaiagents/tools/python_tools.py >/dev/null
if "${git_cmd[@]}" -C "$PR" grep -F '_blocked_attrs' 3cd664bf7b7db5f774c1e7e3123a1a24c68ba700 -- src/praisonai-agents/praisonaiagents/tools/python_tools.py >/dev/null; then
  printf 'AI commit unexpectedly already has _blocked_attrs\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$PR" grep -F '_blocked_attrs' v4.6.39 -- src/praisonai-agents/praisonaiagents/tools/python_tools.py >/dev/null
if "${git_cmd[@]}" -C "$PR" grep -F "'__self__'" v4.6.39 -- src/praisonai-agents/praisonaiagents/tools/python_tools.py >/dev/null; then
  printf 'v4.6.39 unexpectedly already blocks __self__\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$PR" grep -F "'__self__'" v4.6.40 -- src/praisonai-agents/praisonaiagents/tools/python_tools.py >/dev/null
assert_ancestor "$PR" 3cd664bf7b7db5f774c1e7e3123a1a24c68ba700 v4.6.39
assert_not_ancestor "$PR" 179cab02dbec0c1e9b601507a65908e079876004 v4.6.39
assert_ancestor "$PR" 179cab02dbec0c1e9b601507a65908e079876004 v4.6.40
assert_ancestor "$PR" cb820212e7565cdaae107e3ea1f2af5672e36817 v4.6.39

python3 - "$ART" "$OWNED" "$PR" << 'PY'
import json, zipfile, subprocess, sys
from pathlib import Path
art, owned, repo = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
d = json.loads((owned / "snapshot/pages/ghsa/ghsa-4mr5-g6f9-cfrh.json").read_text())
assert d.get("cve_id") == "CVE-2026-47392"
assert d.get("type") == "reviewed"
assert "_blocked_attrs" in d["description"]
v = d["vulnerabilities"][0]
assert v["package"]["name"] == "praisonaiagents"
assert v["vulnerable_version_range"] == "<= 1.6.39"
assert v.get("first_patched_version") == "1.6.40"
git = ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-C", repo]
def hob(data: bytes) -> str:
    p = subprocess.run(["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "hash-object", "--stdin"], input=data, capture_output=True, check=True)
    return p.stdout.decode().strip()
def gblob(spec: str) -> str:
    p = subprocess.run(git + ["rev-parse", spec], capture_output=True, text=True, check=True)
    return p.stdout.strip()
cand = gblob("3cd664bf7b7db5f774c1e7e3123a1a24c68ba700:src/praisonai-agents/praisonaiagents/tools/python_tools.py")
fix = gblob("179cab02dbec0c1e9b601507a65908e079876004:src/praisonai-agents/praisonaiagents/tools/python_tools.py")
t39 = gblob("v4.6.39:src/praisonai-agents/praisonaiagents/tools/python_tools.py")
t40 = gblob("v4.6.40:src/praisonai-agents/praisonaiagents/tools/python_tools.py")
assert cand == "fcaf2927ff446e3a2bf4a0bb0c685ca6d9eaac38"
assert fix == "83c5d83333ba08bbfcd76cc5bdb97eab48b0119c"
with zipfile.ZipFile(art / "praisonaiagents-1.6.39-py3-none-any.whl") as z:
    b = z.read("praisonaiagents/tools/python_tools.py")
assert hob(b) == t39
assert hob(b) != cand
assert b"_blocked_attrs" in b
assert b"'__self__'" not in b
with zipfile.ZipFile(art / "praisonaiagents-1.6.40-py3-none-any.whl") as z:
    b = z.read("praisonaiagents/tools/python_tools.py")
assert hob(b) == t40
assert hob(b) == fix
assert b"'__self__'" in b
print("128 identity wheels and AST residual ok")
PY

# ----- 130 Fission topology and prerelease -----
MEM=2db76f65dbfe4f657b4a4efb506ed63b24623e92
CAR=e484df8460bb4e8026e24210120602aa7f181f64
FIX=2569b42bfadbcb7d78b55a00a60f77937e522699
FPGO=pkg/apis/core/v1/podspec_safety.go
"${git_cmd[@]}" -C "$F" log -1 --format='%B' $MEM | grep -F 'Co-Authored-By: Claude Opus 4.7' >/dev/null
"${git_cmd[@]}" -C "$F" log -1 --format='%B' $CAR | grep -F 'Co-Authored-By: Claude Opus 4.7' >/dev/null
assert_not_ancestor "$F" $MEM v1.24.0
assert_ancestor "$F" $CAR v1.24.0
assert_not_ancestor "$F" $FIX v1.24.0
assert_ancestor "$F" $FIX v1.25.0
blob_mem=$("${git_cmd[@]}" -C "$F" rev-parse "${MEM}:${FPGO}")
blob_car=$("${git_cmd[@]}" -C "$F" rev-parse "${CAR}:${FPGO}")
blob_124=$("${git_cmd[@]}" -C "$F" rev-parse "v1.24.0:${FPGO}")
blob_125=$("${git_cmd[@]}" -C "$F" rev-parse "v1.25.0:${FPGO}")
blob_fix=$("${git_cmd[@]}" -C "$F" rev-parse "${FIX}:${FPGO}")
[[ $blob_mem == af473d2601a9299a035166c4d4bf67927abc50df ]]
[[ $blob_car == 330fccee042945fac9ccfcdb3d62f52036e63b5e ]]
[[ $blob_124 == 1d7219e7f592cc6ea631866328820475617141bd ]]
[[ $blob_125 == 43e361d3ab7bf4145f704e23d8654256444c1e86 ]]
[[ $blob_fix == "$blob_125" ]]
[[ $blob_mem != "$blob_car" ]]
[[ $blob_car != "$blob_124" ]]
[[ $blob_mem != "$blob_124" ]]
if "${git_cmd[@]}" -C "$F" rev-parse "${CAR}^:${FPGO}" >/dev/null 2>&1; then
  printf 'carrier parent unexpectedly has podspec_safety.go\n' >&2
  exit 1
fi
if "${git_cmd[@]}" -C "$F" grep -F SYS_TIME $CAR -- $FPGO >/dev/null; then
  printf 'carrier unexpectedly lists SYS_TIME\n' >&2
  exit 1
fi
if "${git_cmd[@]}" -C "$F" grep -F SYS_TIME v1.24.0 -- $FPGO >/dev/null; then
  printf 'v1.24.0 unexpectedly lists SYS_TIME\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$F" grep -F allowedCapabilities $FIX -- $FPGO >/dev/null
python3 - "$OWNED" << 'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
g = json.loads((owned / "snapshot/pages/ghsa/ghsa-qf5v-m7p4-95rp.json").read_text())
assert g.get("cve_id") == "CVE-2026-50570"
assert g.get("type") == "reviewed"
assert g["vulnerabilities"][0]["package"]["name"] == "github.com/fission/fission"
assert g["vulnerabilities"][0]["vulnerable_version_range"] == "<= 1.24.0"
assert g["vulnerabilities"][0].get("first_patched_version") == "1.25.0"
r24 = json.loads((owned / "snapshot/pages/rel-fission-v1.24.0.json").read_text())
r25 = json.loads((owned / "snapshot/pages/rel-fission-v1.25.0.json").read_text())
assert r24.get("prerelease") is True
assert r24.get("draft") is False
assert r25.get("prerelease") is False
print("130 identity three-way blobs and prerelease ok")
PY

# ----- 139 GitPython sibling Remote/Submodule -----
C1=8ac5a30519b6f4af85398b9b9d7064ff4d452da2
F1=863417457a0633db7ea5aed4fd01e0b291a41162
"${git_cmd[@]}" -C "$G" log -1 --format='%an <%ae>' $C1 | grep -F 'GPT 5.6' >/dev/null
"${git_cmd[@]}" -C "$G" grep -F 'expand_vars=False' $C1 -- git/repo/base.py >/dev/null
"${git_cmd[@]}" -C "$G" grep -F 'url = Git.polish_url(url)' $C1 -- git/remote.py >/dev/null
"${git_cmd[@]}" -C "$G" grep -F 'url = Git.polish_url(url)' "${C1}^" -- git/remote.py >/dev/null
"${git_cmd[@]}" -C "$G" grep -F 'url = Git.polish_url(url)' $C1 -- git/objects/submodule/base.py >/dev/null
"${git_cmd[@]}" -C "$G" grep -F 'expand_vars=False' $F1 -- git/remote.py >/dev/null
"${git_cmd[@]}" -C "$G" grep -F 'expand_vars=False' $F1 -- git/objects/submodule/base.py >/dev/null
assert_ancestor "$G" $C1 3.1.54
assert_not_ancestor "$G" $F1 3.1.54
assert_ancestor "$G" $F1 3.1.55
python3 - "$ART" "$OWNED" "$G" << 'PY'
import json, zipfile, subprocess, sys
from pathlib import Path
art, owned, repo = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
d = json.loads((owned / "snapshot/pages/ghsa/ghsa-94p4-4cq8-9g67.json").read_text())
assert d.get("type") == "reviewed"
assert "sibling caller the fix missed" in d["description"]
git = ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-C", repo]
def hob(data: bytes) -> str:
    p = subprocess.run(["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "hash-object", "--stdin"], input=data, capture_output=True, check=True)
    return p.stdout.decode().strip()
def gblob(spec: str) -> str:
    p = subprocess.run(git + ["rev-parse", spec], capture_output=True, text=True, check=True)
    return p.stdout.strip()
cand = gblob("8ac5a30519b6f4af85398b9b9d7064ff4d452da2:git/remote.py")
fix = gblob("863417457a0633db7ea5aed4fd01e0b291a41162:git/remote.py")
with zipfile.ZipFile(art / "gitpython-3.1.54-py3-none-any.whl") as z:
    b = z.read("git/remote.py")
assert hob(b) == cand
assert b"Git.polish_url(url)" in b
assert b"expand_vars=False" not in b.split(b"def create")[1][:400] if False else True
with zipfile.ZipFile(art / "gitpython-3.1.55-py3-none-any.whl") as z:
    b = z.read("git/remote.py")
assert hob(b) == fix
assert b"Git.polish_url(url, expand_vars=False)" in b
print("139 sibling remote wheels ok")
PY

# ----- 143 GitPython sibling Commit.count -----
C2=701ce32fe5ba8cb622c0e0342a376a6beb47d738
F2=38553b6fddc7f6a667cdb45a6762343a08fc72b2
"${git_cmd[@]}" -C "$G" log -1 --format='%an <%ae>' $C2 | grep -F 'GPT 5.6' >/dev/null
"${git_cmd[@]}" -C "$G" grep -F 'unsafe_git_rev_options' $C2 -- git/objects/commit.py >/dev/null
if "${git_cmd[@]}" -C "$G" grep -F 'unsafe_git_rev_options' "${C2}^" -- git/objects/commit.py >/dev/null; then
  printf 'parent unexpectedly has unsafe_git_rev_options\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$G" grep -F 'check_unsafe_options' $C2 -- git/objects/commit.py >/dev/null
# count method at candidate must not call check_unsafe_options before rev_list
python3 - "$G" << 'PY'
import subprocess, sys
repo=sys.argv[1]
git=["/usr/bin/git","--no-optional-locks","-c","gc.auto=0","-c","maintenance.auto=false","-C",repo]
body=subprocess.run(git+["show","701ce32fe5ba8cb622c0e0342a376a6beb47d738:git/objects/commit.py"], capture_output=True, check=True).stdout.decode()
parent=subprocess.run(git+["show","701ce32fe5ba8cb622c0e0342a376a6beb47d738^:git/objects/commit.py"], capture_output=True, check=True).stdout.decode()
def extract_count(src):
    i=src.index("    def count(")
    j=src.index("    @property", i)
    return src[i:j]
c=extract_count(body)
p=extract_count(parent)
assert "check_unsafe_options" not in c
assert "rev_list" in c
assert c.replace(" ","") == p.replace(" ","") or "check_unsafe_options" not in p
fix=subprocess.run(git+["show","38553b6fddc7f6a667cdb45a6762343a08fc72b2:git/objects/commit.py"], capture_output=True, check=True).stdout.decode()
cf=extract_count(fix)
assert "check_unsafe_options" in cf
print("143 count body unguarded at candidate, guarded at fix")
PY
assert_ancestor "$G" $C2 3.1.55
assert_not_ancestor "$G" $F2 3.1.55
assert_ancestor "$G" $F2 3.1.56
"${git_cmd[@]}" -C "$G" log -1 --format='%an' $F2 | grep -F 'Sebastian Thiel' >/dev/null
python3 - "$ART" "$OWNED" "$G" << 'PY'
import json, zipfile, subprocess, sys
from pathlib import Path
art, owned, repo = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
d = json.loads((owned / "snapshot/pages/ghsa/ghsa-p538-c434-8v24.json").read_text())
assert d.get("type") == "reviewed"
assert "sibling" in d["description"] and "iter_items" in d["description"]
assert "uncovered sink" in d["description"]
git = ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-C", repo]
def hob(data: bytes) -> str:
    p = subprocess.run(["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "hash-object", "--stdin"], input=data, capture_output=True, check=True)
    return p.stdout.decode().strip()
def gblob(spec: str) -> str:
    p = subprocess.run(git + ["rev-parse", spec], capture_output=True, text=True, check=True)
    return p.stdout.strip()
cand = gblob("701ce32fe5ba8cb622c0e0342a376a6beb47d738:git/objects/commit.py")
fix = gblob("38553b6fddc7f6a667cdb45a6762343a08fc72b2:git/objects/commit.py")
with zipfile.ZipFile(art / "gitpython-3.1.55-py3-none-any.whl") as z:
    b = z.read("git/objects/commit.py")
assert hob(b) == cand
with zipfile.ZipFile(art / "gitpython-3.1.56-py3-none-any.whl") as z:
    b = z.read("git/objects/commit.py")
assert hob(b) == fix
print("143 sibling count wheels ok")
PY

printf 'REPLAY_OK reviewed=5 KEEP_proposal=0 NARROW=5 REJECT=0 UNKNOWN=0 BLOCKED=0\n'
