#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-fp211-unseen-hard3-grok46-medium.
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
export TMPDIR=/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unseen-hard3-grok46-medium/work

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fp211-unseen-hard3-grok46-medium
X=/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/xiaomusic
P=/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/pydantic-ai
M=/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/mlflow

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
      if ! grep -Eiq 'path .* does not exist|exists on disk, but not in' "$errf"; then
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
  local errf=$OWNED/work/.giterr
  local outf=$OWNED/work/.gitout
  set +e
  /usr/bin/timeout 30 "${git_cmd[@]}" -C "$repo" rev-parse "$rev:$file" >"$outf" 2>"$errf"
  local rc=$?
  set -e
  if [[ $rc -eq 124 ]]; then
    printf 'git timeout: rev-parse %s:%s\n' "$rev" "$file" >&2
    rm -f "$errf" "$outf"
    exit 1
  fi
  if [[ $rc -eq 0 ]]; then
    printf 'unexpected path present: %s:%s\n' "$rev" "$file" >&2
    rm -f "$errf" "$outf"
    exit 1
  fi
  if grep -Eiq 'promisor|partial clone|could not get object|unable to read|bad object|needed a single revision' "$errf"; then
    printf 'missing git object (fail closed): %s\n' "$(cat "$errf")" >&2
    rm -f "$errf" "$outf"
    exit 1
  fi
  if ! grep -Eiq 'path .* does not exist|exists on disk, but not in' "$errf"; then
    printf 'unexpected missing-path error: %s\n' "$(cat "$errf")" >&2
    rm -f "$errf" "$outf"
    exit 1
  fi
  rm -f "$errf" "$outf"
}

require_dir "$OWNED"
require_dir "$X/.git"
require_dir "$P/.git"
require_dir "$M/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/compact_facts.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/pages/ghsa/GHSA-5J8P-5RRJ-8WJG.json"
require_file "$OWNED/work/pages/ghsa/GHSA-2JRP-274C-JHV3.json"
require_file "$OWNED/work/pages/ghsa/GHSA-2CM6-R77W-6G96.json"
require_file "$OWNED/work/pages/repo-advisory/GHSA-2JRP-274C-JHV3.json"
require_file "$OWNED/notes/releases/github_releases.json"
require_file "$OWNED/notes/releases/pypi.json"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$OWNED/selected.jsonl" \
  e916aaf7eedb458d623fcf2ba8ad6469901e6c4c66d0e72fb923c4208a85b5a2
expect_hash "$OWNED/cases.jsonl" \
  df286befbfef4cdfe446f51f480ac9e6b47a2224377634782f859c92688d3d40
expect_hash "$OWNED/report.md" \
  ebf3d475c2d694d2651d0e48614d05888911b1e5f5e432663ce60d87cd4e246d
expect_hash "$OWNED/compact_facts.json" \
  66eb447f7704e9964e7013b6003879afdae2acb92eac172621b70af00b4e14cd
expect_hash "$OWNED/work/uniqueness.json" \
  4d5cfea0d3ef2c4ce20e2fc5be8fb8dc994e031c2bd1cdef0d5dfb2f92734f2e

python3 - "$OWNED" <<'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
order = [
    "GHSA-5J8P-5RRJ-8WJG",
    "GHSA-2JRP-274C-JHV3",
    "GHSA-2CM6-R77W-6G96",
]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l]
if len(sel) != 3 or len(cases) != 3:
    raise SystemExit("conservation fail: selected/cases not 3")
if [o["case_id"] for o in sel] != order:
    raise SystemExit("selected order mismatch")
if [c["case_id"] for c in cases] != order:
    raise SystemExit("cases order mismatch")
if [o["ordinal"] for o in sel] != [88, 101, 103]:
    raise SystemExit("ordinal order mismatch")
if [o["row_key"] for o in sel] != [
    "strict-200-v3:alias-3cac93e2e744b1b362bb38a6",
    "strict-200-v3:alias-a16652492e42b6eefef74358",
    "strict-200-v3:alias-125fe49a49acf7ef2baeb111",
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
if len(uni["excluded_unseen_twogate8"]) != 8:
    raise SystemExit("twogate8 exclusion count")
cf = json.loads((owned / "compact_facts.json").read_text())
if cf["xiaomusic_5j8p"]["member_ancestor_of_carrier"] is not False:
    raise SystemExit("5j8p member must not be carrier ancestor")
if cf["xiaomusic_5j8p"]["member_eq_carrier_blob"] is not True:
    raise SystemExit("5j8p member blob should equal carrier blob")
if cf["xiaomusic_5j8p"]["carrier_eq_v057_blob"] is not False:
    raise SystemExit("5j8p carrier blob must differ from v0.5.7")
if cf["pydantic_2jrp"]["member_eq_carrier_blob"] is not False:
    raise SystemExit("2jrp member blob must differ from carrier")
if cf["pydantic_2jrp"]["v134_peel_equals_carrier"] is not True:
    raise SystemExit("2jrp v1.34.0 must peel to carrier")
if cf["pydantic_2jrp"]["ssrf_absent_v134"] is not True:
    raise SystemExit("2jrp _ssrf.py must be absent from v1.34.0")
if cf["mlflow_2cm6"]["parent_has_BatchGetTraceInfos"] is not False:
    raise SystemExit("2cm6 parent must lack BatchGetTraceInfos")
if cf["mlflow_2cm6"]["cand_has_BatchGetTraceInfos"] is not True:
    raise SystemExit("2cm6 candidate must add BatchGetTraceInfos")
if cf["mlflow_2cm6"]["v3111_handlers_blob_readable"] is not False:
    raise SystemExit("2cm6 v3.11.1 handlers blob must stay unreadable")
for ghsa, summary in (
    ("GHSA-5J8P-5RRJ-8WJG", "xiaomusic contains an unauthenticated path traversal vulnerability"),
    ("GHSA-2JRP-274C-JHV3", "Pydantic AI has Server-Side Request Forgery (SSRF) in URL Download Handling"),
    ("GHSA-2CM6-R77W-6G96", "MLflow: trace API endpoints lack proper authorization validators"),
):
    o = json.loads((owned / "work/pages/ghsa" / f"{ghsa}.json").read_text())
    if o.get("type") != "reviewed":
        raise SystemExit("global advisory not reviewed " + ghsa)
    if o.get("withdrawn_at") is not None:
        raise SystemExit("withdrawn " + ghsa)
    if summary not in (o.get("summary") or ""):
        raise SystemExit("summary mismatch " + ghsa)
print("CONSERVATION_OK 3=3+0")
PY

# xiaomusic 5J8P
assert_not_ancestor "$X" ac32a09a6a84e5be7777f63701f101a19fa792bb v0.5.7
assert_not_ancestor "$X" ac32a09a6a84e5be7777f63701f101a19fa792bb fa0511f4e19f42e6e20989fd96a2f73eceff7499
assert_ancestor "$X" fa0511f4e19f42e6e20989fd96a2f73eceff7499 v0.5.7
assert_not_ancestor "$X" 88404da7a283f2c0a796a4cd16bbb6e6aa1f4722 v0.5.7
assert_ancestor "$X" 88404da7a283f2c0a796a4cd16bbb6e6aa1f4722 v0.5.8
expect_blob "$X" ac32a09a6a84e5be7777f63701f101a19fa792bb xiaomusic/api/routers/file.py d51edce1b322bcac618359b1fc270f23ab9208da
expect_blob "$X" fa0511f4e19f42e6e20989fd96a2f73eceff7499 xiaomusic/api/routers/file.py d51edce1b322bcac618359b1fc270f23ab9208da
expect_blob "$X" v0.5.7 xiaomusic/api/routers/file.py 3c5adba42ef2a05b5ba183346b0422868d2d3364
expect_blob "$X" v0.5.8 xiaomusic/api/routers/file.py 34be7bd534d1ee0647cff9142f28b7f52384b962
expect_blob "$X" 88404da7a283f2c0a796a4cd16bbb6e6aa1f4722 xiaomusic/api/routers/file.py 34be7bd534d1ee0647cff9142f28b7f52384b962

# pydantic-ai 2JRP
assert_not_ancestor "$P" 6bba553f19e36bb59f63f15998792b7ccf563d22 v1.34.0
assert_not_ancestor "$P" 6bba553f19e36bb59f63f15998792b7ccf563d22 afde1c431371ce24757179ed1cad09af0f382d29
assert_ancestor "$P" afde1c431371ce24757179ed1cad09af0f382d29 v1.34.0
assert_not_ancestor "$P" d398bc9d39aecca6530fa7486a410d5cce936301 v1.34.0
assert_ancestor "$P" d398bc9d39aecca6530fa7486a410d5cce936301 v1.56.0
expect_blob "$P" 6bba553f19e36bb59f63f15998792b7ccf563d22 pydantic_ai_slim/pydantic_ai/models/anthropic.py ecf78bbbd158427e31f34e4779bfd06fb58ea12e
expect_blob "$P" afde1c431371ce24757179ed1cad09af0f382d29 pydantic_ai_slim/pydantic_ai/models/anthropic.py e875cec8f2444169a065de15d42d06f807ab466b
expect_blob "$P" v1.34.0 pydantic_ai_slim/pydantic_ai/models/anthropic.py e875cec8f2444169a065de15d42d06f807ab466b
expect_blob "$P" v1.56.0 pydantic_ai_slim/pydantic_ai/models/anthropic.py 59b0797aecff83ec86d375ec3c41c309d29b6dbc
assert_missing_path "$P" v1.34.0 pydantic_ai_slim/pydantic_ai/_ssrf.py
expect_blob "$P" v1.56.0 pydantic_ai_slim/pydantic_ai/_ssrf.py 0ca446f6f2d154b5adede0a1f8349839274fe759
got=$(g "$P" rev-parse 'v1.34.0^{commit}')
if [[ $got != afde1c431371ce24757179ed1cad09af0f382d29 ]]; then
  printf 'v1.34.0 peel mismatch\n' >&2
  exit 1
fi
got=$(g "$P" rev-parse 'v1.56.0^{commit}')
if [[ $got != d398bc9d39aecca6530fa7486a410d5cce936301 ]]; then
  printf 'v1.56.0 peel mismatch\n' >&2
  exit 1
fi

# mlflow 2CM6: do not cat-file the unreadable v3.11.1 handlers blob
assert_ancestor "$M" 3e590361e0e251382ae30cbc9993d604bfdb67d5 v3.11.1
assert_not_ancestor "$M" f9b1eb510478570609ef451984a255775aa4b937 v3.11.1
assert_ancestor "$M" f9b1eb510478570609ef451984a255775aa4b937 v3.13.0
expect_blob "$M" 3e590361e0e251382ae30cbc9993d604bfdb67d5 mlflow/server/handlers.py 2b0b7c872e0d524266e4617baef625c128c37842
expect_blob "$M" f9b1eb510478570609ef451984a255775aa4b937 mlflow/server/auth/__init__.py d26a7d972f2f86712aabbed1bde5a1282780fb69
got=$(g "$M" rev-parse 'v3.11.1^{commit}')
if [[ $got != 09179c65741c4d40df2e934950e32f526a2c0e9e ]]; then
  printf 'v3.11.1 peel mismatch\n' >&2
  exit 1
fi
got=$(g "$M" rev-parse 'v3.13.0^{commit}')
if [[ $got != 8a774946bc19b59cecf3c54a733ebab52aa766f5 ]]; then
  printf 'v3.13.0 peel mismatch\n' >&2
  exit 1
fi

python3 - "$OWNED" <<'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
rel = json.loads((owned / "notes/releases/github_releases.json").read_text())
for name, tag in (
    ("xiaomusic_v0.5.7.json", "v0.5.7"),
    ("xiaomusic_v0.5.8.json", "v0.5.8"),
    ("pydantic_v1.34.0.json", "v1.34.0"),
    ("pydantic_v1.56.0.json", "v1.56.0"),
    ("mlflow_v3.11.1.json", "v3.11.1"),
    ("mlflow_v3.13.0.json", "v3.13.0"),
):
    o = rel[name]
    if o["tag_name"] != tag or o["draft"] or o["prerelease"]:
        raise SystemExit("release " + name)
pypi = json.loads((owned / "notes/releases/pypi.json").read_text())
if pypi["xiaomusic"]["versions"]["0.5.8"]["sha256"] != "d988feba3206650a13d5770f3b754f7e7811030d6e06feb04ee1c4a5884f3c33":
    raise SystemExit("pypi xiaomusic 0.5.8")
if pypi["pydantic-ai"]["versions"]["1.56.0"]["sha256"] != "643ff71612df52315b3b4c4b41543657f603f567223eb33245dc8098f005bdc4":
    raise SystemExit("pypi pydantic-ai 1.56.0")
if pypi["mlflow"]["versions"]["3.13.0"]["sha256"] != "a95198d592a8a15fad3db7f56b228acc9422c09f0daa7c6c976a9996ab73c3e2":
    raise SystemExit("pypi mlflow 3.13.0")
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

printf 'REPLAY_OK reviewed=3 PASS_proposal=0 NARROW=3 REJECT=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 canonical=84\n'
