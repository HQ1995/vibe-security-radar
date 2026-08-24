#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-cf4-b0-direct-grok46-low.
# English only. No credentials. No clone/commit/push. Caches read-only.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-cf4-b0-direct-grok46-low
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json
REV=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
UNR=/home/hanqing/.cache/cve-analyzer/advisory-database
MM=/home/hanqing/.cache/cve-analyzer/repos/mattermost_mattermost
MCP=/home/hanqing/.cache/cve-analyzer/repos/modelcontextprotocol_python-sdk
GR=/home/hanqing/.cache/cve-analyzer/repos/gradio-app_gradio
ML=/home/hanqing/.cache/cve-analyzer/repos/mlflow_mlflow
GOGS=/home/hanqing/.cache/cve-analyzer/repos/gogs_gogs
VY=/home/hanqing/.cache/cve-analyzer/repos/vyperlang_vyper
AS=/home/hanqing/.cache/cve-analyzer/repos/assimp_assimp
O5=/home/hanqing/.cache/cve-analyzer/repos/open5gs_open5gs

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

expect_eq() {
  if [[ $1 != "$2" ]]; then
    printf 'mismatch %s expected=%s got=%s\n' "$3" "$2" "$1" >&2
    exit 1
  fi
}

expect_hash() {
  local got
  got=$(/usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}')
  expect_eq "$got" "$2" "$1"
}

gitx() {
  local repo=$1
  shift
  local errf
  errf=$(mktemp /tmp/cf4-b0-giterr.XXXXXX)
  set +e
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
  if [[ -s $errf ]]; then
    /usr/bin/grep -vE 'unable to normalize alternate object path|lazy fetching disabled' "$errf" >&2 || true
  fi
  rm -f "$errf"
  return $rc
}

require_file() {
  if [[ ! -f $1 ]]; then
    printf 'missing %s\n' "$1" >&2
    exit 1
  fi
}

require_dir() {
  if [[ ! -d $1 ]]; then
    printf 'missing %s\n' "$1" >&2
    exit 1
  fi
}

require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/result.json"
require_file "$OWNED/report.md"
require_file "$CONTRACT"
require_file "$LEDGER"
require_file "$SUMMARY"
require_dir "$REV/advisories/github-reviewed"
require_dir "$UNR/advisories/unreviewed"

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
expect_hash "$SUMMARY" 81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921

expect_eq "$(gitx "$REV" rev-parse HEAD)" f2c6ab3202aeafb36fbea6e76d892532acfca1a6 reviewed_head
expect_eq "$(gitx "$UNR" rev-parse HEAD)" 39d8887723797efc1804585dd06585c9fd751226 unreviewed_head
expect_eq "$(/usr/bin/test -d "$REV/advisories/unreviewed" && echo yes || echo no)" no f2c6_unreviewed_absent
expect_eq "$(/usr/bin/python3 -c 'import os; print(sum(1 for r,ds,fs in os.walk("'"$REV"'/advisories/github-reviewed") for f in fs if f.startswith("GHSA-") and f.endswith(".json")))')" 34389 reviewed_file_count

/usr/bin/python3 - <<'PY'
import hashlib, json, pathlib, re, collections
ROOT = pathlib.Path("/home/hanqing/agents/ai-slop")
OWNED = ROOT / "autoresearch/herdr-260814-cf4-b0-direct-grok46-low"
GHSA = re.compile(r"GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
KEYS = {"case_id","ghsa_id","reviewed_case_ids","assigned_ids","strict_released_case_ids"}
NAMES = {"assignment.jsonl","cases.jsonl","result.json","selected.jsonl","selected.json","ledger.jsonl","summary.json"}

def norm(s):
    if not isinstance(s, str):
        return None
    s = s.strip().upper()
    return s if GHSA.fullmatch(s) else None

def harvest(obj, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in KEYS:
                if isinstance(v, str):
                    n = norm(v)
                    if n:
                        out.add(n)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, str):
                            n = norm(item)
                            if n:
                                out.add(n)
            elif isinstance(v, (dict, list)):
                harvest(v, out)
    elif isinstance(obj, list):
        for item in obj:
            harvest(item, out)

excluded = set()
ar = ROOT / "autoresearch"
for p in ar.iterdir():
    if not p.is_dir():
        continue
    if not (p.name.startswith("herdr-") or p.name.startswith("orchestrator-")):
        continue
    if p.name == "herdr-260814-cf4-b0-direct-grok46-low":
        continue
    for n in NAMES:
        fp = p / n
        if not fp.is_file():
            continue
        text = fp.read_text(encoding="utf-8", errors="replace")
        if fp.suffix == ".jsonl":
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    harvest(json.loads(line), excluded)
                except Exception:
                    pass
        else:
            try:
                harvest(json.loads(text), excluded)
            except Exception:
                pass

summary = json.loads((ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json").read_text())
canon = set(summary["strict_released_case_ids"])
assigned = []
for line in (OWNED / "assignment.jsonl").read_text().splitlines():
    assigned.append(json.loads(line)["case_id"])
cases = []
for line in (OWNED / "cases.jsonl").read_text().splitlines():
    cases.append(json.loads(line)["case_id"])
assert assigned == cases
assert len(assigned) == 12
assert len(set(assigned)) == 12
for gid in assigned:
    assert int(hashlib.sha256(gid.encode()).hexdigest(), 16) % 6 == 0, gid
    assert gid not in excluded, gid
    assert gid not in canon, gid
result = json.loads((OWNED / "result.json").read_text())
assert result["counts"]["PASS_PROPOSAL"] == 0
assert result["conservation"]["assigned"] == 12
assert result["conservation"]["reviewed"] == 12
assert result["advisory_sources"]["reviewed_head"] == "f2c6ab3202aeafb36fbea6e76d892532acfca1a6"
assert result["advisory_sources"]["unreviewed_head"] == "39d8887723797efc1804585dd06585c9fd751226"
assert result["universe"]["eligible_unreviewed"] == 54
print("bucket_exclusion_ok 12")
print("excluded_structured", len(excluded))
print("canonical88", len(canon))
PY

anc() {
  if gitx "$1" merge-base --is-ancestor "$2" "$3"; then
    printf '0\n'
  else
    printf '1\n'
  fi
}

# Decisive git facts
expect_eq "$(gitx "$MM" rev-parse 'd78d59babeb994106e305531de50b8d515427396^{commit}')" d78d59babeb994106e305531de50b8d515427396 mm_ai
expect_eq "$(anc "$MM" d78d59babeb994106e305531de50b8d515427396 7d8b7b5e4a6076b2f7c87606883c417f9a610df5)" 0 mm_ai_anc_xpg8
expect_eq "$(anc "$MM" d78d59babeb994106e305531de50b8d515427396 5072bbf689a46b3b97b2373f26149f5891396e6b)" 1 mm_ai_not_anc_of_cherry_pick_5072
expect_eq "$(anc "$MCP" f8d98b63a7e9ab5855d79556d3d7e5638472af6c 62137874ff26dd74d2fea80ff528a7fd9ca7a5e7)" 0 hvrp_ai_anc
expect_eq "$(anc "$MCP" 62137874ff26dd74d2fea80ff528a7fd9ca7a5e7 v1.27.2)" 0 hvrp_fix_in_1272
expect_eq "$(anc "$MCP" 62137874ff26dd74d2fea80ff528a7fd9ca7a5e7 v1.27.1)" 1 hvrp_fix_not_in_1271
expect_eq "$(anc "$MCP" f8d98b63a7e9ab5855d79556d3d7e5638472af6c v1.27.1)" 0 hvrp_ai_in_1271
expect_eq "$(gitx "$GR" rev-parse '83b223b746c3933920dfef670e545a12de9177ed^{commit}')" 83b223b746c3933920dfef670e545a12de9177ed gr_ai
expect_eq "$(gitx "$ML" log -1 --format=%s 4a3f2f720cb4f058c9e0c5b883e0acc9ab64a7f3)" "Gate env-var API key resolution behind MLFLOW_GATEWAY_RESOLVE_API_KEY_FROM_ENV (#21544)" ml_fix_subj
expect_eq "$(anc "$GOGS" d3ca23f9f33d5710472a775d6dcd3a7bb128bb05 v0.14.3)" 1 gogs_fix_not_in_v0143
expect_eq "$(gitx "$VY" log -1 --format=%an 3d9c537142fb99b2672f21e2057f5f202cde194f)" "Charles Cooper" vyper_author
expect_eq "$(gitx "$AS" log -1 --format=%an d24b85319bd70c65883a2b96613e07e23fb95981)" "Sai Asish Y" assimp_author
expect_eq "$(anc "$O5" 819db11a08b9736a3576c4f99ceb28f7eb99523a v2.8.0)" 0 o5_fix_in_280

/usr/bin/python3 - <<'PY'
import subprocess
def msg(repo, sha):
    return subprocess.check_output(["git","-C",repo,"log","-1","--format=%B",sha], stderr=subprocess.DEVNULL).decode()
mm="/home/hanqing/.cache/cve-analyzer/repos/mattermost_mattermost"
mcp="/home/hanqing/.cache/cve-analyzer/repos/modelcontextprotocol_python-sdk"
gr="/home/hanqing/.cache/cve-analyzer/repos/gradio-app_gradio"
ml="/home/hanqing/.cache/cve-analyzer/repos/mlflow_mlflow"
assert "Claude" in msg(mm, "d78d59babeb994106e305531de50b8d515427396")
assert "Claude" in msg(mcp, "f8d98b63a7e9ab5855d79556d3d7e5638472af6c")
assert "Claude Opus 4.6" in msg(gr, "83b223b746c3933920dfef670e545a12de9177ed")
assert "Claude" in msg(ml, "4a3f2f720cb4f058c9e0c5b883e0acc9ab64a7f3")
diff = subprocess.check_output(["git","-C",mcp,"show","--format=","f8d98b63a7e9ab5855d79556d3d7e5638472af6c","--","src/mcp/server/lowlevel/experimental.py"]).decode()
assert "TasksCallCapability()" in diff
assert "_require_task_in_requestor_scope" not in diff
print("ai_markers_and_hvrp_delta_ok")
PY

printf 'PASS_PROPOSAL 0\n'
printf 'assigned 12 reviewed 12\n'
printf 'REPLAY_OK\n'
