#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-cf4-b0-predecessor-grok46-low.
# English only. No credentials. No clone/commit/push. Caches read-only.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-cf4-b0-predecessor-grok46-low
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json
REV=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
UNR=/home/hanqing/.cache/cve-analyzer/advisory-database
ML=/home/hanqing/.cache/cve-analyzer/repos/mlflow_mlflow
OC=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw
LF=/home/hanqing/.cache/cve-analyzer/repos/liferay_liferay-portal

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
  errf=$(mktemp /tmp/cf4-b0p-giterr.XXXXXX)
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

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  /usr/bin/python3 - "$OWNED/$f" <<'PY'
import sys
b=open(sys.argv[1],"rb").read()
if b"\x00" in b:
    raise SystemExit("nul")
b.decode("ascii")
PY
done

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
expect_hash "$SUMMARY" 81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921

expect_eq "$(gitx "$REV" rev-parse HEAD)" f2c6ab3202aeafb36fbea6e76d892532acfca1a6 reviewed_head
expect_eq "$(gitx "$UNR" rev-parse HEAD)" 39d8887723797efc1804585dd06585c9fd751226 unreviewed_head
expect_eq "$(/usr/bin/test -d "$REV/advisories/unreviewed" && echo yes || echo no)" no f2c6_unreviewed_absent
expect_eq "$(/usr/bin/python3 -c 'import os; print(sum(1 for r,ds,fs in os.walk("'"$REV"'/advisories/github-reviewed") for f in fs if f.startswith("GHSA-") and f.endswith(".json")))')" 34389 reviewed_file_count
expect_eq "$(/usr/bin/python3 -c 'import os; print(sum(1 for r,ds,fs in os.walk("'"$UNR"'/advisories/unreviewed") for f in fs if f.startswith("GHSA-") and f.endswith(".json")))')" 317316 unreviewed_file_count

/usr/bin/python3 - <<'PY'
import hashlib, json, pathlib, re
ROOT = pathlib.Path("/home/hanqing/agents/ai-slop")
OWNED = ROOT / "autoresearch/herdr-260814-cf4-b0-predecessor-grok46-low"
PINNED_MANIFEST_SHA256 = "5c44164659b06086e813b7559a24a0c7d4c10d3fceac8f7998dd5fdf11bd96ed"
GHSA = re.compile(r"GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
ASSIGNED = ["GHSA-R5M9-WM49-959F", "GHSA-7F25-VHJ7-MXRC"]

def manifest_bytes(excluded_ids):
    body = (
        "cf4-b0-predecessor-frozen-input-v1\n"
        "excluded\n" + "\n".join(excluded_ids) + "\n"
        "inspect\n317\nGHSA-23W4-RPC6-WPCC\nGHSA-XX7C-F2FQ-QMV3\n"
        "GHSA-R5M9-WM49-959F\nGHSA-7F25-VHJ7-MXRC\n"
    )
    return body.encode("ascii")

result = json.loads((OWNED / "result.json").read_text())
frozen = result["frozen_input"]
assert frozen["manifest_version"] == "cf4-b0-predecessor-frozen-input-v1"
excluded = frozen["excluded_ids"]
assert isinstance(excluded, list) and excluded == sorted(excluded)
assert all(isinstance(x, str) and GHSA.fullmatch(x) for x in excluded)
got = hashlib.sha256(manifest_bytes(excluded)).hexdigest()
assert got == PINNED_MANIFEST_SHA256, got
assert got == frozen["manifest_sha256"]
assert len(excluded) == result["conservation"]["excluded_structured_ids"]
assigned = [json.loads(line)["case_id"] for line in (OWNED / "assignment.jsonl").read_text().splitlines() if line.strip()]
cases = [json.loads(line)["case_id"] for line in (OWNED / "cases.jsonl").read_text().splitlines() if line.strip()]
assert assigned == cases == ASSIGNED
assert len(set(assigned)) == 2
assert result["counts"]["PASS_PROPOSAL"] == 0
assert result["conservation"]["assigned"] == 2
assert result["conservation"]["reviewed"] == 1
assert result["conservation"]["unreviewed"] == 1
assert result["conservation"]["equation"] == "2=1+1"
assert result["conservation"]["did_not_pad"] is True
assert result["inspect"]["inspected"] == 317
assert result["inspect"]["cap"] == 600
assert result["inspect"]["hit_count"] == 2
assert result["inspect"]["shortfall"] == 10
assert result["inspect"]["stop_rule"] == "inspected_ranked_real_objects_317_shortfall_10"
assert result["inspect"]["prefix_first"] == "GHSA-23W4-RPC6-WPCC"
assert result["inspect"]["prefix_last"] == "GHSA-XX7C-F2FQ-QMV3"
assert result["advisory_sources"]["reviewed_head"] == "f2c6ab3202aeafb36fbea6e76d892532acfca1a6"
assert result["advisory_sources"]["unreviewed_head"] == "39d8887723797efc1804585dd06585c9fd751226"
canon = set(json.loads((ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json").read_text())["strict_released_case_ids"])
assert len(canon) == 88
for gid in assigned:
    assert int(hashlib.sha256(gid.encode()).hexdigest(), 16) % 6 == 0, gid
    assert gid not in excluded, gid
    assert gid not in canon, gid
assert "GHSA-MP6X-97XJ-9X62" in excluded
print("frozen_manifest_sha256", got)
print("bucket_exclusion_ok 2")
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

expect_eq "$(gitx "$LF" rev-parse '12a076172494707748325836b3d5236507be0490^{commit}')" 12a076172494707748325836b3d5236507be0490 prefix_first_fix_object
expect_eq "$(gitx "$ML" rev-parse 'e151258a559567015b03058c55208fd02550ea9f^{commit}')" e151258a559567015b03058c55208fd02550ea9f ml_ai
expect_eq "$(gitx "$ML" rev-parse '6989066af33fdcb03588fd71a1a67f8fc5ef12c9^{commit}')" 6989066af33fdcb03588fd71a1a67f8fc5ef12c9 ml_fix
expect_eq "$(gitx "$ML" log -1 --format=%s e151258a559567015b03058c55208fd02550ea9f)" "Add permission validation for gateway CRUD operations (#19823)" ml_ai_subj
expect_eq "$(gitx "$ML" log -1 --format=%s 6989066af33fdcb03588fd71a1a67f8fc5ef12c9)" "Add model version search filtering based on user permissions (#20964)" ml_fix_subj
expect_eq "$(anc "$ML" e151258a559567015b03058c55208fd02550ea9f 6989066af33fdcb03588fd71a1a67f8fc5ef12c9)" 0 ml_ai_ancestor
expect_eq "$(anc "$ML" e151258a559567015b03058c55208fd02550ea9f v3.9.0)" 0 ml_ai_in_v390
expect_eq "$(anc "$ML" 6989066af33fdcb03588fd71a1a67f8fc5ef12c9 v3.9.0)" 1 ml_fix_not_in_v390
expect_eq "$(anc "$ML" 6989066af33fdcb03588fd71a1a67f8fc5ef12c9 v3.10.1)" 1 ml_fix_not_in_v3101
expect_eq "$(anc "$ML" 6989066af33fdcb03588fd71a1a67f8fc5ef12c9 v3.11.0rc0)" 0 ml_fix_in_v3110rc0
expect_eq "$(gitx "$OC" rev-parse '60661441b1c231115d090607dd18fedb87d9f8ac^{commit}')" 60661441b1c231115d090607dd18fedb87d9f8ac oc_ai
expect_eq "$(gitx "$OC" rev-parse '76411b2afc4ae721e36c12e0ea24fd23e2fed61e^{commit}')" 76411b2afc4ae721e36c12e0ea24fd23e2fed61e oc_fix
expect_eq "$(gitx "$OC" log -1 --format=%s 60661441b1c231115d090607dd18fedb87d9f8ac)" "feat(gateway-tool): add config.patch action for safe partial config updates (#1624)" oc_ai_subj
expect_eq "$(gitx "$OC" log -1 --format=%s 76411b2afc4ae721e36c12e0ea24fd23e2fed61e)" "Agents: block protected gateway config writes (#55682)" oc_fix_subj
expect_eq "$(anc "$OC" 60661441b1c231115d090607dd18fedb87d9f8ac 76411b2afc4ae721e36c12e0ea24fd23e2fed61e)" 0 oc_ai_ancestor
expect_eq "$(anc "$OC" 60661441b1c231115d090607dd18fedb87d9f8ac v2026.3.22)" 0 oc_ai_in_322
expect_eq "$(anc "$OC" 76411b2afc4ae721e36c12e0ea24fd23e2fed61e v2026.3.22)" 1 oc_fix_not_in_322
expect_eq "$(anc "$OC" 76411b2afc4ae721e36c12e0ea24fd23e2fed61e v2026.3.28)" 0 oc_fix_in_328

/usr/bin/python3 - <<'PY'
import subprocess, sys
sys.path.insert(0, "/home/hanqing/agents/ai-slop/cve-analyzer/src")
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import matches_for_commit

def meta(repo, sha):
    raw = subprocess.check_output(["git","-C",repo,"log","-1","--format=%an%x00%ae%x00%cn%x00%ce%x00%P%x00%B",sha], stderr=subprocess.DEVNULL).decode().split("\x00")
    return raw

ml="/home/hanqing/.cache/cve-analyzer/repos/mlflow_mlflow"
oc="/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw"
ai=meta(ml,"e151258a559567015b03058c55208fd02550ea9f")
assert "Claude" in ai[5]
assert len(ai[4].split())==1
ci=CommitInfo(sha="x",author_name=ai[0],author_email=ai[1],committer_name=ai[2],committer_email=ai[3],message=ai[5],authored_date="")
assert any(m.tool=="claude_code" for m in matches_for_commit(ci))
fix_blob=subprocess.check_output(["git","-C",ml,"show","6989066af33fdcb03588fd71a1a67f8fc5ef12c9:mlflow/server/auth/__init__.py"], stderr=subprocess.DEVNULL).decode()
idx=fix_blob.find("BEFORE_REQUEST_HANDLERS")
chunk=fix_blob[idx:idx+5000]
assert "ListGatewaySecretInfos:" not in chunk
assert "ListGatewayEndpoints:" not in chunk
assert "ListGatewayModelDefinitions:" not in chunk
ai_diff=subprocess.check_output(["git","-C",ml,"show","e151258a559567015b03058c55208fd02550ea9f","--","mlflow/server/auth/__init__.py"], stderr=subprocess.DEVNULL).decode()
assert "BEFORE_REQUEST_HANDLERS" in ai_diff
assert "GetGatewaySecretInfo:" in ai_diff
assert "+    ListGatewaySecretInfos as ListGatewaySecretInfos" in ai_diff
ocai=meta(oc,"60661441b1c231115d090607dd18fedb87d9f8ac")
assert "Claude" in ocai[5]
assert len(ocai[4].split())==1
ci=CommitInfo(sha="x",author_name=ocai[0],author_email=ocai[1],committer_name=ocai[2],committer_email=ocai[3],message=ocai[5],authored_date="")
assert any(m.tool=="claude_code" for m in matches_for_commit(ci))
ocfix=meta(oc,"76411b2afc4ae721e36c12e0ea24fd23e2fed61e")
ci=CommitInfo(sha="x",author_name=ocfix[0],author_email=ocfix[1],committer_name=ocfix[2],committer_email=ocfix[3],message=ocfix[5],authored_date="")
assert matches_for_commit(ci)==()
diff=subprocess.check_output(["git","-C",oc,"show","76411b2afc4ae721e36c12e0ea24fd23e2fed61e","--","src/agents/tools/gateway-tool.ts"], stderr=subprocess.DEVNULL).decode()
assert "PROTECTED_GATEWAY_CONFIG_PATHS" in diff
assert "tools.exec.ask" in diff
print("predecessor_facts_ok")
PY

printf 'PASS_PROPOSAL 0\n'
printf 'assigned 2 reviewed 1 unreviewed 1 shortfall 10 inspected 317\n'
printf 'REPLAY_OK\n'
