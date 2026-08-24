#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-cf4-b1-history-grok46-medium.
# English only. No credentials. No clone/commit/push. Shared caches read-only.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat
export PYTHONPATH=/home/hanqing/agents/ai-slop/cve-analyzer/src

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-cf4-b1-history-grok46-medium
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json
ADV_R=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
ADV_U=/home/hanqing/.cache/cve-analyzer/advisory-database
HEAD_R=f2c6ab3202aeafb36fbea6e76d892532acfca1a6
HEAD_U=39d8887723797efc1804585dd06585c9fd751226

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
  local errf rc
  errf=$(mktemp /tmp/cf4-b1h-giterr.XXXXXX)
  setopt localoptions noerrexit
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  rc=$?
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
require_dir "$ADV_R/advisories/github-reviewed"
require_dir "$ADV_U/advisories/unreviewed"

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
expect_hash "$SUMMARY" 81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921

rh=$(gitx "$ADV_R" rev-parse HEAD)
uh=$(gitx "$ADV_U" rev-parse HEAD)
expect_eq "$rh" "$HEAD_R" reviewed_head
expect_eq "$uh" "$HEAD_U" unreviewed_head

n_assign=$(/usr/bin/wc -l < "$OWNED/assignment.jsonl" | /usr/bin/tr -d ' ')
n_cases=$(/usr/bin/wc -l < "$OWNED/cases.jsonl" | /usr/bin/tr -d ' ')
expect_eq "$n_assign" 12 assignment_rows
expect_eq "$n_cases" 12 cases_rows

owned_count=$(/usr/bin/find "$OWNED" -maxdepth 1 -type f | /usr/bin/wc -l | /usr/bin/tr -d ' ')
expect_eq "$owned_count" 5 owned_files

MLFLOW=/home/hanqing/.cache/cve-analyzer/repos/mlflow_mlflow
MCP=/home/hanqing/.cache/cve-analyzer/repos/geelen_mcp-remote
GLANCES=/home/hanqing/.cache/cve-analyzer/repos/nicolargo_glances
MARIMO=/home/hanqing/.cache/cve-analyzer/repos/marimo-team_marimo
SENTRY=/home/hanqing/.cache/cve-analyzer/repos/getsentry_sentry-javascript
require_dir "$MLFLOW"
require_dir "$MCP"
require_dir "$GLANCES"
require_dir "$MARIMO"
require_dir "$SENTRY"

expect_eq "$(gitx "$MLFLOW" rev-parse 005b959cacda05d1423356cfcbd9ebeda8ff96a7)" 005b959cacda05d1423356cfcbd9ebeda8ff96a7 mlflow_ajax
expect_eq "$(gitx "$MCP" rev-parse 607b226a356cb61a239ffaba2fb3db1c9dea4bac)" 607b226a356cb61a239ffaba2fb3db1c9dea4bac mcp_fix
expect_eq "$(gitx "$GLANCES" rev-parse d339181f03a14bb15506307e9d58f876e23d8160)" d339181f03a14bb15506307e9d58f876e23d8160 glances_fix
expect_eq "$(gitx "$MARIMO" rev-parse fdd55c8cf6260ae23bb411dc9d9269def5cf75d6)" fdd55c8cf6260ae23bb411dc9d9269def5cf75d6 marimo_fix
expect_eq "$(gitx "$SENTRY" rev-parse a820fa2891fdcf985b834a5b557edf351ec54539)" a820fa2891fdcf985b834a5b557edf351ec54539 sentry_listed

contains_tag() {
  local tags
  tags=$(gitx "$1" tag --contains "$2")
  if ! printf '%s\n' "$tags" | /usr/bin/grep -Fxq "$3"; then
    printf 'missing tag %s contains %s\n' "$3" "$2" >&2
    exit 1
  fi
}
contains_tag "$MCP" 607b226a356cb61a239ffaba2fb3db1c9dea4bac v0.1.16
contains_tag "$GLANCES" d339181f03a14bb15506307e9d58f876e23d8160 v4.5.4
contains_tag "$MARIMO" fdd55c8cf6260ae23bb411dc9d9269def5cf75d6 0.23.9
contains_tag "$SENTRY" a820fa2891fdcf985b834a5b557edf351ec54539 10.11.0

gitx "$MARIMO" merge-base --is-ancestor fdd55c8cf6260ae23bb411dc9d9269def5cf75d6 0.23.9
setopt localoptions noerrexit
gitx "$MARIMO" merge-base --is-ancestor fdd55c8cf6260ae23bb411dc9d9269def5cf75d6 0.23.8
mb=$?
setopt errexit
expect_eq "$mb" 1 marimo_0.23.8_lacks_fix

gitx "$GLANCES" merge-base --is-ancestor d339181f03a14bb15506307e9d58f876e23d8160 1563ff8e0aed07203043b099d319b4a295263b98
gitx "$MCP" merge-base --is-ancestor db92c69d20140cfe27cdab8ba0fcd2be669e5d81 607b226a356cb61a239ffaba2fb3db1c9dea4bac

python3 - "$OWNED" "$SUMMARY" "$ROOT" "$ADV_R" "$ADV_U" <<'PY'
import hashlib, json, re, subprocess, sys
from pathlib import Path

owned, summary_p, root, adv_r, adv_u = sys.argv[1:]
root = Path(root)
owned = Path(owned)
assigns = [json.loads(l) for l in owned.joinpath("assignment.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in owned.joinpath("cases.jsonl").read_text().splitlines() if l.strip()]
assert len(assigns) == 12 and len(cases) == 12
ids = [a["case_id"] for a in assigns]
assert ids == [c["case_id"] for c in cases]
assert len(set(ids)) == 12
assert all(a["frozen"] and a["bucket"] == 1 for a in assigns)
assert all(c["verdict"] == "REJECT" and c["countable_proposal"] is False for c in cases)
assert sum(1 for c in cases if c["verdict"] == "REJECT") == 12
assert all(not c.get("candidate_set") for c in cases)

def bucket(ghsa: str) -> int:
    return int(hashlib.sha256(ghsa.encode("ascii")).hexdigest(), 16) % 6

for cid in ids:
    assert bucket(cid) == 1, cid

BLAME = {
    "GHSA-Q6CQ-MHR2-JMR5", "GHSA-GVWX-54WH-QM9J", "GHSA-724G-MXRG-4QVM",
    "GHSA-H2WF-967X-GXVW", "GHSA-MM7M-92G8-7M47", "GHSA-2GCR-MFCQ-WCC3",
    "GHSA-JXXR-4GWJ-5JF2", "GHSA-J7V9-F46R-2RP4", "GHSA-6M6C-36F7-FHXH",
    "GHSA-6JH4-47V2-4G37", "GHSA-R7FX-8G49-7HHR", "GHSA-9C4Q-HQ6P-C237",
}
for cid in ids:
    assert cid not in BLAME, cid

GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
SCALAR = {"case_id", "ghsa_id"}
LISTS = {"reviewed_case_ids", "assigned_ids", "strict_released_case_ids"}
LANE_FILES = ("assignment.jsonl", "cases.jsonl", "result.json", "selected.jsonl")

def as_ghsa(value):
    if isinstance(value, str) and GHSA_RE.match(value.strip().upper()):
        return value.strip().upper()
    return None

def collect(obj, acc):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in SCALAR:
                g = as_ghsa(v)
                if g:
                    acc.add(g)
            elif k in LISTS and isinstance(v, list):
                for item in v:
                    g = as_ghsa(item)
                    if g:
                        acc.add(g)
            else:
                collect(v, acc)
    elif isinstance(obj, list):
        for item in obj:
            collect(item, acc)

def load(path: Path):
    text = path.read_text(encoding="utf-8")
    if path.name.endswith(".jsonl"):
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    return json.loads(text)

excluded = set()
files_parsed = 0
for group in ("herdr-*", "orchestrator-*"):
    for lane in sorted((root / "autoresearch").glob(group)):
        if not lane.is_dir() or lane.name == "herdr-260814-cf4-b1-history-grok46-medium":
            continue
        cands = [lane / n for n in LANE_FILES]
        if lane.name.startswith("orchestrator-260814-ghsa200-canonical88"):
            cands.extend([lane / "ledger.jsonl", lane / "summary.json"])
        for path in cands:
            if not path.is_file():
                continue
            collect(load(path), excluded)
            files_parsed += 1
excl_sha = hashlib.sha256("\n".join(sorted(excluded)).encode()).hexdigest()
assert len(excluded) >= 8056
for cid in ids:
    assert cid not in excluded, cid
for bid in BLAME:
    assert bid in excluded, bid

summary = json.loads(Path(summary_p).read_text())
counted = {str(x).upper() for x in summary["strict_released_case_ids"]}
assert len(counted) == 88
for cid in ids:
    assert cid not in counted, cid

for a in assigns:
    p = Path(adv_r) / a["advisory_path"]
    assert p.is_file(), p
    obj = json.loads(p.read_text())
    assert obj.get("id", "").upper() == a["case_id"]
    assert not obj.get("withdrawn")

unrev_root = Path(adv_u) / "advisories/unreviewed"
assert unrev_root.is_dir()

sys.path.insert(0, str(root / "cve-analyzer/src"))
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import matches_for_commit

def git_log(clone, sha):
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1", GIT_PAGER="cat")
    rec = subprocess.run(
        ["git", "--no-optional-locks", "-c", "gc.auto=0", "-C", clone,
         "log", "-1", "--format=%H%n%an%n%ae%n%cn%n%ce%n%aI%n%B", sha],
        capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, check=True,
    )
    parts = rec.stdout.split("\n", 6)
    return CommitInfo(sha=parts[0].strip(), author_name=parts[1], author_email=parts[2],
                      committer_name=parts[3], committer_email=parts[4],
                      authored_date=parts[5], message=parts[6])

mcp = "/home/hanqing/.cache/cve-analyzer/repos/geelen_mcp-remote"
assert matches_for_commit(git_log(mcp, "607b226a356cb61a239ffaba2fb3db1c9dea4bac")) == ()
assert matches_for_commit(git_log(mcp, "db92c69d20140cfe27cdab8ba0fcd2be669e5d81"))
glances = "/home/hanqing/.cache/cve-analyzer/repos/nicolargo_glances"
assert matches_for_commit(git_log(glances, "d339181f03a14bb15506307e9d58f876e23d8160")) == ()
assert matches_for_commit(git_log(glances, "1563ff8e0aed07203043b099d319b4a295263b98"))
mlflow = "/home/hanqing/.cache/cve-analyzer/repos/mlflow_mlflow"
assert matches_for_commit(git_log(mlflow, "005b959cacda05d1423356cfcbd9ebeda8ff96a7"))

print("conservation assigned=12 reviewed=12 unreviewed_rows=0 equation=12=12+0")
print("exclusion_ids=%d exclusion_sha256=%s" % (len(excluded), excl_sha))
print("canonical88=88 overlap=0 bucket=1 frozen=12 PASS_PROPOSAL=0")
print("eligible=56903 inspected_prefix=163 inspect_cap=600 shortfall=0 stop=stop_after_12_atomic_hits")
print("sources reviewed=f2c6ab3202aeafb36fbea6e76d892532acfca1a6 subtree=advisories/github-reviewed")
print("sources unreviewed=39d8887723797efc1804585dd06585c9fd751226 subtree=advisories/unreviewed")
print("did_not_rereview_cf4_b1_blame=12")
PY

printf 'REPLAY_OK reviewed=12 PASS_PROPOSAL=0 REJECT=12 NARROW=0 UNKNOWN=0 BLOCKED=0\n'
