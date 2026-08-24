#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-cf4-b3-history-grok46-xhigh.
# English only. No credentials. No clone/fetch/commit/push. Shared caches read-only.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat
export PYTHONPATH=/home/hanqing/agents/ai-slop/cve-analyzer/src

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-cf4-b3-history-grok46-xhigh
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json
ADV_R=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
ADV_U=/home/hanqing/.cache/cve-analyzer/advisory-database
HEAD_R=f2c6ab3202aeafb36fbea6e76d892532acfca1a6
HEAD_U=39d8887723797efc1804585dd06585c9fd751226
ML=/home/hanqing/.cache/cve-analyzer/repos/mlflow_mlflow
CAND=3094ab608b1d91bff5830d5a89aa042ccd3c9acc
FIX=64aa0ab7207f9c649b59ba1a5f40d82196817389
PARENT=4a724addefd1950a43b62eb4c89894b4e75e01c6

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
  errf=$(mktemp /tmp/cf4-b3-hist-giterr.XXXXXX)
  setopt localoptions noerrexit
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  rc=$?
  if [[ -s $errf ]]; then
    /usr/bin/grep -vE 'unable to normalize alternate object path|lazy fetching disabled|current branch .* does not have any commits yet' "$errf" >&2 || true
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

require_absent() {
  if [[ -e $1 ]]; then
    printf 'must be absent: %s\n' "$1" >&2
    exit 1
  fi
}

require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/result.json"
require_file "$OWNED/report.md"
require_file "$OWNED/replay.zsh"
require_file "$CONTRACT"
require_file "$LEDGER"
require_file "$SUMMARY"
require_dir "$ADV_R/advisories/github-reviewed"
require_dir "$ADV_U/advisories/unreviewed"
require_absent "$ADV_R/advisories/unreviewed"
require_absent "$OWNED/work"
require_absent "$OWNED/notes"
require_absent "$OWNED/pages"
require_absent "$OWNED/clones"
require_dir "$ML"

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
expect_hash "$SUMMARY" 81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921

rh=$(gitx "$ADV_R" rev-parse HEAD)
uh=$(gitx "$ADV_U" rev-parse HEAD)
expect_eq "$rh" "$HEAD_R" reviewed_head
expect_eq "$uh" "$HEAD_U" unreviewed_head

n_assign=$(/usr/bin/wc -l < "$OWNED/assignment.jsonl" | /usr/bin/tr -d ' ')
n_cases=$(/usr/bin/wc -l < "$OWNED/cases.jsonl" | /usr/bin/tr -d ' ')
expect_eq "$n_assign" 1 assignment_rows
expect_eq "$n_cases" 1 cases_rows

n_owned=$(/usr/bin/ls -1 "$OWNED" | /usr/bin/wc -l | /usr/bin/tr -d ' ')
expect_eq "$n_owned" 5 owned_file_count

require_file "$ADV_R/advisories/github-reviewed/2026/05/GHSA-65h7-c7c4-mghx/GHSA-65h7-c7c4-mghx.json"
require_absent "$ADV_R/advisories/unreviewed/2026/05/GHSA-65h7-c7c4-mghx/GHSA-65h7-c7c4-mghx.json"

python3 - "$OWNED" "$SUMMARY" "$ROOT" "$ADV_R" "$ADV_U" "$ML" "$CAND" "$FIX" "$PARENT" <<'PY'
import hashlib, json, os, re, subprocess, sys
from pathlib import Path

owned, summary_p, root, adv_r, adv_u, ml, cand, fix, parent = sys.argv[1:]
root = Path(root)
owned = Path(owned)
adv_r = Path(adv_r)
adv_u = Path(adv_u)
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(r"ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}")
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
ID_FIELDS = {"case_id", "ghsa_id", "reviewed_case_ids", "assigned_ids", "strict_released_case_ids"}
ARTIFACT_NAMES = {
    "assignment.jsonl", "cases.jsonl", "result.json", "selected.jsonl",
    "queue.jsonl", "ledger.jsonl", "summary.json",
}
SKIP_DIR_PARTS = {"work", "notes", "pages", "snapshot", "clones", "cache", "tmp"}
OWNED_NAME = "herdr-260814-cf4-b3-history-grok46-xhigh"
GATES = [
    "identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate",
    "fix_reversal_gate", "release_gate", "uniqueness_gate",
]
FROZEN = ["GHSA-65H7-C7C4-MGHX"]
TOPOLOGY = {
    "GHSA-MG56-WC4Q-RW4W", "GHSA-6556-FWC2-FG2P", "GHSA-VV6J-3G6G-2PVJ",
    "GHSA-JJJJ-JWHF-8RGR", "GHSA-FGHV-69VJ-QJ49", "GHSA-4HR2-XF7W-JF76",
    "GHSA-FPJQ-C37H-CQCV", "GHSA-XJ37-QJG2-XWV2", "GHSA-X3HX-CH7P-8XGG",
    "GHSA-PW7P-7FQV-HPJ8", "GHSA-XH5W-G8GQ-R3V9", "GHSA-PWFC-QM9R-P6H4",
}

def load_jsonl(p):
    return [json.loads(l) for l in Path(p).read_text().splitlines() if l.strip()]

for name in ("assignment.jsonl", "cases.jsonl", "result.json", "report.md", "replay.zsh"):
    raw = (owned / name).read_text(encoding="utf-8")
    assert raw.endswith("\n") and raw.isascii()
    assert not han.search(raw) and not secret.search(raw)
    for line in raw.splitlines():
        assert line == line.rstrip(" \t")

names = sorted(p.name for p in owned.iterdir())
assert names == ["assignment.jsonl", "cases.jsonl", "replay.zsh", "report.md", "result.json"]

assign = load_jsonl(owned / "assignment.jsonl")
cases = load_jsonl(owned / "cases.jsonl")
result = json.loads((owned / "result.json").read_text())
assert len(assign) == 1 and len(cases) == 1
ids = [r["case_id"] for r in assign]
assert ids == [r["case_id"] for r in cases] == FROZEN
assert len(set(ids)) == 1
assert all(a.get("hypothesis_not_verdict") is True for a in assign)
assert all(a.get("frozen") is True and a.get("bucket") == 3 for a in assign)

def bucket(ghsa: str) -> int:
    return int(hashlib.sha256(ghsa.upper().encode("ascii")).hexdigest(), 16) % 6

for cid in ids:
    assert bucket(cid) == 3, cid

assert result["conservation"]["equation"] == "1=1+0"
assert result["conservation"]["assigned"] == 1
assert result["conservation"]["reviewed"] == 1
assert result["conservation"]["unreviewed"] == 0
assert result["conservation"]["did_not_pad"] is True
assert result["counts"]["PASS_PROPOSAL"] == 0
assert result["PASS_PROPOSAL"] == []
assert result["terminal"] is True
assert result["canonical88_overlap"] == []
assert result["cve_aliases_counted"] is False
assert result["packet_delta"] == 0
assert result["seven_gates_exact_pass_required"] is True
assert result["canonical_ledger_edited"] is False
assert result["bound"]["eligible"] == 57437
assert result["bound"]["inspected_prefix"] == 600
assert result["bound"]["max_inspect"] == 600
assert result["bound"]["stop_rule"] == "prefix_exhausted"
assert result["bound"]["hits"] == 1
assert result["bound"]["shortfall"] == 11
assert result["bound"]["walk_n"] == 200
assert result["advisory_database"]["github_reviewed"]["head"] == "f2c6ab3202aeafb36fbea6e76d892532acfca1a6"
assert result["advisory_database"]["github_reviewed"]["subtree"] == "advisories/github-reviewed"
assert result["advisory_database"]["unreviewed"]["head"] == "39d8887723797efc1804585dd06585c9fd751226"
assert result["advisory_database"]["unreviewed"]["subtree"] == "advisories/unreviewed"
assert result["per_case"]["GHSA-65H7-C7C4-MGHX"] == "NARROW"
assert result["counts"]["NARROW"] == 1
assert result["counts"]["REJECT"] == 0
assert result["counts"]["PASS"] == 0
assert "0 PASS_PROPOSAL" in (owned / "report.md").read_text()
ah = result["artifact_hashes"]
for name in ("assignment.jsonl", "cases.jsonl", "report.md", "replay.zsh"):
    got = hashlib.sha256((owned / name).read_bytes()).hexdigest()
    assert got == ah[name], (name, got, ah[name])
assert "result.json" not in ah

summary = json.loads(Path(summary_p).read_text())
strict = {str(x).upper() for x in summary["strict_released_case_ids"]}
assert len(strict) == 88
assert set(ids).isdisjoint(strict)
assert set(ids).isdisjoint(TOPOLOGY)

for r in cases:
    g = r["gates"]
    assert all(k in g for k in GATES)
    assert r["seven_gates_exact_pass"] is False
    assert r["countable_proposal"] is False
    assert r["authorship_transfer_from_member_to_carrier"] is False
    assert r["in_canonical88_strict"] is False
    if r["verdict"] == "PASS":
        raise SystemExit("unexpected PASS")
    assert bucket(r["case_id"]) == 3
    assert r["verdict"] == "NARROW"

assert assign[0]["advisory_source"] == "f2c6_github-reviewed"
assert assign[0]["github_reviewed"] is True
p = adv_r / assign[0]["advisory_path"]
assert p.is_file(), p
obj = json.loads(p.read_text())
assert obj.get("id", "").upper() == assign[0]["case_id"]
assert not obj.get("withdrawn")
assert (obj.get("database_specific") or {}).get("github_reviewed") is True

def collect_ids(obj, acc, in_field=False):
    if isinstance(obj, dict):
        for k, v in obj.items():
            collect_ids(v, acc, in_field or k in ID_FIELDS)
    elif isinstance(obj, list):
        for x in obj:
            collect_ids(x, acc, in_field)
    elif in_field and isinstance(obj, str):
        s = obj.strip().upper()
        if GHSA_RE.match(s):
            acc.add(s)

excluded = set()
auto = root / "autoresearch"
for path in auto.rglob("*"):
    if not path.is_file() or path.name not in ARTIFACT_NAMES:
        continue
    if SKIP_DIR_PARTS & set(path.parts):
        continue
    if OWNED_NAME in path.parts:
        continue
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        continue
    if path.suffix == ".jsonl":
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                collect_ids(json.loads(line), excluded)
            except Exception:
                continue
    else:
        try:
            collect_ids(json.loads(text), excluded)
        except Exception:
            continue
assert TOPOLOGY <= excluded
assert not (set(ids) & excluded), sorted(set(ids) & excluded)

for lane in sorted((root / "autoresearch").glob("herdr-260814-cf4-*")):
    if lane.name == OWNED_NAME:
        continue
    rj_path = lane / "result.json"
    aj_path = lane / "assignment.jsonl"
    if not (rj_path.is_file() and aj_path.is_file()):
        continue
    try:
        rj = json.loads(rj_path.read_text())
    except Exception:
        continue
    if not (rj.get("terminal") is True or str(rj.get("status", "")).upper().startswith("TERMINAL")):
        continue
    sib = {json.loads(l)["case_id"].upper() for l in aj_path.read_text().splitlines() if l.strip()}
    assert set(ids).isdisjoint(sib), sorted(set(ids) & sib)

env = dict(os.environ)
env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1", GIT_PAGER="cat")

def git(repo, *args):
    r = subprocess.run(
        ["git", "--no-optional-locks", "-c", "gc.auto=0", "-C", repo, *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
    )
    for line in (r.stderr or "").splitlines():
        if not line:
            continue
        if "unable to normalize alternate object path" in line:
            continue
        if "lazy fetching disabled" in line:
            continue
        if "current branch" in line and "does not have any commits yet" in line:
            continue
        if "git cat-file: could not get object info" in line:
            continue
        if "does not exist" in line:
            continue
        if "Not a valid object name" in line:
            continue
        raise SystemExit(line)
    return r

def peel(repo, tag):
    r = git(repo, "rev-parse", f"{tag}^{{commit}}")
    assert r.returncode == 0, (repo, tag, r.stderr)
    return r.stdout.strip()

def n_parents(repo, sha):
    r = git(repo, "rev-list", "--parents", "-n1", sha)
    return len(r.stdout.split()) - 1

assert peel(ml, "v3.2.0") == "e1de6be10b4044f4b4a493ae9dabc3e6827ad41e"
assert peel(ml, "v3.3.0") == "f2266fa9f4583612aa1eb0ca9b63046f12153ce1"
assert peel(ml, "v3.8.1") == "4cc9d5bd7cd1962f7f34017e8d8f133f89ad8d69"
assert peel(ml, "v3.9.0") == "cf3d582a7b8a6f234e4d28ef6987bb8076c6ee54"
assert peel(ml, "v3.10.0") == "d0b97413e383796f1ca742b20cac74543185816c"
assert peel(ml, "v3.11.1") == "09179c65741c4d40df2e934950e32f526a2c0e9e"
assert n_parents(ml, cand) == 1
assert n_parents(ml, fix) == 1
assert git(ml, "rev-parse", f"{cand}^").stdout.strip() == parent
assert git(ml, "merge-base", "--is-ancestor", cand, fix).returncode == 0
assert git(ml, "merge-base", "--is-ancestor", cand, "v3.3.0").returncode == 0
assert git(ml, "merge-base", "--is-ancestor", cand, "v3.2.0").returncode == 1
assert git(ml, "merge-base", "--is-ancestor", cand, "v3.8.1").returncode == 0
assert git(ml, "merge-base", "--is-ancestor", fix, "v3.8.1").returncode == 1
assert git(ml, "merge-base", "--is-ancestor", fix, "v3.9.0").returncode == 1
assert git(ml, "merge-base", "--is-ancestor", fix, "v3.10.0").returncode == 1
assert git(ml, "merge-base", "--is-ancestor", fix, "v3.11.1").returncode == 0
assert git(ml, "cat-file", "-e", f"{parent}:mlflow/webhooks/delivery.py").returncode != 0
assert git(ml, "cat-file", "-e", f"{cand}:mlflow/webhooks/delivery.py").returncode == 0
assert git(ml, "log", "-1", "--format=%an", cand).stdout.strip() == "Harutaka Kawamura"
assert git(ml, "log", "-1", "--format=%an", fix).stdout.strip() == "TomuHirata"
body = git(ml, "log", "-1", "--format=%B", cand).stdout
assert "Co-authored-by: Claude <noreply@anthropic.com>" in body
d_cand = git(ml, "show", f"{cand}:mlflow/utils/validation.py").stdout
assert "def _validate_webhook_url" in d_cand
assert "is_global" not in d_cand
d_fix = git(ml, "show", f"{fix}:mlflow/utils/validation.py").stdout
assert "is_global" in d_fix
d_390 = git(ml, "show", "v3.9.0:mlflow/utils/validation.py").stdout
assert "def _validate_webhook_url" in d_390
assert "is_global" not in d_390
deliv_fix = git(ml, "show", f"{fix}:mlflow/webhooks/delivery.py").stdout
assert "_validate_webhook_url(webhook.url)" in deliv_fix
deliv_cand = git(ml, "show", f"{cand}:mlflow/webhooks/delivery.py").stdout
assert "_validate_webhook_url(webhook.url)" not in deliv_cand
assert "def _send_webhook_request" in deliv_cand
nfiles = len([ln for ln in git(ml, "diff-tree", "--no-commit-id", "-r", "--name-only", cand).stdout.splitlines() if ln])
assert nfiles == 41, nfiles

sys.path.insert(0, str(root / "cve-analyzer/src"))
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit

def git_log(clone, sha):
    rec = git(clone, "log", "-1", "--format=%H%n%an%n%ae%n%cn%n%ce%n%aI%n%B", sha)
    assert rec.returncode == 0
    parts = rec.stdout.split("\n", 6)
    return CommitInfo(
        sha=parts[0].strip(), author_name=parts[1], author_email=parts[2],
        committer_name=parts[3], committer_email=parts[4],
        authored_date=parts[5], message=parts[6],
    )

assert MATCHER_CONTRACT.startswith("ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1")
assert matches_for_commit(git_log(ml, cand))
assert matches_for_commit(git_log(ml, fix)) == ()

print("conservation assigned=1 reviewed=1 unreviewed=0 equation=1=1+0")
print("canonical88=88 overlap=0 bucket=3 frozen=1 PASS_PROPOSAL=0 NARROW=1 REJECT=0")
print("bound eligible=57437 inspected_prefix=600 stop_rule=prefix_exhausted hits=1 shortfall=11")
print("sources reviewed=f2c6ab3202aeafb36fbea6e76d892532acfca1a6 subtree=advisories/github-reviewed")
print("sources unreviewed=39d8887723797efc1804585dd06585c9fd751226 subtree=advisories/unreviewed")
print("union_collisions_f2c6_wins=135 topology_excluded=12")
PY

printf 'REPLAY_OK inspected=600 PASS_PROPOSAL=0 conservation=1=1+0\n'
