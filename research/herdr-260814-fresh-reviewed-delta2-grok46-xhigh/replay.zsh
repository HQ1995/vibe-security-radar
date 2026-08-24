#!/usr/bin/env zsh
# Fail-closed replay for herdr-260814-fresh-reviewed-delta2-grok46-xhigh.
# English ASCII only. Does not clone, fetch, commit, or push. Shared caches read-only.
# Does not walk other workers. Exclusion IDs are frozen in result.json.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat
export PYTHONPATH=/home/hanqing/agents/ai-slop/cve-analyzer/src

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-fresh-reviewed-delta2-grok46-xhigh
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/summary.json
LAYERS=$ROOT/docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md
ADV_N=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
ADV_O=/home/hanqing/.cache/cve-analyzer/advisory-database
HEAD_N=f2c6ab3202aeafb36fbea6e76d892532acfca1a6
HEAD_O=39d8887723797efc1804585dd06585c9fd751226
ADDED_H=d2e0f08843dedcd6a62e067a4b8ac3530c1998d8ac528d7097a7437d1244a6a8
REMOVED_H=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
EXCL_H=ea5500ebc1bd96e9d9da765c49afea9e7c403a5b026dd3f0b69cc9a0c9461f22
TREE_N=3308b2f6c73929d3854bd12908e996787a8bb0c8
TREE_O=3a1267e940595e82f109a750f2779d987ff4d01b
NUXT=/home/hanqing/.cache/cve-analyzer/repos/nuxt_nuxt
NETTY=/home/hanqing/.cache/cve-analyzer/repos/netty_netty
MCP=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/modelcontextprotocol__ruby-sdk
HONO=/home/hanqing/.cache/cve-analyzer/repos/honojs_hono
NX=/home/hanqing/.cache/cve-analyzer/repos/nrwl_nx
GUZZLE=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/guzzle__guzzle

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
  errf=$(mktemp /tmp/fresh-reviewed-delta2-giterr.XXXXXX)
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
require_file "$LAYERS"
require_dir "$ADV_N/advisories/github-reviewed"
require_dir "$ADV_O/advisories/github-reviewed"
require_absent "$OWNED/work"
require_absent "$OWNED/notes"
require_absent "$OWNED/pages"
require_absent "$OWNED/clones"
require_absent /tmp/herdr-260814-fresh-reviewed-delta2-grok46-xhigh

n_owned=$(/usr/bin/ls -1 "$OWNED" | /usr/bin/wc -l | /usr/bin/tr -d ' ')
expect_eq "$n_owned" 5 owned_file_count

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LAYERS" 70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f
expect_hash "$LEDGER" 70b7658fadf41f18c72734a2006601961a2180681bf81353373bccab95ff659e
expect_hash "$SUMMARY" ab47f927a20f374a9b0e3253a1a5a0778e355dda9414189927022325d81ad86f

nh=$(gitx "$ADV_N" rev-parse HEAD)
oh=$(gitx "$ADV_O" rev-parse HEAD)
expect_eq "$nh" "$HEAD_N" new_head
expect_eq "$oh" "$HEAD_O" old_head

nt=$(gitx "$ADV_N" rev-parse "$HEAD_N":advisories/github-reviewed)
ot=$(gitx "$ADV_O" rev-parse "$HEAD_O":advisories/github-reviewed)
expect_eq "$nt" "$TREE_N" new_reviewed_tree
expect_eq "$ot" "$TREE_O" old_reviewed_tree

n_assign=$(/usr/bin/wc -l < "$OWNED/assignment.jsonl" | /usr/bin/tr -d ' ')
n_cases=$(/usr/bin/wc -l < "$OWNED/cases.jsonl" | /usr/bin/tr -d ' ')
expect_eq "$n_assign" 0 assignment_rows
expect_eq "$n_cases" 0 cases_rows

python3 - "$OWNED" "$SUMMARY" "$ROOT" "$ADV_N" "$ADV_O" "$NUXT" "$NETTY" "$MCP" "$HONO" "$NX" "$GUZZLE" "$ADDED_H" "$REMOVED_H" "$EXCL_H" "$HEAD_N" "$HEAD_O" <<'PY'
import hashlib, json, os, re, subprocess, sys
from pathlib import Path

(owned, summary_p, root, adv_n, adv_o, nuxt, netty, mcp, hono, nx, guzzle,
 added_h, removed_h, excl_h, head_n, head_o) = sys.argv[1:]
owned = Path(owned)
root = Path(root)
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(r"ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}")
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
GHSA_PATH = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.I)
COMMIT_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/commit(?:s)?/([0-9a-fA-F]{40})")
ADV_RE = re.compile(
    r"github\.com/([^/]+)/([^/]+)/security/advisories/"
    r"(GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4})",
    re.I,
)
REPO_RE = re.compile(r"github\.com/([^/]+)/([^/#?]+)")
SKIP_OWNERS = {
    x.lower()
    for x in [
        "advisories", "github", "security-advisories", "sponsors",
        "nvd", "CVEProject", "github-community",
    ]
}
SKIP_REPOS = {"advisory-database", "advisories"}
C91_OVERLAP = {
    "GHSA-3RP5-JJMW-4WV2", "GHSA-539M-9XH6-Q6RR", "GHSA-7P8R-X3MC-P8W7",
    "GHSA-8359-H9FX-J6V9", "GHSA-FRVJ-C5QP-XJ4W", "GHSA-GH4H-34GR-87R7",
    "GHSA-HC8V-WWC9-VGXM", "GHSA-JM78-9FVV-MHGR", "GHSA-PFVM-W89X-94JW",
    "GHSA-PQH8-P93P-2RX7", "GHSA-QF5V-M7P4-95RP", "GHSA-R9MR-M37C-5FR3",
    "GHSA-W28W-GP39-M4P6",
}
env = dict(os.environ)
env.update(
    GIT_OPTIONAL_LOCKS="0",
    GIT_TERMINAL_PROMPT="0",
    GIT_NO_LAZY_FETCH="1",
    GIT_PAGER="cat",
)

def load_jsonl(path):
    text = Path(path).read_text()
    return [json.loads(l) for l in text.splitlines() if l.strip()]

for name in ("assignment.jsonl", "cases.jsonl", "result.json", "report.md", "replay.zsh"):
    raw = (owned / name).read_bytes()
    if name.endswith(".jsonl") and raw == b"":
        continue
    text = raw.decode("ascii")
    assert text.endswith("\n"), name
    assert text.isascii(), name
    assert not han.search(text) and not secret.search(text)
    for line in text.splitlines():
        assert line == line.rstrip(" \t")

names = sorted(p.name for p in owned.iterdir())
assert names == [
    "assignment.jsonl", "cases.jsonl", "replay.zsh", "report.md", "result.json",
]
assign = load_jsonl(owned / "assignment.jsonl")
cases = load_jsonl(owned / "cases.jsonl")
result = json.loads((owned / "result.json").read_text())
assert assign == [] and cases == []
assert result["conservation"]["equation"] == "0=0+0"
assert result["conservation"]["assigned"] == 0
assert result["conservation"]["reviewed"] == 0
assert result["conservation"]["unreviewed"] == 0
assert result["conservation"]["did_not_pad"] is True
assert result["counts"]["PASS_PROPOSAL"] == 0
assert result["counts"]["inspected"] == 0
assert result["counts"]["assigned"] == 0
assert result["PASS_PROPOSAL"] == []
assert result["pass_proposal_ids"] == []
assert result["terminal"] is True
assert result["advisory_database"]["new_head"] == head_n
assert result["advisory_database"]["old_head"] == head_o
assert result["advisory_database"]["added_reviewed"] == 743
assert result["advisory_database"]["removed_reviewed"] == 0
assert result["advisory_database"]["added_sha256"] == added_h
assert result["advisory_database"]["removed_sha256"] == removed_h
assert result["exclusion"]["n"] == 8201
assert result["exclusion"]["sha256"] == excl_h
assert result["exclusion"]["live_glob_in_replay"] is False
assert result["canonical91_overlap_added"] == sorted(C91_OVERLAP)
assert result["cve_aliases_counted"] is False
assert result["packet_delta"] == 0
assert result["seven_gates_exact_pass_required"] is True
assert result["canonical_ledger_edited"] is False
assert result["bound"]["inspected"] == 0
assert result["bound"]["max_inspect"] == 12
assert result["bound"]["did_not_pad"] is True
assert result["ai_on_fix_is_not_strict_pass"] is True
assert result["remediation_as_origin_fails_closed"] is True
assert result["marker_transfer_fails_closed"] is True
assert result["missing_release_containment_fails_closed"] is True
assert result["duplicates_fail_closed"] is True
assert "0 PASS_PROPOSAL" in (owned / "report.md").read_text()
assert "Did not pad" in (owned / "report.md").read_text()
ah = result["artifact_hashes"]
for name in ("assignment.jsonl", "cases.jsonl", "report.md", "replay.zsh"):
    got = hashlib.sha256((owned / name).read_bytes()).hexdigest()
    assert got == ah[name], (name, got, ah[name])
assert "result.json" not in ah

summary = json.loads(Path(summary_p).read_text())
strict = {str(x).upper() for x in summary["strict_released_case_ids"]}
assert len(strict) == 91
for x in strict:
    assert GHSA_RE.fullmatch(x), x

excl_ids = result["exclusion"]["ids"]
assert len(excl_ids) == 8201
assert excl_ids == sorted(excl_ids)
assert all(GHSA_RE.fullmatch(x) for x in excl_ids)
got = hashlib.sha256(("\n".join(excl_ids) + "\n").encode("ascii")).hexdigest()
assert got == excl_h
assert strict <= set(excl_ids)

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
        raise SystemExit(line)
    return r

def ids_and_paths(repo, spec):
    r = git(repo, "ls-tree", "-r", "--name-only", spec)
    assert r.returncode == 0, r.stderr
    ids = set()
    paths = {}
    for line in r.stdout.splitlines():
        m = GHSA_PATH.search(line)
        if m:
            gid = m.group(0).upper()
            ids.add(gid)
            paths[gid] = line
    return ids, paths

new, new_paths = ids_and_paths(adv_n, head_n + ":advisories/github-reviewed")
old, _ = ids_and_paths(adv_o, head_o + ":advisories/github-reviewed")
added = sorted(new - old)
removed = sorted(old - new)
assert len(new) == 34389 and len(old) == 33646
assert len(added) == 743 and removed == []
assert hashlib.sha256(("\n".join(added) + "\n").encode("ascii")).hexdigest() == added_h
assert hashlib.sha256(b"").hexdigest() == removed_h
remaining = sorted(set(added) - set(excl_ids))
assert remaining == result["screen"]["remaining_ids"]
assert len(remaining) == 76
assert sorted(set(added) & strict) == sorted(C91_OVERLAP)
assert set(result["screen"]["eligible_ids"]).isdisjoint(strict)
assert set(result["screen"]["eligible_ids"]).isdisjoint(set(excl_ids))

def parse_one(gid):
    rel = new_paths[gid]
    p = Path(adv_n) / "advisories/github-reviewed" / rel
    obj = json.loads(p.read_text())
    urls = [x.get("url") for x in (obj.get("references") or []) if x.get("url")]
    commits = False
    repos = False
    fp = False
    for u in urls:
        m = COMMIT_RE.search(u or "")
        if m and m.group(1).lower() not in SKIP_OWNERS and m.group(2).lower() not in SKIP_REPOS:
            commits = True
        m = ADV_RE.search(u or "")
        if m and m.group(3).upper() == gid:
            fp = True
        m = REPO_RE.search(u or "")
        if m:
            owner = m.group(1)
            repo = m.group(2).removesuffix(".git")
            if owner.lower() not in SKIP_OWNERS and repo.lower() not in SKIP_REPOS:
                repos = True
    db = obj.get("database_specific") or {}
    return {
        "withdrawn": bool(obj.get("withdrawn")),
        "github_reviewed": bool(db.get("github_reviewed")),
        "affected_n": len(obj.get("affected") or []),
        "exact_fix": commits,
        "has_github_repo": repos,
        "fp": fp,
    }

elig = []
fp_elig = []
for gid in remaining:
    rec = parse_one(gid)
    if (
        rec["github_reviewed"]
        and not rec["withdrawn"]
        and rec["has_github_repo"]
        and rec["exact_fix"]
        and rec["affected_n"] > 0
    ):
        elig.append(gid)
        if rec["fp"]:
            fp_elig.append(gid)
assert sorted(elig) == result["screen"]["eligible_ids"]
assert sorted(fp_elig) == result["screen"]["first_party_repo_advisory_eligible_ids"]
assert len(elig) == 31 and len(fp_elig) == 19
assert result["screen"]["plausible_ai_origin"] == 0
assert result["bound"]["eligible_after_rank"] == 0

sys.path.insert(0, str(root / "cve-analyzer/src"))
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit
assert MATCHER_CONTRACT.startswith(
    "ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1"
)
assert result["source_matcher_contract"] == MATCHER_CONTRACT

def ci(repo, sha):
    rec = git(repo, "log", "-1", "--format=%H%n%an%n%ae%n%cn%n%ce%n%aI%n%B", sha)
    assert rec.returncode == 0, (repo, sha, rec.stderr)
    parts = rec.stdout.split("\n", 6)
    while len(parts) < 7:
        parts.append("")
    return CommitInfo(
        sha=parts[0].strip(), author_name=parts[1], author_email=parts[2],
        committer_name=parts[3], committer_email=parts[4],
        authored_date=parts[5], message=parts[6],
    )

def npar(repo, sha):
    r = git(repo, "rev-list", "--parents", "-n1", sha)
    return len(r.stdout.split()) - 1

checks = []
if Path(nuxt).exists():
    checks += [
        (nuxt, "00f71bb6517abff67257c8ea1fcdc777b938b68d", "Daniel Roe", False, 1),
        (nuxt, "4e35ae9babd94be53246e31200232d48438bb34e", "Daniel Roe", False, 1),
    ]
if Path(netty).exists():
    checks.append((netty, "5b68c61f37aa4a3045cba624cbea239655c9003b", "Chris Vest", False, 1))
if Path(mcp).exists():
    checks.append((mcp, "267b8fa6285453525c81ce43db6b7dcd7a8a8c2f", "Koichi ITO", False, 1))
if Path(hono).exists():
    checks.append((hono, "93fc250d8b4df58ea542cb945171de8013d5e6d5", "Yusuke Wada", False, 1))
if Path(nx).exists():
    checks.append((nx, "2b20c2da39d263c32ae05767577589481a309fee", "Jason Jean", False, 1))
if Path(guzzle).exists():
    checks.append((guzzle, "3aeea0406aab88cbbd86531313d7cebf8ae149a4", "Graham Campbell", False, 1))
for repo, sha, author, expect_ai, parents in checks:
    c = ci(repo, sha)
    assert c.author_name == author, (sha, c.author_name, author)
    ms = matches_for_commit(c)
    assert bool(ms) == expect_ai, (sha, ms)
    assert npar(repo, sha) == parents, (sha, npar(repo, sha))

print("VALIDATION_OK inspected=0 PASS_PROPOSAL=0 conservation=0=0+0 added=743 remaining=76")
PY

printf 'REPLAY_OK inspected=0 PASS_PROPOSAL=0 conservation=0=0+0 added=743 frozen=%s old=%s\n' "$HEAD_N" "$HEAD_O"
