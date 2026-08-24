#!/usr/bin/env zsh
# Fail-closed replay for herdr-260815-advisory-delta-0815-grok46-high.
# English ASCII only. Does not commit or push. Shared caches read-only.
# Does not retain clones. Exclusion IDs are rehashed from the frozen inventory cutoff.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_PAGER=cat
export GH_PAGER=cat
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260815-advisory-delta-0815-grok46-high
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical94/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json
LAYERS=$ROOT/docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md
ADV_O=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
HEAD_O=f2c6ab3202aeafb36fbea6e76d892532acfca1a6
HEAD_N=fb4768f4075a98a9356f35655d29c7aeb76d83a9
TREE_O=3308b2f6c73929d3854bd12908e996787a8bb0c8
TREE_N=f637e23cef5f0afbc36d8b6162b2b276d1c47bc2
UTREE_O=8cdc0a0b741cc5df87e9f2b7fa582debca410fdb
UTREE_N=c651ac2a7e2c1a536d7c99ee2a203ee68ecc6876
ADDED_H=e0a7bf058d950fa2ddf7aacddf9648600787d55319b6a304b5b178b01ff9a019
REMOVED_H=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
MOD_H=543b9605ce53a2423468715ccfd19d4cfc4dfab8f647b823eb584cfdd54abff9
AM_H=a2af3f349a5c05e8a0abb5b0a02e83b59ce9c5414b2a10db218b273ac0020406
TERM_H=f9316dd85a737a88318bd864716d2caf3ee7f5fa3aa0308267eabc426679b383
CANON_H=9b00a7b1853ac0f7ca0d8787fe1bb416ed024bc498630d8394bc99f4d2507370
BLOB_9Q54=24b8d65f4317f6d6d7b24292cb193702c621b6fe
CLOSER=6c90fa94bca4b65d1cfb41eb47fcdcd60ef61c5a
PARENT=9ea237a8b571a263bafc62e42902df186775496e
INTRO=a92a3534401e1dc6ffec057dc220a0e0033d78ea
CLAUDE_DC=4b5b4b2b2f803dfafda7b564577f20cf0ee9024b
TAG181=8986c9f5c785db101aa8a26ff403c8ed5d03cb42
TAG182=4438384b247e5cf8615892cfe1ac1c4dc75a2119
CRATE81_H=d1ddd739c1776770dd2ab0b33da1cf372a395500252ae5250c08e2d6bf51b38f
CRATE82_H=3b82fca53ce1734cc1d1dca96cc9ceb65ed528f27cb43b7de865215b6cf17908

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

REPLAY_TMP=""
cleanup_replay_tmp() {
  if [[ -n "${REPLAY_TMP:-}" && -d "$REPLAY_TMP" ]]; then
    rm -rf "$REPLAY_TMP"
  fi
}
trap cleanup_replay_tmp EXIT
REPLAY_TMP=$(mktemp -d /tmp/advisory-delta-0815.XXXXXX)

expect_eq() {
  if [[ $1 != "$2" ]]; then
    printf 'mismatch %s expected=%s got=%s\n' "$3" "$2" "$1" >&2
    exit 1
  fi
}

gitx() {
  local repo=$1
  shift
  "${git_cmd[@]}" -C "$repo" "$@"
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
require_dir "$ADV_O/advisories/github-reviewed"
require_absent "$OWNED/work"
require_absent "$OWNED/notes"
require_absent "$OWNED/pages"
require_absent "$OWNED/clones"
require_absent "$OWNED/snapshot"

n_owned=$(/usr/bin/ls -1 "$OWNED" | /usr/bin/wc -l | /usr/bin/tr -d ' ')
expect_eq "$n_owned" 5 owned_file_count

oh=$(gitx "$ADV_O" rev-parse HEAD)
expect_eq "$oh" "$HEAD_O" old_head
ot=$(gitx "$ADV_O" rev-parse "$HEAD_O":advisories/github-reviewed)
expect_eq "$ot" "$TREE_O" old_reviewed_tree
ou=$(gitx "$ADV_O" rev-parse "$HEAD_O":advisories/unreviewed)
expect_eq "$ou" "$UTREE_O" old_unreviewed_tree

n_assign=$(/usr/bin/wc -l < "$OWNED/assignment.jsonl" | /usr/bin/tr -d ' ')
n_cases=$(/usr/bin/wc -l < "$OWNED/cases.jsonl" | /usr/bin/tr -d ' ')
expect_eq "$n_assign" 1 assignment_rows
expect_eq "$n_cases" 1 cases_rows

OBJ=$(gitx "$ADV_O" rev-parse --git-path objects)
git -c init.defaultBranch=main init --bare "$REPLAY_TMP/adv.git" >/dev/null 2>"$REPLAY_TMP/init.err"
/usr/bin/grep -vE 'unable to normalize alternate object path|hint:' "$REPLAY_TMP/init.err" >&2 || true
mkdir -p "$REPLAY_TMP/adv.git/objects/info"
printf '%s\n' "$OBJ" > "$REPLAY_TMP/adv.git/objects/info/alternates"
git --git-dir="$REPLAY_TMP/adv.git" remote add origin https://github.com/github/advisory-database.git
git --git-dir="$REPLAY_TMP/adv.git" fetch --filter=blob:none --no-tags --depth=1 origin "$HEAD_N" >/dev/null 2>"$REPLAY_TMP/fetch.err"
/usr/bin/grep -vE 'unable to normalize alternate object path|From https://github.com/github/advisory-database|branch .* FETCH_HEAD' "$REPLAY_TMP/fetch.err" >&2 || true
nh=$(git --git-dir="$REPLAY_TMP/adv.git" rev-parse FETCH_HEAD 2>/dev/null)
expect_eq "$nh" "$HEAD_N" new_head
nt=$(git --git-dir="$REPLAY_TMP/adv.git" rev-parse FETCH_HEAD:advisories/github-reviewed 2>/dev/null)
expect_eq "$nt" "$TREE_N" new_reviewed_tree
nu=$(git --git-dir="$REPLAY_TMP/adv.git" rev-parse FETCH_HEAD:advisories/unreviewed 2>/dev/null)
expect_eq "$nu" "$UTREE_N" new_unreviewed_tree
oh2=$(git --git-dir="$REPLAY_TMP/adv.git" rev-parse "$HEAD_O" 2>/dev/null)
expect_eq "$oh2" "$HEAD_O" freeze_via_alternate

git clone --quiet --filter=blob:none --single-branch https://github.com/aws/s2n-quic.git "$REPLAY_TMP/s2n-quic" >/dev/null 2>"$REPLAY_TMP/clone.err" || true
/usr/bin/grep -vE 'unable to normalize alternate object path|Updating files:|Cloning into|lazy fetching disabled|could not fetch|Clone succeeded, but checkout failed' "$REPLAY_TMP/clone.err" >&2 || true
S2N=$REPLAY_TMP/s2n-quic
git --no-optional-locks -c gc.auto=0 -C "$S2N" fetch --filter=blob:none --no-tags origin tag v1.81.0 tag v1.82.0 >/dev/null 2>"$REPLAY_TMP/s2n-fetch.err" || true
/usr/bin/grep -vE 'unable to normalize alternate object path|From https://github.com/aws/s2n-quic|tag .* FETCH_HEAD|\* \[new tag\]' "$REPLAY_TMP/s2n-fetch.err" >&2 || true

python3 - "$OWNED" "$SUMMARY" "$ROOT" "$ADV_O" "$REPLAY_TMP/adv.git" "$S2N" "$REPLAY_TMP" <<'PY'
import hashlib, json, os, re, subprocess, sys, tarfile, urllib.request
from pathlib import Path

(owned, summary_p, root, adv_o, adv_git, s2n, tmp) = sys.argv[1:]
owned = Path(owned)
root = Path(root)
tmp = Path(tmp)
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(
    r"ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|gho_[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]{0,20}PRIVATE KEY"
)
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
GHSA_PATH = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.I)
REPO_ADV_RE = re.compile(r"https://github\.com/([^/]+)/([^/]+)/security/advisories/(GHSA-[0-9A-Za-z-]+)", re.I)
COMMIT_RE = re.compile(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})(?:[/?#]|$)")
HEX40 = re.compile(r"\b[0-9a-fA-F]{40}\b")
VERDICTS = {
    "PASS", "NARROW", "REJECT", "UNKNOWN", "BLOCKED", "KEEP", "FAIL",
    "FALSE_POSITIVE", "CONFIRM", "ACCEPT", "HOLD", "REJECT_ROUTING",
    "ROUTE", "TERMINAL", "NOT_SELECTED", "UNREVIEWED", "REJECT_ROUTE",
    "KEEP_ROUTE", "PASS_PROPOSAL",
}
SKIP_PARTS = {"work", "notes", "pages", "snapshot", "clones", "cache", "tmp", "node_modules", "diffs", "facts"}
OWN_NAME = "herdr-260815-advisory-delta-0815-grok46-high"
SKIP_DIR_NAMES = {OWN_NAME, ".leader-quarantine-260814"}
HEAD_O = "f2c6ab3202aeafb36fbea6e76d892532acfca1a6"
HEAD_N = "fb4768f4075a98a9356f35655d29c7aeb76d83a9"
ADDED_H = "e0a7bf058d950fa2ddf7aacddf9648600787d55319b6a304b5b178b01ff9a019"
REMOVED_H = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
MOD_H = "543b9605ce53a2423468715ccfd19d4cfc4dfab8f647b823eb584cfdd54abff9"
AM_H = "a2af3f349a5c05e8a0abb5b0a02e83b59ce9c5414b2a10db218b273ac0020406"
TERM_H = "f9316dd85a737a88318bd864716d2caf3ee7f5fa3aa0308267eabc426679b383"
BLOB_9Q54 = "24b8d65f4317f6d6d7b24292cb193702c621b6fe"
CLOSER = "6c90fa94bca4b65d1cfb41eb47fcdcd60ef61c5a"
PARENT = "9ea237a8b571a263bafc62e42902df186775496e"
INTRO = "a92a3534401e1dc6ffec057dc220a0e0033d78ea"
CLAUDE_DC = "4b5b4b2b2f803dfafda7b564577f20cf0ee9024b"
TAG181 = "8986c9f5c785db101aa8a26ff403c8ed5d03cb42"
TAG182 = "4438384b247e5cf8615892cfe1ac1c4dc75a2119"
CRATE81_H = "d1ddd739c1776770dd2ab0b33da1cf372a395500252ae5250c08e2d6bf51b38f"
CRATE82_H = "3b82fca53ce1734cc1d1dca96cc9ceb65ed528f27cb43b7de865215b6cf17908"

env = dict(os.environ)
for k in list(env):
    lk = k.lower()
    if any(x in lk for x in ("token", "secret", "password", "credential", "api_key", "auth", "gh_token", "github_token")):
        env.pop(k, None)
env.update(
    PATH="/usr/local/bin:/usr/bin:/bin",
    GIT_OPTIONAL_LOCKS="0",
    GIT_TERMINAL_PROMPT="0",
    GIT_PAGER="cat",
    GIT_CONFIG_NOSYSTEM="1",
    GIT_CONFIG_GLOBAL="/dev/null",
    GIT_CONFIG_SYSTEM="/dev/null",
)

def load_jsonl(path):
    text = Path(path).read_text()
    return [json.loads(l) for l in text.splitlines() if l.strip()]

for name in ("assignment.jsonl", "cases.jsonl", "result.json", "report.md", "replay.zsh"):
    raw = (owned / name).read_bytes()
    text = raw.decode("ascii")
    assert text.endswith("\n"), name
    assert text.isascii(), name
    assert not han.search(text) and not secret.search(text)
    for line in text.splitlines():
        assert line == line.rstrip(" \t")

names = sorted(p.name for p in owned.iterdir())
assert names == ["assignment.jsonl", "cases.jsonl", "replay.zsh", "report.md", "result.json"]
assign = load_jsonl(owned / "assignment.jsonl")
cases = load_jsonl(owned / "cases.jsonl")
result = json.loads((owned / "result.json").read_text())
assert len(assign) == 1 and len(cases) == 1
assert [a["case_id"] for a in assign] == ["GHSA-9Q54-F358-3FQF"]
assert cases[0]["verdict"] == "REJECT_ROUTING"
assert cases[0]["never_pass"] is True
assert cases[0]["proposed_pass"] is False
assert "PASS" not in {cases[0]["verdict"]}
assert cases[0]["identity_gate"] == "PASS"
assert cases[0]["ai_hunk_gate"] == "FAIL"
assert cases[0]["topology_gate"] == "PASS"
assert cases[0]["but_for_gate"] == "FAIL"
assert cases[0]["fix_reversal_gate"] == "FAIL"
assert cases[0]["uniqueness_gate"] == "PASS"
assert result["counts"]["ROUTE"] == 0
assert result["counts"]["PASS"] == 0
assert result["counts"]["PASS_PROPOSAL"] == 0
assert result["counts"]["inspected"] == 1
assert result["route_ids"] == []
assert result["pass_proposals"] == []
assert result["conservation"]["equation"] == "33=32+1"
assert result["conservation"]["assigned_equation"] == "1=1+0"
assert result["conservation"]["holds"] is True
assert result["advisory_database"]["new_head"] == HEAD_N
assert result["advisory_database"]["old_head"] == HEAD_O
assert result["advisory_database"]["added_reviewed"] == 17
assert result["advisory_database"]["removed_reviewed"] == 0
assert result["advisory_database"]["modified_reviewed"] == 16
assert result["exclusion"]["n"] == 12468
assert result["exclusion"]["sha256"] == TERM_H
assert result["packet_delta"] == 0
assert result["cve_aliases_counted"] is False
assert result["canonical_ledger_edited"] is False
assert result["worker_pass_is_proposal_only"] is True
assert result["never_pass"] is True
assert "0 ROUTE" in (owned / "report.md").read_text()
assert "Did not pad" in (owned / "report.md").read_text()
ah = result["artifact_hashes"]
for name in ("assignment.jsonl", "cases.jsonl", "report.md", "replay.zsh"):
    got = hashlib.sha256((owned / name).read_bytes()).hexdigest()
    assert got == ah[name], (name, got, ah[name])
assert "result.json" not in ah

pins = result["current_input_hashes"]
def h(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()
assert h(root / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md") == pins["CONTRACT.md"]
assert h(root / "autoresearch/orchestrator-260814-ghsa200-canonical94/ledger.jsonl") == pins["canonical94_ledger.jsonl"]
assert h(root / "autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json") == pins["canonical94_summary.json"]
assert h(root / "docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md") == pins["RESEARCH-TRUTH-LAYERS-2026-08-14.md"]

summary = json.loads(Path(summary_p).read_text())
strict = {str(x).upper() for x in summary["strict_released_case_ids"]}
assert len(strict) == 94 == summary["canonical_strict_count"]
assert summary.get("status") == "HOLD"
assert "GHSA-76PC-MQXP-3RQ5" in strict
assert "GHSA-8RW6-P7M8-63JP" in strict
assert "GHSA-9Q54-F358-3FQF" not in strict

INV_CUTOFF = float(result["inventory"]["cutoff_mtime"])
AUTO = root / "autoresearch"

def norm(s):
    m = GHSA_PATH.search(str(s or ""))
    return m.group(0).upper() if m else None

def packet_ok(path):
    if path.stat().st_mtime >= INV_CUTOFF:
        return False
    rel = path.relative_to(AUTO)
    top = rel.parts[0]
    if top in SKIP_DIR_NAMES:
        return False
    if any(p in SKIP_PARTS for p in rel.parts[:-1]):
        return False
    return (
        top.startswith("herdr-260813")
        or top.startswith("herdr-260814")
        or top.startswith("herdr-260815")
        or top.startswith("orchestrator-260813")
        or top.startswith("orchestrator-260814")
        or top.startswith("orchestrator-260815")
    )

terminal = set()
files = casesn = adj = resf = rows = 0

def consider(row):
    global rows
    if not isinstance(row, dict):
        return
    rows += 1
    cid = norm(row.get("case_id") or row.get("ghsa_id") or row.get("id"))
    if not cid:
        return
    v = row.get("verdict") or row.get("worker_verdict") or row.get("latest_verdict") or row.get("terminal_verdict")
    if isinstance(v, str) and v.strip().upper() in VERDICTS:
        terminal.add(cid)

for path in sorted(AUTO.glob("*/cases.jsonl")):
    if not packet_ok(path):
        continue
    files += 1
    casesn += 1
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        consider(row)
for path in sorted(list(AUTO.glob("*/*adjudication*.jsonl")) + list(AUTO.glob("*/*adjudication*.json"))):
    if not packet_ok(path):
        continue
    files += 1
    adj += 1
    text = path.read_text(errors="replace")
    chunks = []
    if path.suffix == ".jsonl":
        for l in text.splitlines():
            if l.strip():
                try:
                    chunks.append(json.loads(l))
                except json.JSONDecodeError:
                    pass
    else:
        try:
            chunks = [json.loads(text)]
        except json.JSONDecodeError:
            continue
    for row in chunks:
        consider(row)
for path in sorted(AUTO.glob("*/result.json")):
    if not packet_ok(path):
        continue
    files += 1
    resf += 1
    try:
        payload = json.loads(path.read_text(errors="replace"))
    except json.JSONDecodeError:
        continue
    consider(payload)
    for key in ("remaining_inventory", "cases", "reviewed", "rows"):
        val = payload.get(key)
        if isinstance(val, list):
            for row in val:
                consider(row)

assert files == result["inventory"]["files"]
assert casesn == result["inventory"]["cases_jsonl"]
assert adj == result["inventory"]["adjudications"]
assert resf == result["inventory"]["result_json"]
assert rows == result["inventory"]["rows"]
assert len(terminal) == 12468
got = hashlib.sha256(("\n".join(sorted(terminal)) + "\n").encode("ascii")).hexdigest()
assert got == TERM_H
assert strict <= terminal
assert "GHSA-9Q54-F358-3FQF" not in terminal

def git(repo, *args, gitdir=None, check=True, extra_env=None):
    cmd = ["git", "--no-optional-locks", "-c", "gc.auto=0"]
    e = dict(env)
    e["GIT_NO_LAZY_FETCH"] = "1"
    if extra_env:
        e.update(extra_env)
    if gitdir:
        cmd += ["--git-dir", gitdir]
    else:
        cmd += ["-C", repo]
    cmd += list(args)
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=e)
    if check and p.returncode != 0:
        raise SystemExit(args, p.stderr[:500])
    return p

def ids_and_blobs(spec, gitdir=None, repo=None):
    r = git(repo, "ls-tree", "-r", spec, gitdir=gitdir)
    ids = {}
    for line in r.stdout.splitlines():
        meta, path = line.split("\t", 1)
        sha = meta.split()[2]
        m = GHSA_PATH.search(path)
        if m:
            ids[m.group(0).upper()] = {"path": path, "blob": sha}
    return ids

new_r = ids_and_blobs("FETCH_HEAD:advisories/github-reviewed", gitdir=adv_git)
old_r = ids_and_blobs(HEAD_O + ":advisories/github-reviewed", repo=adv_o)
new_u = ids_and_blobs("FETCH_HEAD:advisories/unreviewed", gitdir=adv_git)
old_u = ids_and_blobs(HEAD_O + ":advisories/unreviewed", repo=adv_o)
assert len(old_r) == 34389 and len(new_r) == 34406
assert len(old_u) == 323477 and len(new_u) == 323651
added = sorted(set(new_r) - set(old_r))
removed = sorted(set(old_r) - set(new_r))
modified = sorted(g for g in set(old_r) & set(new_r) if old_r[g]["blob"] != new_r[g]["blob"])
assert len(added) == 17 and removed == [] and len(modified) == 16
assert hashlib.sha256(("\n".join(added) + "\n").encode("ascii")).hexdigest() == ADDED_H
assert hashlib.sha256(b"").hexdigest() == REMOVED_H
assert hashlib.sha256(("\n".join(modified) + "\n").encode("ascii")).hexdigest() == MOD_H
am = sorted(set(added) | set(modified))
assert hashlib.sha256(("\n".join(am) + "\n").encode("ascii")).hexdigest() == AM_H
assert added == result["advisory_database"]["added_reviewed_ids"]
assert modified == result["advisory_database"]["modified_reviewed_ids"]
assert 34389 + 17 - 0 == 34406
added_u = set(new_u) - set(old_u)
removed_u = set(old_u) - set(new_u)
modified_u = [g for g in set(old_u) & set(new_u) if old_u[g]["blob"] != new_u[g]["blob"]]
assert len(added_u) == 179 and len(removed_u) == 5 and len(modified_u) == 64
assert 323477 + 179 - 5 == 323651
overlap = (set(added) | set(modified)) & terminal
assert len(overlap) == 32
remaining = sorted((set(added) | set(modified)) - terminal)
assert remaining == ["GHSA-9Q54-F358-3FQF"]
assert remaining == result["remaining_ids"]
assert "GHSA-76PC-MQXP-3RQ5" in (set(added) & strict)
assert "GHSA-8RW6-P7M8-63JP" in (set(added) & strict)

# 9Q54 blob via lazy fetch into throwaway repo only
e_lazy = dict(env)
e_lazy["GIT_NO_LAZY_FETCH"] = "0"
p = subprocess.run(
    ["git", "--no-optional-locks", "-c", "gc.auto=0", "--git-dir", adv_git, "cat-file", "-p", BLOB_9Q54],
    capture_output=True, env=e_lazy,
)
assert p.returncode == 0, p.stderr[:400]
raw = p.stdout
obj = json.loads(raw)
assert obj["id"].upper() == "GHSA-9Q54-F358-3FQF"
assert not obj.get("withdrawn")
assert HEX40.findall(raw.decode("utf-8", "replace")) == []
refs = []
for ref in obj.get("references") or []:
    u = ref.get("url") if isinstance(ref, dict) else ref
    if isinstance(u, str):
        refs.append(u)
repo = None
for u in refs:
    m = REPO_ADV_RE.search(u)
    if m and m.group(3).upper() == "GHSA-9Q54-F358-3FQF":
        repo = f"{m.group(1)}/{m.group(2)}"
assert repo == "aws/s2n-quic"
shas = []
for u in refs:
    m = COMMIT_RE.search(u)
    if m and m.group(1).lower() == "aws" and m.group(2).lower() == "s2n-quic":
        shas.append(m.group(3).lower())
assert shas == []
assert new_r["GHSA-9Q54-F358-3FQF"]["blob"] == BLOB_9Q54

sys.path.insert(0, str(Path(root) / "cve-analyzer/src"))
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit
assert MATCHER_CONTRACT == result["source_matcher_contract"]

def git_s2n(*args, check=True):
    e = dict(env)
    e["GIT_NO_LAZY_FETCH"] = "0"
    p = subprocess.run(
        ["git", "--no-optional-locks", "-c", "gc.auto=0", "-C", s2n, *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace", env=e,
    )
    if check and p.returncode != 0:
        raise SystemExit(args, p.stderr[:500])
    return p

def ci(sha):
    rec = git_s2n("log", "-1", "--format=%H%n%an%n%ae%n%cn%n%ce%n%aI%n%B", sha).stdout
    parts = rec.split("\n", 6)
    while len(parts) < 7:
        parts.append("")
    return CommitInfo(
        sha=parts[0].strip(), author_name=parts[1], author_email=parts[2],
        committer_name=parts[3], committer_email=parts[4], authored_date=parts[5], message=parts[6],
    )

def npar(sha):
    return len(git_s2n("rev-list", "--parents", "-n1", sha).stdout.split()) - 1

assert git_s2n("rev-parse", "v1.81.0").stdout.strip() == TAG181
assert git_s2n("rev-parse", "v1.82.0").stdout.strip() == TAG182
assert npar(CLOSER) == 1
c_closer = ci(CLOSER)
assert c_closer.author_name == "Boquan Fang"
assert matches_for_commit(c_closer) == ()
assert "Merge commit from fork" in c_closer.message
assert git_s2n("merge-base", "--is-ancestor", CLOSER, TAG182).returncode == 0
assert git_s2n("merge-base", "--is-ancestor", CLOSER, TAG181, check=False).returncode != 0
parent_body = git_s2n("show", PARENT + ":quic/s2n-quic-transport/src/space/crypto_stream.rs").stdout
assert "TODO we need to limit the buffer size here" in parent_body
assert "MAX_CRYPTO_BUFFER_SIZE" not in parent_body
closer_body = git_s2n("show", CLOSER + ":quic/s2n-quic-transport/src/space/crypto_stream.rs").stdout
assert "MAX_CRYPTO_BUFFER_SIZE" in closer_body
assert "TODO we need to limit the buffer size here" not in closer_body
c_intro = ci(INTRO)
assert matches_for_commit(c_intro) == ()
c_dc = ci(CLAUDE_DC)
ms = matches_for_commit(c_dc)
assert any(m.tool == "claude_code" and m.source_module == "coauthor_trailer" for m in ms)
dc_files = git_s2n("diff-tree", "--no-commit-id", "--name-only", "-r", CLAUDE_DC).stdout.splitlines()
assert "quic/s2n-quic-transport/src/space/crypto_stream.rs" not in dc_files
assert all(x.startswith("dc/s2n-quic-dc/") for x in dc_files)

for ver, expect, want_max, want_todo in (
    ("0.81.0", CRATE81_H, False, True),
    ("0.82.0", CRATE82_H, True, False),
):
    dest = tmp / ("s2n-quic-transport-" + ver + ".crate")
    url = "https://static.crates.io/crates/s2n-quic-transport/s2n-quic-transport-" + ver + ".crate"
    req = urllib.request.Request(url, headers={"User-Agent": "advisory-delta-replay"})
    with urllib.request.urlopen(req, timeout=60) as r:
        dest.write_bytes(r.read())
    got = hashlib.sha256(dest.read_bytes()).hexdigest()
    assert got == expect, (ver, got, expect)
    with tarfile.open(dest) as t:
        member = "s2n-quic-transport-" + ver + "/src/space/crypto_stream.rs"
        js = t.extractfile(member).read().decode()
        assert ("MAX_CRYPTO_BUFFER_SIZE" in js) is want_max
        assert ("TODO we need to limit the buffer size here" in js) is want_todo

print("VALIDATION_OK inspected=1 ROUTE=0 REJECT_ROUTING=1 conservation=33=32+1 added=17 modified=16 remaining=1")
PY

printf 'REPLAY_OK inspected=1 ROUTE=0 REJECT_ROUTING=1 conservation=33=32+1 added=17 modified=16 frozen=%s new=%s\n' "$HEAD_O" "$HEAD_N"
