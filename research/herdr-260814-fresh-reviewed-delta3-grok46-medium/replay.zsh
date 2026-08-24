#!/usr/bin/env zsh
# Fail-closed replay for herdr-260814-fresh-reviewed-delta3-grok46-medium.
# English ASCII only. Does not commit or push. Shared caches read-only.
# Does not walk other workers. Exclusion IDs are frozen in result.json.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_PAGER=cat
export GH_PAGER=cat
export PYTHONPATH=/home/hanqing/agents/ai-slop/cve-analyzer/src

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-fresh-reviewed-delta3-grok46-medium
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/summary.json
LAYERS=$ROOT/docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md
ADV_O=/home/hanqing/.cache/cve-analyzer/advisory-database
ADV_REF=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
HEAD_N=c2edfe3bafcf48ae374e1c5e15ac98ae98fa68da
HEAD_O=39d8887723797efc1804585dd06585c9fd751226
ADDED_H=4849f8318879d992f68c54a58262826624f638b5dc945f25c27ca540b8717c3d
REMOVED_H=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
EXCL_H=958f96dc44696364a621616ffe4212af46f8acd3578a6d47a4b32152944d631e
TREE_N=1741a07b16252ffb489c9f037979a9941007b283
TREE_O=3a1267e940595e82f109a750f2779d987ff4d01b
ORIGIN=051f27474d85d7f3299b56fc61bfcb0666a4e198
CLOSER=b4ee96dac799cbfba0a9f9c17844ce9d613cbcc7
FC358=fc3582544f6df4a14dcd3015edc835780f746aff
NPM501_H=4594c2d6140c20dd64d85fb5ceee660c8f943ff76f779d610d8554eea7267761
NPM511_H=1828e97d1c7dabfb7d6d27ac786b88e1977c5fa95f3da1f12bb1630533e670da

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

REPLAY_TMP=""
cleanup_replay_tmp() {
  if [[ -n "${REPLAY_TMP:-}" && -d "$REPLAY_TMP" ]]; then
    rm -rf "$REPLAY_TMP"
  fi
}
trap cleanup_replay_tmp EXIT
REPLAY_TMP=$(mktemp -d /tmp/fresh-reviewed-delta3.XXXXXX)

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
  errf=$(mktemp "$REPLAY_TMP/giterr.XXXXXX")
  setopt localoptions noerrexit
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  rc=$?
  if [[ -s $errf ]]; then
    /usr/bin/grep -vE 'unable to normalize alternate object path|lazy fetching disabled|current branch .* does not have any commits yet|Clone succeeded, but checkout failed' "$errf" >&2 || true
  fi
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
require_dir "$ADV_O/advisories/github-reviewed"
require_dir "$ADV_REF/advisories/github-reviewed"
require_absent "$OWNED/work"
require_absent "$OWNED/notes"
require_absent "$OWNED/pages"
require_absent "$OWNED/clones"

n_owned=$(/usr/bin/ls -1 "$OWNED" | /usr/bin/wc -l | /usr/bin/tr -d ' ')
expect_eq "$n_owned" 5 owned_file_count

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LAYERS" 70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f
expect_hash "$LEDGER" 70b7658fadf41f18c72734a2006601961a2180681bf81353373bccab95ff659e
expect_hash "$SUMMARY" ab47f927a20f374a9b0e3253a1a5a0778e355dda9414189927022325d81ad86f

oh=$(gitx "$ADV_O" rev-parse HEAD)
expect_eq "$oh" "$HEAD_O" old_head
ot=$(gitx "$ADV_O" rev-parse "$HEAD_O":advisories/github-reviewed)
expect_eq "$ot" "$TREE_O" old_reviewed_tree

n_assign=$(/usr/bin/wc -l < "$OWNED/assignment.jsonl" | /usr/bin/tr -d ' ')
n_cases=$(/usr/bin/wc -l < "$OWNED/cases.jsonl" | /usr/bin/tr -d ' ')
expect_eq "$n_assign" 2 assignment_rows
expect_eq "$n_cases" 2 cases_rows

OBJ=$(gitx "$ADV_REF" rev-parse --git-path objects)
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

git clone --quiet --filter=blob:none --single-branch https://github.com/ooples/token-optimizer-mcp.git "$REPLAY_TMP/token-optimizer-mcp" >/dev/null 2>"$REPLAY_TMP/clone.err"
/usr/bin/grep -vE 'unable to normalize alternate object path|Updating files:|Cloning into' "$REPLAY_TMP/clone.err" >&2 || true
TO=$REPLAY_TMP/token-optimizer-mcp

python3 - "$OWNED" "$SUMMARY" "$ROOT" "$ADV_O" "$REPLAY_TMP/adv.git" "$TO" "$ADDED_H" "$REMOVED_H" "$EXCL_H" "$HEAD_N" "$HEAD_O" "$NPM501_H" "$NPM511_H" "$ORIGIN" "$CLOSER" "$FC358" <<'PY'
import hashlib, json, os, re, subprocess, sys, tarfile, urllib.request
from pathlib import Path

(owned, summary_p, root, adv_o, adv_git, to_repo, added_h, removed_h, excl_h,
 head_n, head_o, npm501_h, npm511_h, origin, closer, fc358) = sys.argv[1:]
owned = Path(owned)
root = Path(root)
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(r"ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}")
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
GHSA_PATH = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.I)
C91_OVERLAP = {
    "GHSA-3RP5-JJMW-4WV2", "GHSA-539M-9XH6-Q6RR", "GHSA-7P8R-X3MC-P8W7", "GHSA-8359-H9FX-J6V9",
    "GHSA-8RW6-P7M8-63JP", "GHSA-FRVJ-C5QP-XJ4W", "GHSA-GH4H-34GR-87R7", "GHSA-HC8V-WWC9-VGXM",
    "GHSA-JM78-9FVV-MHGR", "GHSA-PFVM-W89X-94JW", "GHSA-PQH8-P93P-2RX7", "GHSA-QF5V-M7P4-95RP",
    "GHSA-R9MR-M37C-5FR3", "GHSA-W28W-GP39-M4P6",
}
env = dict(os.environ)
env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_PAGER="cat")

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
assert len(assign) == 2 and len(cases) == 2
assert [a["case_id"] for a in assign] == ["GHSA-76PC-MQXP-3RQ5", "GHSA-49MQ-FC6Q-3H46"]
assert cases[0]["verdict"] == "PASS" and cases[1]["verdict"] == "NARROW"
assert result["conservation"]["equation"] == "2=2+0"
assert result["counts"]["PASS_PROPOSAL"] == 1
assert result["counts"]["NARROW"] == 1
assert result["counts"]["inspected"] == 2
assert result["PASS_PROPOSAL"] == ["GHSA-76PC-MQXP-3RQ5"]
assert result["terminal"] is True
assert result["advisory_database"]["new_head"] == head_n
assert result["advisory_database"]["old_head"] == head_o
assert result["advisory_database"]["added_reviewed"] == 760
assert result["advisory_database"]["removed_reviewed"] == 0
assert result["exclusion"]["n"] == 8200
assert result["exclusion"]["sha256"] == excl_h
assert result["exclusion"]["live_glob_in_replay"] is False
assert result["packet_delta"] == 0
assert result["cve_aliases_counted"] is False
assert result["canonical_ledger_edited"] is False
assert result["seven_gates_exact_pass_required"] is True
assert result["worker_pass_is_proposal_only"] is True
assert "1 PASS_PROPOSAL" in (owned / "report.md").read_text()
assert "Did not pad" in (owned / "report.md").read_text()
ah = result["artifact_hashes"]
for name in ("assignment.jsonl", "cases.jsonl", "report.md", "replay.zsh"):
    got = hashlib.sha256((owned / name).read_bytes()).hexdigest()
    assert got == ah[name], (name, got, ah[name])
assert "result.json" not in ah

summary = json.loads(Path(summary_p).read_text())
strict = {str(x).upper() for x in summary["strict_released_case_ids"]}
assert len(strict) == 91
excl_ids = result["exclusion"]["ids"]
assert len(excl_ids) == 8200
assert excl_ids == sorted(excl_ids)
assert all(GHSA_RE.fullmatch(x) for x in excl_ids)
got = hashlib.sha256(("\n".join(excl_ids) + "\n").encode("ascii")).hexdigest()
assert got == excl_h
assert strict <= set(excl_ids)
assert "GHSA-76PC-MQXP-3RQ5" not in excl_ids
assert "GHSA-49MQ-FC6Q-3H46" not in excl_ids

def git(repo, *args, gitdir=None):
    cmd = ["git", "--no-optional-locks", "-c", "gc.auto=0"]
    if gitdir:
        cmd += ["--git-dir", gitdir]
    else:
        cmd += ["-C", repo]
    cmd += list(args)
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)

def ids_and_paths(repo, spec, gitdir=None):
    r = git(repo, "ls-tree", "-r", "--name-only", spec, gitdir=gitdir)
    assert r.returncode == 0, r.stderr
    ids = set(); paths = {}
    for line in r.stdout.splitlines():
        m = GHSA_PATH.search(line)
        if m:
            gid = m.group(0).upper()
            ids.add(gid); paths[gid] = line
    return ids, paths

new, _ = ids_and_paths(None, "FETCH_HEAD:advisories/github-reviewed", gitdir=adv_git)
old, _ = ids_and_paths(adv_o, head_o + ":advisories/github-reviewed")
added = sorted(new - old)
removed = sorted(old - new)
assert len(new) == 34406 and len(old) == 33646
assert len(added) == 760 and removed == []
assert hashlib.sha256(("\n".join(added) + "\n").encode("ascii")).hexdigest() == added_h
assert hashlib.sha256(b"").hexdigest() == removed_h
remaining = sorted(set(added) - set(excl_ids))
assert remaining == result["screen"]["remaining_ids"]
assert len(remaining) == 79
assert sorted(set(added) & strict) == sorted(C91_OVERLAP)

sys.path.insert(0, str(root / "cve-analyzer/src"))
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit
assert MATCHER_CONTRACT == result["source_matcher_contract"]

def ci(repo, sha):
    rec = git(repo, "log", "-1", "--format=%H%n%an%n%ae%n%cn%n%ce%n%aI%n%B", sha)
    assert rec.returncode == 0, rec.stderr
    parts = rec.stdout.split("\n", 6)
    while len(parts) < 7:
        parts.append("")
    return CommitInfo(sha=parts[0].strip(), author_name=parts[1], author_email=parts[2],
                      committer_name=parts[3], committer_email=parts[4],
                      authored_date=parts[5], message=parts[6])

def npar(repo, sha):
    r = git(repo, "rev-list", "--parents", "-n1", sha)
    return len(r.stdout.split()) - 1

c_origin = ci(to_repo, origin)
assert npar(to_repo, origin) == 1
ms = matches_for_commit(c_origin)
assert any(m.tool == "claude_code" and m.source_module == "coauthor_trailer" for m in ms)
assert "Co-Authored-By: Claude <noreply@anthropic.com>" in c_origin.message
r = git(to_repo, "cat-file", "-e", "5fe1380e53eee6d08ec47980fd7b32a08eb077b6:src/server/web-server.ts")
assert r.returncode != 0
body = git(to_repo, "show", origin + ":src/server/web-server.ts").stdout
assert "session-log-${sessionId}.jsonl" in body
assert "isValidSessionId" not in body
c_fix = ci(to_repo, closer)
assert npar(to_repo, closer) == 1
assert "GHSA-76pc-mqxp-3rq5" in c_fix.message
fix_body = git(to_repo, "show", closer + ":src/server/web-server.ts").stdout
assert "isValidSessionId" in fix_body
assert git(to_repo, "merge-base", "--is-ancestor", origin, "8138f3a6d32eff80387f24d6068039ae8fb7bfa9").returncode == 0
assert git(to_repo, "merge-base", "--is-ancestor", closer, "687b55460d752fa4ee011c58535c733191b831c8").returncode == 0

c_fc = ci(to_repo, fc358)
assert matches_for_commit(c_fc) == ()
assert "claude.com/claude-code" in c_fc.message
su = git(to_repo, "show", fc358 + ":src/tools/system-operations/smart-user.ts").stdout
assert 'getent passwd "${username}"' in su

tmp = Path(to_repo).parent
for ver, expect in (("5.0.1", npm501_h), ("5.1.1", npm511_h)):
    dest = tmp / (ver + ".tgz")
    url = "https://registry.npmjs.org/@ooples/token-optimizer-mcp/-/token-optimizer-mcp-" + ver + ".tgz"
    urllib.request.urlretrieve(url, dest)
    got = hashlib.sha256(dest.read_bytes()).hexdigest()
    assert got == expect, (ver, got, expect)
with tarfile.open(tmp / "5.0.1.tgz") as t:
    js = t.extractfile("package/dist/server/web-server.js").read().decode()
    assert "session-log-" in js and "isValidSessionId" not in js
    su = t.extractfile("package/dist/tools/system-operations/smart-user.js").read().decode()
    assert 'getent passwd "${username}"' in su
with tarfile.open(tmp / "5.1.1.tgz") as t:
    js = t.extractfile("package/dist/server/web-server.js").read().decode()
    assert "isValidSessionId" in js
    su = t.extractfile("package/dist/tools/system-operations/smart-user.js").read().decode()
    assert "execFileSafe" in su

print("VALIDATION_OK inspected=2 PASS_PROPOSAL=1 NARROW=1 conservation=2=2+0 added=760 remaining=79")
PY

printf 'REPLAY_OK inspected=2 PASS_PROPOSAL=1 NARROW=1 conservation=2=2+0 added=760 frozen=%s old=%s\n' "$HEAD_N" "$HEAD_O"
