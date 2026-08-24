#!/usr/bin/env zsh
# Fail-closed replay for herdr-260814-fresh-unreviewed-delta-grok46-high.
# English ASCII only. Does not clone, fetch, commit, or push. Shared caches read-only.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-fresh-unreviewed-delta-grok46-high
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json
LAYERS=$ROOT/docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md
ADV_R=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
ADV_U=/home/hanqing/.cache/cve-analyzer/advisory-database
HEAD_N=f2c6ab3202aeafb36fbea6e76d892532acfca1a6
HEAD_O=39d8887723797efc1804585dd06585c9fd751226
DELTA_H=ce4927c40efa5db05ee070c23ea5d9acc39bbc0f01beb947bae2243602cc477c
EXCL_H=f9b9bcbe7c20e4f96d0db282ddb114aa362e144de87d97f691f9323a3ae86811
GP=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gitpython-developers__GitPython
FB=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/filebrowser__filebrowser
AV=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/WWBN__AVideo
GR=/home/hanqing/.cache/cve-analyzer/repos/getgrav_grav
JC=/home/hanqing/.cache/cve-analyzer/repos/fasterxml_jackson-core
GH=/home/hanqing/.cache/cve-analyzer/repos/github.com_nationalsecurityagency_ghidra

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
  errf=$(mktemp /tmp/fresh-unreviewed-delta-giterr.XXXXXX)
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
require_dir "$ADV_R"
require_dir "$ADV_U/advisories/unreviewed"
require_absent "$ADV_R/advisories/unreviewed"
require_absent "$OWNED/work"
require_absent "$OWNED/notes"
require_absent "$OWNED/pages"
require_absent "$OWNED/clones"
require_absent /tmp/herdr-260814-fresh-unreviewed-delta-grok46-high-clones

n_owned=$(/usr/bin/ls -1 "$OWNED" | /usr/bin/wc -l | /usr/bin/tr -d ' ')
expect_eq "$n_owned" 5 owned_file_count

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LAYERS" 70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f
expect_hash "$LEDGER" 35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
expect_hash "$SUMMARY" 81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921

rh=$(gitx "$ADV_R" rev-parse HEAD)
uh=$(gitx "$ADV_U" rev-parse HEAD)
expect_eq "$rh" "$HEAD_N" reviewed_head
expect_eq "$uh" "$HEAD_O" unreviewed_head

nt=$(gitx "$ADV_R" rev-parse "$HEAD_N":advisories/unreviewed)
ot=$(gitx "$ADV_U" rev-parse "$HEAD_O":advisories/unreviewed)
expect_eq "$nt" 8cdc0a0b741cc5df87e9f2b7fa582debca410fdb new_unreviewed_tree
expect_eq "$ot" 09d03333897c6e461074008a7f2663ffed8fb219 old_unreviewed_tree

n_assign=$(/usr/bin/wc -l < "$OWNED/assignment.jsonl" | /usr/bin/tr -d ' ')
n_cases=$(/usr/bin/wc -l < "$OWNED/cases.jsonl" | /usr/bin/tr -d ' ')
expect_eq "$n_assign" 12 assignment_rows
expect_eq "$n_cases" 12 cases_rows

python3 - "$OWNED" "$SUMMARY" "$ROOT" "$ADV_R" "$ADV_U" "$GP" "$FB" "$AV" "$GR" "$JC" "$GH" "$DELTA_H" "$EXCL_H" <<'PY'
import hashlib, json, os, re, subprocess, sys
from pathlib import Path

owned, summary_p, root, adv_r, adv_u, gp, fb, av, gr, jc, gh, delta_h, excl_h = sys.argv[1:]
root = Path(root)
owned = Path(owned)
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(r"ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}")
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
ID_FIELDS = {"case_id", "ghsa_id", "reviewed_case_ids", "assigned_ids", "strict_released_case_ids"}
ARTIFACT_NAMES = {
    "assignment.jsonl", "cases.jsonl", "result.json", "selected.jsonl",
    "queue.jsonl", "ledger.jsonl", "summary.json",
}
SKIP_DIR_PARTS = {"work", "notes", "pages", "snapshot", "clones", "cache", "tmp"}
OWNED_NAME = "herdr-260814-fresh-unreviewed-delta-grok46-high"
GATES = [
    "identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate",
    "fix_reversal_gate", "release_gate", "uniqueness_gate",
]
FROZEN = [
    "GHSA-9RMJ-FH79-GF6W", "GHSA-32PR-94PQ-34PJ", "GHSA-56H4-P63W-W4WM",
    "GHSA-WX2X-G9FW-53FC", "GHSA-336F-J5CQ-6C4F", "GHSA-MG62-J9W6-5HFH",
    "GHSA-Q6C7-VM4C-28MJ", "GHSA-3M6R-M23G-M2W9", "GHSA-685P-FM6J-C445",
    "GHSA-642R-3GJ9-2PJ5", "GHSA-6QM2-MCQ7-53QP", "GHSA-MFCJ-9FRG-F2R4",
]
HEAD_N = "f2c6ab3202aeafb36fbea6e76d892532acfca1a6"
HEAD_O = "39d8887723797efc1804585dd06585c9fd751226"
env = dict(os.environ)
env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1", GIT_PAGER="cat")

def load_jsonl(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]

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
assert len(assign) == 12 and len(cases) == 12
ids = [r["case_id"] for r in assign]
assert ids == [r["case_id"] for r in cases] == FROZEN
assert len(set(ids)) == 12
for gid in ids:
    assert GHSA_RE.fullmatch(gid), gid
assert all(a.get("frozen") is True for a in assign)
assert all(a.get("kind") == "unreviewed" for a in assign)
assert all(a.get("github_reviewed") is False for a in assign)
assert all(a.get("unreviewed_empty_affected_fails_closed") is True for a in assign)

assert result["conservation"]["equation"] == "12=0+12"
assert result["conservation"]["assigned"] == 12
assert result["conservation"]["reviewed"] == 0
assert result["conservation"]["unreviewed"] == 12
assert result["conservation"]["did_not_pad"] is True
assert result["counts"]["PASS_PROPOSAL"] == 0
assert result["counts"]["REJECT"] == 12
assert result["PASS_PROPOSAL"] == []
assert result["terminal"] is True
assert result["advisory_database"]["new_head"] == HEAD_N
assert result["advisory_database"]["old_head"] == HEAD_O
assert result["advisory_database"]["delta_n"] == 6296
assert result["advisory_database"]["delta_sorted_id_sha256"] == delta_h
assert result["exclusion"]["n"] == 8189
assert result["exclusion"]["sha256"] == excl_h
assert result["canonical88_overlap"] == []
assert result["cve_aliases_counted"] is False
assert result["packet_delta"] == 0
assert result["seven_gates_exact_pass_required"] is True
assert result["canonical_ledger_edited"] is False
assert result["bound"]["inspected"] == 12
assert result["bound"]["max_inspect"] == 12
assert result["ai_on_fix_is_not_strict_pass"] is True
assert result["old_bug_preservation_is_not_strict_pass"] is True
assert result["release_unknown_is_not_strict_pass"] is True
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

for r in cases:
    g = r["gates"]
    assert all(k in g for k in GATES)
    assert r["seven_gates_exact_pass"] is False
    assert r["countable_proposal"] is False
    assert r["verdict"] == "REJECT"
    assert r["identity_gate"] == "FAIL"
    assert r["unreviewed_empty_affected"] is True
    assert r["cross_bound"] is True
    assert r["in_canonical88_strict"] is False
    if r["verdict"] == "PASS":
        raise SystemExit("unexpected PASS")

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

def ids_from(repo, spec):
    r = git(repo, "ls-tree", "-r", "--name-only", spec)
    assert r.returncode == 0, r.stderr
    out = set()
    rx = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.I)
    for line in r.stdout.splitlines():
        m = rx.search(line)
        if m:
            out.add(m.group(0).upper())
    return out

new = ids_from(adv_r, HEAD_N + ":advisories/unreviewed")
old = ids_from(adv_u, HEAD_O + ":advisories/unreviewed")
added = sorted(new - old)
assert len(added) == 6296
got = hashlib.sha256(("\n".join(added) + "\n").encode("ascii")).hexdigest()
assert got == delta_h, (got, delta_h)
assert set(ids) <= set(added)

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
    if not any(str(p).startswith("herdr-") or str(p).startswith("orchestrator-") for p in path.parts):
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
excluded |= strict
assert len(excluded) == 8189
got = hashlib.sha256(("\n".join(sorted(excluded)) + "\n").encode("ascii")).hexdigest()
assert got == excl_h, (got, excl_h)
assert set(ids).isdisjoint(excluded)

def author(repo, sha):
    r = git(repo, "log", "-1", "--format=%an", sha)
    assert r.returncode == 0, (repo, sha, r.stderr)
    return r.stdout.strip()

def npar(repo, sha):
    r = git(repo, "rev-list", "--parents", "-n1", sha)
    return len(r.stdout.split()) - 1

assert Path(gp).exists()
assert author(gp, "8ac5a30519b6f4af85398b9b9d7064ff4d452da2") == "GPT 5.6"
assert npar(gp, "8ac5a30519b6f4af85398b9b9d7064ff4d452da2") == 1
body = git(gp, "log", "-1", "--format=%ae%n%B", "8ac5a30519b6f4af85398b9b9d7064ff4d452da2").stdout
assert "codex@openai.com" in body
assert "GHSA-rwj8-pgh3-r573" in body.lower() or "GHSA-RWJ8-PGH3-R573" in body.upper()

assert Path(fb).exists()
assert author(fb, "72faf6dd3c85628e332d3e567124b86708ce2695") == "Henrique Dias"
assert npar(fb, "72faf6dd3c85628e332d3e567124b86708ce2695") == 1
b847 = git(fb, "log", "-1", "--format=%B", "847d08bdd135e5c3659f2e6dea2f0cd36617af9b").stdout
assert "Co-Authored-By: Claude Opus 4.8" in b847

assert Path(av).exists()
assert author(av, "1adcb75458a3b31058655698a833e8cbde4d0593") == "Daniel Neto"
assert author(av, "1b55a9b3c4911d2f31594ce2e60566c70c6b95e8") == "Daniel Neto"

assert Path(gr).exists()
assert author(gr, "694f1dae06d9061bbf0669c4291e3b206f998d71") == "Andy Miller"
assert npar(gr, "694f1dae06d9061bbf0669c4291e3b206f998d71") == 2
assert "ghsa-xwv3" in git(gr, "log", "-1", "--format=%s", "f81bbd1f3eebddc319c8ef2dfedbd5961cd96349").stdout.lower()

assert Path(jc).exists()
assert author(jc, "b0c428e6f993e1b5ece5c1c3cb2523e887cd52cf") == "PJ Fanning"
assert npar(jc, "b0c428e6f993e1b5ece5c1c3cb2523e887cd52cf") == 1
assert git(jc, "log", "-1", "--format=%ae", "4cdd529749da396cc7edf6d4a2aad41d47902641").stdout.strip() == "tonghuaroot@gmail.com"
assert npar(jc, "050b429804dce2a7e08f0be1b0b4c3d040fdb9cd") == 2

assert Path(gh).exists()
full = git(gh, "rev-parse", "c03a70d").stdout.strip()
assert full == "c03a70ddb702ef0dbf096eb649d53999ef4c1696"
assert author(gh, full) == "Ryan Kurtz"

sys.path.insert(0, str(root / "cve-analyzer/src"))
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit

def ci(repo, sha):
    rec = git(repo, "log", "-1", "--format=%H%n%an%n%ae%n%cn%n%ce%n%aI%n%B", sha)
    assert rec.returncode == 0
    parts = rec.stdout.split("\n", 6)
    while len(parts) < 7:
        parts.append("")
    return CommitInfo(
        sha=parts[0].strip(), author_name=parts[1], author_email=parts[2],
        committer_name=parts[3], committer_email=parts[4],
        authored_date=parts[5], message=parts[6],
    )

assert MATCHER_CONTRACT.startswith("ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1")
assert matches_for_commit(ci(gp, "8ac5a30519b6f4af85398b9b9d7064ff4d452da2"))
assert matches_for_commit(ci(fb, "72faf6dd3c85628e332d3e567124b86708ce2695")) == ()
assert matches_for_commit(ci(fb, "847d08bdd135e5c3659f2e6dea2f0cd36617af9b"))
assert matches_for_commit(ci(jc, "b0c428e6f993e1b5ece5c1c3cb2523e887cd52cf")) == ()
print("VALIDATION_OK inspected=12 PASS_PROPOSAL=0 conservation=12=0+12 delta=6296")
PY

printf 'REPLAY_OK inspected=12 PASS_PROPOSAL=0 conservation=12=0+12 delta=6296 frozen=%s old=%s\n' "$HEAD_N" "$HEAD_O"
