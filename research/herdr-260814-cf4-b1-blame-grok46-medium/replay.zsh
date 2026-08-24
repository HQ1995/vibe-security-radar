#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-cf4-b1-blame-grok46-medium.
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
OWNED=$ROOT/autoresearch/herdr-260814-cf4-b1-blame-grok46-medium
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
  errf=$(mktemp /tmp/cf4-b1-giterr.XXXXXX)
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

NETTY=/home/hanqing/.cache/cve-analyzer/repos/netty_netty
TAR=/home/hanqing/.cache/cve-analyzer/repos/isaacs_node-tar
YAML=/home/hanqing/.cache/cve-analyzer/repos/nodeca_js-yaml
HONO=/home/hanqing/.cache/cve-analyzer/repos/honojs_hono
MINIO=/home/hanqing/.cache/cve-analyzer/repos/minio_minio
require_dir "$NETTY"
require_dir "$TAR"
require_dir "$YAML"
require_dir "$HONO"
require_dir "$MINIO"

expect_eq "$(gitx "$NETTY" rev-parse bb2ff68a1fb71cb4b0eb9a9e17b66c52aff680c6)" bb2ff68a1fb71cb4b0eb9a9e17b66c52aff680c6 netty_fix
expect_eq "$(gitx "$TAR" rev-parse 7a635c29f5edbf083557374d43984273ecfed5b3)" 7a635c29f5edbf083557374d43984273ecfed5b3 tar_fix
expect_eq "$(gitx "$YAML" rev-parse 39f3211a2f01b3c6982710cf21434ab7060acefe)" 39f3211a2f01b3c6982710cf21434ab7060acefe yaml_fix
expect_eq "$(gitx "$HONO" rev-parse 6cbb025ff87fca1a3d00d0ccca0eaf3a6385c3f1)" 6cbb025ff87fca1a3d00d0ccca0eaf3a6385c3f1 hono_fix
expect_eq "$(gitx "$MINIO" rev-parse 76913a9fd5c6e5c2dbd4e8c7faf56ed9e9e24091)" 76913a9fd5c6e5c2dbd4e8c7faf56ed9e9e24091 minio_fix

contains_tag() {
  local tags
  tags=$(gitx "$1" tag --contains "$2")
  if ! printf '%s\n' "$tags" | /usr/bin/grep -Fxq "$3"; then
    printf 'missing tag %s contains %s\n' "$3" "$2" >&2
    exit 1
  fi
}
contains_tag "$NETTY" 5b68c61f37aa4a3045cba624cbea239655c9003b netty-4.2.16.Final
contains_tag "$NETTY" bb2ff68a1fb71cb4b0eb9a9e17b66c52aff680c6 netty-4.1.136.Final
contains_tag "$TAR" 7a635c29f5edbf083557374d43984273ecfed5b3 v7.5.17
contains_tag "$YAML" 39f3211a2f01b3c6982710cf21434ab7060acefe 5.2.1

parent=$(gitx "$TAR" rev-parse 7a635c29f5edbf083557374d43984273ecfed5b3^)
blame=$(gitx "$TAR" blame -l -w -M -C -L176,176 "$parent" -- src/pax.ts)
sha=${blame%% *}
sha=${sha#^}
python3 - "$OWNED" "$SUMMARY" "$ROOT" "$ADV_R" "$ADV_U" "$sha" "$parent" <<'PY'
import hashlib, json, re, subprocess, sys
from pathlib import Path

owned, summary_p, root, adv_r, adv_u, blamed, parent = sys.argv[1:]
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

def bucket(ghsa: str) -> int:
    return int(hashlib.sha256(ghsa.encode("ascii")).hexdigest(), 16) % 6

for cid in ids:
    assert bucket(cid) == 1, cid

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
        rows = []
        for line in text.splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows
    return json.loads(text)

excluded = set()
files_parsed = 0
for group in ("herdr-*", "orchestrator-*"):
    for lane in sorted((root / "autoresearch").glob(group)):
        if not lane.is_dir() or lane.name == "herdr-260814-cf4-b1-blame-grok46-medium":
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

summary = json.loads(Path(summary_p).read_text())
counted = {str(x).upper() for x in summary["strict_released_case_ids"]}
assert len(counted) == 88
for cid in ids:
    assert cid not in counted, cid

# reviewed f2c6 wins: each frozen identity exists under github-reviewed
for a in assigns:
    p = Path(adv_r) / a["advisory_path"]
    assert p.is_file(), p
    obj = json.loads(p.read_text())
    assert obj.get("id", "").upper() == a["case_id"]
    assert not obj.get("withdrawn")
    urls = " ".join((r or {}).get("url") or "" for r in (obj.get("references") or []))
    needle = f"github.com/{a['repository']}/security/advisories/{a['case_id'].lower()}"
    assert needle.lower() in urls.lower(), needle

# unreviewed subtree is present and was not dropped as a source
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

tar = "/home/hanqing/.cache/cve-analyzer/repos/isaacs_node-tar"
assert matches_for_commit(git_log(tar, "7a635c29f5edbf083557374d43984273ecfed5b3")) == ()
assert matches_for_commit(git_log(tar, blamed)) == ()
hono = "/home/hanqing/.cache/cve-analyzer/repos/honojs_hono"
assert matches_for_commit(git_log(hono, "6cbb025ff87fca1a3d00d0ccca0eaf3a6385c3f1")) == ()
minio = "/home/hanqing/.cache/cve-analyzer/repos/minio_minio"
assert matches_for_commit(git_log(minio, "76913a9fd5c6e5c2dbd4e8c7faf56ed9e9e24091")) == ()

print("conservation assigned=12 reviewed=12 unreviewed_rows=0 equation=12=12+0")
print("exclusion_ids=8068 exclusion_sha256=dc2530d076bbd835c6c25809a779724693aa8fb910cd5182ef41449d76e78e6a")
print("canonical88=88 overlap=0 bucket=1 frozen=12 PASS_PROPOSAL=0")
print("sources reviewed=f2c6ab3202aeafb36fbea6e76d892532acfca1a6 subtree=advisories/github-reviewed")
print("sources unreviewed=39d8887723797efc1804585dd06585c9fd751226 subtree=advisories/unreviewed")
print("tar_parent", parent, "tar_blamed", blamed)
PY

printf 'REPLAY_OK reviewed=12 PASS_PROPOSAL=0 REJECT=12 NARROW=0 UNKNOWN=0 BLOCKED=0\n'
