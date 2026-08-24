#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-cf4-b1-predecessor-grok46-medium.
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
OWNED=$ROOT/autoresearch/herdr-260814-cf4-b1-predecessor-grok46-medium
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
  errf=$(mktemp /tmp/cf4-b1p-giterr.XXXXXX)
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
expect_eq "$(/usr/bin/test -d "$ADV_R/advisories/unreviewed" && echo yes || echo no)" no f2c6_unreviewed_absent

n_assign=$(/usr/bin/wc -l < "$OWNED/assignment.jsonl" | /usr/bin/tr -d ' ')
n_cases=$(/usr/bin/wc -l < "$OWNED/cases.jsonl" | /usr/bin/tr -d ' ')
expect_eq "$n_assign" 0 assignment_rows
expect_eq "$n_cases" 0 cases_rows

owned_count=$(/usr/bin/find "$OWNED" -maxdepth 1 -type f | /usr/bin/wc -l | /usr/bin/tr -d ' ')
expect_eq "$owned_count" 5 owned_files

GARD=/home/hanqing/.cache/cve-analyzer/repos/gardener_gardener-extension-provider-aws
H3=/home/hanqing/.cache/cve-analyzer/repos/h3js_h3
MINI=/home/hanqing/.cache/cve-analyzer/repos/isaacs_minimatch
require_dir "$GARD"
require_dir "$H3"
require_dir "$MINI"

expect_eq "$(gitx "$GARD" rev-parse cb5045fc146248296994804bbfe27bd896938bf2)" cb5045fc146248296994804bbfe27bd896938bf2 gardener_fix
expect_eq "$(gitx "$H3" rev-parse 7791538e15ca22437307c06b78fa155bb73632a6)" 7791538e15ca22437307c06b78fa155bb73632a6 h3_fix
expect_eq "$(gitx "$MINI" rev-parse 11d0df6165d15a955462316b26d52e5efae06fce)" 11d0df6165d15a955462316b26d52e5efae06fce minimatch_fix

contains_tag() {
  local tags
  tags=$(gitx "$1" tag --contains "$2")
  if ! printf '%s\n' "$tags" | /usr/bin/grep -Fxq "$3"; then
    printf 'missing tag %s contains %s\n' "$3" "$2" >&2
    exit 1
  fi
}
contains_tag "$GARD" cb5045fc146248296994804bbfe27bd896938bf2 v1.64.0
contains_tag "$H3" 7791538e15ca22437307c06b78fa155bb73632a6 v1.15.8
contains_tag "$MINI" 11d0df6165d15a955462316b26d52e5efae06fce v10.2.3

expect_eq "$(gitx "$GARD" log -1 --format=%s cb5045fc146248296994804bbfe27bd896938bf2)" "Shoot input validation (#1479)" gardener_subj
expect_eq "$(gitx "$GARD" log -1 --format=%an cb5045fc146248296994804bbfe27bd896938bf2)" "Konstantinos Angelopoulos" gardener_author

python3 - "$OWNED" "$SUMMARY" "$ROOT" "$ADV_R" "$ADV_U" <<'PY'
import hashlib, json, os, re, subprocess, sys
from pathlib import Path

owned, summary_p, root, adv_r, adv_u = sys.argv[1:]
root = Path(root)
owned = Path(owned)
assigns = [json.loads(l) for l in owned.joinpath("assignment.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in owned.joinpath("cases.jsonl").read_text().splitlines() if l.strip()]
assert assigns == [] and cases == []
result = json.loads(owned.joinpath("result.json").read_text())
assert result["counts"]["PASS_PROPOSAL"] == 0
assert result["counts"]["assigned"] == 0
assert result["conservation"]["equation"] == "0=0+0"
assert result["conservation"]["did_not_pad"] is True
assert result["universe"]["inspected_prefix"] == 430
assert result["universe"]["inspect_cap"] == 600
assert result["universe"]["atomic_hits_found"] == 0
assert result["universe"]["shortfall"] == 12
assert result["universe"]["stop_reason"] == "qualified_pool_exhausted_shortfall_12"
assert result["bucket"]["eq"] == 1

def bucket(ghsa: str) -> int:
    return int(hashlib.sha256(ghsa.encode("ascii")).hexdigest(), 16) % 6

assert bucket("GHSA-227X-7MH8-3CF6") == 1
assert bucket("GHSA-XVWH-VH35-WWV2") == 1

BLAME = {
    "GHSA-Q6CQ-MHR2-JMR5", "GHSA-GVWX-54WH-QM9J", "GHSA-724G-MXRG-4QVM",
    "GHSA-H2WF-967X-GXVW", "GHSA-MM7M-92G8-7M47", "GHSA-2GCR-MFCQ-WCC3",
    "GHSA-JXXR-4GWJ-5JF2", "GHSA-J7V9-F46R-2RP4", "GHSA-6M6C-36F7-FHXH",
    "GHSA-6JH4-47V2-4G37", "GHSA-R7FX-8G49-7HHR", "GHSA-9C4Q-HQ6P-C237",
}
HISTORY = {
    "GHSA-46R5-X6JQ-V8G6", "GHSA-6465-JGVQ-JHGP", "GHSA-64RR-PP78-62WW",
    "GHSA-6XPM-GGF7-WC3P", "GHSA-8C7Q-86FQ-VVMH", "GHSA-8M59-7XV8-735H",
    "GHSA-C67J-W6G6-Q2CM", "GHSA-CWFJ-642J-GFH4", "GHSA-FMQF-PMCM-8CX9",
    "GHSA-GQ3W-7JJ3-X7GR", "GHSA-GRP3-H8M8-45P7", "GHSA-JH6H-V6MP-H22V",
}

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
        if not lane.is_dir() or lane.name == "herdr-260814-cf4-b1-predecessor-grok46-medium":
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
assert len(excluded) >= 8159
for bid in BLAME:
    assert bid in excluded, bid
for hid in HISTORY:
    assert hid in excluded, hid

summary = json.loads(Path(summary_p).read_text())
counted = {str(x).upper() for x in summary["strict_released_case_ids"]}
assert len(counted) == 88

ADVISORY_RE = re.compile(
    r"https?://github\.com/([^/]+)/([^/]+)/security/advisories/(GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4})"
)
COMMIT_RE = re.compile(r"https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})")

def load_reviewed(cid_lower_path):
    p = Path(adv_r) / cid_lower_path
    obj = json.loads(p.read_text(encoding="utf-8"))
    cid = str(obj.get("id") or "").strip().upper()
    assert not obj.get("withdrawn")
    published = str(obj.get("published") or "")
    assert published.startswith("2025") or published.startswith("2026")
    urls = [str(r.get("url") or "") for r in (obj.get("references") or []) if isinstance(r, dict)]
    fp = False
    exact = False
    repo = None
    for u in urls:
        m = ADVISORY_RE.search(u)
        if m and m.group(3).upper() == cid:
            fp = True
            repo = f"{m.group(1)}/{m.group(2)}"
        cm = COMMIT_RE.search(u)
        if cm and repo and cm.group(1).lower() == repo.split("/")[0].lower() and cm.group(2).lower() == repo.split("/")[1].lower():
            exact = True
    assert fp and exact
    return cid

assert load_reviewed("advisories/github-reviewed/2025/09/GHSA-227x-7mh8-3cf6/GHSA-227x-7mh8-3cf6.json") == "GHSA-227X-7MH8-3CF6"
last_p = Path(adv_u) / "advisories/unreviewed/2026/05/GHSA-xvwh-vh35-wwv2/GHSA-xvwh-vh35-wwv2.json"
last = json.loads(last_p.read_text(encoding="utf-8"))
assert str(last.get("id") or "").strip().upper() == "GHSA-XVWH-VH35-WWV2"
assert not last.get("withdrawn")
assert str(last.get("published") or "").startswith("2026")
assert any("/commit/" in str((r or {}).get("url") or "") for r in (last.get("references") or []))
for cid in BLAME | HISTORY:
    assert cid in excluded

rev_files = 0
for dirpath, ds, fs in os.walk(Path(adv_r) / "advisories/github-reviewed"):
    for f in fs:
        if f.startswith("GHSA-") and f.endswith(".json"):
            rev_files += 1
unr_files = 0
for dirpath, ds, fs in os.walk(Path(adv_u) / "advisories/unreviewed"):
    for f in fs:
        if f.startswith("GHSA-") and f.endswith(".json"):
            unr_files += 1
assert rev_files == 34389
assert unr_files == 317316

rev_ids = {p.stem.upper() for p in (Path(adv_r) / "advisories/github-reviewed").rglob("GHSA-*.json")}
unr_ids = {p.stem.upper() for p in (Path(adv_u) / "advisories/unreviewed").rglob("GHSA-*.json")}
assert len(rev_ids & unr_ids) == 135

sys.path.insert(0, str(root / "cve-analyzer/src"))
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit

assert MATCHER_CONTRACT.startswith("ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1")

def git_log(clone, sha):
    env = dict(os.environ)
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

gard = "/home/hanqing/.cache/cve-analyzer/repos/gardener_gardener-extension-provider-aws"
assert matches_for_commit(git_log(gard, "cb5045fc146248296994804bbfe27bd896938bf2")) == ()

print("conservation assigned=0 reviewed=0 unreviewed_rows=0 equation=0=0+0")
print("exclusion_ids=%d exclusion_sha256=%s files_parsed=%d" % (len(excluded), excl_sha, files_parsed))
print("canonical88=88 overlap=0 bucket=1 frozen=0 PASS_PROPOSAL=0")
print("qualified_pool=430 inspected_prefix=430 inspect_cap=600 shortfall=12 stop=qualified_pool_exhausted_shortfall_12")
print("prefix_first=GHSA-227X-7MH8-3CF6 prefix_last=GHSA-XVWH-VH35-WWV2")
print("sources reviewed=f2c6ab3202aeafb36fbea6e76d892532acfca1a6 subtree=advisories/github-reviewed")
print("sources unreviewed=39d8887723797efc1804585dd06585c9fd751226 subtree=advisories/unreviewed")
print("did_not_rereview_cf4_b1_blame=12 did_not_rereview_cf4_b1_history=12")
PY

printf 'REPLAY_OK reviewed=0 PASS_PROPOSAL=0 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=0\n'
