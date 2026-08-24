#!/usr/bin/env zsh
# Fail-closed zsh replay for herdr-260814-ghsa200-fresh-delta20-grok46-low.
# English only. Do not print credentials or environment values.
# Do not clone, commit, push, or modify shared caches.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# PASS is a proposal only. This script does not admit any row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fresh-delta20-grok46-low
ADV=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
FROZEN=a42c436870111aa3f221257c9d56126a93173ccc
CURRENT=f2c6ab3202aeafb36fbea6e76d892532acfca1a6

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

gitx() {
  local repo=$1
  shift
  local errfile rc
  errfile=$(/usr/bin/mktemp)
  set +e
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errfile"
  rc=$?
  set -e
  /usr/bin/grep -vF -- 'unable to normalize alternate object path:' "$errfile" >&2 || true
  /usr/bin/rm -f "$errfile"
  return $rc
}

require_dir() {
  if [[ ! -d $1 ]]; then
    printf 'missing directory: %s\n' "$1" >&2
    exit 1
  fi
}

require_file() {
  if [[ ! -f $1 ]]; then
    printf 'missing file: %s\n' "$1" >&2
    exit 1
  fi
}

expect_hash() {
  local target=$1 expected=$2
  local got
  got=$(/usr/bin/sha256sum "$target" | /usr/bin/awk '{print $1}')
  if [[ $got != "$expected" ]]; then
    printf 'hash mismatch %s\n expected %s\n got      %s\n' "$target" "$expected" "$got" >&2
    exit 1
  fi
}

require_dir "$OWNED"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/work/exclusion-freeze.json"
require_file "$OWNED/work/delta-summary.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/notes/README.md"
require_dir "$ADV/.git"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/ledger.jsonl" \
  58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" \
  d436f47f82297eb0d9363ad0f3876adc639b1f61e9b23c7f9d613545741e106e
expect_hash "$OWNED/work/exclusion-freeze.json" \
  8068da298c64f7f1f0eace0b77c9a03d1fb920e54278782b0e952582b637b85b
expect_hash "$OWNED/work/delta-summary.json" \
  53fcd3f8f61f294565164497b645c616d66d04d6d3277092939831866a71ad25
expect_hash "$OWNED/work/uniqueness.json" \
  f96ec01277640f4869d285f2615010c68240803e332441ab072d4ca9f8a46adc
expect_hash "$OWNED/selected.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/cases.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/report.md" \
  dc5ba7ab872f77546806935d0847ac52e1125494af8bf4d2d9c34646303dfc55
expect_hash "$OWNED/notes/README.md" \
  82c2403dd86ddbc9dca0dd7d83c3b457c9a596a2890b57e2695ef44f5731163a

[[ "$(gitx "$ADV" rev-parse HEAD)" == "$CURRENT" ]]
[[ "$(gitx "$ADV" rev-parse "$FROZEN")" == "$FROZEN" ]]
gitx "$ADV" merge-base --is-ancestor "$FROZEN" HEAD

python3 - "$OWNED" "$ROOT" "$ADV" "$FROZEN" "$CURRENT" << 'PY'
import json, re, subprocess, sys
from pathlib import Path

owned = Path(sys.argv[1])
root = Path(sys.argv[2])
adv = Path(sys.argv[3])
frozen = sys.argv[4]
current = sys.argv[5]

sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
assert sel == []
assert cases == []
excl = json.loads((owned / "work/exclusion-freeze.json").read_text())
assert excl["preserved_public_case_count"] == 212
assert excl["strict_released_count"] == 82
assert excl["union_ghsa_count"] == 224
assert excl["strict_not_in_pub_count"] == 12
assert len(excl["preserved_public_case_ids"]) == 212
assert len(excl["strict_released_case_ids"]) == 82
assert len(excl["union_exclusion_ids"]) == 224
assert len(excl["strict_not_in_pub"]) == 12
assert set(excl["union_exclusion_ids"]) == set(excl["preserved_public_case_ids"]) | set(excl["strict_released_case_ids"])
assert set(excl["strict_not_in_pub"]) == set(excl["strict_released_case_ids"]) - set(excl["preserved_public_case_ids"])
assert excl["cve_aliases_counted"] is False
c82 = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json").read_text())
assert c82["canonical_strict_count"] == 82
assert len(c82["strict_released_case_ids"]) == 82
assert {x.upper() for x in c82["strict_released_case_ids"]} == set(excl["strict_released_case_ids"])
delta = json.loads((owned / "work/delta-summary.json").read_text())
assert delta["git"]["frozen_commit"] == frozen
assert delta["git"]["current_commit"] == current
assert delta["git"]["added_reviewed_ids"] == []
assert delta["git"]["removed_reviewed_ids"] == []
assert delta["git"]["modified_reviewed_ids"] == []
assert delta["truly_new_reviewed_first_party_ids"] == []
assert delta["frozen_selected_ids"] == []
assert delta["graphql"]["published_nodes"] == 0
assert delta["graphql"]["updated_nodes"] == 1
assert delta["graphql"]["published_truly_new_reviewed"] == []
assert delta["graphql"]["updated_truly_new_reviewed"] == []
uni = json.loads((owned / "work/uniqueness.json").read_text())
assert uni["start_count"] == 82
assert uni["current_leader_accepted_count"] == 82
assert uni["packet_delta"] == 0
assert uni["frozen_selected_ids"] == []
assert uni["pass_proposals"] == []
res = json.loads((owned / "result.json").read_text())
assert res["start_count"] == 82
assert res["current_leader_accepted_count"] == 82
assert res["packet_delta"] == 0
assert res["exact_selected_ids"] == []
assert res["pass_proposals"] == []
assert res["counts"]["PASS"] == 0
assert res["worker_pass_is_proposal_only"] is True
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(r"ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}")
names = [
    "selected.jsonl",
    "cases.jsonl",
    "report.md",
    "replay.zsh",
    "result.json",
    "sha256.txt",
    "notes/README.md",
    "notes/freeze.txt",
    "work/exclusion-freeze.json",
    "work/delta-summary.json",
    "work/uniqueness.json",
]
for name in names:
    text = (owned / name).read_text(encoding="utf-8")
    if name in ("selected.jsonl", "cases.jsonl"):
        assert text == ""
        continue
    assert text
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    assert text.endswith("\n"), name
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (name, line)

def reviewed_ids(rev):
    out = subprocess.check_output(
        ["/usr/bin/git", "--no-optional-locks", "-C", str(adv), "ls-tree", "-r", "--name-only", rev, "--", "advisories/github-reviewed"],
        text=True,
    )
    ids = set()
    for line in out.splitlines():
        m = re.search(r"(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})\.json$", line, re.I)
        if m:
            ids.add(m.group(1).upper())
    return ids

frozen_ids = reviewed_ids(frozen)
current_ids = reviewed_ids(current)
assert len(frozen_ids) == 34389, len(frozen_ids)
assert len(current_ids) == 34389, len(current_ids)
assert frozen_ids == current_ids
print("conservation assigned=0 reviewed=0 unreviewed=0 PASS_proposal=0 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0 truly_new=0")
PY

printf 'REPLAY_OK reviewed=0 PASS_proposal=0 truly_new=0 packet_delta=0 start=82 current=82\n'
