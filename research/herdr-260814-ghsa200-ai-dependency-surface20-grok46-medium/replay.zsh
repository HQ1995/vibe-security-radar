#!/usr/bin/env zsh
# Fail-closed zsh replay for herdr-260814-ghsa200-ai-dependency-surface20-grok46-medium.
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
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-ai-dependency-surface20-grok46-medium

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

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
require_file "$OWNED/work/cross_lane_exclusion.json"
require_file "$OWNED/work/original-hits.jsonl"
require_file "$OWNED/work/remaining-hits.jsonl"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/freeze.json"
require_file "$OWNED/notes/README.md"
require_file "$OWNED/notes/freeze.txt"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/ledger.jsonl" \
  58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" \
  d436f47f82297eb0d9363ad0f3876adc639b1f61e9b23c7f9d613545741e106e
expect_hash "$OWNED/work/cross_lane_exclusion.json" \
  1b5e53fde50984e9e71a36f26a733af67cd06ddd32a19a8ff8b8f4c7056bad8e
expect_hash "$OWNED/work/original-hits.jsonl" \
  539a07eb9a78e33fb260cb287ea89753782ff09d09fb79997d3f3ee1a416e45c
expect_hash "$OWNED/work/remaining-hits.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/work/uniqueness.json" \
  6ba4add385b0c110c6769201f3a17b75832e388c4ebb95b5fd4d7c62cf58803a
expect_hash "$OWNED/work/freeze.json" \
  3b55e8037467a25f37523ad9b249b31ce5868a5876f565909d94e3f30d189db8
expect_hash "$OWNED/selected.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/cases.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/report.md" \
  44aa753a5a052dc2d9b9f33fbf636c5806e1d789f9b0e118c0fbb9754f475bc9
expect_hash "$OWNED/notes/README.md" \
  471336397497542c040c055f33b37ffb7883e47812d693f908d10ad5e1c0eefb
expect_hash "$OWNED/notes/freeze.txt" \
  a219a71e3267092406451a6d0e26ee1bc16308cce11e20f8f6d70b5b6bc99764

python3 - "$OWNED" "$ROOT" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
root = Path(sys.argv[2])
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
assert sel == []
assert cases == []
cross = json.loads((owned / "work/cross_lane_exclusion.json").read_text())
assert cross["owned_n"] == 14
assert len(cross["owned_ids"]) == 14
assert cross["original_surface_hit_ids"] == [
    "GHSA-8883-9W57-VWV6",
    "GHSA-MP66-RF4F-MHH8",
    "GHSA-XHQ5-45PM-2GJR",
]
assert cross["original_hits_in_fixblame14"] == cross["original_surface_hit_ids"]
assert set(cross["original_surface_hit_ids"]).issubset(set(cross["owned_ids"]))
assert cross["remaining_after_cross_lane"] == []
assert cross["remaining_n"] == 0
assert cross["padding"] is False
assert cross["deep_review_of_duplicate_ids"] is False
orig = [json.loads(l) for l in (owned / "work/original-hits.jsonl").read_text().splitlines() if l.strip()]
assert [r["ghsa_id"] for r in orig] == cross["original_surface_hit_ids"]
assert (owned / "work/remaining-hits.jsonl").read_text() == ""
uni = json.loads((owned / "work/uniqueness.json").read_text())
assert uni["start_count"] == 82
assert uni["current_leader_accepted_count"] == 82
assert uni["packet_delta"] == 0
assert uni["frozen_selected_ids"] == []
assert uni["pass_proposals"] == []
assert uni["canonical82_overlap"] == []
assert uni["remaining_after_cross_lane"] == []
c82 = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json").read_text())
assert c82["canonical_strict_count"] == 82
assert not (set(cross["original_surface_hit_ids"]) & set(c82["strict_released_case_ids"]))
freeze = json.loads((owned / "work/freeze.json").read_text())
assert freeze["n_selected"] == 0
assert freeze["selected_ids"] == []
assert freeze["n_surface_hits"] == 0
assert freeze["n_surface_hits_original"] == 3
assert freeze["padding"] is False
assert freeze["deep_review"] is False
assert freeze["terminal_zero_after_cross_lane"] is True
res = json.loads((owned / "result.json").read_text())
assert res["start_count"] == 82
assert res["current_leader_accepted_count"] == 82
assert res["packet_delta"] == 0
assert res["exact_selected_ids"] == []
assert res["pass_proposals"] == []
assert res["counts"]["PASS"] == 0
assert res["deep_review"] is False
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
    "notes/facts/README.md",
    "notes/diffs/README.md",
    "work/cross_lane_exclusion.json",
    "work/original-hits.jsonl",
    "work/remaining-hits.jsonl",
    "work/uniqueness.json",
    "work/freeze.json",
]
for name in names:
    text = (owned / name).read_text(encoding="utf-8")
    if name in ("selected.jsonl", "cases.jsonl", "work/remaining-hits.jsonl"):
        assert text == ""
        continue
    assert text
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    assert text.endswith("\n"), name
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (name, line)
print("conservation assigned=0 reviewed=0 unreviewed=0 PASS_proposal=0 original_hits=3 remaining=0")
PY

printf 'REPLAY_OK reviewed=0 PASS_proposal=0 original_hits=3 remaining=0 packet_delta=0 start=82 current=82\n'
