#!/usr/bin/env zsh
# Fail-closed zsh replay for herdr-260814-ghsa200-ai-route-surface20-grok46-xhigh.
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
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-ai-route-surface20-grok46-xhigh
CLONE=/home/hanqing/.cache/cve-analyzer/repos/doobidoo_mcp-memory-service
AI=fd2bbf49cca2b01ee6cbd158b053e7051f586b7e
AI_PARENT=be7c5b95761a8b11d33f13daf80a533d8f717633
FIX=18f4323ca92763196aa2922f691dfbeb6bd84e48
FIX_PARENT=06faeeef2a94c8db58db9422593c640236b999b2
ORIGIN=4e796e2814149f966901dc59528da230a9da93b3

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

g() {
  local repo=$1
  shift
  local errf=$OWNED/work/.giterr
  set +e
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
  if [[ -s $errf ]]; then
    grep -vF 'unable to normalize alternate object path' "$errf" >&2 || true
  fi
  rm -f "$errf"
  return $rc
}

require_dir "$OWNED"
require_dir "$CLONE"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/work/cross_lane_exclusion.json"
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
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/selected.jsonl" \
  344761d2c9c683ee6bf2b451f79b70b9e0b12802f037f972e8b159dc9b20f43e
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-residual-security20-grok46-high/selected.jsonl" \
  f179f86d9097f71a0d632b2ea572dba0d1f6b1bb16743a332f331f66af6aba3f
expect_hash "$OWNED/work/cross_lane_exclusion.json" \
  f01f89bb8e8fe125ddebbc436ac35d25bc5ec4ee247f94fb71df644073523edd
expect_hash "$OWNED/work/uniqueness.json" \
  9258cba62c76f1c9af511026cf24b79c807ef1a3eb7434d01724760a335c5b51
expect_hash "$OWNED/work/freeze.json" \
  37ef69744b003ef8d56c8a22c05aef4b8bcc2f827123f7b5cc0a2121266d46a1
expect_hash "$OWNED/selected.jsonl" \
  ea375573bac6d4e60cb25a0891831db9c6b7538e13de5caf4f2b79dbc0320330
expect_hash "$OWNED/cases.jsonl" \
  b48a6f4da5a8ed489f2ca224c73b52a4c587b359ce58c09d10faf869a6c7158b
expect_hash "$OWNED/report.md" \
  6fc4cc5720885ac1a0a795dcebad07f3e262e4a0e5841aa35fc432940731df1d
expect_hash "$OWNED/notes/README.md" \
  e022aca1453155f01d54c4f372c6f99dbbaa05ac6e35784f23094603ca2a12ba
expect_hash "$OWNED/notes/freeze.txt" \
  a24d8db3cedbd6e9b8ae45c3da440067c65ab3978f00aa022d4bab42024e1353
expect_hash "$OWNED/notes/facts/GHSA-73HC-M4HX-79PJ.deep.json" \
  4a42224b77daf72552899e986eecfbe4a438621681dcf756ca56cd6c68398c9d

# Topology: claimed AI commit is atomic and an ancestor of the fix parent.
parents=$(g "$CLONE" rev-list --parents -n 1 "$AI")
print -r -- "$parents" | /usr/bin/awk '{ if (NF != 2) { print "AI not atomic" > "/dev/stderr"; exit 1 } }'
g "$CLONE" merge-base --is-ancestor "$AI" "$FIX_PARENT"
g "$CLONE" merge-base --is-ancestor "$ORIGIN" "$AI_PARENT"

# Parent already had the advisory health entrypoint.
g "$CLONE" grep -F -q '/health/detailed' "$AI_PARENT" -- src/mcp_memory_service/web/api/health.py
g "$CLONE" grep -F -q 'database_path' "$AI_PARENT" -- src/mcp_memory_service/web/api/health.py

# Claimed AI commit adds the sibling token, not the health origin.
g "$CLONE" show "$AI" -- src/mcp_memory_service/web/api/health.py | grep -F -q '/memory-stats'
body=$(g "$CLONE" log -1 --format=%B "$ORIGIN")
print -r -- "$body" | grep -Eiq 'claude|copilot|cursor agent|noreply@anthropic|codex@openai' && {
  printf 'unexpected AI marker on health origin\n' >&2
  exit 1
} || true

# Vulnerable tag contains AI and excludes fix. Fixed tag contains fix.
g "$CLONE" merge-base --is-ancestor "$AI" v10.20.6
if g "$CLONE" merge-base --is-ancestor "$FIX" v10.20.6; then
  printf 'fix unexpectedly in v10.20.6\n' >&2
  exit 1
fi
g "$CLONE" merge-base --is-ancestor "$FIX" v10.21.0

python3 - "$OWNED" "$ROOT" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
root = Path(sys.argv[2])
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
assert [r["ghsa_id"] for r in sel] == ["GHSA-73HC-M4HX-79PJ"]
assert len(cases) == 1
assert cases[0]["case_id"] == "GHSA-73HC-M4HX-79PJ"
assert cases[0]["worker_verdict"] == "REJECT"
assert cases[0]["countable_proposal"] is False
assert cases[0]["packet_delta"] == 0
assert cases[0]["gates"]["identity_gate"] == "PASS"
assert cases[0]["gates"]["uniqueness_gate"] == "PASS"
assert cases[0]["gates"]["ai_hunk_gate"] == "FAIL"
assert cases[0]["gates"]["but_for_gate"] == "FAIL"
assert cases[0]["reject_class"] == "SIBLING_ROUTE_PARENT_HAD_EQUIVALENT_ENTRYPOINT"
cross = json.loads((owned / "work/cross_lane_exclusion.json").read_text())
assert cross["fixblame20x"]["n"] == 14
assert cross["residual20"]["n"] == 20
assert cross["overlap_with_fixblame14"] == []
assert cross["overlap_with_residual20"] == []
assert cross["this_lane_selected"] == ["GHSA-73HC-M4HX-79PJ"]
assert cross["padding"] is False
assert cross["mechanical_regardless_of_outcomes"] is True
uni = json.loads((owned / "work/uniqueness.json").read_text())
assert uni["start_count"] == 82
assert uni["current_leader_accepted_count"] == 82
assert uni["packet_delta"] == 0
assert uni["frozen_selected_ids"] == ["GHSA-73HC-M4HX-79PJ"]
assert uni["pass_proposals"] == []
assert uni["canonical82_overlap"] == []
c82 = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json").read_text())
assert c82["canonical_strict_count"] == 82
assert "GHSA-73HC-M4HX-79PJ" not in c82["strict_released_case_ids"]
res = json.loads((owned / "result.json").read_text())
assert res["start_count"] == 82
assert res["current_leader_accepted_count"] == 82
assert res["packet_delta"] == 0
assert res["exact_selected_ids"] == ["GHSA-73HC-M4HX-79PJ"]
assert res["pass_proposals"] == []
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 1
assert res["counts"]["assigned"] == 1
assert res["counts"]["reviewed"] == 1
assert res["counts"]["unreviewed"] == 0
assert res["deep_review"] is True
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
    "work/uniqueness.json",
    "work/freeze.json",
]
for name in names:
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    assert text.endswith("\n"), name
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (name, line)
print("conservation assigned=1 reviewed=1 unreviewed=0 PASS_proposal=0 REJECT=1")
PY

printf 'REPLAY_OK reviewed=1 PASS_proposal=0 REJECT=1 packet_delta=0 start=82 current=82\n'
