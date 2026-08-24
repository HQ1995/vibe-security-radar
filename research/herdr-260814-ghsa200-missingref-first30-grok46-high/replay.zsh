#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-missingref-first30-grok46-high.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Current leader-accepted count is 84. Packet delta is 0.
# PASS is a proposal only. This script admits no row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export PYTHONDONTWRITEBYTECODE=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-missingref-first30-grok46-high
SCAN_MISS=$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/work/scan-miss.jsonl

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

forbid_bytecode() {
  local found
  found=$(/usr/bin/find "$OWNED" \( -name '__pycache__' -o -name '*.pyc' -o -name '*.pyo' \) -print)
  if [[ -n $found ]]; then
    printf 'bytecode present:\n%s\n' "$found" >&2
    exit 1
  fi
}

require_dir "$OWNED"
forbid_bytecode
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/adjudications.jsonl"
require_file "$OWNED/assignment.json"
require_file "$OWNED/assignment.md"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/summary.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/exclusion.json"
require_file "$OWNED/work/scan.jsonl"
require_file "$OWNED/work/assigned30.jsonl"
require_file "$OWNED/work/scan_missingref.py"
require_file "$OWNED/notes/facts/compact.json"
require_file "$OWNED/notes/blame/compact.json"
require_file "$OWNED/notes/releases/compact.json"
require_file "$OWNED/sha256.txt"
require_file "$SCAN_MISS"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$SCAN_MISS" \
  5ec5265e65d957d8a7877a1c27465e9463b404f73790cfb03fc9f011d5625e40
expect_hash "$OWNED/selected.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/cases.jsonl" \
  97b11f7bbc73fc45a34a55c37657f2092dab7de4216d26bc68b88ee7cb7cbfeb
expect_hash "$OWNED/adjudications.jsonl" \
  cce2dba60a02545de81a681e680fdcaf32d41828b581778430518a990b91ffc1
expect_hash "$OWNED/assignment.json" \
  8f6306cc7ab643b9b639e19337442139d0a3ccd6390b310ba9a2d9d2edfe36fe
expect_hash "$OWNED/assignment.md" \
  e6593e9cec1fb6e794d2967380580e67a3b8276e64bc9324fb18203b19434ee5
expect_hash "$OWNED/report.md" \
  d4d4688ddfbc11cc2ceb3ccfb8662adaa4e3cb50f3c98046414816f65c036cd6
expect_hash "$OWNED/summary.json" \
  0310d0efd00f719e23789e31dc833cefcafa92a4748a7f1b52d6b8fa6506d55e
expect_hash "$OWNED/work/scan.jsonl" \
  74f312893398f78a137567072f3a9a368f69421c1ff0fe85311c4694fb472e3b
expect_hash "$OWNED/work/scan-summary.json" \
  b77b3863f80bbc7d67a59d568b0782a4788fe33e3568ee334fb74c0956393592
expect_hash "$OWNED/work/scan_missingref.py" \
  e570d44cb52cde491da884d12ff7f8a11291458eb21ce7dc41bbcafa9dfc7882
expect_hash "$OWNED/work/exclusion.json" \
  f4f245b2e7367e4be75950ba3e67744c3cdc897449531d74c4fc9c67a6a0a542
expect_hash "$OWNED/work/freeze.json" \
  79f85d9d562d37a1a7115ee8005eae96201016b93525830bed17e90730386803
expect_hash "$OWNED/work/uniqueness.json" \
  f084f306f97e40633fd5411ae073ed36ca4495da8dfa0a2a9ef51db7ad71d297
expect_hash "$OWNED/work/facts.json" \
  c45f869ceb251718e72bf9b6674b5bd2b54926bac196d469673af409bb29d9dc
expect_hash "$OWNED/work/assigned30.jsonl" \
  5d9c5773e0e33651b8058fc9ef816ec2bbe3bd665fc952e1a62fcb793bcd0d4d
expect_hash "$OWNED/notes/facts/compact.json" \
  d41682c60547cc11d92dad49afaa102a9e62b77482cabcf288887e037a98a44a
expect_hash "$OWNED/notes/blame/compact.json" \
  5296c7d48bdf58925432cb9a937b09439d220944502411840a558c014f0215a6
expect_hash "$OWNED/notes/releases/compact.json" \
  5960d2eee10d7d307b5db18c76be6bedd54c59c7ecf3dac29b90fe592f76fb69

python3 -B - "$OWNED" "$SCAN_MISS" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" << 'PY'
import json, os, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
scan_miss = Path(sys.argv[2])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
adj = [json.loads(l) for l in (owned / "adjudications.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned / "result.json").read_text())
uniq = json.loads((owned / "work/uniqueness.json").read_text())
scan = [json.loads(l) for l in (owned / "work/scan.jsonl").read_text().splitlines() if l.strip()]
assigned = json.loads((owned / "work/assigned30.json").read_text())
assignment = json.loads((owned / "assignment.json").read_text())
report = (owned / "report.md").read_text()
scanner = owned / "work/scan_missingref.py"
scanp = owned / "work/scan.jsonl"
assert scanp.stat().st_mtime >= scanner.stat().st_mtime
assert sel == []
assert len(rows) == 30
assert len(adj) == 30
assert len(scan) == 30
assert assigned["assigned30_n"] == 30
assert assigned["unique_missing_ref_no_diff_fail_no_source_deleted"] == 141
assert assigned["skipped_already_assigned_n"] == 98
assert assigned["still_unassigned"] == 43
assert assigned["leftover_after_assigned30"] == 13
assert assignment["unique_pool_remaining_not_exhausted"] == 111
assert 141 == 98 + 43
assert 43 == 30 + 13
assert 30 + 111 == 141
assert all(not r.get("hard_hit") for r in scan)
assert all(r.get("advisory_loaded") for r in scan)
assert all((r.get("summary") or "").strip() for r in scan)
assert all(isinstance(r.get("aliases"), list) for r in scan)
assert sum(1 for r in scan if r.get("status") == "heuristic_no_hard_hit") == 29
assert sum(1 for r in scan if r.get("status") == "UNKNOWN") == 1
assert [r["ghsa_id"] for r in scan if r.get("worker_verdict") == "BLOCKED"] == ["GHSA-W7JW-789Q-3M8P"]
assert [r["ghsa_id"] for r in scan] == assigned["assigned30_ids"]
assert [r["case_id"] for r in rows] == assigned["assigned30_ids"]
c84 = json.loads(Path(sys.argv[3]).read_text())
assert len(c84["strict_released_case_ids"]) == 84
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 0
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 1
assert res["counts"]["reviewed"] == 0
assert res["counts"]["scan_assigned"] == 30
assert res["counts"]["selected"] == 0
assert res["current_leader_accepted_count"] == 84
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["pass_proposals"] == []
assert res["did_not_pad"] is True
assert res["did_not_backfill"] is True
assert res["note_prefix_is_routing_only"] is True
assert "0 hard-hit proposals" in report.lower() or "0 hard-hit" in report.lower()
assert "not a finding that those 30 have no AI origin" in report or "not a causal finding" in report.lower() or "not a finding that those 30 have no AI origin" in report
assert "Current leader-accepted strict count is 84" in report
assert "141=98+43" in report
assert "43=30+13" in report
assert "111" in report
assert uniq["role"] == "prefilter_metadata_not_adjudication"
assert uniq["packet_delta"] == 0
assert uniq["frozen_selected_ids"] == []
assert sum(1 for r in rows if r["worker_verdict"] == "NOT_SELECTED") == 29
assert sum(1 for r in rows if r["worker_verdict"] == "BLOCKED") == 1
assert all(r["identity_gate"] == "NOT_OPENED" for r in rows if r["worker_verdict"] == "NOT_SELECTED")
assert all(r["ai_hunk_gate"] == "NOT_OPENED" for r in rows if r["worker_verdict"] == "NOT_SELECTED")
assert all(r["but_for_gate"] == "NOT_OPENED" for r in rows if r["worker_verdict"] == "NOT_SELECTED")
assert all(r["fix_reversal_gate"] == "NOT_OPENED" for r in rows if r["worker_verdict"] == "NOT_SELECTED")
assert all(r["release_gate"] == "NOT_OPENED" for r in rows if r["worker_verdict"] == "NOT_SELECTED")
assert all(r["uniqueness_gate"] == "NOT_OPENED" for r in rows if r["worker_verdict"] == "NOT_SELECTED")
assert all(r["identity_gate"] == "UNKNOWN" for r in rows if r["worker_verdict"] == "BLOCKED")
assert all(r["empty_aliases_do_not_fail_identity"] for r in rows)
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(
    r"ghp_" + r"[A-Za-z0-9]{20,}|"
    r"github" + r"_pat_[A-Za-z0-9_]+|"
    r"sk" + r"_live_|"
    r"xox[baprs]-|"
    r"AKIA" + r"[0-9A-Z]{16}|"
    r"BEGIN" + r" PRIVATE"
)
for name in (
    "cases.jsonl", "selected.jsonl", "adjudications.jsonl", "assignment.json",
    "assignment.md", "report.md", "replay.zsh", "result.json", "summary.json",
    "work/uniqueness.json", "work/exclusion.json", "work/facts.json",
    "work/freeze.json", "notes/README.md", "sha256.txt",
):
    text = (owned / name).read_text(encoding="utf-8")
    if name in ("selected.jsonl",) and text == "":
        continue
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    if text:
        assert text.endswith("\n"), name
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (name, line)
man_names = []
for line in (owned / "sha256.txt").read_text().splitlines():
    if not line.strip():
        continue
    parts = line.split()
    assert len(parts) == 2, line
    man_names.append(parts[1])
assert "./sha256.txt" not in man_names
assert "sha256.txt" not in man_names
assert all(not n.endswith("/sha256.txt") for n in man_names)
assert all("__pycache__" not in n and not n.endswith(".pyc") and not n.endswith(".pyo") for n in man_names)
assert not list(owned.rglob("__pycache__"))
assert not list(owned.rglob("*.pyc"))
assert not list(owned.rglob("*.pyo"))
print("conservation raw=141 excluded=98 eligible=43 assigned=30 leftover=13 outside=111 hits=0 selected=0 reviewed=0 PASS=0 REJECT=0 BLOCKED=1 packet_delta=0 current_leader_accepted_count=84")
PY
forbid_bytecode
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"

printf 'REPLAY_OK reviewed=0 PASS_proposal=0 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=1 scan_assigned=30 hits=0 selected=0 remaining=111 packet_delta=0 current_leader_accepted_count=84\n'
