#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-additiveguard-final36-grok46-high.
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
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-additiveguard-final36-grok46-high
SCAN_MISS=$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/work/scan-miss.jsonl
FIRST30_ASSIGNED=$ROOT/autoresearch/herdr-260814-ghsa200-additiveguard-first30-grok46-high/work/assigned30.jsonl
NEXT30_ASSIGNED=$ROOT/autoresearch/herdr-260814-ghsa200-additiveguard-next30-grok46-high/work/assigned30.jsonl

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
require_file "$OWNED/work/assigned36.jsonl"
require_file "$OWNED/work/scan_additive.py"
require_file "$OWNED/notes/facts/compact.json"
require_file "$OWNED/notes/blame/compact.json"
require_file "$OWNED/notes/releases/compact.json"
require_file "$OWNED/sha256.txt"
require_file "$SCAN_MISS"
require_file "$FIRST30_ASSIGNED"
require_file "$NEXT30_ASSIGNED"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$SCAN_MISS" \
  5ec5265e65d957d8a7877a1c27465e9463b404f73790cfb03fc9f011d5625e40
expect_hash "$FIRST30_ASSIGNED" \
  03051aafee4a8876e01153f7e5220951a340bb69fe0f7059ee6121e862b4c2b1
expect_hash "$NEXT30_ASSIGNED" \
  00a29c3028f87d7a0e8060af3cf387c4d9180af4cad0db72e57843bf3defcf24
expect_hash "$OWNED/selected.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/cases.jsonl" \
  37c3505140bb804b99358c0ee5a8a9dd6299b3d8dcab71f76c4710c4c46e84c8
expect_hash "$OWNED/adjudications.jsonl" \
  78b66239f0141f465fca96711187b58b384d636d0dcbc01a58dd2e67b356cdb5
expect_hash "$OWNED/assignment.json" \
  5956efd3029feacf749e2dc4f6011d6b7c3ad517c4723453e2a457bc6e82d757
expect_hash "$OWNED/assignment.md" \
  db53c86678573ce48b82ec265b55aaba4f6e3a1b008eebd486196389619b73f1
expect_hash "$OWNED/report.md" \
  4296b4cdba20b0685fe3366e14d3d2aa8786438b331c696afeef4424cf9b4b0f
expect_hash "$OWNED/summary.json" \
  74472cc87bff4f0ec49323c8a35f32f8c767c2b65165b080fa9125ad3084e57c
expect_hash "$OWNED/work/scan.jsonl" \
  42c41158ea5b4a075856b55cc69e373744f47964f4489b5b5450c223aa477668
expect_hash "$OWNED/work/scan-summary.json" \
  f0dd3e5230e57eecbda2e69c394057272acd85dadc0ce58e9228d505e9be0ddb
expect_hash "$OWNED/work/scan_additive.py" \
  e5482fca337b70c7369ab7cace8a8b1d4ca40cb6538b96bf6b69c22361254a65
expect_hash "$OWNED/work/exclusion.json" \
  ec8b85cbdb3cf78eae83fb3122a12d1056da278f515249651f156dc49920762c
expect_hash "$OWNED/work/freeze.json" \
  0e632ada32c0636d1e49ed1bf55fcd1e85a39548447b5eba0fa50a8d05cb7943
expect_hash "$OWNED/work/uniqueness.json" \
  8c21cc8e813a5c55cde2d3fb2a782b0290ddbc6161e447813a2a19d6cb1f0bb9
expect_hash "$OWNED/work/facts.json" \
  9c402a24a414227453a6d1dc97f515f1cf72ee2c3ffd62e341b6438e67b24a01
expect_hash "$OWNED/work/assigned36.jsonl" \
  7813029eab8c6d891a6af022b449b39e3dbb8cc40069547601b8034a4c12ed45
expect_hash "$OWNED/notes/facts/compact.json" \
  a8ea6eacbdf4e4ad3ac1d01170e3a631ee2934dca86e6f7fc72462046cb720dd
expect_hash "$OWNED/notes/blame/compact.json" \
  74f59349a53792b102be43465f93e68a2310689797b10b459281404da9e87ae9
expect_hash "$OWNED/notes/releases/compact.json" \
  573ba17a2c56481403a843ae422824f0fffea8f5007767af861db05a0e24fac2

python3 -B - "$OWNED" "$SCAN_MISS" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  "$FIRST30_ASSIGNED" "$NEXT30_ASSIGNED" << 'PY'
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
assigned = json.loads((owned / "work/assigned36.json").read_text())
assignment = json.loads((owned / "assignment.json").read_text())
report = (owned / "report.md").read_text()
first30 = [json.loads(l) for l in Path(sys.argv[4]).read_text().splitlines() if l.strip()]
next30 = [json.loads(l) for l in Path(sys.argv[5]).read_text().splitlines() if l.strip()]
first30_ids = [r["ghsa_id"].upper() for r in first30]
next30_ids = [r["ghsa_id"].upper() for r in next30]
assert len(first30_ids) == 30
assert len(next30_ids) == 30
assert set(first30_ids).isdisjoint(set(next30_ids))
assert set(assigned["assigned36_ids"]).isdisjoint(set(first30_ids) | set(next30_ids))
assert uniq["zero_first30_overlap"] is True
assert uniq["zero_next30_overlap"] is True
assert set(uniq["explicit_first30_mining_ids"]) == set(first30_ids)
assert set(uniq["explicit_next30_mining_ids"]) == set(next30_ids)
scanner = owned / "work/scan_additive.py"
scanp = owned / "work/scan.jsonl"
assert scanp.stat().st_mtime >= scanner.stat().st_mtime
assert sel == []
assert len(rows) == 36
assert len(adj) == 36
assert len(scan) == 36
assert assigned["assigned36_n"] == 36
assert assigned["unique_no_source_deleted_no_diff_fail"] == 381
assert assigned["skipped_already_assigned_n"] == 345
assert assigned["still_unassigned"] == 36
assert assigned["leftover_after_assigned36"] == 0
assert assigned["eligible_exhausted"] is True
assert assignment["unique_pool_remaining_not_exhausted"] == 345
assert assignment["eligible_exhausted"] is True
assert 381 == 315 + 66
assert 66 == 30 + 36
assert 381 == 345 + 36
assert 36 == 36 + 0
assert 36 + 345 == 381
assert all(not r.get("hard_hit") for r in scan)
assert all(r.get("advisory_loaded") for r in scan)
assert all((r.get("summary") or "").strip() for r in scan)
assert all(isinstance(r.get("aliases"), list) for r in scan)
assert sum(1 for r in scan if r.get("status") == "heuristic_no_hard_hit") == 34
assert sum(1 for r in scan if r.get("status") == "UNKNOWN") == 2
assert [r["ghsa_id"] for r in scan] == assigned["assigned36_ids"]
assert [r["case_id"] for r in rows] == assigned["assigned36_ids"]
c84 = json.loads(Path(sys.argv[3]).read_text())
assert len(c84["strict_released_case_ids"]) == 84
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 0
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 2
assert res["counts"]["reviewed"] == 0
assert res["counts"]["scan_assigned"] == 36
assert res["counts"]["selected"] == 0
assert res["current_leader_accepted_count"] == 84
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["pass_proposals"] == []
assert res["did_not_pad"] is True
assert res["did_not_backfill"] is True
assert res["conservation"]["eligible_exhausted"] is True
assert res["no_further_additive_slice"] is True
assert "0 hard-hit proposals" in report.lower() or "0 hard-hit" in report.lower()
assert "not a finding that those 36 have no AI origin" in report
assert "Current leader-accepted strict count is 84" in report
assert "381=315+66" in report
assert "66=30+36" in report
assert "381=345+36" in report
assert "36=36+0" in report
assert "381=36+345" in report
assert "No further additive slice" in report
assert uniq["role"] == "prefilter_metadata_not_adjudication"
assert uniq["packet_delta"] == 0
assert uniq["frozen_selected_ids"] == []
assert sum(1 for r in rows if r["worker_verdict"] == "NOT_SELECTED") == 34
assert sum(1 for r in rows if r["worker_verdict"] == "BLOCKED") == 2
assert all(r["worker_verdict"] != "REJECT" for r in rows)
for r in rows:
    if r["worker_verdict"] == "NOT_SELECTED":
        assert r["identity_gate"] == "NOT_OPENED"
        assert r["ai_hunk_gate"] == "NOT_OPENED"
        assert r["but_for_gate"] == "NOT_OPENED"
        assert r["fix_reversal_gate"] == "NOT_OPENED"
        assert r["release_gate"] == "NOT_OPENED"
        assert r["uniqueness_gate"] == "NOT_OPENED"
        assert r["topology_gate"] == "NOT_OPENED"
    else:
        assert r["worker_verdict"] == "BLOCKED"
        assert r["identity_gate"] == "UNKNOWN"
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
print("conservation raw=381 excluded=345 eligible=36 assigned=36 leftover=0 exhausted=1 outside=345 hits=0 selected=0 reviewed=0 PASS=0 REJECT=0 BLOCKED=2 packet_delta=0 current_leader_accepted_count=84")
PY
forbid_bytecode
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"

printf 'REPLAY_OK reviewed=0 PASS_proposal=0 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=2 scan_assigned=36 hits=0 selected=0 remaining=345 leftover=0 exhausted=1 packet_delta=0 current_leader_accepted_count=84\n'
