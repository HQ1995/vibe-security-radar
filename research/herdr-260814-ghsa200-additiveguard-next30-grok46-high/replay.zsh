#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-additiveguard-next30-grok46-high.
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
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-additiveguard-next30-grok46-high
SCAN_MISS=$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/work/scan-miss.jsonl
FIRST30_ASSIGNED=$ROOT/autoresearch/herdr-260814-ghsa200-additiveguard-first30-grok46-high/work/assigned30.jsonl

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
require_file "$OWNED/work/scan_additive.py"
require_file "$OWNED/notes/facts/compact.json"
require_file "$OWNED/notes/blame/compact.json"
require_file "$OWNED/notes/releases/compact.json"
require_file "$OWNED/sha256.txt"
require_file "$SCAN_MISS"
require_file "$FIRST30_ASSIGNED"

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
expect_hash "$OWNED/selected.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/cases.jsonl" \
  a8dc5b1bbba8da61c91c886b059f7f2244b47b7859ebaac6bcf0d413271c03c3
expect_hash "$OWNED/adjudications.jsonl" \
  e8aee78e8b2914935baff843cf599f9809c583a448858cefdae9e32cff6d54a1
expect_hash "$OWNED/assignment.json" \
  5923cc0d072063f4e705b9ed100311404609e86e35256422d73bf4a83eeb73be
expect_hash "$OWNED/assignment.md" \
  91fdb14b1d87b64fb33da5678f2003a15baf448ab9c33e8d7c79339d99bc7427
expect_hash "$OWNED/report.md" \
  7bd412e27a87cb97a44f54bcdde95e632a6109f1a44a4c1e965d629a0fcb8681
expect_hash "$OWNED/summary.json" \
  ee6b194257ca3a3aa9f4701e4284540f3c485d2054939b3cd8c23dddfb8d6bf0
expect_hash "$OWNED/work/scan.jsonl" \
  fc1778aa596d4bd9e4a1ec3c7c815b15566d3b1ff39cfaf3364d4ffa4d6817eb
expect_hash "$OWNED/work/scan-summary.json" \
  a5863609b14c04433845b542d848a629b9b1eb4035be9d817ee9e98486dd90af
expect_hash "$OWNED/work/scan_additive.py" \
  3791de1c9df06ede3e77e55ca4ffcdcd9392f74fb50bafef63165a6d2931bc70
expect_hash "$OWNED/work/exclusion.json" \
  67abbb3a4ff21623aa6f73743419e2b2aa4831c828866079206c4454d1b8fe5e
expect_hash "$OWNED/work/freeze.json" \
  e3588066b008e54aaae7ea7d0a578f61afb1321de2dd2c8bbadb693dcd032305
expect_hash "$OWNED/work/uniqueness.json" \
  8c7592b0778b0d36eed716e52acde474499628d1430337b31da56f285f7a2654
expect_hash "$OWNED/work/facts.json" \
  263e04fa8dba4a15c2a42921705092805d57804bfdb635a558dbfcd48b4eea61
expect_hash "$OWNED/work/assigned30.jsonl" \
  00a29c3028f87d7a0e8060af3cf387c4d9180af4cad0db72e57843bf3defcf24
expect_hash "$OWNED/notes/facts/compact.json" \
  96606ff4a617836ed965052a3f4a6a7333db25f48d9c4c9e3592d7b2ab083287
expect_hash "$OWNED/notes/blame/compact.json" \
  647677a0f8cbffb544d541ecb2d29b1f5282f04d14a3db0fecf3e128cd4e821d
expect_hash "$OWNED/notes/releases/compact.json" \
  f49a233988f4c1211028cb3fc741622bdfc031b1c6b55acec03e8a7ea79bfe69

python3 -B - "$OWNED" "$SCAN_MISS" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  "$FIRST30_ASSIGNED" << 'PY'
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
first30 = [json.loads(l) for l in Path(sys.argv[4]).read_text().splitlines() if l.strip()]
first30_ids = [r["ghsa_id"].upper() for r in first30]
assert len(first30_ids) == 30
assert set(assigned["assigned30_ids"]).isdisjoint(set(first30_ids))
assert uniq["zero_first30_overlap"] is True
assert set(uniq["explicit_first30_mining_ids"]) == set(first30_ids)
scanner = owned / "work/scan_additive.py"
scanp = owned / "work/scan.jsonl"
assert scanp.stat().st_mtime >= scanner.stat().st_mtime
assert sel == []
assert len(rows) == 30
assert len(adj) == 30
assert len(scan) == 30
assert assigned["assigned30_n"] == 30
assert assigned["unique_no_source_deleted_no_diff_fail"] == 381
assert assigned["skipped_already_assigned_n"] == 315
assert assigned["still_unassigned"] == 66
assert assigned["leftover_after_assigned30"] == 36
assert assignment["unique_pool_remaining_not_exhausted"] == 351
assert 381 == 315 + 66
assert 66 == 30 + 36
assert 30 + 351 == 381
assert all(not r.get("hard_hit") for r in scan)
assert all(r.get("advisory_loaded") for r in scan)
assert all((r.get("summary") or "").strip() for r in scan)
assert all(isinstance(r.get("aliases"), list) for r in scan)
assert sum(1 for r in scan if r.get("status") == "heuristic_no_hard_hit") == 24
assert sum(1 for r in scan if r.get("status") == "UNKNOWN") == 6
assert [r["ghsa_id"] for r in scan] == assigned["assigned30_ids"]
assert [r["case_id"] for r in rows] == assigned["assigned30_ids"]
c84 = json.loads(Path(sys.argv[3]).read_text())
assert len(c84["strict_released_case_ids"]) == 84
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 0
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 6
assert res["counts"]["reviewed"] == 0
assert res["counts"]["scan_assigned"] == 30
assert res["counts"]["selected"] == 0
assert res["current_leader_accepted_count"] == 84
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["pass_proposals"] == []
assert res["did_not_pad"] is True
assert res["did_not_backfill"] is True
assert "0 hard-hit proposals" in report.lower() or "0 hard-hit" in report.lower()
assert "not a finding that those 30 have no AI origin" in report or "not a causal finding" in report.lower() or "not a finding that those 30 have no AI origin" in report
assert "Current leader-accepted strict count is 84" in report
assert "381=315+66" in report
assert "66=30+36" in report
assert "351" in report
assert "final36" in report
assert uniq["role"] == "prefilter_metadata_not_adjudication"
assert uniq["packet_delta"] == 0
assert uniq["frozen_selected_ids"] == []
assert sum(1 for r in rows if r["worker_verdict"] == "NOT_SELECTED") == 24
assert sum(1 for r in rows if r["worker_verdict"] == "BLOCKED") == 6
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
print("conservation raw=381 excluded=315 eligible=66 assigned=30 leftover=36 outside=351 hits=0 selected=0 reviewed=0 PASS=0 REJECT=0 BLOCKED=6 packet_delta=0 current_leader_accepted_count=84")
PY
forbid_bytecode
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"

printf 'REPLAY_OK reviewed=0 PASS_proposal=0 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=6 scan_assigned=30 hits=0 selected=0 remaining=351 leftover=36 packet_delta=0 current_leader_accepted_count=84\n'
