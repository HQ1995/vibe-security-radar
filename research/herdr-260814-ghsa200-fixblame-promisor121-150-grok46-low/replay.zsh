#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-fixblame-promisor121-150-grok46-low.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Current leader-accepted count is 84. Packet delta is 0.
# PASS is a proposal only. This script admits no row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor121-150-grok46-low
REMAINDER=$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-remainder-hits20-grok46-low/work/scan.jsonl

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
require_file "$OWNED/assignment.json"
require_file "$OWNED/adjudications.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/summary.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/exclusion.json"
require_file "$OWNED/work/scan.jsonl"
require_file "$OWNED/work/carrier-gate-summary.json"
require_file "$OWNED/sha256.txt"
require_file "$REMAINDER"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$REMAINDER" \
  da13b7cf8e0c1ccffa182d04c6cd226791cc6641d898fe7f620b36d69b522133
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/work/scan_fixblame.py" \
  0aa4ee042cf25a0af492892fb651f75c02db1352a22d8cc76282bd9b72da15ec
expect_hash "$OWNED/assignment.json" \
  df2fc54e96e4881606d619171d44c8dc71d61218dcb28c6f8db2098fe73c27fa
expect_hash "$OWNED/selected.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/adjudications.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/cases.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/report.md" \
  4dafdc326e315dd0659e32234506a27e51026ab886768ede3ad7472fe8b9f138
expect_hash "$OWNED/work/scan.jsonl" \
  9add8afd167329c698ee1220a3c2842524d72ee3b55d0b37df34b56fe03e19d0
expect_hash "$OWNED/work/scan-summary.json" \
  58fc291f09d88721882d592f7e67bd606dfd4c3f4c5b02af93992088d14fffcf
expect_hash "$OWNED/work/exclusion.json" \
  ef8dbe0d925120bbade1d12de54718878470871ebedae425870906c7494185cf
expect_hash "$OWNED/work/freeze.json" \
  351d72ddaf061c8738f0e1aec4defef8fbee4b01b824679eecb3ec75a34ecb8c
expect_hash "$OWNED/work/uniqueness.json" \
  625b2dac0bf12eb3f2bebab79ad73a20a3387ac61648976689e48fd470800a71
expect_hash "$OWNED/work/facts.json" \
  a1404b5d38b31a27895d41aa499a213865f6f6bd95273216b9953b744323105d
expect_hash "$OWNED/work/carrier-gate-summary.json" \
  e4175116148800a8efd8736407f1e87f058228e1cb1be0dd5496547e107df322

python3 - "$OWNED" "$REMAINDER" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
remainder = Path(sys.argv[2])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
adj = [json.loads(l) for l in (owned / "adjudications.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned / "result.json").read_text())
summary = json.loads((owned / "summary.json").read_text())
uniq = json.loads((owned / "work/uniqueness.json").read_text())
scan = [json.loads(l) for l in (owned / "work/scan.jsonl").read_text().splitlines() if l.strip()]
assign = json.loads((owned / "assignment.json").read_text())
gate = json.loads((owned / "work/carrier-gate-summary.json").read_text())
report = (owned / "report.md").read_text()
assert rows == []
assert sel == []
assert adj == []
assert assign["raw_slice_n"] == 30
assert assign["slice_start_1based"] == 121
assert assign["slice_end_1based"] == 150
assert assign["excluded_overlap_n"] == 0
assert assign["did_not_backfill"] is True
assert assign["outside_slice_not_claimed"] is True
unrepaired = []
for line in remainder.read_text().splitlines():
    if not line.strip():
        continue
    rec = json.loads(line)
    if rec.get("repaired"):
        continue
    unrepaired.append((int(rec.get("scan_miss_order") or 0), rec["ghsa_id"].upper()))
unrepaired.sort()
assert len(unrepaired) == 389
raw = [g for _, g in unrepaired[120:150]]
assert raw == assign["raw_slice_ids"]
assert raw == [r["ghsa_id"] for r in scan]
assert [r["raw_position"] for r in scan] == list(range(121, 151))
assert len(scan) == 30
assert sum(1 for r in scan if r.get("status") == "hit") == 0
assert sum(1 for r in scan if r.get("status") == "no_ai_blame_on_deleted_hunks") == 24
assert sum(1 for r in scan if r.get("status") == "no_deleted_hunk") == 6
assert sum(1 for r in scan if r.get("status") == "UNKNOWN_BLOCKED") == 0
assert sum(1 for r in scan if r.get("status") == "carrier_or_non_atomic_blame") == 0
assert 0 + 24 + 6 + 0 == 30
assert 120 + 30 + 239 == 389
assert gate["applied_before_freeze"] is True
assert gate["pre_gate_hit_rows"] == 0
assert gate["carrier_negatives"] == 0
assert gate["frozen_n"] == 0
c84 = json.loads(Path(sys.argv[3]).read_text())
assert len(c84["strict_released_case_ids"]) == 84
assert c84["canonical_strict_count"] == 84
ids84 = {x.upper() for x in c84["strict_released_case_ids"]}
assert set(raw).isdisjoint(ids84)
assert res["counts"]["PASS"] == 0
assert res["counts"]["assigned"] == 0
assert res["counts"]["reviewed"] == 0
assert res["conservation"]["raw_slice"] == 30
assert res["conservation"]["hits"] == 0
assert res["conservation"]["scanned"] == 30
assert res["conservation"]["equation"] == "389=120+30+239; 30=30+0; 30=0+24+6+0"
assert res["current_leader_accepted_count"] == 84
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["pass_proposals"] == []
assert res["did_not_pad"] is True
assert res["carrier_gate"]["applied_before_freeze"] is True
assert summary["selected_count"] == 0
assert "packet_delta=0" in report or "Packet delta 0" in report
assert "Current leader-accepted strict count is 84" in report
assert "does not claim" in report.lower() or "not claimed" in report.lower() or "does not claim rows outside" in report
assert uniq["canonical84_strict_count"] == 84
assert uniq["packet_delta"] == 0
assert uniq["frozen_selected_ids"] == []
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
    "assignment.json", "adjudications.jsonl", "cases.jsonl", "selected.jsonl",
    "report.md", "replay.zsh", "result.json", "summary.json",
    "work/uniqueness.json", "work/exclusion.json", "work/facts.json",
    "work/freeze.json", "work/carrier-gate-summary.json", "notes/README.md",
    "notes/carrier/README.md",
    "sha256.txt",
):
    text = (owned / name).read_text(encoding="utf-8")
    if name in ("cases.jsonl", "selected.jsonl", "adjudications.jsonl") and text == "":
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
print("conservation unrepaired=389 slice=30 overlap=0 scanned=30 hits=0 frozen=0 carrier_negatives=0 UNKNOWN_BLOCKED=0 PASS_proposal=0 current_leader_accepted_count=84 packet_delta=0")
PY
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"

printf 'REPLAY_OK reviewed=0 PASS_proposal=0 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=0 scanned=30 hits=0 frozen=0 packet_delta=0 current_leader_accepted_count=84\n'
