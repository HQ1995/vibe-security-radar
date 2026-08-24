#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-fixblame-promisor30-grok46-low.
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
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor30-grok46-low
REMAINDER=$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-remainder-hits20-grok46-low/work/scan.jsonl
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
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/exclusion.json"
require_file "$OWNED/work/scan.jsonl"
require_file "$OWNED/work/scan-summary.json"
require_file "$OWNED/work/assigned30.jsonl"
require_file "$OWNED/work/carrier_gate.json"
require_file "$OWNED/sha256.txt"
require_file "$REMAINDER"
require_file "$SCAN_MISS"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$SCAN_MISS" \
  5ec5265e65d957d8a7877a1c27465e9463b404f73790cfb03fc9f011d5625e40
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/work/scan_fixblame.py" \
  0aa4ee042cf25a0af492892fb651f75c02db1352a22d8cc76282bd9b72da15ec
expect_hash "$REMAINDER" \
  da13b7cf8e0c1ccffa182d04c6cd226791cc6641d898fe7f620b36d69b522133
expect_hash "$OWNED/selected.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/cases.jsonl" \
  33e04628518ef41821c68f07aa7be5025676452e88536354c4ab2b9865f8019d
expect_hash "$OWNED/report.md" \
  54c255255845a94a6af43bb762a107bfab03e2d50b7650d17ca78baa7303d1cd
expect_hash "$OWNED/work/scan.jsonl" \
  0f4dd01cd3223b1e5b183234373874a1f72d2f858dc1c224b5bae83893148150
expect_hash "$OWNED/work/scan-summary.json" \
  0943551d459984f54e8be251d0d1a0ce58f22f80b2b80c1063c8f877ac124755
expect_hash "$OWNED/work/exclusion.json" \
  48f80243254c7b55c812ab1f6389ce69542f2b890451dc3000cffcca3a112844
expect_hash "$OWNED/work/freeze.json" \
  f882f1ecbd9bdb8749b607acc277cd94b72e3318283612e33689cf1c241c3cb9
expect_hash "$OWNED/work/uniqueness.json" \
  625b2dac0bf12eb3f2bebab79ad73a20a3387ac61648976689e48fd470800a71
expect_hash "$OWNED/work/facts.json" \
  3052eeccec968b2c7f51108a81effe0a08e9e1b1384ca1f929e97ad29399b7be
expect_hash "$OWNED/work/assigned30.jsonl" \
  712fa5abb2a163cd138cb7f3dfb0e93f27973bacf84598500afa7e01a5ba8f10

python3 -B - "$OWNED" "$REMAINDER" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
remainder = Path(sys.argv[2])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned / "result.json").read_text())
uniq = json.loads((owned / "work/uniqueness.json").read_text())
scan = [json.loads(l) for l in (owned / "work/scan.jsonl").read_text().splitlines() if l.strip()]
summary = json.loads((owned / "work/scan-summary.json").read_text())
assigned = json.loads((owned / "work/assigned30.json").read_text())
report = (owned / "report.md").read_text()
carrier = json.loads((owned / "work/carrier_gate.json").read_text())
assert sel == []
assert len(rows) == 30
assert len(scan) == 30
assert assigned["assigned30_n"] == 30
assert assigned["leftover_after_assigned30"] == 359
assert assigned["unrepaired_in_remainder"] == 389
assert 30 + 359 == 389
assert sum(1 for r in scan if r.get("status") == "hit") == 0
assert sum(1 for r in scan if r.get("status") == "no_ai_blame_on_deleted_hunks") == 22
assert sum(1 for r in scan if r.get("status") == "no_deleted_hunk") == 3
assert sum(1 for r in scan if r.get("status") == "UNKNOWN") == 5
assert 22 + 3 + 5 == 30
assert summary["counts"]["selected"] == 0
assert summary["counts"]["did_not_pad"] is True
assert carrier["applied_before_freeze"] is True
assert [r["ghsa_id"] for r in scan] == assigned["assigned30_ids"]
unrep = [json.loads(l) for l in remainder.read_text().splitlines() if l.strip() and not json.loads(l).get("repaired")]
assert len(unrep) == 389
assert assigned["assigned30_ids"] == [r["ghsa_id"] for r in unrep[:30]]
c84 = json.loads(Path(sys.argv[3]).read_text())
assert len(c84["strict_released_case_ids"]) == 84
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 0
assert res["counts"]["BLOCKED"] == 5
assert res["counts"]["assigned"] == 30
assert res["counts"]["reviewed"] == 30
assert res["current_leader_accepted_count"] == 84
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["pass_proposals"] == []
assert res["did_not_pad"] is True
assert "remaining 359" in report.lower() or "359 unrepaired" in report.lower()
assert "Current leader-accepted strict count is 84" in report
assert uniq["canonical84_strict_count"] == 84
assert uniq["packet_delta"] == 0
assert uniq["frozen_selected_ids"] == []
assert all(r["worker_verdict"] != "REJECT" for r in rows)
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
    "cases.jsonl", "selected.jsonl", "report.md", "replay.zsh", "result.json",
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
print("conservation assigned30=30 leftover=359 unrepaired=389 hits=0 selected=0 PASS_proposal=0 BLOCKED=5 packet_delta=0 current_leader_accepted_count=84")
PY
forbid_bytecode
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"

printf 'REPLAY_OK reviewed=30 PASS_proposal=0 REJECT=0 NARROW=0 UNKNOWN=5 BLOCKED=5 scanned=30 hits=0 assigned30=30 leftover=359 packet_delta=0 current_leader_accepted_count=84\n'
