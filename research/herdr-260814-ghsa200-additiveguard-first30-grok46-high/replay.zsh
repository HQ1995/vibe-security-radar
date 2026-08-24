#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-additiveguard-first30-grok46-high.
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
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-additiveguard-first30-grok46-high
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
require_file "$OWNED/work/scan_additive.py"
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
  b0f43df58752beafe2879abddef09aeaade52ca7c6cbe5e01ffb320b9f60f31e
expect_hash "$OWNED/adjudications.jsonl" \
  8e1adc5063bcf55e8d6e7001f6ac7739493c5a93c8976b1d2bf89764f6bc1cdb
expect_hash "$OWNED/assignment.json" \
  0a71362f6bba413324dab42efcb88f604cd27a43f88d33db49781e0bdaa2e426
expect_hash "$OWNED/assignment.md" \
  930fe1cef0b50fc83b4d2a0d003f8a46e97cfafb764b50d0fe3f2105901e740f
expect_hash "$OWNED/report.md" \
  02a25c3ab844b4df86a4862f37218a6d9b88b3bba85c03a0a4825a4d79569721
expect_hash "$OWNED/summary.json" \
  27bd37a1dda2a7a3ac05c91d7e58b65648e84c686dcb245af2d10c0b31604cb3
expect_hash "$OWNED/work/scan.jsonl" \
  b31a695e911606e9bc7709ace1803f30938ed94da8de7657cb623b18556ff813
expect_hash "$OWNED/work/scan-summary.json" \
  6d3c305f815b7b10ee92f3fd81001476157d82b665d336d7e1c64471bea612ea
expect_hash "$OWNED/work/scan_additive.py" \
  d752d33475adec61c2b45a6fe082351b7888cce7f8c3dae695e286671add20df
expect_hash "$OWNED/work/exclusion.json" \
  31ef3b3d8f00b8987f632a12c345e62c0ec87c93bf2c26a4830eac3e13851954
expect_hash "$OWNED/work/freeze.json" \
  c4bb48a956fa07a6c6761f094eebcea3eb43d447d579a75ec47a544bf78ddab7
expect_hash "$OWNED/work/uniqueness.json" \
  33ad1d0651ac41602ac1a51910eb9117d5816f05d08f44aeafee9de17484c93c
expect_hash "$OWNED/work/facts.json" \
  97903aa8382dbfe8822e80fb13a00e933370bfb57978975e02e944e7fe32d04e
expect_hash "$OWNED/work/assigned30.jsonl" \
  03051aafee4a8876e01153f7e5220951a340bb69fe0f7059ee6121e862b4c2b1
expect_hash "$OWNED/notes/facts/compact.json" \
  377048d75072fde2ac0c545c997ce83d53e2c37e22cd95f5bcf68aaf3f5b5c42
expect_hash "$OWNED/notes/blame/compact.json" \
  eccd36df16d0b9e557f54c33f5dbe59d2b8daab47955fd52c8ba7fdea95f4d37
expect_hash "$OWNED/notes/releases/compact.json" \
  5dd638f5c08a3b3e88e578fe19b51753e62a7eae761f137ba00423a957eded51

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
scanner = owned / "work/scan_additive.py"
scanp = owned / "work/scan.jsonl"
assert scanp.stat().st_mtime >= scanner.stat().st_mtime
assert sel == []
assert len(rows) == 30
assert len(adj) == 30
assert len(scan) == 30
assert assigned["assigned30_n"] == 30
assert assigned["unique_no_source_deleted_no_diff_fail"] == 381
assert assigned["skipped_already_assigned_n"] == 285
assert assigned["still_unassigned"] == 96
assert assigned["leftover_after_assigned30"] == 66
assert assignment["unique_pool_remaining_not_exhausted"] == 351
assert 381 == 285 + 96
assert 96 == 30 + 66
assert 30 + 351 == 381
assert all(not r.get("hard_hit") for r in scan)
assert all(r.get("advisory_loaded") for r in scan)
assert all((r.get("summary") or "").strip() for r in scan)
assert all(isinstance(r.get("aliases"), list) for r in scan)
assert all(r.get("status") == "heuristic_no_hard_hit" for r in scan)
assert [r["ghsa_id"] for r in scan] == assigned["assigned30_ids"]
assert [r["case_id"] for r in rows] == assigned["assigned30_ids"]
c84 = json.loads(Path(sys.argv[3]).read_text())
assert len(c84["strict_released_case_ids"]) == 84
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 0
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 0
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
assert "381=285+96" in report
assert "96=30+66" in report
assert "351" in report
assert uniq["role"] == "prefilter_metadata_not_adjudication"
assert uniq["packet_delta"] == 0
assert uniq["frozen_selected_ids"] == []
assert all(r["worker_verdict"] == "NOT_SELECTED" for r in rows)
assert all(r["identity_gate"] == "NOT_OPENED" for r in rows)
assert all(r["ai_hunk_gate"] == "NOT_OPENED" for r in rows)
assert all(r["but_for_gate"] == "NOT_OPENED" for r in rows)
assert all(r["fix_reversal_gate"] == "NOT_OPENED" for r in rows)
assert all(r["release_gate"] == "NOT_OPENED" for r in rows)
assert all(r["uniqueness_gate"] == "NOT_OPENED" for r in rows)
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
print("conservation raw=381 excluded=285 eligible=96 assigned=30 leftover=66 outside=351 hits=0 selected=0 reviewed=0 PASS=0 REJECT=0 packet_delta=0 current_leader_accepted_count=84")
PY
forbid_bytecode
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"

printf 'REPLAY_OK reviewed=0 PASS_proposal=0 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=0 scan_assigned=30 hits=0 selected=0 remaining=351 packet_delta=0 current_leader_accepted_count=84\n'
