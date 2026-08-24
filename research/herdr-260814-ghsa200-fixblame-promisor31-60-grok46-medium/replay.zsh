#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-fixblame-promisor31-60-grok46-medium.
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
export PYTHONDONTWRITEBYTECODE=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor31-60-grok46-medium
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
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/adjudications.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/exclusion.json"
require_file "$OWNED/work/scan.jsonl"
require_file "$OWNED/work/scan-summary.json"
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
expect_hash "$OWNED/selected.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/cases.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/adjudications.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/assignment.json" \
  593a24c9afbfd04dc4a494748b9ec0a8edeb942da373dc31597b7876b716a3a5
expect_hash "$OWNED/report.md" \
  f2e3bf2d07afe9f949cd8d50b6d520ddf3ff6c34b776fd9a10efd59b59c9198e
expect_hash "$OWNED/work/scan.jsonl" \
  7a4c5e770efa0d5316896d328c026cd40e914cd4225f3df4b3dc083e6f34ec04
expect_hash "$OWNED/work/scan-summary.json" \
  aec6516b0efe2d8b84c433a37bcb8bc142e471a799e9a10dd40d563ef277e29f
expect_hash "$OWNED/work/exclusion.json" \
  8fea1c9d71d08f3c97692131a4c74e29e038b22e76cd5db39f5cdd88b4160b93
expect_hash "$OWNED/work/freeze.json" \
  d11b8c719c931aeade559f119dab6196b4501262157fe5b53e3b14000e5ccef4
expect_hash "$OWNED/work/uniqueness.json" \
  625b2dac0bf12eb3f2bebab79ad73a20a3387ac61648976689e48fd470800a71
expect_hash "$OWNED/work/facts.json" \
  401aa5a351fde41cdf18d37abc273288cd1a1fc4b892b48560bed7da05a23062

if find "$OWNED" \( -name '__pycache__' -o -name '*.pyc' -o -name '*.pyo' \) -print -quit | grep -q .; then
  printf 'bytecode present under owned packet\n' >&2
  exit 1
fi

python3 - "$OWNED" "$REMAINDER" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" << 'PY'
import json, os, re, sys
from pathlib import Path

os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.dont_write_bytecode = True
owned = Path(sys.argv[1])
remainder = Path(sys.argv[2])
bad = [p for p in owned.rglob("*") if p.name == "__pycache__" or p.suffix in {".pyc", ".pyo"}]
assert not bad, bad
assert os.environ.get("PYTHONDONTWRITEBYTECODE") == "1"
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
adj = [json.loads(l) for l in (owned / "adjudications.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned / "result.json").read_text())
uniq = json.loads((owned / "work/uniqueness.json").read_text())
scan = [json.loads(l) for l in (owned / "work/scan.jsonl").read_text().splitlines() if l.strip()]
summary = json.loads((owned / "work/scan-summary.json").read_text())
assign = json.loads((owned / "assignment.json").read_text())
report = (owned / "report.md").read_text()
assert rows == []
assert sel == []
assert adj == []
assert len(scan) == 30
assert assign["slice_start_1based"] == 31
assert assign["slice_end_1based"] == 60
assert assign["slice_end_1based"] == 60
assert assign["assigned_n"] == 30
assert assign["excluded_overlap_n"] == 0
assert assign["did_not_backfill"] is True
assert [r.get("raw_position") for r in scan] == list(range(31, 61))
assert sum(1 for r in scan if r.get("status") == "hit") == 0
assert sum(1 for r in scan if r.get("status") == "no_ai_hit") == 22
assert sum(1 for r in scan if r.get("status") == "no_deleted_hunk") == 7
assert sum(1 for r in scan if r.get("blocked")) == 1
assert summary["conservation"]["equation"] == "389=30+30+329"
assert summary["conservation"]["slice_equation"] == "30=0+22+7+1+0"
assert summary["conservation"]["holds"] is True
assert summary["conservation"]["selected"] == 0
assert summary["squash_carrier_gate"]["applied_before_freeze"] is True

unrepaired = []
for line in remainder.read_text().splitlines():
    if not line.strip():
        continue
    rec = json.loads(line)
    if rec.get("repaired"):
        continue
    unrepaired.append((int(rec.get("scan_miss_order") or 10**9), rec["ghsa_id"].upper()))
unrepaired.sort()
assert len(unrepaired) == 389
slice_ids = [gid for _, gid in unrepaired[30:60]]
assert slice_ids == assign["assigned_ids"]
assert slice_ids == [r["ghsa_id"] for r in scan]
c84 = json.loads(Path(sys.argv[3]).read_text())
assert len(c84["strict_released_case_ids"]) == 84
assert set(slice_ids).isdisjoint({x.upper() for x in c84["strict_released_case_ids"]})
assert res["counts"]["PASS"] == 0
assert res["counts"]["assigned"] == 30
assert res["counts"]["reviewed"] == 0
assert res["counts"]["BLOCKED"] == 1
assert res["conservation"]["scanned"] == 30
assert res["conservation"]["hits"] == 0
assert res["conservation"]["equation"] == "389=30+30+329"
assert res["current_leader_accepted_count"] == 84
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["pass_proposals"] == []
assert res["did_not_pad"] is True
assert res["hygiene"]["no_pycache"] is True
assert "Current leader-accepted strict count is 84" in report
assert "squash" in report.lower() or "Squash" in report
assert uniq["canonical84_strict_count"] == 84
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
    "assignment.json", "cases.jsonl", "adjudications.jsonl", "selected.jsonl",
    "report.md", "replay.zsh", "result.json",
    "work/uniqueness.json", "work/exclusion.json", "work/facts.json",
    "work/freeze.json", "notes/README.md", "sha256.txt",
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
assert all("__pycache__" not in n and not n.endswith(".pyc") for n in man_names)
print("conservation unrepaired=389 slice=31-60 assigned=30 scanned=30 no_ai=22 no_hunk=7 blocked=1 hits=0 selected=0 PASS_proposal=0 current_leader_accepted_count=84 packet_delta=0")
PY
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"

printf 'REPLAY_OK reviewed=0 PASS_proposal=0 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=1 scanned=30 hits=0 packet_delta=0 current_leader_accepted_count=84\n'
