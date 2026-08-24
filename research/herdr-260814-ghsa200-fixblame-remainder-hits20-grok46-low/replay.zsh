#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-fixblame-remainder-hits20-grok46-low.
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
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-remainder-hits20-grok46-low
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

require_dir "$OWNED"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/exclusion.json"
require_file "$OWNED/work/scan.jsonl"
require_file "$OWNED/work/scan-summary.json"
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
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/work/scan_fixblame.py" \
  0aa4ee042cf25a0af492892fb651f75c02db1352a22d8cc76282bd9b72da15ec
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/selected.jsonl" \
  344761d2c9c683ee6bf2b451f79b70b9e0b12802f037f972e8b159dc9b20f43e
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-residual-security20-grok46-high/selected.jsonl" \
  f179f86d9097f71a0d632b2ea572dba0d1f6b1bb16743a332f331f66af6aba3f
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-difffail20-grok46-high/selected.jsonl" \
  1116efd21db9461f60d0aac1831f55b3ad75f33f1c81834ba75e85cf6bacacfa
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-difffail20-grok46-high/work/repair_probes.py" \
  f066d9f241234548d1d93e5ed9ea4b282573fbb7c13874b009ec03c84ab48aaa
expect_hash "$OWNED/selected.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/cases.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/report.md" \
  243d12c867a864d70781ccdc30659ec52253aad32960d1102d2089d74b600f19
expect_hash "$OWNED/work/scan.jsonl" \
  da13b7cf8e0c1ccffa182d04c6cd226791cc6641d898fe7f620b36d69b522133
expect_hash "$OWNED/work/scan-summary.json" \
  71155423d51a7b60eeb3a3f132fc672942cdf8f3a8235763f9eddbfa2e271e34
expect_hash "$OWNED/work/exclusion.json" \
  e9d63bcf6a4909f7f07313e7e9b6c194e7be36edcd0f97e0d6df31c985a038c8
expect_hash "$OWNED/work/freeze.json" \
  408e23d7701bf21188603a425794a981692b75c465f310981b7152fda45cacee
expect_hash "$OWNED/work/uniqueness.json" \
  625b2dac0bf12eb3f2bebab79ad73a20a3387ac61648976689e48fd470800a71
expect_hash "$OWNED/work/facts.json" \
  db087e031cd4074443a0379aadb765d996d900eace6d3d6676ead7073ba53fef

python3 - "$OWNED" "$SCAN_MISS" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/selected.jsonl" \
  "$ROOT/autoresearch/herdr-260814-ghsa200-residual-security20-grok46-high/selected.jsonl" \
  "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-difffail20-grok46-high/selected.jsonl" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
scan_miss = Path(sys.argv[2])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned / "result.json").read_text())
uniq = json.loads((owned / "work/uniqueness.json").read_text())
scan = [json.loads(l) for l in (owned / "work/scan.jsonl").read_text().splitlines() if l.strip()]
summary = json.loads((owned / "work/scan-summary.json").read_text())
excl = json.loads((owned / "work/exclusion.json").read_text())
report = (owned / "report.md").read_text()
assert rows == []
assert sel == []
assert len(scan) == 878
assert len({r["ghsa_id"] for r in scan}) == 878
assert sum(1 for r in scan if r.get("repaired")) == 489
assert sum(1 for r in scan if not r.get("repaired")) == 389
assert sum(1 for r in scan if r.get("status") == "hit") == 0
assert sum(1 for r in scan if r.get("status") == "no_ai_blame_on_deleted_hunks") == 412
assert sum(1 for r in scan if r.get("status") == "no_deleted_hunk") == 77
assert 489 + 389 == 878
assert 412 + 77 + 0 == 489
assert summary["conservation"]["equation"] == "878=489+389"
assert summary["conservation"]["holds"] is True
assert summary["conservation"]["selected"] == 0
assert summary["did_not_pad"] is True

def load_ids(p):
    out = []
    for line in Path(p).read_text().splitlines():
        if line.strip():
            out.append(json.loads(line)["ghsa_id"].upper())
    return out

c84 = json.loads(Path(sys.argv[3]).read_text())
ids84 = {x.upper() for x in c84["strict_released_case_ids"]}
assert len(c84["strict_released_case_ids"]) == 84
assert c84["canonical_strict_count"] == 84
origin14 = set(load_ids(sys.argv[4]))
residual20 = set(load_ids(sys.argv[5]))
first20 = load_ids(sys.argv[6])
assert len(origin14) == 14
assert len(residual20) == 20
assert len(first20) == 20
assert first20 == summary["pool_meta"]["excluded_from_unique_diff_fail"]
block = ids84 | origin14 | residual20 | set(first20) | set(excl["assigned_ids"]) | set(excl["canonical84"]["union"])
derived = []
seen = set()
n_fail = 0
for line in scan_miss.read_text().splitlines():
    if not line.strip():
        continue
    rec = json.loads(line)
    notes = rec.get("notes") or []
    if not any(isinstance(n, str) and n.startswith("diff_fail:") for n in notes):
        continue
    n_fail += 1
    gid = rec["ghsa_id"].upper()
    if gid in seen:
        continue
    seen.add(gid)
    if gid in block:
        continue
    derived.append(gid)
assert n_fail == 898
assert len(seen) == 898
assert len(derived) == 878
assert derived == [r["ghsa_id"] for r in scan]
assert [r["ghsa_id"] for r in scan if r["ghsa_id"] in set(first20)] == []
assert res["counts"]["PASS"] == 0
assert res["counts"]["assigned"] == 0
assert res["counts"]["reviewed"] == 0
assert res["conservation"]["scanned"] == 878
assert res["conservation"]["repaired"] == 489
assert res["conservation"]["unrepaired"] == 389
assert res["conservation"]["hits"] == 0
assert res["conservation"]["equation"] == "878=489+389"
assert res["current_leader_accepted_count"] == 84
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["pass_proposals"] == []
assert res["did_not_pad"] is True
assert "packet_delta=0" in report or "Packet delta 0" in report or "packet_delta=0" in report.replace(" ", "")
assert "Current leader-accepted strict count is 84" in report
assert uniq["canonical84_strict_count"] == 84
assert uniq["packet_delta"] == 0
assert uniq["pass_proposals"] == []
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
    "cases.jsonl", "selected.jsonl", "report.md", "replay.zsh", "result.json",
    "work/uniqueness.json", "work/exclusion.json", "work/facts.json",
    "work/freeze.json", "notes/README.md", "sha256.txt",
):
    text = (owned / name).read_text(encoding="utf-8")
    if name in ("cases.jsonl", "selected.jsonl") and text == "":
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
print("conservation remaining=878 scanned=878 repaired=489 unrepaired=389 hits=0 selected=0 PASS_proposal=0 current_leader_accepted_count=84 packet_delta=0")
PY
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"

printf 'REPLAY_OK reviewed=0 PASS_proposal=0 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=0 scanned=878 repaired=489 unrepaired=389 hits=0 packet_delta=0 current_leader_accepted_count=84\n'
