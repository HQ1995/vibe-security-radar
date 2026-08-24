#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-nofixref-first30-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
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
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-nofixref-first30-grok46-xhigh
POOL=$ROOT/autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh/work/candidate-pool.jsonl
HITS=$ROOT/autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh/work/original-hits.jsonl
TMP=/tmp/ghsa200-nofixref-first30

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

if [[ -e $TMP ]]; then
  printf 'tmp path must be absent for replay: %s\n' "$TMP" >&2
  exit 1
fi

require_dir "$OWNED"
forbid_bytecode
require_file "$OWNED/assignment30.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/adjudications.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/summary.json"
require_file "$OWNED/replay.zsh"
require_file "$OWNED/sha256.txt"
require_file "$OWNED/work/assignment30.jsonl"
require_file "$OWNED/work/recovery.jsonl"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/notes/source-tier.txt"
require_file "$POOL"
require_file "$HITS"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$POOL" \
  7fc0b4741c45d1b3e375b14b51b603045dc6d092e180818c5ae7f861fc783b50
expect_hash "$HITS" \
  bb84ee18b73481805a32074496561e04c08dfed95d0379058c8c2045d5c63a5a
expect_hash "$OWNED/selected.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

python3 -B - "$OWNED" "$POOL" "$HITS" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
pool = [json.loads(l) for l in Path(sys.argv[2]).read_text().splitlines() if l.strip()]
hits = [json.loads(l) for l in Path(sys.argv[3]).read_text().splitlines() if l.strip()]
c84 = json.loads(Path(sys.argv[4]).read_text())
assigned = [json.loads(l) for l in (owned / "assignment30.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
adj = [json.loads(l) for l in (owned / "adjudications.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
rec = [json.loads(l) for l in (owned / "work/recovery.jsonl").read_text().splitlines() if l.strip()]
cons = json.loads((owned / "work/conservation.json").read_text())
res = json.loads((owned / "result.json").read_text())
summary = json.loads((owned / "summary.json").read_text())
report = (owned / "report.md").read_text()
uniq = json.loads((owned / "work/uniqueness.json").read_text())
assert len(pool) == 5980
assert len(hits) == 5980
assert [r["ghsa_id"].upper() for r in pool] == [r["ghsa_id"].upper() for r in hits]
src = [h for h in hits if h.get("skip") == "no_first_party_fix_sha"]
assert len(src) == 2530
assert cons["source_population"] == 2530
assert cons["excluded_in_source"] == 0
assert cons["eligible"] == 2530
assert cons["assigned"] == 30
assert cons["eligible_leftover"] == 2500
assert 2530 == 0 + 2530
assert 2530 == 30 + 2500
assert len(assigned) == 30
assert len(cases) == 30
assert len(adj) == 30
assert len(rec) == 30
assert sel == []
assert [r["ghsa_id"] for r in assigned] == [r["case_id"] for r in cases]
assert [r["ghsa_id"] for r in assigned] == [r["ghsa_id"] for r in rec]
assert len({r["ghsa_id"] for r in assigned}) == 30
assert cons["canonical84_overlap"] == []
assert set(assigned_id := {r["ghsa_id"] for r in assigned}).isdisjoint(set(c84["strict_released_case_ids"]))
assert len(c84["strict_released_case_ids"]) == 84
assert summary["PASS"] == 0
assert summary["REJECT"] == 0
assert summary["NARROW"] == 0
assert summary["BLOCKED"] == 27
assert summary["UNKNOWN"] == 2
assert summary["NOT_SELECTED"] == 1
assert summary["selected"] == 0
assert summary["did_not_pad"] is True
assert summary["did_not_backfill"] is True
assert summary["global_json_role"] == "routing_only"
assert res["packet_delta"] == 0
assert res["current_leader_accepted_count"] == 84
assert res["canonical_count_updated"] is False
assert res["pass_proposals"] == []
assert res["global_json_role"] == "routing_only"
assert "GHSA-47Q7-97XP-M272" in report
assert "routing only" in report.lower()
assert "2530=0+2530" in report
assert "2530=30+2500" in report
assert "Current leader-accepted strict count is 84" in report
assert uniq["frozen_selected_ids"] == []
assert uniq["packet_delta"] == 0
assert sum(1 for r in cases if r["worker_verdict"] == "BLOCKED") == 27
assert sum(1 for r in cases if r["worker_verdict"] == "UNKNOWN") == 2
assert sum(1 for r in cases if r["worker_verdict"] == "NOT_SELECTED") == 1
assert all(not r.get("hard_hit") for r in cases)
assert all(r["identity_gate"] == "NOT_OPENED" for r in cases if r["worker_verdict"] == "NOT_SELECTED")
assert all(r["ai_hunk_gate"] == "NOT_OPENED" for r in cases)
assert all(r["seven_gates_opened"] is False for r in cases)
assert all(r["global_json_role"] == "routing_only" for r in cases)
for row in rec:
    for item in row.get("recovered_fix_sources") or []:
        srcn = str(item.get("source") or "")
        assert "global" not in srcn
        assert "advisory-database" not in srcn
        assert srcn.startswith("repo_advisory") or srcn == ""
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
    "assignment30.jsonl", "cases.jsonl", "selected.jsonl", "adjudications.jsonl",
    "report.md", "replay.zsh", "result.json", "summary.json",
    "work/uniqueness.json", "work/exclusion.json", "work/conservation.json",
    "work/freeze.json", "notes/README.md", "notes/source-tier.txt", "sha256.txt",
):
    text = (owned / name).read_text(encoding="utf-8")
    if name == "selected.jsonl" and text == "":
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
assert not list(owned.rglob("*.html"))
print("conservation source=2530 excluded=0 eligible=2530 assigned=30 leftover=2500 hits=0 selected=0 reviewed=0 PASS=0 REJECT=0 BLOCKED=27 UNKNOWN=2 NOT_SELECTED=1 packet_delta=0 current_leader_accepted_count=84")
PY

forbid_bytecode
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"
while IFS= read -r rel; do
  [[ -z $rel ]] && continue
  /usr/bin/git diff --no-index --check "$OWNED/$rel" "$OWNED/$rel"
done < <(/usr/bin/awk '{print $2}' "$OWNED/sha256.txt" | /usr/bin/sed 's|^\./||')

printf 'REPLAY_OK reviewed=0 PASS_proposal=0 REJECT=0 NARROW=0 UNKNOWN=2 BLOCKED=27 NOT_SELECTED=1 scan_assigned=30 hits=0 selected=0 leftover=2500 packet_delta=0 current_leader_accepted_count=84\n'
