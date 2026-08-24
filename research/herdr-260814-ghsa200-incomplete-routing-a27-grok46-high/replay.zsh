#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-incomplete-routing-a27-grok46-high.
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
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-routing-a27-grok46-high
POOL=$ROOT/autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh/work/candidate-pool.jsonl
HITS=$ROOT/autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh/work/original-hits.jsonl
TMP=/tmp/ghsa200-incomplete-routing-a27

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
require_file "$OWNED/assignment27.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/adjudications.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/summary.json"
require_file "$OWNED/replay.zsh"
require_file "$OWNED/sha256.txt"
require_file "$OWNED/work/assignment27.jsonl"
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
assigned = [json.loads(l) for l in (owned / "assignment27.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
adj = [json.loads(l) for l in (owned / "adjudications.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
cons = json.loads((owned / "work/conservation.json").read_text())
res = json.loads((owned / "result.json").read_text())
summary = json.loads((owned / "summary.json").read_text())
report = (owned / "report.md").read_text()
uniq = json.loads((owned / "work/uniqueness.json").read_text())
expect = [
    "GHSA-25RP-H46X-2HJM", "GHSA-26HH-7CQF-HHC6", "GHSA-286P-VC9P-P5QV",
    "GHSA-2M69-JMVH-6CHR", "GHSA-2PQ5-3Q89-J7CC", "GHSA-2WPX-QPW2-G5H5",
    "GHSA-3298-56P6-RPW2", "GHSA-3J5Q-7Q7H-2HHV", "GHSA-44FC-8FM5-Q62H",
    "GHSA-45Q3-82M4-75JR", "GHSA-47WQ-CJ9Q-WPMP", "GHSA-489G-7RXV-6C8Q",
    "GHSA-4C3Q-X735-J3R5", "GHSA-53MQ-F4W3-F7QV", "GHSA-56MP-4F3V-FGJ2",
    "GHSA-5FC7-F62M-8983", "GHSA-5HC8-QMG8-PW27", "GHSA-5J59-XGG2-R9C4",
    "GHSA-5V5V-WW74-355V", "GHSA-654M-C8P4-X5FP", "GHSA-65PC-FJ4G-8RJX",
    "GHSA-6C2X-GCP3-GP73", "GHSA-6JP5-HH4C-8C5H", "GHSA-6M52-M754-PW2G",
    "GHSA-7526-J432-6PPP", "GHSA-78F9-R8MH-4XM2", "GHSA-7FXW-R6JV-74C8",
]
assert len(pool) == 5980
assert len(hits) == 5980
src = {h["ghsa_id"].upper() for h in hits if h.get("skip") == "no_first_party_fix_sha"}
assert len(src) == 2530
assert cons["source_population"] == 2530
assert cons["assigned"] == 27
assert cons["did_not_backfill"] is True
assert cons["did_not_pad"] is True
assert cons["selector_regex_reproduction"] == "leader_pinned_not_independently_reconstructed"
assert len(assigned) == 27
assert len(cases) == 27
assert len(adj) == 27
assert sel == []
assert [r["ghsa_id"] for r in assigned] == expect
assert [r["case_id"] for r in cases] == expect
assert [r["ghsa_id"] for r in adj] == expect
assert len({r["ghsa_id"] for r in assigned}) == 27
assert set(expect).issubset(src)
assert set(expect).isdisjoint(set(c84["strict_released_case_ids"]))
assert len(c84["strict_released_case_ids"]) == 84
assert cons["canonical84_overlap"] == []
assert cons["incomplete_remediation20_overlap"] == []
assert "GHSA-4C96-W8V2-P28J" not in expect
assert summary["PASS"] == 0
assert summary["REJECT"] == 5
assert summary["UNKNOWN"] == 2
assert summary["BLOCKED"] == 20
assert summary["NOT_SELECTED"] == 0
assert summary["NARROW"] == 0
assert summary["selected"] == 0
assert summary["did_not_pad"] is True
assert summary["did_not_backfill"] is True
assert summary["global_json_role"] == "routing_only"
assert summary["github_api_used"] is False
assert res["packet_delta"] == 0
assert res["current_leader_accepted_count"] == 84
assert res["canonical_count_updated"] is False
assert res["pass_proposals"] == []
assert res["global_json_role"] == "routing_only"
assert "leader-pinned" in report.lower() or "leader-pinned" in report
assert "Current leader-accepted strict count is 84" in report
assert uniq["frozen_selected_ids"] == []
assert uniq["packet_delta"] == 0
assert sum(1 for r in cases if r["worker_verdict"] == "BLOCKED") == 20
assert sum(1 for r in cases if r["worker_verdict"] == "UNKNOWN") == 2
assert sum(1 for r in cases if r["worker_verdict"] == "REJECT") == 5
assert all(not r.get("hard_hit") for r in cases)
assert all(r["seven_gates_opened"] is False for r in cases)
assert all(r["global_json_role"] == "routing_only" for r in cases)
assert all(r["ghsa_wide_not_ai"] is False for r in cases)
assert all(r["countable_proposal"] is False for r in cases)
assert all(r["identity_gate"] == "PASS" for r in cases if r["worker_verdict"] == "REJECT")
assert all(r["ai_hunk_gate"] == "FAIL" for r in cases if r["worker_verdict"] == "REJECT")
assert all(r["identity_gate"] == "UNKNOWN" for r in cases if r["worker_verdict"] == "UNKNOWN")
malware = {"GHSA-286P-VC9P-P5QV", "GHSA-53MQ-F4W3-F7QV", "GHSA-6JP5-HH4C-8C5H"}
human = {"GHSA-489G-7RXV-6C8Q", "GHSA-7526-J432-6PPP"}
assert {r["ghsa_id"] for r in cases if r["worker_verdict"] == "REJECT"} == malware | human
for r in cases:
    if r["ghsa_id"] in malware:
        assert r["contribution_class"] == "NOT_APPLICABLE_ROUTING_FALSE_HIT"
        assert r["reject_class"] == "REJECT_INCOMPLETE_REM_EDGE"
        assert r["ghsa_wide_not_ai"] is False
    else:
        assert r["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    if r["ghsa_id"] in human:
        assert r["reject_class"] == "REJECT_INCOMPLETE_REM_EDGE"
        assert r["ghsa_wide_not_ai"] is False
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
    "assignment27.jsonl", "cases.jsonl", "selected.jsonl", "adjudications.jsonl",
    "report.md", "replay.zsh", "result.json", "summary.json",
    "work/uniqueness.json", "work/conservation.json", "work/freeze.json",
    "notes/README.md", "notes/source-tier.txt", "sha256.txt",
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
print("conservation source=2530 assigned=27 leftover=0 hits=0 selected=0 reviewed=27 PASS=0 REJECT=5 BLOCKED=20 UNKNOWN=2 NOT_SELECTED=0 packet_delta=0 current_leader_accepted_count=84")
PY

forbid_bytecode
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"
while IFS= read -r rel; do
  [[ -z $rel ]] && continue
  /usr/bin/git diff --no-index --check "$OWNED/$rel" "$OWNED/$rel"
done < <(/usr/bin/awk '{print $2}' "$OWNED/sha256.txt" | /usr/bin/sed 's|^\./||')

printf 'REPLAY_OK reviewed=27 PASS_proposal=0 REJECT=5 NARROW=0 UNKNOWN=2 BLOCKED=20 NOT_SELECTED=0 scan_assigned=27 hits=0 selected=0 leftover=0 packet_delta=0 current_leader_accepted_count=84\n'
