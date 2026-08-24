#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-incomplete-routing-c27-grok46-low.
# English only. Do not print credentials. Do not clone, commit, or push.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export PYTHONDONTWRITEBYTECODE=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-routing-c27-grok46-low
POOL=$ROOT/autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh/work/candidate-pool.jsonl
HITS=$ROOT/autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh/work/original-hits.jsonl
TMP=/tmp/ghsa200-incomplete-routing-c27

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
require_file "$POOL"
require_file "$HITS"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
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
sel = (owned / "selected.jsonl").read_bytes()
rec = [json.loads(l) for l in (owned / "work/recovery.jsonl").read_text().splitlines() if l.strip()]
cons = json.loads((owned / "work/conservation.json").read_text())
res = json.loads((owned / "result.json").read_text())
summary = json.loads((owned / "summary.json").read_text())
report = (owned / "report.md").read_text()
uniq = json.loads((owned / "work/uniqueness.json").read_text())
expected = [
    "GHSA-P5CP-R7RG-QPXC","GHSA-PG67-9WJV-MR85","GHSA-PMC9-F5QR-2PCR",
    "GHSA-PMWG-CVHR-8VH7","GHSA-PR59-H9PH-3FR8","GHSA-PVMV-CWG8-V6C8",
    "GHSA-PXX3-G568-HXR4","GHSA-QRMH-QG46-72PP","GHSA-R253-R9JW-QG44",
    "GHSA-RG3H-X3JW-7JM5","GHSA-RJVW-7VVW-549V","GHSA-V2QM-5WXJ-QHJ7",
    "GHSA-V8H7-RR48-VMMV","GHSA-VJV9-7M7J-H833","GHSA-VM69-H85X-8P85",
    "GHSA-VPFX-PXQW-2W79","GHSA-VRQV-52X7-RM4V","GHSA-W2PM-X38X-JP44",
    "GHSA-W6M8-CQVJ-PG5V","GHSA-W727-595X-PC3R","GHSA-W856-8P3R-P338",
    "GHSA-WRR5-99H5-GQ57","GHSA-WRWR-H859-XH2R","GHSA-X8JC-JVQM-PM3F",
    "GHSA-XF64-8MW2-4GR2","GHSA-XP9R-PRPG-373R","GHSA-XW9Q-2MV6-9FR8",
]
assert [r["ghsa_id"] for r in assigned] == expected
assert [r["prompt_ordinal"] for r in assigned] == list(range(55, 82))
assert len(pool) == 5980 and len(hits) == 5980
src = [h for h in hits if h.get("skip") == "no_first_party_fix_sha"]
assert len(src) == 2530
src_ids = {h["ghsa_id"].upper() for h in src}
assert set(expected) <= src_ids
assert "GHSA-4C96-W8V2-P28J" not in expected
assert cons["assigned"] == 27
assert cons["source_population"] == 2530
assert cons["reviewed_unreviewed"] == "27=27+0"
assert len(assigned) == 27 and len(cases) == 27 and len(adj) == 27 and len(rec) == 27
assert sel == b""
assert [r["ghsa_id"] for r in assigned] == [r["case_id"] for r in cases]
assert [r["ghsa_id"] for r in assigned] == [r["ghsa_id"] for r in adj]
assert cons["canonical84_overlap"] == []
assert set(expected).isdisjoint(set(c84["strict_released_case_ids"]))
assert len(c84["strict_released_case_ids"]) == 84
assert summary["PASS"] == 0
assert summary["REJECT"] == 2
assert summary["NARROW"] == 0
assert summary["BLOCKED"] == 22
assert summary["UNKNOWN"] == 0
assert summary["NOT_SELECTED"] == 3
assert summary["selected"] == 0
assert summary["reviewed"] == 27
assert summary["unreviewed"] == 0
assert summary["did_not_pad"] is True
assert summary["did_not_backfill"] is True
assert summary["global_json_role"] == "routing_only"
assert res["packet_delta"] == 0
assert res["current_leader_accepted_count"] == 84
assert res["strict_remains"] == 84
assert res["pass_proposals"] == []
assert uniq["frozen_selected_ids"] == []
assert uniq["packet_delta"] == 0
assert sum(1 for r in cases if r["worker_verdict"] == "BLOCKED") == 22
assert sum(1 for r in cases if r["worker_verdict"] == "REJECT") == 2
assert sum(1 for r in cases if r["worker_verdict"] == "NOT_SELECTED") == 3
assert all(r["worker_verdict"] != "PASS" for r in cases)
assert all(r["seven_gates_opened"] is False for r in cases)
assert all(r["global_json_role"] == "routing_only" for r in cases)
assert all(r["ai_hunk_gate"] == "NOT_OPENED" for r in cases if r["worker_verdict"] != "REJECT")
assert all(r["ai_hunk_gate"] == "FAIL" for r in cases if r["worker_verdict"] == "REJECT")
assert all(r["ghsa_wide_not_ai"] is False for r in cases)
assert "Current leader-accepted strict count is 84" in report
assert "27=27+0" in report
assert "routing only" in report.lower()
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
    "assignment27.jsonl", "cases.jsonl", "adjudications.jsonl",
    "report.md", "replay.zsh", "result.json", "summary.json",
    "work/uniqueness.json", "work/conservation.json", "work/freeze.json",
    "notes/README.md", "notes/source-tier.txt", "sha256.txt",
    "notes/facts/compact.json", "notes/facts/git.json",
):
    text = (owned / name).read_text(encoding="utf-8")
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
assert not list(owned.rglob("*.html"))
print("conservation source=2530 assigned=27 reviewed=27 unreviewed=0 PASS=0 REJECT=2 BLOCKED=22 NOT_SELECTED=3 packet_delta=0 current_leader_accepted_count=84")
PY

forbid_bytecode
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"
while IFS= read -r rel; do
  [[ -z $rel ]] && continue
  /usr/bin/git diff --no-index --check "$OWNED/$rel" "$OWNED/$rel"
done < <(/usr/bin/awk '{print $2}' "$OWNED/sha256.txt" | /usr/bin/sed 's|^\./||')

printf 'REPLAY_OK reviewed=27 PASS_proposal=0 REJECT=2 NARROW=0 UNKNOWN=0 BLOCKED=22 NOT_SELECTED=3 assigned=27 selected=0 leftover=0 packet_delta=0 current_leader_accepted_count=84\n'
