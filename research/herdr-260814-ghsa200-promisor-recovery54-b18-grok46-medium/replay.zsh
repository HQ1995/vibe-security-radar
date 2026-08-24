#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-promisor-recovery54-b18-grok46-medium.
# English only. Do not print credentials. Do not clone, commit, or push.
# Do not use GitHub API. Temporary clones must already be absent.
# PASS is a proposal only; this packet admits none.
# 54=18+36. 18=17 NOT_SELECTED + 1 BLOCKED. PASS=0.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export PYTHONDONTWRITEBYTECODE=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-promisor-recovery54-b18-grok46-medium
SRC=$ROOT/autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh
HITS=$SRC/work/original-hits.jsonl
POOL=$SRC/work/candidate-pool.jsonl
CACHE=/home/hanqing/.cache/ai-slop-ghsa200/herdr-260814-ghsa200-promisor-recovery54-b18-grok46-medium
TMP_FORBIDDEN=/tmp/ghsa200-promisor-recovery54-b18

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

require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/adjudications.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/summary.json"
require_file "$OWNED/replay.zsh"
require_file "$OWNED/sha256.txt"
require_file "$OWNED/work/recover.py"
require_file "$OWNED/work/emit_artifacts.py"
require_file "$OWNED/work/conservation.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/source54.json"
require_file "$HITS"
require_file "$POOL"
forbid_bytecode

if [[ -e $CACHE ]]; then
  printf 'cache lane still present: %s\n' "$CACHE" >&2
  exit 1
fi
if [[ -e $TMP_FORBIDDEN ]]; then
  printf 'forbidden tmp lane still present: %s\n' "$TMP_FORBIDDEN" >&2
  exit 1
fi

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$HITS" \
  bb84ee18b73481805a32074496561e04c08dfed95d0379058c8c2045d5c63a5a
expect_hash "$POOL" \
  7fc0b4741c45d1b3e375b14b51b603045dc6d092e180818c5ae7f861fc783b50

python3 - <<'PY'
import json
import re
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OWNED = ROOT / "autoresearch/herdr-260814-ghsa200-promisor-recovery54-b18-grok46-medium"
SRC = ROOT / "autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh"
C84 = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl"
ASSIGNED = [
    "GHSA-2HW3-H8QX-HQQP",
    "GHSA-3JRG-97F3-RQH9",
    "GHSA-3XM7-QW7J-QC8V",
    "GHSA-4J9M-H44M-2HV8",
    "GHSA-4WG4-P27P-5Q2R",
    "GHSA-58F6-6RJ2-3V8R",
    "GHSA-6FRX-J292-C844",
    "GHSA-744G-7QM9-HJH9",
    "GHSA-76HW-P97H-883F",
    "GHSA-7FQC-P256-7PWJ",
    "GHSA-7MVR-C777-76HP",
    "GHSA-88FW-V6X4-3F58",
    "GHSA-8MVX-P2R9-R375",
    "GHSA-9GFH-4FWJ-W3RJ",
    "GHSA-9HQ9-CR36-4WPJ",
    "GHSA-9J94-67JR-4CQJ",
    "GHSA-C7V7-RQFM-F44J",
    "GHSA-F5VJ-F2HX-8M93",
]
GATES = (
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
)
SECRET = re.compile(
    r"(?i)(ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{36,}|sk-[A-Za-z0-9]{36,})"
)

def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

hits = load_jsonl(SRC / "work/original-hits.jsonl")
pool = load_jsonl(SRC / "work/candidate-pool.jsonl")
assign = load_jsonl(OWNED / "assignment.jsonl")
cases = load_jsonl(OWNED / "cases.jsonl")
adjs = load_jsonl(OWNED / "adjudications.jsonl")
selected = load_jsonl(OWNED / "selected.jsonl")
source54 = json.loads((OWNED / "work/source54.json").read_text(encoding="utf-8"))
cons = json.loads((OWNED / "work/conservation.json").read_text(encoding="utf-8"))
uniq = json.loads((OWNED / "work/uniqueness.json").read_text(encoding="utf-8"))
summary = json.loads((OWNED / "summary.json").read_text(encoding="utf-8"))

src_ids = [r["ghsa_id"].upper() for r in hits if r.get("skip") == "no_resolvable_first_party_fix"]
assert len(src_ids) == 54, len(src_ids)
assert source54["n"] == 54
assert source54["assigned"] == ASSIGNED
assert len(source54["leftover36"]) == 36
assert cons["equation"] == "54=18+36"
assert cons["assigned"] == 18
assert cons["source_population"] == 54
hit_by = {r["ghsa_id"].upper(): r for r in hits}
pool_by = {r["ghsa_id"].upper(): r for r in pool}
assert [r["ghsa_id"] for r in assign] == ASSIGNED
assert [r["ghsa_id"] for r in cases] == ASSIGNED
assert [r["ghsa_id"] for r in adjs] == ASSIGNED
assert [r["assigned_order"] for r in assign] == list(range(1, 19))
for gid in ASSIGNED:
    assert hit_by[gid]["skip"] == "no_resolvable_first_party_fix", gid
    assert gid in pool_by, gid
    assert gid in src_ids, gid
leftover = [g for g in src_ids if g not in set(ASSIGNED)]
assert len(leftover) == 36
assert leftover == source54["leftover36"]

verdicts = [r["worker_verdict"] for r in cases]
assert verdicts.count("PASS") == 0
assert selected == []
assert summary["PASS"] == 0
assert summary["selected"] == 0
assert summary["packet_delta"] == 0
assert cons["pass"] == 0
assert verdicts.count("NOT_SELECTED") == 17
assert verdicts.count("BLOCKED") == 1
assert len(verdicts) == 18
assert 18 == 17 + 1
assert cases[10]["ghsa_id"] == "GHSA-7MVR-C777-76HP"
assert cases[10]["worker_verdict"] == "BLOCKED"
for row in cases:
    if row["worker_verdict"] == "PASS":
        for g in GATES:
            assert row[g] == "PASS", (row["ghsa_id"], g)
    assert row["whole_case_causal_reject"] is False
    assert row["ghsa_wide_not_ai"] is False
    assert row["hard_hit"] is False
    assert row["source_skip"] == "no_resolvable_first_party_fix"

c84 = set()
for row in load_jsonl(C84):
    cid = str(row.get("ghsa_id") or row.get("case_id") or "").upper()
    if cid.startswith("GHSA-"):
        c84.add(cid)
overlap = [g for g in ASSIGNED if g in c84]
assert overlap == [], overlap
assert uniq["canonical84_overlap"] == []

for path in OWNED.rglob("*"):
    if not path.is_file():
        continue
    if path.suffix in {".pyc"}:
        raise SystemExit(f"bytecode {path}")
    data = path.read_bytes()
    if SECRET.search(data.decode("utf-8", "replace")):
        raise SystemExit(f"secret-like text in {path}")
    if path.suffix in {".md", ".json", ".jsonl", ".zsh", ".txt", ".py"}:
        text = data.decode("utf-8")
        for i, line in enumerate(text.splitlines(), 1):
            if line.endswith(" ") or line.endswith("\t"):
                raise SystemExit(f"trailing whitespace {path}:{i}")

report = (OWNED / "report.md").read_text(encoding="utf-8")
assert "0 PASS" in report
assert "54=18+36" in report
print("replay_ok 18=17+1 PASS=0 cache_absent")
PY
