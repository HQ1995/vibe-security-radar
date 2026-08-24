#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-clonemissing84-b28-grok46-medium.
# English only. Do not print credentials. Do not clone, fetch, commit, or push.
# Do not call GitHub API. Temporary clones must already be absent.
# PASS is a proposal only; this packet admits none.
# 85=1+84. 84=28+56. 28=18 UNKNOWN + 6 NOT_SELECTED + 2 BLOCKED + 2 REJECT_CANDIDATE_EDGE.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export PYTHONDONTWRITEBYTECODE=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-clonemissing84-b28-grok46-medium
SRC=$ROOT/autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh
HITS=$SRC/work/original-hits.jsonl
POOL=$SRC/work/candidate-pool.jsonl
RES=$ROOT/autoresearch/herdr-260814-ghsa200-promisor389-residual11-grok46-high
CACHE=/home/hanqing/.cache/ai-slop-ghsa200/herdr-260814-ghsa200-clonemissing84-b28-grok46-medium
TMP_FORBIDDEN=/tmp/ghsa200-clonemissing84-b28

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

require_file "$OWNED/assignment28.jsonl"
require_file "$OWNED/adjudications.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/summary.json"
require_file "$OWNED/replay.zsh"
require_file "$OWNED/sha256.txt"
require_file "$OWNED/work/recover.py"
require_file "$OWNED/work/emit_artifacts.py"
require_file "$OWNED/work/conservation.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/source85.json"
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
expect_hash "$RES/assignment11.jsonl" \
  8b4f6941650662f910aa17cb299c2902791b7fa46692a6b37b485a62ec8fd80b

expect_hash "$OWNED/assignment28.jsonl" 1da7fa1846ab563dfdbb2b4e862b65926187ae024804e37827c87485cc384019
expect_hash "$OWNED/adjudications.jsonl" 7133540f7766c5ec566a1b2e583d3edfebabe349ac586e3654792a764562378a
expect_hash "$OWNED/cases.jsonl" 9fb3a9f66a67201465b3a6b38b1a5c40966d2f62448a1cf32d3384e5fd96dc58
expect_hash "$OWNED/selected.jsonl" e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/report.md" bfd45af9e0c5d51b25da3ed816953cfc8018bfd0c213d44954ae15acbfb5bb3f
expect_hash "$OWNED/summary.json" d3fb6eed445d5115320a77763050caaad5afaf68468a06f906c9a9a7912ba342
expect_hash "$OWNED/work/conservation.json" e2784a0ac49e70423f3b29bb94be6a82b3c62f668d48d8511c8f87aff1fa15c7
expect_hash "$OWNED/work/uniqueness.json" 409aaef8e17fff580b92b7ff699fb2324f03f0ee666ab8db0187b4906e0caa26
expect_hash "$OWNED/work/source85.json" 05277e828444ec3f6c5b7f36b90267c04e063d41a32df856486a5ea0cf0b25ea
expect_hash "$OWNED/work/recover.py" c91e88a01e280cf7cd8df811d81e8890cc393930dd9a81e085d2ea5b62895641
expect_hash "$OWNED/work/emit_artifacts.py" 8475b23994be178a0633acc4096043eb96cba3ff2aa2b1791ef631ff049c7ed3
expect_hash "$OWNED/notes/facts/html_identity.json" a91990d25c601e0eef185b2c63d47ce04de02b2adb1b5a8eae2d26b93662ef57

python3 -B - <<'PY'
import json
import re
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OWNED = ROOT / "autoresearch/herdr-260814-ghsa200-clonemissing84-b28-grok46-medium"
SRC = ROOT / "autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh"
C84 = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl"
RES = ROOT / "autoresearch/herdr-260814-ghsa200-promisor389-residual11-grok46-high/assignment11.jsonl"
PRE = "GHSA-Q2M9-6JP9-C6MC"
ASSIGNED = [
    "GHSA-3R68-X3XC-RXPG",
    "GHSA-3R75-XC34-5F44",
    "GHSA-423P-G724-FR39",
    "GHSA-4C35-WCG5-MM9H",
    "GHSA-64VR-4GR2-M642",
    "GHSA-7XGW-6QF3-7W59",
    "GHSA-88Q9-CMP2-C2VQ",
    "GHSA-CFCJ-HQPF-HCCF",
    "GHSA-F77V-9VPC-6PJM",
    "GHSA-G6WW-W5J2-R7X3",
    "GHSA-GC8W-X73W-P4RH",
    "GHSA-JJ54-R8GM-2FCF",
    "GHSA-JWP7-WG77-3W9V",
    "GHSA-JXH8-JH77-XH6G",
    "GHSA-PWQG-Q8PG-PP6R",
    "GHSA-QHH4-458H-XWH2",
    "GHSA-V228-72C7-FX8J",
    "GHSA-V5MH-H5HX-7V92",
    "GHSA-VRXG-GM77-7Q5G",
    "GHSA-XPWW-F6PM-CFHQ",
    "GHSA-3PVJ-JV98-QHJQ",
    "GHSA-6GQW-JQV7-V88M",
    "GHSA-7QJX-GP9H-65QJ",
    "GHSA-FQ4X-789W-JG5H",
    "GHSA-HJWC-26PJ-V3PM",
    "GHSA-JR33-MW75-7J8F",
    "GHSA-M6VC-F87M-CC2H",
    "GHSA-QH5X-RFWF-RVFV",
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
assign = load_jsonl(OWNED / "assignment28.jsonl")
cases = load_jsonl(OWNED / "cases.jsonl")
adjs = load_jsonl(OWNED / "adjudications.jsonl")
selected = load_jsonl(OWNED / "selected.jsonl")
source85 = json.loads((OWNED / "work/source85.json").read_text(encoding="utf-8"))
cons = json.loads((OWNED / "work/conservation.json").read_text(encoding="utf-8"))
uniq = json.loads((OWNED / "work/uniqueness.json").read_text(encoding="utf-8"))
summary = json.loads((OWNED / "summary.json").read_text(encoding="utf-8"))
residual = load_jsonl(RES)

ordered = []
seen = set()
for row in hits:
    if row.get("skip") != "clone_missing":
        continue
    gid = str(row.get("ghsa_id") or "").upper()
    if gid in seen:
        raise SystemExit("duplicate clone_missing identity")
    seen.add(gid)
    ordered.append(gid)
assert len(ordered) == 85, len(ordered)
assert PRE in ordered
assert PRE in [str(r.get("case_id") or "").upper() for r in residual]
post = [g for g in ordered if g != PRE]
assert len(post) == 84
assert post[28:56] == ASSIGNED
assert PRE not in ASSIGNED
assert source85["n"] == 85
assert source85["preexcluded"] == PRE
assert source85["assigned"] == ASSIGNED
assert source85["equation"] == "85=1+84"
assert cons["equation"] == "85=1+84"
assert cons["packet_equation"] == "28=18+6+2+2"
assert cons["assigned"] == 28
assert cons["leftover56"] == 56
hit_by = {r["ghsa_id"].upper(): r for r in hits}
pool_by = {r["ghsa_id"].upper(): r for r in pool}
assert [r["case_id"] for r in assign] == ASSIGNED
assert [r["case_id"] for r in cases] == ASSIGNED
assert [r["case_id"] for r in adjs] == ASSIGNED
assert [r["order"] for r in assign] == list(range(1, 29))
for gid in ASSIGNED:
    assert hit_by[gid]["skip"] == "clone_missing", gid
    assert gid in pool_by, gid
    assert gid in post, gid
c84 = set()
for row in load_jsonl(C84):
    cid = str(row.get("ghsa_id") or row.get("case_id") or "").upper()
    if cid.startswith("GHSA-"):
        c84.add(cid)
assert not (set(ASSIGNED) & c84)
assert uniq.get("canonical84_overlap") == []
assert selected == []
assert summary["PASS"] == 0
assert summary["pass_proposals"] == 0
assert summary["packet_delta"] == 0
assert summary["ghsa_wide_not_ai_count"] == 0
assert summary["whole_case_causal_reject"] == 0
verdicts = [c["worker_verdict"] for c in cases]
assert verdicts.count("UNKNOWN") == 18
assert verdicts.count("NOT_SELECTED") == 6
assert verdicts.count("BLOCKED") == 2
assert verdicts.count("REJECT_CANDIDATE_EDGE") == 2
assert "PASS" not in verdicts
for case in cases:
    assert case["ghsa_wide_not_ai"] is False
    assert case["whole_case_causal_reject"] is False
    assert case["countable"] is False
    gates = case["gates"]
    assert set(gates) == set(GATES)
    if case["worker_verdict"] == "PASS":
        raise SystemExit("unexpected PASS")
    if all(gates[g] == "PASS" for g in GATES):
        raise SystemExit("all seven gates PASS without packet PASS")
    if case["worker_verdict"] == "NOT_SELECTED":
        assert gates["identity_gate"] == "PASS"
        for g in GATES:
            if g != "identity_gate":
                assert gates[g] == "NOT_OPENED", (case["case_id"], g, gates[g])
ws = re.compile(r"[ \t]+$", re.M)
han = re.compile(r"\bHan\b")
for path in OWNED.rglob("*"):
    if not path.is_file():
        continue
    if path.suffix in {".pyc", ".pyo"} or path.name == "__pycache__":
        raise SystemExit("bytecode")
    text = path.read_text(encoding="utf-8", errors="replace")
    if SECRET.search(text):
        raise SystemExit(f"secret-like token in {path}")
    if ws.search(text):
        raise SystemExit(f"trailing whitespace in {path}")
    if path.suffix == ".md" and han.search(text):
        raise SystemExit(f"Han in {path}")
print("replay_ok 85=1+84 84=28+56 PASS=0")
PY

printf 'replay complete\n'
