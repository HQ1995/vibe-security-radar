#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-clonemissing84-c28-grok46-low.
# English only. Do not print credentials. Do not clone, commit, or push.
# Does not re-fetch. PASS is a proposal only; this packet admits none.
# 85=1+84 clone_missing identities. Slice C is post[56:84]. 28=9+16+3.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export PYTHONDONTWRITEBYTECODE=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-clonemissing84-c28-grok46-low
SRC=$ROOT/autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh
CACHE_LANE=/home/hanqing/.cache/ai-slop-ghsa200/herdr-260814-ghsa200-clonemissing84-c28-grok46-low
PRE=GHSA-Q2M9-6JP9-C6MC

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

forbid_han_and_trail() {
  local bad
  bad=$(/usr/bin/python3 - <<'PY'
from pathlib import Path
owned = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-clonemissing84-c28-grok46-low")
skip_dir = {"pages"}
han = False
trail = False
for p in owned.rglob("*"):
    if not p.is_file():
        continue
    if "pages" in p.parts:
        continue
    if p.suffix.lower() in {".html", ".pyc"}:
        continue
    try:
        text = p.read_text(encoding="utf-8")
    except Exception:
        continue
    for i, line in enumerate(text.splitlines(True), 1):
        if any(ord(ch) > 0x2E80 for ch in line):
            print(f"han {p}:{i}")
            han = True
        if line.endswith(" \n") or line.endswith("\t\n") or line.endswith(" ") or line.endswith("\t"):
            if line.endswith((" \n", "\t\n")) or (not line.endswith("\n") and line.endswith((" ", "\t"))):
                print(f"trail {p}:{i}")
                trail = True
if han or trail:
    raise SystemExit(1)
PY
)
  if [[ $? -ne 0 ]]; then
    printf 'han or trailing whitespace:\n%s\n' "$bad" >&2
    exit 1
  fi
}

for f in \
  assignment28.jsonl adjudications.jsonl cases.jsonl selected.jsonl \
  report.md result.json summary.json replay.zsh sha256.txt \
  work/conservation.json work/uniqueness.json work/emit_artifacts.py \
  work/recover.py work/mine.json notes/facts/compact.json
do
  require_file "$OWNED/$f"
done
if [[ -e $OWNED/notes/pages ]]; then
  printf 'raw pages must be absent: %s\n' "$OWNED/notes/pages" >&2
  exit 1
fi
if [[ -e $OWNED/compact_facts.json ]]; then
  printf 'redundant compact_facts.json must be absent\n' >&2
  exit 1
fi
forbid_bytecode

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$SRC/work/original-hits.jsonl" \
  bb84ee18b73481805a32074496561e04c08dfed95d0379058c8c2045d5c63a5a
expect_hash "$SRC/work/candidate-pool.jsonl" \
  7fc0b4741c45d1b3e375b14b51b603045dc6d092e180818c5ae7f861fc783b50
expect_hash "$SRC/work/scan-summary.json" \
  9f123d6c066b0d79c41c751b429062c27db5a05c01c5b18c4ad36f9c1047e82d

if [[ -e $CACHE_LANE ]]; then
  printf 'cache lane still present: %s\n' "$CACHE_LANE" >&2
  exit 1
fi
tmp_hits=$(/usr/bin/find /tmp -maxdepth 2 \( -iname '*clonemissing84-c28*' -o -iname '*ghsa200-clonemissing*' \) -print 2>/dev/null || true)
if [[ -n $tmp_hits ]]; then
  printf 'tmp residue:\n%s\n' "$tmp_hits" >&2
  exit 1
fi

/usr/bin/python3 - <<'PY'
import json
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OWNED = ROOT / "autoresearch/herdr-260814-ghsa200-clonemissing84-c28-grok46-low"
SRC = ROOT / "autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh"
PRE = "GHSA-Q2M9-6JP9-C6MC"
ASSIGNED = [
    "GHSA-VGRC-HQ28-P3XP",
    "GHSA-XHV3-Q4XX-349R",
    "GHSA-26GQ-P25F-99CP",
    "GHSA-62GX-5Q78-WRVX",
    "GHSA-6GR2-QH89-HXWM",
    "GHSA-8W86-M9H8-HVQG",
    "GHSA-9JPV-C7P4-997X",
    "GHSA-GVPP-V77H-5W8G",
    "GHSA-M4X6-GWGP-4PM7",
    "GHSA-P26J-H7WJ-R568",
    "GHSA-P2F4-R6V6-J797",
    "GHSA-PQPW-CVM4-8MV9",
    "GHSA-R95Q-FP26-H3HC",
    "GHSA-RXW2-PC8J-VXWM",
    "GHSA-VG6X-6PG9-6QWG",
    "GHSA-VQRW-QPHH-P34V",
    "GHSA-VWJC-V7X7-CM6G",
    "GHSA-X9F9-R4M8-9XC2",
    "GHSA-2FMJ-P74R-3WJM",
    "GHSA-5G9F-CWWG-4P8G",
    "GHSA-F5GC-QXF8-MH9G",
    "GHSA-F88M-G3JW-G9CJ",
    "GHSA-X8G9-H984-PC36",
    "GHSA-5QVP-PR9F-2G2V",
    "GHSA-7853-GQQM-VCWX",
    "GHSA-8RQH-VXPR-X77P",
    "GHSA-H8W2-RV57-VC6F",
    "GHSA-J7H9-2JH7-G967",
]
SEVEN = [
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
]

hits = []
with (SRC / "work/original-hits.jsonl").open(encoding="utf-8") as fh:
    for line in fh:
        rec = json.loads(line)
        if rec.get("skip") == "clone_missing":
            hits.append(rec["ghsa_id"])
if len(hits) != 85:
    raise SystemExit(f"clone_missing count {len(hits)} != 85")
uniq = list(dict.fromkeys(hits))
if len(uniq) != 85:
    raise SystemExit("clone_missing uniqueness failed")
if PRE not in uniq:
    raise SystemExit("preexcluded missing from 85")
post = [g for g in uniq if g != PRE]
if len(post) != 84:
    raise SystemExit("post uniqueness != 84")
if post[56:84] != ASSIGNED:
    raise SystemExit("slice C mismatch")
pool = set()
with (SRC / "work/candidate-pool.jsonl").open(encoding="utf-8") as fh:
    for line in fh:
        pool.add(json.loads(line)["ghsa_id"])
if any(g not in pool for g in uniq):
    raise SystemExit("source membership failed")
scan = json.loads((SRC / "work/scan-summary.json").read_text(encoding="utf-8"))
if scan.get("scan_clone_missing") != 85:
    raise SystemExit("scan-summary clone_missing != 85")

assign = []
with (OWNED / "assignment28.jsonl").open(encoding="utf-8") as fh:
    for i, line in enumerate(fh, 1):
        rec = json.loads(line)
        if rec["order"] != i or rec["case_id"] != ASSIGNED[i - 1]:
            raise SystemExit(f"assignment order fail {i}")
        assign.append(rec)
if len(assign) != 28:
    raise SystemExit("assignment n")

c84 = set()
with (ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl").open(encoding="utf-8") as fh:
    for line in fh:
        rec = json.loads(line)
        for k in ("ghsa_id", "case_id", "id"):
            v = rec.get(k)
            if isinstance(v, str) and v.upper().startswith("GHSA-"):
                c84.add(v.upper())
if set(ASSIGNED) & c84:
    raise SystemExit("canonical84 overlap")

sel = (OWNED / "selected.jsonl").read_text(encoding="utf-8")
if sel.strip():
    raise SystemExit("selected not empty")

n = {"PASS": 0, "NOT_SELECTED": 0, "UNKNOWN": 0, "BLOCKED": 0}
with (OWNED / "adjudications.jsonl").open(encoding="utf-8") as fh:
    for i, line in enumerate(fh, 1):
        rec = json.loads(line)
        if rec["order"] != i or rec["case_id"] != ASSIGNED[i - 1]:
            raise SystemExit("adj order")
        if rec.get("ghsa_wide_not_ai") is not False:
            raise SystemExit("ghsa_wide_not_ai")
        if rec.get("whole_case_causal_reject") is not False:
            raise SystemExit("whole_case")
        v = rec["worker_verdict"]
        n[v] = n.get(v, 0) + 1
        if v == "PASS":
            for g in SEVEN:
                if rec.get(g) != "PASS":
                    raise SystemExit(f"PASS missing {g}")
        else:
            if rec.get("ai_hunk_gate") == "PASS" and rec.get("identity_gate") == "PASS":
                # remaining gates must not silently PASS
                pass
if n["PASS"] != 0:
    raise SystemExit("PASS != 0")
if n["NOT_SELECTED"] != 9 or n["UNKNOWN"] != 16 or n["BLOCKED"] != 3:
    raise SystemExit(f"verdict mix {n}")
summary = json.loads((OWNED / "summary.json").read_text(encoding="utf-8"))
if summary.get("PASS") != 0 or summary.get("packet_delta") != 0:
    raise SystemExit("summary PASS")
if summary.get("equation") != "28=9+16+3":
    raise SystemExit("equation")
pins = json.loads((OWNED / "notes/facts/compact.json").read_text(encoding="utf-8"))
if len(pins) != 28:
    raise SystemExit("compact n")
with (OWNED / "adjudications.jsonl").open(encoding="utf-8") as fh:
    adj_rows = [json.loads(line) for line in fh]
for i, pin in enumerate(pins, 1):
    if pin.get("order") != i or pin.get("case_id") != ASSIGNED[i - 1]:
        raise SystemExit("compact order")
    if pin.get("worker_verdict") != adj_rows[i - 1]["worker_verdict"]:
        raise SystemExit("compact verdict drift")
    if "advisory_html" not in pin or "repository" not in pin:
        raise SystemExit("compact pin fields")
    if pin.get("raw_page") != "transient_deleted":
        raise SystemExit("compact raw_page")
    needed = (
        "sha256",
        "bytes",
        "title",
        "withdrawn",
        "login_wall",
        "affected_versions",
        "patched_versions",
        "named_commit_refs",
    )
    for k in needed:
        if k not in pin:
            raise SystemExit(f"compact missing {k}")
if (OWNED / "notes/pages").exists():
    raise SystemExit("pages present")
print("replay_ok 85=1+84 sliceC 28=9+16+3 PASS=0 pages_absent")
PY

forbid_han_and_trail
printf 'replay passed\n'
