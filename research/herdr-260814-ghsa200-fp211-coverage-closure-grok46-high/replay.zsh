#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-fp211-coverage-closure-grok46-high.
# English only. Do not print credentials. Do not clone, commit, or push.
# Coverage-only terminal zero packet. uncovered=0. freeze=0.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fp211-coverage-closure-grok46-high

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

require_file "$OWNED/coverage.jsonl"
require_file "$OWNED/coverage_summary.json"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/freeze.json"
require_file "$OWNED/work/build_coverage.py"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$OWNED/work/build_coverage.py" \
  d1ccef5603fa937ba604581b0ed0d7a12dbeb12794c0fa47dea9024f33ec2fac

# Rebuild coverage and require byte identity with the frozen coverage.jsonl.
before=$(/usr/bin/sha256sum "$OWNED/coverage.jsonl" | /usr/bin/awk '{print $1}')
python3 "$OWNED/work/build_coverage.py" >/dev/null
after=$(/usr/bin/sha256sum "$OWNED/coverage.jsonl" | /usr/bin/awk '{print $1}')
if [[ $before != "$after" ]]; then
  printf 'coverage.jsonl changed on rebuild\n' >&2
  exit 1
fi

expect_hash "$OWNED/coverage.jsonl" d1c77fa951827628a03474d902a664760884734f61698abe4cb1e1d9007a1cbe
expect_hash "$OWNED/coverage_summary.json" 701840b1a02ef745c3d74639f9597f1abf576fcaa4a89c11782010592575b276
expect_hash "$OWNED/work/uniqueness.json" e10effe007545831e1e398e5d4b5576540e1dc174a18a037ff54435cc2fe6923
expect_hash "$OWNED/report.md" 5636c7893070e2a436e242ff519787823b027529fc6bc389e780d61d7d4091f1
expect_hash "$OWNED/selected.jsonl" e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/cases.jsonl" e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/work/freeze.json" a261bb82f07dc0b167994b490a7bf6c76956797ebf825b3f815264e9537bec0f

python3 - "$OWNED" <<'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "coverage.jsonl").read_text().splitlines() if l]
if len(rows) != 92:
    raise SystemExit("coverage rows")
if len({r["ordinal"] for r in rows}) != 92:
    raise SystemExit("ordinal uniqueness")
if len({r["case_id"] for r in rows}) != 92:
    raise SystemExit("primary GHSA uniqueness")
if any(r["disposition"] == "UNCOVERED" for r in rows):
    raise SystemExit("uncovered leaked")
if sum(1 for r in rows if r["disposition"] == "COVERED_CANONICAL84_COUNTED") != 15:
    raise SystemExit("canonical count")
if sum(1 for r in rows if r["disposition"] == "COVERED_TERMINAL_PACKET") != 77:
    raise SystemExit("packet count")
if any(r["source_kind"] == "selected" for r in rows):
    raise SystemExit("selected-only assignment")
if any("fp211-audit" in (r.get("source_path") or "") for r in rows):
    raise SystemExit("inherited audit source")
if any((r.get("assigned_packet") or "").endswith("-gap") for r in rows):
    raise SystemExit("gap inventory assigned")
keys = []
for r in rows:
    keys.append((r["ordinal"], r["assigned_rule"], r["source_path"], r.get("source_line")))
if len(keys) != len(set(keys)):
    raise SystemExit("double assignment")
sel = (owned / "selected.jsonl").read_text()
cas = (owned / "cases.jsonl").read_text()
if sel != "" or cas != "":
    raise SystemExit("zero packet must have empty selected/cases")
res = json.loads((owned / "result.json").read_text())
if res["uncovered"] != 0 or res["frozen"] != 0:
    raise SystemExit("result uncovered/frozen")
if res["conservation"]["equation"] != "0=0+0":
    raise SystemExit("review equation")
if res["coverage_equation"] != "92=92+0":
    raise SystemExit("coverage equation")
if res["canonical_strict_count_untouched"] != 84:
    raise SystemExit("canonical84")
if res["packet_delta"] != 0:
    raise SystemExit("packet_delta")
uni = json.loads((owned / "work/uniqueness.json").read_text())
if uni["double_assignment"] is not False:
    raise SystemExit("uni double")
if uni["uncovered"] != 0:
    raise SystemExit("uni uncovered")
if uni["source_kind_counts"]["cases"] != 77:
    raise SystemExit("uni cases")
print("CONSERVATION_OK 92=92+0 uncovered=0 freeze=0")
PY

python3 - "$OWNED" <<'PY'
from pathlib import Path
import sys
owned = Path(sys.argv[1])
for p in owned.rglob('*'):
    if p.is_dir() and p.name == '__pycache__':
        raise SystemExit('pycache ' + str(p))
    if p.is_file() and any(x in p.name.lower() for x in ('credential', '.env', 'secret')):
        raise SystemExit('hygiene name ' + str(p))
check = [
    owned / 'coverage.jsonl',
    owned / 'coverage_summary.json',
    owned / 'report.md',
    owned / 'result.json',
    owned / 'replay.zsh',
    owned / 'work/uniqueness.json',
]
needles = ('gh' + 'p_', 'github' + '_pat_', 'AKI' + 'A')
for p in check:
    text = p.read_text()
    if any('\u4e00' <= ch <= '\u9fff' for ch in text):
        raise SystemExit('han ' + p.name)
    for ln in text.splitlines():
        if ln.endswith(' ') or ln.endswith('\t'):
            raise SystemExit('trailing whitespace ' + p.name)
    if p.name == 'replay.zsh':
        continue
    for needle in needles:
        if needle in text:
            raise SystemExit('secret string ' + p.name)
print("HYGIENE_OK")
PY

printf 'REPLAY_OK reviewed=0 PASS_proposal=0 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0 uncovered=0 freeze=0 packet_delta=0 canonical=84 coverage=92=92+0\n'
