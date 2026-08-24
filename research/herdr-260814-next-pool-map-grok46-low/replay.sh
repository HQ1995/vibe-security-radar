#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/hanqing/agents/ai-slop
OUT=$ROOT/autoresearch/herdr-260814-next-pool-map-grok46-low
CANON=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85
LEDGER=$CANON/ledger.jsonl
SUMMARY=$CANON/summary.json
NEG=$CANON/negative_controls.json
test -f "$LEDGER"
test -f "$SUMMARY"
test -f "$NEG"
test -f "$OUT/inventory.py"
if find "$OUT" -type d \( -name clones -o -name pages -o -name cache -o -name snapshot -o -name work \) | grep -q .; then
  echo "owned packet must not retain clones/pages/cache/snapshot/work" >&2
  exit 1
fi
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import json, re
root = Path("/home/hanqing/agents/ai-slop")
canon = root / "autoresearch/orchestrator-260814-ghsa200-canonical85"
ledger = canon / "ledger.jsonl"
summary = json.loads((canon / "summary.json").read_text())
neg = json.loads((canon / "negative_controls.json").read_text())
ghsa = re.compile(r"GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}", re.I)
ids = []
for line in ledger.read_text().splitlines():
    if not line.strip():
        continue
    row = json.loads(line)
    if row.get("record_kind") == "STRICT_RELEASED_CASE" and row.get("counted") is True:
        m = ghsa.search(row.get("case_id") or "")
        assert m, row
        ids.append(m.group(0).upper())
assert len(ids) == 85, len(ids)
assert len(set(ids)) == 85
assert set(ids) == set(x.upper() for x in summary["strict_released_case_ids"])
assert summary["conservation"]["fp211_hypotheses"] == 211
assert summary["conservation"]["fp211_source_ghsa_cases"] == 212
control_ids = [ghsa.search(c["case_id"]).group(0).upper() for c in neg["controls"]]
assert control_ids
assert not (set(control_ids) & set(ids))
print("canonical85-ledger:", sha256(ledger.read_bytes()).hexdigest())
print("canonical85-summary:", sha256((canon / "summary.json").read_bytes()).hexdigest())
print("negative_controls:", sha256((canon / "negative_controls.json").read_bytes()).hexdigest())
print("negative_control_ids:", control_ids)
PY
python3 "$OUT/inventory.py"
test -f "$OUT/result.json"
test -f "$OUT/queue.jsonl"
test -f "$OUT/excluded.jsonl"
test -f "$OUT/report.md"
python3 "$OUT/check.py"
echo replay-check: PASS
