#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/hanqing/agents/ai-slop
OUT=$ROOT/autoresearch/herdr-260814-ghsa200-current-proposal-gap-grok46-low
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl
NEG=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/negative_controls.json
test -f "$LEDGER"
test -f "$NEG"
test -f "$OUT/census.py"
# No cached clones or advisory pages in the owned packet.
if find "$OUT" -type d \( -name clones -o -name pages -o -name cache -o -name snapshot \) | grep -q .; then
  echo "owned packet must not retain clones/pages/cache/snapshot" >&2
  exit 1
fi
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
root = Path("/home/hanqing/agents/ai-slop")
ledger = root / "autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl"
neg = root / "autoresearch/orchestrator-260814-ghsa200-canonical84/negative_controls.json"
import json, re
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
assert len(ids) == 84, len(ids)
assert len(set(ids)) == 84, "canonical ids not unique"
controls = json.loads(neg.read_text())["controls"]
control_ids = [ghsa.search(c["case_id"]).group(0).upper() for c in controls]
assert control_ids, "negative_controls.json empty"
assert not (set(control_ids) & set(ids)), "negative-control ids must not be counted"
print("canonical84-unique-84:", sha256(ledger.read_bytes()).hexdigest())
print("negative_controls:", sha256(neg.read_bytes()).hexdigest(), control_ids)
PY
python3 "$OUT/census.py"
test -f "$OUT/result.json"
test -f "$OUT/cases.jsonl"
test -f "$OUT/report.md"
test -f "$OUT/manifest.json"
python3 - <<'PY'
import json
from pathlib import Path
out = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-current-proposal-gap-grok46-low")
r = json.loads((out / "result.json").read_text())
assert r["conservation"]["id_conservation"] is True
assert r["accepted_set"]["counted"] == 84
assert r["conservation"]["canonical_exclusion_of_genuine"] is True
assert r["conservation"]["negative_control_exclusion_of_genuine"] is True
assert r["this_packet_does_not_claim_pass"] is True
assert r["causal_admission"] is False
canon = set(r["accepted_set"]["counted_ids"])
genuine = r["genuine_unresolved_ids"]
assert len(genuine) == len(set(genuine))
assert not (set(genuine) & canon)
neg_ids = set(r["accepted_set"]["negative_control_reject_ids"])
assert neg_ids
assert not (set(genuine) & neg_ids)
assert all(x not in genuine for x in neg_ids)
n = sum(1 for line in (out / "cases.jsonl").read_text().splitlines() if line.strip())
assert n == r["genuine_unresolved_count"]
m = json.loads((out / "manifest.json").read_text())
assert m["accepted_ledger_sha256"] == r["accepted_set"]["sha256"]
print("census-conservation: PASS")
print("unresolved", genuine)
print("packets", r["scan"]["packets"], "files", r["scan"]["files_scanned"], "rows", r["scan"]["jsonl_rows_parsed"])
PY
