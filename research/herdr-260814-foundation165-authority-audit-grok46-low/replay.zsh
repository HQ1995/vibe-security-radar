#!/usr/bin/env zsh
set -euo pipefail
ROOT=/home/hanqing/agents/ai-slop
OUT=$ROOT/autoresearch/herdr-260814-foundation165-authority-audit-grok46-low
FOUND=$ROOT/autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json
NEG=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85/negative_controls.json

test -f "$FOUND"
test -f "$LEDGER"
test -f "$SUMMARY"
test -f "$NEG"
test -f "$OUT/census.py"

if find "$OUT" -type d \( -name clones -o -name pages -o -name cache -o -name snapshot \) | grep -q .; then
  print -u2 "owned packet must not retain clones/pages/cache/snapshot"
  exit 1
fi

python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import json, re
root = Path("/home/hanqing/agents/ai-slop")
found = root / "autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl"
ledger = root / "autoresearch/orchestrator-260814-ghsa200-canonical85/ledger.jsonl"
summary = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json").read_text())
neg = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical85/negative_controls.json").read_text())
ghsa = re.compile(r"GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}", re.I)
fids = []
for line in found.read_text().splitlines():
    if not line.strip():
        continue
    row = json.loads(line)
    m = ghsa.search(row["case_id"])
    assert m, row
    fids.append(m.group(0).upper())
assert len(fids) == 165, len(fids)
assert len(set(fids)) == 165, "foundation ids not unique"
cids = []
for line in ledger.read_text().splitlines():
    if not line.strip():
        continue
    row = json.loads(line)
    if row.get("record_kind") == "STRICT_RELEASED_CASE" and row.get("counted") is True:
        m = ghsa.search(row["case_id"])
        assert m, row
        cids.append(m.group(0).upper())
assert len(cids) == 85, len(cids)
assert len(set(cids)) == 85
assert summary["canonical_strict_count"] == 85
assert set(cids) <= set(fids), sorted(set(cids) - set(fids))
control_ids = [ghsa.search(c["case_id"]).group(0).upper() for c in neg["controls"]]
assert control_ids
assert not (set(control_ids) & set(cids)), "negative-control ids must not be counted"
print("foundation-unique-165:", sha256(found.read_bytes()).hexdigest())
print("canonical85-unique-85:", sha256(ledger.read_bytes()).hexdigest())
print("negative_controls:", sha256((root / "autoresearch/orchestrator-260814-ghsa200-canonical85/negative_controls.json").read_bytes()).hexdigest(), control_ids)
PY

python3 "$OUT/census.py"

python3 - <<'PY'
import json
from pathlib import Path
out = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-foundation165-authority-audit-grok46-low")
r = json.loads((out / "result.json").read_text())
assert r["conservation"]["id_conservation"] is True
assert r["conservation"]["unique_ghsa_ids"] == 165
assert r["accepted_set"]["counted"] == 85
assert r["canonical85_subset_of_foundation"] is True
assert r["this_packet_does_not_claim_pass"] is True
assert r["causal_admission"] is False
assert r["frvj_pending_not_admitted"] is True
assert r["zero_false_positive_claim_for_165"] is False
assert r["conservation"]["stale_excluded_from_strict"] is True
strict = set(r["census_class_ids"]["CANONICAL85_PAYLOAD_IDENTICAL"])
stale = set(r["census_class_ids"]["STALE_SUPERSEDED"])
pending = set(r["census_class_ids"]["PENDING_INDEPENDENT_HOSTILE_REVIEW"])
assert len(strict) == 85
assert not (strict & stale)
assert not (strict & pending)
assert "GHSA-FRVJ-C5QP-XJ4W" in pending
assert "GHSA-FRVJ-C5QP-XJ4W" not in strict
canon = set(r["accepted_set"]["counted_ids"])
assert canon == strict
assert not (set(r["accepted_set"]["negative_control_reject_ids"]) & canon)
n = sum(1 for line in (out / "rows.jsonl").read_text().splitlines() if line.strip())
assert n == 165
seen = []
for line in (out / "rows.jsonl").read_text().splitlines():
    row = json.loads(line)
    seen.append(row["case_id"])
    if row["authority_status"] == "STALE_SUPERSEDED":
        assert row["strict_eligible"] is False
        assert row["canonical85_member"] is False
    if row["strict_eligible"] is True:
        assert row["authority_status"] == "CANONICAL85_PAYLOAD_IDENTICAL"
        assert row["case_id"] not in stale
assert len(seen) == 165
assert len(set(seen)) == 165
print("authority-census-conservation: PASS")
print("strict", len(strict), "stale", sorted(stale), "pending", sorted(pending))
PY
