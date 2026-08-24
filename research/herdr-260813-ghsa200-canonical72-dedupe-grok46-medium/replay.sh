#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260813-ghsa200-canonical72-dedupe-grok46-medium.
# English only. Do not print credentials. Do not clone, commit, or push.
# Do not name a local 'path': zsh ties path to PATH.
# This uniqueness proposal admits none and does not rewrite canonical71.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260813-ghsa200-canonical72-dedupe-grok46-medium
LEDGER=$ROOT/autoresearch/orchestrator-260813-ghsa200-canonical71/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260813-ghsa200-canonical71/summary.json

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

require_file "$OWNED/result.json"
require_file "$OWNED/pairs.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/replay.sh"
require_file "$LEDGER"
require_file "$SUMMARY"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/baseline.json" \
  d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132
expect_hash "$LEDGER" \
  d6faff5d71aa08113dc845c9e5048687fb287778d31910250b2df3f494635bc8
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl" \
  1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$OWNED/pairs.jsonl" \
  7d01ebefa98d871b91a905866c0d78440f59253e8ca44b58b03f3fb2aac3572f
expect_hash "$OWNED/result.json" \
  fb3b97c7b5d207119cc22d255ba48cbda568d56c8fffb447fb0e58ac8878f4fb
expect_hash "$OWNED/report.md" \
  d1db91d9af11aaa69ce4965ea5033358babaf6f48897388d8a4c503e0efa2032

/usr/bin/python3 - "$LEDGER" "$OWNED/pairs.jsonl" "$OWNED/result.json" "$OWNED/report.md" <<'PY'
import json
import sys
from collections import Counter

ledger_path, pairs_path, result_path, report_path = sys.argv[1:5]
rows = [json.loads(line) for line in open(ledger_path) if line.strip()]
kinds = Counter(row["record_kind"] for row in rows)
assert len(rows) == 540, len(rows)
assert kinds["PRESERVED_HYPOTHESIS"] == 211
assert kinds["PRESERVED_PUBLIC_CASE"] == 212
assert kinds["STRICT_RELEASED_CASE"] == 72
assert kinds["APPEND_IDENTITY"] == 3

strict = [row for row in rows if row["record_kind"] == "STRICT_RELEASED_CASE"]
pub = [row for row in rows if row["record_kind"] == "PRESERVED_PUBLIC_CASE"]
app = [row for row in rows if row["record_kind"] == "APPEND_IDENTITY"]
ids = [row["case_id"] for row in strict]
assert len(ids) == len(set(ids)) == 72
assert all(row["counting_unit"] == "first-party GHSA case" for row in strict)
assert all(row["counted"] is True for row in strict)
assert all(not case_id.startswith("CVE-") for case_id in ids)
fps = [row["mechanism_fingerprint"] for row in strict]
keys = [row["mechanism_key"] for row in strict]
assert len(set(fps)) == 72
assert len(set(keys)) == 72
aliases = [item for row in strict for item in (row.get("aliases") or [])]
assert all(item.startswith("CVE-") for item in aliases)
assert len(aliases) == len(set(aliases))
assert not any(item.startswith("GHSA-") for item in aliases)
owners = {}
for row in strict:
    for item in [row["case_id"], *(row.get("aliases") or [])]:
        owners.setdefault(item, set()).add(row["case_id"])
assert all(len(v) == 1 for v in owners.values())

source = {row["case_id"] for row in pub}
append_ids = {row["case_id"] for row in app}
expect_append = {
    "GHSA-6P9M-Q3JP-47H4",
    "GHSA-G39V-CVJH-8FPF",
    "GHSA-PF93-J98V-25PV",
}
assert append_ids == expect_append
assert not (append_ids & source)
for row in strict:
    if row["case_id"] in expect_append:
        assert row["in_fp211_212"] is False

banned = {
    "GHSA-4FXP-2M36-QV64",
    "GHSA-7C3W-FXGH-FRC7",
    "GHSA-F38V-77QJ-H4JQ",
}
assert not (banned & set(ids))
assert not ({"GHSA-3J8Q-FWPJ-F8J5", "GHSA-JJCJ-H3CM-P7X7"} & set(ids))

pairs = [json.loads(line) for line in open(pairs_path) if line.strip()]
assert len(pairs) == 186, len(pairs)
assert all(row["verdict"] == "SEPARATE" for row in pairs)
assert all(row["canonical_survivor"] is None for row in pairs)
assert all(row["shared_sha_alone_dedupes"] is False for row in pairs)
assert all(row["left"] < row["right"] for row in pairs)

result = json.load(open(result_path))
assert result["language"] == "en"
assert result["status"] == "HOLD"
assert result["uniqueness_verdict"] == "72_UNIQUE"
assert result["same_mechanism_duplicates"] == 0
assert result["counted_first_party_ghsa"] == 72
assert result["cve_aliases_counted"] is False
assert result["public_200_claim_supported"] is False
assert result["causal_admission"] is False
assert result["integration_ready"] is False
assert result["publication_ready"] is False
assert result["canonical_survivor"] is None
assert result["duplicate_pairs"] == []
assert result["conservation"]["fp211_hypotheses"] == 211
assert result["conservation"]["fp211_source_ghsa_cases"] == 212
assert result["conservation"]["STRICT_RELEASED_CASE"] == 72
assert result["validations"]["append_identities_absent_from_212"] is True
assert result["did_not_edit_canonical"] is True
assert result["did_not_commit_or_push"] is True
report = open(report_path).read()
assert "72 unique first-party GHSA identities" in report
assert "more-than-200" in report
assert "does not support a more-than-200 claim" in report
low = report.lower()
assert "more than 200 unique" not in low
print("PASS: conservation 211/212/72; uniqueness 72_UNIQUE; pairs 186 SEPARATE; HOLD; no more-than-200 claim")
PY
