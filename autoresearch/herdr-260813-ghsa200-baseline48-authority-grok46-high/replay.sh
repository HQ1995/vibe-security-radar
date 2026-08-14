#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260813-ghsa200-baseline48-authority-grok46-high.
# English only. Do not print credentials. Do not fetch, clone, commit, or push.
# Do not name a local 'path': zsh ties path to PATH.
# Authority audit proposal pending leader replay. Does not admit a 200-case claim.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260813-ghsa200-baseline48-authority-grok46-high

require_dir() {
  if [[ ! -d $1 ]]; then
    printf 'missing directory: %s\n' "$1" >&2
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

require_dir "$OWNED"
require_dir "$ROOT/autoresearch/orchestrator-260813-fp211-canonical"
require_dir "$ROOT/autoresearch/herdr-260813-ghsa200-final-candidate-review-codex"

# Frozen conservation inputs. current must equal frozen.
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/baseline.json" \
  d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl" \
  1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-final-candidate-review-codex/cases.jsonl" \
  e275437954890dca07855b5fcfa545f8f1a366fb85a7ee9f067da5b710b2b3da
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-final-candidate-review-codex/result.json" \
  4be2620a548370c845e22c0d7cbe3ed10ab156ef39b1a0432ff4220ff406e528

# Current hashes of contrary-vote packets considered and rejected as authority.
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-redbase-even/cases.jsonl" \
  e9f419720dc0a72f6badf7f8d989a8da5dc5f096df97896d901dd6bf941a8927
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-redbase-odd/cases.jsonl" \
  3618a883d2366ce8b956371a96cf1d7f52f446687d756aa2b27bd9c5b5e022fc
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-baseline-increm-even/cases.jsonl" \
  5a22f90ab1331aa6236cdeba3ee76ed03457a9777341ace456055fefac8be523
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-baseline-increm-odd/cases.jsonl" \
  4d34a597329e2497b95ec68e9e893c07e07408f2f2775054821527532f79e94f

python3 - "$ROOT" "$OWNED" << 'PY'
import hashlib, json, re, sys
from pathlib import Path

root = Path(sys.argv[1])
owned = Path(sys.argv[2])
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
REQUIRED = [
    "schema_version", "row_kind", "language", "english_only", "case_id", "row_key",
    "ordinal", "repository", "mechanism_key", "contribution_class", "aliases",
    "counting_unit", "cve_aliases_are_not_counting_units", "disposition",
    "replacement_identity", "fp211_released_publication_admitted",
    "authoritative_source", "reason", "conflicts", "later_confirmation",
    "causal_admission", "publication_status", "worker_outcome", "more_than_200_claim",
]
SRC_REQUIRED = [
    "packet", "path", "sha256", "result_path", "result_sha256", "role",
    "terminal_status", "frozen_at_utc", "case_id", "row_key", "verdict", "failed_gate",
]

def fail(msg):
    raise SystemExit(msg)

def assert_no_null(obj, loc):
    if obj is None:
        fail("null at " + loc)
    if isinstance(obj, dict):
        for k, v in obj.items():
            assert_no_null(v, loc + "." + k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            assert_no_null(v, loc + "[%d]" % i)

res = json.loads((owned / "result.json").read_text())
assert_no_null(res, "result.json")
if res["status"] != "TERMINAL":
    fail("status")
if res["terminal"] is not True:
    fail("terminal")
if res["causal_admission"] is not False:
    fail("causal_admission")
if res["publication_status"] != "HOLD":
    fail("publication_status")
if res["more_than_200_claim"] is not True and res["more_than_200_claim"] is not False:
    fail("more_than_200_claim type")
if res["more_than_200_claim"] is not False:
    fail("more_than_200_claim must be false")
if res["worker_outcome"] != "authority audit proposal pending leader replay":
    fail("worker_outcome")
if res["english_only"] is not True:
    fail("english_only")
if res["conservation"]["original"] != 48:
    fail("original")
if res["conservation"]["keep_baseline"] != 47:
    fail("keep")
if res["conservation"]["downgrade"] != 1:
    fail("downgrade")
if res["conservation"]["original"] != res["conservation"]["keep_baseline"] + res["conservation"]["downgrade"]:
    fail("conservation equation")
if res["conservation"]["equation"] != "48 = 47 KEEP_BASELINE + 1 DOWNGRADE":
    fail("equation string")
if res["downgrade_case_ids"] != ["GHSA-4FXP-2M36-QV64"]:
    fail("downgrade_case_ids")

cases_path = owned / "cases.jsonl"
got = hashlib.sha256(cases_path.read_bytes()).hexdigest()
if got != res["artifacts"]["cases.jsonl_sha256"]:
    fail("cases hash " + got)
report_got = hashlib.sha256((owned / "report.md").read_bytes()).hexdigest()
if report_got != res["artifacts"]["report.md_sha256"]:
    fail("report hash " + report_got)
replay_got = hashlib.sha256((owned / "replay.sh").read_bytes()).hexdigest()
if replay_got != res["artifacts"]["replay.sh_sha256"]:
    fail("replay hash " + replay_got)

ledger_path = root / "autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl"
ledger = [json.loads(l) for l in ledger_path.read_text().splitlines() if l.strip()]
admitted = []
for row in ledger:
    counting = row.get("counting") or {}
    if counting.get("fp211_released_publication_admitted") is True:
        ghsas = [str(x).upper() for x in (row.get("public_ids") or []) if GHSA_RE.match(str(x).upper())]
        if len(ghsas) != 1:
            fail("ledger identity " + str(ghsas))
        admitted.append(ghsas[0])
if len(admitted) != 48:
    fail("ledger admitted count %d" % len(admitted))
if len(set(admitted)) != 48:
    fail("ledger duplicate admitted")

raw_lines = [l for l in cases_path.read_text().splitlines() if l.strip()]
if len(raw_lines) != 48:
    fail("cases line count %d" % len(raw_lines))
rows = []
for i, line in enumerate(raw_lines, 1):
    rec = json.loads(line)
    assert_no_null(rec, "cases[%d]" % i)
    if not isinstance(rec, dict):
        fail("row type %d" % i)
    for key in REQUIRED:
        if key not in rec:
            fail("missing %s on row %d" % (key, i))
    if rec["language"] != "en":
        fail("language %s" % rec["case_id"])
    if rec["english_only"] is not True:
        fail("english_only %s" % rec["case_id"])
    if rec["row_kind"] != "BASELINE48_AUTHORITY_AUDIT":
        fail("row_kind %s" % rec["case_id"])
    if rec["schema_version"] != 1:
        fail("schema_version %s" % rec["case_id"])
    if not isinstance(rec["case_id"], str) or not GHSA_RE.match(rec["case_id"]):
        fail("case_id type %s" % rec["case_id"])
    if not isinstance(rec["row_key"], str) or rec["row_key"] == "":
        fail("row_key %s" % rec["case_id"])
    if not isinstance(rec["ordinal"], int):
        fail("ordinal type %s" % rec["case_id"])
    if not isinstance(rec["repository"], str) or rec["repository"] == "":
        fail("repository %s" % rec["case_id"])
    if not isinstance(rec["mechanism_key"], str) or rec["mechanism_key"] == "":
        fail("mechanism_key %s" % rec["case_id"])
    if not isinstance(rec["contribution_class"], str) or rec["contribution_class"] == "":
        fail("contribution_class %s" % rec["case_id"])
    if not isinstance(rec["aliases"], list) or any(not isinstance(a, str) for a in rec["aliases"]):
        fail("aliases %s" % rec["case_id"])
    if rec["counting_unit"] != "first-party GHSA identity":
        fail("counting_unit %s" % rec["case_id"])
    if rec["cve_aliases_are_not_counting_units"] is not True:
        fail("cve aliases %s" % rec["case_id"])
    if rec["disposition"] not in ("KEEP_BASELINE", "DOWNGRADE"):
        fail("disposition %s" % rec["case_id"])
    if rec["fp211_released_publication_admitted"] is not True:
        fail("admitted flag %s" % rec["case_id"])
    if rec["causal_admission"] is not False:
        fail("causal_admission %s" % rec["case_id"])
    if rec["publication_status"] != "HOLD":
        fail("publication_status %s" % rec["case_id"])
    if rec["more_than_200_claim"] is not False:
        fail("more_than_200 %s" % rec["case_id"])
    if rec["worker_outcome"] != "authority audit proposal pending leader replay":
        fail("worker_outcome %s" % rec["case_id"])
    if not isinstance(rec["reason"], str) or rec["reason"] == "":
        fail("reason %s" % rec["case_id"])
    if not isinstance(rec["conflicts"], list):
        fail("conflicts type %s" % rec["case_id"])
    if not isinstance(rec["later_confirmation"], list):
        fail("later_confirmation type %s" % rec["case_id"])
    src = rec["authoritative_source"]
    if not isinstance(src, dict):
        fail("authoritative_source type %s" % rec["case_id"])
    for key in SRC_REQUIRED:
        if key not in src:
            fail("source missing %s on %s" % (key, rec["case_id"]))
        if not isinstance(src[key], str):
            fail("source type %s.%s" % (rec["case_id"], key))
    if src["case_id"] != rec["case_id"]:
        fail("source case_id mismatch %s" % rec["case_id"])
    if src["row_key"] != rec["row_key"]:
        fail("source row_key mismatch %s" % rec["case_id"])
    rows.append(rec)

ids = [r["case_id"] for r in rows]
if len(ids) != 48:
    fail("row count")
if len(set(ids)) != 48:
    fail("duplicate case_id " + str(sorted({i for i in ids if ids.count(i) > 1})))
missing = sorted(set(admitted) - set(ids))
extra = sorted(set(ids) - set(admitted))
if missing:
    fail("missing " + ",".join(missing))
if extra:
    fail("extra " + ",".join(extra))
if [r["ordinal"] for r in rows] != sorted(r["ordinal"] for r in rows):
    fail("ordinal sort")

keep_n = sum(1 for r in rows if r["disposition"] == "KEEP_BASELINE")
down_n = sum(1 for r in rows if r["disposition"] == "DOWNGRADE")
if keep_n + down_n != 48:
    fail("keep+downgrade")
if keep_n != 47 or down_n != 1:
    fail("counts keep=%d down=%d" % (keep_n, down_n))
down_rows = [r for r in rows if r["disposition"] == "DOWNGRADE"]
if down_rows[0]["case_id"] != "GHSA-4FXP-2M36-QV64":
    fail("downgrade id")
src = down_rows[0]["authoritative_source"]
if src["role"] != "final_review":
    fail("downgrade role")
if src["terminal_status"] != "COMPLETE_BOUNDED_REVIEW":
    fail("downgrade status")
if src["frozen_at_utc"] != "2026-08-13T22:03:11Z":
    fail("downgrade freeze")
if src["verdict"] != "NARROW":
    fail("downgrade verdict")
if src["failed_gate"] != "identity_gate":
    fail("downgrade gate")
if src["sha256"] != "e275437954890dca07855b5fcfa545f8f1a366fb85a7ee9f067da5b710b2b3da":
    fail("downgrade cases hash")
if down_rows[0]["replacement_identity"] != "":
    fail("replacement inferred")

for r in rows:
    if r["disposition"] == "KEEP_BASELINE":
        if r["authoritative_source"]["role"] != "frozen_base":
            fail("keep role " + r["case_id"])
        if r["authoritative_source"]["verdict"] != "fp211_released_publication_admitted":
            fail("keep verdict " + r["case_id"])

print("conservation original=48 keep_baseline=47 downgrade=1")
PY

printf 'REPLAY_OK bounded original=48 keep_baseline=47 downgrade=1 DOWNGRADE=GHSA-4FXP-2M36-QV64 pending_leader_replay\n'
