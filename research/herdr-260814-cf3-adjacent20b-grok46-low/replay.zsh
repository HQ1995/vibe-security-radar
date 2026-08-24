#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-cf3-adjacent20b-grok46-low.
# English only. No credentials. No clone/commit/push. Shared caches read-only.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-cf3-adjacent20b-grok46-low
ADJ20=$ROOT/autoresearch/herdr-260814-cf3-adjacent20-grok46-low
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json
FOUND=$ROOT/autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl
NEG=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85/negative_controls.json
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/advisory-database

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

expect_eq() {
  if [[ $1 != "$2" ]]; then
    printf 'mismatch %s expected=%s got=%s\n' "$3" "$2" "$1" >&2
    exit 1
  fi
}

expect_hash() {
  local got
  got=$(/usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}')
  expect_eq "$got" "$2" "$1"
}

gitx() {
  local repo=$1
  shift
  local errf
  errf=$(mktemp /tmp/cf3-adj20b-giterr.XXXXXX)
  set +e
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
  if [[ -s $errf ]]; then
    /usr/bin/grep -vE 'unable to normalize alternate object path|lazy fetching disabled' "$errf" >&2 || true
  fi
  rm -f "$errf"
  return $rc
}

require_file() {
  if [[ ! -f $1 ]]; then
    printf 'missing %s\n' "$1" >&2
    exit 1
  fi
}

require_dir() {
  if [[ ! -d $1 ]]; then
    printf 'missing %s\n' "$1" >&2
    exit 1
  fi
}

require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/result.json"
require_file "$OWNED/report.md"
require_file "$ADJ20/assignment.jsonl"
require_file "$CONTRACT"
require_file "$LEDGER"
require_file "$SUMMARY"
require_file "$FOUND"
require_file "$NEG"
require_dir "$ADV"

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
expect_hash "$SUMMARY" 81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921
expect_hash "$FOUND" 0b9cd2daae23e33faf3f2ceed46bba4802e2f9b0ef9c739f0bce7e6f4a16f687
expect_hash "$NEG" c6bbdf661daf06de0d8de611167a842128c1fa3bfd01c19243dc771a41f0c9e0

adv_head=$(gitx "$ADV" rev-parse HEAD)
expect_eq "$adv_head" a42c436870111aa3f221257c9d56126a93173ccc advisory_db_head

n_assign=$(/usr/bin/wc -l < "$OWNED/assignment.jsonl" | /usr/bin/tr -d ' ')
n_cases=$(/usr/bin/wc -l < "$OWNED/cases.jsonl" | /usr/bin/tr -d ' ')
expect_eq "$n_assign" 20 assignment_rows
expect_eq "$n_cases" 20 cases_rows

python3 - "$OWNED" "$SUMMARY" "$FOUND" "$NEG" "$ADV" "$ADJ20" <<'PY'
import json, re, subprocess, sys
from pathlib import Path
owned, summary_p, found, neg, adv, adj20p = map(Path, sys.argv[1:])
assigns = [json.loads(l) for l in owned.joinpath("assignment.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in owned.joinpath("cases.jsonl").read_text().splitlines() if l.strip()]
assert len(assigns) == 20 and len(cases) == 20
ids = [a["case_id"] for a in assigns]
assert ids == [c["case_id"] for c in cases]
assert len(set(ids)) == 20
assert [a["rank"] for a in assigns] == list(range(21, 41))
assert all(a["frozen"] and a["shared_sha_is_routing_only"] and a["disjoint_from_adjacent20"] for a in assigns)
assert all(c["countable_proposal"] is False and c["not_ai"] is False for c in cases)
assert sum(1 for c in cases if c["verdict"] == "PASS_PROPOSAL") == 0
assert sum(1 for c in cases if c["verdict"] == "NARROW") == 19
assert sum(1 for c in cases if c["verdict"] == "REJECT") == 1
assert cases[0]["case_id"] == "GHSA-FP25-P6MJ-QQG6" and cases[0]["verdict"] == "REJECT"

summary = json.loads(summary_p.read_text())
counted = {str(x).upper() for x in summary["strict_released_case_ids"]}
assert len(counted) == 88, len(counted)
for cid in ids:
    assert cid.upper() not in counted, cid
stale = {str(x).upper() for x in summary.get("excluded", {}) if str(x).upper().startswith("GHSA-")}
for cid in ids:
    assert cid.upper() not in stale, cid

found_ids = set()
for line in found.read_text().splitlines():
    rec = json.loads(line)
    cid = rec.get("case_id") or rec.get("ghsa_id")
    if cid:
        found_ids.add(str(cid).upper())
assert len(found_ids) == 165, len(found_ids)
for cid in ids:
    assert cid.upper() not in found_ids, cid

neg_obj = json.loads(neg.read_text())
neg_ids = set()
for x in neg_obj.get("controls", []):
    cid = x.get("case_id")
    if cid:
        neg_ids.add(str(cid).upper())
for cid in ids:
    assert cid.upper() not in neg_ids, cid

adj20 = set()
for line in adj20p.joinpath("assignment.jsonl").read_text().splitlines():
    rec = json.loads(line)
    adj20.add(rec["case_id"].upper())
assert len(adj20) == 20
for cid in ids:
    assert cid.upper() not in adj20, cid

cf3_ids = set()
for p in owned.parent.glob("herdr-260814-cf3-*/assignment.jsonl"):
    if p.parent.name in (owned.name, adj20p.name):
        continue
    for line in p.read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        cid = rec.get("case_id")
        if cid:
            cf3_ids.add(str(cid).upper())
for cid in ids:
    assert cid.upper() not in cf3_ids, cid

ai_re = re.compile(
    r"Co-Authored-By:.*(Claude|Cursor|Copilot|Codex)|codex@openai\.com|noreply@anthropic\.com|cursoragent|\[AI\]|GPT 5\.|Generated-by Cursor|Aether AI Agent|Copilot",
    re.I,
)
for a in assigns:
    path = adv / a["advisory_path"]
    assert path.is_file(), a["advisory_path"]
    clone = Path(a["clone"])
    assert clone.is_dir(), a["clone"]
    markers = a["ai_marker_shas"] or a["ai_ancestry_shas"]
    assert markers, a["case_id"]
    hit = False
    for sha in markers[:3]:
        msg = subprocess.check_output(
            ["/usr/bin/git", "--no-optional-locks", "-C", str(clone), "log", "-1", "--format=%an %ae%n%s%n%b", sha],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if ai_re.search(msg):
            hit = True
            break
    assert hit, a["case_id"]

print("PYTHON_OK counted=88 found=165 frozen=20 PASS=0 NARROW=19 REJECT=1 disjoint_adj20=1")
PY

LOC=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/locutusjs__locutus
FI=/home/hanqing/.cache/ghsa200-worker-clones/qf5v-redteam-260814/fission__fission
sub=$(gitx "$LOC" log -1 --format='%s' 977a1fb169441e35996a1d2465b512322de500ad)
case $sub in
  *TypeScript*) ;;
  *) printf 'FP25 subject not TypeScript migration: %s\n' "$sub" >&2; exit 1 ;;
esac

sha=$(gitx "$FI" rev-parse e484df8460bb4e8026e24210120602aa7f181f64)
expect_eq "$sha" e484df8460bb4e8026e24210120602aa7f181f64 gx55_shared_sha

printf 'REPLAY_OK reviewed=20 PASS_proposal=0 NARROW=19 REJECT=1 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=88\n'
