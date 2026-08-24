#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-cf3-adjacent20-grok46-low.
# English only. No credentials. No clone/commit/push. Shared caches read-only.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-cf3-adjacent20-grok46-low
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical87/ledger.jsonl
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical87/summary.json
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
  errf=$(mktemp /tmp/cf3-adj-giterr.XXXXXX)
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
require_file "$CONTRACT"
require_file "$LEDGER"
require_file "$SUMMARY"
require_file "$FOUND"
require_file "$NEG"
require_dir "$ADV"

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" b6dc7e781017e60a94725696b5a08b229a5cb026ffd098e6306e9a8941f9fdbe
expect_hash "$SUMMARY" 17487d40720f4c20475df7df270e5bb1139726887c42bc50d999f0f7e713a722
expect_hash "$FOUND" 0b9cd2daae23e33faf3f2ceed46bba4802e2f9b0ef9c739f0bce7e6f4a16f687
expect_hash "$NEG" c6bbdf661daf06de0d8de611167a842128c1fa3bfd01c19243dc771a41f0c9e0

adv_head=$(gitx "$ADV" rev-parse HEAD)
expect_eq "$adv_head" a42c436870111aa3f221257c9d56126a93173ccc advisory_db_head

n_assign=$(/usr/bin/wc -l < "$OWNED/assignment.jsonl" | /usr/bin/tr -d ' ')
n_cases=$(/usr/bin/wc -l < "$OWNED/cases.jsonl" | /usr/bin/tr -d ' ')
expect_eq "$n_assign" 20 assignment_rows
expect_eq "$n_cases" 20 cases_rows

python3 - "$OWNED" "$SUMMARY" "$FOUND" "$NEG" "$ADV" <<'PY'
import json, re, subprocess, sys
from pathlib import Path
owned, summary_p, found, neg, adv = map(Path, sys.argv[1:])
assigns = [json.loads(l) for l in owned.joinpath("assignment.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in owned.joinpath("cases.jsonl").read_text().splitlines() if l.strip()]
assert len(assigns) == 20 and len(cases) == 20
ids = [a["case_id"] for a in assigns]
assert ids == [c["case_id"] for c in cases]
assert len(set(ids)) == 20
assert all(a["frozen"] and a["shared_sha_is_routing_only"] for a in assigns)
assert all(c["countable_proposal"] is False and c["not_ai"] is False for c in cases)
assert sum(1 for c in cases if c["verdict"] == "PASS_PROPOSAL") == 0
assert sum(1 for c in cases if c["verdict"] == "NARROW") == 19
assert sum(1 for c in cases if c["verdict"] == "REJECT") == 1
assert cases[14]["case_id"] == "GHSA-3X3X-H76W-HP98" and cases[14]["verdict"] == "REJECT"

summary = json.loads(summary_p.read_text())
counted = {str(x).upper() for x in summary["strict_released_case_ids"]}
assert len(counted) == 87, len(counted)
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
if isinstance(neg_obj, dict):
    for k, v in neg_obj.items():
        if isinstance(v, list):
            for x in v:
                if isinstance(x, str) and x.upper().startswith("GHSA-"):
                    neg_ids.add(x.upper())
                elif isinstance(x, dict):
                    cid = x.get("case_id") or x.get("ghsa_id")
                    if cid:
                        neg_ids.add(str(cid).upper())
        if isinstance(k, str) and k.upper().startswith("GHSA-"):
            neg_ids.add(k.upper())
elif isinstance(neg_obj, list):
    for x in neg_obj:
        cid = x.get("case_id") if isinstance(x, dict) else x
        if cid:
            neg_ids.add(str(cid).upper())
for cid in ids:
    assert cid.upper() not in neg_ids, cid

cf3_root = owned.parent
cf3_ids = set()
for p in cf3_root.glob("herdr-260814-cf3-*/assignment.jsonl"):
    if p.parent.name == owned.name:
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

print("PYTHON_OK counted=87 found=165 frozen=20 PASS=0 NARROW=19 REJECT=1")
PY

# Bounded git facts
OC=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw
FI=/home/hanqing/.cache/ghsa200-worker-clones/qf5v-redteam-260814/fission__fission
GP=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gitpython-developers__GitPython

sub=$(gitx "$OC" log -1 --format='%s' 466a1e1cdb1e04efd4bf08ad92a0b05b55848b51)
case $sub in
  *clawdock*) ;;
  *) printf '3X3X ancestor subject not clawdock: %s\n' "$sub" >&2; exit 1 ;;
esac

if ! gitx "$FI" merge-base --is-ancestor 80e7ba55228e1ef426f51353e25d2682ec61de34 8fa799417c77ce8a0189d9858bfe11ece29b84a6; then
  printf 'expected 80e7ba55 ancestor of 8fa79941\n' >&2
  exit 1
fi

gpt=$(gitx "$GP" log -1 --format='%b' 4299c990e1ca21896f9485277caf7bb0ae5b404c)
case $gpt in
  *GPT*|*Co-authored-by*|*Co-Authored-By*) ;;
  *) printf 'HMQ2 closer missing AI trailer\n' >&2; exit 1 ;;
esac

printf 'REPLAY_OK reviewed=20 PASS_proposal=0 NARROW=19 REJECT=1 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=87\n'
