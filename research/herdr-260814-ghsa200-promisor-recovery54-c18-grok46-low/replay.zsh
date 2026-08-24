#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-promisor-recovery54-c18-grok46-low.
# English only. Do not print credentials. Do not clone, commit, or push.
# Does not re-fetch. PASS is a proposal only; this packet admits none.
# 18=17 REJECT_CANDIDATE_EDGE + 1 UNKNOWN.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export PYTHONDONTWRITEBYTECODE=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-promisor-recovery54-c18-grok46-low
PRE=$ROOT/autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh
C84=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84
LANE=/home/hanqing/.cache/ai-slop-ghsa200/herdr-260814-ghsa200-promisor-recovery54-c18-grok46-low
TMPLANE=/tmp/promisor-recovery54-c18-grok46-low

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

if [[ -e $LANE ]]; then
  printf 'cache lane still present: %s\n' "$LANE" >&2
  exit 1
fi
if [[ -e $TMPLANE ]]; then
  printf 'tmp lane still present: %s\n' "$TMPLANE" >&2
  exit 1
fi

require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/adjudications.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/summary.json"
require_file "$OWNED/replay.zsh"
require_file "$OWNED/sha256.txt"
require_file "$OWNED/work/conservation.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/freeze.json"
require_file "$PRE/work/original-hits.jsonl"
require_file "$PRE/work/candidate-pool.jsonl"
require_file "$C84/ledger.jsonl"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$C84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$C84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$PRE/work/original-hits.jsonl" \
  bb84ee18b73481805a32074496561e04c08dfed95d0379058c8c2045d5c63a5a
expect_hash "$PRE/work/candidate-pool.jsonl" \
  7fc0b4741c45d1b3e375b14b51b603045dc6d092e180818c5ae7f861fc783b50

expect_hash "$OWNED/assignment.jsonl" 4ad9919f1763016c729640d0dfca05ee4ee3d4d320c10f4c0a855d126f23c520
expect_hash "$OWNED/adjudications.jsonl" 8601e1903cf94c832715b944e67c14960013b1585c9ca68f62603d98b921b008
expect_hash "$OWNED/cases.jsonl" 0bc36e372757182344a3b85909b31b92b700d13fdd3871859bcb0f09d3082863
expect_hash "$OWNED/selected.jsonl" e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/report.md" 2db10d1fee905e08864ae5eaa6fbc112fa62bcf129b4eb2c11fbab54d0414a3f
expect_hash "$OWNED/summary.json" 870602660100b4ba78e29d8ae09733ef4ecb381f6b0fde17c6554367d30eb311
expect_hash "$OWNED/notes/README.md" b2e6dba3dcc8049044101b7083a781262cadd866087d25ac0a41469cc289dac6
expect_hash "$OWNED/work/conservation.json" 994fcb9b8b43d6aa5f12e2dd3e075d36d139e596e37de8ee405a6fab9bf831d8
expect_hash "$OWNED/work/uniqueness.json" 07b49007fa977ec99204226c7c6b49dbdfc8526aa6fc01f6f7950a242cb35eac
expect_hash "$OWNED/work/freeze.json" cd6f67d22d27424a1f2665cb04a0a4bf9412fc875d1a6484beab0dd57570f8e0
expect_hash "$OWNED/work/html_facts.json" ac2d25bf7d6d7ad272a2ca588aef474dd2c9bf5c048a6fe2be364fcee0afc3aa
expect_hash "$OWNED/work/blame.json" abbb402a18b441308ad6a6b51ca8310dc3548105a48883a32855d636be25c9d1

python3 -B - "$OWNED" "$PRE/work/original-hits.jsonl" "$C84/ledger.jsonl" << 'PY'
import json, re, sys
from pathlib import Path
owned = Path(sys.argv[1])
hits_path = Path(sys.argv[2])
ledger_path = Path(sys.argv[3])
order = [
"GHSA-G3QJ-J598-CXMQ","GHSA-H4PH-CRVJ-9H92","GHSA-HHG7-C65M-H7FF","GHSA-HQRP-M84V-2M2F",
"GHSA-J8PH-6FXJ-G533","GHSA-M28W-2PQF-7QGJ","GHSA-M4W9-GCH5-C2G4","GHSA-MQPW-46FH-299H",
"GHSA-MWXV-35WR-4VVJ","GHSA-MX8G-39Q3-5C79","GHSA-P4XX-M758-3HPX","GHSA-P8GP-2W28-MHWG",
"GHSA-PH86-P8F6-F9R2","GHSA-Q62H-354G-5R85","GHSA-QPMX-3RFJ-7RHV","GHSA-RXRH-4J9H-XGG9",
"GHSA-V856-2RF8-9F28","GHSA-WCHH-9X6H-7F6P",
]
src=set()
for line in hits_path.read_text().splitlines():
    o=json.loads(line)
    if o.get("skip")=="no_resolvable_first_party_fix":
        src.add(o["ghsa_id"])
if len(src)!=54:
    raise SystemExit(f"source 54 mismatch {len(src)}")
asg=[]
for line in (owned/"assignment.jsonl").read_text().splitlines():
    asg.append(json.loads(line))
if [x["ghsa_id"] for x in asg]!=order:
    raise SystemExit("assignment order mismatch")
if [x["order"] for x in asg]!=list(range(1,19)):
    raise SystemExit("assignment numbering mismatch")
if any(x["ghsa_id"] not in src for x in asg):
    raise SystemExit("assigned id not in 54-row source")
adjs=[]
for line in (owned/"adjudications.jsonl").read_text().splitlines():
    adjs.append(json.loads(line))
if [x["case_id"] for x in adjs]!=order:
    raise SystemExit("adjudication order mismatch")
if len(adjs)!=18:
    raise SystemExit("adjudication count")
verdicts=[x["worker_verdict"] for x in adjs]
if verdicts.count("REJECT_CANDIDATE_EDGE")!=17 or verdicts.count("UNKNOWN")!=1:
    raise SystemExit(f"outcome conservation {verdicts}")
if any(x.get("worker_verdict")=="PASS" for x in adjs):
    raise SystemExit("unexpected PASS")
gates=["identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
for x in adjs:
    if x["worker_verdict"]=="PASS":
        for g in gates:
            if x.get(g)!="PASS":
                raise SystemExit(f"PASS missing gate {g} {x['case_id']}")
    if x.get("ghsa_wide_not_ai"):
        raise SystemExit("ghsa-wide NOT-AI forbidden")
    if x.get("pass_proposal"):
        raise SystemExit("pass_proposal forbidden")
c84=set()
for line in ledger_path.read_text().splitlines():
    if not line.strip():
        continue
    o=json.loads(line)
    gid=o.get("ghsa_id") or o.get("id") or o.get("case_id")
    if gid:
        c84.add(str(gid).upper())
if set(order) & c84:
    raise SystemExit("canonical84 overlap")
sel=(owned/"selected.jsonl").read_text()
if sel!="":
    raise SystemExit("selected must be empty")
sm=json.loads((owned/"summary.json").read_text())
if sm.get("PASS")!=0 or sm.get("pass_proposals")!=0 or sm.get("packet_delta")!=0:
    raise SystemExit("summary PASS/delta")
if sm.get("equation")!="18=17+1":
    raise SystemExit("summary equation")
secret=re.compile(r"(?i)(ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----)")
for p in owned.rglob("*"):
    if not p.is_file():
        continue
    if p.name.endswith((".pyc",)):
        raise SystemExit("bytecode")
    data=p.read_bytes()
    if b"\x00" in data:
        continue
    text=data.decode("utf-8", "replace")
    if secret.search(text):
        raise SystemExit(f"secret-like token in {p}")
    if p.suffix in {".md",".json",".jsonl",".zsh",".txt"} and p.name!="selected.jsonl":
        for i,line in enumerate(text.splitlines(),1):
            if line.endswith(" ") or line.endswith("\t"):
                raise SystemExit(f"trailing whitespace {p}:{i}")
        if re.search(r"[\u0400-\u04FF\u4e00-\u9fff]", text):
            raise SystemExit(f"non-English script {p}")
print("replay_ok assigned=18 outcomes=17+1 pass=0 canonical84_overlap=0")
PY

printf 'replay complete\n'
