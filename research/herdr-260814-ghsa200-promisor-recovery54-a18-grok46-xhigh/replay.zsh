#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-promisor-recovery54-a18-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
# Does not re-fetch. PASS is a proposal only; this packet admits none.
# 18=9 BLOCKED + 6 REJECT_CANDIDATE_EDGE + 3 NOT_SELECTED.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export PYTHONDONTWRITEBYTECODE=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-promisor-recovery54-a18-grok46-xhigh
PRE=$ROOT/autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh
C84=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84
LANE=/home/hanqing/.cache/ai-slop-ghsa200/herdr-260814-ghsa200-promisor-recovery54-a18-grok46-xhigh
TMPLANE=/tmp/ghsa200-promisor-recovery54-a18

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
require_file "$OWNED/result.json"
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

expect_hash "$OWNED/assignment.jsonl" 9b85bea40840a0060a2e846536e10a73b27d0d54531829034ab9470325c790ed
expect_hash "$OWNED/adjudications.jsonl" e37a950a0e8104aca94410c0b2a6196a171c1e7ee9750c9bd35fb49780595d1b
expect_hash "$OWNED/cases.jsonl" 73ca9e8d91c1efb5e0b35028e73d21aadf177f229c2bbedea280a1a63b96b087
expect_hash "$OWNED/selected.jsonl" e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/report.md" 28e03cc1f5a0bf643ff3a9c57d2a7148e2de1c1c8f816d10cf6ab065be85480f
expect_hash "$OWNED/summary.json" b1700d2b104767c4436ecafdcc0a89cbf82a21bb174be59280193c9df0fdbcc8
expect_hash "$OWNED/result.json" 25bfeecdc8f65ca238baa82309c2ad9b42b00ec5c8d48343e4e4830d77fe4a24
expect_hash "$OWNED/notes/README.md" 78b46ae2594e103a6f82e8deb5d3913a071e609e59b563bb2c330fbe0c23cabd
expect_hash "$OWNED/notes/source-tier.txt" 38ed55be9ba9c37db77304354ac434adb64eda57cd0dccdecc206ac720cae53f
expect_hash "$OWNED/work/conservation.json" 88481e0330aec52069e3d6d04c7dbc1c9fdebff84f0c3fef6a39df527df70bc5
expect_hash "$OWNED/work/uniqueness.json" 3b32928242f30fb8f18fe375563c94588ca8e452e469b8d46d445e64e4699c74
expect_hash "$OWNED/work/freeze.json" 6b05dfac12581e39a2459058eea1bccfecc1ff098dd19657846c087ea5ad9061
expect_hash "$OWNED/work/html_facts.json" ca8932398504bac127d9e12c498369e32d714f6e28eb79e039a02402d2653901
expect_hash "$OWNED/work/blame.json" a8a1ccfa28543f9607d18990524bc5649d88a1d28d241351b75375beaf673faf
expect_hash "$OWNED/work/pinned-facts.json" 54012984998da298c312ada133356b319229e0d1445e9bfdc75792e0a0ad050f
expect_hash "$OWNED/work/recovery.jsonl" 8c9614b069f037155ac0028a4cab20b3288282e417be7659b8775800d5410ecf
expect_hash "$OWNED/work/recovery-summary.json" 3c8086a5f28986ffdb92511207961377b96e744d6e2985e5f8aa926927265371

python3 -B - "$OWNED" "$PRE/work/original-hits.jsonl" "$C84/ledger.jsonl" << 'ENDPY'
import json, re, sys
from pathlib import Path
owned = Path(sys.argv[1])
hits_path = Path(sys.argv[2])
ledger_path = Path(sys.argv[3])
order = [
"GHSA-97V6-998M-FP4G","GHSA-9MRH-V2V3-XPFM","GHSA-C276-FJ82-F2PQ","GHSA-MJ7R-X3H3-7RMR",
"GHSA-XHQ9-58FW-859P","GHSA-RPR9-RXV7-X643","GHSA-VGJ4-345G-JCF8","GHSA-GQXX-248X-G29F",
"GHSA-Q3QX-CP62-F6M7","GHSA-RMW5-F87R-W988","GHSA-9PHM-9P8F-HW5M","GHSA-W7JW-789Q-3M8P",
"GHSA-4JC5-G844-4X33","GHSA-G4PX-6QHM-HQJM","GHSA-Q537-8FR5-CW35","GHSA-227R-JM2G-7CP4",
"GHSA-2497-GP99-2M74","GHSA-29FC-P6C4-24CG",
]
src=[]
for line in hits_path.read_text().splitlines():
    o=json.loads(line)
    if o.get("skip")=="no_resolvable_first_party_fix":
        src.append(o["ghsa_id"])
if len(src)!=54:
    raise SystemExit("source 54 mismatch %s" % len(src))
if src[:18]!=order:
    raise SystemExit("first18 order mismatch")
asg=[]
for line in (owned/"assignment.jsonl").read_text().splitlines():
    asg.append(json.loads(line))
if [x["ghsa_id"] for x in asg]!=order:
    raise SystemExit("assignment order mismatch")
if [x["assigned_order"] for x in asg]!=list(range(1,19)):
    raise SystemExit("assignment numbering mismatch")
if any(x["ghsa_id"] not in src for x in asg):
    raise SystemExit("assigned id not in 54-row source")
adjs=[]
for line in (owned/"adjudications.jsonl").read_text().splitlines():
    adjs.append(json.loads(line))
cases=[]
for line in (owned/"cases.jsonl").read_text().splitlines():
    cases.append(json.loads(line))
if [x["case_id"] for x in adjs]!=order:
    raise SystemExit("adjudication order mismatch")
if [x["case_id"] for x in cases]!=order:
    raise SystemExit("cases order mismatch")
if len(adjs)!=18 or len(cases)!=18:
    raise SystemExit("count")
verdicts=[x["worker_verdict"] for x in adjs]
if verdicts.count("BLOCKED")!=9 or verdicts.count("REJECT_CANDIDATE_EDGE")!=6 or verdicts.count("NOT_SELECTED")!=3:
    raise SystemExit("outcome conservation %s" % verdicts)
if any(x.get("worker_verdict")=="PASS" for x in adjs):
    raise SystemExit("unexpected PASS")
gates=["identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
for x in adjs:
    if x["worker_verdict"]=="PASS":
        for g in gates:
            if x.get(g)!="PASS":
                raise SystemExit("PASS missing gate %s %s" % (g, x["case_id"]))
    if x.get("ghsa_wide_not_ai"):
        raise SystemExit("ghsa-wide NOT-AI forbidden")
    if x.get("whole_case_causal_reject"):
        raise SystemExit("whole-case causal reject forbidden")
    if x.get("pass_proposal"):
        raise SystemExit("pass_proposal forbidden")
    if x["worker_verdict"]=="REJECT_CANDIDATE_EDGE":
        if x.get("reject_class")!="REJECT_CANDIDATE_EDGE":
            raise SystemExit("reject class")
        if x.get("ai_hunk_gate")!="FAIL":
            raise SystemExit("reject ai hunk")
    if x["worker_verdict"]=="BLOCKED":
        if x.get("reason") not in ("missing_fix_or_ref","repo_advisory_unavailable","fix_object_unresolved"):
            raise SystemExit("blocked reason %s" % x.get("reason"))
    if x["worker_verdict"]=="NOT_SELECTED":
        if x.get("reason") not in ("tag_commit_mechanism_mismatch","no_deleted_source_hunk","no_hard_prefilter_hit"):
            raise SystemExit("not_selected reason %s" % x.get("reason"))
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
if sm.get("equation")!="18=9+6+3":
    raise SystemExit("summary equation")
if sm.get("BLOCKED")!=9 or sm.get("REJECT_CANDIDATE_EDGE")!=6 or sm.get("NOT_SELECTED")!=3:
    raise SystemExit("summary counts")
res=json.loads((owned/"result.json").read_text())
if res.get("packet_delta")!=0 or res.get("current_leader_accepted_count")!=84:
    raise SystemExit("result delta/count")
if res.get("canonical_count_updated") is not False:
    raise SystemExit("canonical updated")
secret=re.compile(r"(?i)(ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----)")
han=re.compile(r"[\u3400-\u9fff]")
for p in owned.rglob("*"):
    if not p.is_file():
        continue
    if p.name.endswith((".pyc",".pyo")) or p.name=="__pycache__":
        raise SystemExit("bytecode")
    data=p.read_bytes()
    if b"\x00" in data:
        continue
    text=data.decode("utf-8", "replace")
    if secret.search(text):
        raise SystemExit("secret-like token in %s" % p)
    if p.suffix in {".md",".json",".jsonl",".zsh",".txt"} and p.name!="selected.jsonl":
        for i,line in enumerate(text.splitlines(),1):
            if line.endswith(" ") or line.endswith("\t"):
                raise SystemExit("trailing whitespace %s:%s" % (p, i))
        if han.search(text) or re.search(r"[\u0400-\u04FF]", text):
            raise SystemExit("non-English script %s" % p)
print("replay_ok assigned=18 outcomes=9+6+3 pass=0 canonical84_overlap=0 leftover=36")
ENDPY

forbid_found=$(/usr/bin/find "$OWNED" \( -name '__pycache__' -o -name '*.pyc' -o -name '*.pyo' \) -print)
if [[ -n $forbid_found ]]; then
  printf 'bytecode present:\n%s\n' "$forbid_found" >&2
  exit 1
fi
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"
while IFS= read -r rel; do
  [[ -z $rel ]] && continue
  /usr/bin/git diff --no-index --check "$OWNED/$rel" "$OWNED/$rel"
done < <(/usr/bin/awk '{print $2}' "$OWNED/sha256.txt" | /usr/bin/sed 's|^\./||')

printf 'REPLAY_OK reviewed=18 PASS_proposal=0 REJECT_CANDIDATE_EDGE=6 NOT_SELECTED=3 BLOCKED=9 UNKNOWN=0 selected=0 leftover=36 packet_delta=0 current_leader_accepted_count=84\n'
