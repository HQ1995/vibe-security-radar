#!/usr/bin/env zsh
set -euo pipefail
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-cf2-gj-new-surface-grok46-medium}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
CLONES=${CLONES:-/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones}
GJ=$ROOT/autoresearch/herdr-260813-ghsa200-commitfirst-gj-grok46-medium
fail=0

ascii_check() {
  local f=$1
  if LC_ALL=C grep -n '[^[:print:][:space:]]' "$f" >/dev/null; then
    echo "NON_ASCII $f"
    fail=1
  fi
}

hash_check() {
  local f=$1 want=$2
  local got
  got=$(sha256sum "$f" | awk '{print $1}')
  if [[ $got != $want ]]; then
    echo "HASH_MISMATCH $f got=$got want=$want"
    fail=1
  else
    echo "HASH_OK $f"
  fi
}

echo "== ASCII =="
for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  ascii_check "$OWNED/$f"
done

echo "== conservation =="
n_assign=$(grep -c . "$OWNED/assignment.jsonl" || true)
n_cases=$(grep -c . "$OWNED/cases.jsonl" || true)
n_pass=$(python3 -c 'import json,sys; print(sum(1 for l in open(sys.argv[1]) if json.loads(l).get("worker_verdict")=="PASS"))' "$OWNED/cases.jsonl")
n_rej=$(python3 -c 'import json,sys; print(sum(1 for l in open(sys.argv[1]) if json.loads(l).get("worker_verdict")=="REJECT"))' "$OWNED/cases.jsonl")
echo "assign=$n_assign cases=$n_cases pass=$n_pass reject=$n_rej"
if [[ $n_assign -ne 40 || $n_cases -ne 40 || $n_pass -ne 0 || $n_rej -ne 40 ]]; then
  echo "CONSERVATION_FAIL expected 40=40 REJECT and 0 PASS"
  fail=1
else
  echo "CONSERVATION_OK 40=40+0"
fi

echo "== uniqueness vs canonical85/foundation/source30 =="
python3 - << PY
import json, sys
from pathlib import Path
root = Path("$ROOT")
owned = Path("$OWNED")
gj = Path("$GJ")
canon = json.loads((root/"autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json").read_text())
excl=set(canon["strict_released_case_ids"])
for k in canon.get("excluded",{}):
    if str(k).startswith("GHSA-"):
        excl.add(k)
found=set()
with (root/"autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl").open() as f:
    for line in f:
        found.add(json.loads(line)["case_id"])
src=set()
with (gj/"cases.jsonl").open() as f:
    for line in f:
        src.add(json.loads(line)["case_id"])
ids=[]
with (owned/"assignment.jsonl").open() as f:
    for line in f:
        ids.append(json.loads(line)["case_id"])
bad=[]
if len(ids)!=len(set(ids)):
    bad.append("duplicate_assignment")
for i in ids:
    if i in excl: bad.append("canonical85:"+i)
    if i in found: bad.append("foundation:"+i)
    if i in src: bad.append("source30:"+i)
if bad:
    print("UNIQUENESS_FAIL", bad)
    sys.exit(1)
print("UNIQUENESS_OK", len(ids))
PY

echo "== local git object existence / ancestry (where clone exists) =="
python3 - << PY
import json, subprocess
from pathlib import Path
owned = Path("$OWNED")
clones = Path("$CLONES")
n_ok=n_miss=n_anc=n_not=0
with owned.joinpath("assignment.jsonl").open() as f:
    for line in f:
        a=json.loads(line)
        o,n=a["repository"].split("/",1)
        repo=clones/f"{o}__{n}"
        intro=a.get("routing_intro_sha")
        fix=a.get("routing_fix_sha")
        if not repo.exists():
            print("CLONE_ABSENT", a["case_id"])
            n_miss += 1
            continue
        for label,sha in (("intro",intro),("fix",fix)):
            if not sha:
                continue
            r=subprocess.run(["git","-C",str(repo),"cat-file","-t",sha], capture_output=True, text=True)
            if r.returncode!=0 or r.stdout.strip()!="commit":
                print("OBJECT_MISSING", a["case_id"], label, sha)
                n_miss += 1
            else:
                n_ok += 1
        if intro and fix:
            r=subprocess.run(["git","-C",str(repo),"merge-base","--is-ancestor",intro,fix])
            if r.returncode==0:
                n_anc += 1
            else:
                n_not += 1
print(f"OBJECTS_OK={n_ok} OBJECTS_OR_CLONE_MISS={n_miss} INTRO_ANCESTOR_OF_FIX={n_anc} NOT_ANCESTOR={n_not}")
print("NOTE ancestry of a routing intro is not causal proof")
PY

echo "== result.json pass list empty / terminal =="
python3 - << PY
import json, sys
from pathlib import Path
r=json.loads(Path("$OWNED/result.json").read_text())
assert r.get("terminal") is True
assert r.get("pass_proposal_ids")==[]
assert r["counts"]["PASS_PROPOSAL"]==0
assert r["conservation"]["assigned"]==40
print("RESULT_FLAGS_OK")
PY

echo "== cases seven-gate exact values, no PASS with non-PASS gate =="
python3 - << PY
import json, sys
from pathlib import Path
ok=("PASS","FAIL","UNKNOWN","NARROW","BLOCKED")
n=0
with Path("$OWNED/cases.jsonl").open() as f:
    for line in f:
        rec=json.loads(line)
        n+=1
        g=rec["gates"]
        for k in ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"):
            if g[k] not in ok:
                print("BAD_GATE", rec["case_id"], k, g[k]); sys.exit(1)
        if rec["worker_verdict"]=="PASS" and any(g[k]!="PASS" for k in g):
            print("PASS_WITH_NONPASS_GATE", rec["case_id"]); sys.exit(1)
print("GATES_OK", n)
PY

if [[ $fail -ne 0 ]]; then
  echo REPLAY_FAIL
  exit 1
fi
echo REPLAY_OK
