#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-incomplete-rem-unseen20-grok46-high.
# English only. No credentials. Shared caches read-only.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_PAGER=cat
export PAGER=cat
export GIT_ASKPASS=echo
export GCM_INTERACTIVE=never

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-incomplete-rem-unseen20-grok46-high
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/summary.json
ADV_REV=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
N8N=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/n8n-io__n8n
KV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/kubevirt__kubevirt
git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

fail() { print -r -- "REPLAY_FAIL $*" >&2; exit 1 }

expect_eq() {
  if [[ $1 != "$2" ]]; then
    print -r -- "mismatch $3 expected=$2 got=$1" >&2
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
  errf=$(mktemp /tmp/incomplete-rem-unseen20-giterr.XXXXXX)
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

require_file() { [[ -f $1 ]] || fail "missing $1" }
require_dir() { [[ -d $1 ]] || fail "missing $1" }

require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/result.json"
require_file "$OWNED/report.md"
require_file "$OWNED/replay.zsh"
require_file "$CONTRACT"
require_file "$LEDGER"
require_file "$SUMMARY"
require_dir "$ADV_REV/advisories/github-reviewed"
require_dir "$N8N"
require_dir "$KV"

n_owned=$(/usr/bin/find "$OWNED" -maxdepth 1 -type f | /usr/bin/wc -l | /usr/bin/tr -d ' ')
expect_eq "$n_owned" 5 owned_file_count
for extra in work notes pages clones snapshot; do
  [[ ! -e $OWNED/$extra ]] || fail "retained $extra"
done

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  python3 - "$OWNED/$f" <<'PY' || fail "ascii $f"
import sys
b=open(sys.argv[1],"rb").read()
if b"\x00" in b: raise SystemExit(1)
b.decode("ascii")
PY
done

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 70b7658fadf41f18c72734a2006601961a2180681bf81353373bccab95ff659e
expect_hash "$SUMMARY" ab47f927a20f374a9b0e3253a1a5a0778e355dda9414189927022325d81ad86f

adv_rev_head=$(gitx "$ADV_REV" rev-parse HEAD)
expect_eq "$adv_rev_head" f2c6ab3202aeafb36fbea6e76d892532acfca1a6 reviewed_head

n_assign=$(/usr/bin/wc -l < "$OWNED/assignment.jsonl" | /usr/bin/tr -d ' ')
n_cases=$(/usr/bin/wc -l < "$OWNED/cases.jsonl" | /usr/bin/tr -d ' ')
expect_eq "$n_assign" 3 assignment_rows
expect_eq "$n_cases" 3 cases_rows

python3 - "$OWNED" "$SUMMARY" "$ROOT/autoresearch" "$ADV_REV" <<'PY' || fail "python conservation"
import hashlib, json, re, sys
from pathlib import Path
owned, summary_p, ar, adv_rev = map(Path, sys.argv[1:])
assigns=[json.loads(l) for l in owned.joinpath("assignment.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l) for l in owned.joinpath("cases.jsonl").read_text().splitlines() if l.strip()]
res=json.loads(owned.joinpath("result.json").read_text())
assert len(assigns)==3 and len(cases)==3
ids=[a["case_id"] for a in assigns]
assert ids==[c["case_id"] for c in cases]==res["conservation"]["reviewed_case_ids"]
assert ids==["GHSA-5XRP-6693-JJX9","GHSA-7JCP-V9W4-WJMG","GHSA-MPMF-3W4R-QFPF"]
assert len(set(ids))==3
assert all(a["routing_only"] is True for a in assigns)
assert all(a["canonical91_strict"] is False for a in assigns)
assert all(a["inherited_verdict_forbidden"] is True for a in assigns)
assert res["counts"]["PASS"]==0 and res["counts"]["PASS_PROPOSAL"]==0
assert res["counts"]["REJECT"]==3 and res["conservation"]["equation"]=="3=3+0"
assert res["conservation"]["holds"] is True
assert res["conservation"]["did_not_pad"] is True
assert res["canonical_strict_count_untouched"]==91
assert res["packet_delta"]==0
assert res["worker_pass_is_proposal_only"] is True
assert res["PASS_PROPOSAL"]==[] and res["pass_proposals"]==[]
assert all(c["verdict"]=="REJECT" and c["proposed_pass"] is False for c in cases)
assert all(c["seven_gate_pass"] is False for c in cases)
GATES=["identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
for c in cases:
    g=c["gates"]
    assert list(g)==GATES or set(g)==set(GATES)
    assert g["identity_gate"]=="PASS"
    assert g["ai_hunk_gate"]=="FAIL"
    assert g["topology_gate"]=="NARROW"
    assert g["but_for_gate"]=="FAIL"
    assert g["fix_reversal_gate"]=="FAIL"
    assert g["release_gate"]=="UNKNOWN"
    assert g["uniqueness_gate"]=="PASS"
    assert not all(g[k]=="PASS" for k in GATES)
    assert c["file_overlap_with_closer"]==[]

hashes=res["artifact_hashes"]
for name in ("assignment.jsonl","cases.jsonl","report.md","replay.zsh"):
    got=hashlib.sha256(owned.joinpath(name).read_bytes()).hexdigest()
    assert got==hashes[name], name

GHSA_RE=re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
IDENTITY_KEYS={
    "case_id","ghsa_id","reviewed_case_ids","assigned_ids","inspected_ids",
    "exact_selected_ids","unreviewed_case_ids","PASS_PROPOSAL_ids","pass_proposals",
    "pass_proposals_for_redteam","proposed_pass_ids","strict_released_case_ids",
    "selected_ids","assigned_case_ids",
}
OWNED_NAME="herdr-260814-incomplete-rem-unseen20-grok46-high"

def as_id(s):
    if not isinstance(s,str):
        return None
    n=s.strip().upper()
    return n if GHSA_RE.match(n) else None

def walk(obj, acc):
    if isinstance(obj, dict):
        for k,v in obj.items():
            if k in IDENTITY_KEYS or k=="per_case":
                if isinstance(v,str):
                    n=as_id(v)
                    if n: acc.add(n)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item,str):
                            n=as_id(item)
                            if n: acc.add(n)
                        elif isinstance(item, dict):
                            walk(item, acc)
                elif isinstance(v, dict):
                    for kk in v.keys():
                        n=as_id(str(kk))
                        if n: acc.add(n)
                    walk(v, acc)
            else:
                walk(v, acc)
    elif isinstance(obj, list):
        for item in obj:
            walk(item, acc)

summary=json.loads(summary_p.read_text())
counted={str(x).upper() for x in summary["strict_released_case_ids"]}
assert len(counted)==91
excluded=set(counted)
for d in sorted(ar.iterdir(), key=lambda p: p.name):
    if not d.is_dir() or d.name==OWNED_NAME:
        continue
    if not (
        d.name.startswith("herdr-260813-")
        or d.name.startswith("herdr-260814-")
        or d.name.startswith("orchestrator-260813-")
        or d.name.startswith("orchestrator-260814-")
    ):
        continue
    for p in sorted(d.iterdir()):
        if p.name not in {"assignment.jsonl","cases.jsonl","result.json","selected.jsonl","assigned.jsonl"}:
            continue
        try:
            text=p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if p.suffix==".jsonl":
            for line in text.splitlines():
                if not line.strip():
                    continue
                try:
                    row=json.loads(line)
                except json.JSONDecodeError:
                    continue
                walk(row, excluded)
                cid=as_id(row.get("case_id") or row.get("ghsa_id") or "")
                if cid:
                    excluded.add(cid)
        else:
            try:
                obj=json.loads(text)
            except json.JSONDecodeError:
                continue
            walk(obj, excluded)
            if isinstance(obj, dict):
                pc=obj.get("per_case") or {}
                if isinstance(pc, dict):
                    for k in pc:
                        n=as_id(str(k))
                        if n:
                            excluded.add(n)

for gid in ids:
    assert gid not in counted, "canonical overlap "+gid
    assert gid not in excluded, "excluded overlap "+gid

reviewed_ids={p.stem.upper() for p in (adv_rev/"advisories/github-reviewed").rglob("GHSA-*.json")}
assert len(reviewed_ids)==34389
for a,c in zip(assigns, cases):
    gid=a["case_id"]
    assert gid in reviewed_ids
    adv=adv_rev/c["advisory_path"]
    assert adv.is_file(), c["advisory_path"]
    got=hashlib.sha256(adv.read_bytes()).hexdigest()
    assert got==c["advisory_sha256"], gid
    obj=json.loads(adv.read_text())
    assert obj.get("database_specific",{}).get("github_reviewed") is True
    assert not obj.get("withdrawn")
print("conservation_ok")
PY

overlap() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import subprocess, sys
repo, a, b, extra = sys.argv[1:5]
cmd=["/usr/bin/git","--no-optional-locks","-C",repo,"diff-tree","--no-commit-id","--name-only","-r"]
if extra=="-m":
    cmd.append("-m")
fa=set(subprocess.check_output(cmd+[a], text=True).split())
fb=set(subprocess.check_output(cmd+[b] if extra!="-m" else cmd+[b], text=True).split())
# rebuild b with extra correctly
cmd_b=["/usr/bin/git","--no-optional-locks","-C",repo,"diff-tree","--no-commit-id","--name-only","-r"]
if extra=="-m":
    cmd_b.append("-m")
fb=set(subprocess.check_output(cmd_b+[b], text=True).split())
if fa & fb:
    raise SystemExit("overlap "+sys.argv[2][:12]+" "+sys.argv[3][:12])
print("overlap_empty")
PY
}

gitx "$N8N" cat-file -t d4ef191be0b39b65efa68559a3b8d5dad2e102b2 | grep -qx commit || fail "n8n candidate"
gitx "$N8N" merge-base --is-ancestor d4ef191be0b39b65efa68559a3b8d5dad2e102b2 25c4b9605b420a98d0185a4f01115122a5134d8f || fail "n8n ancestor"
n8n_np=$(gitx "$N8N" cat-file -p d4ef191be0b39b65efa68559a3b8d5dad2e102b2 | /usr/bin/awk '/^parent /{n++} END{print n+0}')
expect_eq "$n8n_np" 1 n8n_candidate_parents
gitx "$N8N" log -1 --format=%s d4ef191be0b39b65efa68559a3b8d5dad2e102b2 | grep -Fqx 'fix(Chat Trigger Node): Prevent XSS vulnerabilities and improve parameter validation (#18148)' || fail "n8n candidate subject"
gitx "$N8N" log -1 --format=%b d4ef191be0b39b65efa68559a3b8d5dad2e102b2 | grep -Fq 'Co-authored-by: Claude <noreply@anthropic.com>' || fail "n8n claude trailer"
gitx "$N8N" log -1 --format=%s 25c4b9605b420a98d0185a4f01115122a5134d8f | grep -Fqx 'Merge commit from fork' || fail "n8n closer subject"
overlap "$N8N" d4ef191be0b39b65efa68559a3b8d5dad2e102b2 25c4b9605b420a98d0185a4f01115122a5134d8f none
n8n_tags=$(gitx "$N8N" tag | /usr/bin/wc -l | /usr/bin/tr -d ' ')
expect_eq "$n8n_tags" 0 n8n_tags

gitx "$KV" cat-file -t f7bd23b848c5d86e459e823848c9ec65a6f7b0f6 | grep -qx commit || fail "kv candidate"
gitx "$KV" merge-base --is-ancestor f7bd23b848c5d86e459e823848c9ec65a6f7b0f6 011eef8129e2c21e0ea496f283ee1676009bc757 || fail "7jcp ancestor"
gitx "$KV" merge-base --is-ancestor f7bd23b848c5d86e459e823848c9ec65a6f7b0f6 6ea563fa94d8ca803f8dd9394cefd8cae36bb0ee || fail "mpmf ancestor"
kv_np=$(gitx "$KV" cat-file -p f7bd23b848c5d86e459e823848c9ec65a6f7b0f6 | /usr/bin/awk '/^parent /{n++} END{print n+0}')
expect_eq "$kv_np" 1 kv_candidate_parents
gitx "$KV" log -1 --format=%s f7bd23b848c5d86e459e823848c9ec65a6f7b0f6 | grep -Fqx 'preserve contentType anno when creating restore pvc' || fail "kv candidate subject"
gitx "$KV" log -1 --format=%b f7bd23b848c5d86e459e823848c9ec65a6f7b0f6 | grep -Fq 'Co-authored-by: Claude <noreply@anthropic.com>' || fail "kv claude trailer"
fix7_np=$(gitx "$KV" cat-file -p 011eef8129e2c21e0ea496f283ee1676009bc757 | /usr/bin/awk '/^parent /{n++} END{print n+0}')
expect_eq "$fix7_np" 2 7jcp_closer_parents
gitx "$KV" log -1 --format=%s 011eef8129e2c21e0ea496f283ee1676009bc757 | grep -Fqx 'Merge pull request #17916 from jean-edouard/safesockets' || fail "7jcp closer subject"
overlap "$KV" f7bd23b848c5d86e459e823848c9ec65a6f7b0f6 011eef8129e2c21e0ea496f283ee1676009bc757 -m
fixm_np=$(gitx "$KV" cat-file -p 6ea563fa94d8ca803f8dd9394cefd8cae36bb0ee | /usr/bin/awk '/^parent /{n++} END{print n+0}')
expect_eq "$fixm_np" 1 mpmf_closer_parents
gitx "$KV" log -1 --format=%s 6ea563fa94d8ca803f8dd9394cefd8cae36bb0ee | grep -Fqx 'Fix symlink traversal in VMExport dir handler' || fail "mpmf closer subject"
overlap "$KV" f7bd23b848c5d86e459e823848c9ec65a6f7b0f6 6ea563fa94d8ca803f8dd9394cefd8cae36bb0ee none
kv_tags=$(gitx "$KV" tag | /usr/bin/wc -l | /usr/bin/tr -d ' ')
expect_eq "$kv_tags" 0 kv_tags

echo "REPLAY_OK reviewed=3 PASS_proposal=0 REJECT=3 packet_delta=0 canonical_strict=91"
