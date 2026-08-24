#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat
export PYTHONPATH=/home/hanqing/agents/ai-slop/cve-analyzer/src

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-queue-glances-js-grok46-medium
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical93/ledger.jsonl
SRC_A=$ROOT/autoresearch/herdr-260814-nextqueue-v2-grok46-low/assignment.jsonl
SRC_C=$ROOT/autoresearch/herdr-260814-nextqueue-v2-grok46-low/cases.jsonl
ADV=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
G=/home/hanqing/.cache/cve-analyzer/repos/nicolargo_glances
K=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/microsoft__kiota-typescript
M=/home/hanqing/.cache/cve-analyzer/repos/mermaid-js_mermaid

fail() { print -r -- "REPLAY_FAIL $*" >&2; exit 1; }
require_file() { [[ -f $1 ]] || fail "missing $1"; }
require_dir() { [[ -d $1 ]] || fail "missing $1"; }
require_absent() { [[ ! -e $1 ]] || fail "must be absent: $1"; }

require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/result.json"
require_file "$OWNED/report.md"
require_file "$OWNED/replay.zsh"
require_file "$CONTRACT"
require_file "$LEDGER"
require_file "$SRC_A"
require_file "$SRC_C"
require_dir "$ADV/advisories/github-reviewed"
require_dir "$G/.git"
require_dir "$K/.git"
require_dir "$M/.git"
require_absent "$OWNED/work"
require_absent "$OWNED/notes"
require_absent "$OWNED/pages"
require_absent "$OWNED/clones"

n_owned=$(/usr/bin/ls -1 "$OWNED" | /usr/bin/wc -l | /usr/bin/tr -d ' ')
[[ $n_owned == 5 ]] || fail "owned_file_count $n_owned"

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  python3 - "$OWNED/$f" <<'PY' || fail "ascii $f"
import sys
b=open(sys.argv[1],"rb").read()
if b"\x00" in b:
    raise SystemExit(1)
b.decode("ascii")
PY
done

expect_hash() {
  local got
  got=$(/usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}')
  [[ $got == "$2" ]] || fail "hash $1 got=$got expected=$2"
}

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 6d652a089329eb23108083fb73ca1a8a3aa00583415b235381f3b37da389dc3d
expect_hash "$SRC_A" 5382496f680de8c811d75ca0d3dd6dbdc1b47af0893689e37d36d9dc4a7b93b3
expect_hash "$SRC_C" 5edd11a19f8bfb7e598290ee5ce22b72e0e3d51c4186c6e8d656f552a38d4ccf

ADV_HEAD=$(/usr/bin/git --no-optional-locks -C "$ADV" rev-parse HEAD)
[[ $ADV_HEAD == f2c6ab3202aeafb36fbea6e76d892532acfca1a6 ]] || fail "adv_head $ADV_HEAD"

python3 - "$OWNED" "$LEDGER" "$SRC_A" "$ADV" "$G" "$K" "$M" <<'PY' || fail "python_checks"
import json, subprocess, sys
from pathlib import Path
from cve_analyzer.source_matcher import matches_for_commit, MATCHER_CONTRACT
from cve_analyzer.models import CommitInfo

owned, ledger, src_a, adv, G, K, M = map(Path, sys.argv[1:])
expect=["GHSA-7P93-6934-F4Q7","GHSA-396Q-4VC8-28X9","GHSA-8GWM-58G9-J8PW","GHSA-VCV2-Q258-WRG7","GHSA-VX5F-957P-QPVM"]
assign=[json.loads(l) for l in (owned/"assignment.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l) for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
res=json.loads((owned/"result.json").read_text())
src=[json.loads(l) for l in Path(src_a).read_text().splitlines() if l.strip()]
src_by={r["case_id"]: r for r in src}
assert [a["case_id"] for a in assign]==expect
assert [c["case_id"] for c in cases]==expect
assert res["conservation"]["reviewed_case_ids"]==expect
assert res["conservation"]["equation"]=="5=5+0"
assert res["conservation"]["holds"] is True
assert res["counts"]["assigned"]==5 and res["counts"]["reviewed"]==5 and res["counts"]["unreviewed"]==0
assert res["counts"]["PASS"]==0 and res["counts"]["REJECT"]==5
assert res["pass_proposals"]==[] and res["packet_delta"]==0
assert res["canonical_strict_count_untouched"]==93
assert res["did_not_pad"] is True
assert MATCHER_CONTRACT==res["matcher_contract"]
text=(owned/"report.md").read_text()
assert "0 PASS" in text and "5=5+0" in text
canon=set()
for line in Path(ledger).read_text().splitlines():
    if not line.strip():
        continue
    o=json.loads(line)
    cid=str(o.get("case_id") or o.get("ghsa") or "").upper()
    if cid.startswith("GHSA-"):
        canon.add(cid)
# ledger rows may use different key
if not canon:
    s=json.loads((Path(ledger).parent/"summary.json").read_text())
    canon=set(str(x).upper() for x in s["strict_released_case_ids"])
assert not set(expect)&canon
assert all(c["verdict"]=="REJECT" for c in cases)
assert all(c.get("proposed_pass") is False for c in cases)
gates=["identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
for c in cases:
    for g in gates:
        assert c[g] in ("PASS","FAIL","NARROW","UNKNOWN","BLOCKED")
    assert not all(c[g]=="PASS" for g in gates)
    assert c["identity_gate"]=="PASS"
    assert c["ai_hunk_gate"]!="PASS"
    assert c["but_for_gate"]!="PASS"
    src_row=src_by[c["case_id"]]
    assert c["candidate_set"]==src_row["pre_fix_ai_candidates"] and False or True
    assert [x["sha"] for x in src_row["pre_fix_ai_candidates"]]==c["candidate_set"]

def git(repo,*a):
    p=subprocess.run(["git","-C",str(repo),*a],capture_output=True,text=True)
    if p.returncode!=0:
        raise SystemExit(f"git {' '.join(a)} rc={p.returncode} {p.stderr[:200]}")
    return p.stdout.strip()

def nparents(repo,sha):
    return len(git(repo,"rev-list","--parents","-n","1",sha).split())-1

def is_anc(repo,a,b):
    return subprocess.run(["git","-C",str(repo),"merge-base","--is-ancestor",a,b],capture_output=True).returncode==0

def commitinfo(repo,sha):
    fmt="%H%x1f%an%x1f%ae%x1f%aI%x1f%cn%x1f%ce%x1f%s%x1f%B"
    raw=git(repo,"log","-1",f"--format={fmt}",sha)
    h,an,ae,ai,cn,ce,subj,body=raw.split("\x1f")
    return CommitInfo(sha=h.strip(),author_name=an,author_email=ae,committer_name=cn,committer_email=ce,message=subj+"\n"+body,authored_date=ai)

def files(repo,sha):
    return [x for x in git(repo,"diff-tree","--no-commit-id","-r","--name-only",sha).splitlines() if x]

# GHSA-7P93
assert nparents(G,"dcb39c3f12b2a1eec708c58d22d7a1d62bdf5fa1")==2
assert nparents(G,"b90a8f2a169f57631118d58beaa12fd322855884")==1
assert not matches_for_commit(commitinfo(G,"b90a8f2a169f57631118d58beaa12fd322855884"))
assert not matches_for_commit(commitinfo(G,"a4d75fedaa374473ebdb1d5dff8e8772352e160e"))
grep=git(G,"grep","-n","Access-Control-Allow-Origin","358d76a225fc21a9f95d2c4d7e46fafe64a644c6","--","glances/server.py")
assert "Access-Control-Allow-Origin" in grep
for sha in ["36e2397fd16499f1c47c04395a34104a351b0423","7b200f00fceb6302cc219d4a1983433e135acb49","a7892c1e292a3fa990284e92607e3e89878af84a"]:
    assert "glances/server.py" not in files(G,sha)
    assert is_anc(G,sha,"dcb39c3f12b2a1eec708c58d22d7a1d62bdf5fa1")
assert is_anc(G,"dcb39c3f12b2a1eec708c58d22d7a1d62bdf5fa1","v4.5.3")
assert not is_anc(G,"dcb39c3f12b2a1eec708c58d22d7a1d62bdf5fa1","v4.5.1")

# GHSA-396Q
assert nparents(K,"09f8bd9b34d68bf412a9b78f6ca7e7961ef14974")==2
assert nparents(K,"4dab0e233e1196817b253006e69498db073b6296")==1
assert nparents(K,"74886cc4c3ddc93a326d3bd091bc80757ab8b532")==1
assert not matches_for_commit(commitinfo(K,"74886cc4c3ddc93a326d3bd091bc80757ab8b532"))
assert not matches_for_commit(commitinfo(K,"4dab0e233e1196817b253006e69498db073b6296"))
assert files(K,"b5ace55100b4cde88875d22589d1dd5ee1e775e8")==["packages/http/fetch/src/httpClient.ts"]
assert "redirectHandlerOptions.ts" not in files(K,"31dab8ce1117e12157dc28e32c49383201fc207a")
diff=git(K,"show","--format=","4dab0e233e1196817b253006e69498db073b6296","--","packages/http/fetch/src/middlewares/options/redirectHandlerOptions.ts")
assert "-				delete headers.Authorization;" in diff
assert "+					if (lower === \"authorization\" || lower === \"cookie\" || lower === \"proxy-authorization\") {" in diff

# GHSA-8GWM
assert nparents(M,"734bde38777c9190a5a72e96421c83424442d4e4")==1
assert not matches_for_commit(commitinfo(M,"734bde38777c9190a5a72e96421c83424442d4e4"))
assert not matches_for_commit(commitinfo(M,"c61a431e2d663ead577cb24fa3c9a6bd846d9061"))
assert files(M,"1c269e0432b9aeac1d3dc24004631d1486e1ec81")==["packages/mermaid-zenuml/README.md"]
assert files(M,"2e5d955e77520b63a3b5ae2a960389d64de6a6bc")==["packages/examples/src/examples/kanban.ts"]
assert is_anc(M,"734bde38777c9190a5a72e96421c83424442d4e4","mermaid@11.1.0")
assert is_anc(M,"2aa83302795183ea5c65caec3da1edd6cb4791fc","mermaid@11.10.0")
assert not is_anc(M,"2aa83302795183ea5c65caec3da1edd6cb4791fc","mermaid@11.9.0")
assert "html(service.iconText)" in git(M,"grep","iconText","734bde38777c9190a5a72e96421c83424442d4e4","--","packages/mermaid/src/diagrams/architecture/svgDraw.ts")

# GHSA-VCV2
assert nparents(G,"6f4ec53d967478e69917078e6f73f448001bf107")==2
assert nparents(G,"5680a5da4afdf762fd44ced1f8160fb6d5c5dd16")==1
assert not matches_for_commit(commitinfo(G,"5680a5da4afdf762fd44ced1f8160fb6d5c5dd16"))
assert "glances/actions.py" not in files(G,"7b200f00fceb6302cc219d4a1983433e135acb49")
assert "glances/actions.py" not in files(G,"a7892c1e292a3fa990284e92607e3e89878af84a")
assert is_anc(G,"7b200f00fceb6302cc219d4a1983433e135acb49","6f4ec53d967478e69917078e6f73f448001bf107")
assert not is_anc(G,"36e2397fd16499f1c47c04395a34104a351b0423","6f4ec53d967478e69917078e6f73f448001bf107")
assert is_anc(G,"6f4ec53d967478e69917078e6f73f448001bf107","v4.5.2")
assert not is_anc(G,"6f4ec53d967478e69917078e6f73f448001bf107","v4.5.1")
adiff=git(G,"diff","61d38eec521703e41e4933d18d5a5ef6f854abd5","6f4ec53d967478e69917078e6f73f448001bf107","--","glances/actions.py")
assert "_sanitize_mustache_dict" in adiff

# GHSA-VX5F
assert nparents(G,"61d38eec521703e41e4933d18d5a5ef6f854abd5")==2
assert nparents(G,"2abe8d8733e354f280bb3616150c7338b4940ff1")==1
assert not matches_for_commit(commitinfo(G,"2abe8d8733e354f280bb3616150c7338b4940ff1"))
assert not matches_for_commit(commitinfo(G,"28ae053e4bdb3c5948d7b1d5d3fbe3091d7a0a67"))
assert "glances/servers_list.py" not in files(G,"7b200f00fceb6302cc219d4a1983433e135acb49")
assert "glances/servers_list.py" not in files(G,"a7892c1e292a3fa990284e92607e3e89878af84a")
assert is_anc(G,"28ae053e4bdb3c5948d7b1d5d3fbe3091d7a0a67","v4.5.1")
assert is_anc(G,"61d38eec521703e41e4933d18d5a5ef6f854abd5","v4.5.2")
assert not is_anc(G,"61d38eec521703e41e4933d18d5a5ef6f854abd5","v4.5.1")
sdiff=git(G,"diff","879ef8688ffa1630839549751d3c7ef9961d361e","61d38eec521703e41e4933d18d5a5ef6f854abd5","--","glances/servers_list.py")
assert "_get_connect_host" in sdiff

# advisory pins
pins={
"GHSA-7p93-6934-f4q7":"18a4cc63258fa4eaced566286ce4b422473c4ad1a20c7edf4038c630a6946690",
"GHSA-396q-4vc8-28x9":"09f9846cde6ab1249d77cec80f114db04ac8ab04a7f19d4096a7366e38e22424",
"GHSA-8gwm-58g9-j8pw":"f4998f6c08f484cdf4d8f0eced541616b20fa415cd2d78c8d4ffe452065b638c",
"GHSA-vcv2-q258-wrg7":"24d871b43d517e5db7515eff108b8a1e4036a989253f71ccf7ac41bce6846a48",
"GHSA-vx5f-957p-qpvm":"3aad0f79375041784ccafe554abf4daf593abd855d0e890df1ba2622bf2fc621",
}
import hashlib
for name,h in pins.items():
    matches=list((adv/"advisories/github-reviewed").rglob(name+".json"))
    assert len(matches)==1, name
    got=hashlib.sha256(matches[0].read_bytes()).hexdigest()
    assert got==h, (name,got,h)
print("json_ok")
PY

print -r -- "REPLAY_OK assigned=5 reviewed=5 unreviewed=0 PASS=0 REJECT=5 equation=5=5+0 canonical93=93"
