#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 GIT_NO_LAZY_FETCH=1 GIT_PAGER=cat
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import json, os, re, subprocess, sys
from collections import Counter

for k in list(os.environ):
    lk=k.lower()
    if any(x in lk for x in ("token","secret","password","credential","api_key","auth","gh_token","github_token")):
        os.environ.pop(k, None)

ROOT=Path("/home/hanqing/agents/ai-slop")
OWN=ROOT/"autoresearch/herdr-260815-pr-body-ai100-grok46-high"
SRC=ROOT/"autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh"
res=json.loads((OWN/"result.json").read_text())
pins=res["current_input_hashes"]

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

assert h(ROOT/"autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md")==pins["CONTRACT.md"]
assert h(ROOT/"autoresearch/orchestrator-260814-ghsa200-canonical94/ledger.jsonl")==pins["canonical94_ledger.jsonl"]
assert h(ROOT/"autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json")==pins["canonical94_summary.json"]
assert h(SRC/"work/candidate-pool.jsonl")==pins["candidate_pool.jsonl"]
assert h(SRC/"work/original-hits.jsonl")==pins["original_hits.jsonl"]
names=sorted(p.name for p in OWN.iterdir() if p.is_file())
assert names==["assignment.jsonl","cases.jsonl","replay.zsh","report.md","result.json"], names
assert not (OWN/"work").exists()
for p in OWN.iterdir():
    if p.is_file():
        assert all(b<128 for b in p.read_bytes()), p.name

a=[json.loads(l) for l in (OWN/"assignment.jsonl").read_text().splitlines() if l.strip()]
c=[json.loads(l) for l in (OWN/"cases.jsonl").read_text().splitlines() if l.strip()]
want=res["inspected_ids"]
assert [x["case_id"] for x in a]==[x["case_id"] for x in c]==want
assert len(want)==res["counts"]["assigned"]==len(set(want))
assert len(want)<=100
assert all(x.get("never_pass") and x.get("routing_only") for x in a+c)
assert all(x.get("proposed_pass") is False for x in c)
assert "PASS" not in {x.get("verdict") for x in c}
assert all(x.get("verdict") in {"REJECT_ROUTING","ROUTE","UNKNOWN"} for x in c)
assert res["counts"]["PASS"]==0
assert res["never_pass"] is True
assert res["canonical94_strict_count"]==94
assert res["conservation"]["holds"] is True
assert res["conservation"]["pool_equation"]=="5980=17+5348+615"
assert res["claim_boundary"]["packet_delta"]==0

sys.path.insert(0, str(ROOT/"cve-analyzer/src"))
from cve_analyzer.source_matcher import MATCHER_CONTRACT
assert MATCHER_CONTRACT==res["matcher_contract"]

ADV=Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database")
GIT_ENV={"PATH":"/usr/local/bin:/usr/bin:/bin","GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0","GIT_NO_LAZY_FETCH":"1","GIT_PAGER":"cat","LC_ALL":"C","GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null","GIT_CONFIG_SYSTEM":"/dev/null"}

def git(repo,*args,timeout=15):
    return subprocess.run(["/usr/bin/git","--no-optional-locks","-c","gc.auto=0","-c","maintenance.auto=false","-C",str(repo),*args],capture_output=True,text=True,env=GIT_ENV,timeout=timeout,check=False)

assert git(ADV,"rev-parse","HEAD").stdout.strip()==res["advisory_database"]["head"]
assert git(ADV,"rev-parse","HEAD:advisories/github-reviewed").stdout.strip()==res["advisory_database"]["github_reviewed_tree"]

GHSA_RE=re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")

def norm_ghsa(v):
    if not isinstance(v,str): return None
    s=v.strip().upper()
    return s if GHSA_RE.match(s) else None

pool=[json.loads(l) for l in (SRC/"work/candidate-pool.jsonl").read_text().splitlines() if l.strip()]
assert len(pool)==5980
ids=[str(r["ghsa_id"]).upper() for r in pool]
assert len(set(ids))==5980
canon=set(str(x).upper() for x in json.loads((ROOT/"autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json").read_text())["strict_released_case_ids"])
assert len(canon)==94
overlap_c94=sorted(set(ids)&canon)
assert len(overlap_c94)==17
remaining_ids=res["remaining_ids"]
assert len(remaining_ids)==615==len(set(remaining_ids))
remain_hash=sha256(json.dumps(remaining_ids,ensure_ascii=True,sort_keys=True,separators=(",",":")).encode("ascii")).hexdigest()
assert remain_hash==res["remaining_ids_sha256"]
assert set(remaining_ids).isdisjoint(canon)
assert set(remaining_ids)<=set(ids)
assert set(want)<=set(remaining_ids)
terminal_overlap_n=5980-17-615
assert terminal_overlap_n==5348
assert f"5980={len(overlap_c94)}+{terminal_overlap_n}+{len(remaining_ids)}"==res["conservation"]["pool_equation"]
sel_hash=sha256(json.dumps(want,ensure_ascii=True,sort_keys=True,separators=(",",":")).encode("ascii")).hexdigest()
assert sel_hash==res["selected_ids_sha256"]
assert [x["case_id"] for x in c if x["verdict"]=="ROUTE"]==res["route_ids"]
assert all(x.get("verdict")!="PASS" for x in c)
assert all(x.get("reject_reason")=="closer_object_missing" for x in c)
text=(OWN/"report.md").read_text()
assert "does not call a PASS" in text
assert "5980=17+5348+615" in text
assert "ROUTE 0" in text
assert h(OWN/"assignment.jsonl")==res["artifact_hashes"]["assignment.jsonl"]
assert h(OWN/"cases.jsonl")==res["artifact_hashes"]["cases.jsonl"]
assert h(OWN/"report.md")==res["artifact_hashes"]["report.md"]
assert h(OWN/"replay.zsh")==res["artifact_hashes"]["replay.zsh"]
print("REPLAY_OK inspected=%d ROUTE=%d PASS=0 canonical94=94 equation=5980=17+5348+615" % (len(want), res["counts"]["ROUTE"]))
PY
