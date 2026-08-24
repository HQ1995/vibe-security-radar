#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 GIT_NO_LAZY_FETCH=1 GIT_PAGER=cat
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import json, os, re, subprocess, sys

for k in list(os.environ):
    lk=k.lower()
    if any(x in lk for x in ("token","secret","password","credential","api_key","auth","gh_token","github_token")):
        os.environ.pop(k, None)

ROOT=Path("/home/hanqing/agents/ai-slop")
OWN=ROOT/"autoresearch/herdr-260815-no-same-repo-fix-r161-220-grok46-xhigh"
SRC=ROOT/"autoresearch/herdr-260814-nextqueue-v2-grok46-low"
PREV=ROOT/"autoresearch/herdr-260814-no-same-repo-fix-recovery-grok46-high"
res=json.loads((OWN/"result.json").read_text())
pins=res["current_input_hashes"]

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

assert h(ROOT/"autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md")==pins["CONTRACT.md"]
assert h(ROOT/"autoresearch/orchestrator-260814-ghsa200-canonical94/ledger.jsonl")==pins["canonical94_ledger.jsonl"]
assert h(ROOT/"autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json")==pins["canonical94_summary.json"]
assert h(SRC/"result.json")==pins["source_result.json"]
assert h(SRC/"report.md")==pins["source_report.md"]
assert h(SRC/"replay.zsh")==pins["source_replay.zsh"]
assert h(PREV/"result.json")==pins["recovery_result.json"]
assert h(PREV/"report.md")==pins["recovery_report.md"]
assert h(PREV/"replay.zsh")==pins["recovery_replay.zsh"]
names=sorted(p.name for p in OWN.iterdir() if p.is_file())
assert names==["assignment.jsonl","cases.jsonl","replay.zsh","report.md","result.json"], names
assert not (OWN/"work").exists()
assert not (OWN/"pages").exists()
assert not (OWN/"clones").exists()
assert not (OWN/"snapshot").exists()
cred_re=re.compile(r"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]{0,20}PRIVATE KEY)")
for p in OWN.iterdir():
    if p.is_file():
        data=p.read_bytes()
        assert all(b<128 for b in data), p.name
        text=data.decode("ascii")
        assert not cred_re.search(text), p.name

a=[json.loads(l) for l in (OWN/"assignment.jsonl").read_text().splitlines() if l.strip()]
c=[json.loads(l) for l in (OWN/"cases.jsonl").read_text().splitlines() if l.strip()]
want=res["inspected_ids"]
assert [x["case_id"] for x in a]==[x["case_id"] for x in c]==want
assert len(want)==60==len(set(want))
assert [x["rank"] for x in a]==list(range(161,221))
assert all(x.get("never_pass") and x.get("routing_only") for x in a+c)
assert all(x.get("verdict")=="REJECT_ROUTING" for x in c)
assert all(x.get("proposed_pass") is False for x in c)
assert "PASS" not in {x.get("verdict") for x in c}
assert "ROUTE" not in {x.get("verdict") for x in c}
assert res["counts"]["PASS"]==0 and res["counts"]["ROUTE"]==0
assert res["pass_proposals"]==[] and res["selected_ids"]==[]
assert res["canonical94_strict_count"]==94
assert res["bucket_reconstruction"]["reconstructed_count"]==10631
assert res["conservation"]["equation"]=="60=60+0" and res["conservation"]["holds"]
assert res["conservation"]["bucket_equation"]=="10631=220+10411"
assert res["conservation"]["unreviewed_remainder_of_bucket"]==10411
src=json.loads((SRC/"result.json").read_text())
assert src["buckets"]["no_same_repo_fix"]==10631
canon=set(str(x).upper() for x in json.loads((ROOT/"autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json").read_text())["strict_released_case_ids"])
assert len(canon)==94
assert not set(want)&canon
prior=res["prior_slice_ids"]
assert len(prior)==160==len(set(prior))
assert not set(want)&set(prior)
text=(OWN/"report.md").read_text()
assert "does not call a PASS" in text and "Fix-recovery" in text
assert "60=60+0" in text and "ROUTE 0" in text
assert "10631=220+10411" in text
assert "ranks 161-220" in text

for other in list((ROOT/"autoresearch").glob("herdr-260814-no-same-repo-fix-*"))+list((ROOT/"autoresearch").glob("herdr-260815-no-same-repo-fix-*")):
    if other.resolve()==OWN.resolve():
        continue
    oj=other/"result.json"
    oids=[]
    if oj.is_file():
        oids=json.loads(oj.read_text()).get("inspected_ids") or []
    else:
        aj=other/"assignment.jsonl"
        if aj.is_file():
            oids=[json.loads(l)["case_id"] for l in aj.read_text().splitlines() if l.strip()]
    assert not set(want)&set(oids), other.name

sys.path.insert(0, str(ROOT/"cve-analyzer/src"))
from cve_analyzer.source_matcher import MATCHER_CONTRACT
assert MATCHER_CONTRACT==res["matcher_contract"]

ADV=Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database")
REPOS=Path("/home/hanqing/.cache/cve-analyzer/repos")
WORKER_CLONES=Path("/home/hanqing/.cache/ghsa200-worker-clones")
SKIP_PARTS={"work","notes","pages","snapshot","clones","cache","tmp","node_modules"}
SKIP_DIR_NAMES={"herdr-260814-nextqueue-v2-grok46-low",".leader-quarantine-260814","herdr-260814-no-same-repo-fix-recovery-grok46-high",OWN.name}
GHSA_RE=re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
COMMIT_RE=re.compile(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})(?:[/?#]|$)")
REPO_ADV_RE=re.compile(r"https://github\.com/([^/]+)/([^/]+)/security/advisories/(GHSA-[0-9A-Za-z-]+)", re.I)
GITHUB_REPO_RE=re.compile(r"^https://github\.com/([^/]+)/([^/]+)/?$")
PR_RE=re.compile(r"https://github\.com/([^/]+)/([^/]+)/pull/([0-9]+)(?:[/?#]|$)", re.I)
COMPARE_RE=re.compile(r"https://github\.com/([^/]+)/([^/]+)/compare/", re.I)
PATCH_RE=re.compile(r"https://github\.com/([^/]+)/([^/]+)/commit/[0-9a-fA-F]+(?:\.patch|\.diff)(?:[/?#]|$)", re.I)
RELEASE_RE=re.compile(r"https://github\.com/([^/]+)/([^/]+)/releases/tag/([^/?#]+)", re.I)
VERDICTS={"PASS","NARROW","REJECT","UNKNOWN","BLOCKED","KEEP","FAIL","FALSE_POSITIVE","CONFIRM","ACCEPT","HOLD"}
GIT_ENV={"PATH":"/usr/local/bin:/usr/bin:/bin","GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0","GIT_NO_LAZY_FETCH":"1","GIT_PAGER":"cat","LC_ALL":"C","GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null","GIT_CONFIG_SYSTEM":"/dev/null"}

def git(repo,*args,timeout=15):
    p=subprocess.run(["/usr/bin/git","--no-optional-locks","-c","gc.auto=0","-c","maintenance.auto=false","-C",str(repo),*args],capture_output=True,text=True,env=GIT_ENV,timeout=timeout,check=False)
    keep=[]
    for line in (p.stderr or "").splitlines():
        if "unable to normalize alternate object path" in line: continue
        if "lazy fetching disabled" in line: continue
        if line.strip(): keep.append(line)
    if keep and p.returncode!=0:
        raise SystemExit("git fail "+str(args)+" "+"\n".join(keep))
    return p

assert git(ADV,"rev-parse","HEAD").stdout.strip()==res["advisory_database"]["head"]
assert git(ADV,"rev-parse","HEAD:advisories/github-reviewed").stdout.strip()==res["advisory_database"]["github_reviewed_tree"]

def norm_ghsa(v):
    if not isinstance(v,str): return None
    s=v.strip().upper()
    return s if GHSA_RE.match(s) else None

def packet_ok(path, cutoff, skip_mtime=False):
    if not skip_mtime and path.stat().st_mtime>=cutoff: return False
    rel=path.relative_to(ROOT/"autoresearch")
    top=rel.parts[0]
    if top in SKIP_DIR_NAMES: return False
    if any(p in SKIP_PARTS for p in rel.parts[:-1]): return False
    return top.startswith("herdr-260813") or top.startswith("herdr-260814") or top.startswith("orchestrator-260813") or top.startswith("orchestrator-260814")

def inventory_terminal(cutoff, skip_mtime=False):
    auto=ROOT/"autoresearch"
    verdict=set(); files=0; rows=0
    cases=adj=resf=0
    def consider(row):
        nonlocal rows
        rows+=1
        cid=norm_ghsa(row.get("case_id") or row.get("ghsa_id") or row.get("id"))
        if not cid: return
        v=row.get("verdict") or row.get("worker_verdict") or row.get("latest_verdict")
        if isinstance(v,str) and v.strip().upper() in VERDICTS:
            verdict.add(cid)
    for path in auto.glob("*/cases.jsonl"):
        if not packet_ok(path,cutoff,skip_mtime): continue
        files+=1; cases+=1
        for line in path.read_text(errors="replace").splitlines():
            if not line.strip(): continue
            try: row=json.loads(line)
            except json.JSONDecodeError: continue
            if isinstance(row,dict): consider(row)
    for path in list(auto.glob("*/*adjudication*.jsonl"))+list(auto.glob("*/*adjudication*.json")):
        if not packet_ok(path,cutoff,skip_mtime): continue
        files+=1; adj+=1
        text=path.read_text(errors="replace")
        chunks=[]
        if path.suffix==".jsonl":
            for l in text.splitlines():
                if l.strip():
                    try: chunks.append(json.loads(l))
                    except json.JSONDecodeError: pass
        else:
            try: chunks=[json.loads(text)]
            except json.JSONDecodeError: continue
        for row in chunks:
            if isinstance(row,dict): consider(row)
    for path in auto.glob("*/result.json"):
        if not packet_ok(path,cutoff,skip_mtime): continue
        files+=1; resf+=1
        try: payload=json.loads(path.read_text(errors="replace"))
        except json.JSONDecodeError: continue
        if isinstance(payload,dict):
            for key in ("remaining_inventory","cases","reviewed","rows"):
                val=payload.get(key)
                if isinstance(val, list):
                    for row in val:
                        if isinstance(row, dict): consider(row)
    return files,cases,adj,resf,rows,verdict

cutoff=(SRC/"result.json").stat().st_mtime
files,cases,adj,resf,rows,verdict=inventory_terminal(cutoff)
assert (files,cases,adj,resf,rows)==(584,267,34,283,12504)
assert len(verdict)==7932
_,_,_,_,_,verdict_now=inventory_terminal(cutoff, skip_mtime=True)
later=verdict_now-verdict

def parse_advisory(path):
    data=json.loads(path.read_text(errors="replace"))
    gid=norm_ghsa(data.get("id") or path.stem)
    if not gid: return None
    refs=[]
    for ref in data.get("references") or []:
        url=ref.get("url") if isinstance(ref,dict) else ref
        if isinstance(url,str): refs.append(url)
    same=[]; repo_adv=[]; github_repo=None
    prs=[]; compares=[]; patches=[]; releases=[]
    for url in refs:
        m=REPO_ADV_RE.search(url)
        if m and m.group(3).upper()==gid:
            github_repo=f"{m.group(1)}/{m.group(2)}"
            repo_adv.append(url.split("#")[0])
        m2=GITHUB_REPO_RE.match(url.rstrip("/"))
        if m2 and github_repo is None:
            github_repo=f"{m2.group(1)}/{m2.group(2)}"
    repos=set(); first_patched=set()
    for aff in data.get("affected") or []:
        for ver in (aff or {}).get("ranges") or []:
            repo=((ver or {}).get("repo")) or ""
            if isinstance(repo,str) and "github.com/" in repo:
                m=re.search(r"github\.com/([^/]+)/([^/#?]+)", repo)
                if m: repos.add(f"{m.group(1)}/{m.group(2).removesuffix('.git')}")
            for ev in (ver or {}).get("events") or []:
                if isinstance(ev,dict) and isinstance(ev.get("fixed"),str) and ev["fixed"]:
                    first_patched.add(ev["fixed"])
    if not github_repo and repos:
        github_repo=sorted(repos)[0]
    if github_repo:
        owner,name=github_repo.split("/",1)
        for url in refs:
            m=COMMIT_RE.search(url)
            if m and m.group(1).lower()==owner.lower() and m.group(2).lower()==name.lower():
                same.append(m.group(3).lower())
            m=PR_RE.search(url)
            if m and m.group(1).lower()==owner.lower() and m.group(2).lower()==name.lower():
                prs.append(int(m.group(3)))
            m=COMPARE_RE.search(url)
            if m and m.group(1).lower()==owner.lower() and m.group(2).lower()==name.lower():
                compares.append(url.split("#")[0])
            m=PATCH_RE.search(url)
            if m and m.group(1).lower()==owner.lower() and m.group(2).lower()==name.lower():
                patches.append(url.split("#")[0])
            m=RELEASE_RE.search(url)
            if m and m.group(1).lower()==owner.lower() and m.group(2).lower()==name.lower():
                releases.append(m.group(3))
    return {"case_id":gid,"withdrawn":bool(data.get("withdrawn")),"repository":github_repo,"same_repo_fixes":sorted(set(same)),"repo_advisory_urls":sorted(set(repo_adv)),"published":data.get("published") or "","aliases":[x for x in (data.get("aliases") or []) if isinstance(x,str)],"prs":sorted(set(prs)),"compares":sorted(set(compares)),"patches":sorted(set(patches)),"releases":sorted(set(releases)),"first_patched":sorted(first_patched),"path":str(path.relative_to(ADV)),"adv_sha256":sha256(path.read_bytes()).hexdigest()}

clone_map={}
if REPOS.is_dir():
    for p in REPOS.iterdir():
        if p.is_dir() and "_" in p.name:
            owner,repo=p.name.split("_",1)
            clone_map.setdefault(f"{owner}/{repo}".lower(), p)
if WORKER_CLONES.is_dir():
    for clone in list(WORKER_CLONES.glob("*/clones/*"))+list(WORKER_CLONES.glob("*/*/clones/*")):
        if clone.is_dir() and "__" in clone.name:
            owner,repo=clone.name.split("__",1)
            clone_map.setdefault(f"{owner}/{repo}".lower(), clone)

nsr=[]
reviewed=0
for path in (ADV/"advisories/github-reviewed").rglob("GHSA-*.json"):
    row=parse_advisory(path)
    if not row: continue
    reviewed+=1
    if row["withdrawn"]: continue
    if not row["repository"]: continue
    if row["same_repo_fixes"]: continue
    if row["case_id"] in verdict: continue
    if row["case_id"] in canon: continue
    nsr.append(row)
assert reviewed==34389
assert len(nsr)==10631==res["bucket_reconstruction"]["reconstructed_count"]
ids_hash=sha256(json.dumps(sorted(r["case_id"] for r in nsr)).encode()).hexdigest()
assert ids_hash==res["bucket_reconstruction"]["no_same_repo_fix_ids_sha256"]
assert ids_hash=="47d68ff02b6bb9f843f8f82d6b894f54da59d30b8302ae02dcfd3713147b53e5"
assert not set(r["case_id"] for r in nsr)&canon
sub_l=sorted(set(r["case_id"] for r in nsr)&later)
assert sub_l==res["bucket_reconstruction"]["subtract_later_terminals"]
assert len(sub_l)==51
remain=[r for r in nsr if r["case_id"] not in later]
assert len(remain)==10580==res["bucket_reconstruction"]["remaining_after_canonical94_and_later_terminals"]

def recov(r):
    return bool(r["repo_advisory_urls"] and (r["prs"] or r["compares"] or r["patches"] or r["releases"] or r["first_patched"]))
rec=[r for r in remain if recov(r)]
assert len(rec)==2844==res["bucket_reconstruction"]["recoverable_n"]

def rank_key(r):
    has_clone=0 if r["repository"] and r["repository"].lower() in clone_map else 1
    recent=0 if (r.get("published") or "") >= "2025-05-01" else 1
    fanout=len(r["prs"]) if r["prs"] else 50
    if r["prs"]: signal=0
    elif r["compares"] or r["patches"]: signal=1
    elif r["releases"]: signal=2
    else: signal=3
    return (has_clone, recent, fanout, signal, r["case_id"])
rec.sort(key=rank_key)
got=[t["case_id"] for t in rec[160:220]]
assert got==want
got_prior=[t["case_id"] for t in rec[:160]]
assert got_prior==prior
assert not set(got)&set(got_prior)
assert rec[:40][0]["case_id"]==json.loads((PREV/"result.json").read_text())["inspected_ids"][0]

by={r["case_id"]: r for r in rec[160:220]}
for row in c:
    cid=row["case_id"]
    adv=by[cid]
    assert row["recovered_closer"]==res["pinned_objects"]["closers"][cid]
    assert a[[x["case_id"] for x in a].index(cid)]["recovered_closer"]==row["recovered_closer"]
    assert adv["adv_sha256"]==res["first_party_advisory_sha256"][cid]
    fname="GHSA-"+cid[5:].lower()+".json"
    matches=list((ADV/"advisories/github-reviewed").rglob(fname))
    assert matches, cid
    assert sha256(matches[0].read_bytes()).hexdigest()==adv["adv_sha256"]
    assert row["hits"]==[]
    assert row["verdict"]=="REJECT_ROUTING"
    assert row.get("proposed_pass") is False
    assert not row.get("same_repo_fixes")
    assert cid not in canon

assert h(OWN/"assignment.jsonl")==res["artifact_hashes"]["assignment.jsonl"]
assert h(OWN/"cases.jsonl")==res["artifact_hashes"]["cases.jsonl"]
assert h(OWN/"report.md")==res["artifact_hashes"]["report.md"]
assert h(OWN/"replay.zsh")==res["artifact_hashes"]["replay.zsh"]
print("REPLAY_OK inspected=60 ROUTE=0 PASS=0 canonical94=94 bucket=10631 equation=60=60+0 slice=161-220 remainder=10411")
PY
