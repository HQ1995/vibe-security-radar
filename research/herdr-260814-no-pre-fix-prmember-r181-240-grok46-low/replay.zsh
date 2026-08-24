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
OWN=ROOT/"autoresearch/herdr-260814-no-pre-fix-prmember-r181-240-grok46-low"
INV=ROOT/"autoresearch/herdr-260814-no-pre-fix-prmember-inventory-grok46-low"
R61=ROOT/"autoresearch/herdr-260814-no-pre-fix-prmember-r61-120-grok46-low"
R121=ROOT/"autoresearch/herdr-260814-no-pre-fix-prmember-r121-180-grok46-medium"
SRC=ROOT/"autoresearch/herdr-260814-nextqueue-v2-grok46-low"
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
assert h(INV/"result.json")==pins["inventory_result.json"]
assert h(INV/"replay.zsh")==pins["inventory_replay.zsh"]
assert h(R61/"result.json")==pins["ranks61_120_result.json"]
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
assert len(want)==60==len(set(want))
assert [x["rank"] for x in a]==list(range(181,241))
assert all(x.get("never_pass") and x.get("routing_only") for x in a+c)
assert all(x.get("verdict")=="REJECT_ROUTING" for x in c)
assert all(x.get("proposed_pass") is False for x in c)
assert "PASS" not in {x.get("verdict") for x in c}
assert res["counts"]["PASS"]==0 and res["counts"]["ROUTE"]==0 and res["pass_proposals"]==[] and res["selected_ids"]==[]
assert res["canonical94_strict_count"]==94
assert res["bucket_reconstruction"]["reconstructed_count"]==729
assert res["conservation"]["equation"]=="60=60+0" and res["conservation"]["holds"]
assert res["conservation"]["bucket_equation"]=="729=240+489"
src=json.loads((SRC/"result.json").read_text())
assert src["buckets"]["no_pre_fix_ai_marker"]==729
canon=set(str(x).upper() for x in json.loads((ROOT/"autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json").read_text())["strict_released_case_ids"])
assert len(canon)==94
assert not set(want)&canon
prior=res["prior_slice_ids"]
active=res["active_slice_ids"]
assert len(prior)==120 and not set(want)&set(prior)
assert len(active)==60 and not set(want)&set(active)
assert not set(prior)&set(active)
text=(OWN/"report.md").read_text()
assert "does not call a PASS" in text and "Recall repair" in text
assert "60=60+0" in text and "729=240+489" in text and "ROUTE 0" in text

# disjoint from other on-disk no-pre-fix slices
for other in (ROOT/"autoresearch").glob("herdr-260814-no-pre-fix-prmember-*"):
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
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit
assert MATCHER_CONTRACT==res["matcher_contract"]

ADV=Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database")
REPOS=Path("/home/hanqing/.cache/cve-analyzer/repos")
WORKER_CLONES=Path("/home/hanqing/.cache/ghsa200-worker-clones")
SKIP_PARTS={"work","notes","pages","snapshot","clones","cache","tmp","node_modules"}
SKIP_DIR_NAMES={"herdr-260814-nextqueue-v2-grok46-low",".leader-quarantine-260814",OWN.name,INV.name,R61.name,R121.name}
GHSA_RE=re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
COMMIT_RE=re.compile(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})(?:[/?#]|$)")
REPO_ADV_RE=re.compile(r"https://github\.com/([^/]+)/([^/]+)/security/advisories/(GHSA-[0-9A-Za-z-]+)", re.I)
GITHUB_REPO_RE=re.compile(r"^https://github\.com/([^/]+)/([^/]+)/?$")
VERDICTS={"PASS","NARROW","REJECT","UNKNOWN","BLOCKED","KEEP","FAIL","FALSE_POSITIVE","CONFIRM","ACCEPT","HOLD"}
CODE_EXT={".c",".cc",".cpp",".cs",".go",".h",".hpp",".java",".js",".jsx",".kt",".php",".py",".rb",".rs",".swift",".ts",".tsx",".vue",".zig"}
SHA_RE=re.compile(r"^[0-9a-f]{40}$")
GIT_ENV={"PATH":"/usr/local/bin:/usr/bin:/bin","GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0","GIT_NO_LAZY_FETCH":"1","GIT_PAGER":"cat","LC_ALL":"C","GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null","GIT_CONFIG_SYSTEM":"/dev/null"}

def git(repo,*args,timeout=15):
    p=subprocess.run(["/usr/bin/git","--no-optional-locks","-c","gc.auto=0","-c","maintenance.auto=false","-C",str(repo),*args],capture_output=True,text=True,env=GIT_ENV,timeout=timeout,check=False)
    keep=[]
    for line in (p.stderr or "").splitlines():
        if "unable to normalize alternate object path" in line: continue
        if "lazy fetching disabled" in line: continue
        if line.strip(): keep.append(line)
    if keep and p.returncode!=0 and args[0] in ("rev-parse",):
        raise SystemExit("git fail "+str(args)+" "+"\n".join(keep))
    return p

assert git(ADV,"rev-parse","HEAD").stdout.strip()==res["advisory_database"]["head"]
assert git(ADV,"rev-parse","HEAD:advisories/github-reviewed").stdout.strip()==res["advisory_database"]["github_reviewed_tree"]

def norm_ghsa(v):
    if not isinstance(v,str): return None
    s=v.strip().upper()
    return s if GHSA_RE.match(s) else None

def packet_ok(path, cutoff):
    if path.stat().st_mtime>=cutoff: return False
    rel=path.relative_to(ROOT/"autoresearch")
    top=rel.parts[0]
    if top in SKIP_DIR_NAMES: return False
    if any(p in SKIP_PARTS for p in rel.parts[:-1]): return False
    return top.startswith("herdr-260813") or top.startswith("herdr-260814") or top.startswith("orchestrator-260813") or top.startswith("orchestrator-260814")

def inventory_terminal(cutoff):
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
        if not packet_ok(path,cutoff): continue
        files+=1; cases+=1
        for line in path.read_text(errors="replace").splitlines():
            if not line.strip(): continue
            try: row=json.loads(line)
            except json.JSONDecodeError: continue
            if isinstance(row,dict): consider(row)
    for path in list(auto.glob("*/*adjudication*.jsonl"))+list(auto.glob("*/*adjudication*.json")):
        if not packet_ok(path,cutoff): continue
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
        if not packet_ok(path,cutoff): continue
        files+=1; resf+=1
        try: payload=json.loads(path.read_text(errors="replace"))
        except json.JSONDecodeError: continue
        if isinstance(payload,dict):
            for key in ("remaining_inventory","cases","reviewed","rows"):
                val=payload.get(key)
                if isinstance(val,list):
                    for row in val:
                        if isinstance(row,dict): consider(row)
    return files,cases,adj,resf,rows,verdict

cutoff=(SRC/"result.json").stat().st_mtime
files,cases,adj,resf,rows,verdict=inventory_terminal(cutoff)
assert (files,cases,adj,resf,rows)==(584,267,34,283,12504)
assert len(verdict)==7932

def parse_advisory(path):
    data=json.loads(path.read_text(errors="replace"))
    gid=norm_ghsa(data.get("id") or path.stem)
    if not gid: return None
    pkgs=[]; repos=set()
    for aff in data.get("affected") or []:
        pkg=((aff or {}).get("package") or {}).get("name")
        if isinstance(pkg,str) and pkg: pkgs.append(pkg)
        for ver in (aff or {}).get("ranges") or []:
            repo=((ver or {}).get("repo")) or ""
            if isinstance(repo,str) and "github.com/" in repo:
                m=re.search(r"github\.com/([^/]+)/([^/#?]+)", repo)
                if m: repos.add(f"{m.group(1)}/{m.group(2).removesuffix('.git')}")
    refs=[]
    for ref in data.get("references") or []:
        url=ref.get("url") if isinstance(ref,dict) else ref
        if isinstance(url,str): refs.append(url)
    same=[]; repo_adv=[]; github_repo=None
    for url in refs:
        m=REPO_ADV_RE.search(url)
        if m and m.group(3).upper()==gid:
            github_repo=f"{m.group(1)}/{m.group(2)}"
            repo_adv.append(url.split("#")[0])
        m2=GITHUB_REPO_RE.match(url.rstrip("/"))
        if m2 and github_repo is None:
            github_repo=f"{m2.group(1)}/{m2.group(2)}"
    if not github_repo and repos:
        github_repo=sorted(repos)[0]
    if github_repo:
        owner,name=github_repo.split("/",1)
        for url in refs:
            m=COMMIT_RE.search(url)
            if m and m.group(1).lower()==owner.lower() and m.group(2).lower()==name.lower():
                same.append(m.group(3).lower())
    return {"case_id":gid,"withdrawn":bool(data.get("withdrawn")),"repository":github_repo,"same_repo_fixes":sorted(set(same)),"repo_advisory_urls":sorted(set(repo_adv)),"published":data.get("published") or "","aliases":[x for x in (data.get("aliases") or []) if isinstance(x,str)]}

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

ai_hit=set(src["queued_ids"])|set(src["leftover_ids"])
structural=[]; buckets=Counter()
for path in (ADV/"advisories/github-reviewed").rglob("GHSA-*.json"):
    row=parse_advisory(path)
    if not row: continue
    cid=row["case_id"]
    if row["withdrawn"]:
        buckets["withdrawn"]+=1; continue
    if not row["repository"]:
        buckets["no_repository"]+=1; continue
    if not row["same_repo_fixes"]:
        buckets["no_same_repo_fix"]+=1; continue
    if (row.get("published") or "") < "2025-05-01":
        buckets["outside_coverage_window"]+=1; continue
    if cid in verdict:
        buckets["terminal_verdict"]+=1; continue
    if not row["repo_advisory_urls"]:
        buckets["no_first_party_repo_advisory"]+=1; continue
    structural.append(row)
assert len(structural)==803
present=[]
for row in structural:
    clone=clone_map.get(row["repository"].lower())
    if clone is None:
        buckets["no_local_clone"]+=1; continue
    saw=False
    for fix in row["same_repo_fixes"][:4]:
        t=git(clone,"cat-file","-t",fix,timeout=8)
        if t.returncode==0 and t.stdout.strip()=="commit":
            saw=True; break
    if not saw:
        buckets["fix_object_missing"]+=1
    else:
        present.append(row)
no_pre=[r for r in present if r["case_id"] not in ai_hit]
assert len(no_pre)==729==res["bucket_reconstruction"]["reconstructed_count"]
ids_hash=sha256(json.dumps(sorted(r["case_id"] for r in no_pre)).encode()).hexdigest()
assert ids_hash==res["bucket_reconstruction"]["no_pre_fix_ids_sha256"]
assert not set(r["case_id"] for r in no_pre)&canon
assert buckets["no_local_clone"]==5 and buckets["fix_object_missing"]==38

def names(repo,sha):
    p=git(repo,"diff-tree","--no-commit-id","--name-only","-r",sha,timeout=15)
    return [l.strip() for l in p.stdout.splitlines() if l.strip()] if p.returncode==0 else []

def commit_info(repo, sha):
    proc=git(repo,"show","-s","--format=%H%n%an%n%ae%n%cn%n%ce%n%aI%n%B",sha,timeout=15)
    if proc.returncode!=0 or not proc.stdout.strip():
        return None
    parts=proc.stdout.split("\n",6)
    if len(parts)<7: return None
    return CommitInfo(sha=parts[0].strip().lower(), author_name=parts[1], author_email=parts[2],
                      committer_name=parts[3], committer_email=parts[4], authored_date=parts[5].strip(), message=parts[6])

ranked=[]
for row in no_pre:
    clone=clone_map[row["repository"].lower()]
    fix=None
    for cand in row["same_repo_fixes"]:
        t=git(clone,"cat-file","-t",cand,timeout=8)
        if t.returncode==0 and t.stdout.strip()=="commit":
            fix=cand; break
    files=names(clone, fix)
    code=[p for p in files if Path(p).suffix.lower() in CODE_EXT]
    ranked.append((0, 0 if code else 1, len(files), row["case_id"], row, clone, fix, files, code))
ranked.sort()
got0=[t[3] for t in ranked[:60]]
got1=[t[3] for t in ranked[60:120]]
got2=[t[3] for t in ranked[120:180]]
got=[t[3] for t in ranked[180:240]]
assert got0+got1==prior
assert got2==active
assert got==want, (got[:3], want[:3])
assert not set(got)&set(got2)

by={t[3]: t for t in ranked[180:240]}
for row in c:
    cid=row["case_id"]
    _z,_codeflag,nfiles,_id,adv,clone,fix,files,code=by[cid]
    assert git(clone,"cat-file","-t",fix).stdout.strip()=="commit"
    pars=git(clone,"rev-list","--parents","-n","1",fix).stdout.split()
    np=max(0,len(pars)-1)
    assert np==row["n_parents"]==1
    assert nfiles==row["n_files"]
    assert len(code)==row["n_code_files"]>=1
    parent=pars[1] if len(pars)>1 else ""
    if row.get("candidate_parent"):
        assert row["candidate_parent"]==parent
    pars2=pars
    np2=np
    members=[]
    if np>=2:
        rl=git(clone,"rev-list","--no-merges",f"{pars[1]}..{pars[2]}",timeout=20)
        members=[x.strip() for x in rl.stdout.splitlines() if SHA_RE.match(x.strip())]
    else:
        after=git(clone,"log","--all","--merges","--reverse","--ancestry-path","--format=%H",f"{fix}..HEAD",timeout=30)
        for m in after.stdout.splitlines():
            mp=git(clone,"rev-list","--parents","-n","1",m).stdout.split()
            if len(mp)<3: continue
            rl=git(clone,"rev-list","--no-merges",f"{mp[1]}..{mp[2]}",timeout=20)
            mem=[x.strip() for x in rl.stdout.splitlines() if SHA_RE.match(x.strip())]
            if fix in mem:
                members=mem
                break
    assert len(members)==row["pr_members_local"]
    for hit in row.get("hits") or []:
        sha=hit["sha"]
        assert git(clone,"cat-file","-t",sha).stdout.strip()=="commit"
        assert git(clone,"merge-base","--is-ancestor",sha,fix).returncode==0
        info=commit_info(clone, sha)
        assert info is not None
        assert matches_for_commit(info)
        assert hit.get("kind")=="hunk_line_overlap"
        assert hit.get("carrier") in (None, "")
    assert row["hits"]==[]
    assert row["verdict"]=="REJECT_ROUTING"

assert h(OWN/"assignment.jsonl")==res["artifact_hashes"]["assignment.jsonl"]
assert h(OWN/"cases.jsonl")==res["artifact_hashes"]["cases.jsonl"]
assert h(OWN/"report.md")==res["artifact_hashes"]["report.md"]
assert h(OWN/"replay.zsh")==res["artifact_hashes"]["replay.zsh"]
print("REPLAY_OK inspected=60 ROUTE=0 PASS=0 canonical94=94 bucket=729 equation=729=240+489 assigned=60=60+0 slice=181-240")
PY
