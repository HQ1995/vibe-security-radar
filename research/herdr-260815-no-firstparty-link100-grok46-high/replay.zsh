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
OWN=ROOT/"autoresearch/herdr-260815-no-firstparty-link100-grok46-high"
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
assert len(want)==100==len(set(want))
assert all(x.get("never_pass") and x.get("routing_only") for x in a+c)
assert all(x.get("proposed_pass") is False for x in c)
assert all(x.get("verdict") in {"REJECT_ROUTING","UNKNOWN"} for x in c)
assert "PASS" not in {x.get("verdict") for x in c}
assert "ROUTE" not in {x.get("verdict") for x in c}
assert res["counts"]["PASS"]==0 and res["counts"]["ROUTE"]==0
assert res["pass_proposals"]==[] and res["route_ids"]==[]
assert res["canonical94_strict_count"]==94
assert res["never_pass"] is True
assert res["bucket_reconstruction"]["reconstructed_count"]==691
assert res["conservation"]["equation"]=="100=100+0" and res["conservation"]["holds"]
assert res["conservation"]["bucket_equation"]=="691=0+11+680"
assert res["conservation"]["remaining_equation"]=="680=100+580"
src=json.loads((SRC/"result.json").read_text())
assert src["buckets"]["no_first_party_repo_advisory"]==691
canon=set(str(x).upper() for x in json.loads((ROOT/"autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json").read_text())["strict_released_case_ids"])
assert len(canon)==94
assert not set(want)&canon
text=(OWN/"report.md").read_text()
assert "does not call a PASS" in text
assert "ROUTE 0" in text
assert "100=100+0" in text
assert "691 = 0 canonical94 + 11 later terminals + 680 remaining" in text

sys.path.insert(0, str(ROOT/"cve-analyzer/src"))
from cve_analyzer.source_matcher import MATCHER_CONTRACT
assert MATCHER_CONTRACT==res["matcher_contract"]

ADV=Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database")
REPOS=Path("/home/hanqing/.cache/cve-analyzer/repos")
WORKER_CLONES=Path("/home/hanqing/.cache/ghsa200-worker-clones")
SKIP_PARTS={"work","notes","pages","snapshot","clones","cache","tmp","node_modules"}
SKIP_DIR_NAMES={"herdr-260814-nextqueue-v2-grok46-low",".leader-quarantine-260814",OWN.name}
GHSA_RE=re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
COMMIT_RE=re.compile(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})(?:[/?#]|$)")
REPO_ADV_RE=re.compile(r"https://github\.com/([^/]+)/([^/]+)/security/advisories/(GHSA-[0-9A-Za-z-]+)", re.I)
GITHUB_REPO_RE=re.compile(r"^https://github\.com/([^/]+)/([^/]+)/?$")
PR_RE=re.compile(r"https://github\.com/([^/]+)/([^/]+)/pull/([0-9]+)(?:[/?#]|$)", re.I)
ISSUE_RE=re.compile(r"https://github\.com/([^/]+)/([^/]+)/issues/([0-9]+)(?:[/?#]|$)", re.I)
RELEASE_RE=re.compile(r"https://github\.com/([^/]+)/([^/]+)/releases/tag/([^/?#]+)", re.I)
CHANGELOG_RE=re.compile(r"https://github\.com/([^/]+)/([^/]+)/(?:blob|raw|tree)/[^?#]*/(?:.*/)?(?:CHANGELOG|CHANGES|HISTORY|NEWS|RELEASE[_-]?NOTES?)(?:\.[A-Za-z0-9.]+)?(?:[/?#]|$)", re.I)
CHANGELOG_GENERIC_RE=re.compile(r"https://github\.com/([^/]+)/([^/]+)/(?:blob|raw)/[^?#]*changelog[^?#]*", re.I)
VERDICTS={"PASS","NARROW","REJECT","UNKNOWN","BLOCKED","KEEP","FAIL","FALSE_POSITIVE","CONFIRM","ACCEPT","HOLD"}
ROUTING_VERDICTS=VERDICTS|{"REJECT_ROUTING","ROUTE","PASS_PROPOSAL"}
GIT_ENV={"PATH":"/usr/local/bin:/usr/bin:/bin","GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0","GIT_NO_LAZY_FETCH":"1","GIT_PAGER":"cat","LC_ALL":"C","GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null","GIT_CONFIG_SYSTEM":"/dev/null"}

def git(repo,*args,timeout=15):
    return subprocess.run(["/usr/bin/git","--no-optional-locks","-c","gc.auto=0","-c","maintenance.auto=false","-C",str(repo),*args],capture_output=True,text=True,env=GIT_ENV,timeout=timeout,check=False)

assert git(ADV,"rev-parse","HEAD").stdout.strip()==res["advisory_database"]["head"]
assert git(ADV,"rev-parse","HEAD:advisories/github-reviewed").stdout.strip()==res["advisory_database"]["github_reviewed_tree"]

def norm_ghsa(v):
    if not isinstance(v,str): return None
    s=v.strip().upper()
    return s if GHSA_RE.match(s) else None

def packet_ok(path, cutoff, skip_mtime=False, include_815=False):
    if not skip_mtime and path.stat().st_mtime>=cutoff: return False
    rel=path.relative_to(ROOT/"autoresearch")
    top=rel.parts[0]
    if top in SKIP_DIR_NAMES: return False
    if (not include_815) and top.startswith("herdr-260815"): return False
    if any(p in SKIP_PARTS for p in rel.parts[:-1]): return False
    return top.startswith("herdr-260813") or top.startswith("herdr-260814") or top.startswith("herdr-260815") or top.startswith("orchestrator-260813") or top.startswith("orchestrator-260814") or top.startswith("orchestrator-260815")

def inventory_terminal(cutoff, skip_mtime=False, include_815=False, extra_ids=False):
    auto=ROOT/"autoresearch"
    verdict=set(); files=0; rows=0
    cases=adj=resf=0
    accept=ROUTING_VERDICTS if extra_ids else VERDICTS
    def consider(row):
        nonlocal rows
        rows+=1
        cid=norm_ghsa(row.get("case_id") or row.get("ghsa_id") or row.get("id"))
        if not cid: return
        v=row.get("verdict") or row.get("worker_verdict") or row.get("latest_verdict")
        if isinstance(v,str) and v.strip().upper() in accept:
            verdict.add(cid)
    for path in auto.glob("*/cases.jsonl"):
        if not packet_ok(path, cutoff, skip_mtime, include_815): continue
        files+=1; cases+=1
        for line in path.read_text(errors="replace").splitlines():
            if not line.strip(): continue
            try: row=json.loads(line)
            except json.JSONDecodeError: continue
            if isinstance(row, dict): consider(row)
    for path in list(auto.glob("*/*adjudication*.jsonl"))+list(auto.glob("*/*adjudication*.json")):
        if not packet_ok(path, cutoff, skip_mtime, include_815): continue
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
            if isinstance(row, dict): consider(row)
    for path in auto.glob("*/result.json"):
        if not packet_ok(path, cutoff, skip_mtime, include_815): continue
        files+=1; resf+=1
        try: payload=json.loads(path.read_text(errors="replace"))
        except json.JSONDecodeError: continue
        if isinstance(payload, dict):
            for key in ("remaining_inventory","cases","reviewed","rows"):
                val=payload.get(key)
                if isinstance(val, list):
                    for row in val:
                        if isinstance(row, dict): consider(row)
            if extra_ids:
                for key in ("inspected_ids","selected_ids","queued_ids","route_ids","deep_inspect_ids","leftover_ids"):
                    val=payload.get(key)
                    if isinstance(val, list):
                        for item in val:
                            cid=norm_ghsa(item)
                            if cid: verdict.add(cid)
    return files, cases, adj, resf, rows, verdict

cutoff=(SRC/"result.json").stat().st_mtime
files,cases,adj,resf,rows,verdict=inventory_terminal(cutoff)
assert (files,cases,adj,resf,rows)==(584,267,34,283,12504)
assert len(verdict)==7932
_,_,_,_,_,verdict_now=inventory_terminal(cutoff, skip_mtime=True, include_815=True, extra_ids=True)
later=verdict_now-verdict

def parse_advisory(path):
    data=json.loads(path.read_text(errors="replace"))
    gid=norm_ghsa(data.get("id") or path.stem)
    if not gid: return None
    refs=[]
    for ref in data.get("references") or []:
        url=ref.get("url") if isinstance(ref, dict) else ref
        if isinstance(url, str): refs.append(url)
    same=[]; repo_adv=[]; github_repo=None
    prs=[]; issues=[]; releases=[]; changelogs=[]
    for url in refs:
        m=REPO_ADV_RE.search(url)
        if m and m.group(3).upper()==gid:
            github_repo=f"{m.group(1)}/{m.group(2)}"
            repo_adv.append(url.split("#")[0])
        m2=GITHUB_REPO_RE.match(url.rstrip("/"))
        if m2 and github_repo is None:
            github_repo=f"{m2.group(1)}/{m2.group(2)}"
    repos=set()
    for aff in data.get("affected") or []:
        for ver in (aff or {}).get("ranges") or []:
            repo=((ver or {}).get("repo")) or ""
            if isinstance(repo, str) and "github.com/" in repo:
                m=re.search(r"github\.com/([^/]+)/([^/#?]+)", repo)
                if m: repos.add(f"{m.group(1)}/{m.group(2).removesuffix('.git')}")
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
            m=ISSUE_RE.search(url)
            if m and m.group(1).lower()==owner.lower() and m.group(2).lower()==name.lower():
                issues.append(int(m.group(3)))
            m=RELEASE_RE.search(url)
            if m and m.group(1).lower()==owner.lower() and m.group(2).lower()==name.lower():
                releases.append(m.group(3))
            m=CHANGELOG_RE.search(url) or CHANGELOG_GENERIC_RE.search(url)
            if m and m.group(1).lower()==owner.lower() and m.group(2).lower()==name.lower():
                changelogs.append(url.split("#")[0])
    return {
        "case_id": gid,
        "withdrawn": bool(data.get("withdrawn")),
        "repository": github_repo,
        "same_repo_fixes": sorted(set(same)),
        "repo_advisory_urls": sorted(set(repo_adv)),
        "published": data.get("published") or "",
        "prs": sorted(set(prs)),
        "issues": sorted(set(issues)),
        "releases": sorted(set(releases)),
        "changelogs": sorted(set(changelogs)),
        "adv_sha256": sha256(path.read_bytes()).hexdigest(),
        "path": str(path.relative_to(ADV)),
    }

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

buckets=Counter(); nfp=[]
reviewed=0
for path in (ADV/"advisories/github-reviewed").rglob("GHSA-*.json"):
    row=parse_advisory(path)
    if not row: continue
    reviewed+=1
    if row["withdrawn"]:
        buckets["withdrawn"]+=1; continue
    if not row["repository"]:
        buckets["no_repository"]+=1; continue
    if not row["same_repo_fixes"]:
        buckets["no_same_repo_fix"]+=1; continue
    if (row.get("published") or "") < "2025-05-01":
        buckets["outside_coverage_window"]+=1; continue
    if row["case_id"] in verdict:
        buckets["terminal_verdict"]+=1; continue
    if not row["repo_advisory_urls"]:
        buckets["no_first_party_repo_advisory"]+=1
        nfp.append(row)
        continue
    buckets["structural_or_canonical"]+=1
assert reviewed==34389
assert buckets["withdrawn"]==910
assert len(nfp)==691==res["bucket_reconstruction"]["reconstructed_count"]
nfp_ids=sorted(r["case_id"] for r in nfp)
nfp_hash=sha256(json.dumps(nfp_ids).encode()).hexdigest()
assert nfp_hash==res["bucket_reconstruction"]["no_first_party_repo_advisory_ids_sha256"]
assert not set(nfp_ids)&canon
later_overlap=sorted(set(nfp_ids)&later)
assert later_overlap==res["bucket_reconstruction"]["subtract_later_terminals"]
remain=[r for r in nfp if r["case_id"] not in later]
assert len(remain)==680==res["bucket_reconstruction"]["remaining_after_canonical94_and_later_terminals"]
remain_hash=sha256(json.dumps(sorted(r["case_id"] for r in remain)).encode()).hexdigest()
assert remain_hash==res["bucket_reconstruction"]["remaining_ids_sha256"]

def identity_signals(r):
    kinds=[]
    if r["issues"]: kinds.append("issue")
    if r["prs"]: kinds.append("pr")
    if r["releases"]: kinds.append("release")
    if r["changelogs"]: kinds.append("changelog")
    return kinds

ranked_src=[]
for r in remain:
    kinds=identity_signals(r)
    if not kinds: continue
    has_clone=0 if r["repository"] and r["repository"].lower() in clone_map else 1
    if "issue" in kinds: signal=0
    elif "pr" in kinds: signal=1
    elif "release" in kinds: signal=2
    else: signal=3
    n_kinds=-len(kinds)
    fanout=(len(r["issues"]) or 50)+ (len(r["prs"]) or 0)
    ranked_src.append((has_clone, signal, n_kinds, fanout, r["case_id"], r, kinds))
ranked_src.sort()
assert len(ranked_src)==329==res["bucket_reconstruction"]["with_identity_n"]
prefix=[t[5] for t in ranked_src[:100]]
got=[t["case_id"] for t in prefix]
assert got==want
sel_hash=sha256(json.dumps(got).encode()).hexdigest()
assert sel_hash==res["selected_ids_sha256"]

by={r["case_id"]: r for r in prefix}
for row in c:
    cid=row["case_id"]
    adv=by[cid]
    assert adv["adv_sha256"]==row["first_party_advisory_sha256"]
    fname="GHSA-"+cid[5:].lower()+".json"
    matches=list((ADV/"advisories/github-reviewed").rglob(fname))
    assert matches, cid
    assert sha256(matches[0].read_bytes()).hexdigest()==adv["adv_sha256"]
    assert row.get("proposed_pass") is False
    assert row.get("never_pass") is True
    if cid=="GHSA-9965-VMPH-33XX":
        assert row["identity_closed"] is True
        assert row["verdict"]=="REJECT_ROUTING"
        assert row["reject_reason"]=="no_atomic_pre_fix_marker_on_mechanism_hunk"
        assert row["minimum_fix"]=="cbef5088f02d36caf978f378bb845fe49bdc0809"
        assert row["candidate_parent"]=="6f436be36945e460ee624bf72a935a06daded859"
    else:
        assert row["identity_closed"] is False
    if row["verdict"]=="UNKNOWN":
        assert row["reject_reason"]=="fix_object_missing"
    else:
        assert row["verdict"]=="REJECT_ROUTING"

unknown_ids=[x["case_id"] for x in c if x["verdict"]=="UNKNOWN"]
assert unknown_ids==res["unknown_ids"]
assert [x["case_id"] for x in c if x["identity_closed"]]==["GHSA-9965-VMPH-33XX"]

assert h(OWN/"assignment.jsonl")==res["artifact_hashes"]["assignment.jsonl"]
assert h(OWN/"cases.jsonl")==res["artifact_hashes"]["cases.jsonl"]
assert h(OWN/"report.md")==res["artifact_hashes"]["report.md"]
assert h(OWN/"replay.zsh")==res["artifact_hashes"]["replay.zsh"]
print("REPLAY_OK inspected=100 ROUTE=0 PASS=0 canonical94=94 bucket=691 equation=100=100+0")
PY
