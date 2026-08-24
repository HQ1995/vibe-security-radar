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
OWN=ROOT/"autoresearch/herdr-260815-marker-gap-global100-grok46-medium"
PREV=ROOT/"autoresearch/herdr-260815-unrecognized-ai-marker729-grok46-medium"
res=json.loads((OWN/"result.json").read_text())
pins=res["current_input_hashes"]

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

assert h(ROOT/"autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md")==pins["CONTRACT.md"]
assert h(ROOT/"autoresearch/orchestrator-260814-ghsa200-canonical94/ledger.jsonl")==pins["canonical94_ledger.jsonl"]
assert h(ROOT/"autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json")==pins["canonical94_summary.json"]
assert h(PREV/"result.json")==pins["marker729_result.json"]
assert h(PREV/"report.md")==pins["marker729_report.md"]
assert h(PREV/"replay.zsh")==pins["marker729_replay.zsh"]
assert h(ROOT/"autoresearch/herdr-260813-ghsa200-commitfirst-gn/assignment-manifest.json")==pins["gn_assignment_manifest.json"]

names=sorted(p.name for p in OWN.iterdir() if p.is_file())
assert names==["cases.jsonl","marker_hits.jsonl","replay.zsh","report.md","result.json"], names
assert not (OWN/"work").exists()

cred_re=re.compile(r"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]{0,20}PRIVATE KEY)")
for p in OWN.iterdir():
    if p.is_file():
        data=p.read_bytes()
        assert all(b<128 for b in data), p.name
        text=data.decode("ascii")
        assert not cred_re.search(text), p.name

c=[json.loads(l) for l in (OWN/"cases.jsonl").read_text().splitlines() if l.strip()]
hits=[json.loads(l) for l in (OWN/"marker_hits.jsonl").read_text().splitlines() if l.strip()]
assert len(c)==100==res["counts"]["inspected"]
assert len(hits)==599==res["counts"]["atomic_pairs"]
assert all(x.get("never_pass") and x.get("routing_only") for x in c)
assert all(x.get("proposed_pass") is False for x in c)
assert "PASS" not in {x.get("verdict") for x in c}
assert set(x["verdict"] for x in c)=={"REJECT_ROUTING"}
assert res["route_ids"]==[]
assert res["counts"]["PASS"]==0 and res["counts"]["ROUTE"]==0 and res["pass_proposals"]==[]
assert res["conservation"]["universe_equation"]=="8757=75+7779+0+903"
assert res["conservation"]["remaining_equation"]=="903=54+847+2"
assert res["conservation"]["inspect_equation"]=="100=0+100+0"
assert res["conservation"]["holds"]
canon=set(str(x).upper() for x in json.loads((ROOT/"autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json").read_text())["strict_released_case_ids"])
assert len(canon)==94==res["canonical94_strict_count"]
assert not {x["case_id"] for x in c}&canon
text=(OWN/"report.md").read_text()
assert "does not call a PASS" in text
assert "Matcher policy is not edited" in text
assert "ROUTE IDs" in text
assert "none" in text.split("ROUTE IDs",1)[1][:80]

PACKETS=[
    "herdr-260814-no-pre-fix-prmember-inventory-grok46-low",
    "herdr-260814-no-pre-fix-prmember-r61-120-grok46-low",
    "herdr-260814-no-pre-fix-prmember-r121-180-grok46-medium",
    "herdr-260814-no-pre-fix-prmember-r181-240-grok46-low",
    "herdr-260814-no-pre-fix-prmember-r241-300-grok46-xhigh",
    "herdr-260814-no-pre-fix-prmember-r301-360-grok46-medium",
    "herdr-260814-no-pre-fix-prmember-r361-420-grok46-low",
    "herdr-260815-no-pre-fix-prmember-r421-480-grok46-xhigh",
    "herdr-260815-no-pre-fix-prmember-r481-540-grok46-high",
    "herdr-260815-no-pre-fix-prmember-r541-600-grok46-medium",
    "herdr-260815-no-pre-fix-prmember-r601-660-grok46-low",
    "herdr-260815-no-pre-fix-prmember-r661-720-grok46-xhigh",
    "herdr-260815-no-pre-fix-prmember-r721-729-grok46-low",
]
seen729=[]
for name in PACKETS:
    n=0
    for line in (ROOT/"autoresearch"/name/"assignment.jsonl").read_text().splitlines():
        if not line.strip(): continue
        cid=json.loads(line)["case_id"]
        assert cid not in seen729
        seen729.append(cid); n+=1
    assert n in (60,9)
ids729=sorted(set(seen729))
assert len(ids729)==729
assert sha256(json.dumps(ids729).encode()).hexdigest()=="ffeceb62c6fa243e5865020390ba5de297d01ce3fc0ac1c9754f46d2739c63b1"
assert not {x["case_id"] for x in c}&set(ids729)

sys.path.insert(0, str(ROOT/"cve-analyzer/src"))
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit
assert MATCHER_CONTRACT==res["matcher_contract"]
samples=[
    CommitInfo(sha="a"*40, author_name="x", author_email="y@z.com", committer_name="x", committer_email="y@z.com", authored_date="2026-04-06T00:00:00Z", message="subject\n\nMade-with: Cursor\n"),
    CommitInfo(sha="b"*40, author_name="x", author_email="y@z.com", committer_name="x", committer_email="y@z.com", authored_date="2026-06-02T00:00:00Z", message="subject\n\nCo-Authored-By: opencode <noreply@opencode.ai>\n"),
    CommitInfo(sha="c"*40, author_name="x", author_email="y@z.com", committer_name="x", committer_email="y@z.com", authored_date="2026-06-02T00:00:00Z", message="subject\n\nGenerated with [opencode](https://opencode.ai)\n"),
    CommitInfo(sha="d"*40, author_name="x", author_email="y@z.com", committer_name="x", committer_email="y@z.com", authored_date="2026-04-06T00:00:00Z", message="subject\n\nMade with Cursor\n"),
]
for info in samples:
    assert matches_for_commit(info)==()

ADV=Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database")
GIT_ENV={"PATH":"/usr/local/bin:/usr/bin:/bin","GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0","GIT_NO_LAZY_FETCH":"1","GIT_PAGER":"cat","LC_ALL":"C","GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null","GIT_CONFIG_SYSTEM":"/dev/null"}

def git(repo,*args,timeout=20):
    try:
        return subprocess.run(["/usr/bin/git","--no-optional-locks","-c","gc.auto=0","-c","maintenance.auto=false","-C",str(repo),*args],capture_output=True,text=True,env=GIT_ENV,timeout=timeout,check=False)
    except subprocess.TimeoutExpired:
        class R: pass
        r=R(); r.returncode=124; r.stdout=""; r.stderr="timeout"; return r

assert git(ADV,"rev-parse","HEAD").stdout.strip()==res["advisory_database"]["head"]
assert git(ADV,"rev-parse","HEAD:advisories/github-reviewed").stdout.strip()==res["advisory_database"]["github_reviewed_tree"]

FIRST_PARTY_RE=re.compile(r"https?://github\.com/([^/]+)/([^/]+)/security/advisories/(GHSA-[0-9a-z-]+)", re.I)
GHSA_RE=re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
WINDOW_START="2025-05-01"
AF=set("abcdef"); GN=set("ghijklmn")

def owner_bucket(owner):
    ch=owner.casefold()[0]
    if ch in AF: return "A-F"
    if ch in GN: return "G-N"
    if "a"<=ch<="z": return "O-Z"
    return "digit-or-other"

ids=[]
part=Counter()
reviewed_root=ADV/"advisories/github-reviewed"
for year_dir in sorted(p for p in reviewed_root.iterdir() if p.is_dir()):
    if year_dir.name not in {"2025","2026"}: continue
    for path in year_dir.rglob("*.json"):
        obj=json.loads(path.read_text(encoding="utf-8"))
        gid=(obj.get("id") or path.stem).strip().upper()
        published=(obj.get("published") or "")[:10]
        withdrawn=bool(obj.get("withdrawn"))
        repository=owner=None
        for ref in obj.get("references") or []:
            url=(ref or {}).get("url") or ""
            m=FIRST_PARTY_RE.search(url)
            if m:
                repository=f"{m.group(1)}/{m.group(2)}"; owner=m.group(1); break
        in_window=bool(published) and published>=WINDOW_START
        if repository and not withdrawn and in_window:
            ids.append(gid)
            part[owner_bucket(owner)]+=1
ids_sorted=sorted(ids)
assert len(ids_sorted)==8757==res["universe"]["n"]
assert dict(part)=={"A-F":2423,"G-N":2623,"O-Z":3680,"digit-or-other":31}
assert sha256(json.dumps(ids_sorted).encode()).hexdigest()==res["universe"]["ids_sha256"]=="e4e79ff90f0331d993ef39e66a8fb4a4b20c8e72e7945b2f4f241aa1b0ea1ad0"
U=set(ids_sorted)
assert len(canon&U)==75

VERDICTS={"PASS","NARROW","REJECT","UNKNOWN","BLOCKED","KEEP","FAIL","FALSE_POSITIVE","CONFIRM","ACCEPT","HOLD"}
ROUTING=VERDICTS|{"REJECT_ROUTING","ROUTE","PASS_PROPOSAL"}
SKIP_PARTS={"work","notes","pages","snapshot","clones","cache","tmp","node_modules"}
SKIP_DIR_NAMES={OWN.name, ".leader-quarantine-260814"}
CUTOFF=res["inventory"]["cutoff_mtime"]

def packet_ok(path):
    if path.stat().st_mtime>=CUTOFF: return False
    rel=path.relative_to(ROOT/"autoresearch")
    top=rel.parts[0]
    if top in SKIP_DIR_NAMES: return False
    if any(p in SKIP_PARTS for p in rel.parts[:-1]): return False
    return top.startswith(("herdr-260813","herdr-260814","herdr-260815","orchestrator-260813","orchestrator-260814","orchestrator-260815"))

def norm(v):
    if not isinstance(v,str): return None
    s=v.strip().upper()
    return s if GHSA_RE.match(s) else None

term=set(); files=0; rows=0; cases=adj=resf=0
auto=ROOT/"autoresearch"
def consider(row):
    global rows
    rows+=1
    cid=norm(row.get("case_id") or row.get("ghsa_id") or row.get("id"))
    if not cid: return
    v=row.get("verdict") or row.get("worker_verdict") or row.get("latest_verdict")
    if isinstance(v,str) and v.strip().upper() in ROUTING:
        term.add(cid)
for path in auto.glob("*/cases.jsonl"):
    if not packet_ok(path): continue
    files+=1; cases+=1
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip(): continue
        try: row=json.loads(line)
        except json.JSONDecodeError: continue
        if isinstance(row, dict): consider(row)
for path in list(auto.glob("*/*adjudication*.jsonl"))+list(auto.glob("*/*adjudication*.json")):
    if not packet_ok(path): continue
    files+=1; adj+=1
    textp=path.read_text(errors="replace")
    chunks=[]
    if path.suffix==".jsonl":
        for l in textp.splitlines():
            if l.strip():
                try: chunks.append(json.loads(l))
                except json.JSONDecodeError: pass
    else:
        try: chunks=[json.loads(textp)]
        except json.JSONDecodeError: continue
    for row in chunks:
        if isinstance(row, dict): consider(row)
for path in auto.glob("*/result.json"):
    if not packet_ok(path): continue
    files+=1; resf+=1
    try: payload=json.loads(path.read_text(errors="replace"))
    except json.JSONDecodeError: continue
    if not isinstance(payload, dict): continue
    for key in ("remaining_inventory","cases","reviewed","rows"):
        val=payload.get(key)
        if isinstance(val, list):
            for row in val:
                if isinstance(row, dict): consider(row)
inv=res["inventory"]
assert inv["cutoff_mtime"]==1786775000==CUTOFF
assert (files,cases,adj,resf,rows,len(term))==(inv["files"],inv["cases"],inv["adj"],inv["result"],inv["rows"],inv["term"])
remaining=sorted(U-canon-term-set(ids729))
assert len(remaining)==903
assert sha256(json.dumps(remaining).encode()).hexdigest()==res["universe"]["remaining_ids_sha256"]=="55aaed45750bff64ad9cf91d84668a2eaa3a1c614048e718ee8238ce45feadd4"
assert not {x["case_id"] for x in c}&term

cmap={}
def add(key, path):
    k=key.lower()
    if k not in cmap:
        cmap[k]=path
for base, split in [
    (Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos"), "__"),
    (Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones"), "__"),
    (Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos"), "__"),
]:
    if base.is_dir():
        for p in base.iterdir():
            if p.is_dir() and split in p.name:
                owner,repo=p.name.split(split,1)
                add(f"{owner}/{repo}", p)
REPOS=Path("/home/hanqing/.cache/cve-analyzer/repos")
if REPOS.is_dir():
    for p in REPOS.iterdir():
        if p.is_dir() and "_" in p.name:
            owner,repo=p.name.split("_",1)
            add(f"{owner}/{repo}", p)
WORKER=Path("/home/hanqing/.cache/ghsa200-worker-clones")
if WORKER.is_dir():
    for clone in list(WORKER.glob("*/clones/*"))+list(WORKER.glob("*/*/clones/*"))+list(WORKER.glob("*/repos/*")):
        if clone.is_dir() and "__" in clone.name:
            owner,repo=clone.name.split("__",1)
            add(f"{owner}/{repo}", clone)

MADE=re.compile(r"^Made-with:[ \t]*Cursor[ \t]*$", re.I)
OC_CO=re.compile(r"^Co-Authored-By:[ \t]*opencode[ \t]+<noreply@opencode\.ai>[ \t]*$", re.I)

for row in c:
    clone=cmap[row["repository"].lower()]
    sha=row["candidate_sha"]
    assert git(clone,"cat-file","-t",sha, timeout=12).stdout.strip()=="commit"
    show=git(clone,"log","-1","--format=%H%n%an%n%ae%n%cn%n%ce%n%aI%n%P%n%B",sha, timeout=12)
    parts=show.stdout.split("\n",7)
    info=CommitInfo(sha=parts[0].strip().lower(), author_name=parts[1], author_email=parts[2], committer_name=parts[3], committer_email=parts[4], authored_date=parts[5].strip(), message=parts[7])
    assert matches_for_commit(info)==()
    lines=[ln.rstrip() for ln in info.message.splitlines()]
    if row["pattern_id"]=="cursor_made_with_hyphen_trailer":
        assert any(MADE.match(l) for l in lines)
    elif row["pattern_id"]=="opencode_noreply_coauthor":
        assert any(OC_CO.match(l) for l in lines)
    pars=git(clone,"rev-list","--parents","-n","1",sha, timeout=12).stdout.split()
    assert max(0,len(pars)-1)==row["n_parents"]==1
    if row["probe_fix"] and row["ancestry_raw"]=="YES":
        assert git(clone,"merge-base","--is-ancestor",sha,row["probe_fix"], timeout=12).returncode==0
    if row["case_id"]=="GHSA-MQXV-9RM6-W8QC" and sha.startswith("3f8fb150"):
        names=set(git(clone,"diff-tree","--no-commit-id","--name-only","-r",sha, timeout=12).stdout.splitlines())
        assert "internal/i18n/i18n.go" not in names

assert h(OWN/"cases.jsonl")==res["artifact_hashes"]["cases.jsonl"]
assert h(OWN/"marker_hits.jsonl")==res["artifact_hashes"]["marker_hits.jsonl"]
assert h(OWN/"report.md")==res["artifact_hashes"]["report.md"]
assert h(OWN/"replay.zsh")==res["artifact_hashes"]["replay.zsh"]
print("REPLAY_OK universe=8757 remaining=903 inspected=100 ROUTE=none PASS=0 canonical94=94 equation=8757=75+7779+0+903")
PY
