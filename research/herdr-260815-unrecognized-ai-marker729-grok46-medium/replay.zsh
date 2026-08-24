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
OWN=ROOT/"autoresearch/herdr-260815-unrecognized-ai-marker729-grok46-medium"
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
assert len(PACKETS)==13==res["conservation"]["n_source_packets"]

names=sorted(p.name for p in OWN.iterdir() if p.is_file())
assert names==["cases.jsonl","marker_inventory.jsonl","replay.zsh","report.md","result.json"], names
assert not (OWN/"work").exists()

cred_re=re.compile(r"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]{0,20}PRIVATE KEY)")
for p in OWN.iterdir():
    if p.is_file():
        data=p.read_bytes()
        assert all(b<128 for b in data), p.name
        text=data.decode("ascii")
        assert not cred_re.search(text), p.name

rows=[]
seen=[]
for name in PACKETS:
    path=ROOT/"autoresearch"/name/"assignment.jsonl"
    n=0
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        row=json.loads(line)
        cid=row["case_id"]
        assert cid not in seen
        seen.append(cid)
        rows.append(row)
        n+=1
    assert n in (60,9)
assert len(rows)==729==len(set(seen))
ids=sorted(set(seen))
assert sha256(json.dumps(ids).encode()).hexdigest()==res["bucket_reconstruction"]["no_pre_fix_ids_sha256"]=="ffeceb62c6fa243e5865020390ba5de297d01ce3fc0ac1c9754f46d2739c63b1"
src=json.loads((SRC/"result.json").read_text())
assert src["buckets"]["no_pre_fix_ai_marker"]==729
canon=set(str(x).upper() for x in json.loads((ROOT/"autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json").read_text())["strict_released_case_ids"])
assert len(canon)==94==res["canonical94_strict_count"]
assert not set(ids)&canon

c=[json.loads(l) for l in (OWN/"cases.jsonl").read_text().splitlines() if l.strip()]
inv=[json.loads(l) for l in (OWN/"marker_inventory.jsonl").read_text().splitlines() if l.strip()]
assert all(x.get("never_pass") and x.get("routing_only") for x in c)
assert all(x.get("proposed_pass") is False for x in c)
assert "PASS" not in {x.get("verdict") for x in c}
assert [x["verdict"] for x in c]==["REJECT_ROUTING","ROUTE","REJECT_ROUTING","REJECT_ROUTING"]
assert res["route_ids"]==["GHSA-V273-448J-V4QJ"]
assert res["counts"]["PASS"]==0 and res["counts"]["ROUTE"]==1 and res["pass_proposals"]==[]
assert res["conservation"]["equation"]=="3=1+2+0"
assert res["conservation"]["bucket_equation"]=="729=1+2+726"
assert res["conservation"]["holds"]
text=(OWN/"report.md").read_text()
assert "does not call a PASS" in text
assert "Matcher policy is not edited" in text
assert "GHSA-V273-448J-V4QJ" in text
assert "ROUTE IDs" in text

sys.path.insert(0, str(ROOT/"cve-analyzer/src"))
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit
assert MATCHER_CONTRACT==res["matcher_contract"]

# synthetic first-party forms still miss
samples=[
    CommitInfo(sha="a"*40, author_name="x", author_email="y@z.com", committer_name="x", committer_email="y@z.com", authored_date="2026-04-06T00:00:00Z", message="subject\n\nMade-with: Cursor\n"),
    CommitInfo(sha="b"*40, author_name="x", author_email="y@z.com", committer_name="x", committer_email="y@z.com", authored_date="2026-06-02T00:00:00Z", message="subject\n\nCo-Authored-By: opencode <noreply@opencode.ai>\n"),
    CommitInfo(sha="c"*40, author_name="x", author_email="y@z.com", committer_name="x", committer_email="y@z.com", authored_date="2026-06-02T00:00:00Z", message="subject\n\nGenerated with [opencode](https://opencode.ai)\n"),
]
for info in samples:
    assert matches_for_commit(info)==()

accepted=[x for x in inv if x.get("accepted") is True]
assert {x["pattern_id"] for x in accepted}=={
    "cursor_made_with_hyphen_trailer",
    "cursor_made_with_help_spacing",
    "opencode_noreply_coauthor",
    "opencode_generated_with_markdown_footer",
}
assert all("https://" in " ".join(x["first_party_sources"]) for x in accepted)

REPOS=Path("/home/hanqing/.cache/cve-analyzer/repos")
WORKER=Path("/home/hanqing/.cache/ghsa200-worker-clones")
cmap={}
if REPOS.is_dir():
    for p in REPOS.iterdir():
        if p.is_dir() and "_" in p.name:
            owner,repo=p.name.split("_",1)
            cmap.setdefault(f"{owner}/{repo}".lower(), p)
if WORKER.is_dir():
    for clone in list(WORKER.glob("*/clones/*"))+list(WORKER.glob("*/*/clones/*")):
        if clone.is_dir() and "__" in clone.name:
            owner,repo=clone.name.split("__",1)
            cmap.setdefault(f"{owner}/{repo}".lower(), clone)

GIT_ENV={"PATH":"/usr/local/bin:/usr/bin:/bin","GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0","GIT_NO_LAZY_FETCH":"1","GIT_PAGER":"cat","LC_ALL":"C","GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null","GIT_CONFIG_SYSTEM":"/dev/null"}
SHA_RE=re.compile(r"^[0-9a-f]{40}$")
MADE=re.compile(r"^Made-with:[ \t]*Cursor[ \t]*$", re.I)

def git(repo,*args,timeout=20):
    p=subprocess.run(["/usr/bin/git","--no-optional-locks","-c","gc.auto=0","-c","maintenance.auto=false","-C",str(repo),*args],capture_output=True,env=GIT_ENV,timeout=timeout)
    class R: pass
    r=R(); r.returncode=p.returncode
    r.stdout=(p.stdout or b"").decode("utf-8","replace")
    r.stderr=(p.stderr or b"").decode("utf-8","replace")
    return r

want_shas=set(res["exact_candidate_shas"])
assert want_shas=={
    "2def22c85ea7a13cf5e9f682fef412774a184e8e",
    "529dd67eeb6b125637623d6a723601f0938d3613",
    "c4711a9b694938fbcc32b30ffd6b72576f0901fc",
}
by_id={r["case_id"]: r for r in rows}
seen_cand=set()
for row in c:
    adv=by_id[row["case_id"]]
    clone=cmap[adv["repository"].lower()]
    sha=row["candidate_sha"]
    assert SHA_RE.match(sha)
    seen_cand.add(sha)
    assert git(clone,"cat-file","-t",sha).stdout.strip()=="commit"
    fix=adv["probe_fix"]
    assert git(clone,"cat-file","-t",fix).stdout.strip()=="commit"
    assert git(clone,"merge-base","--is-ancestor",sha,fix).returncode==0
    show=git(clone,"show","-s","--format=%H%n%an%n%ae%n%cn%n%ce%n%aI%n%B",sha)
    parts=show.stdout.split("\n",6)
    info=CommitInfo(sha=parts[0].strip().lower(), author_name=parts[1], author_email=parts[2], committer_name=parts[3], committer_email=parts[4], authored_date=parts[5].strip(), message=parts[6])
    assert matches_for_commit(info)==()
    assert any(MADE.match(l.rstrip()) for l in info.message.splitlines())
    pars=git(clone,"rev-list","--parents","-n","1",sha).stdout.split()
    assert max(0,len(pars)-1)==row["n_parents"]==1
    fnames=git(clone,"diff-tree","--no-commit-id","--name-only","-r",sha).stdout.splitlines()
    fixnames=git(clone,"diff-tree","--no-commit-id","--name-only","-r",fix).stdout.splitlines()
    overlap=sorted(set(fnames)&set(fixnames))
    assert overlap==row["overlap_paths"]
    if row["case_id"]=="GHSA-V273-448J-V4QJ":
        assert "src/fs/loader.ts" in overlap
        parent_blob=git(clone,"show",f"{sha}^:src/fs/loader.ts").stdout
        assert "type !== LookupType.Root" in parent_blob
assert seen_cand==want_shas

ADV=Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database")
assert git(ADV,"rev-parse","HEAD").stdout.strip()==res["advisory_database"]["head"]
assert git(ADV,"rev-parse","HEAD:advisories/github-reviewed").stdout.strip()==res["advisory_database"]["github_reviewed_tree"]

assert h(OWN/"cases.jsonl")==res["artifact_hashes"]["cases.jsonl"]
assert h(OWN/"marker_inventory.jsonl")==res["artifact_hashes"]["marker_inventory.jsonl"]
assert h(OWN/"report.md")==res["artifact_hashes"]["report.md"]
assert h(OWN/"replay.zsh")==res["artifact_hashes"]["replay.zsh"]
print("REPLAY_OK union=729 ROUTE=GHSA-V273-448J-V4QJ PASS=0 canonical94=94 equation=729=1+2+726")
PY
