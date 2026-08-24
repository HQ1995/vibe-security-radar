#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 GIT_NO_LAZY_FETCH=1 GIT_PAGER=cat GIT_ASKPASS= GCM_INTERACTIVE=never
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null HOME=/tmp XDG_CONFIG_HOME=/tmp LC_ALL=C LANG=C
typeset -a _strip_names
_strip_names=()
for _n in ${(k)parameters}; do
  if [[ $_n == *TOKEN* || $_n == *KEY* || $_n == *SECRET* || $_n == *PASSWORD* || $_n == *AUTH* ]]; then
    _strip_names+=("$_n")
  fi
done
for _n in "${_strip_names[@]}"; do
  unset "$_n"
done
unset _n _strip_names
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import json, os, re, shutil, subprocess, sys, tempfile

for k in list(os.environ):
    u = k.upper()
    if any(x in u for x in ("TOKEN", "KEY", "SECRET", "PASSWORD", "AUTH", "CREDENTIAL", "PASSWD", "API_KEY", "BEARER")):
        os.environ.pop(k, None)
os.environ.update({
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp",
    "XDG_CONFIG_HOME": "/tmp",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_PAGER": "cat",
    "GIT_ASKPASS": "",
    "GCM_INTERACTIVE": "never",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "LC_ALL": "C",
    "LANG": "C",
})
ENV = dict(os.environ)

ROOT = Path("/home/hanqing/agents/ai-slop")
OWN = ROOT / "autoresearch/herdr-260814-gn-heavy-tied2-grok46-xhigh"
GN = ROOT / "autoresearch/herdr-260813-ghsa200-commitfirst-gn"
CAN = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical94"
DEF = ROOT / "autoresearch/herdr-260814-gn-heavy-deferred-grok46-xhigh"
CF2 = ROOT / "autoresearch/herdr-260814-cf2-gn-copy-blame-grok46-high"
ADV = Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database")
AR = ROOT / "autoresearch"
HEAVY = ("n8n-io/n8n", "go-gitea/gitea", "jdx/mise", "MervinPraison/PraisonAI", "gogs/gogs")
SKIP = ("/work/", "/notes/", "/pages/", "/snapshot/", "/clones/", "/cache/", "/tmp/")
GHSA = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
TV = {
    "PASS", "PASS_PROPOSAL", "REJECT", "FALSE_POSITIVE", "NARROW", "UNKNOWN",
    "BLOCKED", "FAIL", "CONFIRM", "HOLD_REJECT", "WRONG_EDGE",
}
sys.path.insert(0, str(ROOT / "cve-analyzer/src"))
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

def load_jsonl(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]

def add(dst, x):
    if not x:
        return
    u = str(x).upper()
    if GHSA.match(u):
        dst.add(u)

res = json.loads((OWN / "result.json").read_text())
pins = res["current_input_hashes"]
assert h(ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md") == pins["CONTRACT.md"] == "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"
assert h(CAN / "ledger.jsonl") == pins["canonical94_ledger.jsonl"] == "7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096"
assert h(CAN / "summary.json") == pins["canonical94_summary.json"]
assert h(GN / "cases.jsonl") == pins["gn_cases.jsonl"]
assert h(GN / "result.json") == pins["gn_result.json"]
assert h(GN / "ai-ghsa-intersections.jsonl") == pins["gn_intersections.jsonl"]
assert h(GN / "assigned.jsonl") == pins["gn_assigned.jsonl"]
assert h(GN / "ai-commit-scans.jsonl") == pins["gn_scans.jsonl"]
assert h(GN / "gn-excluded.jsonl") == pins["gn_excluded.jsonl"]
assert h(DEF / "assignment.jsonl") == pins["deferred_assignment.jsonl"]
assert h(DEF / "cases.jsonl") == pins["deferred_cases.jsonl"]
assert h(DEF / "result.json") == pins["deferred_result.json"]
assert h(DEF / "report.md") == pins["deferred_report.md"]
assert h(DEF / "replay.zsh") == pins["deferred_replay.zsh"]
assert h(CF2 / "assignment.jsonl") == pins["cf2_assignment.jsonl"]
assert h(CF2 / "cases.jsonl") == pins["cf2_cases.jsonl"]
assert h(CF2 / "result.json") == pins["cf2_result.json"]
names = sorted(p.name for p in OWN.iterdir() if p.is_file())
assert names == ["assignment.jsonl", "cases.jsonl", "replay.zsh", "report.md", "result.json"], names
assert not (OWN / "work").exists()
for p in OWN.iterdir():
    if p.is_file():
        b = p.read_bytes()
        assert 0 not in b
        b.decode("ascii")
        assert not b.endswith(b" ")
        assert b" \n" not in b
ah = res["artifact_hashes"]
assert h(OWN / "assignment.jsonl") == ah["assignment.jsonl"]
assert h(OWN / "cases.jsonl") == ah["cases.jsonl"]
assert h(OWN / "report.md") == ah["report.md"]
assert h(OWN / "replay.zsh") == ah["replay.zsh"]
want = ["GHSA-RJV5-9PX2-FQW6", "GHSA-W96V-GF22-CRWP"]
a = [json.loads(l) for l in (OWN / "assignment.jsonl").read_text().splitlines() if l.strip()]
c = [json.loads(l) for l in (OWN / "cases.jsonl").read_text().splitlines() if l.strip()]
assert [x["case_id"] for x in a] == [x["case_id"] for x in c] == want == res["assigned_ids"]
assert all(x["verdict"] == "REJECT" for x in c)
assert all(x["proposed_pass"] is False and x["countable_pass"] is False for x in c)
assert all(x["gates"]["ai_hunk_gate"] == "FAIL" for x in c)
assert all(x["gates"]["identity_gate"] == "PASS" for x in c)
assert all(x["gates"]["uniqueness_gate"] == "PASS" for x in c)
assert all(x["gates"]["fix_reversal_gate"] == "PASS" for x in c)
assert all(x["gates"]["topology_gate"] == "PASS" for x in c)
assert all(x["gates"]["but_for_gate"] == "FAIL" for x in c)
assert all(x["gates"]["release_gate"] == "FAIL" for x in c)
assert all(x["inherited_verdict_forbidden"] is True for x in a)
assert res["counts"]["PASS"] == 0 and res["pass_proposals"] == []
assert res["conservation"]["equation"] == "2=2+0" and res["conservation"]["holds"]
assert res["conservation"]["assigned"] == 2 and res["conservation"]["reviewed"] == 2 and res["conservation"]["unreviewed"] == 0
assert res["canonical94_strict_count"] == 94
assert MATCHER_CONTRACT == res["matcher_contract"]
canon = set(str(x).upper() for x in json.loads((CAN / "summary.json").read_text())["strict_released_case_ids"])
assert not set(want) & canon
assert len(canon) == 94
dres = json.loads((DEF / "result.json").read_text())
assert dres["conservation"]["equation"] == "228=12+216"
assert dres["tied_closer_not_in_cap12"] == want
assert dres["remaining_ids_sha256"] == res["remaining_ids_sha256"] == "987dcad828bb11ef6935e3d5b47c9dc71125ee58eb500ee1a825c7ac509d7e81"

post = set()
skip_names = {
    "herdr-260814-gn-heavy-deferred-grok46-xhigh",
    "herdr-260814-gn-heavy-tied2-grok46-xhigh",
}
for d in sorted(AR.iterdir()):
    if not d.is_dir():
        continue
    n = d.name
    if n in skip_names:
        continue
    if not (
        n.startswith("herdr-260813")
        or n.startswith("herdr-260814")
        or n.startswith("orchestrator-260813")
        or n.startswith("orchestrator-260814")
    ):
        continue
    for p in d.rglob("cases.jsonl"):
        rel = "/" + str(p.relative_to(d)).replace("\\", "/")
        if any(s in rel for s in SKIP):
            continue
        for r in load_jsonl(p):
            verd = str(
                r.get("verdict")
                or r.get("worker_verdict")
                or r.get("terminal_verdict")
                or r.get("disposition")
                or ""
            ).upper()
            if verd in TV:
                add(post, r.get("case_id") or r.get("ghsa_id"))
src = set()
for r in load_jsonl(GN / "cases.jsonl"):
    add(src, r.get("case_id"))
cf2 = set()
for r in load_jsonl(CF2 / "assignment.jsonl"):
    add(cf2, r.get("case_id"))
ix = load_jsonl(GN / "ai-ghsa-intersections.jsonl")
assigned = {r["ghsa_id"].upper(): r for r in load_jsonl(GN / "assigned.jsonl")}
so = [r for r in ix if r.get("subject_overlap_hits") and not r.get("matched_ai_commit_refs")]
heavy = [r for r in so if r["repository"] in HEAVY]
excl = canon | src | cf2 | post
remaining = []
for r in heavy:
    gid = r["ghsa_id"].upper()
    if gid in excl:
        continue
    remaining.append(gid)
remaining.sort()
assert len(heavy) == 294
assert len(remaining) == 228
assert sha256(("\n".join(remaining) + "\n").encode()).hexdigest() == res["remaining_ids_sha256"]
assert set(want).issubset(set(remaining))

def git(repo, *args, timeout=12):
    p = subprocess.run(
        ["git", "-C", str(repo), *args],
        env=ENV,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return p.returncode, p.stdout.decode().strip()

scans = {s["repository"]: s for s in load_jsonl(GN / "ai-commit-scans.jsonl")}
closer_ok = []
for gid in remaining:
    rec = assigned.get(gid) or {}
    repo = rec.get("repository")
    clone = (scans.get(repo) or {}).get("path")
    refs = list(rec.get("commit_refs") or [])[:2]
    ok = False
    if clone and Path(clone).is_dir():
        for ref in refs:
            rc, sha = git(clone, "rev-parse", "--verify", ref + "^{commit}")
            if rc != 0:
                continue
            rc2, parts = git(clone, "rev-list", "--parents", "-n", "1", sha)
            n = max(len(parts.split()) - 1, 0) if rc2 == 0 else 0
            if n == 1:
                ok = True
                break
    if ok:
        closer_ok.append(gid)
assert closer_ok[:12] == dres["assigned_ids"]
assert closer_ok[12:] == want == res["tied_closer_not_in_cap12"]
assert len(closer_ok) == 14

NOISE = re.compile(
    r"^(warning: |hint: |From https://|From git://|error: unable to normalize alternate object path:|Cloning into)"
)

def run(args, timeout=120):
    p = subprocess.run(args, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    err = "\n".join(x for x in p.stderr.decode("utf-8", "replace").splitlines() if x and not NOISE.match(x))
    return p.returncode, p.stdout.decode().strip(), err

def gitdir(tmp, *args, timeout=120):
    return run(
        ["git", "--git-dir=" + tmp, "-c", "credential.helper=", "-c", "gc.auto=0", *args],
        timeout=timeout,
    )

def fetch_shas(url, shas):
    tmp = tempfile.mkdtemp(prefix="tied2-replay-")
    rc, out, err = run(
        ["git", "-c", "credential.helper=", "-c", "init.defaultBranch=main", "init", "-q", "--bare", tmp]
    )
    assert rc == 0 and err == "", err
    for sha in shas:
        rc, out, err = gitdir(tmp, "fetch", "--quiet", "--no-tags", "--depth=2", url, sha)
        if rc != 0:
            rc, out, err = gitdir(tmp, "fetch", "--quiet", "--no-tags", "--depth=1", url, sha)
        assert rc == 0 and err == "", err[:200]
    return tmp

def matcher_on(tmp, sha):
    rc, raw, err = gitdir(tmp, "log", "-1", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%aI%x00%B", sha)
    assert rc == 0 and err == ""
    parts = raw.split(chr(0))
    ci = CommitInfo(
        sha=parts[0],
        author_name=parts[1],
        author_email=parts[2],
        committer_name=parts[3],
        committer_email=parts[4],
        authored_date=parts[5],
        message=parts[6],
    )
    return matches_for_commit(ci)

po = res["pinned_objects"]["GHSA-RJV5-9PX2-FQW6"]
tmp = fetch_shas(
    "https://github.com/gogs/gogs.git",
    [po["closer"], po["parent"], po["intro"], po["pr_tip"], po["tag_vulnerable"], po["tag_fixed"]],
)
try:
    rc, got, err = gitdir(tmp, "rev-parse", po["closer"])
    assert rc == 0 and got == po["closer"]
    rc, got, err = gitdir(tmp, "rev-parse", po["parent"])
    assert rc == 0 and got == po["parent"]
    rc, got, err = gitdir(tmp, "rev-parse", po["closer"] + "^{tree}")
    assert rc == 0 and got == po["closer_tree"]
    rc, got, err = gitdir(tmp, "rev-parse", po["parent"] + "^{tree}")
    assert rc == 0 and got == po["parent_tree"]
    rc, parts, err = gitdir(tmp, "rev-list", "--parents", "-n", "1", po["closer"])
    assert parts.split() == [po["closer"], po["parent"]]
    assert matcher_on(tmp, po["closer"]) == ()
    assert matcher_on(tmp, po["intro"]) == ()
    assert matcher_on(tmp, po["pr_tip"]) == ()
    path = "internal/route/api/v1/api.go"
    rc, got, err = gitdir(tmp, "rev-parse", po["closer"] + ":" + path)
    assert rc == 0 and got == po["blobs"][path]["fixed"]
    rc, got, err = gitdir(tmp, "rev-parse", po["parent"] + ":" + path)
    assert rc == 0 and got == po["blobs"][path]["parent"]
    rc, got, err = gitdir(tmp, "rev-parse", po["tag_vulnerable"] + ":" + path)
    assert rc == 0 and got == po["blobs"][path]["parent"]
    rc, txt, err = gitdir(tmp, "show", po["parent"] + ":" + path)
    assert 'm.Delete("/:username/:reponame", repoAssignment(), repo.Delete)' in txt
    assert "reqRepoOwner" not in txt
    rc, txt, err = gitdir(tmp, "show", po["closer"] + ":" + path)
    assert 'm.Delete("/:username/:reponame", repoAssignment(), reqRepoOwner(), repo.Delete)' in txt
    rc, txt, err = gitdir(tmp, "show", po["tag_fixed"] + ":" + path)
    assert 'm.Delete("/:username/:reponame", repoAssignment(), reqRepoOwner(), repo.Delete)' in txt
    rc, out, err = run(
        ["git", "-c", "credential.helper=", "ls-remote", "--tags", "https://github.com/gogs/gogs.git", "v0.13.3", "v0.13.4"]
    )
    assert rc == 0 and err == ""
    assert "5084b4a9b77a506f5e287e82e945e1c6882b827a\trefs/tags/v0.13.3" in out
    assert "d958a47a0e9d8747e399c687fdb3ec64a3b1a736\trefs/tags/v0.13.4" in out
    assert h(ADV / po["advisory_path"]) == po["advisory_sha256"] == res["first_party_advisory_sha256"]["GHSA-RJV5-9PX2-FQW6"]
    adv = json.loads((ADV / po["advisory_path"]).read_text())
    assert adv["id"].upper() == "GHSA-RJV5-9PX2-FQW6"
    assert adv["database_specific"]["github_reviewed"] is True
    assert not adv.get("withdrawn")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

po = res["pinned_objects"]["GHSA-W96V-GF22-CRWP"]
tmp = fetch_shas(
    "https://github.com/n8n-io/n8n.git",
    [
        po["closer"],
        po["parent"],
        po["intro"],
        po["pr_member_fix"],
        po["pr_member_followup"],
        po["tag_vulnerable"],
        po["tag_fixed"],
    ],
)
try:
    rc, got, err = gitdir(tmp, "rev-parse", po["closer"])
    assert rc == 0 and got == po["closer"]
    rc, got, err = gitdir(tmp, "rev-parse", po["parent"])
    assert rc == 0 and got == po["parent"]
    rc, got, err = gitdir(tmp, "rev-parse", po["closer"] + "^{tree}")
    assert rc == 0 and got == po["closer_tree"]
    rc, got, err = gitdir(tmp, "rev-parse", po["parent"] + "^{tree}")
    assert rc == 0 and got == po["parent_tree"]
    rc, parts, err = gitdir(tmp, "rev-list", "--parents", "-n", "1", po["closer"])
    assert parts.split() == [po["closer"], po["parent"]]
    assert matcher_on(tmp, po["closer"]) == ()
    assert matcher_on(tmp, po["intro"]) == ()
    assert matcher_on(tmp, po["pr_member_fix"]) == ()
    assert matcher_on(tmp, po["pr_member_followup"]) == ()
    path = "packages/nodes-base/nodes/Webhook/utils.ts"
    tpath = "packages/nodes-base/nodes/Webhook/test/utils.test.ts"
    rc, got, err = gitdir(tmp, "rev-parse", po["closer"] + ":" + path)
    assert rc == 0 and got == po["blobs"][path]["fixed"]
    rc, got, err = gitdir(tmp, "rev-parse", po["parent"] + ":" + path)
    assert rc == 0 and got == po["blobs"][path]["parent"]
    rc, got, err = gitdir(tmp, "rev-parse", po["closer"] + ":" + tpath)
    assert rc == 0 and got == po["blobs"][tpath]["fixed"]
    rc, got, err = gitdir(tmp, "rev-parse", po["parent"] + ":" + tpath)
    assert rc == 0 and got == po["blobs"][tpath]["parent"]
    rc, got, err = gitdir(tmp, "rev-parse", po["tag_vulnerable"] + ":" + path)
    assert rc == 0 and got == po["blobs"][path]["parent"]
    rc, got, err = gitdir(tmp, "rev-parse", po["tag_fixed"] + ":" + path)
    assert rc == 0 and got == po["blobs"][path]["fixed"]
    rc, txt, err = gitdir(tmp, "show", po["parent"] + ":" + path)
    assert "if (ip?.includes(address))" in txt
    assert "ips.some((entry) => entry.includes(address))" in txt
    rc, txt, err = gitdir(tmp, "show", po["closer"] + ":" + path)
    assert "BlockList" in txt and "node:net" in txt
    assert "allowList.check" in txt
    assert "ip?.includes(address)" not in txt
    rc, out, err = run(
        [
            "git",
            "-c",
            "credential.helper=",
            "ls-remote",
            "--tags",
            "https://github.com/n8n-io/n8n.git",
            "n8n@2.1.4",
            "n8n@2.2.0",
        ]
    )
    assert rc == 0 and err == ""
    assert "57b61bb708d984886518268132a14cc28ab447c9\trefs/tags/n8n@2.1.4" in out
    assert "67e25c890a7817b36190f7b679fb102864fe02c2\trefs/tags/n8n@2.2.0" in out
    assert h(ADV / po["advisory_path"]) == po["advisory_sha256"] == res["first_party_advisory_sha256"]["GHSA-W96V-GF22-CRWP"]
    adv = json.loads((ADV / po["advisory_path"]).read_text())
    assert adv["id"].upper() == "GHSA-W96V-GF22-CRWP"
    assert adv["database_specific"]["github_reviewed"] is True
    assert not adv.get("withdrawn")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

n8n = res["read_only_clones"]["n8n-io/n8n"]
gogs = res["read_only_clones"]["gogs/gogs"]
rc, out = git(gogs, "diff-tree", "--no-commit-id", "--name-only", "-r", "7b7e38c88007a7c482dbf31efff896185fd9b79c")
assert "internal/route/api/v1/api.go" not in out.splitlines()
assert git(
    gogs,
    "merge-base",
    "--is-ancestor",
    "7b7e38c88007a7c482dbf31efff896185fd9b79c",
    res["pinned_objects"]["GHSA-RJV5-9PX2-FQW6"]["closer"],
)[0] != 0
for sha in ["716577e2820deb35b7057eb9414c9fbe9b6b4fde", "d4ef191be0b39b65efa68559a3b8d5dad2e102b2"]:
    rc, out = git(n8n, "diff-tree", "--no-commit-id", "--name-only", "-r", sha)
    files = set(out.splitlines())
    assert not files & {
        "packages/nodes-base/nodes/Webhook/utils.ts",
        "packages/nodes-base/nodes/Webhook/test/utils.test.ts",
    }

text = (OWN / "report.md").read_text()
assert "PASS=0" in text and "2=2+0" in text
assert "228=12+216" in text
assert "Worker PASS is proposal-only" in text
assert "GHSA-RJV5-9PX2-FQW6 REJECT" in text
assert "GHSA-W96V-GF22-CRWP REJECT" in text
print(
    "REPLAY_OK assigned=2 reviewed=2 unreviewed=0 PASS=0 canonical94=94 equation=2=2+0 tied=GHSA-RJV5-9PX2-FQW6,GHSA-W96V-GF22-CRWP source=228=12+216"
)
PY
