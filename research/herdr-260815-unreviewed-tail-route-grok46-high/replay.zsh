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
    lk = k.lower()
    if any(x in lk for x in ("token", "secret", "password", "credential", "api_key", "auth", "gh_token", "github_token")):
        os.environ.pop(k, None)

ROOT = Path("/home/hanqing/agents/ai-slop")
OWN = ROOT / "autoresearch/herdr-260815-unreviewed-tail-route-grok46-high"
SRC = ROOT / "autoresearch/herdr-260814-ghsa200-unreviewed-commitref20-grok46-medium"
CANON_DIR = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical94"
HITS = SRC / "work/remaining-hits.jsonl"
res = json.loads((OWN / "result.json").read_text())
pins = res["current_input_hashes"]

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

assert h(HITS) == pins["remaining-hits.jsonl"]
assert h(SRC / "work/freeze.json") == pins["source_freeze.json"]
assert h(SRC / "result.json") == pins["source_result.json"]
assert h(SRC / "selected.jsonl") == pins["source_selected.jsonl"]
assert h(CANON_DIR / "ledger.jsonl") == pins["canonical94_ledger.jsonl"]
assert h(CANON_DIR / "summary.json") == pins["canonical94_summary.json"]
assert h(ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md") == pins["CONTRACT.md"]

names = sorted(p.name for p in OWN.iterdir() if p.is_file())
assert names == ["assignment.jsonl", "cases.jsonl", "replay.zsh", "report.md", "result.json"], names
for banned in ("work", "notes", "pages", "snapshot", "clones"):
    assert not (OWN / banned).exists()

cred_re = re.compile(
    r"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|gho_[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]{0,20}PRIVATE KEY)"
)
for p in OWN.iterdir():
    if p.is_file():
        data = p.read_bytes()
        assert all(b < 128 for b in data), p.name
        text = data.decode("ascii")
        assert not cred_re.search(text), p.name
        assert not any(ln.endswith(" ") or ln.endswith("\t") for ln in text.splitlines()), p.name

ah = res["artifact_hashes"]
assert h(OWN / "assignment.jsonl") == ah["assignment.jsonl"]
assert h(OWN / "cases.jsonl") == ah["cases.jsonl"]
assert h(OWN / "replay.zsh") == ah["replay.zsh"]
assert h(OWN / "report.md") == ah["report.md"]

a = [json.loads(l) for l in (OWN / "assignment.jsonl").read_text().splitlines() if l.strip()]
c = [json.loads(l) for l in (OWN / "cases.jsonl").read_text().splitlines() if l.strip()]
want = res["inspected_ids"]
assert [x["case_id"] for x in a] == [x["case_id"] for x in c] == want
assert len(want) == 486 == len(set(want))
assert [x["assigned_order"] for x in a] == list(range(1, 487))
assert all(x.get("never_pass") and x.get("routing_only") and x.get("proposed_pass") is False for x in a + c)
assert all(x.get("verdict") == "REJECT_ROUTING" for x in c)
assert all(x.get("first_party_repo_advisory") is False for x in a + c)
assert all(x.get("identity_gate") == "FAIL" for x in a + c)
assert "PASS" not in {x.get("verdict") for x in c}
assert "ROUTE" not in {x.get("verdict") for x in c}
assert res["counts"]["PASS"] == 0 and res["counts"]["ROUTE"] == 0
assert res["pass_proposals"] == [] and res["selected_ids"] == [] and res["route_ids"] == []
assert res["proposed_pass"] is False
assert res["canonical94_strict_count"] == 94
assert res["publication_status"] == "HOLD"
assert res["conservation"]["equation"] == "513=27+486+0"
assert res["conservation"]["assigned_equation"] == "486=486+0"
assert res["conservation"]["holds"] is True
assert res["conservation"]["input"] == 513
assert res["conservation"]["excluded"] == 27
assert res["conservation"]["screened"] == 486
assert res["conservation"]["unknown"] == 0
assert res["conservation"]["assigned"] == 486
assert res["conservation"]["reviewed"] == 486
assert res["conservation"]["unreviewed"] == 0

hits = [json.loads(l) for l in HITS.read_text().splitlines() if l.strip()]
assert len(hits) == 513
input_ids = [r["ghsa_id"].upper() for r in hits]
assert len(set(input_ids)) == 513
assert all(r.get("skip") == "unprobed_after_cap" for r in hits)
assert all(r.get("stream") == "github-unreviewed" and r.get("github_reviewed") is False for r in hits)

canon = json.loads((CANON_DIR / "summary.json").read_text())
canon_ids = [str(x).upper() for x in canon["strict_released_case_ids"]]
assert len(canon_ids) == 94 == canon["canonical_strict_count"]
assert canon.get("status") == "HOLD"
canon_set = set(canon_ids)
assert not (set(input_ids) & canon_set)
assert not (set(want) & canon_set)

GHSA_RE = re.compile(r"GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}")
VERDICTS = {
    "PASS", "NARROW", "REJECT", "UNKNOWN", "BLOCKED", "KEEP", "FAIL",
    "FALSE_POSITIVE", "CONFIRM", "ACCEPT", "HOLD", "REJECT_ROUTING",
    "ROUTE", "TERMINAL", "NOT_SELECTED",
}
SKIP_PARTS = {"work", "notes", "pages", "snapshot", "clones", "cache", "tmp", "node_modules", "diffs", "facts"}
OWN_NAME = "herdr-260815-unreviewed-tail-route-grok46-high"
SKIP_DIR_NAMES = {OWN_NAME, ".leader-quarantine-260814"}

def norm(s):
    m = GHSA_RE.search(str(s or ""))
    return m.group(0).upper() if m else None

auto = ROOT / "autoresearch"

def packet_ok(path):
    rel = path.relative_to(auto)
    top = rel.parts[0]
    if top in SKIP_DIR_NAMES:
        return False
    if any(p in SKIP_PARTS for p in rel.parts[:-1]):
        return False
    return (
        top.startswith("herdr-260813")
        or top.startswith("herdr-260814")
        or top.startswith("herdr-260815")
        or top.startswith("orchestrator-260813")
        or top.startswith("orchestrator-260814")
    )

terminal = set()
selectedish = set()

def consider(row):
    cid = norm(row.get("case_id") or row.get("ghsa_id") or row.get("id"))
    if not cid:
        return
    v = row.get("verdict") or row.get("worker_verdict") or row.get("latest_verdict") or row.get("terminal_verdict")
    if isinstance(v, str) and v.strip().upper() in VERDICTS:
        terminal.add(cid)

for path in sorted(auto.glob("*/cases.jsonl")):
    if not packet_ok(path):
        continue
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            consider(row)

for path in sorted(list(auto.glob("*/*adjudication*.jsonl")) + list(auto.glob("*/*adjudication*.json"))):
    if not packet_ok(path):
        continue
    text = path.read_text(errors="replace")
    chunks = []
    if path.suffix == ".jsonl":
        for l in text.splitlines():
            if l.strip():
                try:
                    chunks.append(json.loads(l))
                except json.JSONDecodeError:
                    pass
    else:
        try:
            chunks = [json.loads(text)]
        except json.JSONDecodeError:
            continue
    for row in chunks:
        if isinstance(row, dict):
            consider(row)

for path in sorted(auto.glob("*/result.json")):
    if not packet_ok(path):
        continue
    try:
        payload = json.loads(path.read_text(errors="replace"))
    except json.JSONDecodeError:
        continue
    if not isinstance(payload, dict):
        continue
    for key in ("remaining_inventory", "cases", "reviewed", "rows"):
        val = payload.get(key)
        if isinstance(val, list):
            for row in val:
                if isinstance(row, dict):
                    consider(row)
    for key in ("inspected_ids", "exact_selected_ids", "reviewed_case_ids", "selected_ids", "frozen_ids"):
        val = payload.get(key)
        if isinstance(val, list):
            for x in val:
                cid = norm(x)
                if cid:
                    selectedish.add(cid)
    cons = payload.get("conservation")
    if isinstance(cons, dict):
        for key in ("reviewed_case_ids", "unreviewed_case_ids"):
            val = cons.get(key)
            if isinstance(val, list):
                for x in val:
                    cid = norm(x)
                    if cid:
                        selectedish.add(cid)

for path in sorted(auto.glob("*/selected.jsonl")):
    if not packet_ok(path):
        continue
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            cid = norm(line)
            if cid:
                selectedish.add(cid)
            continue
        if isinstance(row, dict):
            cid = norm(row.get("case_id") or row.get("ghsa_id") or row.get("id"))
            if cid:
                selectedish.add(cid)

for path in sorted(auto.glob("*/assignment.jsonl")):
    if not packet_ok(path):
        continue
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            cid = norm(row.get("case_id") or row.get("ghsa_id") or row.get("id"))
            if cid:
                selectedish.add(cid)
            consider(row)

explicit = terminal | selectedish
excluded = [gid for gid in input_ids if gid in canon_set or gid in explicit]
screened = [gid for gid in input_ids if gid not in canon_set and gid not in explicit]
assert excluded == res["excluded_ids"]
assert screened == want
assert len(excluded) == 27 and len(screened) == 486
assert 513 == 27 + 486 + 0
assert not (set(excluded) & set(screened))
assert not (set(want) & set(res["excluded_ids"]))
parent20 = res["parent_cap20_ids"]
assert len(parent20) == 20 == len(set(parent20))
assert not (set(input_ids) & set(parent20))

GIT_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_PAGER": "cat",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
}
ADV = Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database")
FREEZE = Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database")

def git(repo, *args, timeout=180):
    p = subprocess.run(
        ["git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-C", str(repo), *args],
        capture_output=True, text=True, env=GIT_ENV, timeout=timeout,
    )
    assert p.returncode == 0, args
    return (p.stdout or "").strip()

assert git(FREEZE, "rev-parse", "HEAD") == res["advisory_database"]["freeze_head"]
assert git(ADV, "rev-parse", "HEAD") == res["advisory_database"]["head"]
assert git(ADV, "rev-parse", "HEAD:advisories/github-reviewed") == res["advisory_database"]["github_reviewed_tree"]
want_names = {gid.lower() + ".json" for gid in want}
names = git(ADV, "ls-tree", "-r", "--name-only", "HEAD", "advisories/github-reviewed")
hits_rev = [n for n in names.splitlines() if Path(n).name.lower() in want_names]
assert hits_rev == [], hits_rev
names_f = git(FREEZE, "ls-tree", "-r", "--name-only", "HEAD", "advisories/github-reviewed")
hits_f = [n for n in names_f.splitlines() if Path(n).name.lower() in want_names]
assert hits_f == [], hits_f

sys.path.insert(0, str(ROOT / "cve-analyzer/src"))
from cve_analyzer.source_matcher import MATCHER_CONTRACT
assert MATCHER_CONTRACT == res["matcher_contract"]

text = (OWN / "report.md").read_text()
assert "does not call a PASS" in text
assert "ROUTE 0" in text
assert "513=27+486+0" in text
assert "486=486+0" in text
assert "Canonical94 remains 94 HOLD" in text
assert "PASS" not in {ln.split()[0] for ln in text.splitlines() if ln.startswith("PASS")}

print("REPLAY_OK inspected=486 ROUTE=0 PASS=0 canonical94=94 HOLD equation=513=27+486+0 assigned=486=486+0")
PY
