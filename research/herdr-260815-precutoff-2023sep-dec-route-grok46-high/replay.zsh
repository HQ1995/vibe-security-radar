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
OWN = ROOT / "autoresearch/herdr-260815-precutoff-2023sep-dec-route-grok46-high"
CANON_DIR = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical94"
res = json.loads((OWN / "result.json").read_text())
pins = res["current_input_hashes"]

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

assert h(ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md") == pins["CONTRACT.md"]
assert h(CANON_DIR / "ledger.jsonl") == pins["canonical94_ledger.jsonl"]
assert h(CANON_DIR / "summary.json") == pins["canonical94_summary.json"]

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
assert len(want) == 300 == len(set(want))
assert [x["assigned_order"] for x in a] == list(range(1, 301))
assert all(x.get("never_pass") and x.get("routing_only") and x.get("proposed_pass") is False for x in a + c)
assert all(x.get("verdict") == "REJECT_ROUTING" for x in c)
assert all(x.get("first_party_repo_advisory") is True for x in a + c)
assert all(x.get("identity_gate") == "PASS" for x in a + c)
assert "PASS" not in {x.get("verdict") for x in c}
assert "ROUTE" not in {x.get("verdict") for x in c}
assert res["counts"]["PASS"] == 0 and res["counts"]["ROUTE"] == 0
assert res["pass_proposals"] == [] and res["selected_ids"] == [] and res["route_ids"] == []
assert res["proposed_pass"] is False
assert res["canonical94_strict_count"] == 94
assert res["publication_status"] == "HOLD"
assert res["conservation"]["equation"] == "1085=34+615+136+0+0+300+0"
assert res["conservation"]["assigned_equation"] == "300=300+0"
assert res["conservation"]["holds"] is True
assert res["conservation"]["input"] == 1085
assert res["conservation"]["assigned"] == 300
assert res["conservation"]["reviewed"] == 300
assert res["conservation"]["unreviewed"] == 0
assert res["conservation"]["unknown"] == 0

canon = json.loads((CANON_DIR / "summary.json").read_text())
canon_ids = [str(x).upper() for x in canon["strict_released_case_ids"]]
assert len(canon_ids) == 94 == canon["canonical_strict_count"]
assert canon.get("status") == "HOLD"
canon_set = set(canon_ids)
assert not (set(want) & canon_set)

GHSA_RE = re.compile(r"GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}")
VERDICTS = {
    "PASS", "NARROW", "REJECT", "UNKNOWN", "BLOCKED", "KEEP", "FAIL",
    "FALSE_POSITIVE", "CONFIRM", "ACCEPT", "HOLD", "REJECT_ROUTING",
    "ROUTE", "TERMINAL", "NOT_SELECTED", "UNREVIEWED",
}
SKIP_PARTS = {"work", "notes", "pages", "snapshot", "clones", "cache", "tmp", "node_modules", "diffs", "facts"}
OWN_NAME = "herdr-260815-precutoff-2023sep-dec-route-grok46-high"
SKIP_DIR_NAMES = {OWN_NAME, ".leader-quarantine-260814"}

def norm(s):
    m = GHSA_RE.search(str(s or ""))
    return m.group(0).upper() if m else None

def packet_ok(path):
    rel = path.relative_to(ROOT / "autoresearch")
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
        or top.startswith("orchestrator-260815")
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

auto = ROOT / "autoresearch"
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
    for key in ("inspected_ids", "exact_selected_ids", "reviewed_case_ids", "selected_ids", "frozen_ids", "queued_ids", "route_ids", "excluded_ids"):
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
assert not (set(want) & explicit)
assert not (set(want) & canon_set)

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

def git(repo, *args, timeout=180):
    p = subprocess.run(
        ["git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-C", str(repo), *args],
        capture_output=True, text=True, env=GIT_ENV, timeout=timeout,
    )
    assert p.returncode == 0, args
    return (p.stdout or "").strip()

assert git(ADV, "rev-parse", "HEAD") == res["advisory_database"]["head"]
assert git(ADV, "rev-parse", "HEAD:advisories/github-reviewed") == res["advisory_database"]["github_reviewed_tree"]

REPO_ADV_RE = re.compile(r"https://github\.com/([^/]+)/([^/]+)/security/advisories/(GHSA-[0-9A-Za-z-]+)", re.I)
COMMIT_RE = re.compile(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})(?:[/?#]|$)")
window = []
withdrawn = no_fp = no_fix = 0
elig = []
reviewed = 0
for path in sorted((ADV / "advisories/github-reviewed").rglob("GHSA-*.json")):
    reviewed += 1
    data = json.loads(path.read_text(errors="replace"))
    pub = str(data.get("published") or "")
    if not (pub >= "2023-09-01" and pub < "2024-01-01"):
        continue
    gid = (data.get("id") or path.stem).upper()
    window.append(gid)
    if data.get("withdrawn"):
        withdrawn += 1
        continue
    refs = []
    for ref in data.get("references") or []:
        u = ref.get("url") if isinstance(ref, dict) else ref
        if isinstance(u, str):
            refs.append(u)
    repo = None
    for u in refs:
        m = REPO_ADV_RE.search(u)
        if m and m.group(3).upper() == gid:
            repo = f"{m.group(1)}/{m.group(2)}"
            break
    if not repo:
        no_fp += 1
        continue
    owner, name = repo.split("/", 1)
    shas = []
    for u in refs:
        m = COMMIT_RE.search(u)
        if m and m.group(1).lower() == owner.lower() and m.group(2).lower() == name.lower():
            shas.append(m.group(3).lower())
    if not shas:
        no_fix += 1
        continue
    elig.append(gid)
assert reviewed == 34389
assert len(window) == 1085 == len(set(window))
assert withdrawn == 34 and no_fp == 615 and no_fix == 136
elig = sorted(elig)
assert elig == want
assert sha256(json.dumps(window).encode()).hexdigest() == res["window_ids_sha256"]
assert sha256(json.dumps(elig).encode()).hexdigest() == res["eligible_ids_sha256"]
assert 1085 == 34 + 615 + 136 + 300

for row in a:
    gid = row["case_id"]
    owner, name = row["repository"].split("/")
    fname = "GHSA-" + gid[5:].lower() + ".json"
    matches = list((ADV / "advisories/github-reviewed").rglob(fname))
    assert matches, gid
    data = json.loads(matches[0].read_text())
    assert str(data.get("published") or "") >= "2023-09-01"
    assert str(data.get("published") or "") < "2024-01-01"
    assert not data.get("withdrawn")
    refs = []
    for ref in data.get("references") or []:
        u = ref.get("url") if isinstance(ref, dict) else ref
        if isinstance(u, str):
            refs.append(u)
    ok_adv = False
    shas = set()
    for u in refs:
        m = REPO_ADV_RE.search(u)
        if m and m.group(3).upper() == gid and f"{m.group(1)}/{m.group(2)}" == row["repository"]:
            ok_adv = True
        m2 = COMMIT_RE.search(u)
        if m2 and m2.group(1).lower() == owner.lower() and m2.group(2).lower() == name.lower():
            shas.add(m2.group(3).lower())
    assert ok_adv
    assert set(row["same_repo_fixes"]) <= shas
    assert set(row["same_repo_fixes"]) == set(c[[x["case_id"] for x in c].index(gid)]["same_repo_fixes"])

reasons = {}
for row in c:
    reasons[row["reject_reason"]] = reasons.get(row["reject_reason"], 0) + 1
assert reasons["no_local_clone"] == 138
assert reasons["closer_not_in_local_clone"] == 1
assert reasons["no_atomic_source_matcher_on_fix_touched_history"] == 161

sys.path.insert(0, str(ROOT / "cve-analyzer/src"))
from cve_analyzer.source_matcher import MATCHER_CONTRACT
assert MATCHER_CONTRACT == res["matcher_contract"]

text = (OWN / "report.md").read_text()
assert "does not call a PASS" in text
assert "ROUTE 0" in text
assert "1085 = 34 withdrawn" in text
assert "300=300+0" in text
assert "Canonical94 remains 94 HOLD" in text
assert "PASS" not in {ln.split()[0] for ln in text.splitlines() if ln.startswith("PASS")}

print("REPLAY_OK inspected=300 ROUTE=0 PASS=0 canonical94=94 HOLD equation=1085=34+615+136+0+0+300+0 assigned=300=300+0")
PY
