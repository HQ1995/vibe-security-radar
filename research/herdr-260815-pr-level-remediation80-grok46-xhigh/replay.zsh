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
    lk = k.lower()
    if any(x in lk for x in ("token", "secret", "password", "credential", "api_key", "auth", "gh_token", "github_token")):
        os.environ.pop(k, None)

ROOT = Path("/home/hanqing/agents/ai-slop")
OWN = ROOT / "autoresearch/herdr-260815-pr-level-remediation80-grok46-xhigh"
CANON_DIR = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical94"
res = json.loads((OWN / "result.json").read_text())
pins = res["current_input_hashes"]

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

assert h(ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md") == pins["CONTRACT.md"] == "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"
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
assert [x["rank"] for x in a] == list(range(1, 29))
assert len(want) == 28 == len(set(want))
assert all(x.get("never_pass") and x.get("routing_only") for x in a + c)
assert all(x.get("verdict") == "REJECT_ROUTING" for x in c)
assert all(x.get("proposed_pass") is False for x in c)
assert "PASS" not in {x.get("verdict") for x in c}
assert "ROUTE" not in {x.get("verdict") for x in c}
assert all(x.get("bot_issue_count") == 0 for x in c)
assert all(x.get("earlier_ai_pr_count") == 0 for x in c)
assert all(x.get("countable_pass") is False for x in c)
assert res["counts"]["PASS"] == 0 and res["counts"]["ROUTE"] == 0
assert res["pass_proposals"] == [] and res["selected_ids"] == []
assert res["route_ids"] == []
assert res["proposed_pass"] is False
assert res["canonical94_strict_count"] == 94
assert res["publication_status"] == "HOLD"
assert res["never_pass"] is True
assert res["conservation"]["holds"] is True
assert res["conservation"]["assigned_equation"] == "28=28+0"
assert res["conservation"]["did_not_pad"] is True
assert res["conservation"]["universe_equation"] == "34389=910+4068+14050+6637+8724"
assert res["conservation"]["eligible_equation"] == "8724=62+7351+0+1311"
assert res["conservation"]["remaining_equation"] == "1311=1283+28"
assert res["conservation"]["inspect_equation"] == "28=14+1+1+5+7"
assert res["conservation"]["full_row_holds"] is True

canon = json.loads((CANON_DIR / "summary.json").read_text())
canon_ids = [str(x).upper() for x in canon["strict_released_case_ids"]]
assert len(canon_ids) == 94 == canon["canonical_strict_count"]
assert canon.get("status") == "HOLD"
canon_set = set(canon_ids)
assert not set(want) & canon_set

sys.path.insert(0, str(ROOT / "cve-analyzer/src"))
from cve_analyzer.source_matcher import MATCHER_CONTRACT
from cve_analyzer.source_policy import AGENT_KIND_AUTONOMOUS, GITHUB_AI_BOT_LOGINS
assert MATCHER_CONTRACT == res["matcher_contract"]
auto_logins = []
for rule in GITHUB_AI_BOT_LOGINS:
    if rule.get("agent_kind") == AGENT_KIND_AUTONOMOUS:
        auto_logins.extend(str(x).lower() for x in rule["logins"])
assert auto_logins == res["autonomous_bot_logins"]

ADV = Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database")
REPOS = Path("/home/hanqing/.cache/cve-analyzer/repos")
WORKER_CLONES = Path("/home/hanqing/.cache/ghsa200-worker-clones")
AUTO = ROOT / "autoresearch"
SKIP_PARTS = {"work", "pages", "snapshot", "clones", "cache", "tmp", "node_modules", "diffs", "facts", "notes"}
SKIP_DIR_NAMES = set(res["inventory"]["skipped_packets"])
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
GHSA_FIND = re.compile(r"GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}")
COMMIT_RE = re.compile(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})(?:[/?#]|$)")
REPO_ADV_RE = re.compile(r"https://github\.com/([^/]+)/([^/]+)/security/advisories/(GHSA-[0-9A-Za-z-]+)", re.I)
GITHUB_REPO_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/?$")
VERDICTS = {
    "PASS", "NARROW", "REJECT", "UNKNOWN", "BLOCKED", "KEEP", "FAIL",
    "FALSE_POSITIVE", "CONFIRM", "ACCEPT", "HOLD", "REJECT_ROUTING",
    "ROUTE", "TERMINAL", "NOT_SELECTED", "UNREVIEWED", "REJECT_ROUTE",
    "KEEP_ROUTE", "FAIL_ROUTE",
}
RESIDUAL_RES = [
    re.compile(p, re.I) for p in [
        r"incomplete\s+(fix|patch|remediation|sanitiz|validat|escape|filter|blocklist|denylist|allowlist|blacklist|whitelist|hardening)",
        r"insufficient(ly)?\s+(sanitiz|validat|escape|filter|neutraliz|check|guard)",
        r"bypass(es|ed|ing)?\s+(of|the)?\s*(the\s+)?(previous|prior|original|earlier|old(er)?)\s+(fix|patch|cve|ghsa|advisory|check|guard|filter|sanitiz)",
        r"(previous|prior|original|earlier)\s+(fix|patch|cve|ghsa|advisory).{0,80}(bypass|incomplete|insufficient|circumvent|residual)",
        r"residual\s+(bypass|path|issue|vulnerability|xss|ssrf|injection|hole|check)",
        r"incomplete\s+fix\s+for\s+(cve|ghsa)",
        r"follow[- ]up\s+(to|of)\s+(cve|ghsa|advisory)",
        r"did\s+not\s+(fully\s+)?(cover|close|fix|address|block)",
        r"omitted\s+(case|scheme|protocol|character|check|path)",
        r"(blocklist|denylist|allowlist|blacklist|whitelist)\s+bypass",
        r"partial\s+(fix|patch|remediation)",
        r"still\s+(vulnerable|exploitable|possible|bypass)",
        r"circumvent(s|ed|ing)?\s+(the\s+)?(fix|patch|guard|check|filter|sanitiz)",
        r"the\s+(previous|prior|original|earlier)\s+(fix|patch)\s+(is|was|can be|could be)\s+(bypass|incomplete)",
        r"bypass(es|ed)?\s+the\s+(fix|patch|guard|sanitiz|validat|filter|check)",
    ]
]
CODE_EXT = {".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".swift", ".ts", ".tsx", ".vue", ".zig", ".mjs", ".cjs"}
TEST_HINT = re.compile(r"(^|/)(test|tests|spec|specs|__tests__|testdata|fixtures)(/|$)", re.I)
NOISE_NAMES = {
    "package.json", "package-lock.json", "pnpm-lock.yaml", "pnpm-workspace.yaml",
    "yarn.lock", "cargo.lock", "go.sum", "go.mod", "poetry.lock", "composer.lock",
    "gemfile.lock", "changelog.md", "changelog", "license", "license.md",
    "readme.md", "readme", "security.md", ".gitignore", ".npmignore",
}
IR_PACKETS = [
    "herdr-260814-ghsa200-incomplete-remediation20-grok46-low",
    "herdr-260814-ghsa200-incomplete-remediation20b-grok46-low",
    "herdr-260814-ghsa200-incomplete-remediation20c-grok46-low",
    "herdr-260814-ghsa200-incomplete-remediation20d-grok46-low",
    "herdr-260814-ghsa200-incomplete-remediation20e-grok46-low",
    "herdr-260814-ghsa200-incomplete-remediation20f-grok46-low",
    "herdr-260814-ghsa200-incomplete-remediation20g-grok46-low",
    "herdr-260814-ghsa200-incomplete-remediation20h-grok46-low",
    "herdr-260814-ghsa200-incomplete-remediation20i-grok46-low",
    "herdr-260814-ghsa200-incomplete-remediation20j-grok46-low",
    "herdr-260814-ghsa200-incomplete-remediation20k-grok46-low",
    "herdr-260814-ghsa200-incomplete-remediation20l-grok46-high",
    "herdr-260814-ghsa200-incomplete-remediation20m-final8-grok46-low",
]
FRESH_PACKETS = [
    "herdr-260814-fresh-incomplete-remediation-grok46-medium",
    "herdr-260814-fresh-remediation-wave2-grok46-medium",
    "herdr-260814-fresh-remediation-unknowns-grok46-medium",
]
FROZEN_FILES = (
    "cases.jsonl", "candidates.jsonl", "selection.jsonl", "assignment.jsonl",
    "work/selected-20.jsonl", "work/selected-8.jsonl", "work/freeze.json",
    "work/freeze30.json",
)
GIT_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1", "GIT_PAGER": "cat", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}

def git(repo, *args, timeout=20):
    p = subprocess.run(["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-C", str(repo), *args], capture_output=True, env=GIT_ENV, timeout=timeout)
    class R: pass
    r = R(); r.returncode = p.returncode
    r.stdout = (p.stdout or b"").decode("utf-8", "replace")
    r.stderr = (p.stderr or b"").decode("utf-8", "replace")
    return r

assert git(ADV, "rev-parse", "HEAD").stdout.strip() == res["advisory_database"]["head"]
assert git(ADV, "rev-parse", "HEAD:advisories/github-reviewed").stdout.strip() == res["advisory_database"]["github_reviewed_tree"]

def norm_ghsa(v):
    if not isinstance(v, str):
        return None
    s = v.strip().upper()
    return s if GHSA_RE.match(s) else None

def consider_factory(terminal):
    rows = [0]
    def consider(row):
        rows[0] += 1
        cid = None
        m = GHSA_FIND.search(str(row.get("case_id") or row.get("ghsa_id") or row.get("id") or ""))
        if m:
            cid = m.group(0).upper()
        if not cid:
            return
        v = row.get("verdict") or row.get("worker_verdict") or row.get("latest_verdict") or row.get("terminal_verdict")
        if isinstance(v, str) and v.strip().upper() in VERDICTS:
            terminal.add(cid)
    return consider, rows

terminal = set()
files = 0; casesn = 0; adj = 0; resf = 0
consider, rows = consider_factory(terminal)
pinned = res["inventory"]["source_relpaths"]
assert pinned == sorted(pinned)
assert len(pinned) == len(set(pinned))
assert sha256(json.dumps(pinned).encode()).hexdigest() == res["inventory"]["source_relpaths_sha256"]
assert len(pinned) == res["inventory"]["files"]
assert not any(rel.split("/")[0] in SKIP_DIR_NAMES for rel in pinned)
for rel in pinned:
    assert not rel.startswith("herdr-260815-pr-level-remediation80-grok46-xhigh/")
    assert not rel.startswith("herdr-260815-remediation-reverse80-grok46-xhigh/")
    assert not any(p in SKIP_PARTS for p in Path(rel).parts[:-1]), rel
    path = AUTO / rel
    assert path.is_file(), rel
    name = Path(rel).name
    if name == "cases.jsonl":
        files += 1; casesn += 1
        for line in path.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                consider(row)
    elif "adjudication" in name:
        files += 1; adj += 1
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
    elif name == "result.json":
        files += 1; resf += 1
        try:
            payload = json.loads(path.read_text(errors="replace"))
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        consider(payload)
        for key in ("remaining_inventory", "cases", "reviewed", "rows"):
            val = payload.get(key)
            if isinstance(val, list):
                for row in val:
                    if isinstance(row, dict):
                        consider(row)
    else:
        raise AssertionError(rel)
assert files == res["inventory"]["files"] == 728
assert casesn == res["inventory"]["cases_files"]
assert adj == res["inventory"]["adj_files"]
assert resf == res["inventory"]["result_files"]
assert rows[0] == res["inventory"]["rows_parsed"]
assert len(terminal) == res["inventory"]["terminal_verdict_identities"] == 12467

def harvest_ids(obj, out):
    if isinstance(obj, str):
        for m in GHSA_FIND.finditer(obj):
            out.add(m.group(0).upper())
    elif isinstance(obj, dict):
        for v in obj.values():
            harvest_ids(v, out)
    elif isinstance(obj, list):
        for v in obj:
            harvest_ids(v, out)

def freeze_ids_from_packet(name):
    ids = set()
    d = AUTO / name
    assert d.is_dir(), name
    for rel in FROZEN_FILES:
        p = d / rel
        if not p.is_file():
            continue
        if p.suffix == ".jsonl":
            for line in p.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    harvest_ids(line, ids)
                    continue
                if isinstance(row, dict):
                    cid = norm_ghsa(row.get("case_id") or row.get("ghsa_id") or row.get("id") or "")
                    if cid:
                        ids.add(cid)
                    else:
                        harvest_ids(row, ids)
        else:
            try:
                obj = json.loads(p.read_text(errors="replace"))
            except json.JSONDecodeError:
                harvest_ids(p.read_text(errors="replace"), ids)
                continue
            harvest_ids(obj, ids)
    rj = d / "result.json"
    if rj.is_file():
        obj = json.loads(rj.read_text())
        for key in ("selected_ids", "reviewed_ids", "fully_closed_ids", "assigned_ids", "inspected_ids", "route_ids"):
            val = obj.get(key)
            if isinstance(val, list):
                for x in val:
                    cid = norm_ghsa(str(x) if not isinstance(x, str) else x)
                    if cid:
                        ids.add(cid)
    return {x for x in ids if GHSA_RE.match(x)}

frozen_ir = set()
for name in IR_PACKETS:
    frozen_ir |= freeze_ids_from_packet(name)
frozen_fresh = set()
for name in FRESH_PACKETS:
    frozen_fresh |= freeze_ids_from_packet(name)
frozen_all = frozen_ir | frozen_fresh
assert sha256(json.dumps(sorted(frozen_ir)).encode()).hexdigest() == res["identity_lists"]["frozen_ir_sha256"]
assert sha256(json.dumps(sorted(frozen_fresh)).encode()).hexdigest() == res["identity_lists"]["frozen_fresh_sha256"]
assert sha256(json.dumps(sorted(frozen_all)).encode()).hexdigest() == res["identity_lists"]["frozen_union_sha256"]
assert len(frozen_ir) == 249
assert len(frozen_fresh) == 42
assert len(frozen_all) == 291
for key, path in res["frozen_source_hashes"].items():
    assert h(ROOT / path) == pins[key], key

def parse_advisory(path):
    data = json.loads(path.read_text(errors="replace"))
    gid = norm_ghsa(data.get("id") or path.stem)
    if not gid:
        return None
    repos = set()
    for aff in data.get("affected") or []:
        for ver in (aff or {}).get("ranges") or []:
            repo = ((ver or {}).get("repo")) or ""
            if isinstance(repo, str) and "github.com/" in repo:
                m = re.search(r"github\.com/([^/]+)/([^/#?]+)", repo)
                if m:
                    repos.add(f"{m.group(1)}/{m.group(2).removesuffix('.git')}")
    refs = []
    for ref in data.get("references") or []:
        url = ref.get("url") if isinstance(ref, dict) else ref
        if isinstance(url, str):
            refs.append(url)
    same = []; repo_adv = []; github_repo = None
    for url in refs:
        m = REPO_ADV_RE.search(url)
        if m and m.group(3).upper() == gid:
            github_repo = f"{m.group(1)}/{m.group(2)}"
            repo_adv.append(url.split("#")[0].split("?")[0])
        m2 = GITHUB_REPO_RE.match(url.rstrip("/"))
        if m2 and github_repo is None:
            github_repo = f"{m2.group(1)}/{m2.group(2)}"
    if not github_repo and repos:
        github_repo = sorted(repos)[0]
    if github_repo:
        owner, name = github_repo.split("/", 1)
        for url in refs:
            m = COMMIT_RE.search(url)
            if m and m.group(1).lower() == owner.lower() and m.group(2).lower() == name.lower():
                same.append(m.group(3).lower())
    blob = (data.get("summary") or "") + "\n" + (data.get("details") or "")
    residual_patterns = [rx.pattern for rx in RESIDUAL_RES if rx.search(blob)]
    return {
        "case_id": gid,
        "withdrawn": bool(data.get("withdrawn")),
        "repository": github_repo,
        "same_repo_fixes": sorted(set(same)),
        "repo_advisory_urls": sorted(set(repo_adv)),
        "published": data.get("published") or "",
        "residual_hit_count": len(residual_patterns),
    }

reviewed = 0
window = []
for path in (ADV / "advisories/github-reviewed").rglob("GHSA-*.json"):
    row = parse_advisory(path)
    if not row:
        continue
    reviewed += 1
    window.append(row)
assert reviewed == 34389

buckets = Counter()
eligible = []
for row in window:
    if row["withdrawn"]:
        buckets["withdrawn"] += 1
        continue
    if not row["repository"]:
        buckets["no_repository"] += 1
        continue
    if not row["same_repo_fixes"]:
        buckets["no_same_repo_fix"] += 1
        continue
    if not row["repo_advisory_urls"]:
        buckets["no_first_party_repo_advisory"] += 1
        continue
    eligible.append(row)
assert buckets["withdrawn"] == 910
assert buckets["no_repository"] == 4068
assert buckets["no_same_repo_fix"] == 14050
assert buckets["no_first_party_repo_advisory"] == 6637
assert len(eligible) == 8724
elig_ids = sorted(r["case_id"] for r in eligible)
assert sha256(json.dumps(elig_ids).encode()).hexdigest() == res["identity_lists"]["eligible_ids_sha256"]
excl_canon = sorted(r["case_id"] for r in eligible if r["case_id"] in canon_set)
assert len(excl_canon) == 62
assert sha256(json.dumps(excl_canon).encode()).hexdigest() == res["identity_lists"]["excl_canon_sha256"]
excl_term = sorted(r["case_id"] for r in eligible if r["case_id"] in terminal and r["case_id"] not in canon_set)
assert len(excl_term) == 7351
assert sha256(json.dumps(excl_term).encode()).hexdigest() == res["identity_lists"]["excl_term_sha256"]
excl_frozen = sorted(r["case_id"] for r in eligible if r["case_id"] in frozen_all and r["case_id"] not in canon_set and r["case_id"] not in terminal)
assert len(excl_frozen) == 0
remaining = [r for r in eligible if r["case_id"] not in canon_set and r["case_id"] not in terminal and r["case_id"] not in frozen_all]
assert len(remaining) == 1311
rem_ids = sorted(r["case_id"] for r in remaining)
assert sha256(json.dumps(rem_ids).encode()).hexdigest() == res["identity_lists"]["remaining_ids_sha256"]
assert not (set(rem_ids) & canon_set)
assert not (set(rem_ids) & terminal)
assert not (set(rem_ids) & frozen_all)
assert not (set(want) & terminal)
assert not (set(want) & frozen_all)

clone_map = {}
if REPOS.is_dir():
    for p in sorted(REPOS.iterdir(), key=lambda x: x.name):
        if p.is_dir() and "_" in p.name:
            owner, repo = p.name.split("_", 1)
            clone_map.setdefault(f"{owner}/{repo}".lower(), p)
if WORKER_CLONES.is_dir():
    clones = sorted(list(WORKER_CLONES.glob("*/clones/*")) + list(WORKER_CLONES.glob("*/*/clones/*")), key=lambda x: str(x))
    for clone in clones:
        if clone.is_dir() and "__" in clone.name:
            owner, repo = clone.name.split("__", 1)
            clone_map.setdefault(f"{owner}/{repo}".lower(), clone)

for row in remaining:
    row["has_local_clone"] = (row["repository"] or "").lower() in clone_map
assert sum(1 for r in remaining if not r["has_local_clone"]) == 596
assert sum(1 for r in remaining if r["has_local_clone"]) == 715

residual = [r for r in remaining if r["residual_hit_count"] > 0]
residual.sort(key=lambda r: (
    -r["residual_hit_count"],
    0 if r["has_local_clone"] else 1,
    0 if r["same_repo_fixes"] else 1,
    -(len(r["published"] or "")),
    r["published"] or "",
    r["case_id"],
))
assert len(residual) == 28
assert [r["case_id"] for r in residual] == want
assert sha256(json.dumps([r["case_id"] for r in residual]).encode()).hexdigest() == res["identity_lists"]["residual_ids_sha256"]

def is_code(path):
    name = Path(path).name.lower()
    if name in NOISE_NAMES:
        return False
    if Path(path).suffix.lower() not in CODE_EXT:
        return False
    if TEST_HINT.search(path):
        return False
    return True

def names(repo, sha):
    p = git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", sha, timeout=15)
    return [l.strip() for l in p.stdout.splitlines() if l.strip()] if p.returncode == 0 else []

by_c = {x["case_id"]: x for x in c}
for row in residual:
    case = by_c[row["case_id"]]
    clone = clone_map.get((row["repository"] or "").lower())
    assert bool(clone) == case["has_local_clone"] == row["has_local_clone"]
    if not clone:
        assert case["reject_reason"] == "no_local_clone"
        continue
    used = None
    for fix in row["same_repo_fixes"]:
        t = git(clone, "cat-file", "-t", fix, timeout=8)
        if t.returncode == 0 and t.stdout.strip() == "commit":
            used = fix
            break
    if not used:
        assert case["reject_reason"] == "fix_object_missing"
        continue
    files = names(clone, used)
    code = [p for p in files if is_code(p)]
    if not code:
        assert case["reject_reason"] == "closer_no_code"
        continue
    assert case["closer"] == used
    assert case["reject_reason"] in {"no_pr_level_ai_authorship", "no_earlier_ai_security_pr"}

assert 910 + 4068 + 14050 + 6637 + 8724 == 34389
assert 62 + 7351 + 0 + 1311 == 8724
assert 596 + 715 == 1311
assert 1283 + 28 == 1311
assert 14 + 1 + 1 + 5 + 7 == 28
assert 910 + 4068 + 14050 + 6637 + 62 + 7351 + 0 + 1283 + 28 == 34389

text = (OWN / "report.md").read_text()
assert "does not call a PASS" in text
assert "ROUTE IDs: none" in text
assert "Canonical94 remains 94 HOLD" in text
assert "8724 = 62 + 7351 + 0 + 1311" in text
assert "28=28+0" in text
assert "28 = 14 + 1 + 1 + 5 + 7" in text
assert "GHSA-8P72-RCQ4-H6PW" in text
assert "herdr-260815-remediation-reverse80" in text
assert all(ord(ch) < 128 for ch in text)

print("REPLAY_OK inspected=28 ROUTE=0 PASS=0 canonical94=94 HOLD equation=34389=910+4068+14050+6637+62+7351+0+1283+28 assigned=28=28+0")
PY
