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
from concurrent.futures import ThreadPoolExecutor, as_completed

for k in list(os.environ):
    lk = k.lower()
    if any(x in lk for x in ("token", "secret", "password", "credential", "api_key", "auth", "gh_token", "github_token")):
        os.environ.pop(k, None)

ROOT = Path("/home/hanqing/agents/ai-slop")
OWN = ROOT / "autoresearch/herdr-260815-remediation-reverse80-grok46-xhigh"
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
assert a == [] and c == []
assert res["inspected_ids"] == []
assert res["route_ids"] == []
assert "PASS" not in {x.get("verdict") for x in c}
assert res["counts"]["PASS"] == 0 and res["counts"]["ROUTE"] == 0
assert res["pass_proposals"] == [] and res["selected_ids"] == []
assert res["proposed_pass"] is False
assert res["canonical94_strict_count"] == 94
assert res["publication_status"] == "HOLD"
assert res["never_pass"] is True
assert res["conservation"]["holds"] is True
assert res["conservation"]["assigned_equation"] == "0=0+0"
assert res["conservation"]["did_not_pad"] is True

canon = json.loads((CANON_DIR / "summary.json").read_text())
canon_ids = [str(x).upper() for x in canon["strict_released_case_ids"]]
assert len(canon_ids) == 94 == canon["canonical_strict_count"]
assert canon.get("status") == "HOLD"
canon_set = set(canon_ids)

sys.path.insert(0, str(ROOT / "cve-analyzer/src"))
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit
assert MATCHER_CONTRACT == res["matcher_contract"]

ADV = Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database")
REPOS = Path("/home/hanqing/.cache/cve-analyzer/repos")
WORKER_CLONES = Path("/home/hanqing/.cache/ghsa200-worker-clones")
SKIP_PARTS = {"work", "pages", "snapshot", "clones", "cache", "tmp", "node_modules", "diffs", "facts", "notes"}
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
GHSA_FIND = re.compile(r"GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}")
COMMIT_RE = re.compile(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})(?:[/?#]|$)")
REPO_ADV_RE = re.compile(r"https://github\.com/([^/]+)/([^/]+)/security/advisories/(GHSA-[0-9A-Za-z-]+)", re.I)
GITHUB_REPO_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/?$")
VERDICTS = {
    "PASS", "NARROW", "REJECT", "UNKNOWN", "BLOCKED", "KEEP", "FAIL",
    "FALSE_POSITIVE", "CONFIRM", "ACCEPT", "HOLD", "REJECT_ROUTING",
    "ROUTE", "TERMINAL", "NOT_SELECTED", "UNREVIEWED",
}
CODE_EXT = {".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".swift", ".ts", ".tsx", ".vue", ".zig", ".mjs", ".cjs"}
TEST_HINT = re.compile(r"(^|/)(test|tests|spec|specs|__tests__|testdata|fixtures)(/|$)", re.I)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
NOISE_NAMES = {
    "package.json", "package-lock.json", "pnpm-lock.yaml", "pnpm-workspace.yaml",
    "yarn.lock", "cargo.lock", "go.sum", "go.mod", "poetry.lock", "composer.lock",
    "gemfile.lock", "changelog.md", "changelog", "license", "license.md",
    "readme.md", "readme", "security.md", ".gitignore", ".npmignore",
}
SEC_RE = re.compile(
    r"(secur(e|ity)|validat|saniti[sz]|authori[sz]|\bauth[nz]\b|ssrf|"
    r"inject|xss|csrf|travers|allowlist|denylist|whitelist|blacklist|"
    r"escap(e|ing)|canonicali|normali[sz]|sandbox|harden|bypass|"
    r"privilege|permission|untrusted|resource.?limit|rate.?limit|"
    r"cve-|ghsa-|guardrail|mitigat|unauthori|"
    r"access.?control|open.?redirect|prototype.?pollut|redos|"
    r"safe.?path|path.?normal|command.?inject|sql.?inject|code.?inject|"
    r"path.?valid|input.?valid|html.?escap|url.?valid|host.?check|"
    r"fix(es|ed)?\s+(a |the )?(cve|ghsa|sec)|prevent |harden|"
    r"\bguard\b|blocklist|fail[- ]open|cis benchmark|permissions to 0)",
    re.I,
)
NOISE_SUBJ_RE = re.compile(
    r"^(chore|docs|style|ci|test|bump|release|merge |update (deps|lock)|"
    r"lockfile|format|typo|readme)",
    re.I,
)
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
CLASS_TOKS = re.compile(
    r"\b(ssrf|xss|csrf|inject|injection|travers|path|redirect|deserial|pollut|redos|"
    r"command|sql|rce|lfi|rfi|ssti|xxe|idor|jwt|cookie|cors|host|header|sandbox|"
    r"iframe|svg|html|scheme|protocol|allowlist|denylist|blocklist|authz|authn|"
    r"authoriz|saniti|validat|escape|symlink|zip.?slip|canonical|webhook|metadata)\b",
    re.I,
)
GENERIC = {"if", "for", "while", "switch", "catch", "return", "else", "try", "with", "match", "case"}
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

auto = ROOT / "autoresearch"
terminal = set()
files = 0; cases = 0; adj = 0; resf = 0
consider, rows = consider_factory(terminal)
pinned = res["inventory"]["source_relpaths"]
assert pinned == sorted(pinned)
assert len(pinned) == len(set(pinned))
assert sha256(json.dumps(pinned).encode()).hexdigest() == res["inventory"]["source_relpaths_sha256"]
assert len(pinned) == res["inventory"]["files"]
for rel in pinned:
    assert not rel.startswith("herdr-260815-remediation-reverse80-grok46-xhigh/")
    assert not any(p in SKIP_PARTS for p in Path(rel).parts[:-1]), rel
    path = auto / rel
    assert path.is_file(), rel
    name = Path(rel).name
    if name == "cases.jsonl":
        files += 1; cases += 1
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
assert files == res["inventory"]["files"]
assert cases == res["inventory"]["cases_files"]
assert adj == res["inventory"]["adj_files"]
assert resf == res["inventory"]["result_files"]
assert rows[0] == res["inventory"]["rows_parsed"]
assert len(terminal) == res["inventory"]["terminal_verdict_identities"]

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

def freeze_ids_from_packet(name):
    ids = set()
    d = auto / name
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
    return {
        "case_id": gid,
        "withdrawn": bool(data.get("withdrawn")),
        "repository": github_repo,
        "same_repo_fixes": sorted(set(same)),
        "repo_advisory_urls": sorted(set(repo_adv)),
        "published": data.get("published") or "",
        "summary": data.get("summary") or "",
        "details": data.get("details") or "",
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
assert len(excl_term) == 5992
assert sha256(json.dumps(excl_term).encode()).hexdigest() == res["identity_lists"]["excl_term_sha256"]
excl_frozen = sorted(r["case_id"] for r in eligible if r["case_id"] in frozen_all and r["case_id"] not in canon_set and r["case_id"] not in terminal)
assert len(excl_frozen) == 0
remaining = [r for r in eligible if r["case_id"] not in canon_set and r["case_id"] not in terminal and r["case_id"] not in frozen_all]
assert len(remaining) == 2670
rem_ids = sorted(r["case_id"] for r in remaining)
assert sha256(json.dumps(rem_ids).encode()).hexdigest() == res["identity_lists"]["remaining_ids_sha256"]
assert not (set(rem_ids) & canon_set)
assert not (set(rem_ids) & terminal)
assert not (set(rem_ids) & frozen_all)

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

present = []
no_clone = []
for row in remaining:
    clone = clone_map.get(row["repository"].lower())
    if clone is None:
        no_clone.append(row["case_id"])
        continue
    row2 = dict(row)
    row2["clone"] = str(clone)
    present.append(row2)
assert len(no_clone) == 1104
assert len(present) == 1566
assert sha256(json.dumps(sorted(no_clone)).encode()).hexdigest() == res["identity_lists"]["no_clone_ids_sha256"]
pres_ids = sorted(r["case_id"] for r in present)
assert sha256(json.dumps(pres_ids).encode()).hexdigest() == res["identity_lists"]["present_ids_sha256"]
assert set(res["no_clone_ids"]) == set(no_clone)

def is_code(path):
    name = Path(path).name.lower()
    if name in NOISE_NAMES:
        return False
    if Path(path).suffix.lower() not in CODE_EXT:
        return False
    if TEST_HINT.search(path):
        return False
    return True

def residual_hits(text):
    return [rx.pattern for rx in RESIDUAL_RES if rx.search(text)]

def funcs_from_diff(text, added=True):
    nameset = set()
    marker = "+" if added else "-"
    for line in text.splitlines():
        if line.startswith("@@"):
            m = re.search(r"@@ .* @@\s*(.+)$", line)
            if m:
                ctx = m.group(1)
                fm = re.search(r"(?:fn|def|function|func|class|impl)\s+([A-Za-z_][\w]*)", ctx)
                if fm:
                    nameset.add(fm.group(1))
                else:
                    fm2 = re.search(r"([A-Za-z_][\w]*)\s*\(", ctx)
                    if fm2 and fm2.group(1) not in GENERIC:
                        nameset.add(fm2.group(1))
            continue
        if line.startswith(marker) and not line.startswith(marker * 3):
            fm = re.search(r"(?:(?:pub(?:lic)?|private|protected|static|async|export)\s+)*(?:fn|def|function|func)\s+([A-Za-z_][\w]*)", line)
            if fm:
                nameset.add(fm.group(1))
    return {n for n in nameset if len(n) > 2 and n not in GENERIC}

def names(repo, sha):
    p = git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", sha, timeout=15)
    return [l.strip() for l in p.stdout.splitlines() if l.strip()] if p.returncode == 0 else []

def n_parents(repo, sha):
    proc = git(repo, "rev-list", "--parents", "-n", "1", sha, timeout=10)
    toks = proc.stdout.split()
    if not toks:
        return 0, []
    return max(0, len(toks) - 1), [t.lower() for t in toks[1:]]

def parse_log(stdout):
    out = []
    for ch in [c for c in stdout.split("\x1e") if c.strip()]:
        parts = ch.split("\x1f")
        if len(parts) < 8:
            continue
        sha = parts[0].strip().lower()
        if not SHA_RE.match(sha):
            continue
        parents = [p.lower() for p in parts[1].split() if SHA_RE.match(p.lower())]
        out.append({"sha": sha, "parents": parents, "an": parts[2], "ae": parts[3], "cn": parts[4], "ce": parts[5], "ad": parts[6].strip(), "msg": parts[7]})
    return out

def scan_one(row):
    clone = Path(row["clone"])
    cid = row["case_id"]
    blob = (row.get("summary") or "") + "\n" + (row.get("details") or "")
    residual = residual_hits(blob)
    used = None
    for fix in row["same_repo_fixes"]:
        try:
            t = git(clone, "cat-file", "-t", fix, timeout=8)
        except subprocess.TimeoutExpired:
            continue
        if t.returncode == 0 and t.stdout.strip() == "commit":
            used = fix
            break
    if not used:
        return {"case_id": cid, "bucket": "fix_object_missing"}
    try:
        np, pars = n_parents(clone, used)
    except subprocess.TimeoutExpired:
        return {"case_id": cid, "bucket": "git_timeout"}
    parent = pars[0] if pars else ""
    files = names(clone, used)
    code = [p for p in files if is_code(p)]
    if not code:
        return {"case_id": cid, "bucket": "closer_no_code"}
    if len(code) > 80:
        return {"case_id": cid, "bucket": "broad_closer"}
    if not parent:
        return {"case_id": cid, "bucket": "no_ai_security_attempt", "n_ai": 0, "n_ai_sec": 0}
    try:
        lg = git(clone, "log", "--no-merges", "-n", "250", "--format=%H%x1f%P%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%aI%x1f%B%x1e", parent, "--", *code[:40], timeout=55)
    except subprocess.TimeoutExpired:
        return {"case_id": cid, "bucket": "git_timeout"}
    parsed = parse_log(lg.stdout) if lg.returncode == 0 else []
    n_ai = 0
    hist = []
    for p in parsed:
        if p["sha"] == used:
            continue
        if len(p["parents"]) != 1:
            continue
        info = CommitInfo(sha=p["sha"], author_name=p["an"], author_email=p["ae"], committer_name=p["cn"], committer_email=p["ce"], authored_date=p["ad"], message=p["msg"])
        if not matches_for_commit(info):
            continue
        n_ai += 1
        subj = (p["msg"].splitlines() or [""])[0]
        if NOISE_SUBJ_RE.search(subj):
            continue
        probe = subj + "\n" + "\n".join(p["msg"].splitlines()[:16])
        if not SEC_RE.search(probe):
            continue
        hist.append({"sha": p["sha"], "parent": p["parents"][0], "subject": subj, "msg": p["msg"]})
    if not hist:
        return {"case_id": cid, "bucket": "no_ai_security_attempt", "n_ai": n_ai, "n_ai_sec": 0}
    closer_deleted_funcs = set()
    try:
        d = git(clone, "diff", "-U0", "--no-color", parent, used, "--", *code[:40], timeout=25)
        if d.returncode == 0:
            closer_deleted_funcs = funcs_from_diff(d.stdout, added=False) | funcs_from_diff(d.stdout, added=True)
    except subprocess.TimeoutExpired:
        pass
    scored = []
    for hit in hist[:16]:
        sha = hit["sha"]
        cfiles = [p for p in names(clone, sha) if is_code(p)]
        if not cfiles or len(cfiles) > 40:
            continue
        overlap = sorted(set(cfiles) & set(code))
        if not overlap:
            continue
        if len(code) > 15 and len(cfiles) > 15 and len(overlap) / min(len(code), len(cfiles)) < 0.15:
            continue
        cand_funcs = set()
        try:
            ad = git(clone, "diff", "-U0", "--no-color", hit["parent"], sha, "--", *overlap[:20], timeout=20)
            if ad.returncode == 0:
                cand_funcs = funcs_from_diff(ad.stdout, added=True) | funcs_from_diff(ad.stdout, added=False)
        except subprocess.TimeoutExpired:
            pass
        same_fn = sorted(cand_funcs & closer_deleted_funcs)
        adv_toks = {t.lower() for t in CLASS_TOKS.findall(blob)}
        cand_toks = {t.lower() for t in CLASS_TOKS.findall(hit["subject"] + "\n" + hit["msg"])}
        class_overlap = sorted(adv_toks & cand_toks)
        if bool(adv_toks and cand_toks and not class_overlap) and not same_fn:
            continue
        release_ok = False
        try:
            tc = git(clone, "tag", "--contains", sha, timeout=20)
            tf = git(clone, "tag", "--contains", used, timeout=20)
            if tc.returncode == 0 and tf.returncode == 0:
                set_c = {x.strip() for x in tc.stdout.splitlines() if x.strip()}
                set_f = {x.strip() for x in tf.stdout.splitlines() if x.strip()}
                if sorted(set_c - set_f):
                    release_ok = True
        except subprocess.TimeoutExpired:
            pass
        scored.append({"sha": sha, "same_function": bool(same_fn), "release_ok": release_ok, "overlap_n": len(overlap)})
    if not scored:
        return {"case_id": cid, "bucket": "no_same_file_delta", "n_ai": n_ai, "n_ai_sec": len(hist)}
    scored.sort(key=lambda x: (0 if x["same_function"] else 1, 0 if x["release_ok"] else 1, -x["overlap_n"], x["sha"]))
    best = scored[0]
    if not residual:
        return {"case_id": cid, "bucket": "no_residual_named", "n_ai": n_ai, "n_ai_sec": len(hist)}
    if not best["release_ok"]:
        return {"case_id": cid, "bucket": "unreleased_attempt", "n_ai": n_ai, "n_ai_sec": len(hist)}
    return {"case_id": cid, "bucket": "high_signal", "n_ai": n_ai, "n_ai_sec": len(hist), "best": best}

scan_rows = []
with ThreadPoolExecutor(max_workers=8) as ex:
    futs = [ex.submit(scan_one, r) for r in present]
    for fut in as_completed(futs):
        scan_rows.append(fut.result())
scan_rows.sort(key=lambda x: x["case_id"])
ctr = Counter(r["bucket"] for r in scan_rows)
assert ctr["fix_object_missing"] == 36
assert ctr["closer_no_code"] == 263
assert ctr["broad_closer"] == 1
assert ctr["no_ai_security_attempt"] == 1266
assert ctr.get("high_signal", 0) == 0
assert ctr.get("git_timeout", 0) == 0
assert sum(ctr.values()) == 1566
assert sorted(r["case_id"] for r in scan_rows if r["bucket"] == "fix_object_missing") == res["fix_object_missing_ids"]
assert sorted(r["case_id"] for r in scan_rows if r["bucket"] == "broad_closer") == res["broad_closer_ids"]
n_ai_any = sum(1 for r in scan_rows if r.get("n_ai", 0) > 0)
n_ai_sec = sum(1 for r in scan_rows if r.get("n_ai_sec", 0) > 0)
assert n_ai_any == 1
assert n_ai_sec == 0

assert 910 + 4068 + 14050 + 6637 + 8724 == 34389
assert 62 + 5992 + 0 + 2670 == 8724
assert 1104 + 1566 == 2670
assert 36 + 263 + 1 + 1266 + 0 == 1566
assert 910 + 4068 + 14050 + 6637 + 62 + 5992 + 0 + 1104 + 36 + 263 + 1 + 1266 + 0 == 34389

text = (OWN / "report.md").read_text()
assert "does not call a PASS" in text
assert "ROUTE 0" in text
assert "ROUTE IDs: none" in text
assert "Canonical94 remains 94 HOLD" in text
assert "8724 = 62 + 5992 + 0 + 2670" in text
assert "1566 = 36 + 263 + 1 + 1266 + 0" in text
assert "0=0+0" in text
assert "GHSA-92CP-5422-2MW7" in text
assert "AI_INCOMPLETE_REMEDIATION" not in text or "patch-delta" in text.lower() or "incomplete-remediation" in text.lower()

print("REPLAY_OK inspected=0 ROUTE=0 PASS=0 canonical94=94 HOLD equation=34389=910+4068+14050+6637+62+5992+0+1104+36+263+1+1266+0 assigned=0=0+0")
PY
