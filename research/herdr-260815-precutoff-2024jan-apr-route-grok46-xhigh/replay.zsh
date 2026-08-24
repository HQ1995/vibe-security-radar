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
OWN = ROOT / "autoresearch/herdr-260815-precutoff-2024jan-apr-route-grok46-xhigh"
CANON_DIR = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical94"
SRC = ROOT / "autoresearch/herdr-260814-nextqueue-v2-grok46-low"
res = json.loads((OWN / "result.json").read_text())
pins = res["current_input_hashes"]

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

assert h(ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md") == pins["CONTRACT.md"]
assert h(CANON_DIR / "ledger.jsonl") == pins["canonical94_ledger.jsonl"]
assert h(CANON_DIR / "summary.json") == pins["canonical94_summary.json"]
assert h(SRC / "result.json") == pins["source_result.json"]
assert h(SRC / "report.md") == pins["source_report.md"]
assert h(SRC / "replay.zsh") == pins["source_replay.zsh"]
assert h(ROOT / "autoresearch/herdr-260813-ghsa200-remediation/cases.jsonl") == pins["term_src_2mqj_cases.jsonl"]
assert h(ROOT / "autoresearch/herdr-260814-cf4-b0-direct-grok46-low/cases.jsonl") == pins["term_src_4hwq_cases.jsonl"]

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
assert [x.get("case_id") for x in a] == [x.get("case_id") for x in c] == want
assert want == []
assert len(a) == 0 == len(c)
assert "PASS" not in {x.get("verdict") for x in c}
assert "ROUTE" not in {x.get("verdict") for x in c}
assert res["counts"]["PASS"] == 0 and res["counts"]["ROUTE"] == 0
assert res["pass_proposals"] == [] and res["selected_ids"] == [] and res["route_ids"] == []
assert res["proposed_pass"] is False
assert res["canonical94_strict_count"] == 94
assert res["publication_status"] == "HOLD"
assert res["conservation"]["holds"] is True
assert res["conservation"]["assigned"] == 0
assert res["conservation"]["reviewed"] == 0
assert res["conservation"]["unreviewed"] == 0
assert res["conservation"]["assigned_equation"] == "0=0+0"
assert res["conservation"]["assigned_equals_reviewed_plus_unreviewed"] is True
assert res["deep_inspect_cap"] == 20
assert res["counts"]["deep_inspect"] == 0
assert res["never_pass"] is True

canon = json.loads((CANON_DIR / "summary.json").read_text())
canon_ids = [str(x).upper() for x in canon["strict_released_case_ids"]]
assert len(canon_ids) == 94 == canon["canonical_strict_count"]
assert canon.get("status") == "HOLD"
canon_set = set(canon_ids)
assert not (set(want) & canon_set)
assert res["canonical94_overlap"] == []

sys.path.insert(0, str(ROOT / "cve-analyzer/src"))
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit
assert MATCHER_CONTRACT == res["matcher_contract"]

ADV = Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database")
REPOS = Path("/home/hanqing/.cache/cve-analyzer/repos")
WORKER_CLONES = Path("/home/hanqing/.cache/ghsa200-worker-clones")
SKIP_PARTS = {"work", "pages", "snapshot", "clones", "cache", "tmp", "node_modules", "diffs", "facts", "notes"}
SKIP_DIR_NAMES = {"herdr-260815-precutoff-2024jan-apr-route-grok46-xhigh", ".leader-quarantine-260814"}
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
GIT_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1", "GIT_PAGER": "cat", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}

def git(repo, *args, timeout=20):
    try:
        p = subprocess.run(["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-C", str(repo), *args], capture_output=True, env=GIT_ENV, timeout=timeout)
    except subprocess.TimeoutExpired:
        class R: pass
        r = R(); r.returncode = 124; r.stdout = ""; r.stderr = "timeout"
        return r
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

INV_CUTOFF = float(res["inventory"]["cutoff_mtime"])

def packet_ok(path):
    if path.stat().st_mtime >= INV_CUTOFF:
        return False
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
for path in sorted(auto.glob("*/cases.jsonl")):
    if not packet_ok(path):
        continue
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
for path in sorted(list(auto.glob("*/*adjudication*.jsonl")) + list(auto.glob("*/*adjudication*.json"))):
    if not packet_ok(path):
        continue
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
for path in sorted(auto.glob("*/result.json")):
    if not packet_ok(path):
        continue
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
inv = res["inventory"]
assert (files, cases, adj, resf, rows[0]) == (inv["files"], inv["cases_files"], inv["adj_files"], inv["result_files"], inv["rows_parsed"])
assert len(terminal) == inv["terminal_verdict_identities"]
assert sha256(json.dumps(sorted(terminal)).encode()).hexdigest() == res["identity_lists"]["terminal_ids_sha256"]

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
    }

reviewed = 0
janapr = []
before = 0
after = 0
empty_pub = 0
for path in (ADV / "advisories/github-reviewed").rglob("GHSA-*.json"):
    row = parse_advisory(path)
    if not row:
        continue
    reviewed += 1
    pub = row["published"] or ""
    if not pub:
        empty_pub += 1
        continue
    if "2024-01-01" <= pub < "2024-05-01":
        janapr.append(row)
    elif pub < "2024-01-01":
        before += 1
    else:
        after += 1
assert reviewed == res["counts"]["reviewed_identities"] == 34389
assert empty_pub == res["counts"]["empty_published"] == 0
assert len(janapr) == res["counts"]["janapr_published"]
assert before == res["counts"]["before_2024_01_01"]
assert after == res["counts"]["on_or_after_2024_05_01"]
assert len({r["case_id"] for r in janapr}) == len(janapr)
assert all("2024-01-01" <= r["published"] < "2024-05-01" for r in janapr)
assert min(r["published"] for r in janapr) == res["date_window"]["min_published"]
assert max(r["published"] for r in janapr) == res["date_window"]["max_published"]
assert res["date_window"]["start_inclusive"] == "2024-01-01"
assert res["date_window"]["end_exclusive"] == "2024-05-01"

buckets = Counter()
eligible = []
for row in janapr:
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
assert buckets["withdrawn"] == res["counts"]["withdrawn"]
assert buckets["no_repository"] == res["counts"]["no_repository"]
assert buckets["no_same_repo_fix"] == res["counts"]["no_same_repo_fix"]
assert buckets["no_first_party_repo_advisory"] == res["counts"]["no_first_party_repo_advisory"]
assert len(eligible) == res["counts"]["identity_eligible"]
elig_ids = sorted(r["case_id"] for r in eligible)
assert sha256(json.dumps(elig_ids).encode()).hexdigest() == res["identity_lists"]["eligible_ids_sha256"]
assert not (set(elig_ids) & canon_set)
term_excl = sorted(r["case_id"] for r in eligible if r["case_id"] in terminal)
assert term_excl == res["term_excl_ids"]
assert sha256(json.dumps(term_excl).encode()).hexdigest() == res["identity_lists"]["term_excl_sha256"]
assert set(term_excl).issubset(terminal)
remaining = [r for r in eligible if r["case_id"] not in terminal]
assert len(remaining) == res["counts"]["remaining_after_canonical_and_terminal"]
rem_ids = sorted(r["case_id"] for r in remaining)
assert sha256(json.dumps(rem_ids).encode()).hexdigest() == res["identity_lists"]["remaining_ids_sha256"]
assert not (set(rem_ids) & canon_set)
assert not (set(rem_ids) & terminal)

clone_map = {}
if REPOS.is_dir():
    for p in REPOS.iterdir():
        if p.is_dir() and "_" in p.name:
            owner, repo = p.name.split("_", 1)
            clone_map.setdefault(f"{owner}/{repo}".lower(), p)
if WORKER_CLONES.is_dir():
    for clone in list(WORKER_CLONES.glob("*/clones/*")) + list(WORKER_CLONES.glob("*/*/clones/*")):
        if clone.is_dir() and "__" in clone.name:
            owner, repo = clone.name.split("__", 1)
            clone_map.setdefault(f"{owner}/{repo}".lower(), clone)

present = []
no_clone = []
missing = []
for row in remaining:
    clone = clone_map.get(row["repository"].lower())
    if clone is None:
        no_clone.append(row["case_id"])
        continue
    saw = False
    used = None
    for fix in row["same_repo_fixes"]:
        t = git(clone, "cat-file", "-t", fix, timeout=8)
        if t.returncode == 0 and t.stdout.strip() == "commit":
            saw = True
            used = fix
            break
    if not saw:
        missing.append(row["case_id"])
    else:
        row2 = dict(row)
        row2["clone"] = str(clone)
        row2["probe_fix"] = used
        present.append(row2)
assert sorted(missing) == res["missing_ids"]
assert len(missing) == res["counts"]["fix_object_missing"]
assert len(no_clone) == res["counts"]["no_local_clone"]
assert len(present) == res["counts"]["closer_present"]
assert sha256(json.dumps(sorted(no_clone)).encode()).hexdigest() == res["identity_lists"]["no_clone_ids_sha256"]
pres_ids = sorted(r["case_id"] for r in present)
assert sha256(json.dumps(pres_ids).encode()).hexdigest() == res["identity_lists"]["present_ids_sha256"]
assert set(res["no_clone_ids"]) == set(no_clone)
assert set(pres_ids).isdisjoint(canon_set)
assert set(pres_ids).isdisjoint(terminal)
assert len(pres_ids) == len(set(pres_ids))
assert set(no_clone).isdisjoint(set(missing))
assert set(no_clone).isdisjoint(set(pres_ids))
assert set(missing).isdisjoint(set(pres_ids))
for row in present:
    assert row["repo_advisory_urls"]
    assert row["same_repo_fixes"]
    owner, name = row["repository"].split("/", 1)
    ok = False
    for u in row["repo_advisory_urls"]:
        m = REPO_ADV_RE.search(u)
        if m and m.group(1).lower() == owner.lower() and m.group(2).lower() == name.lower() and m.group(3).upper() == row["case_id"]:
            ok = True
    assert ok, row["case_id"]
    assert SHA_RE.match(row["probe_fix"])

def is_code(path):
    return Path(path).suffix.lower() in CODE_EXT and not TEST_HINT.search(path)

def names(repo, sha):
    p = git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", sha, timeout=15)
    return [l.strip() for l in p.stdout.splitlines() if l.strip()] if p.returncode == 0 else []

def parse_log_records(text):
    recs = []
    for chunk in text.split("\x1e"):
        chunk = chunk.strip("\n")
        if not chunk.strip():
            continue
        parts = chunk.split("\x1f")
        if len(parts) < 7:
            continue
        sha = parts[0].strip().lower()
        if not SHA_RE.match(sha):
            continue
        recs.append(CommitInfo(sha=sha, author_name=parts[1], author_email=parts[2], committer_name=parts[3], committer_email=parts[4], authored_date=parts[5].strip(), message=parts[6]))
    return recs

def parse_diff_lines(text, added=True):
    out = {}
    path = None
    marker = "+" if added else "-"
    for line in text.splitlines():
        if line.startswith("diff --git "):
            path = None
            continue
        if line.startswith("+++ b/"):
            path = line[6:]
            if path == "/dev/null":
                path = None
            continue
        if path is None:
            if line.startswith("--- a/") and not added:
                pth = line[6:]
                if pth != "/dev/null":
                    path = pth
            continue
        if line.startswith("+++ ") or line.startswith("--- ") or line.startswith("@@") or line.startswith("diff "):
            continue
        if line.startswith(marker) and not line.startswith(marker * 3):
            s = line[1:].strip()
            if s and s not in ("{", "}", "end", "pass"):
                out.setdefault(path, set()).add(s)
    return out

FMT = "%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%aI%x1f%B%x1e"

def scan_one(row):
    clone = Path(row["clone"])
    fix = row["probe_fix"]
    pars = git(clone, "rev-list", "--parents", "-n", "1", fix, timeout=12).stdout.split()
    parent = pars[1] if len(pars) > 1 else ""
    n_parents = max(0, len(pars) - 1)
    files = names(clone, fix)
    code = [p for p in files if is_code(p)]
    deleted = {}
    if parent:
        d = git(clone, "diff", "-U0", "--no-color", parent, fix, timeout=30)
        if d.returncode == 0:
            deleted = parse_diff_lines(d.stdout, added=False)
    infos = []
    if parent and (code or files):
        lg = git(clone, "log", "--no-merges", "-n", "250", f"--format={FMT}", parent, "--", *(code or files)[:40], timeout=50)
        if lg.returncode == 0:
            infos.extend(parse_log_records(lg.stdout))
    if n_parents >= 2:
        ml = git(clone, "log", "--no-merges", "-n", "80", f"--format={FMT}", f"{pars[1]}..{pars[2]}", timeout=40)
        if ml.returncode == 0:
            infos.extend(parse_log_records(ml.stdout))
    hits = 0
    seen = set()
    for info in infos:
        sha = info.sha
        if sha == fix or sha in seen:
            continue
        seen.add(sha)
        if not matches_for_commit(info):
            continue
        anc = git(clone, "merge-base", "--is-ancestor", sha, fix, timeout=10)
        if anc.returncode != 0:
            continue
        np2 = git(clone, "rev-list", "--parents", "-n", "1", sha, timeout=8)
        toks = np2.stdout.split()
        if max(0, len(toks) - 1) != 1 or len(toks) < 2:
            continue
        ad = git(clone, "diff", "-U0", "--no-color", toks[1], sha, timeout=20)
        added = parse_diff_lines(ad.stdout, added=True) if ad.returncode == 0 else {}
        for path, dlines in deleted.items():
            if dlines & added.get(path, set()):
                hits += 1
                break
    closer_ai = False
    cshow = git(clone, "log", "-1", f"--format={FMT}", fix, timeout=12)
    cinfos = parse_log_records(cshow.stdout) if cshow.returncode == 0 else []
    if cinfos and matches_for_commit(cinfos[0]):
        closer_ai = True
    return row["case_id"], hits, closer_ai

exact = 0
closer_ai_n = 0
with ThreadPoolExecutor(max_workers=6) as ex:
    futs = [ex.submit(scan_one, r) for r in present]
    for fut in as_completed(futs):
        cid, hits, closer_ai = fut.result()
        exact += hits
        if closer_ai:
            closer_ai_n += 1
assert exact == 0
assert closer_ai_n == 0
assert res["counts"]["exact_hunk_candidates"] == 0
assert res["non_routing_ai_markers"] == []

nq = json.loads((SRC / "result.json").read_text())
assert nq["buckets"]["outside_coverage_window"] == res["date_window"]["prior_nextqueue_count"]
assert nq["advisory_database"]["head"] == res["advisory_database"]["head"]

cons = res["conservation"]
parts = [int(x) for x in cons["equation"].split("=", 1)[1].split("+")]
assert sum(parts) == cons["input"] == res["counts"]["janapr_published"]
assert cons["equation"] == (
    f"{cons['input']}={cons['excluded_withdrawn']}+{cons['excluded_no_repository']}+"
    f"{cons['excluded_no_same_repo_fix']}+{cons['excluded_no_first_party_repo_advisory']}+"
    f"{cons['excluded_canonical94']}+{cons['excluded_later_terminals']}+"
    f"{cons['excluded_no_local_clone']}+{cons['excluded_fix_object_missing']}+"
    f"{cons['excluded_no_exact_hunk']}+{cons['assigned']}"
)

text = (OWN / "report.md").read_text()
assert "does not call a PASS" in text
assert "ROUTE 0" in text
assert cons["equation"] in text
assert "0=0+0" in text
assert "Canonical94 remains 94 HOLD" in text
assert "outside_coverage_window" in text
assert "2024-01-01" in text and "2024-05-01" in text

print(
    "REPLAY_OK inspected=0 ROUTE=0 PASS=0 canonical94=94 HOLD equation="
    + cons["equation"]
    + " assigned=0=0+0"
)
PY
