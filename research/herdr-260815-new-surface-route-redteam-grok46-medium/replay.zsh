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
OWN = ROOT / "autoresearch/herdr-260815-new-surface-route-redteam-grok46-medium"
SRC = ROOT / "autoresearch/herdr-260815-new-surface-reverse80-grok46-high"
CANON_DIR = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical94"
res = json.loads((OWN / "result.json").read_text())
pins = res["current_input_hashes"]

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

assert h(ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md") == pins["CONTRACT.md"] == "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"
assert h(CANON_DIR / "ledger.jsonl") == pins["canonical94_ledger.jsonl"] == "7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096"
assert h(CANON_DIR / "summary.json") == pins["canonical94_summary.json"] == "c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b"
assert h(SRC / "assignment.jsonl") == pins["source_assignment.jsonl"] == "51ee418b222265cff667674b0a9d3fb8cd8c7a8b518de637533c87923b7ed0c2"
assert h(SRC / "cases.jsonl") == pins["source_cases.jsonl"] == "73bc756be68a318ecd5825a9604de29663f08113e509440e38f1874475a3a8bc"
assert h(SRC / "report.md") == pins["source_report.md"] == "800b5c53a12929489d1e5f413af3ddacd4b2be9268d4f136aca5c9af50575595"
assert h(SRC / "replay.zsh") == pins["source_replay.zsh"] == "55459be2d17f64acd8e0c3482d6a0e303e52340b36050d1cae63d7ca833d6f71"
assert h(SRC / "result.json") == pins["source_result.json"] == "d23678631e3214a7bdf991a30a8aae392b7830e93852d63f7d9288cd83740065"

names = sorted(p.name for p in OWN.iterdir() if p.is_file())
assert names == ["replay.zsh", "report.md", "result.json"], names
for banned in ("work", "notes", "pages", "snapshot", "clones", "assignment.jsonl", "cases.jsonl"):
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
assert h(OWN / "replay.zsh") == ah["replay.zsh"]
assert h(OWN / "report.md") == ah["report.md"]

c = [json.loads(l) for l in (SRC / "cases.jsonl").read_text().splitlines() if l.strip()]
want = res["source_route_ids"]
assert [x["case_id"] for x in c] == want
assert len(want) == 22 == len(set(want))
assert [x["assigned_order"] for x in c] == list(range(1, 23))
assert all(x.get("verdict") == "ROUTE" for x in c)
assert "PASS" not in {x.get("verdict") for x in c}

per = res["per_case"]
assert list(per) == want
assert all(per[i] == "REJECT_ROUTE" for i in want)
assert res["counts"]["KEEP_ROUTE"] == 0
assert res["counts"]["REJECT_ROUTE"] == 22
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["PASS"] == 0
assert res["surviving_route_ids"] == []
assert res["conservation"]["equation"] == "22=22+0"
assert res["conservation"]["redteam_equation"] == "22=0+22+0"
assert res["conservation"]["holds"] is True
assert res["canonical94_strict_count"] == 94
assert res["publication_status"] == "HOLD"
assert res["never_pass"] is True
assert res["canonical_count_updated"] is False
assert res["reject_class_histogram"] == {"MATCHER_FAIL": 15, "NO_CLOSER_SURFACE_OVERLAP": 6, "NO_NEW_SURFACE": 1}

canon = json.loads((CANON_DIR / "summary.json").read_text())
canon_ids = [str(x).upper() for x in canon["strict_released_case_ids"]]
assert len(canon_ids) == 94 == canon["canonical_strict_count"]
assert canon.get("status") == "HOLD"
assert not (set(want) & set(canon_ids))

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

sys.path.insert(0, str(ROOT / "cve-analyzer/src"))
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit
assert MATCHER_CONTRACT == res["matcher_contract"]

def commit_info(repo, sha):
    proc = subprocess.run(
        ["git", "--no-optional-locks", "-c", "gc.auto=0", "-C", str(repo),
         "show", "-s", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%aI%x1f%B%x1e", sha],
        capture_output=True, text=True, env=GIT_ENV, timeout=15,
    )
    assert proc.returncode == 0
    parts = proc.stdout.split("\x1f")
    msg = parts[6].split("\x1e", 1)[0]
    return CommitInfo(sha=parts[0].strip().lower(), author_name=parts[1], author_email=parts[2], committer_name=parts[3], committer_email=parts[4], authored_date=parts[5].strip(), message=msg)

def paths(repo, sha):
    out = git(repo, "diff-tree", "--no-commit-id", "-r", "--name-only", sha)
    return set(x for x in out.splitlines() if x.strip())

def added(repo, sha):
    out = git(repo, "diff-tree", "--no-commit-id", "-r", "--name-status", sha)
    a = []
    for line in out.splitlines():
        parts = line.split("\t")
        if parts and parts[0].startswith("A"):
            a.append(parts[-1])
    return set(a)

hist = {"MATCHER_FAIL": 0, "NO_CLOSER_SURFACE_OVERLAP": 0, "NO_NEW_SURFACE": 0}
exact_new = 0
for row in c:
    clone = Path(row["clone"])
    cand = row["candidate_set"][0]
    closer0 = row["minimum_fix_set"][0]
    adv = json.loads((ADV / row["advisory_path"]).read_text())
    assert adv.get("withdrawn") in (None, "")
    assert (adv.get("database_specific") or {}).get("github_reviewed") is True
    assert adv.get("id", "").upper() == row["case_id"]
    parents = git(clone, "rev-list", "--parents", "-n", "1", cand).split()
    assert parents[0] == cand
    assert len(parents) == 2, (row["case_id"], parents)
    assert row["candidate_parent"] == parents[1]
    rc = subprocess.run(
        ["git", "--no-optional-locks", "-c", "gc.auto=0", "-C", str(clone), "merge-base", "--is-ancestor", cand, closer0],
        env=GIT_ENV, capture_output=True, timeout=15,
    )
    assert rc.returncode == 0, row["case_id"]
    ci = commit_info(clone, cand)
    matched = bool(matches_for_commit(ci))
    assert matched is bool(row["matcher"]), (row["case_id"], matched, row["matcher"])
    cand_paths = paths(clone, cand)
    closer_paths = set()
    for cl in row["minimum_fix_set"]:
        closer_paths |= paths(clone, cl)
    overlap = cand_paths & closer_paths
    added_overlap = added(clone, cand) & closer_paths
    if added_overlap:
        exact_new += 1
    assert not added_overlap, (row["case_id"], added_overlap)
    if row["case_id"] == "GHSA-92CP-5422-2MW7":
        assert overlap == {"README.md", "redis_test.go"}
    else:
        assert overlap == set(), (row["case_id"], overlap)
    hist[row["reject_class"]] += 1
    assert per[row["case_id"]] == "REJECT_ROUTE"
    assert row["exact_added_attack_surface"].startswith("no_new_")

assert hist == {"MATCHER_FAIL": 15, "NO_CLOSER_SURFACE_OVERLAP": 6, "NO_NEW_SURFACE": 1}
assert exact_new == 0 == res["counts"]["exact_new_surface_hits"]
assert res["counts"]["matcher_true"] == 7

text = (OWN / "report.md").read_text()
assert "does not call a PASS" in text
assert "KEEP_ROUTE 0" in text
assert "REJECT_ROUTE 22" in text
assert "Surviving ROUTE IDs: none" in text
assert "Canonical94 remains 94 HOLD" in text
assert "PASS" not in {per[i] for i in want}
print("REPLAY_OK inspected=22 KEEP_ROUTE=0 REJECT_ROUTE=22 UNKNOWN=0 surviving_route_ids=none canonical94=94 HOLD equation=22=22+0 redteam=22=0+22+0 exact_new_surface=0")
PY
