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
OWN = ROOT / "autoresearch/herdr-260815-pr-bot-origin100-grok46-xhigh"
CANON = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical94"
AF = ROOT / "autoresearch/herdr-260813-ghsa200-commitfirst-af"
GJ = ROOT / "autoresearch/herdr-260813-ghsa200-commitfirst-gj-grok46-medium"
GN = ROOT / "autoresearch/herdr-260813-ghsa200-commitfirst-gn"
KN = ROOT / "autoresearch/herdr-260813-ghsa200-commitfirst-kn-grok46-low"
OZ = Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/work")
R20 = ROOT / "autoresearch/herdr-260814-ghsa200-commitfirst-remainder20-grok46-high/work/candidate-pool.jsonl"
ADV = Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database")
res = json.loads((OWN / "result.json").read_text())
pins = res["current_input_hashes"]

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

assert h(ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md") == pins["CONTRACT.md"] == "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"
assert h(CANON / "ledger.jsonl") == pins["canonical94_ledger.jsonl"]
assert h(CANON / "summary.json") == pins["canonical94_summary.json"]

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
assert h(OWN / "report.md") == ah["report.md"]
assert h(OWN / "replay.zsh") == ah["replay.zsh"]

a = [json.loads(l) for l in (OWN / "assignment.jsonl").read_text().splitlines() if l.strip()]
c = [json.loads(l) for l in (OWN / "cases.jsonl").read_text().splitlines() if l.strip()]
want = res["inspected_ids"]
assert [x["case_id"] for x in a] == [x["case_id"] for x in c] == want
assert len(want) == 100 == len(set(want))
assert all(x.get("never_pass") and x.get("routing_only") for x in a + c)
assert all(x.get("proposed_pass") is False for x in c)
assert all(x.get("countable_pass") is False for x in c)
assert all(x.get("verdict") == "REJECT_ROUTING" for x in c)
assert "PASS" not in {x.get("verdict") for x in c}
assert "ROUTE" not in {x.get("verdict") for x in c}
assert all(x.get("authorship_transfer_from_bot_pr_or_squash") is False for x in c)
assert all("PASS" not in x["gates"].values() for x in c)
assert res["counts"]["PASS"] == 0 and res["counts"]["ROUTE"] == 0
assert res["pass_proposals"] == [] and res["route_ids"] == []
assert res["canonical94_strict_count"] == 94
assert res["never_pass"] is True
assert res["conservation"]["equation"] == "5980=17+5352+611"
assert res["conservation"]["remaining_equation"] == "611=100+511"
assert res["conservation"]["assigned_equation"] == "100=100+0"
assert res["conservation"]["verdict_equation"] == "100=100+0+0"
assert res["conservation"]["holds"] is True
assert res["conservation"]["did_not_pad"] is True

summary = json.loads((CANON / "summary.json").read_text())
canon = set(str(x).upper() for x in summary["strict_released_case_ids"])
assert len(canon) == 94 == summary["canonical_strict_count"]
assert summary.get("status") == "HOLD"
assert not set(want) & canon
assert "GHSA-2MHJ-FHVG-V428" not in set(res["remaining_ids"])
assert "GHSA-2MHJ-FHVG-V428" not in set(want)

sys.path.insert(0, str(ROOT / "cve-analyzer/src"))
from cve_analyzer.source_matcher import MATCHER_CONTRACT
assert MATCHER_CONTRACT == res["matcher_contract"]

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

def git(repo, *args, timeout=20):
    return subprocess.run(
        ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-C", str(repo), *args],
        capture_output=True, text=True, env=GIT_ENV, timeout=timeout, check=False,
    )

assert git(ADV, "rev-parse", "HEAD").stdout.strip() == res["advisory_database"]["head"]
assert git(ADV, "rev-parse", "HEAD:advisories/github-reviewed").stdout.strip() == res["advisory_database"]["github_reviewed_tree"]

files = {
    ("af", "review-queue", AF / "review-queue.jsonl", "fef5b3b2d175b57fd9ec043644dd0def5cc314a4574e675a2900bde071c9cdea"),
    ("af", "ai-commits", AF / "ai-commits.jsonl", "9659e93e82df4428df361507c6728ac83988211b0282ffbc3c12e3aba529d6d0"),
    ("gj", "origin-rank", GJ / "origin-rank.jsonl", "4ed1d2c6683593916536d2ada5c961f5c2120f00582da895a2f78bfdaa9534b3"),
    ("gn", "ai-ghsa-intersections", GN / "ai-ghsa-intersections.jsonl", "c58444221e9cc00555ba251da75f518281bacd660a438f6cc8a5df3ac5cf331e"),
    ("gn", "ai-commit-scans", GN / "ai-commit-scans.jsonl", "a6d7ca1584dbeb1596c57643092df0178001925efe0de60ca3eee5f72182481a"),
    ("kn", "ranking", KN / "ranking.jsonl", "26570a27d1474f220ae8cac5f01805d37019b67cec401a3bf90610588951cd37"),
    ("oz", "shard_novel", OZ / "shard_novel.jsonl", "bad0e50986cce173f3e1f440c041bdd937576b4ecec2a10caa3f01556983b543"),
    ("oz", "ai_mine", OZ / "ai_mine.jsonl", "047bbb068b09194a59a934117fec1448563e073147bf2e005d53f427bdc8c18a"),
}
for shard, kind, path, digest in files:
    assert path.exists(), path
    assert h(path) == digest, (kind, h(path))

def load_jsonl(path):
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows

def reconstruct_pool_ids():
    seen = set()
    ids = []
    def add(gid):
        gid = str(gid or "").upper()
        if gid.startswith("GHSA-") and gid not in seen:
            seen.add(gid)
            ids.append(gid)
    for r in load_jsonl(AF / "review-queue.jsonl"):
        add(r.get("case_id"))
    for r in load_jsonl(GJ / "origin-rank.jsonl"):
        add(r.get("ghsa_id"))
    for r in load_jsonl(GN / "ai-ghsa-intersections.jsonl"):
        add(r.get("ghsa_id"))
    for r in load_jsonl(KN / "ranking.jsonl"):
        add(r.get("ghsa_id"))
    for r in load_jsonl(OZ / "shard_novel.jsonl"):
        add(r.get("ghsa_id"))
    return ids

pool = reconstruct_pool_ids()
assert len(pool) == 5980 == len(set(pool))
r20 = [r["ghsa_id"] for r in load_jsonl(R20)]
assert r20 == pool
pool_hash = sha256("\n".join(pool).encode("ascii")).hexdigest()
assert pool_hash == res["conservation"]["pool_ids_sha256"] == "0c5ec3f753e27e6bcf78d1edcb77496fce7406ab510034dacd43fd1f5703581a"
canon_in_pool = sorted(canon & set(pool))
assert len(canon_in_pool) == 17
assert canon_in_pool == res["conservation"]["canonical94_in_pool"]
remaining_ids = res["remaining_ids"]
assert len(remaining_ids) == 611 == len(set(remaining_ids))
assert set(remaining_ids).isdisjoint(canon)
assert set(remaining_ids) <= set(pool)
assert sha256("\n".join(remaining_ids).encode("ascii")).hexdigest() == res["conservation"]["remaining_ids_sha256"] == "91095c0b6e9e9453a5f8dcf54031ac92eb7a7648601f5c785e9c9773428514d4"
term_excl = 5980 - 17 - 611
assert term_excl == 5352
assert 5980 == 17 + 5352 + 611
assert set(want) <= set(remaining_ids)
assert len(remaining_ids) - 100 == 511
assert sha256("\n".join(want).encode("ascii")).hexdigest() == res["selected_ids_sha256"]

text = (OWN / "report.md").read_text()
assert "does not call a PASS" in text
assert "ROUTE 0" in text
assert "5980 = 17 canonical94-in-pool + 5352 terminals-in-pool-excluding-canonical + 611 remaining" in text
assert "ROUTE IDs: none." in text

pins_git = res["git_pins"]
for cid, spec in pins_git.items():
    clone = Path(spec["clone"])
    assert clone.exists(), clone
    out = git(clone, "rev-list", "--parents", "-n", "1", spec["member"]).stdout.strip().split()
    assert len(out) - 1 == spec["expect_parents"], (cid, out)
    ident = git(clone, "log", "-1", "--format=%an <%ae>", spec["member"]).stdout
    assert spec["expect_author_substr"].lower() in ident.lower(), (cid, ident)
    if spec.get("expect_ancestor") is False:
        rc = git(clone, "merge-base", "--is-ancestor", spec["member"], spec["closer"]).returncode
        assert rc != 0, cid

print("REPLAY_OK inspected=100 ROUTE=0 PASS=0 canonical94=94 equation=5980=17+5352+611")
PY
