#!/usr/bin/env zsh
# Fail-closed replay for herdr-260814-cf2-fresh-delta-grok46-xhigh. English ASCII only.
# Does not clone, fetch, commit, or push. Does not print credentials.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-cf2-fresh-delta-grok46-xhigh
FROZEN=a42c436870111aa3f221257c9d56126a93173ccc
CURRENT=6253da86d07848917009b6e81740ffbed19e349f
CONTRACT_H=cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
LAYERS_H=70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f
C85_H=47209f841a5cb793ae6146b4247990fd2af1d4e50d3d881e0b53904f850bbd0c
FOUND_H=0b9cd2daae23e33faf3f2ceed46bba4802e2f9b0ef9c739f0bce7e6f4a16f687

expect_hash() {
  local target=$1 expected=$2
  local got
  got=$(/usr/bin/sha256sum "$target" | /usr/bin/awk '{print $1}')
  if [[ $got != "$expected" ]]; then
    printf 'hash mismatch %s\n expected %s\n got      %s\n' "$target" "$expected" "$got" >&2
    exit 1
  fi
}

require_file() {
  if [[ ! -f $1 ]]; then
    printf 'missing file: %s\n' "$1" >&2
    exit 1
  fi
}

require_absent() {
  if [[ -e $1 ]]; then
    printf 'must be absent: %s\n' "$1" >&2
    exit 1
  fi
}

require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/result.json"
require_file "$OWNED/report.md"
require_file "$OWNED/replay.zsh"
require_file "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
require_file "$ROOT/docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md"
require_file "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json"
require_file "$ROOT/autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" "$CONTRACT_H"
expect_hash "$ROOT/docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md" "$LAYERS_H"
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json" "$C85_H"
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl" "$FOUND_H"

require_absent /tmp/herdr-260814-cf2-fresh-delta-grok46-xhigh
require_absent "$OWNED/work/advisories"

PIN=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database
if [[ -d $PIN/.git ]]; then
  pin_got=$(git -C "$PIN" rev-parse HEAD)
  if [[ $pin_got != "$FROZEN" ]]; then
    printf 'pinned advisory clone moved: %s\n' "$pin_got" >&2
    exit 1
  fi
fi

python3 - <<'PY'
import hashlib, json, re
from pathlib import Path

root = Path("/home/hanqing/agents/ai-slop")
owned = root / "autoresearch/herdr-260814-cf2-fresh-delta-grok46-xhigh"
frozen = "a42c436870111aa3f221257c9d56126a93173ccc"
current = "6253da86d07848917009b6e81740ffbed19e349f"
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(r"ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}")
ghsa_re = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")

def load_jsonl(path):
    rows = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows

for name in ("assignment.jsonl", "cases.jsonl", "result.json", "report.md", "replay.zsh"):
    raw = (owned / name).read_text(encoding="utf-8")
    assert raw.endswith("\n"), name
    assert raw.isascii(), name
    assert not han.search(raw), name
    assert not secret.search(raw), name
    for line in raw.splitlines():
        assert line == line.rstrip(" \t"), (name, line)

assign = load_jsonl(owned / "assignment.jsonl")
cases = load_jsonl(owned / "cases.jsonl")
result = json.loads((owned / "result.json").read_text())
assert len(assign) == 29
assert len(cases) == 29
a_ids = [r["case_id"] for r in assign]
c_ids = [r["case_id"] for r in cases]
assert a_ids == c_ids
assert len(set(a_ids)) == 29
for gid in a_ids:
    assert ghsa_re.fullmatch(gid), gid
assert result["conservation"]["equation"] == "29=29+0"
assert result["conservation"]["holds"] is True
assert result["counts"]["assigned"] == 29
assert result["counts"]["reviewed"] == 29
assert result["counts"]["unreviewed"] == 0
assert result["counts"]["PASS"] == 0
assert result["counts"]["PASS_PROPOSAL"] == 0
assert result["pass_proposal_ids"] == []
assert result["PASS_PROPOSAL"] == []
assert result["net_new"]["PASS_PROPOSAL"] == []
assert result["upgrades"]["PASS_PROPOSAL"] == []
assert result["upgrade_scan"]["upgrade_PASS_PROPOSAL"] == []
assert result["counts"]["net_new_pass_proposal"] == 0
assert result["counts"]["upgrade_pass_proposal"] == 0
assert result["terminal"] is True
assert result["advisory_database"]["frozen_head"] == frozen
assert result["advisory_database"]["current_head"] == current
assert result["advisory_database"]["added_reviewed"] == 14
assert result["advisory_database"]["modified_reviewed"] == 15
assert len(result["advisory_database"]["changed_paths"]) == 29
assert result["canonical85_overlap"] == []
assert result["cve_aliases_counted"] is False
assert result["packet_delta"] == 0
assert result["seven_gates_exact_pass_required"] is True
assert sum(1 for r in cases if r["verdict"] == "REJECT") == result["counts"]["REJECT"]
assert sum(1 for r in cases if r["verdict"] == "UNKNOWN") == result["counts"]["UNKNOWN"]
assert all(r["verdict"] != "PASS" for r in cases)
gates = ["identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
c85 = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json").read_text())
strict = {x.upper() for x in c85["strict_released_case_ids"]}
assert len(strict) == 85
found = set()
for line in (root / "autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl").read_text().splitlines():
    if line.strip():
        found.add(json.loads(line)["case_id"].upper())
assert len(found) == 165
found_in_delta = set(a_ids) & found
strict_in_delta = set(a_ids) & strict
assert sorted(found_in_delta) == result["upgrade_scan"]["foundation_modified"]
assert sorted(strict_in_delta) == result["upgrade_scan"]["canonical85_modified"]
modified_ids = [r["case_id"] for r in assign if r["delta_status"] == "M"]
assert len(modified_ids) == 15
for r in cases:
    g = r["gates"]
    assert all(k in g for k in gates)
    if r["verdict"] == "PASS":
        assert all(g[k] == "PASS" for k in gates), r["case_id"]
        assert r["case_id"] not in strict
    assert r.get("countable_proposal") is False
    assert r.get("net_new_countable_proposal") is False
    assert r.get("upgrade_countable_proposal") is False
    if r["in_canonical85_strict"] or r["case_id"] in strict:
        assert r["count_class"] == "canonical85_excluded_from_net_new"
        assert r["case_id"] not in result["net_new"]["PASS_PROPOSAL"]
    elif r["in_foundation"] or r["case_id"] in found:
        assert r["count_class"] == "foundation_upgrade"
        assert r["row_track"] == "foundation_upgrade"
        assert r["delta_status"] == "M"
        ur = r.get("upgrade_review") or {}
        assert "may_close_identity" in ur
        assert "may_close_release" in ur
        assert ur.get("seven_gates_exact_pass_after_replay") is False or all(g[k]=="PASS" for k in gates)
    else:
        assert r["count_class"] in ("net_new_added", "net_new_modified")
        assert r["row_track"] == "net_new"
    if r["delta_status"] == "M":
        ur = r.get("upgrade_review") or {}
        assert ur.get("upgrade_pass") is False
        assert ur.get("seven_gates_exact_pass_after_replay") is False
report = (owned / "report.md").read_text()
assert "0 PASS_PROPOSAL" in report
assert "0 upgrade PASS" in report
assert "0 net-new PASS" in report
assert "Policy correction" in report
assert frozen in report and current in report
assert not (owned / "work/advisories").exists()
assert not Path("/tmp/herdr-260814-cf2-fresh-delta-grok46-xhigh").exists()
ah = result["artifact_hashes"]
for name in ("assignment.jsonl", "cases.jsonl", "report.md", "replay.zsh"):
    got = hashlib.sha256((owned / name).read_bytes()).hexdigest()
    assert got == ah[name], (name, got, ah[name])
assert "result.json" not in ah

import subprocess
def present(path):
    return Path(path).exists()

def git_out(repo, *args):
    return subprocess.check_output(["git", "-C", repo, *args], text=True, stderr=subprocess.STDOUT)

# Optional local object checks. Skip if the shared cache is gone. Never fetch.
checks = [
    ("/home/hanqing/.cache/cve-analyzer/repos/pyasn1_pyasn1", "be353d755f42ea36539b4f5053c652ddf56979a6", False, "Simon Pichugin"),
    ("/home/hanqing/.cache/cve-analyzer/repos/nuxt_nuxt", "0103ce06fbbbdfa079a7f020ef8ce00121eac4a3", False, "Daniel Roe"),
    ("/home/hanqing/.cache/cve-analyzer/repos/nuxt_nuxt", "abded715723517a6b66d53109cfeb6d2d4fd600c", True, None),
    ("/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/cakephp__authentication", "1c1e29c7e8129cfbcae74558316ecd3ea50a8273", False, "Mark Story"),
    ("/home/hanqing/.cache/cve-analyzer/repos/github.com_fasterxml_jackson-databind", "24529da29fdf46ff94ca38de9ebf31cd188f5e8e", False, "Tatu Saloranta"),
    ("/home/hanqing/.cache/ghsa200-worker-clones/tail11/clones/migration-planner", "fd21a239216f5eeec635d16c72be9c033bd5d1aa", False, "Aviel Segev"),
    ("/home/hanqing/.cache/ghsa200-worker-clones/tail11/clones/migration-planner", "ec47a336a620f4a995f29c1c53e4e4bd70a26e00", False, "Ronen Avraham"),
    ("/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/fastify__fast-uri", "2a6d357a18a68e6d812824379fd3388a1ae50d05", False, None),
    ("/home/hanqing/.cache/cve-analyzer/repos/immutable-js_immutable-js", "3dd7e5655012597a41873e328bf9142a8901527b", True, None),
    ("/home/hanqing/.cache/cve-analyzer/repos/github.com_authorizerdev_authorizer", "66fe488fd2a4e7acf1e517334344d5e8f3ddd296", False, "Lakhan Samani"),
    ("/home/hanqing/.cache/cve-analyzer/repos/getgrav_grav", "d9f9f0369a07ae5c96cde700c7949e1237b29cf6", False, "Andy Miller"),
    ("/home/hanqing/.cache/cve-analyzer/repos/surrealdb_surrealdb", "8f89b260bb9692e5b0d58930793d482a8207eedc", False, "Tobie Morgan Hitchcock"),
    ("/home/hanqing/.cache/cve-analyzer/repos/surrealdb_surrealdb", "15579bd2cc57a3f88074acf54b42008598d9c87f", True, None),
    ("/home/hanqing/.cache/cve-analyzer/repos/openidentityplatform_openam", "2af597267e6eb9302f75445c2c726f9b84f62966", False, "Valera V Harseko"),
]
for repo, sha, expect_ai, author in checks:
    if not present(repo):
        continue
    kind = git_out(repo, "cat-file", "-t", sha).strip()
    assert kind == "commit", (repo, sha, kind)
    meta = git_out(repo, "log", "-1", "--format=%an%n%B", sha)
    has_ai = ("co-authored-by:" in meta.lower()) or ("made-with: cursor" in meta.lower())
    if expect_ai:
        assert has_ai, (repo, sha)
    else:
        if author:
            assert meta.splitlines()[0] == author, (repo, sha, meta.splitlines()[0])
fu = "/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/fastify__fast-uri"
if present(fu):
    rc = subprocess.call(["git", "-C", fu, "merge-base", "--is-ancestor", "0542a216860fd70c062a4730e620576f62ded057", "2a6d357a18a68e6d812824379fd3388a1ae50d05"])
    assert rc == 1, "counted 7P8R SHA must not be an ancestor of 4C8G closer"
print("VALIDATION_OK inspected=29 PASS_PROPOSAL=0 conservation=29=29+0")
PY

printf 'REPLAY_OK inspected=29 PASS_PROPOSAL=0 frozen=a42c436870111aa3f221257c9d56126a93173ccc current=6253da86d07848917009b6e81740ffbed19e349f\n'
