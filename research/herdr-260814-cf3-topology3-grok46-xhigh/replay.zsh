#!/usr/bin/env zsh
# Fail-closed replay for herdr-260814-cf3-topology3-grok46-xhigh. English ASCII only.
# Does not clone, fetch, commit, or push. Does not print credentials.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-cf3-topology3-grok46-xhigh
CONTRACT_H=cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
LAYERS_H=70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f
C86_H=74efef286737bcbd852bf1887ffa34b30224f7902f96a2c45455ba399a4d739c
FOUND_H=0b9cd2daae23e33faf3f2ceed46bba4802e2f9b0ef9c739f0bce7e6f4a16f687
PIN=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database
Z=/home/hanqing/.cache/cve-analyzer/repos/qhkm_zeptoclaw
L=/home/hanqing/.cache/cve-analyzer/repos/langroid_langroid
FROZEN=a42c436870111aa3f221257c9d56126a93173ccc

expect_hash() {
  local target=$1 expected=$2
  local got
  got=$(/usr/bin/sha256sum "$target" | /usr/bin/awk '{print $1}')
  if [[ $got != "$expected" ]]; then
    printf 'hash mismatch %s\n' "$target" >&2
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
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" "$CONTRACT_H"
expect_hash "$ROOT/docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md" "$LAYERS_H"
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical86/summary.json" "$C86_H"
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl" "$FOUND_H"
require_absent "$OWNED/work/clones"
require_absent "$OWNED/work/pages"
require_absent "$OWNED/work/advisories"
require_absent /tmp/herdr-260814-cf3-topology3-grok46-xhigh

if [[ -d $PIN/.git ]]; then
  pin_got=$(git -C "$PIN" rev-parse HEAD)
  if [[ $pin_got != "$FROZEN" ]]; then
    printf 'pinned advisory clone moved: %s\n' "$pin_got" >&2
    exit 1
  fi
  if [[ -e $PIN/advisories/github-reviewed/2026/08/GHSA-cw23-qwr7-c655/GHSA-cw23-qwr7-c655.json ]]; then
    printf 'unexpected reviewed CW23 object\n' >&2
    exit 1
  fi
  require_file "$PIN/advisories/github-reviewed/2026/03/GHSA-5wp8-q9mx-8jx8/GHSA-5wp8-q9mx-8jx8.json"
  require_file "$PIN/advisories/github-reviewed/2026/02/GHSA-x34r-63hx-w57f/GHSA-x34r-63hx-w57f.json"
fi

python3 - <<'PY'
import hashlib, json, re, subprocess
from pathlib import Path
root = Path("/home/hanqing/agents/ai-slop")
owned = root / "autoresearch/herdr-260814-cf3-topology3-grok46-xhigh"
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(r"ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}")
def load_jsonl(p):
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
for name in ("assignment.jsonl", "cases.jsonl", "result.json", "report.md", "replay.zsh"):
    raw = (owned / name).read_text(encoding="utf-8")
    assert raw.endswith("\n") and raw.isascii()
    assert not han.search(raw) and not secret.search(raw)
    for line in raw.splitlines():
        assert line == line.rstrip(" \t")
assign = load_jsonl(owned / "assignment.jsonl")
cases = load_jsonl(owned / "cases.jsonl")
result = json.loads((owned / "result.json").read_text())
assert len(assign) == 3 and len(cases) == 3
assert [r["case_id"] for r in assign] == [r["case_id"] for r in cases]
assert result["conservation"]["equation"] == "3=3+0"
assert result["counts"]["PASS_PROPOSAL"] == 0
assert result["PASS_PROPOSAL"] == []
assert result["terminal"] is True
assert result["canonical86_overlap"] == []
assert result["cve_aliases_counted"] is False
assert result["packet_delta"] == 0
assert result["seven_gates_exact_pass_required"] is True
assert result["canonical_ledger_edited"] is False
c86 = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical86/summary.json").read_text())
strict = {x.upper() for x in c86["strict_released_case_ids"]}
assert len(strict) == 86
ids = [r["case_id"] for r in cases]
assert set(ids).isdisjoint(strict)
gates = ["identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate", "uniqueness_gate"]
for r in cases:
    g = r["gates"]
    assert all(k in g for k in gates)
    assert r["seven_gates_exact_pass"] is False
    assert r["countable_proposal"] is False
    assert r["authorship_transfer_from_member_to_carrier"] is False
    assert r["in_canonical86_strict"] is False
    if r["verdict"] == "PASS":
        raise SystemExit("unexpected PASS")
assert result["per_case"]["GHSA-5WP8-Q9MX-8JX8"] == "NARROW"
assert result["per_case"]["GHSA-CW23-QWR7-C655"] == "REJECT"
assert result["per_case"]["GHSA-X34R-63HX-W57F"] == "REJECT"
assert "0 PASS_PROPOSAL" in (owned / "report.md").read_text()
ah = result["artifact_hashes"]
for name in ("assignment.jsonl", "cases.jsonl", "report.md", "replay.zsh"):
    got = hashlib.sha256((owned / name).read_bytes()).hexdigest()
    assert got == ah[name], (name, got, ah[name])
assert "result.json" not in ah
Z = "/home/hanqing/.cache/cve-analyzer/repos/qhkm_zeptoclaw"
L = "/home/hanqing/.cache/cve-analyzer/repos/langroid_langroid"
def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
if Path(Z).exists():
    r = git(Z, "merge-base", "--is-ancestor", "3c4368da0ab48c1091858d3f9503c378a209997f", "v0.6.1")
    assert r.returncode == 1
    mb = git(Z, "rev-parse", "3c4368da0ab48c1091858d3f9503c378a209997f:src/security/shell.rs").stdout.strip()
    vb = git(Z, "rev-parse", "v0.6.1:src/security/shell.rs").stdout.strip()
    assert mb != vb
    np = git(Z, "rev-list", "--parents", "-n1", "3c4368da0ab48c1091858d3f9503c378a209997f").stdout.split()
    assert len(np) - 1 == 1
    pk = git(Z, "log", "--first-parent", "-S", "allowlist.is_empty", "--format=%H", "v0.6.1", "--", "src/security/shell.rs").stdout.split()
    assert pk and pk[0].startswith("1712debb")
    peel = git(Z, "rev-parse", "v0.6.1^{commit}").stdout.strip()
    assert peel.startswith("ad14ed8d")
if Path(L).exists():
    r = git(L, "merge-base", "--is-ancestor", "b1c45e3fc0f3578a5dea9844c0216044321ae1c8", "0.59.31")
    assert r.returncode == 1
    mb = git(L, "rev-parse", "b1c45e3fc0f3578a5dea9844c0216044321ae1c8:langroid/utils/pandas_utils.py").stdout.strip()
    vb = git(L, "rev-parse", "0.59.31:langroid/utils/pandas_utils.py").stdout.strip()
    fb = git(L, "rev-parse", "30abbc1a854dee22fbd2f8b2f575dfdabdb603ea:langroid/utils/pandas_utils.py").stdout.strip()
    assert mb != vb and vb != fb
    np = git(L, "rev-list", "--parents", "-n1", "b1c45e3fc0f3578a5dea9844c0216044321ae1c8").stdout.split()
    assert len(np) - 1 == 1
print("VALIDATION_OK inspected=3 PASS_PROPOSAL=0 conservation=3=3+0")
PY
printf 'REPLAY_OK inspected=3 PASS_PROPOSAL=0 conservation=3=3+0\n'
