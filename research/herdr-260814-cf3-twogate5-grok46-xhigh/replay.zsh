#!/usr/bin/env zsh
# Fail-closed replay for herdr-260814-cf3-twogate5-grok46-xhigh. English ASCII only.
# Does not clone, fetch, commit, or push. Does not print credentials.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-cf3-twogate5-grok46-xhigh
CONTRACT_H=cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
LAYERS_H=70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f
C87_H=17487d40720f4c20475df7df270e5bb1139726887c42bc50d999f0f7e713a722
FOUND_H=0b9cd2daae23e33faf3f2ceed46bba4802e2f9b0ef9c739f0bce7e6f4a16f687
RW6_H=8cb85b42f405595b834a4ccae9b782c488b8dfa340900ad5717bb0dac71cfae9
PIN=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database
C=/home/hanqing/.cache/cve-analyzer/repos/churchcrm_crm
O=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw
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
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical87/summary.json" "$C87_H"
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl" "$FOUND_H"
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/8rw6_acceptance.json" "$RW6_H"
require_absent "$OWNED/work/clones"
require_absent "$OWNED/work/pages"
require_absent "$OWNED/work/advisories"
require_absent /tmp/herdr-260814-cf3-twogate5-grok46-xhigh

if [[ -d $PIN/.git ]]; then
  pin_got=$(git -C "$PIN" rev-parse HEAD)
  if [[ $pin_got != "$FROZEN" ]]; then
    printf 'pinned advisory clone moved: %s\n' "$pin_got" >&2
    exit 1
  fi
  require_file "$PIN/advisories/github-reviewed/2026/07/GHSA-qjpc-qf9m-xwmr/GHSA-qjpc-qf9m-xwmr.json"
  if [[ -e $PIN/advisories/github-reviewed/2026/06/GHSA-37mf-vq43-5qp9/GHSA-37mf-vq43-5qp9.json ]]; then
    printf 'unexpected reviewed 37MF object\n' >&2
    exit 1
  fi
fi

python3 - <<'PY'
import hashlib, json, re, subprocess
from pathlib import Path
root = Path("/home/hanqing/agents/ai-slop")
owned = root / "autoresearch/herdr-260814-cf3-twogate5-grok46-xhigh"
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
assert len(assign) == 5 and len(cases) == 5
assert [r["case_id"] for r in assign] == [r["case_id"] for r in cases]
assert result["conservation"]["equation"] == "5=5+0"
assert result["counts"]["PASS_PROPOSAL"] == 0
assert result["PASS_PROPOSAL"] == []
assert result["terminal"] is True
assert result["canonical87_overlap"] == []
assert result["accepted_pending_8rw6"] == "GHSA-8RW6-P7M8-63JP"
assert result["cve_aliases_counted"] is False
assert result["packet_delta"] == 0
c87 = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical87/summary.json").read_text())
strict = {x.upper() for x in c87["strict_released_case_ids"]}
assert len(strict) == 87
ids = [r["case_id"] for r in cases]
assert set(ids).isdisjoint(strict)
assert "GHSA-8RW6-P7M8-63JP" not in ids
gates = ["identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate", "uniqueness_gate"]
for r in cases:
    g = r["gates"]
    assert all(k in g for k in gates)
    assert r["seven_gates_exact_pass"] is False
    assert r["countable_proposal"] is False
    assert r["authorship_transfer_from_member_to_carrier"] is False
    assert r["verdict"] == "REJECT"
ah = result["artifact_hashes"]
for name in ("assignment.jsonl", "cases.jsonl", "report.md", "replay.zsh"):
    got = hashlib.sha256((owned / name).read_bytes()).hexdigest()
    assert got == ah[name], (name, got, ah[name])
C = "/home/hanqing/.cache/cve-analyzer/repos/churchcrm_crm"
O = "/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw"
def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
if Path(C).exists():
    r = git(C, "merge-base", "--is-ancestor", "095bf81b318c892258a9874e63ebb017b971443d", "7.3.3")
    assert r.returncode == 1
    mb = git(C, "rev-parse", "095bf81b318c892258a9874e63ebb017b971443d:src/ChurchCRM/Plugin/PluginInstaller.php").stdout.strip()
    vb = git(C, "rev-parse", "7.3.3:src/ChurchCRM/Plugin/PluginInstaller.php").stdout.strip()
    assert mb != vb
    r = git(C, "merge-base", "--is-ancestor", "6ef78813e04987da217bbb081706715c1ecb19e9", "7.2.2")
    assert r.returncode == 1
    mb = git(C, "rev-parse", "6ef78813e04987da217bbb081706715c1ecb19e9:src/FundRaiserDelete.php").stdout.strip()
    vb = git(C, "rev-parse", "7.2.2:src/FundRaiserDelete.php").stdout.strip()
    assert mb != vb
if Path(O).exists():
    r = git(O, "merge-base", "--is-ancestor", "8e41c118fa80c186ac40676e87bfecf988101ecb", "v2026.6.6")
    assert r.returncode == 0
    r = git(O, "merge-base", "--is-ancestor", "55d1324c7d0d2146b16aaef9572b7177a710f881", "v2026.6.6")
    assert r.returncode == 1
    pb = git(O, "rev-parse", "0e702f106313c1c63a32a6e7b3dbb5e96e620656^:src/gateway/server/ws-connection/connect-policy.ts").stdout.strip()
    cb = git(O, "rev-parse", "0e702f106313c1c63a32a6e7b3dbb5e96e620656:src/gateway/server/ws-connection/connect-policy.ts").stdout.strip()
    assert pb == cb
    pb = git(O, "rev-parse", "17ceca86d698c104df48149ba85f8dfab3ea622c^:src/trajectory/export.ts").stdout.strip()
    cb = git(O, "rev-parse", "17ceca86d698c104df48149ba85f8dfab3ea622c:src/trajectory/export.ts").stdout.strip()
    assert pb == cb
print("VALIDATION_OK inspected=5 PASS_PROPOSAL=0 conservation=5=5+0")
PY
printf 'REPLAY_OK inspected=5 PASS_PROPOSAL=0 conservation=5=5+0\n'
