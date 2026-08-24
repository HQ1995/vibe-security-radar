#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Current leader-accepted count is 84. Packet delta is 0.
# PASS is a proposal only. This script admits no row.
# Hard-prefilter misses are NOT_SELECTED, not causal REJECT.
# Seven gates stay NOT_OPENED because frozen=0.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export PYTHONDONTWRITEBYTECODE=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh

require_dir() {
  if [[ ! -d $1 ]]; then
    printf 'missing directory: %s\n' "$1" >&2
    exit 1
  fi
}

require_file() {
  if [[ ! -f $1 ]]; then
    printf 'missing file: %s\n' "$1" >&2
    exit 1
  fi
}

expect_hash() {
  local target=$1 expected=$2
  local got
  got=$(/usr/bin/sha256sum "$target" | /usr/bin/awk '{print $1}')
  if [[ $got != "$expected" ]]; then
    printf 'hash mismatch %s\n expected %s\n got      %s\n' "$target" "$expected" "$got" >&2
    exit 1
  fi
}

require_dir "$OWNED"
# Remove compile leftovers before hashing. Do not hash __pycache__ or pyc.
find "$OWNED" -type d -name '__pycache__' -prune -exec rm -rf {} +
find "$OWNED" -type f '(' -name '*.pyc' -o -name '*.pyo' ')' -delete
require_file "$OWNED/adjudications.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/summary.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/exclusion.json"
require_file "$OWNED/work/freeze.json"
require_file "$OWNED/work/probe-log.jsonl"
require_file "$OWNED/work/candidate-pool.jsonl"
require_file "$OWNED/work/scan-summary.json"
require_file "$OWNED/work/mining-outcomes.json"
require_file "$OWNED/sha256.txt"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-commitfirst-remainder20-grok46-high/selected.jsonl" \
  2a88815964279babab0591f7bfa01bf05cfd0741643889ffcbdbbac16d6159e8
expect_hash "/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-commitfirst-af/review-queue.jsonl" \
  fef5b3b2d175b57fd9ec043644dd0def5cc314a4574e675a2900bde071c9cdea
expect_hash "/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-commitfirst-af/ai-commits.jsonl" \
  9659e93e82df4428df361507c6728ac83988211b0282ffbc3c12e3aba529d6d0
expect_hash "/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-commitfirst-gj-grok46-medium/origin-rank.jsonl" \
  4ed1d2c6683593916536d2ada5c961f5c2120f00582da895a2f78bfdaa9534b3
expect_hash "/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-commitfirst-gn/ai-ghsa-intersections.jsonl" \
  c58444221e9cc00555ba251da75f518281bacd660a438f6cc8a5df3ac5cf331e
expect_hash "/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-commitfirst-gn/ai-commit-scans.jsonl" \
  a6d7ca1584dbeb1596c57643092df0178001925efe0de60ca3eee5f72182481a
expect_hash "/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-commitfirst-kn-grok46-low/ranking.jsonl" \
  26570a27d1474f220ae8cac5f01805d37019b67cec401a3bf90610588951cd37
expect_hash "/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/work/shard_novel.jsonl" \
  bad0e50986cce173f3e1f440c041bdd937576b4ecec2a10caa3f01556983b543
expect_hash "/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/work/ai_mine.jsonl" \
  047bbb068b09194a59a934117fec1448563e073147bf2e005d53f427bdc8c18a
expect_hash "$OWNED/selected.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/adjudications.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/cases.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/report.md" \
  491924f361d09b53fd7b008fa66fbd366727c7d9e94f56b7235745c6de861f24
expect_hash "$OWNED/work/candidate-files.json" \
  a01625535f356d0f2268873714c62a14ca37a78d657ccfc8de8fbcfde35740bd
expect_hash "$OWNED/work/candidate-pool.jsonl" \
  7fc0b4741c45d1b3e375b14b51b603045dc6d092e180818c5ae7f861fc783b50
expect_hash "$OWNED/work/exclusion.json" \
  32ba63a237dcbfbfe60a7e8ecf97af9c82b5861d86ebaa5904fc899f84dfa274
expect_hash "$OWNED/work/probe-log.jsonl" \
  1f687ee95fb804c6ea688b4cf7ef9433de5ea8edaef7ccdf09bf50b78fee7853
expect_hash "$OWNED/work/original-hits.jsonl" \
  bb84ee18b73481805a32074496561e04c08dfed95d0379058c8c2045d5c63a5a
expect_hash "$OWNED/work/freeze.json" \
  b13c60cce569671c1085c326dbcaf412627ee945756ebed00e14fffb143b2b34
expect_hash "$OWNED/work/uniqueness.json" \
  6adf0e2ea1c69213a8d43794f671f7c431c95a53b4aac7ffeb54495660d40adc
expect_hash "$OWNED/work/facts.json" \
  7d59e61b3282b649572455f222c2d28278aab24379f94ca2db0d482e59c5492f
expect_hash "$OWNED/work/scan-summary.json" \
  9f123d6c066b0d79c41c751b429062c27db5a05c01c5b18c4ad36f9c1047e82d
expect_hash "$OWNED/work/selector-correction.json" \
  3a0b9d7687e71b47b272aca63c75ad34a88f9d0347f3d79800dd982732b73ad1
expect_hash "$OWNED/work/mining-outcomes.json" \
  1d0ad22783f7d4c8480c8efd526cb6fdbff67410f02a52d56084e9ecaa3072cb
expect_hash "$OWNED/work/prefilter.py" \
  8e5abc258d20141e07db37b41c94d63d87b0464aae2e28d7b2d5f33bf418770e

python3 - "$OWNED" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
adj = [json.loads(l) for l in (owned / "adjudications.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned / "result.json").read_text())
summary = json.loads((owned / "summary.json").read_text())
uniq = json.loads((owned / "work/uniqueness.json").read_text())
freeze = json.loads((owned / "work/freeze.json").read_text())
probes = [json.loads(l) for l in (owned / "work/probe-log.jsonl").read_text().splitlines() if l.strip()]
pool = [json.loads(l) for l in (owned / "work/candidate-pool.jsonl").read_text().splitlines() if l.strip()]
report = (owned / "report.md").read_text()
assert rows == []
assert sel == []
assert adj == []
assert freeze["frozen_n"] == 0
assert freeze["selected_n"] == 0
assert freeze["seven_gates_opened"] is False
for gate in (
    "identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate",
    "fix_reversal_gate", "release_gate", "uniqueness_gate",
):
    assert freeze["seven_gates"][gate] == "NOT_OPENED"
    assert res["seven_gates"][gate] == "NOT_OPENED"
assert all(not r.get("ok") for r in probes)
assert len(pool) == 5980
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 0
assert res["counts"]["assigned"] == 0
assert res["counts"]["reviewed"] == 0
assert res["conservation"]["frozen"] == 0
assert res["conservation"]["excluded"] == 1064
assert res["conservation"]["scanned"] == 2301
assert res["conservation"]["unprobed"] == 2615
assert res["conservation"]["equation"] == "5980=1064+2301+2615"
assert res["conservation"]["scan_equation"] == "2301=2247+54+0"
assert res["conservation"]["unprobed_equation"] == "2615=85+2530"
assert res["conservation"]["scanned"] == len(probes)
assert res["mining"]["hard_prefilter_misses_are_not_causal_reject"] is True
assert "NOT_SELECTED" in report
assert "NOT_OPENED" in report
c84 = json.loads(Path(sys.argv[2]).read_text())
assert len(c84["strict_released_case_ids"]) == 84
assert res["packet_delta"] == 0
assert uniq["canonical84_strict_count"] == 84
assert uniq["uniqueness_gate"] == "NOT_OPENED"
assert summary["frozen"] == 0
assert summary["selected_count"] == 0
assert summary["excluded"] == 1064
assert summary["scanned"] == 2301
assert summary["unprobed"] == 2615
assert summary["equation"] == "5980=1064+2301+2615"
assert freeze["conservation"]["equation"] == "5980=1064+2301+2615"
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(
    r"ghp_" + r"[A-Za-z0-9]{20,}|"
    r"github" + r"_pat_[A-Za-z0-9_]+|"
    r"sk" + r"_live_|"
    r"xox[baprs]-|"
    r"AKIA" + r"[0-9A-Z]{16}|"
    r"BEGIN" + r" PRIVATE"
)
for name in (
    "adjudications.jsonl", "cases.jsonl", "selected.jsonl", "report.md",
    "replay.zsh", "result.json", "summary.json",
    "work/uniqueness.json", "work/exclusion.json", "work/facts.json",
    "work/freeze.json", "work/mining-outcomes.json", "notes/README.md",
    "sha256.txt",
):
    text = (owned / name).read_text(encoding="utf-8")
    if name in ("cases.jsonl", "selected.jsonl", "adjudications.jsonl") and text == "":
        continue
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    if text:
        assert text.endswith("\n"), name
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (name, line)
man_names = []
for line in (owned / "sha256.txt").read_text().splitlines():
    if not line.strip():
        continue
    parts = line.split()
    assert len(parts) == 2, line
    man_names.append(parts[1])
assert "./sha256.txt" not in man_names
assert "sha256.txt" not in man_names
assert all(not n.endswith("/sha256.txt") for n in man_names)
assert all("__pycache__" not in n and not n.endswith(".pyc") and not n.endswith(".pyo") for n in man_names)
print("conservation pool=5980 excluded=1064 scanned=2301 unprobed=2615 frozen=0 assigned=0 reviewed=0 REJECT=0 NOT_SELECTED NOT_OPENED PASS_proposal=0 current_leader_accepted_count=84 packet_delta=0")
PY
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"

printf 'REPLAY_OK reviewed=0 PASS_proposal=0 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=0 frozen=0 excluded=1064 scanned=2301 unprobed=2615 packet_delta=0 current_leader_accepted_count=84\n'
