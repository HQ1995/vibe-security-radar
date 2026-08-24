#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-promisor389-residual11-grok46-high.
# English only. Do not print credentials. Do not clone, fetch, commit, or push.
# Do not call GitHub API. PASS is a proposal only; this packet admits none.
# 11=10 UNKNOWN + 1 REJECT_CANDIDATE_EDGE. PASS=0. Whole-case REJECT=0.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export PYTHONDONTWRITEBYTECODE=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-promisor389-residual11-grok46-high
P389=$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor389-consolidated-grok46-low
B19=$ROOT/autoresearch/herdr-260814-ghsa200-blocked19-recovery-grok46-xhigh
CACHE=/home/hanqing/.cache/ai-slop-ghsa200/promisor389-residual11

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

forbid_bytecode() {
  local found
  found=$(/usr/bin/find "$OWNED" \( -name '__pycache__' -o -name '*.pyc' -o -name '*.pyo' \) -print)
  if [[ -n $found ]]; then
    printf 'bytecode present:\n%s\n' "$found" >&2
    exit 1
  fi
}

require_file "$OWNED/assignment11.jsonl"
require_file "$OWNED/adjudications.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/summary.json"
require_file "$OWNED/replay.zsh"
require_file "$OWNED/sha256.txt"
require_file "$OWNED/work/conservation.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/freeze.json"
require_file "$OWNED/work/emit_artifacts.py"
require_file "$OWNED/notes/facts/html_identity.json"
require_file "$OWNED/notes/facts/residual_candidates.json"
forbid_bytecode

if [[ -e $CACHE ]]; then
  printf 'clone lane still present: %s\n' "$CACHE" >&2
  exit 1
fi

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$P389/work/blocked.json" \
  bd5ecb641641fabd8da1981ea77dbfc13142770e9b53fa10ca515a6a9524b881
expect_hash "$P389/summary.json" \
  a84be77a88e51bf355b1ea51c88898d146e4eb88d84b5c24fc61c47a38387d27
expect_hash "$B19/adjudications.jsonl" \
  b7a2c1b9eed9478fe8f3716ce2e5744ae7515e7533995b774ea01f77fc8cac83
expect_hash "$B19/summary.json" \
  01d9fcd819bd324aa50122d9b637ea443828cc811b174ba015a14dac39ad65f6

expect_hash "$OWNED/assignment11.jsonl" 8b4f6941650662f910aa17cb299c2902791b7fa46692a6b37b485a62ec8fd80b
expect_hash "$OWNED/adjudications.jsonl" a8693acb6c9506bf804f7d367d400942a09326790cb74096d0aa362055ecc834
expect_hash "$OWNED/cases.jsonl" 16f571ef65ef1b6200a982862f4d789b80099b6d52f979e3decaee3e31a5820b
expect_hash "$OWNED/selected.jsonl" e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/report.md" 3604175a4d797da49c52f55f3848908bf00cdea12c38817877f94e3c18f47412
expect_hash "$OWNED/result.json" b3460c530bee10c3b7dabb0fe3d407f243a842aa0961d3e4704caabd61fe882b
expect_hash "$OWNED/summary.json" c190eb60b2d2af68d6c9e3fe72638f74724e570d3af8b46cd1006aabc386e599
expect_hash "$OWNED/work/conservation.json" 45ca08b9dd7c0f995f5c02ea944a93fe04daf9c89d99b4606509390411a30ed0
expect_hash "$OWNED/work/uniqueness.json" 7c0837b784df45853bc03a6b48f9b9704e38e3d60d96aa9f00d3e81df7aad8c1
expect_hash "$OWNED/work/freeze.json" 0bd876e855461dcb0f738c1ba31aaaf32585cd35fa8c828055d67a1689af62ff
expect_hash "$OWNED/work/input_pins.json" 1199e379dbab32d7e5a341a69e87bb81d358b7056bf374b9c6427da463e15afa
expect_hash "$OWNED/work/emit_artifacts.py" cdd8d42f552e8543aa02b0f6a15fb9579e0d88511fd7fc97925d4731af09166f
expect_hash "$OWNED/work/mine.py" c929ea7866b081fd7d7027e87636c797a9f3dbe955bce60f036649180993b2f6
expect_hash "$OWNED/notes/facts/html_identity.json" 061d04d65537956a3b67ef00f1fd20b3598fd3908cbdc5cf2f608aaaa447d595
expect_hash "$OWNED/notes/facts/residual_candidates.json" 8f01779b8babd9f6e7e54d0ee903087b5fe3fe0dec5ccd330f2509d5aeef75ff
expect_hash "$OWNED/notes/facts/uniqueness.json" 7c0837b784df45853bc03a6b48f9b9704e38e3d60d96aa9f00d3e81df7aad8c1
expect_hash "$OWNED/notes/README.md" 25fd801e11dc9612df9b66a7c4fcc02554cf0b8cd92ca7a76d17d2f7f1949d47

python3 -B - "$OWNED" \
  "$P389/work/blocked.json" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" << 'PY'
import json, re, sys
from pathlib import Path
owned = Path(sys.argv[1])
blocked = json.loads(Path(sys.argv[2]).read_text())
expected = [
    "GHSA-RMJ7-2VXQ-3G9F",
    "GHSA-833P-95JQ-929Q",
    "GHSA-Q2M9-6JP9-C6MC",
    "GHSA-F2R5-5M7W-P5CX",
    "GHSA-4X76-22X2-RX8V",
    "GHSA-C27G-Q93R-2CWF",
    "GHSA-R854-JRXH-36QX",
    "GHSA-94G3-G5V7-Q4JG",
    "GHSA-XJ4F-8JJG-VX4Q",
    "GHSA-MP2F-45PM-3CG9",
    "GHSA-W3CP-G2PF-65WH",
]
src = [x.upper() for x in blocked["blocked_ids"]]
assert src == expected
assigned = [json.loads(l)["case_id"] for l in (owned / "assignment11.jsonl").read_text().splitlines() if l.strip()]
adj = [json.loads(l) for l in (owned / "adjudications.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
assert assigned == expected
assert [r["order"] for r in adj] == list(range(1, 12))
assert [r["case_id"] for r in adj] == expected
assert [r["case_id"] for r in cases] == expected
assert [r["assigned_order"] for r in cases] == list(range(1, 12))
assert sel == []
assert len(adj) == 11 and len(cases) == 11
assert sum(1 for r in adj if r["worker_verdict"] == "UNKNOWN") == 10
assert sum(1 for r in adj if r["worker_verdict"] == "REJECT_CANDIDATE_EDGE") == 1
assert all(r["worker_verdict"] != "PASS" for r in adj)
assert all(r["worker_verdict"] != "REJECT" for r in adj)
assert all(r["whole_case_causal_reject"] is False for r in adj)
assert all(r["ghsa_wide_not_ai"] is False for r in adj)
assert all(r["no_hit_is_not_causal_negative"] is True for r in adj)
assert adj[1]["case_id"] == "GHSA-833P-95JQ-929Q"
assert adj[1]["worker_verdict"] == "REJECT_CANDIDATE_EDGE"
seven = [
    "identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate",
    "fix_reversal_gate", "release_gate", "uniqueness_gate",
]
pass_n = 0
for r in cases:
    if r["worker_verdict"] == "PASS":
        pass_n += 1
        for g in seven:
            assert r["gates"][g] == "PASS", (r["case_id"], g, r["gates"][g])
        assert r["countable_proposal"] is True
assert pass_n == 0
for r in adj:
    assert r["identity_gate"] == "PASS"
    if r["worker_verdict"] == "UNKNOWN":
        assert r["ai_hunk_gate"] == "NOT_OPENED"
        assert r["uniqueness_gate"] == "NOT_OPENED"
        assert r["failing_gates"] == []
    if r["worker_verdict"] == "REJECT_CANDIDATE_EDGE":
        assert r["ai_hunk_gate"] == "FAIL"
        assert r["topology_gate"] == "FAIL"
        assert r["but_for_gate"] == "FAIL"
        assert r["fix_reversal_gate"] == "FAIL"
        assert r["uniqueness_gate"] == "NOT_OPENED"
res = json.loads((owned / "result.json").read_text())
summary = json.loads((owned / "summary.json").read_text())
cons = json.loads((owned / "work/conservation.json").read_text())
uniq = json.loads((owned / "work/uniqueness.json").read_text())
assert res["status"] == "TERMINAL"
assert res["counts"]["PASS"] == 0
assert res["counts"]["UNKNOWN"] == 10
assert res["counts"]["REJECT_CANDIDATE_EDGE"] == 1
assert res["counts"]["whole_case_causal_reject"] == 0
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["current_leader_accepted_count"] == 84
assert res["github_api_used"] is False
assert summary["pass_proposals"] == 0
assert summary["equation"] == "11=10+1"
assert cons["equation"] == "11=10+1"
assert cons["assigned"] == 11
assert cons["did_not_pad"] is True
assert cons["did_not_backfill"] is True
c84 = json.loads(Path(sys.argv[3]).read_text())
assert c84["canonical_strict_count"] == 84
assert len(c84["strict_released_case_ids"]) == 84
assert set(expected).isdisjoint(set(x.upper() for x in c84["strict_released_case_ids"]))
assert uniq["canonical_overlap_n"] == 0
html = json.loads((owned / "notes/facts/html_identity.json").read_text())
assert set(html.keys()) == set(expected)
assert len(html) == 11
for cid in expected:
    row = html[cid]
    assert row["ghsa_present"] is True
    assert row["withdrawn"] is False
    assert row["login_wall"] is False
report = (owned / "report.md").read_text()
assert "Proposed PASS = 0" in report
assert "11=10+1" in report
assert "REJECT_CANDIDATE_EDGE" in report
assert "Stop at zero PASS" in report
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
    "assignment11.jsonl", "adjudications.jsonl", "cases.jsonl", "selected.jsonl",
    "report.md", "replay.zsh", "result.json", "summary.json",
    "work/uniqueness.json", "work/freeze.json", "work/conservation.json",
    "notes/README.md", "sha256.txt", "notes/facts/html_identity.json",
    "notes/facts/residual_candidates.json",
):
    text = (owned / name).read_text(encoding="utf-8")
    if name == "selected.jsonl" and text == "":
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
assert not list(owned.rglob("__pycache__"))
assert not list(owned.rglob("*.pyc"))
assert not list(owned.rglob("*.html"))
print("conservation assigned=11 equation=11=10+1 UNKNOWN=10 REJECT_CANDIDATE_EDGE=1 PASS=0 REJECT=0 BLOCKED=0 selected=0 packet_delta=0 current_leader_accepted_count=84 clone_lane_absent=1")
PY

cd "$OWNED"
/usr/bin/python3 - << 'CHK'
from pathlib import Path
owned = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-promisor389-residual11-grok46-high")
bad = []
for p in owned.rglob("*"):
    if not p.is_file():
        continue
    if p.name == "sha256.txt":
        continue
    if "__pycache__" in str(p) or p.suffix in (".pyc", ".pyo"):
        continue
    try:
        text = p.read_text(encoding="utf-8")
    except Exception:
        continue
    if text.endswith("\n\n"):
        bad.append(str(p.relative_to(owned)))
    for i, line in enumerate(text.splitlines(), 1):
        if line != line.rstrip(" \t"):
            bad.append("%s:%s:trailing" % (p.relative_to(owned), i))
if bad:
    raise SystemExit("whitespace: " + ", ".join(bad[:20]))
print("whitespace_ok")
CHK
for f in report.md replay.zsh summary.json result.json adjudications.jsonl cases.jsonl assignment11.jsonl; do
  set +e
  /usr/bin/git --no-pager diff --no-index --check /dev/null "$OWNED/$f"
  rc=$?
  set -e
  if [[ $rc -eq 2 || $rc -eq 3 ]]; then
    printf 'whitespace error %s rc=%s\n' "$f" "$rc" >&2
    exit 1
  fi
done
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"
printf 'replay_ok PASS=0 UNKNOWN=10 REJECT_CANDIDATE_EDGE=1 clone_lane_absent\n'
