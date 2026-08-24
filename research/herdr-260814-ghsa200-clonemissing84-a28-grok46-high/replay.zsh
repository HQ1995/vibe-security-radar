#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-clonemissing84-a28-grok46-high.
# English only. Do not print credentials. Do not clone, fetch, commit, or push.
# Do not call GitHub API. PASS is a proposal only; this packet admits none.
# 85=1+84 clone_missing conservation. Slice 1-28. 28=26 NOT_SELECTED + 2 BLOCKED.
# PASS=0. Whole-case REJECT=0.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export PYTHONDONTWRITEBYTECODE=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-clonemissing84-a28-grok46-high
SRC=$ROOT/autoresearch/herdr-260814-ghsa200-commitfirst-prefilter20-grok46-xhigh
R11=$ROOT/autoresearch/herdr-260814-ghsa200-promisor389-residual11-grok46-high
CACHE=/home/hanqing/.cache/ai-slop-ghsa200/clonemissing84-a28

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

require_file "$OWNED/assignment28.jsonl"
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
require_file "$OWNED/work/recover.py"
require_file "$OWNED/notes/facts/html_identity.json"
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
expect_hash "$SRC/work/original-hits.jsonl" \
  bb84ee18b73481805a32074496561e04c08dfed95d0379058c8c2045d5c63a5a
expect_hash "$SRC/work/candidate-pool.jsonl" \
  7fc0b4741c45d1b3e375b14b51b603045dc6d092e180818c5ae7f861fc783b50
expect_hash "$SRC/summary.json" \
  e25dc5bf1578f9667b25aee55ba87001107afa8945fbde77b12fa76035d721ba
expect_hash "$R11/assignment11.jsonl" \
  8b4f6941650662f910aa17cb299c2902791b7fa46692a6b37b485a62ec8fd80b

expect_hash "$OWNED/assignment28.jsonl" 32fca2d9b1c295e2ed2da5171a862817326ad59a31258d18b243a0a7955ebd54
expect_hash "$OWNED/adjudications.jsonl" 71a8302111473b32609b6ee155e0c163d2bd65d5f30d1b3994476c4c1026d5d4
expect_hash "$OWNED/cases.jsonl" bea3d67275a74621abe00fa6e950e088e0f97853dd6e8b877458cc4c00419750
expect_hash "$OWNED/selected.jsonl" e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/report.md" 54a8da3bf76e0ebb041300fc0a7df7182933bc1727a3c4ad8dd3176c731c4059
expect_hash "$OWNED/result.json" 9ffcb5abbf434953db50bbcba8fa23f37ffbe7b6891bfb34a09267923cd6c074
expect_hash "$OWNED/summary.json" 066881053a7adc535ff4207f759c7c0105a8e13d3d0492e0ada59edaf96a7670
expect_hash "$OWNED/work/conservation.json" 757a8182e4e8bd19b92bded22b857c9e547beec9a710a8f1f1d77809c6237ee1
expect_hash "$OWNED/work/uniqueness.json" 014e10168d52913d6352fd0a23074d6b9da16ac819067ed1db58fbfb62d9c950
expect_hash "$OWNED/work/freeze.json" 4dba1402d26a24c326ef2e988a5fd5d8606f907bd7ceb0b3bc9af9626cb82e06
expect_hash "$OWNED/work/input_pins.json" b93bd1b4428b335a1aa56a7ee6eb5aad1b9d30668d21b40fdd75bbcca305ca81
expect_hash "$OWNED/work/emit_artifacts.py" ad349bfcead4623a4afa8d45f64ae40531d26231b4f37e493dd96c61da0361d1
expect_hash "$OWNED/work/recover.py" 11c7cc9d0fc7cd1a3a6467152141378181cafee750f4002dad6961023cb38548
expect_hash "$OWNED/notes/facts/html_identity.json" 57637ee6ad5bf4b65f538bf05c4af66768b6a5672c11eb61a352e089b406e456
expect_hash "$OWNED/notes/README.md" c1e3dfc8434361ea91eb81e95033c2d242f6b482811718baf93f8ea5bc57fda0

python3 -B - "$OWNED" "$SRC/work/original-hits.jsonl" "$SRC/work/candidate-pool.jsonl" \
  "$R11/assignment11.jsonl" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" << 'PY'
import json, re, sys
from pathlib import Path
owned = Path(sys.argv[1])
hits = [json.loads(l) for l in Path(sys.argv[2]).read_text().splitlines() if l.strip()]
pool = [json.loads(l) for l in Path(sys.argv[3]).read_text().splitlines() if l.strip()]
r11 = [json.loads(l)["case_id"].upper() for l in Path(sys.argv[4]).read_text().splitlines() if l.strip()]
cm = [r["ghsa_id"].upper() for r in hits if r.get("skip") == "clone_missing"]
assert len(hits) == 5980
assert len(pool) == 5980
assert len(cm) == 85
assert len(set(cm)) == 85
pool_ids = {r["ghsa_id"].upper() for r in pool}
assert set(cm) <= pool_ids
PRE = "GHSA-Q2M9-6JP9-C6MC"
assert PRE in cm
assert PRE in r11
assert r11.index(PRE) == 2
post = [x for x in cm if x != PRE]
assert len(post) == 84
assert len(set(post)) == 84
expected = [
    "GHSA-45HJ-9X76-WP9G",
    "GHSA-VX5F-VMR6-32WF",
    "GHSA-38F7-945M-QR2G",
    "GHSA-8CR7-R8QW-GP3C",
    "GHSA-8MPM-Q7MH-8FVH",
    "GHSA-C5C6-37VQ-PJCQ",
    "GHSA-PHQM-JGC3-QF8G",
    "GHSA-QXMC-6F24-G86G",
    "GHSA-23JG-5F8M-GW8C",
    "GHSA-3GXM-WFJX-M847",
    "GHSA-5478-66C3-RHXR",
    "GHSA-65W6-PF7X-5G85",
    "GHSA-8GGF-R3VM-P3JC",
    "GHSA-95MQ-XWJ4-R47P",
    "GHSA-FCMH-QFXC-W685",
    "GHSA-MRXX-39G5-PH77",
    "GHSA-P5RH-VMHP-GVCW",
    "GHSA-QC5P-3MG5-9FH8",
    "GHSA-R466-RXW4-3J9J",
    "GHSA-RW2C-8RFQ-GWFV",
    "GHSA-VVF7-6RMR-M29Q",
    "GHSA-X3F4-V83F-7WP2",
    "GHSA-X92X-PX7W-4GX4",
    "GHSA-XJVP-7243-RG9H",
    "GHSA-258C-965C-P3HC",
    "GHSA-32Q2-HHR5-6QVV",
    "GHSA-37J4-88RP-2F6H",
    "GHSA-3H23-7824-PJ8R",
]
assert post[:28] == expected
assert PRE not in expected
assigned = [json.loads(l)["case_id"] for l in (owned / "assignment28.jsonl").read_text().splitlines() if l.strip()]
adj = [json.loads(l) for l in (owned / "adjudications.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
assert assigned == expected
assert [r["order"] for r in adj] == list(range(1, 29))
assert [r["case_id"] for r in adj] == expected
assert [r["case_id"] for r in cases] == expected
assert [r["assigned_order"] for r in cases] == list(range(1, 29))
assert sel == []
assert len(adj) == 28 and len(cases) == 28
assert sum(1 for r in adj if r["worker_verdict"] == "NOT_SELECTED") == 26
assert sum(1 for r in adj if r["worker_verdict"] == "BLOCKED") == 2
assert all(r["worker_verdict"] != "PASS" for r in adj)
assert all(r["worker_verdict"] != "REJECT" for r in adj)
assert all(r["whole_case_causal_reject"] is False for r in adj)
assert all(r["ghsa_wide_not_ai"] is False for r in adj)
assert all(r["no_hit_is_not_causal_negative"] is True for r in adj)
assert adj[8]["case_id"] == "GHSA-23JG-5F8M-GW8C" and adj[8]["worker_verdict"] == "BLOCKED"
assert adj[12]["case_id"] == "GHSA-8GGF-R3VM-P3JC" and adj[12]["worker_verdict"] == "BLOCKED"
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
    if r["worker_verdict"] == "NOT_SELECTED":
        assert r["identity_gate"] == "PASS"
        assert r["ai_hunk_gate"] == "NOT_OPENED"
        assert r["uniqueness_gate"] == "NOT_OPENED"
        assert r["failing_gates"] == []
    if r["worker_verdict"] == "BLOCKED":
        assert r["identity_gate"] == "FAIL"
        assert r["ai_hunk_gate"] == "NOT_OPENED"
cons = json.loads((owned / "work/conservation.json").read_text())
assert cons["clone_missing_source"] == 85
assert cons["preexcluded"] == 1
assert cons["preexcluded_id"] == PRE
assert cons["post_uniqueness"] == 84
assert cons["equation"] == "85=1+84"
assert cons["slice_ids"] == expected
assert cons["did_not_pad"] is True
assert cons["did_not_backfill"] is True
assert cons["did_not_replace"] is True
assert cons["did_not_silent_drop"] is True
assert cons["slice_equation"] == "28=26+2"
res = json.loads((owned / "result.json").read_text())
summary = json.loads((owned / "summary.json").read_text())
uniq = json.loads((owned / "work/uniqueness.json").read_text())
assert res["status"] == "TERMINAL"
assert res["counts"]["PASS"] == 0
assert res["counts"]["NOT_SELECTED"] == 26
assert res["counts"]["BLOCKED"] == 2
assert res["counts"]["whole_case_causal_reject"] == 0
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["current_leader_accepted_count"] == 84
assert res["github_api_used"] is False
assert summary["pass_proposals"] == 0
assert summary["equation"] == "28=26+2"
assert summary["source_equation"] == "85=1+84"
c84 = json.loads(Path(sys.argv[5]).read_text())
assert c84["canonical_strict_count"] == 84
assert len(c84["strict_released_case_ids"]) == 84
assert set(expected).isdisjoint(set(x.upper() for x in c84["strict_released_case_ids"]))
assert uniq["canonical_overlap_n"] == 0
html = json.loads((owned / "notes/facts/html_identity.json").read_text())
assert set(html.keys()) == set(expected)
assert len(html) == 28
for cid in expected:
    row = html[cid]
    if cid in ("GHSA-23JG-5F8M-GW8C", "GHSA-8GGF-R3VM-P3JC"):
        assert row["http_ok"] is False
        assert row["ghsa_present"] is False
        assert row["http_code"] == 404
    else:
        assert row["ghsa_present"] is True
        assert row["withdrawn"] is False
        assert row["login_wall"] is False
        assert row["http_ok"] is True
report = (owned / "report.md").read_text()
assert "Proposed PASS = 0" in report
assert "85=1+84" in report
assert "28=26+2" in report
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
    "assignment28.jsonl", "adjudications.jsonl", "cases.jsonl", "selected.jsonl",
    "report.md", "replay.zsh", "result.json", "summary.json",
    "work/uniqueness.json", "work/freeze.json", "work/conservation.json",
    "notes/README.md", "sha256.txt", "notes/facts/html_identity.json",
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
print("conservation assigned=28 equation=85=1+84 slice=28=26+2 NOT_SELECTED=26 BLOCKED=2 PASS=0 REJECT=0 selected=0 packet_delta=0 current_leader_accepted_count=84 clone_lane_absent=1")
PY

cd "$OWNED"
/usr/bin/python3 - << 'CHK'
from pathlib import Path
owned = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-clonemissing84-a28-grok46-high")
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
for f in report.md replay.zsh summary.json result.json adjudications.jsonl cases.jsonl assignment28.jsonl; do
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
printf 'replay_ok PASS=0 NOT_SELECTED=26 BLOCKED=2 clone_lane_absent\n'
