#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-blocked19-recovery-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
# Does not re-fetch. PASS is a proposal only; this packet admits none.
# 19=11 REJECT_CANDIDATE_EDGE + 8 NOT_SELECTED. Whole-case REJECT=0. BLOCKED=0.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export PYTHONDONTWRITEBYTECODE=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-blocked19-recovery-grok46-xhigh
P389=$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor389-consolidated-grok46-low
A1=$ROOT/autoresearch/herdr-260814-ghsa200-additiveguard-first30-grok46-high
A2=$ROOT/autoresearch/herdr-260814-ghsa200-additiveguard-next30-grok46-high
A3=$ROOT/autoresearch/herdr-260814-ghsa200-additiveguard-final36-grok46-high

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

require_file "$OWNED/target19.jsonl"
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
require_file "$OWNED/work/reconstruct_check.json"
require_file "$OWNED/work/emit_artifacts.py"
forbid_bytecode

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
expect_hash "$P389/result.json" \
  521f0783757f33519ce974bb30f8a56fcc3add3047a950f0b096e02aed2d728a
expect_hash "$A1/adjudications.jsonl" \
  8e1adc5063bcf55e8d6e7001f6ac7739493c5a93c8976b1d2bf89764f6bc1cdb
expect_hash "$A1/summary.json" \
  27bd37a1dda2a7a3ac05c91d7e58b65648e84c686dcb245af2d10c0b31604cb3
expect_hash "$A2/adjudications.jsonl" \
  e8aee78e8b2914935baff843cf599f9809c583a448858cefdae9e32cff6d54a1
expect_hash "$A2/summary.json" \
  ee6b194257ca3a3aa9f4701e4284540f3c485d2054939b3cd8c23dddfb8d6bf0
expect_hash "$A3/adjudications.jsonl" \
  78b66239f0141f465fca96711187b58b384d636d0dcbc01a58dd2e67b356cdb5
expect_hash "$A3/summary.json" \
  74472cc87bff4f0ec49323c8a35f32f8c767c2b65165b080fa9125ad3084e57c

expect_hash "$OWNED/target19.jsonl" cbc969d0a3cca0eb0a38e8330cdd47d2b405651ba18f4445732c091dbe2a4719
expect_hash "$OWNED/adjudications.jsonl" b7a2c1b9eed9478fe8f3716ce2e5744ae7515e7533995b774ea01f77fc8cac83
expect_hash "$OWNED/cases.jsonl" 402b739694cbf725a7efffc05e63574197ff115d5ecd3a530b15d4a51fdf8160
expect_hash "$OWNED/selected.jsonl" e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/report.md" 6c6a925b2258fecd12b3949820729341e37599147b0b18fbf7481af7dc9d4110
expect_hash "$OWNED/result.json" e1e1bfcc5e971a713007f4d6fd310654cee823f99d7a742de90c708f08ba05c0
expect_hash "$OWNED/summary.json" 01d9fcd819bd324aa50122d9b637ea443828cc811b174ba015a14dac39ad65f6
expect_hash "$OWNED/work/uniqueness.json" d89d2ddb649ce0742d7bf5d68d498807eb29afba0ef4dba105cb79f3bf33b5d9
expect_hash "$OWNED/work/freeze.json" f083969910cee02af9b0ed8073d61fd795fbed25e3d53ef04bece380a2d904e2
expect_hash "$OWNED/work/conservation.json" a91b926aad3e14034c86bb74f796fab741d9ee703056a8a8be6a2b7f5b50af5b
expect_hash "$OWNED/work/reconstruct_check.json" 5e8ca8c40c87b3031f8096170ba20628fd4ca8652ca44ba885dc2d27dee4cd20
expect_hash "$OWNED/work/emit_artifacts.py" dfa82531e580821bb1de28a76eeb68476f6b84b2fb667e91ee50261c877fc8c5
expect_hash "$OWNED/work/recover.py" af8b7eb205980caa269ebbdb323d0f9fb3bd9d70ed50fb17b3692638ef3bb760
expect_hash "$OWNED/work/analysis.json" 1f0f034ceaf57022635848d9861ed4382385c0a69556dad65f31b8ded0300039
expect_hash "$OWNED/notes/README.md" e97d7ee026e039c14ff326301ecde664a033d3357e07876f9a4489265c10e8fd
expect_hash "$OWNED/notes/scan/README.md" b1dcf505272ae0966719fa46a403e68a51ea710b4d73d397164d99a934202f26
expect_hash "$OWNED/work/input_pins.json" 1181502dcbb41a2ee6a0185cdb0190cd7eddee6a360e390ecabbd8c3a88a20f3
expect_hash "$OWNED/work/counts_check.json" e54926c0da1a5122533ca263676b993a21193aad4358c85708c5382095e966f7

python3 -B - "$OWNED" \
  "$P389/work/blocked.json" \
  "$A1/adjudications.jsonl" \
  "$A2/adjudications.jsonl" \
  "$A3/adjudications.jsonl" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" << 'PY'
import json, re, sys
from pathlib import Path
owned = Path(sys.argv[1])
blocked = json.loads(Path(sys.argv[2]).read_text())
def blocked_from(path):
    ids = []
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("worker_verdict") == "BLOCKED":
            ids.append(row["case_id"].upper())
    return ids
a = [x.upper() for x in blocked["blocked_ids"]]
b1 = blocked_from(sys.argv[3])
b2 = blocked_from(sys.argv[4])
b3 = blocked_from(sys.argv[5])
assert len(a) == 11
assert b1 == []
assert len(b2) == 6
assert len(b3) == 2
union = a + b2 + b3
assert len(union) == 19
assert len(set(union)) == 19
targets = [json.loads(l) for l in (owned / "target19.jsonl").read_text().splitlines() if l.strip()]
adj = [json.loads(l) for l in (owned / "adjudications.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
assert [t["ghsa_id"] for t in targets] == union
assert [r["case_id"] for r in adj] == union
assert [r["case_id"] for r in cases] == union
assert sel == []
assert sum(1 for r in adj if r["worker_verdict"] == "REJECT_CANDIDATE_EDGE") == 11
assert sum(1 for r in adj if r["worker_verdict"] == "NOT_SELECTED") == 8
assert all(r["worker_verdict"] != "REJECT" for r in adj)
assert all(r["worker_verdict"] != "PASS" for r in adj)
assert all(r["whole_case_causal_reject"] is False for r in adj)
assert all(r["ghsa_wide_not_ai"] is False for r in adj)
assert all(r["no_hit_is_not_causal_negative"] is True for r in adj)
for r in adj:
    if r["source_set"] == "A":
        assert r["worker_verdict"] == "REJECT_CANDIDATE_EDGE"
        assert r["ai_hunk_gate"] == "FAIL"
        assert r["but_for_gate"] == "NOT_OPENED"
        assert r["fix_reversal_gate"] == "NOT_OPENED"
        assert r["release_gate"] == "NOT_OPENED"
        assert r["uniqueness_gate"] == "NOT_OPENED"
        assert r["identity_gate"] == "PASS"
        assert r["topology_gate"] == "PASS"
    else:
        assert r["source_set"] == "B"
        assert r["worker_verdict"] == "NOT_SELECTED"
        assert r["ai_hunk_gate"] == "NOT_OPENED"
        assert r["identity_gate"] == "NOT_OPENED"
        assert r["topology_gate"] == "NOT_OPENED"
        assert r["but_for_gate"] == "NOT_OPENED"
        assert r["fix_reversal_gate"] == "NOT_OPENED"
        assert r["release_gate"] == "NOT_OPENED"
        assert r["uniqueness_gate"] == "NOT_OPENED"
        assert r["failing_gates"] == []
res = json.loads((owned / "result.json").read_text())
summary = json.loads((owned / "summary.json").read_text())
cons = json.loads((owned / "work/conservation.json").read_text())
assert res["status"] == "TERMINAL"
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 0
assert res["counts"]["REJECT_CANDIDATE_EDGE"] == 11
assert res["counts"]["NOT_SELECTED"] == 8
assert res["counts"]["BLOCKED"] == 0
assert res["counts"]["whole_case_causal_reject"] == 0
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["current_leader_accepted_count"] == 84
assert res["claim_boundary"]["no_hit_is_not_causal_negative"] is True
assert summary["pass_proposals"] == 0
assert summary["whole_case_causal_reject"] == 0
assert summary["causal_reject_from_no_hit"] is False
assert cons["equation"] == "19=11+8"
assert cons["assigned"] == 19
c84 = json.loads(Path(sys.argv[6]).read_text())
assert c84["canonical_strict_count"] == 84
assert len(c84["strict_released_case_ids"]) == 84
assert set(union).isdisjoint(set(x.upper() for x in c84["strict_released_case_ids"]))
report = (owned / "report.md").read_text()
assert "REJECT_CANDIDATE_EDGE" in report
assert "NOT_SELECTED" in report
assert "not a GHSA-wide causal negative" in report
assert "Residual recall" in report
assert "19=11+8" in report
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
    "target19.jsonl", "adjudications.jsonl", "cases.jsonl", "selected.jsonl",
    "report.md", "replay.zsh", "result.json", "summary.json",
    "work/uniqueness.json", "work/freeze.json", "work/conservation.json",
    "work/reconstruct_check.json", "notes/README.md", "sha256.txt",
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
print("conservation assigned=19 equation=19=11+8 REJECT_CANDIDATE_EDGE=11 NOT_SELECTED=8 PASS=0 REJECT=0 BLOCKED=0 selected=0 packet_delta=0 current_leader_accepted_count=84")
PY
forbid_bytecode
cd "$OWNED"
/usr/bin/python3 - << 'CHK'
from pathlib import Path
owned = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-blocked19-recovery-grok46-xhigh")
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
for f in report.md replay.zsh summary.json result.json adjudications.jsonl cases.jsonl target19.jsonl; do
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

printf 'REPLAY_OK assigned=19 claimed_edges=11 mining_windows=8 PASS_proposal=0 REJECT=0 REJECT_CANDIDATE_EDGE=11 NOT_SELECTED=8 NARROW=0 UNKNOWN=0 BLOCKED=0 selected=0 packet_delta=0 current_leader_accepted_count=84\n'
