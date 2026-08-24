#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-fresh-strict-grok46-xhigh.
# English ASCII. Do not print credentials. Do not clone, commit, or push.
# Worker PASS is a proposal only. Packet delta is 0. Canonical84 stays 84.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-fresh-strict-grok46-xhigh
OW=/home/hanqing/.cache/cve-analyzer/repos/open-webui_open-webui
CANON=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84
ATTEMPT=03547759179672d216d2e1376dd1ae4fdad76a94
CLOSER=05098d25a58d03738e01c4e85e8852c3b4ad849c
git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0)

expect_hash() {
  local target=$1 expected=$2
  local got
  got=$(/usr/bin/sha256sum "$target" | /usr/bin/awk '{print $1}')
  if [[ $got != "$expected" ]]; then
    printf 'hash mismatch %s\n expected %s\n got      %s\n' "$target" "$expected" "$got" >&2
    exit 1
  fi
}

python3 - <<'PY'
import json, re, subprocess
from pathlib import Path
root = Path("/home/hanqing/agents/ai-slop")
owned = root / "autoresearch/herdr-260814-fresh-strict-grok46-xhigh"
canon = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json").read_text())
strict = set(canon["strict_released_case_ids"])
assert "GHSA-FRVJ-C5QP-XJ4W" not in strict
assert "GHSA-29RF-F4VV-PVQ6" not in strict
res = json.loads((owned / "result.json").read_text())
assert res["packet_delta"] == 0
assert res["current_leader_accepted_count"] == 84
assert res["publication_status"] == "HOLD"
assert res["pass_proposals"] == ["GHSA-FRVJ-C5QP-XJ4W"]
assert res["causal_admission"] is False
assert res["canonical_ledger_edited"] is False
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
ids = [c["case_id"] for c in cases]
assert ids == res["conservation"]["reviewed_case_ids"]
assert len(cases) == 13
assert len(set(ids)) == 13
assert res["conservation"]["equation"] == "13=13+0"
verdicts = {c["case_id"]: c["worker_verdict"] for c in cases}
assert verdicts["GHSA-FRVJ-C5QP-XJ4W"] == "PASS"
assert verdicts["GHSA-48P8-G2FX-3WWM"] == "UNKNOWN"
assert verdicts["GHSA-P5RM-JG5C-8C77"] == "NARROW"
assert verdicts["GHSA-WVPP-8HX9-P66J"] == "REJECT"
fr = next(c for c in cases if c["case_id"] == "GHSA-FRVJ-C5QP-XJ4W")
for g in ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"):
    assert fr["gates"][g] == "PASS"
assert fr["countable"] is False
assert fr["countable_proposal"] is True
assert fr["unclosed_gates"] == []
assert fr["failing_gates"] == []
SEVEN = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
from collections import Counter
vc = Counter(c["worker_verdict"] for c in cases)
assert dict(vc) == {"PASS": 1, "REJECT": 10, "NARROW": 1, "UNKNOWN": 1}
for c in cases:
    g = c["gates"]
    failing = c["failing_gates"]
    unclosed = c["unclosed_gates"]
    for k in SEVEN:
        v = g[k]
        if v == "FAIL":
            assert k in failing, (c["case_id"], k)
        else:
            assert k not in failing, (c["case_id"], k)
        if v == "UNKNOWN":
            assert k in unclosed, (c["case_id"], k)
        else:
            assert k not in unclosed, (c["case_id"], k)
    if c["worker_verdict"] == "PASS":
        assert all(g[k] == "PASS" for k in SEVEN)
        assert failing == [] and unclosed == []
    elif c["worker_verdict"] == "REJECT":
        assert failing, c["case_id"]
    elif c["worker_verdict"] == "UNKNOWN":
        assert failing == [] and unclosed, c["case_id"]
    elif c["worker_verdict"] == "NARROW":
        assert failing == []
        assert any(g[k] == "NARROW" for k in SEVEN)
    else:
        raise SystemExit("unexpected verdict " + c["case_id"])
for p in (owned / "result.json", owned / "cases.jsonl", owned / "report.md", owned / "replay.txt"):
    raw = p.read_text()
    if re.search(r"[^\x09\x0a\x0d\x20-\x7e]", raw):
        raise SystemExit("non-ascii " + str(p))
print("conservation and ASCII ok")
PY

expect_hash "$CANON/ledger.jsonl" "a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06"
expect_hash "$CANON/summary.json" "6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a"
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"
expect_hash "$OWNED/cases.jsonl" "6a13b08e9b569dfab705385985d5ea49f561c26e8ac28831e620c3e4dce1a742"
expect_hash "$OWNED/report.md" "94bc6f93423407f51115fcae412b690fdc497ce8d81f800c0ad3dd33cad02eec"
expect_hash "$OWNED/selected.jsonl" "058759c5468abb9fb80a458a000796af0a8848415911db954200d742fdfa9aaa"
expect_hash "$OWNED/replay.txt" "90e64c8230392235ea1de06ffd63550f8d31294afef1412311df0ec414858974"

if [[ ! -d $OW/.git && ! -e $OW/HEAD ]]; then
  printf 'missing open-webui clone\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$OW" merge-base --is-ancestor "$ATTEMPT" "$CLOSER"
parents=$("${git_cmd[@]}" -C "$OW" log -1 --format=%P "$ATTEMPT")
if [[ $parents != d4030a8aa5d48c2a1cb06c461566844aca2530ab ]]; then
  printf 'unexpected parent %s\n' "$parents" >&2
  exit 1
fi
body=$("${git_cmd[@]}" -C "$OW" log -1 --format=%B "$ATTEMPT")
printf '%s\n' "$body" | /usr/bin/grep -F 'Claude Opus 4.7' >/dev/null
python3 - <<'PY'
import re, subprocess
from pathlib import Path
ow = "/home/hanqing/.cache/cve-analyzer/repos/open-webui_open-webui"
owned = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-fresh-strict-grok46-xhigh")

def sanitizer(text: str) -> str:
    m = re.search(r"def _sanitize_proxy_path\(path: str\) -> str \| None:.*?return cleaned\n", text, re.S)
    assert m, "missing sanitizer"
    return m.group(0)

def git_show(rev):
    p = subprocess.run(
        ["/usr/bin/git","--no-optional-locks","-C",ow,"show",rev + ":backend/open_webui/routers/terminals.py"],
        capture_output=True, text=True, check=True,
    )
    return p.stdout

attempt = sanitizer(git_show("03547759179672d216d2e1376dd1ae4fdad76a94"))
closer = sanitizer(git_show("05098d25a58d03738e01c4e85e8852c3b4ad849c"))
assert "for _ in range(8)" in attempt
assert "if unquote(decoded) != decoded" not in attempt
assert "if unquote(decoded) != decoded" in closer
assert attempt == (owned / "work/releases/sanitizer-0.9.6.py").read_text()
assert closer == (owned / "work/releases/sanitizer-0.10.0.py").read_text()
print("FRVJ sanitizer equality ok")
PY

printf 'replay ok\n'
