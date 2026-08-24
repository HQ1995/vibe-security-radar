#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-canonical84-sourcetier-qa-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
# Does not re-fetch. Raw /tmp pages must be absent.
# git diff --no-index --check /dev/null vs file. Never compare a file to itself.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export PYTHONDONTWRITEBYTECODE=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-canonical84-sourcetier-qa-grok46-xhigh
TMP=/tmp/ghsa200-canonical84-sourcetier-qa

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

if [[ -e $TMP ]]; then
  printf 'tmp path must be absent: %s\n' "$TMP" >&2
  exit 1
fi

require_file "$OWNED/cases84.jsonl"
require_file "$OWNED/negative-controls.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/summary.json"
require_file "$OWNED/manifest.json"
require_file "$OWNED/evidence/manifest.json"
require_file "$OWNED/replay.zsh"
require_file "$OWNED/sha256.txt"
require_file "$OWNED/work/freeze84.py"
require_file "$OWNED/work/freeze84.jsonl"
require_file "$OWNED/work/freeze_meta.json"
require_file "$OWNED/work/input_hashes.json"
require_file "$OWNED/work/tmp_raw_hashes.json"
forbid_bytecode

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$OWNED/work/freeze84.jsonl" \
  2f72b229454e21e3aade7b06a442e1cfcbfc1b9ad7b50b156c4c0e26224afda9

python3 "$OWNED/work/freeze84.py" >/dev/null
expect_hash "$OWNED/work/freeze84.jsonl" \
  2f72b229454e21e3aade7b06a442e1cfcbfc1b9ad7b50b156c4c0e26224afda9

python3 - << 'PY'
import json, re, subprocess
from pathlib import Path
root = Path("/home/hanqing/agents/ai-slop")
owned = root / "autoresearch/herdr-260814-ghsa200-canonical84-sourcetier-qa-grok46-xhigh"
rows = [json.loads(l) for l in (owned / "cases84.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
neg = [json.loads(l) for l in (owned / "negative-controls.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
fr = [json.loads(l) for l in (owned / "work/freeze84.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
summary = json.loads((owned / "summary.json").read_text(encoding="utf-8"))
assert len(rows) == 84, len(rows)
assert len(fr) == 84, len(fr)
ids = [r["case_id"] for r in rows]
assert ids == [r["case_id"] for r in fr]
assert len(set(ids)) == 84
assert "GHSA-47Q7-97XP-M272" not in ids
assert len(neg) == 1
assert neg[0]["case_id"] == "GHSA-47Q7-97XP-M272"
assert neg[0]["counted"] is False
assert neg[0]["status"] == "FAIL"
assert "negative_control_routing_object_inconsistency" in neg[0]["mismatch_reason"]
assert summary["canonical_strict_count"] == 84
assert summary["canonical_source_tier_status"] == "HOLD"
assert summary["strict_count_unchanged"] is True
assert summary["negative_control_in_count"] is False
assert summary["conservation"]["cases84"] == 84
assert summary["conservation"]["fetched_repo_advisory_http_200"] + summary["conservation"]["unfetched_or_non_200"] == 84
assert summary["counts"]["FAIL"] == 0
assert summary["counts"]["PASS"] == 1
assert summary["counts"]["UNKNOWN"] == 20
assert summary["counts"]["BLOCKED"] == 63
assert "GHSA-5RV5-XJ5J-3484" in summary["unknown_case_ids"]
assert "GHSA-68V4-HMWV-F43H" in summary["unknown_case_ids"]
for gid in ("GHSA-5RV5-XJ5J-3484", "GHSA-68V4-HMWV-F43H"):
    row = next(r for r in rows if r["case_id"] == gid)
    assert row["status"] == "UNKNOWN", (gid, row["status"])
    assert "exact_fix_topology_unresolved" in row["mismatch_reason"], gid
    assert row["status"] != "FAIL"
assert all(r["status"] != "FAIL" for r in rows)
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(
    r"git" + r"hub_pat_|"
    r"ghp_" + r"[A-Za-z0-9]{20,}|"
    r"xox[baprs]-|"
    r"AKIA" + r"[0-9A-Z]{16}|"
    r"BEGIN" + r" PRIVATE"
)
ws_hits = []
for p in owned.rglob("*"):
    if not p.is_file():
        continue
    if p.suffix in {".pyc", ".pyo"} or "__pycache__" in p.parts:
        continue
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    rel = str(p.relative_to(owned))
    for i, line in enumerate(text.splitlines(), 1):
        if line != line.rstrip(" \t"):
            ws_hits.append((rel, i))
    if rel != "sha256.txt":
        assert text.isascii(), rel
        assert not han.search(text), rel
        assert not secret.search(text), rel
        if text:
            assert text.endswith("\n"), rel
assert ws_hits == [], ws_hits[:8]
ws_err = ("trailing whitespace", "space before tab", "conflict marker")
check_files = [
    owned / "report.md",
    owned / "cases84.jsonl",
    owned / "negative-controls.jsonl",
    owned / "summary.json",
    owned / "replay.zsh",
    owned / "manifest.json",
]
for path in check_files:
    proc = subprocess.run(
        ["/usr/bin/git", "diff", "--no-index", "--check", "/dev/null", str(path)],
        capture_output=True,
        text=True,
    )
    blob = (proc.stdout or "") + (proc.stderr or "")
    low = blob.lower()
    if any(x in low for x in ws_err):
        raise AssertionError(("whitespace_error", path.name, blob[:400]))
    if proc.returncode not in (0, 1):
        raise AssertionError(("git_diff_unexpected_rc", path.name, proc.returncode, blob[:400]))
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
print("conservation counted=84 PASS=%s FAIL=%s UNKNOWN=%s BLOCKED=%s http200=%s http404=%s neg=1 out_of_count" % (
    summary["counts"]["PASS"],
    summary["counts"]["FAIL"],
    summary["counts"]["UNKNOWN"],
    summary["counts"]["BLOCKED"],
    summary["conservation"]["fetched_repo_advisory_http_200"],
    summary["conservation"]["fetched_repo_advisory_http_404"],
))
PY
forbid_bytecode
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"
printf 'REPLAY_OK counted=84 packet=PARTIAL canonical_source_tier=HOLD\n'
