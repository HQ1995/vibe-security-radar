#!/usr/bin/env zsh
# Fail-fast self-contained replay. English only. Do not print credentials.
# Deterministic path does not use network or /tmp/ghsa200-missingref-final13.
# PASS is a proposal only. This script admits no row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export PYTHONDONTWRITEBYTECODE=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-missingref-final13-grok46-medium
TMP_DECLARED=/tmp/ghsa200-missingref-final13

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

if [[ -e $TMP_DECLARED ]]; then
  printf 'declared temp path must be absent: %s\n' "$TMP_DECLARED" >&2
  exit 1
fi

require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/replay.zsh"
require_file "$OWNED/sha256.txt"
require_file "$OWNED/notes/pinned-facts.json"
require_file "$OWNED/notes/aliases.json"
require_file "$OWNED/notes/pin-manifest.sha256"
require_file "$OWNED/notes/git/a7463723257f.log.txt"
require_file "$OWNED/notes/git/release-containment.txt"
require_file "$OWNED/notes/git/33e70a01fe13.log.txt"
require_file "$OWNED/notes/diffs/db7eb4d.notification.go.diff.txt"
require_file "$OWNED/notes/diffs/33e70a01.notification.go.diff.txt"
forbid_bytecode

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/work/scan-miss.jsonl" \
  5ec5265e65d957d8a7877a1c27465e9463b404f73790cfb03fc9f011d5625e40

python3 -B - "$OWNED" <<'PY'
import json
import re
import sys
from pathlib import Path

owned = Path(sys.argv[1])
tmp = Path("/tmp/ghsa200-missingref-final13")
assert not tmp.exists(), "declared temp path must be absent"

facts = json.loads((owned / "notes/pinned-facts.json").read_text(encoding="utf-8"))
objs = facts["objects"]
assert objs["a746372_ssrf_rem"] == "a7463723257f84b139b69ffac011ffb5273ab8b1"
assert objs["squash_9e84deb"] == "9e84deb969aff5c1115c2984e41250f28c78451f"
assert objs["notify_33e70_rem"] == "33e70a01fe13958b0a860c0f34355aa3d7098e8e"
assert objs["notify_33e70_parent"] == objs["a746372_ssrf_rem"]
assert facts["semantic"]["ghsa_rqhx"]["verdict"] == "REJECT"
assert facts["semantic"]["ghsa_rqhx"]["a746_is_origin"] is False
assert facts["semantic"]["ghsa_rqhx"]["incomplete_rem_class_met"] is False
assert facts["semantic"]["ghsa_44qc"]["verdict"] == "NOT_SELECTED"
assert facts["semantic"]["ghsa_44qc"]["db7_is_origin"] is False
assert facts["provenance"]["deterministic_replay_requires_network"] is False

a746_log = (owned / "notes/git/a7463723257f.log.txt").read_text(encoding="utf-8")
assert "a7463723257f84b139b69ffac011ffb5273ab8b1" in a746_log
assert "fix(sec): block redirects in repository migration clone (SSRF)" in a746_log
assert "Assisted-by: Claude:claude-opus-4-8" in a746_log
parents = (owned / "notes/git/a7463723257f.parents.txt").read_text(encoding="utf-8")
assert objs["a746372_parent"] in parents
rel = (owned / "notes/git/release-containment.txt").read_text(encoding="utf-8")
assert "a746372 in v1.26.2 no" in rel
assert "a746372 in v1.26.4 no" in rel
assert objs["v1.26.2_peel"] in rel
assert objs["v1.26.3_peel"] in rel
assert objs["v1.26.4_peel"] in rel
n33 = (owned / "notes/git/33e70a01fe13.log.txt").read_text(encoding="utf-8")
assert "redact notification subject after repo access revoked" in n33
assert "Assisted-by: Claude:claude-opus-4-8" in n33
n33p = (owned / "notes/git/33e70a01fe13.parents.txt").read_text(encoding="utf-8")
assert objs["notify_33e70_parent"] in n33p
db7 = (owned / "notes/diffs/db7eb4d.notification.go.diff.txt").read_text(encoding="utf-8")
assert "GetUserRepoPermission" in db7
assert "GetIndividualUserRepoPermission" in db7
n33d = (owned / "notes/diffs/33e70a01.notification.go.diff.txt").read_text(encoding="utf-8")
assert "handle Subject" in n33d
assert "do not leak repo or subject info" in n33d
for cmd in facts["pinned_commands"]:
    src = (owned / cmd["source_note"]).read_text(encoding="utf-8")
    if "stdout" in cmd:
        assert cmd["stdout"] in src
    if "stdout_contains" in cmd:
        assert cmd["stdout_contains"] in src

fr = json.loads((owned / "work/freeze.json").read_text(encoding="utf-8"))
assert fr["equation"] == "141=98+43; 43=30+13"
assert fr["assigned13_n"] == 13
assert fr["did_not_pad"] and fr["did_not_backfill"]
assert fr["used_first30_outcomes"] is False
hits = json.loads((owned / "work/freeze-hits.json").read_text(encoding="utf-8"))
assert hits["did_not_union_by_repository"] is True
assert "GHSA-44QC-PGVP-WX7V" not in hits["frozen_hit_ids"]
assert hits["frozen_hit_ids"] == []
assert hits["frozen_hit_n"] == 0
assert "GHSA-RQHX-647V-WX32" in hits.get("reviewed_reject_ids", [])
probe = json.loads((owned / "work/probe.json").read_text(encoding="utf-8"))
by = {r["ghsa_id"]: r for r in probe["rows"]}
qc = by["GHSA-44QC-PGVP-WX7V"]
rq = by["GHSA-RQHX-647V-WX32"]
assert objs["a746372_ssrf_rem"] not in qc["fix_shas"]
assert objs["cleanup_492a914"] not in qc["fix_shas"]
assert objs["notify_33e70_rem"] not in rq["fix_shas"]
assert "1b1edda5cb58972cdc80b0acf03d0dad35b64b43" not in rq["fix_shas"]
assert rq["status"] == "REJECT"
assert rq.get("heuristic_hit_not_promoted") is True
assert qc["status"] == "NOT_SELECTED" and qc["gates_opened"] is False
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
assert len(cases) == 13
assert all(c["worker_verdict"] != "PASS" for c in cases)
assert sum(1 for c in cases if c["worker_verdict"] == "REJECT") == 1
assert sum(1 for c in cases if c["worker_verdict"] == "BLOCKED") == 2
assert sum(1 for c in cases if c["worker_verdict"] == "NOT_SELECTED") == 10
rq_c = next(c for c in cases if c["case_id"] == "GHSA-RQHX-647V-WX32")
qc_c = next(c for c in cases if c["case_id"] == "GHSA-44QC-PGVP-WX7V")
assert rq_c["worker_verdict"] == "REJECT"
assert rq_c["ai_hunk_gate"] == "FAIL"
assert rq_c["contribution_class"] == "REMEDIATION_AS_ORIGIN"
assert rq_c["incomplete_rem_class_met"] is False
assert rq_c["gates"]["release_gate"] != "PASS"
assert "/tmp/ghsa200-missingref-final13" not in json.dumps(rq_c.get("replay_commands") or [])
assert qc_c["worker_verdict"] == "NOT_SELECTED"
assert qc_c["gates_opened"] is False
res = json.loads((owned / "result.json").read_text(encoding="utf-8"))
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 1
assert res["frozen_hit_n"] == 0
assert res["replay"]["self_contained"] is True
assert res["replay"]["requires_deleted_tmp"] is False
assert res["replay"]["requires_network"] is False
report = (owned / "report.md").read_text(encoding="utf-8")
assert "Proposed PASS = 0" in report
assert "self-contained" in report.lower()
assert "141=98+43" in report
print("pinned_facts_and_cases_ok")
PY

python3 -B - "$OWNED" <<'PY'
import re
import sys
from pathlib import Path

owned = Path(sys.argv[1])
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(
    r"ghp_" + r"[A-Za-z0-9]{20,}|"
    r"github" + r"_pat_[A-Za-z0-9_]+|"
    r"sk" + r"_live_|"
    r"xox[baprs]-|"
    r"AKIA" + r"[0-9A-Z]{16}|"
    r"BEGIN" + r" PRIVATE"
)
names = [
    "cases.jsonl",
    "report.md",
    "replay.zsh",
    "result.json",
    "assignment.json",
    "work/freeze.json",
    "work/uniqueness.json",
    "notes/aliases.json",
    "notes/pinned-facts.json",
    "notes/optional-public-refresh.txt",
    "sha256.txt",
]
for name in names:
    text = (owned / name).read_text(encoding="utf-8")
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    assert text.endswith("\n"), name
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (name, line)
man_names = []
for line in (owned / "sha256.txt").read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    parts = line.split()
    assert len(parts) == 2, line
    man_names.append(parts[1])
assert "sha256.txt" not in man_names
assert all(not n.endswith("/sha256.txt") for n in man_names)
assert all("__pycache__" not in n and not n.endswith(".pyc") and not n.endswith(".pyo") for n in man_names)
assert not list(owned.rglob("__pycache__"))
assert not list(owned.rglob("*.pyc"))
assert not list(owned.rglob("*.pyo"))
print("hygiene_ok")
PY

forbid_bytecode
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/notes/pin-manifest.sha256"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"
printf 'REPLAY_OK reviewed=13 PASS_proposal=0 REJECT=1 BLOCKED=2 NOT_SELECTED=10 frozen_hits=0 packet_delta=0\n'
