#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-sharedhelper-newcaller20-grok46-high.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Current leader-accepted count is 84. Packet delta is 0.
# PASS is a proposal only. This script admits no row.
# Selector routing is not claim-grade first-party bind.
# Trailing whitespace: owned-tree Python assertion plus git diff --no-index --check /dev/null vs file.
# Ordinary git diff exit 1 is content-new, not a whitespace error. Never compare a file to itself.
# Replay is independent of /tmp pages.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export PYTHONDONTWRITEBYTECODE=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-sharedhelper-newcaller20-grok46-high

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

forbid_bytecode() {
  local found
  found=$(/usr/bin/find "$OWNED" \( -name '__pycache__' -o -name '*.pyc' -o -name '*.pyo' \) -print)
  if [[ -n $found ]]; then
    printf 'bytecode present:\n%s\n' "$found" >&2
    exit 1
  fi
}

require_dir "$OWNED"
forbid_bytecode
require_file "$OWNED/population.jsonl"
require_file "$OWNED/selection.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/adjudications.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/summary.json"
require_file "$OWNED/result.json"
require_file "$OWNED/input_manifest.json"
require_file "$OWNED/replay.zsh"
require_file "$OWNED/sha256.txt"
require_file "$OWNED/work/freeze.json"
require_file "$OWNED/work/scan.jsonl"
require_file "$OWNED/work/scan_sharedhelper.py"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/notes/facts/source_bind.json"
require_file "$OWNED/notes/facts/GHSA-47Q7-97XP-M272.json"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$OWNED/selected.jsonl" \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/population.jsonl" \
  7d1a987fa9123e7aadbee15145c0c082387826bf5180b5e870c5c74d5bd2b57a
expect_hash "$OWNED/selection.jsonl" \
  adef0159ba6a111a0baec6437402f469e0464d3200513d6fe50d8bb7b1a7d623
expect_hash "$OWNED/adjudications.jsonl" \
  4e6a08e0a33aaeebe39eb1d6e3ec0212a6669dfff4662bdea6be62f964ee8738
expect_hash "$OWNED/report.md" \
  12f599154bd7f1904f1d5344d44b20f35ddd1d2994329fbf4b8992c9fb9c74e1
expect_hash "$OWNED/summary.json" \
  f856480c0b586ff154d31edc60c2e4828f347c582bf5243e1d973304ff0a5636
expect_hash "$OWNED/input_manifest.json" \
  68fef8ddfffe9298475f9eb44c0d51f547caf11a81d551af905477a6bb9b012c
expect_hash "$OWNED/work/freeze.json" \
  6d08cd8b02754d3209f5dea6b92dad25811a402a46b226d6d7354a9b0d34b44c
expect_hash "$OWNED/work/scan.jsonl" \
  de470d46967aa698e620cf6ab5df9d7506433f9a02f219a8ba55bab0ede3bd11
expect_hash "$OWNED/work/scan_sharedhelper.py" \
  a351cfac3c3f883e57cf6829f2a952428adcb9ac1bc0d023caece0538cf0dc87
expect_hash "$OWNED/work/uniqueness.json" \
  e53b3d6cbfcb9068096ad4e0e2701277dab8fc3ea2da82c7e8811e33de3e328e
expect_hash "$OWNED/work/scan-summary.json" \
  3413a975e6aae181d70a5f54a6e63bd86dc7784bdc61b415ff56cb64de0b5e72
expect_hash "$OWNED/notes/facts/source_bind.json" \
  6ff7467fdcd369832389fdcfd11753912d2c6cc6da612e351af6c23b00030f9f

python3 -B - "$OWNED" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" << 'PY'
import json, re, sys, subprocess
from pathlib import Path
from collections import Counter

owned = Path(sys.argv[1])
pop = [json.loads(l) for l in (owned / "population.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selection.jsonl").read_text().splitlines() if l.strip()]
chosen = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
adj = [json.loads(l) for l in (owned / "adjudications.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned / "result.json").read_text())
summary = json.loads((owned / "summary.json").read_text())
uniq = json.loads((owned / "work/uniqueness.json").read_text())
freeze = json.loads((owned / "work/freeze.json").read_text())
scan = [json.loads(l) for l in (owned / "work/scan.jsonl").read_text().splitlines() if l.strip()]
report = (owned / "report.md").read_text()
c84 = json.loads(Path(sys.argv[2]).read_text())
fact47 = json.loads((owned / "notes/facts/GHSA-47Q7-97XP-M272.json").read_text())
bind = json.loads((owned / "notes/facts/source_bind.json").read_text())
FROZEN = [
    "GHSA-33HM-CQ8R-WC49",
    "GHSA-47Q7-97XP-M272",
    "GHSA-4HG8-92X6-H2F3",
    "GHSA-CHM3-VQCF-52RX",
    "GHSA-CPF4-PMR4-W6CX",
    "GHSA-F3RG-XQJJ-CJ9W",
    "GHSA-FR6G-7CQ8-FG82",
    "GHSA-G353-MGV3-8PCJ",
    "GHSA-HV93-R4J3-Q65F",
    "GHSA-JMM5-FVH5-GF4P",
]
assert len(c84["strict_released_case_ids"]) == 84
assert chosen == []
assert len(pop) == 4591
assert len(scan) == 4591
assert len(sel) == 10
assert len(adj) == 10
assert freeze["n_selected"] == 10
assert freeze["n_hard_hits"] == 10
assert freeze["n_misses"] == 4581
assert freeze["padding"] is False
assert freeze["did_not_backfill"] is True
assert freeze["exact_first_party_fix_claim"] is False
assert freeze["population_claim"] == "advisory_database_routing_with_same_repo_commit_refs"
assert freeze["source_tier"] == "advisory_database_routing"
assert [r["ghsa_id"] for r in sel] == FROZEN
assert [r["case_id"] for r in adj] == FROZEN
verdicts = Counter(r["worker_verdict"] for r in adj)
assert verdicts["REJECT"] == 3
assert verdicts["UNKNOWN"] == 6
assert verdicts["BLOCKED"] == 1
assert verdicts["PASS"] == 0
assert not all(r["worker_verdict"] == "REJECT" for r in adj)
assert all(r["countable_proposal"] is False for r in adj)
by_id = {r["case_id"]: r for r in adj}
assert by_id["GHSA-47Q7-97XP-M272"]["worker_verdict"] == "BLOCKED"
assert by_id["GHSA-47Q7-97XP-M272"]["negative_control"] is True
assert by_id["GHSA-47Q7-97XP-M272"]["exact_fix_closed"] is False
assert "113ebfd6" in " ".join(by_id["GHSA-47Q7-97XP-M272"]["counterevidence"])
assert "config-secrets" in " ".join(by_id["GHSA-47Q7-97XP-M272"]["counterevidence"]).lower() or "config secrets" in " ".join(by_id["GHSA-47Q7-97XP-M272"]["counterevidence"]).lower()
assert by_id["GHSA-HV93-R4J3-Q65F"]["worker_verdict"] == "UNKNOWN"
assert "3421b2ec" in " ".join(by_id["GHSA-HV93-R4J3-Q65F"]["counterevidence"])
assert by_id["GHSA-33HM-CQ8R-WC49"]["worker_verdict"] == "REJECT"
assert by_id["GHSA-4HG8-92X6-H2F3"]["worker_verdict"] == "REJECT"
assert by_id["GHSA-JMM5-FVH5-GF4P"]["worker_verdict"] == "REJECT"
assert by_id["GHSA-JMM5-FVH5-GF4P"]["exact_fix_closed"] is True
assert sum(1 for r in pop if r["worker_verdict"] == "NOT_SELECTED") == 4581
assert sum(1 for r in pop if r["worker_verdict"] == "FROZEN_SELECTED") == 10
assert all(r["source_tier"] == "advisory_database_routing" for r in pop)
assert 4591 == 10 + 4581
assert summary["PASS"] == 0
assert summary["REJECT"] == 3
assert summary["UNKNOWN"] == 6
assert summary["BLOCKED"] == 1
assert summary["reviewed"] == 10
assert summary["selected"] == 0
assert summary["exact_first_party_fix_claim"] is False
assert summary["current_leader_accepted_count"] == 84
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 3
assert res["counts"]["UNKNOWN"] == 6
assert res["counts"]["BLOCKED"] == 1
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["pass_proposals"] == []
assert res["did_not_pad"] is True
assert res["did_not_backfill"] is True
assert res["conservation"]["exact_first_party_fix_claim"] is False
assert uniq["canonical84_overlap"] == []
assert uniq["zero_canonical84_overlap"] is True
assert "0 PASS" in report
assert "4591=10+4581" in report
assert "Current leader-accepted strict count is 84" in report
assert "NOT_SELECTED" in report
assert "routing only" in report.lower() or "routing-only" in report.lower()
assert "negative control" in report.lower()
assert fact47["internal_consistency"] == "INCONSISTENT"
assert fact47["negative_control"] is True
assert bind["ghsa_47q7_description_sha256_equals_jmm5"] is True
assert bind["tmp_pages_required_for_replay"] is False
assert res["hygiene"]["owned_tree_trailing_whitespace"] is True
assert "/dev/null versus" in res["hygiene"]["git_diff_no_index_check"]
assert "never file versus itself" in res["hygiene"]["git_diff_no_index_check"]
replay_text = (owned / "replay.zsh").read_text()
vacuous = "git diff --no-index --check " + '"$OWNED/'
assert vacuous not in replay_text
assert "/dev/null" in replay_text
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(
    r"ghp_" + r"[A-Za-z0-9]{20,}|"
    r"github" + r"_pat_[A-Za-z0-9_]+|"
    r"sk" + r"_live_|"
    r"xox[baprs]-|"
    r"AKIA" + r"[0-9A-Z]{16}|"
    r"BEGIN" + r" PRIVATE"
)
ws_hits = []
raw_pages = []
for p in owned.rglob("*"):
    if not p.is_file():
        continue
    if p.suffix in {".pyc", ".pyo"} or "__pycache__" in p.parts:
        continue
    if p.name.endswith(".repo-advisory.html") or p.name.endswith(".repo-advisory.api"):
        raw_pages.append(str(p))
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    rel = str(p.relative_to(owned))
    for i, line in enumerate(text.splitlines(), 1):
        if line != line.rstrip(" \t"):
            ws_hits.append((rel, i))
assert ws_hits == [], ws_hits[:8]
assert raw_pages == [], raw_pages[:4]
for r in adj:
    joined = " ".join(r["counterevidence"]).lower()
    if r["worker_verdict"] == "REJECT":
        positive = any(
            s in joined
            for s in (
                "parent already",
                "already had",
                "already performed",
                "test file",
                "chrome extension",
            )
        )
        assert positive, r["case_id"]
        assert r["exact_fix_closed"] is True
        assert r["claim_grade"] is True
    else:
        assert r["worker_verdict"] in ("UNKNOWN", "BLOCKED"), r["case_id"]
        assert r["exact_fix_closed"] is False
        assert r["claim_grade"] is False
        assert any(
            s in joined
            for s in (
                "cannot be closed",
                "internally inconsistent",
                "does not name",
                "do not call",
                "do not swap",
                "unknown, not reject",
                "blocked, not reject",
            )
        ), r["case_id"]
    assert not (
        len(r["counterevidence"]) == 1 and "does not name" in joined
    ), r["case_id"]
ws_err = ("trailing whitespace", "space before tab", "conflict marker")
check_files = [
    owned / "report.md",
    owned / "adjudications.jsonl",
    owned / "summary.json",
    owned / "result.json",
    owned / "population.jsonl",
    owned / "selection.jsonl",
    owned / "replay.zsh",
]
for path in check_files:
    proc = subprocess.run(
        ["/usr/bin/git", "diff", "--no-index", "--check", "/dev/null", str(path)],
        capture_output=True,
        text=True,
    )
    blob = (proc.stdout or "") + (proc.stderr or "")
    low = blob.lower()
    if any(s in low for s in ws_err):
        raise AssertionError(("whitespace_error", path.name, blob[:400]))
    if proc.returncode not in (0, 1):
        raise AssertionError(("git_diff_unexpected_rc", path.name, proc.returncode, blob[:400]))
for name in (
    "population.jsonl", "selection.jsonl", "selected.jsonl", "adjudications.jsonl",
    "report.md", "replay.zsh", "result.json", "summary.json", "input_manifest.json",
    "work/uniqueness.json", "work/exclusion.json", "work/freeze.json",
    "notes/README.md", "notes/facts/source_bind.json", "sha256.txt",
):
    text = (owned / name).read_text(encoding="utf-8")
    if name == "selected.jsonl" and text == "":
        continue
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    if text:
        assert text.endswith("\n"), name
for fact_path in sorted((owned / "notes/facts").glob("GHSA-*.json")):
    text = fact_path.read_text(encoding="utf-8")
    assert text.isascii(), fact_path.name
    assert not han.search(text), fact_path.name
    assert not secret.search(text), fact_path.name
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
assert all("/snapshot/" not in n and not n.endswith("snapshot") for n in man_names)
assert all("__pycache__" not in n and not n.endswith(".pyc") and not n.endswith(".pyo") for n in man_names)
assert not list(owned.rglob("__pycache__"))
assert not list(owned.rglob("*.pyc"))
assert not list(owned.rglob("*.pyo"))
print("conservation probed=4591 hits=10 misses=4581 frozen=10 reviewed=10 PASS=0 REJECT=3 UNKNOWN=6 BLOCKED=1 packet_delta=0 current_leader_accepted_count=84")
PY
forbid_bytecode
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"

printf 'REPLAY_OK reviewed=10 PASS_proposal=0 REJECT=3 UNKNOWN=6 BLOCKED=1 NARROW=0 scanned=4591 hits=10 misses=4581 frozen=10 selected=0 packet_delta=0 current_leader_accepted_count=84\n'
