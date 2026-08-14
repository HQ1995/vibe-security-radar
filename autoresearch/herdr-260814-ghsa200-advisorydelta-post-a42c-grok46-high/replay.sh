#!/usr/bin/env bash
# Fail-closed replay for herdr-260814-ghsa200-advisorydelta-post-a42c-grok46-high.
# English only. Do not print credentials. Do not clone, fetch, commit, or push.
# Validates counts, unique IDs, hashes, exclusions, and absence of cache/temps.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-advisorydelta-post-a42c-grok46-high
CANON=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84

CAND_H=c73d6696bb6eb0f4b64c90a4770aaedf83dbbe9ed74b43a358ea41935cd6f77c
REPORT_H=35f8e591ea96e16fb3f54541fb23605d82d9444da950543ac20b1fdd81e9c22b
MAN_H=4195abaddeaed7410b48b606c84bebf0bf3883805948ccc38cb77d822b27d386
LEDGER_H=a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
SUMMARY_H=6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a

expect_hash() {
  local target=$1 expected=$2
  local got
  got=$(/usr/bin/sha256sum "$target" | /usr/bin/awk '{print $1}')
  if [[ $got != "$expected" ]]; then
    printf 'hash mismatch %s\n expected %s\n got      %s\n' "$target" "$expected" "$got" >&2
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

require_file "$OWNED/candidates.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/manifest.json"
require_file "$OWNED/replay.sh"
require_file "$CANON/ledger.jsonl"
require_file "$CANON/summary.json"

expect_hash "$OWNED/candidates.jsonl" "$CAND_H"
expect_hash "$OWNED/report.md" "$REPORT_H"
expect_hash "$OWNED/manifest.json" "$MAN_H"
expect_hash "$CANON/ledger.jsonl" "$LEDGER_H"
expect_hash "$CANON/summary.json" "$SUMMARY_H"

require_absent /home/hanqing/.cache/ai-slop-ghsa200/advisorydelta-post-a42c
require_absent /tmp/ghsa36jr-old.json
require_absent /tmp/ghsa36jr-new.json
require_absent /tmp/ghsa36jr-new.err

/usr/bin/python3 - <<'PY'
import hashlib, json, re
from pathlib import Path

root = Path("/home/hanqing/agents/ai-slop")
owned = root / "autoresearch/herdr-260814-ghsa200-advisorydelta-post-a42c-grok46-high"
canon = root / "autoresearch/orchestrator-260814-ghsa200-canonical84"
gid = "GHSA-36JR-MH4H-2G58"
ghsa_re = re.compile(r"GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}$")

absent = [
    Path("/home/hanqing/.cache/ai-slop-ghsa200/advisorydelta-post-a42c"),
    Path("/tmp/ghsa36jr-old.json"),
    Path("/tmp/ghsa36jr-new.json"),
    Path("/tmp/ghsa36jr-new.err"),
]
for p in absent:
    assert not p.exists(), p

lines = [ln for ln in (owned / "candidates.jsonl").read_text().splitlines() if ln.strip()]
assert len(lines) == 1, len(lines)
row = json.loads(lines[0])
ids = [row["ghsa_id"]]
assert ids == [gid]
assert len(set(ids)) == 1
assert ghsa_re.fullmatch(gid)
assert row["delta_status"] == "MODIFIED"
assert row["delta_kind"] == "nonsemantic_metadata_reorder"
assert row["semantic_fields_changed"] is False
assert row["source_repo_cloned"] is False
assert row["net_new"] is False
assert row["retained"] is False
assert row["routing_outcome"] == "NONSEMANTIC_METADATA_REORDER"
assert row["cwe_ids_before"] == ["CWE-400", "CWE-1333"]
assert row["cwe_ids_after"] == ["CWE-1333", "CWE-400"]
assert row["frozen_commit"] == "a42c436870111aa3f221257c9d56126a93173ccc"
assert row["current_commit"] == "37f259e500d68dec361b264b9a3027fc0a715088"
assert row["source_commit_ids"] == ["e5cd38e04446540cd1a831d5653237b978843c43"]
assert row["frozen_blob_sha1"] == "aed54f0f7c43edcfcbc185c0172f63e0a80466c6"
assert row["current_blob_sha1"] == "483a07a3f0d43db4aba0f8fb4a6c49ea605b9024"
assert row["frozen_blob_sha256"] == "901eb7a6bd047d507ac1e34eca968e602592188a9dad2fc01fac26c99d37714f"
assert row["current_blob_sha256"] == "35ba98fb18293a0d84db2dceefcb5bd4b926d6b78faaa3ee6094bb4d095268fa"
assert row.get("claim_pass") in (None, False)

man = json.loads((owned / "manifest.json").read_text())
assert man["causal_admission"] is False
assert man["claim_pass"] is False
assert man["delta_kind"] == "nonsemantic_metadata_reorder"
assert man["counts"]["added_reviewed"] == 0
assert man["counts"]["modified_reviewed"] == 1
assert man["counts"]["deleted_reviewed"] == 0
assert man["counts"]["in_range_reviewed"] == 1
assert man["counts"]["net_new"] == 0
assert man["counts"]["retained"] == 0
assert man["counts"]["nonsemantic_metadata_reorder"] == 1
assert man["counts"]["semantic_fields_changed"] == 0
assert man["net_new_ids"] == []
assert man["in_range_ids"] == [gid]
assert len(set(man["in_range_ids"])) == 1
assert man["leader_replay"]["reviewed_tree_delta_files"] == 1
assert man["leader_replay"]["semantic_fields_changed"] is False
assert man["leader_replay"]["source_repo_cloned"] is False
assert man["source_clones_retained"] is False
assert man["raw_advisory_clone_retained"] is False
assert man["cache_removed_at_handoff"] is True
assert man["hashes"]["candidates.jsonl"] == "c73d6696bb6eb0f4b64c90a4770aaedf83dbbe9ed74b43a358ea41935cd6f77c"
assert man["hashes"]["report.md"] == "35f8e591ea96e16fb3f54541fb23605d82d9444da950543ac20b1fdd81e9c22b"
for path in man["handoff_absent_paths"]:
    assert not Path(path).exists(), path

summary = json.loads((canon / "summary.json").read_text())
strict = [x.upper() for x in summary["strict_released_case_ids"]]
assert len(strict) == 84
assert len(set(strict)) == 84
assert gid not in set(strict)
canon_ids = set(strict)
with (canon / "ledger.jsonl").open() as f:
    for line in f:
        if not line.strip():
            continue
        rec = json.loads(line)
        for k in ("case_id", "ghsa_id", "ghsa"):
            v = rec.get(k)
            if isinstance(v, str) and re.fullmatch(r"GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}", v):
                canon_ids.add(v.upper())
assert len(canon_ids) == 226
assert gid not in canon_ids
strict_h = hashlib.sha256(("\n".join(sorted(strict)) + "\n").encode()).hexdigest()
repr_h = hashlib.sha256(("\n".join(sorted(canon_ids)) + "\n").encode()).hexdigest()
assert strict_h == man["canonical84"]["strict_ids_sha256"]
assert repr_h == man["canonical84"]["represented_ids_sha256"]

overlap_path = root / "autoresearch/herdr-260813-ghsa200-current-delta/cases.jsonl"
assert gid in overlap_path.read_text().upper()

han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(r"ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}")
for name in ("candidates.jsonl", "report.md", "manifest.json", "replay.sh"):
    raw = (owned / name).read_text(encoding="utf-8")
    assert raw.endswith("\n"), name
    assert raw.isascii(), name
    assert not han.search(raw), name
    assert not secret.search(raw), name
    for line in raw.splitlines():
        assert line == line.rstrip(" \t"), (name, line)

report = (owned / "report.md").read_text()
assert "net-new candidate count = 0" in report
assert "nonsemantic metadata reorder" in report
assert "does not emit PASS" in report
assert gid in report
assert "NONSEMANTIC_METADATA_REORDER" in report
assert "source repo was not cloned" in report.lower() or "The source repo was not cloned." in report
print("VALIDATION_OK in_range=1 unique=1 added=0 modified=1 net_new=0 nonsemantic_reorder=1")
PY

printf 'REPLAY_OK in_range=1 unique=1 net_new=0 cache_absent=1 temps_absent=1\n'
