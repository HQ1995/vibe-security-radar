#!/usr/bin/env zsh
# Fail-closed zsh replay for herdr-260814-ghsa200-commitfirst-remainder20-grok46-high.
# English only. Do not print credentials or environment values.
# Do not clone, commit, push, or modify shared caches.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# PASS is a proposal only. This script does not admit any row.
# Freeze admitted post-fix/path-only hits. These 20 did not exhaust pre-fix remainder.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export TMPDIR=/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-commitfirst-remainder20-grok46-high/work

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-commitfirst-remainder20-grok46-high
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database
git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

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
assert_not_ancestor() {
  local repo=$1 ai=$2 fix=$3
  local errf=$OWNED/work/.giterr
  set +e
  /usr/bin/timeout 30 "${git_cmd[@]}" -C "$repo" merge-base --is-ancestor "$ai" "$fix" 2>"$errf"
  local rc=$?
  set -e
  if [[ $rc -eq 124 ]]; then
    printf 'git timeout\n' >&2
    rm -f "$errf"
    exit 1
  fi
  if [[ $rc -eq 0 ]]; then
    printf 'unexpected ancestor\n' >&2
    rm -f "$errf"
    exit 1
  fi
  if [[ $rc -ne 1 ]]; then
    printf 'missing git object (fail closed)\n' >&2
    cat "$errf" >&2
    rm -f "$errf"
    exit 1
  fi
  rm -f "$errf"
}

require_dir "$OWNED"
require_dir "$ADV"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/compact_facts.json"
require_file "$OWNED/work/freeze.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/notes/freeze.txt"
require_file "$OWNED/notes/releases/compact.json"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$OWNED/selected.jsonl" \
  2a88815964279babab0591f7bfa01bf05cfd0741643889ffcbdbbac16d6159e8
expect_hash "$OWNED/cases.jsonl" \
  62c89fa0c271d07e70ae69fb7122a6f29c86e7d12901a7839803248914edf487
expect_hash "$OWNED/report.md" \
  77666a003e090ed780550ea47dd0a7a6b6f50f66a92b4b78f4e44051e3035661
expect_hash "$OWNED/compact_facts.json" \
  33a526699cf3ce4808399b8207e8e6b0cfd018b1fc2b8332e05ea943b43dea92
expect_hash "$OWNED/work/freeze.json" \
  ec9b14edf48fd2b87bca88c578871720d0222f20179cac21cb88221c912593a1
expect_hash "$OWNED/work/uniqueness.json" \
  e1a95ca9d791f55f80765bcb7bff16f2a2f6cf94f9ad36f9eff9013339022b81
expect_hash "$OWNED/work/candidate-files.json" \
  a01625535f356d0f2268873714c62a14ca37a78d657ccfc8de8fbcfde35740bd
expect_hash "$OWNED/notes/releases/compact.json" \
  38087fa947351400a6523603125891197e31ff572ec9ab5929d11d8eabd599f6

head=$(/usr/bin/timeout 30 "${git_cmd[@]}" -C "$ADV" rev-parse HEAD)
if [[ $head != a42c436870111aa3f221257c9d56126a93173ccc ]]; then
  printf 'advisory HEAD mismatch %s\n' "$head" >&2
  exit 1
fi

assert_not_ancestor "/home/hanqing/.cache/cve-analyzer/repos/cyanheads_git-mcp-server" 1134dd1efe155fed8a1255e58de000f368197096 0dbd6995ccdf76ab770b58013034365b2d06c4d9  # GHSA-3Q26-F695-PP76
assert_not_ancestor "/home/hanqing/.cache/cve-analyzer/repos/conductor-oss_conductor" 51d3500795d70be98f12f43a79898547ad68983c e9816501df1e364a3d39d7fe37d6e167c40eaa1b  # GHSA-8GQP-HR9G-PG62
assert_not_ancestor "/home/hanqing/.cache/cve-analyzer/repos/coredns_coredns" 9fac0b6e9e48b6e284bdf384e4cf203836c082e7 efaed02c6a480ec147b1f799aab7cf815b17dfe1  # GHSA-CVX7-X8PJ-X2GW
assert_not_ancestor "/home/hanqing/.cache/cve-analyzer/repos/flux159_mcp-server-kubernetes" 1119609a9df415dea4d3f8e1aa1428f90c03cd55 ab165f5a0eea917fef5dbae954506fff6f4bf514  # GHSA-GJV4-GHM7-Q58Q
assert_not_ancestor "/home/hanqing/.cache/cve-analyzer/repos/academysoftwarefoundation_openexr" 783b654273bf6cba2ca17f6a348395cb41f0fe74 916cc729e24aa16b86d82813f6e136340ab2876f  # GHSA-H45X-QHG2-Q375
assert_not_ancestor "/home/hanqing/.cache/cve-analyzer/repos/fedify-dev_fedify" 12243f498ad141fb9e2caa50b846064636f53312 14a2f8c6d2c3cbc00c3170a86ad3b7b8555c6847  # GHSA-6JCC-XGCR-Q3H4
assert_not_ancestor "/home/hanqing/.cache/cve-analyzer/repos/consensys_gnark" b53af634876c74df52562b858b333ad8be6ff6a4 0ba6730f05537a351517998add89a61a0d82716e  # GHSA-95V9-HV42-PWRJ
assert_not_ancestor "/home/hanqing/.cache/cve-analyzer/repos/eugeny_russh" 32fd46f100e011acf4cde467aea147fec5f2a107 0eb5e406780890e21ff71dd25d731b30676478e5  # GHSA-H5RC-J5F5-3GCM
assert_not_ancestor "/home/hanqing/.cache/cve-analyzer/repos/axios_axios" 6bb12c191f5380fad321322fb90216ae0dc36985 945435fc51467303768202250debb8d4ae892593  # GHSA-4HJH-WCWX-XVWJ
assert_not_ancestor "/home/hanqing/.cache/cve-analyzer/repos/axios_axios" 6bb12c191f5380fad321322fb90216ae0dc36985 a1b1d3f073a988601583a604f5f9f5d05a3d0b67  # GHSA-4HJH-WCWX-XVWJ
assert_not_ancestor "/home/hanqing/.cache/cve-analyzer/repos/axios_axios" 6bb12c191f5380fad321322fb90216ae0dc36985 c30252f685e8f4326722de84923fcbc8cf557f06  # GHSA-4HJH-WCWX-XVWJ
assert_not_ancestor "/home/hanqing/.cache/cve-analyzer/repos/frontfin_mesh-web-sdk" 396ef27034b6f9ed2f35309e14d8cf8ea7228011 7f22148516d58e21a8b7670dde927d614c0d15c2  # GHSA-VH3F-QPPR-J97F

/usr/bin/python3 - <<'PY'
import hashlib
import json
from pathlib import Path
root = Path("/home/hanqing/agents/ai-slop")
owned = root / "autoresearch/herdr-260814-ghsa200-commitfirst-remainder20-grok46-high"
sel = [json.loads(l) for l in (owned/"selected.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned/"result.json").read_text())
uni = json.loads((owned/"work/uniqueness.json").read_text())
fr = json.loads((owned/"work/freeze.json").read_text())
assert len(sel) == 20
assert len(cases) == 20
assert [r["ghsa_id"] for r in sel] == [c["case_id"] for c in cases]
assert [r["ghsa_id"] for r in sel] == fr["frozen_ids"]
assert all(c["worker_verdict"] == "REJECT" for c in cases)
assert all(c["uniqueness_gate"] == "PASS" for c in cases)
assert all(c["identity_gate"] == "PASS" for c in cases)
assert all(c["ai_hunk_gate"] == "FAIL" for c in cases)
assert all(c["freeze_selector_admitted_postfix_or_path_only"] is True for c in cases)
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 20
assert res["claim_boundary"]["packet_delta"] == 0
assert res["current_leader_accepted_count"] == 84
assert res["analysis_stopped"] is True
assert res["freeze_selector_limitation"]["did_not_exhaust_prefix_candidates"] is True
assert res["freeze_selector_limitation"]["fix_probe_not_ancestor"] == 12
assert res["freeze_selector_limitation"]["fix_probe_entries"] == 13
assert uni["canonical84_overlap"] == []
assert uni["packet_delta"] == 0
assert uni["did_not_exhaust_prefix_candidates"] is True
assert fr["padding"] is False
assert fr["frozen_n"] == 20
assert fr["conservation"]["candidate_pool"] == 5980
assert fr["freeze_selector_limitation"]["admitted_postfix_or_path_only_hits"] is True
c84 = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json").read_text())
assert c84["canonical_strict_count"] == 84
strict = {x.upper() for x in c84["strict_released_case_ids"]}
assert not strict.intersection({r["ghsa_id"] for r in sel})
sha_path = owned / "sha256.txt"
sha_lines = [ln for ln in sha_path.read_text().splitlines() if ln.strip()]
rels = []
for ln in sha_lines:
    digest, rel = ln.split("  ", 1)
    if rel == "sha256.txt" or rel.endswith("/sha256.txt"):
        raise SystemExit("sha256 self-entry")
    got = hashlib.sha256((owned / rel).read_bytes()).hexdigest()
    if got != digest:
        raise SystemExit("sha256 mismatch " + rel)
    rels.append(rel)
if "sha256.txt" in rels:
    raise SystemExit("sha256 self-entry")
needles = ("gh" + "p_", "github" + "_pat_", "AKI" + "A")
for p in owned.rglob("*"):
    if not p.is_file() or p.name.startswith("."):
        continue
    raw = p.read_bytes()
    if b"\0" in raw:
        continue
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        continue
    if any("\u4e00" <= ch <= "\u9fff" for ch in text):
        raise SystemExit("han " + str(p.relative_to(owned)))
    for ln in text.splitlines():
        if ln.endswith(" ") or ln.endswith("\t"):
            raise SystemExit("trailing whitespace " + str(p.relative_to(owned)))
    if p.name == "replay.zsh":
        continue
    for needle in needles:
        if needle in text:
            raise SystemExit("secret string " + str(p.relative_to(owned)))
print("replay asserts ok")
PY

printf 'REPLAY_OK reviewed=20 PASS_proposal=0 REJECT=20 NARROW=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 canonical=84\n'
