#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-fixblame-difffail20-grok46-high.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Current leader-accepted count is 82. Packet delta is 0.
# PASS is a proposal only. This script admits no row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-difffail20-grok46-high
FB=/home/hanqing/.cache/ghsa200-worker-clones/baseline-increm-even/clones/filebrowser
FB_ALT=/home/hanqing/.cache/cve-analyzer/repos/filebrowser_filebrowser/.git/objects
GOGS=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs
GOGS_ALT=/home/hanqing/.cache/cve-analyzer/repos/gogs_gogs/.git/objects
DNN=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/dnnsoftware__Dnn.Platform
WL=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/WeblateOrg__weblate
SCAN_MISS=$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/work/scan-miss.jsonl

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

require_dir() {
  if [[ ! -d $1 ]]; then
    printf 'missing directory: %s\n' "$1" >&2
    exit 1
  fi
}

require_git() {
  if [[ -d $1/.git || -f $1/HEAD ]]; then
    return 0
  fi
  printf 'missing git repo: %s\n' "$1" >&2
  exit 1
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

g() {
  local repo=$1
  shift
  local errf=$OWNED/work/.giterr
  set +e
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
  if [[ -s $errf ]]; then
    grep -vE 'unable to normalize alternate object path|lazy fetching disabled|could not fetch .* from promisor remote' "$errf" >&2 || true
  fi
  rm -f "$errf"
  return $rc
}

require_dir "$OWNED"
require_git "$FB"
require_dir "$FB_ALT"
require_git "$GOGS"
require_dir "$GOGS_ALT"
require_git "$DNN"
require_git "$WL"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/exclusion.json"
require_file "$OWNED/sha256.txt"
require_file "$SCAN_MISS"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/ledger.jsonl" \
  58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" \
  d436f47f82297eb0d9363ad0f3876adc639b1f61e9b23c7f9d613545741e106e
expect_hash "$OWNED/selected.jsonl" \
  1116efd21db9461f60d0aac1831f55b3ad75f33f1c81834ba75e85cf6bacacfa
expect_hash "$SCAN_MISS" \
  5ec5265e65d957d8a7877a1c27465e9463b404f73790cfb03fc9f011d5625e40
expect_hash "$OWNED/cases.jsonl" \
  7a86703537c5c27e1a8837307d64bfe3bc3412560dadbda329ba14578b2d25ca
expect_hash "$OWNED/report.md" \
  394e1592af1a5c82e6fe04d5beacc5b4d4877eec1b5808f97bb425f3d7ade6ab
expect_hash "$OWNED/work/uniqueness.json" \
  4bf27990dfaa9b01064f256fd03e5f5f32604659f4010e00506697ef75aa0cd8
expect_hash "$OWNED/work/exclusion.json" \
  0882870e281abdbe3da0a3c50dff64afaee7caf868d6c05ff5a6d94c0203dff6
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/selected.jsonl" \
  344761d2c9c683ee6bf2b451f79b70b9e0b12802f037f972e8b159dc9b20f43e
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-residual-security20-grok46-high/selected.jsonl" \
  f179f86d9097f71a0d632b2ea572dba0d1f6b1bb16743a332f331f66af6aba3f
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-ai-route-surface20-grok46-xhigh/selected.jsonl" \
  ea375573bac6d4e60cb25a0891831db9c6b7538e13de5caf4f2b79dbc0320330

python3 - "$OWNED" "$SCAN_MISS" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" \
  "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/selected.jsonl" \
  "$ROOT/autoresearch/herdr-260814-ghsa200-residual-security20-grok46-high/selected.jsonl" \
  "$ROOT/autoresearch/herdr-260814-ghsa200-ai-route-surface20-grok46-xhigh/selected.jsonl" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
scan_miss = Path(sys.argv[2])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned / "result.json").read_text())
uniq = json.loads((owned / "work/uniqueness.json").read_text())
excl = json.loads((owned / "work/exclusion.json").read_text())
report = (owned / "report.md").read_text()
replay = (owned / "replay.zsh").read_text()
assert len(rows) == 20, len(rows)
assert len(sel) == 20, len(sel)
want = [r["ghsa_id"] for r in sel]
assert want == [r["case_id"] for r in rows]
assert len(set(want)) == 20
assert want == ['GHSA-JJ2R-455P-5GVF', 'GHSA-3Q2W-42MV-CPH4', 'GHSA-CM2R-RG7R-P7GG', 'GHSA-WJ44-9VCG-WJQ7', 'GHSA-4WX8-5GM2-2J97', 'GHSA-RMWH-G367-MJ4X', 'GHSA-W7QC-6GRJ-W7R8', 'GHSA-PF4H-VRV6-CMVR', 'GHSA-57JG-M997-CX3Q', 'GHSA-WCWH-7GFW-5WRR', 'GHSA-4QQF-9M5C-W2C5', 'GHSA-M49C-G9WR-HV6V', 'GHSA-377J-WJ38-4728', 'GHSA-WQ2J-W9PM-7X2P', 'GHSA-867C-P784-5Q6G', 'GHSA-2374-6CVW-QMX6', 'GHSA-WPP4-VQFQ-V4HP', 'GHSA-2CJV-6WG9-F4F3', 'GHSA-2V5M-CQ9W-FC33', 'GHSA-495J-H493-42Q2']
assert [r["assigned_order"] for r in sel] == list(range(1, 21))
assert [r["probe_outcome"] for r in sel] == ["diff_fail"] * 20

def load_ids(p):
    out = []
    for line in Path(p).read_text().splitlines():
        if line.strip():
            out.append(json.loads(line)["ghsa_id"].upper())
    return out

c82 = json.loads(Path(sys.argv[3]).read_text())
ids82 = {x.upper() for x in c82["strict_released_case_ids"]}
assert len(c82["strict_released_case_ids"]) == 82
assert c82["canonical_strict_count"] == 82
fix14 = set(load_ids(sys.argv[4]))
res20 = set(load_ids(sys.argv[5]))
route = set(load_ids(sys.argv[6]))
leftover = set(excl["leftover4"])
pending = set(excl["accepted_pending"])
block = ids82 | fix14 | res20 | leftover | route | pending
assert len(fix14) == 14
assert len(res20) == 20
assert route == {"GHSA-73HC-M4HX-79PJ"}

derived = []
seen = set()
for i, line in enumerate(scan_miss.read_text().splitlines(), 1):
    if not line.strip():
        continue
    rec = json.loads(line)
    notes = rec.get("notes") or []
    if not any(isinstance(n, str) and n.startswith("diff_fail:") for n in notes):
        continue
    gid = rec["ghsa_id"].upper()
    if gid in seen:
        continue
    seen.add(gid)
    if gid in block:
        continue
    derived.append(gid)
    if len(derived) == 20:
        break
assert derived == want, (derived, want)
for i in want:
    assert i not in block, i

assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 20
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 0
assert res["current_leader_accepted_count"] == 82
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["pass_proposals"] == []
assert res["did_not_pad"] is True
assert "Current leader-accepted count 82" in report
assert "Packet delta 0" in report
assert uniq["canonical82_strict_count"] == 82
assert uniq["packet_delta"] == 0
assert uniq["pass_proposals"] == []
assert uniq["assigned_in_canonical82_strict"] == []
for rec in rows:
    assert rec["worker_verdict"] == "REJECT", rec["case_id"]
    assert rec["countable_proposal"] is False, rec["case_id"]
    assert rec["causal_admission"] is False, rec["case_id"]
    assert rec["ai_hunk_gate"] == "FAIL", rec["case_id"]
    assert rec["but_for_gate"] == "FAIL", rec["case_id"]
    assert rec["identity_gate"] == "PASS", rec["case_id"]
    assert rec["uniqueness_gate"] == "PASS", rec["case_id"]
    assert rec["original_probe_outcome"] == "diff_fail", rec["case_id"]
    assert rec["repaired_probe"] is True, rec["case_id"]
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(
    r"ghp_" + r"[A-Za-z0-9]{20,}|"
    r"github" + r"_pat_[A-Za-z0-9_]+|"
    r"sk" + r"_live_|"
    r"xox[baprs]-|"
    r"AKIA" + r"[0-9A-Z]{16}|"
    r"BEGIN" + r" PRIVATE"
)
for name in ("cases.jsonl", "selected.jsonl", "report.md", "replay.zsh", "result.json", "work/uniqueness.json", "work/exclusion.json", "notes/README.md", "sha256.txt"):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
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
print("conservation assigned=20 reviewed=20 unreviewed=0 PASS_proposal=0 REJECT=20 NARROW=0 UNKNOWN=0 BLOCKED=0 current_leader_accepted_count=82 packet_delta=0")
PY
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"

export GIT_ALTERNATE_OBJECT_DIRECTORIES=$FB_ALT
perm=$(g "$FB" show ca86f916216620365c0f81629c0934ce02574d76:files/file.go)
printf '%s\n' "$perm" | grep -F 'const PermFile = 0640' >/dev/null
printf '%s\n' "$perm" | grep -F 'const PermDir = 0750' >/dev/null
parent_perm=$(g "$FB" show 4bfbf332499fc8aea5f6df6aae1efa0de918d1ae:files/file.go)
printf '%s\n' "$parent_perm" | grep -F 'const PermFile = 0644' >/dev/null
pc=$(g "$FB" log -1 --format='%P' ca86f916216620365c0f81629c0934ce02574d76)
[[ $pc == 4bfbf332499fc8aea5f6df6aae1efa0de918d1ae ]]
unset GIT_ALTERNATE_OBJECT_DIRECTORIES

export GIT_ALTERNATE_OBJECT_DIRECTORIES=$GOGS_ALT
gogs_pc=$(g "$GOGS" log -1 --format='%P' 77a4a945ae9a87f77e392e9066b560edb71b5de9)
[[ $gogs_pc == b09f317aa078f09b68d5911ff38cbed0bab6e2a9 ]]
gogs_diff=$(g "$GOGS" diff --no-ext-diff -U0 77a4a945ae9a87f77e392e9066b560edb71b5de9^ 77a4a945ae9a87f77e392e9066b560edb71b5de9 -- internal/database/repo_editor.go)
printf '%s\n' "$gogs_diff" | grep -F 'isRepositoryGitPath' >/dev/null
if printf '%s\n' "$gogs_diff" | grep -E '^-' | grep -vE '^(--- |^diff |^index )' >/dev/null; then
  printf 'gogs fix unexpectedly deletes source lines\n' >&2
  exit 1
fi
unset GIT_ALTERNATE_OBJECT_DIRECTORIES

dnn_pc=$(g "$DNN" rev-list --parents -n 1 74f6de68da1572c1d7e9c6e30e9f77f7c5596b1b)
[[ $dnn_pc == '74f6de68da1572c1d7e9c6e30e9f77f7c5596b1b 21f49f5c97482d38f818952037b36cb1a7e5e885 34290ec669355195dbdf972c73b75ddb490d7ade' ]]

wl_tree=$(g "$WL" diff-tree -r --name-status f806293451248c5d95e45b3b507e9d158bc4f384^ f806293451248c5d95e45b3b507e9d158bc4f384)
[[ $wl_tree == $'M\tdocs/admin/optionals.rst' ]]

printf 'REPLAY_OK reviewed=20 PASS_proposal=0 REJECT=20 NARROW=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=82\n'
