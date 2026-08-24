#!/usr/bin/env zsh
# Fail-closed zsh replay for herdr-260814-ghsa200-fp211-unknown4a-grok46-low.
# English only. Do not print credentials or environment values.
# Do not clone, commit, push, or modify shared caches.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# PASS is a proposal only. This script does not admit any row.
# Canonical baseline is 84. Packet delta is 0. Terminal UNKNOWN. Zero PASS.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fp211-unknown4a-grok46-low
export TMPDIR=$OWNED/work
O=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw
T=/home/hanqing/.cache/cve-analyzer/repos/tailot_taylored
W=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/wacrm

VJP_M=f05553413db29ebcf5d8c75c8a6154a9e9987690
VJP_C=daf13dbb0616115bf0aa946f46c3ba2afb93d283
VJP_F=a0c5e28f3bf0cc0cd9311f9e9ec2ca0352550dcf
JQH_M=b7b362ae427ccf4b33b8e8cd147f16410f3ce800
JQH_X=23838a9959550e975d732ae08a44a3a2f0cc084b
JQH_F=7d1ddbfdb8296058ab787f7c57b8943c0214d14d
G98_M=c139c021f68a09d22c2af88641b61c00f67f2af4
G98_F=57b7634391959dbbdb39b387ac4dc68157cd58a1
VH5_F=fdf67a6fba0deae30912905a79fb5a9e83751a79

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

g() {
  local repo=$1
  shift
  local errf=$OWNED/work/.giterr
  set +e
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
  if [[ -s $errf ]]; then
    grep -vF 'unable to normalize alternate object path' "$errf" >&2 || true
  fi
  rm -f "$errf"
  return $rc
}

assert_ancestor() {
  g "$1" merge-base --is-ancestor "$2" "$3"
}

assert_not_ancestor() {
  if g "$1" merge-base --is-ancestor "$2" "$3"; then
    printf 'unexpected ancestor: %s is ancestor of %s\n' "$2" "$3" >&2
    exit 1
  fi
}

require_dir "$OWNED"
require_dir "$O/.git"
require_dir "$T/.git"
require_dir "$W/.git"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/replay.zsh"
require_file "$OWNED/sha256.txt"
require_file "$OWNED/compact_facts.json"
require_file "$OWNED/notes/README.md"
require_file "$OWNED/notes/freeze.txt"
require_file "$OWNED/work/freeze.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/pages/ghsa/GHSA-vjp8-wprm-2jw9.json"
require_file "$OWNED/work/pages/repo/GHSA-8jqh-598v-rfxc.json"
require_file "$OWNED/work/pages/ghsa/GHSA-8jqh-598v-rfxc.404.json"
require_file "$OWNED/work/pages/npm/taylored.compact.json"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/baseline.json" \
  d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
expect_hash "$OWNED/selected.jsonl" \
  3a0e88c6b1b097588a4261e17847f3b1a43f87c5a9fa0dd208aa68166a6b27e4
expect_hash "$OWNED/cases.jsonl" \
  505485a12b5a438f3fe1e401bedb89ac2ef93afaaba3dc130bffebf4013c1ff0
expect_hash "$OWNED/report.md" \
  2558447498a90c51e9f6ca2b8a9f1a2f1c1a366c22c7b0cef707d1c45582b2b1
expect_hash "$OWNED/compact_facts.json" \
  2929113bfaf32bef72f12e485d06dac4df5f8799299fde434d512de414250f7e
expect_hash "$OWNED/notes/README.md" \
  c533586200ac28674e7b6109b2a6daf791646970f6c1c73f887393bd37d5eb62
expect_hash "$OWNED/notes/freeze.txt" \
  5b7e1c0efac87673c2c6215356790fbf950551852e41b0dfe9e2b2b3c503346a
expect_hash "$OWNED/work/freeze.json" \
  d1a3117afbc18f4c9851d299dc9bb4d6bfa027a8931056f39eeb95d390a44d17
expect_hash "$OWNED/work/uniqueness.json" \
  d7d27e67129e68ceb4eae18cc08322597b5efdcc47a070c1366b335300dcacdc

vjp_parents=$(g "$O" rev-list --parents -n 1 "$VJP_M")
print -r -- "$vjp_parents" | /usr/bin/awk '{ if (NF != 2) { print "VJP8 member not atomic" > "/dev/stderr"; exit 1 } }'
jqh_parents=$(g "$W" rev-list --parents -n 1 "$JQH_M")
print -r -- "$jqh_parents" | /usr/bin/awk '{ if (NF != 2) { print "8JQH member not atomic" > "/dev/stderr"; exit 1 } }'
g98_parents=$(g "$T" rev-list --parents -n 1 "$G98_M")
print -r -- "$g98_parents" | /usr/bin/awk '{ if (NF != 2) { print "8G98 member not atomic" > "/dev/stderr"; exit 1 } }'
g98f_parents=$(g "$T" rev-list --parents -n 1 "$G98_F")
print -r -- "$g98f_parents" | /usr/bin/awk '{ if (NF != 2) { print "57b76343 not atomic" > "/dev/stderr"; exit 1 } }'
jqh_merge=$(g "$W" rev-list --parents -n 1 "$JQH_X")
print -r -- "$jqh_merge" | /usr/bin/awk '{ if (NF != 3) { print "23838a99 is not a two-parent merge" > "/dev/stderr"; exit 1 } }'

assert_ancestor "$O" "$VJP_M" "$VJP_C"
assert_ancestor "$O" "$VJP_M" v2026.2.25
assert_ancestor "$O" "$VJP_F" v2026.2.26
assert_not_ancestor "$O" "$VJP_F" v2026.2.25
assert_ancestor "$W" "$JQH_M" "$JQH_F"
assert_ancestor "$W" "$JQH_F" "$JQH_X"
assert_ancestor "$T" "$G98_M" "$G98_F"
assert_ancestor "$T" "$G98_F" 8.2.4
assert_ancestor "$T" "$VH5_F" 8.2.4

python3 - "$OWNED" "$ROOT" "$O" "$T" "$W" << 'PY'
import json, os, re, subprocess, sys
from pathlib import Path

owned = Path(sys.argv[1])
root = Path(sys.argv[2])
openclaw = sys.argv[3]
tayl = sys.argv[4]
wacrm = sys.argv[5]
git = [
    "/usr/bin/git",
    "--no-optional-locks",
    "-c",
    "gc.auto=0",
    "-c",
    "maintenance.auto=false",
    "-c",
    "advice.detachedHead=false",
]
env = os.environ.copy()
env["GIT_OPTIONAL_LOCKS"] = "0"
env["GIT_TERMINAL_PROMPT"] = "0"
env["GIT_NO_LAZY_FETCH"] = "1"


def git_run(repo, *args, ok=(0,)):
    r = subprocess.run(git + ["-C", repo, *args], capture_output=True, text=True, env=env, timeout=180)
    err = "\n".join(
        line
        for line in r.stderr.splitlines()
        if "unable to normalize alternate object path" not in line
        and "exists on disk, but not in" not in line
    )
    if err.strip():
        raise SystemExit(f"git stderr {args}: {err}")
    if r.returncode not in ok:
        raise SystemExit(f"git rc={r.returncode} {args}")
    return r


def blob(repo, rev, rel):
    return git_run(repo, "rev-parse", f"{rev}:{rel}").stdout.strip()


def first_parent_has(repo, commit, tag):
    out = git_run(repo, "rev-list", "--first-parent", tag).stdout.split()
    return commit in out


VJP_M = "f05553413db29ebcf5d8c75c8a6154a9e9987690"
VJP_C = "daf13dbb0616115bf0aa946f46c3ba2afb93d283"
VJP_F = "a0c5e28f3bf0cc0cd9311f9e9ec2ca0352550dcf"
JQH_M = "b7b362ae427ccf4b33b8e8cd147f16410f3ce800"
JQH_X = "23838a9959550e975d732ae08a44a3a2f0cc084b"
JQH_F = "7d1ddbfdb8296058ab787f7c57b8943c0214d14d"
G98_M = "c139c021f68a09d22c2af88641b61c00f67f2af4"
G98_F = "57b7634391959dbbdb39b387ac4dc68157cd58a1"
VH5_F = "fdf67a6fba0deae30912905a79fb5a9e83751a79"
bot = "extensions/feishu/src/bot.ts"
eng = "src/lib/automations/engine.ts"
idx = "templates/backend-in-a-box/index.js"

body = git_run(openclaw, "log", "-1", "--format=%B", VJP_M).stdout
assert "Generated by staged fix workflow" in body
assert "Co-Authored-By:" not in body
assert "noreply@anthropic.com" not in body
assert first_parent_has(openclaw, VJP_M, "v2026.2.25")
assert first_parent_has(openclaw, VJP_C, "v2026.2.25")
assert first_parent_has(openclaw, VJP_F, "v2026.2.26")
assert not first_parent_has(openclaw, VJP_F, "v2026.2.25")
assert git_run(openclaw, "rev-parse", "v2026.2.25^{commit}").stdout.strip() == "4b5d4a4c660d05e4bd73f0e11123e68fd9664432"
assert git_run(openclaw, "rev-parse", "v2026.2.26^{commit}").stdout.strip() == "bc507080577c620243617e8fadd294bec3efa252"
assert blob(openclaw, VJP_M, bot) == "eed6f5bc527e2c9218f424f50f31bc190093dc2f"
assert blob(openclaw, "v2026.2.25", bot) == "f18658e62b50763b533b1c1d530c85b3f6b525c4"
assert blob(openclaw, VJP_F, bot) == "61c65973762ce72760a3bfdb18482a55a49d7aa9"
assert blob(openclaw, "v2026.2.26", bot) == "61c65973762ce72760a3bfdb18482a55a49d7aa9"
g25 = git_run(openclaw, "grep", "-n", "readAllowFromStore", "v2026.2.25", "--", bot).stdout
assert 'readAllowFromStore("feishu")' in g25
g26 = git_run(openclaw, "grep", "-n", "readAllowFromStore", "v2026.2.26", "--", bot).stdout
assert "pairing.readAllowFromStore()" in g26
assert 'readAllowFromStore("feishu")' not in g26

jqh_body = git_run(wacrm, "log", "-1", "--format=%B", JQH_M).stdout
assert "noreply@anthropic.com" in jqh_body
assert git_run(wacrm, "cat-file", "-e", f"{JQH_M}^:{eng}", ok=(0, 1, 128)).returncode != 0
member_eng = git_run(wacrm, "show", f"{JQH_M}:{eng}").stdout
assert "case 'send_webhook'" in member_eng
assert "isDeliverableUrl" not in member_eng
fix_eng = git_run(wacrm, "show", f"{JQH_F}:{eng}").stdout
assert "isDeliverableUrl" in fix_eng
tags = git_run(wacrm, "tag", "--list").stdout.split()
assert tags == []
merge_parents = git_run(wacrm, "rev-list", "--parents", "-n", "1", JQH_X).stdout.split()
assert len(merge_parents) == 3
assert JQH_F in merge_parents

assert "google-labs-jules[bot]" in git_run(tayl, "log", "-1", "--format=%an", G98_M).stdout
origin = git_run(tayl, "show", f"{G98_M}:{idx}").stdout
assert "app.post('/paypal/webhook'" in origin
assert "verifyAndGetWebhookEvent" not in origin
paypal = git_run(tayl, "show", f"{G98_F}:{idx}").stdout
assert "verifyAndGetWebhookEvent" in paypal or "Webhooks" in paypal
assert "token_used_at" in paypal
assert "UPDATE purchases SET token_used_at = CURRENT_TIMESTAMP WHERE id = ?" in paypal
race = git_run(tayl, "show", f"{VH5_F}:{idx}").stdout
assert "AND token_used_at IS NULL" in race
ttags = git_run(tayl, "tag", "--list").stdout.split()
assert ttags == ["8.2.4"]
assert first_parent_has(tayl, G98_M, "8.2.4")
assert first_parent_has(tayl, G98_F, "8.2.4")
assert first_parent_has(tayl, VH5_F, "8.2.4")
assert blob(tayl, "8.2.4", idx) == "706a6e1da64c99778f8e5cfe9cf0a143998a1e2f"
assert blob(tayl, G98_M, idx) != blob(tayl, "8.2.4", idx)

order = [
    "GHSA-VJP8-WPRM-2JW9",
    "GHSA-8JQH-598V-RFXC",
    "GHSA-8G98-M4J9-QWW5",
    "GHSA-VH5J-5FHQ-9XWG",
]
ordinals = [51, 53, 56, 84]
sel = [json.loads(line) for line in (owned / "selected.jsonl").read_text().splitlines() if line.strip()]
cases = [json.loads(line) for line in (owned / "cases.jsonl").read_text().splitlines() if line.strip()]
assert [row["case_id"] for row in sel] == order
assert [row["ordinal"] for row in sel] == ordinals
assert [row["case_id"] for row in cases] == order
assert [row["ordinal"] for row in cases] == ordinals
assert len(sel) == 4 and len(cases) == 4
assert all(row["worker_verdict"] == "UNKNOWN" for row in cases)
assert all(row["countable_proposal"] is False for row in cases)
assert all(row["packet_delta"] == 0 for row in cases)
assert all(row["causal_admission"] is False for row in cases)
assert all(row["worker_pass_is_proposal_only"] is True for row in cases)
assert all(row["publication_status"] == "HOLD" for row in cases)
assert all(row["authorship_transfer_from_member_to_carrier"] is False for row in cases)
gates = [
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
]
for row in cases:
    assert set(row["gates"]) == set(gates)
    assert all(row["gates"][g] in {"PASS", "UNKNOWN"} for g in gates)
    assert row["gates"]["uniqueness_gate"] == "PASS"
    assert row["worker_verdict"] != "PASS"
assert cases[0]["gates"]["ai_hunk_gate"] == "UNKNOWN"
assert cases[1]["gates"]["release_gate"] == "UNKNOWN"
assert cases[2]["gates"]["release_gate"] == "UNKNOWN"
assert cases[3]["gates"]["release_gate"] == "UNKNOWN"
assert cases[3]["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
assert cases[3]["incomplete_remediation"]["explicit_ai_security_attempt"] is True
assert cases[3]["incomplete_remediation"]["same_boundary_patch_delta"] is True
assert cases[1]["carrier_set"] == []

freeze = json.loads((owned / "work/freeze.json").read_text())
assert freeze["frozen_ids"] == order
assert freeze["frozen_ordinals"] == ordinals
assert freeze["frozen_n"] == 4
assert freeze["padding"] is False
assert freeze["substitution"] is False
assert freeze["packet_delta"] == 0
assert freeze["canonical84_commit"] == "ca034f064fd696201c81baae7392c14f0d501d2b"

uni = json.loads((owned / "work/uniqueness.json").read_text())
assert uni["start_count"] == 84
assert uni["current_leader_accepted_count"] == 84
assert uni["packet_delta"] == 0
assert uni["pass_proposals"] == []
assert uni["canonical84_overlap"] == []
assert uni["frozen_selected_ids"] == order

c84 = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json").read_text())
assert c84["canonical_strict_count"] == 84
ids = set(c84["strict_released_case_ids"])
for case_id in order:
    assert case_id not in ids
assert c84["publication_ready"] is False
assert c84["public_200_claim_supported"] is False

res = json.loads((owned / "result.json").read_text())
assert res["status"] == "TERMINAL"
assert res["terminal"] is True
assert res["start_count"] == 84
assert res["current_leader_accepted_count"] == 84
assert res["packet_delta"] == 0
assert res["counts"]["PASS"] == 0
assert res["counts"]["UNKNOWN"] == 4
assert res["counts"]["assigned"] == 4
assert res["counts"]["reviewed"] == 4
assert res["counts"]["unreviewed"] == 0
assert res["conservation"]["equation"] == "4=4+0"
assert res["pass_proposals"] == []
assert res["exact_selected_ids"] == order
assert res["worker_pass_is_proposal_only"] is True
assert res["canonical_count_updated"] is False
assert res["claim_boundary"]["publication_status"] == "HOLD"
assert res["claim_boundary"]["more_than_200_claim_supported_by_this_review"] is False
assert res["did_not_commit_or_push"] is True
assert all(res["per_case"][case_id] == "UNKNOWN" for case_id in order)
assert res["canonical_ledger_commit"] == "ca034f064fd696201c81baae7392c14f0d501d2b"

han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(r"ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}")
names = [
    "selected.jsonl",
    "cases.jsonl",
    "report.md",
    "replay.zsh",
    "result.json",
    "sha256.txt",
    "compact_facts.json",
    "notes/README.md",
    "notes/freeze.txt",
    "work/freeze.json",
    "work/uniqueness.json",
]
for name in names:
    text = (owned / name).read_text(encoding="utf-8")
    assert text, name
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    assert text.endswith("\n"), name
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (name, line)
print("conservation assigned=4 reviewed=4 unreviewed=0 PASS_proposal=0 UNKNOWN=4")
PY

printf 'REPLAY_OK reviewed=4 PASS_proposal=0 UNKNOWN=4 packet_delta=0 start=84 current=84\n'
