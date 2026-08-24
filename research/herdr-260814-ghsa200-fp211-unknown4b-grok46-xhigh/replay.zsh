#!/usr/bin/env zsh
# Fail-closed zsh replay for herdr-260814-ghsa200-fp211-unknown4b-grok46-xhigh.
# English only. Do not print credentials or environment values.
# Do not clone, commit, push, or modify shared caches.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# PASS is a proposal only. This script does not admit any row.
# Canonical baseline is 84. Packet delta is 0. Terminal NARROW. Zero PASS. Two UNKNOWN.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat
export PAGER=cat

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fp211-unknown4b-grok46-xhigh
export TMPDIR=$OWNED/work
CY=/home/hanqing/.cache/cve-analyzer/repos/coollabsio_coolify
AW=/home/hanqing/.cache/cve-analyzer/repos/argoproj_argo-workflows
MP=/home/hanqing/.cache/cve-analyzer/repos/misp_misp
OM=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/omnifaces__omnifaces

CG_C=e1fe58639756cf7b232458eddd6978e4ed0031f5
CG_K=98569e4edbfc316877c9e0d27ea89fab3c49e3bd
CG_F=e1d4b4682efc898ba5aa3751b2da2072f89c7e24
A1=251bb231d62a0f4e5e03dcc13c3f2ae456b2fa34
A2=2727f3f701677d467dfb5e053c57237cbc752c3c
AF3=358cc3968c8f06f1be0967e41df191088db0b662
AF4=277e9cef0ad16d7eaaab253573d0695951a65dbd
M_C=bc182d55dde5686a36ca2eb88fe6c2adabb9fad9
M_F=025f711506850aadb69cde1b57e5e5d57628c87f
O_C=aa42da361821ddfbb85b126564e71587347d2786
O_F=a52b92461cf39d983f51ce8724fe7e6b944073e4

git_cmd=(/usr/bin/git --no-pager --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false -c core.pager=cat)

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
  /usr/bin/timeout 30 "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
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
require_dir "$CY/.git"
require_dir "$AW/.git"
require_dir "$MP/.git"
require_dir "$OM/.git"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/replay.zsh"
require_file "$OWNED/sha256.txt"
require_file "$OWNED/notes/README.md"
require_file "$OWNED/notes/freeze.txt"
require_file "$OWNED/work/freeze.json"
require_file "$OWNED/work/uniqueness.json"

expect_hash $ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash $ROOT/autoresearch/orchestrator-260813-ghsa200-leader/baseline.json \
  d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132
expect_hash $ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash $ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash $ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash $ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
expect_hash "$OWNED/selected.jsonl" \
  0a666fd71357d724fb8f068f5ee07ca2e85beccdca64d5a7fa1eca97ac0c2962
expect_hash "$OWNED/cases.jsonl" \
  c1324d678ff030779203ab31026daa546aaa39382e4a4d464a6bf3db2cb9c2c5
expect_hash "$OWNED/report.md" \
  393c2b87065e0d9b5ebf56378193df837c40f9f6f33b29b3f121b60af1268db6
expect_hash "$OWNED/result.json" \
  b4258cbffbd1fe4db750b2fe0ae3427cea208d727dad05a86644fb7459e2ec57
expect_hash "$OWNED/notes/README.md" \
  398038962e4249186fc0345968936282bb11903abf8bf877c2316aa9ab3a0e36
expect_hash "$OWNED/notes/freeze.txt" \
  6217dd7081c52459ffd197072fd409135382343bfd6ffe4ad9a245d661944571
expect_hash "$OWNED/notes/facts/README.md" \
  d61cd5f0fe13bcd504c398556ab8968b001fb57051638acf1976231e1561498d
expect_hash "$OWNED/notes/diffs/README.md" \
  31afb43dc14155f01920c541d3a37ce5f2f736330872318cbe1a97037d6c1c36
expect_hash "$OWNED/notes/releases/README.md" \
  46eb52002c4a20b660961923b31b204580367e4e7263980d8db10b4142e36846
expect_hash "$OWNED/notes/releases/tags.json" \
  1ff865c628e3df9e0a9059eb9be1c5de3e5eaf1ef6d1d901de256fb2eab667e0
expect_hash "$OWNED/work/freeze.json" \
  8872fdb3f6f413fd9538ea98a9f1c95d39530993df6308638497522fa6c46e94
expect_hash "$OWNED/work/uniqueness.json" \
  5b4f24dd36fcd8fee5b4ea9581337e182492a9d66fa731d55ecceb5913d6c494
expect_hash "$OWNED/notes/facts/GHSA-CGJ8-7M5Q-X5GV.topology.json" \
  1957abd00b2bd98c18dc29fd38c0579566247115501ef4d18167cb5620873553
expect_hash "$OWNED/notes/facts/GHSA-48P8-G2FX-3WWM.topology.json" \
  11144e575b1a0ad7055fdca248528672e84dc9b4d6920620a2d434e0ec029207
expect_hash "$OWNED/notes/facts/GHSA-MF7V-X7R6-FQ57.topology.json" \
  dcf18b1a1903930aa7bee6a94837d23b9e12a4a1a80bda4534e4ceb980c16ad0
expect_hash "$OWNED/notes/facts/GHSA-FP43-VJ7G-PG92.topology.json" \
  d2a2987f5abe7302527c0dac3fd3233e5e12bb690b70062acf16495e395c0118

cg_parents=$(g "$CY" rev-parse "${CG_C}^@")
print -r -- "$cg_parents" | /usr/bin/awk '{ if (NF != 1) { print "CGJ8 candidate not atomic" > "/dev/stderr"; exit 1 } }'
a1_parents=$(g "$AW" rev-parse "${A1}^@")
print -r -- "$a1_parents" | /usr/bin/awk '{ if (NF != 1) { print "48P8 cand1 not single-parent" > "/dev/stderr"; exit 1 } }'
a2_parents=$(g "$AW" rev-parse "${A2}^@")
print -r -- "$a2_parents" | /usr/bin/awk '{ if (NF != 1) { print "48P8 cand2 not single-parent" > "/dev/stderr"; exit 1 } }'
mc_parents=$(g "$MP" rev-parse "${M_C}^@")
print -r -- "$mc_parents" | /usr/bin/awk '{ if (NF != 1) { print "MF7V candidate not atomic" > "/dev/stderr"; exit 1 } }'
oc_parents=$(g "$OM" rev-parse "${O_C}^@")
print -r -- "$oc_parents" | /usr/bin/awk '{ if (NF != 1) { print "FP43 candidate not atomic" > "/dev/stderr"; exit 1 } }'

assert_not_ancestor "$CY" "$CG_C" v4.0.0-beta.436
assert_ancestor "$CY" "$CG_C" v4.0.0-beta.437
assert_not_ancestor "$CY" "$CG_F" v4.0.0-beta.470
assert_ancestor "$CY" "$CG_F" v4.0.0-beta.471
assert_ancestor "$CY" "$CG_C" "$CG_K"

assert_ancestor "$AW" "$A1" v3.7.14
assert_not_ancestor "$AW" "$AF3" v3.7.14
assert_ancestor "$AW" "$AF3" v3.7.15
assert_ancestor "$AW" "$A2" v4.0.5
assert_not_ancestor "$AW" "$AF4" v4.0.5
assert_ancestor "$AW" "$AF4" v4.0.6

assert_not_ancestor "$MP" "$M_C" v2.5.41
assert_ancestor "$MP" "$M_C" v2.5.42
assert_not_ancestor "$MP" "$M_F" v2.5.41
assert_ancestor "$MP" "$M_F" v2.5.42

python3 - "$OWNED" "$ROOT" "$CY" "$AW" "$MP" "$OM" << 'PY'
import json, os, re, subprocess, sys
from pathlib import Path

owned = Path(sys.argv[1])
root = Path(sys.argv[2])
cy, aw, mp, om = sys.argv[3:7]
git = [
    "/usr/bin/git",
    "--no-pager",
    "--no-optional-locks",
    "-c", "gc.auto=0",
    "-c", "maintenance.auto=false",
    "-c", "advice.detachedHead=false",
    "-c", "core.pager=cat",
]
env = os.environ.copy()
env["GIT_OPTIONAL_LOCKS"] = "0"
env["GIT_TERMINAL_PROMPT"] = "0"
env["GIT_NO_LAZY_FETCH"] = "1"
env["GIT_PAGER"] = "cat"


def git_run(repo, *args, ok=(0,)):
    r = subprocess.run(
        ["/usr/bin/timeout", "30"] + git + ["-C", repo, *args],
        capture_output=True,
        text=True,
        env=env,
        stdin=subprocess.DEVNULL,
    )
    err = "\n".join(
        line
        for line in r.stderr.splitlines()
        if "unable to normalize alternate object path" not in line
    )
    if err.strip() and r.returncode not in ok:
        raise SystemExit(f"git stderr {args}: {err}")
    if r.returncode not in ok:
        raise SystemExit(f"git rc={r.returncode} {args}")
    return r


def blob(repo, rev, rel):
    return git_run(repo, "rev-parse", f"{rev}:{rel}").stdout.strip()


def marker(repo, sha, needle):
    body = git_run(repo, "log", "-1", "--format=%B", sha).stdout
    return needle.lower() in body.lower()


CG_C = "e1fe58639756cf7b232458eddd6978e4ed0031f5"
CG_K = "98569e4edbfc316877c9e0d27ea89fab3c49e3bd"
CG_F = "e1d4b4682efc898ba5aa3751b2da2072f89c7e24"
A1 = "251bb231d62a0f4e5e03dcc13c3f2ae456b2fa34"
AF3 = "358cc3968c8f06f1be0967e41df191088db0b662"
AF4 = "277e9cef0ad16d7eaaab253573d0695951a65dbd"
M_C = "bc182d55dde5686a36ca2eb88fe6c2adabb9fad9"
M_F = "025f711506850aadb69cde1b57e5e5d57628c87f"
O_C = "aa42da361821ddfbb85b126564e71587347d2786"
O_F = "a52b92461cf39d983f51ce8724fe7e6b944073e4"
TH = "app/Http/Middleware/TrustHosts.php"
RP = "app/Notifications/TransactionalEmails/ResetPassword.php"
EV = "app/Model/Event.php"

assert not marker(cy, CG_C, "noreply@anthropic.com")
assert "conductor" in git_run(cy, "log", "-1", "--format=%s", CG_C).stdout.lower()
assert marker(cy, CG_F, "noreply@anthropic.com")
assert blob(cy, CG_C, TH) == blob(cy, "v4.0.0-beta.437", TH)
assert blob(cy, "v4.0.0-beta.471", TH) == blob(cy, CG_K, TH)
assert blob(cy, "v4.0.0-beta.471", TH) != blob(cy, CG_F, TH)
assert blob(cy, "v4.0.0-beta.471", RP) == blob(cy, CG_K, RP)
assert blob(cy, CG_K, RP) == blob(cy, CG_F, RP)

assert marker(aw, A1, "noreply@anthropic.com")
assert git_run(aw, "rev-parse", "v3.7.15^{commit}").stdout.strip() == AF3
assert git_run(aw, "rev-parse", "v4.0.6^{commit}").stdout.strip() == AF4
mh = git_run(aw, "diff", "-U1", A1 + "^", A1, "--", "workflow/util/merge.go").stdout
assert "ArtifactGC" in mh
assert "allowedUserOverrideFields" in mh
fx = git_run(aw, "diff", "-U1", A1, AF3, "--", "workflow/util/merge.go").stdout
assert "artifactGCOverrideViolations" in fx or "ArtifactGC.PodSpecPatch" in fx

assert marker(mp, M_C, "noreply@anthropic.com")
assert blob(mp, M_C, EV) == blob(mp, M_F, EV)
names_c = git_run(mp, "diff-tree", "--no-commit-id", "--name-only", "-r", M_C).stdout.split()
names_f = git_run(mp, "diff-tree", "--no-commit-id", "--name-only", "-r", M_F).stdout.split()
assert names_c == ["app/Model/Event.php"]
assert names_f == ["app/Model/Taxonomy.php"]

assert marker(om, O_C, "noreply@anthropic.com")
oc_files = git_run(om, "diff-tree", "--no-commit-id", "--name-only", "-r", O_C).stdout.split()
of_files = git_run(om, "diff-tree", "--no-commit-id", "--name-only", "-r", O_F).stdout.split()
assert "src/main/java/org/omnifaces/resourcehandler/CombinedResourceInfo.java" in oc_files
assert of_files == ["src/main/java/org/omnifaces/resourcehandler/SourceMapResourceHandler.java"]
tags = git_run(om, "tag", "--contains", O_C).stdout.strip()
assert tags == ""

order = [
    "GHSA-CGJ8-7M5Q-X5GV",
    "GHSA-48P8-G2FX-3WWM",
    "GHSA-MF7V-X7R6-FQ57",
    "GHSA-FP43-VJ7G-PG92",
]
ordinals = [116, 129, 153, 154]
sel = [json.loads(line) for line in (owned / "selected.jsonl").read_text().splitlines() if line.strip()]
cases = [json.loads(line) for line in (owned / "cases.jsonl").read_text().splitlines() if line.strip()]
assert [row["case_id"] for row in sel] == order
assert [row["ordinal"] for row in sel] == ordinals
assert [row["case_id"] for row in cases] == order
assert [row["ordinal"] for row in cases] == ordinals
assert len(sel) == 4 and len(cases) == 4
assert all(row["countable_proposal"] is False for row in cases)
assert all(row["packet_delta"] == 0 for row in cases)
assert all(row["causal_admission"] is False for row in cases)
assert all(row["worker_pass_is_proposal_only"] is True for row in cases)
assert all(row["publication_status"] == "HOLD" for row in cases)
assert all(row.get("authorship_transfer_from_member_to_carrier") is False for row in cases)
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
    assert row["gates"]["uniqueness_gate"] == "PASS"
    assert row["worker_verdict"] != "PASS"
assert cases[0]["worker_verdict"] == "NARROW"
assert cases[0]["gates"]["ai_hunk_gate"] == "FAIL"
assert cases[1]["worker_verdict"] == "UNKNOWN"
assert cases[1]["gates"]["ai_hunk_gate"] == "UNKNOWN"
assert cases[1]["gates"]["fix_reversal_gate"] == "PASS"
assert cases[1]["gates"]["release_gate"] == "PASS"
assert cases[2]["worker_verdict"] == "NARROW"
assert cases[2]["gates"]["ai_hunk_gate"] == "PASS"
assert cases[2]["gates"]["fix_reversal_gate"] == "FAIL"
assert cases[3]["worker_verdict"] == "UNKNOWN"
assert cases[3]["gates"]["topology_gate"] == "PASS"
assert cases[3]["gates"]["fix_reversal_gate"] == "FAIL"
assert cases[3]["gates"]["release_gate"] == "UNKNOWN"
assert all(row["padding"] is False for row in sel)
assert all(row["substitution"] is False for row in sel)

freeze = json.loads((owned / "work/freeze.json").read_text())
assert freeze["frozen_ids"] == order
assert freeze["frozen_ordinals"] == ordinals
assert freeze["frozen_n"] == 4
assert freeze["did_not_pad"] is True
assert freeze["packet_delta"] == 0

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

res = json.loads((owned / "result.json").read_text())
assert res["status"] == "TERMINAL"
assert res["terminal"] is True
assert res["start_count"] == 84
assert res["current_leader_accepted_count"] == 84
assert res["packet_delta"] == 0
assert res["counts"]["PASS"] == 0
assert res["counts"]["NARROW"] == 2
assert res["counts"]["UNKNOWN"] == 2
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
assert res["per_case"]["GHSA-48P8-G2FX-3WWM"] == "UNKNOWN"
assert res["per_case"]["GHSA-FP43-VJ7G-PG92"] == "UNKNOWN"
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
    "notes/README.md",
    "notes/freeze.txt",
    "notes/facts/README.md",
    "notes/diffs/README.md",
    "notes/releases/README.md",
    "notes/releases/tags.json",
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
print("conservation assigned=4 reviewed=4 unreviewed=0 PASS_proposal=0 NARROW=2 UNKNOWN=2")
PY

printf 'REPLAY_OK reviewed=4 PASS_proposal=0 NARROW=2 UNKNOWN=2 packet_delta=0 start=84 current=84\n'
