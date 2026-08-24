#!/usr/bin/env zsh
# Fail-closed zsh replay for herdr-260814-ghsa200-fp211-topologyonly3-grok46-xhigh.
# English only. Do not print credentials or environment values.
# Do not clone, commit, push, or modify shared caches.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# PASS is a proposal only. This script does not admit any row.
# Canonical baseline is 82. Packet delta is 0. Terminal NARROW. Zero PASS.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fp211-topologyonly3-grok46-xhigh
export TMPDIR=$OWNED/work
IRON=$OWNED/work/clones/ironclaw
ZEPTO=/home/hanqing/.cache/cve-analyzer/repos/qhkm_zeptoclaw
LANG=/home/hanqing/.cache/cve-analyzer/repos/langroid_langroid

CW23_M=b20880c12837df41d7f49de6a33ebe4562b27c5b
CW23_C=b58b421535e593b165393846a4c37d74283060ad
CW23_F=a1d7c3ba428ed575900469b207fb5668725f9a71
WP8_M=3c4368da0ab48c1091858d3f9503c378a209997f
WP8_B=91f6c2bf98e40238ad4d175513f0ee400fd62068
WP8_C=1712debbea60af6adf4a8a5939a43f7ef9a1ac16
WP8_F=68916c3e4f3af107f11940b27854fc7ef517058b
X34_M=b1c45e3fc0f3578a5dea9844c0216044321ae1c8
X34_C=0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6
X34_F=30abbc1a854dee22fbd2f8b2f575dfdabdb603ea

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
require_dir "$IRON/.git"
require_dir "$ZEPTO/.git"
require_dir "$LANG/.git"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/replay.zsh"
require_file "$OWNED/sha256.txt"
require_file "$OWNED/notes/README.md"
require_file "$OWNED/notes/freeze.txt"
require_file "$OWNED/notes/facts/README.md"
require_file "$OWNED/notes/diffs/README.md"
require_file "$OWNED/work/freeze.json"
require_file "$OWNED/work/uniqueness.json"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/baseline.json" \
  d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/ledger.jsonl" \
  58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json" \
  d436f47f82297eb0d9363ad0f3876adc639b1f61e9b23c7f9d613545741e106e
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
expect_hash "$OWNED/selected.jsonl" \
  9de54c83b0328d875636035f1de80df3cc41c63c07d68e20a885906a40af667d
expect_hash "$OWNED/cases.jsonl" \
  3890a90bf6910eff386497bce1e362874d81c7b67e07c2be9f8eefe9c58cba27
expect_hash "$OWNED/report.md" \
  23a4253bd17f7894dce35b740d5b67ec2ea200655d873f84ddc823d0084486c5
expect_hash "$OWNED/notes/README.md" \
  c413a3fc7461e7f64fd07c2a738e12d003b7d16af15feb5dd6f8d54a003aa414
expect_hash "$OWNED/notes/freeze.txt" \
  124ee4eb09c16110b599ec5dfb41181e54269c63062832c4d0b732ebcdf06e03
expect_hash "$OWNED/notes/facts/README.md" \
  0efa2449a6a1e28707d3ceff247e41a256ddd413b6f778ddc8086dc92b995fba
expect_hash "$OWNED/notes/diffs/README.md" \
  63c0241991713179a361027945655e38170784eecf4b4a9717445df2a373f178
expect_hash "$OWNED/work/freeze.json" \
  376247558079573f4673e5a231e564bd21110227c8c64cba5972169f7b944b1c
expect_hash "$OWNED/work/uniqueness.json" \
  7b108af03306030926acdf2abf4829c3e7392b826a9f7cd70f6baaec277f47e4
expect_hash "$OWNED/notes/facts/GHSA-CW23-QWR7-C655.topology.json" \
  88371898b24e0c9df3cbe4ff8a35450f4aea5171a1fec131ae53d9a3df511d5a
expect_hash "$OWNED/notes/facts/GHSA-5WP8-Q9MX-8JX8.topology.json" \
  89a2271194d2cf786dc3f91039f981aa3e505a7ea3bcb754f7e50a02968d6443
expect_hash "$OWNED/notes/facts/GHSA-X34R-63HX-W57F.topology.json" \
  653cc99edced88bcf3bf5c73513cb954da1f7c0313ed9888fe5399924b33af54

# Atomic members. Capture git stdout; do not leak it.
cw23_parents=$(g "$IRON" rev-list --parents -n 1 "$CW23_M")
print -r -- "$cw23_parents" | /usr/bin/awk '{ if (NF != 2) { print "CW23 member not atomic" > "/dev/stderr"; exit 1 } }'
wp8_parents=$(g "$ZEPTO" rev-list --parents -n 1 "$WP8_M")
print -r -- "$wp8_parents" | /usr/bin/awk '{ if (NF != 2) { print "5WP8 allowlist member not atomic" > "/dev/stderr"; exit 1 } }'
x34_parents=$(g "$LANG" rev-list --parents -n 1 "$X34_M")
print -r -- "$x34_parents" | /usr/bin/awk '{ if (NF != 2) { print "X34R member not atomic" > "/dev/stderr"; exit 1 } }'

# Ironclaw: member is not an ancestor of carrier/tag/fix. Carrier is any-ancestor of the crate tag.
assert_not_ancestor "$IRON" "$CW23_M" "$CW23_C"
assert_not_ancestor "$IRON" "$CW23_M" ironclaw-v0.29.1
assert_not_ancestor "$IRON" "$CW23_M" "$CW23_F"
assert_ancestor "$IRON" "$CW23_C" ironclaw-v0.29.1
assert_ancestor "$IRON" "$CW23_F" ironclaw-v1.0.0
assert_not_ancestor "$IRON" "$CW23_F" ironclaw-v0.29.1

# Zeptoclaw: allowlist member is not a tag ancestor. Squash carrier and blocklist member are.
assert_not_ancestor "$ZEPTO" "$WP8_M" "$WP8_C"
assert_not_ancestor "$ZEPTO" "$WP8_M" v0.6.1
assert_ancestor "$ZEPTO" "$WP8_C" v0.6.1
assert_ancestor "$ZEPTO" "$WP8_B" v0.6.1
assert_ancestor "$ZEPTO" "$WP8_F" v0.6.2
assert_not_ancestor "$ZEPTO" "$WP8_F" v0.6.1

# Langroid: Copilot member is not a tag ancestor. Mixed squash is. Fix is first-parent of 0.59.32.
assert_not_ancestor "$LANG" "$X34_M" "$X34_C"
assert_not_ancestor "$LANG" "$X34_M" 0.59.31
assert_ancestor "$LANG" "$X34_C" 0.59.31
assert_ancestor "$LANG" "$X34_F" 0.59.32
assert_not_ancestor "$LANG" "$X34_F" 0.59.31

python3 - "$OWNED" "$ROOT" "$IRON" "$ZEPTO" "$LANG" << 'PY'
import json, os, re, subprocess, sys
from pathlib import Path

owned = Path(sys.argv[1])
root = Path(sys.argv[2])
iron = sys.argv[3]
zepto = sys.argv[4]
lang = sys.argv[5]
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
    r = subprocess.run(git + ["-C", repo, *args], capture_output=True, text=True, env=env)
    err = "\n".join(
        line
        for line in r.stderr.splitlines()
        if "unable to normalize alternate object path" not in line
    )
    if err.strip():
        raise SystemExit(f"git stderr {args}: {err}")
    if r.returncode not in ok:
        raise SystemExit(f"git rc={r.returncode} {args}")
    return r


def blob(repo, rev, rel):
    # Brace-safe: never let zsh see SHA:src as a modifier.
    return git_run(repo, "rev-parse", f"{rev}:{rel}").stdout.strip()


def first_parent_has(repo, commit, tag):
    out = git_run(repo, "rev-list", "--first-parent", tag).stdout.split()
    return commit in out


def missing_tag(repo, tag):
    r = git_run(repo, "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}", ok=(0, 1))
    return r.returncode == 1


CW23_M = "b20880c12837df41d7f49de6a33ebe4562b27c5b"
CW23_C = "b58b421535e593b165393846a4c37d74283060ad"
CW23_F = "a1d7c3ba428ed575900469b207fb5668725f9a71"
WP8_M = "3c4368da0ab48c1091858d3f9503c378a209997f"
WP8_B = "91f6c2bf98e40238ad4d175513f0ee400fd62068"
WP8_C = "1712debbea60af6adf4a8a5939a43f7ef9a1ac16"
WP8_F = "68916c3e4f3af107f11940b27854fc7ef517058b"
X34_M = "b1c45e3fc0f3578a5dea9844c0216044321ae1c8"
X34_C = "0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6"
X34_F = "30abbc1a854dee22fbd2f8b2f575dfdabdb603ea"

iron_shell = "src/tools/builtin/shell.rs"
zepto_shell = "src/security/shell.rs"
table = "langroid/agent/special/table_chat_agent.py"
pandas = "langroid/utils/pandas_utils.py"

assert blob(iron, CW23_M, iron_shell) == "4798d0c3c1a9a5c59c30cd878e9fb85564cddacf"
assert blob(iron, CW23_C, iron_shell) == "fa92cb372320d5e75ee41408d8f29695392873fc"
assert blob(iron, "ironclaw-v0.29.1", iron_shell) == "8f574e900eecc8aa344fe8989641689b4cbfe659"
assert blob(iron, CW23_F, iron_shell) == "90672a7321eb4d85d208146dbdc65c0d10f03dc2"
assert blob(iron, "ironclaw-v1.0.0", iron_shell) == "90672a7321eb4d85d208146dbdc65c0d10f03dc2"
assert git_run(iron, "rev-parse", "ironclaw-v0.29.1^{commit}").stdout.strip() == "556dfd07789c8230c5241b64f4b7c9d549589b10"
assert git_run(iron, "rev-parse", "ironclaw-v1.0.0^{commit}").stdout.strip() == "e3a075222c551e5c127041a9747338ac5845ac97"
assert missing_tag(iron, "v0.29.1")
assert missing_tag(iron, "v1.0.0")
assert first_parent_has(iron, CW23_F, "ironclaw-v1.0.0")
assert not first_parent_has(iron, CW23_C, "ironclaw-v0.29.1")
assert not first_parent_has(iron, CW23_M, "ironclaw-v0.29.1")
assert "noreply@anthropic.com" in git_run(iron, "log", "-1", "--format=%B", CW23_M).stdout
assert "codex@openai.com" in git_run(iron, "log", "-1", "--format=%B", CW23_F).stdout

assert blob(zepto, WP8_M, zepto_shell) == "a09e61719a32cb101160796755f777787007bdc6"
assert blob(zepto, WP8_C, zepto_shell) == "165b10b5034f1782eb84ad8e97834581c07bddc4"
assert blob(zepto, "v0.6.1", zepto_shell) == "87b9d900ab6e3a3504908518c1f62270ccb0cc97"
assert blob(zepto, WP8_B, zepto_shell) == "9eb95303bf40842c4e885eaa55f13f5ab86944b6"
assert blob(zepto, WP8_F, zepto_shell) == "d923a585eb91f1cd6fb2c9e16874f64f14cab5b6"
assert blob(zepto, "v0.6.2", zepto_shell) == "d923a585eb91f1cd6fb2c9e16874f64f14cab5b6"
assert first_parent_has(zepto, WP8_C, "v0.6.1")
assert first_parent_has(zepto, WP8_B, "v0.6.1")
assert not first_parent_has(zepto, WP8_M, "v0.6.1")
assert first_parent_has(zepto, WP8_F, "v0.6.2")
pick = git_run(
    zepto,
    "log",
    "--first-parent",
    "-S",
    "allowlist.is_empty",
    "--pretty=%H",
    "v0.6.1",
    "--",
    zepto_shell,
).stdout.split()
assert pick[:1] == [WP8_C]
assert "noreply@anthropic.com" in git_run(zepto, "log", "-1", "--format=%B", WP8_M).stdout

assert blob(lang, X34_M, table) == "ba8bc96c26093765086ccaef31f48c24b9101db0"
assert blob(lang, X34_C, table) == "c7b320658aaa0cbb6d9bae916485780f3ae7ff31"
assert blob(lang, "0.59.31", table) == "28c3c288b1198f8b7b539c7fc11bbbeb4a7be79f"
assert blob(lang, X34_F, table) == "28c3c288b1198f8b7b539c7fc11bbbeb4a7be79f"
assert blob(lang, X34_M, pandas) == "50684588f5d1792c217c809113109cf3f9ace9ac"
assert blob(lang, "556196b88149b5b494ad9e676f9923001f9aecb9", pandas) == "50684588f5d1792c217c809113109cf3f9ace9ac"
assert blob(lang, "0.59.31", pandas) == "d2d156b476ac6ead114aa5d204574d7d5e588a5b"
assert blob(lang, X34_F, pandas) == "108acf56187c1856d225bbe8c39a64a4df5e0f1e"
assert first_parent_has(lang, X34_C, "0.59.31")
assert not first_parent_has(lang, X34_M, "0.59.31")
assert first_parent_has(lang, X34_F, "0.59.32")
files = git_run(lang, "diff-tree", "--no-commit-id", "--name-only", "-r", X34_M).stdout.split()
assert files == [table]
pandas31 = git_run(lang, "show", f"0.59.31:{pandas}").stdout
pandas_fix = git_run(lang, "show", f"{X34_F}:{pandas}").stdout
assert "visit_Attribute" not in pandas31
assert "visit_Attribute" in pandas_fix
assert "Copilot@users.noreply.github.com" in git_run(lang, "log", "-1", "--format=%B", X34_M).stdout

order = ["GHSA-CW23-QWR7-C655", "GHSA-5WP8-Q9MX-8JX8", "GHSA-X34R-63HX-W57F"]
ordinals = [107, 126, 156]
excluded = [
    "GHSA-FMFG-9G7C-3VQ7",
    "GHSA-WV46-V6XC-2QHF",
    "GHSA-RG8M-3943-VM6Q",
    "GHSA-G3XQ-3GMV-QQ8G",
]
pending = ["GHSA-425G-FJHQ-5H92", "GHSA-HC8V-WWC9-VGXM"]
sel = [json.loads(line) for line in (owned / "selected.jsonl").read_text().splitlines() if line.strip()]
cases = [json.loads(line) for line in (owned / "cases.jsonl").read_text().splitlines() if line.strip()]
assert [row["ghsa_id"] for row in sel] == order
assert [row["ordinal"] for row in sel] == ordinals
assert [row["case_id"] for row in cases] == order
assert [row["ordinal"] for row in cases] == ordinals
assert len(sel) == 3 and len(cases) == 3
assert all(row["worker_verdict"] == "NARROW" for row in cases)
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
    assert all(row["gates"][g] in {"PASS", "NARROW"} for g in gates)
    assert row["gates"]["topology_gate"] == "NARROW"
    assert row["gates"]["uniqueness_gate"] == "PASS"
    assert "PASS" != row["worker_verdict"]
assert cases[0]["gates"]["identity_gate"] == "NARROW"
assert cases[1]["gates"]["identity_gate"] == "PASS"
assert cases[2]["gates"]["identity_gate"] == "PASS"
assert cases[2]["gates"]["ai_hunk_gate"] == "NARROW"
assert cases[1]["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
assert cases[1]["incomplete_remediation"]["explicit_ai_security_attempt"] is True
assert cases[1]["incomplete_remediation"]["same_boundary_patch_delta"] is False

freeze = json.loads((owned / "work/freeze.json").read_text())
assert freeze["frozen_ids"] == order
assert freeze["frozen_ordinals"] == ordinals
assert freeze["frozen_n"] == 3
assert freeze["excluded_n"] == 4
assert freeze["source_pool_n"] == 7
assert freeze["padding"] is False
assert freeze["substitution"] is False
assert freeze["packet_delta"] == 0
assert freeze["pending_excluded"] == pending
assert [row["case_id"] for row in freeze["mechanical_exclusion"]] == excluded

uni = json.loads((owned / "work/uniqueness.json").read_text())
assert uni["start_count"] == 82
assert uni["current_leader_accepted_count"] == 82
assert uni["packet_delta"] == 0
assert uni["pass_proposals"] == []
assert uni["canonical82_overlap"] == []
assert uni["frozen_selected_ids"] == order
assert uni["pending_425G_HC8V_excluded"] is True
assert uni["pending_ids"] == pending

c82 = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical82/summary.json").read_text())
assert c82["canonical_strict_count"] == 82
ids = set(c82["strict_released_case_ids"])
for case_id in order:
    assert case_id not in ids
for case_id in excluded:
    assert case_id in ids
assert "GHSA-PMCH-G965-GRMR" in ids
assert "GHSA-425G-FJHQ-5H92" not in ids
assert "GHSA-HC8V-WWC9-VGXM" not in ids

res = json.loads((owned / "result.json").read_text())
assert res["status"] == "TERMINAL"
assert res["terminal"] is True
assert res["start_count"] == 82
assert res["current_leader_accepted_count"] == 82
assert res["packet_delta"] == 0
assert res["counts"]["PASS"] == 0
assert res["counts"]["NARROW"] == 3
assert res["counts"]["assigned"] == 3
assert res["counts"]["reviewed"] == 3
assert res["counts"]["unreviewed"] == 0
assert res["conservation"]["equation"] == "3=3+0"
assert res["conservation"]["pool_equation"] == "7=4+3"
assert res["pass_proposals"] == []
assert res["exact_selected_ids"] == order
assert res["worker_pass_is_proposal_only"] is True
assert res["pending_425G_HC8V_excluded"] is True
assert res["canonical_count_updated"] is False
assert res["claim_boundary"]["publication_status"] == "HOLD"
assert res["claim_boundary"]["more_than_200_claim_supported_by_this_review"] is False
assert res["did_not_commit_or_push"] is True
assert all(res["per_case"][case_id] == "NARROW" for case_id in order)

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
print("conservation assigned=3 reviewed=3 unreviewed=0 PASS_proposal=0 NARROW=3")
PY

printf 'REPLAY_OK reviewed=3 PASS_proposal=0 NARROW=3 packet_delta=0 start=82 current=82\n'
