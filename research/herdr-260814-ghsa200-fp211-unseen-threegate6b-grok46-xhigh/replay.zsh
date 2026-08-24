#!/usr/bin/env zsh
# Fail-closed zsh replay for herdr-260814-ghsa200-fp211-unseen-threegate6b-grok46-xhigh.
# English only. Do not print credentials or environment values.
# Do not clone, commit, push, or modify shared caches.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# PASS is a proposal only. This script does not admit any row.
# Canonical baseline is 84. Packet delta is 0. Terminal NARROW. Zero PASS.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fp211-unseen-threegate6b-grok46-xhigh
export TMPDIR=$OWNED/work
O=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw
RC=/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/rconfig
DD=/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/ddev
BA=/home/hanqing/.cache/cve-analyzer/repos/better-auth_better-auth
AG=/home/hanqing/.cache/cve-analyzer/repos/significant-gravitas_autogpt

RXXP_C=506bed5aed40820565b7db66a963b8163968208f
RXXP_F=73d93dee64127a26f1acd09d0403b794cdeb4f5c
RXXP_N1=35a57bc940833a6c1f594b2308e349e5ee0148db
RXXP_N2=70dd6a30e7935691fc487cd78fbf52cde4eec9d7
H4_M=4b0938dd509025e6630b86eb61442d2d69c68295
H4_C=ebb39d59d259152855cc297859f5a24632a14e80
H4_F=84822f4051ed97d651b1b4d191c6da2aa8c3c037
X2_M=93f80ea4470c9984ae2b95662008b589ed8f35d9
X2_C=5f9884519a8c4e4e9d2af5e97e31abfea1098a82
X2_F=05cbe299770a590b89bfc8dddab33e61b4302e43
WX_M=3d3435b32ded72482fbe0d2fc917d5d6857647d1
WX_C=0deaaa4e67c3067bd3b0570b3adfef2b532c7085
WX_F=9deb7936aba7931f2db4b460141f476508f11bfd
VW_M=a75c1af2e4d3009a84bf0ad837a09cec3a4a07c9
VW_C=f172b314a4db5084fd46ce8ddcb94592a96d8a49
VW_F=57a06f70883ce6be18738c6ae8bb41085c71e266
HF_C=e0b8ddc1a55185aff1cf9e0e095014d2e4f1d894
HF_F=3d93174c4398088066a1de9372ea1103cd713df1

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)
TIMEOUT_BIN=/usr/bin/timeout

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
  "$TIMEOUT_BIN" 40 "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
  if [[ $rc -eq 124 ]]; then
    printf 'git timeout\n' >&2
    rm -f "$errf"
    exit 1
  fi
  if grep -qE 'could not fetch|bad object|not our ref|could not get object info|promisor|partial clone|unable to read' "$errf" 2>/dev/null; then
    printf 'missing object (fail closed)\n' >&2
    rm -f "$errf"
    exit 1
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

expect_blob() {
  local repo=$1 rev=$2 file=$3 want=$4
  local got
  got=$(g "$repo" rev-parse "$rev:$file")
  if [[ $got != "$want" ]]; then
    printf 'blob mismatch %s:%s\n expected %s\n got %s\n' "$rev" "$file" "$want" "$got" >&2
    exit 1
  fi
}

require_dir "$OWNED"
require_dir "$O/.git"
require_dir "$RC/.git"
require_dir "$DD/.git"
require_dir "$BA/.git"
require_dir "$AG/.git"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/replay.zsh"
require_file "$OWNED/compact_facts.json"
require_file "$OWNED/notes/README.md"
require_file "$OWNED/notes/freeze.txt"
require_file "$OWNED/notes/facts/README.md"
require_file "$OWNED/notes/diffs/README.md"
require_file "$OWNED/notes/releases/README.md"
require_file "$OWNED/work/freeze.json"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/pages/repo-advisory/openclaw__openclaw__GHSA-RXXP-482V-7MRH.json"
require_file "$OWNED/work/pages/repo-advisory/rconfig__rconfig__GHSA-H4RQ-P45C-642R.json"
require_file "$OWNED/work/pages/ghsa/GHSA-H4RQ-P45C-642R.json"
require_file "$OWNED/work/pages/npm/openclaw.json"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$OWNED/selected.jsonl" \
  e117de598cd07700a302ae543837c9e53e6f0d563f81b0df59c298cf9d62a705
expect_hash "$OWNED/cases.jsonl" \
  bad39b29ff9e15ec5d1646a7de0011471ef967ba5784c0955de38d061e3b2d6f
expect_hash "$OWNED/report.md" \
  12977842abc02694913d54a936822760d62a763af1b9dc2af9cb2a4acedc81ae
expect_hash "$OWNED/compact_facts.json" \
  d894e51e3f2cf430ff9d51b7b19d6e555c42e2cc13239f3bf48d5c2897794034
expect_hash "$OWNED/notes/README.md" \
  aa86d23cf798e2d757ea48a9aa1102c529def522e5035429b8cf49dc34dca6b4
expect_hash "$OWNED/notes/freeze.txt" \
  4579973ddf4f577e10082261de5f6491d1b4135f7785ea6d62ffe5114c11f7fe
expect_hash "$OWNED/notes/facts/README.md" \
  5e2951f1b75e006ada09e631cbb7466b237ee6de7cd98c82876781af60508253
expect_hash "$OWNED/notes/diffs/README.md" \
  3a34d5be12dec77a8ab015f0a9281aedb8a7612525fe5dbe53d4129c8317051e
expect_hash "$OWNED/work/freeze.json" \
  11dca128c1d88cdc1fcd516d580757cdcd8e014e4e3b75e4db0d64de9062a424
expect_hash "$OWNED/work/uniqueness.json" \
  78681f164e3cff0b76a0a508caafc9c99303aac8f6ec804fd09d64ae9ac07b8a
expect_hash "$OWNED/notes/facts/GHSA-RXXP-482V-7MRH.compact.json" \
  9421341f88d9ff18812357f737bbe6f9cbb7ea2aca58faf7a0f6319e58ea8d2c
expect_hash "$OWNED/notes/facts/GHSA-H4RQ-P45C-642R.compact.json" \
  021cb307acbdae116e0836394c1764c52bd1dd65d775398cea055d4ef7bb487f
expect_hash "$OWNED/notes/facts/GHSA-X2XQ-QHJF-5MVG.compact.json" \
  d51af46efe62ebca92684752f3da60fd64f9bd364223176d1486edbdc1f964a7
expect_hash "$OWNED/notes/facts/GHSA-WXW3-Q3M9-C3JR.compact.json" \
  ee35435ecd4a95790b23223d498080af62c6bf7a5dc75320be4cc7226aa1b459
expect_hash "$OWNED/notes/facts/GHSA-VW3V-WHVP-33V5.compact.json" \
  15bc1ecfbed3fe2db639defe507559e671ad35cad06411942174d757dd5150da
expect_hash "$OWNED/notes/facts/GHSA-2HFG-4FH4-QP7F.compact.json" \
  337424d9780569a907684aa695e3d060f2c331a0ed0549c9ea5ce1436d8c64b8
expect_hash "$OWNED/notes/releases/github_releases.json" \
  0a9ed4e06cf47eb7fba318f1b02bab6722964c960daa57fc7877a613ca9d450b

# Atomic parents. Capture git stdout; do not leak it.
rxxp_parents=$(g "$O" rev-list --parents -n 1 "$RXXP_C")
print -r -- "$rxxp_parents" | /usr/bin/awk '{ if (NF != 2) { print "RXXP candidate not atomic" > "/dev/stderr"; exit 1 } }'
h4_parents=$(g "$RC" rev-list --parents -n 1 "$H4_M")
print -r -- "$h4_parents" | /usr/bin/awk '{ if (NF != 2) { print "H4RQ member not atomic" > "/dev/stderr"; exit 1 } }'
h4c_parents=$(g "$RC" rev-list --parents -n 1 "$H4_C")
print -r -- "$h4c_parents" | /usr/bin/awk '{ if (NF != 3) { print "H4RQ carrier must be a merge" > "/dev/stderr"; exit 1 } }'
x2_parents=$(g "$DD" rev-list --parents -n 1 "$X2_M")
print -r -- "$x2_parents" | /usr/bin/awk '{ if (NF != 2) { print "X2XQ member not atomic" > "/dev/stderr"; exit 1 } }'
wx_parents=$(g "$BA" rev-list --parents -n 1 "$WX_M")
print -r -- "$wx_parents" | /usr/bin/awk '{ if (NF != 2) { print "WXW3 member not atomic" > "/dev/stderr"; exit 1 } }'
vw_parents=$(g "$AG" rev-list --parents -n 1 "$VW_M")
print -r -- "$vw_parents" | /usr/bin/awk '{ if (NF != 2) { print "VW3V member not atomic" > "/dev/stderr"; exit 1 } }'
hf_parents=$(g "$O" rev-list --parents -n 1 "$HF_C")
print -r -- "$hf_parents" | /usr/bin/awk '{ if (NF != 2) { print "2HFG candidate not atomic" > "/dev/stderr"; exit 1 } }'

# RXXP: candidate in npm 2026.2.21-2; closer not; both in npm 2026.2.22.
assert_ancestor "$O" "$RXXP_C" "$RXXP_N1"
assert_not_ancestor "$O" "$RXXP_F" "$RXXP_N1"
assert_ancestor "$O" "$RXXP_C" "$RXXP_N2"
assert_ancestor "$O" "$RXXP_F" "$RXXP_N2"
assert_ancestor "$O" "$RXXP_C" v2026.2.21
assert_not_ancestor "$O" "$RXXP_F" v2026.2.21
assert_ancestor "$O" "$RXXP_F" v2026.2.22

# H4RQ: member is a tag ancestor. Merge carrier is not a substitute.
assert_ancestor "$RC" "$H4_M" "$H4_C"
assert_ancestor "$RC" "$H4_M" core-8.2.3
assert_not_ancestor "$RC" "$H4_F" core-8.2.3
assert_ancestor "$RC" "$H4_F" core-8.2.8
expect_blob "$RC" "$H4_M" app/Http/Requests/StoreUserRequest.php bd685aacce450928b00b300e01056d93b8c6a693
expect_blob "$RC" "$H4_M^" app/Http/Requests/StoreUserRequest.php bd685aacce450928b00b300e01056d93b8c6a693
expect_blob "$RC" core-8.2.3 app/Http/Controllers/Api/v1/UserController.php a51f880a4cb9a30c0fb75729c918bf7dd014b77c

# X2XQ: member is not a tag/carrier ancestor. Do not transfer.
assert_not_ancestor "$DD" "$X2_M" "$X2_C"
assert_not_ancestor "$DD" "$X2_M" v1.25.1
assert_ancestor "$DD" "$X2_C" v1.25.1
assert_not_ancestor "$DD" "$X2_F" v1.25.1
assert_ancestor "$DD" "$X2_F" v1.25.2
expect_blob "$DD" "$X2_M" pkg/archive/archive.go 850c6f5f8ac7e717ae160ca0ab3a06059286bcc6
expect_blob "$DD" "$X2_C" pkg/archive/archive.go 491dd68b69888b900059e0542a1e27df81e31592
expect_blob "$DD" v1.25.1 pkg/archive/archive.go 491dd68b69888b900059e0542a1e27df81e31592
expect_blob "$DD" v1.25.2 pkg/archive/archive.go e318b848a6f27c2b4006a8a49450d65aed172178

# WXW3: member is not a tag/carrier ancestor. Do not transfer.
assert_not_ancestor "$BA" "$WX_M" "$WX_C"
assert_not_ancestor "$BA" "$WX_M" v1.6.0
assert_ancestor "$BA" "$WX_C" v1.6.0
assert_not_ancestor "$BA" "$WX_F" v1.6.1
assert_ancestor "$BA" "$WX_F" v1.6.2
expect_blob "$BA" "$WX_M" packages/better-auth/src/plugins/oauth-proxy/index.ts 224bd60556abbc622014565d1774a7d09a6937aa
expect_blob "$BA" v1.6.0 packages/better-auth/src/plugins/oauth-proxy/index.ts e8577b6a81a70959d0c214efc97961ed2629cd7e
expect_blob "$BA" v1.6.2 packages/better-auth/src/plugins/oauth-proxy/index.ts 674187d322b01724ad8a6bfbd7c81b6e45d63f84

# VW3V: member is not a tag/carrier ancestor. Do not transfer.
assert_not_ancestor "$AG" "$VW_M" "$VW_C"
assert_not_ancestor "$AG" "$VW_M" autogpt-platform-beta-v0.6.30
assert_ancestor "$AG" "$VW_C" autogpt-platform-beta-v0.6.30
assert_not_ancestor "$AG" "$VW_F" autogpt-platform-beta-v0.6.30
assert_ancestor "$AG" "$VW_F" autogpt-platform-beta-v0.6.32
expect_blob "$AG" "$VW_M" autogpt_platform/docker-compose.platform.yml 3da6115e1c4cf10cadb8c38a98c8b28a03ffc741
expect_blob "$AG" autogpt-platform-beta-v0.6.30 autogpt_platform/docker-compose.platform.yml bf3d17fc33b3d075b899aa9c9d14aa0e84ceebe3
expect_blob "$AG" autogpt-platform-beta-v0.6.32 autogpt_platform/docker-compose.platform.yml b2df626029fb665dc60785ed88f001378260212f

# 2HFG: candidate in v2026.5.12; closer in v2026.5.18 only.
assert_ancestor "$O" "$HF_C" v2026.5.12
assert_not_ancestor "$O" "$HF_F" v2026.5.12
assert_ancestor "$O" "$HF_F" v2026.5.18

python3 - "$OWNED" "$ROOT" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
root = Path(sys.argv[2])
order = [
    "GHSA-RXXP-482V-7MRH",
    "GHSA-H4RQ-P45C-642R",
    "GHSA-X2XQ-QHJF-5MVG",
    "GHSA-WXW3-Q3M9-C3JR",
    "GHSA-VW3V-WHVP-33V5",
    "GHSA-2HFG-4FH4-QP7F",
]
ordinals = [85, 87, 91, 97, 102, 199]
sel = [json.loads(line) for line in (owned / "selected.jsonl").read_text().splitlines() if line.strip()]
cases = [json.loads(line) for line in (owned / "cases.jsonl").read_text().splitlines() if line.strip()]
assert len(sel) == 6
assert len(cases) == 6
assert [row["case_id"] for row in sel] == order
assert [row["case_id"] for row in cases] == order
assert [row["ordinal"] for row in sel] == ordinals
assert all(row["padding"] is False and row["substitution"] is False for row in sel)
assert [row["worker_verdict"] for row in cases] == ["NARROW"] * 6
assert all(row["countable"] is False and row["countable_proposal"] is False for row in cases)
assert all(row["packet_delta"] == 0 for row in cases)
assert all(row["causal_admission"] is False for row in cases)
assert all(row["worker_pass_is_proposal_only"] is True for row in cases)
assert all(row["publication_status"] == "HOLD" for row in cases)
assert all(row["inherited_labels_are_not_proof"] is True for row in cases)
assert cases[1]["authorship_transfer_from_member_to_carrier"] is False
assert cases[2]["authorship_transfer_from_member_to_carrier"] is False
assert cases[3]["authorship_transfer_from_member_to_carrier"] is False
assert cases[4]["authorship_transfer_from_member_to_carrier"] is False
assert cases[5]["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
assert cases[5]["incomplete_remediation"]["ai_hunk_proven"] is False
assert cases[0]["gates"]["identity_gate"] == "PASS"
assert cases[1]["gates"]["identity_gate"] == "NARROW"
assert cases[1]["gates"]["topology_gate"] == "PASS"
assert cases[5]["gates"]["ai_hunk_gate"] == "NARROW"
assert all(row["worker_verdict"] != "PASS" for row in cases)

freeze = json.loads((owned / "work/freeze.json").read_text())
assert freeze["frozen_n"] == 6
assert freeze["frozen_ordinals"] == ordinals
assert freeze["did_not_pad"] is True
assert freeze["did_not_substitute"] is True
assert freeze["packet_delta"] == 0
assert freeze["canonical_strict_count"] == 84
assert freeze["pool_equation"] == "12=threegate6a_6+assigned_6"

uni = json.loads((owned / "work/uniqueness.json").read_text())
assert uni["canonical_strict_count"] == 84
assert all(v is False for v in uni["assigned_in_counted"].values())
assert uni["xwcj_counted"] is False
assert uni["cve_2026_53812_not_added"] is True

c84 = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json").read_text())
assert c84["canonical_strict_count"] == 84
ids = set(c84["strict_released_case_ids"])
for case_id in order:
    assert case_id not in ids
assert "GHSA-8JPQ-5H99-FF5R" in ids
assert "GHSA-W28W-GP39-M4P6" in ids

def is_404(obj):
    if obj.get("status") in {"404", 404}:
        return True
    err = str(obj.get("error") or obj.get("message") or "")
    return "404" in err or err == "Not Found"

pages = owned / "work/pages"
rxxp = json.loads((pages / "repo-advisory/openclaw__openclaw__GHSA-RXXP-482V-7MRH.json").read_text())
assert rxxp["state"] == "published" and rxxp["withdrawn_at"] is None
assert "byte" in (rxxp.get("summary") or "").lower()
h4r = json.loads((pages / "repo-advisory/rconfig__rconfig__GHSA-H4RQ-P45C-642R.json").read_text())
assert is_404(h4r)
h4g = json.loads((pages / "ghsa/GHSA-H4RQ-P45C-642R.json").read_text())
assert h4g.get("type") == "unreviewed"
x2 = json.loads((pages / "repo-advisory/ddev__ddev__GHSA-X2XQ-QHJF-5MVG.json").read_text())
assert x2["state"] == "published" and x2["withdrawn_at"] is None
wx = json.loads((pages / "repo-advisory/better-auth__better-auth__GHSA-WXW3-Q3M9-C3JR.json").read_text())
assert wx["state"] == "published" and wx.get("cve_id") is None
vw = json.loads((pages / "repo-advisory/Significant-Gravitas__AutoGPT__GHSA-VW3V-WHVP-33V5.json").read_text())
assert vw["state"] == "published" and vw["withdrawn_at"] is None
assert is_404(json.loads((pages / "ghsa/GHSA-VW3V-WHVP-33V5.json").read_text()))
hf = json.loads((pages / "repo-advisory/openclaw__openclaw__GHSA-2HFG-4FH4-QP7F.json").read_text())
assert hf["state"] == "published" and hf.get("cve_id") is None
hfg = json.loads((pages / "ghsa/GHSA-2HFG-4FH4-QP7F.json").read_text())
assert hfg.get("cve_id") == "CVE-2026-53812"
npm = json.loads((pages / "npm/openclaw.json").read_text())
vers = npm.get("versions") or {}
assert vers["2026.2.21-2"]["gitHead"] == "35a57bc940833a6c1f594b2308e349e5ee0148db"
assert vers["2026.2.22"]["gitHead"] == "70dd6a30e7935691fc487cd78fbf52cde4eec9d7"
assert vers["2026.5.12"].get("gitHead") is None
assert vers["2026.5.18"].get("gitHead") is None
ba = json.loads((pages / "npm/better-auth.json").read_text())
bvers = ba.get("versions") or {}
assert bvers["1.6.0"].get("gitHead") is None
assert bvers["1.6.2"].get("gitHead") is None
rel = json.loads((owned / "notes/releases/github_releases.json").read_text())
for name in (
    "openclaw_v2026.2.21.json",
    "openclaw_v2026.2.22.json",
    "rconfig_core-8.2.3.json",
    "rconfig_core-8.2.8.json",
    "ddev_v1.25.1.json",
    "ddev_v1.25.2.json",
    "better-auth_v1.6.0.json",
    "better-auth_v1.6.2.json",
    "autogpt_v0.6.30.json",
    "autogpt_v0.6.32.json",
    "openclaw_v2026.5.12.json",
    "openclaw_v2026.5.18.json",
):
    o = rel[name]
    assert o["draft"] is False and o["prerelease"] is False, name

res = json.loads((owned / "result.json").read_text())
assert res["status"] == "TERMINAL"
assert res["terminal"] is True
assert res["terminal_status"] == "NARROW"
assert res["start_count"] == 84
assert res["current_leader_accepted_count"] == 84
assert res["packet_delta"] == 0
assert res["counts"]["PASS"] == 0
assert res["counts"]["NARROW"] == 6
assert res["conservation"]["equation"] == "6=6+0"
assert res["pass_proposals"] == []
assert res["worker_pass_is_proposal_only"] is True
assert res["canonical_count_updated"] is False
assert res["canonical_strict_count_untouched"] == 84
assert res["claim_boundary"]["publication_status"] == "HOLD"
assert res["claim_boundary"]["more_than_200_claim_supported_by_this_review"] is False
assert res["did_not_commit_or_push"] is True
for case_id in order:
    assert res["per_case"][case_id] == "NARROW"

han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(r"ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}")
names = [
    "selected.jsonl",
    "cases.jsonl",
    "report.md",
    "replay.zsh",
    "result.json",
    "compact_facts.json",
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
    assert not han.search(text), name
    assert not secret.search(text), name
    assert text.endswith("\n"), name
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (name, line)
print("CONSERVATION_OK 6=6+0")
PY

printf 'REPLAY_OK reviewed=6 PASS_proposal=0 NARROW=6 REJECT=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 canonical=84\n'
