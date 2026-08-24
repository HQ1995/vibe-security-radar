#!/usr/bin/env zsh
# Fail-closed zsh replay for herdr-260814-ghsa200-fp211-singlegate5-grok46-xhigh.
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
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fp211-singlegate5-grok46-xhigh
export TMPDIR=$OWNED/work
HUD=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/claude-hud
OC=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw
CRM=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/churchcrm
SOL=$OWNED/work/clones/solidcam-gppl-ide

HUD_C=26a3e984e442382f83297b545626f7293f4379b4
HUD_F=234d9aad919b51326a43bcf90b45ae35c23afc30
F7_C=75602014dbc5088b80e9b236146dfe5fdcc59e20
F7_F=bc356cc8c2beaa747c71dd86cceab8f804699665
Q2_M=fc1b156dc4105bdbcdc24d4c25d4f5af25cfd7bb
Q2_C=f4cc93dc7da7359c35130bbbb244d3fac695740f
Q2_F=53c29df2a9eb242a70d0ff29f3d1e67c8d6801f0
VG_C=d1944bca6e984665fb98f5ea824c6c370fd618d6
VG_F=9d0ba808afd143ede448026a5dc681bfdc5c138d
CR_C=b3edc22580116beb6bc8463d1876f2a7c9b96a28
CR_F=83c19611701b96300872390071440151360dfb48

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
require_dir "$HUD/.git"
require_dir "$OC/.git"
require_dir "$CRM/.git"
require_dir "$SOL/.git"
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
require_file "$OWNED/work/freeze.json"
require_file "$OWNED/work/uniqueness.json"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$OWNED/selected.jsonl" \
  92e865d61826095602f1aa39c3dd14224d710cd07488933bc045af0c2b6bd676
expect_hash "$OWNED/cases.jsonl" \
  4bc2dce15507c75588e19127cd7b104aa628e1b1c71e6833b835bbc417d03be8
expect_hash "$OWNED/report.md" \
  934747b34d504a168ade0cc499153c9081490d326a6943185be52542a4e675f9
expect_hash "$OWNED/compact_facts.json" \
  36ce4e486045425bccf1bc5b315b277e2db94c59b5cecc3d84b135ee79b3fab4
expect_hash "$OWNED/notes/README.md" \
  5e32fc0e13545171640f783d024b05ca45c3b9eb1bf3b9d9a85e4ecb470aa7b6
expect_hash "$OWNED/notes/freeze.txt" \
  1b7ca1cd5aed69aad2cc555975c77e740d353bb868f5e7507f03666c68ed290c
expect_hash "$OWNED/notes/facts/README.md" \
  2b7fcc27da0f3808dcc66555839a5b31812bc26b7d2f6136f400e026d75198c8
expect_hash "$OWNED/notes/diffs/README.md" \
  86afb95dda0dfffbc995ab4ab2ab224c83ca7b3bdcfa210fc68074b2ee4e3b3e
expect_hash "$OWNED/work/freeze.json" \
  0bf90bcfd3de151518f93f3a91a87291e2790bf886fdf8bf2fcb465f58dec3dd
expect_hash "$OWNED/work/uniqueness.json" \
  295e904fce54c4fd31604019a4757a7d5555c1e21838ae828ce25ccb0ba135d1
expect_hash "$OWNED/notes/facts/GHSA-4524-X6PC-RR9X.compact.json" \
  d9cc3ef9f4f782f3082603650f0260e3a3f84db18b2a741cc952ca6e0d501110
expect_hash "$OWNED/notes/facts/GHSA-F7FH-QG34-X2XH.compact.json" \
  6cf63ce3c024c3276269c9bfa092a105b966be43c20843dc33dccdc88eb36979
expect_hash "$OWNED/notes/facts/GHSA-92VG-F4FQ-FXM9.compact.json" \
  b047f7c32fb61491bfb9ea0791165358cab92963421aac7a48428d77fb1408a6
expect_hash "$OWNED/notes/facts/GHSA-2QRV-RC5X-2G2H.compact.json" \
  4a89cf6d5b5cc43f833f5c7dd49fa51986c725c44a0f03c88b3f7fe2a58e093d
expect_hash "$OWNED/notes/facts/GHSA-3J8Q-FWPJ-F8J5.compact.json" \
  e57443593d91ad0cb5513e5c20c73ed4c5754eb456bb7a30dfe832226b6395a2

# Atomic parents. Capture git stdout; do not leak it.
hud_parents=$(g "$HUD" rev-list --parents -n 1 "$HUD_C")
print -r -- "$hud_parents" | /usr/bin/awk '{ if (NF != 2) { print "4524 candidate not atomic" > "/dev/stderr"; exit 1 } }'
f7_parents=$(g "$OC" rev-list --parents -n 1 "$F7_C")
print -r -- "$f7_parents" | /usr/bin/awk '{ if (NF != 2) { print "F7FH candidate not atomic" > "/dev/stderr"; exit 1 } }'
q2_parents=$(g "$OC" rev-list --parents -n 1 "$Q2_M")
print -r -- "$q2_parents" | /usr/bin/awk '{ if (NF != 2) { print "2QRV member not atomic" > "/dev/stderr"; exit 1 } }'
vg_parents=$(g "$SOL" rev-list --parents -n 1 "$VG_C")
print -r -- "$vg_parents" | /usr/bin/awk '{ if (NF != 2) { print "92VG candidate not atomic" > "/dev/stderr"; exit 1 } }'
cr_parents=$(g "$CRM" rev-list --parents -n 1 "$CR_C")
print -r -- "$cr_parents" | /usr/bin/awk '{ if (NF != 2) { print "ord200 candidate not atomic" > "/dev/stderr"; exit 1 } }'

# 4524: candidate in v0.0.12; closer not in that tag; closer in v0.1.0.
assert_ancestor "$HUD" "$HUD_C" v0.0.12
assert_not_ancestor "$HUD" "$HUD_F" v0.0.12
assert_ancestor "$HUD" "$HUD_F" v0.1.0

# F7FH: candidate in v2026.4.1 and v2026.3.8; closer in v2026.4.5 only.
assert_ancestor "$OC" "$F7_C" v2026.3.8
assert_ancestor "$OC" "$F7_C" v2026.4.1
assert_not_ancestor "$OC" "$F7_F" v2026.4.1
assert_ancestor "$OC" "$F7_F" v2026.4.5

# 2QRV: member is not a tag/carrier ancestor. Do not transfer authorship.
assert_not_ancestor "$OC" "$Q2_M" "$Q2_C"
assert_not_ancestor "$OC" "$Q2_M" v2026.3.22
assert_not_ancestor "$OC" "$Q2_M" v2026.4.1
assert_ancestor "$OC" "$Q2_C" v2026.4.1
assert_not_ancestor "$OC" "$Q2_F" v2026.4.1
assert_ancestor "$OC" "$Q2_F" v2026.4.2

# 92VG: candidate is the v1.0.0 peel; assigned closer is v1.0.2.
assert_ancestor "$SOL" "$VG_C" v1.0.0
assert_ancestor "$SOL" "$VG_F" v1.0.2

# ord200: candidate in 7.3.3; closer in 7.4.0 only.
assert_ancestor "$CRM" "$CR_C" 7.3.3
assert_not_ancestor "$CRM" "$CR_F" 7.3.3
assert_ancestor "$CRM" "$CR_F" 7.4.0

python3 - "$OWNED" "$ROOT" "$HUD" "$OC" "$CRM" "$SOL" << 'PY'
import json, os, re, subprocess, sys
from pathlib import Path

owned = Path(sys.argv[1])
root = Path(sys.argv[2])
hud, oc, crm, sol = sys.argv[3:7]
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

HUD_C = "26a3e984e442382f83297b545626f7293f4379b4"
HUD_P = "c94b88e9d97e5beb69690ee31bdfe9350f4fc64e"
HUD_F = "234d9aad919b51326a43bcf90b45ae35c23afc30"
F7_C = "75602014dbc5088b80e9b236146dfe5fdcc59e20"
F7_P = "3cf75f760c0f89adbad9415b3d5fdb5b83f2dd82"
Q2_M = "fc1b156dc4105bdbcdc24d4c25d4f5af25cfd7bb"
Q2_P = "c74042ba04515894e584ad8a76c9e7b7b92fec54"
Q2_C = "f4cc93dc7da7359c35130bbbb244d3fac695740f"
Q2_F = "53c29df2a9eb242a70d0ff29f3d1e67c8d6801f0"
VG_C = "d1944bca6e984665fb98f5ea824c6c370fd618d6"
VG_F = "9d0ba808afd143ede448026a5dc681bfdc5c138d"
CR_C = "b3edc22580116beb6bc8463d1876f2a7c9b96a28"
CR_P = "51e49adbc1b3b40ec93988267dcad7ffa02d0372"
CR_F = "83c19611701b96300872390071440151360dfb48"


def git_run(repo, *args, ok=(0,)):
    r = subprocess.run(git + ["-C", repo, *args], capture_output=True, text=True, env=env)
    err = "\n".join(
        line
        for line in r.stderr.splitlines()
        if "unable to normalize alternate object path" not in line
        and "exhaustive rename detection" not in line
        and "diff.renameLimit" not in line
    )
    if err.strip():
        raise SystemExit(f"git stderr {args}: {err}")
    if r.returncode not in ok:
        raise SystemExit(f"git rc={r.returncode} {args}")
    return r


def blob(repo, rev, rel):
    return git_run(repo, "rev-parse", f"{rev}:{rel}").stdout.strip()


def missing(repo, rev, rel):
    r = git_run(repo, "ls-tree", "--name-only", rev, "--", rel)
    return r.stdout.strip() == ""


def first_parent_has(repo, commit, tag):
    out = git_run(repo, "rev-list", "--first-parent", tag).stdout.split()
    return commit in out


assert missing(hud, HUD_P, "src/transcript.ts")
assert missing(hud, HUD_P, "src/index.ts")
assert blob(hud, HUD_C, "src/transcript.ts") == "1eb1b450d0329c4922847f3468db28fd90d4cbf1"
assert blob(hud, "v0.0.12", "src/transcript.ts") == "d92ddf92c2e1e33af0a4f735bb5669cc3e97782c"
assert blob(hud, HUD_C, "src/transcript.ts") != blob(hud, "v0.0.12", "src/transcript.ts")
assert git_run(hud, "rev-parse", "v0.0.12^{commit}").stdout.strip() == "c4fd79e6d31fe40d8e57b1e3db768025254df553"
assert git_run(hud, "rev-parse", "v0.1.0^{commit}").stdout.strip() == "b0ab7e6a303b8f67845e3ca07d52dd3cd722428e"
assert "harden links and Windows version lookup" in git_run(hud, "log", "-1", "--format=%s", HUD_F).stdout
assert "noreply@anthropic.com" in git_run(hud, "log", "-1", "--format=%B", HUD_C).stdout
v010 = git_run(hud, "show", f"v0.1.0:src/transcript.ts").stdout
assert "allowlist" not in v010
assert first_parent_has(hud, HUD_C, "v0.0.12")

assert first_parent_has(oc, F7_C, "v2026.4.1")
pick = git_run(oc, "log", "--first-parent", "-S", "isWebSocketUrl", "--pretty=%H", "v2026.4.1").stdout.split()
assert pick[-1] == F7_C
parent_cdp = git_run(oc, "show", f"{F7_P}:src/browser/cdp.ts").stdout
assert "json/version" in parent_cdp
assert "webSocketDebuggerUrl" in parent_cdp
assert "isWebSocketUrl" not in parent_cdp
cand_cdp = git_run(oc, "show", f"{F7_C}:src/browser/cdp.ts").stdout
assert "isWebSocketUrl" in cand_cdp
assert git_run(oc, "rev-parse", "v2026.3.8^{commit}").stdout.strip() == "3caab9260cb0a0064e6a37b2de3bedc8a547e599"
assert git_run(oc, "rev-parse", "v2026.4.1^{commit}").stdout.strip() == "da64a978e5814567f7797cc34fbe29b61b7eae7a"
assert git_run(oc, "rev-parse", "v2026.4.5^{commit}").stdout.strip() == "3e72c0352dde84a0bcb3aabafa99c2d4b12d1c46"
assert "noreply@anthropic.com" in git_run(oc, "log", "-1", "--format=%B", F7_C).stdout

assert blob(oc, Q2_M, "src/channels/plugins/catalog.ts") == "a853dcdf80580c28f94948d9f750e01358ae8507"
assert blob(oc, Q2_P, "src/channels/plugins/catalog.ts") == "a853dcdf80580c28f94948d9f750e01358ae8507"
assert blob(oc, Q2_M, "src/plugins/loader.ts") == "86d83fa81ddde9c65075ca6025dc582bf435d945"
assert blob(oc, Q2_C, "src/plugins/loader.ts") == "b9132c08f3322d506f6dc9778d979b777ca9cf0c"
assert blob(oc, "v2026.4.1", "src/plugins/loader.ts") == "7b6cebb7490b6044665351dabb1b71a9c21eb204"
assert blob(oc, Q2_M, "src/plugins/loader.ts") != blob(oc, Q2_C, "src/plugins/loader.ts")
assert blob(oc, Q2_C, "src/plugins/loader.ts") != blob(oc, "v2026.4.1", "src/plugins/loader.ts")
member_files = git_run(oc, "diff-tree", "--no-commit-id", "--name-only", "-r", Q2_M).stdout.split()
assert "src/channels/plugins/catalog.ts" not in member_files
assert "noreply@anthropic.com" in git_run(oc, "log", "-1", "--format=%B", Q2_M).stdout
assert "noreply@anthropic.com" in git_run(oc, "log", "-1", "--format=%B", Q2_C).stdout
assert blob(oc, Q2_F, "src/channels/plugins/catalog.ts") == blob(oc, "v2026.4.2", "src/channels/plugins/catalog.ts")

assert git_run(sol, "rev-parse", "v1.0.0^{commit}").stdout.strip() == VG_C
assert git_run(sol, "rev-parse", "v1.0.2^{commit}").stdout.strip() == VG_F
vg_files = git_run(sol, "diff-tree", "--no-commit-id", "--name-only", "-r", VG_C).stdout.split()
assert vg_files == [
    "CHANGELOG.md",
    "README.md",
    "package.json",
    "server/SolidCAM.GPPL.Server.exe",
    "server/SolidCAM.GPPL.Server.pdb",
]
cs = [n for n in git_run(sol, "ls-tree", "-r", "--name-only", VG_C).stdout.split() if n.endswith(".cs")]
assert cs == []
missing_fix = git_run(sol, "rev-parse", "--verify", "--quiet", "4939a1b", ok=(0, 1))
assert missing_fix.returncode == 1
assert "noreply@anthropic.com" in git_run(sol, "log", "-1", "--format=%B", VG_C).stdout

assert missing(crm, CR_P, "src/api/routes/people/notes.php")
assert blob(crm, CR_C, "src/api/routes/people/notes.php") == "00773c583aa923494ba85ca84ef442275f8833c1"
assert blob(crm, "7.3.3", "src/api/routes/people/notes.php") == "2df274e2920dc3b458e074f87cf59cd755494dbc"
assert blob(crm, CR_F, "src/api/routes/people/notes.php") == "a244f82d0c4d3d73ad16173a4b340f3663843abc"
assert blob(crm, "7.4.0", "src/api/routes/people/notes.php") == "a244f82d0c4d3d73ad16173a4b340f3663843abc"
assert blob(crm, CR_C, "src/api/routes/people/notes.php") != blob(crm, "7.3.3", "src/api/routes/people/notes.php")
assert git_run(crm, "rev-parse", "7.3.3^{commit}").stdout.strip() == "da7ffe51e09dfab869750d6f56e94e03960346d1"
assert git_run(crm, "rev-parse", "7.4.0^{commit}").stdout.strip() == "66a731a1cf9b56e96b9a27de1bcb16364bbd986a"
fix_body = git_run(crm, "log", "-1", "--format=%B", CR_F).stdout.lower()
assert "ghsa-jjcj-h3cm-p7x7" in fix_body
assert "ghsa-3j8q" not in fix_body
assert "noreply@anthropic.com" in git_run(crm, "log", "-1", "--format=%B", CR_C).stdout
notes733 = git_run(crm, "show", "7.3.3:src/api/routes/people/notes.php").stdout
assert "canEditPerson" not in notes733

sel_order = [
    "GHSA-4524-X6PC-RR9X",
    "GHSA-F7FH-QG34-X2XH",
    "GHSA-92VG-F4FQ-FXM9",
    "GHSA-2QRV-RC5X-2G2H",
]
ord200_ids = ["GHSA-3J8Q-FWPJ-F8J5", "GHSA-JJCJ-H3CM-P7X7"]
case_order = sel_order + ord200_ids
ordinals = [74, 78, 110, 123, 200]
sel = [json.loads(line) for line in (owned / "selected.jsonl").read_text().splitlines() if line.strip()]
cases = [json.loads(line) for line in (owned / "cases.jsonl").read_text().splitlines() if line.strip()]
assert len(sel) == 5
assert len(cases) == 6
assert [row["ordinal"] for row in sel] == ordinals
assert [row["ghsa_ids"][0] for row in sel] == sel_order + ["GHSA-3J8Q-FWPJ-F8J5"]
assert sel[4]["ghsa_ids"] == ord200_ids
assert [row["case_id"] for row in cases] == case_order
assert all(row["padding"] is False and row["substitution"] is False for row in sel)
assert [row["worker_verdict"] for row in cases] == [
    "NARROW",
    "NARROW",
    "NARROW",
    "NARROW",
    "NARROW",
    "REJECT",
]
assert all(row["countable"] is False and row["countable_proposal"] is False for row in cases)
assert all(row["packet_delta"] == 0 for row in cases)
assert all(row["causal_admission"] is False for row in cases)
assert all(row["worker_pass_is_proposal_only"] is True for row in cases)
assert all(row["publication_status"] == "HOLD" for row in cases)
assert all(row["inherited_pass_is_not_proof"] is True for row in cases)
gates = [
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
]
ids_by_case = {row["case_id"]: row for row in cases}
for row in cases:
    assert set(row["gates"]) == set(gates)
    assert all(row["gates"][g] in {"PASS", "NARROW", "FAIL"} for g in gates)
    assert row["worker_verdict"] != "PASS"
    assert any(row["gates"][g] != "PASS" for g in gates)
    dup = row.get("duplicate_mechanism_of")
    if dup:
        assert dup != row["case_id"]
        assert dup in ids_by_case
        assert row["gates"]["uniqueness_gate"] == "FAIL"
        assert "uniqueness_gate" in row["failing_gates"]
        assert row["countable"] is False
        assert row["countable_proposal"] is False
        assert row["worker_verdict"] == "REJECT"
    else:
        assert row["gates"]["uniqueness_gate"] == "PASS"
assert cases[4]["case_id"] == "GHSA-3J8Q-FWPJ-F8J5"
assert cases[4]["worker_verdict"] == "NARROW"
assert cases[4]["gates"]["uniqueness_gate"] == "PASS"
assert "uniqueness_gate" not in cases[4]["failing_gates"]
assert cases[4]["identity_disposition"].startswith("omnibus_")
assert cases[5]["duplicate_mechanism_of"] == "GHSA-3J8Q-FWPJ-F8J5"
assert cases[5]["gates"]["uniqueness_gate"] == "FAIL"
assert cases[5]["uniqueness_gate"] == "FAIL"
assert "uniqueness_gate" in cases[5]["failing_gates"]
assert cases[5]["worker_verdict"] == "REJECT"
assert cases[4]["mechanism_fingerprint"] == cases[5]["mechanism_fingerprint"]
assert cases[4]["unique_countable_with_related"] is False
assert cases[5]["unique_countable_with_related"] is False
assert cases[3]["authorship_transfer_from_member_to_carrier"] is False

freeze = json.loads((owned / "work/freeze.json").read_text())
assert freeze["frozen_mechanism_rows"] == 5
assert freeze["frozen_ordinals"] == ordinals
assert freeze["declared_ghsa_identities"] == 6
assert freeze["did_not_pad"] is True
assert freeze["did_not_substitute"] is True
assert freeze["packet_delta"] == 0
assert freeze["canonical_strict_count"] == 84
assert freeze["excluded_because_already_canonical84"][0]["case_id"] == "GHSA-3WXW-XV34-2FRG"

uni = json.loads((owned / "work/uniqueness.json").read_text())
assert uni["assigned_mechanism_rows"] == 5
assert uni["declared_ghsa_identities"] == 6
assert uni["reviewed_identities"] == 6
assert uni["unique_countable_cases"] == 0
assert uni["packet_delta"] == 0
assert uni["pass_proposals"] == []
assert uni["canonical_strict_count"] == 84
assert uni["ord180_uniqueness_only_excluded"] is True
assert all(v is False for v in uni["assigned_in_counted"].values())
assert uni["never_count_two_ids_for_one_fingerprint"] is True
assert uni["jjcj_duplicate_mechanism_of"] == "GHSA-3J8Q-FWPJ-F8J5"
assert uni["jjcj_uniqueness_gate"] == "FAIL"
assert uni["jjcj_worker_verdict"] == "REJECT"

c84 = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json").read_text())
assert c84["canonical_strict_count"] == 84
ids = set(c84["strict_released_case_ids"])
for case_id in case_order:
    assert case_id not in ids
assert "GHSA-3WXW-XV34-2FRG" in ids
assert "GHSA-82QX-6VJ7-P8M2" not in ids
assert "GHSA-425G-FJHQ-5H92" in ids
assert "GHSA-HC8V-WWC9-VGXM" in ids

def is_404(obj):
    if obj.get("status") in {"404", 404}:
        return True
    err = str(obj.get("error") or obj.get("message") or "")
    return "404" in err or err == "Not Found"


pages = owned / "work/pages"
a4524 = json.loads((pages / "ghsa/GHSA-4524-X6PC-RR9X.json").read_text())
assert a4524["type"] == "unreviewed"
assert a4524["vulnerabilities"] == []
assert is_404(json.loads((pages / "repo-advisory/claude-hud__claude-hud__GHSA-4524-X6PC-RR9X.json").read_text()))
assert is_404(json.loads((pages / "repo-advisory/jarrodwatts__claude-hud__GHSA-4524-X6PC-RR9X.json").read_text()))
f7 = json.loads((pages / "repo-advisory/openclaw__openclaw__GHSA-F7FH-QG34-X2XH.json").read_text())
assert "json/version" in f7["summary"]
assert f7["state"] == "published" and f7["withdrawn_at"] is None
q2 = json.loads((pages / "repo-advisory/openclaw__openclaw__GHSA-2QRV-RC5X-2G2H.json").read_text())
assert "channel shadow" in q2["summary"].lower()
assert q2["state"] == "published" and q2["withdrawn_at"] is None
vg = json.loads((pages / "repo-advisory/anzory__SolidCAM-GPPL-IDE__GHSA-92VG-F4FQ-FXM9.json").read_text())
assert vg["state"] == "published" and vg["withdrawn_at"] is None
assert is_404(json.loads((pages / "ghsa/GHSA-92VG-F4FQ-FXM9.json").read_text()))
assert is_404(json.loads((pages / "releases/anzory_SolidCAM-GPPL-IDE_v1.0.0.json").read_text()))
j8 = json.loads((pages / "repo-advisory/ChurchCRM__CRM__GHSA-3J8Q-FWPJ-F8J5.json").read_text())
jj = json.loads((pages / "repo-advisory/ChurchCRM__CRM__GHSA-JJCJ-H3CM-P7X7.json").read_text())
assert j8["state"] == "published" and jj["state"] == "published"
assert j8["withdrawn_at"] is None and jj["withdrawn_at"] is None
overlap = set(i["value"] for i in j8["identifiers"]) & set(i["value"] for i in jj["identifiers"])
assert overlap == set()
assert is_404(json.loads((pages / "ghsa/GHSA-3J8Q-FWPJ-F8J5.json").read_text()))
r733 = json.loads((pages / "releases/ChurchCRM_CRM_7.3.3.json").read_text())
r740 = json.loads((pages / "releases/ChurchCRM_CRM_7.4.0.json").read_text())
assert r733["draft"] is False and r733["prerelease"] is False
assert r740["draft"] is False and r740["prerelease"] is False
assert r733["target_commitish"].startswith("da7ffe51")
assert r740["target_commitish"].startswith("66a731a1")
npm = json.loads((pages / "npm/openclaw.wanted.json").read_text())
assert npm["wanted"]["2026.3.8"]["gitHead"] == "3caab9260cb0a0064e6a37b2de3bedc8a547e599"

res = json.loads((owned / "result.json").read_text())
assert res["status"] == "TERMINAL"
assert res["terminal"] is True
assert res["terminal_status"] == "NARROW"
assert res["start_count"] == 84
assert res["current_leader_accepted_count"] == 84
assert res["packet_delta"] == 0
assert res["counts"]["PASS"] == 0
assert res["counts"]["NARROW"] == 5
assert res["counts"]["REJECT"] == 1
assert res["verdicts"]["NARROW"] == 5
assert res["verdicts"]["REJECT"] == 1
assert res["conservation"]["assigned_mechanism_rows"] == 5
assert res["conservation"]["declared_ghsa_identities"] == 6
assert res["conservation"]["reviewed_identities"] == 6
assert res["conservation"]["unique_countable_cases"] == 0
assert res["conservation"]["selected_jsonl_rows"] == 5
assert res["conservation"]["cases_jsonl_rows"] == 6
assert res["conservation"]["mechanism_equation"] == "5=5+0"
assert res["conservation"]["identity_equation"] == "6=6+0"
assert res["pass_proposals"] == []
assert res["worker_pass_is_proposal_only"] is True
assert res["canonical_count_updated"] is False
assert res["canonical_strict_count_untouched"] == 84
assert res["claim_boundary"]["publication_status"] == "HOLD"
assert res["claim_boundary"]["more_than_200_claim_supported_by_this_review"] is False
assert res["did_not_commit_or_push"] is True
assert res["per_case"]["GHSA-4524-X6PC-RR9X"] == "NARROW"
assert res["per_case"]["GHSA-F7FH-QG34-X2XH"] == "NARROW"
assert res["per_case"]["GHSA-92VG-F4FQ-FXM9"] == "NARROW"
assert res["per_case"]["GHSA-2QRV-RC5X-2G2H"] == "NARROW"
assert res["per_case"]["GHSA-3J8Q-FWPJ-F8J5"] == "NARROW"
assert res["per_case"]["GHSA-JJCJ-H3CM-P7X7"] == "REJECT"
assert res["ord200_disposition"] == "one_mechanism_two_nonalias_identities"

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
print("conservation assigned_mechanism_rows=5 declared_ghsa_identities=6 reviewed_identities=6 unique_countable_cases=0 PASS_proposal=0 NARROW=5 REJECT=1")
PY

printf 'REPLAY_OK assigned_mechanism_rows=5 declared_ghsa_identities=6 reviewed_identities=6 unique_countable_cases=0 PASS_proposal=0 NARROW=5 REJECT=1 packet_delta=0 canonical=84\n'
