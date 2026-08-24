#!/usr/bin/env zsh
# Fail-closed zsh replay for herdr-260814-ghsa200-fp211-unseen-twogate8-grok46-medium.
# English only. Do not print credentials or environment values.
# Do not clone, commit, push, or modify shared caches.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# PASS is a proposal only. This script does not admit any row.
# Canonical baseline is 84. Packet delta is 0. Terminal NARROW. Zero PASS. One UNKNOWN.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat
export PAGER=cat

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fp211-unseen-twogate8-grok46-medium
export TMPDIR=$OWNED/work
OC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/openclaw
CO=/home/hanqing/.cache/cve-analyzer/repos/conductor-oss_conductor
CM=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/claude-mem
OU=/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/ouroboros
GA=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/garminconnect
HE=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/hermes-webui

RQPP_M=079af0d0b02ca2c722f90b6c4e38e27ba16227b4
RQPP_F=5e389d5e7c9233ec91026ab2fea299ebaf3249f6
X5Q_M=840ec19c1f68f46b1c9c6a68e6bfa0d9481c3434
X5Q_C=d874e6e551a3354ade452ee5c9b99e3b453ee334
X5Q_F1=87a7d96aabbb706d6e84f812b93da5165028d18f
X5Q_F2=c691e35e768caeb802c9f06ecdd9674c80081af1
G5_M=01d568c9f54585d2df3002e1090067c9dd621e43
G5_C=483fba41b9f9fb57964f31b90a2ddacb185d54d7
G5_F=a30214a624946fc5c85c9558a27c1580172374fd
GV_M=924a11eeca832ddaafc200eb51cff5657354ba4a
GV_C=c6f932988a71e4eb0bf15108c91eec7d9eb64349
GV_F=f32fda8b35e9fe9329f87da65c31149362a03f97
C4_M=d30b61759b8efe4554978438abbcc5a9d698d055
C4_C=4aaf9147a6c6f76aecc775defcd1a542537cf01f
C4_F=4e70b760b4eb157469b58645339ba831f6513d37
WJ_M=21aea2d95b823a15c81a3efe87566de5dcc3befc
WJ_L=f74174a5647e1af78eca1f8f3a0aa5dc5a899947
WJ_F=77a3837f1f79d486663c9646438e70e8319e1a48
MG_M=d2b27f6f1edb83634730f93dc8f19721d877bd07
MG_C=2c7b530071bb29ae4184e83e33be5799d529568e
MG_F=8d8ae89d27a4547b2edc388a986ef0d55549f7d4
G3_M=b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517
G3_C=5c2cb6c591e4b63c2df0549ad2202403256e2a96
G3_F=7844bc89a1612800810617c823eb0c76ef945804

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
require_dir "$OC/.git"
require_dir "$CO/.git"
require_dir "$CM/.git"
require_dir "$OU/.git"
require_dir "$GA/.git"
require_dir "$HE/.git"
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
  739f3228a2ddd4fcc2156472e88a057540c07f9d431584348d257874d2e6b8b2
expect_hash "$OWNED/cases.jsonl" \
  5846d6765042818758fc8a390c80f2676448f0656a32bad4defdd01e6a621c87
expect_hash "$OWNED/report.md" \
  f446479ce7d610d7ef78e16266bd315b5c4eae99f8acce687ba6f0d18415098d
expect_hash "$OWNED/result.json" \
  9b234700caf53ba87d1220bcf79243015d08183532cc024a12df88a41ac08220
expect_hash "$OWNED/notes/README.md" \
  552eeaf712f7edc8e9eccae63390d50c4f25f514d584d9aa0ced026564d2fbc4
expect_hash "$OWNED/notes/freeze.txt" \
  7a43d53b8f666ccf1b6c3ce70043a93ded6dcb96f03342953c9274a01129f5df
expect_hash "$OWNED/notes/facts/README.md" \
  eae4ae249cc3ea146f256bd497ecfcc2eedce5ac45ab7f9dfcf825c0a2b04d9e
expect_hash "$OWNED/notes/diffs/README.md" \
  d7da75721e96a3f90292f77cb3d57b5ee28b494f2b206f24e855d9c00ec6d61b
expect_hash "$OWNED/notes/releases/README.md" \
  aae9fe74149093129b09f131ed9d8f095227b70e8a02dddfe57ff58759fcb0d1
expect_hash "$OWNED/work/freeze.json" \
  d0a9967f817bc0a1eeae2f04e4a8a815a5002b1d1befba105eeb71f48d221ee5
expect_hash "$OWNED/work/uniqueness.json" \
  419cda2b8f259d938e4642a16b788d1edaa0f3548ad47605670f819043af3bd0
expect_hash "$OWNED/notes/facts/GHSA-RQPP-RJJ8-7WV8.topology.json" \
  71b97252e9d70208d2051a0b62a9d8375eec89db55af825f533d68f7fd5b9b4f
expect_hash "$OWNED/notes/facts/GHSA-7X5Q-8F6H-RJRC.topology.json" \
  a8b34b165f9dd486bbbc6e80d2f34506e47dfeb8f9e70f7dc61b4840f80b04b0
expect_hash "$OWNED/notes/facts/GHSA-G5CG-8X5W-7JPM.topology.json" \
  130b3f6572570a12dc82061c3f98851bbff79248fdfd64c0703dc9da71d5c285
expect_hash "$OWNED/notes/facts/GHSA-5GVR-V6QV-H5MM.topology.json" \
  f1ef2f277dbca280dbef483e1ab0213611354a42cac301ad79b68e791dfc6fff
expect_hash "$OWNED/notes/facts/GHSA-C4M7-2GWP-VW76.topology.json" \
  94528a1bf6a5910630b37ce6a00b04534f2d4467bdec9ed461e2c20b7cc00e60
expect_hash "$OWNED/notes/facts/GHSA-WJHR-76VG-2HVC.topology.json" \
  6d52155c1c56b97745ee79723fc760fe19789a218eb38d4f94c6239d1acabf2c
expect_hash "$OWNED/notes/facts/GHSA-MGXW-V6RH-WCV6.topology.json" \
  cc11e38b0f15a2abd4018cc4168ec1dc2b16d219a485d57e02ca952415139d89
expect_hash "$OWNED/notes/facts/GHSA-G353-MGV3-8PCJ.topology.json" \
  4006cf578fa6cd67a8cc93a7e5d0ef7e6820b7b0594ef4e04732332cffeb3fe5
expect_hash "$OWNED/notes/facts/GHSA-MGXW-V6RH-WCV6.blobs.json" \
  7e1d73328764fc2fecd95eb89913cf90993e0d78da5ce2e1a688bc7510502430

rqpp_parents=$(g "$OC" rev-parse "${RQPP_M}^@")
print -r -- "$rqpp_parents" | /usr/bin/awk '{ if (NF != 1) { print "RQPP member not atomic" > "/dev/stderr"; exit 1 } }'
x5q_parents=$(g "$CO" rev-parse "${X5Q_M}^@")
print -r -- "$x5q_parents" | /usr/bin/awk '{ if (NF != 1) { print "7X5Q member not atomic" > "/dev/stderr"; exit 1 } }'
g5_parents=$(g "$OC" rev-parse "${G5_M}^@")
print -r -- "$g5_parents" | /usr/bin/awk '{ if (NF != 1) { print "G5CG member not atomic" > "/dev/stderr"; exit 1 } }'
gv_parents=$(g "$CM" rev-parse "${GV_M}^@")
print -r -- "$gv_parents" | /usr/bin/awk '{ if (NF != 1) { print "5GVR member not atomic" > "/dev/stderr"; exit 1 } }'
c4_parents=$(g "$OU" rev-parse "${C4_M}^@")
print -r -- "$c4_parents" | /usr/bin/awk '{ if (NF != 1) { print "C4M7 member not atomic" > "/dev/stderr"; exit 1 } }'
wj_parents=$(g "$GA" rev-parse "${WJ_M}^@")
print -r -- "$wj_parents" | /usr/bin/awk '{ if (NF != 1) { print "WJHR candidate not atomic" > "/dev/stderr"; exit 1 } }'
mg_parents=$(g "$HE" rev-parse "${MG_M}^@")
print -r -- "$mg_parents" | /usr/bin/awk '{ if (NF != 1) { print "MGXW member not atomic" > "/dev/stderr"; exit 1 } }'
g3_parents=$(g "$OC" rev-parse "${G3_M}^@")
print -r -- "$g3_parents" | /usr/bin/awk '{ if (NF != 1) { print "G353 member not atomic" > "/dev/stderr"; exit 1 } }'

assert_ancestor "$OC" "$RQPP_M" v2026.3.11
assert_not_ancestor "$OC" "$RQPP_F" v2026.3.11
assert_ancestor "$OC" "$RQPP_F" v2026.3.12

assert_ancestor "$CO" "$X5Q_M" v3.21.21
assert_ancestor "$CO" "$X5Q_C" v3.21.21
assert_not_ancestor "$CO" "$X5Q_F1" v3.21.21
assert_ancestor "$CO" "$X5Q_F1" v3.30.0
assert_not_ancestor "$CO" "$X5Q_F2" v3.30.1
assert_ancestor "$CO" "$X5Q_F2" v3.30.2

assert_not_ancestor "$OC" "$G5_M" v2026.3.28
assert_ancestor "$OC" "$G5_C" v2026.3.28
assert_not_ancestor "$OC" "$G5_F" v2026.3.28
assert_ancestor "$OC" "$G5_F" v2026.3.31

assert_not_ancestor "$CM" "$GV_M" v11.0.0
assert_ancestor "$CM" "$GV_C" v11.0.0
assert_not_ancestor "$CM" "$GV_F" v11.0.0
assert_ancestor "$CM" "$GV_F" v12.0.0

assert_not_ancestor "$OU" "$C4_M" "$C4_C"
assert_not_ancestor "$OU" "$C4_M" v0.38.2
assert_ancestor "$OU" "$C4_C" v0.38.2
assert_not_ancestor "$OU" "$C4_F" v0.38.2
assert_ancestor "$OU" "$C4_F" v0.39.0

assert_not_ancestor "$GA" "$WJ_M" 0.3.4
assert_not_ancestor "$GA" "$WJ_F" 0.3.5
assert_not_ancestor "$GA" "$WJ_L" 0.3.5

assert_ancestor "$HE" "$MG_M" v0.51.268
assert_not_ancestor "$HE" "$MG_F" v0.51.269
assert_ancestor "$HE" "$MG_C" v0.51.269

assert_not_ancestor "$OC" "$G3_M" "$G3_C"
assert_not_ancestor "$OC" "$G3_M" v2026.2.12
assert_ancestor "$OC" "$G3_C" v2026.2.12
assert_not_ancestor "$OC" "$G3_F" v2026.3.11
assert_ancestor "$OC" "$G3_F" v2026.3.12

python3 - "$OWNED" "$ROOT" "$OC" "$CO" "$CM" "$OU" "$GA" "$HE" << 'PY'
import json, os, re, subprocess, sys
from pathlib import Path

owned = Path(sys.argv[1])
root = Path(sys.argv[2])
oc, co, cm, ou, ga, he = sys.argv[3:9]
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
        git + ["-C", repo, *args],
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


RQPP_M = "079af0d0b02ca2c722f90b6c4e38e27ba16227b4"
X5Q_M = "840ec19c1f68f46b1c9c6a68e6bfa0d9481c3434"
X5Q_C = "d874e6e551a3354ade452ee5c9b99e3b453ee334"
G5_M = "01d568c9f54585d2df3002e1090067c9dd621e43"
G5_C = "483fba41b9f9fb57964f31b90a2ddacb185d54d7"
GV_F = "f32fda8b35e9fe9329f87da65c31149362a03f97"
C4_M = "d30b61759b8efe4554978438abbcc5a9d698d055"
C4_C = "4aaf9147a6c6f76aecc775defcd1a542537cf01f"
WJ_L = "f74174a5647e1af78eca1f8f3a0aa5dc5a899947"
WJ_F = "77a3837f1f79d486663c9646438e70e8319e1a48"
MG_M = "d2b27f6f1edb83634730f93dc8f19721d877bd07"
MG_C = "2c7b530071bb29ae4184e83e33be5799d529568e"
MG_F = "8d8ae89d27a4547b2edc388a986ef0d55549f7d4"
G3_M = "b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517"

assert marker(oc, RQPP_M, "noreply@anthropic.com")
mh = git_run(
    oc,
    "diff",
    "-U1",
    RQPP_M + "^",
    RQPP_M,
    "--",
    "src/gateway/server/ws-connection/message-handler.ts",
).stdout
assert "hasTokenAuth" in mh
assert blob(oc, G5_M, "src/infra/heartbeat-runner.ts") == blob(
    oc, G5_C, "src/infra/heartbeat-runner.ts"
)
assert blob(oc, G5_M, "src/infra/heartbeat-runner.ts") != blob(
    oc, "v2026.3.28", "src/infra/heartbeat-runner.ts"
)
assert blob(oc, "v2026.3.31", "src/infra/heartbeat-runner.ts") == blob(
    oc,
    "a30214a624946fc5c85c9558a27c1580172374fd",
    "src/infra/heartbeat-runner.ts",
)

pars = git_run(co, "rev-parse", X5Q_C + "^@").stdout.split()
assert len(pars) == 2
assert marker(co, X5Q_M, "claude")

gv_pars = git_run(cm, "rev-parse", GV_F + "^@").stdout.split()
assert len(gv_pars) == 2
store = git_run(
    cm,
    "diff",
    GV_F + "^1",
    GV_F,
    "--",
    "src/services/sqlite/observations/store.ts",
).stdout
assert "\\x00" in store
assert "slice(0, 16)" in store or "slice(0,16)" in store

assert blob(ou, C4_M, "src/ouroboros/providers/claude_code_adapter.py") != blob(
    ou, "v0.38.2", "src/ouroboros/providers/claude_code_adapter.py"
)
assert blob(ou, C4_C, "src/ouroboros/providers/claude_code_adapter.py") != blob(
    ou, C4_M, "src/ouroboros/providers/claude_code_adapter.py"
)
assert blob(ou, "v0.39.0", "src/ouroboros/providers/claude_code_adapter.py") == blob(
    ou,
    "4e70b760b4eb157469b58645339ba831f6513d37",
    "src/ouroboros/providers/claude_code_adapter.py",
)

wj_pars = git_run(ga, "rev-parse", WJ_L + "^@").stdout.split()
assert WJ_F in wj_pars
assert len(wj_pars) == 2
dump = git_run(
    ga,
    "diff",
    "21aea2d95b823a15c81a3efe87566de5dcc3befc^",
    "21aea2d95b823a15c81a3efe87566de5dcc3befc",
    "--",
    "garminconnect/client.py",
).stdout
assert "write_text" in dump and "def dump" in dump
fixd = git_run(ga, "diff", WJ_F + "^", WJ_F, "--", "garminconnect/client.py").stdout
assert "0o600" in fixd and "os.open" in fixd

assert blob(he, MG_M, "api/routes.py") == "b90c8e97f8565aafc6ba7e195d0ee0cb40dd75f7"
assert blob(he, "v0.51.268", "api/routes.py") == "fc3fab70de41c1ab76951d7879ed45589f0eb7d1"
assert blob(he, MG_F, "api/routes.py") == "d5c5be6ab34c2bb9c76baef09c81ac88be040ecd"
assert blob(he, MG_C, "api/routes.py") == "433317aeb3e3f87d9ca226cf48e14ca3b84a6fef"
assert blob(he, "v0.51.269", "api/routes.py") == "433317aeb3e3f87d9ca226cf48e14ca3b84a6fef"
assert marker(he, MG_M, "anthropic")
assert marker(oc, G3_M, "anthropic")

order = [
    "GHSA-RQPP-RJJ8-7WV8",
    "GHSA-7X5Q-8F6H-RJRC",
    "GHSA-G5CG-8X5W-7JPM",
    "GHSA-5GVR-V6QV-H5MM",
    "GHSA-C4M7-2GWP-VW76",
    "GHSA-WJHR-76VG-2HVC",
    "GHSA-MGXW-V6RH-WCV6",
    "GHSA-G353-MGV3-8PCJ",
]
ordinals = [80, 86, 95, 98, 100, 108, 115, 124]
sel = [json.loads(line) for line in (owned / "selected.jsonl").read_text().splitlines() if line.strip()]
cases = [json.loads(line) for line in (owned / "cases.jsonl").read_text().splitlines() if line.strip()]
assert [row["case_id"] for row in sel] == order
assert [row["ordinal"] for row in sel] == ordinals
assert [row["case_id"] for row in cases] == order
assert [row["ordinal"] for row in cases] == ordinals
assert len(sel) == 8 and len(cases) == 8
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
assert cases[5]["worker_verdict"] == "UNKNOWN"
assert cases[5]["gates"]["release_gate"] == "UNKNOWN"
assert cases[7]["gates"]["identity_gate"] == "PASS"
assert cases[7]["public_ids_remove"] == ["CVE-2026-44109", "GHSA-XH72-V6V9-MWHC"]
assert all(row["padding"] is False for row in sel)
assert all(row["substitution"] is False for row in sel)

freeze = json.loads((owned / "work/freeze.json").read_text())
assert freeze["frozen_ids"] == order
assert freeze["frozen_ordinals"] == ordinals
assert freeze["frozen_n"] == 8
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
assert res["counts"]["NARROW"] == 7
assert res["counts"]["UNKNOWN"] == 1
assert res["counts"]["assigned"] == 8
assert res["counts"]["reviewed"] == 8
assert res["counts"]["unreviewed"] == 0
assert res["conservation"]["equation"] == "8=8+0"
assert res["pass_proposals"] == []
assert res["exact_selected_ids"] == order
assert res["worker_pass_is_proposal_only"] is True
assert res["canonical_count_updated"] is False
assert res["claim_boundary"]["publication_status"] == "HOLD"
assert res["claim_boundary"]["more_than_200_claim_supported_by_this_review"] is False
assert res["did_not_commit_or_push"] is True
assert res["per_case"]["GHSA-WJHR-76VG-2HVC"] == "UNKNOWN"
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
print("conservation assigned=8 reviewed=8 unreviewed=0 PASS_proposal=0 NARROW=7 UNKNOWN=1")
PY

printf 'REPLAY_OK reviewed=8 PASS_proposal=0 NARROW=7 UNKNOWN=1 packet_delta=0 start=84 current=84\n'
