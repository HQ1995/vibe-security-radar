#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260813-ghsa200-nearclosed-upgrades-grok46-high.
# English only. Do not print credentials. Do not fetch, clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Worker PASS is a proposal. This script admits zero PASS and does not admit a 200-case claim.
# Packet status TERMINAL. Expansion stopped. No further candidates.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260813-ghsa200-nearclosed-upgrades-grok46-high
TY=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/taylored
IC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/ironclaw
GC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/garminconnect
ZC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/zeptoclaw
LR=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/langroid
CR=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/churchcrm
OC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/openclaw
GP=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/gitpython

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

require_dir() {
  if [[ ! -d $1 ]]; then
    printf 'missing directory: %s\n' "$1" >&2
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

assert_ancestor() {
  "${git_cmd[@]}" -C "$1" merge-base --is-ancestor "$2" "$3"
}

assert_not_ancestor() {
  if "${git_cmd[@]}" -C "$1" merge-base --is-ancestor "$2" "$3"; then
    printf 'unexpected ancestor: %s is ancestor of %s in %s\n' "$2" "$3" "$1" >&2
    exit 1
  fi
}

assert_blob_is() {
  local repo=$1 spec=$2 expected=$3
  local got
  got=$("${git_cmd[@]}" -C "$repo" rev-parse "$spec")
  if [[ $got != "$expected" ]]; then
    printf 'blob %s expected %s got %s\n' "$spec" "$expected" "$got" >&2
    exit 1
  fi
}

assert_blob_ne() {
  local repo=$1 left=$2 right=$3
  local a b
  a=$("${git_cmd[@]}" -C "$repo" rev-parse "$left")
  b=$("${git_cmd[@]}" -C "$repo" rev-parse "$right")
  if [[ $a == "$b" ]]; then
    printf 'blobs unexpectedly equal: %s == %s (%s)\n' "$left" "$right" "$a" >&2
    exit 1
  fi
}

require_dir "$OWNED"
require_dir "$TY"
require_dir "$IC"
require_dir "$GC"
require_dir "$ZC"
require_dir "$LR"
require_dir "$CR"
require_dir "$OC"
require_dir "$GP"

# Frozen conservation inputs. current must equal frozen.
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/baseline.json" \
  d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl" \
  1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-final-candidate-review-codex/cases.jsonl" \
  e275437954890dca07855b5fcfa545f8f1a366fb85a7ee9f067da5b710b2b3da
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-final-candidate-review-codex/result.json" \
  4be2620a548370c845e22c0d7cbe3ed10ab156ef39b1a0432ff4220ff406e528

# Current exclusion-set pins (terminal packets). current must equal frozen-at-this-worker.
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh/result.json" \
  c50b878583f3b09f37d7c88638ea179e75cf6b0ccf2e4ade689f2d673f7b0829
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-actual-gogs-redteam-grok46-high/result.json" \
  bf3676928fb61809f425e0b369b010d79018a890852e8d6310d13912a6d83b9d
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh/result.json" \
  78a101f809e7d65269db834e60211d87404d2faa48b8e3bf6a46693fa7dfd644

python3 - "$ROOT" "$OWNED" << 'PY'
import hashlib, json, sys
from pathlib import Path
root = Path(sys.argv[1])
owned = Path(sys.argv[2])
res = json.loads((owned / "result.json").read_text())
assert res["status"] == "TERMINAL"
assert res["terminal"] is True
assert res["expansion_stopped"] is True
assert res["causal_admission"] is False
assert res["publication_status"] == "HOLD"
assert res["worker_pass_is_proposal_only"] is True
assert res["english_only"] is True
assert res["pass_proposals"] == []
assert res["verdicts"]["PASS"] == 0
assert res["verdicts"]["NARROW"] == 10
assert res["verdicts"]["UNKNOWN"] == 2
assert res["conservation"]["assigned"] == 12
assert res["conservation"]["reviewed"] == 12
assert res["conservation"]["unreviewed"] == 0
assert res["conservation"]["assigned"] == res["conservation"]["reviewed"] + res["conservation"]["unreviewed"]
cases_path = owned / "cases.jsonl"
got = hashlib.sha256(cases_path.read_bytes()).hexdigest()
assert got == res["artifacts"]["cases.jsonl_sha256"], got
report_got = hashlib.sha256((owned / "report.md").read_bytes()).hexdigest()
assert report_got == res["artifacts"]["report.md_sha256"], report_got
replay_got = hashlib.sha256((owned / "replay.sh").read_bytes()).hexdigest()
assert replay_got == res["artifacts"]["replay.sh_sha256"], replay_got
rows = [json.loads(l) for l in cases_path.read_text().splitlines() if l.strip()]
assert len(rows) == 12
assert len({r["case_id"] for r in rows}) == 12
assert [r["ordinal"] for r in rows] == sorted(r["ordinal"] for r in rows)
gates = ["identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate", "uniqueness_gate"]
pass_n = narrow_n = unknown_n = 0
for r in rows:
    assert r["language"] == "en"
    assert r["causal_admission"] is False
    assert r["authorship_transfer_from_member_to_carrier"] is False
    assert r["cve_aliases_are_not_counting_units"] is True
    seven = all(r.get(g) == "PASS" for g in gates)
    fg = r.get("failing_gates") or []
    if r["verdict"] == "PASS":
        raise SystemExit("unexpected PASS " + r["case_id"])
    assert not seven, r["case_id"]
    assert fg, r["case_id"]
    if r["verdict"] == "NARROW":
        narrow_n += 1
    elif r["verdict"] == "UNKNOWN":
        unknown_n += 1
    else:
        raise SystemExit("unexpected verdict " + r["verdict"])
assert pass_n == 0
assert narrow_n == 10
assert unknown_n == 2
excl = set(res["excluded"]["frozen_48"]) | set(res["excluded"]["netred_21_keep"]) | set(res["excluded"]["actual_gogs_keep"]) | set(res["excluded"]["pending_b3_three"])
ids = [r["case_id"] for r in rows]
assert not (set(ids) & excl), set(ids) & excl
assert res["excluded"]["actual_gogs_keep"] == ["GHSA-6P9M-Q3JP-47H4", "GHSA-7GH7-258J-4MPQ"]
assert res["excluded"]["pending_b3_three"] == ["GHSA-F38V-77QJ-H4JQ", "GHSA-G3XQ-3GMV-QQ8G", "GHSA-PV2J-RGHR-V5R9"]
print("conservation assigned=12 reviewed=12 unreviewed=0 PASS=0 NARROW=10 UNKNOWN=2")
PY

# ----- UNKNOWN 56 / 84 taylored: only 8.2.4 tarball; that tag already contains origin and fix -----
"${git_cmd[@]}" -C "$TY" log -1 --format='%an' c139c021f68a09d22c2af88641b61c00f67f2af4 | /usr/bin/grep -F 'google-labs-jules' >/dev/null
assert_ancestor "$TY" c139c021f68a09d22c2af88641b61c00f67f2af4 8.2.4
assert_ancestor "$TY" 57b7634391959dbbdb39b387ac4dc68157cd58a1 8.2.4
assert_ancestor "$TY" fdf67a6fba0deae30912905a79fb5a9e83751a79 8.2.4
python3 - "$OWNED" << 'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
d = json.loads((owned / "snapshot/pages/npm/npm-taylored.json").read_text())
assert list(d["versions"].keys()) == ["8.2.4"]
for ver in ("7.0.5", "7.0.7", "7.0.8", "8.1.2", "8.1.3"):
    assert ver not in d["versions"]
    assert ver in d["time"]
print("56/84 npm time keys without tarballs ok")
PY

# ----- NARROW 107 ironclaw: member not tag ancestor; three-way blob mismatch -----
"${git_cmd[@]}" -C "$IC" log -1 --format='%B' b20880c12837df41d7f49de6a33ebe4562b27c5b | /usr/bin/grep -F 'Co-Authored-By: Claude Sonnet 4.6' >/dev/null
assert_not_ancestor "$IC" b20880c12837df41d7f49de6a33ebe4562b27c5b ironclaw-v0.29.1
assert_ancestor "$IC" b58b421535e593b165393846a4c37d74283060ad ironclaw-v0.29.1
assert_ancestor "$IC" a1d7c3ba428ed575900469b207fb5668725f9a71 ironclaw-v1.0.0
assert_blob_is "$IC" b20880c12837df41d7f49de6a33ebe4562b27c5b:src/tools/builtin/shell.rs 4798d0c3c1a9a5c59c30cd878e9fb85564cddacf
assert_blob_is "$IC" b58b421535e593b165393846a4c37d74283060ad:src/tools/builtin/shell.rs fa92cb372320d5e75ee41408d8f29695392873fc
assert_blob_is "$IC" ironclaw-v0.29.1:src/tools/builtin/shell.rs 8f574e900eecc8aa344fe8989641689b4cbfe659
assert_blob_ne "$IC" b20880c12837df41d7f49de6a33ebe4562b27c5b:src/tools/builtin/shell.rs b58b421535e593b165393846a4c37d74283060ad:src/tools/builtin/shell.rs
assert_blob_ne "$IC" b58b421535e593b165393846a4c37d74283060ad:src/tools/builtin/shell.rs ironclaw-v0.29.1:src/tools/builtin/shell.rs
python3 - "$OWNED" << 'PY'
import json, sys
from pathlib import Path
d = json.loads((Path(sys.argv[1]) / "snapshot/pages/ghsa/ghsa-cw23-qwr7-c655.json").read_text())
assert d.get("type") == "unreviewed"
assert d.get("vulnerabilities") == []
assert d.get("github_reviewed_at") is None
print("107 unreviewed empty-vulns identity ok")
PY

# ----- NARROW 108 garmin: AI origin not tag ancestor; human blob is -----
"${git_cmd[@]}" -C "$GC" log -1 --format='%B' 21aea2d95b823a15c81a3efe87566de5dcc3befc | /usr/bin/grep -F 'Co-Authored-By: Claude Opus 4.6' >/dev/null
assert_not_ancestor "$GC" 21aea2d95b823a15c81a3efe87566de5dcc3befc 0.3.4
assert_not_ancestor "$GC" 21aea2d95b823a15c81a3efe87566de5dcc3befc 0.3.5
assert_ancestor "$GC" e36613f3 0.3.4
assert_not_ancestor "$GC" 77a3837f1f79d486663c9646438e70e8319e1a48 0.3.5
assert_blob_is "$GC" 21aea2d95b823a15c81a3efe87566de5dcc3befc:garminconnect/client.py e612db67d43f94161d39de27b23f501749d6839b
assert_blob_is "$GC" e36613f3:garminconnect/client.py e612db67d43f94161d39de27b23f501749d6839b
assert_blob_is "$GC" 0.3.4:garminconnect/client.py 4f1a9c88c804c3b41c64a976edcc43e9efc1153a
assert_blob_is "$GC" 0.3.5:garminconnect/client.py ddda26b27d5079bec3e3c0cf83da0c85d7177902
assert_blob_is "$GC" 77a3837f1f79d486663c9646438e70e8319e1a48:garminconnect/client.py ddda26b27d5079bec3e3c0cf83da0c85d7177902
assert_blob_ne "$GC" 21aea2d95b823a15c81a3efe87566de5dcc3befc:garminconnect/client.py 0.3.4:garminconnect/client.py
if "${git_cmd[@]}" -C "$GC" log -1 --format='%B' e36613f3 | /usr/bin/grep -E -i 'co-authored-by:|generated with'; then
  printf 'human e36613f3 unexpectedly has an AI trailer\n' >&2
  exit 1
fi

# ----- NARROW 124 G353: member not ancestor; three-way channel.ts mismatch -----
"${git_cmd[@]}" -C "$OC" log -1 --format='%B' b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517 | /usr/bin/grep -F 'Co-Authored-By: Claude Opus 4.6' >/dev/null
assert_not_ancestor "$OC" b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517 v2026.3.11
assert_ancestor "$OC" 5c2cb6c591e4b63c2df0549ad2202403256e2a96 v2026.3.11
assert_ancestor "$OC" 7844bc89a1612800810617c823eb0c76ef945804 v2026.3.12
assert_blob_is "$OC" b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517:extensions/feishu/src/channel.ts eaa48cd0efed8ec07d6e98e0b2f1a4077ba3b743
assert_blob_is "$OC" 5c2cb6c591e4b63c2df0549ad2202403256e2a96:extensions/feishu/src/channel.ts d4c8e10201620855317c1f9aca7fc20d0e6694c6
assert_blob_is "$OC" v2026.3.11:extensions/feishu/src/channel.ts 7c90136e70f419522016679ab16a3f8eb636e95e
assert_blob_ne "$OC" b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517:extensions/feishu/src/channel.ts 5c2cb6c591e4b63c2df0549ad2202403256e2a96:extensions/feishu/src/channel.ts
assert_blob_ne "$OC" 5c2cb6c591e4b63c2df0549ad2202403256e2a96:extensions/feishu/src/channel.ts v2026.3.11:extensions/feishu/src/channel.ts
"${git_cmd[@]}" -C "$OC" grep -F 'verificationToken' '5c2cb6c591e4b63c2df0549ad2202403256e2a96^' -- extensions/feishu/src/config-schema.ts >/dev/null

# ----- NARROW 126 zeptoclaw: allowlist member not ancestor; squash blob != tag -----
assert_not_ancestor "$ZC" 3c4368da0ab48c1091858d3f9503c378a209997f v0.6.1
assert_ancestor "$ZC" 1712debbea60af6adf4a8a5939a43f7ef9a1ac16 v0.6.1
assert_ancestor "$ZC" 68916c3e4f3af107f11940b27854fc7ef517058b v0.6.2
assert_blob_ne "$ZC" 1712debbea60af6adf4a8a5939a43f7ef9a1ac16:src/security/shell.rs v0.6.1:src/security/shell.rs
assert_blob_is "$ZC" 68916c3e4f3af107f11940b27854fc7ef517058b:src/security/shell.rs d923a585eb91f1cd6fb2c9e16874f64f14cab5b6
assert_blob_is "$ZC" v0.6.2:src/security/shell.rs d923a585eb91f1cd6fb2c9e16874f64f14cab5b6
if "${git_cmd[@]}" -C "$ZC" grep -F 'allowlist.is_empty' '1712debbea60af6adf4a8a5939a43f7ef9a1ac16^' -- src/security/shell.rs >/dev/null; then
  printf 'parent of squash unexpectedly has allowlist.is_empty\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$ZC" grep -F 'allowlist.is_empty' 1712debbea60af6adf4a8a5939a43f7ef9a1ac16 -- src/security/shell.rs >/dev/null

# ----- NARROW 156 langroid: member not ancestor; mixed squash; released table_chat equals fix -----
assert_not_ancestor "$LR" b1c45e3fc0f3578a5dea9844c0216044321ae1c8 0.59.31
assert_ancestor "$LR" 0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6 0.59.31
assert_ancestor "$LR" 30abbc1a854dee22fbd2f8b2f575dfdabdb603ea 0.59.32
assert_blob_ne "$LR" b1c45e3fc0f3578a5dea9844c0216044321ae1c8:langroid/agent/special/table_chat_agent.py 0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6:langroid/agent/special/table_chat_agent.py
assert_blob_is "$LR" 0.59.31:langroid/agent/special/table_chat_agent.py 28c3c288b1198f8b7b539c7fc11bbbeb4a7be79f
assert_blob_is "$LR" 30abbc1a854dee22fbd2f8b2f575dfdabdb603ea:langroid/agent/special/table_chat_agent.py 28c3c288b1198f8b7b539c7fc11bbbeb4a7be79f
"${git_cmd[@]}" -C "$LR" log -1 --format='%B' 0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6 | /usr/bin/grep -F 'Co-authored-by: Copilot' >/dev/null
"${git_cmd[@]}" -C "$LR" log -1 --format='%B' 0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6 | /usr/bin/grep -F 'Co-Authored-By: Claude' >/dev/null

# ----- NARROW 170 GitPython: candidate is ancestor of 3.1.50; do not promote -----
assert_ancestor "$GP" c9a26789d88b18f8b4620f37307df2976292d2a0 3.1.50
assert_not_ancestor "$GP" 56806080c1348749b07daa4a2024ce47b3cad285 3.1.50
assert_ancestor "$GP" 56806080c1348749b07daa4a2024ce47b3cad285 3.1.51
"${git_cmd[@]}" -C "$GP" grep -F 'startswith' c9a26789d88b18f8b4620f37307df2976292d2a0 -- git/cmd.py >/dev/null

# ----- NARROW 186 ChurchCRM: member not ancestor; unmarked carrier is -----
assert_not_ancestor "$CR" cbea916e77e2d8cbe34f04efdd00792e3af27e2c 7.5.1
assert_ancestor "$CR" 1bfc187ac41238a2488d58f06361d7377d3cdf11 7.5.1
assert_ancestor "$CR" 07be35d7fdaae872f2f6ff404779368f201fe8b5 7.6.0
assert_not_ancestor "$CR" 32599b3d5975f95a5dfa09847855bfdd085b07fb 7.6.0
if "${git_cmd[@]}" -C "$CR" log -1 --format='%B' 1bfc187ac41238a2488d58f06361d7377d3cdf11 | /usr/bin/grep -E -i 'co-authored-by:|generated with'; then
  printf 'carrier 1bfc187a unexpectedly has an AI trailer\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$CR" log -1 --format='%B' cbea916e77e2d8cbe34f04efdd00792e3af27e2c | /usr/bin/grep -F 'Co-Authored-By: Claude Haiku 4.5' >/dev/null

# ----- NARROW 192 / 195 / 197 openclaw: ancestry only; do not promote -----
assert_ancestor "$OC" b75ad800a59009fc47eaa3471410f69046150e59 v2026.5.22
assert_not_ancestor "$OC" 06047005ef7dedda5ea655f52117e8aaa1cca373 v2026.5.22
assert_ancestor "$OC" 06047005ef7dedda5ea655f52117e8aaa1cca373 v2026.5.26
assert_ancestor "$OC" 47eb2d48d43452afc4b0160e40a2630e4a38a0ff v2026.6.1
assert_ancestor "$OC" 3c6259ebb70c76523a7b3fb7cfdac2e40a7f7449 v2026.6.5
assert_ancestor "$OC" 6c918ca85fc6256a309ca0a737d7729059b34e1e v2026.6.1
assert_ancestor "$OC" 797bcd5bdb28cd8bab4f5385f4515467e42bfcfd v2026.6.5

printf 'REPLAY_OK bounded assigned=12 reviewed=12 unreviewed=0 PASS_proposal=0 NARROW=10 UNKNOWN=2\n'
