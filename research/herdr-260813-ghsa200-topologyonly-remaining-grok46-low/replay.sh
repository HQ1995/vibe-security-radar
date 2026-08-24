#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260813-ghsa200-topologyonly-remaining-grok46-low.
# English only. Do not print credentials. Do not fetch, clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Worker PASS is a proposal. This script admits zero PASS and does not admit a 200-case claim.
# Packet status TERMINAL. Expansion stopped. No further candidates.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260813-ghsa200-topologyonly-remaining-grok46-low
OC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/openclaw
LR=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/langroid

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
require_dir "$OC"
require_dir "$LR"

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
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-canonical72-dedupe-grok46-medium/result.json" \
  fb3b97c7b5d207119cc22d255ba48cbda568d56c8fffb447fb0e58ac8878f4fb
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-final-candidate-review-codex/result.json" \
  4be2620a548370c845e22c0d7cbe3ed10ab156ef39b1a0432ff4220ff406e528
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh/result.json" \
  c50b878583f3b09f37d7c88638ea179e75cf6b0ccf2e4ade689f2d673f7b0829
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-nearclosed-upgrades-grok46-high/result.json" \
  32067537d773147e4b0dd700780e4f448e3e7e0602464c95bbcff813b27229ce
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-medium5-redteam-grok46-low/result.json" \
  254c7c509a4af7ec3099c890b73b46904b97ef6ab60d7ec9ff799455b505d96b
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh/result.json" \
  78a101f809e7d65269db834e60211d87404d2faa48b8e3bf6a46693fa7dfd644
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-actual-gogs-redteam-grok46-high/result.json" \
  bf3676928fb61809f425e0b369b010d79018a890852e8d6310d13912a6d83b9d
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-q855-redteam-grok46-medium/cases.jsonl" \
  fa6d7dca9993999a9946f54e395138c6cc6dbbc7b03e79abb1efe108ee526856

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
assert res["verdicts"]["NARROW"] == 3
assert res["conservation"]["assigned"] == 3
assert res["conservation"]["reviewed"] == 3
assert res["conservation"]["unreviewed"] == 0
assert res["conservation"]["assigned"] == res["conservation"]["reviewed"] + res["conservation"]["unreviewed"]
assert res["selection"]["source_pool_ordinals"] == [1, 92, 93, 107, 113, 126, 156]
assert res["conservation"]["pool_equation_holds"] is True
cases_path = owned / "cases.jsonl"
got = hashlib.sha256(cases_path.read_bytes()).hexdigest()
assert got == res["artifacts"]["cases.jsonl_sha256"], got
report_got = hashlib.sha256((owned / "report.md").read_bytes()).hexdigest()
assert report_got == res["artifacts"]["report.md_sha256"], report_got
replay_got = hashlib.sha256((owned / "replay.sh").read_bytes()).hexdigest()
assert replay_got == res["artifacts"]["replay.sh_sha256"], replay_got
rows = [json.loads(l) for l in cases_path.read_text().splitlines() if l.strip()]
assert len(rows) == 3
assert [r["ordinal"] for r in rows] == [92, 93, 156]
assert [r["case_id"] for r in rows] == [
    "GHSA-WV46-V6XC-2QHF",
    "GHSA-RG8M-3943-VM6Q",
    "GHSA-X34R-63HX-W57F",
]
gates = ["identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate", "uniqueness_gate"]
for r in rows:
    assert r["language"] == "en"
    assert r["causal_admission"] is False
    assert r["authorship_transfer_from_member_to_carrier"] is False
    assert r["cve_aliases_are_not_counting_units"] is True
    assert r["verdict"] == "NARROW"
    assert r["failing_gates"] == ["topology_gate"]
    assert r["topology_gate"] == "NARROW"
    assert all(r[g] == "PASS" for g in gates if g != "topology_gate")
    assert not all(r.get(g) == "PASS" for g in gates)
assert "GHSA-Q855-8RH5-JFGQ" not in {r["case_id"] for r in rows}
assert res["excluded"]["recovered_covered"] == [
    "GHSA-FMFG-9G7C-3VQ7",
    "GHSA-G3XQ-3GMV-QQ8G",
]
assert res["excluded"]["nearclosed_107_126"] == [
    "GHSA-CW23-QWR7-C655",
    "GHSA-5WP8-Q9MX-8JX8",
]
print("conservation assigned=3 reviewed=3 unreviewed=0 PASS=0 NARROW=3")
PY

# ----- NARROW 92 openclaw synology member not tag ancestor; blob mismatch -----
"${git_cmd[@]}" -C "$OC" cat-file -t ce12b9092f03d85603f0b6b8193d512260a65dab >/dev/null
"${git_cmd[@]}" -C "$OC" log -1 --format='%B' ce12b9092f03d85603f0b6b8193d512260a65dab | /usr/bin/grep -F 'Co-Authored-By: Claude Opus 4.6' >/dev/null
"${git_cmd[@]}" -C "$OC" log -1 --format='%B' 9a3800d8e6e69bc0a125dca5760d47515e746454 | /usr/bin/grep -F 'Co-Authored-By: Claude Opus 4.6' >/dev/null
pc=$("${git_cmd[@]}" -C "$OC" rev-list --parents -n1 ce12b9092f03d85603f0b6b8193d512260a65dab | /usr/bin/awk '{print NF-1}')
if [[ $pc != 1 ]]; then
  printf 'ce12b909 parent_count expected 1 got %s\n' "$pc" >&2
  exit 1
fi
assert_not_ancestor "$OC" ce12b9092f03d85603f0b6b8193d512260a65dab 9a3800d8e6e69bc0a125dca5760d47515e746454
assert_not_ancestor "$OC" ce12b9092f03d85603f0b6b8193d512260a65dab v2026.3.2
assert_ancestor "$OC" 9a3800d8e6e69bc0a125dca5760d47515e746454 v2026.3.2
assert_not_ancestor "$OC" 7ade3553b74ee3f461c4acd216653d5ba411f455 v2026.3.2
assert_ancestor "$OC" 7ade3553b74ee3f461c4acd216653d5ba411f455 v2026.3.22
assert_blob_is "$OC" ce12b9092f03d85603f0b6b8193d512260a65dab:extensions/synology-chat/src/client.ts db04677dc1a620bbb159eba8ffcf2c54b9b1834f
assert_blob_is "$OC" 9a3800d8e6e69bc0a125dca5760d47515e746454:extensions/synology-chat/src/client.ts 95240e556f5be49e8763dcf0e276a1576dd71393
assert_blob_is "$OC" v2026.3.2:extensions/synology-chat/src/client.ts 95240e556f5be49e8763dcf0e276a1576dd71393
assert_blob_ne "$OC" ce12b9092f03d85603f0b6b8193d512260a65dab:extensions/synology-chat/src/client.ts 9a3800d8e6e69bc0a125dca5760d47515e746454:extensions/synology-chat/src/client.ts
assert_blob_is "$OC" ce12b9092f03d85603f0b6b8193d512260a65dab:extensions/synology-chat/src/channel.ts 61fbc7450b5196d70fbfdb9ee33a807118b02c7f
assert_blob_is "$OC" 9a3800d8e6e69bc0a125dca5760d47515e746454:extensions/synology-chat/src/channel.ts 61fbc7450b5196d70fbfdb9ee33a807118b02c7f
assert_blob_is "$OC" v2026.3.2:extensions/synology-chat/src/channel.ts 142f39d7f4563334a97790cd04d92fb930570e22
assert_blob_ne "$OC" ce12b9092f03d85603f0b6b8193d512260a65dab:extensions/synology-chat/src/channel.ts v2026.3.2:extensions/synology-chat/src/channel.ts
if "${git_cmd[@]}" -C "$OC" grep -q resolveChatUserId ce12b9092f03d85603f0b6b8193d512260a65dab^ -- extensions/synology-chat/src/client.ts; then
  printf 'parent unexpectedly has resolveChatUserId\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$OC" grep -F resolveChatUserId ce12b9092f03d85603f0b6b8193d512260a65dab -- extensions/synology-chat/src/client.ts >/dev/null

# ----- NARROW 93 openclaw matrix three-way handler blob mismatch -----
"${git_cmd[@]}" -C "$OC" cat-file -t fbfe2f15fc316904972711b3391031d6c99682b4 >/dev/null
"${git_cmd[@]}" -C "$OC" log -1 --format='%B' fbfe2f15fc316904972711b3391031d6c99682b4 | /usr/bin/grep -F 'Co-Authored-By: Claude Opus 4.5' >/dev/null
"${git_cmd[@]}" -C "$OC" log -1 --format='%B' 49c60e9065d98a6848e62c717315eb91eeaa6038 | /usr/bin/grep -F 'Co-authored-by: Claude Opus 4.5' >/dev/null
assert_not_ancestor "$OC" fbfe2f15fc316904972711b3391031d6c99682b4 49c60e9065d98a6848e62c717315eb91eeaa6038
assert_not_ancestor "$OC" fbfe2f15fc316904972711b3391031d6c99682b4 v2026.2.12
assert_ancestor "$OC" 49c60e9065d98a6848e62c717315eb91eeaa6038 v2026.2.12
assert_not_ancestor "$OC" 8a563d603b70ef6338915f0527bee87282c3bad5 v2026.2.12
assert_not_ancestor "$OC" 8a563d603b70ef6338915f0527bee87282c3bad5 v2026.3.28
assert_ancestor "$OC" 8a563d603b70ef6338915f0527bee87282c3bad5 v2026.3.31
H=extensions/matrix/src/matrix/monitor/handler.ts
assert_blob_is "$OC" fbfe2f15fc316904972711b3391031d6c99682b4:$H 018f4dc093133e883844048f1e1d847f96fee3b1
assert_blob_is "$OC" 49c60e9065d98a6848e62c717315eb91eeaa6038:$H eef2bed43ff81d8e22702e768169c36b48edbe9d
assert_blob_is "$OC" v2026.2.12:$H c63ea3eee4ada8469153df18794510019332f413
assert_blob_is "$OC" 8a563d603b70ef6338915f0527bee87282c3bad5:$H 5e2ec946137fe0cdcb8cc1e5a6840d099f8e7869
assert_blob_is "$OC" v2026.3.31:$H 5e2ec946137fe0cdcb8cc1e5a6840d099f8e7869
assert_blob_ne "$OC" fbfe2f15fc316904972711b3391031d6c99682b4:$H 49c60e9065d98a6848e62c717315eb91eeaa6038:$H
assert_blob_ne "$OC" 49c60e9065d98a6848e62c717315eb91eeaa6038:$H v2026.2.12:$H
assert_blob_ne "$OC" fbfe2f15fc316904972711b3391031d6c99682b4:$H v2026.2.12:$H
if "${git_cmd[@]}" -C "$OC" grep -q ThreadStarterBody fbfe2f15fc316904972711b3391031d6c99682b4^ -- "$H"; then
  printf 'parent unexpectedly has ThreadStarterBody\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$OC" grep -F ThreadStarterBody fbfe2f15fc316904972711b3391031d6c99682b4 -- "$H" >/dev/null

# ----- NARROW 156 langroid mixed squash; member not tag ancestor -----
"${git_cmd[@]}" -C "$LR" log -1 --format='%B' b1c45e3fc0f3578a5dea9844c0216044321ae1c8 | /usr/bin/grep -F 'Co-authored-by: Copilot' >/dev/null
"${git_cmd[@]}" -C "$LR" log -1 --format='%B' 0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6 | /usr/bin/grep -F 'Co-authored-by: Copilot' >/dev/null
"${git_cmd[@]}" -C "$LR" log -1 --format='%B' 0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6 | /usr/bin/grep -F 'Co-Authored-By: Claude' >/dev/null
assert_not_ancestor "$LR" b1c45e3fc0f3578a5dea9844c0216044321ae1c8 0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6
assert_not_ancestor "$LR" b1c45e3fc0f3578a5dea9844c0216044321ae1c8 0.59.31
assert_ancestor "$LR" 0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6 0.59.31
assert_not_ancestor "$LR" 30abbc1a854dee22fbd2f8b2f575dfdabdb603ea 0.59.31
assert_ancestor "$LR" 30abbc1a854dee22fbd2f8b2f575dfdabdb603ea 0.59.32
T=langroid/agent/special/table_chat_agent.py
assert_blob_is "$LR" b1c45e3fc0f3578a5dea9844c0216044321ae1c8:$T ba8bc96c26093765086ccaef31f48c24b9101db0
assert_blob_is "$LR" 0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6:$T c7b320658aaa0cbb6d9bae916485780f3ae7ff31
assert_blob_is "$LR" 0.59.31:$T 28c3c288b1198f8b7b539c7fc11bbbeb4a7be79f
assert_blob_is "$LR" 0.59.32:$T 28c3c288b1198f8b7b539c7fc11bbbeb4a7be79f
assert_blob_is "$LR" 30abbc1a854dee22fbd2f8b2f575dfdabdb603ea:$T 28c3c288b1198f8b7b539c7fc11bbbeb4a7be79f
assert_blob_ne "$LR" b1c45e3fc0f3578a5dea9844c0216044321ae1c8:$T 0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6:$T
assert_blob_ne "$LR" b1c45e3fc0f3578a5dea9844c0216044321ae1c8:$T 0.59.31:$T
P=langroid/utils/pandas_utils.py
assert_blob_is "$LR" b1c45e3fc0f3578a5dea9844c0216044321ae1c8:$P 50684588f5d1792c217c809113109cf3f9ace9ac
assert_blob_is "$LR" 0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6:$P 4dc8271567ffbb9a382173051fdf3155658a74da
assert_blob_is "$LR" 0.59.31:$P d2d156b476ac6ead114aa5d204574d7d5e588a5b
assert_blob_is "$LR" 30abbc1a854dee22fbd2f8b2f575dfdabdb603ea:$P 108acf56187c1856d225bbe8c39a64a4df5e0f1e
assert_blob_ne "$LR" b1c45e3fc0f3578a5dea9844c0216044321ae1c8:$P 0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6:$P
assert_blob_ne "$LR" 0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6:$P 0.59.31:$P

python3 - "$OWNED" << 'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
w = json.loads((owned / "snapshot/pages/ghsa/ghsa-wv46-v6xc-2qhf.json").read_text())
assert w["id"] == "GHSA-wv46-v6xc-2qhf"
assert "CVE-2026-35670" in w.get("aliases", [])
assert w["database_specific"]["github_reviewed"] is True
r = json.loads((owned / "snapshot/pages/ghsa/ghsa-rg8m-3943-vm6q.json").read_text())
assert r["id"] == "GHSA-rg8m-3943-vm6q"
assert "CVE-2026-41376" in r.get("aliases", [])
x = json.loads((owned / "snapshot/pages/ghsa/ghsa-x34r-63hx-w57f.json").read_text())
assert x.get("ghsa_id") == "GHSA-x34r-63hx-w57f"
assert x.get("type") == "reviewed"
assert x.get("github_reviewed_at")
print("identities reviewed ok")
PY

printf 'REPLAY_OK bounded assigned=3 reviewed=3 unreviewed=0 PASS_proposal=0 NARROW=3\n'
