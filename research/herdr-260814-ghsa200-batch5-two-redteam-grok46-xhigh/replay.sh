#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-batch5-two-redteam-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Red-team KEEP is a proposal. This script admits none.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-batch5-two-redteam-grok46-xhigh
EN=/home/hanqing/.cache/cve-analyzer/repos/agentfront_enclave
OC=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/openclaw__openclaw
AF=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/agentfront__enclave

SQUASH_F229=9e1a930cd8efa1c4b6fb699f79bba6b4889d1910
PARENT_F229=164bee431c14e800fa7d8620c0bafc827613e49d
HUMAN_SEC=4e2de7bedad05691974ecb4ecd5e1e990a4a449e
CLAUDE_F229=b4bd9b8e006eb753a64a869f9252da5b20c292ef
FIX_F229=09afbebe4cb6d0586c1145aa71ffabd2103932db
REL2110=1dd877cf30d1eafd9ace6c47dea74aa07c5cbc23
REL2111=0ec916f6676df2a5e9792f17f648b9aeefa79394
RULE=libs/ast/src/rules/disallowed-identifier.rule.ts
BLOB_PARENT=bcbdd443fc9596b7e73d96635a65539a05df574e
BLOB_ATTEMPT=368fa4fe619da98dab99e83bf88c91d6849c4e96
BLOB_CLOSER=06c7947ee528a53c9a346197901a45e6d8c7c98b

SQUASH_33=f5c90f0e5c7a12285ceea6c3102666a7b904b16f
PARENT_33=c5ffc11df52f03d5b64ae5e6a381412fac35ee7b
CLAUDE_33=0a99064a997c34bf0c59d9a076497a3ad42451a3
HUMAN_COPY=ebf7dcc05424a5f144bf7d0805a248a3769372c4
FIX_33=8c7901c984866a776eb59662dc9d8b028de4f0d0
REL129=62e4ad23d3f6cb11ea779df76f10b5597b784402
REL201=85cd55e22be191f82bd90f609815877dd8a44192
ACL=extensions/twitch/src/access-control.ts
BLOB_HARD_DENY=cb0bed15b87546f012dd104923ea1f0fbb832542
BLOB_FALLTHROUGH=0ce86d78bd552b5f565745b994fb32f7bdd4538f

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

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

assert_ancestor() {
  "${git_cmd[@]}" -C "$1" merge-base --is-ancestor "$2" "$3"
}

assert_not_ancestor() {
  if "${git_cmd[@]}" -C "$1" merge-base --is-ancestor "$2" "$3"; then
    printf 'unexpected ancestor: %s is ancestor of %s in %s\n' "$2" "$3" "$1" >&2
    exit 1
  fi
}

require_dir "$OWNED"
require_dir "$EN/.git"
require_dir "$OC/.git"
require_dir "$AF"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/baseline.json" \
  d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl" \
  1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-canonical72-dedupe-grok46-medium/result.json" \
  fb3b97c7b5d207119cc22d255ba48cbda568d56c8fffb447fb0e58ac8878f4fb
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json" \
  699f6160b6ecb9c9ce2cdae257c9a12dbdf4f7ef8a925196fcfd4fcf0b1140d8
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-directroot-batch5-grok46-medium/cases.jsonl" \
  d71e03c0cbccd812d3defdc6d7baa2a4f43f5badf3b5addd6e5ccea6941c816e
expect_hash "$ROOT/scripts/publication_adjudications.json" \
  9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f
expect_hash "$OWNED/cases.jsonl" \
  ef902eb150d5cf4f5c8c7090e4b2911d9208d7e8fa070b96bd8f5f00c25d5e21
expect_hash "$OWNED/snapshot/advisory-database/GHSA-f229-3862-4942.json" \
  71647cf96c893742e309ff05ce37254831230a0e2a5532755c0f32f61dec1299
expect_hash "$OWNED/snapshot/advisory-database/GHSA-33rq-m5x2-fvgf.json" \
  b1832492d6e10a7723470f95af53311eca2e597f6747ae551774baccb24a2133
expect_hash "$OWNED/snapshot/pages/pr/enclave-52-commits.json" \
  1f07c83a7968d1415f0de2a5d08d4eeba6381aa6729910409c011a2ab2a13f61
expect_hash "$OWNED/snapshot/pages/pr/openclaw-1612-commits.json" \
  26a27741061b8ba72c0d811becd4777daafffba29ddc955cbbf71ba3b28ababb
expect_hash "$OWNED/snapshot/pages/gh_commit_files/0a99064a-files.json" \
  ff5fe7e8b467016fc7d7e1335075fe681e4bdbfdb0f0f37f5c333ea8cfde2817
expect_hash "$OWNED/snapshot/pages/gh_commit_files/b4bd9b8e-files.json" \
  071e21b012857da33aab0006ee6a695cfea2e2d8e65a3cc3004f98bdc23c6a35
expect_hash "$OWNED/snapshot/pages/gh_commit_files/4e2de7be-files.json" \
  541271a7bd3c281e2d0db8d6de27fa87e1c670d6909acbbce491fc94d81494b3

python3 - "$OWNED/cases.jsonl" "$ROOT/autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json" "$OWNED" "$ROOT/scripts/publication_adjudications.json" "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" << 'PY'
import json, re, sys
from pathlib import Path
rows = [json.loads(l) for l in Path(sys.argv[1]).read_text().splitlines() if l.strip()]
assert len(rows) == 2, len(rows)
assert [r["case_id"] for r in rows] == ["GHSA-F229-3862-4942", "GHSA-33RQ-M5X2-FVGF"]
assert [r["verdict"] for r in rows] == ["NARROW", "NARROW"]
gates = ["identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate", "uniqueness_gate"]
for r in rows:
    assert r["causal_admission"] is False
    assert r["countable"] is False
    assert r["countable_proposal"] is False
    assert r["publication_status"] == "HOLD"
    assert r["uniqueness_gate"] == "PASS"
    assert r["identity_gate"] == "PASS"
    assert not all(r.get(g) == "PASS" for g in gates), r["case_id"]
    assert r.get("failing_gates")
han = re.compile(r"[\u3400-\u9fff]")
owned = Path(sys.argv[3])
for name in ("cases.jsonl", "report.md", "replay.sh"):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert not han.search(text), name
c73 = json.loads(Path(sys.argv[2]).read_text())
ids = set(c73["strict_released_case_ids"])
assert len(ids) == 73
assert "GHSA-F229-3862-4942" not in ids
assert "GHSA-33RQ-M5X2-FVGF" not in ids
pub = Path(sys.argv[4]).read_text()
assert "GHSA-F229-3862-4942" not in pub
assert "GHSA-33RQ-M5X2-FVGF" not in pub
public = Path(sys.argv[5]).read_text()
assert "GHSA-F229-3862-4942" not in public
assert "GHSA-33RQ-M5X2-FVGF" not in public
f229 = json.loads((owned / "snapshot/advisory-database/GHSA-f229-3862-4942.json").read_text())
assert f229["id"] == "GHSA-f229-3862-4942"
assert f229["database_specific"]["github_reviewed"] is True
assert f229["affected"][0]["package"]["name"] == "@enclave-vm/core"
assert f229["affected"][0]["database_specific"]["last_known_affected_version_range"] == "<= 2.10.1"
assert "{}[['__proto__']]" in f229["details"] or '{}[["__proto__"]]' in f229["details"]
t33 = json.loads((owned / "snapshot/advisory-database/GHSA-33rq-m5x2-fvgf.json").read_text())
assert t33["id"] == "GHSA-33rq-m5x2-fvgf"
assert t33["database_specific"]["github_reviewed"] is True
assert t33["affected"][0]["package"]["name"] == "openclaw"
events = t33["affected"][0]["ranges"][0]["events"]
assert events[0]["introduced"] == "2026.1.29"
assert events[1]["fixed"] == "2026.2.1"
pr52 = json.loads((owned / "snapshot/pages/pr/enclave-52-commits.json").read_text())
assert [c["sha"][:8] for c in pr52] == ["4e2de7be", "3c8a0042", "963cba6a", "b4bd9b8e", "7b8d7ba0"]
assert "Claude" not in pr52[0]["commit"]["message"]
assert "Claude Opus 4.6" in pr52[3]["commit"]["message"]
pr1612 = json.loads((owned / "snapshot/pages/pr/openclaw-1612-commits.json").read_text())
assert len(pr1612) == 54
claude = [c for c in pr1612 if "Claude" in c["commit"]["message"]]
assert len(claude) == 1
assert claude[0]["sha"] == "0a99064a997c34bf0c59d9a076497a3ad42451a3"
assert any(c["sha"].startswith("cf311730") and "adjust access control logic" in c["commit"]["message"] for c in pr1612)
files_claude = json.loads((owned / "snapshot/pages/gh_commit_files/0a99064a-files.json").read_text())
assert "extensions/twitch/src/access-control.ts" not in files_claude
files_b4 = json.loads((owned / "snapshot/pages/gh_commit_files/b4bd9b8e-files.json").read_text())
assert files_b4 == ["libs/core/package.json", "yarn.lock"]
files_4e = json.loads((owned / "snapshot/pages/gh_commit_files/4e2de7be-files.json").read_text())
assert "libs/ast/src/rules/disallowed-identifier.rule.ts" in files_4e
print("conservation reviewed=2 KEEP_proposal=0 NARROW=2 REJECT=0 UNKNOWN=0 BLOCKED=0")
PY

# ----- F229 squash marker, human vs Claude members, tags -----
"${git_cmd[@]}" -C "$EN" log -1 --format='%B' "$SQUASH_F229" | grep -F 'Co-authored-by: Claude Opus 4.6' >/dev/null
parents_f229=$("${git_cmd[@]}" -C "$EN" rev-parse "${SQUASH_F229}^@")
printf '%s\n' "$parents_f229" | grep -Fx "$PARENT_F229" >/dev/null
[[ $("${git_cmd[@]}" -C "$EN" rev-parse "${SQUASH_F229}^") == "$PARENT_F229" ]]
[[ $("${git_cmd[@]}" -C "$EN" rev-parse "${HUMAN_SEC}^") == "$PARENT_F229" ]]
"${git_cmd[@]}" -C "$EN" log -1 --format='%B' "$CLAUDE_F229" | grep -F 'Co-Authored-By: Claude Opus 4.6' >/dev/null
if "${git_cmd[@]}" -C "$EN" log -1 --format='%B' "$HUMAN_SEC" | grep -E 'Claude|Co-Authored-By|Co-authored-by' >/dev/null; then
  printf 'human security member unexpectedly has AI marker\n' >&2
  exit 1
fi
blob_parent=$("${git_cmd[@]}" -C "$EN" rev-parse "${PARENT_F229}:${RULE}")
blob_human=$("${git_cmd[@]}" -C "$EN" rev-parse "${HUMAN_SEC}:${RULE}")
blob_claude_member=$("${git_cmd[@]}" -C "$EN" rev-parse "${CLAUDE_F229}:${RULE}")
blob_squash=$("${git_cmd[@]}" -C "$EN" rev-parse "${SQUASH_F229}:${RULE}")
blob_2110=$("${git_cmd[@]}" -C "$EN" rev-parse "v2.11.0:${RULE}")
blob_2111=$("${git_cmd[@]}" -C "$EN" rev-parse "v2.11.1:${RULE}")
blob_2101=$("${git_cmd[@]}" -C "$EN" rev-parse "v2.10.1:${RULE}")
blob_fix=$("${git_cmd[@]}" -C "$EN" rev-parse "${FIX_F229}:${RULE}")
[[ $blob_parent == "$BLOB_PARENT" ]]
[[ $blob_human == "$BLOB_ATTEMPT" ]]
[[ $blob_claude_member == "$BLOB_ATTEMPT" ]]
[[ $blob_squash == "$BLOB_ATTEMPT" ]]
[[ $blob_2110 == "$BLOB_ATTEMPT" ]]
[[ $blob_2101 == "$BLOB_PARENT" ]]
[[ $blob_fix == "$BLOB_CLOSER" ]]
[[ $blob_2111 == "$BLOB_CLOSER" ]]
"${git_cmd[@]}" -C "$EN" grep -F 'tryGetArrayCoercedString' "$HUMAN_SEC" -- "$RULE" >/dev/null
if "${git_cmd[@]}" -C "$EN" grep -F 'tryGetArrayCoercedString' "$PARENT_F229" -- "$RULE" >/dev/null; then
  printf 'parent unexpectedly has tryGetArrayCoercedString\n' >&2
  exit 1
fi
if "${git_cmd[@]}" -C "$EN" cat-file -e "v2.11.0:libs/ast/src/rules/coercion-utils.ts" 2>/dev/null; then
  printf 'v2.11.0 unexpectedly has coercion-utils.ts\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$EN" cat-file -e "v2.11.1:libs/ast/src/rules/coercion-utils.ts" 2>/dev/null
stat_claude=$("${git_cmd[@]}" -C "$EN" diff --stat "${CLAUDE_F229}^" "$CLAUDE_F229")
printf '%s\n' "$stat_claude" | grep -F 'libs/core/package.json' >/dev/null
if printf '%s\n' "$stat_claude" | grep -F 'disallowed-identifier.rule.ts' >/dev/null; then
  printf 'Claude member unexpectedly edits disallowed-identifier.rule.ts\n' >&2
  exit 1
fi
peel2110=$("${git_cmd[@]}" -C "$EN" rev-parse 'v2.11.0^{commit}')
peel2111=$("${git_cmd[@]}" -C "$EN" rev-parse 'v2.11.1^{commit}')
peel2101=$("${git_cmd[@]}" -C "$EN" rev-parse 'v2.10.1^{commit}')
[[ $peel2110 == "$REL2110" ]]
[[ $peel2111 == "$REL2111" ]]
[[ $peel2101 == 7a9b981e9986bbd14055247e1474397713e533ff ]]
[[ $("${git_cmd[@]}" -C "$EN" rev-parse "${REL2110}^") == "$SQUASH_F229" ]]
[[ $("${git_cmd[@]}" -C "$EN" rev-parse "${FIX_F229}^") == "$REL2110" ]]
[[ $("${git_cmd[@]}" -C "$EN" rev-parse "${REL2111}^") == "$FIX_F229" ]]
assert_ancestor "$EN" "$SQUASH_F229" v2.11.0
assert_not_ancestor "$EN" "$FIX_F229" v2.11.0
assert_ancestor "$EN" "$FIX_F229" v2.11.1
assert_not_ancestor "$EN" "$SQUASH_F229" v2.10.1
"${git_cmd[@]}" -C "$EN" grep -F "'__proto__'" "$PARENT_F229" -- libs/ast/src/presets/agentscript.preset.ts >/dev/null
core2110=$("${git_cmd[@]}" -C "$EN" show 'v2.11.0:libs/core/package.json')
printf '%s\n' "$core2110" | grep -F '"version": "2.11.0"' >/dev/null
core2111=$("${git_cmd[@]}" -C "$EN" show 'v2.11.1:libs/core/package.json')
printf '%s\n' "$core2111" | grep -F '"version": "2.11.1"' >/dev/null
if "${git_cmd[@]}" -C "$EN" log -1 --format='%B' "$FIX_F229" | grep -E 'Claude|Co-Authored-By|Co-authored-by' >/dev/null; then
  printf 'closer unexpectedly has AI marker\n' >&2
  exit 1
fi

# AF partial clone still has the squash (no tags required here)
assert_ancestor "$AF" "$SQUASH_F229" "$REL2110"
assert_not_ancestor "$AF" "$FIX_F229" "$REL2110"

# ----- 33RQ Claude did not author fallthrough; releases contain it / the fix -----
"${git_cmd[@]}" -C "$OC" log -1 --format='%B' "$SQUASH_33" | grep -F 'Co-Authored-By: Claude Sonnet 4.5' >/dev/null
[[ $("${git_cmd[@]}" -C "$OC" rev-parse "${SQUASH_33}^") == "$PARENT_33" ]]
if "${git_cmd[@]}" -C "$OC" cat-file -e "${PARENT_33}:${ACL}" 2>/dev/null; then
  printf 'squash parent unexpectedly has access-control.ts\n' >&2
  exit 1
fi
blob_copy=$("${git_cmd[@]}" -C "$OC" rev-parse "${HUMAN_COPY}:${ACL}")
blob_claude33=$("${git_cmd[@]}" -C "$OC" rev-parse "${CLAUDE_33}:${ACL}")
blob_squash33=$("${git_cmd[@]}" -C "$OC" rev-parse "${SQUASH_33}:${ACL}")
blob_129=$("${git_cmd[@]}" -C "$OC" rev-parse "${REL129}:${ACL}")
[[ $blob_copy == "$BLOB_HARD_DENY" ]]
[[ $blob_claude33 == "$BLOB_HARD_DENY" ]]
[[ $blob_squash33 == "$BLOB_FALLTHROUGH" ]]
[[ $blob_129 == "$BLOB_FALLTHROUGH" ]]
[[ $blob_copy != "$blob_squash33" ]]
human_src=$("${git_cmd[@]}" -C "$OC" show "${HUMAN_COPY}:${ACL}")
printf '%s\n' "$human_src" | grep -F 'sender not in allowlist' >/dev/null
if printf '%s\n' "$human_src" | grep -F 'sender is not in allowFrom allowlist' >/dev/null; then
  printf 'human copy unexpectedly already has the later deny reason\n' >&2
  exit 1
fi
squash_src=$("${git_cmd[@]}" -C "$OC" show "${SQUASH_33}:${ACL}")
if printf '%s\n' "$squash_src" | grep -F 'sender not in allowlist' >/dev/null; then
  printf 'squash unexpectedly still has the human hard deny\n' >&2
  exit 1
fi
if printf '%s\n' "$squash_src" | grep -F 'sender is not in allowFrom allowlist' >/dev/null; then
  printf 'squash unexpectedly already has the fix deny\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$OC" log -1 --format='%B' "$CLAUDE_33" | grep -F 'Co-Authored-By: Claude Sonnet 4.5' >/dev/null
pkg129=$("${git_cmd[@]}" -C "$OC" show "${REL129}:package.json")
printf '%s\n' "$pkg129" | grep -F '"version": "2026.1.29"' >/dev/null
pkg201=$("${git_cmd[@]}" -C "$OC" show "${REL201}:package.json")
printf '%s\n' "$pkg201" | grep -F '"version": "2026.2.1"' >/dev/null
assert_ancestor "$OC" "$SQUASH_33" "$REL129"
assert_not_ancestor "$OC" "$FIX_33" "$REL129"
assert_ancestor "$OC" "$FIX_33" "$REL201"
"${git_cmd[@]}" -C "$OC" grep -F 'sender is not in allowFrom allowlist' "$FIX_33" -- "$ACL" >/dev/null
"${git_cmd[@]}" -C "$OC" grep -F 'sender is not in allowFrom allowlist' "$REL201" -- "$ACL" >/dev/null
if "${git_cmd[@]}" -C "$OC" grep -F 'sender is not in allowFrom allowlist' "$REL129" -- "$ACL" >/dev/null; then
  printf '2026.1.29 unexpectedly already has deny reason\n' >&2
  exit 1
fi
deny_hits=$("${git_cmd[@]}" -C "$OC" log --reverse --format='%H' -S 'sender is not in allowFrom allowlist' -- "$ACL")
first_deny=${deny_hits%%$'\n'*}
[[ $first_deny == "$FIX_33" ]]
[[ $("${git_cmd[@]}" -C "$OC" rev-parse "${FIX_33}^@") == aa2eb48b9c0fe63aa7b8be6329869d3a2539c446 ]]
blame201=$("${git_cmd[@]}" -C "$OC" blame -l -L70,72 "$REL201" -- "$ACL")
printf '%s\n' "$blame201" | grep -F "$FIX_33" >/dev/null

printf 'REPLAY_OK reviewed=2 KEEP_proposal=0 NARROW=2 REJECT=0 UNKNOWN=0 BLOCKED=0\n'
