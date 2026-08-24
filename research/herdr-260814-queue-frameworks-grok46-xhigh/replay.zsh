#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat
export GIT_ALLOW_PROTOCOL=file

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-queue-frameworks-grok46-xhigh
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical93/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical93/summary.json
SRC_ASSIGN=$ROOT/autoresearch/herdr-260814-nextqueue-v2-grok46-low/assignment.jsonl
SRC_CASES=$ROOT/autoresearch/herdr-260814-nextqueue-v2-grok46-low/cases.jsonl
ADV=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
JIN=/home/hanqing/.cache/cve-analyzer/repos/hubspot_jinjava
MAT=/home/hanqing/.cache/cve-analyzer/repos/matrix-org_matrix-rust-sdk
NES=/home/hanqing/.cache/cve-analyzer/repos/nestjs_nest
FLE=/home/hanqing/.cache/cve-analyzer/repos/fleetdm_fleet

fail() { print -r -- "REPLAY_FAIL $*" >&2; exit 1; }
require_file() { [[ -f $1 ]] || fail "missing $1"; }
require_dir() { [[ -d $1 ]] || fail "missing $1"; }
require_absent() { [[ ! -e $1 ]] || fail "must be absent: $1"; }
sha() { sha256sum -- "$1" | awk '{print $1}'; }

require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/result.json"
require_file "$OWNED/report.md"
require_file "$OWNED/replay.zsh"
require_file "$CONTRACT"
require_file "$LEDGER"
require_file "$SUMMARY"
require_file "$SRC_ASSIGN"
require_file "$SRC_CASES"
require_dir "$ADV/advisories/github-reviewed"
require_dir "$JIN/.git"
require_dir "$MAT/.git"
require_dir "$NES/.git"
require_dir "$FLE/.git"
require_absent "$OWNED/work"
require_absent "$OWNED/notes"
require_absent "$OWNED/pages"
require_absent "$OWNED/clones"

n_owned=$(/usr/bin/ls -1 "$OWNED" | /usr/bin/wc -l | /usr/bin/tr -d ' ')
[[ $n_owned == 5 ]] || fail "owned_file_count $n_owned"

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  python3 - "$OWNED/$f" <<'PY' || fail "ascii $f"
import sys
b=open(sys.argv[1],"rb").read()
if b"\x00" in b:
    raise SystemExit(1)
b.decode("ascii")
PY
done

[[ $(sha "$CONTRACT") == cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3 ]] || fail CONTRACT
[[ $(sha "$LEDGER") == 6d652a089329eb23108083fb73ca1a8a3aa00583415b235381f3b37da389dc3d ]] || fail ledger
[[ $(sha "$SUMMARY") == cf8a3eb231830303803e2e1a198207b2a8e117990a675982e8d9e346c9cc46c0 ]] || fail summary
[[ $(sha "$SRC_ASSIGN") == 5382496f680de8c811d75ca0d3dd6dbdc1b47af0893689e37d36d9dc4a7b93b3 ]] || fail src_assign
[[ $(sha "$SRC_CASES") == 5edd11a19f8bfb7e598290ee5ce22b72e0e3d51c4186c6e8d656f552a38d4ccf ]] || fail src_cases

python3 - "$OWNED" "$SUMMARY" <<'PY' || fail "json conservation"
import json,sys
from pathlib import Path
d=Path(sys.argv[1])
summary=json.loads(Path(sys.argv[2]).read_text())
assign=[json.loads(l) for l in (d/"assignment.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l) for l in (d/"cases.jsonl").read_text().splitlines() if l.strip()]
res=json.loads((d/"result.json").read_text())
expect=["GHSA-GJX9-J8F8-7J74","GHSA-QHJ8-Q5R6-8Q6J","GHSA-R4WM-X892-VJMX","GHSA-2V6M-6XW3-6467"]
assert [a["case_id"] for a in assign]==expect
assert [c["case_id"] for c in cases]==expect
assert "GHSA-3VCP-CHFH-F6R2" not in expect
assert res["conservation"]["equation"]=="4=4+0"
assert res["conservation"]["holds"] is True
assert res["conservation"]["reviewed"]==4 and res["conservation"]["unreviewed"]==0
assert res["counts"]["assigned"]==4 and res["counts"]["reviewed"]==4
assert res["counts"]["PASS"]==0 and res["counts"]["REJECT"]==4
assert res["did_not_pad"] is True
assert res["pass_proposals"]==[]
assert res["packet_delta"]==0
assert res["canonical_strict_count_untouched"]==93
assert summary["canonical_strict_count"]==93
strict=set(summary["strict_released_case_ids"])
assert not set(expect)&strict
assert all(c["verdict"]=="REJECT" for c in cases)
assert all(c.get("proposed_pass") is False for c in cases)
assert not any(all(v=="PASS" for v in c["gates"].values()) for c in cases)
assert all(c["gates"]["identity_gate"]=="PASS" for c in cases)
assert all(c["gates"]["uniqueness_gate"]=="PASS" for c in cases)
PY

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)
anc() { "${git_cmd[@]}" -C "$1" merge-base --is-ancestor "$2" "$3"; }

# GHSA-GJX9
AI_J=eb83265f8a0832328d19ffc4881fc1c28a1c445e
FIXM_J=3d02e504d8bbb13bf3fe019e9ca7b51dfce7a998
PEEL_J=71a8003a4034ec22b7f5e48309c0184f23fec075
P1_J=$("${git_cmd[@]}" -C "$JIN" rev-parse ${FIXM_J}^1)
parents_j=$("${git_cmd[@]}" -C "$JIN" rev-list --parents -n 1 "$AI_J")
[[ $parents_j == "$AI_J 372c0a85f7c1bde13cad7303590937399ca74559" ]] || fail "jinjava parents"
names_ai_j=$("${git_cmd[@]}" -C "$JIN" diff-tree -r --name-only --no-commit-id "$AI_J")
print -r -- "$names_ai_j" | grep -q 'AstFilterChain.java' || fail "jinjava missing AstFilterChain"
if print -r -- "$names_ai_j" | grep -q 'ForTag.java'; then fail "jinjava AI touched ForTag"; fi
names_fix_j=$("${git_cmd[@]}" -C "$JIN" diff --name-only "$P1_J" "$FIXM_J")
print -r -- "$names_fix_j" | grep -q 'ForTag.java' || fail "jinjava fix missing ForTag"
if print -r -- "$names_fix_j" | grep -q 'AstFilterChain.java'; then fail "jinjava closer touched AstFilterChain"; fi
"${git_cmd[@]}" -C "$JIN" grep -q 'getReadMethod' "$AI_J" -- src/main/java/com/hubspot/jinjava/lib/tag/ForTag.java || fail "jinjava AI tree missing old invoke"
"${git_cmd[@]}" -C "$JIN" grep -q 'resolveProperty' "$PEEL_J" -- src/main/java/com/hubspot/jinjava/lib/tag/ForTag.java || fail "jinjava peel missing resolveProperty"
if anc "$JIN" "$AI_J" jinjava-2.8.2; then fail "jinjava AI in 2.8.2"; fi
anc "$JIN" "$AI_J" jinjava-2.8.3 || fail "jinjava AI not in 2.8.3"
if anc "$JIN" "$PEEL_J" jinjava-2.8.2; then fail "jinjava closer in 2.8.2"; fi
anc "$JIN" "$PEEL_J" jinjava-2.8.3 || fail "jinjava closer not in 2.8.3"
[[ $("${git_cmd[@]}" -C "$JIN" rev-parse jinjava-2.8.2^{commit}) == 122f112baabb6448d3a94b034f257f414f2fdef8 ]] || fail peel_282
[[ $("${git_cmd[@]}" -C "$JIN" rev-parse jinjava-2.8.3^{commit}) == 867dde7725b86829ad64d609d916c16d2b8b5d59 ]] || fail peel_283
body_j=$("${git_cmd[@]}" -C "$JIN" show -s --format=%B "$AI_J")
print -r -- "$body_j" | grep -q 'Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>' || fail "jinjava trailer"

# GHSA-QHJ8
AI_M=9848d1472e067df3bccf4fc11f696a599ba531ef
LIST_M=ce3b67f801446387972ff120e907ca828a9f1207
REAL_M=476fe5f9d2bc4c7c7dde62875311d37d419f354f
names_ai_m=$("${git_cmd[@]}" -C "$MAT" diff-tree -r --name-only --no-commit-id "$AI_M")
print -r -- "$names_ai_m" | grep -q 'low_priority.rs' || fail "matrix missing low_priority"
if print -r -- "$names_ai_m" | grep -q 'members.rs'; then fail "matrix AI touched members.rs"; fi
names_list_m=$("${git_cmd[@]}" -C "$MAT" diff-tree -r --name-only --no-commit-id "$LIST_M")
[[ $names_list_m == bindings/matrix-sdk-ffi/CHANGELOG.md ]] || fail "listed not changelog-only"
names_real_m=$("${git_cmd[@]}" -C "$MAT" diff-tree -r --name-only --no-commit-id "$REAL_M")
print -r -- "$names_real_m" | grep -q 'crates/matrix-sdk-base/src/room/members.rs' || fail "real closer missing members.rs"
auth_m=$("${git_cmd[@]}" -C "$MAT" show -s --format='%an <%ae>' "$AI_M")
[[ $auth_m == 'copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>' ]] || fail "matrix author"
if anc "$MAT" "$REAL_M" matrix-sdk-base-0.14.0; then fail "real closer in 0.14.0"; fi
anc "$MAT" "$REAL_M" matrix-sdk-base-0.14.1 || fail "real closer not in 0.14.1"
if anc "$MAT" "$LIST_M" matrix-sdk-base-0.14.1; then fail "listed sha in 0.14.1"; fi
anc "$MAT" "$AI_M" matrix-sdk-base-0.14.0 || fail "AI not in 0.14.0"
[[ $("${git_cmd[@]}" -C "$MAT" rev-parse matrix-sdk-base-0.14.0^{commit}) == 9ffe5aa6ca99f00341a1ff9750ea5eeeaf9d9715 ]] || fail peel_0140
[[ $("${git_cmd[@]}" -C "$MAT" rev-parse matrix-sdk-base-0.14.1^{commit}) == 5ef3ecac8c63d2373d8e45a47807769e602ebd89 ]] || fail peel_0141

# GHSA-R4WM
AI_N=884e8a2296d465c14ab2b2678b624d2ccc8e16d9
FIXM_N=fd8d073e0e048b185147209338ca7042e52c10ba
PEEL_N=d74e9a8c5f3f1785445fd0dd37ea4818127b1f1c
P1_N=$("${git_cmd[@]}" -C "$NES" rev-parse ${FIXM_N}^1)
[[ $("${git_cmd[@]}" -C "$NES" rev-list --parents -n 1 "$FIXM_N") == "$FIXM_N $P1_N $PEEL_N" ]] || fail "nest merge parents"
names_ai_n=$("${git_cmd[@]}" -C "$NES" diff-tree -r --name-only --no-commit-id "$AI_N")
[[ $names_ai_n == packages/core/router/router-response-controller.ts ]] || fail "nest 884e files"
names_fix_n=$("${git_cmd[@]}" -C "$NES" diff --name-only "$P1_N" "$FIXM_N")
print -r -- "$names_fix_n" | grep -q 'fastify-adapter.ts' || fail "nest fix missing adapter"
if print -r -- "$names_fix_n" | grep -q 'router-response-controller.ts'; then fail "nest closer touched core router"; fi
body_n=$("${git_cmd[@]}" -C "$NES" show -s --format=%B "$AI_N")
print -r -- "$body_n" | grep -q 'Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>' || fail "nest copilot trailer"
if anc "$NES" "$PEEL_N" v11.1.13; then fail "nest closer in 11.1.13"; fi
anc "$NES" "$PEEL_N" v11.1.14 || fail "nest closer not in 11.1.14"
if "${git_cmd[@]}" -C "$NES" grep -q sanitizeUrl v11.1.13 -- packages/platform-fastify/adapters/fastify-adapter.ts; then fail "sanitizeUrl in 11.1.13"; fi
"${git_cmd[@]}" -C "$NES" grep -q sanitizeUrl v11.1.14 -- packages/platform-fastify/adapters/fastify-adapter.ts || fail "sanitizeUrl missing 11.1.14"
[[ $("${git_cmd[@]}" -C "$NES" rev-parse v11.1.13^{commit}) == e3a958ac3efebe7995e6d487e00bbc6fd6267fd5 ]] || fail peel_1113
[[ $("${git_cmd[@]}" -C "$NES" rev-parse v11.1.14^{commit}) == 5d31df7eb62d89952d827eadc19123fb441f541e ]] || fail peel_1114

# GHSA-2V6M
AI_F=5bf82e29354d8c53c6e8d839b9583a142164a569
FIX_F=23fc6804efe785f806f769d6be1f5f05b2e13ec2
parents_f=$("${git_cmd[@]}" -C "$FLE" rev-list --parents -n 1 "$AI_F")
[[ $parents_f == "$AI_F 29b9391d30dbfe71e9492f24289ad6e0aa7b155e" ]] || fail "fleet parents"
names_ai_f=$("${git_cmd[@]}" -C "$FLE" diff-tree -r --name-only --no-commit-id "$AI_F")
print -r -- "$names_ai_f" | grep -q 'server/service/hosts.go' || fail "fleet missing hosts.go"
if print -r -- "$names_ai_f" | grep -q 'google_calendar'; then fail "fleet AI touched calendar"; fi
if print -r -- "$names_ai_f" | grep -q 'server/fleet/app.go'; then fail "fleet AI touched app.go"; fi
names_fix_f=$("${git_cmd[@]}" -C "$FLE" diff-tree -r --name-only --no-commit-id "$FIX_F")
print -r -- "$names_fix_f" | grep -q 'server/fleet/app.go' || fail "fleet closer missing app.go"
body_f=$("${git_cmd[@]}" -C "$FLE" show -s --format=%B "$AI_F")
print -r -- "$body_f" | grep -q 'Co-authored-by: Claude <noreply@anthropic.com>' || fail "fleet claude trailer"
print -r -- "$body_f" | grep -q '(#36009)' || fail "fleet squash marker"
if anc "$FLE" "$FIX_F" fleet-v4.80.0; then fail "fleet closer in 4.80.0"; fi
anc "$FLE" "$FIX_F" fleet-v4.80.1 || fail "fleet closer not in 4.80.1"
anc "$FLE" "$AI_F" fleet-v4.80.0 || fail "fleet AI not in 4.80.0"
[[ $("${git_cmd[@]}" -C "$FLE" rev-parse fleet-v4.80.0^{commit}) == adaef7e0e3cbb62d959aea3efa75a46feab23e12 ]] || fail peel_4800
[[ $("${git_cmd[@]}" -C "$FLE" rev-parse fleet-v4.80.1^{commit}) == 5c2a408a4ddb0866a8393159fe71abec5f450e6d ]] || fail peel_4801

# advisories
[[ $("${git_cmd[@]}" -C "$ADV" rev-parse HEAD) == f2c6ab3202aeafb36fbea6e76d892532acfca1a6 ]] || fail adv_head
[[ $("${git_cmd[@]}" -C "$ADV" rev-parse HEAD:advisories/github-reviewed) == 3308b2f6c73929d3854bd12908e996787a8bb0c8 ]] || fail adv_tree
[[ $(sha "$ADV/advisories/github-reviewed/2026/02/GHSA-gjx9-j8f8-7j74/GHSA-gjx9-j8f8-7j74.json") == 3490f83eae1e3680da4b20866a724cb19f536ca1b02174f5f3ea8efc1008314c ]] || fail adv_gjx9
[[ $(sha "$ADV/advisories/github-reviewed/2025/09/GHSA-qhj8-q5r6-8q6j/GHSA-qhj8-q5r6-8q6j.json") == 82c488d00cadae189d478d62aac08e04292ebc826f31eb907cc47603b16c164b ]] || fail adv_qhj8
[[ $(sha "$ADV/advisories/github-reviewed/2026/03/GHSA-r4wm-x892-vjmx/GHSA-r4wm-x892-vjmx.json") == 8fc9967575736c46d7b4200edff6afa3a1b60866dde3f95dde6673139cfd373e ]] || fail adv_r4wm
[[ $(sha "$ADV/advisories/github-reviewed/2026/02/GHSA-2v6m-6xw3-6467/GHSA-2v6m-6xw3-6467.json") == 17fc7ce95727fc18769e95dc119e971849b33c7b5d6cc90c781171c3aea98bf2 ]] || fail adv_2v6m

print -r -- "REPLAY_OK reviewed=4 PASS=0 REJECT=4 packet_delta=0 canonical_strict=93 equation=4=4+0"
