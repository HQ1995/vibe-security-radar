#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-causalonly-release-recheck-grok46-high.
# English only. No credentials. Shared caches read-only. mktemp cleaned.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export LC_ALL=C

OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-causalonly-release-recheck-grok46-high}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/summary.json
TAYL=$ROOT/autoresearch/herdr-260814-ghsa200-fp211-unknown4a-grok46-low/work/pages/releases/taylored_releases.json
V324=$ROOT/autoresearch/herdr-260814-ghsa200-fp211-releaseonly11-grok46-low/work/pages/github-releases/vitest_v3.2.4.json
V325=$ROOT/autoresearch/herdr-260814-ghsa200-fp211-releaseonly11-grok46-low/work/pages/github-releases/vitest_v3.2.5.json
ADV=/home/hanqing/.cache/cve-analyzer/advisory-database
A8=$ADV/advisories/github-reviewed/2025/06/GHSA-8g98-m4j9-qww5/GHSA-8g98-m4j9-qww5.json
AV=$ADV/advisories/github-reviewed/2025/06/GHSA-vh5j-5fhq-9xwg/GHSA-vh5j-5fhq-9xwg.json
AH=$ADV/advisories/unreviewed/2025/11/GHSA-h2v8-4c3f-vqgv/GHSA-h2v8-4c3f-vqgv.json
AG=$ADV/advisories/github-reviewed/2026/06/GHSA-g8mr-85jm-7xhm/GHSA-g8mr-85jm-7xhm.json
TREPO=/home/hanqing/.cache/cve-analyzer/repos/tailot_taylored
BREPO=/home/hanqing/.cache/cve-analyzer/repos/brentmid_evernote-mcp-server
VREPO=/home/hanqing/.cache/cve-analyzer/repos/vitest-dev_vitest
UA=ai-slop-research/causalonly-release-recheck-grok46-high

fail() { print -r -- "REPLAY_FAIL $*" >&2; exit 1; }

REPLAY_TMP=""
cleanup_replay_tmp() {
  if [[ -n ${REPLAY_TMP:-} && -d $REPLAY_TMP ]]; then
    rm -rf "$REPLAY_TMP"
  fi
}
trap cleanup_replay_tmp EXIT
REPLAY_TMP="$(mktemp -d /tmp/causalonly-recheck-replay.XXXXXX)"

gitx() {
  local repo=$1
  shift
  /usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$repo" "$@"
}

expect_eq() {
  if [[ $1 != "$2" ]]; then
    fail "mismatch $3 expected=$2 got=$1"
  fi
}

expect_hash() {
  local got
  got=$(/usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}')
  expect_eq "$got" "$2" "$1"
}

git_path_absent() {
  local repo=$1 spec=$2
  if gitx "$repo" cat-file -e "$spec" >/dev/null 2>&1; then
    fail "path present $spec"
  fi
}

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  python3 - "$OWNED/$f" <<'PY' || fail "ascii $f"
import sys
b=open(sys.argv[1],"rb").read()
if b"\x00" in b:
    raise SystemExit(1)
b.decode("ascii")
if b.endswith(b" ") or b" \n" in b:
    raise SystemExit(1)
PY
done

require_file() { [[ -f $1 ]] || fail "missing $1"; }
require_dir() { [[ -d $1 ]] || fail "missing $1"; }
require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/result.json"
require_file "$OWNED/report.md"
require_file "$OWNED/replay.zsh"
require_file "$CONTRACT"
require_file "$LEDGER"
require_file "$SUMMARY"
require_file "$A8"
require_file "$AV"
require_file "$AH"
require_file "$AG"
require_file "$TAYL"
require_file "$V324"
require_file "$V325"
require_dir "$TREPO"
require_dir "$BREPO"
require_dir "$VREPO"

echo "== input hashes =="
expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 70b7658fadf41f18c72734a2006601961a2180681bf81353373bccab95ff659e
expect_hash "$SUMMARY" ab47f927a20f374a9b0e3253a1a5a0778e355dda9414189927022325d81ad86f
expect_hash "$A8" f9f1f975f2d2223b8e8b98c55217a39a989ade18e61aa5625b70252c863cce79
expect_hash "$AV" 7b4729eb07a7f4aaf96697dd628f51dae1b55e9148600ae5e33d382fb02b23b6
expect_hash "$AH" eea310ecbf64f4e0d5b929965eb3c32a4fbb2c422ee62a4654655bad9883607b
expect_hash "$AG" 8a284425df6d7e2b2ba1cb99dc7c700dd0a519f1adab46427015be91fbb5317f
expect_hash "$TAYL" 37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570
expect_hash "$V324" ae8cd3a95ea27893495d91ee39a5eedaae849d746cf803cf9a5ad96a921c02f4
expect_hash "$V325" 1fc48f0acc2906b7984e67d809ed7728ef36079fead0ce9ac21e0e671536bde3
echo HASH_OK inputs

n_assign=$(/usr/bin/wc -l < "$OWNED/assignment.jsonl" | /usr/bin/tr -d ' ')
n_cases=$(/usr/bin/wc -l < "$OWNED/cases.jsonl" | /usr/bin/tr -d ' ')
expect_eq "$n_assign" 4 assignment_rows
expect_eq "$n_cases" 4 cases_rows

python3 - "$OWNED" "$SUMMARY" "$A8" "$AV" "$AH" "$AG" "$TAYL" "$V324" "$V325" <<'PY' || fail "python conservation"
import json, sys
from pathlib import Path
owned, summary_p, a8, av, ah, ag, tayl, v324, v325 = map(Path, sys.argv[1:])
assigns=[json.loads(l) for l in owned.joinpath("assignment.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l) for l in owned.joinpath("cases.jsonl").read_text().splitlines() if l.strip()]
res=json.loads(owned.joinpath("result.json").read_text())
report=owned.joinpath("report.md").read_text()
assert all(ord(c) < 128 for c in report)
want=["GHSA-8G98-M4J9-QWW5","GHSA-VH5J-5FHQ-9XWG","GHSA-H2V8-4C3F-VQGV","GHSA-G8MR-85JM-7XHM"]
assert [a["case_id"] for a in assigns]==want
assert [c["case_id"] for c in cases]==want
assert res["conservation"]["equation"]=="4=4+0"
assert res["conservation"]["holds"] is True
assert res["counts"]["PASS"]==0
assert res["counts"]["PASS_PROPOSAL"]==0
assert res["counts"]["NARROW"]==4
assert res["counts"]["countable_pass"]==0
assert res["canonical_strict_count_untouched"]==91
assert res["canonical_ledger_edited"] is False
assert res["did_not_commit_or_push"] is True
assert res["pass_proposals"]==[]
CAUSAL=["identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","uniqueness_gate"]
pairs={
 "GHSA-8G98-M4J9-QWW5":("c139c021f68a09d22c2af88641b61c00f67f2af4","57b7634391959dbbdb39b387ac4dc68157cd58a1"),
 "GHSA-VH5J-5FHQ-9XWG":("57b7634391959dbbdb39b387ac4dc68157cd58a1","fdf67a6fba0deae30912905a79fb5a9e83751a79"),
 "GHSA-H2V8-4C3F-VQGV":("e08547bcdb42aaa86190c6e2dfc64159fcd3a146","1e66c78c4ce6ea294ac6b0eb289a9eae9c5e9579"),
 "GHSA-G8MR-85JM-7XHM":("af88b1f5d82844a4761ea9a977156c98e2b14ca8","385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7"),
}
for a,c in zip(assigns, cases):
    cid=c["case_id"]
    assert a["hypothesized_candidate"]==pairs[cid][0]
    assert a["hypothesized_fix"]==pairs[cid][1]
    assert c["candidate_set"]==[pairs[cid][0]]
    assert c["minimum_fix_set"]==[pairs[cid][1]]
    assert c["observed_candidate"]==pairs[cid][0]
    assert c["observed_fix"]==pairs[cid][1]
    assert c["candidate_fix_hypothesis_unchanged"] is True
    assert c["verdict"]=="NARROW"
    assert c["countable"] is False
    assert c["proposed_pass"] is False
    assert c["n_parents"]==1
    assert all(c["gates"][k]=="PASS" for k in CAUSAL)
    assert c["gates"]["release_gate"]=="NARROW"
    assert a["prior_packets_are_routing_only"] is True
assert cases[0]["shared_sha_is_not_dedupe"] is True
assert cases[1]["shared_sha_is_not_dedupe"] is True
assert cases[0]["minimum_fix_set"]==cases[1]["candidate_set"]
assert cases[2]["release_class"]=="commit_only"
assert cases[3]["release_class"]=="same_first_tag"
assert cases[3]["release_evidence"]["same_first_tag"] is True
summary=json.loads(summary_p.read_text())
counted={str(x).upper() for x in summary["strict_released_case_ids"]}
assert len(counted)==91
for i in want:
    assert i not in counted
a8j=json.loads(a8.read_text()); assert a8j["id"]=="GHSA-8g98-m4j9-qww5"; assert a8j["database_specific"]["github_reviewed"] is True
avj=json.loads(av.read_text()); assert avj["id"]=="GHSA-vh5j-5fhq-9xwg"
ahj=json.loads(ah.read_text()); assert ahj["id"]=="GHSA-h2v8-4c3f-vqgv"; assert "CVE-2025-12489" in ahj["aliases"]
agj=json.loads(ag.read_text()); assert agj["id"]=="GHSA-g8mr-85jm-7xhm"; assert "CVE-2026-53633" in agj["aliases"]
assert tayl.read_text()=="[]\n"
v4=json.loads(v324.read_text()); assert v4["tag_name"]=="v3.2.4"; assert v4["draft"] is False; assert v4["prerelease"] is False
v5=json.loads(v325.read_text()); assert v5["tag_name"]=="v3.2.5"; assert v5["draft"] is False; assert v5["prerelease"] is False; assert v5["immutable"] is True
assert "Canonical91 stays 91" in report
assert "NARROW 4" in report
print("conservation_ok")
PY

echo "== git facts =="
C8=c139c021f68a09d22c2af88641b61c00f67f2af4
P8=610281a664bd4e8c8d0c7052116bedaea5c8a4c6
F8=57b7634391959dbbdb39b387ac4dc68157cd58a1
FV=fdf67a6fba0deae30912905a79fb5a9e83751a79
IDX=templates/backend-in-a-box/index.js
expect_eq "$(gitx "$TREPO" rev-list --parents -n 1 "$C8")" "$C8 $P8" 8g98_parents
expect_eq "$(gitx "$TREPO" log -1 --format='%an' "$C8")" "google-labs-jules[bot]" 8g98_author
git_path_absent "$TREPO" "${P8}:$IDX"
expect_eq "$(gitx "$TREPO" rev-parse "${C8}:$IDX")" 0dd0853c7f2c5b9443f9d5564d79a7b96d179bc7 8g98_cand_blob
gitx "$TREPO" grep -q 'webhookEvent = req.body' "$C8" -- "$IDX" || fail "8g98 cand body"
if gitx "$TREPO" grep -q verifyAndGetWebhookEvent "$C8" -- "$IDX"; then fail "8g98 cand has verify"; fi
expect_eq "$(gitx "$TREPO" rev-list --parents -n 1 "$F8")" "$F8 $C8" 8g98_fix_parents
expect_eq "$(gitx "$TREPO" rev-parse "${F8}:$IDX")" 8a5317f90c56685b73d643b5757679a2c9ba177c 8g98_fix_blob
gitx "$TREPO" grep -q verifyAndGetWebhookEvent "$F8" -- "$IDX" || fail "8g98 fix verify"
gitx "$TREPO" merge-base --is-ancestor "$C8" "$F8" || fail "8g98 cand not ancestor of fix"
empty=$(gitx "$TREPO" tag --contains "$C8" --no-contains "$F8")
[[ -z $empty ]] || fail "8g98 vuln tag $empty"
expect_eq "$(gitx "$TREPO" rev-parse '8.2.4^{commit}')" 05da9137527cb7be236bb8e63f1c3b0dffcc6b2a tag824
gitx "$TREPO" merge-base --is-ancestor "$F8" '8.2.4^{commit}' || fail "8g98 fix not in 8.2.4"
if gitx "$TREPO" grep -q token_used_at "$C8" -- "$IDX"; then fail "vh5j parent has token"; fi
gitx "$TREPO" grep -q token_used_at "$F8" -- "$IDX" || fail "vh5j cand token"
if gitx "$TREPO" grep -q 'token_used_at IS NULL' "$F8" -- "$IDX"; then fail "vh5j cand already atomic"; fi
expect_eq "$(gitx "$TREPO" rev-list --parents -n 1 "$FV")" "$FV f4d210457781256860c0779cc2090f957d1ebf3d" vh5j_fix_parents
expect_eq "$(gitx "$TREPO" rev-parse "${FV}:$IDX")" 4cc255d79c158e4f2552ac1f7efcf0742bbedd81 vh5j_fix_blob
gitx "$TREPO" grep -q 'token_used_at IS NULL' "$FV" -- "$IDX" || fail "vh5j fix atomic"
empty=$(gitx "$TREPO" tag --contains "$F8" --no-contains "$FV")
[[ -z $empty ]] || fail "vh5j vuln tag $empty"
D812=d6f5477f05ed015a3846ff282dd31423af730ed2
gitx "$TREPO" merge-base --is-ancestor "$F8" "$D812" || fail "d812 missing cand"
if gitx "$TREPO" merge-base --is-ancestor "$FV" "$D812"; then fail "d812 already has closer"; fi
d812tags=$(gitx "$TREPO" tag --points-at "$D812")
[[ -z $d812tags ]] || fail "d812 is a tag"
echo 8G98_VH5J_OK

HCAND=e08547bcdb42aaa86190c6e2dfc64159fcd3a146
HPARENT=9f7c1b36d698845ea8bd968ad7446550995a2a3d
HFIX=1e66c78c4ce6ea294ac6b0eb289a9eae9c5e9579
expect_eq "$(gitx "$BREPO" rev-list --parents -n 1 "$HCAND")" "$HCAND $HPARENT" h2_parents
expect_eq "$(gitx "$BREPO" rev-parse "${HCAND}^{tree}")" 98e79e9a9233d08fe614e5dcf860be77d5270377 h2_tree
git_path_absent "$BREPO" "${HPARENT}:auth.js"
expect_eq "$(gitx "$BREPO" rev-parse "${HCAND}:auth.js")" e9729ced5fc86193f3bb7705776def88f960dc22 h2_cand_blob
expect_eq "$(gitx "$BREPO" rev-parse "${HFIX}:auth.js")" 24f6ccebb1a188a4e45d966da45bb90fe4fb12f9 h2_fix_blob
gitx "$BREPO" grep -q 'exec(`${command} "${url}"`' "$HCAND" -- auth.js || fail "h2 cand exec"
if gitx "$BREPO" grep -q 'exec(`${command} "${url}"`' "$HFIX" -- auth.js; then fail "h2 fix still exec"; fi
gitx "$BREPO" grep -q 'spawn(command, args' "$HFIX" -- auth.js || fail "h2 fix spawn"
hbody=$(gitx "$BREPO" log -1 --format='%B' "$HCAND")
print -r -- "$hbody" | /usr/bin/grep -q 'Generated with' || fail "h2 generated with"
print -r -- "$hbody" | /usr/bin/grep -q 'Co-Authored-By: Claude <noreply@anthropic.com>' || fail "h2 claude trailer"
htag=$(gitx "$BREPO" tag | /usr/bin/wc -l | /usr/bin/tr -d ' ')
expect_eq "$htag" 0 h2_local_tags
echo H2V8_OK

GCAND=af88b1f5d82844a4761ea9a977156c98e2b14ca8
GPARENT=5a7d56e2235d63441a23c54dc85ecffcbfe7cf44
GFIX=385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7
GRPC=packages/browser/src/node/rpc.ts
expect_eq "$(gitx "$VREPO" rev-list --parents -n 1 "$GCAND")" "$GCAND $GPARENT" g8_parents
expect_eq "$(gitx "$VREPO" rev-list --parents -n 1 "$GFIX")" "$GFIX $GCAND" g8_fix_parents
expect_eq "$(gitx "$VREPO" rev-parse "${GPARENT}:${GRPC}")" 7619c5f0fc4b66ea0992e61e357331c6280e4a29 g_parent_rpc
expect_eq "$(gitx "$VREPO" rev-parse "${GCAND}:${GRPC}")" 358ac355f89983297c18932c68e5aea7d78020ea g_cand_rpc
expect_eq "$(gitx "$VREPO" rev-parse "${GFIX}:${GRPC}")" 72818584f0669b58db74b6e093e04173c083293e g_fix_rpc
expect_eq "$(gitx "$VREPO" rev-parse 'v3.2.4^{commit}')" c666d149a4516761bae92ca56ce1336d2fd352c3 g324
expect_eq "$(gitx "$VREPO" rev-parse 'v3.2.5^{commit}')" 2cbad0a923c48c6144266df3cd25f93547cb5221 g325
expect_eq "$(gitx "$VREPO" rev-parse "v3.2.4:${GRPC}")" 7619c5f0fc4b66ea0992e61e357331c6280e4a29 g324_rpc
expect_eq "$(gitx "$VREPO" rev-parse "v3.2.5:${GRPC}")" 72818584f0669b58db74b6e093e04173c083293e g325_rpc
if gitx "$VREPO" merge-base --is-ancestor "$GCAND" 'v3.2.4^{commit}'; then fail "candidate ancestor of v3.2.4"; fi
gitx "$VREPO" merge-base --is-ancestor "$GCAND" 'v3.2.5^{commit}' || fail "candidate not in v3.2.5"
gitx "$VREPO" merge-base --is-ancestor "$GFIX" 'v3.2.5^{commit}' || fail "fix not in v3.2.5"
empty=$(gitx "$VREPO" tag --contains "$GCAND" --no-contains "$GFIX")
[[ -z $empty ]] || fail "g8 residual tags $empty"
rpc_log=$(gitx "$VREPO" log --format='%H' v3.2.4..v3.2.5 -- "$GRPC")
expect_eq "$(print -r -- "$rpc_log")" "$GFIX
$GCAND" g_rpc_log
gbody=$(gitx "$VREPO" log -1 --format='%B' "$GCAND")
print -r -- "$gbody" | /usr/bin/grep -q 'Co-authored-by: Codex <noreply@openai.com>' || fail "g8 codex trailer"
if gitx "$VREPO" grep -q allowWrite "$GPARENT" -- "$GRPC"; then fail "parent has allowWrite"; fi
gitx "$VREPO" grep -q 'function canWrite' "$GCAND" -- "$GRPC" || fail "cand missing canWrite"
if gitx "$VREPO" grep -q assertCdpAllowed "$GCAND" -- "$GRPC"; then fail "cand already gates CDP"; fi
gitx "$VREPO" grep -q assertCdpAllowed "$GFIX" -- "$GRPC" || fail "fix missing assertCdpAllowed"
gitx "$VREPO" grep -q assertCdpAllowed 'v3.2.7^{commit}' -- "$GRPC" || fail "v3.2.7 lost assertCdpAllowed"
echo G8MR_OK

echo "== live npm/pypi/crates/docker pins =="
curlq() {
  local out=$1 url=$2
  /usr/bin/curl -sS -L --max-time 40 -A "$UA" -o "$out" "$url" || fail "curl $url"
}

curlq "$REPLAY_TMP/npm-taylored.json" https://registry.npmjs.org/taylored
curlq "$REPLAY_TMP/npm-evernote.json" https://registry.npmjs.org/evernote-mcp-server
curlq "$REPLAY_TMP/npm-scoped.json" https://registry.npmjs.org/@brentmid/evernote-mcp-server
curlq "$REPLAY_TMP/pypi-evernote.json" https://pypi.org/pypi/evernote-mcp-server/json
curlq "$REPLAY_TMP/crates-taylored.json" https://crates.io/api/v1/crates/taylored
curlq "$REPLAY_TMP/docker-brentmid.json" https://hub.docker.com/v2/repositories/brentmid/evernote-mcp-server/
expect_hash "$REPLAY_TMP/npm-taylored.json" 2084ea76b9723ec0663c633b3f0bf37fb61fc6edf93021a7123de46d33a711ca
expect_hash "$REPLAY_TMP/npm-evernote.json" fb6e9147b8d787b213a5fe9576c8c30a75197008bf4c63842eb7d607f2cc2422
expect_hash "$REPLAY_TMP/npm-scoped.json" c8d3eae160a892e32837db3dcae515e843e5383fef52b8141940c8bcf8b6d59f
expect_hash "$REPLAY_TMP/pypi-evernote.json" b82014934f66beeb9e05a37f65357c4b50db0349d25d68d818ed0319dd4feb40
expect_hash "$REPLAY_TMP/crates-taylored.json" 14e35833fcf1767de5973303c41ffcddd709d10d1be64d89ce19b808b1b07a6c
expect_hash "$REPLAY_TMP/docker-brentmid.json" 80019e0eccb66899c98d834b3cb71c777f67f5724ec63cc7ce355350e28da5e7

fetch_tgz() {
  local out=$1 url=$2 want=$3
  /usr/bin/curl -sS -L --max-time 40 -A "$UA" -o "$out" "$url" || fail "tgz $url"
  expect_hash "$out" "$want"
}

fetch_tgz "$REPLAY_TMP/taylored-8.2.4.tgz" https://registry.npmjs.org/taylored/-/taylored-8.2.4.tgz 932bd516fdc4e42ba349cd5c2fd3937021bb0a731eb593262d1807df811ef9ec
fetch_tgz "$REPLAY_TMP/evernote-0.0.2.tgz" https://registry.npmjs.org/evernote-mcp-server/-/evernote-mcp-server-0.0.2.tgz f3caba45b2d68a4be472ab2b880b62dbb7a687ed4a0932b32090d197b980b0cc
fetch_tgz "$REPLAY_TMP/evernote-0.0.3.tgz" https://registry.npmjs.org/evernote-mcp-server/-/evernote-mcp-server-0.0.3.tgz 098f5a1d96317cab57c258708853a9d95b19c573b7cc9c1c4a664088f9efcc9e
fetch_tgz "$REPLAY_TMP/browser-3.2.4.tgz" https://registry.npmjs.org/@vitest/browser/-/browser-3.2.4.tgz a24c6adef75dbebadbadbb1eef2723ad5dd44e4c3509e4c46370310646cb5f38
fetch_tgz "$REPLAY_TMP/browser-3.2.5.tgz" https://registry.npmjs.org/@vitest/browser/-/browser-3.2.5.tgz 0f4e1678d753e9f0cd70d0f29326561dafcb1242156b8010fa83c914fb19120b
fetch_tgz "$REPLAY_TMP/browser-3.2.6.tgz" https://registry.npmjs.org/@vitest/browser/-/browser-3.2.6.tgz c23deb91c38711dad513b2f427c50b77a1c8b1a8551969fb6495920fbf6306df
fetch_tgz "$REPLAY_TMP/browser-3.2.7.tgz" https://registry.npmjs.org/@vitest/browser/-/browser-3.2.7.tgz 1ef783d2c8e73419dd867309fe89cef319b240585660d83b6a78c0005129f4f6

python3 - "$REPLAY_TMP" <<'PY' || fail "artifact contents"
import json, tarfile, sys
from pathlib import Path
w=Path(sys.argv[1])
d=json.loads((w/"npm-taylored.json").read_text())
assert d["name"]=="taylored"
assert list(d.get("versions") or {})==["8.2.4"]
assert d["versions"]["8.2.4"]["gitHead"]=="9b3bb75b8c1b740f0b77cb1389994e3219f0e527"
for k in ("7.0.5","7.0.8","8.1.2","8.1.3"):
    assert k in (d.get("time") or {})
    assert k not in (d.get("versions") or {})
e=json.loads((w/"npm-evernote.json").read_text())
assert e["name"]=="evernote-mcp-server"
assert (e.get("author") or {}).get("name")=="yasuhiroki"
assert set(e.get("versions") or {})=={"0.0.2","0.0.3"}
assert json.loads((w/"npm-scoped.json").read_text())=={"error":"Not found"}
assert json.loads((w/"pypi-evernote.json").read_text())=={"message":"Not Found"}
assert "does not exist" in (w/"crates-taylored.json").read_text()
assert json.loads((w/"docker-brentmid.json").read_text())["message"]=="object not found"

def text_of(path):
    tf=tarfile.open(path, "r:gz")
    blob=b""
    names=tf.getnames()
    for m in tf.getmembers():
        if m.isfile() and m.size<2_000_000:
            blob += tf.extractfile(m).read()
    return names, blob.decode("utf-8","replace")

names, t = text_of(w/"taylored-8.2.4.tgz")
assert "package/dist/templates/backend-in-a-box/index.js" in names
assert "verify-webhook-signature" in t
assert "token_used_at IS NULL" in t
assert "webhookEvent = req.body" not in t
for ver, p in (("0.0.2", w/"evernote-0.0.2.tgz"), ("0.0.3", w/"evernote-0.0.3.tgz")):
    names, t = text_of(p)
    assert not any(n.endswith("auth.js") for n in names)
    pj=json.loads(tarfile.open(p,"r:gz").extractfile("package/package.json").read())
    assert pj["name"]=="evernote-mcp-server" and pj["version"]==ver
    assert "yasuhiroki" in str(pj.get("author"))
rows=[
 (w/"browser-3.2.4.tgz","3.2.4", False, False, True),
 (w/"browser-3.2.5.tgz","3.2.5", True, True, True),
 (w/"browser-3.2.6.tgz","3.2.6", True, True, True),
 (w/"browser-3.2.7.tgz","3.2.7", True, True, True),
]
for path, ver, has_aw, has_cdp, has_send in rows:
    names, t = text_of(path)
    pj=json.loads(tarfile.open(path,"r:gz").extractfile("package/package.json").read())
    assert pj["name"]=="@vitest/browser" and pj["version"]==ver
    assert ("allowWrite" in t) is has_aw
    assert ("isCdpAllowed" in t) is has_cdp
    assert ("sendCdpEvent" in t) is has_send
print("artifacts_ok")
PY

python3 - "$OWNED" <<'PY' || fail "artifact_hashes"
import hashlib, json, sys
from pathlib import Path
d=Path(sys.argv[1])
res=json.loads((d/"result.json").read_text())
for name in ("assignment.jsonl","cases.jsonl","report.md","replay.zsh"):
    got=hashlib.sha256((d/name).read_bytes()).hexdigest()
    want=res["artifact_hashes"][name]
    if got!=want:
        print("ARTIFACT_HASH_FAIL", name, got, want)
        raise SystemExit(1)
print("ARTIFACT_HASH_OK")
PY

python3 - "$OWNED" <<'PY' || fail "durable extras"
from pathlib import Path
import sys
d=Path(sys.argv[1])
allowed={"assignment.jsonl","cases.jsonl","result.json","report.md","replay.zsh"}
names={p.name for p in d.iterdir()}
extra=names-allowed
if extra:
    raise SystemExit("extra " + ",".join(sorted(extra)))
print("hygiene_ok")
PY

print -r -- "REPLAY_OK reviewed=4 PASS_proposal=0 NARROW=4 REJECT=0 UNKNOWN=0 packet_delta=0 canonical_strict=91"
