#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-commitonly-h2v8-vitest-grok46-high.
# English only. No credentials. No canonical edit. mktemp caches removed.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
unset GIT_NO_LAZY_FETCH

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-commitonly-h2v8-vitest-grok46-high
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json
ADV_UN=/home/hanqing/.cache/cve-analyzer/advisory-database
H2_ADV=$ADV_UN/advisories/unreviewed/2025/11/GHSA-h2v8-4c3f-vqgv/GHSA-h2v8-4c3f-vqgv.json
G8_ADV=$ADV_UN/advisories/github-reviewed/2026/06/GHSA-g8mr-85jm-7xhm/GHSA-g8mr-85jm-7xhm.json
HCLONE=/home/hanqing/.cache/cve-analyzer/repos/brentmid_evernote-mcp-server
VCLONE=/home/hanqing/.cache/cve-analyzer/repos/vitest-dev_vitest
git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)
UA=ai-slop-research/commitonly-h2v8-vitest

HPARENT=9f7c1b36d698845ea8bd968ad7446550995a2a3d
HCAND=e08547bcdb42aaa86190c6e2dfc64159fcd3a146
HFIX=1e66c78c4ce6ea294ac6b0eb289a9eae9c5e9579
HTREE=98e79e9a9233d08fe614e5dcf860be77d5270377
HBLOB_CAND=e9729ced5fc86193f3bb7705776def88f960dc22
HBLOB_FIXP=9cbeb76daf6fc36e57808f0d48fb8d79412e3d6e
HBLOB_FIX=24f6ccebb1a188a4e45d966da45bb90fe4fb12f9

GPARENT=5a7d56e2235d63441a23c54dc85ecffcbfe7cf44
GCAND=af88b1f5d82844a4761ea9a977156c98e2b14ca8
GFIX=385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7
GRPC=packages/browser/src/node/rpc.ts
GBLOB_PAR=7619c5f0fc4b66ea0992e61e357331c6280e4a29
GBLOB_CAND=358ac355f89983297c18932c68e5aea7d78020ea
GBLOB_FIX=72818584f0669b58db74b6e093e04173c083293e
G324=c666d149a4516761bae92ca56ce1336d2fd352c3
G325=2cbad0a923c48c6144266df3cd25f93547cb5221

fail() { print -r -- "REPLAY_FAIL $*" >&2; exit 1 }

expect_eq() {
  if [[ $1 != "$2" ]]; then
    print -r -- "mismatch $3 expected=$2 got=$1" >&2
    exit 1
  fi
}

expect_hash() {
  local got
  got=$(/usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}')
  expect_eq "$got" "$2" "$1"
}

gitx() {
  local repo=$1
  shift
  "${git_cmd[@]}" -C "$repo" "$@" 2>/dev/null
}

require_file() { [[ -f $1 ]] || fail "missing $1" }
require_dir() { [[ -d $1 ]] || fail "missing $1" }

require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/result.json"
require_file "$OWNED/report.md"
require_file "$OWNED/replay.zsh"
require_file "$CONTRACT"
require_file "$LEDGER"
require_file "$SUMMARY"
require_file "$H2_ADV"
require_file "$G8_ADV"
require_dir "$HCLONE"
require_dir "$VCLONE"

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  python3 - "$OWNED/$f" <<'PY' || fail "ascii $f"
import sys
b=open(sys.argv[1],"rb").read()
if b"\x00" in b: raise SystemExit(1)
b.decode("ascii")
if b.endswith(b" ") or b" \n" in b: raise SystemExit(1)
PY
done

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
expect_hash "$SUMMARY" 81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921
expect_hash "$H2_ADV" eea310ecbf64f4e0d5b929965eb3c32a4fbb2c422ee62a4654655bad9883607b
expect_hash "$G8_ADV" 8a284425df6d7e2b2ba1cb99dc7c700dd0a519f1adab46427015be91fbb5317f

n_assign=$(/usr/bin/wc -l < "$OWNED/assignment.jsonl" | /usr/bin/tr -d ' ')
n_cases=$(/usr/bin/wc -l < "$OWNED/cases.jsonl" | /usr/bin/tr -d ' ')
expect_eq "$n_assign" 2 assignment_rows
expect_eq "$n_cases" 2 cases_rows

python3 - "$OWNED" "$SUMMARY" "$H2_ADV" "$G8_ADV" <<'PY' || fail "python conservation"
import hashlib, json, sys
from pathlib import Path
owned, summary_p, h2adv, g8adv = map(Path, sys.argv[1:])
assigns=[json.loads(l) for l in owned.joinpath("assignment.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l) for l in owned.joinpath("cases.jsonl").read_text().splitlines() if l.strip()]
res=json.loads(owned.joinpath("result.json").read_text())
report=owned.joinpath("report.md").read_text()
assert all(ord(c) < 128 for c in report)
assert len(assigns)==2 and len(cases)==2
assert [a["case_id"] for a in assigns]==["GHSA-H2V8-4C3F-VQGV","GHSA-G8MR-85JM-7XHM"]
assert [c["case_id"] for c in cases]==["GHSA-H2V8-4C3F-VQGV","GHSA-G8MR-85JM-7XHM"]
CAUSAL=["identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","uniqueness_gate"]
for c in cases:
    assert all(c["gates"][k]=="PASS" for k in CAUSAL)
    assert c["causal_six_all_pass"] is True
    assert c["proposed_pass"] is True
    assert c["countable"] is False
    assert c["n_parents"]==1
    assert c["did_not_inherit_prior_packets"] is True
    assert int(hashlib.sha256(c["case_id"].encode("ascii")).hexdigest(),16)%6 == { "GHSA-H2V8-4C3F-VQGV":2, "GHSA-G8MR-85JM-7XHM":4 }[c["case_id"]]
h2,g8=cases
assert h2["gates"]["release_gate"]=="UNKNOWN"
assert g8["gates"]["release_gate"]=="NARROW"
assert h2["candidate_set"]==["e08547bcdb42aaa86190c6e2dfc64159fcd3a146"]
assert h2["minimum_fix_set"]==["1e66c78c4ce6ea294ac6b0eb289a9eae9c5e9579"]
assert g8["candidate_set"]==["af88b1f5d82844a4761ea9a977156c98e2b14ca8"]
assert g8["minimum_fix_set"]==["385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7"]
assert g8["older_ungated_cdp_is_out_of_scope"] is True
assert h2["release_evidence"]["brentmid_shipped_any_artifact"] is False
assert g8["release_evidence"]["same_first_tag"] is True
assert res["counts"]["PASS"]==0
assert res["counts"]["PASS_PROPOSAL"]==2
assert res["conservation"]["equation"]=="2=2+0"
assert res["canonical88_strict_count"]==88
assert res["canonical_ledger_edited"] is False
assert res["did_not_commit_or_push"] is True
summary=json.loads(summary_p.read_text())
counted={str(x).upper() for x in summary["strict_released_case_ids"]}
assert len(counted)==88
assert "GHSA-H2V8-4C3F-VQGV" not in counted
assert "GHSA-G8MR-85JM-7XHM" not in counted
h2a=json.loads(h2adv.read_text())
assert h2a["id"]=="GHSA-h2v8-4c3f-vqgv"
assert "CVE-2025-12489" in h2a["aliases"]
assert h2a["database_specific"]["github_reviewed"] is False
assert any("1e66c78c4ce6ea294ac6b0eb289a9eae9c5e9579" in (r.get("url") or "") for r in h2a["references"])
g8a=json.loads(g8adv.read_text())
assert g8a["id"]=="GHSA-g8mr-85jm-7xhm"
assert "CVE-2026-53633" in g8a["aliases"]
assert g8a["database_specific"]["github_reviewed"] is True
print("conservation_ok")
PY

expect_eq "$(gitx "$HCLONE" cat-file -t "$HPARENT")" commit h_parent_type
expect_eq "$(gitx "$HCLONE" cat-file -t "$HCAND")" commit h_cand_type
expect_eq "$(gitx "$HCLONE" cat-file -t "$HFIX")" commit h_fix_type
expect_eq "$(gitx "$HCLONE" rev-parse "${HCAND}^{tree}")" "$HTREE" h_cand_tree
expect_eq "$(gitx "$HCLONE" rev-list --parents -n 1 "$HCAND")" "$HCAND $HPARENT" h_cand_parents
gitx "$HCLONE" merge-base --is-ancestor "$HCAND" "$HFIX" || fail "h2 candidate not ancestor of fix"
if "${git_cmd[@]}" -C "$HCLONE" cat-file -e "${HPARENT}:auth.js" >/dev/null 2>&1; then fail "h2 parent has auth.js"; fi
expect_eq "$(gitx "$HCLONE" rev-parse "${HCAND}:auth.js")" "$HBLOB_CAND" h_cand_auth
expect_eq "$(gitx "$HCLONE" rev-parse "${HFIX}^:auth.js")" "$HBLOB_FIXP" h_fixp_auth
expect_eq "$(gitx "$HCLONE" rev-parse "${HFIX}:auth.js")" "$HBLOB_FIX" h_fix_auth
gitx "$HCLONE" grep -q 'exec(`${command} "${url}"`' "$HCAND" -- auth.js || fail "h2 candidate missing exec"
if gitx "$HCLONE" grep -q 'exec(`${command} "${url}"`' "$HFIX" -- auth.js; then fail "h2 fix still has exec"; fi
gitx "$HCLONE" grep -q 'spawn(command, args' "$HFIX" -- auth.js || fail "h2 fix missing spawn"
hbody=$(gitx "$HCLONE" log -1 --format='%B' "$HCAND")
print -r -- "$hbody" | /usr/bin/grep -q 'Generated with' || fail "h2 candidate missing Generated with"
print -r -- "$hbody" | /usr/bin/grep -q 'Co-Authored-By: Claude <noreply@anthropic.com>' || fail "h2 candidate missing Claude trailer"
htag=$(gitx "$HCLONE" tag | /usr/bin/wc -l | /usr/bin/tr -d ' ')
expect_eq "$htag" 0 h2_local_tags
hremote=$(gitx "$HCLONE" ls-remote --tags origin | /usr/bin/wc -l | /usr/bin/tr -d ' ')
expect_eq "$hremote" 0 h2_origin_tags

expect_eq "$(gitx "$VCLONE" rev-list --parents -n 1 "$GCAND")" "$GCAND $GPARENT" g_cand_parents
expect_eq "$(gitx "$VCLONE" rev-list --parents -n 1 "$GFIX")" "$GFIX $GCAND" g_fix_parents
expect_eq "$(gitx "$VCLONE" rev-parse "${GPARENT}:${GRPC}")" "$GBLOB_PAR" g_parent_rpc
expect_eq "$(gitx "$VCLONE" rev-parse "${GCAND}:${GRPC}")" "$GBLOB_CAND" g_cand_rpc
expect_eq "$(gitx "$VCLONE" rev-parse "${GFIX}:${GRPC}")" "$GBLOB_FIX" g_fix_rpc
expect_eq "$(gitx "$VCLONE" rev-parse "v3.2.4^{commit}")" "$G324" g_324_peel
expect_eq "$(gitx "$VCLONE" rev-parse "v3.2.5^{commit}")" "$G325" g_325_peel
expect_eq "$(gitx "$VCLONE" rev-parse "v3.2.4:${GRPC}")" "$GBLOB_PAR" g_324_rpc
expect_eq "$(gitx "$VCLONE" rev-parse "v3.2.5:${GRPC}")" "$GBLOB_FIX" g_325_rpc
if gitx "$VCLONE" merge-base --is-ancestor "$GCAND" "$G324"; then fail "candidate must not be ancestor of v3.2.4"; fi
gitx "$VCLONE" merge-base --is-ancestor "$GCAND" "$G325" || fail "candidate not ancestor of v3.2.5"
gitx "$VCLONE" merge-base --is-ancestor "$GFIX" "$G325" || fail "fix not ancestor of v3.2.5"
rpc_log=$(gitx "$VCLONE" log --format='%H' v3.2.4..v3.2.5 -- "$GRPC")
expect_eq "$(print -r -- "$rpc_log")" "$GFIX
$GCAND" g_rpc_log
gbody=$(gitx "$VCLONE" log -1 --format='%B' "$GCAND")
print -r -- "$gbody" | /usr/bin/grep -q 'Co-authored-by: Codex <noreply@openai.com>' || fail "g8 candidate missing Codex trailer"
if gitx "$VCLONE" grep -q 'allowWrite' "$GPARENT" -- "$GRPC"; then fail "parent rpc must lack allowWrite"; fi
gitx "$VCLONE" grep -q 'function canWrite' "$GCAND" -- "$GRPC" || fail "candidate missing canWrite"
if gitx "$VCLONE" grep -q 'assertCdpAllowed' "$GCAND" -- "$GRPC"; then fail "candidate must not gate CDP"; fi
gitx "$VCLONE" grep -q 'assertCdpAllowed' "$GFIX" -- "$GRPC" || fail "fix missing assertCdpAllowed"

WORKDIR=$(mktemp -d /tmp/h2g8-replay.XXXXXX)
cleanup() { rm -rf "$WORKDIR" }
trap cleanup EXIT

/usr/bin/curl -sS -L --max-time 25 -o "$WORKDIR/npm-h2.json" -A "$UA" 'https://registry.npmjs.org/evernote-mcp-server' || fail "h2 npm meta"
/usr/bin/curl -sS -L --max-time 25 -o "$WORKDIR/gh-rel.json" -A "$UA" -H 'Accept: application/vnd.github+json' 'https://api.github.com/repos/brentmid/evernote-mcp-server/releases' || fail "h2 gh releases"
/usr/bin/curl -sS -L --max-time 25 -o "$WORKDIR/gh-tags.json" -A "$UA" -H 'Accept: application/vnd.github+json' 'https://api.github.com/repos/brentmid/evernote-mcp-server/tags' || fail "h2 gh tags"
python3 - "$WORKDIR" <<'PY' || fail "h2 npm/github artifacts"
import hashlib, json, sys, tarfile, io, urllib.request
from pathlib import Path
w=Path(sys.argv[1])
d=json.loads((w/"npm-h2.json").read_text())
assert d["name"]=="evernote-mcp-server"
assert (d.get("author") or {}).get("name")=="yasuhiroki"
assert set(d.get("versions") or {})=={"0.0.2","0.0.3"}
def empty_or_api_error(p):
    try:
        obj=json.loads(p.read_text())
    except json.JSONDecodeError:
        return
    if isinstance(obj, list):
        assert obj==[]
    elif isinstance(obj, dict):
        assert "message" in obj
    else:
        raise AssertionError(p)
empty_or_api_error(w/"gh-rel.json")
empty_or_api_error(w/"gh-tags.json")
ua={"User-Agent":"ai-slop-research/commitonly-h2v8-vitest"}
want={"0.0.2":"f3caba45b2d68a4be472ab2b880b62dbb7a687ed4a0932b32090d197b980b0cc","0.0.3":"098f5a1d96317cab57c258708853a9d95b19c573b7cc9c1c4a664088f9efcc9e"}
for ver in ("0.0.2","0.0.3"):
    spec=d["versions"][ver]
    data=urllib.request.urlopen(urllib.request.Request(spec["dist"]["tarball"], headers=ua), timeout=30).read()
    assert hashlib.sha256(data).hexdigest()==want[ver], ver
    tf=tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    names=tf.getnames()
    assert not any(n.endswith("auth.js") for n in names)
    pj=json.loads(tf.extractfile("package/package.json").read())
    assert pj["name"]=="evernote-mcp-server" and pj["version"]==ver
    assert "yasuhiroki" in str(pj.get("author"))
print("h2_artifacts_ok")
PY

python3 - "$WORKDIR" <<'PY' || fail "g8 npm artifacts"
import hashlib, json, tarfile, io, urllib.request, sys
from pathlib import Path
w=Path(sys.argv[1])
ua={"User-Agent":"ai-slop-research/commitonly-h2v8-vitest"}
rows=[
 ("https://registry.npmjs.org/@vitest/browser/-/browser-3.2.4.tgz","a24c6adef75dbebadbadbb1eef2723ad5dd44e4c3509e4c46370310646cb5f38","@vitest/browser","3.2.4", False, False, True),
 ("https://registry.npmjs.org/@vitest/browser/-/browser-3.2.5.tgz","0f4e1678d753e9f0cd70d0f29326561dafcb1242156b8010fa83c914fb19120b","@vitest/browser","3.2.5", True, True, True),
 ("https://registry.npmjs.org/vitest/-/vitest-3.2.4.tgz","156342494358f193bcd24a94b2f947b0d133bd127bf97486d371d3d097073dcd","vitest","3.2.4", False, False, False),
 ("https://registry.npmjs.org/vitest/-/vitest-3.2.5.tgz","28a261aaba852876d36fe2a75565e2eff3e45085270f99cbb10e8a5f5dfc46f6","vitest","3.2.5", True, False, False),
]
for url, sha, name, ver, has_aw, has_cdp, has_send in rows:
    data=urllib.request.urlopen(urllib.request.Request(url, headers=ua), timeout=40).read()
    assert hashlib.sha256(data).hexdigest()==sha, (name, ver)
    tf=tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    pj=json.loads(tf.extractfile("package/package.json").read())
    assert pj["name"]==name and pj["version"]==ver
    text=b""
    for m in tf.getmembers():
        if m.isfile() and m.name.endswith((".js",".d.ts")) and m.size<2_000_000:
            text += tf.extractfile(m).read()
    t=text.decode("utf-8","replace")
    assert ("allowWrite" in t) is has_aw, (name, ver, "allowWrite")
    assert ("isCdpAllowed" in t) is has_cdp, (name, ver, "isCdpAllowed")
    assert ("sendCdpEvent" in t) is has_send, (name, ver, "sendCdpEvent")
print("g8_artifacts_ok")
PY

print -r -- "REPLAY_OK reviewed=2 PASS_proposal=2 REJECT=0 release_UNKNOWN=1 release_NARROW=1 packet_delta=0 canonical_strict=88"
