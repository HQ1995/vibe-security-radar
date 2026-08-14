#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-specifyjs-five-redteam-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# KEEP rows are proposals. This script does not admit any row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-specifyjs-five-redteam-grok46-xhigh
SP=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/asymmetric-effort__specifyjs

HTTPS=30f9b76f848b681e2806ac6ebcebebb055af3999
SAST=caa8fbfa4d7d99e02dca3ee0df642b30a5d856cc
FIX=25d1fb491d99479efdf501f5f75e0bb80c908f0a
V135=a84103e7dc3e3283279058d8f7e5a3c01a79fa3d
V134=4d98a9b87590b0045409b7b203dfcbf1787d90dd
HP=a2ee52acbf594fcbda6ed7ca6afb59c1c01d5b94
SPARENT=56749d121bcbc26d1905db2e326b808ef8cce02e
EF00=ef00e291d04420c8a9ef99949e1f95e76e615e9f

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
require_dir "$SP/objects"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"

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
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json" \
  699f6160b6ecb9c9ce2cdae257c9a12dbdf4f7ef8a925196fcfd4fcf0b1140d8
expect_hash "$ROOT/scripts/publication_adjudications.json" \
  9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-directroot-batch4-grok46-high/cases.jsonl" \
  53faf9d6eeb5a8aae901c8bd4c1ca40e04eb1c40062a54be078f6d56d28d8684
expect_hash "$OWNED/cases.jsonl" \
  35d68b458f8505bf116f5f46a7b5380b3a76306cbfd0a48d69aa473abb629fdf
expect_hash "$OWNED/report.md" \
  554296a3dff3f3f94203e9aeb91b9da0174d372926323d085ce6d1fb8ed062b3
expect_hash "$OWNED/pages/ghsa/GHSA-8882-FRVV-92W4.json" \
  f25e989839fe02bccb2fd13b09209aa1c4218d5cc859f886852bee724279d63c
expect_hash "$OWNED/pages/ghsa/GHSA-J5QP-P44G-2M49.json" \
  64ff5a754cff8841825dc5aef7a15239fdd8e2ad1e0cdf2b5a2d03a2744e0e53
expect_hash "$OWNED/pages/ghsa/GHSA-2944-57XV-2682.json" \
  9bbd5460d87b49def6ebe10c3e6387c4c0d9cbe3c9920c6fc52d1a189688ae9c
expect_hash "$OWNED/pages/ghsa/GHSA-5C7W-4WM3-85VW.json" \
  102ed9e384dbe7ad3cf3da1dd97460c6c457e00e3486504a0e069a3021d3e291
expect_hash "$OWNED/pages/ghsa/GHSA-93Q6-WWJH-JC6H.json" \
  7d16483cc2ca393001257edf1db18e27bf2f0d4f384433ceb8ed96e250c6c3a8
expect_hash "$OWNED/pages/npm/_asymmetric-effort_specifyjs_0.2.135.json" \
  1afdadd1f09e321c56a046166056316ed9786a2af9073fd540c6bbf3350a34f2
expect_hash "$OWNED/pages/npm/_asymmetric-effort_specifyjs_0.2.136.json" \
  6aafc8347a91a7340c66d796cc1753b6f39b5e63ecf047cb612b94930dc77f73
expect_hash "$OWNED/pages/npm/_asymmetric-effort_specifyjs_0.2.134.json" \
  158c5e689da64efbb71a5ce48844d4a4321045e8a363719f85b473e34cbd6236
expect_hash "$OWNED/pages/releases/specifyjs_tagobj_v0.2.135.json" \
  00561f543d591deab3ee07e77cf78c688e703574e95ba06b23550b8a9a2ad47e
expect_hash "$OWNED/pages/releases/specifyjs_tagobj_v0.2.136.json" \
  cdbb16be1c232ece841e8089d204147351ee286030f1853451e197570d99b1bc
expect_hash "$OWNED/pages/repo-advisory/asymmetric-effort__specifyjs__GHSA-8882-FRVV-92W4.json" \
  edbd0367cec893df36f67acb56c3aa23810be28850977c35e0fedaf64aad286b
expect_hash "$OWNED/snapshot/tarballs/specifyjs-0.2.135.tgz" \
  06ef2f4f36baf2ba1be086bcd782171cbfb81477bddc25acc685b8a652fffa1c
expect_hash "$OWNED/snapshot/tarballs/specifyjs-0.2.136.tgz" \
  924ad43cf57d1dcefeaec15b4a7fa53794fb50f5f365d62ac8c643cd34c78d10

python3 - "$OWNED/cases.jsonl" "$ROOT/autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json" "$OWNED" << 'PY'
import json, re, tarfile, sys
from pathlib import Path

assigned = [
    "GHSA-8882-FRVV-92W4",
    "GHSA-J5QP-P44G-2M49",
    "GHSA-2944-57XV-2682",
    "GHSA-5C7W-4WM3-85VW",
    "GHSA-93Q6-WWJH-JC6H",
]
https = "30f9b76f848b681e2806ac6ebcebebb055af3999"
sast = "caa8fbfa4d7d99e02dca3ee0df642b30a5d856cc"
fix = "25d1fb491d99479efdf501f5f75e0bb80c908f0a"
v135 = "a84103e7dc3e3283279058d8f7e5a3c01a79fa3d"
v134 = "4d98a9b87590b0045409b7b203dfcbf1787d90dd"
rows = [json.loads(l) for l in Path(sys.argv[1]).read_text().splitlines() if l.strip()]
assert len(rows) == 5, len(rows)
ids = [r["case_id"] for r in rows]
assert ids == assigned
assert all(r["verdict"] == "KEEP" for r in rows)
assert all(r["causal_admission"] is False for r in rows)
assert all(r["countable"] is False for r in rows)
assert all(r["countable_proposal"] is True for r in rows)
assert all(r["publication_status"] == "HOLD" for r in rows)
assert all(r["contribution_class"] == "AI_INCOMPLETE_REMEDIATION" for r in rows)
assert all(r["cartesian_candidate_fix_refused"] is True for r in rows)
gates = [
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
]
for r in rows:
    assert r["failing_gates"] == []
    assert r["remediation_patch_delta_gate"] == "PASS"
    for g in gates:
        assert r[g] == "PASS", (r["case_id"], g, r[g])
assert rows[0]["candidate_set"] == [https]
assert rows[1]["candidate_set"] == [https]
assert rows[2]["candidate_set"] == [https]
assert rows[3]["candidate_set"] == [sast]
assert rows[4]["candidate_set"] == [sast]
assert all(r["minimum_fix_set"] == [fix] for r in rows)
assert rows[0]["aliases"] == ["CVE-2026-50288"]
assert rows[4]["aliases"] == ["CVE-2026-50290"]
assert rows[1]["aliases"] == []
assert len({r["mechanism_key"] for r in rows}) == 5
han = re.compile(r"[\u3400-\u9fff]")
owned = Path(sys.argv[3])
for name in ("cases.jsonl", "report.md", "replay.sh"):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert not han.search(text), name
c73 = json.loads(Path(sys.argv[2]).read_text())
cids = set(c73["strict_released_case_ids"])
assert len(cids) == 73
assert not any(i in cids for i in assigned)
for i in assigned:
    g = json.loads((owned / "pages/ghsa" / f"{i}.json").read_text())
    assert g.get("type") == "reviewed"
    assert g.get("withdrawn_at") in (None, "")
    assert g.get("source_code_location") == "https://github.com/asymmetric-effort/specifyjs"
    vulns = g.get("vulnerabilities") or []
    assert vulns
    assert vulns[0]["package"]["name"] == "@asymmetric-effort/specifyjs"
    assert vulns[0]["first_patched_version"] == "0.2.136"
repo404 = json.loads((owned / "pages/repo-advisory/asymmetric-effort__specifyjs__GHSA-8882-FRVV-92W4.json").read_text())
assert repo404.get("message") == "Not Found" or repo404.get("status") == "404"
rel404 = json.loads((owned / "pages/releases/specifyjs_v0.2.135.json").read_text())
assert rel404.get("status") == "404" or rel404.get("message") == "Not Found"
npm135 = json.loads((owned / "pages/npm/_asymmetric-effort_specifyjs_0.2.135.json").read_text())
npm136 = json.loads((owned / "pages/npm/_asymmetric-effort_specifyjs_0.2.136.json").read_text())
npm134 = json.loads((owned / "pages/npm/_asymmetric-effort_specifyjs_0.2.134.json").read_text())
assert npm135["name"] == "@asymmetric-effort/specifyjs"
assert npm135["gitHead"] == v135
assert npm136["gitHead"] == fix
assert npm134["gitHead"] == v134
tag135 = json.loads((owned / "pages/releases/specifyjs_tagobj_v0.2.135.json").read_text())
tag136 = json.loads((owned / "pages/releases/specifyjs_tagobj_v0.2.136.json").read_text())
tag134 = json.loads((owned / "pages/releases/specifyjs_tagobj_v0.2.134.json").read_text())
assert tag135["object"]["sha"] == v135
assert tag136["object"]["sha"] == fix
assert tag134["object"]["sha"] == v134
assert tag135["tag"] == "v0.2.135"
assert tag136["tag"] == "v0.2.136"

def tarball_has(archive, needle):
    with tarfile.open(archive, "r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            if m.name.endswith((".map",)):
                continue
            f = tf.extractfile(m)
            if f is None:
                continue
            data = f.read()
            if needle.encode("utf-8") in data:
                return True
    return False

t135 = owned / "snapshot/tarballs/specifyjs-0.2.135.tgz"
t136 = owned / "snapshot/tarballs/specifyjs-0.2.136.tgz"
assert tarball_has(t135, "Interpolated value contains GraphQL metacharacters")
assert not tarball_has(t135, "unable to validate URL")
assert not tarball_has(t135, "data: URI exceeds 1MB")
assert not tarball_has(t135, 'redirect: "error"')
assert not tarball_has(t135, "normalizedCss")
assert tarball_has(t136, "unable to validate URL")
assert tarball_has(t136, "data: URI exceeds 1MB")
assert tarball_has(t136, 'redirect: "error"')
assert tarball_has(t136, "normalizedCss")
assert not tarball_has(t136, "Interpolated value contains GraphQL metacharacters")
reviewed, unreviewed = 5, 0
assigned_n = 5
assert assigned_n == reviewed + unreviewed
print("conservation assigned=5 reviewed=5 unreviewed=0 KEEP_proposal=5 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0")
PY

# Markers and parent counts.
"${git_cmd[@]}" -C "$SP" log -1 --format='%B' "$HTTPS" | grep -F 'Co-Authored-By: Claude Opus 4.6' >/dev/null
"${git_cmd[@]}" -C "$SP" log -1 --format='%B' "$SAST" | grep -F 'Co-Authored-By: Claude Opus 4.6' >/dev/null
[[ "$("${git_cmd[@]}" -C "$SP" rev-list --parents -n 1 "$HTTPS" | awk '{print NF-1}')" == 1 ]]
[[ "$("${git_cmd[@]}" -C "$SP" rev-list --parents -n 1 "$SAST" | awk '{print NF-1}')" == 1 ]]
[[ "$("${git_cmd[@]}" -C "$SP" rev-list --parents -n 1 "$FIX" | awk '{print NF-1}')" == 1 ]]
parents_https=$("${git_cmd[@]}" -C "$SP" rev-parse "${HTTPS}^@")
printf '%s\n' "$parents_https" | grep -Fx "$HP" >/dev/null
parents_sast=$("${git_cmd[@]}" -C "$SP" rev-parse "${SAST}^@")
printf '%s\n' "$parents_sast" | grep -Fx "$SPARENT" >/dev/null
parents_fix=$("${git_cmd[@]}" -C "$SP" rev-parse "${FIX}^@")
printf '%s\n' "$parents_fix" | grep -Fx "$V135" >/dev/null

assert_ancestor "$SP" "$HTTPS" "$SAST"
assert_not_ancestor "$SP" "$SAST" "$HTTPS"
assert_ancestor "$SP" "$HTTPS" "$V134"
assert_ancestor "$SP" "$SAST" "$V134"
assert_ancestor "$SP" "$HTTPS" "$V135"
assert_ancestor "$SP" "$SAST" "$V135"
assert_not_ancestor "$SP" "$FIX" "$V134"
assert_not_ancestor "$SP" "$FIX" "$V135"
assert_ancestor "$SP" "$V135" "$FIX"
assert_ancestor "$SP" "$HTTPS" "$FIX"
assert_ancestor "$SP" "$SAST" "$FIX"

if "${git_cmd[@]}" -C "$SP" cat-file -e "${HP}:core/src/shared/secure-fetch.ts" 2>/dev/null; then
  printf 'parent unexpectedly has secure-fetch.ts\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$SP" cat-file -e "${HTTPS}:core/src/shared/secure-fetch.ts"

# Package names at candidates versus named npm package at residual/fix.
"${git_cmd[@]}" -C "$SP" show "${HTTPS}:core/package.json" | grep -F '"name": "liquidjs-framework"' >/dev/null
"${git_cmd[@]}" -C "$SP" show "${SAST}:core/package.json" | grep -F '"name": "specifyjs-framework"' >/dev/null
"${git_cmd[@]}" -C "$SP" show "${V135}:core/package.json" | grep -F '"name": "@asymmetric-effort/specifyjs"' >/dev/null
"${git_cmd[@]}" -C "$SP" show "${V135}:core/package.json" | grep -F '"version": "0.2.135"' >/dev/null
"${git_cmd[@]}" -C "$SP" show "${FIX}:core/package.json" | grep -F '"version": "0.2.136"' >/dev/null

# Blobs: gql identical from SAST through residual; secure-fetch identical 0.2.134==0.2.135.
[[ "$("${git_cmd[@]}" -C "$SP" rev-parse "${SAST}:core/src/client/graphql.ts")" == 83221c09acb250e9d325632d7993e96ab2ae8024 ]]
[[ "$("${git_cmd[@]}" -C "$SP" rev-parse "${V134}:core/src/client/graphql.ts")" == 83221c09acb250e9d325632d7993e96ab2ae8024 ]]
[[ "$("${git_cmd[@]}" -C "$SP" rev-parse "${V135}:core/src/client/graphql.ts")" == 83221c09acb250e9d325632d7993e96ab2ae8024 ]]
[[ "$("${git_cmd[@]}" -C "$SP" rev-parse "${FIX}:core/src/client/graphql.ts")" == 0830d4a185a1694dbaa78596813c661891064b72 ]]
[[ "$("${git_cmd[@]}" -C "$SP" rev-parse "${V134}:core/src/shared/secure-fetch.ts")" == 8f6e3bd37edcdca78470694874c65489fe81bc67 ]]
[[ "$("${git_cmd[@]}" -C "$SP" rev-parse "${V135}:core/src/shared/secure-fetch.ts")" == 8f6e3bd37edcdca78470694874c65489fe81bc67 ]]
[[ "$("${git_cmd[@]}" -C "$SP" rev-parse "${FIX}:core/src/shared/secure-fetch.ts")" == 7c630409816c180a15c65f8c2b66b5caf0581077 ]]
[[ "$("${git_cmd[@]}" -C "$SP" rev-parse "${V134}:core/src/server/render-to-string.ts")" == 7202c0e5a0d0dd064b927c27552da205d6c02e84 ]]
[[ "$("${git_cmd[@]}" -C "$SP" rev-parse "${V135}:core/src/server/render-to-string.ts")" == 7202c0e5a0d0dd064b927c27552da205d6c02e84 ]]
[[ "$("${git_cmd[@]}" -C "$SP" rev-parse "${FIX}:core/src/server/render-to-string.ts")" == 49f04dbb85ebf4f0b2d923c025ec28d83a4e560b ]]

# GHSA-8882: catch return owned by HTTPS, comment owned by later test.
"${git_cmd[@]}" -C "$SP" blame -l -w -L44,44 "$V135" -- core/src/shared/secure-fetch.ts | grep -q "$HTTPS"
"${git_cmd[@]}" -C "$SP" blame -l -w -L43,43 "$V135" -- core/src/shared/secure-fetch.ts | grep -q "$EF00"
"${git_cmd[@]}" -C "$SP" grep -F 'unable to validate URL' "$FIX" -- core/src/shared/secure-fetch.ts >/dev/null
if "${git_cmd[@]}" -C "$SP" grep -F 'unable to validate URL' "$V135" -- core/src/shared/secure-fetch.ts >/dev/null; then
  printf 'v0.2.135 unexpectedly throws on parse failure\n' >&2
  exit 1
fi

# GHSA-J5QP: fetch(input, init) owned by HTTPS; closer sets redirect:error.
"${git_cmd[@]}" -C "$SP" blame -l -w -L73,73 "$V135" -- core/src/shared/secure-fetch.ts | grep -q "$HTTPS"
"${git_cmd[@]}" -C "$SP" grep -F 'return fetch(input, init);' "$V135" -- core/src/shared/secure-fetch.ts >/dev/null
"${git_cmd[@]}" -C "$SP" grep -F "redirect: 'error'" "$FIX" -- core/src/shared/secure-fetch.ts >/dev/null
if "${git_cmd[@]}" -C "$SP" grep -F "redirect: 'error'" "$V135" -- core/src/shared/secure-fetch.ts >/dev/null; then
  printf 'v0.2.135 unexpectedly already has redirect error\n' >&2
  exit 1
fi

# GHSA-2944: data: allowlist owned by HTTPS.
"${git_cmd[@]}" -C "$SP" blame -l -w -L33,35 "$V135" -- core/src/shared/secure-fetch.ts | grep -q "$HTTPS"
"${git_cmd[@]}" -C "$SP" grep -F 'Data URLs are allowed' "$V135" -- core/src/shared/secure-fetch.ts >/dev/null
"${git_cmd[@]}" -C "$SP" grep -F 'data: URI exceeds 1MB' "$FIX" -- core/src/shared/secure-fetch.ts >/dev/null
if "${git_cmd[@]}" -C "$SP" grep -F 'data: URI exceeds 1MB' "$V135" -- core/src/shared/secure-fetch.ts >/dev/null; then
  printf 'v0.2.135 unexpectedly already caps data URIs\n' >&2
  exit 1
fi

# GHSA-5C7W: warn block owned by SAST; parent concatenated without warn.
"${git_cmd[@]}" -C "$SP" blame -l -w -L68,72 "$V135" -- core/src/client/graphql.ts | grep -q "$SAST"
"${git_cmd[@]}" -C "$SP" grep -F 'result += String(values[i]);' "$SPARENT" -- core/src/client/graphql.ts >/dev/null
if "${git_cmd[@]}" -C "$SP" grep -F 'console.warn' "$SPARENT" -- core/src/client/graphql.ts >/dev/null; then
  printf 'SAST parent unexpectedly already warns on gql interpolation\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$SP" grep -F 'console.warn' "$V135" -- core/src/client/graphql.ts >/dev/null
if "${git_cmd[@]}" -C "$SP" grep -F 'console.warn' "$FIX" -- core/src/client/graphql.ts >/dev/null; then
  printf 'closer still warns instead of throwing on gql interpolation\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$SP" grep -F 'contains GraphQL metacharacters' "$FIX" -- core/src/client/graphql.ts >/dev/null

# GHSA-93Q6: CSS strip owned by SAST; parent has none; closer normalizes.
"${git_cmd[@]}" -C "$SP" blame -l -w -L307,310 "$V135" -- core/src/server/render-to-string.ts | grep -q "$SAST"
if "${git_cmd[@]}" -C "$SP" grep -F 'expression\s*\(' "$SPARENT" -- core/src/server/render-to-string.ts >/dev/null; then
  printf 'SAST parent unexpectedly already strips CSS expression\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$SP" grep -F 'expression\s*\(' "$V135" -- core/src/server/render-to-string.ts >/dev/null
"${git_cmd[@]}" -C "$SP" grep -F 'normalizedCss' "$FIX" -- core/src/server/render-to-string.ts >/dev/null
if "${git_cmd[@]}" -C "$SP" grep -F 'normalizedCss' "$V135" -- core/src/server/render-to-string.ts >/dev/null; then
  printf 'v0.2.135 unexpectedly already normalizes CSS escapes\n' >&2
  exit 1
fi

# Local clone still has no tags; do not pretend otherwise.
tagcount=$("${git_cmd[@]}" -C "$SP" tag --list | /usr/bin/wc -l | /usr/bin/awk '{print $1}')
[[ $tagcount == 0 ]]

printf 'REPLAY_OK reviewed=5 KEEP_proposal=5 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0\n'
