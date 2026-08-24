#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-causal-consensus-b-grok46-xhigh.
# English only. No network. No clone/commit/push. Canonical88 read-only.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_LFS_SKIP_SMUDGE=1

ROOT=/home/hanqing/agents/ai-slop
OWN=$ROOT/autoresearch/herdr-260814-causal-consensus-b-grok46-xhigh
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json
REV=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
UNR=/home/hanqing/.cache/cve-analyzer/advisory-database
GIT=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c color.ui=never)

expect_eq() {
  if [[ $1 != "$2" ]]; then
    printf 'mismatch %s expected=%s got=%s\n' "$3" "$2" "$1" >&2
    exit 1
  fi
}

sha256_file() {
  /usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}'
}

gitx() {
  local repo=$1
  shift
  local errf
  errf=$(mktemp /tmp/ccb-giterr.XXXXXX)
  set +e
  "${GIT[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
  if [[ -s $errf ]]; then
    /usr/bin/grep -vE 'unable to normalize alternate object path|lazy fetching disabled' "$errf" >&2 || true
  fi
  rm -f "$errf"
  return $rc
}

n_parents() {
  local repo=$1 sha=$2
  local line
  line=$(gitx "$repo" rev-list --parents -n 1 "$sha")
  local -a parts
  parts=(${=line})
  print $(( ${#parts} - 1 ))
}

require_file() {
  if [[ ! -f $1 ]]; then
    printf 'missing %s\n' "$1" >&2
    exit 1
  fi
}

require_dir() {
  if [[ ! -d $1 ]]; then
    printf 'missing %s\n' "$1" >&2
    exit 1
  fi
}

CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
require_file "$OWN/assignment.jsonl"
require_file "$OWN/cases.jsonl"
require_file "$OWN/result.json"
require_file "$OWN/report.md"
require_file "$OWN/replay.zsh"
require_file "$LEDGER"
require_file "$SUMMARY"
require_file "$CONTRACT"
require_dir "$REV/advisories/github-reviewed"
require_dir "$UNR/advisories/unreviewed"

owned_n=$(/usr/bin/find "$OWN" -maxdepth 1 -type f | /usr/bin/wc -l)
expect_eq "${owned_n// /}" "5" "owned_file_count"

expect_eq "$(sha256_file "$LEDGER")" "35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074" ledger
expect_eq "$(sha256_file "$SUMMARY")" "81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921" summary
expect_eq "$(sha256_file "$CONTRACT")" "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3" contract
expect_eq "$(gitx "$REV" rev-parse HEAD)" "f2c6ab3202aeafb36fbea6e76d892532acfca1a6" reviewed_head
expect_eq "$(gitx "$UNR" rev-parse HEAD)" "39d8887723797efc1804585dd06585c9fd751226" unreviewed_head

python3 - <<'ENDPY'
from __future__ import annotations
import json, hashlib, re
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OWN = ROOT / "autoresearch/herdr-260814-causal-consensus-b-grok46-xhigh"
LEDGER = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl"
SUMMARY = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json"
REV = Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database")

def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

res = json.loads((OWN / "result.json").read_text())
asn = [json.loads(l) for l in (OWN / "assignment.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (OWN / "cases.jsonl").read_text().splitlines() if l.strip()]
report = (OWN / "report.md").read_text()
replay = (OWN / "replay.zsh").read_text()
for blob in (report, replay, json.dumps(res), (OWN / "assignment.jsonl").read_text(), (OWN / "cases.jsonl").read_text()):
    assert all(ord(c) < 128 for c in blob), "non-ascii"
PROPOSE = ["GHSA-PQH8-P93P-2RX7", "GHSA-XMXX-7P24-H892"]
UNCHANGED = {
    "GHSA-3RMJ-9M5H-8FPV": "REJECT",
    "GHSA-C32J-VQHX-RX3X": "REJECT",
    "GHSA-FQ7H-9X26-6J22": "REJECT",
    "GHSA-M98R-6667-4WQ7": "REJECT",
    "GHSA-X2HW-PX52-WP4M": "REJECT",
    "GHSA-W85G-3H6X-4XH2": "REJECT",
    "GHSA-G3VG-VX23-3858": "REJECT",
    "GHSA-H2VW-PH2C-JVWF": "REJECT",
    "GHSA-J6V5-G24H-VG4J": "REJECT",
}
assert res["PASS_PROPOSAL"] == PROPOSE
assert res["pass_proposals"] == PROPOSE
assert res["counts"]["PASS_PROPOSAL"] == 2
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 10
assert res["counts"]["NARROW"] == 0
assert res["causal_only_six_gate_ids"] == []
assert res["canonical88_strict_count"] == 88
assert res["canonical_ledger_edited"] is False
assert res["did_not_pad"] is True
assert res["did_not_inherit_pass"] is True
assert res["did_not_reuse_other_miner_logic"] is True
assert res["did_not_require_removing_older_siblings"] is True
assert res["conservation"]["holds"] is True
assert res["conservation"]["check"] == "12 = 12 + 0"
assert len(asn) == 12 and len(cases) == 12
ids = [a["case_id"] for a in asn]
assert ids == [c["case_id"] for c in cases]
assert ids == res["frozen12_ids"]
assert ids == res["conservation"]["reviewed_case_ids"]
canon = set(x.upper() for x in json.loads(SUMMARY.read_text())["strict_released_case_ids"])
assert len(canon) == 88
assert not (set(ids) & canon)
assert res["canonical88_overlap"] == []
assert sha256(LEDGER) == res["hash_roles"]["canonical88_ledger.jsonl"]
assert sha256(SUMMARY) == res["hash_roles"]["canonical88_summary.json"]
assert sha256(ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md") == res["hash_roles"]["CONTRACT.md"]
for name in ("assignment.jsonl", "cases.jsonl", "report.md", "replay.zsh"):
    assert sha256(OWN / name) == res["artifact_hashes"][name], name
assert "**2 PASS_PROPOSAL**" in report
assert "Causal-only six-gate rows **0**" in report
assert "Did not pad" in report
assert "formatter wrap" in report
assert "span()[0] :]" in (OWN / "cases.jsonl").read_text()
assert "ai_hunk_gate" in report
verdicts = [c["verdict"] for c in cases]
assert verdicts.count("REJECT") == 10
assert verdicts.count("NARROW") == 0
assert verdicts.count("PASS_PROPOSAL") == 2
assert all(c["gates"]["identity_gate"] == "PASS" for c in cases)
assert all(c["gates"]["uniqueness_gate"] == "PASS" for c in cases)
assert all(c["n_parents"] == 1 for c in cases)
assert all(c["github_reviewed"] is True for c in cases)
CAUSAL = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","uniqueness_gate")
by = {c["case_id"]: c for c in cases}
for cid, v in UNCHANGED.items():
    assert by[cid]["verdict"] == v
    assert by[cid]["proposed_pass"] is False
    assert by[cid].get("scoped_contributor_reopen") is not True
for cid in PROPOSE:
    c = by[cid]
    assert c["verdict"] == "PASS_PROPOSAL"
    assert c["proposed_pass"] is True
    assert c["countable"] is False
    assert c["causal_admission"] is False
    assert all(c["gates"][k] == "PASS" for k in CAUSAL)
    assert c["gates"]["release_gate"] == "PASS"
    assert c["gates_all_pass"] is True
sc = by["GHSA-6C8G-7P36-R338"]
assert sc["verdict"] == "REJECT"
assert sc["gates"]["ai_hunk_gate"] == "FAIL"
assert sc["named_failing_gate"] == "ai_hunk_gate"
assert sc["proposed_pass"] is False
for c in cases:
    six = all(c["gates"][k] == "PASS" for k in CAUSAL)
    seven = six and c["gates"]["release_gate"] == "PASS"
    if c["case_id"] in PROPOSE:
        assert six and seven
    else:
        assert not seven
        if six:
            raise AssertionError("unexpected causal-only " + c["case_id"])
    adv = REV / c["advisory_path"]
    assert adv.is_file(), c["advisory_path"]
    assert sha256(adv) == c["advisory_sha256"], c["case_id"]
    obj = json.loads(adv.read_text())
    assert obj.get("database_specific", {}).get("github_reviewed") is True
    assert not obj.get("withdrawn")
print("PY_OK")
ENDPY

check_edge() {
  local repo=$1 cand=$2 cparent=$3 fix=$4 fparent=$5 label=$6
  expect_eq "$(gitx "$repo" cat-file -t "$cand")" "commit" "$label-cand-type"
  expect_eq "$(gitx "$repo" cat-file -t "$fix")" "commit" "$label-fix-type"
  expect_eq "$(n_parents "$repo" "$cand")" "1" "$label-cand-parents"
  expect_eq "$(n_parents "$repo" "$fix")" "1" "$label-fix-parents"
  expect_eq "$(gitx "$repo" rev-list --parents -n 1 "$cand" | /usr/bin/awk '{print $2}')" "$cparent" "$label-cand-parent"
  expect_eq "$(gitx "$repo" rev-list --parents -n 1 "$fix" | /usr/bin/awk '{print $2}')" "$fparent" "$label-fix-parent"
  gitx "$repo" merge-base --is-ancestor "$cand" "$fix"
}

check_edge /home/hanqing/.cache/cve-analyzer/repos/withastro_astro \
  336b003351d79708d71f54f14bf86f733a74d04c 7ff7b1160d2d60e40073ddc422fc7a00c59696aa \
  f9ee8685dd26e9afeba3b48d41ad6714f624b12f e9e3cceff35cc103b647d48d36ee9f515312439b 3RMJ

check_edge /home/hanqing/.cache/cve-analyzer/repos/jwt_ruby-jwt \
  3a31a200a8af8aeaee5e113e54185838f51ddf46 8d21f95279ac6c2e6cd21523739137c4936d7fff \
  db560b769a07bd9724e77ff505011ac01872106f ffef4f2cc49f4c07447fa67601b396880e519704 C32J

check_edge /home/hanqing/.cache/cve-analyzer/repos/external-secrets_external-secrets \
  472acbb5307d7f1633a30da219b95984bee35418 c4be01b8183d20d17dae7bbce4c81853473d4a39 \
  4ddd240af7fe88725d9857b9a0c198073502e288 b06495ed7478b804e74dbb327ef391a376a309b9 FQ7H

check_edge /home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/aegra__aegra \
  044d0273343d514a92e3abd726c91be7fdfe0456 717fc7023f7a982ad5d2419cad1f9921cd3de87f \
  e1b2042254fd49072ca281bc35b3f2a3bed74b31 d7d80c850010a9c5a3d2be59254c19b9eb0e25dd M98R

check_edge /home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/dynatrace-mcp \
  66ff2a7c8bedc23939d6d70ab4c3bdce53673843 c11191125271e676109e78fef32df4a61bfa4ce6 \
  15d3546c0618ffbaeaeca477337e08e92f2151bc 35db4695ce24f19d5326edee5a86e9ba39e13f69 PQH8

check_edge /home/hanqing/.cache/cve-analyzer/repos/stellar_rs-soroban-sdk \
  ecad5addcae1dfc3b9bd9865ea5977aef5f16843 a60b7e8f8464e6bd6ffea4a5d7b9843a76deeb71 \
  082424b30bf22ea7fb8c79f16ccd135e0ae9f3db 3e529a68b449c4dc3f3c2d54304a23ba8597d1cf X2HW

check_edge /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  8d74578ceb0c3b913555dff6265821eb0fc09749 f7123ec30af8c96bb2cb4da198e19bc03312ba16 \
  0ed4f8a72bb140045962e97ab01c94c076b758a4 aaf6077f273ab2378d83157ba4e750c6cb7d4894 W85G

check_edge /home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/sharpcompress \
  8b95e0a76d6b387533175730e2895ccd16772d07 3f9986c13c973f5e9b8e08da8bfb5e8259044a44 \
  2021a06626d0555a4d69471386e763ca5f5d5dfb a3772608f3977c145c7d40754f559951ced57d3b 6C8G

check_edge /home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/oscal-compass__compliance-trestle \
  f85944cf7a544e0073fb66f64725422712494c90 70747217681b921135a8e2e8d8d6b8cf29854850 \
  89f4e53d159e8ff901da4d7c3b51c9556bd32ec0 7e39242351fa81420938bbb70282093ab6be8d1b G3VG

check_edge /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  7d7f5d85b4ff0bf9a135ced8022d8860a1979a06 49d962a82f67203994c39cc577b39aa47632fef4 \
  2f06696579a1ab0cb5bbbbb6a900414a6b2e3cd1 99a896797f02d7387dca4297678dc907ce3341a7 H2VW

check_edge /home/hanqing/.cache/cve-analyzer/repos/github.com_montferret_ferret \
  a252ad8edcf8d4b9d5c64f509a0c4588454effa7 2d44ff845b6f3af196d2f49279baeca09c676ad8 \
  160ebad6bd50f153453e120f6d909f5b83322917 c9dd8076090c4beb3e0a93633905af5abc749adc J6V5

check_edge /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  f4b03599f0fb9c2f76e8dbe5fde13948d68dbc3f 7f6e87e9180b9f236aa88b90936be8f6f7988bc2 \
  acd4e0a32f12e1ad85f3130f63b42443ce90f094 0a877070923e266e5e80aea3553711e3a68af8ee XMXX

# Semantic git checks that lock the vetoes.
jwt_overlap=$(gitx /home/hanqing/.cache/cve-analyzer/repos/jwt_ruby-jwt diff-tree --no-commit-id -r --name-only 3a31a200a8af8aeaee5e113e54185838f51ddf46 | /usr/bin/sort)
fix_overlap=$(gitx /home/hanqing/.cache/cve-analyzer/repos/jwt_ruby-jwt diff-tree --no-commit-id -r --name-only db560b769a07bd9724e77ff505011ac01872106f | /usr/bin/sort)
common=$(comm -12 <(print -r -- "$jwt_overlap") <(print -r -- "$fix_overlap"))
print -r -- "$common" | /usr/bin/grep -qx 'CHANGELOG.md'
print -r -- "$common" | /usr/bin/grep -qx 'lib/jwt/version.rb'
if print -r -- "$common" | /usr/bin/grep -q 'hmac.rb'; then
  printf 'jwt hmac overlap unexpected\n' >&2
  exit 1
fi

TRE=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/oscal-compass__compliance-trestle
trestle_common=$(comm -12 \
  <(gitx "$TRE" diff-tree --no-commit-id -r --name-only f85944cf7a544e0073fb66f64725422712494c90 | /usr/bin/sort -u) \
  <(gitx "$TRE" diff-tree --no-commit-id -r --name-only 89f4e53d159e8ff901da4d7c3b51c9556bd32ec0 | /usr/bin/sort -u) \
  | /usr/bin/grep -v '^$' || true)
expect_eq "$trestle_common" "trestle/core/remote/cache.py" trestle-overlap
gitx "$TRE" diff 'f85944cf7a544e0073fb66f64725422712494c90^' f85944cf7a544e0073fb66f64725422712494c90 -- trestle/core/remote/cache.py | /usr/bin/grep -F 'span()[0] :]' >/dev/null
gitx "$TRE" diff-tree --no-commit-id -r --name-status 89f4e53d159e8ff901da4d7c3b51c9556bd32ec0 | /usr/bin/grep -qx $'A\ttrestle/core/remote/security.py'
gitx "$TRE" cat-file -e 'f85944cf7a544e0073fb66f64725422712494c90^:trestle/core/remote/cache.py'

gitx /home/hanqing/.cache/cve-analyzer/repos/github.com_montferret_ferret cat-file -e 'a252ad8edcf8d4b9d5c64f509a0c4588454effa7^:pkg/stdlib/io/fs/write.go'
if "${GIT[@]}" -C /home/hanqing/.cache/cve-analyzer/repos/stellar_rs-soroban-sdk cat-file -e 'ecad5addcae1dfc3b9bd9865ea5977aef5f16843^:soroban-sdk/src/crypto/bn254.rs' >/dev/null 2>&1; then
  printf 'soroban parent unexpectedly has bn254.rs\n' >&2
  exit 1
fi
gitx /home/hanqing/.cache/cve-analyzer/repos/stellar_rs-soroban-sdk cat-file -e ecad5addcae1dfc3b9bd9865ea5977aef5f16843:soroban-sdk/src/crypto/bn254.rs

gitx /home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/sharpcompress merge-base --is-ancestor 8b95e0a76d6b387533175730e2895ccd16772d07 0.43.0
if gitx /home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/sharpcompress merge-base --is-ancestor 2021a06626d0555a4d69471386e763ca5f5d5dfb 0.43.0; then
  printf 'sharpcompress 0.43.0 unexpectedly contains fix\n' >&2
  exit 1
fi
gitx /home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/sharpcompress merge-base --is-ancestor 2021a06626d0555a4d69471386e763ca5f5d5dfb 0.48.0

gitx /home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/dynatrace-mcp merge-base --is-ancestor 66ff2a7c8bedc23939d6d70ab4c3bdce53673843 v2.1.0
if gitx /home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/dynatrace-mcp merge-base --is-ancestor 15d3546c0618ffbaeaeca477337e08e92f2151bc v2.1.0; then
  printf 'dynatrace v2.1.0 unexpectedly contains fix\n' >&2
  exit 1
fi
gitx /home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/dynatrace-mcp merge-base --is-ancestor 15d3546c0618ffbaeaeca477337e08e92f2151bc v2.1.1

# Scoped-contributor reopen locks for the three reopened GHSAs.
SC=/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/sharpcompress
C6=8b95e0a76d6b387533175730e2895ccd16772d07
P6=3f9986c13c973f5e9b8e08da8bfb5e8259044a44
if "${GIT[@]}" -C "$SC" cat-file -e "${C6}:src/SharpCompress/Archives/IAsyncArchiveExtensions.cs" >/dev/null 2>&1; then
  printf '6C8G candidate unexpectedly has IAsyncArchiveExtensions.cs\n' >&2
  exit 1
fi
if "${GIT[@]}" -C "$SC" cat-file -e "${P6}:src/SharpCompress/Archives/IAsyncArchiveExtensions.cs" >/dev/null 2>&1; then
  printf '6C8G parent unexpectedly has IAsyncArchiveExtensions.cs\n' >&2
  exit 1
fi
gitx "$SC" grep -F 'WriteToDirectoryAsyncInternal' "$C6" -- src/SharpCompress/Archives/IArchiveExtensions.cs >/dev/null && {
  printf '6C8G candidate unexpectedly contains WriteToDirectoryAsyncInternal\n' >&2
  exit 1
} || true
gitx "$SC" grep -F 'WriteToDirectoryAsync(' "$C6" -- src/SharpCompress/Archives/IArchiveExtensions.cs >/dev/null
gitx "$SC" grep -F 'WriteToDirectoryAsync(' "$P6" -- src/SharpCompress/Archives/IArchiveExtensions.cs >/dev/null && {
  printf '6C8G parent unexpectedly has WriteToDirectoryAsync\n' >&2
  exit 1
} || true
gitx "$SC" diff-tree --no-commit-id -r --name-status b501bac54ae3f70fba9d86e437fb2e4ea79fd960 | /usr/bin/grep -qx $'A\tsrc/SharpCompress/Archives/IAsyncArchiveExtensions.cs'

DT=/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/dynatrace-mcp
C5=66ff2a7c8bedc23939d6d70ab4c3bdce53673843
P5=c11191125271e676109e78fef32df4a61bfa4ce6
F5=15d3546c0618ffbaeaeca477337e08e92f2151bc
gitx "$DT" grep -F 'now()-${timeframe}' "$P5" -- src/capabilities/list-vulnerabilities.ts >/dev/null && {
  printf 'PQH8 parent list-vulnerabilities already interpolates timeframe\n' >&2
  exit 1
} || true
gitx "$DT" grep -F 'now()-${timeframe}' "$P5" -- src/capabilities/get-events-for-cluster.ts >/dev/null && {
  printf 'PQH8 parent get-events already interpolates timeframe\n' >&2
  exit 1
} || true
gitx "$DT" grep -F 'now()-${timeframe}' "$C5" -- src/capabilities/list-vulnerabilities.ts >/dev/null
gitx "$DT" grep -F 'now()-${timeframe}' "$C5" -- src/capabilities/get-events-for-cluster.ts >/dev/null
gitx "$DT" grep -F 'validateTimeframe' "$F5" -- src/capabilities/list-vulnerabilities.ts >/dev/null
gitx "$DT" grep -F 'validateTimeframe' "$F5" -- src/capabilities/get-events-for-cluster.ts >/dev/null
gitx "$DT" grep -F 'now()-${timeframe}' v2.1.0 -- src/capabilities/list-vulnerabilities.ts >/dev/null
gitx "$DT" grep -F 'validateTimeframe' v2.1.0 -- src/capabilities/list-vulnerabilities.ts >/dev/null && {
  printf 'PQH8 v2.1.0 unexpectedly has validateTimeframe\n' >&2
  exit 1
} || true
gitx "$DT" grep -F 'validateTimeframe' v2.1.1 -- src/capabilities/list-vulnerabilities.ts >/dev/null
expect_eq "$(gitx "$DT" log -1 --format='%an' "$C5")" "copilot-swe-agent[bot]" pqh8-author

OC=/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw
C12=f4b03599f0fb9c2f76e8dbe5fde13948d68dbc3f
P12=7f6e87e9180b9f236aa88b90936be8f6f7988bc2
if "${GIT[@]}" -C "$OC" cat-file -e "${P12}:src/gateway/openresponses-http.ts" >/dev/null 2>&1; then
  printf 'XMXX parent unexpectedly has openresponses-http.ts\n' >&2
  exit 1
fi
gitx "$OC" cat-file -e "${C12}:src/gateway/openresponses-http.ts"
gitx "$OC" grep -F 'handleOpenResponsesHttpRequest(req, res, { auth: resolvedAuth })' "$C12" -- src/gateway/server-http.ts >/dev/null
gitx "$OC" cat-file -e 'v2026.4.14^{commit}:src/gateway/openresponses-http.ts'
gitx "$OC" grep -F 'getResolvedAuth' 'v2026.4.14^{commit}' -- src/gateway/server-http.ts >/dev/null && {
  printf 'XMXX v2026.4.14 unexpectedly has getResolvedAuth\n' >&2
  exit 1
} || true
gitx "$OC" grep -F 'getResolvedAuth' 'v2026.4.15^{commit}' -- src/gateway/server-http.ts >/dev/null
gitx "$OC" merge-base --is-ancestor "$C12" 'v2026.4.14^{commit}'
if gitx "$OC" merge-base --is-ancestor acd4e0a32f12e1ad85f3130f63b42443ce90f094 'v2026.4.14^{commit}'; then
  printf 'XMXX v2026.4.14 unexpectedly contains fix\n' >&2
  exit 1
fi
gitx "$OC" merge-base --is-ancestor acd4e0a32f12e1ad85f3130f63b42443ce90f094 'v2026.4.15^{commit}'
gitx "$OC" log -1 --format='%b' "$C12" | /usr/bin/grep -F 'Co-Authored-By: Claude Opus 4.5' >/dev/null

print 'REPLAY_OK reviewed=12 PASS_PROPOSAL=2 REJECT=10 NARROW=0 causal_only=0 conservation=12=12+0 canonical88=88'
