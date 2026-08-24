#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-qf5v-redteam-grok46-high.
# English only. Do not print credentials. Do not clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# KEEP is a proposal, never leader admission. This script does not admit the row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-qf5v-redteam-grok46-high
CLONE=/home/hanqing/.cache/ghsa200-worker-clones/qf5v-redteam-260814/fission__fission
FILE=pkg/apis/core/v1/podspec_safety.go
MERGE=pkg/executor/util/merge.go

MEMBER=2db76f65dbfe4f657b4a4efb506ed63b24623e92
SQUASH=e484df8460bb4e8026e24210120602aa7f181f64
PARENT=8fa799417c77ce8a0189d9858bfe11ece29b84a6
FIX=2569b42bfadbcb7d78b55a00a60f77937e522699
FIXPARENT=0deed6bf3f26bc0f10e9130cd0d479b0b9f5f609
BLOB_MEMBER=af473d2601a9299a035166c4d4bf67927abc50df
BLOB_SQUASH=330fccee042945fac9ccfcdb3d62f52036e63b5e
BLOB_V124=1d7219e7f592cc6ea631866328820475617141bd
BLOB_FIX=43e361d3ab7bf4145f704e23d8654256444c1e86
PEEL24=ce617120c41b9e4a51d577f81b441238264e88fd
PEEL25=ae970aaa9bc76ec93d748bdaf03fd7523b6b6a62
PEEL23=710d8431bbbcdb82d7a1ac2b93c068baa829959b

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
require_dir "$CLONE/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/replay.sh"

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
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c
expect_hash "$ROOT/scripts/publication_adjudications.json" \
  9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-medium5-redteam-grok46-low/cases.jsonl" \
  01452d3e62530b31ef912f9f206fcb5271c39be9a0b472c837abeb3fbb864fc3
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam/cases.jsonl" \
  30277261b159d74fa264294816b64bbf57dff8924dac80b8be417322b13b1944
expect_hash "$OWNED/cases.jsonl" \
  d55b2c2b53c9f5174f936750f2da79ace05ffa7e49a80f4a1356623969e7728d
expect_hash "$OWNED/report.md" \
  3f43b5c5a2b6782d6dd8cab149a66139b99f5760db225d71a779d1b79f09ddd0
expect_hash "$OWNED/pages/ghsa/GHSA-qf5v-m7p4-95rp.json" \
  940e51477efca6a924226cbbcab696f3829fa80dc82be61e30ae33622e1bbe8d
expect_hash "$OWNED/pages/repo-advisory/fission__fission__GHSA-qf5v-m7p4-95rp.json" \
  6877953b69e116268bb84bb0ad6e0aa91473b6689582fa419b8fc432bad63c45
expect_hash "$OWNED/pages/releases/v1.24.0.json" \
  d0f873b809b7f87ced9e5f17cf4abafd69ffa102f4404b672b8ec5e32e04b083
expect_hash "$OWNED/pages/releases/v1.25.0.json" \
  e21d6fac1d126ca9a431516ce0ef15574ea0ac2745f829f7616cfecd60fb9816
expect_hash "$OWNED/pages/goproxy/fission_v1.24.0.info.json" \
  4fd96fc3c158a50f0288c1ddb4ba985c7ae34d3fb1f060e3cb167114ffd1f4f9
expect_hash "$OWNED/pages/goproxy/fission_v1.25.0.info.json" \
  ffbd1550672c162530b8f21e151d2d0b01c811d9c80efa236be0034a2c16d0af
expect_hash "$OWNED/pages/pr/3391_commits.json" \
  3d1475504ca1a648161d99c1b7c7193f91980ff54c65ba589367237d6d62fd25
expect_hash "$OWNED/work/git_facts.json" \
  cfc189f9cf31ec21f2a3ee58ca89f9da4ee22c3640ca4dfc9e002672ef7ffbec
expect_hash "$OWNED/work/input_hashes.json" \
  57885dfc9d8fa44aecf8f92ffa6da20f9b81136fe4e3376b2eadb98a95d6e42f
expect_hash "$OWNED/work/uniqueness.json" \
  6b8fe72f1ab5333518b698b3dd6626f15e1668efea4c0e3580d0ebffc7dc89d1
expect_hash "$OWNED/work/diffs/map_member.go.txt" \
  ad325615ca2257b65de131f8b48fe673c8f8f174b5b0dcb22f167bbe361f8b88
expect_hash "$OWNED/work/diffs/map_carrier.go.txt" \
  ad325615ca2257b65de131f8b48fe673c8f8f174b5b0dcb22f167bbe361f8b88
expect_hash "$OWNED/work/diffs/map_v124.go.txt" \
  ad325615ca2257b65de131f8b48fe673c8f8f174b5b0dcb22f167bbe361f8b88

python3 - "$OWNED/cases.jsonl" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" "$OWNED" << 'PY'
import json, re, sys
from pathlib import Path

rows = [json.loads(l) for l in Path(sys.argv[1]).read_text().splitlines() if l.strip()]
assert len(rows) == 1, len(rows)
r = rows[0]
assert r["case_id"] == "GHSA-QF5V-M7P4-95RP"
assert r["verdict"] == "KEEP"
assert r["causal_admission"] is False
assert r["countable"] is False
assert r["countable_proposal"] is True
assert r["publication_status"] == "HOLD"
assert r["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
assert r["candidate_set"] == ["e484df8460bb4e8026e24210120602aa7f181f64"]
assert r["hypothesized_candidate_member"] == "2db76f65dbfe4f657b4a4efb506ed63b24623e92"
assert r["member_binding_rejected"] is True
assert r["authorship_transfer"] is False
assert r["minimum_fix_set"] == ["2569b42bfadbcb7d78b55a00a60f77937e522699"]
assert r["candidate_parent"] == "8fa799417c77ce8a0189d9858bfe11ece29b84a6"
assert r["ai_hunk_gate"] == "PASS"
assert r["topology_gate"] == "PASS"
assert r["but_for_gate"] == "PASS"
assert r["remediation_patch_delta_gate"] == "PASS"
assert r["identity_gate"] == "PASS"
assert r["fix_reversal_gate"] == "PASS"
assert r["release_gate"] == "PASS"
assert r["uniqueness_gate"] == "PASS"
assert r["failing_gates"] == []
assert r["baseline_overlap"]["in_canonical81"] is False
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(r"ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}")
owned = Path(sys.argv[3])
for name in ("cases.jsonl", "report.md", "replay.sh"):
    raw = (owned / name).read_bytes()
    text = raw.decode("utf-8")
    assert text
    assert not han.search(text), name
    assert all(b < 128 for b in raw), name
    if name != "cases.jsonl":
        for line in text.splitlines():
            assert not line.endswith(" "), name
            assert not line.endswith("\t"), name
    if name != "replay.sh":
        assert "DEBUG" not in text
    assert not secret.search(text), name
g = json.loads((owned / "pages/ghsa/GHSA-qf5v-m7p4-95rp.json").read_text())
assert g["ghsa_id"].lower() == "ghsa-qf5v-m7p4-95rp"
assert g["type"] == "reviewed"
assert g["withdrawn_at"] is None
assert g["cve_id"] == "CVE-2026-50570"
assert g["source_code_location"] == "https://github.com/fission/fission"
assert g["vulnerabilities"][0]["package"]["name"] == "github.com/fission/fission"
assert g["vulnerabilities"][0]["first_patched_version"] == "1.25.0"
assert g["vulnerabilities"][0]["vulnerable_version_range"] == "<= 1.24.0"
repo = json.loads((owned / "pages/repo-advisory/fission__fission__GHSA-qf5v-m7p4-95rp.json").read_text())
assert repo.get("state") == "published"
assert repo.get("ghsa_id", "").lower() == "ghsa-qf5v-m7p4-95rp"
assert repo.get("withdrawn_at") is None
rel = json.loads((owned / "pages/releases/v1.24.0.json").read_text())
assert rel["tag_name"] == "v1.24.0"
assert rel["draft"] is False
assert rel["prerelease"] is True
rel25 = json.loads((owned / "pages/releases/v1.25.0.json").read_text())
assert rel25["tag_name"] == "v1.25.0"
assert rel25["draft"] is False
assert rel25["prerelease"] is False
proxy24 = json.loads((owned / "pages/goproxy/fission_v1.24.0.info.json").read_text())
assert proxy24["Version"] == "v1.24.0"
assert proxy24["Origin"]["Hash"] == "ce617120c41b9e4a51d577f81b441238264e88fd"
proxy25 = json.loads((owned / "pages/goproxy/fission_v1.25.0.info.json").read_text())
assert proxy25["Version"] == "v1.25.0"
assert proxy25["Origin"]["Hash"] == "ae970aaa9bc76ec93d748bdaf03fd7523b6b6a62"
pr = json.loads((owned / "pages/pr/3391_commits.json").read_text())
assert len(pr) == 4
assert pr[0]["sha"] == "2db76f65dbfe4f657b4a4efb506ed63b24623e92"
for c in pr:
    assert "Claude" in c["commit"]["message"]
c81 = json.loads(Path(sys.argv[2]).read_text())
cids = set(c81["strict_released_case_ids"])
assert len(cids) == 81
assert "GHSA-QF5V-M7P4-95RP" not in cids
print("conservation assigned=1 reviewed=1 unreviewed=0 KEEP_proposal=1 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0")
PY

got_parent=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${SQUASH}^")
[[ $got_parent == "$PARENT" ]]
nparents=$("${git_cmd[@]}" -C "$CLONE" rev-list --parents -n 1 "$SQUASH")
[[ $nparents == "$SQUASH $PARENT" ]]
member_parent=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${MEMBER}^")
[[ $member_parent == "$PARENT" ]]
fix_parent=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${FIX}^")
[[ $fix_parent == "$FIXPARENT" ]]

"${git_cmd[@]}" -C "$CLONE" log -1 --format='%B' "$SQUASH" | grep -F 'Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>' >/dev/null
"${git_cmd[@]}" -C "$CLONE" log -1 --format='%B' "$MEMBER" | grep -F 'Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>' >/dev/null
"${git_cmd[@]}" -C "$CLONE" log -1 --format='%B' "$FIX" | grep -F 'Co-authored-by: Claude Opus 4.7 <noreply@anthropic.com>' >/dev/null

if "${git_cmd[@]}" -C "$CLONE" cat-file -e "${PARENT}:${FILE}" 2>/dev/null; then
  printf 'parent unexpectedly has %s\n' "$FILE" >&2
  exit 1
fi
if "${git_cmd[@]}" -C "$CLONE" cat-file -e "v1.23.0:${FILE}" 2>/dev/null; then
  printf 'v1.23.0 unexpectedly has %s\n' "$FILE" >&2
  exit 1
fi

blob_m=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${MEMBER}:${FILE}")
blob_s=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${SQUASH}:${FILE}")
blob_24=$("${git_cmd[@]}" -C "$CLONE" rev-parse "v1.24.0:${FILE}")
blob_fp=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${FIXPARENT}:${FILE}")
blob_fix=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${FIX}:${FILE}")
blob_25=$("${git_cmd[@]}" -C "$CLONE" rev-parse "v1.25.0:${FILE}")
[[ $blob_m == "$BLOB_MEMBER" ]]
[[ $blob_s == "$BLOB_SQUASH" ]]
[[ $blob_24 == "$BLOB_V124" ]]
[[ $blob_fp == "$BLOB_V124" ]]
[[ $blob_fix == "$BLOB_FIX" ]]
[[ $blob_25 == "$BLOB_FIX" ]]
if [[ $blob_m == "$blob_s" || $blob_s == "$blob_24" || $blob_m == "$blob_24" ]]; then
  printf 'expected three-way unequal podspec_safety.go blobs\n' >&2
  exit 1
fi

assert_not_ancestor "$CLONE" "$MEMBER" "$SQUASH"
assert_not_ancestor "$CLONE" "$MEMBER" v1.24.0
assert_not_ancestor "$CLONE" "$MEMBER" v1.25.0
assert_ancestor "$CLONE" "$SQUASH" v1.24.0
assert_ancestor "$CLONE" "$SQUASH" v1.25.0
assert_ancestor "$CLONE" "$SQUASH" "$FIX"
assert_not_ancestor "$CLONE" "$FIX" v1.24.0
assert_ancestor "$CLONE" "$FIX" v1.25.0
assert_not_ancestor "$CLONE" "$SQUASH" v1.23.0

peel23=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v1.23.0^{commit}')
peel24=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v1.24.0^{commit}')
peel25=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v1.25.0^{commit}')
[[ $peel23 == "$PEEL23" ]]
[[ $peel24 == "$PEEL24" ]]
[[ $peel25 == "$PEEL25" ]]

map_m=$("${git_cmd[@]}" -C "$CLONE" show "${MEMBER}:${FILE}" | /usr/bin/python3 -c 'import sys; t=sys.stdin.read(); s=t.find("var dangerousCapabilities"); e=t.find("\n}", s)+2; sys.stdout.write(t[s:e]+"\n")')
map_s=$("${git_cmd[@]}" -C "$CLONE" show "${SQUASH}:${FILE}" | /usr/bin/python3 -c 'import sys; t=sys.stdin.read(); s=t.find("var dangerousCapabilities"); e=t.find("\n}", s)+2; sys.stdout.write(t[s:e]+"\n")')
map_24=$("${git_cmd[@]}" -C "$CLONE" show "v1.24.0:${FILE}" | /usr/bin/python3 -c 'import sys; t=sys.stdin.read(); s=t.find("var dangerousCapabilities"); e=t.find("\n}", s)+2; sys.stdout.write(t[s:e]+"\n")')
[[ $map_m == "$map_s" ]]
[[ $map_s == "$map_24" ]]
printf '%s' "$map_24" | grep -F 'SYS_ADMIN' >/dev/null
if printf '%s' "$map_24" | grep -F 'SYS_TIME' >/dev/null; then
  printf 'v1.24.0 map unexpectedly contains SYS_TIME\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$CLONE" grep -F 'SYS_TIME' "$FIX" -- "$FILE" >/dev/null
if "${git_cmd[@]}" -C "$CLONE" grep -F 'var dangerousCapabilities' "$FIX" -- "$FILE" >/dev/null; then
  printf 'fix unexpectedly still has dangerousCapabilities\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$CLONE" grep -F 'var allowedCapabilities' "$FIX" -- "$FILE" >/dev/null

blame_map=$("${git_cmd[@]}" -C "$CLONE" blame -L 17,24 v1.24.0 -- "$FILE")
printf '%s\n' "$blame_map" | grep -F 'e484df846' >/dev/null
if printf '%s\n' "$blame_map" | grep -v 'e484df846' | grep -q .; then
  printf 'v1.24.0 map blame is not solely the squash\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$CLONE" blame -L 341,347 v1.24.0 -- "$MERGE" | grep -F 'e484df846' >/dev/null

printf 'REPLAY_OK reviewed=1 KEEP_proposal=1 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0\n'
