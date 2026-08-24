#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-pimcore-2mhj-counterredteam-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# REJECT is not leader admission. This script does not admit the row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-pimcore-2mhj-counterredteam-grok46-xhigh
CLONE=/home/hanqing/.cache/ghsa200-worker-clones/pimcore-2mhj-counterredteam-260814/pimcore__pimcore
FILE=models/DataObject/ClassDefinition.php

AI=dbe1d131e49421eee5a427f1ae0dec5735639ff3
PARENT=4b85df494e87b4fbb9c6e8b4c303cb193b1e317e
HUMAN=e96631216bb439896cc5979ed9f2850eaf28d2f4
FIX=33a0e1887e1e31b4283b016ac5440c35ea5697b4
FIXPARENT=f7565e26ca7ad5f3811db833ba486d0c105734f5
BLOB_PARENT=b09f5e65afbc29d66ca9e10fbd888d05318ad0ee
BLOB_INCOMPLETE=b954e1360463ded328e2bdc0ae067bf083e6cae3
BLOB_FIX=cce70e10cfd91b8531f27337a8c59e051234fa26
T1238=f025d3c7c46dda34e09c4236657b37c5dd3d0d59
T1239=355ac351e1a672e92246b2cd54763bfa59158cb4
T202614=0565917f83f9f4844ad92165a58871e3fd92f54b
T202615=fbf5ab61f4c890dbd9fe44b8bd4430af596305c9

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
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-fresh-nz/cases.jsonl" \
  627274ecd543b647ab65ef8da9f79cf271616bd3c5f254e4411cca86174f660d
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-directroot-batch27-grok46-high/cases.jsonl" \
  1b3b009f456e35cef1768f1aecfc8b55fbca09f7706023dec6f8f735db60530f
expect_hash "$OWNED/cases.jsonl" \
  28b62d03c770a88756c4599a0f05b9c391c8ff8e62c1b905b6d33e51443e76de
expect_hash "$OWNED/report.md" \
  83e42270ae2b1215baa54f9b186fdc0028d9c829315de1f8cf2ef58183175e03
expect_hash "$OWNED/pages/ghsa/GHSA-2mhj-fhvg-v428.json" \
  7991005c243cef89a455e323af6ee9b3ead1da8729253247f4bb90583288b5e2
expect_hash "$OWNED/pages/repo-advisory/pimcore__pimcore__GHSA-2mhj-fhvg-v428.json" \
  e348b7c8b18dbcb62377a648e8718d0721b4bddef7641be746bf5d7d963a5821
expect_hash "$OWNED/pages/advisory-database/GHSA-2mhj-fhvg-v428.json" \
  6ad8ffa9a2adf1a2ba7dc9013e57efd4ee8ce762f667a0257a43f3d934d418fa
expect_hash "$OWNED/pages/releases/v12.3.8.json" \
  f138fe0681780c1b2bfc135bc645642d4d76cd8ebfcd6dccad76be8a2cb0ec0b
expect_hash "$OWNED/pages/releases/v12.3.9.json" \
  dcc420a9b1e58431f4fa4b43b0a5e08284c28a1ba56a895b213371f4df6a7dcc
expect_hash "$OWNED/pages/releases/v2026.1.4.json" \
  99cc7db1e29f17cc8205a7921252ed45c6d9de579da8728f3f5ced085936b7c3
expect_hash "$OWNED/pages/releases/v2026.1.5.json" \
  e2c04921d3541b11f3663cf13133dbda9a9d156572db5ca5d4a94b34062c346a
expect_hash "$OWNED/pages/pr/19145_commits.json" \
  1e8cbf6a97bbd32755558c6032ae285d96d91dc5483bab1bd477addb2dd8968e
expect_hash "$OWNED/work/git_facts.json" \
  55f5efe491c4d16b91e0a7b5a441fcaa81e7359d9d39846a59a76bc8d76a0e05
expect_hash "$OWNED/work/input_hashes.json" \
  663d230345f96e8c47caff206ee5250b87baa0f896b2a950e74cd5d0657349b8
expect_hash "$OWNED/work/packagist_versions.json" \
  13531579a5828b9f5a0c108e81f2f539063f0309c63bc582a3afe92ab44dd6a4
expect_hash "$OWNED/work/uniqueness.json" \
  1f8cd327b53fca3363a8b979f2c7f9fbdd75b131c3a31ad5dbd5732b87d1b6db
expect_hash "$OWNED/work/diffs/classdefinition_human_draft.diff" \
  8c2f3f9226c7251b6e2814491d2c15f2e6807d2910ac1693125c89291671c17c

python3 - "$OWNED/cases.jsonl" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" "$OWNED" << 'PY'
import json, re, sys
from pathlib import Path

rows = [json.loads(l) for l in Path(sys.argv[1]).read_text().splitlines() if l.strip()]
assert len(rows) == 1, len(rows)
r = rows[0]
assert r["case_id"] == "GHSA-2MHJ-FHVG-V428"
assert r["verdict"] == "REJECT"
assert r["causal_admission"] is False
assert r["countable"] is False
assert r["countable_proposal"] is False
assert r["publication_status"] == "HOLD"
assert r["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
assert r["candidate_set"] == ["dbe1d131e49421eee5a427f1ae0dec5735639ff3"]
assert r["candidate_parent"] == "4b85df494e87b4fbb9c6e8b4c303cb193b1e317e"
assert r["human_security_member"] == "e96631216bb439896cc5979ed9f2850eaf28d2f4"
assert r["minimum_fix_set"] == ["33a0e1887e1e31b4283b016ac5440c35ea5697b4"]
assert r["authorship_transfer"] is True
assert r["ai_hunk_gate"] == "FAIL"
assert r["topology_gate"] == "FAIL"
assert r["but_for_gate"] == "FAIL"
assert r["remediation_patch_delta_gate"] == "FAIL"
assert r["identity_gate"] == "PASS"
assert r["fix_reversal_gate"] == "PASS"
assert r["release_gate"] == "PASS"
assert r["uniqueness_gate"] == "PASS"
assert r["baseline_overlap"]["in_canonical81"] is False
assert r["failing_gates"] == [
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "remediation_patch_delta_gate",
]
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
    assert "DEBUG" not in text or name == "replay.sh"
    assert not secret.search(text), name
g = json.loads((owned / "pages/ghsa/GHSA-2mhj-fhvg-v428.json").read_text())
assert g["ghsa_id"].lower() == "ghsa-2mhj-fhvg-v428"
assert g["type"] == "reviewed"
assert g["withdrawn_at"] is None
assert g["cve_id"] == "CVE-2026-55072"
assert g["source_code_location"] == "https://github.com/pimcore/pimcore"
assert g["vulnerabilities"][0]["package"]["name"] == "pimcore/pimcore"
assert g["vulnerabilities"][0]["first_patched_version"] == "2026.1.5"
assert g["vulnerabilities"][1]["first_patched_version"] == "12.3.9"
repo = json.loads((owned / "pages/repo-advisory/pimcore__pimcore__GHSA-2mhj-fhvg-v428.json").read_text())
assert repo.get("state") == "published"
assert repo.get("ghsa_id", "").lower() == "ghsa-2mhj-fhvg-v428"
assert repo.get("withdrawn_at") is None
rel = json.loads((owned / "pages/releases/v12.3.8.json").read_text())
assert rel["tag_name"] == "v12.3.8"
assert rel["draft"] is False
assert rel["prerelease"] is False
rel9 = json.loads((owned / "pages/releases/v12.3.9.json").read_text())
assert rel9["tag_name"] == "v12.3.9"
assert rel9["draft"] is False
assert rel9["prerelease"] is False
rel4 = json.loads((owned / "pages/releases/v2026.1.4.json").read_text())
assert rel4["tag_name"] == "v2026.1.4"
assert rel4["draft"] is False
assert rel4["prerelease"] is False
rel5 = json.loads((owned / "pages/releases/v2026.1.5.json").read_text())
assert rel5["tag_name"] == "v2026.1.5"
assert rel5["draft"] is False
assert rel5["prerelease"] is False
pkg = json.loads((owned / "work/packagist_versions.json").read_text())
assert pkg["v12.3.8"]["source_reference"] == "f025d3c7c46dda34e09c4236657b37c5dd3d0d59"
assert pkg["v12.3.9"]["source_reference"] == "355ac351e1a672e92246b2cd54763bfa59158cb4"
assert pkg["v2026.1.4"]["source_reference"] == "0565917f83f9f4844ad92165a58871e3fd92f54b"
assert pkg["v2026.1.5"]["source_reference"] == "fbf5ab61f4c890dbd9fe44b8bd4430af596305c9"
pr = json.loads((owned / "pages/pr/19145_commits.json").read_text())
assert len(pr) == 7
assert pr[0]["sha"] == "e96631216bb439896cc5979ed9f2850eaf28d2f4"
assert (pr[0].get("author") or {}).get("login") == "kingjia90"
assert pr[0]["commit"]["message"].strip() == "draft"
assert "Co-authored-by" not in pr[0]["commit"]["message"]
for c in pr[3:]:
    assert (c.get("author") or {}).get("login") == "Copilot"
c81 = json.loads(Path(sys.argv[2]).read_text())
cids = set(c81["strict_released_case_ids"])
assert len(cids) == 81
assert "GHSA-2MHJ-FHVG-V428" not in cids
print("conservation assigned=1 reviewed=1 unreviewed=0 KEEP_proposal=0 NARROW=0 REJECT=1 UNKNOWN=0 BLOCKED=0")
PY

got_parent=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${AI}^")
[[ $got_parent == "$PARENT" ]]
nparents=$("${git_cmd[@]}" -C "$CLONE" rev-list --parents -n 1 "$AI")
[[ $nparents == "$AI $PARENT" ]]
"${git_cmd[@]}" -C "$CLONE" log -1 --format='%B' "$AI" | grep -F 'Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>' >/dev/null
human_author=$("${git_cmd[@]}" -C "$CLONE" log -1 --format='%an' "$HUMAN")
[[ $human_author == 'Ji Jia Jia' ]]
human_body=$("${git_cmd[@]}" -C "$CLONE" log -1 --format='%s' "$HUMAN")
[[ $human_body == draft ]]
human_files=$("${git_cmd[@]}" -C "$CLONE" diff-tree --no-commit-id --name-only -r "$HUMAN")
printf '%s\n' "$human_files" | grep -F "$FILE" >/dev/null

for sha in b780ab6776f5f98e8bf882a9e8ceba86af278fe8 95e8021f7b0c65432809462f01c92f772ca2fbb9 a4ca8d91f3924a560450613e4a42d32c97eae576 c518a75c0dbd8cb758782175849b68ab3d711698; do
  "${git_cmd[@]}" -C "$CLONE" log -1 --format='%an' "$sha" | grep -F 'copilot-swe-agent[bot]' >/dev/null
  if "${git_cmd[@]}" -C "$CLONE" diff-tree --no-commit-id --name-only -r "$sha" | grep -Fx "$FILE" >/dev/null; then
    printf 'copilot member unexpectedly touches ClassDefinition.php: %s\n' "$sha" >&2
    exit 1
  fi
done

blob_p=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${PARENT}:${FILE}")
blob_h=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${HUMAN}:${FILE}")
blob_ai=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${AI}:${FILE}")
blob_fp=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${FIXPARENT}:${FILE}")
blob_fix=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${FIX}:${FILE}")
[[ $blob_p == "$BLOB_PARENT" ]]
[[ $blob_h == "$BLOB_INCOMPLETE" ]]
[[ $blob_ai == "$BLOB_INCOMPLETE" ]]
[[ $blob_fp == "$BLOB_INCOMPLETE" ]]
[[ $blob_fix == "$BLOB_FIX" ]]

assert_ancestor "$CLONE" "$AI" "$FIX"
assert_ancestor "$CLONE" "$AI" v12.3.8
assert_not_ancestor "$CLONE" "$FIX" v12.3.8
assert_ancestor "$CLONE" "$FIX" v12.3.9
assert_ancestor "$CLONE" "$AI" v2026.1.4
assert_not_ancestor "$CLONE" "$FIX" v2026.1.4
assert_ancestor "$CLONE" "$FIX" v2026.1.5
assert_not_ancestor "$CLONE" "$AI" v2026.1.3
assert_not_ancestor "$CLONE" "$AI" v12.3.7
assert_ancestor "$CLONE" v12.3.8 v2026.1.4

peel38=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v12.3.8^{commit}')
peel39=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v12.3.9^{commit}')
peel14=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v2026.1.4^{commit}')
peel15=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v2026.1.5^{commit}')
[[ $peel38 == "$T1238" ]]
[[ $peel39 == "$T1239" ]]
[[ $peel14 == "$T202614" ]]
[[ $peel15 == "$T202615" ]]

blob_38=$("${git_cmd[@]}" -C "$CLONE" rev-parse "v12.3.8:${FILE}")
blob_39=$("${git_cmd[@]}" -C "$CLONE" rev-parse "v12.3.9:${FILE}")
blob_13=$("${git_cmd[@]}" -C "$CLONE" rev-parse "v2026.1.3:${FILE}")
blob_14=$("${git_cmd[@]}" -C "$CLONE" rev-parse "v2026.1.4:${FILE}")
blob_15=$("${git_cmd[@]}" -C "$CLONE" rev-parse "v2026.1.5:${FILE}")
blob_37=$("${git_cmd[@]}" -C "$CLONE" rev-parse "v12.3.7:${FILE}")
[[ $blob_38 == "$BLOB_INCOMPLETE" ]]
[[ $blob_39 == "$BLOB_FIX" ]]
[[ $blob_14 == "$BLOB_INCOMPLETE" ]]
[[ $blob_15 == "$BLOB_FIX" ]]
[[ $blob_13 == "$BLOB_PARENT" ]]
[[ $blob_37 == "$BLOB_PARENT" ]]

parents14=$("${git_cmd[@]}" -C "$CLONE" log -1 --format='%P' v2026.1.4)
printf '%s\n' "$parents14" | grep -F "$T1238" >/dev/null
parents15=$("${git_cmd[@]}" -C "$CLONE" log -1 --format='%P' v2026.1.5)
printf '%s\n' "$parents15" | grep -F "$T1239" >/dev/null

"${git_cmd[@]}" -C "$CLONE" grep -F '/^[a-zA-Z]\w+/' "$AI" -- "$FILE" >/dev/null
"${git_cmd[@]}" -C "$CLONE" grep -F '/^[a-zA-Z]\w+$/' "$FIX" -- "$FILE" >/dev/null
if "${git_cmd[@]}" -C "$CLONE" grep -F '/^[a-zA-Z]\w+$/' "$AI" -- "$FILE" >/dev/null; then
  printf 'candidate unexpectedly already has end anchor\n' >&2
  exit 1
fi
if "${git_cmd[@]}" -C "$CLONE" grep -F '/^[a-zA-Z]\w+/' "$PARENT" -- "$FILE" >/dev/null; then
  printf 'parent unexpectedly already has leading anchor\n' >&2
  exit 1
fi

printf 'REPLAY_OK reviewed=1 KEEP_proposal=0 NARROW=0 REJECT=1 UNKNOWN=0 BLOCKED=0\n'
