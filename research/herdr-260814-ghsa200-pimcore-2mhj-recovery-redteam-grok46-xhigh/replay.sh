#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-pimcore-2mhj-recovery-redteam-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# PASS is a proposal only. This script does not admit the row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-pimcore-2mhj-recovery-redteam-grok46-xhigh
CLONE=/home/hanqing/.cache/ghsa200-worker-clones/pimcore-2mhj-recovery-260814/pimcore__pimcore
FILE=models/DataObject/ClassDefinition.php
BLOCK=models/DataObject/ClassDefinition/Data/Block.php

AI=dbe1d131e49421eee5a427f1ae0dec5735639ff3
PARENT=4b85df494e87b4fbb9c6e8b4c303cb193b1e317e
FIX=33a0e1887e1e31b4283b016ac5440c35ea5697b4
FIXPARENT=f7565e26ca7ad5f3811db833ba486d0c105734f5
V14=0565917f83f9f4844ad92165a58871e3fd92f54b
V15=fbf5ab61f4c890dbd9fe44b8bd4430af596305c9
V128=f025d3c7c46dda34e09c4236657b37c5dd3d0d59
V129=355ac351e1a672e92246b2cd54763bfa59158cb4
BLOB_PARENT=b09f5e65afbc29d66ca9e10fbd888d05318ad0ee
BLOB_AI=b954e1360463ded328e2bdc0ae067bf083e6cae3
BLOB_FIX=cce70e10cfd91b8531f27337a8c59e051234fa26
BLOB_BLOCK=bb2537d5eab76c0e8f0406f0f8042acf3b6e8f81

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

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
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/ledger.jsonl" \
  3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9
expect_hash "$ROOT/scripts/publication_adjudications.json" \
  9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-directroot-batch27-grok46-high/cases.jsonl" \
  1b3b009f456e35cef1768f1aecfc8b55fbca09f7706023dec6f8f735db60530f
expect_hash "$OWNED/cases.jsonl" \
  f24104862ae27d35e6efda8f6940641aebf3a0d538a46eaba8248d8e49f41fc0
expect_hash "$OWNED/report.md" \
  c07b4c54f0e4c448fee2d321b017596da630ee7a71bf5595b16d3d12bff0f8ec
expect_hash "$OWNED/work/pages/ghsa/GHSA-2mhj-fhvg-v428.json" \
  7991005c243cef89a455e323af6ee9b3ead1da8729253247f4bb90583288b5e2
expect_hash "$OWNED/work/pages/repo-advisory/pimcore__pimcore__GHSA-2mhj-fhvg-v428.json" \
  e348b7c8b18dbcb62377a648e8718d0721b4bddef7641be746bf5d7d963a5821
expect_hash "$OWNED/work/pages/advisory/GHSA-2mhj-fhvg-v428.json" \
  6ad8ffa9a2adf1a2ba7dc9013e57efd4ee8ce762f667a0257a43f3d934d418fa
expect_hash "$OWNED/work/pages/commits/dbe1d131.json" \
  f211b222cac51b091e20b4a97ef953ac71e2a5888066dac322b9339991770a5e
expect_hash "$OWNED/work/pages/commits/33a0e188.json" \
  008a37d9a338661bd999ff8d961b499a18bc552f0e84a66b42d678a54d12ec5d
expect_hash "$OWNED/work/pages/tags/v2026.1.4.json" \
  ddbbd9a30b03ce7189f4484ccc3038bbec1338d53eca8b1018f362b9770f36dd
expect_hash "$OWNED/work/pages/tags/v2026.1.5.json" \
  b01c3a32423be30c1458302de67e475421d6f87fb0613fc4fd0f55eca4cf4071
expect_hash "$OWNED/work/pages/tags/v12.3.8.json" \
  28b113dfc527de442298efe538e45ebf14ded86e30b44148f5d33d25cccdd03d
expect_hash "$OWNED/work/pages/tags/v12.3.9.json" \
  bc6b38570e3b41ded32ffb63b37d252a01a354dd3373f8720ee98ce63c7c38c4
expect_hash "$OWNED/work/pages/releases/v2026.1.4.json" \
  99cc7db1e29f17cc8205a7921252ed45c6d9de579da8728f3f5ced085936b7c3
expect_hash "$OWNED/work/pages/releases/v2026.1.5.json" \
  e2c04921d3541b11f3663cf13133dbda9a9d156572db5ca5d4a94b34062c346a
expect_hash "$OWNED/work/pages/releases/v12.3.8.json" \
  f138fe0681780c1b2bfc135bc645642d4d76cd8ebfcd6dccad76be8a2cb0ec0b
expect_hash "$OWNED/work/pages/releases/v12.3.9.json" \
  dcc420a9b1e58431f4fa4b43b0a5e08284c28a1ba56a895b213371f4df6a7dcc
expect_hash "$OWNED/work/pages/packagist/pimcore.json" \
  3202fb32d980216be2286212e779f62289536999ccdb6a0547f0a1bf27cd249b

python3 - "$OWNED" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  "$ROOT/scripts/publication_adjudications.json" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 1, len(rows)
r = rows[0]
assert r["case_id"] == "GHSA-2MHJ-FHVG-V428"
assert r["aliases"] == ["CVE-2026-55072"]
assert r["verdict"] == "PASS"
assert r["worker_verdict"] == "PASS"
assert r["causal_admission"] is False
assert r["countable"] is False
assert r["countable_proposal"] is True
assert r["publication_status"] == "HOLD"
assert r["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
assert r["candidate_set"] == ["dbe1d131e49421eee5a427f1ae0dec5735639ff3"]
assert r["candidate_parent"] == "4b85df494e87b4fbb9c6e8b4c303cb193b1e317e"
assert r["candidate_parent"] != "f7565e26ca7ad5f3811db833ba486d0c105734f5"
assert r["minimum_fix_set"] == ["33a0e1887e1e31b4283b016ac5440c35ea5697b4"]
assert r["fix_parent"] == "f7565e26ca7ad5f3811db833ba486d0c105734f5"
assert r["failing_gates"] == []
for g in (
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
    "remediation_patch_delta_gate",
):
    assert r[g] == "PASS", g
    assert r["gates"][g] == "PASS", g
han = re.compile(r"[\u3400-\u9fff]")
for name in ("cases.jsonl", "report.md", "replay.sh"):
    raw = (owned / name).read_bytes()
    text = raw.decode("utf-8")
    assert text, name
    assert text.isascii(), name
    assert not han.search(text), name
    assert raw.endswith(b"\n"), name
    assert b"\t" not in raw or name == "replay.sh"
    for i, line in enumerate(text.splitlines(), 1):
        assert line == line.rstrip(" \t"), (name, i)
secret = re.compile(rb"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})")
for p in [owned / "cases.jsonl", owned / "report.md", owned / "replay.sh"]:
    blob = p.read_bytes()
    assert not secret.search(blob), p.name
assert "debug" not in r
assert "TODO" not in r["scope_statement"]
c81 = json.loads(Path(sys.argv[2]).read_text())
cids = {x.upper() for x in c81["strict_released_case_ids"]}
assert len(c81["strict_released_case_ids"]) == 81
assert "GHSA-2MHJ-FHVG-V428" not in cids
fp_ids = set()
for line in Path(sys.argv[3]).read_text().splitlines():
    if line.strip():
        o = json.loads(line)
        fp_ids.add((o.get("case_id") or "").upper())
assert "GHSA-2MHJ-FHVG-V428" not in fp_ids
pub = Path(sys.argv[4]).read_text()
assert "GHSA-2MHJ-FHVG-V428" not in pub.upper()
g = json.loads((owned / "work/pages/ghsa/GHSA-2mhj-fhvg-v428.json").read_text())
assert g["ghsa_id"] == "GHSA-2mhj-fhvg-v428"
assert g["type"] == "reviewed"
assert g["withdrawn_at"] is None
assert g["cve_id"] == "CVE-2026-55072"
assert g["source_code_location"] == "https://github.com/pimcore/pimcore"
assert g["vulnerabilities"][0]["package"]["name"] == "pimcore/pimcore"
assert g["vulnerabilities"][0]["first_patched_version"] == "2026.1.5"
assert "dbe1d131e4" in g["description"]
assert "omitted the trailing" in g["description"]
repo = json.loads((owned / "work/pages/repo-advisory/pimcore__pimcore__GHSA-2mhj-fhvg-v428.json").read_text())
assert repo.get("state") == "published"
assert repo.get("ghsa_id", "").lower() == "ghsa-2mhj-fhvg-v428"
assert repo.get("withdrawn_at") is None
adv = json.loads((owned / "work/pages/advisory/GHSA-2mhj-fhvg-v428.json").read_text())
assert adv["id"] == "GHSA-2mhj-fhvg-v428"
assert adv["aliases"] == ["CVE-2026-55072"]
assert adv["database_specific"]["github_reviewed"] is True
c_ai = json.loads((owned / "work/pages/commits/dbe1d131.json").read_text())
assert c_ai["sha"] == "dbe1d131e49421eee5a427f1ae0dec5735639ff3"
assert c_ai["parents"][0]["sha"] == "4b85df494e87b4fbb9c6e8b4c303cb193b1e317e"
assert len(c_ai["parents"]) == 1
assert "copilot-swe-agent[bot]" in c_ai["commit"]["message"]
c_fix = json.loads((owned / "work/pages/commits/33a0e188.json").read_text())
assert c_fix["sha"] == "33a0e1887e1e31b4283b016ac5440c35ea5697b4"
assert c_fix["parents"][0]["sha"] == "f7565e26ca7ad5f3811db833ba486d0c105734f5"
for tag, sha in (
    ("v2026.1.4", "0565917f83f9f4844ad92165a58871e3fd92f54b"),
    ("v2026.1.5", "fbf5ab61f4c890dbd9fe44b8bd4430af596305c9"),
    ("v12.3.8", "f025d3c7c46dda34e09c4236657b37c5dd3d0d59"),
    ("v12.3.9", "355ac351e1a672e92246b2cd54763bfa59158cb4"),
):
    t = json.loads((owned / f"work/pages/tags/{tag}.json").read_text())
    assert t["object"]["sha"] == sha, tag
    rel = json.loads((owned / f"work/pages/releases/{tag}.json").read_text())
    assert rel["tag_name"] == tag
    assert rel["draft"] is False
    assert rel["prerelease"] is False
pkg = json.loads((owned / "work/pages/packagist/pimcore.json").read_text())
versions = {p["version"]: p for p in pkg["packages"]["pimcore/pimcore"]}
for ver, sha in (
    ("v2026.1.4", "0565917f83f9f4844ad92165a58871e3fd92f54b"),
    ("v2026.1.5", "fbf5ab61f4c890dbd9fe44b8bd4430af596305c9"),
    ("v12.3.8", "f025d3c7c46dda34e09c4236657b37c5dd3d0d59"),
    ("v12.3.9", "355ac351e1a672e92246b2cd54763bfa59158cb4"),
):
    assert versions[ver]["source"]["reference"] == sha, ver
    assert versions[ver]["source"]["url"] == "https://github.com/pimcore/pimcore.git"
print("conservation assigned=1 reviewed=1 unreviewed=0 PASS_proposal=1 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0")
PY

# topology
got_parent=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${AI}^")
[[ $got_parent == "$PARENT" ]]
nparents=$("${git_cmd[@]}" -C "$CLONE" rev-list --parents -n 1 "$AI")
[[ $nparents == "$AI $PARENT" ]]
"${git_cmd[@]}" -C "$CLONE" log -1 --format='%B' "$AI" | grep -F 'Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>' >/dev/null
"${git_cmd[@]}" -C "$CLONE" log -1 --format='%s' "$AI" | grep -F '[Security]: Enhance Class Definition security (#19145)' >/dev/null
fix_parents=$("${git_cmd[@]}" -C "$CLONE" rev-list --parents -n 1 "$FIX")
[[ $fix_parents == "$FIX $FIXPARENT" ]]
assert_ancestor "$CLONE" "$AI" "$FIX"
assert_ancestor "$CLONE" "$AI" "v2026.1.4"
assert_not_ancestor "$CLONE" "$FIX" "v2026.1.4"
assert_ancestor "$CLONE" "$FIX" "v2026.1.5"
assert_not_ancestor "$CLONE" "$AI" "v2026.1.3"
assert_ancestor "$CLONE" "$AI" "v12.3.8"
assert_not_ancestor "$CLONE" "$FIX" "v12.3.8"
assert_ancestor "$CLONE" "$FIX" "v12.3.9"
assert_not_ancestor "$CLONE" "$AI" "v12.3.7"

peel14=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v2026.1.4^{commit}')
peel15=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v2026.1.5^{commit}')
peel128=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v12.3.8^{commit}')
peel129=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v12.3.9^{commit}')
[[ $peel14 == "$V14" ]]
[[ $peel15 == "$V15" ]]
[[ $peel128 == "$V128" ]]
[[ $peel129 == "$V129" ]]

blob_p=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${PARENT}:${FILE}")
blob_ai=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${AI}:${FILE}")
blob_14=$("${git_cmd[@]}" -C "$CLONE" rev-parse "v2026.1.4:${FILE}")
blob_fp=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${FIXPARENT}:${FILE}")
blob_fix=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${FIX}:${FILE}")
blob_15=$("${git_cmd[@]}" -C "$CLONE" rev-parse "v2026.1.5:${FILE}")
blob_128=$("${git_cmd[@]}" -C "$CLONE" rev-parse "v12.3.8:${FILE}")
blob_129=$("${git_cmd[@]}" -C "$CLONE" rev-parse "v12.3.9:${FILE}")
blob_13=$("${git_cmd[@]}" -C "$CLONE" rev-parse "v2026.1.3:${FILE}")
[[ $blob_p == "$BLOB_PARENT" ]]
[[ $blob_ai == "$BLOB_AI" ]]
[[ $blob_14 == "$BLOB_AI" ]]
[[ $blob_fp == "$BLOB_AI" ]]
[[ $blob_fix == "$BLOB_FIX" ]]
[[ $blob_15 == "$BLOB_FIX" ]]
[[ $blob_128 == "$BLOB_AI" ]]
[[ $blob_129 == "$BLOB_FIX" ]]
[[ $blob_13 == "$BLOB_PARENT" ]]

block_p=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${PARENT}:${BLOCK}")
block_ai=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${AI}:${BLOCK}")
[[ $block_p == "$BLOB_BLOCK" ]]
[[ $block_ai == "$BLOB_BLOCK" ]]

blame14=$("${git_cmd[@]}" -C "$CLONE" blame -l -w -L1149,1153 'v2026.1.4' -- "$FILE")
printf '%s\n' "$blame14" | grep -F "$AI" >/dev/null
printf '%s\n' "$blame14" | grep -F "/^[a-zA-Z0-9]([a-zA-Z0-9_]+)?" >/dev/null
blame15=$("${git_cmd[@]}" -C "$CLONE" blame -l -w -L1149,1156 'v2026.1.5' -- "$FILE")
printf '%s\n' "$blame15" | grep -F "$FIX" >/dev/null
printf '%s\n' "$blame15" | grep -F "/^[a-zA-Z0-9][a-zA-Z0-9_]*$/" >/dev/null

python3 - "$CLONE" "$AI" "$FIX" "$PARENT" "$FILE" << 'PY'
import re, subprocess, sys
clone, ai, fix, parent, file = sys.argv[1:]
git = ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-C", clone]

def show(rev):
    return subprocess.check_output(git + ["show", f"{rev}:{file}"], text=True)

def patterns(src):
    name = re.search(r"preg_match\('/(.+?)/', \$this->getName\(\)\)", src)
    ident = re.search(r"preg_match\('/(.+?)/', \$this->getId\(\)\)", src)
    assert name and ident, (bool(name), bool(ident))
    return name.group(1), ident.group(1)

pn, pi = patterns(show(parent))
an, ai_id = patterns(show(ai))
fn, fi = patterns(show(fix))
assert pn == r"[a-zA-Z]\w+"
assert pi == r"[a-zA-Z0-9]([a-zA-Z0-9_]+)?"
assert an == r"^[a-zA-Z]\w+"
assert ai_id == r"^[a-zA-Z0-9]([a-zA-Z0-9_]+)?"
assert fn == r"^[a-zA-Z]\w+$"
assert fi == r"^[a-zA-Z0-9][a-zA-Z0-9_]*$"

sqli = "1 UNION SELECT password FROM users-- "
valid = "1"
assert re.search(pi, sqli)
assert re.search(ai_id, sqli)
assert not re.search(fi, sqli)
assert re.search(pi, valid)
assert re.search(ai_id, valid)
assert re.search(fi, valid)
print("regex_delta_ok")
PY

printf 'REPLAY_OK reviewed=1 PASS_proposal=1 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0\n'
