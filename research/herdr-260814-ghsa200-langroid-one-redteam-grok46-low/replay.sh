#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-langroid-one-redteam-grok46-low.
# English only. Do not print credentials. Do not clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# KEEP is a proposal only. This script does not admit the row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-langroid-one-redteam-grok46-low
CLONE=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/langroid
FILE=langroid/agent/special/sql/sql_chat_agent.py

AI=60933b4860a8952894b31caa0dd3f9dcba512c8e
PARENT=763d5cba68f24720b72e2c75a2dcddd501d87e1e
FIX=00b7dd7b79c5d03c94be284cf3459d98195ebfba
FIXPARENT=56e2756ecab70a70a7e6edbee2f2187b8484683e
V63=fee670d502ed6d82b8414388bd137a315830331f
V64=84d2aff0af173d75417fc37fc629be97177098f3
BLOB_PARENT=e8d817aef9137943c4943c94662d57ee7770b392
BLOB_AI=887a10a4e2c2c5758560d0783b1b526a345502af
BLOB_FIX=a55f6d345c8f3f33b5b316939359b52a1e4fb6e3

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
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-directroot-batch11-grok46-medium/cases.jsonl" \
  8000c4d38e5cd1068360963a278aa249cf22dc4401a469043b6a598708dc11cf
expect_hash "$OWNED/cases.jsonl" \
  0ce1c58b9bd71653f710afc598e9a966089fa18de1d4004e42c642756bdb48da
expect_hash "$OWNED/report.md" \
  bc0f9f088fa19dfee8bb7f1bcab0d87df32eef6d5cde4d5e3e82252f4a36b061
expect_hash "$OWNED/pages/ghsa/GHSA-pmch-g965-grmr.json" \
  348f0fb224e251b5c9594ed71e1e425d67351dd074dc515ecdce62ab815513c7
expect_hash "$OWNED/pages/ghsa/GHSA-mxfr-6hcw-j9rq.json" \
  4bfd10a9fb10f2c46f5f3b626eb138e9cc5bd860d90b3c1f2729fca85799b370
expect_hash "$OWNED/pages/repo-advisory/langroid__langroid__GHSA-pmch-g965-grmr.json" \
  9ecc25f822ec14a58e0991e2efa875a66471637a07d1dbce64076e4c98521feb
expect_hash "$OWNED/pages/pypi/langroid_0.63.0.json" \
  d3e6187be4d08a37ec45ff420ea93715443fcaaefcebe8ecbd8a8681dec7cf45
expect_hash "$OWNED/pages/pypi/langroid_0.64.0.json" \
  8bea418dac6a044bcdd6e96151f5d253647946c310a2cf464c44f5c9d912378f
expect_hash "$OWNED/pages/releases/0.63.0.json" \
  d923e3f84ea2c1e7d8d1d5f783104a63b597de0c80db9b8770c7a0385d370e8b
expect_hash "$OWNED/pages/releases/0.64.0.json" \
  47dd38251fed6540552b923de9f1fd64bfa2552f07c910952fdb9b8e98f9c73f

python3 - "$OWNED/cases.jsonl" "$ROOT/autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json" "$OWNED" << 'PY'
import json, re, sys
from pathlib import Path

rows = [json.loads(l) for l in Path(sys.argv[1]).read_text().splitlines() if l.strip()]
assert len(rows) == 1, len(rows)
r = rows[0]
assert r["case_id"] == "GHSA-PMCH-G965-GRMR"
assert r["verdict"] == "KEEP"
assert r["causal_admission"] is False
assert r["countable"] is False
assert r["countable_proposal"] is True
assert r["publication_status"] == "HOLD"
assert r["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
assert r["candidate_set"] == ["60933b4860a8952894b31caa0dd3f9dcba512c8e"]
assert r["candidate_parent"] == "763d5cba68f24720b72e2c75a2dcddd501d87e1e"
assert r["minimum_fix_set"] == ["00b7dd7b79c5d03c94be284cf3459d98195ebfba"]
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
assert r["failing_gates"] == []
han = re.compile(r"[\u3400-\u9fff]")
owned = Path(sys.argv[3])
for name in ("cases.jsonl", "report.md", "replay.sh"):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert not han.search(text), name
c73 = json.loads(Path(sys.argv[2]).read_text())
cids = set(c73["strict_released_case_ids"])
assert len(cids) == 73
assert "GHSA-PMCH-G965-GRMR" not in cids
g = json.loads((owned / "pages/ghsa/GHSA-pmch-g965-grmr.json").read_text())
assert g["ghsa_id"] == "GHSA-pmch-g965-grmr"
assert g["type"] == "reviewed"
assert g["withdrawn_at"] is None
assert g["cve_id"] == "CVE-2026-50180"
assert g["source_code_location"] == "https://github.com/langroid/langroid"
assert g["vulnerabilities"][0]["package"]["name"] == "langroid"
assert g["vulnerabilities"][0]["first_patched_version"] == "0.64.0"
mx = json.loads((owned / "pages/ghsa/GHSA-mxfr-6hcw-j9rq.json").read_text())
assert mx["cve_id"] == "CVE-2026-25879"
assert mx["vulnerabilities"][0]["first_patched_version"] == "0.63.0"
assert mx["ghsa_id"] != g["ghsa_id"]
repo = json.loads((owned / "pages/repo-advisory/langroid__langroid__GHSA-pmch-g965-grmr.json").read_text())
assert repo.get("state") == "published"
assert repo.get("ghsa_id", "").lower() == "ghsa-pmch-g965-grmr"
p63 = json.loads((owned / "pages/pypi/langroid_0.63.0.json").read_text())
p64 = json.loads((owned / "pages/pypi/langroid_0.64.0.json").read_text())
assert p63["info"]["name"] == "langroid"
assert p63["info"]["version"] == "0.63.0"
assert p63["info"]["yanked"] is False
assert p64["info"]["version"] == "0.64.0"
w63 = next(u for u in p63["urls"] if u["packagetype"] == "bdist_wheel")
w64 = next(u for u in p64["urls"] if u["packagetype"] == "bdist_wheel")
assert w63["sha256"] == "8a91de0ea8cb02b636b33a0ec9cca4b8455059c994dd832caff7de8b3e36ea6a"
assert w64["sha256"] == "795bd1f62e08ba6f5381248cbf17404dc501db59fdc11c14fcbdb80fedab91f6"
rel63 = json.loads((owned / "pages/releases/0.63.0.json").read_text())
rel64 = json.loads((owned / "pages/releases/0.64.0.json").read_text())
assert rel63["tag_name"] == "0.63.0"
assert rel64["tag_name"] == "0.64.0"
assert any(a.get("digest") == "sha256:8a91de0ea8cb02b636b33a0ec9cca4b8455059c994dd832caff7de8b3e36ea6a" for a in rel63["assets"])
assert any(a.get("digest") == "sha256:795bd1f62e08ba6f5381248cbf17404dc501db59fdc11c14fcbdb80fedab91f6" for a in rel64["assets"])
print("conservation assigned=1 reviewed=1 unreviewed=0 KEEP_proposal=1 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0")
PY

# topology
got_parent=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${AI}^")
[[ $got_parent == "$PARENT" ]]
nparents=$("${git_cmd[@]}" -C "$CLONE" rev-list --parents -n 1 "$AI")
[[ $nparents == "$AI $PARENT" ]]
"${git_cmd[@]}" -C "$CLONE" log -1 --format='%B' "$AI" | grep -F 'Co-authored-by: Claude <noreply@anthropic.com>' >/dev/null
"${git_cmd[@]}" -C "$CLONE" log -1 --format='%s' "$AI" | grep -F 'Add SQL query validation to mitigate CVE-2026-25879' >/dev/null
fix_parents=$("${git_cmd[@]}" -C "$CLONE" rev-list --parents -n 1 "$FIX")
[[ $fix_parents == "$FIX $FIXPARENT" ]]
assert_ancestor "$CLONE" "$AI" "$FIX"
assert_ancestor "$CLONE" "$AI" "$V63"
assert_not_ancestor "$CLONE" "$FIX" "$V63"
assert_ancestor "$CLONE" "$FIX" "$V64"

peel63=$("${git_cmd[@]}" -C "$CLONE" rev-parse '0.63.0^{commit}')
peel64=$("${git_cmd[@]}" -C "$CLONE" rev-parse '0.64.0^{commit}')
[[ $peel63 == "$V63" ]]
[[ $peel64 == "$V64" ]]

blob_p=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${PARENT}:${FILE}")
blob_ai=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${AI}:${FILE}")
blob_63=$("${git_cmd[@]}" -C "$CLONE" rev-parse "0.63.0:${FILE}")
blob_fp=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${FIXPARENT}:${FILE}")
blob_fix=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${FIX}:${FILE}")
blob_64=$("${git_cmd[@]}" -C "$CLONE" rev-parse "0.64.0:${FILE}")
[[ $blob_p == "$BLOB_PARENT" ]]
[[ $blob_ai == "$BLOB_AI" ]]
[[ $blob_63 == "$BLOB_AI" ]]
[[ $blob_fp == "$BLOB_AI" ]]
[[ $blob_fix == "$BLOB_FIX" ]]
[[ $blob_64 == "$BLOB_FIX" ]]

if "${git_cmd[@]}" -C "$CLONE" grep -F '_DANGEROUS_SQL_PATTERNS' "$PARENT" -- "$FILE" >/dev/null; then
  printf 'parent unexpectedly has denylist\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$CLONE" grep -F '_DANGEROUS_SQL_PATTERNS' "$AI" -- "$FILE" >/dev/null
"${git_cmd[@]}" -C "$CLONE" grep -F 'pg_read_server_files?' "$AI" -- "$FILE" >/dev/null
if "${git_cmd[@]}" -C "$CLONE" grep -F 'pg_(read|stat|ls|current_logfile)' "$AI" -- "$FILE" >/dev/null; then
  printf 'AI commit unexpectedly has family regex\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$CLONE" grep -F 'pg_(read|stat|ls|current_logfile)' "$FIX" -- "$FILE" >/dev/null

blame63=$("${git_cmd[@]}" -C "$CLONE" blame -l -w -L118,120 '0.63.0' -- "$FILE")
printf '%s\n' "$blame63" | grep -F "$AI" >/dev/null
blame64=$("${git_cmd[@]}" -C "$CLONE" blame -l -w -L122,123 '0.64.0' -- "$FILE")
printf '%s\n' "$blame64" | grep -F "$FIX" >/dev/null

stat63=$("${git_cmd[@]}" -C "$CLONE" show --stat --format='' "$V63")
printf '%s\n' "$stat63" | grep -F 'pyproject.toml' >/dev/null
if printf '%s\n' "$stat63" | grep -F "$FILE" >/dev/null; then
  printf '0.63 bump unexpectedly edits sql agent\n' >&2
  exit 1
fi
stat64=$("${git_cmd[@]}" -C "$CLONE" show --stat --format='' "$V64")
printf '%s\n' "$stat64" | grep -F 'pyproject.toml' >/dev/null
if printf '%s\n' "$stat64" | grep -F "$FILE" >/dev/null; then
  printf '0.64 bump unexpectedly edits sql agent\n' >&2
  exit 1
fi

python3 - "$CLONE" "$AI" "$FIX" "$PARENT" "$FILE" << 'PY'
import re, subprocess, sys
clone, ai, fix, parent, file = sys.argv[1:]

def show(rev):
    return subprocess.check_output(
        ["/usr/bin/git", "--no-optional-locks", "-C", clone, "show", f"{rev}:{file}"],
        text=True,
    )

def patterns(src):
    block = re.search(r"_DANGEROUS_SQL_PATTERNS:[^=]*=\s*\[(.*?)]\s*\n", src, re.DOTALL)
    return eval("[" + block.group(1) + "]", {"re": re, "List": list})

parent_src = show(parent)
assert "_DANGEROUS_SQL_PATTERNS" not in parent_src
assert "def _validate_query" not in parent_src
ai_p = patterns(show(ai))
fx_p = patterns(show(fix))
assert len(ai_p) == 17
assert len(fx_p) == 15

def hit(pats, q):
    return any(p.search(q) for p in pats)

blocked = [
    "COPY log(content) FROM PROGRAM 'id'",
    "SELECT pg_read_server_file('/etc/passwd')",
]
bypass = [
    "SELECT pg_read_file('postgresql.conf')",
    "SELECT pg_stat_file('postgresql.conf')",
    "SELECT pg_ls_logdir()",
    "SELECT pg_ls_waldir()",
    "SELECT pg_current_logfile()",
]
for q in blocked:
    assert hit(ai_p, q), q
    assert hit(fx_p, q), q
for q in bypass:
    assert not hit(ai_p, q), q
    assert hit(fx_p, q), q
print("regex_delta_ok")
PY

printf 'REPLAY_OK reviewed=1 KEEP_proposal=1 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0\n'
