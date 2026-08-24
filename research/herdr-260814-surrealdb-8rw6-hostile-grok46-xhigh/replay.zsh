#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-surrealdb-8rw6-hostile-grok46-xhigh.
# English only. Do not print credentials. Do not commit or push.
# Do not mutate the shared cve-analyzer clone.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# KEEP is a proposal only. Packet delta is 0. This script does not admit GHSA-8RW6.
# Network fetch, clone, and crate download occur only under mktemp -d.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-surrealdb-8rw6-hostile-grok46-xhigh
SHARED=/home/hanqing/.cache/cve-analyzer/repos/surrealdb_surrealdb
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

CAND=15579bd2cc57a3f88074acf54b42008598d9c87f
PARENT=ce74c0278e0a6901e197ec4fa1b55c90dee2e491
FIX=8f89b260bb9692e5b0d58930793d482a8207eedc
FIXP=11430e25f523b6a8f84fa1800a236c828351bf28
V313=7db9a42083e164dcaede273a48bf22df53a3c8c6
V314=c9e039542e85c3853f26219198df1ae64291edda
ADVHEAD=6253da86d07848917009b6e81740ffbed19e349f
BLOB_PARENT=844402787fbbf75e9bdab2432ed664e48266db01
BLOB_CAND=876132653b5c095d3787a57c86e28e728e05cbc1
BLOB_V313_PIPE=0160c213fea8f30027867cb90b187947d1901a2e
BLOB_V314_PIPE=e0e00f7ab83bdffa355d0fc71ece39c35699997b
BLOB_V313_OUT=beee67cad49fe72ce861d9b09694b0f95652305d
BLOB_V314_OUT=8c0392d701c5ab4f486d1a9fb8b47dd64642d4a6
BLOB_V313_RED=dffe1b59006781f04ae0e112535d8772709bbd5f
BLOB_V314_RED=fb4e9cd56fd35129995ce6899a1f8f6bf82bbe10
PIPE=surrealdb/core/src/exec/operators/scan/pipeline.rs
OUTF=surrealdb/core/src/doc/output.rs
RED=surrealdb/core/src/doc/reduce.rs
PLUCK=surrealdb/core/src/doc/pluck.rs
SURQL=language-tests/tests/reproductions/7356_array_element_select_permission_leak.surql
APATH=advisories/github-reviewed/2026/08/GHSA-8rw6-p7m8-63jp/GHSA-8rw6-p7m8-63jp.json

TMP=
cleanup() {
  if [[ -n ${TMP:-} && -d $TMP ]]; then
    rm -rf "$TMP"
  fi
}
trap cleanup EXIT INT TERM
TMP=$(mktemp -d /tmp/surrealdb-8rw6-replay.XXXXXX)
export SURREAL_8RW6_REPLAY_TMP=$TMP

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

g() {
  local repo=$1
  shift
  local errf=$TMP/giterr
  set +e
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    cat "$errf" >&2
    return $rc
  fi
  return 0
}

require_dir "$OWNED"
require_dir "$SHARED/.git"
require_file "$OWNED/case.json"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/facts/gates.json"
require_file "$OWNED/facts/git.json"
require_file "$OWNED/facts/identity.json"
require_file "$OWNED/facts/releases.json"
require_file "$OWNED/facts/uniqueness.json"
require_file "$OWNED/diffs/parent.filter_fields.rs"
require_file "$OWNED/diffs/cand.filter_fields.rs"
require_file "$OWNED/diffs/fix.filter_fields.rs"
require_file "$OWNED/diffs/parent.pluck_select_loop.rs"
require_file "$OWNED/diffs/fix.7356.surql"
require_file "$OWNED/diffs/cand.message.txt"
require_file "$OWNED/diffs/fix.message.txt"

if [[ -e $OWNED/work ]]; then
  printf 'durable packet must not retain work/\n' >&2
  exit 1
fi

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85/ledger.jsonl" \
  2927924603a76a2565d9c244c3b79f70d4693c127f1bc6fcc63e8099172ba568
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json" \
  47209f841a5cb793ae6146b4247990fd2af1d4e50d3d881e0b53904f850bbd0c
expect_hash "$OWNED/case.json" \
  243a5e18cc2628398b0e2b3843ba910c418eb3d9479ce64b2364ac4c3b48de50
expect_hash "$OWNED/report.md" \
  925b72330cdcd4e6a8c660f11abff91d09f247103d481a86dae92b00d21ca022
expect_hash "$OWNED/facts/identity.json" \
  1614038ba16c35720c8157063d4d9b045d40b452d0c974915bdf0da10a3324b8
expect_hash "$OWNED/facts/git.json" \
  043c1948f45d27f5faa3b7190cd3fe739b58ef902c2834b6656a8d2be103d8a7
expect_hash "$OWNED/facts/releases.json" \
  314804ef4dbef14d942b4e2f38a332d6a3e62160e20a6aaa1812de4847c1f69f
expect_hash "$OWNED/facts/uniqueness.json" \
  712d5acbb6d7521a96c73919ad207ea42bd3445150a88c8575a32aedf3ddc64c
expect_hash "$OWNED/facts/gates.json" \
  e555c67c566a3c700ececc126f59274dd6c7f21e6ee61d8c0798763261bdc505
expect_hash "$OWNED/diffs/cand.message.txt" \
  f347a8e248ca192c872f7927a23b4c228a94cff83a6e0c68113b7122b787a54f
expect_hash "$OWNED/diffs/fix.message.txt" \
  106321e322075f7695687ab7285ab4b4817710fe6397bf39583378a1eba87bd4
expect_hash "$OWNED/diffs/parent.filter_fields.rs" \
  9e3a0406c7d091676c0b8a004171b6954f024b4f44a44cbf93eaeda4e9b48171
expect_hash "$OWNED/diffs/cand.filter_fields.rs" \
  b8fbb4316c9819d4f22e97c1e17375520d739556a5fd9422b2c40fa49e5158aa
expect_hash "$OWNED/diffs/fix.filter_fields.rs" \
  f48b4e937d543d0682ba7df2a453eff399f7fa6946bd604efdefcd0dd3bab6a5
expect_hash "$OWNED/diffs/parent.pluck_select_loop.rs" \
  2dc96c9f12472845dd84c3cb6ae418ed0a2a20f868758bc7e8c56bb8b8547f4e
expect_hash "$OWNED/diffs/fix.7356.surql" \
  afea93b7bc8edba9af8018171b6a9117fd91e85c666f3faa4ed3182a59e0a8ac

# Shared clone: commit-only, no fetch, no tag mutation.
export GIT_NO_LAZY_FETCH=1
[[ "$(g "$SHARED" log -1 --format='%P' "$CAND")" == "$PARENT" ]]
[[ "$(g "$SHARED" log -1 --format='%P' "$FIX")" == "$FIXP" ]]
g "$SHARED" merge-base --is-ancestor "$CAND" "$FIX"
if g "$SHARED" tag | grep -E '^v3\.1\.(3|4)$' >/dev/null; then
  printf 'shared clone unexpectedly gained v3.1.3/v3.1.4 tags\n' >&2
  exit 1
fi

candbody=$(g "$SHARED" log -1 --format='%B' "$CAND")
printf '%s\n' "$candbody" | grep -F 'Co-authored-by: Claude Opus 4.7 (1M context) <noreply@anthropic.com>' >/dev/null
fixbody=$(g "$SHARED" log -1 --format='%B' "$FIX")
if printf '%s\n' "$fixbody" | grep -E 'Claude|Copilot|cursoragent' >/dev/null; then
  printf 'fix unexpectedly had an AI trailer\n' >&2
  exit 1
fi

if [[ -d $ADV/.git ]]; then
  [[ "$(g "$ADV" rev-parse "$ADVHEAD")" == "$ADVHEAD" ]]
  g "$ADV" cat-file -t "$ADVHEAD:$APATH" >/dev/null
  g "$ADV" cat-file blob "$ADVHEAD:$APATH" >"$TMP/advisory-shared.json"
  expect_hash "$TMP/advisory-shared.json" \
    7a7e9e01101f9dd9e7c623154f07d11b99793d859fbf2731e78ecc8a0a65f4eb
fi

# Owned bounded tag fetch into mktemp. No alternates. Do not touch SHARED remotes.
CLONE=$TMP/clone
"${git_cmd[@]}" init -q "$CLONE"
"${git_cmd[@]}" -C "$CLONE" remote add origin https://github.com/surrealdb/surrealdb.git
if [[ -f $CLONE/.git/objects/info/alternates ]]; then
  printf 'owned clone must not use alternates\n' >&2
  exit 1
fi
g "$CLONE" fetch --quiet --no-tags --no-recurse-submodules --filter=blob:none --depth=1 origin \
  refs/tags/v3.1.3:refs/tags/v3.1.3 \
  refs/tags/v3.1.4:refs/tags/v3.1.4 \
  ${CAND}:refs/heads/cand \
  ${PARENT}:refs/heads/parent \
  ${FIX}:refs/heads/fix \
  ${FIXP}:refs/heads/fixparent

[[ "$(g "$CLONE" rev-parse 'v3.1.3^{commit}')" == "$V313" ]]
[[ "$(g "$CLONE" rev-parse 'v3.1.4^{commit}')" == "$V314" ]]
[[ "$(g "$CLONE" ls-tree v3.1.3 -- "$PIPE" | awk '{print $3}')" == "$BLOB_V313_PIPE" ]]
[[ "$(g "$CLONE" ls-tree v3.1.4 -- "$PIPE" | awk '{print $3}')" == "$BLOB_V314_PIPE" ]]
[[ "$(g "$CLONE" ls-tree v3.1.3 -- "$OUTF" | awk '{print $3}')" == "$BLOB_V313_OUT" ]]
[[ "$(g "$CLONE" ls-tree v3.1.4 -- "$OUTF" | awk '{print $3}')" == "$BLOB_V314_OUT" ]]
[[ "$(g "$CLONE" ls-tree v3.1.3 -- "$RED" | awk '{print $3}')" == "$BLOB_V313_RED" ]]
[[ "$(g "$CLONE" ls-tree v3.1.4 -- "$RED" | awk '{print $3}')" == "$BLOB_V314_RED" ]]
[[ "$(g "$CLONE" ls-tree cand -- "$PIPE" | awk '{print $3}')" == "$BLOB_CAND" ]]
[[ "$(g "$CLONE" ls-tree parent -- "$PIPE" | awk '{print $3}')" == "$BLOB_PARENT" ]]
[[ "$(g "$CLONE" ls-tree fix -- "$PIPE" | awk '{print $3}')" == "$BLOB_V314_PIPE" ]]
[[ "$(g "$CLONE" ls-tree fixparent -- "$PIPE" | awk '{print $3}')" == "$BLOB_V313_PIPE" ]]

parent_out=$(g "$CLONE" ls-tree parent -- "$OUTF" || true)
if [[ -n ${parent_out} ]]; then
  printf 'parent unexpectedly has output.rs\n' >&2
  exit 1
fi
cand_out=$(g "$CLONE" ls-tree cand -- "$OUTF" || true)
if [[ -n ${cand_out} ]]; then
  printf 'candidate unexpectedly has output.rs\n' >&2
  exit 1
fi

python3 - "$OWNED" "$ROOT" "$PIPE" "$PLUCK" "$SURQL" "$APATH" \
  "$CAND" "$PARENT" "$FIX" "$FIXP" "$V313" "$V314" \
  "$BLOB_PARENT" "$BLOB_CAND" "$BLOB_V313_PIPE" "$BLOB_V314_PIPE" << 'PY'
import hashlib, json, os, re, sys, tarfile, urllib.request
from pathlib import Path

owned = Path(sys.argv[1])
root = Path(sys.argv[2])
pipe, pluck, surql, apath = sys.argv[3:7]
cand, parent, fix, fixp, v313, v314 = sys.argv[7:13]
blob_parent, blob_cand, blob_v313, blob_v314 = sys.argv[13:17]
tmp = Path(os.environ["SURREAL_8RW6_REPLAY_TMP"])
ua = "ai-slop-research-8rw6"

def ascii_norm(s: str) -> str:
    return (
        s.replace("\u2014", "--")
        .replace("\u2013", "--")
        .replace("\u2026", "...")
        .replace("\u00a0", " ")
    )

def extract_fn(text: str, needle: str) -> str:
    lines = text.splitlines(True)
    fn_i = next(i for i, line in enumerate(lines) if needle in line and "fn " in line)
    start = fn_i
    while start > 0 and lines[start - 1].startswith("///"):
        start -= 1
    depth = 0
    started = False
    end = None
    for j in range(fn_i, len(lines)):
        depth += lines[j].count("{") - lines[j].count("}")
        if "{" in lines[j]:
            started = True
        if started and depth == 0:
            end = j + 1
            break
    return ascii_norm("".join(lines[start:end]).rstrip() + "\n")

def extract_pluck_loop(text: str) -> str:
    lines = text.splitlines(True)
    fn = next(i for i, line in enumerate(lines) if "pub(super) async fn pluck_select" in line)
    start = next(
        i
        for i, line in enumerate(lines[fn:], fn)
        if "for fd in table_fields.iter()" in line
    )
    depth = 0
    started = False
    end = None
    for j in range(start, len(lines)):
        depth += lines[j].count("{") - lines[j].count("}")
        if "{" in lines[j]:
            started = True
        if started and depth == 0:
            end = j + 1
            break
    return ascii_norm("".join(lines[start:end]).rstrip() + "\n")

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def git_headers():
    headers = {"User-Agent": ua, "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    return headers

def fetch(url: str, dest: Path, headers=None, timeout=120):
    req = urllib.request.Request(
        url,
        headers=headers or {"User-Agent": ua, "Accept": "*/*"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        dest.write_bytes(resp.read())

def hash_object(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data).hexdigest()

# ASCII: every retained owned file
bad = []
for p in sorted(owned.rglob("*")):
    if not p.is_file():
        continue
    try:
        p.read_bytes().decode("ascii")
    except UnicodeDecodeError:
        bad.append(str(p.relative_to(owned)))
if bad:
    raise SystemExit("non-ASCII retained files: " + " ".join(bad))
print("ASCII ok")

case = json.loads((owned / "case.json").read_text())
res = json.loads((owned / "result.json").read_text())
gates = json.loads((owned / "facts/gates.json").read_text())
uniq = json.loads((owned / "facts/uniqueness.json").read_text())
ident = json.loads((owned / "facts/identity.json").read_text())
gitf = json.loads((owned / "facts/git.json").read_text())
rels = json.loads((owned / "facts/releases.json").read_text())
report = (owned / "report.md").read_text()
replay = (owned / "replay.zsh").read_text()

assert case["verdict"] == "KEEP"
assert case["countable"] is False
assert case["countable_proposal"] is True
assert case["causal_admission"] is False
assert case["packet_delta"] == 0
assert case["current_leader_accepted_count"] == 85
assert case["contribution_class"] == "AI_NEW_SURFACE_CONTRIBUTOR"
assert case["leader_may_admit"] is True
assert case["identity_gate"] == "PASS"
assert case["ai_hunk_gate"] == "PASS"
assert case["topology_gate"] == "PASS"
assert case["but_for_gate"] == "PASS"
assert case["fix_reversal_gate"] == "PASS"
assert case["release_gate"] == "PASS"
assert case["uniqueness_gate"] == "PASS"
assert case["failing_gates"] == []
assert case["authorship_transfer_from_member_to_carrier"] is False
assert case["candidate_set"] == [cand]
assert case["minimum_fix_set"] == [fix]
assert gates["verdict"] == "KEEP"
assert gates["all_seven_pass"] is True
assert res["verdicts"]["KEEP"] == 1
assert res["verdicts"]["REJECT"] == 0
assert res["packet_delta"] == 0
assert res["current_leader_accepted_count"] == 85
assert res["causal_admission"] is False
assert res["canonical_count_updated"] is False
assert res["leader_may_admit"] is True
assert "work/" not in res["artifact_hashes"]
assert ident["github_reviewed"] is True
assert ident["withdrawn"] is False
assert ident["aliases"] == []
assert gitf["parent_filter_uses_value_each_cut"] is False
assert gitf["candidate_introduces_value_each_forward_cut"] is True
assert gitf["github_pr_81_is_unrelated"] is True
assert rels["v3_1_3"]["pipeline_blob_equals_fixparent"] is True
assert rels["v3_1_4"]["pipeline_blob_equals_fix"] is True
assert rels["fix_sha_not_ancestor_of_v3_1_4"] is True
assert rels["fix_bytes_present_on_v3_1_4"] is True
assert uniq["in_canonical85_strict"] is False
assert uniq["in_foundation_jsonl"] is False
assert "KEEP proposal 1" in report
assert "Packet delta 0" in report
assert "does not rebuild canonical85" in report
assert "Leader may admit" in report
assert "mktemp -d" in report
assert "git_cmd is a zsh array" in replay
assert "Do not name a local 'path'" in replay
assert "Do not mutate the shared" in replay
assert "mktemp -d" in replay
assert "trap cleanup" in replay

han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(
    r"ghp_" + r"[A-Za-z0-9]{20,}|"
    r"github" + r"_pat_[A-Za-z0-9_]+|"
    r"sk" + r"_live_|"
    r"xox[baprs]-|"
    r"AKIA" + r"[0-9A-Z]{16}|"
    r"BEGIN" + r" PRIVATE"
)
for name in (
    "case.json",
    "report.md",
    "replay.zsh",
    "result.json",
    "facts/identity.json",
    "facts/git.json",
    "facts/releases.json",
    "facts/uniqueness.json",
    "facts/gates.json",
):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    assert text.endswith("\n"), name
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (name, line)
    if name.endswith(".json"):
        json.loads(text)

c85 = json.loads(
    (root / "autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json").read_text()
)
ids85 = {x.upper() for x in c85["strict_released_case_ids"]}
assert len(c85["strict_released_case_ids"]) == 85
assert c85["canonical_strict_count"] == 85
assert "GHSA-8RW6-P7M8-63JP" not in ids85
found = False
with (root / "autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl").open() as fh:
    for line in fh:
        if not line.strip():
            continue
        row = json.loads(line)
        if str(row.get("case_id", "")).upper() == "GHSA-8RW6-P7M8-63JP":
            found = True
            break
assert found is False

parent_fn = (owned / "diffs/parent.filter_fields.rs").read_text()
cand_fn = (owned / "diffs/cand.filter_fields.rs").read_text()
fix_fn = (owned / "diffs/fix.filter_fields.rs").read_text()
pluck_loop = (owned / "diffs/parent.pluck_select_loop.rs").read_text()
test = (owned / "diffs/fix.7356.surql").read_text()
msg = (owned / "diffs/cand.message.txt").read_text()
assert "for path in original.each(&idiom.0)" not in parent_fn
assert "value.cut" not in parent_fn
assert "obj.remove" in parent_fn
assert "HashMap<String, PhysicalPermission>" in parent_fn or "field_permissions.get" in parent_fn
assert "for path in original.each(&idiom.0)" in cand_fn
assert "into_iter().rev()" not in cand_fn
assert "value.cut(&path.0)" in cand_fn
assert "for path in original.each(&idiom.0).into_iter().rev()" in fix_fn
assert "issue #7356" in fix_fn
assert "for k in out.each(&fd.name).iter()" in pluck_loop
assert "out.cut(k)" in pluck_loop
assert "filter_fields_by_permission" in test
assert "SELECT * FROM ONLY doc:1" in test
assert "Co-authored-by: Claude Opus 4.7 (1M context) <noreply@anthropic.com>" in msg

# Network fetches into mktemp only.
raw_base = "https://raw.githubusercontent.com/surrealdb/surrealdb"
fetch(
    f"https://raw.githubusercontent.com/github/advisory-database/{ident['advisory_database_head']}/{apath}",
    tmp / "advisory-raw.json",
)
expect_adv = "7a7e9e01101f9dd9e7c623154f07d11b99793d859fbf2731e78ecc8a0a65f4eb"
got_adv = sha256_bytes((tmp / "advisory-raw.json").read_bytes())
if got_adv != expect_adv:
    raise SystemExit("advisory raw hash mismatch")
shared_adv = tmp / "advisory-shared.json"
if shared_adv.exists():
    if sha256_bytes(shared_adv.read_bytes()) != expect_adv:
        raise SystemExit("advisory shared hash mismatch")
gpage = json.loads((tmp / "advisory-raw.json").read_bytes())
assert gpage["id"].lower() == "ghsa-8rw6-p7m8-63jp"
assert gpage["database_specific"]["github_reviewed"] is True
assert gpage.get("withdrawn") in (None, False)

fetch(
    "https://api.github.com/repos/surrealdb/surrealdb/git/refs/tags/v3.1.3",
    tmp / "git-ref-v3.1.3.json",
    headers=git_headers(),
)
fetch(
    "https://api.github.com/repos/surrealdb/surrealdb/git/refs/tags/v3.1.4",
    tmp / "git-ref-v3.1.4.json",
    headers=git_headers(),
)
cref = json.loads((tmp / "git-ref-v3.1.3.json").read_text())
assert cref["object"]["sha"] == v313
assert cref["object"]["type"] == "commit"
fref = json.loads((tmp / "git-ref-v3.1.4.json").read_text())
assert fref["object"]["sha"] == v314

fetch(
    f"https://api.github.com/repos/surrealdb/surrealdb/compare/{cand}...v3.1.3",
    tmp / "compare-cand-v313.json",
    headers=git_headers(),
)
fetch(
    f"https://api.github.com/repos/surrealdb/surrealdb/compare/{fix}...v3.1.4",
    tmp / "compare-fix-v314.json",
    headers=git_headers(),
)
cmpc = json.loads((tmp / "compare-cand-v313.json").read_text())
assert cmpc["status"] == "ahead"
assert cmpc["behind_by"] == 0
assert cmpc["merge_base_commit"]["sha"] == cand
cmpf = json.loads((tmp / "compare-fix-v314.json").read_text())
assert cmpf["status"] == "diverged"

fetch(
    "https://api.github.com/repos/surrealdb/surrealdb/security-advisories/GHSA-8rw6-p7m8-63jp",
    tmp / "repo-advisory.json",
    headers=git_headers(),
)
radv = json.loads((tmp / "repo-advisory.json").read_text())
assert radv["state"] == "published"
assert radv.get("withdrawn_at") in (None, "")

files = {
    "parent.pipeline.rs": (parent, pipe, blob_parent),
    "cand.pipeline.rs": (cand, pipe, blob_cand),
    "fixparent.pipeline.rs": (fixp, pipe, blob_v313),
    "fix.pipeline.rs": (fix, pipe, blob_v314),
    "v313.pipeline.rs": (v313, pipe, blob_v313),
    "v314.pipeline.rs": (v314, pipe, blob_v314),
    "parent.pluck.rs": (parent, pluck, None),
    "fix.7356.surql": (fix, surql, None),
}
for name, (sha, rel, blob) in files.items():
    dest = tmp / name
    fetch(f"{raw_base}/{sha}/{rel}", dest)
    data = dest.read_bytes()
    if blob is not None:
        if hash_object(data) != blob:
            raise SystemExit(f"blob mismatch {name}")

assert extract_fn((tmp / "parent.pipeline.rs").read_text(encoding="utf-8"), "filter_fields_by_permission") == parent_fn
assert extract_fn((tmp / "cand.pipeline.rs").read_text(encoding="utf-8"), "filter_fields_by_permission") == cand_fn
assert extract_fn((tmp / "fixparent.pipeline.rs").read_text(encoding="utf-8"), "filter_fields_by_permission") == cand_fn
assert extract_fn((tmp / "v313.pipeline.rs").read_text(encoding="utf-8"), "filter_fields_by_permission") == cand_fn
assert extract_fn((tmp / "fix.pipeline.rs").read_text(encoding="utf-8"), "filter_fields_by_permission") == fix_fn
assert extract_fn((tmp / "v314.pipeline.rs").read_text(encoding="utf-8"), "filter_fields_by_permission") == fix_fn
assert extract_pluck_loop((tmp / "parent.pluck.rs").read_text(encoding="utf-8")) == pluck_loop
assert ascii_norm((tmp / "fix.7356.surql").read_text(encoding="utf-8")) == test
v313_fn = extract_fn((tmp / "v313.pipeline.rs").read_text(encoding="utf-8"), "filter_fields_by_permission")
v314_fn = extract_fn((tmp / "v314.pipeline.rs").read_text(encoding="utf-8"), "filter_fields_by_permission")
assert "into_iter().rev()" not in v313_fn
assert "into_iter().rev()" in v314_fn

for ver, want_file, want_sha, want_fn in (
    ("3.1.3", tmp / "v313.pipeline.rs", rels["v3_1_3"]["crates_io_surrealdb_core_checksum"], cand_fn),
    ("3.1.4", tmp / "v314.pipeline.rs", rels["v3_1_4"]["crates_io_surrealdb_core_checksum"], fix_fn),
):
    crate = tmp / f"surrealdb-core-{ver}.crate"
    fetch(
        f"https://static.crates.io/crates/surrealdb-core/surrealdb-core-{ver}.crate",
        crate,
        headers={"User-Agent": ua},
    )
    if sha256_bytes(crate.read_bytes()) != want_sha:
        raise SystemExit(f"crate checksum mismatch {ver}")
    with tarfile.open(crate, "r:gz") as tf:
        inner = f"surrealdb-core-{ver}/src/exec/operators/scan/pipeline.rs"
        data = tf.extractfile(inner).read()
    if sha256_bytes(data) != sha256_bytes(want_file.read_bytes()):
        raise SystemExit(f"crate pipeline bytes mismatch {ver}")
    if extract_fn(data.decode("utf-8"), "filter_fields_by_permission") != want_fn:
        raise SystemExit(f"crate function mismatch {ver}")
    meta = tmp / f"crates-io-surrealdb-core-{ver}.json"
    fetch(
        f"https://crates.io/api/v1/crates/surrealdb-core/{ver}",
        meta,
        headers={"User-Agent": ua, "Accept": "application/json"},
    )
    yanked = json.loads(meta.read_text())["version"]["yanked"]
    if yanked:
        raise SystemExit(f"crate yanked {ver}")

print("conservation assigned=1 reviewed=1 unreviewed=0 KEEP_proposal=1 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=0 current_leader_accepted_count=85 packet_delta=0")
PY

printf 'REPLAY_OK reviewed=1 KEEP_proposal=1 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=85\n'
