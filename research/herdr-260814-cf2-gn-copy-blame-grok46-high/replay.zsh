#!/usr/bin/env zsh
set -euo pipefail
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-cf2-gn-copy-blame-grok46-high}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
KO=${KO:-/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/kozou-dev__kozou}
GN=$ROOT/autoresearch/herdr-260813-ghsa200-commitfirst-gn
fail=0

ascii_check() {
  local f=$1
  if LC_ALL=C grep -n '[^[:print:][:space:]]' "$f" >/dev/null; then
    echo "NON_ASCII $f"
    fail=1
  fi
}

hash_check() {
  local f=$1 want=$2
  local got
  got=$(sha256sum "$f" | awk '{print $1}')
  if [[ $got != $want ]]; then
    echo "HASH_MISMATCH $f got=$got want=$want"
    fail=1
  else
    echo "HASH_OK $(basename "$f")"
  fi
}

echo "== ASCII =="
for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  ascii_check "$OWNED/$f"
done

echo "== input hashes =="
hash_check "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
hash_check "$ROOT/docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md" \
  70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json" \
  47209f841a5cb793ae6146b4247990fd2af1d4e50d3d881e0b53904f850bbd0c
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl" \
  0b9cd2daae23e33faf3f2ceed46bba4802e2f9b0ef9c739f0bce7e6f4a16f687
hash_check "$GN/ai-ghsa-intersections.jsonl" \
  c58444221e9cc00555ba251da75f518281bacd660a438f6cc8a5df3ac5cf331e
hash_check "$GN/ai-commit-scans.jsonl" \
  a6d7ca1584dbeb1596c57643092df0178001925efe0de60ca3eee5f72182481a
hash_check "$GN/assigned.jsonl" \
  89cf34362e3f1cc36d91595ddab808eeefc477c0756a924b705d581207149a73
hash_check "$GN/cases.jsonl" \
  47538e731f8c4979651ff36ead7063ea23a1adc05e551a99ae94ceaafd835b2d
hash_check "$GN/gn-excluded.jsonl" \
  216666f22aaf5afa87997e1092758a0c904b6ae4763fc9bcfb9980cd2d4209d0

echo "== conservation =="
python3 - << PY
import json, sys
from pathlib import Path
owned = Path("$OWNED")
ass = [json.loads(l)["case_id"] for l in owned.joinpath("assignment.jsonl").open()]
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open()]
res = json.loads(owned.joinpath("result.json").read_text())
ids = [c["case_id"] for c in cas]
verdicts = [c["verdict"] for c in cas]
n_pass = sum(1 for v in verdicts if v == "PASS_PROPOSAL")
n_rej = sum(1 for v in verdicts if v == "REJECT")
ok = True
if ass != ids or ids != res["inspected_ids"]:
    print("ID_ORDER_FAIL"); ok = False
if len(ass) != 14 or n_pass != 1 or n_rej != 13:
    print("COUNT_FAIL", len(ass), n_pass, n_rej); ok = False
if res["conservation"]["equation"] != "633=14+619":
    print("EQ_FAIL", res["conservation"]["equation"]); ok = False
if res["conservation"]["inspected"] + res["conservation"]["remaining_unreviewed_subject_only"] != 633:
    print("EQ_ARITH_FAIL"); ok = False
if res["pass_proposal_ids"] != ["GHSA-V52W-28XH-V562"]:
    print("PASS_LIST_FAIL", res["pass_proposal_ids"]); ok = False
if res.get("terminal") is not True or res["counts"]["countable_pass"] != 0:
    print("FLAG_FAIL"); ok = False
if res["canonical85_strict_count"] != 85 or res["claim_boundary"]["packet_delta"] != 0:
    print("CANON_FAIL"); ok = False
if ok:
    print("CONSERVATION_OK 633=14+619 PASS_PROPOSAL=1 REJECT=13 countable=0")
else:
    sys.exit(1)
PY

echo "== uniqueness vs canonical85/foundation/source cases =="
python3 - << PY
import json, sys
from pathlib import Path
root = Path("$ROOT")
owned = Path("$OWNED")
gn = Path("$GN")
canon = json.loads((root/"autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json").read_text())
excl = set(x.upper() for x in canon["strict_released_case_ids"])
found = set()
with (root/"autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl").open() as f:
    for line in f:
        found.add(json.loads(line)["case_id"].upper())
src = set()
with (gn/"cases.jsonl").open() as f:
    for line in f:
        src.add(json.loads(line)["case_id"].upper())
ids = []
with (owned/"assignment.jsonl").open() as f:
    for line in f:
        ids.append(json.loads(line)["case_id"].upper())
bad = []
if len(ids) != len(set(ids)):
    bad.append("duplicate_assignment")
for i in ids:
    if i in excl: bad.append("canonical85:"+i)
    if i in found: bad.append("foundation:"+i)
    if i in src: bad.append("source_cases:"+i)
if bad:
    print("UNIQUENESS_FAIL", bad)
    sys.exit(1)
print("UNIQUENESS_OK", len(ids))
PY

echo "== seven gates; PASS requires all PASS =="
python3 - << PY
import json, sys
from pathlib import Path
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
okv = ("PASS","FAIL","UNKNOWN","NARROW","BLOCKED")
n = 0
with Path("$OWNED/cases.jsonl").open() as f:
    for line in f:
        rec = json.loads(line)
        n += 1
        g = rec["gates"]
        for k in need:
            if g[k] not in okv:
                print("BAD_GATE", rec["case_id"], k, g[k]); sys.exit(1)
        if rec["verdict"] == "PASS_PROPOSAL" and any(g[k] != "PASS" for k in need):
            print("PASS_WITH_NONPASS_GATE", rec["case_id"], g); sys.exit(1)
        if rec["verdict"] == "PASS_PROPOSAL" and rec["contribution_class"] != "AI_DIRECT_ROOT":
            print("UNEXPECTED_CLASS", rec["contribution_class"]); sys.exit(1)
print("GATES_OK", n)
PY

echo "== source_matcher negative control: human vendor email is not AI =="
python3 - << PY
import json, re, subprocess, sys
from pathlib import Path
sys.path.insert(0, "$ROOT/cve-analyzer/src")
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit

owned = Path("$OWNED")
clones = Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones")
HUMAN = "7901552eba29d68d1227f2976b8d114b9712abce"
CLAUDE = "568cbd1a66eaa0aa8a2ceca7f5c84719d9210871"
OVERBROAD = re.compile(
    r"Co-authored-by:.*(?:Claude|Cursor|Copilot|Codex|Jules|Gemini|aider|Aider|OpenAI|anthropic)",
    re.I,
)
want_contract = (
    "ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1"
    ":author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4"
)
if MATCHER_CONTRACT != want_contract:
    print("CONTRACT_DRIFT", MATCHER_CONTRACT); sys.exit(1)

def load_commit(clone, sha):
    proc = subprocess.run(
        ["git", "-C", str(clone), "log", "-1",
         "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%aI%x00%B", sha],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if proc.returncode != 0:
        return None
    p = proc.stdout.split("\0")
    if len(p) < 7:
        return None
    return CommitInfo(sha=p[0], author_name=p[1], author_email=p[2],
                      committer_name=p[3], committer_email=p[4],
                      authored_date=p[5], message=p[6])

pysdk = clones / "modelcontextprotocol__python-sdk"
human = load_commit(pysdk, HUMAN)
claude = load_commit(pysdk, CLAUDE)
if human is None or claude is None:
    print("OBJECT_MISSING_CONTROL"); sys.exit(1)
if "ihrpr <inna@anthropic.com>" not in human.message:
    print("HUMAN_TRAILER_MISSING"); sys.exit(1)
if OVERBROAD.search(human.message) is None:
    print("OVERBROAD_SHOULD_MATCH_HUMAN"); sys.exit(1)
if matches_for_commit(human):
    print("HUMAN_VENDOR_FALSE_POSITIVE", [m.to_dict() for m in matches_for_commit(human)])
    sys.exit(1)
if "Co-authored-by: Claude <noreply@anthropic.com>" not in claude.message:
    print("CLAUDE_TRAILER_MISSING"); sys.exit(1)
if not matches_for_commit(claude):
    print("CLAUDE_SHOULD_MATCH"); sys.exit(1)

res = json.loads((owned/"result.json").read_text())
sp = res.get("source_policy") or {}
if sp.get("removed_sha") != HUMAN:
    print("RESULT_REMOVED_SHA_FAIL", sp); sys.exit(1)
if sp.get("human_vendor_email_is_not_ai") is not True:
    print("RESULT_FLAG_FAIL"); sys.exit(1)

seen_human = False
for line in (owned/"cases.jsonl").open():
    rec = json.loads(line)
    cset = rec.get("candidate_set") or []
    if HUMAN in cset:
        print("HUMAN_STILL_IN_CANDIDATE_SET", rec["case_id"]); sys.exit(1)
    if rec["case_id"] == "GHSA-J975-95F5-7WQH":
        if cset != [CLAUDE]:
            print("J975_CANDIDATE_SET_FAIL", cset); sys.exit(1)
        seen_human = True
    repo = rec["repository"]
    owner, name = repo.split("/", 1)
    clone = clones / f"{owner}__{name}"
    for sha in cset:
        ci = load_commit(clone, sha)
        if ci is None:
            print("CANDIDATE_OBJECT_MISSING", rec["case_id"], sha); sys.exit(1)
        if not matches_for_commit(ci):
            print("CANDIDATE_NOT_POLICY_AI", rec["case_id"], sha); sys.exit(1)
if not seen_human:
    print("J975_ROW_MISSING"); sys.exit(1)
print("NEGATIVE_CONTROL_OK human=ihrpr/inna@anthropic.com dropped; Claude 568cbd1 kept")
PY

echo "== kozou object existence / topology / blobs =="
MEMBER=4f86724bd112b07e68033098562c1c4ddc37d93b
SQUASH=bc9dc69d62aaa567a2ccefee12d28a58b96d96c4
HARDEN=7c3ae2e3b7c996571acc07c96222b6dc2de01a3e
V180=e631527918dc2e90c3f324d64af6cf75db8f8aa2
V181=17f3207e24ca0e7858d6836824539bfb0628415b
PARENT=c84c70c7088f70718a5411d4ef20fabbfe3a429c
FILE=packages/mcp/src/startHttpServer.ts
ORIGIN_BLOB=1c4a96662fa37741472954bae28a834156802ded
V180_BLOB=9643e54351d621ce8af90ef5b8f8365d6b9cd643
HARDEN_BLOB=91cc618dbf3ccc448f13deb0e72e0f48b7616898
TREE=c743d1b43bd3739c9a255d4f3520361e2a373ba6

if [[ ! -d $KO ]]; then
  echo "CLONE_ABSENT $KO"
  fail=1
else
  for sha in $MEMBER $SQUASH $HARDEN $V180 $V181 $PARENT; do
    t=$(git -C "$KO" cat-file -t "$sha" 2>/dev/null || true)
    if [[ $t != commit ]]; then
      echo "OBJECT_MISSING $sha got=$t"
      fail=1
    else
      echo "OBJECT_OK ${sha:0:12}"
    fi
  done
  if [[ $(git -C "$KO" rev-parse "$MEMBER^{tree}") != $TREE ]]; then
    echo "TREE_MISMATCH member"; fail=1
  fi
  if [[ $(git -C "$KO" rev-parse "$SQUASH^{tree}") != $TREE ]]; then
    echo "TREE_MISMATCH squash"; fail=1
  fi
  if [[ $(git -C "$KO" rev-parse "$MEMBER:$FILE") != $ORIGIN_BLOB ]]; then
    echo "BLOB_MISMATCH member"; fail=1
  fi
  if [[ $(git -C "$KO" rev-parse "$SQUASH:$FILE") != $ORIGIN_BLOB ]]; then
    echo "BLOB_MISMATCH squash"; fail=1
  fi
  if [[ $(git -C "$KO" rev-parse "$V180:$FILE") != $V180_BLOB ]]; then
    echo "BLOB_MISMATCH v180"; fail=1
  fi
  if [[ $(git -C "$KO" rev-parse "$HARDEN:$FILE") != $HARDEN_BLOB ]]; then
    echo "BLOB_MISMATCH harden"; fail=1
  fi
  if [[ $(git -C "$KO" rev-parse "$V181:$FILE") != $HARDEN_BLOB ]]; then
    echo "BLOB_MISMATCH v181"; fail=1
  fi
  if git -C "$KO" cat-file -e "$PARENT:$FILE" 2>/dev/null; then
    echo "PARENT_HAS_FILE_FAIL"; fail=1
  else
    echo "PARENT_LACKS_FILE_OK"
  fi
  git -C "$KO" merge-base --is-ancestor "$SQUASH" "$V180" || { echo "SQUASH_NOT_ANC_V180"; fail=1; }
  git -C "$KO" merge-base --is-ancestor "$HARDEN" "$V180" && { echo "HARDEN_ANC_V180_FAIL"; fail=1; } || echo "HARDEN_NOT_IN_V180_OK"
  git -C "$KO" merge-base --is-ancestor "$HARDEN" "$V181" || { echo "HARDEN_NOT_ANC_V181"; fail=1; }
  git -C "$KO" merge-base --is-ancestor "$SQUASH" "$V181" || { echo "SQUASH_NOT_ANC_V181"; fail=1; }
  if ! git -C "$KO" cat-file -p "$MEMBER" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.7'; then
    echo "MEMBER_MARKER_FAIL"; fail=1
  else
    echo "MEMBER_MARKER_OK"
  fi
  mcp180=$(git -C "$KO" show "$V180:packages/mcp/package.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')
  mcp181=$(git -C "$KO" show "$V181:packages/mcp/package.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')
  if [[ $mcp180 != 1.8.0 || $mcp181 != 1.8.1 ]]; then
    echo "PKG_VER_FAIL $mcp180 $mcp181"; fail=1
  else
    echo "PKG_VER_OK 1.8.0/1.8.1"
  fi
  if git -C "$KO" show "$V180:$FILE" | LC_ALL=C grep -q allowedHosts; then
    echo "V180_HAS_GUARD_FAIL"; fail=1
  else
    echo "V180_UNGUARDED_OK"
  fi
  if ! git -C "$KO" show "$HARDEN:$FILE" | LC_ALL=C grep -q allowedHosts; then
    echo "HARDEN_MISSING_GUARD_FAIL"; fail=1
  else
    echo "HARDEN_GUARD_OK"
  fi
fi

echo "== release tags via smart-HTTP (no REST) =="
TMP=$(mktemp -d /tmp/kozou-replay-tags.XXXXXX)
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
git -c init.defaultBranch=main init -q --bare "$TMP"
if git --git-dir="$TMP" fetch --quiet --no-tags --filter=blob:none --depth=1 \
    https://github.com/kozou-dev/kozou.git tag v1.8.1 tag v1.8.0; then
  got180=$(git --git-dir="$TMP" rev-parse "v1.8.0^{commit}")
  got181=$(git --git-dir="$TMP" rev-parse "v1.8.1^{commit}")
  if [[ $got180 != $V180 ]]; then echo "TAG_V180_FAIL $got180"; fail=1; else echo "TAG_V180_OK"; fi
  if [[ $got181 != $V181 ]]; then echo "TAG_V181_PEEL_FAIL $got181"; fail=1; else echo "TAG_V181_PEEL_OK"; fi
else
  echo "TAG_FETCH_FAIL"
  fail=1
fi

if [[ $fail -ne 0 ]]; then
  echo REPLAY_FAIL
  exit 1
fi
echo REPLAY_OK
