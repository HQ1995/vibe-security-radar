#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-nearclosed-i-grok46-medium.
# English only. No credentials. Shared caches read-only. No clone, fetch, commit, or push.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearclosed-i-grok46-medium}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
CY=${CY:-/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/coolify}
OC=${OC:-/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw}
AP=${AP:-/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/apm}
ADV_C339=${ADV_C339:-/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/advisories/repo-coollabsio__coolify__ghsa-c339-w3cq-2rjr.json}
ADV_C339_GLOBAL=${ADV_C339_GLOBAL:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/pages/ghsa/ghsa-c339-w3cq-2rjr.json}
ADV_Q6QF=${ADV_Q6QF:-/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/03/GHSA-q6qf-4p5j-r25g/GHSA-q6qf-4p5j-r25g.json}
ADV_Q5PP=${ADV_Q5PP:-/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/05/GHSA-q5pp-gvjg-h7v4/GHSA-q5pp-gvjg-h7v4.json}
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

fail() { print -r -- "REPLAY_FAIL $*" >&2; exit 1 }

REPLAY_TMP=""
cleanup_replay_tmp() {
  if [[ -n "${REPLAY_TMP:-}" && -d "$REPLAY_TMP" ]]; then
    rm -rf "$REPLAY_TMP"
  fi
}
trap cleanup_replay_tmp EXIT
REPLAY_TMP="$(mktemp -d)"

GITQ_N=0
gitq() {
  GITQ_N=$((GITQ_N + 1))
  local outfile errfile rc filtered
  outfile="$REPLAY_TMP/out.$GITQ_N"
  errfile="$REPLAY_TMP/err.$GITQ_N"
  set +e
  command git "$@" >"$outfile" 2>"$errfile"
  rc=$?
  set -e
  filtered="$(grep -v -E -- '^error: unable to normalize alternate object path:' "$errfile" || true)"
  if [[ -n "$filtered" ]]; then
    rm -f "$outfile" "$errfile"
    fail "git stderr: $filtered"
  fi
  cat "$outfile"
  rm -f "$outfile" "$errfile"
  return $rc
}

git_expect_fail() {
  local outfile errfile rc
  GITQ_N=$((GITQ_N + 1))
  outfile="$REPLAY_TMP/out.$GITQ_N"
  errfile="$REPLAY_TMP/err.$GITQ_N"
  set +e
  command git "$@" >"$outfile" 2>"$errfile"
  rc=$?
  set -e
  rm -f "$outfile" "$errfile"
  if [[ $rc -eq 0 ]]; then
    return 1
  fi
  return 0
}

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  python3 - "$OWNED/$f" <<'PY' || fail "ascii $f"
import sys
p=sys.argv[1]
b=open(p,"rb").read()
if b"\x00" in b:
    raise SystemExit(1)
try:
    b.decode("ascii")
except UnicodeDecodeError:
    raise SystemExit(1)
PY
done

hash_check() {
  local f=$1 want=$2
  local got
  got=$(sha256sum "$f" | awk '{print $1}')
  if [[ $got != $want ]]; then
    fail "HASH_MISMATCH $f got=$got want=$want"
  fi
  print -r -- "HASH_OK $(basename "$f")"
}

echo "== input hashes =="
hash_check "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
hash_check "$ROOT/docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md" \
  70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical90/summary.json" \
  5222879219a975fa4388f3f07f5c62cd6687a642b6509afe48a4250fb4be81ef
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical90/ledger.jsonl" \
  daf706e14d514ad62d197e61aa8ec7f52eefd958bc19a4a7c58591a0be8654ec
hash_check "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
hash_check "$ADV_C339" \
  5c4cafb52378a38f3fc3bdda6ac7514105945d527d01b40da128c57e4f85f17a
hash_check "$ADV_C339_GLOBAL" \
  697903cacf5bc304cf4ffd98450696a32d846ca83662edd93265e04111f92aa0
hash_check "$ADV_Q6QF" \
  4b8061cb5dda7a12aea4c6ace0e767c709fcccda6a3e339ce5c8e03e86585cd7
hash_check "$ADV_Q5PP" \
  d96ce646231d072b606e75a3fc12e30242b9408bf9ac4560b2ae9c67666cc1fb

echo "== conservation 3=3+0 =="
python3 - << PY
import json, sys
from pathlib import Path
owned = Path("$OWNED")
ass = [json.loads(l) for l in owned.joinpath("assignment.jsonl").open() if l.strip()]
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open() if l.strip()]
res = json.loads(owned.joinpath("result.json").read_text())
aids = [a["case_id"] for a in ass]
cids = [c["case_id"] for c in cas]
want = [
    "GHSA-C339-W3CQ-2RJR",
    "GHSA-Q6QF-4P5J-R25G",
    "GHSA-Q5PP-GVJG-H7V4",
]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if [a["fp211_ordinal"] for a in ass] != [55, 60, 70]:
    print("ORDINAL_FAIL"); sys.exit(1)
n_pass = sum(1 for c in cas if c["verdict"] == "PASS_PROPOSAL")
n_nar = sum(1 for c in cas if c["verdict"] == "NARROW")
n_rej = sum(1 for c in cas if c["verdict"] == "REJECT")
if n_pass != 0 or n_nar != 3 or n_rej != 0 or len(cas) != 3:
    print("COUNT_FAIL", n_pass, n_nar, n_rej); sys.exit(1)
if res["conservation"]["equation"] != "3=3+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposals"] != []:
    print("PASS_LIST_FAIL", res["pass_proposals"]); sys.exit(1)
if res["canonical_strict_count_untouched"] != 90 or res["counts"]["countable_pass"] != 0:
    print("FLAG_FAIL"); sys.exit(1)
for rec in cas:
    g = rec["gates"]
    for k in need:
        if k not in g:
            print("GATE_MISSING", rec["case_id"], k); sys.exit(1)
    if rec.get("osv_introduced_used_as_causal_proof") is not False:
        print("OSV_USED_AS_PROOF", rec["case_id"]); sys.exit(1)
    if rec.get("proposed_pass") is not False or rec.get("seven_gates_exact_pass") is not False:
        print("PROPOSAL_DRIFT", rec["case_id"]); sys.exit(1)
    if rec["verdict"] != "NARROW" or rec["gates"]["but_for_gate"] != "NARROW":
        print("NOT_NARROW", rec["case_id"]); sys.exit(1)
    if rec["contribution_class"] != "AI_NEW_SURFACE_CONTRIBUTOR":
        print("CLASS_FAIL", rec["case_id"]); sys.exit(1)
if cas[0]["gates"]["identity_gate"] != "PASS" or cas[0]["authorship_transfer"] is not False:
    print("C339_ID_OR_TRANSFER"); sys.exit(1)
if cas[1]["gates"]["uniqueness_gate"] != "PASS":
    print("Q6QF_UNIQ"); sys.exit(1)
if cas[2]["n_parents"] != 1:
    print("Q5PP_PARENTS"); sys.exit(1)
print("CONSERVATION_OK 3=3+0 NARROW=3 PASS_PROPOSAL=0")
PY

echo "== uniqueness vs canonical90 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical90/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open() if l.strip()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical90", hit); sys.exit(1)
if "GHSA-8RW6-P7M8-63JP" in ids:
    print("UNIQUENESS_FAIL 8RW6"); sys.exit(1)
if len(strict) != 90:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
print("UNIQUENESS_OK", len(ids))
PY

echo "== git facts =="
[[ -d $CY && -d $OC && -d $AP ]] || fail "CLONE_ABSENT"

# C339 ordinal 55
C=acff543e09ae5c7f8da78e5a092ebb1e57f24dc0
CAR=009b4e7d4803493ff9e3dadae864615dfa90e8dc
F=0fed553207383f384b93cba24d28122065fa67d5
P=4a4d64ac3132dc5ec200d6541a7638ce9dcd61a8
UP=app/Livewire/Settings/Updates.php
gitq -C "$CY" cat-file -t "$C" >/dev/null
gitq -C "$CY" cat-file -t "$CAR" >/dev/null
gitq -C "$CY" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$CY" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "C339_PARENTS $parents"
gitq -C "$CY" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Haiku 4.5' || fail "C339_MARKER"
git_expect_fail -C "$CY" grep -q isInstanceAdmin "$P" -- "$UP" || fail "C339_PARENT_HAS_ADMIN"
git_expect_fail -C "$CY" grep -q isCloud "$P" -- "$UP" || fail "C339_PARENT_HAS_CLOUD"
gitq -C "$CY" grep -q isCloud "$C" -- "$UP" || fail "C339_CAND_CLOUD"
git_expect_fail -C "$CY" grep -q isInstanceAdmin "$C" -- "$UP" || fail "C339_CAND_HAS_ADMIN"
gitq -C "$CY" grep -q isInstanceAdmin "$F" -- "$UP" || fail "C339_FIX_ADMIN"
blob_p=$(gitq -C "$CY" rev-parse "${P}:${UP}")
blob_c=$(gitq -C "$CY" rev-parse "${C}:${UP}")
blob_car=$(gitq -C "$CY" rev-parse "${CAR}:${UP}")
blob_v=$(gitq -C "$CY" rev-parse "v4.0.0-beta.461:${UP}")
blob_f=$(gitq -C "$CY" rev-parse "${F}:${UP}")
blob_t=$(gitq -C "$CY" rev-parse "v4.0.0-beta.471:${UP}")
[[ $blob_p == fe20763b6a09202568b906616c95c8374eeaa1a3 ]] || fail "C339_PARENT_BLOB $blob_p"
[[ $blob_c == 01a67c38ca21b13002577ff108982ce7ffe172dd ]] || fail "C339_CAND_BLOB $blob_c"
[[ $blob_c == "$blob_car" && $blob_c == "$blob_v" ]] || fail "C339_SHIPPED_BLOB"
[[ $blob_f == a200ef689030246b26b287dfbf3491649ef19c00 ]] || fail "C339_FIX_BLOB $blob_f"
[[ $blob_f == "$blob_t" ]] || fail "C339_FIX_TAG_BLOB"
gitq -C "$CY" merge-base --is-ancestor "$C" "$CAR" || fail "C339_MEMBER_OF_CARRIER"
gitq -C "$CY" merge-base --is-ancestor "$C" v4.0.0-beta.461 || fail "C339_MEMBER_TAG"
git_expect_fail -C "$CY" merge-base --is-ancestor "$F" v4.0.0-beta.461 || fail "C339_FIX_IN_VULN"
gitq -C "$CY" merge-base --is-ancestor "$F" v4.0.0-beta.471 || fail "C339_FIX_TAG"
peel=$(gitq -C "$CY" rev-parse 'v4.0.0-beta.461^{commit}')
[[ $peel == 04e71916e5ecbaa412ae74c2604278ba52eff0a2 ]] || fail "C339_PEEL461 $peel"
peel=$(gitq -C "$CY" rev-parse 'v4.0.0-beta.471^{commit}')
[[ $peel == 914d7e0b50505bc1fd56c34974fca09ad354e92a ]] || fail "C339_PEEL471 $peel"
python3 - "$ADV_C339" "$ADV_C339_GLOBAL" <<'PY' || fail "C339_GHSA"
import json,sys
a=json.load(open(sys.argv[1]))
g=json.load(open(sys.argv[2]))
assert a["state"]=="published"
assert a.get("withdrawn_at") in (None,"")
assert a["ghsa_id"].lower()=="ghsa-c339-w3cq-2rjr"
assert "isInstanceAdmin" in (a.get("description") or a.get("summary") or "")
assert g.get("error")==404
print("C339_GHSA_OK")
PY
echo "C339_OK"

# Q6QF ordinal 60
C=8d74578ceb0c3b913555dff6265821eb0fc09749
F=dd9d9c1c609dcb4579f9e57bd7b5c879d0146b53
P=f7123ec30af8c96bb2cb4da198e19bc03312ba16
IT=src/agents/tools/image-tool.ts
gitq -C "$OC" cat-file -t "$C" >/dev/null
gitq -C "$OC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "Q6QF_PARENTS $parents"
gitq -C "$OC" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5' || fail "Q6QF_MARKER"
gitq -C "$OC" grep -q 'if (primarySupportsImages === true) return null' "$P" -- "$IT" || fail "Q6QF_PARENT_GATE"
gitq -C "$OC" grep -q 'intentionally do NOT gate based on primarySupportsImages' "$C" -- "$IT" || fail "Q6QF_CAND_GATE"
git_expect_fail -C "$OC" grep -q workspaceOnly "$P" -- "$IT" || fail "Q6QF_PARENT_HAS_WO"
git_expect_fail -C "$OC" grep -q workspaceOnly "$C" -- "$IT" || fail "Q6QF_CAND_HAS_WO"
git_expect_fail -C "$OC" grep -q workspaceOnly v2026.2.22 -- "$IT" || fail "Q6QF_VULN_HAS_WO"
gitq -C "$OC" grep -q workspaceOnly "$F" -- "$IT" || fail "Q6QF_FIX_WO"
gitq -C "$OC" grep -q workspaceOnly v2026.2.23 -- "$IT" || fail "Q6QF_TAG_WO"
blob_c=$(gitq -C "$OC" rev-parse "${C}:${IT}")
blob_v=$(gitq -C "$OC" rev-parse "v2026.2.22:${IT}")
[[ $blob_c == 119423353c302f4c9afc9a9570f825b3f7a4b2e3 ]] || fail "Q6QF_CAND_BLOB $blob_c"
[[ $blob_v == f27f9bdaaaf2a1484ef5d1af62f059ab3c111390 ]] || fail "Q6QF_VULN_BLOB $blob_v"
gitq -C "$OC" merge-base --is-ancestor "$C" v2026.2.22 || fail "Q6QF_CAND_TAG"
git_expect_fail -C "$OC" merge-base --is-ancestor "$F" v2026.2.22 || fail "Q6QF_FIX_IN_VULN"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.2.23 || fail "Q6QF_FIX_TAG"
peel=$(gitq -C "$OC" rev-parse 'v2026.2.22^{commit}')
[[ $peel == a54dc7fe80fc02e2a02e6901668a468fcb0cf8b4 ]] || fail "Q6QF_PEEL222 $peel"
peel=$(gitq -C "$OC" rev-parse 'v2026.2.23^{commit}')
[[ $peel == b817600533129771ace2801d7c05901c7f850fb8 ]] || fail "Q6QF_PEEL223 $peel"
python3 - "$ADV_Q6QF" <<'PY' || fail "Q6QF_GHSA"
import json,sys
d=json.load(open(sys.argv[1]))
assert d["id"].lower()=="ghsa-q6qf-4p5j-r25g"
assert d["database_specific"]["github_reviewed"] is True
s=(d.get("details") or "")+(d.get("summary") or "")
assert "workspaceOnly" in s
assert "primarySupportsImages" not in s
print("Q6QF_GHSA_OK")
PY
echo "Q6QF_OK"

# Q5PP ordinal 70
C=810d87b2af77b05a3b82cc6e076b053835d6adc3
CAR=84abb22ce4b1f74145e63de1c4464007855c6a08
F=f85b9f54ad303159f9c448268eb7005c319fe02a
P=d92a3d08405e2f840a4895692f4816f5fae54a79
AI=src/apm_cli/integration/agent_integrator.py
gitq -C "$AP" cat-file -t "$C" >/dev/null
gitq -C "$AP" cat-file -t "$CAR" >/dev/null
gitq -C "$AP" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$AP" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "Q5PP_PARENTS $parents"
gitq -C "$AP" cat-file -p "$C" | LC_ALL=C grep -q 'copilot-swe-agent' || fail "Q5PP_MARKER"
gitq -C "$AP" show "${P}:${AI}" >"$REPLAY_TMP/q5pp.parent.py"
gitq -C "$AP" show "${C}:${AI}" >"$REPLAY_TMP/q5pp.cand.py"
gitq -C "$AP" show "${F}:${AI}" >"$REPLAY_TMP/q5pp.fix.py"
python3 - "$REPLAY_TMP/q5pp.parent.py" "$REPLAY_TMP/q5pp.cand.py" "$REPLAY_TMP/q5pp.fix.py" <<'PY' || fail "Q5PP_FUNCS"
import sys
from pathlib import Path
def fn(t, name):
    key = "    def " + name
    i = t.find(key)
    if i < 0:
        return None
    j = t.find("\n    def ", i + 1)
    return t[i:j]
p=Path(sys.argv[1]).read_text()
c=Path(sys.argv[2]).read_text()
f=Path(sys.argv[3]).read_text()
if "integrate_package_agents_claude" in p:
    raise SystemExit("PARENT_HAS_CLAUDE_FN")
if "integrate_package_agents_claude" not in c:
    raise SystemExit("CAND_NO_CLAUDE_FN")
if "Also target .claude/agents" not in p:
    raise SystemExit("PARENT_NO_DUAL")
if fn(p,"find_agent_files") != fn(c,"find_agent_files"):
    raise SystemExit("FINDER_CHANGED")
if fn(p,"copy_agent") != fn(c,"copy_agent"):
    raise SystemExit("COPY_CHANGED")
if "find_files_by_glob" not in f:
    raise SystemExit("FIX_NO_SAFE")
if "package_path.glob" in f and "def find_agent_files" in f:
    # safer helper must be used in the fixed finder
    body=fn(f,"find_agent_files") or ""
    if "find_files_by_glob" not in body:
        raise SystemExit("FIX_FINDER_STILL_GLOB")
print("Q5PP_FUNCS_OK")
PY
blob_p=$(gitq -C "$AP" rev-parse "${P}:${AI}")
blob_c=$(gitq -C "$AP" rev-parse "${C}:${AI}")
blob_v=$(gitq -C "$AP" rev-parse "v0.12.4:${AI}")
blob_f=$(gitq -C "$AP" rev-parse "${F}:${AI}")
blob_t=$(gitq -C "$AP" rev-parse "v0.13.0:${AI}")
[[ $blob_p == 739905c49421d8431b90d48ba88d6a8fe2ee6c5c ]] || fail "Q5PP_PARENT_BLOB $blob_p"
[[ $blob_c == 0211259cfc1a7c0dd7ec0bda84910732a7256660 ]] || fail "Q5PP_CAND_BLOB $blob_c"
[[ $blob_v == 0436d027e1b6555acf4e2f71c6c51c34ddc9d110 ]] || fail "Q5PP_VULN_BLOB $blob_v"
[[ $blob_f == 5327d95a09173dfff8c84f382760ca22b9818996 ]] || fail "Q5PP_FIX_BLOB $blob_f"
[[ $blob_f == "$blob_t" ]] || fail "Q5PP_FIX_TAG_BLOB"
gitq -C "$AP" merge-base --is-ancestor "$C" "$CAR" || fail "Q5PP_MEMBER_OF_CARRIER"
gitq -C "$AP" merge-base --is-ancestor "$C" v0.12.4 || fail "Q5PP_MEMBER_TAG"
git_expect_fail -C "$AP" merge-base --is-ancestor "$F" v0.12.4 || fail "Q5PP_FIX_IN_VULN"
gitq -C "$AP" merge-base --is-ancestor "$F" v0.13.0 || fail "Q5PP_FIX_TAG"
peel=$(gitq -C "$AP" rev-parse 'v0.12.4^{commit}')
[[ $peel == 6aceef72be490a9c716547f600a2659f3f2826b7 ]] || fail "Q5PP_PEEL124 $peel"
peel=$(gitq -C "$AP" rev-parse 'v0.13.0^{commit}')
[[ $peel == 921651639e4bc8231190d816ad4982a163529951 ]] || fail "Q5PP_PEEL130 $peel"
python3 - "$ADV_Q5PP" <<'PY' || fail "Q5PP_GHSA"
import json,sys
d=json.load(open(sys.argv[1]))
assert d["id"].lower()=="ghsa-q5pp-gvjg-h7v4"
assert d["database_specific"]["github_reviewed"] is True
s=d.get("details") or ""
assert "find_agent_files" in s and "copy_agent" in s
assert ".apm/agents" in s
assert "integrate_package_agents_claude" not in s
print("Q5PP_GHSA_OK")
PY
echo "Q5PP_OK"

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
import sys
from pathlib import Path
d=Path(sys.argv[1])
allowed={"assignment.jsonl","cases.jsonl","result.json","report.md","replay.zsh"}
names={p.name for p in d.iterdir()}
extra=names-allowed
if extra:
    raise SystemExit(f"extra {sorted(extra)}")
print("hygiene_ok")
PY

echo "REPLAY_OK reviewed=3 PASS_proposal=0 NARROW=3 REJECT=0 UNKNOWN=0 BLOCKED=0"
