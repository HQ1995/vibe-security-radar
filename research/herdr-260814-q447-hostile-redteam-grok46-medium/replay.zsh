#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-q447-hostile-redteam-grok46-medium.
# English only. No credentials. Shared caches read-only. mktemp cleaned.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-q447-hostile-redteam-grok46-medium}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
Z=${Z:-/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw}
ADV=${ADV:-/home/hanqing/.cache/cve-analyzer/advisory-database}
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }

REPLAY_TMP=""
cleanup_replay_tmp() {
  if [[ -n "${REPLAY_TMP:-}" && -d "$REPLAY_TMP" ]]; then
    rm -rf "$REPLAY_TMP"
  fi
}
trap cleanup_replay_tmp EXIT
REPLAY_TMP="$(mktemp -d /tmp/q447-hostile.XXXXXX)"

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
  echo "HASH_OK $(basename "$f")"
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
hash_check "$ADV/advisories/github-reviewed/2026/02/GHSA-q447-rj3r-2cgh/GHSA-q447-rj3r-2cgh.json" \
  9d5a4294f2d0886bfbf8c4130ab9edc803c36190d068abda475b798009e0c812
adv_head=$(gitq -C "$ADV" rev-parse HEAD)
[[ $adv_head == 39d8887723797efc1804585dd06585c9fd751226 ]] || fail "ADV_HEAD $adv_head"

echo "== conservation 1=1+0 =="
python3 - << PY
import json, sys
from pathlib import Path
owned = Path("$OWNED")
ass = [json.loads(l) for l in owned.joinpath("assignment.jsonl").open() if l.strip()]
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open() if l.strip()]
res = json.loads(owned.joinpath("result.json").read_text())
aids = [a["case_id"] for a in ass]
cids = [c["case_id"] for c in cas]
want = ["GHSA-Q447-RJ3R-2CGH"]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c or "clone" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if any(a.get("nearclosed_h_is_not_evidence") is not True for a in ass):
    print("NEARCLOSED_FLAG_FAIL"); sys.exit(1)
if [a["fp211_ordinal"] for a in ass] != [47]:
    print("ORDINAL_FAIL"); sys.exit(1)
if len(cas) != 1 or cas[0]["verdict"] != "PASS_PROPOSAL":
    print("COUNT_FAIL", cas[0]["verdict"] if cas else None); sys.exit(1)
if res["conservation"]["equation"] != "1=1+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposal_ids"] != ["GHSA-Q447-RJ3R-2CGH"]:
    print("PASS_IDS_FAIL"); sys.exit(1)
if res["canonical_strict_count_untouched"] != 90:
    print("FLAG_FAIL"); sys.exit(1)
rec = cas[0]
g = rec["gates"]
for k in need:
    if g[k] != "PASS":
        print("BAD_GATE", k, g[k]); sys.exit(1)
if rec.get("osv_introduced_used_as_causal_proof") is not False:
    print("OSV_USED_AS_PROOF"); sys.exit(1)
if rec.get("authorship_transfer") is not False:
    print("TRANSFER"); sys.exit(1)
if rec.get("nearclosed_h_is_not_evidence") is not True:
    print("CASE_NEARCLOSED_FLAG"); sys.exit(1)
if rec["seven_gates_exact_pass"] is not True:
    print("SEVEN_NOT_PASS"); sys.exit(1)
if rec["contribution_class"] != "AI_NEW_SURFACE_CONTRIBUTOR":
    print("CLASS"); sys.exit(1)
if rec["candidate_set"] != ["5c2cb6c591e4b63c2df0549ad2202403256e2a96"]:
    print("CAND"); sys.exit(1)
if "b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517" in rec["candidate_set"]:
    print("MEMBER_IN_CAND"); sys.exit(1)
if rec["minimum_fix_set"] != ["3cbcba10cf30c2ffb898f0d8c7dfb929f15f8930"]:
    print("FIXSET"); sys.exit(1)
if rec["aliases"] != ["CVE-2026-28478"]:
    print("ALIAS"); sys.exit(1)
print("CONSERVATION_OK 1=1+0 PASS_PROPOSAL=1")
PY

echo "== uniqueness vs pinned canonical90 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical90/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open() if l.strip()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical90", hit); sys.exit(1)
if "GHSA-Q447-RJ3R-2CGH" in strict:
    print("UNIQUENESS_FAIL Q447_COUNTED"); sys.exit(1)
if "GHSA-G353-MGV3-8PCJ" in strict:
    print("UNIQUENESS_FAIL G353_COUNTED"); sys.exit(1)
if "GHSA-XH72-V6V9-MWHC" in strict:
    print("UNIQUENESS_FAIL XH72_COUNTED"); sys.exit(1)
if len(strict) != 90:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
if "GHSA-XMXX-7P24-H892" not in strict:
    print("XMXX_MISSING_COUNTED"); sys.exit(1)
if "GHSA-PQH8-P93P-2RX7" not in strict:
    print("PQH8_MISSING_COUNTED"); sys.exit(1)
adv = json.loads(Path("$ADV/advisories/github-reviewed/2026/02/GHSA-q447-rj3r-2cgh/GHSA-q447-rj3r-2cgh.json").read_text())
if adv.get("id","").upper() != "GHSA-Q447-RJ3R-2CGH":
    print("ADV_ID", adv.get("id")); sys.exit(1)
if adv.get("aliases") != ["CVE-2026-28478"]:
    print("ADV_ALIASES", adv.get("aliases")); sys.exit(1)
if adv["database_specific"].get("github_reviewed") is not True:
    print("ADV_NOT_REVIEWED"); sys.exit(1)
details = adv.get("details","")
if "Feishu" not in details:
    print("ADV_MISSING_FEISHU"); sys.exit(1)
if "unbounded webhook" not in details.lower() and "buffered request bodies" not in details:
    print("ADV_MISSING_BODY"); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "Q447_ABSENT_CANONICAL90 DISTINCT_G353_XH72")
PY

echo "== git facts =="
[[ -d $Z ]] || fail "CLONE_ABSENT"
SQ=5c2cb6c591e4b63c2df0549ad2202403256e2a96
M=b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517
F=3cbcba10cf30c2ffb898f0d8c7dfb929f15f8930
P=49c60e9065d98a6848e62c717315eb91eeaa6038
PEEL12=d8d69ccbf464788a3ac0406b917d422ddf0dd84e
PEEL13=e91d957d7089d2ca9589255245eead0edddc16d5
NPM12=f9e444dd56ccfc2271e8ae1729b7a14a55e1c11e
NPM13=203b5bdf710ad636844d4142f16e81c95890c2c7
FILE=extensions/feishu/src/monitor.ts
gitq -C "$Z" cat-file -t "$SQ" >/dev/null
gitq -C "$Z" cat-file -t "$M" >/dev/null
gitq -C "$Z" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$Z" rev-list --parents -n 1 "$SQ")
[[ $parents == "$SQ $P" ]] || fail "PARENTS $parents"
gitq -C "$Z" cat-file -p "$SQ" | LC_ALL=C grep -q 'Co-authored-by: Claude Opus 4.6' || fail "SQUASH_MARKER"
gitq -C "$Z" cat-file -p "$M" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.6' || fail "MEMBER_MARKER"
gitq -C "$Z" cat-file -p "$F" | LC_ALL=C grep -E -q 'Co-authored-by:|Co-Authored-By:|Claude' && fail "FIX_HAS_AI" || true
if gitq -C "$Z" grep -q adaptDefault "$P" -- "$FILE"; then
  fail "PARENT_HAS_ADAPT"
fi
gitq -C "$Z" grep -q 'webhook mode not implemented in monitor' "$P" -- "$FILE" || fail "PARENT_UNIMPLEMENTED"
gitq -C "$Z" grep -q 'Lark.adaptDefault' "$SQ" -- "$FILE" || fail "SQUASH_ADAPT"
if gitq -C "$Z" grep -q installRequestBodyLimitGuard "$SQ" -- "$FILE"; then
  fail "SQUASH_HAS_GUARD"
fi
gitq -C "$Z" grep -q 'Lark.adaptDefault' v2026.2.12 -- "$FILE" || fail "V212_ADAPT"
if gitq -C "$Z" grep -q installRequestBodyLimitGuard v2026.2.12 -- "$FILE"; then
  fail "V212_HAS_GUARD"
fi
gitq -C "$Z" grep -q installRequestBodyLimitGuard "$F" -- "$FILE" || fail "FIX_GUARD"
pk=$(gitq -C "$Z" log --first-parent -S adaptDefault --format='%H' v2026.2.12 -- "$FILE")
print -r -- "$pk" | LC_ALL=C grep -q '^5c2cb6c591e4b63c2df0549ad2202403256e2a96' || fail "PICKAXE $pk"
later=$(gitq -C "$Z" log --first-parent --format='%H' ${SQ}..v2026.2.12 -- "$FILE")
[[ -z "$later" ]] || fail "LATER_REWRITE $later"
gitq -C "$Z" merge-base --is-ancestor "$M" "$SQ" && fail "MEMBER_ANC_SQUASH" || true
gitq -C "$Z" merge-base --is-ancestor "$M" "$PEEL12" && fail "MEMBER_IN_VULN" || true
gitq -C "$Z" merge-base --is-ancestor "$M" "$F" && fail "MEMBER_ANC_FIX" || true
gitq -C "$Z" merge-base --is-ancestor "$SQ" "$PEEL12" || fail "SQUASH_TAG"
gitq -C "$Z" merge-base --is-ancestor "$F" "$PEEL12" && fail "FIX_IN_VULN" || true
gitq -C "$Z" merge-base --is-ancestor "$F" "$PEEL13" || fail "FIX_TAG"
gitq -C "$Z" merge-base --is-ancestor "$SQ" "$NPM12" || fail "SQUASH_NPM12"
gitq -C "$Z" merge-base --is-ancestor "$F" "$NPM12" && fail "FIX_IN_NPM12" || true
gitq -C "$Z" merge-base --is-ancestor "$F" "$NPM13" || fail "FIX_NPM13"
peel=$(gitq -C "$Z" rev-parse 'v2026.2.12^{commit}')
[[ $peel == "$PEEL12" ]] || fail "PEEL12 $peel"
peel=$(gitq -C "$Z" rev-parse 'v2026.2.13^{commit}')
[[ $peel == "$PEEL13" ]] || fail "PEEL13 $peel"
tagobj=$(gitq -C "$Z" rev-parse v2026.2.12)
[[ $tagobj == ed0a4cb3611d764773ee7c2ac6ee309750175192 ]] || fail "TAGOBJ12 $tagobj"
blob_p=$(gitq -C "$Z" rev-parse "${P}:${FILE}")
blob_m=$(gitq -C "$Z" rev-parse "${M}:${FILE}")
blob_s=$(gitq -C "$Z" rev-parse "${SQ}:${FILE}")
blob_v=$(gitq -C "$Z" rev-parse "${PEEL12}:${FILE}")
blob_f=$(gitq -C "$Z" rev-parse "${F}:${FILE}")
blob_v2=$(gitq -C "$Z" rev-parse "${PEEL13}:${FILE}")
blob_n12=$(gitq -C "$Z" rev-parse "${NPM12}:${FILE}")
blob_n13=$(gitq -C "$Z" rev-parse "${NPM13}:${FILE}")
[[ $blob_p == 24ba1211c9c10be9b895674831abdf92fd296a6c ]] || fail "BLOB_P $blob_p"
[[ $blob_m == 31a890c2f92da2586c0c1f96c1d47a71100be610 ]] || fail "BLOB_M $blob_m"
[[ $blob_s == 31a890c2f92da2586c0c1f96c1d47a71100be610 ]] || fail "BLOB_S $blob_s"
[[ $blob_v == 31a890c2f92da2586c0c1f96c1d47a71100be610 ]] || fail "BLOB_V $blob_v"
[[ $blob_f == 51af5a4aeb48d3732c02bcfaf7538172cfd17ea0 ]] || fail "BLOB_F $blob_f"
[[ $blob_f == "$blob_v2" ]] || fail "FIX_BLOB $blob_f $blob_v2"
[[ $blob_m == "$blob_s" ]] || fail "MEMBER_NE_SQUASH_BLOB"
[[ $blob_s == "$blob_v" ]] || fail "SQUASH_NE_V212"
[[ $blob_n12 == "$blob_v" ]] || fail "NPM12_BLOB"
[[ $blob_n13 == "$blob_v2" ]] || fail "NPM13_BLOB"
http212=$(gitq -C "$Z" ls-tree --name-only "$PEEL12" -- src/infra/http-body.ts)
[[ -z "$http212" ]] || fail "HTTP_BODY_IN_212"
http213=$(gitq -C "$Z" ls-tree --name-only "$PEEL13" -- src/infra/http-body.ts)
[[ $http213 == src/infra/http-body.ts ]] || fail "HTTP_BODY_MISSING_213"
fsubj=$(gitq -C "$Z" log -1 --format='%s' "$F")
[[ $fsubj == *"bounded webhook body handling"* ]] || fail "FIX_SUBJ $fsubj"
echo "GIT_OK"

echo "== npm archives =="
curl -fsSL -o "$REPLAY_TMP/openclaw-2026.2.12.tgz" \
  https://registry.npmjs.org/openclaw/-/openclaw-2026.2.12.tgz
curl -fsSL -o "$REPLAY_TMP/openclaw-2026.2.13.tgz" \
  https://registry.npmjs.org/openclaw/-/openclaw-2026.2.13.tgz
c1=$(sha256sum "$REPLAY_TMP/openclaw-2026.2.12.tgz" | awk '{print $1}')
c2=$(sha256sum "$REPLAY_TMP/openclaw-2026.2.13.tgz" | awk '{print $1}')
[[ $c1 == 0adafbffc20a4db8e6e4e1f51c6363fdf5a510b811dded7a752788740a31a8ba ]] || fail "NPM12 $c1"
[[ $c2 == 52a6d49b5dbfffd20ed8540dac438bc234c96cd5a59ab9c012e1a63b017198c8 ]] || fail "NPM13 $c2"
mkdir "$REPLAY_TMP/n12" "$REPLAY_TMP/n13"
tar -C "$REPLAY_TMP/n12" -xzf "$REPLAY_TMP/openclaw-2026.2.12.tgz"
tar -C "$REPLAY_TMP/n13" -xzf "$REPLAY_TMP/openclaw-2026.2.13.tgz"
LC_ALL=C grep -q 'Lark.adaptDefault' \
  "$REPLAY_TMP/n12/package/extensions/feishu/src/monitor.ts" || fail "NPM12_ADAPT"
if LC_ALL=C grep -q installRequestBodyLimitGuard \
  "$REPLAY_TMP/n12/package/extensions/feishu/src/monitor.ts"; then
  fail "NPM12_STILL_GUARD"
fi
LC_ALL=C grep -q installRequestBodyLimitGuard \
  "$REPLAY_TMP/n13/package/extensions/feishu/src/monitor.ts" || fail "NPM13_GUARD"
gitq -C "$Z" show "${PEEL12}:${FILE}" >"$REPLAY_TMP/git12.ts"
gitq -C "$Z" show "${PEEL13}:${FILE}" >"$REPLAY_TMP/git13.ts"
cmp -s "$REPLAY_TMP/n12/package/extensions/feishu/src/monitor.ts" "$REPLAY_TMP/git12.ts" || fail "NPM12_NE_GIT"
cmp -s "$REPLAY_TMP/n13/package/extensions/feishu/src/monitor.ts" "$REPLAY_TMP/git13.ts" || fail "NPM13_NE_GIT"
echo "NPM_OK"

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
    raise SystemExit("extra %s" % sorted(extra))
print("hygiene_ok")
PY

echo "REPLAY_OK reviewed=1 PASS_proposal=1 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0"
