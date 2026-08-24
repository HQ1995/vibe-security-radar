#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-5wp8-hostile-redteam-grok46-high.
# English only. No credentials. Shared caches read-only. mktemp cleaned.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-5wp8-hostile-redteam-grok46-high}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
Z=${Z:-/home/hanqing/.cache/cve-analyzer/repos/qhkm_zeptoclaw}
ADV=${ADV:-/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database}
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
REPLAY_TMP="$(mktemp -d /tmp/5wp8-hostile.XXXXXX)"

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
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json" \
  81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl" \
  35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
hash_check "$ADV/advisories/github-reviewed/2026/03/GHSA-5wp8-q9mx-8jx8/GHSA-5wp8-q9mx-8jx8.json" \
  2dadc4ca9b6944e557d695d6097257d44d4bdd12048aefef6d54d566990884ba
adv_head=$(gitq -C "$ADV" rev-parse HEAD)
[[ $adv_head == a42c436870111aa3f221257c9d56126a93173ccc ]] || fail "ADV_HEAD $adv_head"

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
want = ["GHSA-5WP8-Q9MX-8JX8"]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c or "clone" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if any(a.get("nearclosed_e_is_not_evidence") is not True for a in ass):
    print("NEARCLOSED_FLAG_FAIL"); sys.exit(1)
if [a["fp211_ordinal"] for a in ass] != [126]:
    print("ORDINAL_FAIL"); sys.exit(1)
if len(cas) != 1 or cas[0]["verdict"] != "PASS_PROPOSAL":
    print("COUNT_FAIL", cas[0]["verdict"] if cas else None); sys.exit(1)
if res["conservation"]["equation"] != "1=1+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposal_ids"] != ["GHSA-5WP8-Q9MX-8JX8"]:
    print("PASS_IDS_FAIL"); sys.exit(1)
if res["canonical_strict_count_untouched"] != 88:
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
if rec.get("nearclosed_e_is_not_evidence") is not True:
    print("CASE_NEARCLOSED_FLAG"); sys.exit(1)
if rec["seven_gates_exact_pass"] is not True:
    print("SEVEN_NOT_PASS"); sys.exit(1)
if rec["contribution_class"] != "AI_INCOMPLETE_REMEDIATION":
    print("CLASS"); sys.exit(1)
if rec["candidate_set"] != ["1712debbea60af6adf4a8a5939a43f7ef9a1ac16"]:
    print("CAND"); sys.exit(1)
if "3c4368da0ab48c1091858d3f9503c378a209997f" in rec["candidate_set"]:
    print("MEMBER_IN_CAND"); sys.exit(1)
if "91f6c2bf98e40238ad4d175513f0ee400fd62068" in rec["candidate_set"]:
    print("BLOCKLIST_IN_CAND"); sys.exit(1)
if rec["minimum_fix_set"] != ["68916c3e4f3af107f11940b27854fc7ef517058b"]:
    print("FIXSET"); sys.exit(1)
print("CONSERVATION_OK 1=1+0 PASS_PROPOSAL=1")
PY

echo "== uniqueness vs pinned canonical88 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
neg = set(x.upper() for x in canon["checkpoint"]["negative_control_rejected"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open() if l.strip()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical88", hit); sys.exit(1)
if "GHSA-5WP8-Q9MX-8JX8" in strict:
    print("UNIQUENESS_FAIL 5WP8_COUNTED"); sys.exit(1)
if "GHSA-8RW6-P7M8-63JP" in ids:
    print("UNIQUENESS_FAIL 8RW6"); sys.exit(1)
if len(strict) != 88:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
if "GHSA-46Q5-G3J9-WX5C" not in strict:
    print("46Q5_MISSING_COUNTED"); sys.exit(1)
if "GHSA-HHJV-JQ77-CMVX" in strict:
    print("HHJV_COUNTED"); sys.exit(1)
if "GHSA-HHJV-JQ77-CMVX" not in neg:
    print("HHJV_NOT_NEGATIVE_CONTROL"); sys.exit(1)
if "GHSA-J8Q9-R9PQ-2HH9" in strict:
    print("J8Q9_COUNTED"); sys.exit(1)
adv = json.loads(Path("$ADV/advisories/github-reviewed/2026/03/GHSA-5wp8-q9mx-8jx8/GHSA-5wp8-q9mx-8jx8.json").read_text())
if adv.get("id","").upper() != "GHSA-5WP8-Q9MX-8JX8":
    print("ADV_ID", adv.get("id")); sys.exit(1)
if adv.get("aliases"):
    print("ADV_ALIASES", adv.get("aliases")); sys.exit(1)
if adv["database_specific"].get("github_reviewed") is not True:
    print("ADV_NOT_REVIEWED"); sys.exit(1)
details = adv.get("details","")
if "!self.allowlist.is_empty()" not in details:
    print("ADV_MISSING_SKIP_QUOTE"); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "5WP8_ABSENT_CANONICAL88 DISTINCT_46Q5_HHJV_J8Q9")
PY

echo "== git facts =="
[[ -d $Z ]] || fail "CLONE_ABSENT"
SQ=1712debbea60af6adf4a8a5939a43f7ef9a1ac16
M=3c4368da0ab48c1091858d3f9503c378a209997f
BL=91f6c2bf98e40238ad4d175513f0ee400fd62068
F=68916c3e4f3af107f11940b27854fc7ef517058b
P=c5bd830cd8969336f03a87f416d2ac7b4d244be2
DF=df8159e99685c9ddf71c06d641e61e693a95f78a
HUM=5059bea80259f6f4d28c3cfb7973ae84f4dba967
gitq -C "$Z" cat-file -t "$SQ" >/dev/null
gitq -C "$Z" cat-file -t "$M" >/dev/null
gitq -C "$Z" cat-file -t "$BL" >/dev/null
gitq -C "$Z" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$Z" rev-list --parents -n 1 "$SQ")
[[ $parents == "$SQ $P" ]] || fail "PARENTS $parents"
gitq -C "$Z" cat-file -p "$SQ" | LC_ALL=C grep -q 'Co-authored-by: Claude Sonnet 4.6' || fail "SQUASH_MARKER"
if gitq -C "$Z" grep -q ShellAllowlistMode "$P" -- src/security/shell.rs; then
  fail "PARENT_HAS_ALLOWLIST"
fi
gitq -C "$Z" grep -q 'allowlist_mode != ShellAllowlistMode::Off && !self.allowlist.is_empty()' "$SQ" -- src/security/shell.rs || fail "SQUASH_EMPTY_SKIP"
gitq -C "$Z" grep -q 'allowlist_mode != ShellAllowlistMode::Off && !self.allowlist.is_empty()' v0.6.1 -- src/security/shell.rs || fail "V061_EMPTY_SKIP"
if gitq -C "$Z" grep -q 'allowlist_mode != ShellAllowlistMode::Off && !self.allowlist.is_empty()' "$F" -- src/security/shell.rs; then
  fail "FIX_STILL_EMPTY_SKIP"
fi
gitq -C "$Z" grep -q 'Previously, `!self.allowlist.is_empty()` guard skipped' "$F" -- src/security/shell.rs || fail "FIX_COMMENT"
gitq -C "$Z" grep -q 'if self.allowlist_mode != ShellAllowlistMode::Off {' "$F" -- src/security/shell.rs || fail "FIX_NEW_GUARD"
pk=$(gitq -C "$Z" log --first-parent -S allowlist.is_empty --format='%H' v0.6.1 -- src/security/shell.rs)
print -r -- "$pk" | LC_ALL=C grep -q '^1712debbea60af6adf4a8a5939a43f7ef9a1ac16' || fail "PICKAXE $pk"
print -r -- "$pk" | LC_ALL=C grep -q "$DF" && fail "DF_PICKAXE" || true
if gitq -C "$Z" grep -q 'allowlist.is_empty' "$BL" -- src/security/shell.rs; then
  fail "BLOCKLIST_HAS_SKIP"
fi
gitq -C "$Z" cat-file -p "$HUM" | LC_ALL=C grep -E -q 'Co-authored-by:|Co-Authored-By:|Claude' && fail "HUMAN_BWRAP_MARKER" || true
gitq -C "$Z" merge-base --is-ancestor "$M" "$SQ" && fail "MEMBER_ANC_SQUASH" || true
gitq -C "$Z" merge-base --is-ancestor "$M" v0.6.1 && fail "MEMBER_IN_VULN" || true
gitq -C "$Z" merge-base --is-ancestor "$M" "$F" && fail "MEMBER_ANC_FIX" || true
gitq -C "$Z" merge-base --is-ancestor "$BL" "$SQ" || fail "BLOCKLIST_NOT_ANC_SQUASH"
gitq -C "$Z" merge-base --is-ancestor "$SQ" v0.6.1 || fail "SQUASH_TAG"
gitq -C "$Z" merge-base --is-ancestor "$F" v0.6.1 && fail "FIX_IN_VULN" || true
gitq -C "$Z" merge-base --is-ancestor "$F" v0.6.2 || fail "FIX_TAG"
peel=$(gitq -C "$Z" rev-parse 'v0.6.1^{commit}')
[[ $peel == ad14ed8d4e6f982af272523f4accc107b191fb18 ]] || fail "PEEL61 $peel"
peel=$(gitq -C "$Z" rev-parse 'v0.6.2^{commit}')
[[ $peel == f052aa21f298559729aa19b770da988f00a193df ]] || fail "PEEL62 $peel"
blob_p=$(gitq -C "$Z" rev-parse "${P}:src/security/shell.rs")
blob_m=$(gitq -C "$Z" rev-parse "${M}:src/security/shell.rs")
blob_s=$(gitq -C "$Z" rev-parse "${SQ}:src/security/shell.rs")
blob_v=$(gitq -C "$Z" rev-parse "v0.6.1:src/security/shell.rs")
blob_f=$(gitq -C "$Z" rev-parse "${F}:src/security/shell.rs")
blob_v2=$(gitq -C "$Z" rev-parse "v0.6.2:src/security/shell.rs")
[[ $blob_p == d82f28d314d572dc685c15ede7b8aeaa3b0fe8ae ]] || fail "BLOB_P $blob_p"
[[ $blob_m == a09e61719a32cb101160796755f777787007bdc6 ]] || fail "BLOB_M $blob_m"
[[ $blob_s == 165b10b5034f1782eb84ad8e97834581c07bddc4 ]] || fail "BLOB_S $blob_s"
[[ $blob_v == 87b9d900ab6e3a3504908518c1f62270ccb0cc97 ]] || fail "BLOB_V $blob_v"
[[ $blob_f == d923a585eb91f1cd6fb2c9e16874f64f14cab5b6 ]] || fail "BLOB_F $blob_f"
[[ $blob_f == "$blob_v2" ]] || fail "FIX_BLOB $blob_f $blob_v2"
[[ $blob_m != "$blob_s" ]] || fail "MEMBER_EQUALS_SQUASH"
[[ $blob_s != "$blob_v" ]] || fail "SQUASH_EQUALS_V061"
fsubj=$(gitq -C "$Z" log -1 --format='%s' "$F")
[[ $fsubj == *"patch shell blocklist bypass"* ]] || fail "FIX_SUBJ $fsubj"
echo "GIT_OK"

echo "== crates.io archives =="
curl -fsSL -o "$REPLAY_TMP/zeptoclaw-0.6.1.crate" \
  https://static.crates.io/crates/zeptoclaw/zeptoclaw-0.6.1.crate
curl -fsSL -o "$REPLAY_TMP/zeptoclaw-0.6.2.crate" \
  https://static.crates.io/crates/zeptoclaw/zeptoclaw-0.6.2.crate
c1=$(sha256sum "$REPLAY_TMP/zeptoclaw-0.6.1.crate" | awk '{print $1}')
c2=$(sha256sum "$REPLAY_TMP/zeptoclaw-0.6.2.crate" | awk '{print $1}')
[[ $c1 == 6df2cb167c5333e6152cc64bf14c8d4af1492aea5778fe6bf2870a418590aaf5 ]] || fail "CRATE061 $c1"
[[ $c2 == 1b834e0d7e0079342c339abb8620a7aca51cf22a330a8a754d0095a4da57cdb0 ]] || fail "CRATE062 $c2"
mkdir "$REPLAY_TMP/c061" "$REPLAY_TMP/c062"
tar -C "$REPLAY_TMP/c061" -xf "$REPLAY_TMP/zeptoclaw-0.6.1.crate"
tar -C "$REPLAY_TMP/c062" -xf "$REPLAY_TMP/zeptoclaw-0.6.2.crate"
LC_ALL=C grep -q 'allowlist_mode != ShellAllowlistMode::Off && !self.allowlist.is_empty()' \
  "$REPLAY_TMP/c061/zeptoclaw-0.6.1/src/security/shell.rs" || fail "CRATE061_SKIP"
if LC_ALL=C grep -q 'allowlist_mode != ShellAllowlistMode::Off && !self.allowlist.is_empty()' \
  "$REPLAY_TMP/c062/zeptoclaw-0.6.2/src/security/shell.rs"; then
  fail "CRATE062_STILL_SKIP"
fi
gitq -C "$Z" show 'v0.6.1:src/security/shell.rs' >"$REPLAY_TMP/git061.rs"
gitq -C "$Z" show 'v0.6.2:src/security/shell.rs' >"$REPLAY_TMP/git062.rs"
cmp -s "$REPLAY_TMP/c061/zeptoclaw-0.6.1/src/security/shell.rs" "$REPLAY_TMP/git061.rs" || fail "CRATE061_NE_GIT"
cmp -s "$REPLAY_TMP/c062/zeptoclaw-0.6.2/src/security/shell.rs" "$REPLAY_TMP/git062.rs" || fail "CRATE062_NE_GIT"
echo "CRATES_OK"

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
