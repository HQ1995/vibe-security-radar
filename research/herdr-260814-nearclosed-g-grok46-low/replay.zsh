#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearclosed-g-grok46-low}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
CB=${CB:-/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/codexbar}
ZC=${ZC:-/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/zeptoclaw}
CY=${CY:-/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/coolify}
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

catfile_e() {
  GITQ_N=$((GITQ_N + 1))
  local outfile errfile rc
  outfile="$REPLAY_TMP/out.$GITQ_N"
  errfile="$REPLAY_TMP/err.$GITQ_N"
  set +e
  command git -C "$1" cat-file -e "$2" >"$outfile" 2>"$errfile"
  rc=$?
  set -e
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
hash_check "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/8rw6_acceptance.json" \
  8cb85b42f405595b834a4ccae9b782c488b8dfa340900ad5717bb0dac71cfae9

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
    "GHSA-42M6-XH7C-6XM4",
    "GHSA-2M67-CXXQ-C3H8",
    "GHSA-Q9J6-XCVX-PX63",
]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
okv = ("PASS","FAIL","UNKNOWN","NARROW","BLOCKED")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c or "clone" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
n_pass = sum(1 for c in cas if c["verdict"] == "PASS_PROPOSAL")
n_nar = sum(1 for c in cas if c["verdict"] == "NARROW")
if n_pass != 0 or n_nar != 3 or len(cas) != 3:
    print("COUNT_FAIL", n_pass, n_nar); sys.exit(1)
if res["conservation"]["equation"] != "3=3+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposals"] != [] or res["canonical_strict_count_untouched"] != 88:
    print("FLAG_FAIL"); sys.exit(1)
for rec in cas:
    g = rec["gates"]
    for k in need:
        if g[k] not in okv:
            print("BAD_GATE", rec["case_id"], k, g[k]); sys.exit(1)
    if rec.get("osv_introduced_used_as_causal_proof") is not False:
        print("OSV_USED_AS_PROOF", rec["case_id"]); sys.exit(1)
    if rec.get("authorship_transfer") is not False:
        print("TRANSFER", rec["case_id"]); sys.exit(1)
    if rec["verdict"] != "NARROW" or rec.get("proposed_pass") is not False:
        print("NOT_NARROW", rec["case_id"]); sys.exit(1)
    if g["release_gate"] != "PASS":
        print("RELEASE_NOT_PASS", rec["case_id"]); sys.exit(1)
    if g["but_for_gate"] != "NARROW":
        print("BUTFOR_NOT_NARROW", rec["case_id"]); sys.exit(1)
print("CONSERVATION_OK 3=3+0 NARROW=3 PASS_PROPOSAL=0")
PY

echo "== uniqueness vs pinned canonical88 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open() if l.strip()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical88", hit); sys.exit(1)
if "GHSA-8RW6-P7M8-63JP" in ids:
    print("UNIQUENESS_FAIL 8RW6"); sys.exit(1)
if len(strict) != 88:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
print("UNIQUENESS_OK", len(ids))
PY

echo "== git facts =="
[[ -d $CB && -d $ZC && -d $CY ]] || fail "CLONE_ABSENT"

# 42M6
OR=8348c85cd8d43affa0c9d83be20ff42d895fe1dc
DS=b6b77b4b8ea803b671dea666bc76135e6af0c057
KM=c3a0304298597ace4026a9778cb0025309b628a3
HT=f62bb8c8d5640c079af6934f14406a5cffe2e367
FX=08c171b6b487654a0eb188494fa24bd1c4272a2e
gitq -C "$CB" cat-file -t "$OR" >/dev/null
gitq -C "$CB" cat-file -t "$DS" >/dev/null
gitq -C "$CB" cat-file -t "$KM" >/dev/null
gitq -C "$CB" cat-file -t "$HT" >/dev/null
gitq -C "$CB" cat-file -t "$FX" >/dev/null
parents=$(gitq -C "$CB" rev-list --parents -n 1 "$OR")
[[ $parents == "$OR b8189b4cf93f92e2c5c3920b100f9e455c40a77b" ]] || fail "42M6_OR_PARENTS $parents"
parents=$(gitq -C "$CB" rev-list --parents -n 1 "$DS")
[[ $parents == "$DS 26316483a851398bcd0bdf19d2e26057e994f968" ]] || fail "42M6_DS_PARENTS $parents"
parents=$(gitq -C "$CB" rev-list --parents -n 1 "$KM")
[[ $parents == "$KM e23a0c4411eae846816a0359dbed3aec52522b7d" ]] || fail "42M6_KM_PARENTS $parents"
gitq -C "$CB" cat-file -p "$OR" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5' || fail "42M6_OR_MARKER"
gitq -C "$CB" cat-file -p "$DS" | LC_ALL=C grep -q 'Co-Authored-By: Claude Sonnet 4.6' || fail "42M6_DS_MARKER"
gitq -C "$CB" cat-file -p "$KM" | LC_ALL=C grep -q 'Co-Authored-By: Claude' || fail "42M6_KM_MARKER"
if gitq -C "$CB" cat-file -p "$HT" | LC_ALL=C grep -q 'Co-Authored-By: Claude'; then
  fail "42M6_HUMAN_TRANSPORT_CLAUDE"
fi
catfile_e "$CB" "${OR}:Sources/CodexBarCore/ProviderHTTPClient.swift" && fail "42M6_OR_HAS_TRANSPORT" || true
catfile_e "$CB" "${DS}:Sources/CodexBarCore/ProviderHTTPClient.swift" && fail "42M6_DS_HAS_TRANSPORT" || true
catfile_e "$CB" "${KM}:Sources/CodexBarCore/ProviderHTTPClient.swift" && fail "42M6_KM_HAS_TRANSPORT" || true
gitq -C "$CB" grep -q 'class ProviderHTTPClient' "$HT" -- Sources/CodexBarCore/ProviderHTTPClient.swift || fail "42M6_HUMAN_TRANSPORT"
gitq -C "$CB" grep -q ProviderHTTPClient "$FX" -- Sources/CodexBarCore/ProviderHTTPClient.swift || fail "42M6_FIX_TRANSPORT"
fsubj=$(gitq -C "$CB" log -1 --format='%s' "$FX")
[[ $fsubj == *"credentialed redirects"* ]] || fail "42M6_FIX_SUBJ $fsubj"
gitq -C "$CB" merge-base --is-ancestor "$OR" v0.32.0 || fail "42M6_OR_TAG"
gitq -C "$CB" merge-base --is-ancestor "$DS" v0.32.0 || fail "42M6_DS_TAG"
gitq -C "$CB" merge-base --is-ancestor "$KM" v0.32.0 || fail "42M6_KM_TAG"
gitq -C "$CB" merge-base --is-ancestor "$HT" v0.32.0 || fail "42M6_HT_TAG"
gitq -C "$CB" merge-base --is-ancestor "$FX" v0.32.0 && fail "42M6_FIX_IN_VULN" || true
gitq -C "$CB" merge-base --is-ancestor "$FX" v0.33.0 || fail "42M6_FIX_TAG"
peel32=$(gitq -C "$CB" rev-parse 'v0.32.0^{commit}')
peel33=$(gitq -C "$CB" rev-parse 'v0.33.0^{commit}')
[[ $peel32 == 1351961f4d6a286df8dc26cb6e021ab40e7b552d ]] || fail "42M6_PEEL_32 $peel32"
[[ $peel33 == 6cf422512061924c5bae185fef5dd39194e0ac50 ]] || fail "42M6_PEEL_33 $peel33"
echo "42M6_OK"

# 2M67
MEM=fe70dcd422adbd1e95c90b097489380bf84c4c55
CAR=51bc07a02484ddfd2ec9c7f382dc43f829a9df86
F1=f50c17e11ae3e2d40c96730abac41974ef2ee2a8
F2=bf004a20d3687a0c1a9e052ec79536e30d6de134
P=24386e4b289c6e247e0b32bf5bae1814cdb024ae
gitq -C "$ZC" cat-file -t "$MEM" >/dev/null
gitq -C "$ZC" cat-file -t "$CAR" >/dev/null
gitq -C "$ZC" cat-file -t "$F1" >/dev/null
gitq -C "$ZC" cat-file -t "$F2" >/dev/null
parents=$(gitq -C "$ZC" rev-list --parents -n 1 "$CAR")
[[ $parents == "$CAR $P" ]] || fail "2M67_CAR_PARENTS $parents"
gitq -C "$ZC" cat-file -p "$CAR" | LC_ALL=C grep -q 'Co-authored-by: Claude Sonnet 4.6' || fail "2M67_CAR_MARKER"
gitq -C "$ZC" merge-base --is-ancestor "$MEM" "$CAR" && fail "2M67_MEMBER_ANC_CARRIER" || true
gitq -C "$ZC" merge-base --is-ancestor "$MEM" v0.5.0 && fail "2M67_MEMBER_IN_VULN" || true
gitq -C "$ZC" merge-base --is-ancestor "$MEM" v0.7.6 && fail "2M67_MEMBER_IN_FIXED" || true
catfile_e "$ZC" "${P}:src/tools/pdf_read.rs" && fail "2M67_PARENT_HAS_PDF" || true
gitq -C "$ZC" grep -q validate_path_in_workspace "$P" -- src/tools/filesystem.rs || fail "2M67_PARENT_FS"
gitq -C "$ZC" grep -q validate_path_in_workspace "$CAR" -- src/tools/pdf_read.rs || fail "2M67_SQUASH_PDF"
if gitq -C "$ZC" grep -q revalidate_path v0.5.0 -- src/tools/pdf_read.rs; then
  fail "2M67_V050_ALREADY_REVALIDATE"
fi
gitq -C "$ZC" grep -q revalidate_path "$F1" -- src/tools/pdf_read.rs || fail "2M67_F1_PDF"
gitq -C "$ZC" grep -q revalidate_path "$F1" -- src/tools/filesystem.rs || fail "2M67_F1_FS"
blob050=$(gitq -C "$ZC" rev-parse 'v0.5.0:src/tools/pdf_read.rs')
blob070=$(gitq -C "$ZC" rev-parse 'v0.7.0:src/tools/pdf_read.rs')
blob076=$(gitq -C "$ZC" rev-parse 'v0.7.6:src/tools/pdf_read.rs')
blobf1=$(gitq -C "$ZC" rev-parse "${F1}:src/tools/pdf_read.rs")
[[ $blob050 == 8d9747ecbd6d8229e92053598682faeeeae7967e ]] || fail "2M67_BLOB050 $blob050"
[[ $blob070 == "$blob076" && $blob076 == "$blobf1" ]] || fail "2M67_PDF_ALREADY_EQUAL_AT_076"
[[ $blobf1 == 21e0bd740010585619a7407a7416f216ba379d17 ]] || fail "2M67_BLOBF1 $blobf1"
fsubj=$(gitq -C "$ZC" log -1 --format='%s' "$F1")
[[ $fsubj == *"dangling symlink"* ]] || fail "2M67_F1_SUBJ $fsubj"
gitq -C "$ZC" merge-base --is-ancestor "$CAR" v0.5.0 || fail "2M67_CAR_V050"
gitq -C "$ZC" merge-base --is-ancestor "$F1" v0.5.0 && fail "2M67_F1_IN_V050" || true
gitq -C "$ZC" merge-base --is-ancestor "$F1" v0.7.0 || fail "2M67_F1_V070"
gitq -C "$ZC" merge-base --is-ancestor "$F2" v0.5.0 && fail "2M67_F2_IN_V050" || true
gitq -C "$ZC" merge-base --is-ancestor "$F2" v0.7.6 || fail "2M67_F2_V076"
peel050=$(gitq -C "$ZC" rev-parse 'v0.5.0^{commit}')
peel070=$(gitq -C "$ZC" rev-parse 'v0.7.0^{commit}')
peel076=$(gitq -C "$ZC" rev-parse 'v0.7.6^{commit}')
[[ $peel050 == 4ba4e4318cccc335f3fe8f7e30d5b4e0729c8c48 ]] || fail "2M67_PEEL050 $peel050"
[[ $peel070 == 478028ac29ba42799b5816f4bc2d83f5aa0d2561 ]] || fail "2M67_PEEL070 $peel070"
[[ $peel076 == b64cb54d013af1bb2a3be5a3b629e86f7bf25079 ]] || fail "2M67_PEEL076 $peel076"
echo "2M67_OK"

# Q9J6
MEM=bbb2aa9ad4e0c14517d32272b5e6d83318fde493
CAR=4d4254b591ede243b38df7b678cf36619cb25825
FX=f267a28cb2badc7e712c4592af4d79d090fe5063
FM=48ba4ece3c1b43cb4b9627438c0ff4e4251e3511
PP=b484c0cc253ff9845fda130671004f5451fea84f
gitq -C "$CY" cat-file -t "$MEM" >/dev/null
gitq -C "$CY" cat-file -t "$CAR" >/dev/null
gitq -C "$CY" cat-file -t "$FX" >/dev/null
gitq -C "$CY" cat-file -t "$FM" >/dev/null
parents=$(gitq -C "$CY" rev-list --parents -n 1 "$MEM")
[[ $parents == "$MEM $PP" ]] || fail "Q9J6_MEM_PARENTS $parents"
parents=$(gitq -C "$CY" rev-list --parents -n 1 "$CAR")
[[ $parents == "$CAR 8be1a9b5de3aa287cebf705ed7bd39400d4f7291 $MEM" ]] || fail "Q9J6_CAR_PARENTS $parents"
an=$(gitq -C "$CY" log -1 --format='%an' "$MEM")
[[ $an == "Claude" ]] || fail "Q9J6_AUTHOR $an"
gitq -C "$CY" grep -q 'docker logs -n' "$PP" -- app/Livewire/Project/Shared/GetLogs.php || fail "Q9J6_PARENT_GETLOGS"
if gitq -C "$CY" grep -q downloadAllLogs "$PP" -- app/Livewire/Project/Shared/GetLogs.php; then
  fail "Q9J6_PARENT_HAS_DOWNLOAD_ALL"
fi
gitq -C "$CY" grep -q downloadAllLogs "$MEM" -- app/Livewire/Project/Shared/GetLogs.php || fail "Q9J6_MEM_DOWNLOAD"
gitq -C "$CY" grep -q 'docker logs' "$MEM" -- app/Livewire/Project/Shared/GetLogs.php || fail "Q9J6_MEM_INTERP"
gitq -C "$CY" grep -q '#\[Locked\]' "$FM" -- app/Livewire/Project/Shared/GetLogs.php || fail "Q9J6_FM_LOCKED"
gitq -C "$CY" grep -q downloadAllLogs "$FM" -- app/Livewire/Project/Shared/GetLogs.php || fail "Q9J6_FM_DOWNLOAD"
blobfm=$(gitq -C "$CY" rev-parse "${FM}:app/Livewire/Project/Shared/GetLogs.php")
blobfx=$(gitq -C "$CY" rev-parse "${FX}:app/Livewire/Project/Shared/GetLogs.php")
blob471=$(gitq -C "$CY" rev-parse 'v4.0.0-beta.471:app/Livewire/Project/Shared/GetLogs.php')
[[ $blobfm == "$blobfx" && $blobfx == "$blob471" ]] || fail "Q9J6_GETLOGS_BLOB"
[[ $blobfm == d0121bdc51768e57e1db709eccb317528264a591 ]] || fail "Q9J6_BLOB $blobfm"
gitq -C "$CY" merge-base --is-ancestor "$MEM" "$CAR" || fail "Q9J6_MEM_ANC_CAR"
gitq -C "$CY" merge-base --is-ancestor "$MEM" v4.0.0-beta.470 || fail "Q9J6_MEM_V470"
gitq -C "$CY" merge-base --is-ancestor "$FM" v4.0.0-beta.470 && fail "Q9J6_FM_IN_VULN" || true
gitq -C "$CY" merge-base --is-ancestor "$FX" v4.0.0-beta.470 && fail "Q9J6_FX_IN_VULN" || true
gitq -C "$CY" merge-base --is-ancestor "$FM" v4.0.0-beta.471 || fail "Q9J6_FM_FIXED"
gitq -C "$CY" merge-base --is-ancestor "$FX" v4.0.0-beta.471 || fail "Q9J6_FX_FIXED"
peel470=$(gitq -C "$CY" rev-parse 'v4.0.0-beta.470^{commit}')
peel471=$(gitq -C "$CY" rev-parse 'v4.0.0-beta.471^{commit}')
[[ $peel470 == 575b0766d12bad2a78febff72ab59c017772bcf7 ]] || fail "Q9J6_PEEL470 $peel470"
[[ $peel471 == 914d7e0b50505bc1fd56c34974fca09ad354e92a ]] || fail "Q9J6_PEEL471 $peel471"
echo "Q9J6_OK"

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

echo "REPLAY_OK reviewed=3 PASS_proposal=0 NARROW=3 REJECT=0 UNKNOWN=0 BLOCKED=0"
