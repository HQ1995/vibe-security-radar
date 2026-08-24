#!/usr/bin/env zsh
set -euo pipefail
OWNED="autoresearch/herdr-260814-confirmmedium-a-grok46-high"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OWNED_ABS="$ROOT/$OWNED"
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

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  python3 - "$OWNED_ABS/$f" <<'PY' || fail "ascii $f"
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

python3 - "$OWNED_ABS" <<'PY' || fail "json parse/conservation"
import json,sys
from pathlib import Path
d=Path(sys.argv[1])
assign=[json.loads(l) for l in (d/"assignment.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l) for l in (d/"cases.jsonl").read_text().splitlines() if l.strip()]
res=json.loads((d/"result.json").read_text())
assert len(assign)==3 and len(cases)==3
aids=[a["case_id"] for a in assign]
cids=[c["case_id"] for c in cases]
expect=["GHSA-P52P-4VMG-4VQ3","GHSA-4MR5-G6F9-CFRH","GHSA-94P4-4CQ8-9G67"]
assert aids==cids==expect==res["conservation"]["reviewed_case_ids"]
assert res["conservation"]["equation"]=="3=3+0"
assert res["conservation"]["holds"] is True
assert res["counts"]["assigned"]==3 and res["counts"]["reviewed"]==3
assert res["counts"]["PASS"]==0 and res["counts"]["NARROW"]==2 and res["counts"]["REJECT"]==1
assert res["pass_proposals"]==[]
assert res["packet_delta"]==0
assert res["canonical_strict_count_untouched"]==91
assert cases[0]["verdict"]=="NARROW" and cases[1]["verdict"]=="NARROW" and cases[2]["verdict"]=="REJECT"
assert all(c.get("proposed_pass") is False for c in cases)
assert cases[0]["gates"]["identity_gate"]!="PASS"
assert cases[1]["gates"]["but_for_gate"]!="PASS"
assert cases[2]["gates"]["but_for_gate"]=="FAIL"
assert all(v in ("PASS","FAIL","NARROW","UNKNOWN","BLOCKED") for c in cases for v in c["gates"].values())
print("json_ok")
PY

need_obj() {
  local repo="$1" sha="$2"
  [[ -e "$repo/.git" || -f "$repo/.git" ]] || fail "missing clone $repo"
  gitq -C "$repo" cat-file -t "$sha" | grep -qx commit || fail "missing commit $sha in $repo"
}

H="/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/hermes-webui"
P="/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/praisonai"
G="/home/hanqing/.cache/ghsa200-worker-clones/incomplete-rem-redteam/clones/GitPython"

C114=b8b62722ec2f6b3cd394737ab409c35650f29ca6
M114=1126e541325d401538f6a272a9c024c37d47ae08
F114=f2ef2851d389cf7a41308dcf0180d7cfbe446379
C128=3cd664bf7b7db5f774c1e7e3123a1a24c68ba700
F128=179cab02dbec0c1e9b601507a65908e079876004
C139=8ac5a30519b6f4af85398b9b9d7064ff4d452da2
F139=863417457a0633db7ea5aed4fd01e0b291a41162

need_obj "$H" "$C114"
need_obj "$H" "$M114"
need_obj "$H" "$F114"
[[ "$(gitq -C "$H" rev-list --parents -n 1 "$C114" | awk '{print NF-1}')" == "1" ]] || fail "p52p cand not atomic"
[[ "$(gitq -C "$H" rev-list --parents -n 1 "$M114" | awk '{print NF-1}')" == "2" ]] || fail "p52p inherited carrier not two-parent"
gitq -C "$H" rev-list --parents -n 1 "$M114" | grep -q "$F114" || fail "p52p inherited carrier missing closer parent"
[[ "$(gitq -C "$H" rev-parse "v0.51.357^{commit}")" == "5dceb2993cc0a6bc42697a30d370425db482609a" ]] || fail "p52p 357 peel"
[[ "$(gitq -C "$H" rev-parse "v0.51.358^{commit}")" == "$M114" ]] || fail "p52p 358 peel"
gitq -C "$H" merge-base --is-ancestor "$C114" v0.51.357 || fail "p52p cand not in 357"
if gitq -C "$H" merge-base --is-ancestor "$F114" v0.51.357; then
  fail "p52p closer unexpectedly in 357"
fi
gitq -C "$H" merge-base --is-ancestor "$F114" v0.51.358 || fail "p52p closer not in 358"
[[ "$(gitq -C "$H" rev-parse "v0.51.357:api/routes.py")" == "f7833569d4dd74d99aa0c942600943c4f379d6a2" ]] || fail "p52p 357 routes blob"
[[ "$(gitq -C "$H" rev-parse "${F114}:api/routes.py")" == "6b6ddcbb9638179411ea4564805df708c124a572" ]] || fail "p52p fix routes blob"
gitq -C "$H" grep -q "_set_password" "$C114" -- api/config.py || fail "p52p cand missing _set_password"
if gitq -C "$H" grep -q "_set_password" "${C114}^" -- api/config.py; then
  fail "p52p parent unexpectedly has _set_password"
fi

need_obj "$P" "$C128"
need_obj "$P" "$F128"
[[ "$(gitq -C "$P" rev-list --parents -n 1 "$C128" | awk '{print NF-1}')" == "1" ]] || fail "4mr5 cand not atomic"
gitq -C "$P" merge-base --is-ancestor "$C128" v4.6.39 || fail "4mr5 cand not in v4.6.39"
if gitq -C "$P" merge-base --is-ancestor "$F128" v4.6.39; then
  fail "4mr5 closer unexpectedly in v4.6.39"
fi
gitq -C "$P" merge-base --is-ancestor "$F128" v4.6.40 || fail "4mr5 closer not in v4.6.40"
[[ "$(gitq -C "$P" rev-parse "v4.6.39^{commit}")" == "402d7ed9fc5926babaa70c97a6ee5353e3d0dd62" ]] || fail "4mr5 v39 peel"
PYPATH="src/praisonai-agents/praisonaiagents/tools/python_tools.py"
[[ "$(gitq -C "$P" rev-parse "${C128}:${PYPATH}")" == "fcaf2927ff446e3a2bf4a0bb0c685ca6d9eaac38" ]] || fail "4mr5 cand python blob"
[[ "$(gitq -C "$P" rev-parse "v4.6.39:${PYPATH}")" == "c4ba5d9763f8dc05da26179f43172d9091a5116f" ]] || fail "4mr5 v39 python blob"
[[ "$(gitq -C "$P" rev-parse "${F128}:${PYPATH}")" == "83c5d83333ba08bbfcd76cc5bdb97eab48b0119c" ]] || fail "4mr5 fix python blob"
[[ "$(gitq -C "$P" rev-parse "v4.6.40:${PYPATH}")" == "83c5d83333ba08bbfcd76cc5bdb97eab48b0119c" ]] || fail "4mr5 v40 python blob"
[[ "$(gitq -C "$P" rev-parse "${C128}:${PYPATH}")" != "$(gitq -C "$P" rev-parse "v4.6.39:${PYPATH}")" ]] || fail "4mr5 cand blob unexpectedly equals v39"

need_obj "$G" "$C139"
need_obj "$G" "$F139"
[[ "$(gitq -C "$G" rev-list --parents -n 1 "$C139" | awk '{print NF-1}')" == "1" ]] || fail "94p4 cand not atomic"
gitq -C "$G" merge-base --is-ancestor "$C139" 3.1.54 || fail "94p4 cand not in 3.1.54"
if gitq -C "$G" merge-base --is-ancestor "$F139" 3.1.54; then
  fail "94p4 closer unexpectedly in 3.1.54"
fi
gitq -C "$G" merge-base --is-ancestor "$F139" 3.1.55 || fail "94p4 closer not in 3.1.55"
[[ "$(gitq -C "$G" rev-parse "3.1.54^{commit}")" == "e59d9bab02b095a97e179f47019afee95f4e3c18" ]] || fail "94p4 3.1.54 peel"
[[ "$(gitq -C "$G" rev-parse "${F139}^")" == "e59d9bab02b095a97e179f47019afee95f4e3c18" ]] || fail "94p4 closer parent not 3.1.54"
RPARENT="$(gitq -C "$G" rev-parse "${C139}^:git/remote.py")"
RCAND="$(gitq -C "$G" rev-parse "${C139}:git/remote.py")"
R3154="$(gitq -C "$G" rev-parse "3.1.54:git/remote.py")"
RFIX="$(gitq -C "$G" rev-parse "${F139}:git/remote.py")"
[[ "$RPARENT" == "0c3dbfe158628fdb5c9b0a76368a7209e0add34e" ]] || fail "94p4 parent remote blob"
[[ "$RCAND" == "$RPARENT" && "$R3154" == "$RPARENT" ]] || fail "94p4 remote blob not identical parent/cand/3.1.54"
[[ "$RFIX" == "e2d5cbc1d39039a66b3d9060fdb418d2f532f133" ]] || fail "94p4 fix remote blob"
[[ "$RFIX" != "$RPARENT" ]] || fail "94p4 fix remote blob unexpectedly equals parent"
if gitq -C "$G" diff --name-only "${C139}^" "$C139" | grep -qx git/remote.py; then
  fail "94p4 cand unexpectedly edits remote.py"
fi
gitq -C "$G" diff --name-only "${F139}^" "$F139" | grep -qx git/remote.py || fail "94p4 closer missing remote.py"

python3 - "$OWNED_ABS" <<'PY' || fail "hash mismatch"
import hashlib, json, sys
from pathlib import Path
d=Path(sys.argv[1])
res=json.loads((d/"result.json").read_text())
for name, expected in res["artifact_hashes"].items():
    got=hashlib.sha256((d/name).read_bytes()).hexdigest()
    if got!=expected:
        raise SystemExit(f"{name} {got} != {expected}")
print("hashes_ok")
PY

python3 - "$OWNED_ABS" <<'PY' || fail "durable extras"
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

echo "REPLAY_OK reviewed=3 PASS_proposal=0 NARROW=2 REJECT=1 UNKNOWN=0 BLOCKED=0"
