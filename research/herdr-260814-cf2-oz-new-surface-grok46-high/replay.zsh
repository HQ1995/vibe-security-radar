#!/usr/bin/env zsh
set -euo pipefail
OWNED="autoresearch/herdr-260814-cf2-oz-new-surface-grok46-high"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OWNED_ABS="$ROOT/$OWNED"
CACHE="/home/hanqing/.cache/ghsa200-worker-clones/commit-oz"
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }

# ASCII-only owned outputs (exclude work/ helper scripts that may be larger)
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

python3 - "$OWNED_ABS" <<'PY' || fail "json parse"
import json,sys
from pathlib import Path
d=Path(sys.argv[1])
assign=[json.loads(l) for l in (d/"assignment.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l) for l in (d/"cases.jsonl").read_text().splitlines() if l.strip()]
res=json.loads((d/"result.json").read_text())
assert len(assign)==12 and len(cases)==12
aids=[a["case_id"] for a in assign]
cids=[c["case_id"] for c in cases]
assert aids==cids==res["conservation"]["reviewed_case_ids"]
assert res["counts"]["PASS"]==0 and res["counts"]["REJECT"]==12
assert res["counts"]["reviewed"]==12 and res["did_not_pad"] is True
assert all(c["verdict"]=="REJECT" for c in cases)
assert all(c.get("proposed_pass") is False for c in cases)
print("json_ok")
PY

clone_of() {
  echo "$CACHE/repos/${1//\//__}"
}

check_pair() {
  local spec="$1" ai="$2" fix="$3" extra="${4:-}"
  local repo
  repo="$(clone_of "$spec")"
  [[ -e "$repo/.git" || -f "$repo/.git" ]] || fail "missing clone $spec"
  git -C "$repo" cat-file -t "$ai" | grep -qx commit || fail "missing ai $ai"
  git -C "$repo" cat-file -t "$fix" | grep -qx commit || fail "missing fix $fix"
  git -C "$repo" merge-base --is-ancestor "$ai" "$fix" || fail "not ancestor $ai $fix"
  if [[ "$extra" == "merge_second_parent" ]]; then
    local parents
    parents="$(git -C "$repo" rev-list --parents -n 1 "$fix")"
    print -- "$parents" | grep -q "$ai" || fail "fix merge missing ai parent $fix"
  fi
}

check_pair OliveTin/OliveTin 0e45f3b0e3c9e81685bc85b7c4f21187bb0df085 995ff79736f2bccc364448a3ece84087b550b232 merge_second_parent
check_pair OliveTin/OliveTin 422044317ccd530d1f392039fe432c5512a1603e ec114e95d297b806c3ca0c37bc139b3c9c517b3f merge_second_parent
check_pair startreedata/mcp-pinot 3ee5500f730abe2928707c745225c7717b05f0a5 1c7d3f9cd384854bf72c127d230bdb32299475ad
check_pair pinchtab/pinchtab 8ba78240112e5f4a26c94ad3322131e92ce951e1 c619c43a4f29d1d1a481e859c193baf78e0d648b
check_pair pinchtab/pinchtab d3895105635099d982539c914f4f2d275cd8c050 25b3374bdcdf0dad32c44d5d726bf953238cd8bd
check_pair TryGhost/Ghost 5295aef2205fb1937693e38044baa0345fb5d8e7 ec065a774fa125953d2aa644a59cd8990329e0a0
check_pair remix-run/react-router 44c34783abbdd2be1a9fe1a4b843d49e704f9a0e 9d22943fd46c8ae4b08236425fa3549e10e9ad1a
check_pair trailofbits/fickling 5e054ddc4de001e4d3d9ec3d2d3f2bc9ba7c7d1b dc8ae12966edee27a78fe05c5745171a2b138d43
check_pair trailofbits/fickling 5e054ddc4de001e4d3d9ec3d2d3f2bc9ba7c7d1b 9a2b3f89bd0598b528d62c10a64c1986fcb09f66
check_pair withastro/astro ee079d4c7f143076b84d663c832911009a077c7f 0b30b35f864310bee8485c952d1877e82e2b9b1a
check_pair withastro/astro ee079d4c7f143076b84d663c832911009a077c7f 5240e26c9dd91f9bc7140dcfacdb48d5a132830d
check_pair withastro/astro ee079d4c7f143076b84d663c832911009a077c7f 3a43cf0f3690a8e33cb30109bc5165611cf38fcd

python3 - "$OWNED_ABS" <<'PY' || fail "hash mismatch"
import hashlib, json, sys
from pathlib import Path
d=Path(sys.argv[1])
res=json.loads((d/"result.json").read_text())
for rel, expect in res["artifact_hashes"].items():
    p=d/rel
    got=hashlib.sha256(p.read_bytes()).hexdigest()
    if got!=expect:
        raise SystemExit(f"{rel} {got} != {expect}")
print("hashes_ok")
PY

echo "REPLAY_OK reviewed=12 PASS_proposal=0 REJECT=12 packet_delta=0 canonical_strict=85"
