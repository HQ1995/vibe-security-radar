#!/usr/bin/env zsh
set -euo pipefail
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-cf3-singlegate5-grok46-high}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
OC=${OC:-/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw}
CH=${CH:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/churchcrm}
HUD=${HUD:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/claude-hud}
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
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical86/summary.json" \
  74efef286737bcbd852bf1887ffa34b30224f7902f96a2c45455ba399a4d739c
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl" \
  0b9cd2daae23e33faf3f2ceed46bba4802e2f9b0ef9c739f0bce7e6f4a16f687

echo "== conservation 5=5+0 =="
python3 - << PY
import json, sys
from pathlib import Path
owned = Path("$OWNED")
ass = [json.loads(l)["case_id"] for l in owned.joinpath("assignment.jsonl").open()]
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open()]
res = json.loads(owned.joinpath("result.json").read_text())
ids = [c["case_id"] for c in cas]
want = [
    "GHSA-2QRV-RC5X-2G2H",
    "GHSA-3J8Q-FWPJ-F8J5",
    "GHSA-4524-X6PC-RR9X",
    "GHSA-92VG-F4FQ-FXM9",
    "GHSA-F7FH-QG34-X2XH",
]
ok = True
if ass != ids or ids != want or ids != res["inspected_ids"]:
    print("ID_ORDER_FAIL", ass, ids); ok = False
n_pass = sum(1 for c in cas if c["verdict"] == "PASS_PROPOSAL")
n_rej = sum(1 for c in cas if c["verdict"] == "REJECT")
n_nar = sum(1 for c in cas if c["verdict"] == "NARROW")
if n_pass != 0 or n_rej != 1 or n_nar != 4 or len(cas) != 5:
    print("COUNT_FAIL", n_pass, n_rej, n_nar); ok = False
if res["conservation"]["equation"] != "5=5+0":
    print("EQ_FAIL"); ok = False
if res["pass_proposal_ids"] != [] or res["canonical86_strict_count"] != 86:
    print("FLAG_FAIL"); ok = False
if any(c["verdict"] == "PASS_PROPOSAL" for c in cas):
    print("PROMOTED_PASS"); ok = False
if ok:
    print("CONSERVATION_OK 5=5+0 REJECT=1 NARROW=4 PASS_PROPOSAL=0")
else:
    sys.exit(1)
PY

echo "== uniqueness vs canonical86 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical86/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical86", hit); sys.exit(1)
print("UNIQUENESS_OK", len(ids))
PY

echo "== seven gates; no PASS_PROPOSAL with non-PASS gate; no FAIL promoted to PASS =="
python3 - << PY
import json, sys
from pathlib import Path
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
okv = ("PASS","FAIL","UNKNOWN","NARROW","BLOCKED")
with Path("$OWNED/cases.jsonl").open() as f:
    for line in f:
        rec = json.loads(line)
        g = rec["gates"]
        for k in need:
            if g[k] not in okv:
                print("BAD_GATE", rec["case_id"], k, g[k]); sys.exit(1)
        if rec["verdict"] == "PASS_PROPOSAL" and any(g[k] != "PASS" for k in need):
            print("PASS_WITH_NONPASS_GATE", rec["case_id"]); sys.exit(1)
        if rec["verdict"] == "PASS_PROPOSAL" and "FAIL" in g.values():
            print("PROMOTED_FAIL", rec["case_id"]); sys.exit(1)
        if rec["case_id"] == "GHSA-2QRV-RC5X-2G2H":
            if rec["verdict"] != "REJECT" or g["ai_hunk_gate"] != "FAIL":
                print("2QRV_FAIL_NOT_HELD"); sys.exit(1)
print("GATES_OK")
PY

echo "== openclaw / churchcrm / claude-hud git =="
if [[ ! -d $OC || ! -d $CH || ! -d $HUD ]]; then
  echo CLONE_ABSENT; fail=1
else
  git -C "$OC" cat-file -t fc1b156dc4105bdbcdc24d4c25d4f5af25cfd7bb >/dev/null
  git -C "$OC" cat-file -t 53c29df2a9eb242a70d0ff29f3d1e67c8d6801f0 >/dev/null
  git -C "$OC" cat-file -t 75602014dbc5088b80e9b236146dfe5fdcc59e20 >/dev/null
  git -C "$OC" cat-file -t bc356cc8c2beaa747c71dd86cceab8f804699665 >/dev/null
  CATALOG_C=$(git -C "$OC" rev-parse fc1b156dc4105bdbcdc24d4c25d4f5af25cfd7bb:src/channels/plugins/catalog.ts)
  CATALOG_P=$(git -C "$OC" rev-parse "fc1b156dc4105bdbcdc24d4c25d4f5af25cfd7bb^:src/channels/plugins/catalog.ts")
  if [[ $CATALOG_C != $CATALOG_P ]]; then echo CATALOG_CHANGED; fail=1; else echo CATALOG_UNCHANGED_OK; fi
  git -C "$OC" merge-base --is-ancestor fc1b156dc4105bdbcdc24d4c25d4f5af25cfd7bb v2026.4.1 && { echo MEMBER_IN_V202641_FAIL; fail=1; } || echo MEMBER_NOT_IN_V202641_OK
  git -C "$OC" merge-base --is-ancestor 75602014dbc5088b80e9b236146dfe5fdcc59e20 v2026.4.1 || { echo F7FH_CAND_NOT_ANC; fail=1; }
  git -C "$OC" merge-base --is-ancestor bc356cc8c2beaa747c71dd86cceab8f804699665 v2026.4.1 && { echo F7FH_FIX_IN_V202641_FAIL; fail=1; } || echo F7FH_FIX_NOT_IN_V202641_OK
  git -C "$OC" merge-base --is-ancestor bc356cc8c2beaa747c71dd86cceab8f804699665 v2026.4.5 || { echo F7FH_FIX_NOT_ANC_V202645; fail=1; }
  if git -C "$OC" cat-file -p 75602014dbc5088b80e9b236146dfe5fdcc59e20 | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.6'; then
    echo F7FH_MARKER_OK
  else
    echo F7FH_MARKER_FAIL; fail=1
  fi
  git -C "$CH" cat-file -e 51e49adbc1b3b40ec93988267dcad7ffa02d0372:src/api/routes/people/notes.php 2>/dev/null && { echo NOTES_IN_PARENT_FAIL; fail=1; } || echo NOTES_PARENT_LACKS_OK
  git -C "$CH" merge-base --is-ancestor b3edc22580116beb6bc8463d1876f2a7c9b96a28 7.3.3 || { echo NOTES_CAND_NOT_ANC_733; fail=1; }
  git -C "$CH" merge-base --is-ancestor 83c19611701b96300872390071440151360dfb48 7.3.3 && { echo NOTES_FIX_IN_733_FAIL; fail=1; } || echo NOTES_FIX_NOT_IN_733_OK
  git -C "$CH" merge-base --is-ancestor 83c19611701b96300872390071440151360dfb48 7.4.0 || { echo NOTES_FIX_NOT_ANC_740; fail=1; }
  git -C "$HUD" cat-file -e "26a3e984e442382f83297b545626f7293f4379b4^:src/transcript.ts" 2>/dev/null && { echo TRANSCRIPT_IN_PARENT_FAIL; fail=1; } || echo TRANSCRIPT_PARENT_LACKS_OK
  git -C "$HUD" merge-base --is-ancestor 26a3e984e442382f83297b545626f7293f4379b4 v0.0.12 || { echo HUD_CAND_NOT_ANC; fail=1; }
  git -C "$HUD" merge-base --is-ancestor 234d9aad919b51326a43bcf90b45ae35c23afc30 v0.1.0 || { echo HUD_FIX_NOT_ANC; fail=1; }
fi

echo "== solidcam tags via smart-HTTP mktemp (no durable clone) =="
TMP=$(mktemp -d /tmp/solidcam-replay.XXXXXX)
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
git -c init.defaultBranch=main init -q --bare "$TMP"
if git --git-dir="$TMP" fetch --quiet --filter=blob:none --depth=1 \
    https://github.com/anzory/SolidCAM-GPPL-IDE.git tag v1.0.0 tag v1.0.2; then
  got0=$(git --git-dir="$TMP" rev-parse "v1.0.0^{commit}")
  got2=$(git --git-dir="$TMP" rev-parse "v1.0.2^{commit}")
  if [[ $got0 != d1944bca6e984665fb98f5ea824c6c370fd618d6 ]]; then echo TAG_V100_FAIL $got0; fail=1; else echo TAG_V100_OK; fi
  if [[ $got2 != 9d0ba808afd143ede448026a5dc681bfdc5c138d ]]; then echo TAG_V102_FAIL $got2; fail=1; else echo TAG_V102_OK; fi
  names=$(git --git-dir="$TMP" diff-tree --no-commit-id --name-only -r d1944bca6e984665fb98f5ea824c6c370fd618d6)
  if print -r -- "$names" | LC_ALL=C grep -q '\.cs$'; then echo CS_SOURCE_PRESENT_FAIL; fail=1; else echo NO_CS_SOURCE_OK; fi
  if git --git-dir="$TMP" cat-file -t 4939a1b >/dev/null 2>&1; then echo ADVISORY_FIX_PRESENT_UNEXPECTED; fail=1; else echo ADVISORY_FIX_ABSENT_OK; fi
else
  echo SOLIDCAM_FETCH_FAIL
  fail=1
fi

if [[ $fail -ne 0 ]]; then
  echo REPLAY_FAIL
  exit 1
fi
echo REPLAY_OK
