#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-nearclosed-d-grok46-xhigh.
# English only. No credentials. Shared caches read-only. No clone, fetch, commit, or push.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearclosed-d-grok46-xhigh}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
OC=${OC:-/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw}
ADV_REV=${ADV_REV:-/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database}
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

git_path_absent() {
  local outfile errfile rc
  GITQ_N=$((GITQ_N + 1))
  outfile="$REPLAY_TMP/out.$GITQ_N"
  errfile="$REPLAY_TMP/err.$GITQ_N"
  set +e
  command git "$@" >"$outfile" 2>"$errfile"
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    rm -f "$outfile" "$errfile"
    return 1
  fi
  rm -f "$outfile" "$errfile"
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
if b.endswith(b" ") or b" \n" in b:
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
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json" \
  81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl" \
  35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
hash_check "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
hash_check "$ADV_REV/advisories/github-reviewed/2026/04/GHSA-h2vw-ph2c-jvwf/GHSA-h2vw-ph2c-jvwf.json" \
  c0f0681b7479fee3a4721ad9cf47610ba18e2b1ebced848fb849d7bff06d4dd3
hash_check "$ADV_REV/advisories/github-reviewed/2026/04/GHSA-xq94-r468-qwgj/GHSA-xq94-r468-qwgj.json" \
  77a88909ea48a9ce05d28074d24dec1d1b85347bd2a8220b9a96836059df8812
hash_check "$ADV_REV/advisories/github-reviewed/2026/04/GHSA-w85g-3h6x-4xh2/GHSA-w85g-3h6x-4xh2.json" \
  1ed6a5f579a291a1f128bbbfe625d804553f0514080631511259d68beb62ff07

echo "== first-party advisory identities =="
python3 - << PY
import json, sys
from pathlib import Path
adv = Path("$ADV_REV/advisories/github-reviewed/2026/04")
h2 = json.loads((adv / "GHSA-h2vw-ph2c-jvwf/GHSA-h2vw-ph2c-jvwf.json").read_text())
xq = json.loads((adv / "GHSA-xq94-r468-qwgj/GHSA-xq94-r468-qwgj.json").read_text())
w8 = json.loads((adv / "GHSA-w85g-3h6x-4xh2/GHSA-w85g-3h6x-4xh2.json").read_bytes().decode("utf-8"))
if h2.get("id") != "GHSA-h2vw-ph2c-jvwf":
    print("H2_ID", h2.get("id")); sys.exit(1)
if "MINIMAX_API_HOST" not in h2.get("details", ""):
    print("H2_NO_HOST"); sys.exit(1)
if "TTS" in h2.get("details", "") or "speech" in h2.get("details", "").lower():
    print("H2_NAMES_TTS"); sys.exit(1)
if h2.get("database_specific", {}).get("github_reviewed") is not True:
    print("H2_REVIEWED"); sys.exit(1)
if xq.get("id") != "GHSA-xq94-r468-qwgj":
    print("XQ_ID"); sys.exit(1)
det = xq.get("details", "")
if "DNS rebinding" not in det:
    print("XQ_NO_DNS"); sys.exit(1)
if "Browserbase" in det or "WebSocket" in det:
    print("XQ_NAMES_WS"); sys.exit(1)
if xq.get("database_specific", {}).get("github_reviewed") is not True:
    print("XQ_REVIEWED"); sys.exit(1)
if w8.get("id") != "GHSA-w85g-3h6x-4xh2":
    print("W8_ID"); sys.exit(1)
if "sips" not in w8.get("details", ""):
    print("W8_NO_SIPS"); sys.exit(1)
if "images.ts" in w8.get("details", "") or "ingest" in w8.get("details", "").lower():
    print("W8_NAMES_INGEST"); sys.exit(1)
if w8.get("aliases") != []:
    print("W8_ALIASES", w8.get("aliases")); sys.exit(1)
if w8.get("database_specific", {}).get("github_reviewed") is not True:
    print("W8_REVIEWED"); sys.exit(1)
print("ADVISORY_OK")
PY

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
    "GHSA-H2VW-PH2C-JVWF",
    "GHSA-XQ94-R468-QWGJ",
    "GHSA-W85G-3H6X-4XH2",
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
if [a["fp211_ordinal"] for a in ass] != [117, 120, 121]:
    print("ORDINAL_FAIL"); sys.exit(1)
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
    if rec["verdict"] == "PASS_PROPOSAL":
        print("PROMOTED_PASS", rec["case_id"]); sys.exit(1)
    if rec["verdict"] != "NARROW" or g["but_for_gate"] != "NARROW":
        print("BUTFOR_NOT_NARROW", rec["case_id"]); sys.exit(1)
    if g["fix_reversal_gate"] != "PASS" or g["release_gate"] != "PASS":
        print("NAMED_CLOSER_NOT_PASS", rec["case_id"], g); sys.exit(1)
    if rec.get("proposed_pass") is not False:
        print("PROPOSED_PASS_FLAG", rec["case_id"]); sys.exit(1)
    if rec.get("osv_introduced_used_as_causal_proof") is not False:
        print("OSV_USED_AS_PROOF", rec["case_id"]); sys.exit(1)
    if rec.get("seven_gates_exact_pass") is not False:
        print("SEVEN_PASS_FLAG", rec["case_id"]); sys.exit(1)
    if rec.get("authorship_transfer") is not False:
        print("TRANSFER", rec["case_id"]); sys.exit(1)
print("CONSERVATION_OK 3=3+0 NARROW=3 PASS_PROPOSAL=0")
PY

echo "== uniqueness vs canonical88 =="
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
if "GHSA-9F72-QCPW-2HXC" not in strict:
    print("COUNTED_9F72_MISSING"); sys.exit(1)
if "GHSA-9F72-QCPW-2HXC" in ids:
    print("MERGED_9F72"); sys.exit(1)
if "GHSA-F7FH-QG34-X2XH" in ids:
    print("MERGED_F7FH"); sys.exit(1)
if len(strict) != 88:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
print("UNIQUENESS_OK", len(ids))
PY

echo "== git facts =="
[[ -d $OC ]] || fail "CLONE_ABSENT"

# H2VW ordinal 117
C=7d7f5d85b4ff0bf9a135ced8022d8860a1979a06
F=2f06696579a1ab0cb5bbbbb6a900414a6b2e3cd1
P=49d962a82f67203994c39cc577b39aa47632fef4
V=36a02b3e6755c65ed4df4dc4d0de1dd93fa8bbc5
gitq -C "$OC" cat-file -t "$C" >/dev/null
gitq -C "$OC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "H2VW_PARENTS $parents"
gitq -C "$OC" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.6 (1M context)' || fail "H2VW_MARKER"
gitq -C "$OC" grep -F -q 'env.MINIMAX_API_HOST?.trim()' "$P" -- src/agents/minimax-vlm.ts || fail "H2VW_PARENT_VLM_HOST"
gitq -C "$OC" grep -F -q 'Bearer ${apiKey}' "$P" -- src/agents/minimax-vlm.ts || fail "H2VW_PARENT_VLM_AUTH"
git_path_absent -C "$OC" cat-file -e "${P}:extensions/minimax/speech-provider.ts" || fail "H2VW_PARENT_HAS_TTS"
gitq -C "$OC" grep -F -q 'process.env.MINIMAX_API_HOST' "$C" -- extensions/minimax/speech-provider.ts || fail "H2VW_CAND_TTS_HOST"
gitq -C "$OC" grep -F -q 'Bearer ${apiKey}' "$C" -- extensions/minimax/tts.ts || fail "H2VW_CAND_TTS_AUTH"
if gitq -C "$OC" grep -q MINIMAX_API_HOST "$P" -- src/infra/dotenv.ts; then
  fail "H2VW_PARENT_DOTENV_HAS_HOST"
fi
gitq -C "$OC" merge-base --is-ancestor "$V" v2026.3.22 || fail "H2VW_VLM_NOT_322"
gitq -C "$OC" merge-base --is-ancestor "$V" v2026.4.5 || fail "H2VW_VLM_NOT_45"
fsubj=$(gitq -C "$OC" log -1 --format='%s' "$F")
[[ $fsubj == *"MINIMAX_API_HOST workspace env injection"* ]] || fail "H2VW_FIX_SUBJ $fsubj"
gitq -C "$OC" grep -q '"MINIMAX_API_HOST"' "$F" -- src/infra/dotenv.ts || fail "H2VW_FIX_DOTENV"
spdiff=$(gitq -C "$OC" diff "${F}^" "$F" -- extensions/minimax/speech-provider.ts)
[[ -z $spdiff ]] || fail "H2VW_FIX_TOUCHED_TTS"
gitq -C "$OC" merge-base --is-ancestor "$C" v2026.4.1 && fail "H2VW_CAND_IN_41" || true
gitq -C "$OC" merge-base --is-ancestor "$C" v2026.4.5 || fail "H2VW_CAND_TAG"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.4.5 && fail "H2VW_FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.4.20 || fail "H2VW_FIX_TAG"
peel=$(gitq -C "$OC" rev-parse 'v2026.4.5^{commit}')
[[ $peel == 3e72c0352dde84a0bcb3aabafa99c2d4b12d1c46 ]] || fail "H2VW_PEEL45 $peel"
peel=$(gitq -C "$OC" rev-parse 'v2026.4.20^{commit}')
[[ $peel == 115f05d5952adeaa8043311c24c4b8a3803481ba ]] || fail "H2VW_PEEL420 $peel"
echo "H2VW_OK"

# XQ94 ordinal 120
C=75602014dbc5088b80e9b236146dfe5fdcc59e20
F=121c452d666d4749744dc2089287d0227aae2ed3
P=3cf75f760c0f89adbad9415b3d5fdb5b83f2dd82
gitq -C "$OC" cat-file -t "$C" >/dev/null
gitq -C "$OC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "XQ94_PARENTS $parents"
gitq -C "$OC" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.6' || fail "XQ94_MARKER"
pfiles=$(gitq -C "$OC" diff-tree --no-commit-id --name-only -r "$P")
[[ $pfiles == "docs/tools/browser.md" ]] || fail "XQ94_PARENT_NOT_DOCS $pfiles"
gitq -C "$OC" grep -q '/json/version' "$P" -- src/browser/cdp.ts || fail "XQ94_PARENT_JSON"
if gitq -C "$OC" grep -q isWebSocketUrl "$P" -- src/browser/cdp.ts src/browser/cdp.helpers.ts; then
  fail "XQ94_PARENT_HAS_WS"
fi
gitq -C "$OC" grep -q isWebSocketUrl "$C" -- src/browser/cdp.ts || fail "XQ94_CAND_WS"
fsubj=$(gitq -C "$OC" log -1 --format='%s' "$F")
[[ $fsubj == *"hostname navigation"* ]] || fail "XQ94_FIX_SUBJ $fsubj"
gitq -C "$OC" grep -q isWebSocketUrl "$F" -- extensions/browser/src/browser/cdp.helpers.ts || fail "XQ94_FIX_KEEPS_WS"
gitq -C "$OC" merge-base --is-ancestor "$C" v2026.4.5 || fail "XQ94_CAND_TAG"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.4.5 && fail "XQ94_FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.4.10 || fail "XQ94_FIX_TAG"
peel=$(gitq -C "$OC" rev-parse 'v2026.4.10^{commit}')
[[ $peel == 44e5b62c27e088128e32e209c146de346c3ea7e6 ]] || fail "XQ94_PEEL410 $peel"
echo "XQ94_OK"

# W85G ordinal 121
C=8d74578ceb0c3b913555dff6265821eb0fc09749
F=0ed4f8a72bb140045962e97ab01c94c076b758a4
P=f7123ec30af8c96bb2cb4da198e19bc03312ba16
gitq -C "$OC" cat-file -t "$C" >/dev/null
gitq -C "$OC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "W85G_PARENTS $parents"
gitq -C "$OC" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5' || fail "W85G_MARKER"
gitq -C "$OC" grep -q sipsMetadataFromBuffer "$P" -- src/media/image-ops.ts || fail "W85G_PARENT_SIPS"
if gitq -C "$OC" grep -q limitInputPixels "$P" -- src/media/image-ops.ts; then
  fail "W85G_PARENT_HAS_CAP"
fi
git_path_absent -C "$OC" cat-file -e "${P}:src/agents/pi-embedded-runner/run/images.ts" || fail "W85G_PARENT_HAS_IMAGES"
gitq -C "$OC" cat-file -e "${C}:src/agents/pi-embedded-runner/run/images.ts" >/dev/null || fail "W85G_CAND_IMAGES"
gitq -C "$OC" grep -q loadWebMedia "$C" -- src/agents/pi-embedded-runner/run/images.ts || fail "W85G_CAND_LOAD"
if gitq -C "$OC" grep -q limitInputPixels "$C" -- src/media/image-ops.ts; then
  fail "W85G_CAND_HAS_CAP"
fi
fsubj=$(gitq -C "$OC" log -1 --format='%s' "$F")
[[ $fsubj == *"oversized image inputs"* ]] || fail "W85G_FIX_SUBJ $fsubj"
names=$(gitq -C "$OC" diff-tree --no-commit-id --name-only -r "$F")
print -r -- "$names" | LC_ALL=C grep -qx 'src/media/image-ops.ts' || fail "W85G_FIX_IMAGE_OPS"
print -r -- "$names" | LC_ALL=C grep -q 'images.ts' && fail "W85G_FIX_TOUCHES_IMAGES" || true
gitq -C "$OC" grep -q limitInputPixels "$F" -- src/media/image-ops.ts || fail "W85G_FIX_CAP"
gitq -C "$OC" merge-base --is-ancestor "$C" v2026.3.28 || fail "W85G_CAND_TAG"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.3.28 && fail "W85G_FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.3.31 || fail "W85G_FIX_TAG"
peel=$(gitq -C "$OC" rev-parse 'v2026.3.28^{commit}')
[[ $peel == f9b1079283a8ee25a7cee77c8f8225d5c813bc30 ]] || fail "W85G_PEEL328 $peel"
peel=$(gitq -C "$OC" rev-parse 'v2026.3.31^{commit}')
[[ $peel == 213a704b71f4996dc82a583288ee53785215f627 ]] || fail "W85G_PEEL331 $peel"
echo "W85G_OK"

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
