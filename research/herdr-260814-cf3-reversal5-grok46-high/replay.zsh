#!/usr/bin/env zsh
set -euo pipefail
OWNED="autoresearch/herdr-260814-cf3-reversal5-grok46-high"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OWNED_ABS="$ROOT/$OWNED"
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

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

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh replay.txt; do
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
assert len(assign)==5 and len(cases)==5
expect=["GHSA-42M6-XH7C-6XM4","GHSA-HFF7-CCV5-52F8","GHSA-HHFF-FJ5F-QG48","GHSA-Q6QF-4P5J-R25G","GHSA-W4H3-GPV2-82QC"]
assert [a["case_id"] for a in assign]==[c["case_id"] for c in cases]==expect==res["conservation"]["reviewed_case_ids"]
assert res["conservation"]["equation"]=="5=5+0" and res["conservation"]["holds"] is True
assert res["counts"]["PASS"]==0 and res["counts"]["REJECT"]==5
assert res["pass_proposals"]==[] and res["packet_delta"]==0
assert res["canonical_strict_count_untouched"]==88
assert all(c["verdict"]=="REJECT" for c in cases)
assert all(c.get("proposed_pass") is False for c in cases)
assert all(c["gates"]["but_for_gate"]=="FAIL" and c["gates"]["fix_reversal_gate"]=="FAIL" for c in cases)
print("json_ok")
PY

need_obj() {
  local repo="$1" sha="$2"
  [[ -e "$repo/.git" || -f "$repo/.git" ]] || fail "missing clone $repo"
  gitq -C "$repo" cat-file -t "$sha" | grep -qx commit || fail "missing commit $sha in $repo"
}

C="/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/codexbar"
O="/home/hanqing/.cache/ghsa200-worker-clones/redbase/clones/openclaw"

need_obj "$C" 8348c85cd8d43affa0c9d83be20ff42d895fe1dc
need_obj "$C" b6b77b4b8ea803b671dea666bc76135e6af0c057
need_obj "$C" c3a0304298597ace4026a9778cb0025309b628a3
need_obj "$C" 08c171b6b487654a0eb188494fa24bd1c4272a2e
need_obj "$C" f62bb8c8d5640c079af6934f14406a5cffe2e367
gitq -C "$C" merge-base --is-ancestor 8348c85cd8d43affa0c9d83be20ff42d895fe1dc 08c171b6b487654a0eb188494fa24bd1c4272a2e || fail "42m6 ancestry"
if print -- "$(gitq -C "$C" diff --name-only 8348c85cd8d43affa0c9d83be20ff42d895fe1dc^ 8348c85cd8d43affa0c9d83be20ff42d895fe1dc)" | grep -q ProviderHTTPClient.swift; then
  fail "42m6 cand touched transport"
fi
print -- "$(gitq -C "$C" diff --name-only 08c171b6b487654a0eb188494fa24bd1c4272a2e^ 08c171b6b487654a0eb188494fa24bd1c4272a2e)" | grep -q ProviderHTTPClient.swift || fail "42m6 closer missed transport"

need_obj "$O" f4b03599f0fb9c2f76e8dbe5fde13948d68dbc3f
need_obj "$O" 356d61aacfa5b0f1d5830716ec59d70682a3e7b8
gitq -C "$O" merge-base --is-ancestor f4b03599f0fb9c2f76e8dbe5fde13948d68dbc3f 356d61aacfa5b0f1d5830716ec59d70682a3e7b8 || fail "hff7 ancestry"
gitq -C "$O" grep -q authorizeGatewayConnect 'f4b03599^' -- src/gateway/openai-http.ts || fail "hff7 parent missing helper call"
if print -- "$(gitq -C "$O" diff --name-only 356d61aacfa5b0f1d5830716ec59d70682a3e7b8^ 356d61aacfa5b0f1d5830716ec59d70682a3e7b8)" | grep -q openresponses-http.ts; then
  fail "hff7 closer reversed AI route file"
fi

need_obj "$O" b9b47f50023d9f6384372bad6eee1a181b98c48e
need_obj "$O" ee52f64226a03efadfdf1e3b759e13424a3d4e41
gitq -C "$O" merge-base --is-ancestor b9b47f50023d9f6384372bad6eee1a181b98c48e ee52f64226a03efadfdf1e3b759e13424a3d4e41 || fail "hhff ancestry"
print -- "$(gitq -C "$O" diff --name-only b9b47f50023d9f6384372bad6eee1a181b98c48e^ b9b47f50023d9f6384372bad6eee1a181b98c48e)" | grep -qx src/discord/monitor/message-handler.preflight.ts || fail "hhff cand files"

need_obj "$O" 8d74578ceb0c3b913555dff6265821eb0fc09749
need_obj "$O" dd9d9c1c609dcb4579f9e57bd7b5c879d0146b53
need_obj "$O" 4fd7feb0fd4ec16c48ed983980dba79a09b3aaf5
need_obj "$O" 93880717f1cd34feaa45e74e939b7a5256288901
gitq -C "$O" merge-base --is-ancestor 8d74578ceb0c3b913555dff6265821eb0fc09749 dd9d9c1c609dcb4579f9e57bd7b5c879d0146b53 || fail "q6qf ancestry"
if gitq -C "$O" grep -q workspaceOnly 8d74578ceb0c3b913555dff6265821eb0fc09749 -- src/agents/tools/image-tool.ts; then
  fail "q6qf candidate already had workspaceOnly"
fi
gitq -C "$O" grep -q workspaceOnly dd9d9c1c609dcb4579f9e57bd7b5c879d0146b53 -- src/agents/tools/image-tool.ts || fail "q6qf closer missing workspaceOnly"
if gitq -C "$O" grep -q fileURLToPath 8d74578ceb0c3b913555dff6265821eb0fc09749 -- src/agents/pi-embedded-runner/run/images.ts; then
  fail "w4h3 assigned cand already had fileURLToPath"
fi

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
allowed={"assignment.jsonl","cases.jsonl","result.json","report.md","replay.zsh","replay.txt"}
extra={p.name for p in d.iterdir()}-allowed
if extra:
    raise SystemExit(f"extra {sorted(extra)}")
print("hygiene_ok")
PY

echo "REPLAY_OK reviewed=5 PASS_proposal=0 NARROW=0 REJECT=5 UNKNOWN=0 BLOCKED=0"
