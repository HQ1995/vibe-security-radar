#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat

OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-cf4-b5-indirect-grok46-xhigh}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
ADV_REV=${ADV_REV:-/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database}
ADV_UNR=${ADV_UNR:-/home/hanqing/.cache/cve-analyzer/advisory-database}
KEDRO=${KEDRO:-/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/kedro-org__kedro-plugins}
N8N=${N8N:-/home/hanqing/.cache/cve-analyzer/repos/n8n-io_n8n}
MISP=${MISP:-/home/hanqing/.cache/cve-analyzer/repos/misp_misp}
LANGF=${LANGF:-/home/hanqing/.cache/cve-analyzer/repos/langflow-ai_langflow}
GRAD=${GRAD:-/home/hanqing/.cache/cve-analyzer/repos/gradio-app_gradio}

fail() { print -r -- "REPLAY_FAIL $*" >&2; exit 1; }

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
  local clone=$1
  shift
  local outfile errfile rc filtered
  outfile="$REPLAY_TMP/out.$GITQ_N"
  errfile="$REPLAY_TMP/err.$GITQ_N"
  set +e
  command git --no-optional-locks -c gc.auto=0 -C "$clone" "$@" >"$outfile" 2>"$errfile"
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
  echo "HASH_OK $(basename "$f")"
}

echo "== input hashes =="
hash_check "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl" \
  35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json" \
  81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921

echo "== advisory split sources =="
rev_h=$(gitq "$ADV_REV" rev-parse HEAD | tr -d '\n')
unr_h=$(gitq "$ADV_UNR" rev-parse HEAD | tr -d '\n')
[[ $rev_h == f2c6ab3202aeafb36fbea6e76d892532acfca1a6 ]] || fail "reviewed head $rev_h"
[[ $unr_h == 39d8887723797efc1804585dd06585c9fd751226 ]] || fail "unreviewed head $unr_h"
[[ -d $ADV_REV/advisories/github-reviewed ]] || fail "missing reviewed subtree"
[[ -d $ADV_UNR/advisories/unreviewed ]] || fail "missing unreviewed subtree"
[[ ! -d $ADV_REV/advisories/unreviewed ]] || fail "reviewed clone must not supply unreviewed"
echo "SOURCE_OK reviewed=$ADV_REV#$rev_h subtree=advisories/github-reviewed"
echo "SOURCE_OK unreviewed=$ADV_UNR#$unr_h subtree=advisories/unreviewed"

echo "== conservation 12=12+0 bucket=5 =="
python3 - "$OWNED" "$ROOT" "$ADV_REV" "$ADV_UNR" <<'PY' || fail "python conservation"
import hashlib, json, sys
from pathlib import Path
owned, root, adv_rev, adv_unr = map(Path, sys.argv[1:])
ass = [json.loads(l) for l in owned.joinpath("assignment.jsonl").open() if l.strip()]
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open() if l.strip()]
res = json.loads(owned.joinpath("result.json").read_text())
want = [
    "GHSA-CJG8-H5QC-HRJV",
    "GHSA-RF6X-R45M-XV3W",
    "GHSA-6CQR-8CFR-67F8",
    "GHSA-6VWW-2WX8-Q6X4",
    "GHSA-44MV-JQ72-GJ49",
    "GHSA-6655-8PH2-63J3",
    "GHSA-679F-WMRG-QF57",
    "GHSA-75CM-X2W3-8MGF",
    "GHSA-8JCJ-G9F4-QX42",
    "GHSA-C4WP-7485-699W",
    "GHSA-F996-H3C6-GCWG",
    "GHSA-RJ25-5M4J-HCXQ",
]
if [a["case_id"] for a in ass] != want or [c["case_id"] for c in cas] != want:
    raise SystemExit("ID_ORDER")
if any("clone" in a or "clone_path" in a for a in ass+cas):
    raise SystemExit("CLONE_KEY")
for a in ass:
    gid=a["case_id"]
    b=int(hashlib.sha256(gid.encode("ascii")).hexdigest(),16)%6
    if b!=5 or a.get("bucket")!=5 or a.get("frozen") is not True:
        raise SystemExit("BUCKET "+gid)
ID_KEYS={"case_id","ghsa_id","reviewed_case_ids","assigned_ids","strict_released_case_ids"}
GHSA=__import__("re").compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
excl=set()
def collect(obj):
    if isinstance(obj, dict):
        for k,v in obj.items():
            if k in ID_KEYS:
                vals=v if isinstance(v,list) else [v]
                for item in vals:
                    if isinstance(item,str) and GHSA.match(item.strip().upper()):
                        excl.add(item.strip().upper())
            else:
                collect(v)
    elif isinstance(obj, list):
        for x in obj:
            collect(x)
auto=root/"autoresearch"
for group in auto.iterdir():
    if not group.is_dir() or group.name==owned.name:
        continue
    if not (group.name.startswith("herdr-") or group.name.startswith("orchestrator-")):
        continue
    for name in ("assignment.jsonl","cases.jsonl","result.json","selected.jsonl","queue.jsonl","ledger.jsonl","summary.json"):
        p=group/name
        if not p.is_file():
            continue
        text=p.read_text(encoding="utf-8", errors="replace")
        if p.suffix==".jsonl":
            for line in text.splitlines():
                if line.strip():
                    try:
                        collect(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        else:
            try:
                collect(json.loads(text))
            except json.JSONDecodeError:
                pass
for gid in want:
    if gid in excl:
        raise SystemExit("EXCL_OVERLAP "+gid)
strict=json.loads((root/"autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json").read_text())["strict_released_case_ids"]
if len(strict)!=88:
    raise SystemExit("STRICT_COUNT")
if set(want) & {str(x).upper() for x in strict}:
    raise SystemExit("CANONICAL_OVERLAP")
n_pass=sum(1 for c in cas if c["verdict"]=="PASS_PROPOSAL")
n_nar=sum(1 for c in cas if c["verdict"]=="NARROW")
n_rej=sum(1 for c in cas if c["verdict"]=="REJECT")
if n_pass!=0 or n_nar!=4 or n_rej!=8 or len(cas)!=12:
    raise SystemExit("COUNT")
if res["conservation"]["equation"]!="12=12+0" or res["pass_proposals"]!=[]:
    raise SystemExit("EQ")
if res["canonical_strict_count_untouched"]!=88:
    raise SystemExit("HOLD")
if res["advisory_sources"]["n_unreviewed_dropped"]!=0:
    raise SystemExit("UNREVIEWED_DROPPED")
kinds=[a["kind"] for a in ass]
if kinds.count("unreviewed")!=4 or kinds.count("reviewed")!=8:
    raise SystemExit("KIND")
print("PYTHON_OK excluded=%d frozen=12 PASS=0 NARROW=4 REJECT=8 unreviewed_in_freeze=4" % len(excl))
PY

echo "== git facts =="
sub=$(gitq "$KEDRO" log -1 --format=%s 65115f76b872217317734b6bde8927170c98fc4b)
[[ $sub == *partition* ]] || fail "kedro closer subject"
files=$(gitq "$KEDRO" diff-tree --no-commit-id --name-only -r 1284db703e63)
print -r -- "$files" | grep -q partitioned_dataset.py && fail "kedro PathLike touched partitioned_dataset"
parent_join=$(gitq "$KEDRO" show 65115f76^:kedro-datasets/kedro_datasets/partitions/partitioned_dataset.py)
print -r -- "$parent_join" | grep -q '_sep.join(\[dir_path, path\])' || fail "kedro parent join missing"
echo "GIT_OK kedro parent-join no-AI-overlap"

nsub=$(gitq "$N8N" log -1 --format=%s 7860896909b3d42993a36297f053d2b0e633235d)
[[ $nsub == *Git\ Node* ]] || fail "n8n listed closer not Git Node"
lock=$(gitq "$N8N" diff-tree --no-commit-id --name-only -r 8ab4492e8c0b)
print -r -- "$lock" | grep -q pnpm-lock.yaml || fail "n8n vm2 unfork missing lockfile"
echo "GIT_OK n8n git-node-closer vm2-lockfile"

msub=$(gitq "$MISP" log -1 --format=%b 0ed79b4d3177f4b9e44040962161a1a436d2587d)
print -r -- "$msub" | grep -q 'Claude Opus 4.8' || fail "misp closer missing Claude trailer"
pmod=$(gitq "$MISP" show 0ed79b4d^:app/Model/Module.php)
print -r -- "$pmod" | grep -q 'function getEnabledModule($name, $type)' || fail "misp parent signature"
echo "GIT_OK misp AI-on-fix parent-getEnabledModule"

lsub=$(gitq "$LANGF" log -1 --format=%s 52118559413d)
[[ $lsub == *merge\ 1.7.1* ]] || fail "langflow squash subject"
echo "GIT_OK langflow squash-carrier"

gbody=$(gitq "$GRAD" log -1 --format=%b 1c609af6918b20d0b4347b9f41b04569d6adca24)
print -r -- "$gbody" | grep -q 'Claude Opus 4.7' || fail "gradio audio closer missing Claude"
echo "GIT_OK gradio AI-on-fix"

echo "REPLAY_OK reviewed=12 PASS_proposal=0 NARROW=4 REJECT=8 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=88"
