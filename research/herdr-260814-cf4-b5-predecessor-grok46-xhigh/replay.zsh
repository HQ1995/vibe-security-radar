#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat

OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-cf4-b5-predecessor-grok46-xhigh}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
ADV_REV=${ADV_REV:-/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database}
ADV_UNR=${ADV_UNR:-/home/hanqing/.cache/cve-analyzer/advisory-database}
MM=${MM:-/home/hanqing/.cache/cve-analyzer/repos/mattermost_mattermost}
DF=${DF:-/home/hanqing/.cache/cve-analyzer/repos/github.com_bytedance_deer-flow}

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

echo "== conservation 2=2+0 bucket=5 inspected=397 shortfall=10 =="
python3 - "$OWNED" "$ROOT" "$ADV_REV" "$ADV_UNR" <<'PY' || fail "python conservation"
import hashlib, json, sys
from pathlib import Path
owned, root, adv_rev, adv_unr = map(Path, sys.argv[1:])
ass = [json.loads(l) for l in owned.joinpath("assignment.jsonl").open() if l.strip()]
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open() if l.strip()]
res = json.loads(owned.joinpath("result.json").read_text())
want = ["GHSA-CGJG-P2M2-QM4P", "GHSA-GXX6-2VWG-3GC3"]
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
n_rej=sum(1 for c in cas if c["verdict"]=="REJECT")
if n_pass!=0 or n_rej!=2 or len(cas)!=2:
    raise SystemExit("COUNT")
if res["conservation"]["equation"]!="2=2+0" or res["pass_proposals"]!=[]:
    raise SystemExit("EQ")
if res["canonical_strict_count_untouched"]!=88:
    raise SystemExit("HOLD")
if res["bound"]["n_inspected"]!=397 or res["bound"]["shortfall"]!=10:
    raise SystemExit("BOUND")
if res["bound"]["stop_rule"]!="prefix_exhausted":
    raise SystemExit("STOP")
if res["advisory_sources"]["n_unreviewed_dropped"]!=0:
    raise SystemExit("UNREVIEWED_DROPPED")
kinds=[a["kind"] for a in ass]
if kinds!=["reviewed","unreviewed"]:
    raise SystemExit("KIND")
p0=adv_rev/ass[0]["advisory_path"]
p1=adv_unr/ass[1]["advisory_path"]
if not p0.is_file() or not p1.is_file():
    raise SystemExit("ADV")
print("PYTHON_OK excluded=%d frozen=2 PASS=0 REJECT=2 shortfall=10 inspected=397" % len(excl))
PY

echo "== git facts =="
msub=$(gitq "$MM" log -1 --format=%s 6404ab29acc04901c5cb1cf5ad97fc3c0693e2cd)
[[ $msub == *MM-66424* ]] || fail "mattermost closer subject"
parent_fn=$(gitq "$MM" show 6404ab29acc04901c5cb1cf5ad97fc3c0693e2cd^:server/channels/app/channel.go)
print -r -- "$parent_fn" | grep -q 'func (a \*App) GetDirectOrGroupMessageMembersCommonTeams' || fail "parent missing common teams"
abody=$(gitq "$MM" log -1 --format=%b d78d59babeb994106e305531de50b8d515427396)
print -r -- "$abody" | grep -q 'Co-Authored-By: Claude <noreply@anthropic.com>' || fail "mattermost missing Claude"
afiles=$(gitq "$MM" diff-tree --no-commit-id --name-only -r d78d59babeb994106e305531de50b8d515427396)
print -r -- "$afiles" | grep -q 'server/channels/app/channel.go' || fail "rctx did not touch channel.go"
gitq "$MM" merge-base --is-ancestor d78d59babeb994106e305531de50b8d515427396 6404ab29acc04901c5cb1cf5ad97fc3c0693e2cd || fail "rctx not ancestor"
if gitq "$MM" merge-base --is-ancestor 6404ab29acc04901c5cb1cf5ad97fc3c0693e2cd v10.11.9; then
  fail "listed closer in v10.11.9"
fi
if gitq "$MM" merge-base --is-ancestor 6404ab29acc04901c5cb1cf5ad97fc3c0693e2cd v10.11.10; then
  fail "listed closer unexpectedly in v10.11.10"
fi
gitq "$MM" merge-base --is-ancestor a07b1d7a8c0d324665fe641ce8c1ce8bb70b6d08 v10.11.10 || fail "cherry-pick not in v10.11.10"
if gitq "$MM" merge-base --is-ancestor a07b1d7a8c0d324665fe641ce8c1ce8bb70b6d08 v10.11.9; then
  fail "cherry-pick in v10.11.9"
fi
echo "GIT_OK mattermost rctx-rename common-teams listed-SHA-not-in-v10.11.10"

dsub=$(gitq "$DF" log -1 --format=%s 92c7a20cb74addc3038d2131da78f2e239ef542e)
[[ $dsub == *host-shell\ escape* ]] || fail "deer-flow closer subject"
dbody=$(gitq "$DF" log -1 --format=%b 253fe4d87fb8128c5e5633c3a7ee81f99fb32b71)
print -r -- "$dbody" | grep -q 'copilot-swe-agent' || fail "deer-flow missing Copilot"
parent_src=$(gitq "$DF" show 253fe4d87fb8128c5e5633c3a7ee81f99fb32b71^:backend/src/sandbox/tools.py)
print -r -- "$parent_src" | grep -q validate_local_bash_command_paths && fail "parent already had regex guard"
ai_src=$(gitq "$DF" show 253fe4d87fb8128c5e5633c3a7ee81f99fb32b71:backend/src/sandbox/tools.py)
print -r -- "$ai_src" | grep -q validate_local_bash_command_paths || fail "AI commit missing regex guard"
closer_cfg=$(gitq "$DF" show 92c7a20cb74addc3038d2131da78f2e239ef542e:backend/packages/harness/deerflow/config/sandbox_config.py)
print -r -- "$closer_cfg" | grep -q allow_host_bash || fail "closer missing allow_host_bash"
parent_cfg=$(gitq "$DF" show 92c7a20cb74addc3038d2131da78f2e239ef542e^:backend/packages/harness/deerflow/config/sandbox_config.py)
print -r -- "$parent_cfg" | grep -q allow_host_bash && fail "parent already had allow_host_bash"
gitq "$DF" merge-base --is-ancestor 253fe4d87fb8128c5e5633c3a7ee81f99fb32b71 92c7a20cb74addc3038d2131da78f2e239ef542e || fail "copilot not ancestor"
dtags=$(gitq "$DF" tag)
[[ -z $dtags ]] || fail "deer-flow unexpectedly has tags"
echo "GIT_OK deer-flow copilot-regex closer-fail-closed 0-tags"

echo "REPLAY_OK reviewed=2 PASS_proposal=0 NARROW=0 REJECT=2 UNKNOWN=0 BLOCKED=0 packet_delta=0 shortfall=10 inspected=397 current_leader_accepted_count=88"
