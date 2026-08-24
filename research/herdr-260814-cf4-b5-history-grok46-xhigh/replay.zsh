#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat

OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-cf4-b5-history-grok46-xhigh}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
ADV_REV=${ADV_REV:-/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database}
ADV_UNR=${ADV_UNR:-/home/hanqing/.cache/cve-analyzer/advisory-database}
GL=${GL:-/home/hanqing/.cache/cve-analyzer/repos/nicolargo_glances}
MM=${MM:-/home/hanqing/.cache/cve-analyzer/repos/mattermost_mattermost}
GX=${GX:-/home/hanqing/.cache/cve-analyzer/repos/gitoxidelabs_gitoxide}
LF=${LF:-/home/hanqing/.cache/cve-analyzer/repos/langflow-ai_langflow}
ML=${ML:-/home/hanqing/.cache/cve-analyzer/repos/mlflow_mlflow}
HM=${HM:-/home/hanqing/.cache/ghsa200-worker-clones/current-delta/repos/NousResearch__hermes-agent}

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

echo "== conservation 7=7+0 bucket=5 inspected=600 shortfall=5 =="
python3 - "$OWNED" "$ROOT" "$ADV_REV" "$ADV_UNR" <<'PY' || fail "python conservation"
import hashlib, json, sys
from pathlib import Path
owned, root, adv_rev, adv_unr = map(Path, sys.argv[1:])
ass = [json.loads(l) for l in owned.joinpath("assignment.jsonl").open() if l.strip()]
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open() if l.strip()]
res = json.loads(owned.joinpath("result.json").read_text())
want = [
    "GHSA-49G7-2WW7-3VF5",
    "GHSA-69J8-PRX2-VX98",
    "GHSA-6MW6-MJ76-GRWC",
    "GHSA-9JPJ-CPH8-W449",
    "GHSA-PGQP-8H46-6X4J",
    "GHSA-WM96-9GFH-VVGQ",
    "GHSA-WVCV-9XPM-7MQC",
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
n_rej=sum(1 for c in cas if c["verdict"]=="REJECT")
if n_pass!=0 or n_rej!=7 or len(cas)!=7:
    raise SystemExit("COUNT")
if res["conservation"]["equation"]!="7=7+0" or res["pass_proposals"]!=[]:
    raise SystemExit("EQ")
if res["canonical_strict_count_untouched"]!=88:
    raise SystemExit("HOLD")
if res["bound"]["n_inspected"]!=600 or res["bound"]["shortfall"]!=5:
    raise SystemExit("BOUND")
if res["bound"]["stop_rule"]!="max_inspect_600":
    raise SystemExit("STOP")
if res["advisory_sources"]["n_unreviewed_dropped"]!=0:
    raise SystemExit("UNREVIEWED_DROPPED")
if any(a["kind"]!="reviewed" for a in ass):
    raise SystemExit("KIND")
for a in ass:
    p=adv_rev/a["advisory_path"]
    if not p.is_file():
        raise SystemExit("ADV "+a["case_id"])
print("PYTHON_OK excluded=%d frozen=7 PASS=0 REJECT=7 shortfall=5 inspected=600" % len(excl))
PY

echo "== git facts =="
gsub=$(gitq "$GL" log -1 --format=%s 63b7da28895249d775202d639e5531ba63491a5c)
[[ $gsub == *GHSA-49g7* ]] || fail "glances closer subject"
parent_sql=$(gitq "$GL" show 63b7da28895249d775202d639e5531ba63491a5c^:glances/exports/glances_duckdb/__init__.py)
print -r -- "$parent_sql" | grep -q 'CREATE TABLE {plugin}' || fail "glances parent DDL"
afiles=$(gitq "$GL" diff-tree --no-commit-id --name-only -r 7b200f00fceb6302cc219d4a1983433e135acb49)
print -r -- "$afiles" | grep -q glances_duckdb && fail "glances MCP touched duckdb"
abody=$(gitq "$GL" log -1 --format=%b 7b200f00fceb6302cc219d4a1983433e135acb49)
print -r -- "$abody" | grep -q 'Claude Sonnet 4.6' || fail "glances MCP missing Claude"
if gitq "$GL" merge-base --is-ancestor 63b7da28895249d775202d639e5531ba63491a5c v4.5.1; then
  fail "glances closer in v4.5.1"
fi
gitq "$GL" merge-base --is-ancestor 63b7da28895249d775202d639e5531ba63491a5c v4.5.2 || fail "glances closer not in v4.5.2"
echo "GIT_OK glances MCP-pyproject parent-DDL v4.5.2"

msub=$(gitq "$MM" log -1 --format=%s 13cd76009d31754db46115bddef5287a8a29871a)
[[ $msub == *redirect* ]] || fail "mattermost oauth closer subject"
mbody=$(gitq "$MM" log -1 --format=%b bfb15ab17905472628cb2069ac02c896e80e41dc)
print -r -- "$mbody" | grep -q 'Co-authored-by: Claude' || fail "mattermost oauth AI trailer"
mfiles=$(gitq "$MM" diff-tree --no-commit-id --name-only -r bfb15ab17905472628cb2069ac02c896e80e41dc)
print -r -- "$mfiles" | grep -q 'server/channels/web/oauth.go' && fail "errcheck touched oauth.go"
parent_rt=$(gitq "$MM" show 13cd76009d31754db46115bddef5287a8a29871a^:server/channels/web/oauth.go)
print -r -- "$parent_rt" | grep -q 'redirect_to' || fail "oauth parent missing redirect_to"
if gitq "$MM" merge-base --is-ancestor 13cd76009d31754db46115bddef5287a8a29871a v10.9.4; then
  fail "oauth closer in v10.9.4"
fi
gitq "$MM" merge-base --is-ancestor 13cd76009d31754db46115bddef5287a8a29871a v10.9.5 || fail "oauth closer not in v10.9.5"
echo "GIT_OK mattermost oauth test-only-AI v10.9.5"

gfix=$(gitq "$GX" log -1 --format=%s 76376ef5e97c63e108db0c9fe2eb096f4bfe70f7)
[[ $gfix == *2306* ]] || fail "gitoxide closer not merge 2306"
gan=$(gitq "$GX" log -1 --format='%an <%ae>' f9051e775cf8598ac8ad51c95b5d249a10bb9a57)
print -r -- "$gan" | grep -q 'copilot-swe-agent' || fail "TimeBuf member not Copilot"
zfiles=$(gitq "$GX" diff-tree --no-commit-id --name-only -r 60290f10d5da07552d93a36d1cd76ee45a9883e6)
print -r -- "$zfiles" | grep -q gix-date && fail "zip swap touched gix-date"
if gitq "$GX" merge-base --is-ancestor 76376ef5e97c63e108db0c9fe2eb096f4bfe70f7 gix-date-v0.11.1; then
  fail "gitoxide closer in gix-date-v0.11.1"
fi
gitq "$GX" merge-base --is-ancestor 76376ef5e97c63e108db0c9fe2eb096f4bfe70f7 gix-date-v0.12.0 || fail "gitoxide closer not in gix-date-v0.12.0"
echo "GIT_OK gitoxide AI-on-fix lockfile gix-date-v0.12.0"

lsub=$(gitq "$LF" log -1 --format=%s 45325f6376309a91f5017fa033a96c09c7e295e3)
[[ $lsub == *SDK* ]] || fail "langflow closer subject"
lfiles=$(gitq "$LF" diff-tree --no-commit-id --name-only -r f553896a1fdec2dc85073df8c6592eab895f1758)
print -r -- "$lfiles" | grep -q 'api/v1/projects.py' && fail "langflow AI merge touched projects.py"
lparent=$(gitq "$LF" show 45325f6376309a91f5017fa033a96c09c7e295e3^:src/backend/base/langflow/api/v1/projects.py)
print -r -- "$lparent" | grep -q encrypt_auth_settings || fail "langflow parent missing encrypt"
gitq "$LF" merge-base --is-ancestor 45325f6376309a91f5017fa033a96c09c7e295e3 v1.9.1 || fail "langflow closer not in v1.9.1"
echo "GIT_OK langflow merge-config parent-encrypt"

mlsub=$(gitq "$ML" log -1 --format=%s b0ffd289e9b0d0cc32c9e3a9b9f3843ae83dbec3)
[[ $mlsub == *security\ middleware* ]] || fail "mlflow closer subject"
mlfiles=$(gitq "$ML" diff-tree --no-commit-id --name-only -r 96c9bf45fd8bd597fbaa331a1e0cb6399fdb9fd9)
print -r -- "$mlfiles" | grep -q fastapi_security && fail "ruff commit added fastapi_security"
gitq "$ML" merge-base --is-ancestor b0ffd289e9b0d0cc32c9e3a9b9f3843ae83dbec3 v3.5.0 || fail "mlflow closer not in v3.5.0"
if gitq "$ML" merge-base --is-ancestor b0ffd289e9b0d0cc32c9e3a9b9f3843ae83dbec3 v3.4.0; then
  fail "mlflow closer in v3.4.0"
fi
echo "GIT_OK mlflow lint-extra v3.5.0"

hsub=$(gitq "$HM" log -1 --format=%s 285bb2b9150b93445e5eded9bc897a4001b66e55)
[[ $hsub == *execute_code* ]] || fail "hermes closer subject"
hbody=$(gitq "$HM" log -1 --format=%b 1789c2699afb00f84e70b15a4dbbb6092a357ad1)
print -r -- "$hbody" | grep -q 'Cursor Agent' || fail "hermes missing Cursor trailer"
hfiles=$(gitq "$HM" diff-tree --no-commit-id --name-only -r 1789c2699afb00f84e70b15a4dbbb6092a357ad1)
print -r -- "$hfiles" | grep -q code_execution_tool.py && fail "nix commit touched execute_code"
echo "GIT_OK hermes nix-config not-sandbox"

csub=$(gitq "$MM" log -1 --format=%s f5fe8ded6b633db7804ae25b42ea12ce635d6ea6)
[[ $csub == *MM-67377* ]] || fail "mattermost command closer subject"
cfiles=$(gitq "$MM" diff-tree --no-commit-id --name-only -r 1be8a68dd7f387bb24d0b2c80a048c84af93740a)
print -r -- "$cfiles" | grep -q 'server/channels/app/command.go' && fail "pluginapi touched command.go"
if gitq "$MM" merge-base --is-ancestor f5fe8ded6b633db7804ae25b42ea12ce635d6ea6 v11.5.2; then
  fail "command closer unexpectedly in v11.5.2"
fi
echo "GIT_OK mattermost command pluginapi-not-uniqueness"

echo "REPLAY_OK reviewed=7 PASS_proposal=0 NARROW=0 REJECT=7 UNKNOWN=0 BLOCKED=0 packet_delta=0 shortfall=5 inspected=600 current_leader_accepted_count=88"
