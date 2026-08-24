#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-cf4-b2-remediation-grok46-high.
# English only. No credentials. Shared caches read-only.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-cf4-b2-remediation-grok46-high
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json
ADV_REV=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
ADV_UN=/home/hanqing/.cache/cve-analyzer/advisory-database
git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

fail() { print -r -- "REPLAY_FAIL $*" >&2; exit 1 }

expect_eq() {
  if [[ $1 != "$2" ]]; then
    print -r -- "mismatch $3 expected=$2 got=$1" >&2
    exit 1
  fi
}

expect_hash() {
  local got
  got=$(/usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}')
  expect_eq "$got" "$2" "$1"
}

gitx() {
  local repo=$1
  shift
  local errf
  errf=$(mktemp /tmp/cf4-b2-giterr.XXXXXX)
  set +e
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
  if [[ -s $errf ]]; then
    /usr/bin/grep -vE 'unable to normalize alternate object path|lazy fetching disabled' "$errf" >&2 || true
  fi
  rm -f "$errf"
  return $rc
}

require_file() { [[ -f $1 ]] || fail "missing $1" }
require_dir() { [[ -d $1 ]] || fail "missing $1" }

require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/result.json"
require_file "$OWNED/report.md"
require_file "$OWNED/replay.zsh"
require_file "$CONTRACT"
require_file "$LEDGER"
require_file "$SUMMARY"
require_dir "$ADV_REV/advisories/github-reviewed"
require_dir "$ADV_UN/advisories/unreviewed"

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  python3 - "$OWNED/$f" <<'PY' || fail "ascii $f"
import sys
b=open(sys.argv[1],"rb").read()
if b"\x00" in b: raise SystemExit(1)
b.decode("ascii")
PY
done

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
expect_hash "$SUMMARY" 81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921

adv_rev_head=$(gitx "$ADV_REV" rev-parse HEAD)
adv_un_head=$(gitx "$ADV_UN" rev-parse HEAD)
expect_eq "$adv_rev_head" f2c6ab3202aeafb36fbea6e76d892532acfca1a6 reviewed_head
expect_eq "$adv_un_head" 39d8887723797efc1804585dd06585c9fd751226 unreviewed_head

n_assign=$(/usr/bin/wc -l < "$OWNED/assignment.jsonl" | /usr/bin/tr -d ' ')
n_cases=$(/usr/bin/wc -l < "$OWNED/cases.jsonl" | /usr/bin/tr -d ' ')
expect_eq "$n_assign" 12 assignment_rows
expect_eq "$n_cases" 12 cases_rows

python3 - "$OWNED" "$SUMMARY" "$ROOT/autoresearch" "$ADV_REV" "$ADV_UN" <<'PY' || fail "python conservation"
import hashlib, json, re, sys
from pathlib import Path
owned, summary_p, ar, adv_rev, adv_un = map(Path, sys.argv[1:])
assigns=[json.loads(l) for l in owned.joinpath("assignment.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l) for l in owned.joinpath("cases.jsonl").read_text().splitlines() if l.strip()]
res=json.loads(owned.joinpath("result.json").read_text())
assert len(assigns)==12 and len(cases)==12
ids=[a["case_id"] for a in assigns]
assert ids==[c["case_id"] for c in cases]==res["conservation"]["reviewed_case_ids"]
assert len(set(ids))==12
assert all(a["frozen"] and a["bucket"]==2 for a in assigns)
assert res["counts"]["PASS"]==0 and res["counts"]["REJECT"]==11 and res["counts"]["UNKNOWN"]==1
assert res["conservation"]["equation"]=="12=12+0" and res["conservation"]["holds"] is True
assert sum(1 for c in cases if c["verdict"]=="PASS")==0
assert sum(1 for c in cases if c["verdict"]=="REJECT")==11
assert sum(1 for c in cases if c["verdict"]=="UNKNOWN")==1
assert cases[2]["case_id"]=="GHSA-H2V8-4C3F-VQGV" and cases[2]["verdict"]=="UNKNOWN"

def bucket(gid):
    return int(hashlib.sha256(gid.encode("ascii")).hexdigest(), 16) % 6
for gid in ids:
    assert bucket(gid)==2, gid

GHSA_RE=re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
FIELD_KEYS={"case_id","ghsa_id","reviewed_case_ids","assigned_ids","strict_released_case_ids"}
OWNED_NAME="herdr-260814-cf4-b2-remediation-grok46-high"

def norm(x):
    if not isinstance(x,str):
        return None
    s=x.strip().upper()
    return s if GHSA_RE.match(s) else None

def walk(obj, acc):
    if isinstance(obj, dict):
        for k,v in obj.items():
            if k in FIELD_KEYS:
                if isinstance(v,str):
                    n=norm(v)
                    if n: acc.add(n)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item,str):
                            n=norm(item)
                            if n: acc.add(n)
            walk(v, acc)
    elif isinstance(obj, list):
        for item in obj:
            walk(item, acc)

excluded=set()
for p in [ar/"orchestrator-260814-ghsa200-canonical88/ledger.jsonl", summary_p]:
    text=p.read_text(encoding="utf-8", errors="replace")
    if p.suffix==".jsonl":
        for line in text.splitlines():
            if line.strip():
                walk(json.loads(line), excluded)
    else:
        walk(json.loads(text), excluded)

for d in sorted(ar.iterdir()):
    if not d.is_dir() or d.name==OWNED_NAME:
        continue
    if not (d.name.startswith("herdr-") or d.name.startswith("orchestrator-")):
        continue
    result=d/"result.json"
    is_terminal=False
    if result.exists():
        try:
            obj=json.loads(result.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            obj={}
        if obj.get("terminal") is True or str(obj.get("status") or "").upper()=="TERMINAL" or obj.get("analysis_stopped") is True:
            is_terminal=True
    if (d/"cases.jsonl").exists() or (d/"assignment.jsonl").exists():
        is_terminal=True
    if not is_terminal and not ((d/"ledger.jsonl").exists() or (d/"summary.json").exists()):
        continue
    for p in sorted(d.iterdir()):
        if p.suffix not in {".json",".jsonl"}:
            continue
        try:
            text=p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        try:
            if p.suffix==".jsonl":
                for line in text.splitlines():
                    if line.strip():
                        walk(json.loads(line), excluded)
            else:
                walk(json.loads(text), excluded)
        except Exception:
            continue

for gid in ids:
    assert gid not in excluded, "excluded overlap "+gid

summary=json.loads(summary_p.read_text())
counted={str(x).upper() for x in summary["strict_released_case_ids"]}
assert len(counted)==88
for gid in ids:
    assert gid not in counted

reviewed_ids={p.stem.upper() for p in (adv_rev/"advisories/github-reviewed").rglob("GHSA-*.json")}
for a in assigns:
    gid=a["case_id"]
    if a["source"]=="reviewed_f2c6":
        assert gid in reviewed_ids, gid
        assert (adv_rev/a["advisory_path"]).is_file(), a["advisory_path"]
    else:
        assert gid not in reviewed_ids, "collision must prefer reviewed "+gid
        assert (adv_un/a["advisory_path"]).is_file(), a["advisory_path"]
print("conservation_ok")
PY

gitx /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/MervinPraison__PraisonAI cat-file -t 846568c7a5d8ce9e71e56e4c213f027c04909753 | grep -qx commit || fail "vp55 closer"
gitx /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/MervinPraison__PraisonAI merge-base --is-ancestor 3ea83766103638d3188c0eccfc3aae81727bc8eb 846568c7a5d8ce9e71e56e4c213f027c04909753 || fail "vp55 ancestor"
gitx /home/hanqing/.cache/cve-analyzer/repos/getgrav_grav merge-base --is-ancestor 1c1003cfcab5344203d6fde1aaa1f9a4ee3413ff 2.0.1 || fail "grav prior in 2.0.1"
gitx /home/hanqing/.cache/cve-analyzer/repos/getgrav_grav merge-base --is-ancestor 734f7f4c266693a486198047c10f79d3e175e90c 2.0.2 || fail "grav closer in 2.0.2"
if gitx /home/hanqing/.cache/cve-analyzer/repos/getgrav_grav merge-base --is-ancestor 734f7f4c266693a486198047c10f79d3e175e90c 2.0.1; then fail "grav closer must not be in 2.0.1"; fi
gitx /home/hanqing/.cache/cve-analyzer/repos/brentmid_evernote-mcp-server merge-base --is-ancestor e08547bcdb42aaa86190c6e2dfc64159fcd3a146 1e66c78c4ce6ea294ac6b0eb289a9eae9c5e9579 || fail "evernote ancestor"
gitx /home/hanqing/.cache/cve-analyzer/repos/misp_misp merge-base --is-ancestor ada02fa6d7558732aa4712fd5e9451cd8c5b7a64 24d7e91339a3ef043652dd5799c36e5065b2bb4a || fail "misp dpt1 ancestor"
if gitx /home/hanqing/.cache/cve-analyzer/repos/misp_misp merge-base --is-ancestor 24d7e91339a3ef043652dd5799c36e5065b2bb4a v2.5.41; then fail "misp closer in v2.5.41"; fi
gitx /home/hanqing/.cache/cve-analyzer/repos/misp_misp merge-base --is-ancestor 24d7e91339a3ef043652dd5799c36e5065b2bb4a v2.5.42 || fail "misp closer in v2.5.42"
gitx /home/hanqing/.cache/cve-analyzer/repos/seaweedfs_seaweedfs merge-base --is-ancestor 28fe92065a7ffa20de38eff0f907782c7900dcb1 0345658ea8e7c6a3948ad190634b00866ec244c9 || fail "seaweed ancestor"
if gitx /home/hanqing/.cache/cve-analyzer/repos/seaweedfs_seaweedfs merge-base --is-ancestor 0345658ea8e7c6a3948ad190634b00866ec244c9 4.33; then fail "seaweed closer in 4.33"; fi
gitx /home/hanqing/.cache/cve-analyzer/repos/seaweedfs_seaweedfs merge-base --is-ancestor 0345658ea8e7c6a3948ad190634b00866ec244c9 4.34 || fail "seaweed closer in 4.34"
gitx /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw cat-file -t b623557a2ec7e271bda003eb3ac33fbb2e218505 | grep -qx commit || fail "openclaw closer"
if gitx /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw merge-base --is-ancestor b623557a2ec7e271bda003eb3ac33fbb2e218505 v2026.1.24; then fail "openclaw closer in v2026.1.24"; fi
gitx /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw merge-base --is-ancestor b623557a2ec7e271bda003eb3ac33fbb2e218505 v2026.1.29 || fail "openclaw closer in v2026.1.29"
gitx /home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/streamlit__streamlit cat-file -t fec0f584dae9261abed16cad35b32922104bb933 | grep -qx commit || fail "streamlit closer"
gitx /home/hanqing/.cache/ghsa200-worker-clones/current-delta/repos/NousResearch__hermes-agent cat-file -t b944c6e821c2177eac6da857c99ff24566aa56b0 | grep -qx commit || fail "hermes closer"
gitx /home/hanqing/.cache/cve-analyzer/repos/onnx_onnx merge-base --is-ancestor bfdf92badb43 a7bf3a0f1d18bb62575236ef6e4944980c40e045 || fail "onnx ancestor"

echo "REPLAY_OK reviewed=12 PASS_proposal=0 REJECT=11 UNKNOWN=1 packet_delta=0 canonical_strict=88"
