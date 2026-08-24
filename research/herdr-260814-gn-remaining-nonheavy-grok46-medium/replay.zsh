#!/usr/bin/env zsh
set -euo pipefail
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-gn-remaining-nonheavy-grok46-medium}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
GN=$ROOT/autoresearch/herdr-260813-ghsa200-commitfirst-gn
CF2=$ROOT/autoresearch/herdr-260814-cf2-gn-copy-blame-grok46-high
OC=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones

ascii_check() {
  if LC_ALL=C grep -n '[^[:print:][:space:]]' "$1" >/dev/null; then
    echo "NON_ASCII $1"
    exit 1
  fi
}

hash_check() {
  local got
  got=$(sha256sum "$1" | awk '{print $1}')
  if [[ $got != $2 ]]; then
    echo "HASH_MISMATCH $1 got=$got want=$2"
    exit 1
  fi
}

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  ascii_check "$OWNED/$f"
done

hash_check "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
hash_check "$GN/cases.jsonl" \
  47538e731f8c4979651ff36ead7063ea23a1adc05e551a99ae94ceaafd835b2d
hash_check "$GN/result.json" \
  4443df9d098302be1b3fc3b73dbdc0ae7b76471a5f2f67aeed97c98ec1d6c08a
hash_check "$CF2/cases.jsonl" \
  cc50fc12ef27f9e417acd6e58f2bd4bbbfb7e8a43c8f9f1234b0296ea31b8437
hash_check "$CF2/result.json" \
  0f3e056a36daec32658ffd9434def475308b9d9ff452ee5686c7862e46d2ff97
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical94/ledger.jsonl" \
  7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096

python3 - << PY
import json, re, sys
from pathlib import Path
root = Path("$ROOT")
owned = Path("$OWNED")
gn = root / "autoresearch/herdr-260813-ghsa200-commitfirst-gn"
cf2 = root / "autoresearch/herdr-260814-cf2-gn-copy-blame-grok46-high"
can85 = json.loads((root/"autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json").read_text())
can94 = json.loads((root/"autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json").read_text())
res = json.loads((owned/"result.json").read_text())
ass = [json.loads(l)["case_id"] for l in (owned/"assignment.jsonl").open()]
cas = [json.loads(l) for l in (owned/"cases.jsonl").open()]
ids = [c["case_id"] for c in cas]
assert ass == ids == res["inspected_ids"]
assert len(ass) == 12
assert all(c["verdict"] == "REJECT" for c in cas)
assert res["counts"]["PASS_PROPOSAL"] == 0
assert res["counts"]["REJECT"] == 12
assert res["canonical94_strict_count"] == 94
assert res["conservation"]["cf2_equation"] == "633=14+619"
assert res["terminal"] is True

def load_jsonl(p):
    return [json.loads(l) for l in Path(p).read_text(encoding="utf-8").splitlines() if l.strip()]

ix = load_jsonl(gn/"ai-ghsa-intersections.jsonl")
so = [r for r in ix if (not r.get("matched_ai_commit_refs")) and r.get("subject_overlap_hits")]
assert len(so) == 640
c85 = {x.upper() for x in can85["strict_released_case_ids"]}
for k in can85.get("excluded", {}):
    if str(k).upper().startswith("GHSA-"):
        c85.add(str(k).upper())
for nc in can85.get("negative_controls", []):
    c85.add(nc["case_id"].upper())
src = {r["case_id"].upper() for r in load_jsonl(gn/"cases.jsonl")}
excl7 = sorted({r["ghsa_id"].upper() for r in so if r["ghsa_id"].upper() in c85 or r["ghsa_id"].upper() in src})
assert excl7 == res["selector_excl7"]
e633 = [r for r in so if r["ghsa_id"].upper() not in set(excl7)]
assert len(e633) == 633
cf2_ids = [json.loads(l)["case_id"].upper() for l in (cf2/"assignment.jsonl").open()]
assert cf2_ids == json.loads((cf2/"result.json").read_text())["inspected_ids"]
remaining = [r for r in e633 if r["ghsa_id"].upper() not in set(cf2_ids)]
assert len(remaining) == 619
c94 = {x.upper() for x in can94["strict_released_case_ids"]}
assert len(c94) == 94
assert not {r["ghsa_id"].upper() for r in remaining} & c94
later = set(res["later_terminal_in_remaining"])
assert len(later) == 161
after = [r for r in remaining if r["ghsa_id"].upper() not in later]
assert len(after) == 458
HEAVY = {"n8n-io/n8n","go-gitea/gitea","jdx/mise","MervinPraison/PraisonAI","gogs/gogs"}
assigned_map = {r["ghsa_id"].upper(): r for r in load_jsonl(gn/"assigned.jsonl")}
INC = re.compile(r"incomplete|residual|bypass|variant of|follow-?up|partial fix|not fully", re.I)
NEW = re.compile(r"\\b(introduc|new (endpoint|route|server|handler|surface|feature)|added |adds |add a |unauth|0\\.0\\.0\\.0|bind |mcp |http server|streamable)\\b", re.I)
hq=[]
for r in remaining:
    gid=r["ghsa_id"].upper()
    if gid in c94 or gid in later:
        continue
    if r["repository"] in HEAVY:
        continue
    a=assigned_map[gid]
    refs=list(a.get("commit_refs") or [])
    if not refs or not a.get("first_party") or a.get("withdrawn"):
        continue
    summary=(r.get("summary") or a.get("summary") or "")
    inc=bool(INC.search(summary)); new=bool(NEW.search(summary))
    if not (inc or new):
        continue
    hq.append((int(new and inc), int(new), int(inc), gid))
hq.sort(reverse=True)
assert [h[3] for h in hq[:12]] == ass
assert hq[12][3] == "GHSA-33G4-646G-QWMM"
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
for rec in cas:
    g=rec["gates"]
    for k in need:
        assert g[k] in ("PASS","FAIL","UNKNOWN","NARROW","BLOCKED")
    assert rec["verdict"] != "PASS_PROPOSAL"
    assert rec["identity_gate"]=="PASS" if False else g["identity_gate"]=="PASS"
    assert g["ai_hunk_gate"]=="FAIL"
    assert rec["case_id"] not in c94
print("CONSERVATION_OK 640-7=633 633-14=619 later=161 HQ=13 assigned=12 REJECT=12")
PY

python3 - << PY
import subprocess, sys
from pathlib import Path
C="/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones"
def git(repo, args):
    p=subprocess.run(["git","-C",f"{C}/{repo}",*args], capture_output=True, text=True)
    if p.returncode!=0:
        sys.exit("git fail "+repo+" "+str(args)+" "+p.stderr)
    return p.stdout.strip()
# origin object/parent/topology
assert git("Gitlawb__openclaude", ["rev-list","--parents","-n","1","d2542c9a628b"]) == "d2542c9a628b1ec65d2d96b015aa1f3541fdc095"
assert git("Gitlawb__openclaude", ["rev-list","--parents","-n","1","739b8d1f40fd"]).split()[1] == "f166ec1a4ec7d3311226653ec020a7dab737e769"
assert git("JSONbored__gittensory", ["rev-list","--parents","-n","1","811ef5fb9d74"]).split()[1] == "0fb238021991ac9f1cb033f311078b9e5643f239"
ext = git("JSONbored__gittensory", ["diff","eb440f1f5ea7^","eb440f1f5ea7","--","src/api/routes.ts"])
assert "/v1/extension/contributors" in ext
assert "app.get(\"/v1/contributors/:login/profile\"" not in ext
prof = git("JSONbored__gittensory", ["show","0fb238021991:src/api/routes.ts"])
assert 'app.get("/v1/contributors/:login/profile"' in prof
assert git("inspektor-gadget__inspektor-gadget", ["rev-list","--parents","-n","1","c51d419964f5"]).count(" ") == 2
assert git("mastra-ai__mastra", ["log","--follow","--diff-filter=A","--format=%an","-n","1","9e4abde7cef3","--","packages/mcp-docs-server/src/tools/docs.ts"]) == "Tyler Barnes"
assert "Inline lodash.set" in git("langchain-ai__langsmith-sdk", ["log","-1","--format=%s","a872906b8f0c"])
print("OBJECT_TOPOLOGY_OK")
PY
