#!/usr/bin/env zsh
# Deterministic offline replay for herdr-260814-queue-mautic-formwork-grok46-high.
# English ASCII only. No credentials. No GitHub API. Temporary clones cleaned.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-queue-mautic-formwork-grok46-high}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
ADV=${ADV:-/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database}
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat
unset GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }

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
if not b.endswith(b"\n"):
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
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical93/ledger.jsonl" \
  6d652a089329eb23108083fb73ca1a8a3aa00583415b235381f3b37da389dc3d
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical93/summary.json" \
  cf8a3eb231830303803e2e1a198207b2a8e117990a675982e8d9e346c9cc46c0
hash_check "$ROOT/autoresearch/herdr-260814-nextqueue-v2-grok46-low/assignment.jsonl" \
  5382496f680de8c811d75ca0d3dd6dbdc1b47af0893689e37d36d9dc4a7b93b3
hash_check "$ROOT/autoresearch/herdr-260814-nextqueue-v2-grok46-low/cases.jsonl" \
  5edd11a19f8bfb7e598290ee5ce22b72e0e3d51c4186c6e8d656f552a38d4ccf

echo "== advisory pins =="
hash_check "$ADV/advisories/github-reviewed/2025/09/GHSA-3ggv-qwcp-j6xg/GHSA-3ggv-qwcp-j6xg.json" \
  9099081e8114bb03d5e028561fd285a558f4d32beb7f6367a1f560fb31e237d1
hash_check "$ADV/advisories/github-reviewed/2025/09/GHSA-438m-6mhw-hq5w/GHSA-438m-6mhw-hq5w.json" \
  34686bf84c20cdfc55c0bd74c40dcd826746edde75d94ee476ba027de2a4aadc
hash_check "$ADV/advisories/github-reviewed/2025/09/GHSA-hj6f-7hp7-xg69/GHSA-hj6f-7hp7-xg69.json" \
  0275843e433361f8ef12a33770b2d1388643d684d844e806933d5184e36a7f56
hash_check "$ADV/advisories/github-reviewed/2026/02/GHSA-34p4-7w83-35g2/GHSA-34p4-7w83-35g2.json" \
  e32aa20f9dc1e2d96f8a2c66ec229ebc9d8daf00b199cbe7ad21a1277f179d69
hash_check "$ADV/advisories/github-reviewed/2025/11/GHSA-7j46-f57w-76pj/GHSA-7j46-f57w-76pj.json" \
  a70132c96197e36b4c2bfd8ceb09649b56934dee4ea6cca4cfd6e9b3adeae73b
got=$(git -C "$ADV" rev-parse HEAD)
[[ $got == f2c6ab3202aeafb36fbea6e76d892532acfca1a6 ]] || fail "ADV_HEAD $got"
got=$(git -C "$ADV" rev-parse HEAD:advisories/github-reviewed)
[[ $got == 3308b2f6c73929d3854bd12908e996787a8bb0c8 ]] || fail "ADV_TREE $got"
echo "ADV_HEAD_OK"

echo "== conservation 5=5+0 =="
python3 - << PY
import json, sys
from pathlib import Path
owned = Path("$OWNED")
root = Path("$ROOT")
ass = [json.loads(l) for l in owned.joinpath("assignment.jsonl").open() if l.strip()]
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open() if l.strip()]
res = json.loads(owned.joinpath("result.json").read_text())
want = [
    "GHSA-3GGV-QWCP-J6XG",
    "GHSA-438M-6MHW-HQ5W",
    "GHSA-HJ6F-7HP7-XG69",
    "GHSA-34P4-7W83-35G2",
    "GHSA-7J46-F57W-76PJ",
]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
aids = [a["case_id"] for a in ass]
cids = [c["case_id"] for c in cas]
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if any(a.get("routing_only") is not True for a in ass):
    print("ASSIGN_NOT_ROUTING"); sys.exit(1)
n_pass = sum(1 for c in cas if c["verdict"] in ("PASS", "PASS_PROPOSAL"))
n_rej = sum(1 for c in cas if c["verdict"] == "REJECT")
if n_pass != 0 or n_rej != 5 or len(cas) != 5:
    print("COUNT_FAIL", n_pass, n_rej); sys.exit(1)
if res["conservation"]["equation"] != "5=5+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposals"] != [] or res["canonical_strict_count_untouched"] != 93:
    print("FLAG_FAIL"); sys.exit(1)
if res["counts"]["PASS"] != 0 or res["counts"]["PASS_PROPOSAL"] != 0:
    print("PASS_COUNT_FAIL"); sys.exit(1)
src_ids = [json.loads(l)["case_id"] for l in (root/"autoresearch/herdr-260814-nextqueue-v2-grok46-low/assignment.jsonl").open() if l.strip()]
if any(i not in src_ids for i in want):
    print("NOT_FROM_SOURCE"); sys.exit(1)
extra = [i for i in cids if i not in want]
if extra:
    print("PADDED", extra); sys.exit(1)
for rec in cas:
    g = rec["gates"]
    for k in need:
        if g[k] not in ("PASS","FAIL","UNKNOWN","NARROW","BLOCKED","NA"):
            print("BAD_GATE", rec["case_id"], k, g[k]); sys.exit(1)
    if rec["verdict"] == "PASS_PROPOSAL" or rec.get("proposed_pass") is not False:
        print("PROMOTED_PASS", rec["case_id"]); sys.exit(1)
    if rec["verdict"] != "REJECT":
        print("NOT_REJECT", rec["case_id"]); sys.exit(1)
    if g["identity_gate"] != "PASS" or g["uniqueness_gate"] != "PASS":
        print("ID_UNIQ_FAIL", rec["case_id"]); sys.exit(1)
    if g["ai_hunk_gate"] != "FAIL" or g["but_for_gate"] != "FAIL" or g["release_gate"] != "FAIL":
        print("EXPECTED_FAIL_GATES", rec["case_id"], g); sys.exit(1)
    if rec.get("osv_introduced_used_as_causal_proof") is not False:
        print("OSV_USED_AS_PROOF", rec["case_id"]); sys.exit(1)
    if rec.get("authorship_transfer") is not False:
        print("TRANSFER", rec["case_id"]); sys.exit(1)
    if rec.get("countable_proposal") is not False:
        print("COUNTABLE", rec["case_id"]); sys.exit(1)
print("CONSERVATION_OK 5=5+0 REJECT=5 PASS_PROPOSAL=0")
PY

echo "== uniqueness vs canonical93 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical93/summary.json").read_text())
strict = set(str(x).upper() for x in canon["strict_released_case_ids"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open() if l.strip()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical93", hit); sys.exit(1)
if canon["canonical_strict_count"] != 93 or len(strict) != 93:
    print("CANON_COUNT_FAIL", canon["canonical_strict_count"], len(strict)); sys.exit(1)
print("UNIQUENESS_OK", len(ids))
PY

echo "== first-party identity pins =="
python3 - << PY
import json, sys
from pathlib import Path
adv = Path("$ADV")
owned = Path("$OWNED")
want = {
    "GHSA-3GGV-QWCP-J6XG": ("2025/09/GHSA-3ggv-qwcp-j6xg/GHSA-3ggv-qwcp-j6xg.json", "mautic/mautic", "mautic/core"),
    "GHSA-438M-6MHW-HQ5W": ("2025/09/GHSA-438m-6mhw-hq5w/GHSA-438m-6mhw-hq5w.json", "mautic/mautic", "mautic/core"),
    "GHSA-HJ6F-7HP7-XG69": ("2025/09/GHSA-hj6f-7hp7-xg69/GHSA-hj6f-7hp7-xg69.json", "mautic/mautic", "mautic/core"),
    "GHSA-34P4-7W83-35G2": ("2026/02/GHSA-34p4-7w83-35g2/GHSA-34p4-7w83-35g2.json", "getformwork/formwork", "getformwork/formwork"),
    "GHSA-7J46-F57W-76PJ": ("2025/11/GHSA-7j46-f57w-76pj/GHSA-7j46-f57w-76pj.json", "getformwork/formwork", "getformwork/formwork"),
}
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open() if l.strip()]
for rec in cas:
    rel, repo, pkg = want[rec["case_id"]]
    data = json.loads((adv/"advisories/github-reviewed"/rel).read_text())
    if data.get("withdrawn"):
        print("WITHDRAWN", rec["case_id"]); sys.exit(1)
    if data.get("database_specific", {}).get("github_reviewed") is not True:
        print("NOT_REVIEWED", rec["case_id"]); sys.exit(1)
    names = {a.get("package", {}).get("name") for a in data.get("affected") or []}
    if pkg not in names:
        print("PKG_FAIL", rec["case_id"], names); sys.exit(1)
    if rec["repository"].lower() != repo:
        print("REPO_FAIL", rec["case_id"]); sys.exit(1)
    if rec["identity_projection"]["withdrawn"] is not None:
        print("PROJ_WITHDRAWN", rec["case_id"]); sys.exit(1)
print("IDENTITY_PINS_OK")
PY

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
names={p.name for p in d.iterdir() if p.is_file() or p.is_dir()}
extra=names-allowed
if extra:
    raise SystemExit(f"extra {sorted(extra)}")
print("hygiene_ok")
PY

echo "REPLAY_OK reviewed=5 PASS_proposal=0 REJECT=5 NARROW=0 UNKNOWN=0 BLOCKED=0 equation=5=5+0 canonical93=93"
