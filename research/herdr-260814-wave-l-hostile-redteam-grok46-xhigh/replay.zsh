#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-wave-l-hostile-redteam-grok46-xhigh.
# English only. No credentials. Shared caches read-only. mktemp cleaned.
# Network-unavailable: identity is pinned offline projections; local git only.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-wave-l-hostile-redteam-grok46-xhigh}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
Z=${Z:-/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw}
C=${C:-/home/hanqing/.cache/cve-analyzer/repos/churchcrm_crm}
ADV=${ADV:-/home/hanqing/.cache/cve-analyzer/advisory-database}
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat
export https_proxy=http://127.0.0.1:1
export http_proxy=http://127.0.0.1:1
export HTTPS_PROXY=http://127.0.0.1:1
export HTTP_PROXY=http://127.0.0.1:1
export ALL_PROXY=http://127.0.0.1:1
unset GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }

REPLAY_TMP=""
cleanup_replay_tmp() {
  if [[ -n "${REPLAY_TMP:-}" && -d "$REPLAY_TMP" ]]; then
    rm -rf "$REPLAY_TMP"
  fi
}
trap cleanup_replay_tmp EXIT
REPLAY_TMP="$(mktemp -d /tmp/wavel-hostile.XXXXXX)"

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
hash_check "$ROOT/docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md" \
  70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/summary.json" \
  ab47f927a20f374a9b0e3253a1a5a0778e355dda9414189927022325d81ad86f
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/ledger.jsonl" \
  70b7658fadf41f18c72734a2006601961a2180681bf81353373bccab95ff659e
hash_check "$ADV/advisories/github-reviewed/2026/03/GHSA-g353-mgv3-8pcj/GHSA-g353-mgv3-8pcj.json" \
  efd6c3ef3fd0c944db26b799456c9298d733dad672756f0a2ea8d1652265006a
hash_check "$ADV/advisories/github-reviewed/2026/04/GHSA-xh72-v6v9-mwhc/GHSA-xh72-v6v9-mwhc.json" \
  463dc5cff66f0f528929aeefc4cbaa286dfabe01173ab088045679dce6004914
hash_check "$ADV/advisories/github-reviewed/2026/02/GHSA-q447-rj3r-2cgh/GHSA-q447-rj3r-2cgh.json" \
  9d5a4294f2d0886bfbf8c4130ab9edc803c36190d068abda475b798009e0c812

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
want = ["GHSA-G353-MGV3-8PCJ","GHSA-MFMP-Q643-VJ39","GHSA-M649-24Q9-Q6R4"]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c or "clone" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if any(a.get("nearclosed_l_is_not_evidence") is not True for a in ass):
    print("NEARCLOSED_FLAG_FAIL"); sys.exit(1)
if [a["fp211_ordinal"] for a in ass] != [124, 183, 184]:
    print("ORDINAL_FAIL"); sys.exit(1)
if [c["verdict"] for c in cas] != ["REJECT","PASS_PROPOSAL","PASS_PROPOSAL"]:
    print("COUNT_FAIL", [c["verdict"] for c in cas]); sys.exit(1)
if res["conservation"]["equation"] != "3=3+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposal_ids"] != ["GHSA-MFMP-Q643-VJ39","GHSA-M649-24Q9-Q6R4"]:
    print("PASS_IDS_FAIL", res.get("pass_proposal_ids")); sys.exit(1)
if res["canonical_strict_count_untouched"] != 91:
    print("FLAG_FAIL"); sys.exit(1)
if cas[0]["seven_gates_exact_pass"] is not False:
    print("G353_SEVEN_SHOULD_NOT_PASS"); sys.exit(1)
if cas[1]["seven_gates_exact_pass"] is not True or cas[2]["seven_gates_exact_pass"] is not True:
    print("CHURCH_SEVEN_SHOULD_PASS"); sys.exit(1)
g0 = cas[0]["gates"]
for k in need:
    if k not in g0:
        print("MISSING_GATE", k); sys.exit(1)
if g0["identity_gate"] != "PASS" or g0["topology_gate"] != "PASS" or g0["uniqueness_gate"] != "PASS":
    print("G353_EXPECTED_PASS_GATES", g0); sys.exit(1)
if g0["ai_hunk_gate"] != "FAIL" or g0["but_for_gate"] != "FAIL" or g0["fix_reversal_gate"] != "FAIL" or g0["release_gate"] != "FAIL":
    print("G353_EXPECTED_FAIL_GATES", g0); sys.exit(1)
for rec in cas[1:]:
    g = rec["gates"]
    for k in need:
        if g[k] != "PASS":
            print("CHURCH_GATE_FAIL", rec["case_id"], k, g[k]); sys.exit(1)
if cas[1]["mechanism_key"] == cas[2]["mechanism_key"]:
    print("MFMP_M649_SAME_KEY"); sys.exit(1)
if cas[1]["minimum_fix_set"] == cas[2]["minimum_fix_set"]:
    print("MFMP_M649_SAME_FIX"); sys.exit(1)
if any(c.get("osv_introduced_used_as_causal_proof") is not False for c in cas):
    print("OSV_USED_AS_PROOF"); sys.exit(1)
if any(c.get("authorship_transfer") is not False for c in cas):
    print("TRANSFER"); sys.exit(1)
if any(c.get("nearclosed_l_is_not_evidence") is not True for c in cas):
    print("CASE_NEARCLOSED_FLAG"); sys.exit(1)
if any(c.get("identity_source") != "offline_normalized_projection" for c in cas):
    print("IDENTITY_SOURCE_FAIL"); sys.exit(1)
if any(c.get("identity_network_used_at_replay") is not False for c in cas):
    print("IDENTITY_NETWORK_FLAG"); sys.exit(1)
if res.get("identity_source") != "offline_normalized_projection":
    print("RES_IDENTITY_SOURCE"); sys.exit(1)
if res.get("no_network_at_replay") is not True:
    print("RES_NETWORK_FLAG"); sys.exit(1)
rsrc = owned.joinpath("replay.zsh").read_text()
if ("gh" " api") in rsrc or ("curl" " -") in rsrc:
    print("LIVE_NETWORK_IN_REPLAY"); sys.exit(1)
print("CONSERVATION_OK 3=3+0 REJECT=1 PASS_PROPOSAL=2")
PY

echo "== uniqueness vs pinned canonical91 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open() if l.strip()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical91", hit); sys.exit(1)
if len(strict) != 91:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
for must in ("GHSA-8JPQ-5H99-FF5R","GHSA-J4XF-96QF-RX69","GHSA-5WP8-Q9MX-8JX8","GHSA-HM7V-JRHM-FMFX","GHSA-CWP8-RM8G-Q5C9"):
    if must not in strict:
        print("COUNTED_MISSING", must); sys.exit(1)
for absent in ("GHSA-G353-MGV3-8PCJ","GHSA-XH72-V6V9-MWHC","GHSA-Q447-RJ3R-2CGH","GHSA-MFMP-Q643-VJ39","GHSA-M649-24Q9-Q6R4"):
    if absent in strict:
        print("SHOULD_BE_ABSENT", absent); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "WAVE_L_ABSENT_CANONICAL91 DISTINCT_8JPQ_J4XF_HM7V_CWP8")
PY

echo "== first-party identity =="
python3 - "$OWNED" "$ADV" <<'PY' || fail "identity"
import hashlib, json, sys
from pathlib import Path

owned = Path(sys.argv[1])
adv_root = Path(sys.argv[2])
CANON_KEYS = (
    "aliases",
    "first_party_url",
    "ghsa_id",
    "github_reviewed",
    "global_catalog",
    "package_ecosystem",
    "package_name",
    "patched_version",
    "published_at",
    "repository",
    "retrieved_at",
    "state",
    "vulnerable_version_range",
    "withdrawn",
)
WANT_SHA = {
    "GHSA-G353-MGV3-8PCJ": "dcc2c024c6ff0dea55487a96e791f044b6a762856a7c39ee5c3e197883adc655",
    "GHSA-XH72-V6V9-MWHC": "b9b39f0bf8a5ea0d6589073e7eb48c8cffe0e9ec16acc4dc376a1713c120fb23",
    "GHSA-Q447-RJ3R-2CGH": "59122089a613befaf12f21e131d15ef41b98ef8bee1a5ea133bcaa494728aeaa",
    "GHSA-MFMP-Q643-VJ39": "040c803180132591235557382882b58a56ce57f79c4f8f9f4226590237c596fd",
    "GHSA-M649-24Q9-Q6R4": "ce88e06dec9db95abd18584069c8638da6ae913614a682581e56c7795b1989b0",
    "GHSA-HM7V-JRHM-FMFX": "fdc00396b841671c5bd2936e6f57c3ff257011ed54f03700fcf5ffb7df6c5d8f",
}
WANT_FIELDS = {
    "GHSA-G353-MGV3-8PCJ": {
        "aliases": ["CVE-2026-32974"],
        "first_party_url": "https://github.com/openclaw/openclaw/security/advisories/GHSA-g353-mgv3-8pcj",
        "ghsa_id": "GHSA-G353-MGV3-8PCJ",
        "github_reviewed": True,
        "global_catalog": "present",
        "package_ecosystem": "npm",
        "package_name": "openclaw",
        "patched_version": "2026.3.12",
        "published_at": "2026-03-13T20:55:34Z",
        "repository": "openclaw/openclaw",
        "retrieved_at": "2026-08-15T00:50:00Z",
        "state": "published",
        "vulnerable_version_range": "<= 2026.3.11",
        "withdrawn": False,
    },
    "GHSA-XH72-V6V9-MWHC": {
        "aliases": ["CVE-2026-44109"],
        "first_party_url": "https://github.com/openclaw/openclaw/security/advisories/GHSA-xh72-v6v9-mwhc",
        "ghsa_id": "GHSA-XH72-V6V9-MWHC",
        "github_reviewed": True,
        "global_catalog": "present",
        "package_ecosystem": "npm",
        "package_name": "openclaw",
        "patched_version": "2026.4.15",
        "published_at": "2026-04-17T22:32:47Z",
        "repository": "openclaw/openclaw",
        "retrieved_at": "2026-08-15T00:50:00Z",
        "state": "published",
        "vulnerable_version_range": "< 2026.4.15",
        "withdrawn": False,
    },
    "GHSA-Q447-RJ3R-2CGH": {
        "aliases": ["CVE-2026-28478"],
        "first_party_url": "https://github.com/openclaw/openclaw/security/advisories/GHSA-q447-rj3r-2cgh",
        "ghsa_id": "GHSA-Q447-RJ3R-2CGH",
        "github_reviewed": True,
        "global_catalog": "present",
        "package_ecosystem": "npm",
        "package_name": "openclaw",
        "patched_version": "2026.2.13",
        "published_at": "2026-02-18T00:53:07Z",
        "repository": "openclaw/openclaw",
        "retrieved_at": "2026-08-15T00:50:00Z",
        "state": "published",
        "vulnerable_version_range": "< 2026.2.13",
        "withdrawn": False,
    },
    "GHSA-MFMP-Q643-VJ39": {
        "aliases": [],
        "first_party_url": "https://github.com/ChurchCRM/CRM/security/advisories/GHSA-mfmp-q643-vj39",
        "ghsa_id": "GHSA-MFMP-Q643-VJ39",
        "github_reviewed": False,
        "global_catalog": "absent_404",
        "package_ecosystem": "composer",
        "package_name": "churchcrm/crm",
        "patched_version": "7.4.3",
        "published_at": "2026-07-26T22:06:39Z",
        "repository": "ChurchCRM/CRM",
        "retrieved_at": "2026-08-15T00:50:00Z",
        "state": "published",
        "vulnerable_version_range": "< 7.4.3",
        "withdrawn": False,
    },
    "GHSA-M649-24Q9-Q6R4": {
        "aliases": [],
        "first_party_url": "https://github.com/ChurchCRM/CRM/security/advisories/GHSA-m649-24q9-q6r4",
        "ghsa_id": "GHSA-M649-24Q9-Q6R4",
        "github_reviewed": False,
        "global_catalog": "absent_404",
        "package_ecosystem": "composer",
        "package_name": "churchcrm/crm",
        "patched_version": "7.6.0",
        "published_at": "2026-08-10T03:22:52Z",
        "repository": "ChurchCRM/CRM",
        "retrieved_at": "2026-08-15T00:50:00Z",
        "state": "published",
        "vulnerable_version_range": "7.5.1",
        "withdrawn": False,
    },
    "GHSA-HM7V-JRHM-FMFX": {
        "aliases": [],
        "first_party_url": "https://github.com/ChurchCRM/CRM/security/advisories/GHSA-hm7v-jrhm-fmfx",
        "ghsa_id": "GHSA-HM7V-JRHM-FMFX",
        "github_reviewed": False,
        "global_catalog": "absent_404",
        "package_ecosystem": "composer",
        "package_name": "churchcrm/crm",
        "patched_version": "7.6.0",
        "published_at": "2026-08-10T03:21:29Z",
        "repository": "ChurchCRM/CRM",
        "retrieved_at": "2026-08-15T00:50:00Z",
        "state": "published",
        "vulnerable_version_range": "7.5.1",
        "withdrawn": False,
    },
}

def canon_sha(proj):
    missing = [k for k in CANON_KEYS if k not in proj]
    if missing:
        print("PROJ_MISSING_KEYS", missing); sys.exit(1)
    body_obj = {k: proj[k] for k in CANON_KEYS}
    body = json.dumps(body_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if not body.isascii():
        print("PROJ_NON_ASCII"); sys.exit(1)
    return hashlib.sha256(body.encode("ascii")).hexdigest(), body_obj

def check_proj(proj, expect_id):
    if proj.get("ghsa_id") != expect_id:
        print("PROJ_ID", proj.get("ghsa_id"), expect_id); sys.exit(1)
    sha, body_obj = canon_sha(proj)
    if sha != proj.get("sha256"):
        print("PROJ_SHA_MISMATCH", expect_id, sha, proj.get("sha256")); sys.exit(1)
    if sha != WANT_SHA[expect_id]:
        print("PROJ_SHA_PIN", expect_id, sha); sys.exit(1)
    want = WANT_FIELDS[expect_id]
    for k in CANON_KEYS:
        if body_obj[k] != want[k]:
            print("PROJ_FIELD", expect_id, k, body_obj[k], want[k]); sys.exit(1)
    if body_obj["state"] != "published" or body_obj["withdrawn"] is not False:
        print("PROJ_STATE", expect_id); sys.exit(1)
    return sha

cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open() if l.strip()]
res = json.loads(owned.joinpath("result.json").read_text())
catalog = res.get("advisory_projections") or {}
if set(catalog) != set(WANT_SHA):
    print("CATALOG_KEYS", sorted(catalog)); sys.exit(1)
for gid, pin in WANT_SHA.items():
    check_proj(catalog[gid], gid)
    if catalog[gid]["sha256"] != pin:
        print("CATALOG_PIN", gid); sys.exit(1)

assigned = ["GHSA-G353-MGV3-8PCJ", "GHSA-MFMP-Q643-VJ39", "GHSA-M649-24Q9-Q6R4"]
related_map = {
    "GHSA-G353-MGV3-8PCJ": ["GHSA-Q447-RJ3R-2CGH", "GHSA-XH72-V6V9-MWHC"],
    "GHSA-MFMP-Q643-VJ39": ["GHSA-M649-24Q9-Q6R4", "GHSA-HM7V-JRHM-FMFX"],
    "GHSA-M649-24Q9-Q6R4": ["GHSA-MFMP-Q643-VJ39", "GHSA-HM7V-JRHM-FMFX"],
}
for rec, cid in zip(cas, assigned):
    if rec["case_id"] != cid:
        print("CASE_ORDER", rec["case_id"], cid); sys.exit(1)
    proj = rec.get("first_party_advisory_projection") or {}
    check_proj(proj, cid)
    if proj != catalog[cid]:
        print("CASE_NE_CATALOG", cid); sys.exit(1)
    if rec.get("repository") != proj["repository"]:
        print("REPO_NE", cid); sys.exit(1)
    if proj["first_party_url"] not in (rec.get("first_party_sources") or []):
        print("URL_NOT_IN_SOURCES", cid); sys.exit(1)
    rel = rec.get("related_advisory_projections") or []
    rel_ids = [x.get("ghsa_id") for x in rel]
    if rel_ids != related_map[cid]:
        print("RELATED_IDS", cid, rel_ids); sys.exit(1)
    for rp in rel:
        rid = rp["ghsa_id"]
        check_proj(rp, rid)
        if rp != catalog[rid]:
            print("RELATED_NE_CATALOG", cid, rid); sys.exit(1)

def load_adv(rel):
    pth = adv_root / rel
    return json.loads(pth.read_text())

g353 = load_adv("advisories/github-reviewed/2026/03/GHSA-g353-mgv3-8pcj/GHSA-g353-mgv3-8pcj.json")
if g353.get("id", "").upper() != "GHSA-G353-MGV3-8PCJ":
    print("ADV_G353_ID"); sys.exit(1)
if g353.get("aliases") != ["CVE-2026-32974"] or g353.get("published") != "2026-03-13T20:55:34Z":
    print("ADV_G353_META"); sys.exit(1)
if g353.get("withdrawn") not in (None, ""):
    print("ADV_G353_WITHDRAWN"); sys.exit(1)
if "verificationToken" not in (g353.get("summary") or ""):
    print("ADV_G353_SUMMARY"); sys.exit(1)
blob = (g353.get("details") or "") + (g353.get("summary") or "")
if "encryptKey" not in blob:
    print("ADV_G353_ENCRYPT"); sys.exit(1)
aff = (g353.get("affected") or [{}])[0]
if aff.get("package") != {"ecosystem": "npm", "name": "openclaw"}:
    print("ADV_G353_PKG", aff.get("package")); sys.exit(1)
if (aff.get("database_specific") or {}).get("last_known_affected_version_range") != "<= 2026.3.11":
    print("ADV_G353_RANGE"); sys.exit(1)
fixed = [e.get("fixed") for r in (aff.get("ranges") or []) for e in (r.get("events") or []) if "fixed" in e]
if fixed != ["2026.3.12"]:
    print("ADV_G353_FIXED", fixed); sys.exit(1)
refs = [r.get("url") for r in (g353.get("references") or [])]
if catalog["GHSA-G353-MGV3-8PCJ"]["first_party_url"] not in refs:
    print("ADV_G353_URL"); sys.exit(1)
if not (g353.get("database_specific") or {}).get("github_reviewed"):
    print("ADV_G353_REVIEWED"); sys.exit(1)

xh72 = load_adv("advisories/github-reviewed/2026/04/GHSA-xh72-v6v9-mwhc/GHSA-xh72-v6v9-mwhc.json")
if xh72.get("id", "").upper() != "GHSA-XH72-V6V9-MWHC":
    print("ADV_XH72_ID"); sys.exit(1)
if xh72.get("aliases") != ["CVE-2026-44109"] or xh72.get("published") != "2026-04-17T22:32:47Z":
    print("ADV_XH72_META"); sys.exit(1)
xaff = (xh72.get("affected") or [{}])[0]
xfixed = [e.get("fixed") for r in (xaff.get("ranges") or []) for e in (r.get("events") or []) if "fixed" in e]
if xfixed != ["2026.4.15"]:
    print("ADV_XH72_FIXED", xfixed); sys.exit(1)
xrefs = [r.get("url") for r in (xh72.get("references") or [])]
if catalog["GHSA-XH72-V6V9-MWHC"]["first_party_url"] not in xrefs:
    print("ADV_XH72_URL"); sys.exit(1)

q447 = load_adv("advisories/github-reviewed/2026/02/GHSA-q447-rj3r-2cgh/GHSA-q447-rj3r-2cgh.json")
if q447.get("id", "").upper() != "GHSA-Q447-RJ3R-2CGH":
    print("ADV_Q447_ID"); sys.exit(1)
if q447.get("aliases") != ["CVE-2026-28478"] or q447.get("published") != "2026-02-18T00:53:07Z":
    print("ADV_Q447_META"); sys.exit(1)
qaff = next(a for a in (q447.get("affected") or []) if (a.get("package") or {}).get("name") == "openclaw")
qfixed = [e.get("fixed") for r in (qaff.get("ranges") or []) for e in (r.get("events") or []) if "fixed" in e]
if qfixed != ["2026.2.13"]:
    print("ADV_Q447_FIXED", qfixed); sys.exit(1)
qrefs = [r.get("url") for r in (q447.get("references") or [])]
if catalog["GHSA-Q447-RJ3R-2CGH"]["first_party_url"] not in qrefs:
    print("ADV_Q447_URL"); sys.exit(1)

for rel in (
    "advisories/github-reviewed/2026/07/GHSA-mfmp-q643-vj39/GHSA-mfmp-q643-vj39.json",
    "advisories/github-reviewed/2026/08/GHSA-m649-24q9-q6r4/GHSA-m649-24q9-q6r4.json",
    "advisories/github-reviewed/2026/08/GHSA-hm7v-jrhm-fmfx/GHSA-hm7v-jrhm-fmfx.json",
):
    if (adv_root / rel).exists():
        print("REVIEWED_SHOULD_BE_ABSENT", rel); sys.exit(1)

if catalog["GHSA-MFMP-Q643-VJ39"]["ghsa_id"] == catalog["GHSA-M649-24Q9-Q6R4"]["ghsa_id"]:
    print("MFMP_M649_SAME_ID"); sys.exit(1)
if catalog["GHSA-M649-24Q9-Q6R4"]["ghsa_id"] == catalog["GHSA-HM7V-JRHM-FMFX"]["ghsa_id"]:
    print("M649_HM7V_SAME_ID"); sys.exit(1)
if catalog["GHSA-G353-MGV3-8PCJ"]["ghsa_id"] == catalog["GHSA-XH72-V6V9-MWHC"]["ghsa_id"]:
    print("G353_XH72_SAME_ID"); sys.exit(1)
if catalog["GHSA-MFMP-Q643-VJ39"]["patched_version"] == catalog["GHSA-M649-24Q9-Q6R4"]["patched_version"]:
    print("MFMP_M649_SAME_PATCH"); sys.exit(1)
print("IDENTITY_OK")
PY

echo "== git facts G353 =="
[[ -d $Z ]] || fail "OPENCLAW_CLONE_ABSENT"
SQ=5c2cb6c591e4b63c2df0549ad2202403256e2a96
P=49c60e9065d98a6848e62c717315eb91eeaa6038
F=7844bc89a1612800810617c823eb0c76ef945804
M=b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517
A23=a23e0d5140e5126f5055a46824cae4ba0a097ba3
SPLIT=f46bd2e0cc1742bf33ae916e3b26eda3330cab8b
TFIX=496ca3a6373a3c1203b7a0b82ed8c93acfbb22e0
QFIX=3cbcba10cf30c2ffb898f0d8c7dfb929f15f8930
XFIX=c8003f1b33ed2924be5f62131bd28742c5a41aae
NPM11=29dc65403faf41dc52944c02a0db9fa4b8457395
NPM12=6472949f25250a58382c0fbeed436e3fb3875954
PEEL11=29dc65403faf41dc52944c02a0db9fa4b8457395
PEEL12=70d7a0854c54c489eaefd56bb406ad885f2b3ea2
FILE=extensions/feishu/src/monitor.ts
SCHEMA=extensions/feishu/src/config-schema.ts
ACCT=extensions/feishu/src/monitor.account.ts
TRANS=extensions/feishu/src/monitor.transport.ts
CLIENT=extensions/feishu/src/client.ts

parents=$(gitq -C "$Z" rev-list --parents -n 1 "$SQ")
[[ $parents == "$SQ $P" ]] || fail "G353_PARENTS $parents"
gitq -C "$Z" cat-file -p "$SQ" | LC_ALL=C grep -q 'Co-authored-by: Claude Opus 4.6' || fail "G353_CAND_MARKER"
gitq -C "$Z" cat-file -p "$F" | LC_ALL=C grep -E -q 'Co-Authored-By:|Co-authored-by:|Claude|Codex|Copilot' && fail "G353_FIX_MARKER" || true
gitq -C "$Z" cat-file -p "$A23" | LC_ALL=C grep -E -q 'Co-Authored-By:|Co-authored-by:|Claude|Codex|Copilot' && fail "G353_A23_MARKER" || true
gitq -C "$Z" grep -q 'webhook mode not implemented in monitor' "$P" -- "$FILE" || fail "G353_PARENT_UNIMPLEMENTED"
if gitq -C "$Z" grep -q 'Lark.adaptDefault' "$P" -- "$FILE"; then
  fail "G353_PARENT_HAS_ADAPT"
fi
gitq -C "$Z" grep -q 'Lark.adaptDefault' "$SQ" -- "$FILE" || fail "G353_SQUASH_ADAPT"
gitq -C "$Z" grep -q 'encryptKey: account.encryptKey' "$P" -- "$CLIENT" || fail "G353_PARENT_DISPATCHER"
blob_c_p=$(gitq -C "$Z" rev-parse "${P}:${CLIENT}")
blob_c_s=$(gitq -C "$Z" rev-parse "${SQ}:${CLIENT}")
[[ $blob_c_p == "$blob_c_s" ]] || fail "G353_CLIENT_CHANGED"
[[ $blob_c_p == 3c30890741789cb67e56b899bcef5ca1cd5253c4 ]] || fail "G353_CLIENT_BLOB $blob_c_p"
pk=$(gitq -C "$Z" log --first-parent -S 'connectionMode="webhook" requires channels.feishu.verificationToken' --format='%H' v2026.3.11 -- "$SCHEMA")
print -r -- "$pk" | LC_ALL=C grep -q "^${A23}" || fail "G353_TOKEN_PICKAXE $pk"
pk=$(gitq -C "$Z" log --first-parent -S 'connectionMode="webhook" requires channels.feishu.encryptKey' --format='%H' v2026.3.12 -- "$SCHEMA")
print -r -- "$pk" | LC_ALL=C grep -q "^${F}" || fail "G353_ENCRYPT_PICKAXE $pk"
gitq -C "$Z" merge-base --is-ancestor "$M" "$SQ" && fail "G353_MEMBER_ANC_SQUASH" || true
gitq -C "$Z" merge-base --is-ancestor "$M" v2026.3.11 && fail "G353_MEMBER_IN_VULN" || true
gitq -C "$Z" merge-base --is-ancestor "$SQ" v2026.3.11 || fail "G353_SQUASH_TAG"
gitq -C "$Z" merge-base --is-ancestor "$F" v2026.3.11 && fail "G353_FIX_IN_VULN" || true
gitq -C "$Z" merge-base --is-ancestor "$F" v2026.3.12 || fail "G353_FIX_TAG"
gitq -C "$Z" merge-base --is-ancestor "$A23" v2026.3.11 || fail "G353_A23_TAG"
gitq -C "$Z" merge-base --is-ancestor "$TFIX" v2026.3.11 && fail "G353_TFIX_IN_VULN" || true
gitq -C "$Z" merge-base --is-ancestor "$TFIX" v2026.3.12 || fail "G353_TFIX_TAG"
gitq -C "$Z" merge-base --is-ancestor "$QFIX" v2026.3.11 || fail "G353_QFIX_IN_311"
gitq -C "$Z" merge-base --is-ancestor "$XFIX" v2026.3.12 && fail "G353_XFIX_IN_312" || true
gitq -C "$Z" merge-base --is-ancestor "$F" "$TFIX" || fail "G353_F_ANC_TFIX"
if gitq -C "$Z" ls-tree --name-only "$SQ" -- "$ACCT" | LC_ALL=C grep -q .; then
  fail "G353_SQUASH_HAS_ACCOUNT"
fi
gitq -C "$Z" grep -q 'webhook mode requires verificationToken' v2026.3.11 -- "$ACCT" || fail "G353_VULN_TOKEN"
if gitq -C "$Z" grep -q 'webhook mode requires encryptKey' v2026.3.11 -- "$ACCT"; then
  fail "G353_VULN_HAS_ENCRYPT"
fi
gitq -C "$Z" grep -q 'webhook mode requires encryptKey' "$F" -- "$ACCT" || fail "G353_FIX_ENCRYPT"
blob_m11=$(gitq -C "$Z" rev-parse "v2026.3.11:${FILE}")
blob_m12=$(gitq -C "$Z" rev-parse "v2026.3.12:${FILE}")
[[ $blob_m11 == "$blob_m12" ]] || fail "G353_MONITOR_CHANGED_ACROSS_FIX"
[[ $blob_m11 == 50241d36baa5c2327c8965906bc0ab21bbe438c4 ]] || fail "G353_MONITOR_BLOB $blob_m11"
blob_t_f=$(gitq -C "$Z" rev-parse "${F}:${TRANS}")
blob_t_v=$(gitq -C "$Z" rev-parse "v2026.3.11:${TRANS}")
[[ $blob_t_f == "$blob_t_v" ]] || fail "G353_FIX_TOUCHED_TRANSPORT"
blob_t12=$(gitq -C "$Z" rev-parse "v2026.3.12:${TRANS}")
blob_tt=$(gitq -C "$Z" rev-parse "${TFIX}:${TRANS}")
[[ $blob_t12 == "$blob_tt" ]] || fail "G353_312_TRANSPORT_NE_TFIX"
peel=$(gitq -C "$Z" rev-parse 'v2026.3.11^{commit}')
[[ $peel == "$PEEL11" ]] || fail "G353_PEEL11 $peel"
peel=$(gitq -C "$Z" rev-parse 'v2026.3.12^{commit}')
[[ $peel == "$PEEL12" ]] || fail "G353_PEEL12 $peel"
gitq -C "$Z" merge-base --is-ancestor "$F" "$NPM12" || fail "G353_FIX_NPM12"
gitq -C "$Z" merge-base --is-ancestor "$F" "$NPM11" && fail "G353_FIX_NPM11" || true
echo "GIT_G353_OK"

echo "== git facts ChurchCRM =="
[[ -d $C ]] || fail "CHURCHCRM_CLONE_ABSENT"
SQC=80a3e620a4aa046c2644937a5a2fa799a2e750d6
PC=9166d9983afcc59df343cf19c7595351d6f750af
F1=330d0d6a2e6995f017d5943bd3b4806d713b181c
F2=ae2b73550452056cc45a65a4165340ae17c2c3e5
MEM=0ea20d01050cd25b30bca1418bb821fbd3bcb7ab
EDE=ede1bfb08633e6d1157744e99d176e258fc58aba
M1=3b8b474519272e0d6bb2a7f07c4f1202d2a02bf4
M2=367dd18e4b017a5bc893e1fab1ce55cc34647f08
M3=5631bb084da530732dbef5aa2f3f71c67c739298
GV=src/skin/js/GroupView.js
GR=src/skin/js/GroupRoles.js

parents=$(gitq -C "$C" rev-list --parents -n 1 "$SQC")
[[ $parents == "$SQC $PC" ]] || fail "CRM_PARENTS $parents"
gitq -C "$C" cat-file -p "$SQC" | LC_ALL=C grep -q 'Co-authored-by: Claude Sonnet 4.6' || fail "CRM_SQUASH_MARKER"
gitq -C "$C" cat-file -p "$F1" | LC_ALL=C grep -E -q 'Co-Authored-By:|Co-authored-by:|Claude|Codex|Copilot' && fail "CRM_F1_MARKER" || true
gitq -C "$C" cat-file -p "$F2" | LC_ALL=C grep -E -q 'Co-Authored-By:|Co-authored-by:|Claude|Codex|Copilot' && fail "CRM_F2_MARKER" || true
if gitq -C "$C" grep -q buildRolePills "$PC" -- "$GV"; then
  fail "CRM_PARENT_HAS_PILLS"
fi
if gitq -C "$C" grep -q 'tel:' "$PC" -- "$GV"; then
  fail "CRM_PARENT_HAS_TEL"
fi
if gitq -C "$C" grep -q 'mailto:' "$PC" -- "$GV"; then
  fail "CRM_PARENT_HAS_MAILTO"
fi
gitq -C "$C" grep -q 'data-name' "$PC" -- "$GV" || fail "CRM_PARENT_MISSING_DATANAME"
gitq -C "$C" grep -q buildRolePills "$SQC" -- "$GV" || fail "CRM_SQUASH_PILLS"
gitq -C "$C" grep -q 'tel:' "$SQC" -- "$GV" || fail "CRM_SQUASH_TEL"
gitq -C "$C" grep -q 'mailto:' "$SQC" -- "$GV" || fail "CRM_SQUASH_MAILTO"
blob_gr_p=$(gitq -C "$C" rev-parse "${PC}:${GR}")
blob_gr_s=$(gitq -C "$C" rev-parse "${SQC}:${GR}")
blob_gr_m=$(gitq -C "$C" rev-parse "${MEM}:${GR}")
[[ $blob_gr_p == 62dfbce14ca2bd0f7ff7a0e5f69152ef289ea2b0 ]] || fail "CRM_GR_PARENT $blob_gr_p"
[[ $blob_gr_p == "$blob_gr_s" ]] || fail "CRM_GR_SQUASH_CHANGED"
[[ $blob_gr_p == "$blob_gr_m" ]] || fail "CRM_GR_MEMBER_CHANGED"
blob_gv_p=$(gitq -C "$C" rev-parse "${PC}:${GV}")
blob_gv_e=$(gitq -C "$C" rev-parse "${EDE}:${GV}")
[[ $blob_gv_p == "$blob_gv_e" ]] || fail "CRM_PARENT_NE_EDE"
blob_gv_s=$(gitq -C "$C" rev-parse "${SQC}:${GV}")
blob_gv_mem=$(gitq -C "$C" rev-parse "${MEM}:${GV}")
[[ $blob_gv_s != "$blob_gv_mem" ]] || fail "CRM_MEMBER_EQ_SQUASH"
pk=$(gitq -C "$C" log --first-parent -S buildRolePills --format='%H' 7.4.2 -- "$GV")
print -r -- "$pk" | LC_ALL=C grep -q "^${SQC}" || fail "CRM_PILLS_PICKAXE $pk"
pk=$(gitq -C "$C" log --first-parent -S 'tel:' --format='%H' 7.5.1 -- "$GV")
print -r -- "$pk" | LC_ALL=C grep -q "^${SQC}" || fail "CRM_TEL_PICKAXE $pk"
pk=$(gitq -C "$C" log --first-parent -S 'mailto:' --format='%H' 7.5.1 -- "$GV")
print -r -- "$pk" | LC_ALL=C grep -q "^${SQC}" || fail "CRM_MAILTO_PICKAXE $pk"
pk=$(gitq -C "$C" log --first-parent -S 'data-name' --format='%H' 7.5.1 -- "$GV")
print -r -- "$pk" | LC_ALL=C grep -q "^${EDE}" || fail "CRM_DATANAME_PICKAXE $pk"
gitq -C "$C" merge-base --is-ancestor "$MEM" "$SQC" && fail "CRM_MEMBER_ANC_SQUASH" || true
gitq -C "$C" merge-base --is-ancestor "$MEM" 7.4.2 && fail "CRM_MEMBER_IN_742" || true
gitq -C "$C" merge-base --is-ancestor "$SQC" 7.4.2 || fail "CRM_SQUASH_742"
gitq -C "$C" merge-base --is-ancestor "$F1" 7.4.2 && fail "CRM_F1_IN_742" || true
gitq -C "$C" merge-base --is-ancestor "$F1" 7.4.3 || fail "CRM_F1_743"
gitq -C "$C" merge-base --is-ancestor "$F2" 7.5.1 && fail "CRM_F2_IN_751" || true
gitq -C "$C" merge-base --is-ancestor "$F2" 7.6.0 || fail "CRM_F2_760"
gitq -C "$C" merge-base --is-ancestor "$M1" "$F1" && fail "CRM_M1_ANC_F1" || true
gitq -C "$C" merge-base --is-ancestor "$M2" 7.4.3 && fail "CRM_M2_IN_743" || true
gitq -C "$C" merge-base --is-ancestor "$M3" "$F2" && fail "CRM_M3_ANC_F2" || true
gitq -C "$C" grep -q 'i18next.t(role.OptionName)' 7.4.2 -- "$GV" || fail "CRM_742_UNESCAPED"
gitq -C "$C" grep -q 'window.CRM.escapeHtml(i18next.t(role.OptionName))' "$F1" -- "$GV" || fail "CRM_F1_ESCAPEHTML"
if gitq -C "$C" grep -q 'window.CRM.escapeHtml(i18next.t(role.OptionName))' 7.4.2 -- "$GV"; then
  fail "CRM_742_ALREADY_ESCAPED"
fi
gitq -C "$C" grep -q 'href="tel:' 7.5.1 -- "$GV" || fail "CRM_751_TEL"
gitq -C "$C" grep -q 'window.CRM.escapeAttribute(data)' "$F2" -- "$GV" || fail "CRM_F2_ATTR"
if gitq -C "$C" grep -q 'window.CRM.escapeAttribute(data)' 7.5.1 -- "$GV"; then
  fail "CRM_751_ALREADY_ATTR"
fi
blob=$(gitq -C "$C" rev-parse "7.4.2:${GV}")
[[ $blob == 1cb473c551a7625ef1c35f9e3d8d449853b54c1a ]] || fail "CRM_742_GV $blob"
blob=$(gitq -C "$C" rev-parse "7.4.3:${GV}")
blobf=$(gitq -C "$C" rev-parse "${F1}:${GV}")
[[ $blob == "$blobf" ]] || fail "CRM_743_NE_F1"
[[ $blob == 116f1bffe566960053ee9aff479dfa3c02e8d9a7 ]] || fail "CRM_743_GV $blob"
blob=$(gitq -C "$C" rev-parse "7.4.3:${GR}")
blobf=$(gitq -C "$C" rev-parse "${F1}:${GR}")
[[ $blob == "$blobf" ]] || fail "CRM_743_GR_NE_F1"
blob=$(gitq -C "$C" rev-parse "7.5.1:${GV}")
[[ $blob == ed5347f0d5562d99266539e83a1db9e05b53b92d ]] || fail "CRM_751_GV $blob"
blob=$(gitq -C "$C" rev-parse "7.6.0:${GV}")
blobf=$(gitq -C "$C" rev-parse "${F2}:${GV}")
[[ $blob == "$blobf" ]] || fail "CRM_760_NE_F2"
[[ $blob == 041a9794dc64be0b0c3931edba027ca7a1030a47 ]] || fail "CRM_760_GV $blob"
peel=$(gitq -C "$C" rev-parse '7.4.2^{commit}')
[[ $peel == f54eea0ff476d4a343e98be0cbbaee42440c436f ]] || fail "CRM_PEEL742 $peel"
peel=$(gitq -C "$C" rev-parse '7.4.3^{commit}')
[[ $peel == dbdc6133165b906a84c5bf4d919c74ee797c192b ]] || fail "CRM_PEEL743 $peel"
peel=$(gitq -C "$C" rev-parse '7.5.1^{commit}')
[[ $peel == 9ee9c00c6ea99582a7d65b5d1d8c6197b51a77a8 ]] || fail "CRM_PEEL751 $peel"
peel=$(gitq -C "$C" rev-parse '7.6.0^{commit}')
[[ $peel == 9b5993c0918ce45522e57f28114929ac75a29b9b ]] || fail "CRM_PEEL760 $peel"
later=$(gitq -C "$C" log --first-parent --format='%H' ${F1}..7.4.3 -- "$GV" "$GR")
[[ -z "$later" ]] || fail "CRM_LATER_AFTER_F1 $later"
later=$(gitq -C "$C" log --first-parent --format='%H' ${F2}..7.6.0 -- "$GV")
[[ -z "$later" ]] || fail "CRM_LATER_AFTER_F2 $later"
echo "GIT_CRM_OK"

echo "== pinned npm archives plus git schema =="
python3 - "$OWNED" <<'PY' || fail "npm pins"
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open() if l.strip()]
res = json.loads(owned.joinpath("result.json").read_text())
g353 = cas[0]
want = {
    "2026.3.11": {
        "sha1": "48fad3b27140ad3b05ca86bfe6941e0244a8a930",
        "sha256": "4c6641bac62ce2ccb86d8df2d0252dc2a4769fe3ddca12c1f1ee1013ebd65dba",
    },
    "2026.3.12": {
        "sha1": "62e0f64a49ed9ff99a77ae34dde2be2e05f48d26",
        "sha256": "2ee324fc0d378deb13cf24be16a3996aec35e27f44d1a58ba9a1ded3afce3d37",
    },
}
vuln = g353["vulnerable_release_evidence"]
fix = g353["fixed_release_evidence"]
if vuln.get("npm_tarball_sha256") != want["2026.3.11"]["sha256"] or vuln.get("npm_tarball_sha1") != want["2026.3.11"]["sha1"]:
    print("NPM11_PIN"); sys.exit(1)
if fix.get("npm_tarball_sha256") != want["2026.3.12"]["sha256"] or fix.get("npm_tarball_sha1") != want["2026.3.12"]["sha1"]:
    print("NPM12_PIN"); sys.exit(1)
pin = res.get("npm_archive_projection") or {}
if pin.get("versions") != want:
    print("NPM_RES_PIN", pin); sys.exit(1)
print("NPM_PINNED_OK")
PY
gitq -C "$Z" grep -q 'requires channels.feishu.verificationToken' v2026.3.11 -- "$SCHEMA" || fail "GIT11_TOKEN"
if gitq -C "$Z" grep -q 'requires channels.feishu.encryptKey' v2026.3.11 -- "$SCHEMA"; then
  fail "GIT11_HAS_ENCRYPT"
fi
gitq -C "$Z" grep -q 'requires channels.feishu.encryptKey' v2026.3.12 -- "$SCHEMA" || fail "GIT12_ENCRYPT"
blob=$(gitq -C "$Z" rev-parse "v2026.3.11:${SCHEMA}")
[[ $blob == 4060e6e2cbb8fbbf2a8c78991538c8bdbf0571e3 ]] || fail "GIT11_SCHEMA_BLOB $blob"
blob=$(gitq -C "$Z" rev-parse "v2026.3.12:${SCHEMA}")
[[ $blob == b78404de6f821f4a630167b09275aa450d79fec1 ]] || fail "GIT12_SCHEMA_BLOB $blob"
echo "NPM_OFFLINE_OK"

echo "== pinned ChurchCRM releases plus composer.json =="
python3 - "$OWNED" "$C" <<'PY' || fail "composer pins"
import json, subprocess, sys
from pathlib import Path
owned = Path(sys.argv[1])
clone = sys.argv[2]
res = json.loads(owned.joinpath("result.json").read_text())
pin = res.get("github_release_projection") or {}
want_peel = {
    "7.4.2": "f54eea0ff476d4a343e98be0cbbaee42440c436f",
    "7.4.3": "dbdc6133165b906a84c5bf4d919c74ee797c192b",
    "7.5.1": "9ee9c00c6ea99582a7d65b5d1d8c6197b51a77a8",
    "7.6.0": "9b5993c0918ce45522e57f28114929ac75a29b9b",
}
if pin.get("repository") != "ChurchCRM/CRM":
    print("REL_REPO"); sys.exit(1)
if pin.get("retrieved_at") != "2026-08-15T00:50:00Z":
    print("REL_RETRIEVED"); sys.exit(1)
tags = pin.get("tags") or {}
if set(tags) != set(want_peel):
    print("REL_TAGS", sorted(tags)); sys.exit(1)
for tag, peel in want_peel.items():
    rec = tags[tag]
    if rec.get("draft") is not False or rec.get("prerelease") is not False:
        print("REL_DRAFT", tag); sys.exit(1)
    if rec.get("peel") != peel or rec.get("target_commitish") != peel:
        print("REL_PEEL", tag, rec); sys.exit(1)
    show = subprocess.run(
        ["git", "-C", clone, "show", tag + ":src/composer.json"],
        capture_output=True, text=True, check=True,
    )
    comp = json.loads(show.stdout)
    if comp.get("name") != "churchcrm/crm" or str(comp.get("version")) != tag:
        print("COMPOSER", tag, comp.get("name"), comp.get("version")); sys.exit(1)
print("RELEASES_OFFLINE_OK")
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
names={p.name for p in d.iterdir()}
extra=names-allowed
if extra:
    raise SystemExit("extra %s" % sorted(extra))
print("hygiene_ok")
PY

echo "REPLAY_OK reviewed=3 PASS_proposal=2 REJECT=1 NARROW=0 UNKNOWN=0 BLOCKED=0"
