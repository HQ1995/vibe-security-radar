#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearclosed-e-grok46-high}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
OC=${OC:-/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw}
Z=${Z:-/home/hanqing/.cache/cve-analyzer/repos/qhkm_zeptoclaw}
FS=${FS:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/fission}
ADV=${ADV:-/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database}
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

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
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json" \
  81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl" \
  35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
hash_check "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/8rw6_acceptance.json" \
  8cb85b42f405595b834a4ccae9b782c488b8dfa340900ad5717bb0dac71cfae9
hash_check "$ADV/advisories/github-reviewed/2026/04/GHSA-2qrv-rc5x-2g2h/GHSA-2qrv-rc5x-2g2h.json" \
  795ba73fa7aa7ccc84d40492f2106784cf54305019e3039b59237a631ab6332c
hash_check "$ADV/advisories/github-reviewed/2026/04/GHSA-82qx-6vj7-p8m2/GHSA-82qx-6vj7-p8m2.json" \
  bd5b282ff4ed001a9bf62c9d16505d88553860fe3f583a8ebf8f30a8d5b7ba7e
hash_check "$ADV/advisories/github-reviewed/2026/03/GHSA-5wp8-q9mx-8jx8/GHSA-5wp8-q9mx-8jx8.json" \
  2dadc4ca9b6944e557d695d6097257d44d4bdd12048aefef6d54d566990884ba
hash_check "$ADV/advisories/github-reviewed/2026/07/GHSA-r5jh-q2mw-gcx4/GHSA-r5jh-q2mw-gcx4.json" \
  82cfd76b2a45f3afc85ec74ce1777e347983bccd1b0cf193a79b99c05f26f1c3
adv_head=$(gitq -C "$ADV" rev-parse HEAD)
[[ $adv_head == a42c436870111aa3f221257c9d56126a93173ccc ]] || fail "ADV_HEAD $adv_head"

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
    "GHSA-2QRV-RC5X-2G2H",
    "GHSA-5WP8-Q9MX-8JX8",
    "GHSA-R5JH-Q2MW-GCX4",
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
if [a["fp211_ordinal"] for a in ass] != [123, 126, 133]:
    print("ORDINAL_FAIL"); sys.exit(1)
n_pass = sum(1 for c in cas if c["verdict"] == "PASS_PROPOSAL")
n_nar = sum(1 for c in cas if c["verdict"] == "NARROW")
n_rej = sum(1 for c in cas if c["verdict"] == "REJECT")
if n_pass != 1 or n_nar != 2 or n_rej != 0 or len(cas) != 3:
    print("COUNT_FAIL", n_pass, n_nar, n_rej); sys.exit(1)
if res["conservation"]["equation"] != "3=3+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposal_ids"] != ["GHSA-5WP8-Q9MX-8JX8"]:
    print("PASS_IDS_FAIL"); sys.exit(1)
if res["canonical_strict_count_untouched"] != 88:
    print("FLAG_FAIL"); sys.exit(1)
for rec in cas:
    g = rec["gates"]
    for k in need:
        if g[k] not in okv:
            print("BAD_GATE", rec["case_id"], k, g[k]); sys.exit(1)
    if rec.get("osv_introduced_used_as_causal_proof") is not False:
        print("OSV_USED_AS_PROOF", rec["case_id"]); sys.exit(1)
    if rec.get("authorship_transfer") is not False:
        print("TRANSFER", rec["case_id"]); sys.exit(1)
    if g["release_gate"] != "PASS":
        print("RELEASE_NOT_PASS", rec["case_id"]); sys.exit(1)
    if g["uniqueness_gate"] != "PASS":
        print("UNIQ_NOT_PASS", rec["case_id"]); sys.exit(1)
    if g["identity_gate"] != "PASS":
        print("IDENTITY_NOT_PASS", rec["case_id"]); sys.exit(1)
if cas[0]["verdict"] != "NARROW" or cas[0]["seven_gates_exact_pass"] is not False:
    print("2QRV_NOT_NARROW"); sys.exit(1)
if cas[0].get("proposed_pass") is not False:
    print("2QRV_PROPOSED"); sys.exit(1)
if cas[0].get("distinct_from_82qx") is not True:
    print("2QRV_82QX_FLAG"); sys.exit(1)
if "CVE-2026-43571" in cas[0].get("aliases", []):
    print("2QRV_PACKED_82QX_ALIAS"); sys.exit(1)
if cas[1]["verdict"] != "PASS_PROPOSAL" or cas[1]["seven_gates_exact_pass"] is not True:
    print("5WP8_NOT_PASS"); sys.exit(1)
if cas[1].get("proposed_pass") is not True:
    print("5WP8_PROPOSED_FLAG"); sys.exit(1)
if any(g != "PASS" for g in cas[1]["gates"].values()):
    print("5WP8_GATE_NOT_PASS", cas[1]["gates"]); sys.exit(1)
if cas[1]["contribution_class"] != "AI_INCOMPLETE_REMEDIATION":
    print("5WP8_CLASS"); sys.exit(1)
if cas[1]["candidate_set"] != ["1712debbea60af6adf4a8a5939a43f7ef9a1ac16"]:
    print("5WP8_CAND"); sys.exit(1)
if "3c4368da0ab48c1091858d3f9503c378a209997f" in cas[1]["candidate_set"]:
    print("5WP8_MEMBER_IN_CAND"); sys.exit(1)
if cas[2]["verdict"] != "NARROW" or cas[2]["gates"]["but_for_gate"] != "NARROW":
    print("R5JH_NOT_NARROW"); sys.exit(1)
if cas[2].get("proposed_pass") is not False:
    print("R5JH_PROPOSED"); sys.exit(1)
if cas[2]["candidate_set"] != ["5a3d68a349b001302b1acb6e838f05283160548d"]:
    print("R5JH_CAND"); sys.exit(1)
if "0d851525a35ba517dda7fe892333df5d0919dffc" in cas[2]["candidate_set"]:
    print("R5JH_MEMBER_IN_CAND"); sys.exit(1)
print("CONSERVATION_OK 3=3+0 NARROW=2 PASS_PROPOSAL=1")
PY

echo "== uniqueness vs pinned canonical88 and 82QX =="
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
if "GHSA-82QX-6VJ7-P8M2" in ids:
    print("UNIQUENESS_FAIL 82QX_COUNTED"); sys.exit(1)
if len(strict) != 88:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
a2 = json.loads(Path("$ADV/advisories/github-reviewed/2026/04/GHSA-2qrv-rc5x-2g2h/GHSA-2qrv-rc5x-2g2h.json").read_text())
a8 = json.loads(Path("$ADV/advisories/github-reviewed/2026/04/GHSA-82qx-6vj7-p8m2/GHSA-82qx-6vj7-p8m2.json").read_text())
ids2 = {a2.get("id","").lower()} | {x.lower() for x in a2.get("aliases", [])}
ids8 = {a8.get("id","").lower()} | {x.lower() for x in a8.get("aliases", [])}
if ids2 & ids8:
    print("ALIAS_OVERLAP", ids2 & ids8); sys.exit(1)
if a2.get("aliases") != ["CVE-2026-41295"]:
    print("2QRV_ALIAS", a2.get("aliases")); sys.exit(1)
if a8.get("aliases") != ["CVE-2026-43571"]:
    print("82QX_ALIAS", a8.get("aliases")); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "2QRV_DISTINCT_FROM_82QX")
PY

echo "== git facts =="
[[ -d $OC && -d $Z && -d $FS ]] || fail "CLONE_ABSENT"

# 2QRV ordinal 123
SQ=f4cc93dc7da7359c35130bbbb244d3fac695740f
M=fc1b156dc4105bdbcdc24d4c25d4f5af25cfd7bb
F=53c29df2a9eb242a70d0ff29f3d1e67c8d6801f0
P=a058bf918dda7bb422d042bed576bf766637920c
F82=1fede43b948df40ca8674511d4bd08d39f6c5837
HMAN=b68c59116cfd30918ca48a6b9890cd95815b9f21
gitq -C "$OC" cat-file -t "$SQ" >/dev/null
gitq -C "$OC" cat-file -t "$M" >/dev/null
gitq -C "$OC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$SQ")
[[ $parents == "$SQ $P" ]] || fail "2QRV_PARENTS $parents"
gitq -C "$OC" cat-file -p "$SQ" | LC_ALL=C grep -q 'Co-authored-by: Claude Opus 4.6' || fail "2QRV_MARKER"
gitq -C "$OC" grep -q reloadOnboardingPluginRegistry "$P" -- src/commands/onboard-channels.ts || fail "2QRV_PARENT_RELOAD"
if gitq -C "$OC" grep -q onlyPluginIds "$P" -- src/plugins/loader.ts; then
  fail "2QRV_PARENT_HAS_ONLYPLUGINIDS"
fi
gitq -C "$OC" grep -q onlyPluginIds "$SQ" -- src/plugins/loader.ts || fail "2QRV_SQUASH_ONLYPLUGINIDS"
blob_m=$(gitq -C "$OC" rev-parse "${M}:src/channels/plugins/catalog.ts")
blob_mp=$(gitq -C "$OC" rev-parse "${M}^:src/channels/plugins/catalog.ts")
[[ $blob_m == "$blob_mp" ]] || fail "2QRV_MEMBER_CATALOG_CHANGED"
blob_sq=$(gitq -C "$OC" rev-parse "${SQ}:src/channels/plugins/catalog.ts")
blob_p=$(gitq -C "$OC" rev-parse "${P}:src/channels/plugins/catalog.ts")
[[ $blob_sq != "$blob_p" ]] || fail "2QRV_SQUASH_CATALOG_UNCHANGED"
fsubj=$(gitq -C "$OC" log -1 --format='%s' "$F")
[[ $fsubj == *"ignore untrusted workspace shadows"* ]] || fail "2QRV_FIX_SUBJ $fsubj"
gitq -C "$OC" merge-base --is-ancestor "$M" "$SQ" && fail "2QRV_MEMBER_ANC_SQUASH" || true
gitq -C "$OC" merge-base --is-ancestor "$M" v2026.4.1 && fail "2QRV_MEMBER_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$HMAN" "$SQ" && fail "2QRV_HUMAN_ANC_SQUASH" || true
gitq -C "$OC" merge-base --is-ancestor "$SQ" v2026.4.1 || fail "2QRV_SQUASH_TAG"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.4.1 && fail "2QRV_FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.4.2 || fail "2QRV_FIX_TAG"
gitq -C "$OC" merge-base --is-ancestor "$F82" v2026.4.2 && fail "2QRV_82QX_FIX_IN_42" || true
gitq -C "$OC" merge-base --is-ancestor "$F82" v2026.4.10 || fail "2QRV_82QX_FIX_TAG"
peel=$(gitq -C "$OC" rev-parse 'v2026.4.1^{commit}')
[[ $peel == da64a978e5814567f7797cc34fbe29b61b7eae7a ]] || fail "2QRV_PEEL41 $peel"
echo "2QRV_OK"

# 5WP8 ordinal 126
SQ=1712debbea60af6adf4a8a5939a43f7ef9a1ac16
M=3c4368da0ab48c1091858d3f9503c378a209997f
F=68916c3e4f3af107f11940b27854fc7ef517058b
P=c5bd830cd8969336f03a87f416d2ac7b4d244be2
gitq -C "$Z" cat-file -t "$SQ" >/dev/null
gitq -C "$Z" cat-file -t "$M" >/dev/null
gitq -C "$Z" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$Z" rev-list --parents -n 1 "$SQ")
[[ $parents == "$SQ $P" ]] || fail "5WP8_PARENTS $parents"
gitq -C "$Z" cat-file -p "$SQ" | LC_ALL=C grep -q 'Co-authored-by: Claude Sonnet 4.6' || fail "5WP8_MARKER"
if gitq -C "$Z" grep -q ShellAllowlistMode "$P" -- src/security/shell.rs; then
  fail "5WP8_PARENT_HAS_ALLOWLIST"
fi
gitq -C "$Z" grep -q 'allowlist_mode != ShellAllowlistMode::Off && !self.allowlist.is_empty()' "$SQ" -- src/security/shell.rs || fail "5WP8_SQUASH_EMPTY_SKIP"
gitq -C "$Z" grep -q 'allowlist_mode != ShellAllowlistMode::Off && !self.allowlist.is_empty()' v0.6.1 -- src/security/shell.rs || fail "5WP8_V061_EMPTY_SKIP"
if gitq -C "$Z" grep -q 'allowlist_mode != ShellAllowlistMode::Off && !self.allowlist.is_empty()' "$F" -- src/security/shell.rs; then
  fail "5WP8_FIX_STILL_EMPTY_SKIP"
fi
gitq -C "$Z" grep -q 'Previously, `!self.allowlist.is_empty()` guard skipped' "$F" -- src/security/shell.rs || fail "5WP8_FIX_COMMENT"
pk=$(gitq -C "$Z" log --first-parent -S allowlist.is_empty --format='%H' v0.6.1 -- src/security/shell.rs)
print -r -- "$pk" | LC_ALL=C grep -q '^1712debbea60af6adf4a8a5939a43f7ef9a1ac16' || fail "5WP8_PICKAXE $pk"
gitq -C "$Z" merge-base --is-ancestor "$M" "$SQ" && fail "5WP8_MEMBER_ANC_SQUASH" || true
gitq -C "$Z" merge-base --is-ancestor "$M" v0.6.1 && fail "5WP8_MEMBER_IN_VULN" || true
gitq -C "$Z" merge-base --is-ancestor "$SQ" v0.6.1 || fail "5WP8_SQUASH_TAG"
gitq -C "$Z" merge-base --is-ancestor "$F" v0.6.1 && fail "5WP8_FIX_IN_VULN" || true
gitq -C "$Z" merge-base --is-ancestor "$F" v0.6.2 || fail "5WP8_FIX_TAG"
peel=$(gitq -C "$Z" rev-parse 'v0.6.1^{commit}')
[[ $peel == ad14ed8d4e6f982af272523f4accc107b191fb18 ]] || fail "5WP8_PEEL61 $peel"
peel=$(gitq -C "$Z" rev-parse 'v0.6.2^{commit}')
[[ $peel == f052aa21f298559729aa19b770da988f00a193df ]] || fail "5WP8_PEEL62 $peel"
blob_f=$(gitq -C "$Z" rev-parse "${F}:src/security/shell.rs")
blob_v=$(gitq -C "$Z" rev-parse "v0.6.2:src/security/shell.rs")
[[ $blob_f == "$blob_v" ]] || fail "5WP8_FIX_BLOB $blob_f $blob_v"
fsubj=$(gitq -C "$Z" log -1 --format='%s' "$F")
[[ $fsubj == *"patch shell blocklist bypass"* ]] || fail "5WP8_FIX_SUBJ $fsubj"
echo "5WP8_OK"

# R5JH ordinal 133
SQ=5a3d68a349b001302b1acb6e838f05283160548d
M=0d851525a35ba517dda7fe892333df5d0919dffc
F=8298e33ea7457702f893eae11077987cf905edb4
P=c4125e170a222a4bf1539a5c4167533e35612588
gitq -C "$FS" cat-file -t "$SQ" >/dev/null
gitq -C "$FS" cat-file -t "$M" >/dev/null
gitq -C "$FS" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$FS" rev-list --parents -n 1 "$SQ")
[[ $parents == "$SQ $P" ]] || fail "R5JH_PARENTS $parents"
gitq -C "$FS" cat-file -p "$SQ" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.7' || fail "R5JH_MARKER"
gitq -C "$FS" grep -q 'strings.HasPrefix(normalizedPath, safedir)' "$P" -- pkg/utils/utils.go || fail "R5JH_PARENT_HASPREFIX"
gitq -C "$FS" grep -q SanitizeFilePath "$P" -- pkg/fetcher/fetcher.go || fail "R5JH_PARENT_FETCHER"
gitq -C "$FS" show "${P}:pkg/builder/builder.go" | LC_ALL=C grep -A25 'func (builder \*Builder) Clean' | LC_ALL=C grep -q SanitizeFilePath && fail "R5JH_PARENT_CLEAN_HAS_SANITIZE" || true
gitq -C "$FS" show "${SQ}:pkg/builder/builder.go" | LC_ALL=C grep -A25 'func (builder \*Builder) Clean' | LC_ALL=C grep -q SanitizeFilePath || fail "R5JH_SQUASH_CLEAN_MISSING"
gitq -C "$FS" merge-base --is-ancestor "$M" "$SQ" && fail "R5JH_MEMBER_ANC_SQUASH" || true
gitq -C "$FS" merge-base --is-ancestor "$M" v1.24.0 && fail "R5JH_MEMBER_IN_VULN" || true
gitq -C "$FS" merge-base --is-ancestor "$SQ" v1.24.0 || fail "R5JH_SQUASH_TAG"
gitq -C "$FS" merge-base --is-ancestor "$F" v1.24.0 && fail "R5JH_FIX_IN_VULN" || true
gitq -C "$FS" merge-base --is-ancestor "$F" v1.25.0 || fail "R5JH_FIX_TAG"
fsubj=$(gitq -C "$FS" log -1 --format='%s' "$F")
[[ $fsubj == *"os.Root"* ]] || fail "R5JH_FIX_SUBJ $fsubj"
peel=$(gitq -C "$FS" rev-parse 'v1.24.0^{commit}')
[[ $peel == ce617120c41b9e4a51d577f81b441238264e88fd ]] || fail "R5JH_PEEL124 $peel"
echo "R5JH_OK"

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

echo "REPLAY_OK reviewed=3 PASS_proposal=1 NARROW=2 REJECT=0 UNKNOWN=0 BLOCKED=0"
