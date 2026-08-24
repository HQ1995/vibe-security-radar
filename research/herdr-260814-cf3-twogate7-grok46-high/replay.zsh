#!/usr/bin/env zsh
set -euo pipefail
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-cf3-twogate7-grok46-high}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
OC=${OC:-/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw}
COND=${COND:-/home/hanqing/.cache/cve-analyzer/repos/conductor-oss_conductor}
CM=${CM:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/claude-mem}
OU=${OU:-/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/ouroboros}
HE=${HE:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/hermes-webui}
fail=0

ascii_check() {
  local f=$1
  if LC_ALL=C grep -n '[^[:print:][:space:]]' "$f" >/dev/null; then
    echo "NON_ASCII $f"
    fail=1
  fi
}

hash_check() {
  local f=$1 want=$2
  local got
  got=$(sha256sum "$f" | awk '{print $1}')
  if [[ $got != $want ]]; then
    echo "HASH_MISMATCH $f got=$got want=$want"
    fail=1
  else
    echo "HASH_OK $(basename "$f")"
  fi
}

fp_has() {
  local repo=$1 sha=$2 tag=$3 n=$4
  local out
  out=$(GIT_OPTIONAL_LOCKS=0 git --no-optional-locks -C "$repo" log --first-parent -n "$n" --format=%H "$tag")
  [[ $'\n'"$out"$'\n' == *$'\n'"$sha"$'\n'* ]]
}

echo "== ASCII =="
for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  ascii_check "$OWNED/$f"
done

echo "== input hashes =="
hash_check "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
hash_check "$ROOT/docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md" \
  70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical87/summary.json" \
  17487d40720f4c20475df7df270e5bb1139726887c42bc50d999f0f7e713a722
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl" \
  0b9cd2daae23e33faf3f2ceed46bba4802e2f9b0ef9c739f0bce7e6f4a16f687
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/8rw6_acceptance.json" \
  8cb85b42f405595b834a4ccae9b782c488b8dfa340900ad5717bb0dac71cfae9

echo "== conservation 7=7+0 =="
python3 - << PY
import json, sys
from pathlib import Path
owned = Path("$OWNED")
ass = [json.loads(l)["case_id"] for l in owned.joinpath("assignment.jsonl").open()]
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open()]
res = json.loads(owned.joinpath("result.json").read_text())
ids = [c["case_id"] for c in cas]
want = [
    "GHSA-5GVR-V6QV-H5MM",
    "GHSA-7X5Q-8F6H-RJRC",
    "GHSA-C4M7-2GWP-VW76",
    "GHSA-G353-MGV3-8PCJ",
    "GHSA-G5CG-8X5W-7JPM",
    "GHSA-MGXW-V6RH-WCV6",
    "GHSA-RQPP-RJJ8-7WV8",
]
ok = True
if ass != ids or ids != want or ids != res["inspected_ids"]:
    print("ID_ORDER_FAIL", ass, ids); ok = False
n_pass = sum(1 for c in cas if c["verdict"] == "PASS_PROPOSAL")
n_rej = sum(1 for c in cas if c["verdict"] == "REJECT")
n_nar = sum(1 for c in cas if c["verdict"] == "NARROW")
n_unk = sum(1 for c in cas if c["verdict"] == "UNKNOWN")
if n_pass != 0 or n_rej != 0 or n_nar != 7 or n_unk != 0 or len(cas) != 7:
    print("COUNT_FAIL", n_pass, n_rej, n_nar, n_unk); ok = False
if res["conservation"]["equation"] != "7=7+0":
    print("EQ_FAIL"); ok = False
if res["pass_proposal_ids"] != [] or res["canonical87_strict_count"] != 87:
    print("FLAG_FAIL"); ok = False
if any(c["verdict"] == "PASS_PROPOSAL" for c in cas):
    print("PROMOTED_PASS"); ok = False
if any("FAIL" in c["gates"].values() for c in cas):
    print("UNEXPECTED_FAIL"); ok = False
if ok:
    print("CONSERVATION_OK 7=7+0 NARROW=7 PASS_PROPOSAL=0")
else:
    sys.exit(1)
PY

echo "== uniqueness vs canonical87 plus pending 8RW6 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical87/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
pending = "GHSA-8RW6-P7M8-63JP"
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open()]
hit = [i for i in ids if i in strict or i == pending]
if hit:
    print("UNIQUENESS_FAIL", hit); sys.exit(1)
acc = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/8rw6_acceptance.json").read_text())
if acc["case_id"].upper() != pending:
    print("PENDING_ID_FAIL"); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "pending", pending)
PY

echo "== seven gates; no PASS_PROPOSAL; no FAIL promoted =="
python3 - << PY
import json, sys
from pathlib import Path
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
okv = ("PASS","FAIL","UNKNOWN","NARROW","BLOCKED")
primary = {
    "GHSA-5GVR-V6QV-H5MM": "topology_gate",
    "GHSA-7X5Q-8F6H-RJRC": "identity_gate",
    "GHSA-C4M7-2GWP-VW76": "topology_gate",
    "GHSA-G353-MGV3-8PCJ": "topology_gate",
    "GHSA-G5CG-8X5W-7JPM": "topology_gate",
    "GHSA-MGXW-V6RH-WCV6": "identity_gate",
    "GHSA-RQPP-RJJ8-7WV8": "topology_gate",
}
with Path("$OWNED/cases.jsonl").open() as f:
    for line in f:
        rec = json.loads(line)
        g = rec["gates"]
        for k in need:
            if g[k] not in okv:
                print("BAD_GATE", rec["case_id"], k, g[k]); sys.exit(1)
        if rec["verdict"] == "PASS_PROPOSAL":
            print("PASS_PROPOSAL_PRESENT", rec["case_id"]); sys.exit(1)
        if "FAIL" in g.values():
            print("PROMOTED_OR_UNEXPECTED_FAIL", rec["case_id"]); sys.exit(1)
        if rec["unresolved_or_failed_gate"] != primary[rec["case_id"]]:
            print("PRIMARY_GATE_FAIL", rec["case_id"]); sys.exit(1)
        if g[rec["unresolved_or_failed_gate"]] == "PASS":
            print("PRIMARY_WAS_PASS", rec["case_id"]); sys.exit(1)
print("GATES_OK")
PY

echo "== git replay (shared clones, no fetch, no durable writes) =="
if [[ ! -d $OC || ! -d $COND || ! -d $CM || ! -d $OU || ! -d $HE ]]; then
  echo CLONE_ABSENT; fail=1
else
  export GIT_OPTIONAL_LOCKS=0
  git --no-optional-locks -C "$CM" cat-file -t 924a11eeca832ddaafc200eb51cff5657354ba4a >/dev/null
  git --no-optional-locks -C "$CM" merge-base --is-ancestor 924a11eeca832ddaafc200eb51cff5657354ba4a v11.0.0 && { echo MEM_IN_V11_FAIL; fail=1; } || echo 5GVR_MEMBER_NOT_ANC_V11_OK
  STORE_C=$(git --no-optional-locks -C "$CM" rev-parse 924a11eeca832ddaafc200eb51cff5657354ba4a:src/services/sqlite/observations/store.ts)
  STORE_T=$(git --no-optional-locks -C "$CM" rev-parse v11.0.0:src/services/sqlite/observations/store.ts)
  if [[ $STORE_C != 20727332fc3b71bc780f83e59e43fbd9f6950017 || $STORE_C != $STORE_T ]]; then echo 5GVR_BLOB_FAIL; fail=1; else echo 5GVR_STORE_BLOB_OK; fi
  nparents=$(git --no-optional-locks -C "$CM" rev-list --parents -n 1 f32fda8b35e9fe9329f87da65c31149362a03f97 | awk '{print NF-1}')
  if [[ $nparents -ne 2 ]]; then echo 5GVR_FIX_NOT_MERGE; fail=1; else echo 5GVR_FIX_MERGE_OK; fi

  git --no-optional-locks -C "$COND" merge-base --is-ancestor 840ec19c1f68f46b1c9c6a68e6bfa0d9481c3434 v3.21.21 || { echo 7X5Q_MEM_NOT_ANY; fail=1; }
  if fp_has "$COND" 840ec19c1f68f46b1c9c6a68e6bfa0d9481c3434 v3.21.21 800; then echo 7X5Q_MEM_FP_FAIL; fail=1; else echo 7X5Q_MEM_NOT_FP_OK; fi
  if fp_has "$COND" d874e6e551a3354ade452ee5c9b99e3b453ee334 v3.21.21 800; then echo 7X5Q_CARR_FP_OK; else echo 7X5Q_CARR_FP_FAIL; fail=1; fi
  git --no-optional-locks -C "$COND" merge-base --is-ancestor c691e35e768caeb802c9f06ecdd9674c80081af1 v3.30.1 && { echo 7X5Q_FIX2_IN_3301; fail=1; } || echo 7X5Q_FIX2_NOT_IN_3301_OK
  git --no-optional-locks -C "$COND" merge-base --is-ancestor c691e35e768caeb802c9f06ecdd9674c80081af1 v3.30.2 || { echo 7X5Q_FIX2_NOT_3302; fail=1; }

  git --no-optional-locks -C "$OU" merge-base --is-ancestor d30b61759b8efe4554978438abbcc5a9d698d055 v0.38.2 && { echo C4M7_MEM_IN_382; fail=1; } || echo C4M7_MEMBER_NOT_ANC_382_OK
  AD_C=$(git --no-optional-locks -C "$OU" rev-parse d30b61759b8efe4554978438abbcc5a9d698d055:src/ouroboros/providers/claude_code_adapter.py)
  AD_T=$(git --no-optional-locks -C "$OU" rev-parse v0.38.2:src/ouroboros/providers/claude_code_adapter.py)
  if [[ $AD_C == $AD_T ]]; then echo C4M7_BLOB_EQUAL_FAIL; fail=1; else echo C4M7_ADAPTER_BLOBS_UNEQUAL_OK; fi
  git --no-optional-locks -C "$OU" merge-base --is-ancestor 4e70b760b4eb157469b58645339ba831f6513d37 v0.39.0 || { echo C4M7_FIX_NOT_390; fail=1; }

  git --no-optional-locks -C "$OC" merge-base --is-ancestor b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517 v2026.2.12 && { echo G353_MEM_IN_212; fail=1; } || echo G353_MEMBER_NOT_ANC_212_OK
  MON_C=$(git --no-optional-locks -C "$OC" rev-parse b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517:extensions/feishu/src/monitor.ts)
  MON_T=$(git --no-optional-locks -C "$OC" rev-parse v2026.2.12:extensions/feishu/src/monitor.ts)
  if [[ $MON_C != 31a890c2f92da2586c0c1f96c1d47a71100be610 || $MON_C != $MON_T ]]; then echo G353_MON_BLOB_FAIL; fail=1; else echo G353_MONITOR_BLOB_OK; fi
  git --no-optional-locks -C "$OC" merge-base --is-ancestor 7844bc89a1612800810617c823eb0c76ef945804 v2026.3.11 && { echo G353_FIX_IN_311; fail=1; } || echo G353_FIX_NOT_IN_311_OK
  git --no-optional-locks -C "$OC" merge-base --is-ancestor 7844bc89a1612800810617c823eb0c76ef945804 v2026.3.12 || { echo G353_FIX_NOT_312; fail=1; }

  git --no-optional-locks -C "$OC" merge-base --is-ancestor 01d568c9f54585d2df3002e1090067c9dd621e43 v2026.3.28 && { echo G5CG_MEM_IN_328; fail=1; } || echo G5CG_MEMBER_NOT_ANC_328_OK
  HB_C=$(git --no-optional-locks -C "$OC" rev-parse 01d568c9f54585d2df3002e1090067c9dd621e43:src/infra/heartbeat-runner.ts)
  HB_T=$(git --no-optional-locks -C "$OC" rev-parse v2026.3.28:src/infra/heartbeat-runner.ts)
  if [[ $HB_C == $HB_T ]]; then echo G5CG_HB_EQUAL_FAIL; fail=1; else echo G5CG_HB_BLOBS_UNEQUAL_OK; fi
  git --no-optional-locks -C "$OC" merge-base --is-ancestor a30214a624946fc5c85c9558a27c1580172374fd v2026.3.31 || { echo G5CG_FIX_NOT_331; fail=1; }
  if git --no-optional-locks -C "$OC" cat-file -p 01d568c9f54585d2df3002e1090067c9dd621e43 | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5'; then
    echo G5CG_MARKER_OK
  else
    echo G5CG_MARKER_FAIL; fail=1
  fi

  git --no-optional-locks -C "$HE" merge-base --is-ancestor d2b27f6f1edb83634730f93dc8f19721d877bd07 v0.51.268 || { echo MGXW_MEM_NOT_ANY; fail=1; }
  if fp_has "$HE" d2b27f6f1edb83634730f93dc8f19721d877bd07 v0.51.268 400; then echo MGXW_MEM_FP_FAIL; fail=1; else echo MGXW_MEM_NOT_FP_OK; fi
  RT_C=$(git --no-optional-locks -C "$HE" rev-parse d2b27f6f1edb83634730f93dc8f19721d877bd07:api/routes.py)
  RT_T=$(git --no-optional-locks -C "$HE" rev-parse v0.51.268:api/routes.py)
  if [[ $RT_C == $RT_T ]]; then echo MGXW_ROUTES_EQUAL_FAIL; fail=1; else echo MGXW_ROUTES_UNEQUAL_OK; fi
  git --no-optional-locks -C "$HE" merge-base --is-ancestor 8d8ae89d27a4547b2edc388a986ef0d55549f7d4 v0.51.269 && { echo MGXW_FIX_IN_269; fail=1; } || echo MGXW_FIX_NOT_ANC_269_OK
  PEEL=$(git --no-optional-locks -C "$HE" rev-parse "v0.51.269^{commit}")
  if [[ $PEEL != 2c7b530071bb29ae4184e83e33be5799d529568e ]]; then echo MGXW_PEEL_FAIL; fail=1; else echo MGXW_PEEL_OK; fi

  git --no-optional-locks -C "$OC" merge-base --is-ancestor 079af0d0b02ca2c722f90b6c4e38e27ba16227b4 v2026.3.11 || { echo RQPP_MEM_NOT_ANY; fail=1; }
  if fp_has "$OC" 079af0d0b02ca2c722f90b6c4e38e27ba16227b4 v2026.3.11 4000; then echo RQPP_MEM_FP_FAIL; fail=1; else echo RQPP_MEM_NOT_FP_OK; fi
  WH_C=$(git --no-optional-locks -C "$OC" rev-parse 079af0d0b02ca2c722f90b6c4e38e27ba16227b4:src/gateway/server/ws-connection/message-handler.ts)
  WH_T=$(git --no-optional-locks -C "$OC" rev-parse v2026.3.11:src/gateway/server/ws-connection/message-handler.ts)
  if [[ $WH_C == $WH_T ]]; then echo RQPP_BLOB_EQUAL_FAIL; fail=1; else echo RQPP_HANDLER_UNEQUAL_OK; fi
  git --no-optional-locks -C "$OC" merge-base --is-ancestor 5e389d5e7c9233ec91026ab2fea299ebaf3249f6 v2026.3.12 || { echo RQPP_FIX_NOT_312; fail=1; }
  if git --no-optional-locks -C "$OC" cat-file -p 079af0d0b02ca2c722f90b6c4e38e27ba16227b4 | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5'; then
    echo RQPP_MARKER_OK
  else
    echo RQPP_MARKER_FAIL; fail=1
  fi
fi

if [[ $fail -ne 0 ]]; then
  echo REPLAY_FAIL
  exit 1
fi
echo REPLAY_OK
