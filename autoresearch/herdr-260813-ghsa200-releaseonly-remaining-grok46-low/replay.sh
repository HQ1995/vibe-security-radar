#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260813-ghsa200-releaseonly-remaining-grok46-low.
# English only. Do not print credentials. Do not fetch, clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Worker PASS is a proposal. This script admits zero PASS and does not admit a 200-case claim.
# Packet status TERMINAL. Expansion stopped. No further candidates.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260813-ghsa200-releaseonly-remaining-grok46-low
FS=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/fission
KT=/home/hanqing/.cache/ghsa200-worker-clones/delta-even-batch2/microsoft__kiota
WA=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/wacrm
PR=/home/hanqing/.cache/ghsa200-worker-clones/baseline-increm-even/clones/prospero-flow-crm
VT=/tmp/fp211-cross-02/clones/vitest

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

require_dir() {
  if [[ ! -d $1 ]]; then
    printf 'missing directory: %s\n' "$1" >&2
    exit 1
  fi
}

expect_hash() {
  local target=$1 expected=$2
  local got
  got=$(/usr/bin/sha256sum "$target" | /usr/bin/awk '{print $1}')
  if [[ $got != "$expected" ]]; then
    printf 'hash mismatch %s\n expected %s\n got      %s\n' "$target" "$expected" "$got" >&2
    exit 1
  fi
}

assert_ancestor() {
  "${git_cmd[@]}" -C "$1" merge-base --is-ancestor "$2" "$3"
}

assert_not_ancestor() {
  if "${git_cmd[@]}" -C "$1" merge-base --is-ancestor "$2" "$3"; then
    printf 'unexpected ancestor: %s is ancestor of %s in %s\n' "$2" "$3" "$1" >&2
    exit 1
  fi
}

assert_blob_is() {
  local repo=$1 spec=$2 expected=$3
  local got
  got=$("${git_cmd[@]}" -C "$repo" rev-parse "$spec")
  if [[ $got != "$expected" ]]; then
    printf 'blob %s expected %s got %s\n' "$spec" "$expected" "$got" >&2
    exit 1
  fi
}

assert_blob_ne() {
  local repo=$1 left=$2 right=$3
  local a b
  a=$("${git_cmd[@]}" -C "$repo" rev-parse "$left")
  b=$("${git_cmd[@]}" -C "$repo" rev-parse "$right")
  if [[ $a == "$b" ]]; then
    printf 'blobs unexpectedly equal: %s == %s (%s)\n' "$left" "$right" "$a" >&2
    exit 1
  fi
}

require_dir "$OWNED"
require_dir "$FS"
require_dir "$KT"
require_dir "$WA"
require_dir "$PR"
require_dir "$VT"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/baseline.json" \
  d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl" \
  1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-nearclosed-upgrades-grok46-high/result.json" \
  32067537d773147e4b0dd700780e4f448e3e7e0602464c95bbcff813b27229ce
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh/result.json" \
  78a101f809e7d65269db834e60211d87404d2faa48b8e3bf6a46693fa7dfd644
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-canonical71/summary.json" \
  b17ab8cf9a490b0a3969309d98ff158bf2a779eab29fa0b27d3727f60104544f

python3 - "$ROOT" "$OWNED" << 'PY'
import hashlib, json, sys
from pathlib import Path
root = Path(sys.argv[1])
owned = Path(sys.argv[2])
res = json.loads((owned / "result.json").read_text())
assert res["status"] == "TERMINAL"
assert res["terminal"] is True
assert res["expansion_stopped"] is True
assert res["causal_admission"] is False
assert res["publication_status"] == "HOLD"
assert res["worker_pass_is_proposal_only"] is True
assert res["english_only"] is True
assert res["pass_proposals"] == []
assert res["verdicts"]["PASS"] == 0
assert res["verdicts"]["NARROW"] == 5
assert res["conservation"]["assigned"] == 5
assert res["conservation"]["reviewed"] == 5
assert res["conservation"]["unreviewed"] == 0
assert res["conservation"]["assigned"] == res["conservation"]["reviewed"] + res["conservation"]["unreviewed"]
cases_path = owned / "cases.jsonl"
got = hashlib.sha256(cases_path.read_bytes()).hexdigest()
assert got == res["artifacts"]["cases.jsonl_sha256"], got
report_got = hashlib.sha256((owned / "report.md").read_bytes()).hexdigest()
assert report_got == res["artifacts"]["report.md_sha256"], report_got
replay_got = hashlib.sha256((owned / "replay.sh").read_bytes()).hexdigest()
assert replay_got == res["artifacts"]["replay.sh_sha256"], replay_got
rows = [json.loads(l) for l in cases_path.read_text().splitlines() if l.strip()]
assert len(rows) == 5
assert len({r["case_id"] for r in rows}) == 5
assert [r["ordinal"] for r in rows] == [132, 136, 152, 155, 157]
gates = ["identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate", "uniqueness_gate"]
narrow_n = 0
for r in rows:
    assert r["language"] == "en"
    assert r["causal_admission"] is False
    assert r["authorship_transfer_from_member_to_carrier"] is False
    assert r["cve_aliases_are_not_counting_units"] is True
    seven = all(r.get(g) == "PASS" for g in gates)
    fg = r.get("failing_gates") or []
    if r["verdict"] == "PASS":
        raise SystemExit("unexpected PASS " + r["case_id"])
    assert not seven, r["case_id"]
    assert fg, r["case_id"]
    assert r["verdict"] == "NARROW"
    narrow_n += 1
assert narrow_n == 5
near = set(json.loads((root / "autoresearch/herdr-260813-ghsa200-nearclosed-upgrades-grok46-high/result.json").read_text())["conservation"]["reviewed_case_ids"])
strict = set(json.loads((root / "autoresearch/orchestrator-260813-ghsa200-canonical71/summary.json").read_text())["strict_released_case_ids"])
b3 = set(res["excluded"]["b3"])
ids = {r["case_id"] for r in rows}
assert not (ids & near), ids & near
assert not (ids & strict), ids & strict
assert not (ids & b3), ids & b3
assert res["excluded"]["nearclosed_overlap_from_pool"] == [
    "GHSA-V396-V7Q4-X2QJ",
    "GHSA-F2FQ-4RMP-9X8C",
    "GHSA-2X93-H3HG-2XFP",
    "GHSA-9C3V-684M-579C",
    "GHSA-WP73-F3GG-W4VR",
]
assert res["excluded"]["strict72_from_pool"] == ["GHSA-XW8C-RRVX-F7XQ", "GHSA-JV46-XFWM-36J7"]
assert res["excluded"]["b3"] == ["GHSA-F38V-77QJ-H4JQ"]
print("conservation assigned=5 reviewed=5 unreviewed=0 PASS=0 NARROW=5")
PY

# ----- NARROW 132 fission: member not tag ancestor; same-first-tag complete fix -----
"${git_cmd[@]}" -C "$FS" log -1 --format='%B' 2db76f65dbfe4f657b4a4efb506ed63b24623e92 | /usr/bin/grep -F 'Co-Authored-By: Claude Opus 4.7' >/dev/null
assert_not_ancestor "$FS" 2db76f65dbfe4f657b4a4efb506ed63b24623e92 v1.24.0
assert_not_ancestor "$FS" 2db76f65dbfe4f657b4a4efb506ed63b24623e92 v1.23.0
assert_ancestor "$FS" e484df8460bb4e8026e24210120602aa7f181f64 v1.24.0
assert_ancestor "$FS" 695d3e97e3a20463ab7c8c081843e69e65e952e5 v1.24.0
assert_blob_is "$FS" 2db76f65dbfe4f657b4a4efb506ed63b24623e92:pkg/apis/core/v1/podspec_safety.go af473d2601a9299a035166c4d4bf67927abc50df
assert_blob_is "$FS" e484df8460bb4e8026e24210120602aa7f181f64:pkg/apis/core/v1/podspec_safety.go 330fccee042945fac9ccfcdb3d62f52036e63b5e
assert_blob_is "$FS" v1.24.0:pkg/apis/core/v1/podspec_safety.go 1d7219e7f592cc6ea631866328820475617141bd
assert_blob_is "$FS" 695d3e97e3a20463ab7c8c081843e69e65e952e5:pkg/apis/core/v1/podspec_safety.go 1d7219e7f592cc6ea631866328820475617141bd
assert_blob_ne "$FS" 2db76f65dbfe4f657b4a4efb506ed63b24623e92:pkg/apis/core/v1/podspec_safety.go e484df8460bb4e8026e24210120602aa7f181f64:pkg/apis/core/v1/podspec_safety.go
assert_blob_ne "$FS" e484df8460bb4e8026e24210120602aa7f181f64:pkg/apis/core/v1/podspec_safety.go v1.24.0:pkg/apis/core/v1/podspec_safety.go
if "${git_cmd[@]}" -C "$FS" cat-file -e v1.23.0:pkg/apis/core/v1/podspec_safety.go 2>/dev/null; then
  printf 'v1.23.0 unexpectedly has podspec_safety.go\n' >&2
  exit 1
fi
if [[ -n $("${git_cmd[@]}" -C "$FS" tag --contains 2db76f65dbfe4f657b4a4efb506ed63b24623e92 --no-contains 695d3e97e3a20463ab7c8c081843e69e65e952e5) ]]; then
  printf 'unexpected fission residual tag\n' >&2
  exit 1
fi
python3 - "$OWNED" << 'PY'
import json, sys
from pathlib import Path
d = json.loads((Path(sys.argv[1]) / "snapshot/pages/ghsa/ghsa-m63v-2g9w-2w6v.json").read_text())
assert d.get("type") == "reviewed"
assert d.get("github_reviewed_at")
assert d["vulnerabilities"][0]["first_patched_version"] == "1.24.0"
print("132 reviewed identity ok")
PY

# ----- NARROW 136 kiota: member not tag ancestor; v1.34.0 already complete -----
"${git_cmd[@]}" -C "$KT" log -1 --format='%B' f51f4971ea3459cd410b363b34e156a116b530f4 | /usr/bin/grep -F 'Co-authored-by: Copilot' >/dev/null
assert_not_ancestor "$KT" f51f4971ea3459cd410b363b34e156a116b530f4 v1.33.0
assert_not_ancestor "$KT" f51f4971ea3459cd410b363b34e156a116b530f4 v1.34.0
assert_ancestor "$KT" de3d18d9fe31ced4ac749728d3a2f94811f59268 v1.34.0
assert_ancestor "$KT" 430008e9d700b3fe80f206c672415cfbd8e830e7 v1.34.0
assert_not_ancestor "$KT" de3d18d9fe31ced4ac749728d3a2f94811f59268 v1.33.0
F=src/Kiota.Builder/OpenApiExtensions/OpenApiAiCapabilitiesExtension.cs
assert_blob_is "$KT" f51f4971ea3459cd410b363b34e156a116b530f4:$F 782a03f5a90908d179e6b2ddc971762ce2818cd3
assert_blob_is "$KT" de3d18d9fe31ced4ac749728d3a2f94811f59268:$F 782a03f5a90908d179e6b2ddc971762ce2818cd3
assert_blob_is "$KT" v1.33.0:$F 1391bf0c317ededff61d42336eb20cc168c584f5
assert_blob_is "$KT" v1.34.0:$F 1b62b65383747873569474fbcf4d2895976ad405
assert_blob_is "$KT" 430008e9d700b3fe80f206c672415cfbd8e830e7:$F 1b62b65383747873569474fbcf4d2895976ad405
assert_blob_ne "$KT" f51f4971ea3459cd410b363b34e156a116b530f4:$F v1.33.0:$F
assert_blob_ne "$KT" de3d18d9fe31ced4ac749728d3a2f94811f59268:$F v1.34.0:$F
if [[ -n $("${git_cmd[@]}" -C "$KT" tag --contains f51f4971ea3459cd410b363b34e156a116b530f4 --no-contains 430008e9d700b3fe80f206c672415cfbd8e830e7) ]]; then
  printf 'unexpected kiota residual tag\n' >&2
  exit 1
fi
python3 - "$OWNED" << 'PY'
import json, sys
from pathlib import Path
d = json.loads((Path(sys.argv[1]) / "snapshot/pages/ghsa/ghsa-p5rm-jg5c-8c77.json").read_text())
assert d.get("type") == "reviewed"
assert d["vulnerabilities"][0]["package"]["name"] == "Microsoft.OpenApi.Kiota"
print("136 reviewed identity ok")
PY

# ----- NARROW 152 wacrm: unreviewed identity; zero tags -----
"${git_cmd[@]}" -C "$WA" log -1 --format='%B' 4afa9bea32cd4538af19cbba45a874dbb614be8d | /usr/bin/grep -F 'Co-Authored-By: Claude Opus 4.7' >/dev/null
if [[ -n $("${git_cmd[@]}" -C "$WA" tag) ]]; then
  printf 'wacrm unexpectedly has tags\n' >&2
  exit 1
fi
python3 - "$OWNED" << 'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
d = json.loads((owned / "snapshot/pages/ghsa/ghsa-x2w7-xr2g-qhjr.json").read_text())
assert d.get("type") == "unreviewed"
assert d.get("vulnerabilities") == []
assert d.get("github_reviewed_at") is None
r = json.loads((owned / "snapshot/pages/repo-advisory/GHSA-X2W7-XR2G-QHJR.json").read_text())
assert str(r.get("status")) == "404"
print("152 unreviewed empty-vulns identity ok")
PY

# ----- NARROW 155 prospero: unreviewed identity; same-first-tag equals fix -----
"${git_cmd[@]}" -C "$PR" log -1 --format='%B' 56ea64c80fd36840fe3c84d0c6a6a38296a8f111 | /usr/bin/grep -F 'Co-Authored-By: Claude Haiku 4.5' >/dev/null
"${git_cmd[@]}" -C "$PR" log -1 --format='%B' 86f406519fd208f9be09cd7cf32cd24d292779fd | /usr/bin/grep -F 'Co-Authored-By: Claude Haiku 4.5' >/dev/null
assert_not_ancestor "$PR" 56ea64c80fd36840fe3c84d0c6a6a38296a8f111 v4.6.0
assert_ancestor "$PR" 56ea64c80fd36840fe3c84d0c6a6a38296a8f111 v5.5.3
assert_ancestor "$PR" 9a859c4de3d49674916773d346c60d89ad7febe0 v5.5.3
if "${git_cmd[@]}" -C "$PR" cat-file -e v4.6.0:app/Http/Controllers/Api/Order/OrderReadController.php 2>/dev/null; then
  printf 'v4.6.0 unexpectedly has OrderReadController.php\n' >&2
  exit 1
fi
assert_blob_is "$PR" 56ea64c80fd36840fe3c84d0c6a6a38296a8f111:app/Http/Controllers/Api/Order/OrderReadController.php c3082407aceb561ef47dd89c91ccefe31aa80912
assert_blob_is "$PR" v5.5.3:app/Http/Controllers/Api/Order/OrderReadController.php d2e097debc95c4d936afbc94b0a8ecf29885e676
assert_blob_is "$PR" 9a859c4de3d49674916773d346c60d89ad7febe0:app/Http/Controllers/Api/Order/OrderReadController.php d2e097debc95c4d936afbc94b0a8ecf29885e676
assert_blob_ne "$PR" 56ea64c80fd36840fe3c84d0c6a6a38296a8f111:app/Http/Controllers/Api/Order/OrderReadController.php v5.5.3:app/Http/Controllers/Api/Order/OrderReadController.php
if [[ -n $("${git_cmd[@]}" -C "$PR" tag --contains 56ea64c80fd36840fe3c84d0c6a6a38296a8f111 --no-contains 9a859c4de3d49674916773d346c60d89ad7febe0) ]]; then
  printf 'unexpected prospero residual tag\n' >&2
  exit 1
fi
python3 - "$OWNED" << 'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
d = json.loads((owned / "snapshot/pages/ghsa/ghsa-x8qq-m4qc-rpj5.json").read_text())
assert d.get("type") == "unreviewed"
assert d.get("vulnerabilities") == []
r = json.loads((owned / "snapshot/pages/repo-advisory/GHSA-X8QQ-M4QC-RPJ5.json").read_text())
assert str(r.get("status")) == "404"
print("155 unreviewed empty-vulns identity ok")
PY

# ----- NARROW 157 vitest: topology holds; same-first-tag equals fix -----
"${git_cmd[@]}" -C "$VT" log -1 --format='%B' af88b1f5d82844a4761ea9a977156c98e2b14ca8 | /usr/bin/grep -F 'Co-authored-by: Codex' >/dev/null
assert_not_ancestor "$VT" af88b1f5d82844a4761ea9a977156c98e2b14ca8 v3.2.4
assert_not_ancestor "$VT" 385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7 v3.2.4
assert_ancestor "$VT" af88b1f5d82844a4761ea9a977156c98e2b14ca8 v3.2.5
assert_ancestor "$VT" 385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7 v3.2.5
assert_blob_is "$VT" af88b1f5d82844a4761ea9a977156c98e2b14ca8:packages/browser/src/node/rpc.ts 358ac355f89983297c18932c68e5aea7d78020ea
assert_blob_is "$VT" v3.2.4:packages/browser/src/node/rpc.ts 7619c5f0fc4b66ea0992e61e357331c6280e4a29
assert_blob_is "$VT" v3.2.5:packages/browser/src/node/rpc.ts 72818584f0669b58db74b6e093e04173c083293e
assert_blob_is "$VT" 385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7:packages/browser/src/node/rpc.ts 72818584f0669b58db74b6e093e04173c083293e
assert_blob_ne "$VT" af88b1f5d82844a4761ea9a977156c98e2b14ca8:packages/browser/src/node/rpc.ts v3.2.4:packages/browser/src/node/rpc.ts
assert_blob_ne "$VT" af88b1f5d82844a4761ea9a977156c98e2b14ca8:packages/browser/src/node/rpc.ts v3.2.5:packages/browser/src/node/rpc.ts
parent=$("${git_cmd[@]}" -C "$VT" rev-parse 385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7^)
if [[ $parent != af88b1f5d82844a4761ea9a977156c98e2b14ca8 ]]; then
  printf 'fix parent expected candidate, got %s\n' "$parent" >&2
  exit 1
fi
if [[ -n $("${git_cmd[@]}" -C "$VT" tag --contains af88b1f5d82844a4761ea9a977156c98e2b14ca8 --no-contains 385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7) ]]; then
  printf 'unexpected vitest residual tag\n' >&2
  exit 1
fi
python3 - "$OWNED" << 'PY'
import json, sys
from pathlib import Path
d = json.loads((Path(sys.argv[1]) / "snapshot/pages/repo-advisory/GHSA-G8MR-85JM-7XHM.json").read_text())
assert d.get("state") == "published"
assert any(v["package"]["name"] == "@vitest/browser" for v in d["vulnerabilities"])
print("157 reviewed identity ok")
PY

printf 'REPLAY_OK bounded assigned=5 reviewed=5 unreviewed=0 PASS_proposal=0 NARROW=5\n'
