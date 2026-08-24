#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260813-ghsa200-reintroduction-grok46-xhigh.
# English only. Do not print credentials. Do not fetch, clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Worker PASS is a proposal. This script admits zero PASS and does not admit a 200-case claim.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260813-ghsa200-reintroduction-grok46-xhigh
ADB=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database
HU=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/kerberosmansour__hulumi
ECHO=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/labstack__echo
OW=/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/open-webui__open-webui
IC=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/ironclaw
PM=/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/facelessuser__pymdown-extensions
HA=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/hapifhir__org.hl7.fhir.core

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

require_dir() {
  if [[ ! -d $1 ]]; then
    printf 'missing directory: %s\n' "$1" >&2
    exit 1
  fi
}

require_file() {
  if [[ ! -f $1 ]]; then
    printf 'missing file: %s\n' "$1" >&2
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
require_dir "$ADB"
require_dir "$HU"
require_dir "$ECHO"
require_dir "$OW"
require_dir "$IC"
require_dir "$PM"
require_dir "$HA"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/work/freeze.json"
require_file "$OWNED/work/dispositions.json"
require_file "$OWNED/work/leftover_fetches.json"

# Frozen input hashes (explicit current vs frozen).
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/baseline.json" d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" 0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl" 1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-final-candidate-review-codex/result.json" 4be2620a548370c845e22c0d7cbe3ed10ab156ef39b1a0432ff4220ff406e528
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-proposal-census-grok46-low/result.json" 457a723120c2b6809c27859f99b67f4356df5ed0692e9b2b946e67ad5eaeaedb
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh/result.json" c50b878583f3b09f37d7c88638ea179e75cf6b0ccf2e4ade689f2d673f7b0829
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh/result.json" 78a101f809e7d65269db834e60211d87404d2faa48b8e3bf6a46693fa7dfd644
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-actual-gogs-redteam-grok46-high/result.json" bf3676928fb61809f425e0b369b010d79018a890852e8d6310d13912a6d83b9d
expect_hash "$OWNED/work/freeze.json" f7cb96a39a44bb94eec3640a4759b13b9f87bef5ee785727e39b2cdea2109e34
expect_hash "$OWNED/cases.jsonl" 6242d0daafe51a0031f2720cf90d077121b13baa70402cda695c61731235e288
expect_hash "$OWNED/report.md" 04bf426a82a55fe002081b88c2181d518d073b803e3ac62b2b440ad85b0a900b
expect_hash "$OWNED/work/dispositions.json" a2b9e1dc1c4fe3b36a9b7866b630551d0c798257d217c59bdecb1017f50b9117
expect_hash "$OWNED/work/leftover_fetches.json" 78231382e3111645895b629a966a76f894d0cd9c52656f1dbc1c1aaca63db4b0

adb_head=$("${git_cmd[@]}" -C "$ADB" rev-parse HEAD)
if [[ $adb_head != a42c436870111aa3f221257c9d56126a93173ccc ]]; then
  printf 'advisory-database HEAD expected a42c436870111aa3f221257c9d56126a93173ccc got %s\n' "$adb_head" >&2
  exit 1
fi

# Conservation, uniqueness, zero PASS, English-only JSON, excluded-set disjoint.
python3 - "$OWNED" << 'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
rows = [json.loads(line) for line in (owned / "cases.jsonl").read_text().splitlines() if line.strip()]
assert len(rows) == 30, len(rows)
ids = [r["case_id"] for r in rows]
assert len(ids) == len(set(ids)), "duplicate GHSA identity"
assert all(r.get("language") == "en" for r in rows)
assert all(r.get("verdict") != "PASS" for r in rows)
assert all(r.get("countable_proposal") is False for r in rows)
assert all(r.get("causal_admission") is False for r in rows)
assert sum(1 for r in rows if r["verdict"] == "NARROW") == 4
assert sum(1 for r in rows if r["verdict"] == "REJECT") == 26
assert {r["case_id"] for r in rows if r["verdict"] == "NARROW"} == {
    "GHSA-7X5Q-8F6H-RJRC",
    "GHSA-CW23-QWR7-C655",
    "GHSA-P8RR-9CVG-CX5J",
    "GHSA-2MXR-P26X-MJ73",
}
freeze = json.loads((owned / "work/freeze.json").read_text())
excluded = set(freeze["strict_73"]) | set(freeze["pending_discovery_proposals_excluded"])
overlap = set(ids) & excluded
assert not overlap, overlap
result = json.loads((owned / "result.json").read_text())
cons = result["conservation"]
assert cons["assigned"] == 30
assert cons["reviewed"] == 30
assert cons["unreviewed"] == 0
assert cons["assigned"] == cons["reviewed"] + cons["unreviewed"]
assert cons["holds"] is True
assert result["verdicts"]["PASS"] == 0
assert result["worker_pass_is_proposal_only"] is True
assert result["publication_status"] == "HOLD"
assert result["causal_admission"] is False
assert result.get("terminal") is True
assert result.get("no_further_candidates") is True
assert result.get("terminal_status") == "TERMINAL"
disp = json.loads((owned / "work/dispositions.json").read_text())
assert disp["terminal"] is True
assert disp["no_further_candidates"] is True
assert disp["PASS"] == 0
assert [d["case_id"] for d in disp["rows"]] == [r["case_id"] for r in rows]
assert [d["verdict"] for d in disp["rows"]] == [r["verdict"] for r in rows]
leftover = json.loads((owned / "work/leftover_fetches.json").read_text())
leftover_ids = {x["case_id"] for x in leftover["not_assigned"]}
assert leftover_ids.isdisjoint(set(ids))
assert all(x["deep_reviewed"] is False and x["inferred_reject"] is False for x in leftover["not_assigned"])
blob = (owned / "cases.jsonl").read_bytes() + (owned / "report.md").read_bytes()
assert all(b < 128 for b in blob), "non-ASCII in cases.jsonl or report.md"
print("conservation assigned=30 reviewed=30 unreviewed=0 PASS=0 ok")
PY

# ----- NARROW GHSA-2MXR hulumi: AI opt-out never ships without the closer -----
CAND=0d5c4d2e3bea25a853c882a41271b9e53136f543
FIX=070da5d314249e9fd930ab1f766bf6f6793ff4c9
V132=53e9bafaa3a7cabde60685453874caa27b65bfa3
V140=f5f95fd2626c0ce0f0100445e79e602ae05d1d4f
"${git_cmd[@]}" -C "$HU" log -1 --format='%B' "$CAND" | /usr/bin/grep -F 'Co-authored-by: Claude Opus 4.7' >/dev/null
pc=$("${git_cmd[@]}" -C "$HU" rev-list --parents -n 1 "$CAND" | /usr/bin/awk '{print NF-1}')
if [[ $pc != 1 ]]; then
  printf 'hulumi candidate parent_count expected 1 got %s\n' "$pc" >&2
  exit 1
fi
assert_not_ancestor "$HU" "$CAND" "$V132"
assert_not_ancestor "$HU" "$FIX" "$V132"
assert_ancestor "$HU" "$CAND" "$V140"
assert_ancestor "$HU" "$FIX" "$V140"
assert_blob_is "$HU" "$CAND^:packages/baseline/src/aws/secure-bucket.ts" 6a4f528f1817127cbedb49fc6b8be893daa94840
assert_blob_is "$HU" "$CAND:packages/baseline/src/aws/secure-bucket.ts" a521a021f281569db35087c95886df71fd235c73
assert_blob_is "$HU" "$FIX:packages/baseline/src/aws/secure-bucket.ts" 5723e68adf1cd3a1a7d2653a9bee4fc440ec2c65
assert_blob_ne "$HU" "$CAND^:packages/baseline/src/aws/secure-bucket.ts" "$CAND:packages/baseline/src/aws/secure-bucket.ts"
assert_blob_ne "$HU" "$CAND:packages/baseline/src/aws/secure-bucket.ts" "$FIX:packages/baseline/src/aws/secure-bucket.ts"
"${git_cmd[@]}" -C "$HU" grep -F 'objectLockEnabled: true' "$CAND^" -- packages/baseline/src/aws/secure-bucket.ts >/dev/null
"${git_cmd[@]}" -C "$HU" grep -F 'objectLock: false' "$CAND" -- packages/baseline/src/aws/account-foundation.ts >/dev/null
"${git_cmd[@]}" -C "$HU" grep -F 'objectLock: false' "$FIX" -- packages/baseline/src/aws/account-foundation.ts >/dev/null
python3 - "$OWNED" << 'PY'
from pathlib import Path
import sys
text = (Path(sys.argv[1]) / "work/notes/hulumi-npm.txt").read_text()
assert "1.3.2 time 2026-05-15T20:37:13.837Z" in text
assert "1.4.0 time 2026-05-20T12:28:16.912Z" in text
assert "baseline-1.3.2.tgz" in text
assert "baseline-1.4.0.tgz" in text
print("hulumi npm dual-release notes ok")
PY

# ----- REJECT GHSA-PGVM echo: parent already path.Clean; no AI on v5 change -----
F071=f071367e3c6d3b5cf624e8d91167215bfae1a538
M6C=6c162596b43157c8a4d6c7d88a7db9f45be95ef2
MERGE=b1d443086ea27cf51345ec72a71e9b7e9d9ce5f1
"${git_cmd[@]}" -C "$ECHO" grep -F 'path.Clean' "$F071^" -- middleware/static.go >/dev/null
"${git_cmd[@]}" -C "$ECHO" grep -F 'path.Clean' "$F071" -- middleware/static.go >/dev/null
assert_ancestor "$ECHO" "$M6C" "$MERGE"
if "${git_cmd[@]}" -C "$ECHO" log -1 --format='%B' "$F071" | /usr/bin/grep -E -i 'co-authored-by:|generated with'; then
  printf 'echo f071367 unexpectedly has an AI trailer\n' >&2
  exit 1
fi
if "${git_cmd[@]}" -C "$ECHO" log -1 --format='%B' "$M6C" | /usr/bin/grep -E -i 'co-authored-by:|generated with'; then
  printf 'echo 6c16259 unexpectedly has an AI trailer\n' >&2
  exit 1
fi

# ----- REJECT GHSA-HCWP open-webui: v0.8.0 sanitizes; human f962bae98 drops it -----
F962=f962bae98306ea9264967b78b803397f4821f9b0
FIXOW=3746339cfc224f85953297da04c4a44ba0dfa58e
assert_blob_is "$OW" v0.8.0:src/lib/components/common/FileItemModal.svelte e34c904585809ad9c490b6e46bf9fb3ce3ce3c3b
assert_blob_is "$OW" v0.8.12:src/lib/components/common/FileItemModal.svelte ea161a5c289ff9336459deb4d23db4f8ce847871
assert_blob_is "$OW" v0.9.3:src/lib/components/common/FileItemModal.svelte 470bb6b52ef8220097a3001fc2852b94a1cca985
assert_blob_ne "$OW" v0.8.0:src/lib/components/common/FileItemModal.svelte v0.8.12:src/lib/components/common/FileItemModal.svelte
assert_ancestor "$OW" "$F962" v0.8.12
assert_not_ancestor "$OW" "$FIXOW" v0.9.2
assert_ancestor "$OW" "$FIXOW" v0.9.3
"${git_cmd[@]}" -C "$OW" grep -F 'excelHtml = DOMPurify.sanitize' v0.8.0 -- src/lib/components/common/FileItemModal.svelte >/dev/null
"${git_cmd[@]}" -C "$OW" grep -F 'excelHtml = result.html' v0.8.12 -- src/lib/components/common/FileItemModal.svelte >/dev/null
"${git_cmd[@]}" -C "$OW" grep -F 'excelHtml = DOMPurify.sanitize(result.html)' v0.9.3 -- src/lib/components/common/FileItemModal.svelte >/dev/null
if "${git_cmd[@]}" -C "$OW" log -1 --format='%B' "$F962" | /usr/bin/grep -E -i 'co-authored-by:|generated with'; then
  printf 'open-webui f962bae98 unexpectedly has an AI trailer\n' >&2
  exit 1
fi

# ----- NARROW GHSA-CW23: unreviewed identity; member not tag ancestor -----
assert_not_ancestor "$IC" b20880c12837df41d7f49de6a33ebe4562b27c5b ironclaw-v0.29.1
python3 - "$OWNED" << 'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
for name, expected_type in (
    ("GHSA-7x5q-8f6h-rjrc.json", "unreviewed"),
    ("GHSA-cw23-qwr7-c655.json", "unreviewed"),
    ("GHSA-p8rr-9cvg-cx5j.json", "unreviewed"),
):
    d = json.loads((owned / "work/pages/global" / name).read_text())
    assert d.get("type") == expected_type, (name, d.get("type"))
    assert d.get("vulnerabilities") in ([], None) or d.get("vulnerabilities") == []
    assert d.get("github_reviewed_at") is None
    assert d.get("repository_advisory_url") in (None, "")
print("unreviewed identity trio ok")
PY

# ----- REJECT GHSA-62Q4 pymdown: 2023 human -----
"${git_cmd[@]}" -C "$PM" log -1 --format='%cI %an' 7c13bda5b7793b172efd1abb6712e156a83fe07d | /usr/bin/grep -F '2023-05-15' >/dev/null
if "${git_cmd[@]}" -C "$PM" log -1 --format='%B' 7c13bda5b7793b172efd1abb6712e156a83fe07d | /usr/bin/grep -E -i 'co-authored-by:|generated with'; then
  printf 'pymdown 7c13bda5 unexpectedly has an AI trailer\n' >&2
  exit 1
fi

# ----- REJECT GHSA-FGV2 hapi: human host-equality removal -----
"${git_cmd[@]}" -C "$HA" log -1 --format='%an' 3871cc69c0516628c19adf824e5e7b0a0531511b | /usr/bin/grep -F 'dotasek' >/dev/null
if "${git_cmd[@]}" -C "$HA" log -1 --format='%B' 3871cc69c0516628c19adf824e5e7b0a0531511b | /usr/bin/grep -E -i 'co-authored-by:|generated with'; then
  printf 'hapi 3871cc69 unexpectedly has an AI trailer\n' >&2
  exit 1
fi

# ----- REJECT GHSA-M8MH / GHSA-MW35: human authors from fetched commit objects -----
python3 - "$OWNED" << 'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
apk = json.loads((owned / "work/notes/apktool-e10a.json").read_text())
assert apk["sha"] == "e10a0450c7afcd9462c0b76bcbff0e7428b92bdd"
assert apk["author"]["name"] == "Igor Eisberg"
assert "Co-authored-by" not in apk["message"]
assert "Generated with" not in apk["message"]
ray = json.loads((owned / "work/notes/ray-f6d21.json").read_text())
assert ray["sha"] == "f6d21db1a48f0ff4bdafc48fff986ed999434668"
assert ray["author"] == "Srinath Krishnamachari"
assert "Co-authored-by" not in ray["message"]
assert "Generated with" not in ray["message"]
print("apktool/ray human origin objects ok")
PY

printf 'REPLAY_OK bounded assigned=30 reviewed=30 unreviewed=0 PASS_proposal=0 NARROW=4 REJECT=26\n'
