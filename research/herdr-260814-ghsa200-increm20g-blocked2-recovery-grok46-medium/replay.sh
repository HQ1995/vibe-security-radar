#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-increm20g-blocked2-recovery-grok46-medium.
# English only. Do not print credentials. Do not clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# PASS is a proposal only. This script does not admit any row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-increm20g-blocked2-recovery-grok46-medium
CACHE=/home/hanqing/.cache/ghsa200-worker-clones/recovery20g-260814
ARGO=$CACHE/argoproj__argo-events
ASH=$CACHE/team-alembic__ash_authentication
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database

ARGO_FIX=18412293a699f559848b00e6e459c9ce2de0d3e2
ARGO_PARENT=3c913b571e686148ac96bea5779b6a887d907d01
ARGO_CP=061b403011991f01a978cd35d84cb723794fa581
ARGO_CP_PARENT=066aaffb0829edf1516cd1974a2710d60ed0925a
ARGO_195=7fc4271d91d0d1e693a722822907e6463699ba3d
ARGO_196=80f5951150be80996b63f7d84d092812d5ea73a3
ARGO_T=pkg/apis/events/v1alpha1/template.go
ARGO_R=pkg/reconciler/eventsource/resource.go
ARGO_T_PARENT=b772e6119971b925d676712df44130a73a827263
ARGO_T_FIX=70acab571c7c52ac4e5e69bff871644ca17b86e4
ARGO_R_PARENT=decc44ebcc711be0450656a53be9dbd996fc7551
ARGO_R_FIX=5e7a487fbf822918e9dc10de364e28314d4c9e4a

ASH_FIX=99ea38977fd4f421d2aaae0c2fb29f8e5f8f707d
ASH_PARENT=c425a4b898adbc850529daca656e8d259766c75a
ASH_464=f6d4a264d64bfff9902771aa456bd821284eae8f
ASH_470=d9b0ca8fc1dac3c72d84536dc673f2b495eea1b2
ASH_PLUG=lib/ash_authentication/add_ons/confirmation/plug.ex
ASH_TF=lib/ash_authentication/add_ons/confirmation/transformer.ex
ASH_PLUG_PARENT=7a65b47a64c029495a5dda3b48f7b5375f8b5ed5
ASH_PLUG_FIX=141e590eafb4462edb85ad06afb91707bebf2276
ASH_TF_PARENT=9119e0c68fefc2914e8d88a2dcce267f54c55c2e
ASH_TF_FIX=a76d50cc445034909298b79217ee77aa94322cb9
ASH_CURSOR=5b729e8dc3c0213a13039d98769174f7a87fe9b0
ASH_DOCS=de4932d3d08d685ff4e199c4d8e25f176e395026

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

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

require_dir "$OWNED"
require_dir "$ARGO/.git"
require_dir "$ASH/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/ledger.jsonl" \
  3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20g-grok46-low/cases.jsonl" \
  bc7fc71abf2f624199f195e40137831a0f00306ce957ccd61048c7f961f226ab
expect_hash "$OWNED/cases.jsonl" \
  9dac9177c0c7773f3b464ad4c45b38cfb1ee952706e24d77c8742f126a6c89b9
expect_hash "$OWNED/report.md" \
  9464a56537ce3e6904affa4ac64aa4755543bc8fc3baff30ff55a4fbd999a894
expect_hash "$OWNED/work/pages/advisory/GHSA-hmp7-x699-cvhq.json" \
  309da007d703579f15edc93944010966dad54b947b2a5a65e8da8e131dbf8f52
expect_hash "$OWNED/work/pages/advisory/GHSA-3988-q8q7-p787.json" \
  b3fcf22e0219bc5efd8e8a267b3c82e3240abe43c8fdbfa411dbea08dad630e9
expect_hash "$OWNED/work/pages/ghsa/GHSA-hmp7-x699-cvhq.json" \
  c1e8738361cd813e5fa8e2a1b7461bea19d73eeaf6ae7d678ac5cd59df557d7f
expect_hash "$OWNED/work/pages/ghsa/GHSA-3988-q8q7-p787.json" \
  4f9f52109f36604cb3a121b9d269c1196dae649d8806b9dcd10ceea5227a29f0

[[ "$("${git_cmd[@]}" -C "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]

SRC20G_CASES=$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20g-grok46-low/cases.jsonl
python3 - "$OWNED" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  "$SRC20G_CASES" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 2, len(rows)
want = ["GHSA-HMP7-X699-CVHQ", "GHSA-3988-Q8Q7-P787"]
assert [r["case_id"] for r in rows] == want
src = [json.loads(l) for l in Path(sys.argv[3]).read_text().splitlines() if l.strip()]
src_ids = [r["case_id"] for r in src if r["case_id"] in set(want)]
assert src_ids == want
assert all(r.get("worker_verdict") == "BLOCKED" for r in src if r["case_id"] in set(want))
assert all(r["worker_verdict"] == "REJECT" for r in rows)
assert all(r["worker_verdict"] != "PASS" for r in rows)
assert all(r["worker_verdict"] != "BLOCKED" for r in rows)
for r in rows:
    assert r["causal_admission"] is False
    assert r["countable"] is False
    assert r["publication_status"] == "HOLD"
    assert r["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    assert r["identity_gate"] == "PASS" and r["gates"]["identity_gate"] == "PASS"
    assert r["uniqueness_gate"] == "PASS" and r["gates"]["uniqueness_gate"] == "PASS"
    assert r["ai_hunk_gate"] == "FAIL"
    assert r["remediation_patch_delta"] == "FAIL"
    causal = ["ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate"]
    for g in causal:
        assert r[g] == "FAIL" and r["gates"][g] == "FAIL"
        assert r[g] != "BLOCKED"
han = re.compile(r"[\u3400-\u9fff]")
for name in ("cases.jsonl", "report.md", "replay.sh"):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert not han.search(text), name
    text.encode("ascii")
c81 = json.loads(Path(sys.argv[2]).read_text())
cids = {x.upper() for x in c81["strict_released_case_ids"]}
assert len(c81["strict_released_case_ids"]) == 81
for i in want:
    assert i not in cids
g1 = json.loads((owned / "work/pages/ghsa/GHSA-hmp7-x699-cvhq.json").read_text())
assert g1["ghsa_id"] == "GHSA-hmp7-x699-cvhq"
assert g1["withdrawn_at"] is None
assert g1["source_code_location"] == "https://github.com/argoproj/argo-events"
assert g1["cve_id"] == "CVE-2025-32445"
g2 = json.loads((owned / "work/pages/ghsa/GHSA-3988-q8q7-p787.json").read_text())
assert g2["ghsa_id"] == "GHSA-3988-q8q7-p787"
assert g2["withdrawn_at"] is None
assert g2["source_code_location"] == "https://github.com/team-alembic/ash_authentication"
assert g2["cve_id"] == "CVE-2025-32782"
print("conservation assigned=2 reviewed=2 unreviewed=0 PASS_proposal=0 NARROW=0 REJECT=2 UNKNOWN=0 BLOCKED=0")
PY

# argo-events
"${git_cmd[@]}" -C "$ARGO" cat-file -e "$ARGO_FIX^{commit}"
got_aparent=$("${git_cmd[@]}" -C "$ARGO" rev-parse "${ARGO_FIX}^")
[[ $got_aparent == "$ARGO_PARENT" ]]
aauthor=$("${git_cmd[@]}" -C "$ARGO" log -1 --format='%an' "$ARGO_FIX")
[[ $aauthor == 'Derek Wang' ]]
asubj=$("${git_cmd[@]}" -C "$ARGO" log -1 --format='%s' "$ARGO_FIX")
[[ $asubj == 'fix: disable the capability of attaching any properties to the container (#3528)' ]]
abody=$("${git_cmd[@]}" -C "$ARGO" log -1 --format='%B' "$ARGO_FIX")
if printf '%s\n' "$abody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'argo closer unexpectedly has AI marker\n' >&2
  exit 1
fi
cauthor=$("${git_cmd[@]}" -C "$ARGO" log -1 --format='%an' "$ARGO_CP")
[[ $cauthor == 'Derek Wang' ]]
csubj=$("${git_cmd[@]}" -C "$ARGO" log -1 --format='%s' "$ARGO_CP")
[[ $csubj == 'fix: disable the capability of attaching any properties to the container (#3528)' ]]
got_cpparent=$("${git_cmd[@]}" -C "$ARGO" rev-parse "${ARGO_CP}^")
[[ $got_cpparent == "$ARGO_CP_PARENT" ]]
peel195=$("${git_cmd[@]}" -C "$ARGO" rev-parse 'v1.9.5^{commit}')
peel196=$("${git_cmd[@]}" -C "$ARGO" rev-parse 'v1.9.6^{commit}')
[[ $peel195 == "$ARGO_195" ]]
[[ $peel196 == "$ARGO_196" ]]
assert_ancestor "$ARGO" "$ARGO_CP" "v1.9.6"
assert_not_ancestor "$ARGO" "$ARGO_CP" "v1.9.5"
assert_not_ancestor "$ARGO" "$ARGO_FIX" "v1.9.6"
assert_ancestor "$ARGO" "$ARGO_FIX" "HEAD"
atblob_p=$("${git_cmd[@]}" -C "$ARGO" rev-parse "${ARGO_FIX}^:${ARGO_T}")
atblob_f=$("${git_cmd[@]}" -C "$ARGO" rev-parse "${ARGO_FIX}:${ARGO_T}")
atblob_195=$("${git_cmd[@]}" -C "$ARGO" rev-parse "v1.9.5:${ARGO_T}")
atblob_196=$("${git_cmd[@]}" -C "$ARGO" rev-parse "v1.9.6:${ARGO_T}")
atblob_cp=$("${git_cmd[@]}" -C "$ARGO" rev-parse "${ARGO_CP}:${ARGO_T}")
[[ $atblob_p == "$ARGO_T_PARENT" ]]
[[ $atblob_f == "$ARGO_T_FIX" ]]
[[ $atblob_195 == "$ARGO_T_PARENT" ]]
[[ $atblob_196 == "$ARGO_T_FIX" ]]
[[ $atblob_cp == "$ARGO_T_FIX" ]]
arblob_195=$("${git_cmd[@]}" -C "$ARGO" rev-parse "v1.9.5:${ARGO_R}")
arblob_196=$("${git_cmd[@]}" -C "$ARGO" rev-parse "v1.9.6:${ARGO_R}")
[[ $arblob_195 == "$ARGO_R_PARENT" ]]
[[ $arblob_196 == "$ARGO_R_FIX" ]]
aparent_src=$("${git_cmd[@]}" -C "$ARGO" show "${ARGO_FIX}^:${ARGO_R}")
printf '%s\n' "$aparent_src" | grep -F 'mergo.Merge(&eventSourceContainer' >/dev/null
afix_src=$("${git_cmd[@]}" -C "$ARGO" show "${ARGO_FIX}:${ARGO_T}")
printf '%s\n' "$afix_src" | grep -F 'func (c *Container) ApplyToContainer' >/dev/null

# ash_authentication
"${git_cmd[@]}" -C "$ASH" cat-file -e "$ASH_FIX^{commit}"
got_sparent=$("${git_cmd[@]}" -C "$ASH" rev-parse "${ASH_FIX}^")
[[ $got_sparent == "$ASH_PARENT" ]]
sauthor=$("${git_cmd[@]}" -C "$ASH" log -1 --format='%an' "$ASH_FIX")
[[ $sauthor == 'Zach Daniel' ]]
ssubj=$("${git_cmd[@]}" -C "$ASH" log -1 --format='%s' "$ASH_FIX")
[[ $ssubj == 'improvement: mitigate medium-sev security issue for confirmation emails (#968)' ]]
sbody=$("${git_cmd[@]}" -C "$ASH" log -1 --format='%B' "$ASH_FIX")
if printf '%s\n' "$sbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'ash closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel464=$("${git_cmd[@]}" -C "$ASH" rev-parse 'v4.6.4^{commit}')
peel470=$("${git_cmd[@]}" -C "$ASH" rev-parse 'v4.7.0^{commit}')
[[ $peel464 == "$ASH_464" ]]
[[ $peel470 == "$ASH_470" ]]
assert_ancestor "$ASH" "$ASH_FIX" "v4.7.0"
assert_not_ancestor "$ASH" "$ASH_FIX" "v4.6.4"
assert_not_ancestor "$ASH" "$ASH_CURSOR" "v4.7.0"
assert_not_ancestor "$ASH" "$ASH_DOCS" "v4.7.0"
spblob_p=$("${git_cmd[@]}" -C "$ASH" rev-parse "${ASH_FIX}^:${ASH_PLUG}")
spblob_f=$("${git_cmd[@]}" -C "$ASH" rev-parse "${ASH_FIX}:${ASH_PLUG}")
spblob_464=$("${git_cmd[@]}" -C "$ASH" rev-parse "v4.6.4:${ASH_PLUG}")
spblob_470=$("${git_cmd[@]}" -C "$ASH" rev-parse "v4.7.0:${ASH_PLUG}")
[[ $spblob_p == "$ASH_PLUG_PARENT" ]]
[[ $spblob_f == "$ASH_PLUG_FIX" ]]
[[ $spblob_464 == "$ASH_PLUG_PARENT" ]]
[[ $spblob_470 == "$ASH_PLUG_FIX" ]]
stblob_p=$("${git_cmd[@]}" -C "$ASH" rev-parse "${ASH_FIX}^:${ASH_TF}")
stblob_f=$("${git_cmd[@]}" -C "$ASH" rev-parse "${ASH_FIX}:${ASH_TF}")
stblob_464=$("${git_cmd[@]}" -C "$ASH" rev-parse "v4.6.4:${ASH_TF}")
stblob_470=$("${git_cmd[@]}" -C "$ASH" rev-parse "v4.7.0:${ASH_TF}")
[[ $stblob_p == "$ASH_TF_PARENT" ]]
[[ $stblob_f == "$ASH_TF_FIX" ]]
[[ $stblob_464 == "$ASH_TF_PARENT" ]]
[[ $stblob_470 == "$ASH_TF_FIX" ]]
sfix_src=$("${git_cmd[@]}" -C "$ASH" show "${ASH_FIX}:${ASH_TF}")
printf '%s\n' "$sfix_src" | grep -F 'require_interaction?' >/dev/null
sparent_src=$("${git_cmd[@]}" -C "$ASH" show "${ASH_FIX}^:${ASH_TF}")
if printf '%s\n' "$sparent_src" | grep -F 'require_interaction?' >/dev/null; then
  printf 'ash parent unexpectedly has require_interaction?\n' >&2
  exit 1
fi

python3 - "$ARGO" "$ASH" << 'PY'
import re, subprocess, sys

argo, ash = sys.argv[1], sys.argv[2]
pat = re.compile(
    r"Co-authored-by:.*(Claude|Cursor|Copilot|GPT|OpenAI|Gemini|Codex|Anthropic)|"
    r"Generated with Claude|Generated with Copilot|noreply@anthropic|chatgpt|claude\.ai|"
    r"Made-with: Cursor",
    re.I,
)
git = ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]
out = subprocess.check_output(git + ["-C", argo, "log", "--all", "--format=%H%x1f%an%x1f%s%x1f%b%x1e"], text=True)
hits = []
for rec in out.split("\x1e"):
    if pat.search(rec):
        hits.append(rec.split("\x1f", 1)[0][:40])
assert hits == [], ("argo", hits[:5])
out = subprocess.check_output(git + ["-C", ash, "log", "v4.7.0", "--format=%H%x1f%an%x1f%s%x1f%b%x1e"], text=True)
hits = []
for rec in out.split("\x1e"):
    if pat.search(rec):
        hits.append(rec.split("\x1f", 1)[0][:40])
assert hits == [], ("ash-v4.7.0", hits[:5])
print("ai_trailer_scan_empty_on_relevant_history")
PY

printf 'REPLAY_OK reviewed=2 PASS_proposal=0 NARROW=0 REJECT=2 UNKNOWN=0 BLOCKED=0\n'
