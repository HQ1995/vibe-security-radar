#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-increm-blocked4-recovery-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# KEEP is a proposal only. This script does not admit any row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-increm-blocked4-recovery-grok46-xhigh
CACHE=/home/hanqing/.cache/ghsa200-worker-clones/recovery-260814
SPID=$CACHE/italia__spid-aspnetcore
CIE=$CACHE/italia__cie-aspnetcore
FELD=$CACHE/DavidOsipov__PostQuantum-Feldman-VSS
LS3=$CACHE/Robothy__local-s3
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database

SPID_FIX=093efa2273f8a1e0481f678a0bfcd57fbdc7b029
SPID_PARENT=c3fda19a4418ea1a171592f3338f32c1ff835711
SPID_XML=src/SPID.AspNetCore.Authentication/Helpers/XmlHelpers.cs
SPID_BLOB_PARENT=e2de37f60a1a746dabd550b782191f573bf6abed
SPID_BLOB_FIX=1370c1970257583425e2de836f13707eb423f646
SPID_330=d5d8d979cf4140e68362c3d8d47f947b335b926f
SPID_340=a5cf16d3f823db2e80ff96e98cb62b7fee44dc7f

CIE_FIX=e66b7f336ff5d4c69f95f197f27f3145f2484994
CIE_PARENT=920e382a29d7dd77db32f3e2a34092ff362247eb
CIE_XML=CIE.AspNetCore.Authentication/CIE.AspNetCore.Authentication/Helpers/XmlHelpers.cs
CIE_BLOB_PARENT=de31f0439f50e5e496d418213576c541fe41af68
CIE_BLOB_FIX=8827100b6953f4e5311523e416cfc070d5d5ed7f
CIE_204=4bc32a4cfcb78063935f70c2c2bc3cf965163f5f

FELD_INTRO=12cb6ec1fb33d759aa7116e730f98d179159416e
FELD_080B2=36d6fb742bd3008848bc5b7eb0588dd034f4b07e
FELD_BLOB_080B2=02b42d6e06c9129d4189e2ab232b796fc82f64ec
FELD_BLOB_080B3=3a6b8a891c60c95ed45990ff415f544d2f07d838

LS3_FIX=d6ed756ceb30c1eb9d4263321ac683d734f8836f
LS3_PARENT=009901882be8b543e85b67c5ec2e9f30d83d62ef
LS3_XML=local-s3-rest/src/main/java/com/robothy/s3/rest/utils/XmlUtils.java
LS3_BLOB_PARENT=67aab78b4c9874e9eb51bf9ad0482acf72dae28a
LS3_BLOB_FIX=e937b98bd33df6593e1ea02c29ea49ba951b5acd
LS3_120=45cb60cec18c16e14e728d801414b484a591a97d
LS3_121=ac5983447db7a1385b81958dc4cb49faa9222a72

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
require_dir "$SPID/.git"
require_dir "$CIE/.git"
require_dir "$FELD/.git"
require_dir "$LS3/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/baseline.json" \
  d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/ledger.jsonl" \
  3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20-grok46-low/cases.jsonl" \
  d6eb7fa00f05edfb4e715fc63392b1435b7a79b96a9520b13f09b8e83ca1cb71
expect_hash "$OWNED/cases.jsonl" \
  ab73cb548acdcd900481cf2aa15cc29bcd8e91a89708e7e32481c9ce5d15759d
expect_hash "$OWNED/report.md" \
  637abb0e85bbb4d42e3dc578ffd05bc310b6101fa215487ef1fe730e380befa6
expect_hash "$OWNED/work/pages/advisory/GHSA-36h8-r92j-w9vw.json" \
  a5b07629bef481e9ad504ce00278153672ad2883881c1a57c9504d5002ec8101
expect_hash "$OWNED/work/pages/advisory/GHSA-vq63-8f72-f486.json" \
  84c1829f779eb4093b0479bf936053c65adffa4a81897f7664875f0ac297769e
expect_hash "$OWNED/work/pages/advisory/GHSA-r8gc-qc2c-c7vh.json" \
  966970be240c7eb823045d3722a5d82e4bfa2adfdca15c51450939a40915501d
expect_hash "$OWNED/work/pages/advisory/GHSA-47qw-ccjm-9c2c.json" \
  284b8999807ffebfd60527ac267f8290ef3bc53a0e75cc8f759641d2fe6a322d
expect_hash "$OWNED/work/pages/ghsa/GHSA-36h8-r92j-w9vw.json" \
  7f202b98be079b51f5a7f644382f14da2a28df2a5215812391199180ac9e3fe2
expect_hash "$OWNED/work/pages/ghsa/GHSA-vq63-8f72-f486.json" \
  c2cb841d3ad707e8c7b3a93c9d5fb0333aa1ea8cb15978fff10c271b65b31879
expect_hash "$OWNED/work/pages/ghsa/GHSA-r8gc-qc2c-c7vh.json" \
  666200bb35a9716d0db29218fef7f16fd3ffb169ec93c38cda217be90394d51d
expect_hash "$OWNED/work/pages/ghsa/GHSA-47qw-ccjm-9c2c.json" \
  4847ce0d2cebb0611e560b7a43b75ea6df16f5f1b91c7e276269e2fa5c5a29a3

[[ "$("${git_cmd[@]}" -C "$ADV" rev-parse HEAD)" == a42c436870111aa3f221257c9d56126a93173ccc ]]

python3 - "$OWNED" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json" \
  "$ROOT/autoresearch/herdr-260814-ghsa200-incomplete-remediation20-grok46-low/cases.jsonl" << 'PY'
import json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 4, len(rows)
want = [
    "GHSA-36H8-R92J-W9VW",
    "GHSA-VQ63-8F72-F486",
    "GHSA-R8GC-QC2C-C7VH",
    "GHSA-47QW-CCJM-9C2C",
]
assert [r["case_id"] for r in rows] == want
src = [json.loads(l) for l in Path(sys.argv[3]).read_text().splitlines() if l.strip()]
src_ids = [r["case_id"] for r in src if r["case_id"] in set(want)]
assert src_ids == want
assert all(r.get("worker_verdict") == "BLOCKED" for r in src if r["case_id"] in set(want))
for r in rows:
    assert r["verdict"] == "REJECT"
    assert r["worker_verdict"] == "REJECT"
    assert r["causal_admission"] is False
    assert r["countable"] is False
    assert r["countable_proposal"] is False
    assert r["publication_status"] == "HOLD"
    assert r["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    assert r["identity_gate"] == "PASS" and r["gates"]["identity_gate"] == "PASS"
    assert r["uniqueness_gate"] == "PASS" and r["gates"]["uniqueness_gate"] == "PASS"
    assert r["ai_hunk_gate"] == "FAIL"
    assert r["remediation_patch_delta"] == "FAIL"
    for g in ("topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate"):
        assert r[g] == "FAIL" and r["gates"][g] == "FAIL"
        assert r[g] != "BLOCKED"
    assert r["verdict"] != "KEEP"
han = re.compile(r"[\u3400-\u9fff]")
for name in ("cases.jsonl", "report.md", "replay.sh"):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert not han.search(text), name
c81 = json.loads(Path(sys.argv[2]).read_text())
cids = {x.upper() for x in c81["strict_released_case_ids"]}
assert len(c81["strict_released_case_ids"]) == 81
for i in want:
    assert i not in cids
adv36 = json.loads((owned / "work/pages/advisory/GHSA-36h8-r92j-w9vw.json").read_text())
assert adv36["id"] == "GHSA-36h8-r92j-w9vw"
assert adv36["affected"][0]["package"]["name"] == "SPID.AspNetCore.Authentication"
g36 = json.loads((owned / "work/pages/ghsa/GHSA-36h8-r92j-w9vw.json").read_text())
assert g36["ghsa_id"] == "GHSA-36h8-r92j-w9vw"
assert g36["withdrawn_at"] is None
assert g36["source_code_location"] == "https://github.com/italia/spid-aspnetcore"
g_v = json.loads((owned / "work/pages/ghsa/GHSA-vq63-8f72-f486.json").read_text())
assert g_v["source_code_location"] == "https://github.com/italia/cie-aspnetcore"
assert g_v["vulnerabilities"][0]["package"]["name"] == "CIE.AspNetCore.Authentication"
g_r = json.loads((owned / "work/pages/ghsa/GHSA-r8gc-qc2c-c7vh.json").read_text())
assert g_r["source_code_location"] == "https://github.com/DavidOsipov/PostQuantum-Feldman-VSS"
assert g_r["vulnerabilities"][0]["first_patched_version"] is None
g_l = json.loads((owned / "work/pages/ghsa/GHSA-47qw-ccjm-9c2c.json").read_text())
assert g_l["source_code_location"] == "https://github.com/Robothy/local-s3"
fp = g_l["vulnerabilities"][0]["first_patched_version"]
if isinstance(fp, dict):
    fp = fp.get("identifier")
assert fp == "1.21"
print("conservation assigned=4 reviewed=4 unreviewed=0 KEEP_proposal=0 NARROW=0 REJECT=4 UNKNOWN=0 BLOCKED=0")
PY

# SPID
"${git_cmd[@]}" -C "$SPID" cat-file -e "$SPID_FIX^{commit}"
"${git_cmd[@]}" -C "$SPID" cat-file -e "$SPID_PARENT^{commit}"
got_parent=$("${git_cmd[@]}" -C "$SPID" rev-parse "${SPID_FIX}^")
[[ $got_parent == "$SPID_PARENT" ]]
nparents=$("${git_cmd[@]}" -C "$SPID" rev-list --parents -n 1 "$SPID_FIX")
[[ $nparents == "$SPID_FIX $SPID_PARENT" ]]
author=$("${git_cmd[@]}" -C "$SPID" log -1 --format='%an' "$SPID_FIX")
[[ $author == 'Daniele Giallonardo' ]]
subj=$("${git_cmd[@]}" -C "$SPID" log -1 --format='%s' "$SPID_FIX")
[[ $subj == 'Fix xml signature verification and update to .net 9.0 (#84)' ]]
body=$("${git_cmd[@]}" -C "$SPID" log -1 --format='%B' "$SPID_FIX")
if printf '%s\n' "$body" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'spid closer unexpectedly has AI marker\n' >&2
  exit 1
fi
printf '%s\n' "$body" | grep -F 'Co-authored-by: Daniele Giallonardo' >/dev/null
peel330=$("${git_cmd[@]}" -C "$SPID" rev-parse '3.3.0^{commit}')
peel340=$("${git_cmd[@]}" -C "$SPID" rev-parse '3.4.0^{commit}')
[[ $peel330 == "$SPID_330" ]]
[[ $peel340 == "$SPID_340" ]]
assert_ancestor "$SPID" "$SPID_FIX" "3.4.0"
assert_not_ancestor "$SPID" "$SPID_FIX" "3.3.0"
blob_p=$("${git_cmd[@]}" -C "$SPID" rev-parse "${SPID_PARENT}:${SPID_XML}")
blob_f=$("${git_cmd[@]}" -C "$SPID" rev-parse "${SPID_FIX}:${SPID_XML}")
blob_330=$("${git_cmd[@]}" -C "$SPID" rev-parse "3.3.0:${SPID_XML}")
blob_340=$("${git_cmd[@]}" -C "$SPID" rev-parse "3.4.0:${SPID_XML}")
[[ $blob_p == "$SPID_BLOB_PARENT" ]]
[[ $blob_f == "$SPID_BLOB_FIX" ]]
[[ $blob_330 == "$SPID_BLOB_PARENT" ]]
[[ $blob_340 == "$SPID_BLOB_FIX" ]]
parent_src=$("${git_cmd[@]}" -C "$SPID" show "${SPID_PARENT}:${SPID_XML}")
printf '%s\n' "$parent_src" | grep -F 'nodeList[0]' >/dev/null
if printf '%s\n' "$parent_src" | grep -F 'VerifyAllSignatures' >/dev/null; then
  printf 'spid parent unexpectedly has VerifyAllSignatures\n' >&2
  exit 1
fi
fix_src=$("${git_cmd[@]}" -C "$SPID" show "${SPID_FIX}:${SPID_XML}")
printf '%s\n' "$fix_src" | grep -F 'VerifyAllSignatures' >/dev/null

# CIE
"${git_cmd[@]}" -C "$CIE" cat-file -e "$CIE_FIX^{commit}"
got_cparent=$("${git_cmd[@]}" -C "$CIE" rev-parse "${CIE_FIX}^")
[[ $got_cparent == "$CIE_PARENT" ]]
cauthor=$("${git_cmd[@]}" -C "$CIE" log -1 --format='%an' "$CIE_FIX")
[[ $cauthor == 'Daniele Giallonardo' ]]
csubj=$("${git_cmd[@]}" -C "$CIE" log -1 --format='%s' "$CIE_FIX")
[[ $csubj == 'Fix xml signature verification and update to .net 9.0 (#19)' ]]
cbody=$("${git_cmd[@]}" -C "$CIE" log -1 --format='%B' "$CIE_FIX")
if printf '%s\n' "$cbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'cie closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel204=$("${git_cmd[@]}" -C "$CIE" rev-parse '2.0.4^{commit}')
peel210=$("${git_cmd[@]}" -C "$CIE" rev-parse '2.1.0^{commit}')
[[ $peel204 == "$CIE_204" ]]
[[ $peel210 == "$CIE_FIX" ]]
assert_ancestor "$CIE" "$CIE_FIX" "2.1.0"
assert_not_ancestor "$CIE" "$CIE_FIX" "2.0.4"
cblob_p=$("${git_cmd[@]}" -C "$CIE" rev-parse "${CIE_PARENT}:${CIE_XML}")
cblob_f=$("${git_cmd[@]}" -C "$CIE" rev-parse "${CIE_FIX}:${CIE_XML}")
cblob_204=$("${git_cmd[@]}" -C "$CIE" rev-parse "2.0.4:${CIE_XML}")
cblob_210=$("${git_cmd[@]}" -C "$CIE" rev-parse "2.1.0:${CIE_XML}")
[[ $cblob_p == "$CIE_BLOB_PARENT" ]]
[[ $cblob_f == "$CIE_BLOB_FIX" ]]
[[ $cblob_204 == "$CIE_BLOB_PARENT" ]]
[[ $cblob_210 == "$CIE_BLOB_FIX" ]]
cparent_src=$("${git_cmd[@]}" -C "$CIE" show "${CIE_PARENT}:${CIE_XML}")
printf '%s\n' "$cparent_src" | grep -F 'nodeList[0]' >/dev/null
cfix_src=$("${git_cmd[@]}" -C "$CIE" show "${CIE_FIX}:${CIE_XML}")
printf '%s\n' "$cfix_src" | grep -F 'VerifyAllSignatures' >/dev/null

# Feldman
"${git_cmd[@]}" -C "$FELD" cat-file -e "$FELD_INTRO^{commit}"
fauthor=$("${git_cmd[@]}" -C "$FELD" log -1 --format='%an' "$FELD_INTRO")
[[ $fauthor == 'DavidOsipov' ]]
fbody=$("${git_cmd[@]}" -C "$FELD" log -1 --format='%B' "$FELD_INTRO")
printf '%s\n' "$fbody" | grep -F 'Signed-off-by: DavidOsipov' >/dev/null
if printf '%s\n' "$fbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'feldman intro unexpectedly has AI marker\n' >&2
  exit 1
fi
peel_b2=$("${git_cmd[@]}" -C "$FELD" rev-parse 'v0.8.0b2^{commit}')
[[ $peel_b2 == "$FELD_080B2" ]]
assert_not_ancestor "$FELD" "$FELD_INTRO" "v0.8.0b2"
assert_not_ancestor "$FELD" "$FELD_INTRO" "v0.8.0b3"
assert_ancestor "$FELD" "$FELD_INTRO" "v0.8.1b1"
fblob_b2=$("${git_cmd[@]}" -C "$FELD" rev-parse 'v0.8.0b2:feldman_vss.py')
fblob_b3=$("${git_cmd[@]}" -C "$FELD" rev-parse 'v0.8.0b3:feldman_vss.py')
[[ $fblob_b2 == "$FELD_BLOB_080B2" ]]
[[ $fblob_b3 == "$FELD_BLOB_080B3" ]]
b2src=$("${git_cmd[@]}" -C "$FELD" show 'v0.8.0b2:feldman_vss.py')
printf '%s\n' "$b2src" | grep -F 'def secure_redundant_execution' >/dev/null
printf '%s\n' "$b2src" | grep -F 'num_executions: int = 5' >/dev/null

# local-s3
"${git_cmd[@]}" -C "$LS3" cat-file -e "$LS3_FIX^{commit}"
got_lparent=$("${git_cmd[@]}" -C "$LS3" rev-parse "${LS3_FIX}^")
[[ $got_lparent == "$LS3_PARENT" ]]
lauthor=$("${git_cmd[@]}" -C "$LS3" log -1 --format='%an' "$LS3_FIX")
[[ $lauthor == 'Luo' ]]
lsubj=$("${git_cmd[@]}" -C "$LS3" log -1 --format='%s' "$LS3_FIX")
[[ $lsubj == 'fix XML External Entity (XXE) Injection (#172)' ]]
lbody=$("${git_cmd[@]}" -C "$LS3" log -1 --format='%B' "$LS3_FIX")
if printf '%s\n' "$lbody" | grep -qiE 'Claude|Copilot|Cursor Agent|noreply@anthropic|Generated with Claude|ChatGPT'; then
  printf 'locals3 closer unexpectedly has AI marker\n' >&2
  exit 1
fi
peel120=$("${git_cmd[@]}" -C "$LS3" rev-parse '1.20^{commit}')
peel121=$("${git_cmd[@]}" -C "$LS3" rev-parse '1.21^{commit}')
[[ $peel120 == "$LS3_120" ]]
[[ $peel121 == "$LS3_121" ]]
assert_ancestor "$LS3" "$LS3_FIX" "1.21"
assert_not_ancestor "$LS3" "$LS3_FIX" "1.20"
lblob_p=$("${git_cmd[@]}" -C "$LS3" rev-parse "${LS3_PARENT}:${LS3_XML}")
lblob_f=$("${git_cmd[@]}" -C "$LS3" rev-parse "${LS3_FIX}:${LS3_XML}")
lblob_120=$("${git_cmd[@]}" -C "$LS3" rev-parse "1.20:${LS3_XML}")
lblob_121=$("${git_cmd[@]}" -C "$LS3" rev-parse "1.21:${LS3_XML}")
[[ $lblob_p == "$LS3_BLOB_PARENT" ]]
[[ $lblob_f == "$LS3_BLOB_FIX" ]]
[[ $lblob_120 == "$LS3_BLOB_PARENT" ]]
[[ $lblob_121 == "$LS3_BLOB_FIX" ]]
lfix_src=$("${git_cmd[@]}" -C "$LS3" show "${LS3_FIX}:${LS3_XML}")
printf '%s\n' "$lfix_src" | grep -F 'XMLInputFactory.SUPPORT_DTD' >/dev/null
lparent_src=$("${git_cmd[@]}" -C "$LS3" show "${LS3_PARENT}:${LS3_XML}")
if printf '%s\n' "$lparent_src" | grep -F 'SUPPORT_DTD' >/dev/null; then
  printf 'locals3 parent unexpectedly disables DTD\n' >&2
  exit 1
fi
namerev=$("${git_cmd[@]}" -C "$LS3" name-rev --tags --name-only "$LS3_FIX")
[[ $namerev == '1.21~3' ]]

python3 - "$SPID" "$CIE" "$FELD" "$LS3" << 'PY'
import re, subprocess, sys

repos = sys.argv[1:]
pat = re.compile(
    r"Co-authored-by:.*(Claude|Cursor|Copilot|GPT|OpenAI|Gemini|Codex|Anthropic)|"
    r"Generated with Claude|Generated with Copilot|noreply@anthropic|chatgpt|claude\.ai",
    re.I,
)
git = ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]
for repo in repos:
    out = subprocess.check_output(git + ["-C", repo, "log", "--all", "--format=%H%x1f%an%x1f%s%x1f%b%x1e"], text=True)
    hits = []
    for rec in out.split("\x1e"):
        if pat.search(rec):
            hits.append(rec.split("\x1f", 1)[0][:40])
    assert hits == [], (repo, hits[:5])
print("ai_trailer_scan_empty")
PY

printf 'REPLAY_OK reviewed=4 KEEP_proposal=0 NARROW=0 REJECT=4 UNKNOWN=0 BLOCKED=0\n'
