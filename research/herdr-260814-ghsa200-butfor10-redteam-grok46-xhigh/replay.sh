#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-butfor10-redteam-grok46-xhigh.
# English only. Do not print credentials. Do not clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# All ten rows are NARROW. This script does not admit any row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-butfor10-redteam-grok46-xhigh
HERMES=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/hermes-webui
SHARP=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/sharpcompress
TITRA=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/titra
DYNA=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/dynatrace-mcp
OPEN=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/openclaw
FISS=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/fission

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

require_dir "$OWNED"
require_dir "$HERMES/.git"
require_dir "$SHARP/.git"
require_dir "$TITRA/.git"
require_dir "$DYNA/.git"
require_dir "$OPEN/.git"
require_dir "$FISS/.git"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/baseline.json" \
  d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl" \
  1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json" \
  699f6160b6ecb9c9ce2cdae257c9a12dbdf4f7ef8a925196fcfd4fcf0b1140d8
expect_hash "$ROOT/scripts/publication_adjudications.json" \
  9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f
expect_hash "$OWNED/cases.jsonl" \
  13014d335b9b6a56e7691e26f1fafdf20484a95cda047ab66e7e922543c95df7
expect_hash "$OWNED/report.md" \
  5b5e1dd3748245b84819d1e6c436abe5c98b4afa2631e7baff24c1d007fb9911
expect_hash "$OWNED/pages/ghsa/GHSA-5wqv-fhmr-pjgh.json" \
  4d9bfae34b5f6e2ff8487192d94e1ddc029ad5297c82be0b704eadca4b06e8cd
expect_hash "$OWNED/pages/ghsa/GHSA-6c8g-7p36-r338.json" \
  5e28f2f1ff755d645788c760fa6f9f9c5b57e7993278f09dd3a94ab9f5105402
expect_hash "$OWNED/pages/ghsa/GHSA-7jx6-764p-fgg9.json" \
  2218b50c8a811e2f609d256cc18fa9a5c1ecabca78a58f10ea7977e8a8392684
expect_hash "$OWNED/pages/ghsa/GHSA-pqgx-6wg3-gmvr.json" \
  2218b50c8a811e2f609d256cc18fa9a5c1ecabca78a58f10ea7977e8a8392684
expect_hash "$OWNED/pages/repo-advisory/nesquena__hermes-webui__GHSA-5wqv-fhmr-pjgh.json" \
  790eded25807b4eba5072a42f10b85b0dfc1712aaadb2e4b4fb39d0e3026223f
expect_hash "$OWNED/pages/repo-advisory/adamhathcock__sharpcompress__GHSA-6c8g-7p36-r338.json" \
  0068218d7082270b1b98654c67711c0c5b6bb323509207df457246b54147a019
expect_hash "$OWNED/pages/repo-advisory/kromitgmbh__titra__GHSA-pqgx-6wg3-gmvr.json" \
  14e43955de48d1f3730c5cd9658a3975e0e3508912dd2b5509588f2bb5aa5143
expect_hash "$OWNED/pages/repo-advisory/openclaw__openclaw__GHSA-7jx6-764p-fgg9.json" \
  cff87da200bdc6eb32cd7881483bde231a14e0d5fbb9f1cf689573bf423c9e33
expect_hash "$OWNED/pages/npm/_dynatrace-oss_dynatrace-mcp-server_1.2.0.json" \
  670fe6ca2226ce36cd18dea71bae2cc875a05a0e67f76448bbbb50b54d016514
expect_hash "$OWNED/pages/npm/_dynatrace-oss_dynatrace-mcp-server_2.1.1.json" \
  3ed85121098666e53d88dab641920f56e88acb91c86586844a039bca0995e9ae
expect_hash "$OWNED/pages/npm/openclaw_2026.3.8.json" \
  57b9273d775b1d0a16fa4dc49a905edf1b1b5b8b1d69b7478d0d765f025f630c
expect_hash "$OWNED/pages/npm/openclaw_2026.3.31.json" \
  74715c0266e1d20851e63aac36e19f186a58ee1ae01b190ea083c4b6f051fab6
expect_hash "$OWNED/pages/npm/openclaw_2026.1.20.json" \
  da8638471fd1ffddbbbd4c4f6fc3c335bc8e7d3be03264e3c6ed17356c69260f

python3 - "$OWNED/cases.jsonl" "$ROOT/autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json" "$OWNED" << 'PY'
import json, re, sys
from pathlib import Path

assigned = [
    "GHSA-5WQV-FHMR-PJGH",
    "GHSA-6C8G-7P36-R338",
    "GHSA-PQGX-6WG3-GMVR",
    "GHSA-XMXX-7P24-H892",
    "GHSA-PQH8-P93P-2RX7",
    "GHSA-H2VW-PH2C-JVWF",
    "GHSA-XQ94-R468-QWGJ",
    "GHSA-W85G-3H6X-4XH2",
    "GHSA-R5JH-Q2MW-GCX4",
    "GHSA-7JX6-764P-FGG9",
]
rows = [json.loads(l) for l in Path(sys.argv[1]).read_text().splitlines() if l.strip()]
assert len(rows) == 10, len(rows)
ids = [r["case_id"] for r in rows]
assert ids == assigned
assert "GHSA-WXHM-2MQ7-7697" not in ids
assert all(r["verdict"] == "NARROW" for r in rows)
assert all(r["causal_admission"] is False for r in rows)
assert all(r["countable"] is False for r in rows)
assert all(r["countable_proposal"] is False for r in rows)
assert all(r["publication_status"] == "HOLD" for r in rows)
assert all(r["but_for_gate"] == "NARROW" for r in rows)
assert rows[0]["identity_gate"] == "NARROW"
assert rows[0]["fix_reversal_gate"] == "NARROW"
assert rows[9]["remediation_patch_delta_gate"] == "NARROW"
assert rows[9]["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
han = re.compile(r"[\u3400-\u9fff]")
owned = Path(sys.argv[3])
for name in ("cases.jsonl", "report.md", "replay.sh"):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert not han.search(text), name
c73 = json.loads(Path(sys.argv[2]).read_text())
cids = set(c73["strict_released_case_ids"])
assert len(cids) == 73
assert "GHSA-WXHM-2MQ7-7697" in cids
assert not any(i in cids for i in assigned)
g5 = json.loads((owned / "pages/ghsa/GHSA-5wqv-fhmr-pjgh.json").read_text())
assert g5.get("type") == "unreviewed"
assert g5.get("vulnerabilities") == []
assert g5.get("source_code_location") == ""
assert g5.get("repository_advisory_url") in (None, "")
r5 = json.loads((owned / "pages/repo-advisory/nesquena__hermes-webui__GHSA-5wqv-fhmr-pjgh.json").read_text())
assert r5.get("message") == "Not Found" or r5.get("status") == "404"
for name in ("GHSA-pqgx-6wg3-gmvr.json", "GHSA-7jx6-764p-fgg9.json"):
    g = json.loads((owned / "pages/ghsa" / name).read_text())
    assert g.get("message") == "Not Found" or g.get("status") == "404"
repo_titra = json.loads((owned / "pages/repo-advisory/kromitgmbh__titra__GHSA-pqgx-6wg3-gmvr.json").read_text())
assert repo_titra.get("state") == "published"
assert repo_titra.get("ghsa_id", "").lower() == "ghsa-pqgx-6wg3-gmvr"
repo_7 = json.loads((owned / "pages/repo-advisory/openclaw__openclaw__GHSA-7jx6-764p-fgg9.json").read_text())
assert repo_7.get("state") == "published"
assert repo_7.get("ghsa_id", "").lower() == "ghsa-7jx6-764p-fgg9"
npm12 = json.loads((owned / "pages/npm/_dynatrace-oss_dynatrace-mcp-server_1.2.0.json").read_text())
npm211 = json.loads((owned / "pages/npm/_dynatrace-oss_dynatrace-mcp-server_2.1.1.json").read_text())
assert npm12["name"] == "@dynatrace-oss/dynatrace-mcp-server"
assert npm12["gitHead"] == "1c192a0427bb348b0843779207f556052d6c28e7"
assert npm211["gitHead"] == "9a5f6f86d186f1168645e24673c73bc56a94dda8"
npm38 = json.loads((owned / "pages/npm/openclaw_2026.3.8.json").read_text())
npm331 = json.loads((owned / "pages/npm/openclaw_2026.3.31.json").read_text())
assert npm38.get("gitHead") == "3caab9260cb0a0064e6a37b2de3bedc8a547e599"
assert npm331.get("gitHead") == "213a704b71f4996dc82a583288ee53785215f627"
npm120 = (owned / "pages/npm/openclaw_2026.1.20.json").read_text()
assert "version not found" in npm120
reviewed, unreviewed = 10, 0
assigned_n = 10
assert assigned_n == reviewed + unreviewed
print("conservation assigned=10 reviewed=10 unreviewed=0 KEEP_proposal=0 NARROW=10 REJECT=0 UNKNOWN=0 BLOCKED=0")
PY

# ----- GHSA-5WQV-FHMR-PJGH -----
H_AI=ee672df463e285791e4466e6132297e5feb4a1df
H_FIX=2a3baa71b81ca92da8ece8616a09f15894beec71
H_PARENT=465b97a9f5e5b7bd733eaab6fe251d73e815df6e
"${git_cmd[@]}" -C "$HERMES" log -1 --format='%B' "$H_AI" | grep -F 'Co-Authored-By: Claude Sonnet 4.6' >/dev/null
parents=$("${git_cmd[@]}" -C "$HERMES" rev-parse "${H_AI}^@")
printf '%s\n' "$parents" | grep -Fx "$H_PARENT" >/dev/null
"${git_cmd[@]}" -C "$HERMES" grep -F 'def get_state_db_session_messages(sid, *, stitch_continuations: bool = False) -> list:' "$H_PARENT" -- api/models.py >/dev/null
"${git_cmd[@]}" -C "$HERMES" grep -F 'profile=None' "$H_AI" -- api/models.py >/dev/null
assert_ancestor "$HERMES" "$H_AI" v0.51.442
assert_not_ancestor "$HERMES" "$H_FIX" v0.51.442
assert_ancestor "$HERMES" "$H_FIX" v0.51.443
peel442=$("${git_cmd[@]}" -C "$HERMES" rev-parse 'v0.51.442^{commit}')
peel443=$("${git_cmd[@]}" -C "$HERMES" rev-parse 'v0.51.443^{commit}')
[[ $peel442 == 4d90577e25d5537cb07290eca3fb8abff3bab316 ]]
[[ $peel443 == "$H_FIX" ]]

# ----- GHSA-6C8G-7P36-R338 -----
S_AI=8b95e0a76d6b387533175730e2895ccd16772d07
S_FIX=2021a06626d0555a4d69471386e763ca5f5d5dfb
S_PARENT=3f9986c13c973f5e9b8e08da8bfb5e8259044a44
author=$("${git_cmd[@]}" -C "$SHARP" log -1 --format='%an' "$S_AI")
[[ $author == 'copilot-swe-agent[bot]' ]]
parents=$("${git_cmd[@]}" -C "$SHARP" rev-parse "${S_AI}^@")
printf '%s\n' "$parents" | grep -Fx "$S_PARENT" >/dev/null
"${git_cmd[@]}" -C "$SHARP" grep -F 'public static void ExtractToDirectory(' "$S_PARENT" -- src/SharpCompress/Archives/IArchiveExtensions.cs >/dev/null
"${git_cmd[@]}" -C "$SHARP" grep -F 'Path.Combine(destination, entry.Key' "$S_PARENT" -- src/SharpCompress/Archives/IArchiveExtensions.cs >/dev/null
"${git_cmd[@]}" -C "$SHARP" grep -F 'WriteToDirectoryAsync' "$S_AI" -- src/SharpCompress/Archives/IArchiveExtensions.cs >/dev/null
if "${git_cmd[@]}" -C "$SHARP" grep -F 'Path.GetFullPath' "$S_PARENT" -- src/SharpCompress/Archives/IArchiveExtensions.cs >/dev/null; then
  printf 'parent IArchiveExtensions unexpectedly has GetFullPath\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$SHARP" grep -F 'Path.GetFullPath' "$S_FIX" -- src/SharpCompress/Archives/IArchiveExtensions.cs >/dev/null
assert_ancestor "$SHARP" "$S_AI" 0.47.4
assert_not_ancestor "$SHARP" "$S_FIX" 0.47.4
assert_ancestor "$SHARP" "$S_FIX" 0.48.0
peel474=$("${git_cmd[@]}" -C "$SHARP" rev-parse '0.47.4^{commit}')
peel480=$("${git_cmd[@]}" -C "$SHARP" rev-parse '0.48.0^{commit}')
[[ $peel474 == 5758b08236b275b926bc2c3d97604a96d21546c0 ]]
[[ $peel480 == 6e59c7d7bbf8c19a8a92c3c382599906684bb93d ]]

# ----- GHSA-PQGX-6WG3-GMVR -----
T_MEMBER=40331e610075e7c9a076873cc5b3655362d136db
T_CARRIER=67c7b7663219c9e28fce487b1803706b333c2a4f
T_FIX=2e2ac5cbeed47a76720b21c7fde0214a242e065e
T_PRE=62fe0533d792ca72794af098cd6b1d3301514ff7
author=$("${git_cmd[@]}" -C "$TITRA" log -1 --format='%an' "$T_CARRIER")
[[ $author == Copilot ]]
parents=$("${git_cmd[@]}" -C "$TITRA" rev-parse "${T_CARRIER}^@")
printf '%s\n' "$parents" | grep -Fx "$T_PRE" >/dev/null
assert_not_ancestor "$TITRA" "$T_MEMBER" "$T_CARRIER"
"${git_cmd[@]}" -C "$TITRA" grep -F "from 'vm2'" "$T_PRE" -- imports/api/timecards/server/methods.js >/dev/null
"${git_cmd[@]}" -C "$TITRA" grep -F 'vm.run(await getGlobalSettingAsync' "$T_PRE" -- imports/api/timecards/server/methods.js >/dev/null
"${git_cmd[@]}" -C "$TITRA" grep -F 'vm_sandbox.js' "$T_CARRIER" -- imports/api/timecards/server/methods.js >/dev/null
if "${git_cmd[@]}" -C "$TITRA" grep -F 'validateSandboxCode' "$T_CARRIER" -- imports/utils/vm_sandbox.js >/dev/null; then
  printf 'carrier unexpectedly has validateSandboxCode\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$TITRA" grep -F 'validateSandboxCode' "$T_FIX" -- imports/utils/vm_sandbox.js >/dev/null
blob48=$("${git_cmd[@]}" -C "$TITRA" rev-parse '0.99.48:imports/utils/vm_sandbox.js')
blob_c=$("${git_cmd[@]}" -C "$TITRA" rev-parse "${T_CARRIER}:imports/utils/vm_sandbox.js")
blob49=$("${git_cmd[@]}" -C "$TITRA" rev-parse '0.99.49:imports/utils/vm_sandbox.js')
blob_f=$("${git_cmd[@]}" -C "$TITRA" rev-parse "${T_FIX}:imports/utils/vm_sandbox.js")
[[ $blob48 == a8cef4021e5cec591e3d843477e4b4544b44ee5f ]]
[[ $blob48 == "$blob_c" ]]
[[ $blob49 == 0d5acbdd4c4d6e1b7414ac038dd689623b4c8ad8 ]]
[[ $blob49 == "$blob_f" ]]
assert_ancestor "$TITRA" "$T_CARRIER" 0.99.48
assert_not_ancestor "$TITRA" "$T_MEMBER" 0.99.48
assert_not_ancestor "$TITRA" "$T_FIX" 0.99.48
assert_ancestor "$TITRA" "$T_FIX" 0.99.49

# ----- GHSA-XMXX-7P24-H892 -----
X_AI=f4b03599f0fb9c2f76e8dbe5fde13948d68dbc3f
X_FIX=acd4e0a32f12e1ad85f3130f63b42443ce90f094
X_PARENT=7f6e87e9180b9f236aa88b90936be8f6f7988bc2
"${git_cmd[@]}" -C "$OPEN" log -1 --format='%B' "$X_AI" | grep -F 'Co-Authored-By: Claude Opus 4.5' >/dev/null
parents=$("${git_cmd[@]}" -C "$OPEN" rev-parse "${X_AI}^@")
printf '%s\n' "$parents" | grep -Fx "$X_PARENT" >/dev/null
"${git_cmd[@]}" -C "$OPEN" grep -F 'handleOpenAiHttpRequest' "$X_PARENT" -- src/gateway/server-http.ts >/dev/null
"${git_cmd[@]}" -C "$OPEN" grep -F 'resolvedAuth' "$X_PARENT" -- src/gateway/server-http.ts >/dev/null
if "${git_cmd[@]}" -C "$OPEN" cat-file -e "${X_PARENT}:src/gateway/openresponses-http.ts" 2>/dev/null; then
  printf 'parent unexpectedly has openresponses-http.ts\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$OPEN" grep -F '/v1/responses' "$X_AI" -- src/gateway/openresponses-http.ts >/dev/null
assert_ancestor "$OPEN" "$X_AI" v2026.4.14
assert_not_ancestor "$OPEN" "$X_FIX" v2026.4.14
assert_ancestor "$OPEN" "$X_FIX" v2026.4.15
peel414=$("${git_cmd[@]}" -C "$OPEN" rev-parse 'v2026.4.14^{commit}')
peel415=$("${git_cmd[@]}" -C "$OPEN" rev-parse 'v2026.4.15^{commit}')
[[ $peel414 == 323493fa1b6adc1e10b9954a68d5eaa5a6ef1170 ]]
[[ $peel415 == 041266a6699cac3baef8ef39db41fa26f29f9db3 ]]

# ----- GHSA-PQH8-P93P-2RX7 -----
D_AI=66ff2a7c8bedc23939d6d70ab4c3bdce53673843
D_FIX=15d3546c0618ffbaeaeca477337e08e92f2151bc
D_PARENT=c11191125271e676109e78fef32df4a61bfa4ce6
author=$("${git_cmd[@]}" -C "$DYNA" log -1 --format='%an' "$D_AI")
[[ $author == 'copilot-swe-agent[bot]' ]]
parents=$("${git_cmd[@]}" -C "$DYNA" rev-parse "${D_AI}^@")
printf '%s\n' "$parents" | grep -Fx "$D_PARENT" >/dev/null
"${git_cmd[@]}" -C "$DYNA" grep -F 'now()-${timeframe}' "$D_PARENT" -- src/capabilities/list-problems.ts >/dev/null
"${git_cmd[@]}" -C "$DYNA" grep -F 'now()-${timeframe}' "$D_PARENT" -- src/capabilities/list-exceptions.ts >/dev/null
"${git_cmd[@]}" -C "$DYNA" grep -F 'now()-${timeframe}' "$D_AI" -- src/capabilities/list-vulnerabilities.ts >/dev/null
if "${git_cmd[@]}" -C "$DYNA" grep -F 'validateTimeframe' "$D_AI" -- src/capabilities/list-problems.ts >/dev/null; then
  printf 'AI commit unexpectedly has validateTimeframe\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$DYNA" grep -F 'validateTimeframe' "$D_FIX" -- src/capabilities/list-problems.ts >/dev/null
assert_ancestor "$DYNA" "$D_AI" v1.2.0
assert_not_ancestor "$DYNA" "$D_FIX" v1.2.0
assert_ancestor "$DYNA" "$D_FIX" v2.1.1
peel120=$("${git_cmd[@]}" -C "$DYNA" rev-parse 'v1.2.0^{commit}')
peel211=$("${git_cmd[@]}" -C "$DYNA" rev-parse 'v2.1.1^{commit}')
[[ $peel120 == 1c192a0427bb348b0843779207f556052d6c28e7 ]]
[[ $peel211 == 9a5f6f86d186f1168645e24673c73bc56a94dda8 ]]

# ----- GHSA-H2VW-PH2C-JVWF -----
M_AI=7d7f5d85b4ff0bf9a135ced8022d8860a1979a06
M_FIX=2f06696579a1ab0cb5bbbbb6a900414a6b2e3cd1
M_PARENT=49d962a82f67203994c39cc577b39aa47632fef4
"${git_cmd[@]}" -C "$OPEN" log -1 --format='%B' "$M_AI" | grep -F 'Co-Authored-By: Claude Opus 4.6' >/dev/null
parents=$("${git_cmd[@]}" -C "$OPEN" rev-parse "${M_AI}^@")
printf '%s\n' "$parents" | grep -Fx "$M_PARENT" >/dev/null
"${git_cmd[@]}" -C "$OPEN" grep -F 'MINIMAX_API_HOST' "$M_PARENT" -- src/agents/minimax-vlm.ts >/dev/null
if "${git_cmd[@]}" -C "$OPEN" cat-file -e "${M_PARENT}:extensions/minimax/speech-provider.ts" 2>/dev/null; then
  printf 'parent unexpectedly has speech-provider.ts\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$OPEN" grep -F 'MINIMAX_API_HOST' "$M_AI" -- extensions/minimax/speech-provider.ts >/dev/null
"${git_cmd[@]}" -C "$OPEN" grep -F '"MINIMAX_API_HOST"' "$M_FIX" -- src/infra/dotenv.ts >/dev/null
assert_ancestor "$OPEN" "$M_AI" v2026.4.5
assert_not_ancestor "$OPEN" "$M_FIX" v2026.4.5
assert_ancestor "$OPEN" "$M_FIX" v2026.4.20
peel45=$("${git_cmd[@]}" -C "$OPEN" rev-parse 'v2026.4.5^{commit}')
peel420=$("${git_cmd[@]}" -C "$OPEN" rev-parse 'v2026.4.20^{commit}')
[[ $peel45 == 3e72c0352dde84a0bcb3aabafa99c2d4b12d1c46 ]]
[[ $peel420 == 115f05d5952adeaa8043311c24c4b8a3803481ba ]]

# ----- GHSA-XQ94-R468-QWGJ -----
Q_AI=75602014dbc5088b80e9b236146dfe5fdcc59e20
Q_FIX=121c452d666d4749744dc2089287d0227aae2ed3
Q_PARENT=3cf75f760c0f89adbad9415b3d5fdb5b83f2dd82
"${git_cmd[@]}" -C "$OPEN" log -1 --format='%B' "$Q_AI" | grep -F 'Co-Authored-By: Claude Opus 4.6' >/dev/null
parents=$("${git_cmd[@]}" -C "$OPEN" rev-parse "${Q_AI}^@")
printf '%s\n' "$parents" | grep -Fx "$Q_PARENT" >/dev/null
"${git_cmd[@]}" -C "$OPEN" grep -F 'cdpUrl' "$Q_PARENT" -- src/browser/cdp.ts >/dev/null
"${git_cmd[@]}" -C "$OPEN" grep -F 'isWebSocketUrl' "$Q_AI" -- src/browser/cdp.helpers.ts >/dev/null
assert_ancestor "$OPEN" "$Q_AI" v2026.3.8
assert_not_ancestor "$OPEN" "$Q_FIX" v2026.3.8
assert_ancestor "$OPEN" "$Q_FIX" v2026.4.10
peel38=$("${git_cmd[@]}" -C "$OPEN" rev-parse 'v2026.3.8^{commit}')
peel410=$("${git_cmd[@]}" -C "$OPEN" rev-parse 'v2026.4.10^{commit}')
[[ $peel38 == 3caab9260cb0a0064e6a37b2de3bedc8a547e599 ]]
[[ $peel410 == 44e5b62c27e088128e32e209c146de346c3ea7e6 ]]

# ----- GHSA-W85G-3H6X-4XH2 -----
W_AI=8d74578ceb0c3b913555dff6265821eb0fc09749
W_FIX=0ed4f8a72bb140045962e97ab01c94c076b758a4
W_PARENT=f7123ec30af8c96bb2cb4da198e19bc03312ba16
"${git_cmd[@]}" -C "$OPEN" log -1 --format='%B' "$W_AI" | grep -F 'Co-Authored-By: Claude Opus 4.5' >/dev/null
parents=$("${git_cmd[@]}" -C "$OPEN" rev-parse "${W_AI}^@")
printf '%s\n' "$parents" | grep -Fx "$W_PARENT" >/dev/null
"${git_cmd[@]}" -C "$OPEN" grep -F 'sipsResizeToJpeg' "$W_PARENT" -- src/media/image-ops.ts >/dev/null
if "${git_cmd[@]}" -C "$OPEN" grep -F 'limitInputPixels' "$W_PARENT" -- src/media/image-ops.ts >/dev/null; then
  printf 'parent unexpectedly has limitInputPixels\n' >&2
  exit 1
fi
if "${git_cmd[@]}" -C "$OPEN" cat-file -e "${W_PARENT}:src/agents/pi-embedded-runner/run/images.ts" 2>/dev/null; then
  printf 'parent unexpectedly has images.ts\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$OPEN" cat-file -e "${W_AI}:src/agents/pi-embedded-runner/run/images.ts"
"${git_cmd[@]}" -C "$OPEN" grep -F 'limitInputPixels' "$W_FIX" -- src/media/image-ops.ts >/dev/null
assert_ancestor "$OPEN" "$W_AI" v2026.3.28
assert_not_ancestor "$OPEN" "$W_FIX" v2026.3.28
assert_ancestor "$OPEN" "$W_FIX" v2026.3.31
peel328=$("${git_cmd[@]}" -C "$OPEN" rev-parse 'v2026.3.28^{commit}')
peel331=$("${git_cmd[@]}" -C "$OPEN" rev-parse 'v2026.3.31^{commit}')
[[ $peel328 == f9b1079283a8ee25a7cee77c8f8225d5c813bc30 ]]
[[ $peel331 == 213a704b71f4996dc82a583288ee53785215f627 ]]

# ----- GHSA-R5JH-Q2MW-GCX4 -----
F_MEMBER=0d851525a35ba517dda7fe892333df5d0919dffc
F_CARRIER=5a3d68a349b001302b1acb6e838f05283160548d
F_FIX=8298e33ea7457702f893eae11077987cf905edb4
F_PARENT=c4125e170a222a4bf1539a5c4167533e35612588
"${git_cmd[@]}" -C "$FISS" log -1 --format='%B' "$F_CARRIER" | grep -F 'Co-Authored-By: Claude Opus 4.7' >/dev/null
parents=$("${git_cmd[@]}" -C "$FISS" rev-parse "${F_CARRIER}^@")
printf '%s\n' "$parents" | grep -Fx "$F_PARENT" >/dev/null
assert_not_ancestor "$FISS" "$F_MEMBER" "$F_CARRIER"
"${git_cmd[@]}" -C "$FISS" grep -F 'func SanitizeFilePath' "$F_PARENT" -- pkg/utils/utils.go >/dev/null
"${git_cmd[@]}" -C "$FISS" grep -F 'strings.HasPrefix(normalizedPath, safedir)' "$F_PARENT" -- pkg/utils/utils.go >/dev/null
"${git_cmd[@]}" -C "$FISS" grep -F 'SanitizeFilePath' "$F_PARENT" -- pkg/fetcher/fetcher.go >/dev/null
if "${git_cmd[@]}" -C "$FISS" grep -F 'SanitizeFilePath(filepath.Join(builder.sharedVolumePath, srcPkgFilename)' "$F_PARENT" -- pkg/builder/builder.go >/dev/null; then
  printf 'parent Builder.Clean already sanitizes srcPkgFilename\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$FISS" grep -F 'SanitizeFilePath(filepath.Join(builder.sharedVolumePath, srcPkgFilename)' "$F_CARRIER" -- pkg/builder/builder.go >/dev/null
assert_ancestor "$FISS" "$F_CARRIER" v1.24.0
assert_not_ancestor "$FISS" "$F_MEMBER" v1.24.0
assert_not_ancestor "$FISS" "$F_FIX" v1.24.0
assert_ancestor "$FISS" "$F_FIX" v1.25.0
peel124=$("${git_cmd[@]}" -C "$FISS" rev-parse 'v1.24.0^{commit}')
peel125=$("${git_cmd[@]}" -C "$FISS" rev-parse 'v1.25.0^{commit}')
[[ $peel124 == ce617120c41b9e4a51d577f81b441238264e88fd ]]
[[ $peel125 == ae970aaa9bc76ec93d748bdaf03fd7523b6b6a62 ]]

# ----- GHSA-7JX6-764P-FGG9 -----
J_AI=6e498a1f628873b16aaeeecfbc3dc249b9a1d8bf
J_FIX=08a73dbe4b09e6a15db591649ddec81b48c59584
J_PARENT=2ec1a27c9fba56ac30e4a8b35a89343029be9492
subj=$("${git_cmd[@]}" -C "$OPEN" log -1 --format='%s' "$J_AI")
printf '%s\n' "$subj" | grep -F '[AI]' >/dev/null
parents=$("${git_cmd[@]}" -C "$OPEN" rev-parse "${J_AI}^@")
printf '%s\n' "$parents" | grep -Fx "$J_PARENT" >/dev/null
if "${git_cmd[@]}" -C "$OPEN" grep -F 'authorizeQQBotApprovalAction' "$J_PARENT" -- extensions/qqbot/src/exec-approvals.ts >/dev/null; then
  printf 'parent unexpectedly has authorizeQQBotApprovalAction\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$OPEN" grep -F 'authorizeQQBotApprovalAction' "$J_AI" -- extensions/qqbot/src/exec-approvals.ts >/dev/null
"${git_cmd[@]}" -C "$OPEN" grep -F 'isImplicitSameChatApprovalAuthorization' "$J_FIX" -- extensions/qqbot/src/engine/gateway/interaction-handler.ts >/dev/null
assert_ancestor "$OPEN" "$J_AI" v2026.5.26
assert_not_ancestor "$OPEN" "$J_FIX" v2026.5.26
assert_ancestor "$OPEN" "$J_FIX" v2026.5.27
peel526=$("${git_cmd[@]}" -C "$OPEN" rev-parse 'v2026.5.26^{commit}')
peel527=$("${git_cmd[@]}" -C "$OPEN" rev-parse 'v2026.5.27^{commit}')
[[ $peel526 == 10ad3aa16068baa84a1bd9ac4f7d42ae725cedb7 ]]
[[ $peel527 == 27ae826f65256c7fbd1d78475fca87b674a53e7b ]]

printf 'REPLAY_OK reviewed=10 KEEP_proposal=0 NARROW=10 REJECT=0 UNKNOWN=0 BLOCKED=0\n'
