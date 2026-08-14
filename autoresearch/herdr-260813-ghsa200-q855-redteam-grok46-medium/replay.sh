#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260813-ghsa200-q855-redteam-grok46-medium.
# English only. Do not print credentials. Do not clone, commit, or push.
# Do not use command strings. git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# Red-team KEEP is a proposal. This script does not admit the row.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260813-ghsa200-q855-redteam-grok46-medium
ART=$OWNED/snapshot/artifacts
CLONE=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/homeassistant-ai__ha-mcp
AI=9783f346795be919bffda8a6475ae716a9e3580c
FIX=9f5b085ad4a7b38b067c9da0dc5b45462c4d796e
PARENT=8ba80aee1e942651e34d64a5c501a98d6c49adb6

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
require_dir "$CLONE/.git"
require_dir "$ART"

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
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-canonical72-dedupe-grok46-medium/result.json" \
  fb3b97c7b5d207119cc22d255ba48cbda568d56c8fffb447fb0e58ac8878f4fb
expect_hash "$ROOT/autoresearch/herdr-260813-ghsa200-directroot-mining-grok46-xhigh/cases.jsonl" \
  ff2c0b9e3e148b9ff561d89fb9e2864722068f43d9d3ed1a4c4d42b7b8a2ed22
expect_hash "$ROOT/scripts/publication_adjudications.json" \
  9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f
expect_hash "$OWNED/cases.jsonl" \
  fa6d7dca9993999a9946f54e395138c6cc6dbbc7b03e79abb1efe108ee526856
expect_hash "$OWNED/snapshot/advisory-database/GHSA-q855-8rh5-jfgq.json" \
  fa423727d9fe61f903e744547f85e41dd1020ac79473b8d807c023dbda9a0346
expect_hash "$OWNED/snapshot/pages/ghsa/ghsa-q855-8rh5-jfgq.json" \
  ccdd9cd36c41d84e67a5f5d5fa7d8ce600ecc792326fb6504604e2827c905554
expect_hash "$OWNED/snapshot/pages/repo-advisory/GHSA-Q855-8RH5-JFGQ.json" \
  3087dd71c909c661387cd0e8c1f3dc58e8d395a772d2d0b5c838b56608c70be1
expect_hash "$OWNED/snapshot/pages/releases/v7.5.0.json" \
  329f6fc85edbb6cb8c64fc71559524bf28678b682782bea979c064dd009a8a66
expect_hash "$OWNED/snapshot/pages/releases/v7.6.0.json" \
  fe1dbd1c08fd2be6227b8a1ec659ab0afe3a4597887ea1124561a443fcc693a9
expect_hash "$OWNED/snapshot/pages/releases/v7.7.0.json" \
  e81d2403a33febcf7ec196b5ed895b2cbdcc1c95989c81add29e08ce28ec3aa0
expect_hash "$OWNED/snapshot/pages/releases/v7.10.0.json" \
  dd7f5aad7badf3792257077d0f612c45e7b75c9781789406abfba60feeccdf77
expect_hash "$ART/ha_mcp-7.5.0-py3-none-any.whl" \
  a94521373161d1202907190d64a75716c4d664aa133b00067718f9c9e0700538
expect_hash "$ART/ha_mcp-7.6.0-py3-none-any.whl" \
  4030809080221a96346d97f6052f88eabfea5e2c80ff89aa1539f7f5beb8aadf
expect_hash "$ART/ha_mcp-7.7.0-py3-none-any.whl" \
  7fb6fa548779da9c946afef19919eb75bcd60e1ef9f7cc8f793e4e05576cba89
expect_hash "$ART/ha_mcp-7.10.0-py3-none-any.whl" \
  62c2d3c79f3c8796488a3df6812eac4eda5bef14f0718c1f51a51d330b035332

python3 - "$OWNED/cases.jsonl" "$ROOT/autoresearch/herdr-260813-ghsa200-canonical72-dedupe-grok46-medium/result.json" "$OWNED" << 'PY'
import json, re, sys
from pathlib import Path
rows = [json.loads(l) for l in Path(sys.argv[1]).read_text().splitlines() if l.strip()]
assert len(rows) == 1, len(rows)
r = rows[0]
assert r["case_id"] == "GHSA-Q855-8RH5-JFGQ"
assert r["verdict"] == "KEEP"
assert r["causal_admission"] is False
assert r["countable"] is False
assert r["countable_proposal"] is True
assert r["publication_status"] == "HOLD"
gates = ["identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate", "uniqueness_gate"]
assert all(r.get(g) == "PASS" for g in gates), {g: r.get(g) for g in gates}
assert r.get("failing_gates") == []
han = re.compile(r"[\u3400-\u9fff]")
owned = Path(sys.argv[3])
for name in ("cases.jsonl", "report.md", "replay.sh"):
    text = (owned / name).read_text(encoding="utf-8")
    assert text
    assert not han.search(text), name
c72 = json.loads(Path(sys.argv[2]).read_text())
ids = set(c72["strict_released_case_ids"])
assert len(ids) == 72
assert "GHSA-Q855-8RH5-JFGQ" not in ids
glob = json.loads((owned / "snapshot/pages/ghsa/ghsa-q855-8rh5-jfgq.json").read_text())
assert glob.get("type") == "reviewed"
assert glob.get("withdrawn_at") in (None, "")
assert glob.get("source_code_location") == "https://github.com/homeassistant-ai/ha-mcp"
assert glob["vulnerabilities"][0]["package"]["name"] == "ha-mcp"
assert glob["vulnerabilities"][0].get("first_patched_version") == "7.10.0"
assert glob["vulnerabilities"][0]["vulnerable_version_range"] == "< 7.10.0"
repo = json.loads((owned / "snapshot/pages/repo-advisory/GHSA-Q855-8RH5-JFGQ.json").read_text())
assert repo.get("state") == "published"
assert repo.get("withdrawn_at") in (None, "")
assert repo["vulnerabilities"][0]["vulnerable_version_range"] == "<= 7.6.0"
adb = json.loads((owned / "snapshot/advisory-database/GHSA-q855-8rh5-jfgq.json").read_text())
assert adb["id"] == "GHSA-q855-8rh5-jfgq"
assert adb["database_specific"]["github_reviewed"] is True
assert adb["affected"][0]["package"]["name"] == "ha-mcp"
assert adb["affected"][0]["ranges"][0]["events"][-1]["fixed"] == "7.10.0"
for tag, pre in (("v7.5.0", False), ("v7.6.0", False), ("v7.7.0", False), ("v7.10.0", False)):
    rel = json.loads((owned / f"snapshot/pages/releases/{tag}.json").read_text())
    assert rel.get("prerelease") is pre
    assert rel.get("draft") is False
print("conservation reviewed=1 KEEP_proposal=1 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0")
PY

# ----- AI marker, parent surface, ancestry -----
"${git_cmd[@]}" -C "$CLONE" log -1 --format='%B' "$AI" | grep -F 'Co-authored-by: Claude Opus 4.6' >/dev/null
parents=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${AI}^@")
printf '%s\n' "$parents" | grep -Fx "$PARENT" >/dev/null
if "${git_cmd[@]}" -C "$CLONE" cat-file -e "${AI}^:src/ha_mcp/settings_ui.py" 2>/dev/null; then
  printf 'parent unexpectedly has settings_ui.py\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$CLONE" grep -F 'custom_route("/", methods=["GET"])' "$AI" -- src/ha_mcp/settings_ui.py >/dev/null
if "${git_cmd[@]}" -C "$CLONE" grep -F '_ingress_only' "$AI" -- src/ha_mcp/settings_ui.py >/dev/null; then
  printf 'AI commit unexpectedly has _ingress_only\n' >&2
  exit 1
fi
assert_ancestor "$CLONE" "$AI" v7.5.0
assert_not_ancestor "$CLONE" "$FIX" v7.5.0
assert_not_ancestor "$CLONE" "$FIX" v7.6.0
assert_ancestor "$CLONE" "$FIX" v7.7.0
assert_ancestor "$CLONE" "$FIX" v7.10.0
assert_ancestor "$CLONE" "$AI" "$FIX"

blob_ai=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${AI}:src/ha_mcp/settings_ui.py")
blob_750=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v7.5.0:src/ha_mcp/settings_ui.py')
blob_760=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v7.6.0:src/ha_mcp/settings_ui.py')
blob_fix=$("${git_cmd[@]}" -C "$CLONE" rev-parse "${FIX}:src/ha_mcp/settings_ui.py")
blob_770=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v7.7.0:src/ha_mcp/settings_ui.py')
blob_710=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v7.10.0:src/ha_mcp/settings_ui/__init__.py')
[[ $blob_ai == 7e829d740a564b4ad6eb1f60f7fb1a1ca451d47a ]]
[[ $blob_750 == 46d32362fbed4d0706bf70601cbfbbf2dfc69b08 ]]
[[ $blob_760 == 47286cb4ee15171373b40b843a3354949189464e ]]
[[ $blob_fix == 4275a831b5724cf30a050204e9cfbf98c80d64bd ]]
[[ $blob_770 == 36479aaa873cba5d0cad41d21327f01646c7bb72 ]]
[[ $blob_710 == 905311e7fc89a7637dc1a8c37a5dc37bd2266821 ]]
[[ $blob_ai != "$blob_750" ]]
[[ $blob_fix != "$blob_770" ]]

peel750=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v7.5.0^{commit}')
peel760=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v7.6.0^{commit}')
peel770=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v7.7.0^{commit}')
peel710=$("${git_cmd[@]}" -C "$CLONE" rev-parse 'v7.10.0^{commit}')
[[ $peel750 == d28b7c4513743466e10b441ac0a5d37f46617952 ]]
[[ $peel760 == 59c8d176db0ef12222d66211f55eb0e066379669 ]]
[[ $peel770 == 48100b11ef774efa540752ea509348a58e959694 ]]
[[ $peel710 == 77892222190d966168ff2283993ea816f11ac4f3 ]]

blame750=$("${git_cmd[@]}" -C "$CLONE" blame -l -L968,968 v7.5.0 -- src/ha_mcp/settings_ui.py)
printf '%s\n' "$blame750" | grep -F "$AI" >/dev/null
blame760=$("${git_cmd[@]}" -C "$CLONE" blame -l -L4427,4427 v7.6.0 -- src/ha_mcp/settings_ui.py)
printf '%s\n' "$blame760" | grep -F 6c3c0ac4bd61840a603eb6ee806aed0547154d9c >/dev/null
blame770=$("${git_cmd[@]}" -C "$CLONE" blame -l -L3129,3129 v7.7.0 -- src/ha_mcp/settings_ui.py)
printf '%s\n' "$blame770" | grep -F "$FIX" >/dev/null
blame710=$("${git_cmd[@]}" -C "$CLONE" blame -l -L3313,3313 v7.10.0 -- src/ha_mcp/settings_ui/__init__.py)
printf '%s\n' "$blame710" | grep -F "$FIX" >/dev/null

ingress_hits=($("${git_cmd[@]}" -C "$CLONE" log --reverse --format='%H' -S '_ingress_only' -- src/ha_mcp/settings_ui.py))
[[ ${ingress_hits[1]} == "$FIX" ]]

python3 - "$ART" "$CLONE" << 'PY'
import zipfile, subprocess, sys
from pathlib import Path
art, repo = Path(sys.argv[1]), sys.argv[2]
git = ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-C", repo]

def hob(data: bytes) -> str:
    p = subprocess.run(
        ["/usr/bin/git", "--no-optional-locks", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "hash-object", "--stdin"],
        input=data, capture_output=True, check=True,
    )
    return p.stdout.decode().strip()

def gblob(spec: str) -> str:
    p = subprocess.run(git + ["rev-parse", spec], capture_output=True, text=True, check=True)
    return p.stdout.strip()

def show(spec: str) -> str:
    p = subprocess.run(git + ["show", spec], capture_output=True, check=True)
    return p.stdout.decode()

with zipfile.ZipFile(art / "ha_mcp-7.5.0-py3-none-any.whl") as z:
    b = z.read("ha_mcp/settings_ui.py")
assert hob(b) == gblob("v7.5.0:src/ha_mcp/settings_ui.py")
assert b'_ingress_only' not in b
assert b'/api/settings/tools' in b
assert b'/api/policy/config' not in b
assert b'/api/settings/features' not in b
assert b'custom_route("/", methods=["GET"])(_root_page)' in b

with zipfile.ZipFile(art / "ha_mcp-7.6.0-py3-none-any.whl") as z:
    b = z.read("ha_mcp/settings_ui.py")
assert hob(b) == gblob("v7.6.0:src/ha_mcp/settings_ui.py")
assert b'_ingress_only' not in b
assert b'/api/policy/config' in b
assert b'/api/settings/features' in b
assert b'/api/settings/backups' in b
assert b'custom_route("/", methods=["GET"])(handlers["root_page"])' in b

with zipfile.ZipFile(art / "ha_mcp-7.7.0-py3-none-any.whl") as z:
    b = z.read("ha_mcp/settings_ui.py")
assert hob(b) == gblob("v7.7.0:src/ha_mcp/settings_ui.py")
assert b'SUPERVISOR_INGRESS_IP' in b
assert b'_ingress_only' in b
assert b'_mount("", guard=True)' in b
assert b'/api/settings/tools' in b
assert b'/api/settings/features' in b
assert b'/api/settings/backups' in b
assert b'/api/settings/backup-config' in b
assert b'/api/settings/restart' in b
assert b'/api/policy/config' in b
assert b'/api/policy/approve' in b
assert b'/api/policy/deny' in b
assert b'_ingress_only(handlers["root_page"])' in b
src770 = show("v7.7.0:src/ha_mcp/settings_ui.py")
assert '_mount(secret_prefix)' in src770
assert 'custom_route("/", methods=["GET"])(handlers["root_page"])' not in src770

with zipfile.ZipFile(art / "ha_mcp-7.10.0-py3-none-any.whl") as z:
    b = z.read("ha_mcp/settings_ui/__init__.py")
assert hob(b) == gblob("v7.10.0:src/ha_mcp/settings_ui/__init__.py")
assert b'_ingress_only' in b
assert b'_mount("", guard=True)' in b
assert b'/api/policy/config' in b
print("wheels map; 7.7.0 and 7.10.0 close every named root route")
PY

printf 'REPLAY_OK reviewed=1 KEEP_proposal=1 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0\n'
