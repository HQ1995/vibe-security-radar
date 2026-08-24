#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-fixblame-promisor389-consolidated-grok46-low.
# English only. Do not print credentials. Do not clone, commit, or push.
# Mining exhaustion proof only. PASS proposals 0. Packet delta 0. Canonical 84 unchanged.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
AR=$ROOT/autoresearch
OWNED=$AR/herdr-260814-ghsa200-fixblame-promisor389-consolidated-grok46-low
REMAINDER=$AR/herdr-260814-ghsa200-fixblame-remainder-hits20-grok46-low/work/scan.jsonl

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

require_file "$OWNED/coverage.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/summary.json"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/work/build_coverage.py"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/freeze.json"
require_file "$OWNED/work/blocked.json"
require_file "$OWNED/work/source_pins.json"
require_file "$OWNED/sha256.txt"
require_file "$REMAINDER"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$REMAINDER" \
  da13b7cf8e0c1ccffa182d04c6cd226791cc6641d898fe7f620b36d69b522133
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/work/scan_fixblame.py" \
  0aa4ee042cf25a0af492892fb651f75c02db1352a22d8cc76282bd9b72da15ec
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor30-grok46-low/result.json" \
  0bb3aaa2248a44b168bed3569caee05e07db26b4b731ccfac0b7235d10b6cbf3
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor30-grok46-low/work/scan.jsonl" \
  0f4dd01cd3223b1e5b183234373874a1f72d2f858dc1c224b5bae83893148150
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor30-grok46-low/work/scan-summary.json" \
  0943551d459984f54e8be251d0d1a0ce58f22f80b2b80c1063c8f877ac124755
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor30-grok46-low/work/assigned30.json" \
  06f22572efbd1fe7b446c2f41d4aa83e50ba9e47bc0c3d55da7c921c00083d27
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor31-60-grok46-medium/result.json" \
  9f081e2856441567d347b34641a859926267efa8fd7658143d6d0f22bd469485
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor31-60-grok46-medium/summary.json" \
  37225d78ff4e0920087e8c783b803e10179f2827bee05723e64727c0766ff71f
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor31-60-grok46-medium/work/scan.jsonl" \
  7a4c5e770efa0d5316896d328c026cd40e914cd4225f3df4b3dc083e6f34ec04
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor31-60-grok46-medium/work/scan-summary.json" \
  aec6516b0efe2d8b84c433a37bcb8bc142e471a799e9a10dd40d563ef277e29f
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor31-60-grok46-medium/assignment.json" \
  593a24c9afbfd04dc4a494748b9ec0a8edeb942da373dc31597b7876b716a3a5
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor61-90-grok46-high/result.json" \
  1fb06e13536aa14c0ce8cd67624867ee2e9f30f8a6aaa18dbba47c5206087a6f
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor61-90-grok46-high/summary.json" \
  36fb07732eac2c2523224da9fcbc71fa04cab1f0c1a17178edcdf748ed1c292e
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor61-90-grok46-high/work/scan.jsonl" \
  37d1f392cd9dea4e899ce87e71df5cee8ca8de6b2de30f3f5153ed1203a17cfd
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor61-90-grok46-high/work/scan-summary.json" \
  983fb43c5976b753b0d7ee0765a08b3df83ef3b72627a7d67797c0df17e7d85e
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor61-90-grok46-high/assignment.json" \
  e2da96960ab5f59a8934e26ed7df24265a01e3c0d8fe0d615fd6d70900115e36
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor91-120-grok46-high/result.json" \
  d54d1459ab092a65fd3750f563f2ac350583ab1f1a5acdd2aeb0b5bb69177244
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor91-120-grok46-high/summary.json" \
  10c98cc14b8fd7647e0742396402104add105fefcb1e06e3174710566a0e148c
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor91-120-grok46-high/work/scan.jsonl" \
  9da2af20d465db25cc969e4a63195feee8d715aff9454a3772865d5ff14e8126
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor91-120-grok46-high/work/scan-summary.json" \
  36a264c2bcb7fb5cee3634feed1db4f686e78fae073d6d02b6128a963341e5fa
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor91-120-grok46-high/assignment.json" \
  58585c2e530bc6ad0ee39062bb1999f7832b5735397c1191fcf183d7b074cefc
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor121-150-grok46-low/result.json" \
  3bb952d2d83f0920c6777198cd9c3c9ad6f081ffa04203c226b90e6541dd1df6
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor121-150-grok46-low/summary.json" \
  68ab1e04c965aafad254cd312e5363f99410ebe3837204db4f2f153e07d22a42
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor121-150-grok46-low/work/scan.jsonl" \
  9add8afd167329c698ee1220a3c2842524d72ee3b55d0b37df34b56fe03e19d0
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor121-150-grok46-low/work/scan-summary.json" \
  58fc291f09d88721882d592f7e67bd606dfd4c3f4c5b02af93992088d14fffcf
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor121-150-grok46-low/assignment.json" \
  df2fc54e96e4881606d619171d44c8dc71d61218dcb28c6f8db2098fe73c27fa
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor151-180-grok46-medium/result.json" \
  7abf9c8623d5a70582305dd8b13d46c0eab2226141e7b0535c31a5df8e11267f
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor151-180-grok46-medium/summary.json" \
  470ec092aac7c5ea216c7a381eca1023e2dd06a1232dbdc14b8be0afe2e4e707
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor151-180-grok46-medium/work/scan.jsonl" \
  ec45e1078c06dd46cc0db4c50e735229a3f6835a0192febab6dc49d34d0b57b1
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor151-180-grok46-medium/work/scan-summary.json" \
  0c603b1c49c316eb4f69ceccc8a9d89e3186ebbc13583b143af7cdcdfad0112b
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor151-180-grok46-medium/assignment.json" \
  f0799f8fdfed0206f009e2ddae229be01bda536b74558070da15a94f00a35478
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor181-210-grok46-low/result.json" \
  429906853dab46745dda5f9e8e5a191bf7e11526e261c6ffd866eed598b7cfb2
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor181-210-grok46-low/summary.json" \
  30354c333a938f2c7cd25ddfe284bd376df32d960f5310e4a92f4593ca0e7695
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor181-210-grok46-low/work/scan.jsonl" \
  2a71e921ddd84dd2edec3ce1b297bf2cf9c4d97514a8804e0d97743e476daddf
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor181-210-grok46-low/work/scan-summary.json" \
  3c3e40d4df4abb0ac4581fa9b6a5c3729219832b095f7a93e6bc098cafca9713
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor181-210-grok46-low/assignment.json" \
  76b35a97a32e6c6c7e57dcd817a59d8f407ecb9595c846b541d79364ad3bb836
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor211-240-grok46-high/result.json" \
  ecf226f9fce710f72b35687c3ea475cbc85c86fe0f511d73be6798c1edf1d969
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor211-240-grok46-high/summary.json" \
  53af25d62e245f6b200ac17ea44bf07842d1ce4f1a3aac03bdc38e65f799f368
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor211-240-grok46-high/work/scan.jsonl" \
  c922a6fa218b16185f040ec686888f43f8b8e24f4f9a1400751521d0f0eed17e
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor211-240-grok46-high/work/scan-summary.json" \
  b87f4c6ee7287bfee345b71aa0f5d76bab1e58593a225d2c22df2f72dac43d17
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor211-240-grok46-high/assignment.json" \
  7ef8a1cc55b70f768b3bb84be07f84fefca164411b270bd30b0771892b56ded6
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor241-270-grok46-medium/result.json" \
  f13c0655b7278a3394a5b67f421754415e590ee6b8c2825ec6de364c0e19e550
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor241-270-grok46-medium/summary.json" \
  9ae65afe7a44b5bac8d0b5efc8b051f345540ae8d7b47e3c174d11a1163f1383
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor241-270-grok46-medium/work/scan.jsonl" \
  b8f3f7b9ab75dd8ce5537783a9ad1fd441966724aadc754bc74998da873c5fea
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor241-270-grok46-medium/work/scan-summary.json" \
  bc5d5ea1b6af6ce3f4da7490e4767520730c8f7a0c35b386376070d2420a70dc
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor241-270-grok46-medium/assignment.json" \
  0b29e8b3bae44915cee70d34f4dd40c7a2d9d4637e705d2ea8d1ab8eb910c50b
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor271-300-grok46-low/result.json" \
  ef9d63d53a4fe6f81ab39ea661c6cbe021e7e9d2b5278417a78ce4285aaaf627
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor271-300-grok46-low/summary.json" \
  a7f290f4975c91a76ab2abdfd80e09cbffefce5f3d396ae5dc6e201cebf2e118
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor271-300-grok46-low/work/scan.jsonl" \
  e29ee60da37da2a45d8ea7569416412d5a3b82b7e21fff3390bbee3990f0dcfc
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor271-300-grok46-low/work/scan-summary.json" \
  95d3deaaf7d2c155cefab6a41bdb06b1c15d31fe42b75bc53ca97dd6e5515a5d
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor271-300-grok46-low/assignment.json" \
  c03d95984f7cf61dcd146590b07661a5d7ab66127c36d712b27c5d97e9c8b7af
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor301-330-grok46-high/result.json" \
  a5359f3a2c8487876fa93e78d0c83433e7817eb4006b6087557d83aacaa00be3
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor301-330-grok46-high/summary.json" \
  065651304006d0565d07c1bd47ec3ca0d436d21fffc10fafaa45de4a16bae669
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor301-330-grok46-high/work/scan.jsonl" \
  66772f6bf69881a219ca639a5d5cd7cf95967957d8881b675db872e7161b3ff2
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor301-330-grok46-high/work/scan-summary.json" \
  8c8f12aa43b953c0f8cfbdd016ec226fc1d18544057285ffe0808242e7dd29a9
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor301-330-grok46-high/assignment.json" \
  6330250fe7eceb4730b80611a21a8db3f2979bc56bacfe434ab3fa7852dc3d00
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor331-360-grok46-medium/result.json" \
  64875584217516e2e8e1692b8f1d59f4bcca5b6897d2a7b89311b18d4207710c
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor331-360-grok46-medium/summary.json" \
  874c23bd52c8b6f83d4fd045753756465dfc6fc93317af86aa52994fe0493faf
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor331-360-grok46-medium/work/scan.jsonl" \
  6515242b5b2b768a971fa97438df20721fb2d3394250c194f6ef1deab26a2574
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor331-360-grok46-medium/work/scan-summary.json" \
  0d46952b716b86e7037701db281cbb5c56c2c4f2d97699d81c4def62d06acec7
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor331-360-grok46-medium/assignment.json" \
  93c58e9fe2f47f7b3e82c257ea05eef9c8a51caef0bc82dbb53bd2c4e4a9ce47
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor361-389-grok46-low/result.json" \
  3d76e3d0778a9fe0193117f7e8fee5d5e9a2cff0cb9d45c78262aef35b6d391a
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor361-389-grok46-low/summary.json" \
  61397ae0d1cffff86b9e2cc8e52c769064ce5da1622c9967b8c0f9497cdd85df
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor361-389-grok46-low/work/scan.jsonl" \
  37efdb64641ffedac0ba7cb83936cd3e19408d3f956a0a53402a376d3f36267f
expect_hash "$AR/herdr-260814-ghsa200-fixblame-promisor361-389-grok46-low/work/scan-summary.json" \
  71974e00e0c43572284e44c64361b1c80d11db85302a67bbfecc726333cd6bf5
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-fixblame-promisor361-389-grok46-low/assignment.json" \
  48c42bbfb62089fc8af37837eb6c6d91e4b335542f2d9103a32320b42898e773

before=$(/usr/bin/sha256sum "$OWNED/coverage.jsonl" | /usr/bin/awk '{print $1}')
python3 "$OWNED/work/build_coverage.py" >/dev/null
after=$(/usr/bin/sha256sum "$OWNED/coverage.jsonl" | /usr/bin/awk '{print $1}')
if [[ $before != "$after" ]]; then
  printf 'coverage.jsonl changed on rebuild\n' >&2
  exit 1
fi

expect_hash "$OWNED/coverage.jsonl" 9683973eb9e2563bf2b4285d643b06c9e2635fa584619de9b32eb427e300d724
expect_hash "$OWNED/report.md" bd2c6a744a1ef9fa058c0c4f96b90543138157b7c161992e912b37a9930760c3
expect_hash "$OWNED/result.json" 521f0783757f33519ce974bb30f8a56fcc3add3047a950f0b096e02aed2d728a
expect_hash "$OWNED/summary.json" a84be77a88e51bf355b1ea51c88898d146e4eb88d84b5c24fc61c47a38387d27
expect_hash "$OWNED/selected.jsonl" e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/cases.jsonl" e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/work/build_coverage.py" d8181fe2a22421cb16338de4a696c8bb658847ff40ef8805ba097d7b64de05e1
expect_hash "$OWNED/work/uniqueness.json" 8dc69de79482c2c875e6e00e5af7be4ccc10df1f36f6356c076d73c64b6f2675
expect_hash "$OWNED/work/freeze.json" 025422028f7edd7afb6ed4d7167759be0b2c356894d90e9561fb4e9abc470fb9
expect_hash "$OWNED/work/blocked.json" bd5ecb641641fabd8da1981ea77dbfc13142770e9b53fa10ca515a6a9524b881
expect_hash "$OWNED/work/source_pins.json" b45953c869f371b63d9798d5ba62363273fc1a3732b2c0f62ce18548c4d724a1
expect_hash "$OWNED/work/conservation.json" f2d00f4219c65620407d5a205896d2d3220b919aa4f3b4a72acfbc7cfbce088e
expect_hash "$OWNED/notes/README.md" 940a38e7a7f63f245c0f24f748242ef435645cd6c2c44e114aae332dd314192f
expect_hash "$OWNED/notes/scan/README.md" 979dd16a99c77330b242f2367fb850a76d9aeb756975a40137bdafe40e9455a1
expect_hash "$OWNED/notes/scan/blocked.json" bd5ecb641641fabd8da1981ea77dbfc13142770e9b53fa10ca515a6a9524b881
expect_hash "$OWNED/notes/scan/conservation.json" f2d00f4219c65620407d5a205896d2d3220b919aa4f3b4a72acfbc7cfbce088e

python3 - "$OWNED" "$REMAINDER" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" << 'PY'
import json, re, sys
from pathlib import Path
owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "coverage.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 389
assert [r["raw_position"] for r in rows] == list(range(1, 390))
assert len({r["ghsa_id"] for r in rows}) == 389
assert all(r["selected"] is False and r["hit"] is False and r["causal_reject"] is False for r in rows)
raw = {}
resolved = {}
for r in rows:
    raw[r["raw_status"]] = raw.get(r["raw_status"], 0) + 1
    resolved[r["resolved_class"]] = resolved.get(r["resolved_class"], 0) + 1
assert raw["no_ai_blame_on_deleted_hunks"] == 282
assert raw["no_ai_hit"] == 22
assert raw["no_deleted_hunk"] == 74
assert raw["UNKNOWN"] == 5
assert raw["UNKNOWN_BLOCKED"] == 5
assert raw["blocked_shallow_boundary"] == 1
assert resolved["no_ai_blame_on_deleted_hunks"] == 304
assert resolved["no_deleted_hunk"] == 74
assert resolved["UNKNOWN_BLOCKED"] == 11
assert 304 + 74 + 11 == 389
blocked = [r for r in rows if r["resolved_class"] == "UNKNOWN_BLOCKED"]
ids = [r["ghsa_id"] for r in blocked]
assert ids == [
    "GHSA-RMJ7-2VXQ-3G9F",
    "GHSA-833P-95JQ-929Q",
    "GHSA-Q2M9-6JP9-C6MC",
    "GHSA-F2R5-5M7W-P5CX",
    "GHSA-4X76-22X2-RX8V",
    "GHSA-C27G-Q93R-2CWF",
    "GHSA-R854-JRXH-36QX",
    "GHSA-94G3-G5V7-Q4JG",
    "GHSA-XJ4F-8JJG-VX4Q",
    "GHSA-MP2F-45PM-3CG9",
    "GHSA-W3CP-G2PF-65WH",
]
c27 = next(r for r in blocked if r["ghsa_id"] == "GHSA-C27G-Q93R-2CWF")
assert c27["raw_status"] == "blocked_shallow_boundary"
assert c27["blocked_flag"] is True
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
assert sel == []
res = json.loads((owned / "result.json").read_text())
summary = json.loads((owned / "summary.json").read_text())
assert res["status"] == "TERMINAL"
assert res["counts"]["PASS"] == 0
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["current_leader_accepted_count"] == 84
assert res["mining_exhaustion_proof_only"] is True
assert summary["pass_proposals"] == 0
assert summary["unknown_blocked"] == 11
assert summary["causal_reject_from_heuristic_miss"] is False
c84 = json.loads(Path(sys.argv[3]).read_text())
assert c84["canonical_strict_count"] == 84
assert len(c84["strict_released_case_ids"]) == 84
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(
    r"ghp_" + r"[A-Za-z0-9]{20,}|"
    r"github" + r"_pat_[A-Za-z0-9_]+|"
    r"sk" + r"_live_|"
    r"xox[baprs]-|"
    r"AKIA" + r"[0-9A-Z]{16}|"
    r"BEGIN" + r" PRIVATE"
)
for name in (
    "coverage.jsonl", "report.md", "replay.zsh", "result.json", "summary.json",
    "work/uniqueness.json", "work/freeze.json", "work/blocked.json",
    "work/source_pins.json", "work/conservation.json", "notes/README.md",
    "sha256.txt",
):
    text = (owned / name).read_text(encoding="utf-8")
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    if text:
        assert text.endswith("\n"), name
    for line in text.splitlines():
        assert line == line.rstrip(" \t"), (name, line)
man_names = []
for line in (owned / "sha256.txt").read_text().splitlines():
    if not line.strip():
        continue
    parts = line.split()
    assert len(parts) == 2, line
    man_names.append(parts[1])
assert "./sha256.txt" not in man_names
assert "sha256.txt" not in man_names
assert all(not n.endswith("/sha256.txt") for n in man_names)
assert all("__pycache__" not in n and not n.endswith(".pyc") for n in man_names)
print("conservation unrepaired=389 no_ai=304 no_deleted=74 UNKNOWN_BLOCKED=11 hits=0 selected=0 PASS_proposal=0 current_leader_accepted_count=84 packet_delta=0")
PY
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"

printf 'REPLAY_OK reviewed=0 PASS_proposal=0 REJECT=0 NARROW=0 UNKNOWN=11 BLOCKED=11 scanned=389 hits=0 selected=0 packet_delta=0 current_leader_accepted_count=84\n'
