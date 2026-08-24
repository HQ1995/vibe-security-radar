#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-additiveguard96-consolidated-grok46-high.
# English only. Do not print credentials. Do not clone, commit, or push.
# Selection/mining exhaustion only. PASS proposals 0. Packet delta 0. Canonical 84 unchanged.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export PYTHONDONTWRITEBYTECODE=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
AR=$ROOT/autoresearch
OWNED=$AR/herdr-260814-ghsa200-additiveguard96-consolidated-grok46-high
SCAN_MISS=$AR/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/work/scan-miss.jsonl

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

forbid_bytecode() {
  local found
  found=$(/usr/bin/find "$OWNED" \( -name '__pycache__' -o -name '*.pyc' -o -name '*.pyo' \) -print)
  if [[ -n $found ]]; then
    printf 'bytecode present:\n%s\n' "$found" >&2
    exit 1
  fi
}

forbid_bytecode
require_file "$OWNED/coverage.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/assignments.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/summary.json"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/adjudications.jsonl"
require_file "$OWNED/work/build_coverage.py"
require_file "$OWNED/work/uniqueness.json"
require_file "$OWNED/work/freeze.json"
require_file "$OWNED/work/blocked.json"
require_file "$OWNED/work/source_pins.json"
require_file "$OWNED/work/conservation.json"
require_file "$OWNED/work/pool.json"
require_file "$OWNED/sha256.txt"
require_file "$SCAN_MISS"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$SCAN_MISS" \
  5ec5265e65d957d8a7877a1c27465e9463b404f73790cfb03fc9f011d5625e40
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-first30-grok46-high/result.json" \
  536cea061d71746916a000f040de8c108d01f5091c9d5c665249d00fd95cab42
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-first30-grok46-high/summary.json" \
  27bd37a1dda2a7a3ac05c91d7e58b65648e84c686dcb245af2d10c0b31604cb3
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-first30-grok46-high/cases.jsonl" \
  b0f43df58752beafe2879abddef09aeaade52ca7c6cbe5e01ffb320b9f60f31e
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-first30-grok46-high/assignment.json" \
  0a71362f6bba413324dab42efcb88f604cd27a43f88d33db49781e0bdaa2e426
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-first30-grok46-high/work/assigned30.jsonl" \
  03051aafee4a8876e01153f7e5220951a340bb69fe0f7059ee6121e862b4c2b1
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-first30-grok46-high/work/assigned30.json" \
  2972ac225ef9bc131bda2d042e426a82091b39ed97844c6e4c078ba688b6b51a
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-first30-grok46-high/work/scan.jsonl" \
  b31a695e911606e9bc7709ace1803f30938ed94da8de7657cb623b18556ff813
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-first30-grok46-high/work/scan-summary.json" \
  6d3c305f815b7b10ee92f3fd81001476157d82b665d336d7e1c64471bea612ea
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-first30-grok46-high/work/exclusion.json" \
  31ef3b3d8f00b8987f632a12c345e62c0ec87c93bf2c26a4830eac3e13851954
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-first30-grok46-high/replay.zsh" \
  7deed2e475f55884a4cb577a9db7c0fc364ad8a89f64864a412b68966ec0cca9
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-first30-grok46-high/sha256.txt" \
  30e63105ecbdda3a8c2128850b59b2fd00ae19afacb5210bc29bb6bd1ce77039
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-next30-grok46-high/result.json" \
  d91b6a1c50fd019e7a6cbf188537aced0141669cd3ae9385b9eb0591be2a1292
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-next30-grok46-high/summary.json" \
  ee6b194257ca3a3aa9f4701e4284540f3c485d2054939b3cd8c23dddfb8d6bf0
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-next30-grok46-high/cases.jsonl" \
  a8dc5b1bbba8da61c91c886b059f7f2244b47b7859ebaac6bcf0d413271c03c3
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-next30-grok46-high/assignment.json" \
  5923cc0d072063f4e705b9ed100311404609e86e35256422d73bf4a83eeb73be
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-next30-grok46-high/work/assigned30.jsonl" \
  00a29c3028f87d7a0e8060af3cf387c4d9180af4cad0db72e57843bf3defcf24
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-next30-grok46-high/work/assigned30.json" \
  1ca9a9a34337dfded462c15eb2f5396fce32b53927ed911c723819edfa26a520
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-next30-grok46-high/work/scan.jsonl" \
  fc1778aa596d4bd9e4a1ec3c7c815b15566d3b1ff39cfaf3364d4ffa4d6817eb
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-next30-grok46-high/work/scan-summary.json" \
  a5863609b14c04433845b542d848a629b9b1eb4035be9d817ee9e98486dd90af
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-next30-grok46-high/work/exclusion.json" \
  67abbb3a4ff21623aa6f73743419e2b2aa4831c828866079206c4454d1b8fe5e
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-next30-grok46-high/replay.zsh" \
  24a3e568309d9df3ec4930bdd917ff6aef23983e89a88a9999ca2112b7df3cf3
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-next30-grok46-high/sha256.txt" \
  c45a93eaa452c019d4083f1b7fbccd07f367899a02d58ca8d90c9fad861b3c5e
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-final36-grok46-high/result.json" \
  7f5dd4d74babd0f5c9fa3babc9474cd89e094b63e4880fe2ed398882656fc758
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-final36-grok46-high/summary.json" \
  74472cc87bff4f0ec49323c8a35f32f8c767c2b65165b080fa9125ad3084e57c
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-final36-grok46-high/cases.jsonl" \
  37c3505140bb804b99358c0ee5a8a9dd6299b3d8dcab71f76c4710c4c46e84c8
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-final36-grok46-high/assignment.json" \
  5956efd3029feacf749e2dc4f6011d6b7c3ad517c4723453e2a457bc6e82d757
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-final36-grok46-high/work/assigned36.jsonl" \
  7813029eab8c6d891a6af022b449b39e3dbb8cc40069547601b8034a4c12ed45
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-final36-grok46-high/work/assigned36.json" \
  5a1a91412f7e96b15226a3fe0381c30f5053ed6a7be32d94868e48c3219732cd
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-final36-grok46-high/work/scan.jsonl" \
  42c41158ea5b4a075856b55cc69e373744f47964f4489b5b5450c223aa477668
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-final36-grok46-high/work/scan-summary.json" \
  f0dd3e5230e57eecbda2e69c394057272acd85dadc0ce58e9228d505e9be0ddb
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-final36-grok46-high/work/exclusion.json" \
  ec8b85cbdb3cf78eae83fb3122a12d1056da278f515249651f156dc49920762c
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-final36-grok46-high/replay.zsh" \
  2819894d734ae0aae9e20ecb8b5d93d83a6e7d014e9edd197edeb342bc593393
expect_hash "$AR/herdr-260814-ghsa200-additiveguard-final36-grok46-high/sha256.txt" \
  7d97eab3e55ed7841576d8d61b59eb7779f3365054b18636d3e5559efcc9476e

cov_before=$(/usr/bin/sha256sum "$OWNED/coverage.jsonl" | /usr/bin/awk '{print $1}')
cases_before=$(/usr/bin/sha256sum "$OWNED/cases.jsonl" | /usr/bin/awk '{print $1}')
assign_before=$(/usr/bin/sha256sum "$OWNED/assignments.jsonl" | /usr/bin/awk '{print $1}')
python3 -B "$OWNED/work/build_coverage.py" >/dev/null
cov_after=$(/usr/bin/sha256sum "$OWNED/coverage.jsonl" | /usr/bin/awk '{print $1}')
cases_after=$(/usr/bin/sha256sum "$OWNED/cases.jsonl" | /usr/bin/awk '{print $1}')
assign_after=$(/usr/bin/sha256sum "$OWNED/assignments.jsonl" | /usr/bin/awk '{print $1}')
if [[ $cov_before != "$cov_after" ]]; then
  printf 'coverage.jsonl changed on rebuild\n' >&2
  exit 1
fi
if [[ $cases_before != "$cases_after" ]]; then
  printf 'cases.jsonl changed on rebuild\n' >&2
  exit 1
fi
if [[ $assign_before != "$assign_after" ]]; then
  printf 'assignments.jsonl changed on rebuild\n' >&2
  exit 1
fi

expect_hash "$OWNED/coverage.jsonl" f02ad68b333088c8a027f7167874babc8970366cdbd29828e92c13cc5f96f6fa
expect_hash "$OWNED/cases.jsonl" 282170530f4e50c7c36b4a80658777c3c57682f2b68c382e859aa2cdabe2006a
expect_hash "$OWNED/assignments.jsonl" e77ecf5af157517bc987a8017137c4b9e2eea9da6447319131f77d7dd64fe6fd
expect_hash "$OWNED/report.md" 2a8049d0affc70d44eb8b01f2b7f29758d239261e1cfd11cc7267eb541e23e31
expect_hash "$OWNED/result.json" 7efe0ed16d45ca93aece3027c3c92d4da50cc135f228688b1bb3fda529ca93d7
expect_hash "$OWNED/summary.json" 2b1c89212e6526123739e93868a990bb4c6a5de4e64646ea7701a88cc431036a
expect_hash "$OWNED/selected.jsonl" e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/adjudications.jsonl" e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
expect_hash "$OWNED/work/build_coverage.py" 0d86fc5a546681864614ac7f95d3a306642271f3d472de4557c97c3748948ef1
expect_hash "$OWNED/work/uniqueness.json" e1adf30d86fc378770ef97939f7275cc06110283a3c0fcf3fcd7b8a4b0b0aba4
expect_hash "$OWNED/work/freeze.json" 43fdc443fc08e834e6b6a1ce87af7eaf2e2230d409c9f921a31d92b3a27d2a70
expect_hash "$OWNED/work/blocked.json" fe3defcd4c841e58ddfb82b565912f1fa0ee90c0c48396c756da8176989ee9ff
expect_hash "$OWNED/work/source_pins.json" c9c66b26c6d33b3a36c41080f515b5186388677e1d86fd9ec14b9a807f0fa93b
expect_hash "$OWNED/work/conservation.json" 75b548d2ffe854dd110aa1ef7b50f86885ff981fd72024bfca14e8e937d3ea13
expect_hash "$OWNED/work/pool.json" c69150e34c627f6000aef98faf727816196670a450505c5218a48cf72f57ee19
expect_hash "$OWNED/notes/README.md" f490ddf2fc71a00f1e07792ee75b634081155fbe0a26ecda30b954357cc1e59e
expect_hash "$OWNED/notes/scan/README.md" 8cdc6eb182c4cfbbf646be5250d479db6a726f518cf002ac941237d98fcdb809
expect_hash "$OWNED/notes/scan/blocked.json" fe3defcd4c841e58ddfb82b565912f1fa0ee90c0c48396c756da8176989ee9ff
expect_hash "$OWNED/notes/scan/conservation.json" 75b548d2ffe854dd110aa1ef7b50f86885ff981fd72024bfca14e8e937d3ea13

python3 -B - "$OWNED" \
  "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" << 'PY'
import json, re, sys
from pathlib import Path
owned = Path(sys.argv[1])
rows = [json.loads(l) for l in (owned / "coverage.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
assigns = [json.loads(l) for l in (owned / "assignments.jsonl").read_text().splitlines() if l.strip()]
assert len(rows) == 96
assert len(cases) == 96
assert len(assigns) == 96
assert [r["global_order"] for r in rows] == list(range(1, 97))
assert len({r["ghsa_id"] for r in rows}) == 96
assert [r["slice"] for r in rows].count("first30") == 30
assert [r["slice"] for r in rows].count("next30") == 30
assert [r["slice"] for r in rows].count("final36") == 36
assert all(r["selected"] is False and r["hit"] is False and r["causal_reject"] is False and r["hard_hit"] is False for r in rows)
assert sum(1 for r in rows if r["worker_verdict"] == "NOT_SELECTED") == 88
assert sum(1 for r in rows if r["worker_verdict"] == "BLOCKED") == 8
assert all(r["gates"] == "NOT_OPENED" for r in rows if r["worker_verdict"] == "NOT_SELECTED")
assert all(r["gates"] == "UNKNOWN" for r in rows if r["worker_verdict"] == "BLOCKED")
assert [r["scan_miss_order"] for r in rows] == sorted(r["scan_miss_order"] for r in rows)
blocked = [r for r in rows if r["worker_verdict"] == "BLOCKED"]
ids = [r["ghsa_id"] for r in blocked]
assert ids == [
    "GHSA-97F8-7CMV-76J2",
    "GHSA-7C4H-VH2M-743M",
    "GHSA-6J5F-24FW-PQP4",
    "GHSA-8VRH-3PM2-V4V6",
    "GHSA-8398-GMMX-564H",
    "GHSA-96PC-27RX-PR36",
    "GHSA-WF6X-7X77-MVGW",
    "GHSA-M272-9RP6-32MC",
]
reasons = [r["blocked_reason"] for r in blocked]
assert reasons == [
    "fetch_fail",
    "log_l_fail",
    "blame_fail+log_l_fail",
    "log_l_fail",
    "log_l_fail",
    "blame_fail+log_l_fail",
    "blame_fail",
    "blame_fail",
]
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l.strip()]
adj = [json.loads(l) for l in (owned / "adjudications.jsonl").read_text().splitlines() if l.strip()]
assert sel == []
assert adj == []
res = json.loads((owned / "result.json").read_text())
summary = json.loads((owned / "summary.json").read_text())
assert res["status"] == "TERMINAL"
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 0
assert res["counts"]["BLOCKED"] == 8
assert res["counts"]["not_selected"] == 88
assert res["counts"]["reviewed"] == 0
assert res["packet_delta"] == 0
assert res["canonical_count_updated"] is False
assert res["current_leader_accepted_count"] == 84
assert res["mining_exhaustion_proof_only"] is True
assert res["selection_mining_exhaustion_only"] is True
assert summary["pass_proposals"] == 0
assert summary["not_selected"] == 88
assert summary["BLOCKED"] == 8
assert summary["causal_reject_from_heuristic_miss"] is False
assert summary["heuristic_miss_is_not_evidence_not_ai_caused"] is True
c84 = json.loads(Path(sys.argv[2]).read_text())
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
forbid = ("." + "zshrc", "auth" + ".json", "." + "cache/", "clone" + "_meta")
for name in (
    "coverage.jsonl", "cases.jsonl", "assignments.jsonl", "report.md", "replay.zsh",
    "result.json", "summary.json", "work/uniqueness.json", "work/freeze.json",
    "work/blocked.json", "work/source_pins.json", "work/conservation.json",
    "work/pool.json", "notes/README.md", "sha256.txt",
):
    text = (owned / name).read_text(encoding="utf-8")
    if name in ("selected.jsonl", "adjudications.jsonl") and text == "":
        continue
    assert text.isascii(), name
    assert not han.search(text), name
    assert not secret.search(text), name
    low = text.lower()
    for bad in forbid:
        assert bad.lower() not in low, (name, bad)
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
assert all("__pycache__" not in n and not n.endswith(".pyc") and not n.endswith(".pyo") for n in man_names)
assert not list(owned.rglob("__pycache__"))
assert not list(owned.rglob("*.pyc"))
assert not list(owned.rglob("*.pyo"))
print("conservation raw=381 excluded=285 eligible=96 assigned=96 leftover=0 NOT_SELECTED=88 BLOCKED=8 hits=0 selected=0 reviewed=0 PASS=0 REJECT=0 packet_delta=0 current_leader_accepted_count=84")
PY
forbid_bytecode
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"

ws_fail=0
while IFS= read -r f; do
  out=$(/usr/bin/git diff --no-index --check /dev/null "$f" 2>&1 || true)
  if print -r -- "$out" | /usr/bin/grep -E 'trailing whitespace|space before tab|indent with Tab' >/dev/null; then
    printf '%s\n' "$out" >&2
    ws_fail=1
  fi
done < <(/usr/bin/find "$OWNED" -type f ! -name sha256.txt | /usr/bin/sort)
if [[ $ws_fail -ne 0 ]]; then
  printf 'git diff --no-index --check found whitespace errors\n' >&2
  exit 1
fi

printf 'REPLAY_OK reviewed=0 PASS_proposal=0 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=8 NOT_SELECTED=88 scanned=96 hits=0 selected=0 leftover=0 packet_delta=0 current_leader_accepted_count=84\n'
