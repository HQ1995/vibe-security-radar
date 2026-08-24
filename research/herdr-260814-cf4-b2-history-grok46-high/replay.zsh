#!/usr/bin/env zsh
set -euo pipefail
unset GIT_NO_LAZY_FETCH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_CONFIG_NOSYSTEM=1
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

OWNED="autoresearch/herdr-260814-cf4-b2-history-grok46-high"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OWNED_ABS="$ROOT/$OWNED"
F2="/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database"
U39="/home/hanqing/.cache/cve-analyzer/advisory-database"
LEDGER="$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl"
SUMMARY="$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json"
CONTRACT="$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
OV="/home/hanqing/.cache/cve-analyzer/repos/volcengine_openviking"
RD="/home/hanqing/.cache/cve-analyzer/repos/rustdesk_rustdesk"
FB="/home/hanqing/.cache/cve-analyzer/repos/formbricks_formbricks"

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }

expect_hash() {
  local p="$1" h="$2"
  local g
  g="$(sha256sum "$p" | awk '{print $1}')"
  [[ "$g" == "$h" ]] || fail "hash $p"
}

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
expect_hash "$SUMMARY" 81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921

[[ "$(git -C "$F2" rev-parse HEAD)" == "f2c6ab3202aeafb36fbea6e76d892532acfca1a6" ]] || fail "f2c6 HEAD"
[[ -d "$F2/advisories/github-reviewed" ]] || fail "f2c6 reviewed subtree"
[[ ! -d "$F2/advisories/unreviewed" ]] || fail "f2c6 must not supply unreviewed"
[[ "$(git -C "$U39" rev-parse HEAD)" == "39d8887723797efc1804585dd06585c9fd751226" ]] || fail "39d888 HEAD"
[[ -d "$U39/advisories/unreviewed" ]] || fail "39d unreviewed subtree"

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  python3 - "$OWNED_ABS/$f" <<'PY' || fail "ascii $f"
import sys
b=open(sys.argv[1],"rb").read()
if b"\x00" in b:
    raise SystemExit(1)
b.decode("ascii")
if b.endswith(b" ") or b" \n" in b:
    raise SystemExit(1)
PY
done

python3 - "$OWNED_ABS" "$ROOT" "$F2" "$U39" "$LEDGER" "$SUMMARY" <<'PY' || fail "conservation"
import hashlib, json, re, sys
from pathlib import Path
owned, root, f2, u39, ledger, summary = map(Path, sys.argv[1:])
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
ID_FIELDS = {"case_id", "ghsa_id", "reviewed_case_ids", "assigned_ids", "strict_released_case_ids"}
OWNED_NAME = "herdr-260814-cf4-b2-history-grok46-high"
B2_REM = {
    "GHSA-VP55-5C2V-3597","GHSA-V626-428R-43P8","GHSA-H2V8-4C3F-VQGV",
    "GHSA-R3V6-QW6X-WF6H","GHSA-3VHV-JX5J-GJ6P","GHSA-X9X8-26MR-9WMM",
    "GHSA-9CQ9-W9QM-WC9P","GHSA-Q65P-7P84-495C","GHSA-226M-2JQQ-4XGV",
    "GHSA-52VJ-FVRV-7Q82","GHSA-VQWP-45WM-R9R5","GHSA-MV8X-FG99-32MF",
}
H2V8 = {"GHSA-H2V8-4C3F-VQGV"}
skip_dirs = {".git", "node_modules", "work", "notes", "pages", "snapshot", "caches", "tmp"}

def norm(s):
    if not isinstance(s, str):
        return None
    u = s.strip().upper()
    return u if GHSA_RE.fullmatch(u) else None

def bucket(gid):
    return int(hashlib.sha256(gid.encode("ascii")).hexdigest(), 16) % 6

def walk_collect(obj, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ID_FIELDS:
                if isinstance(v, str):
                    n = norm(v)
                    if n:
                        out.add(n)
                elif isinstance(v, list):
                    for item in v:
                        n = norm(item) if isinstance(item, str) else None
                        if n:
                            out.add(n)
            else:
                walk_collect(v, out)
    elif isinstance(obj, list):
        for item in obj:
            walk_collect(item, out)

assign = [json.loads(l) for l in (owned/"assignment.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned/"result.json").read_text())
assert len(assign) == 3 and len(cases) == 3
aids = [a["case_id"] for a in assign]
cids = [c["case_id"] for c in cases]
assert aids == cids == res["conservation"]["reviewed_case_ids"]
assert res["counts"]["PASS"] == 0 and res["counts"]["REJECT"] == 3
assert res["counts"]["PASS_PROPOSAL"] == 0
assert res["counts"]["reviewed"] == 3 and res["did_not_pad"] is True
assert all(c["verdict"] == "REJECT" for c in cases)
assert all(c.get("proposed_pass") is False for c in cases)
assert all(bucket(i) == 2 for i in aids)
assert set(aids).isdisjoint(B2_REM)
assert set(aids).isdisjoint(H2V8)
assert "GHSA-H2V8-4C3F-VQGV" not in aids
assert res["bound"]["eligible"] == 577
assert res["bound"]["inspected_prefix"] == 577
assert res["bound"]["max_inspect"] == 600
assert res["bound"]["stop_rule"] == "prefix_exhausted"
assert res["bound"]["hits"] == 3
assert res["bound"]["shortfall"] == 9

excluded = set()
auto = root / "autoresearch"
for p in sorted(auto.iterdir()):
    if not p.is_dir():
        continue
    if p.name == OWNED_NAME:
        continue
    if not (p.name.startswith("herdr-") or p.name.startswith("orchestrator-")):
        continue
    for f in p.rglob("*"):
        if not f.is_file() or f.suffix not in {".json", ".jsonl"}:
            continue
        if set(f.parts) & skip_dirs:
            continue
        if f.stat().st_size > 50_000_000:
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        if f.suffix == ".jsonl":
            for line in text.splitlines():
                if not line.strip():
                    continue
                try:
                    walk_collect(json.loads(line), excluded)
                except Exception:
                    continue
        else:
            try:
                walk_collect(json.loads(text), excluded)
            except Exception:
                continue

canon = set()
for line in ledger.read_text().splitlines():
    if line.strip():
        walk_collect(json.loads(line), canon)
walk_collect(json.loads(summary.read_text()), canon)
excluded |= canon
assert not (set(aids) & excluded), "exclusion overlap"
strict = set(json.loads(summary.read_text())["strict_released_case_ids"])
assert not (set(aids) & strict), "canonical88 overlap"
assert len(strict) == 88
assert B2_REM <= excluded
assert H2V8 <= excluded

f2_ids = set()
for pth in (f2 / "advisories/github-reviewed").rglob("*.json"):
    n = norm(pth.stem)
    if n:
        f2_ids.add(n)
for a in assign:
    ap = Path(a["advisory_path"])
    ufile = u39 / ap
    assert ufile.is_file(), a["case_id"]
    rec = json.loads(ufile.read_text())
    assert rec["id"].upper() == a["case_id"]
    assert rec.get("affected") == []
    assert rec.get("database_specific", {}).get("github_reviewed") is False
    assert a["case_id"] not in f2_ids, a["case_id"] + " f2c6 reviewed collision"
print("json_ok")
print("exclusion_ok")
print("bucket2_ok")
print("no_overlap_ok")
print("source_split_ok")
print("bound_ok")
print("proposal_count 0")
print("conservation 3=3+0")
PY

gitq() { git -c advice.detachedHead=false "$@" 2>/dev/null; }

[[ -e "$OV/.git" || -f "$OV/.git" ]] || fail "missing openviking clone"
[[ -e "$RD/.git" || -f "$RD/.git" ]] || fail "missing rustdesk clone"
[[ -e "$FB/.git" || -f "$FB/.git" ]] || fail "missing formbricks clone"

gitq -C "$OV" cat-file -t 1b175344e8ff358b626f93afe1f30bccaa5197ee | grep -qx commit || fail "missing cand openviking"
gitq -C "$OV" cat-file -t 27acda8d1701ff68423fbd6c902208e3c1ed9373 | grep -qx commit || fail "missing fix openviking"
gitq -C "$OV" merge-base --is-ancestor 1b175344e8ff358b626f93afe1f30bccaa5197ee 27acda8d1701ff68423fbd6c902208e3c1ed9373 || fail "cand not ancestor of fix openviking"
gitq -C "$OV" merge-base --is-ancestor 27acda8d1701ff68423fbd6c902208e3c1ed9373 v0.2.14 || fail "fix not in v0.2.14"
if gitq -C "$OV" merge-base --is-ancestor 27acda8d1701ff68423fbd6c902208e3c1ed9373 v0.2.13; then
  fail "fix unexpectedly in v0.2.13"
fi
gitq -C "$OV" merge-base --is-ancestor 1b175344e8ff358b626f93afe1f30bccaa5197ee v0.2.13 || fail "cand not in v0.2.13"
gitq -C "$OV" log -1 --format=%B 1b175344e8ff358b626f93afe1f30bccaa5197ee | grep -q "Co-Authored-By: Claude Opus 4.6" || fail "openviking AI marker"
n_ov="$(gitq -C "$OV" log -1 --format=%P 1b175344e8ff358b626f93afe1f30bccaa5197ee | awk '{print NF}')"
[[ "$n_ov" == "1" ]] || fail "openviking cand not atomic"

gitq -C "$RD" cat-file -t 02da7132e76fe85c2662a7aac42cc6754fbe51e0 | grep -qx commit || fail "missing cand rustdesk"
gitq -C "$RD" cat-file -t 493b14ba78abc3dfb33f109c7f93c1c95a1dabc4 | grep -qx commit || fail "missing fix rustdesk"
gitq -C "$RD" merge-base --is-ancestor 02da7132e76fe85c2662a7aac42cc6754fbe51e0 493b14ba78abc3dfb33f109c7f93c1c95a1dabc4 || fail "cand not ancestor of fix rustdesk"
gitq -C "$RD" merge-base --is-ancestor 493b14ba78abc3dfb33f109c7f93c1c95a1dabc4 1.4.9 || fail "fix not in 1.4.9"
if gitq -C "$RD" merge-base --is-ancestor 493b14ba78abc3dfb33f109c7f93c1c95a1dabc4 1.4.8; then
  fail "fix unexpectedly in 1.4.8"
fi
gitq -C "$RD" merge-base --is-ancestor 02da7132e76fe85c2662a7aac42cc6754fbe51e0 1.4.8 || fail "cand not in 1.4.8"
[[ "$(gitq -C "$RD" log -1 --format=%an 02da7132e76fe85c2662a7aac42cc6754fbe51e0)" == "Copilot" ]] || fail "rustdesk Copilot author"
n_rd="$(gitq -C "$RD" log -1 --format=%P 02da7132e76fe85c2662a7aac42cc6754fbe51e0 | awk '{print NF}')"
[[ "$n_rd" == "1" ]] || fail "rustdesk cand not atomic"

gitq -C "$FB" cat-file -t 939fedfca42bf82a981e4f3706e8127cb8ab2ae8 | grep -qx commit || fail "missing cand formbricks"
gitq -C "$FB" cat-file -t af6023b5ac3b030ffcea24fac799f76f3e3512c6 | grep -qx commit || fail "missing fix formbricks"
gitq -C "$FB" merge-base --is-ancestor 939fedfca42bf82a981e4f3706e8127cb8ab2ae8 af6023b5ac3b030ffcea24fac799f76f3e3512c6 || fail "cand not ancestor of fix formbricks"
if gitq -C "$FB" rev-parse --verify --quiet "5.1.0-rc.1^{commit}"; then
  fail "formbricks 5.1.0-rc.1 unexpectedly present"
fi
if gitq -C "$FB" rev-parse --verify --quiet "5.0.0^{commit}"; then
  fail "formbricks 5.0.0 unexpectedly present"
fi
[[ -z "$(gitq -C "$FB" tag --contains af6023b5ac3b030ffcea24fac799f76f3e3512c6)" ]] || fail "formbricks unexpected tag contains fix"
gitq -C "$FB" log -1 --format=%B 939fedfca42bf82a981e4f3706e8127cb8ab2ae8 | grep -q "Co-authored-by: Claude Opus 4.6" || fail "formbricks AI marker"
gitq -C "$FB" log -1 --format=%B af6023b5ac3b030ffcea24fac799f76f3e3512c6 | grep -q "Co-authored-by: Claude Sonnet 4.6" || fail "formbricks AI-on-fix"
n_fb="$(gitq -C "$FB" log -1 --format=%P 939fedfca42bf82a981e4f3706e8127cb8ab2ae8 | awk '{print NF}')"
[[ "$n_fb" == "1" ]] || fail "formbricks cand not atomic"

print "git_ok"
print "REPLAY_OK"
