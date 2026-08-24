#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-ghsa200-canonical-fixmismatch2-grok46-high.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# KEEP_WITH_CORRECTION is a proposal. Packet delta is 0. This script does not admit rows.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export PYTHONDONTWRITEBYTECODE=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-canonical-fixmismatch2-grok46-high
TMP=/tmp/ghsa200-fixmismatch2
git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

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

if [[ -e $TMP ]]; then
  printf 'tmp path must be absent: %s\n' "$TMP" >&2
  exit 1
fi

require_file "$OWNED/cases2.jsonl"
require_file "$OWNED/corrections.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/summary.json"
require_file "$OWNED/replay.zsh"
require_file "$OWNED/sha256.txt"
require_file "$OWNED/facts/input_hashes.json"
require_file "$OWNED/facts/first_party.json"
require_file "$OWNED/facts/git.json"
require_file "$OWNED/facts/release.json"
require_file "$OWNED/facts/gates.json"
require_file "$OWNED/facts/uniqueness.json"
require_file "$OWNED/facts/snippets/faraday.parent.guard.rb.txt"
require_file "$OWNED/facts/snippets/faraday.cand.guard.rb.txt"
require_file "$OWNED/facts/snippets/faraday.fix.guard.rb.txt"
require_file "$OWNED/facts/snippets/openclaw.cand.redirect.ts.txt"
require_file "$OWNED/facts/snippets/openclaw.fix.redirect.ts.txt"
require_file "$OWNED/facts/snippets/openclaw.named.redirect.ts.txt"
forbid_bytecode

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-canonical84-sourcetier-qa-grok46-xhigh/evidence/facts/GHSA-5RV5-XJ5J-3484.json" \
  175361955d9aa53af6518846b4910d4ac29c9e63c37f72fb2f7bdc5d16da72f4
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-canonical84-sourcetier-qa-grok46-xhigh/evidence/facts/GHSA-68V4-HMWV-F43H.json" \
  6c1f04ad7ff3fbd073a4692b5d2620a420589f3baa4b14ca9f9f3e32092f5104
expect_hash "$ROOT/autoresearch/herdr-260814-ghsa200-canonical84-sourcetier-qa-grok46-xhigh/cases84.jsonl" \
  6ab9e26d60e547b6e9047cf18c6271b2b0b7e60a9b8987ec61e98e7042643f51

[[ "$("${git_cmd[@]}" -C "$ROOT" rev-parse ca034f064fd696201c81baae7392c14f0d501d2b)" == ca034f064fd696201c81baae7392c14f0d501d2b ]]

python3 - "$OWNED" "$ROOT" << 'PY'
import json, re, subprocess, sys
from pathlib import Path

owned = Path(sys.argv[1])
root = Path(sys.argv[2])
rows = [json.loads(l) for l in (owned / "cases2.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
corr = [json.loads(l) for l in (owned / "corrections.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
summary = json.loads((owned / "summary.json").read_text(encoding="utf-8"))
gates = json.loads((owned / "facts/gates.json").read_text(encoding="utf-8"))
gitf = json.loads((owned / "facts/git.json").read_text(encoding="utf-8"))
rel = json.loads((owned / "facts/release.json").read_text(encoding="utf-8"))
fp = json.loads((owned / "facts/first_party.json").read_text(encoding="utf-8"))
uniq = json.loads((owned / "facts/uniqueness.json").read_text(encoding="utf-8"))
report = (owned / "report.md").read_text(encoding="utf-8")
qa_rows = [json.loads(l) for l in (root / "autoresearch/herdr-260814-ghsa200-canonical84-sourcetier-qa-grok46-xhigh/cases84.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
c84 = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json").read_text(encoding="utf-8"))

assert len(rows) == 2
assert [r["case_id"] for r in rows] == ["GHSA-5RV5-XJ5J-3484", "GHSA-68V4-HMWV-F43H"]
assert [c["case_id"] for c in corr] == ["GHSA-5RV5-XJ5J-3484", "GHSA-68V4-HMWV-F43H"]
assert summary["canonical_strict_count"] == 84
assert summary["packet_delta"] == 0
assert summary["causal_admission"] is False
assert summary["counts"]["KEEP_WITH_CORRECTION"] == 2
assert summary["counts"]["KEEP"] == 0
assert summary["counts"]["REJECT"] == 0
assert summary["conservation"]["assigned"] == 2
assert summary["conservation"]["reviewed"] == 2
assert summary["conservation"]["unreviewed"] == 0
assert c84["canonical_strict_count"] == 84
assert len(c84["strict_released_case_ids"]) == 84
ids84 = {x.upper() for x in c84["strict_released_case_ids"]}
assert "GHSA-5RV5-XJ5J-3484" in ids84
assert "GHSA-68V4-HMWV-F43H" in ids84
assert "GHSA-33MH-2634-FWR2" not in ids84
assert uniq["GHSA-33MH-2634-FWR2_in_canonical84_strict"] is False
assert uniq["packet_delta"] == 0

seven = [
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
]
for row, gid, cls in (
    (rows[0], "GHSA-5RV5-XJ5J-3484", "AI_INCOMPLETE_REMEDIATION"),
    (rows[1], "GHSA-68V4-HMWV-F43H", "AI_DIRECT_ROOT"),
):
    assert row["case_id"] == gid
    assert row["verdict"] == "KEEP_WITH_CORRECTION"
    assert row["contribution_class"] == cls
    assert row["failing_gates"] == []
    assert row["packet_delta"] == 0
    assert row["countable"] is False
    assert row["canonical_minimum_fix_set_semantically_correct"] is True
    assert row["canonical_release_sha_mislabeled"] is True
    assert row["carrier_set"] == []
    for g in seven:
        assert row[g] == "PASS", (gid, g)
    gobj = gates[gid]
    assert gobj["verdict"] == "KEEP_WITH_CORRECTION"
    assert gobj["all_seven_pass"] is True
    for g in seven:
        assert gobj[g] == "PASS", (gid, g)

qa_f = next(r for r in qa_rows if r["case_id"] == "GHSA-5RV5-XJ5J-3484")
qa_o = next(r for r in qa_rows if r["case_id"] == "GHSA-68V4-HMWV-F43H")
assert qa_f["status"] == "UNKNOWN"
assert "exact_fix_topology_unresolved" in qa_f["mismatch_reason"]
assert qa_o["status"] == "UNKNOWN"
assert "exact_fix_topology_unresolved" in qa_o["mismatch_reason"]
assert qa_f["first_party_named_fix_shas"] == ["a01039c948d3e9e41e03d152aed7244f0fb4d5ca"]
assert qa_o["first_party_named_fix_shas"] == ["e704323ff388ed21f6963f9b8e0b1b8dfaaabc5f"]

f = rows[0]
assert f["minimum_fix_set"] == ["3f1280c69e93297d574e85a2d462d05ebadf1d09"]
assert f["candidate_set"] == ["a6d3a3a0bf59c2ab307d0abd91bc126aef5561bc"]
assert f["fixed_release"]["sha"] == "2ecd5e05388303087c3f6872ef7f98f260e9560f"
assert f["vulnerable_release"]["sha"] == "16cbd38ef252d25dedf416a4d2510a2f3db10c87"
assert f["named_sha_role"] == "advisory_tested_head_docs_commit_not_mechanism_closer"
assert f["remediation_patch_delta_gate"] == "PASS"
assert gitf["GHSA-5RV5-XJ5J-3484"]["named"]["touches_mechanism_file"] is False
assert gitf["GHSA-5RV5-XJ5J-3484"]["connection_rb_blobs"]["named"] == gitf["GHSA-5RV5-XJ5J-3484"]["connection_rb_blobs"]["candidate"]
assert gitf["GHSA-5RV5-XJ5J-3484"]["connection_rb_blobs"]["named"] != gitf["GHSA-5RV5-XJ5J-3484"]["connection_rb_blobs"]["closer"]
assert gitf["GHSA-5RV5-XJ5J-3484"]["connection_rb_blobs"]["v2_14_1"] == "b58b6175deaf5c2e2399c6caf6f356f2dce49e58"
assert gitf["GHSA-5RV5-XJ5J-3484"]["connection_rb_blobs"]["v2_14_2"] == "23fcda3e73291c5b96639c44ba1403f7e9416e3a"
assert rel["GHSA-5RV5-XJ5J-3484"]["vulnerable"]["has_uri_to_s"] is False
assert rel["GHSA-5RV5-XJ5J-3484"]["fixed"]["has_uri_to_s"] is True
assert rel["GHSA-5RV5-XJ5J-3484"]["vulnerable"]["connection_rb_sha256"] == "5d6fdf6e4becaaaf4a0c9dfbd3c1f04f28e657a088c536ff7c6965b0f4f98819"
assert rel["GHSA-5RV5-XJ5J-3484"]["fixed"]["connection_rb_sha256"] == "b31aed7f80959e754bb08a5d4ae5ed0f17abe1a087d5bca801ff7302f385f1f2"
assert fp["GHSA-5RV5-XJ5J-3484"]["withdrawn"] is False

o = rows[1]
assert o["minimum_fix_set"] == ["f865a5455ee03924a444e9ba0f1c4743d8fb6566"]
assert o["candidate_set"] == ["06dd9b8ed864eb6668d42c497f0615e743da483a"]
assert o["fixed_release"]["sha"] == "213a704b71f4996dc82a583288ee53785215f627"
assert o["vulnerable_release"]["sha"] == "f9b1079283a8ee25a7cee77c8f8225d5c813bc30"
assert o["named_sha_role"] == "same_mechanism_descendant_refactor_not_minimum_reversal"
assert o["remediation_patch_delta_gate"] == "NOT_APPLICABLE"
assert gitf["GHSA-68V4-HMWV-F43H"]["ancestry"]["closer_ancestor_of_named"] is True
assert gitf["GHSA-68V4-HMWV-F43H"]["ancestry"]["named_ancestor_of_closer"] is False
assert gitf["GHSA-68V4-HMWV-F43H"]["store_ts_blobs"]["named_parent_equals_closer"] is True
assert gitf["GHSA-68V4-HMWV-F43H"]["store_ts_blobs"]["v2026_3_31"] == gitf["GHSA-68V4-HMWV-F43H"]["store_ts_blobs"]["named"]
assert gitf["GHSA-68V4-HMWV-F43H"]["ancestry"]["pr_member_ancestor_of_closer_or_tag"] is False
assert rel["GHSA-68V4-HMWV-F43H"]["vulnerable"]["dist_auth_profiles_forwards_original_headers"] is True
assert rel["GHSA-68V4-HMWV-F43H"]["vulnerable"]["dist_auth_profiles_has_retain_safe"] is False
assert rel["GHSA-68V4-HMWV-F43H"]["fixed"]["dist_store_has_retain_safe"] is True
assert fp["GHSA-68V4-HMWV-F43H"]["withdrawn"] is False
assert fp["GHSA-68V4-HMWV-F43H"]["aliases_on_repo_advisory"] == []

cf, co = corr
assert cf["proposed_minimum_fix_set"] == ["3f1280c69e93297d574e85a2d462d05ebadf1d09"]
assert cf["proposed_fixed_release"]["sha"] == "2ecd5e05388303087c3f6872ef7f98f260e9560f"
assert cf["proposed_vulnerable_release"]["sha"] == "16cbd38ef252d25dedf416a4d2510a2f3db10c87"
assert cf["canonical_fixed_release"]["sha"] == "3f1280c69e93297d574e85a2d462d05ebadf1d09"
assert co["proposed_minimum_fix_set"] == ["f865a5455ee03924a444e9ba0f1c4743d8fb6566"]
assert co["proposed_fixed_release"]["sha"] == "213a704b71f4996dc82a583288ee53785215f627"
assert co["proposed_vulnerable_release"]["sha"] == "f9b1079283a8ee25a7cee77c8f8225d5c813bc30"
assert co["canonical_fixed_release"]["sha"] == "f865a5455ee03924a444e9ba0f1c4743d8fb6566"

fc = (owned / "facts/snippets/faraday.cand.guard.rb.txt").read_text()
ff = (owned / "facts/snippets/faraday.fix.guard.rb.txt").read_text()
fpn = (owned / "facts/snippets/faraday.parent.guard.rb.txt").read_text()
assert "url.start_with?('//')" in fc
assert "url.to_s" not in fc
assert "url = url.to_s if url.respond_to?(:host)" in ff
assert "url.start_with?('//')" in ff
assert "url.start_with?('//')" not in fpn
oc = (owned / "facts/snippets/openclaw.cand.redirect.ts.txt").read_text()
ofx = (owned / "facts/snippets/openclaw.fix.redirect.ts.txt").read_text()
on = (owned / "facts/snippets/openclaw.named.redirect.ts.txt").read_text()
assert "downloadToFile(redirectUrl, dest, headers, maxRedirects - 1)" in oc
assert "retainSafeHeadersForCrossOriginRedirectHeaders" in ofx
assert "retainSafeHeadersForCrossOriginRedirect(" in on
assert "redirect-headers" not in ofx
assert "KEEP_WITH_CORRECTION" in report
assert "does not rebuild canonical84" in report
assert "Packet delta 0" in report or "packet delta 0" in report.lower()
assert "a01039c" in report
assert "e704323" in report

han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(
    r"git" + r"hub_pat_|"
    r"ghp_" + r"[A-Za-z0-9]{20,}|"
    r"github" + r"_pat_[A-Za-z0-9_]+|"
    r"sk" + r"_live_|"
    r"xox[baprs]-|"
    r"AKIA" + r"[0-9A-Z]{16}|"
    r"BEGIN" + r" PRIVATE"
)
ws_hits = []
for p in owned.rglob("*"):
    if not p.is_file():
        continue
    if p.suffix in {".pyc", ".pyo"} or "__pycache__" in p.parts:
        continue
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    relp = str(p.relative_to(owned))
    for i, line in enumerate(text.splitlines(), 1):
        if line != line.rstrip(" \t"):
            ws_hits.append((relp, i))
    if relp != "sha256.txt":
        assert text.isascii(), relp
        assert not han.search(text), relp
        assert not secret.search(text), relp
        if text:
            assert text.endswith("\n"), relp
assert ws_hits == [], ws_hits[:8]
ws_err = ("trailing whitespace", "space before tab", "conflict marker")
check_files = [
    owned / "report.md",
    owned / "cases2.jsonl",
    owned / "corrections.jsonl",
    owned / "summary.json",
    owned / "replay.zsh",
    owned / "facts/gates.json",
    owned / "facts/git.json",
    owned / "facts/release.json",
]
for chk in check_files:
    proc = subprocess.run(
        ["/usr/bin/git", "diff", "--no-index", "--check", "/dev/null", str(chk)],
        capture_output=True,
        text=True,
    )
    blob = (proc.stdout or "") + (proc.stderr or "")
    low = blob.lower()
    if any(x in low for x in ws_err):
        raise AssertionError(("whitespace_error", chk.name, blob[:400]))
    if proc.returncode not in (0, 1):
        raise AssertionError(("git_diff_unexpected_rc", chk.name, proc.returncode, blob[:400]))

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
print("conservation assigned=2 reviewed=2 unreviewed=0 KEEP=0 KEEP_WITH_CORRECTION=2 REJECT=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=84")
PY

forbid_bytecode
cd "$OWNED"
/usr/bin/sha256sum --status -c "$OWNED/sha256.txt"
printf 'REPLAY_OK assigned=2 reviewed=2 KEEP_WITH_CORRECTION=2 REJECT=0 packet_delta=0 canonical_strict_count=84\n'
