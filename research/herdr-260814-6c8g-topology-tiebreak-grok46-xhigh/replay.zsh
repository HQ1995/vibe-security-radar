#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-6c8g-topology-tiebreak-grok46-xhigh.
# English ASCII only. No clone/commit/push. Canonical88 read-only.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
unsetopt xtrace

ROOT=/home/hanqing/agents/ai-slop
OWN=$ROOT/autoresearch/herdr-260814-6c8g-topology-tiebreak-grok46-xhigh
S=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/sharpcompress
REV=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LAYERS=$ROOT/docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl
RW6=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/8rw6_acceptance.json
ADV=$REV/advisories/github-reviewed/2026/05/GHSA-6c8g-7p36-r338/GHSA-6c8g-7p36-r338.json

fail() { printf 'REPLAY_FAIL %s\n' "$*" >&2; exit 1; }

REPLAY_TMP=""
cleanup_replay_tmp() {
  if [[ -n "${REPLAY_TMP:-}" && -d "$REPLAY_TMP" ]]; then
    rm -rf "$REPLAY_TMP"
  fi
}
trap cleanup_replay_tmp EXIT
REPLAY_TMP="$(mktemp -d)"

sha256_file() {
  /usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}'
}

expect_hash() {
  local got
  got=$(sha256_file "$1")
  if [[ $got != "$2" ]]; then
    fail "HASH_MISMATCH $1 got=$got want=$2"
  fi
}

GITQ_N=0
gitq() {
  GITQ_N=$((GITQ_N + 1))
  local outfile errfile rc filtered
  outfile="$REPLAY_TMP/out.$GITQ_N"
  errfile="$REPLAY_TMP/err.$GITQ_N"
  set +e
  command git "$@" >"$outfile" 2>"$errfile"
  rc=$?
  set -e
  filtered="$(grep -v -E -- '^error: unable to normalize alternate object path:|^fatal: lazy fetching disabled' "$errfile" || true)"
  if [[ -n "$filtered" ]]; then
    fail "git stderr: $filtered"
  fi
  cat "$outfile"
  rm -f "$outfile" "$errfile"
  return $rc
}

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  python3 - "$OWN/$f" <<'PY' || fail "ascii $f"
import sys
b=open(sys.argv[1],"rb").read()
if b"\x00" in b:
    raise SystemExit(1)
b.decode("ascii")
if not b.endswith(b"\n"):
    raise SystemExit(1)
if b.endswith(b" ") or b" \n" in b:
    raise SystemExit(1)
PY
done

owned_n=$(/usr/bin/find "$OWN" -maxdepth 1 -type f | /usr/bin/wc -l)
if [[ ${owned_n// /} != 5 ]]; then
  fail "owned_file_count $owned_n"
fi

echo "== input hashes =="
expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LAYERS" 70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f
expect_hash "$SUMMARY" 81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921
expect_hash "$LEDGER" 35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
expect_hash "$RW6" 8cb85b42f405595b834a4ccae9b782c488b8dfa340900ad5717bb0dac71cfae9
expect_hash "$ADV" 48c903f727ee06ce23d71a01df78940279ceb1f017e157817419f06470c9e014
head=$(gitq -C "$REV" rev-parse HEAD | tr -d '\n')
[[ $head == f2c6ab3202aeafb36fbea6e76d892532acfca1a6 ]] || fail "reviewed_head $head"
echo "HASH_OK inputs"

python3 - "$OWN" "$ROOT" "$S" "$ADV" "$SUMMARY" "$REPLAY_TMP" <<'PY' || fail "python_checks"
from __future__ import annotations
import hashlib, json, os, re, subprocess, sys, urllib.request, zipfile
from pathlib import Path

owned, root, clone, adv, summary, tmp = map(Path, sys.argv[1:])
CAND = "8b95e0a76d6b387533175730e2895ccd16772d07"
PARENT = "3f9986c13c973f5e9b8e08da8bfb5e8259044a44"
FIX = "2021a06626d0555a4d69471386e763ca5f5d5dfb"
FIXP = "a3772608f3977c145c7d40754f559951ced57d3b"
C2E = "c2e01798f8bbe63fd4c3568d8e2d594d7c504ae9"
E842 = "8e42296c3a6454e9a5f91446cd040cef64dde2ee"
B501 = "b501bac54ae3f70fba9d86e437fb2e4ea79fd960"
C547 = "5c4719f4a92c0a9bcc84334b6b5784e7aaba0199"
V0474 = "5758b08236b275b926bc2c3d97604a96d21546c0"
V0480 = "6e59c7d7bbf8c19a8a92c3c382599906684bb93d"
IARCH = "src/SharpCompress/Archives/IArchiveExtensions.cs"
IASYNC = "src/SharpCompress/Archives/IAsyncArchiveExtensions.cs"
IOLD = "src/SharpCompress/Archives/IArchiveAsyncExtensions.cs"

def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def git(*args: str) -> subprocess.CompletedProcess:
    r = subprocess.run(["git", "-C", str(clone), *args], capture_output=True)
    err = r.stderr.decode("utf-8", "replace")
    keep = []
    for line in err.splitlines():
        if "unable to normalize alternate object path" in line:
            continue
        if "lazy fetching disabled" in line:
            continue
        keep.append(line)
    if keep:
        raise SystemExit("git stderr: " + " | ".join(keep))
    return r

def git_ok(*args: str) -> str:
    r = git(*args)
    if r.returncode != 0:
        raise SystemExit("git fail %s rc=%s" % (" ".join(args), r.returncode))
    return r.stdout.decode()

def git_rc(*args: str) -> int:
    return git(*args).returncode

def blob(sha: str, path: str) -> str:
    return git_ok("rev-parse", "%s:%s" % (sha, path)).strip()

def patch_id_diff(a: str, ap: str, b: str, bp: str) -> str:
    r = git("diff", "--no-ext-diff", "%s:%s" % (a, ap), "%s:%s" % (b, bp))
    if r.returncode != 0:
        raise SystemExit("diff fail")
    p = subprocess.run(["git", "patch-id", "--stable"], input=r.stdout, capture_output=True)
    return p.stdout.decode().split()[0]

def extract_dir_block(text: str, hint: str) -> str:
    idx = text.find(hint)
    if idx < 0:
        raise SystemExit("hint missing " + hint)
    sub = text[idx:]
    m = re.search(r"if \(entry\.IsDirectory\)\s*\{", sub)
    if not m:
        raise SystemExit("isdir missing " + hint)
    start = m.start()
    brace = 0
    started = False
    i = start
    while i < len(sub):
        if sub[i] == "{":
            brace += 1
            started = True
        elif sub[i] == "}":
            brace -= 1
            if started and brace == 0:
                return sub[start:i + 1]
        i += 1
    raise SystemExit("block unclosed " + hint)

def show(sha: str, path: str) -> str:
    return git_ok("show", "%s:%s" % (sha, path))

def block_sha(sha: str, path: str, hint: str) -> str:
    blk = extract_dir_block(show(sha, path), hint)
    return hashlib.sha256(blk.encode()).hexdigest()

asn = [json.loads(l) for l in (owned / "assignment.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned / "result.json").read_text())
report = (owned / "report.md").read_text()
assert len(asn) == 1 and len(cases) == 1
assert asn[0]["case_id"] == cases[0]["case_id"] == "GHSA-6C8G-7P36-R338"
assert res["per_case"]["GHSA-6C8G-7P36-R338"] == "REJECT"
assert res["conservation"]["equation"] == "1=1+0"
assert res["conservation"]["holds"] is True
assert res["counts"]["PASS_PROPOSAL"] == 0
assert res["counts"]["REJECT"] == 1
assert res["pass_proposals"] == []
assert res["canonical88_strict_count"] == 88
assert res["did_not_pad"] is True
assert res["canonical_ledger_edited"] is False
assert res["scoped_contributor_but_for_applied"] is False
assert res["authorship_transfer"] is False
c = cases[0]
g = c["gates"]
assert g["identity_gate"] == "PASS"
assert g["ai_hunk_gate"] == "FAIL"
assert g["topology_gate"] == "FAIL"
assert g["but_for_gate"] == "FAIL"
assert g["fix_reversal_gate"] == "NARROW"
assert g["release_gate"] == "PASS"
assert g["uniqueness_gate"] == "PASS"
assert c["verdict"] == "REJECT"
assert c["proposed_pass"] is False
assert c["contribution_class"] == "HUMAN_REIMPLEMENTATION"
assert c["named_failing_gate"] == "ai_hunk_gate"
assert c["authorship_transfer"] is False
assert c["scoped_contributor_but_for_applied"] is False
assert "**REJECT**" in report
assert "ai_hunk_gate" in report
assert "5c4719f4" in report
assert "b501bac54" in report
assert "Did not pad" in report
canon = set(x.upper() for x in json.loads(summary.read_text())["strict_released_case_ids"])
assert len(canon) == 88
assert "GHSA-6C8G-7P36-R338" not in canon
assert "GHSA-8RW6-P7M8-63JP" in canon
adv_obj = json.loads(adv.read_text())
assert adv_obj.get("database_specific", {}).get("github_reviewed") is True
assert not adv_obj.get("withdrawn")
details = adv_obj.get("details", "")
assert "WriteToDirectoryAsyncInternal" in details
assert "IAsyncArchiveExtensions.cs" in details
assert "WriteToDirectoryInternal" in details

# git objects
assert git_ok("cat-file", "-t", CAND).strip() == "commit"
assert git_ok("cat-file", "-t", FIX).strip() == "commit"
parents = git_ok("rev-list", "--parents", "-n", "1", CAND).split()
assert parents == [CAND, PARENT]
assert git_ok("log", "-1", "--format=%an", CAND).strip() == "copilot-swe-agent[bot]"
fparents = git_ok("rev-list", "--parents", "-n", "1", FIX).split()
assert fparents == [FIX, FIXP]
assert git_ok("log", "-1", "--format=%an", C2E).strip() == "Adam Hathcock"
assert git_ok("log", "-1", "--format=%an", B501).strip() == "Adam Hathcock"
assert git_ok("log", "-1", "--format=%an", C547).strip() == "Adam Hathcock"
assert git_ok("log", "-1", "--format=%s", C547).strip() == "missing extensions"

# parent vs candidate symbols
assert "ExtractToDirectory" in show(PARENT, IARCH)
assert "Path.Combine" in show(PARENT, IARCH)
assert "WriteToDirectoryAsync" not in show(PARENT, IARCH)
assert "WriteToDirectoryAsync" in show(CAND, IARCH)
assert "WriteToDirectoryAsyncInternal" not in show(CAND, IARCH)
ls = git_ok("ls-tree", "--name-only", CAND, "--", IASYNC).strip()
assert ls == ""
assert "WriteToDirectoryAsyncInternal" in show(C2E, IARCH)
ls_old = git_ok("ls-tree", "--name-only", E842, "--", IOLD).strip()
assert ls_old == IOLD

# copy/rename status
dt = git_ok("diff-tree", "--no-commit-id", "-r", "-C", "--name-status", E842)
assert "C053\t%s\t%s" % (IARCH, IOLD) in dt.replace(" ", "") or "C053\t%s\t%s" % (IARCH, IOLD) in dt
dt20 = git_ok("diff-tree", "--no-commit-id", "-r", "-C20", "--find-copies-harder", "--name-status", B501)
assert "A\t%s" % IASYNC in dt20
assert "R" not in [ln.split("\t", 1)[0][0] for ln in dt20.splitlines() if IASYNC in ln]
dt90 = git_ok("diff-tree", "--no-commit-id", "-r", "-C90", "--name-status", B501)
assert "A\t%s" % IASYNC in dt90

# first-parent: c2e not on first-parent of 8e42
fp = git_ok("log", "--first-parent", "--format=%H", E842)
assert C2E not in fp.split()
assert git_rc("merge-base", "--is-ancestor", C2E, E842) == 0

# blobs
assert blob(CAND, IARCH) == "628155995c06131bcba910a5f2504fda5d0804f6"
assert blob(C2E, IARCH) == "0d39c6e2c149064467b74ddf77bfe58d058a863b"
assert blob(E842, IOLD) == "ca3db1cf2c9cbbecd9eb299f2d3de7dc61bd4b75"
assert blob(B501, IASYNC) == "b6b0cad1e9ee799c03539e46c70cf11150084450"
assert blob(C547, IASYNC) == "df4cb05c4a7f55e3fb0a4080f31a21cdc3605557"
assert blob(V0474, IASYNC) == "9ba599776f56d4e238f93416343cb3a181033f7a"
assert blob(V0474, IARCH) == "80857a25c30fac320fdda30fce98ddfe2fedd03d"
assert blob(FIX, IASYNC) == "5d9ef261594aeaab45f56226794cd007b3622423"
assert blob(CAND, IARCH) != blob(V0474, IASYNC)
assert blob(B501, IASYNC) != blob(E842, IOLD)

# directory-entry blocks
assert block_sha(PARENT, IARCH, "ExtractToDirectory") == "e11b2796e6756d5363472f4891b817ea317d14479d88922fd7b2ad6b2da6bd6b"
assert block_sha(CAND, IARCH, "WriteToDirectoryAsync") == "87dff43f93eeb3f466845cac0dcf58b783771129230ede4744b60a3aa3b60524"
assert block_sha(C2E, IARCH, "WriteToDirectoryAsyncInternal") == "5409fc198a65a099e4b3ac7cee16dd7f66fa595102849f8e7d40ea7c9fd57771"
assert block_sha(V0474, IASYNC, "WriteToDirectoryAsyncInternal") == "5409fc198a65a099e4b3ac7cee16dd7f66fa595102849f8e7d40ea7c9fd57771"
assert block_sha(FIX, IASYNC, "WriteToDirectoryAsyncInternal") == "88f4b199310cd166b52561b33f0c46db84a02b4bc99a197d21fee1900c7675fb"
assert block_sha(CAND, IARCH, "WriteToDirectoryAsync") != block_sha(V0474, IASYNC, "WriteToDirectoryAsyncInternal")

# patch-ids
assert patch_id_diff(PARENT, IARCH, CAND, IARCH) == "7bd36bfff290ee3baef0236ca9f0b1e9ee69e9b4"
assert patch_id_diff(CAND, IARCH, V0474, IASYNC) == "7fcbcbc5aaa67a48f542fb9e6cfeada650127e17"
assert patch_id_diff(E842, IOLD, B501, IASYNC) == "1d747d822b24e758dd225c2736cfa561ec87aa59"
assert patch_id_diff("1b4cedfa13188fcd7896b1a03fc1902d3907cfb3", IASYNC, C547, IASYNC) == "2114e31f94bc85b6e19a5c46a3054b6d1b7440ec"

# default blame: Path.Combine lines are b501, not cand
blame = git_ok("blame", "-l", "-w", "-L", "72,75", V0474, "--", IASYNC)
for line in blame.splitlines():
    assert line.startswith(B501), line
    assert CAND not in line
blame_ext = git_ok("blame", "-l", "-w", "-L", "12,13", V0474, "--", IASYNC)
for line in blame_ext.splitlines():
    assert line.startswith(C547), line

# 0.47.4 async has Path.Combine, no GetFullPath
async0474 = show(V0474, IASYNC)
assert "WriteToDirectoryAsyncInternal" in async0474
assert "Path.Combine" in async0474
assert "GetFullPath" not in async0474
assert "extension(IAsyncArchive archive)" in async0474
fixasync = show(FIX, IASYNC)
assert "GetFullPath" in fixasync
assert "StartsWith" in fixasync

# ancestry / tags
assert git_ok("rev-parse", "0.47.4").strip() == V0474
assert git_ok("rev-parse", "0.48.0").strip() == V0480
assert git_rc("merge-base", "--is-ancestor", CAND, "0.47.4") == 0
assert git_rc("merge-base", "--is-ancestor", FIX, "0.47.4") == 1
assert git_rc("merge-base", "--is-ancestor", FIX, "0.48.0") == 0
assert git_rc("merge-base", "--is-ancestor", CAND, C2E) == 0
assert git_rc("merge-base", "--is-ancestor", CAND, B501) == 0
assert git_rc("merge-base", "--is-ancestor", CAND, C547) == 0
assert git_rc("merge-base", "--is-ancestor", C547, "0.47.4") == 0

# nuget artifacts
want = {
    "0.47.4": ("987d11f9a976194a26218922798b9d4e61759809c852289f40f4e9d77794160f", V0474),
    "0.48.0": ("d8c5da8a76d325eb81c1103a78953e025513f22ade36b5b11d8342324146f0b7", V0480),
}
for ver, (sha, commit) in want.items():
    url = "https://api.nuget.org/v3-flatcontainer/sharpcompress/%s/sharpcompress.%s.nupkg" % (ver, ver)
    dest = tmp / ("sharpcompress.%s.nupkg" % ver)
    urllib.request.urlretrieve(url, dest)
    got = hashlib.sha256(dest.read_bytes()).hexdigest()
    if got != sha:
        raise SystemExit("nupkg hash %s %s" % (ver, got))
    z = zipfile.ZipFile(dest)
    spec = z.read("SharpCompress.nuspec").decode("utf-8")
    if 'commit="%s"' % commit not in spec:
        raise SystemExit("nuspec commit %s" % ver)
    dll = z.read("lib/net8.0/SharpCompress.dll")
    marker = "WriteToDirectoryAsyncInternal"
    if marker.encode("ascii") not in dll and marker.encode("utf-16le") not in dll:
        raise SystemExit("dll missing Internal %s" % ver)

for name in ("assignment.jsonl", "cases.jsonl", "report.md", "replay.zsh"):
    got = sha256(owned / name)
    want_h = res["artifact_hashes"][name]
    if got != want_h:
        raise SystemExit("ARTIFACT_HASH_FAIL %s %s %s" % (name, got, want_h))
assert "result.json" not in res["artifact_hashes"]
print("PY_OK")
PY

echo "REPLAY_OK reviewed=1 REJECT=1 PASS_PROPOSAL=0 conservation=1=1+0 canonical88=88"
