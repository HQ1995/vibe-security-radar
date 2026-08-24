#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-frvj-hostile2-grok46-medium.
# English only. Do not print credentials. Do not clone, commit, or push.
# Public PyPI wheels and first-party advisory JSON are fetched into mktemp.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# KEEP is a proposal. Packet delta is 0. This script does not admit GHSA-FRVJ.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-frvj-hostile2-grok46-medium
REPO=/home/hanqing/.cache/cve-analyzer/repos/open-webui_open-webui

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

CAND=03547759179672d216d2e1376dd1ae4fdad76a94
PARENT=d4030a8aa5d48c2a1cb06c461566844aca2530ab
FIX=05098d25a58d03738e01c4e85e8852c3b4ad849c
FIX_PARENT=3266a8c9eb6b8408a869a33378a0f4ad8a46809e
FILE=backend/open_webui/routers/terminals.py
BLOB_PARENT=d2ef5f0ea318901212ec8c150515235a75288188
BLOB_CAND=4c61d6ec1d8185b34ab6008561835bfc124c2631
BLOB_FIXPARENT=6a942cf9b246359277922196f439ece628c6118e
BLOB_FIX=4c71322bfbfc18e2c998c57eb468a98bd670566d

TMP=
cleanup() {
  if [[ -n ${TMP:-} && -d $TMP ]]; then
    rm -rf "$TMP"
  fi
}
trap cleanup EXIT INT TERM
TMP=$(mktemp -d /tmp/frvj-hostile2.XXXXXX)
export FRVJ_REPLAY_TMP=$TMP

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

gitx() {
  local repo=$1
  shift
  local errf=$TMP/giterr
  set +e
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
  if [[ -s $errf ]]; then
    grep -vF 'unable to normalize alternate object path' "$errf" >&2 || true
  fi
  rm -f "$errf"
  return $rc
}

assert_ancestor() {
  gitx "$1" merge-base --is-ancestor "$2" "$3"
}

require_dir "$OWNED"
require_dir "$REPO/.git"
require_file "$OWNED/case.json"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/facts/gates.json"
require_file "$OWNED/facts/git.json"
require_file "$OWNED/facts/identity.json"
require_file "$OWNED/facts/pypi.json"
require_file "$OWNED/facts/uniqueness.json"
require_file "$OWNED/facts/nine_x.json"
require_file "$OWNED/diffs/sanitizer.cand.py"
require_file "$OWNED/diffs/sanitizer.fix.py"
require_file "$OWNED/diffs/sanitizer.parent.py"
require_file "$OWNED/diffs/cand.vs.parent.terminals.diff"
require_file "$OWNED/diffs/fix.vs.fixparent.terminals.diff"
if [[ -e $OWNED/pages || -e $OWNED/work/releases ]]; then
  printf 'durable packet must not retain pages or raw wheels\n' >&2
  exit 1
fi

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85/ledger.jsonl" \
  2927924603a76a2565d9c244c3b79f70d4693c127f1bc6fcc63e8099172ba568
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json" \
  47209f841a5cb793ae6146b4247990fd2af1d4e50d3d881e0b53904f850bbd0c
expect_hash "$ROOT/autoresearch/herdr-260814-fresh-strict-grok46-xhigh/cases.jsonl" \
  6a13b08e9b569dfab705385985d5ea49f561c26e8ac28831e620c3e4dce1a742

# ASCII: every retained owned file
python3 - <<'PY'
from pathlib import Path
owned = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-frvj-hostile2-grok46-medium")
bad = []
for p in sorted(owned.rglob("*")):
    if not p.is_file():
        continue
    try:
        p.read_bytes().decode("ascii")
    except UnicodeDecodeError:
        bad.append(str(p.relative_to(owned)))
if bad:
    raise SystemExit("non-ASCII retained files: " + " ".join(bad))
print("ASCII ok")
PY

# Fetch wheels and first-party advisory into mktemp; verify recorded SHA256.
python3 - <<'PY'
import json, hashlib, urllib.request
from pathlib import Path

owned = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-frvj-hostile2-grok46-medium")
tmp = Path(__import__("os").environ["FRVJ_REPLAY_TMP"])
pypi = json.loads((owned / "facts/pypi.json").read_text())
ident = json.loads((owned / "facts/identity.json").read_text())

def fetch(url, dest, timeout=120):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "frvj-hostile2-replay",
            "Accept": "*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        dest.write_bytes(resp.read())

def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

w96 = tmp / pypi["0.9.6"]["filename"]
w10 = tmp / pypi["0.10.0"]["filename"]
fetch(pypi["0.9.6"]["url"], w96)
fetch(pypi["0.10.0"]["url"], w10)
got96 = sha256(w96)
got10 = sha256(w10)
if got96 != pypi["0.9.6"]["sha256"]:
    raise SystemExit("0.9.6 wheel hash mismatch")
if got10 != pypi["0.10.0"]["sha256"]:
    raise SystemExit("0.10.0 wheel hash mismatch")

adv_url = ident["advisory_fetch"]["advisory_database_raw"]
adv = tmp / "GHSA-frvj-c5qp-xj4w.json"
fetch(adv_url, adv)
if sha256(adv) != ident["advisory_fetch"]["recorded_advisory_database_sha256"]:
    raise SystemExit("advisory json hash mismatch")
obj = json.loads(adv.read_text())
if obj.get("id") != "GHSA-frvj-c5qp-xj4w":
    raise SystemExit("advisory id mismatch")
if "range(8)" not in obj.get("details", ""):
    raise SystemExit("advisory missing range(8)")
if "9x" not in obj.get("details", ""):
    raise SystemExit("advisory missing 9x residual")
if obj.get("withdrawn_at"):
    raise SystemExit("advisory withdrawn")

html_url = ident["advisory_fetch"]["first_party_html"]
html = tmp / "ghsa-frvj.html"
fetch(html_url, html)
html_text = html.read_text(errors="replace")
if "GHSA-frvj-c5qp-xj4w" not in html_text:
    raise SystemExit("first-party HTML missing GHSA id")
if "range(8)" not in html_text:
    raise SystemExit("first-party HTML missing range(8)")
print("fetch hash ok")
PY

# object / topology / ancestry
parents=$(gitx "$REPO" rev-parse ${CAND}^)
if [[ $parents != $PARENT ]]; then
  printf 'parent mismatch: %s\n' "$parents" >&2
  exit 1
fi
nparents=$(gitx "$REPO" rev-list --parents -n 1 $CAND | awk '{print NF-1}')
if [[ $nparents != 1 ]]; then
  printf 'expected 1 parent, got %s\n' "$nparents" >&2
  exit 1
fi
assert_ancestor "$REPO" "$PARENT" "$CAND"
assert_ancestor "$REPO" "$CAND" "$FIX"
fp=$(gitx "$REPO" rev-parse ${FIX}^)
if [[ $fp != $FIX_PARENT ]]; then
  printf 'fix parent mismatch: %s\n' "$fp" >&2
  exit 1
fi

blob_p=$(gitx "$REPO" rev-parse ${PARENT}:$FILE)
blob_c=$(gitx "$REPO" rev-parse ${CAND}:$FILE)
blob_fp=$(gitx "$REPO" rev-parse ${FIX}^:$FILE)
blob_f=$(gitx "$REPO" rev-parse ${FIX}:$FILE)
if [[ $blob_p != $BLOB_PARENT || $blob_c != $BLOB_CAND || $blob_fp != $BLOB_FIXPARENT || $blob_f != $BLOB_FIX ]]; then
  printf 'blob mismatch\n' >&2
  exit 1
fi

ns=$(gitx "$REPO" diff --name-only $PARENT $CAND)
if [[ $ns != $FILE ]]; then
  printf 'candidate not atomic terminals.py: %s\n' "$ns" >&2
  exit 1
fi

msg=$(gitx "$REPO" log -1 --format=%B $CAND)
if [[ $msg != *'Co-authored-by: Claude Opus 4.7 (1M context) <noreply@anthropic.com>'* ]]; then
  printf 'missing Claude trailer on candidate\n' >&2
  exit 1
fi
if [[ $msg != *'#25157'* ]]; then
  printf 'missing PR 25157 on candidate\n' >&2
  exit 1
fi

gitx "$REPO" diff $PARENT $CAND -- $FILE | grep -F 'for _ in range(8):' >/dev/null
gitx "$REPO" diff $PARENT $CAND -- $FILE | grep -F 'decoded = unquote(path)' >/dev/null
gitx "$REPO" diff ${FIX}^ $FIX -- $FILE | grep -F 'if unquote(decoded) != decoded:' >/dev/null

python3 - <<'PY'
import json
from pathlib import Path
from urllib.parse import unquote
import posixpath
owned = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-frvj-hostile2-grok46-medium")

def parent_sanitize(p):
    decoded = unquote(p)
    cleaned = posixpath.normpath(decoded).lstrip("/")
    if cleaned.startswith("..") or cleaned == ".":
        return None
    return cleaned

def cand_sanitize(p):
    decoded = p
    for _ in range(8):
        once = unquote(decoded)
        if once == decoded:
            break
        decoded = once
    cleaned = posixpath.normpath(decoded).lstrip("/")
    if cleaned.startswith("..") or cleaned == ".":
        return None
    return cleaned

def fix_sanitize(p):
    decoded = p
    for _ in range(8):
        once = unquote(decoded)
        if once == decoded:
            break
        decoded = once
    if unquote(decoded) != decoded:
        return None
    cleaned = posixpath.normpath(decoded).lstrip("/")
    if cleaned.startswith("..") or cleaned == ".":
        return None
    return cleaned

def enc(s, rounds):
    out = "".join(f"%{b:02X}" for b in s.encode())
    for _ in range(rounds - 1):
        out = out.replace("%", "%25")
    return out

payload = "../admin/system"
assert cand_sanitize(enc(payload, 8)) is None
nine = cand_sanitize(enc(payload, 9))
assert nine == "%2E%2E%2F%61%64%6D%69%6E%2F%73%79%73%74%65%6D"
assert fix_sanitize(enc(payload, 9)) is None
assert parent_sanitize(enc(payload, 2)) is not None
assert parent_sanitize(enc(payload, 1)) is None
rows = json.loads((owned / "facts/nine_x.json").read_text())
assert rows[3]["rounds"] == 9
assert rows[3]["cand"] == nine
assert rows[3]["fix"] is None
print("9x behavior ok")
PY

python3 - <<'PY'
import json, os, zipfile
from pathlib import Path
owned = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-frvj-hostile2-grok46-medium")
tmp = Path(os.environ["FRVJ_REPLAY_TMP"])
pypi = json.loads((owned / "facts/pypi.json").read_text())

def ascii_norm(s: str) -> str:
    return s.replace("\u2014", "--")

def extract(whl: Path) -> str:
    with zipfile.ZipFile(whl) as z:
        names = [n for n in z.namelist() if n.endswith("open_webui/routers/terminals.py")]
        text = z.read(names[0]).decode()
    lines = text.splitlines(True)
    start = next(i for i, l in enumerate(lines) if l.startswith("def _sanitize_proxy_path"))
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].strip() and not lines[j].startswith((" ", "\t")):
            end = j
            break
    return ascii_norm("".join(lines[start:end]).rstrip() + "\n")

p96 = extract(tmp / pypi["0.9.6"]["filename"])
p10 = extract(tmp / pypi["0.10.0"]["filename"])
assert p96 == (owned / "diffs/sanitizer.cand.py").read_text()
assert p10 == (owned / "diffs/sanitizer.fix.py").read_text()
assert "for _ in range(8):" in p96
assert "if unquote(decoded) != decoded:" not in p96
assert "if unquote(decoded) != decoded:" in p10
print("wheel sanitizer equality ok")
PY

python3 - <<'PY'
import json
from pathlib import Path
root = Path("/home/hanqing/agents/ai-slop")
owned = root / "autoresearch/herdr-260814-frvj-hostile2-grok46-medium"
uniq = json.loads((owned / "facts/uniqueness.json").read_text())
assert uniq["canonical_layer"] == "L0 canonical85"
assert uniq["counted_strict"] == 85
assert uniq["prospective_count"] == 86
assert uniq["ledger_sha256"] == "2927924603a76a2565d9c244c3b79f70d4693c127f1bc6fcc63e8099172ba568"
assert uniq["summary_sha256"] == "47209f841a5cb793ae6146b4247990fd2af1d4e50d3d881e0b53904f850bbd0c"
assert uniq["uniqueness_source"] == "canonical85_counted_ids_only"
ledger = root / "autoresearch/orchestrator-260814-ghsa200-canonical85/ledger.jsonl"
summary = json.loads((root / "autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json").read_text())
assert summary["canonical_strict_count"] == 85
ids = []
for line in ledger.read_text().splitlines():
    if not line.strip():
        continue
    o = json.loads(line)
    if o.get("counted") is True and o.get("record_kind") == "STRICT_RELEASED_CASE":
        ids.append(o.get("case_id"))
assert len(ids) == 85
assert len(set(ids)) == 85
assert "GHSA-FRVJ-C5QP-XJ4W" not in ids
assert "GHSA-R2WG-2MCR-66RV" not in ids
case = json.loads((owned / "case.json").read_text())
res = json.loads((owned / "result.json").read_text())
assert case["verdict"] == "KEEP"
assert case["countable"] is False
assert case["worker_pass_is_proposal_only"] is True
assert case["current_leader_accepted_count"] == 85
assert case["prospective_count"] == 86
assert res["packet_delta"] == 0
assert res["current_leader_accepted_count"] == 85
assert res["canonical85_strict_count"] == 85
assert res["prospective_count"] == 86
assert res["verdicts"]["KEEP"] == 1
assert res["conservation"]["holds"] is True
assert res["conservation"]["assigned"] == 1
assert res["conservation"]["reviewed"] == 1
assert res["conservation"]["unreviewed"] == 0
print("uniqueness and conservation ok")
PY

print "REPLAY_OK reviewed=1 KEEP_proposal=1 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=85 prospective_count=86"
