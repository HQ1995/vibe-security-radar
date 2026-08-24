#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-cf4-b3-topology-grok46-xhigh.
# English only. No credentials. No clone/fetch/commit/push. Shared caches read-only.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat
export PYTHONPATH=/home/hanqing/agents/ai-slop/cve-analyzer/src

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-cf4-b3-topology-grok46-xhigh
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json
ADV_R=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
ADV_U=/home/hanqing/.cache/cve-analyzer/advisory-database
HEAD_R=f2c6ab3202aeafb36fbea6e76d892532acfca1a6
HEAD_U=39d8887723797efc1804585dd06585c9fd751226

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

expect_eq() {
  if [[ $1 != "$2" ]]; then
    printf 'mismatch %s expected=%s got=%s\n' "$3" "$2" "$1" >&2
    exit 1
  fi
}

expect_hash() {
  local got
  got=$(/usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}')
  expect_eq "$got" "$2" "$1"
}

gitx() {
  local repo=$1
  shift
  local errf rc
  errf=$(mktemp /tmp/cf4-b3-giterr.XXXXXX)
  setopt localoptions noerrexit
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  rc=$?
  if [[ -s $errf ]]; then
    /usr/bin/grep -vE 'unable to normalize alternate object path|lazy fetching disabled' "$errf" >&2 || true
  fi
  rm -f "$errf"
  return $rc
}

require_file() {
  if [[ ! -f $1 ]]; then
    printf 'missing %s\n' "$1" >&2
    exit 1
  fi
}

require_dir() {
  if [[ ! -d $1 ]]; then
    printf 'missing %s\n' "$1" >&2
    exit 1
  fi
}

require_absent() {
  if [[ -e $1 ]]; then
    printf 'must be absent: %s\n' "$1" >&2
    exit 1
  fi
}

require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/result.json"
require_file "$OWNED/report.md"
require_file "$OWNED/replay.zsh"
require_file "$CONTRACT"
require_file "$LEDGER"
require_file "$SUMMARY"
require_dir "$ADV_R/advisories/github-reviewed"
require_dir "$ADV_U/advisories/unreviewed"
require_absent "$ADV_R/advisories/unreviewed"
require_absent "$OWNED/work"
require_absent "$OWNED/notes"
require_absent "$OWNED/pages"
require_absent "$OWNED/clones"

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
expect_hash "$SUMMARY" 81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921

rh=$(gitx "$ADV_R" rev-parse HEAD)
uh=$(gitx "$ADV_U" rev-parse HEAD)
expect_eq "$rh" "$HEAD_R" reviewed_head
expect_eq "$uh" "$HEAD_U" unreviewed_head

n_assign=$(/usr/bin/wc -l < "$OWNED/assignment.jsonl" | /usr/bin/tr -d ' ')
n_cases=$(/usr/bin/wc -l < "$OWNED/cases.jsonl" | /usr/bin/tr -d ' ')
expect_eq "$n_assign" 12 assignment_rows
expect_eq "$n_cases" 12 cases_rows

n_owned=$(/usr/bin/ls -1 "$OWNED" | /usr/bin/wc -l | /usr/bin/tr -d ' ')
expect_eq "$n_owned" 5 owned_file_count

MEM=/home/hanqing/.cache/cve-analyzer/repos/usememos_memos
PS=/home/hanqing/.cache/cve-analyzer/repos/mmaitre314_picklescan
MI=/home/hanqing/.cache/cve-analyzer/repos/minio_minio
NT=/home/hanqing/.cache/cve-analyzer/repos/netty_netty
CD=/home/hanqing/.cache/cve-analyzer/repos/line_centraldogma
KY=/home/hanqing/.cache/cve-analyzer/repos/kyverno_kyverno
QL=/home/hanqing/.cache/cve-analyzer/repos/whyour_qinglong
MM=/home/hanqing/.cache/cve-analyzer/repos/mattermost_mattermost
GB=/home/hanqing/.cache/cve-analyzer/repos/osrg_gobgp
KL=/home/hanqing/.cache/cve-analyzer/repos/keylime_keylime
HW=/home/hanqing/.cache/ghsa200-worker-clones/red-upgrade-b-direct/clones/nesquena__hermes-webui
require_dir "$MEM"
require_dir "$PS"
require_dir "$MI"
require_dir "$NT"
require_dir "$CD"
require_dir "$KY"
require_dir "$QL"
require_dir "$MM"
require_dir "$GB"
require_dir "$KL"
require_dir "$HW"

require_file "$ADV_R/advisories/github-reviewed/2025/12/GHSA-mg56-wc4q-rw4w/GHSA-mg56-wc4q-rw4w.json"
require_file "$ADV_U/advisories/unreviewed/2026/04/GHSA-pwfc-qm9r-p6h4/GHSA-pwfc-qm9r-p6h4.json"
require_absent "$ADV_R/advisories/unreviewed/2026/04/GHSA-pwfc-qm9r-p6h4/GHSA-pwfc-qm9r-p6h4.json"
require_absent "$ADV_R/advisories/github-reviewed/2026/04/GHSA-pwfc-qm9r-p6h4/GHSA-pwfc-qm9r-p6h4.json"

python3 - "$OWNED" "$SUMMARY" "$ROOT" "$ADV_R" "$ADV_U" <<'PY'
import hashlib, json, os, re, subprocess, sys
from pathlib import Path

owned, summary_p, root, adv_r, adv_u = sys.argv[1:]
root = Path(root)
owned = Path(owned)
adv_r = Path(adv_r)
adv_u = Path(adv_u)
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(r"ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16}")
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
ID_FIELDS = {"case_id", "ghsa_id", "reviewed_case_ids", "assigned_ids", "strict_released_case_ids"}
ARTIFACT_NAMES = {
    "assignment.jsonl", "cases.jsonl", "result.json", "selected.jsonl",
    "queue.jsonl", "ledger.jsonl", "summary.json",
}
SKIP_DIR_PARTS = {"work", "notes", "pages", "snapshot", "clones", "cache", "tmp"}
OWNED_NAME = "herdr-260814-cf4-b3-topology-grok46-xhigh"
GATES = [
    "identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate",
    "fix_reversal_gate", "release_gate", "uniqueness_gate",
]
FROZEN = [
    "GHSA-MG56-WC4Q-RW4W", "GHSA-6556-FWC2-FG2P", "GHSA-VV6J-3G6G-2PVJ",
    "GHSA-JJJJ-JWHF-8RGR", "GHSA-FGHV-69VJ-QJ49", "GHSA-4HR2-XF7W-JF76",
    "GHSA-FPJQ-C37H-CQCV", "GHSA-XJ37-QJG2-XWV2", "GHSA-X3HX-CH7P-8XGG",
    "GHSA-PW7P-7FQV-HPJ8", "GHSA-XH5W-G8GQ-R3V9", "GHSA-PWFC-QM9R-P6H4",
]

def load_jsonl(p):
    return [json.loads(l) for l in Path(p).read_text().splitlines() if l.strip()]

for name in ("assignment.jsonl", "cases.jsonl", "result.json", "report.md", "replay.zsh"):
    raw = (owned / name).read_text(encoding="utf-8")
    assert raw.endswith("\n") and raw.isascii()
    assert not han.search(raw) and not secret.search(raw)
    for line in raw.splitlines():
        assert line == line.rstrip(" \t")

names = sorted(p.name for p in owned.iterdir())
assert names == ["assignment.jsonl", "cases.jsonl", "replay.zsh", "report.md", "result.json"]

assign = load_jsonl(owned / "assignment.jsonl")
cases = load_jsonl(owned / "cases.jsonl")
result = json.loads((owned / "result.json").read_text())
assert len(assign) == 12 and len(cases) == 12
ids = [r["case_id"] for r in assign]
assert ids == [r["case_id"] for r in cases] == FROZEN
assert len(set(ids)) == 12
assert all(a.get("hypothesis_not_verdict") is True for a in assign)
assert all(a.get("frozen") is True and a.get("bucket") == 3 for a in assign)

def bucket(ghsa: str) -> int:
    return int(hashlib.sha256(ghsa.upper().encode("ascii")).hexdigest(), 16) % 6

for cid in ids:
    assert bucket(cid) == 3, cid

assert result["conservation"]["equation"] == "12=11+1"
assert result["conservation"]["assigned"] == 12
assert result["conservation"]["reviewed"] == 11
assert result["conservation"]["unreviewed"] == 1
assert result["conservation"]["did_not_pad"] is True
assert result["counts"]["PASS_PROPOSAL"] == 0
assert result["PASS_PROPOSAL"] == []
assert result["terminal"] is True
assert result["canonical88_overlap"] == []
assert result["cve_aliases_counted"] is False
assert result["packet_delta"] == 0
assert result["seven_gates_exact_pass_required"] is True
assert result["canonical_ledger_edited"] is False
assert result["advisory_database"]["github_reviewed"]["head"] == "f2c6ab3202aeafb36fbea6e76d892532acfca1a6"
assert result["advisory_database"]["github_reviewed"]["subtree"] == "advisories/github-reviewed"
assert result["advisory_database"]["unreviewed"]["head"] == "39d8887723797efc1804585dd06585c9fd751226"
assert result["advisory_database"]["unreviewed"]["subtree"] == "advisories/unreviewed"
assert result["advisory_database"]["did_not_drop_unreviewed"] is True
assert result["per_case"]["GHSA-MG56-WC4Q-RW4W"] == "NARROW"
assert result["per_case"]["GHSA-FGHV-69VJ-QJ49"] == "NARROW"
assert result["counts"]["NARROW"] == 2
assert result["counts"]["REJECT"] == 10
assert "0 PASS_PROPOSAL" in (owned / "report.md").read_text()
ah = result["artifact_hashes"]
for name in ("assignment.jsonl", "cases.jsonl", "report.md", "replay.zsh"):
    got = hashlib.sha256((owned / name).read_bytes()).hexdigest()
    assert got == ah[name], (name, got, ah[name])
assert "result.json" not in ah

summary = json.loads(Path(summary_p).read_text())
strict = {str(x).upper() for x in summary["strict_released_case_ids"]}
assert len(strict) == 88
assert set(ids).isdisjoint(strict)

for r in cases:
    g = r["gates"]
    assert all(k in g for k in GATES)
    assert r["seven_gates_exact_pass"] is False
    assert r["countable_proposal"] is False
    assert r["authorship_transfer_from_member_to_carrier"] is False
    assert r["in_canonical88_strict"] is False
    if r["verdict"] == "PASS":
        raise SystemExit("unexpected PASS")
    assert bucket(r["case_id"]) == 3

assert [a["advisory_source"] for a in assign].count("f2c6_github-reviewed") == 11
assert [a["advisory_source"] for a in assign].count("39d888_unreviewed") == 1
assert assign[-1]["case_id"] == "GHSA-PWFC-QM9R-P6H4"
assert assign[-1]["github_reviewed"] is False

for a in assign:
    if a["advisory_source"] == "f2c6_github-reviewed":
        p = adv_r / a["advisory_path"]
        assert a["advisory_path"].startswith("advisories/github-reviewed/")
    else:
        p = adv_u / a["advisory_path"]
        assert a["advisory_path"].startswith("advisories/unreviewed/")
    assert p.is_file(), p
    obj = json.loads(p.read_text())
    assert obj.get("id", "").upper() == a["case_id"]
    assert not obj.get("withdrawn")
    db = obj.get("database_specific") or {}
    if a["github_reviewed"]:
        assert db.get("github_reviewed") is True
    else:
        assert db.get("github_reviewed") is False

def collect_ids(obj, acc, in_field=False):
    if isinstance(obj, dict):
        for k, v in obj.items():
            collect_ids(v, acc, in_field or k in ID_FIELDS)
    elif isinstance(obj, list):
        for x in obj:
            collect_ids(x, acc, in_field)
    elif in_field and isinstance(obj, str):
        s = obj.strip().upper()
        if GHSA_RE.match(s):
            acc.add(s)

excluded = set()
auto = root / "autoresearch"
for path in auto.rglob("*"):
    if not path.is_file() or path.name not in ARTIFACT_NAMES:
        continue
    if SKIP_DIR_PARTS & set(path.parts):
        continue
    if OWNED_NAME in path.parts:
        continue
    rel = path.relative_to(auto)
    top = rel.parts[0] if rel.parts else ""
    if top.startswith("herdr-260814-cf4-") and top != OWNED_NAME:
        rj_path = auto / top / "result.json"
        if not rj_path.exists():
            continue
        try:
            rj = json.loads(rj_path.read_text())
        except Exception:
            continue
        if not (rj.get("terminal") is True or str(rj.get("status", "")).upper().startswith("TERMINAL")):
            continue
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        continue
    if path.suffix == ".jsonl":
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                collect_ids(json.loads(line), excluded)
            except Exception:
                continue
    else:
        try:
            collect_ids(json.loads(text), excluded)
        except Exception:
            continue
assert len(excluded) >= 8056
# Freeze-time conservation: assigned IDs were outside the 8056-ID freeze and
# canonical88. Live rglob may grow after freeze; do not invalidate the freeze
# on later non-cf4 terminals. CF4 sibling terminals must stay disjoint.
for lane in sorted((root / "autoresearch").glob("herdr-260814-cf4-*")):
    if lane.name == OWNED_NAME:
        continue
    rj_path = lane / "result.json"
    aj_path = lane / "assignment.jsonl"
    if not (rj_path.is_file() and aj_path.is_file()):
        continue
    try:
        rj = json.loads(rj_path.read_text())
    except Exception:
        continue
    if not (rj.get("terminal") is True or str(rj.get("status", "")).upper().startswith("TERMINAL")):
        continue
    sib = {json.loads(l)["case_id"].upper() for l in aj_path.read_text().splitlines() if l.strip()}
    assert set(ids).isdisjoint(sib), sorted(set(ids) & sib)

env = dict(os.environ)
env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1", GIT_PAGER="cat")

def git(repo, *args):
    r = subprocess.run(
        ["git", "--no-optional-locks", "-c", "gc.auto=0", "-C", repo, *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
    )
    for line in (r.stderr or "").splitlines():
        if not line:
            continue
        if "unable to normalize alternate object path" in line:
            continue
        if "lazy fetching disabled" in line:
            continue
        if "git cat-file: could not get object info" in line:
            continue
        raise SystemExit(line)
    return r

def peel(repo, tag):
    r = git(repo, "rev-parse", f"{tag}^{{commit}}")
    assert r.returncode == 0, (repo, tag, r.stderr)
    return r.stdout.strip()

def n_parents(repo, sha):
    r = git(repo, "rev-list", "--parents", "-n1", sha)
    return len(r.stdout.split()) - 1

MEM = "/home/hanqing/.cache/cve-analyzer/repos/usememos_memos"
PS = "/home/hanqing/.cache/cve-analyzer/repos/mmaitre314_picklescan"
MI = "/home/hanqing/.cache/cve-analyzer/repos/minio_minio"
NT = "/home/hanqing/.cache/cve-analyzer/repos/netty_netty"
CD = "/home/hanqing/.cache/cve-analyzer/repos/line_centraldogma"
KY = "/home/hanqing/.cache/cve-analyzer/repos/kyverno_kyverno"
QL = "/home/hanqing/.cache/cve-analyzer/repos/whyour_qinglong"
MM = "/home/hanqing/.cache/cve-analyzer/repos/mattermost_mattermost"
GB = "/home/hanqing/.cache/cve-analyzer/repos/osrg_gobgp"
KL = "/home/hanqing/.cache/cve-analyzer/repos/keylime_keylime"
HW = "/home/hanqing/.cache/ghsa200-worker-clones/red-upgrade-b-direct/clones/nesquena__hermes-webui"

C_MEM = "769dcd0cf9be83d472829f6e7903b201e42f6b3c"
CLAUDE_MEM = "1a3298554b76bb85bf9fe0925933b68bd7808601"
assert peel(MEM, "v0.25.2") == "0c0d2a629428ee72f9af074a3fa137ace256d904"
assert peel(MEM, "v0.25.3") == "e17cd163c6c37726f8397c8f426d585b540c9562"
assert git(MEM, "merge-base", "--is-ancestor", C_MEM, "v0.25.3").returncode == 0
assert git(MEM, "merge-base", "--is-ancestor", CLAUDE_MEM, "v0.25.3").returncode == 1
assert n_parents(MEM, C_MEM) == 1
assert n_parents(MEM, CLAUDE_MEM) == 1
assert git(MEM, "log", "-1", "--format=%an", C_MEM).stdout.strip() == "Florian Dewald"
assert git(MEM, "log", "-1", "--format=%an", CLAUDE_MEM).stdout.strip() == "Claude"
b_closer = git(MEM, "rev-parse", f"{C_MEM}:server/router/api/v1/user_service.go").stdout.strip()
b_old = git(MEM, "rev-parse", "v0.25.2:server/router/api/v1/user_service.go").stdout.strip()
b_new = git(MEM, "rev-parse", "v0.25.3:server/router/api/v1/user_service.go").stdout.strip()
b_ai = git(MEM, "rev-parse", f"{CLAUDE_MEM}:server/router/api/v1/user_service.go").stdout.strip()
assert b_closer == "e5de08db3d841bc4fc109a96a17725fd6ac1007a"
assert b_old == "3bead551ee9d32b43ce0e929f6f51bf75d94db6f"
assert b_new == "8ca617734c0c20187b1723145286e6ffc866dec7"
assert b_ai == "b5e452fc3954525ae526fc0057d48bb154bf88f8"
assert len({b_closer, b_old, b_new, b_ai}) == 4
assert git(MEM, "cat-file", "-t", "75deb94f5058b4a1b439726305a71187fca3e891").returncode != 0

assert peel(PS, "v0.0.33") == "70c1c6c31beb6baaf52c8db1b6c3c0e84a6f9dab"
assert peel(PS, "v0.0.32") == "d3273f4225da08c0998177a5ac0588724fa4bba0"
assert peel(PS, "v0.0.28") == "7f994d62084fe43f1cffdef2f9bae6923344ef53"
assert peel(PS, "v0.0.27") == "58983e1c20973ac42f2df7ff15d7c8cd32f9b688"
assert n_parents(PS, "70c1c6c31beb6baaf52c8db1b6c3c0e84a6f9dab") == 1
assert n_parents(PS, "7f994d62084fe43f1cffdef2f9bae6923344ef53") == 1

MI_NEW = "RELEASE.2025-10-15T17-29-55Z"
MI_OLD = "RELEASE.2025-09-07T16-13-09Z"
MI_C = "c1a49490c78e9c3ebcad86ba0662319138ace190"
assert peel(MI, MI_OLD) == "07c3a429bfed433e49018cb0f78a52145d4bedeb"
assert git(MI, "merge-base", "--is-ancestor", MI_C, MI_NEW).returncode == 0
assert git(MI, "merge-base", "--is-ancestor", MI_C, MI_OLD).returncode == 1
assert n_parents(MI, MI_C) == 1

NT_C = "edb55fd8e0a3bcbd85881e423464f585183d1284"
assert git(NT, "merge-base", "--is-ancestor", NT_C, "netty-4.2.5.Final").returncode == 0
assert git(NT, "merge-base", "--is-ancestor", NT_C, "netty-4.2.4.Final").returncode == 1
assert n_parents(NT, NT_C) == 1
assert git(NT, "log", "-1", "--format=%an", NT_C).stdout.strip() == "Norman Maurer"

CD_C = "95e7bbd77266493e4ec70b670bd91fa3e3289de0"
assert peel(CD, "centraldogma-0.78.0") == "36231f7a48fd90738d02d6b6395e0b75428ff10f"
assert git(CD, "merge-base", "--is-ancestor", CD_C, "centraldogma-0.78.0").returncode == 0
assert n_parents(CD, CD_C) == 1

KY76 = "76c8fdbe87328722e099e1fd44c3f21c9f7809cb"
KY80 = "80e728c2283a0c65e5adb02d8a907106e6ebe7e3"
assert git(KY, "merge-base", "--is-ancestor", KY80, "v1.16.4").returncode == 0
assert git(KY, "merge-base", "--is-ancestor", KY76, "v1.16.4").returncode == 1
assert git(KY, "merge-base", "--is-ancestor", KY76, "v1.17.2").returncode == 0
assert n_parents(KY, KY76) == 1 and n_parents(KY, KY80) == 1

QL_C = "6bec52dca158481258315ba0fc2f11206df7b719"
assert peel(QL, "v2.20.1") == QL_C
assert git(QL, "merge-base", "--is-ancestor", QL_C, "v2.20.2").returncode == 0
assert n_parents(QL, QL_C) == 1
assert git(QL, "log", "-1", "--format=%an", QL_C).stdout.strip() == "Copilot"

MM_C = "c8d66301415d5b447df0e829bdbaa92e8a83ecf8"
assert git(MM, "merge-base", "--is-ancestor", MM_C, "v11.0.0-alpha.1").returncode == 0
assert n_parents(MM, MM_C) == 1

GB_F = "9ce8936672ebc07df524da77fa4c6ae26d92be6d"
GB_A = "38c64c91204c0acf615eb38f6e5b69e81139a162"
assert git(GB, "merge-base", "--is-ancestor", GB_F, "v4.4.0").returncode == 0
assert git(GB, "merge-base", "--is-ancestor", GB_F, "v4.3.0").returncode == 1
assert git(GB, "merge-base", "--is-ancestor", GB_A, GB_F).returncode == 0
d_ai = git(GB, "diff", f"{GB_A}^", GB_A, "--", "pkg/packet/bgp/bgp.go").stdout
d_fix = git(GB, "diff", f"{GB_F}^", GB_F, "--", "pkg/packet/bgp/bgp.go").stdout
assert "DecodeFromBytes" not in d_ai
assert "DecodeFromBytes" in d_fix
assert n_parents(GB, GB_F) == 1

KL_C = "e1ae8de1f7b1385eaeec66572a92ff1338e6e157"
assert git(KL, "merge-base", "--is-ancestor", KL_C, "v7.13.0").returncode == 0
assert git(KL, "merge-base", "--is-ancestor", KL_C, "v7.12.0").returncode == 1
assert git(KL, "diff-tree", "--no-commit-id", "--name-only", "-r", KL_C).stdout.strip() == "keylime/cloud_verifier_tornado.py"

HW_C = "3cc5839bf303fa6758bfdac538507407a2929655"
assert n_parents(HW, HW_C) == 1
assert git(HW, "log", "-1", "--format=%an", HW_C).stdout.strip() == "nesquena-hermes"

sys.path.insert(0, str(root / "cve-analyzer/src"))
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import matches_for_commit

def git_log(clone, sha):
    rec = git(clone, "log", "-1", "--format=%H%n%an%n%ae%n%cn%n%ce%n%aI%n%B", sha)
    assert rec.returncode == 0
    parts = rec.stdout.split("\n", 6)
    return CommitInfo(
        sha=parts[0].strip(), author_name=parts[1], author_email=parts[2],
        committer_name=parts[3], committer_email=parts[4],
        authored_date=parts[5], message=parts[6],
    )

assert matches_for_commit(git_log(MEM, C_MEM)) == ()
assert matches_for_commit(git_log(MEM, CLAUDE_MEM))
assert matches_for_commit(git_log(PS, "70c1c6c31beb6baaf52c8db1b6c3c0e84a6f9dab")) == ()
assert matches_for_commit(git_log(QL, QL_C))
assert matches_for_commit(git_log(MM, MM_C))
assert matches_for_commit(git_log(GB, GB_F)) == ()
assert matches_for_commit(git_log(GB, GB_A))
assert matches_for_commit(git_log(HW, HW_C)) == ()

print("conservation assigned=12 reviewed=11 unreviewed=1 equation=12=11+1")
print("canonical88=88 overlap=0 bucket=3 frozen=12 PASS_PROPOSAL=0 NARROW=2 REJECT=10")
print("sources reviewed=f2c6ab3202aeafb36fbea6e76d892532acfca1a6 subtree=advisories/github-reviewed")
print("sources unreviewed=39d8887723797efc1804585dd06585c9fd751226 subtree=advisories/unreviewed")
print("union_collisions_f2c6_wins=1 did_not_drop_unreviewed=1")
PY

printf 'REPLAY_OK inspected=12 PASS_PROPOSAL=0 conservation=12=11+1\n'
