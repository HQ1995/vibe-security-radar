#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-cf4-b0-history-grok46-low.
# English only. No credentials. No clone/commit/push. Caches read-only.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-cf4-b0-history-grok46-low
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json
REV=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
UNR=/home/hanqing/.cache/cve-analyzer/advisory-database
MM=/home/hanqing/.cache/cve-analyzer/repos/mattermost_mattermost
LF=/home/hanqing/.cache/cve-analyzer/repos/liferay_liferay-portal

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
  local errf
  errf=$(mktemp /tmp/cf4-b0h-giterr.XXXXXX)
  set +e
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
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

require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/result.json"
require_file "$OWNED/report.md"
require_file "$CONTRACT"
require_file "$LEDGER"
require_file "$SUMMARY"
require_dir "$REV/advisories/github-reviewed"
require_dir "$UNR/advisories/unreviewed"

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
expect_hash "$SUMMARY" 81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921

expect_eq "$(gitx "$REV" rev-parse HEAD)" f2c6ab3202aeafb36fbea6e76d892532acfca1a6 reviewed_head
expect_eq "$(gitx "$UNR" rev-parse HEAD)" 39d8887723797efc1804585dd06585c9fd751226 unreviewed_head
expect_eq "$(/usr/bin/test -d "$REV/advisories/unreviewed" && echo yes || echo no)" no f2c6_unreviewed_absent
expect_eq "$(/usr/bin/python3 -c 'import os; print(sum(1 for r,ds,fs in os.walk("'"$REV"'/advisories/github-reviewed") for f in fs if f.startswith("GHSA-") and f.endswith(".json")))')" 34389 reviewed_file_count
expect_eq "$(/usr/bin/python3 -c 'import os; print(sum(1 for r,ds,fs in os.walk("'"$UNR"'/advisories/unreviewed") for f in fs if f.startswith("GHSA-") and f.endswith(".json")))')" 317316 unreviewed_file_count

/usr/bin/python3 - <<'PY'
import hashlib, json, os, re, pathlib
ROOT = pathlib.Path("/home/hanqing/agents/ai-slop")
OWNED = ROOT / "autoresearch/herdr-260814-cf4-b0-history-grok46-low"
REV = pathlib.Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database")
UNR = pathlib.Path("/home/hanqing/.cache/cve-analyzer/advisory-database")
REPOS = pathlib.Path("/home/hanqing/.cache/cve-analyzer/repos")
GHSA = re.compile(r"GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
COMMIT_RE = re.compile(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})")
PKG_RE = re.compile(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$")
ADV_RE = re.compile(r"https://github\.com/([^/]+)/([^/]+)/security/advisories/(GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4})", re.I)
KEYS = {"case_id","ghsa_id","reviewed_case_ids","assigned_ids","strict_released_case_ids"}
NAMES = {"assignment.jsonl","cases.jsonl","result.json","selected.jsonl","selected.json","ledger.jsonl","summary.json"}

def norm(s):
    if not isinstance(s, str):
        return None
    s = s.strip().upper()
    return s if GHSA.fullmatch(s) else None

def harvest(obj, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in KEYS:
                if isinstance(v, str):
                    n = norm(v)
                    if n:
                        out.add(n)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, str):
                            n = norm(item)
                            if n:
                                out.add(n)
            elif isinstance(v, (dict, list)):
                harvest(v, out)
    elif isinstance(obj, list):
        for item in obj:
            harvest(item, out)

excluded = set()
ar = ROOT / "autoresearch"
for p in ar.iterdir():
    if not p.is_dir():
        continue
    if not (p.name.startswith("herdr-") or p.name.startswith("orchestrator-")):
        continue
    if p.name == "herdr-260814-cf4-b0-history-grok46-low":
        continue
    for n in NAMES:
        fp = p / n
        if not fp.is_file():
            continue
        text = fp.read_text(encoding="utf-8", errors="replace")
        if fp.suffix == ".jsonl":
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    harvest(json.loads(line), excluded)
                except Exception:
                    pass
        else:
            try:
                harvest(json.loads(text), excluded)
            except Exception:
                pass
canon = set(json.loads((ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json").read_text())["strict_released_case_ids"])
assert len(canon) == 88
assert "GHSA-MP6X-97XJ-9X62" in excluded
assigned = [json.loads(line)["case_id"] for line in (OWNED / "assignment.jsonl").read_text().splitlines() if line.strip()]
cases = [json.loads(line)["case_id"] for line in (OWNED / "cases.jsonl").read_text().splitlines() if line.strip()]
assert assigned == cases == []
result = json.loads((OWNED / "result.json").read_text())
assert result["counts"]["PASS_PROPOSAL"] == 0
assert result["conservation"]["assigned"] == 0
assert result["conservation"]["did_not_pad"] is True
assert result["inspect"]["inspected"] == 600
assert result["inspect"]["shortfall"] == 12
assert result["inspect"]["hit_count"] == 0
assert result["inspect"]["stop_rule"] == "inspected_prefix_600_shortfall_12"
assert result["advisory_sources"]["reviewed_head"] == "f2c6ab3202aeafb36fbea6e76d892532acfca1a6"
assert result["advisory_sources"]["unreviewed_head"] == "39d8887723797efc1804585dd06585c9fd751226"
clone_names = set(os.listdir(REPOS))

def clone_exists(repo):
    if not repo:
        return False
    owner, name = repo.split("/", 1)
    return f"{owner}_{name}" in clone_names

def load(base, subtree, kind):
    rows = {}
    for dirpath, ds, fs in os.walk(base / subtree):
        for f in fs:
            if not (f.startswith("GHSA-") and f.endswith(".json")):
                continue
            obj = json.loads((pathlib.Path(dirpath) / f).read_text(encoding="utf-8"))
            gid = norm(obj.get("id") or f[:-5])
            if not gid:
                continue
            refs = obj.get("references") or []
            commits = []
            repo = None
            has_adv = False
            for ref in refs:
                url = (ref or {}).get("url") or ""
                m = COMMIT_RE.search(url)
                if m:
                    repo = f"{m.group(1)}/{m.group(2)}"
                    commits.append(m.group(3).lower())
                if (ref or {}).get("type") == "PACKAGE":
                    m = PKG_RE.fullmatch(url.rstrip("/"))
                    if m and not repo:
                        repo = f"{m.group(1)}/{m.group(2)}"
                m = ADV_RE.search(url)
                if m and m.group(3).upper() == gid:
                    has_adv = True
                    repo = repo or f"{m.group(1)}/{m.group(2)}"
            published = obj.get("published") or ""
            rows[gid] = {"kind": kind, "withdrawn": bool(obj.get("withdrawn")), "repo": repo, "commits": commits, "has_adv": has_adv, "year": published[:4]}
    return rows
reviewed = load(REV, "advisories/github-reviewed", "github-reviewed")
unreviewed = load(UNR, "advisories/unreviewed", "unreviewed")
union = dict(unreviewed)
collisions = sum(1 for g in reviewed if g in union)
union.update(reviewed)
assert collisions == 135
assert len(reviewed) == 34389

def bucket(gid):
    return int(hashlib.sha256(gid.encode()).hexdigest(), 16) % 6
b0 = {g: r for g, r in union.items() if bucket(g) == 0 and not r["withdrawn"]}
eligible = {g: r for g, r in b0.items() if g not in excluded and g not in canon}
assert len(b0) == 58514
assert result["universe"]["eligible_after_exclude"] == len(eligible)
assert len(eligible) == 57203

def rank_tuple(gid, row):
    return (
        0 if row["kind"] == "github-reviewed" else 1,
        0 if (row["has_adv"] or row["commits"]) else 1,
        0 if row["year"] in ("2025", "2026") else 1,
        0 if clone_exists(row["repo"]) else 1,
        gid,
    )
ranked = sorted(eligible.items(), key=lambda kv: rank_tuple(kv[0], kv[1]))
prefix = [g for g, _ in ranked[:600]]
assert prefix[0] == "GHSA-23W4-RPC6-WPCC"
assert prefix[-1] == "GHSA-3V63-F83X-37X4"
assert all(eligible[g]["kind"] == "github-reviewed" for g in prefix)
assert all(bucket(g) == 0 for g in prefix)
print("bucket_exclusion_ok 0")
print("eligible", len(eligible))
print("prefix_head", prefix[0], "prefix_tail", prefix[-1])
print("excluded_structured", len(excluded))
print("canonical88", len(canon))
PY

anc() {
  if gitx "$1" merge-base --is-ancestor "$2" "$3"; then
    printf '0\n'
  else
    printf '1\n'
  fi
}

expect_eq "$(gitx "$LF" rev-parse '12a076172494707748325836b3d5236507be0490^{commit}')" 12a076172494707748325836b3d5236507be0490 liferay_fix_object
expect_eq "$(gitx "$MM" rev-parse '61651b0df7ea5db55d1e54f8d6fb5fce4149309c^{commit}')" 61651b0df7ea5db55d1e54f8d6fb5fce4149309c mm_fix
expect_eq "$(gitx "$MM" log -1 --format=%s 61651b0df7ea5db55d1e54f8d6fb5fce4149309c)" "User id auth control (#34441)" mm_fix_subj
expect_eq "$(anc "$MM" d78d59babeb994106e305531de50b8d515427396 61651b0df7ea5db55d1e54f8d6fb5fce4149309c)" 0 mm_ai_is_ancestor
expect_eq "$(gitx "$MM" log -1 --format=%s d78d59babeb994106e305531de50b8d515427396)" "Standardize request.CTX parameter naming to rctx (#33499)" mm_ai_subj

/usr/bin/python3 - <<'PY'
import subprocess
mm="/home/hanqing/.cache/cve-analyzer/repos/mattermost_mattermost"
fix="61651b0df7ea5db55d1e54f8d6fb5fce4149309c"
ai="d78d59babeb994106e305531de50b8d515427396"
parent=subprocess.check_output(["git","-C",mm,"log","-1","--format=%P",fix], stderr=subprocess.DEVNULL).decode().split()[0]
assert parent=="a21169e2a864565b0019eb8c00fa7de74901d19e"
diff=subprocess.check_output(["git","-C",mm,"diff","-U0",parent,fix,"--","server/channels/app/login.go"], stderr=subprocess.DEVNULL).decode()
deleted=set()
for line in diff.splitlines():
    if line.startswith(("+++","---","diff","index","@@")):
        continue
    if line.startswith("-"):
        s=line[1:].strip()
        if len(s)>12:
            deleted.add(s)
adiff=subprocess.check_output(["git","-C",mm,"show","--format=","-U0",ai,"--","server/channels/app/login.go"], stderr=subprocess.DEVNULL).decode()
added=set()
for line in adiff.splitlines():
    if line.startswith(("+++","---","diff","index","@@")):
        continue
    if line.startswith("+"):
        s=line[1:].strip()
        if len(s)>12:
            added.add(s)
assert len(deleted & added)==0
msg=subprocess.check_output(["git","-C",mm,"log","-1","--format=%B",ai], stderr=subprocess.DEVNULL).decode()
assert "Claude" in msg
print("proximity_rejected_overlap0")
PY

printf 'PASS_PROPOSAL 0\n'
printf 'assigned 0 shortfall 12 inspected 600\n'
printf 'REPLAY_OK\n'
