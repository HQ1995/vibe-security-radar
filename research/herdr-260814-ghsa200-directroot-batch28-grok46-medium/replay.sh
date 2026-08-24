#!/usr/bin/env zsh
set -euo pipefail

# Fail-fast read-only offline replay.
# Do not fetch, clone, commit, push, or rerun ranking.

export GIT_OPTIONAL_LOCKS=0

ROOT=/home/hanqing/agents/ai-slop
cd "$ROOT"

OWNED=autoresearch/herdr-260814-ghsa200-directroot-batch28-grok46-medium
FIRST=autoresearch/herdr-260813-ghsa200-directroot-mining-grok46-xhigh
ADB=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database

hash_file() {
  sha256sum -- "$1" | awk '{print $1}'
}

[[ -f "$OWNED/result.json" ]]
[[ -f "$OWNED/cases.jsonl" ]]
[[ -f "$OWNED/report.md" ]]
[[ -f "$OWNED/replay.sh" ]]
[[ -f "$OWNED/sha256.txt" ]]
[[ -f "$OWNED/work/selected-20.jsonl" ]]
[[ -f "$OWNED/selected-20.jsonl" ]]
[[ -f "$FIRST/work/selected-30.jsonl" ]]
[[ -f "$FIRST/work/rank-hits.jsonl" ]]
[[ -d "$ADB/.git" ]]

[[ "$(hash_file autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md)" == "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-ghsa200-leader/baseline.json)" == "d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl)" == "e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl)" == "1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl)" == "0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh/result.json)" == "c50b878583f3b09f37d7c88638ea179e75cf6b0ccf2e4ade689f2d673f7b0829" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh/cases.jsonl)" == "d4d3c96ba0a60214971ab88f3de7adce1edfc27f39a388906600aad91b5c1889" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-commitfirst-gn/ai-commit-scans.jsonl)" == "a6d7ca1584dbeb1596c57643092df0178001925efe0de60ca3eee5f72182481a" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-commitfirst-af/ai-commits.jsonl)" == "9659e93e82df4428df361507c6728ac83988211b0282ffbc3c12e3aba529d6d0" ]]
[[ "$(hash_file /home/hanqing/.cache/ghsa200-worker-clones/commit-oz/work/ai_mine.jsonl)" == "047bbb068b09194a59a934117fec1448563e073147bf2e005d53f427bdc8c18a" ]]
[[ "$(hash_file "$FIRST/work/selected-30.jsonl")" == "908f64f5f00195dae78574e86e9379f0b65cdd34c92ed1217c18702e35c59365" ]]
[[ "$(hash_file "$FIRST/work/rank-hits.jsonl")" == "7247f2cd6d3835385eb96a1acad945702b15cd8a618b0465bf73551de0af7e49" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-canonical72-dedupe-grok46-medium/result.json)" == "fb3b97c7b5d207119cc22d255ba48cbda568d56c8fffb447fb0e58ac8878f4fb" ]]
[[ "$(hash_file autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json)" == "699f6160b6ecb9c9ce2cdae257c9a12dbdf4f7ef8a925196fcfd4fcf0b1140d8" ]]
[[ "$(hash_file autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json)" == "dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c" ]]
[[ "$(hash_file autoresearch/orchestrator-260814-ghsa200-canonical81/ledger.jsonl)" == "3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9" ]]
[[ "$(git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$ADB" rev-parse HEAD)" == "a42c436870111aa3f221257c9d56126a93173ccc" ]]
[[ "$(hash_file "$OWNED/work/selected-20.jsonl")" == "5ed204c376024839e6d16ae30f2305afc0ce951832da1594a41d1a26ed567ef2" ]]
[[ "$(hash_file "$OWNED/selected-20.jsonl")" == "5ed204c376024839e6d16ae30f2305afc0ce951832da1594a41d1a26ed567ef2" ]]
[[ "$(hash_file autoresearch/herdr-260814-ghsa200-directroot-batch27-grok46-high/work/selected-30.jsonl)" == "b0fa717b15971eb9ea9d96ec9aa9b68ff7aeb56f07c91e50c2dd594f38af3923" ]]
[[ "$(hash_file autoresearch/herdr-260814-ghsa200-directroot-batch27-grok46-high/work/unreviewed-hit-ids.txt)" == "$(python3 -c "import hashlib,pathlib; p=pathlib.Path('autoresearch/herdr-260814-ghsa200-directroot-batch27-grok46-high/work/unreviewed-hit-ids.txt'); print(hashlib.sha256(p.read_bytes()).hexdigest())")" ]]
[[ "$(hash_file autoresearch/herdr-260813-ghsa200-directroot-batch3-grok46-xhigh/work/selected-30.jsonl)" == "$(hash_file autoresearch/herdr-260814-ghsa200-directroot-batch3-grok46-xhigh/work/selected-30.jsonl)" ]]

python3 - "$OWNED" "$FIRST" <<'PY'
import hashlib, json, re, sys
from pathlib import Path

owned = Path(sys.argv[1])
first = Path(sys.argv[2])
han = re.compile(r"[\u3400-\u9fff]")
secret = re.compile(r"BEGIN (RSA |OPENSSH )?PRIVATE KEY|sk_live_[0-9A-Za-z]+|xox[baprs]-[0-9A-Za-z-]+")
for name in ("cases.jsonl", "report.md", "replay.sh", "result.json", "selected-20.jsonl", "sha256.txt"):
    raw = (owned / name).read_bytes()
    text = raw.decode("utf-8")
    assert text, name
    assert not han.search(text), name
    assert not secret.search(text), name
    if name != "replay.sh":
        assert "auth.json" not in text.lower(), name
        assert "zshrc" not in text.lower(), name
    assert "\t" not in text or name == "replay.sh", name
    assert not text.endswith(" \n") and not any(line.endswith(" ") for line in text.splitlines()), name

res = json.loads((owned / "result.json").read_text())
for name, digest in res["artifact_hashes"].items():
    got = hashlib.sha256((owned / name).read_bytes()).hexdigest()
    assert got == digest, (name, got, digest)

assert res["status"] == "TERMINAL"
assert res["hold"] is True
assert res["publication_status"] == "HOLD"
assert res["causal_admission"] is False
assert res["worker_pass_is_proposal_only"] is True
assert res["hard_terminal_checkpoint"] is True
assert res["discovery_stopped"] is True
assert res["analysis_stopped"] is True
assert res["counts"]["PASS"] == 0
assert res["counts"]["REJECT"] == 20
assert res["counts"]["NARROW"] == 0
assert res["counts"]["UNKNOWN"] == 0
assert res["counts"]["BLOCKED"] == 0
assert res["counts"]["assigned"] == 20
assert res["counts"]["reviewed"] == 20
assert res["counts"]["unreviewed"] == 0
assert res["counts"]["countable_pass"] == 0
assert res["proposed_pass_ids"] == []
assert res["claim_boundary"]["more_than_200_claim_supported_by_this_review"] is False
assert set(res["dispositions"]) == {"PASS", "REJECT", "NARROW", "UNKNOWN", "BLOCKED"}

cons = res["conservation"]
assert cons["assigned"] == 20
assert cons["reviewed"] == 20
assert cons["unreviewed"] == 0
assert cons["prior_directroot_reviewed"] == 810
assert cons["prior_directroot_reviewed"] + cons["deep_reviewed"] + cons["unreviewed_hits"] + cons["rank_misses"] == cons["rank_pool"]
assert cons["assigned_equals_reviewed"] is True
assert cons["selected_equals_ranked_811_to_830"] is True
assert 810 + 20 + 0 + 2643 == 3473
assert 810 + 20 == 830
assert cons["equation"] == "810+20+0+2643=3473"

assigned = ["GHSA-FM2F-4339-4P2F", "GHSA-JFM3-95JQ-Q3RF", "GHSA-RM43-82J9-R4MJ", "GHSA-4F78-QHMW-8J8M", "GHSA-C4C3-PG64-4M4V", "GHSA-MJ63-M3RC-8PPR", "GHSA-8X5V-CPV7-8JJP", "GHSA-87X5-VMC3-756J", "GHSA-WG86-R78F-74MP", "GHSA-MJ5R-JF49-M3W7", "GHSA-9F4C-93C8-JC8G", "GHSA-5XVG-PMGG-3MXR", "GHSA-CHM3-VQCF-52RX", "GHSA-XC48-889X-5QMW", "GHSA-FR6G-7CQ8-FG82", "GHSA-JR45-8VMC-QM54", "GHSA-W62W-66V9-VVGV", "GHSA-RQ84-P6RR-VF89", "GHSA-F2R8-JV7C-XQMP", "GHSA-8XCM-R25X-G524"]
auth = [ln.strip() for ln in Path("autoresearch/herdr-260814-ghsa200-directroot-batch27-grok46-high/work/unreviewed-hit-ids.txt").read_text().splitlines() if ln.strip()]
assert auth == assigned
cases = [json.loads(line) for line in (owned / "cases.jsonl").read_text().splitlines() if line.strip()]
assert len(cases) == 20
ids = [c["case_id"] for c in cases]
assert ids == assigned
assert ids == res["selection"]["selected_ids"]
sel_file = [json.loads(l)["ghsa_id"] for l in (owned / "work/selected-20.jsonl").read_text().splitlines() if l.strip()]
assert ids == sel_file
assert sum(c["worker_verdict"] == "REJECT" for c in cases) == 20
assert all(c["countable"] is False for c in cases)
assert all(c["causal_admission"] is False for c in cases)
assert all(c["english_only"] is True for c in cases)
assert "WVPP" not in json.dumps(ids)
assert "HMQ2" not in json.dumps(ids)

gates = ["identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]
for row in cases:
    failed = [g for g in gates if row[g] != "PASS"]
    assert failed, row["case_id"]
    assert row["identity_gate"] == "PASS"

def load_ids(path, key):
    p = Path(path)
    if not p.exists():
        return set()
    out = set()
    for line in p.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        val = row.get(key) or row.get("case_id") or row.get("ghsa_id")
        if isinstance(val, str) and val.upper().startswith("GHSA-"):
            out.add(val.upper())
    return out

c81 = set(json.loads(Path("autoresearch/orchestrator-260814-ghsa200-canonical81/summary.json").read_text())["strict_released_case_ids"])
assert len(c81) == 81
assert not (set(ids) & c81)
inc20k = load_ids(Path("autoresearch/herdr-260814-ghsa200-incomplete-remediation20k-grok46-low/work/selected-20.jsonl"), "ghsa_id")
assert not (set(ids) & inc20k)
stale = load_ids(Path("autoresearch/herdr-260813-ghsa200-directroot-batch3-grok46-xhigh/work/selected-30.jsonl"), "ghsa_id")
formal = load_ids(Path("autoresearch/herdr-260814-ghsa200-directroot-batch3-grok46-xhigh/work/selected-30.jsonl"), "ghsa_id")
assert stale == formal
assert len(stale) == 30
prior_dirs = [
    first / "work/selected-30.jsonl",
    Path("autoresearch/herdr-260813-ghsa200-directroot-batch2-grok46-xhigh/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260813-ghsa200-directroot-batch3-grok46-xhigh/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch3-grok46-xhigh/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch4-grok46-high/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch5-grok46-medium/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch6-grok46-low/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch7-grok46-low/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch8-grok46-medium/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch9-grok46-low/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch10-grok46-high/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch11-grok46-medium/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch12-grok46-high/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch13-grok46-low/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch14-grok46-medium/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch15-grok46-high/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch16-grok46-medium/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch17-grok46-xhigh/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch18-grok46-high/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch19-grok46-medium/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch20-grok46-high/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch21-grok46-medium/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch22-grok46-medium/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch23-grok46-high/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch24-grok46-medium/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch25-grok46-high/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch26-grok46-medium/work/selected-30.jsonl"),
    Path("autoresearch/herdr-260814-ghsa200-directroot-batch27-grok46-high/work/selected-30.jsonl"),
]
for p in prior_dirs:
    prior = load_ids(p, "ghsa_id")
    assert not (set(ids) & prior), str(p)

hits = {json.loads(l)["ghsa_id"].upper() for l in (first / "work/rank-hits.jsonl").read_text().splitlines() if l.strip()}
assert set(ids) <= hits
assert [c["original_rank"] for c in cases] == list(range(811, 831))
assert res["selection"]["selected_original_ranks"] == list(range(811, 831))
assert res["frozen_input_hashes"]["CONTRACT.md"] == res["current_input_hashes"]["CONTRACT.md"]
assert res["did_not_edit_tracked_or_canonical"] is True
assert res["did_not_commit_or_push"] is True

merge = next(c for c in cases if c["case_id"] == "GHSA-8XCM-R25X-G524")
assert merge["topology_gate"] == "FAIL"
assert merge["worker_verdict"] == "REJECT"
rm43 = next(c for c in cases if c["case_id"] == "GHSA-RM43-82J9-R4MJ")
assert rm43["but_for_gate"] == "FAIL"
assert rm43["ai_hunk_gate"] == "FAIL"

for i in ids:
    assert (owned / "work/pages" / f"{i.lower()}.json").is_file()

ckpt = json.loads((owned / "work/checkpoint.json").read_text())
assert ckpt["assigned"] == 20
assert ckpt["reviewed"] == 20
assert ckpt["unreviewed"] == 0
assert ckpt["reviewed_ids"] == ids
assert ckpt["expansion_stopped"] is True

manifest = {}
for line in (owned / "sha256.txt").read_text().splitlines():
    if not line.strip():
        continue
    digest, path = line.split(None, 1)
    manifest[path] = digest
for name in ("cases.jsonl", "report.md", "replay.sh", "result.json"):
    got = hashlib.sha256((owned / name).read_bytes()).hexdigest()
    assert manifest[name] == got
PY

echo OK
