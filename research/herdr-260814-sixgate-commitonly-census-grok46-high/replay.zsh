#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-sixgate-commitonly-census-grok46-high.
# English only. No network. No clone/commit/push. Canonical88 read-only.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
ROOT=/home/hanqing/agents/ai-slop
OWN=$ROOT/autoresearch/herdr-260814-sixgate-commitonly-census-grok46-high
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json
test -f "$OWN/assignment.jsonl"
test -f "$OWN/cases.jsonl"
test -f "$OWN/result.json"
test -f "$OWN/report.md"
test -f "$LEDGER"
test -f "$SUMMARY"
python3 - <<'ENDPY'
from __future__ import annotations
import hashlib, json, re
from collections import defaultdict
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OWN = ROOT / "autoresearch/herdr-260814-sixgate-commitonly-census-grok46-high"
OWN.mkdir(parents=True, exist_ok=True)
LEDGER = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl"
SUMMARY = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json"
H2V8_DIR = ROOT / "autoresearch/herdr-260814-h2v8-release-closure-grok46-high"

GHSA_RE = re.compile(r"\bGHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}\b", re.I)
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
CAUSAL = (
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "uniqueness_gate",
)
SEVEN = CAUSAL + ("release_gate",)
RELEASE_OPEN = {"UNKNOWN", "NARROW", "FAIL", "COMMIT_ONLY", "COMMITONLY"}
VALID_GATE = {
    "PASS", "FAIL", "NARROW", "UNKNOWN", "NA", "N_A", "COMMIT_ONLY",
    "COMMITONLY", "BLOCKED", "HOLD", "REJECT",
}
SKIP_DIR = {
    "node_modules", ".git", "snapshot", "work", "pages", "clones", "clone",
    "cache", "raw_cache", "tmp", "notes",
}
SKIP_PACKET = (
    "sixgate-commitonly-census",
    "next-pool-map",
    "proposal-census",
    "current-proposal-gap",
    "cf3-nextqueue",
    "foundation165",
)
INVENTORY_NEEDLES = (
    "ghsa200-gap",
    "freshness-qa",
    "current-delta",
    "cross-dedupe",
    "coverage-closure",
)
FROZEN_NEG = [
    "GHSA-VP55-5C2V-3597",
    "GHSA-C5CP-VX83-JHQX",
    "GHSA-8QXC-57HF-HC9J",
    "GHSA-F29H-2H58-48R7",
    "GHSA-M8XG-8XG9-MXHM",
]
POSITIVE_CONTROL = "GHSA-H2V8-4C3F-VQGV"


def sha256_path(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def as_upper(v):
    if isinstance(v, str):
        return v.strip().upper().replace(" ", "_").replace("-", "_")
    return None


def extract_ghsa(v):
    if isinstance(v, str):
        m = GHSA_RE.search(v)
        if m:
            return m.group(0).upper()
    return None


def first_ghsa(obj):
    for k in ("case_id", "ghsa_id", "ghsa", "id", "primary_id", "advisory_id"):
        g = extract_ghsa(obj.get(k) if isinstance(obj.get(k), str) else None)
        if g:
            return g
    return None


def sha_list(v):
    out, seen = [], set()
    if isinstance(v, str) and SHA_RE.fullmatch(v):
        return [v.lower()]
    if not isinstance(v, list):
        return []
    for i in v:
        s = None
        if isinstance(i, str) and SHA_RE.fullmatch(i):
            s = i.lower()
        elif isinstance(i, dict):
            for k in ("sha", "commit", "oid"):
                if isinstance(i.get(k), str) and SHA_RE.fullmatch(i[k]):
                    s = i[k].lower()
                    break
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def gate_map(obj):
    out = {}
    g = obj.get("gates")
    if isinstance(g, dict):
        for k, v in g.items():
            if isinstance(k, str) and k.endswith("_gate") and v is not None and not isinstance(v, (dict, list)):
                u = as_upper(str(v))
                if u and u in VALID_GATE:
                    out[k] = u
    for k in SEVEN:
        if k in obj and obj[k] is not None and not isinstance(obj[k], (dict, list)):
            u = as_upper(str(obj[k]))
            if u and u in VALID_GATE:
                out.setdefault(k, u)
    return out


def complete_causal(gm):
    return all(k in gm for k in CAUSAL)


def review_role(packet):
    n = packet.lower()
    if "hostile" in n:
        return "hostile"
    if "release-closure" in n:
        return "release_closure"
    if "redteam" in n or "red-upgrade" in n or "redbase" in n:
        return "redteam"
    if any(x in n for x in (
        "final-candidate-review", "confirm11-closure", "unknown4",
        "narrow-recovery", "nearclosed", "unified-verifier", "third-review",
        "h2v8-release", "final-unknown",
    )):
        return "independent"
    if any(x in n for x in ("cf4-", "cf3-", "cf2-")):
        return "campaign"
    if any(x in n for x in ("commitfirst", "topologyonly", "releaseonly", "nearpass", "directroot")):
        return "gap_close"
    if any(x in n for x in INVENTORY_NEEDLES):
        return "inventory"
    return "worker"


ROLE_RANK = {
    "inventory": 1, "worker": 3, "gap_close": 4, "campaign": 5,
    "independent": 6, "redteam": 7, "release_closure": 8, "hostile": 9,
}


def source_kind_rank(kind):
    if "gates.json" in kind:
        return 5
    if kind in {"cases.jsonl", "case.json"} or str(kind).endswith("cases.jsonl"):
        return 4
    if "gate_vector" in kind:
        return 3
    if str(kind).startswith("result.json"):
        return 2
    return 0


def fingerprint(mech, cand, fix):
    if isinstance(mech, str) and mech.strip():
        return "mech:" + mech.strip().lower()
    return "sets:" + json.dumps([sorted(cand), sorted(fix)], separators=(",", ":"))


def aliases_of(obj):
    out, seen = [], set()
    for key in ("aliases", "cve_aliases", "public_ids"):
        val = obj.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.strip() and item.strip() not in seen:
                    seen.add(item.strip())
                    out.append(item.strip())
    return out


def first_party_ok(obj):
    fps = obj.get("first_party_sources")
    if isinstance(fps, list) and any(isinstance(x, str) and "github.com" in x for x in fps):
        return True
    if obj.get("github_reviewed") is True:
        return True
    ap = str(obj.get("advisory_path") or "")
    if "github-reviewed" in ap:
        return True
    return False


def atomic_ok(obj):
    if obj.get("n_parents") == 1:
        return True
    ev = obj.get("ai_marker_evidence") or obj.get("exact_ai_marker") or obj.get("explicit_ai_markers")
    text = ev if isinstance(ev, str) else json.dumps(ev)
    t = text.lower()
    return "parent_count=1" in t or "atomic" in t or "n_parents=1" in t


def packet_terminal(obj):
    if not obj:
        return False
    if obj.get("terminal") is True:
        return True
    st = str(obj.get("status") or obj.get("terminal_status") or "").upper()
    if obj.get("terminal") is False and st not in {"TERMINAL", "COMPLETE"}:
        return False
    return st in {"TERMINAL", "COMPLETE", "HOLD", "FINAL", "CENSUS_COMPLETE"}


canon_ids = [x.upper() for x in json.loads(SUMMARY.read_text())["strict_released_case_ids"]]
assert len(canon_ids) == 88
canon = set(canon_ids)

base = ROOT / "autoresearch"
scan_files = []
packet_meta = {}
for pat in ("herdr-260813-*", "herdr-260814-*"):
    for d in sorted(base.glob(pat)):
        if not d.is_dir() or d.resolve() == OWN.resolve():
            continue
        if any(n in d.name.lower() for n in SKIP_PACKET):
            continue
        pkt = "autoresearch/" + d.name
        rj = d / "result.json"
        meta = {"terminal": False, "status": "NO_RESULT_JSON"}
        if rj.is_file():
            try:
                raw = rj.read_bytes()
                obj = json.loads(raw.decode("utf-8"))
                meta["status"] = str(obj.get("status") or obj.get("terminal_status") or "STATUS_ABSENT")
                meta["terminal"] = packet_terminal(obj)
            except Exception:
                meta["status"] = "RESULT_PARSE_FAIL"
        packet_meta[pkt] = meta
        for p in d.rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(d)
            if set(rel.parts) & SKIP_DIR:
                continue
            if p.name in {"cases.jsonl", "case.json", "result.json"}:
                scan_files.append(p)
            elif p.parent.name == "facts" and p.name == "gates.json":
                scan_files.append(p)
            elif "adjudication" in p.name and p.suffix == ".jsonl":
                scan_files.append(p)

scan_files = sorted(set(scan_files), key=lambda p: str(p))
source_pins = []
rows = []
schema_fail = 0
skipped_incomplete = 0

for p in scan_files:
    rel = str(p.relative_to(ROOT))
    packet = "autoresearch/" + p.relative_to(base).parts[0]
    try:
        raw = p.read_bytes()
        src_sha = hashlib.sha256(raw).hexdigest()
        text = raw.decode("utf-8")
    except Exception:
        schema_fail += 1
        continue
    source_pins.append({"path": rel, "sha256": src_sha})
    objs = []
    if p.suffix == ".jsonl":
        for i, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                objs.append((i, json.loads(line)))
            except Exception:
                schema_fail += 1
    else:
        try:
            o = json.loads(text)
        except Exception:
            schema_fail += 1
            continue
        if isinstance(o, dict):
            objs.append((None, o))
        elif isinstance(o, list):
            for i, item in enumerate(o, 1):
                if isinstance(item, dict):
                    objs.append((i, item))
    date = 814 if "260814" in packet else 813
    role = review_role(packet)
    term = packet_meta.get(packet, {}).get("terminal", False)
    for lineno, o in objs:
        if not isinstance(o, dict):
            continue
        cands = [(p.name, lineno, o)]
        if p.name == "result.json":
            for key in ("cases", "reviewed_cases", "adjudications", "rows"):
                val = o.get(key)
                if isinstance(val, list):
                    for j, item in enumerate(val, 1):
                        if isinstance(item, dict):
                            cands.append(("result.json:" + key, j, item))
            gv = o.get("gate_vectors") or o.get("gate_vector")
            if isinstance(gv, dict) and any(str(k).endswith("_gate") for k in gv):
                d = dict(gv)
                d.setdefault("case_id", o.get("case_id"))
                cands.append(("result.json:gate_vector", None, d))
            elif isinstance(gv, dict):
                for cid, vec in gv.items():
                    if isinstance(vec, dict):
                        dd = dict(vec)
                        dd.setdefault("case_id", cid)
                        cands.append(("result.json:gate_vectors", None, dd))
        for kind, ln, obj in cands:
            g = first_ghsa(obj)
            gm = gate_map(obj)
            if not g:
                continue
            if not complete_causal(gm):
                skipped_incomplete += 1
                continue
            cand = sha_list(obj.get("candidate_set") or obj.get("counted_candidate") or obj.get("candidate"))
            fix = sha_list(obj.get("minimum_fix_set") or obj.get("minimum_fix") or obj.get("fix_set") or obj.get("official_fix_shas"))
            mech = obj.get("mechanism_key") or obj.get("mechanism_fingerprint")
            mech = mech.strip() if isinstance(mech, str) and mech.strip() else None
            fp = fingerprint(mech, cand, fix)
            strength = (date, ROLE_RANK[role], source_kind_rank(kind), 1 if ln else 0)
            rows.append({
                "case_id": g, "packet": packet, "source": rel, "kind": kind, "line": ln,
                "gates": gm, "cand": cand, "fix": fix, "mech": mech, "fp": fp,
                "repo": obj.get("repository") if isinstance(obj.get("repository"), str) else None,
                "src_sha": src_sha, "role": role, "date": date, "strength": strength,
                "terminal": term, "n_parents": obj.get("n_parents"),
                "aliases": aliases_of(obj),
                "scope": obj.get("scope_statement") if isinstance(obj.get("scope_statement"), str) else None,
                "verdict": as_upper(str(obj.get("verdict") or obj.get("worker_verdict") or obj.get("final_verdict") or "")) or None,
                "fps": obj.get("first_party_sources") if isinstance(obj.get("first_party_sources"), list) else [],
                "contrib": obj.get("contribution_class") if isinstance(obj.get("contribution_class"), str) else None,
                "counter": obj.get("counterevidence") if isinstance(obj.get("counterevidence"), list) else [],
                "first_party": first_party_ok(obj), "atomic": atomic_ok(obj),
            })

usable = [r for r in rows if r["terminal"] and r["role"] != "inventory"]
by_all = defaultdict(list)
for r in rows:
    by_all[r["case_id"]].append(r)
by_id = defaultdict(list)
for r in usable:
    by_id[r["case_id"]].append(r)

selected = []
fail_closed = []
near_six_open_but_latest_not = []
for cid, hits in by_id.items():
    hits_sorted = sorted(hits, key=lambda r: r["strength"] + (r["source"], r["line"] or 0), reverse=True)
    top = hits_sorted[0]
    gm = top["gates"]
    six = all(gm.get(k) == "PASS" for k in CAUSAL)
    relg = gm.get("release_gate")
    all_hits = by_all[cid]
    veto = []
    for h in all_hits:
        if h["packet"] == top["packet"] and h["kind"] == top["kind"]:
            continue
        if h["strength"] >= top["strength"] and any(h["gates"].get(k) != gm.get(k) for k in CAUSAL):
            veto.append(h)
        if h["date"] == top["date"] and ROLE_RANK[h["role"]] >= ROLE_RANK[top["role"]] and six and any(h["gates"].get(k) != "PASS" for k in CAUSAL):
            veto.append(h)
        if h["date"] > top["date"] and any(h["gates"].get(k) == "FAIL" for k in CAUSAL) and six:
            veto.append(h)
    rec = {"cid": cid, "fp": top["fp"], "top": top, "hits": hits_sorted, "all_hits": all_hits, "six": six, "relg": relg, "veto": veto}
    if cid in canon:
        continue
    if six and relg in RELEASE_OPEN:
        if veto:
            fail_closed.append(rec)
        else:
            selected.append(rec)
    else:
        older = [h for h in hits if all(h["gates"].get(k) == "PASS" for k in CAUSAL) and h["gates"].get("release_gate") in RELEASE_OPEN]
        if older:
            near_six_open_but_latest_not.append(rec)

# Dedupe remaining inventory by mechanism fingerprint or exact candidate/fix sets.
# Shared SHA alone does not merge distinct IDs.
deduped = []
seen_fp = {}
for rec in selected:
    t = rec["top"]
    keys = []
    if t["mech"]:
        keys.append("mech:" + t["mech"].lower())
    if t["cand"] or t["fix"]:
        keys.append("sets:" + json.dumps([sorted(t["cand"]), sorted(t["fix"])], separators=(",", ":")))
    drop = False
    for k in keys:
        if k in seen_fp and seen_fp[k] != rec["cid"]:
            # same mechanism or exact cand/fix pair already kept under another ID
            rec["dedupe_of"] = seen_fp[k]
            drop = True
            break
    if drop:
        fail_closed.append(rec)
        continue
    for k in keys:
        seen_fp.setdefault(k, rec["cid"])
    deduped.append(rec)
selected = deduped


def rank_tuple(rec):
    t = rec["top"]
    butfor_conflict = any(
        h["gates"].get("but_for_gate") not in {None, "PASS"} and h["strength"][1] >= t["strength"][1]
        for h in rec["hits"] if h["packet"] != t["packet"]
    )
    rel_pref = {"UNKNOWN": 0, "COMMIT_ONLY": 0, "COMMITONLY": 0, "NARROW": 1, "FAIL": 2}.get(rec["relg"], 9)
    high = (
        t["first_party"] and t["atomic"] and bool(t["cand"]) and bool(t["fix"])
        and (not butfor_conflict) and rec["six"]
        and t["role"] in {"campaign", "independent", "redteam", "release_closure", "hostile"}
    )
    cls = 1 if high else (2 if t["first_party"] and t["cand"] and t["fix"] else 3)
    force = 0 if rec["cid"] == POSITIVE_CONTROL else 1
    return (cls, force, rel_pref, rec["cid"], rec["fp"])

selected.sort(key=rank_tuple)

neg_rows = []
for cid in FROZEN_NEG:
    hits = by_id.get(cid, [])
    assert hits, ("missing neg", cid)
    top = sorted(hits, key=lambda r: r["strength"] + (r["source"], r["line"] or 0), reverse=True)[0]
    gm = top["gates"]
    causal_fail = [k for k in CAUSAL if gm.get(k) == "FAIL"]
    assert gm.get("release_gate") in RELEASE_OPEN, (cid, gm)
    assert causal_fail, (cid, gm)
    assert cid not in canon
    neg_rows.append({"cid": cid, "top": top, "hits": sorted(hits, key=lambda r: r["strength"], reverse=True), "causal_fail": causal_fail})

h2 = [s for s in selected if s["cid"] == POSITIVE_CONTROL]
assert len(h2) == 1, [s["cid"] for s in selected]
h2t = h2[0]["top"]
assert h2t["packet"].endswith("h2v8-release-closure-grok46-high")
assert h2t["cand"] == ["e08547bcdb42aaa86190c6e2dfc64159fcd3a146"]
assert h2t["fix"] == ["1e66c78c4ce6ea294ac6b0eb289a9eae9c5e9579"]
assert all(h2t["gates"][k] == "PASS" for k in CAUSAL)
assert h2t["gates"]["release_gate"] == "UNKNOWN"
assert h2t["n_parents"] == 1
h2_hashes = {n: sha256_path(H2V8_DIR / n) for n in ("assignment.jsonl", "cases.jsonl", "result.json", "report.md", "replay.zsh")}
assert h2_hashes["cases.jsonl"] == "db9b6c7c456e2909c9c6395edf7bcb828e76b432b3b981389fadea3010b8d0f9"
assert h2_hashes["result.json"] == "dbdff9bbb5526db941a04f681c2f7609950505bf2cc3b87340e903cadee8c568"
assert h2_hashes["assignment.jsonl"] == "f8c2ae028b9e803584892f7774a8ea23068ded1c8623cbd35ac5242d06d28d51"
assert not ({s["cid"] for s in selected} & canon)


# Replay checks against frozen artifacts.
from pathlib import Path as _P
OWN = ROOT / "autoresearch/herdr-260814-sixgate-commitonly-census-grok46-high"
res = json.loads((OWN / "result.json").read_text())
asn = [json.loads(l) for l in (OWN / "assignment.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (OWN / "cases.jsonl").read_text().splitlines() if l.strip()]
report = (OWN / "report.md").read_text()
assert all(ord(c) < 128 for c in report)
assert res["canonical88_unchanged"] is True
assert res["canonical88_strict_count"] == 88
assert res["canonical_ledger_edited"] is False
assert res["causal_admission"] is False
assert res["pass_proposals"] == []
assert res["counts"]["PASS"] == 0
assert res["counts"]["PASS_PROPOSAL"] == 0
got_ledger = sha256_path(LEDGER)
got_summary = sha256_path(SUMMARY)
assert got_ledger == res["hash_roles"]["canonical88_ledger.jsonl"] == "35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074"
assert got_summary == res["hash_roles"]["canonical88_summary.json"] == "81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921"
for pin in res["source_file_hashes"]:
    p = ROOT / pin["path"]
    assert p.is_file(), pin["path"]
    assert sha256_path(p) == pin["sha256"], pin["path"]
h2p = ROOT / "autoresearch/herdr-260814-h2v8-release-closure-grok46-high"
for n, exp in res["h2v8_positive_control"]["packet_hashes"].items():
    assert sha256_path(h2p / n) == exp, n
ids = [a["case_id"] for a in asn]
assert ids == res["inventory_ids"]
assert ids == [s["cid"] for s in selected]
assert len(ids) == 7
assert ids[0] == "GHSA-H2V8-4C3F-VQGV"
assert "GHSA-8G98-M4J9-QWW5" in ids and "GHSA-VH5J-5FHQ-9XWG" in ids
assert not (set(ids) & canon)
assert res["canonical88_overlap"] == []
# shared SHA 57b76343 is fix of 8G98 and candidate of VH5J, not a duplicate
a8 = next(a for a in asn if a["case_id"] == "GHSA-8G98-M4J9-QWW5")
av = next(a for a in asn if a["case_id"] == "GHSA-VH5J-5FHQ-9XWG")
assert a8["minimum_fix_set"] == ["57b7634391959dbbdb39b387ac4dc68157cd58a1"]
assert av["candidate_set"] == ["57b7634391959dbbdb39b387ac4dc68157cd58a1"]
assert a8["fingerprint"] != av["fingerprint"]
assert all(a["canonical88_strict"] is False and a["never_promote"] is True for a in asn)
assert all(c["gates"]["identity_gate"] == "PASS" for c in cases if c.get("inventory_role") == "ranked_commit_only_candidate")
assert all(c["gates"]["release_gate"] in RELEASE_OPEN for c in cases if c.get("inventory_role") == "ranked_commit_only_candidate")
neg = [c for c in cases if c.get("negative_control")]
assert [c["case_id"] for c in neg] == res["negative_control_ids"]
assert all(c.get("causal_fail_gates") for c in neg)
assert "8JQH" in report and "fail-closed" in report.lower() or "Fail-closed" in report
assert "Canonical88 stays 88" in report
assert res["conservation"]["holds"] is True
print("REPLAY_OK inventory=7 overlap=0 canonical88=88 PASS_PROPOSAL=0")
ENDPY
