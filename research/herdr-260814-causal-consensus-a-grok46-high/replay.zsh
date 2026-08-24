#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-causal-consensus-a-grok46-high.
# English only. No network. No clone/commit/push. Canonical88 read-only.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
ROOT=/home/hanqing/agents/ai-slop
OWN=$ROOT/autoresearch/herdr-260814-causal-consensus-a-grok46-high
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json
test -f "$OWN/assignment.jsonl"
test -f "$OWN/cases.jsonl"
test -f "$OWN/result.json"
test -f "$OWN/report.md"
test -f "$LEDGER"
test -f "$SUMMARY"
python3 - <<'ENDPY'
#!/usr/bin/env python3
"""Read-only consensus miner. Writes JSON dump to /tmp only. Does not touch canonical88."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OWN_NAME = "herdr-260814-causal-consensus-a-grok46-high"
LEDGER = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl"
SUMMARY = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json"
ADV = Path(
    "/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database"
)

GHSA_RE = re.compile(r"\bGHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}\b", re.I)
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
MODEL_RE = re.compile(
    r"(grok46-xhigh|grok46-high|grok46-medium|grok46-low|deepseek|claude|opus|sonnet|sol-max|gpt-5)",
    re.I,
)
CAUSAL = (
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "uniqueness_gate",
)
SEVEN = CAUSAL + ("release_gate",)
VALID_GATE = {
    "PASS",
    "FAIL",
    "NARROW",
    "UNKNOWN",
    "NA",
    "N_A",
    "COMMIT_ONLY",
    "COMMITONLY",
    "BLOCKED",
    "HOLD",
    "REJECT",
}
RELEASE_OPEN = {"UNKNOWN", "NARROW", "FAIL", "COMMIT_ONLY", "COMMITONLY", "NA", "N_A"}
SKIP_DIR = {
    "node_modules",
    ".git",
    "snapshot",
    "work",
    "pages",
    "clones",
    "clone",
    "cache",
    "raw_cache",
    "tmp",
    "notes",
}
SKIP_PACKET = (
    "sixgate-commitonly-census",
    "next-pool-map",
    "proposal-census",
    "current-proposal-gap",
    "cf3-nextqueue",
    "foundation165",
    "causal-consensus",
    "canonical-fixmismatch",
)
INVENTORY_NEEDLES = (
    "ghsa200-gap",
    "freshness-qa",
    "current-delta",
    "cross-dedupe",
    "coverage-closure",
    "proposal-census",
    "next-pool",
    "nextqueue",
    "foundation165",
    "sixgate-commitonly",
)
INDEPENDENT_NEEDLES = (
    "final-candidate-review",
    "confirm11-closure",
    "unknown4",
    "narrow-recovery",
    "nearclosed",
    "unified-verifier",
    "third-review",
    "h2v8-release",
    "final-unknown",
    "release-closure",
    "hostile",
)
ROLE_RANK = {
    "inventory": 1,
    "worker": 3,
    "other": 4,
    "gap_close": 4,
    "campaign": 6,
    "independent": 7,
    "redteam": 8,
    "release_closure": 8,
    "hostile": 9,
}


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
    return sorted(set(out))


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


def packet_model(name: str) -> str:
    m = MODEL_RE.search(name)
    return m.group(1).lower() if m else "unspecified"


def campaign_stem(name: str) -> str:
    n = name.lower()
    n = re.sub(r"^herdr-\d+-", "", n)
    n = re.sub(r"^orchestrator-\d+-", "", n)
    n = MODEL_RE.sub("", n)
    n = re.sub(r"-+", "-", n).strip("-")
    # collapse split suffixes that are the same campaign
    n = re.sub(r"-(even|odd|a|b|c|batch\d+|ord\d+)$", "", n)
    return n


def review_role(packet: str) -> str:
    n = packet.lower()
    if any(x in n for x in SKIP_PACKET) or any(x in n for x in INVENTORY_NEEDLES):
        return "inventory"
    if "hostile" in n:
        return "hostile"
    if "release-closure" in n:
        return "release_closure"
    if "redteam" in n or "red-upgrade" in n or "redbase" in n:
        return "redteam"
    if any(x in n for x in INDEPENDENT_NEEDLES):
        return "independent"
    if any(x in n for x in ("cf4-", "cf3-", "cf2-")):
        return "campaign"
    if any(x in n for x in ("commitfirst", "topologyonly", "releaseonly", "nearpass", "directroot")):
        return "gap_close"
    if n.startswith("autoresearch/orchestrator-"):
        return "inventory"
    return "worker"


def is_independent_role(role: str) -> bool:
    return role in {"hostile", "redteam", "independent", "campaign", "release_closure"}


def source_kind_rank(kind):
    if "gates.json" in str(kind):
        return 5
    if kind in {"cases.jsonl", "case.json"} or str(kind).endswith("cases.jsonl"):
        return 4
    if "gate_vector" in str(kind):
        return 3
    if str(kind).startswith("result.json"):
        return 2
    return 0


def fingerprint(mech, cand, fix):
    if isinstance(mech, str) and mech.strip():
        return "mech:" + mech.strip().lower()
    return "sets:" + json.dumps([sorted(cand), sorted(fix)], separators=(",", ":"))


def first_party_ok(obj):
    fps = obj.get("first_party_sources")
    if isinstance(fps, list) and any(isinstance(x, str) and ("github.com" in x or "github-reviewed" in x) for x in fps):
        return True
    if obj.get("github_reviewed") is True:
        return True
    ap = str(obj.get("advisory_path") or "")
    if "github-reviewed" in ap:
        return True
    return False


def packet_terminal(obj):
    if not obj:
        return False
    if obj.get("terminal") is True:
        return True
    st = str(obj.get("status") or obj.get("terminal_status") or "").upper()
    if obj.get("terminal") is False and st not in {"TERMINAL", "COMPLETE", "HOLD", "FINAL", "CENSUS_COMPLETE"}:
        return False
    return st in {
        "TERMINAL",
        "COMPLETE",
        "HOLD",
        "FINAL",
        "CENSUS_COMPLETE",
        "REDTEAM_COMPLETE",
        "REDTEAM_TERMINAL",
        "REVIEW_COMPLETE",
        "COMPLETE_BOUNDED_REVIEW",
        "COMPLETE_THIRD_REVIEW",
        "PARTIAL_TERMINAL",
    }


def genuinely_independent(a, b) -> bool:
    """Two terminal rows are independent authorities, not worker/same-model copies."""
    if a["packet"] == b["packet"]:
        return False
    if not is_independent_role(a["role"]) or not is_independent_role(b["role"]):
        return False
    # same campaign stem is the same task (possibly different model) - not independent
    if a["stem"] == b["stem"]:
        return False
    # same-model agreement inside the same role bucket is not independent
    if a["model"] != "unspecified" and a["model"] == b["model"] and a["role"] == b["role"]:
        return False
    return True


def load_advisory_index():
    idx = {}
    root = ADV / "advisories" / "github-reviewed"
    if not root.is_dir():
        return idx
    for p in root.rglob("GHSA-*.json"):
        try:
            obj = json.loads(p.read_text())
        except Exception:
            continue
        gid = extract_ghsa(obj.get("id") or p.stem)
        if not gid:
            continue
        withdrawn = obj.get("withdrawn")
        gh_reviewed = obj.get("github_reviewed")
        idx[gid] = {
            "path": str(p),
            "withdrawn": bool(withdrawn),
            "github_reviewed": gh_reviewed is True or gh_reviewed is None,
            "schema_version": obj.get("schema_version"),
            "nvd_published_at": obj.get("nvd_published_at"),
        }
    return idx


def main():
    summary = json.loads(SUMMARY.read_text())
    canon_ids = [x.upper() for x in summary["strict_released_case_ids"]]
    assert len(canon_ids) == 88
    canon = set(canon_ids)
    ledger_sha = sha256_path(LEDGER)
    summary_sha = sha256_path(SUMMARY)

    adv_idx = load_advisory_index()

    base = ROOT / "autoresearch"
    scan_files = []
    packet_meta = {}
    for pat in ("herdr-260813-*", "herdr-260814-*"):
        for d in sorted(base.glob(pat)):
            if not d.is_dir() or d.name == OWN_NAME:
                continue
            if any(n in d.name.lower() for n in SKIP_PACKET):
                continue
            pkt = "autoresearch/" + d.name
            rj = d / "result.json"
            meta = {"terminal": False, "status": "NO_RESULT_JSON"}
            if rj.is_file():
                try:
                    obj = json.loads(rj.read_bytes().decode("utf-8"))
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
        model = packet_model(packet)
        stem = campaign_stem(p.relative_to(base).parts[0])
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
            for kind, ln, obj in cands:
                g = first_ghsa(obj)
                gm = gate_map(obj)
                if not g:
                    continue
                if not complete_causal(gm):
                    skipped_incomplete += 1
                    continue
                cand = sha_list(obj.get("candidate_set") or obj.get("counted_candidate") or obj.get("candidate"))
                fix = sha_list(
                    obj.get("minimum_fix_set")
                    or obj.get("minimum_fix")
                    or obj.get("fix_set")
                    or obj.get("official_fix_shas")
                )
                parent = sha_list(
                    obj.get("parent_set")
                    or obj.get("parents")
                    or obj.get("candidate_parents")
                    or obj.get("parent_sha")
                    or obj.get("parent")
                )
                mech = obj.get("mechanism_key") or obj.get("mechanism_fingerprint")
                mech = mech.strip() if isinstance(mech, str) and mech.strip() else None
                fp = fingerprint(mech, cand, fix)
                strength = (date, ROLE_RANK[role], source_kind_rank(kind), 1 if ln else 0)
                rows.append(
                    {
                        "case_id": g,
                        "packet": packet,
                        "source": rel,
                        "kind": kind,
                        "line": ln,
                        "gates": gm,
                        "cand": cand,
                        "fix": fix,
                        "parent": parent,
                        "mech": mech,
                        "fp": fp,
                        "repo": obj.get("repository") if isinstance(obj.get("repository"), str) else None,
                        "src_sha": src_sha,
                        "role": role,
                        "date": date,
                        "model": model,
                        "stem": stem,
                        "strength": strength,
                        "terminal": term,
                        "n_parents": obj.get("n_parents"),
                        "verdict": as_upper(str(obj.get("verdict") or obj.get("worker_verdict") or obj.get("final_verdict") or ""))
                        or None,
                        "first_party": first_party_ok(obj),
                        "contrib": obj.get("contribution_class") if isinstance(obj.get("contribution_class"), str) else None,
                        "scope": obj.get("scope_statement") if isinstance(obj.get("scope_statement"), str) else None,
                    }
                )

    usable = [r for r in rows if r["terminal"] and r["role"] != "inventory"]
    by_group = defaultdict(list)
    by_id = defaultdict(list)
    for r in usable:
        # Semantic mechanism identity is GHSA plus exact candidate/fix sets.
        # Mechanism_key is a label and must not split the same SHA pair.
        # Shared SHA alone (one set overlapping another GHSA) is not a group.
        by_group[(r["case_id"], tuple(r["cand"]), tuple(r["fix"]))].append(r)
        by_id[r["case_id"]].append(r)
    all_by_group = defaultdict(list)
    for r in rows:
        all_by_group[(r["case_id"], tuple(r["cand"]), tuple(r["fix"]))].append(r)

    clusters = []
    rejected_worker_only = 0
    rejected_same_model = 0
    rejected_conflict = 0
    rejected_canon = 0
    rejected_identity = 0
    rejected_no_sets = 0
    rejected_not_two = 0
    near = []
    conflict_hits = []
    canon_hits = []
    worker_hits = []

    for key, hits in by_group.items():
        cid, cand, fix = key
        fp = fingerprint(next((h["mech"] for h in hits if h.get("mech")), None), list(cand), list(fix))
        six_pass = [
            h
            for h in hits
            if all(h["gates"].get(k) == "PASS" for k in CAUSAL)
            and h["cand"]
            and h["fix"]
        ]
        if not six_pass:
            continue
        for shits in [six_pass]:
            # collapse to one row per packet (strongest source kind)
            by_pkt = {}
            for h in shits:
                prev = by_pkt.get(h["packet"])
                if prev is None or h["strength"] > prev["strength"]:
                    by_pkt[h["packet"]] = h
            pkts = list(by_pkt.values())
            ind = [p for p in pkts if is_independent_role(p["role"])]
            workers = [p for p in pkts if p["role"] == "worker"]
            summary_hit = {
                "case_id": cid,
                "fp": fp,
                "n_pkts": len(pkts),
                "n_ind": len(ind),
                "roles": sorted({p["role"] for p in pkts}),
                "packets": sorted({p["packet"] for p in pkts}),
                "cand": list(cand),
                "fix": list(fix),
                "release": sorted({p["gates"].get("release_gate") for p in pkts}),
                "canon": cid in canon,
            }
            if len(ind) < 2:
                if len(pkts) >= 2:
                    rejected_worker_only += 1
                    worker_hits.append(summary_hit)
                else:
                    rejected_not_two += 1
                    if cid not in canon:
                        near.append(summary_hit)
                continue
            # find a pair that is genuinely independent
            pair = None
            for i, a in enumerate(ind):
                for b in ind[i + 1 :]:
                    if genuinely_independent(a, b):
                        pair = (a, b)
                        break
                if pair:
                    break
            if not pair:
                rejected_same_model += 1
                near.append({**summary_hit, "why": "same_model_or_stem"})
                continue
            if cid in canon:
                rejected_canon += 1
                canon_hits.append(summary_hit)
                continue
            if not cand or not fix:
                rejected_no_sets += 1
                continue

            # equal-or-stronger causal conflict against this six-PASS vector
            top_strength = max(h["strength"] for h in pkts)
            veto = []
            for h in all_by_group[key]:
                if h["packet"] in by_pkt and all(h["gates"].get(k) == "PASS" for k in CAUSAL):
                    continue
                disagree = any(h["gates"].get(k) != "PASS" for k in CAUSAL)
                if not disagree:
                    continue
                # equal or stronger than the weakest independent member of the pair
                pair_min = min(pair[0]["strength"], pair[1]["strength"])
                if h["strength"] >= pair_min or h["strength"] >= top_strength:
                    veto.append(
                        {
                            "packet": h["packet"],
                            "role": h["role"],
                            "source": h["source"],
                            "gates": h["gates"],
                            "strength": list(h["strength"]),
                            "disagree_gates": [k for k in CAUSAL if h["gates"].get(k) != "PASS"],
                        }
                    )
            if veto:
                rejected_conflict += 1
                conflict_hits.append({**summary_hit, "veto": veto[:4]})
                continue

            adv = adv_idx.get(cid)
            current_fp = bool(adv) and not adv["withdrawn"] and adv.get("github_reviewed", True)
            # also accept first_party flags from agreeing packets if advisory missing but github.com cited
            packet_fp = any(p["first_party"] for p in (pair[0], pair[1]))
            if not (current_fp or packet_fp):
                rejected_identity += 1
                continue
            if adv and adv["withdrawn"]:
                rejected_identity += 1
                continue

            release_vals = sorted({p["gates"].get("release_gate") for p in (pair[0], pair[1])})
            release_agreed_pass = all(p["gates"].get("release_gate") == "PASS" for p in (pair[0], pair[1]))
            release_all_open = all(p["gates"].get("release_gate") in RELEASE_OPEN or p["gates"].get("release_gate") is None for p in (pair[0], pair[1]))

            extra_ind = [p for p in ind if genuinely_independent(pair[0], p) or genuinely_independent(pair[1], p) or p["packet"] in {pair[0]["packet"], pair[1]["packet"]}]
            n_ind = len({p["packet"] for p in extra_ind})
            max_role = max(ROLE_RANK[p["role"]] for p in extra_ind)
            latest_row = sorted(extra_ind, key=lambda p: p["strength"] + (p["source"], p["line"] or 0), reverse=True)[0]
            repo = pair[0]["repo"] or pair[1]["repo"] or latest_row["repo"]
            mech = latest_row["mech"] or pair[0]["mech"] or pair[1]["mech"]
            rec = {
                "case_id": cid,
                "fingerprint": fp,
                "mechanism_key": mech,
                "candidate_set": list(cand),
                "minimum_fix_set": list(fix),
                "parent_set": sorted(set(pair[0]["parent"] + pair[1]["parent"])),
                "repository": repo,
                "n_independent": n_ind,
                "pair": [
                    {
                        "packet": pair[0]["packet"],
                        "role": pair[0]["role"],
                        "model": pair[0]["model"],
                        "stem": pair[0]["stem"],
                        "source": pair[0]["source"],
                        "src_sha": pair[0]["src_sha"],
                        "kind": pair[0]["kind"],
                        "line": pair[0]["line"],
                        "gates": pair[0]["gates"],
                        "n_parents": pair[0]["n_parents"],
                        "contrib": pair[0]["contrib"],
                        "scope": pair[0]["scope"],
                        "verdict": pair[0]["verdict"],
                    },
                    {
                        "packet": pair[1]["packet"],
                        "role": pair[1]["role"],
                        "model": pair[1]["model"],
                        "stem": pair[1]["stem"],
                        "source": pair[1]["source"],
                        "src_sha": pair[1]["src_sha"],
                        "kind": pair[1]["kind"],
                        "line": pair[1]["line"],
                        "gates": pair[1]["gates"],
                        "n_parents": pair[1]["n_parents"],
                        "contrib": pair[1]["contrib"],
                        "scope": pair[1]["scope"],
                        "verdict": pair[1]["verdict"],
                    },
                ],
                "independent_packets": sorted({p["packet"] for p in extra_ind}),
                "worker_support": sorted({w["packet"] for w in workers}),
                "release_vals": release_vals,
                "release_agreed_pass": release_agreed_pass,
                "release_all_open": release_all_open,
                "current_first_party": current_fp,
                "packet_first_party": packet_fp,
                "advisory_path": adv["path"] if adv else None,
                "max_role_rank": max_role,
                "date_max": max(p["date"] for p in extra_ind),
                "contrib": latest_row["contrib"] or pair[0]["contrib"] or pair[1]["contrib"],
                "scope": latest_row["scope"] or pair[0]["scope"] or pair[1]["scope"],
                "latest_authority": latest_row["packet"],
                "latest_source": latest_row["source"],
                "latest_src_sha": latest_row["src_sha"],
                "latest_kind": latest_row["kind"],
                "latest_line": latest_row["line"],
                "latest_gates": latest_row["gates"],
                "latest_verdict": latest_row["verdict"],
                "latest_n_parents": latest_row["n_parents"],
                "independent_rows": [
                    {
                        "packet": p["packet"],
                        "role": p["role"],
                        "model": p["model"],
                        "stem": p["stem"],
                        "source": p["source"],
                        "src_sha": p["src_sha"],
                        "kind": p["kind"],
                        "line": p["line"],
                        "gates": p["gates"],
                        "date": p["date"],
                    }
                    for p in sorted(extra_ind, key=lambda x: (x["packet"], x["line"] or 0))
                ],
            }
            clusters.append(rec)

    def rank_key(c):
        # stronger: more independent packets, higher role, first-party advisory, 814, id
        rel_pref = 0 if c["release_agreed_pass"] else 1
        return (
            rel_pref,
            -c["n_independent"],
            -c["max_role_rank"],
            -c["date_max"],
            0 if c["current_first_party"] else 1,
            c["case_id"],
            c["fingerprint"],
        )

    clusters.sort(key=rank_key)
    released = [c for c in clusters if c["release_agreed_pass"]][:25]
    causal_only = [c for c in clusters if not c["release_agreed_pass"]]

    dump = {
        "canonical88_strict_count": 88,
        "canonical88_ledger_sha256": ledger_sha,
        "canonical88_summary_sha256": summary_sha,
        "scan_files": len(scan_files),
        "complete_causal_rows": len(rows),
        "terminal_non_inventory": len(usable),
        "schema_fail": schema_fail,
        "skipped_incomplete": skipped_incomplete,
        "advisory_index_size": len(adv_idx),
        "rejected": {
            "worker_only_or_not_independent_roles": rejected_worker_only,
            "same_model_or_same_stem": rejected_same_model,
            "equal_or_stronger_conflict": rejected_conflict,
            "canonical88": rejected_canon,
            "identity": rejected_identity,
            "no_sets": rejected_no_sets,
            "not_two_packets": rejected_not_two,
        },
        "n_clusters": len(clusters),
        "n_released": len(released),
        "n_causal_only": len(causal_only),
        "released": released,
        "causal_only": causal_only,
        "source_file_count": len(source_pins),
        "source_file_hashes": source_pins,
        "debug_conflict": conflict_hits,
        "debug_worker": worker_hits,
        "debug_near_noncanon_one_pkt": sorted(near, key=lambda x: x["case_id"])[:80],
        "debug_canon_sample": canon_hits[:10],
    }
    return dump

from pathlib import Path as _P
import hashlib as _hashlib
import json as _json
import subprocess as _sp

ROOT = _P("/home/hanqing/agents/ai-slop")
OWN = ROOT / "autoresearch/herdr-260814-causal-consensus-a-grok46-high"
LEDGER = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl"
SUMMARY = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json"
TAYLORED = _P("/home/hanqing/.cache/cve-analyzer/repos/tailot_taylored")
VITEST = _P("/home/hanqing/.cache/cve-analyzer/repos/vitest-dev_vitest")


def _sha(p: _P) -> str:
    return _hashlib.sha256(p.read_bytes()).hexdigest()


def _git(*args, cwd):
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    r = _sp.run(["git", *args], cwd=str(cwd), capture_output=True, text=True, env=env, check=True)
    err = "\n".join(ln for ln in (r.stderr or "").splitlines() if "unable to normalize alternate object path" not in ln)
    if err.strip():
        raise RuntimeError(err)
    return r.stdout


dump = main()
res = _json.loads((OWN / "result.json").read_text())
asn = [_json.loads(l) for l in (OWN / "assignment.jsonl").read_text().splitlines() if l.strip()]
cases = [_json.loads(l) for l in (OWN / "cases.jsonl").read_text().splitlines() if l.strip()]
report = (OWN / "report.md").read_text()
assert all(ord(c) < 128 for c in report)
assert res["canonical88_unchanged"] is True
assert res["canonical88_strict_count"] == 88
assert res["canonical_ledger_edited"] is False
assert res["causal_admission"] is False
assert res["pass_proposals"] == []
assert res["released_ids"] == []
assert res["counts"]["PASS"] == 0
assert res["counts"]["PASS_PROPOSAL"] == 0
assert res["counts"]["released_ranked"] == 0
assert dump["canonical88_ledger_sha256"] == _sha(LEDGER) == res["hash_roles"]["canonical88_ledger.jsonl"] == "35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074"
assert dump["canonical88_summary_sha256"] == _sha(SUMMARY) == res["hash_roles"]["canonical88_summary.json"] == "81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921"
assert dump["n_released"] == 0
assert [c["case_id"] for c in dump["causal_only"]] == res["causal_only_ids"] == [a["case_id"] for a in asn] == ["GHSA-8G98-M4J9-QWW5", "GHSA-VH5J-5FHQ-9XWG", "GHSA-G8MR-85JM-7XHM"]
assert len(asn) == 3
assert all(a["list_kind"] == "causal_only" and a["pass_proposal"] is False and a["canonical88_strict"] is False for a in asn)
assert not (set(res["causal_only_ids"]) & set(_json.loads(SUMMARY.read_text())["strict_released_case_ids"]))
assert res["canonical88_overlap"] == []
for pin in res["source_file_hashes"]:
    p = ROOT / pin["path"]
    assert p.is_file(), pin["path"]
    assert _sha(p) == pin["sha256"], pin["path"]
# shared SHA opposite roles
a8 = next(a for a in asn if a["case_id"] == "GHSA-8G98-M4J9-QWW5")
av = next(a for a in asn if a["case_id"] == "GHSA-VH5J-5FHQ-9XWG")
assert a8["minimum_fix_set"] == ["57b7634391959dbbdb39b387ac4dc68157cd58a1"]
assert av["candidate_set"] == ["57b7634391959dbbdb39b387ac4dc68157cd58a1"]
assert a8["fingerprint"] != av["fingerprint"]
assert a8["independent_packet_count"] >= 2 and av["independent_packet_count"] >= 2
assert next(a for a in asn if a["case_id"] == "GHSA-G8MR-85JM-7XHM")["independent_packet_count"] >= 2
props = [c for c in cases if c.get("inventory_role") == "causal_only_consensus_proposal"]
assert [c["case_id"] for c in props] == res["causal_only_ids"]
assert all(all(c["gates"][k] == "PASS" for k in CAUSAL) for c in props)
assert all(c["gates"]["release_gate"] in RELEASE_OPEN for c in props)
assert any(c.get("row_kind") == "fail_closed_conflict" and c["case_id"] == "GHSA-7C3W-FXGH-FRC7" for c in cases)
assert res["conservation"]["holds"] is True
assert res["conservation"]["did_not_pad"] is True
assert "Canonical88 stays 88" in report
assert "PASS_PROPOSAL=0" in report
assert "Shared SHA" in report or "shared SHA" in report
# live git replay of the three causal-only edges
assert int(_git("rev-list", "--parents", "-n", "1", "c139c021f68a09d22c2af88641b61c00f67f2af4", cwd=TAYLORED).split().__len__() - 1) == 1
assert int(_git("rev-list", "--parents", "-n", "1", "57b7634391959dbbdb39b387ac4dc68157cd58a1", cwd=TAYLORED).split().__len__() - 1) == 1
assert int(_git("rev-list", "--parents", "-n", "1", "fdf67a6fba0deae30912905a79fb5a9e83751a79", cwd=TAYLORED).split().__len__() - 1) == 1
assert "google-labs-jules[bot]" in _git("show", "-s", "--format=%an", "c139c021f68a09d22c2af88641b61c00f67f2af4", cwd=TAYLORED)
_git("merge-base", "--is-ancestor", "610281a664bd4e8c8d0c7052116bedaea5c8a4c6", "c139c021f68a09d22c2af88641b61c00f67f2af4", cwd=TAYLORED)
_git("merge-base", "--is-ancestor", "c139c021f68a09d22c2af88641b61c00f67f2af4", "57b7634391959dbbdb39b387ac4dc68157cd58a1", cwd=TAYLORED)
_git("merge-base", "--is-ancestor", "57b7634391959dbbdb39b387ac4dc68157cd58a1", "fdf67a6fba0deae30912905a79fb5a9e83751a79", cwd=TAYLORED)
assert _git("rev-parse", "fdf67a6fba0deae30912905a79fb5a9e83751a79^", cwd=TAYLORED).strip() == "f4d210457781256860c0779cc2090f957d1ebf3d"
assert int(_git("rev-list", "--parents", "-n", "1", "af88b1f5d82844a4761ea9a977156c98e2b14ca8", cwd=VITEST).split().__len__() - 1) == 1
assert int(_git("rev-list", "--parents", "-n", "1", "385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7", cwd=VITEST).split().__len__() - 1) == 1
assert "Codex" in _git("show", "-s", "--format=%B", "af88b1f5d82844a4761ea9a977156c98e2b14ca8", cwd=VITEST)
assert _git("rev-parse", "af88b1f5d82844a4761ea9a977156c98e2b14ca8:packages/browser/src/node/rpc.ts", cwd=VITEST).strip() == "358ac355f89983297c18932c68e5aea7d78020ea"
assert _git("rev-parse", "385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7:packages/browser/src/node/rpc.ts", cwd=VITEST).strip() == "72818584f0669b58db74b6e093e04173c083293e"
assert _git("rev-parse", "v3.2.4:packages/browser/src/node/rpc.ts", cwd=VITEST).strip() == "7619c5f0fc4b66ea0992e61e357331c6280e4a29"
assert _git("rev-parse", "v3.2.5:packages/browser/src/node/rpc.ts", cwd=VITEST).strip() == "72818584f0669b58db74b6e093e04173c083293e"
print("REPLAY_OK released=0 causal_only=3 overlap=0 canonical88=88 PASS_PROPOSAL=0")
ENDPY
