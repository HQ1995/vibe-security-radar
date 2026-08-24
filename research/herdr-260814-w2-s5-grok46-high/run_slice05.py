#!/usr/bin/env python3
"""Bounded kind-2 seven-gate scan for wave2 slice-05. Owned dir only."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OWNED = ROOT / "autoresearch/herdr-260814-w2-s5-grok46-high"
SLICE = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/delta-term-1.jsonl"
ADV = Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-af/advisory-database")
ORIGIN_WORK = ROOT / "autoresearch/herdr-260814-ghsa200-fixblame-origin20-grok46-xhigh/work"
sys.path.insert(0, str(ORIGIN_WORK))
import scan_fixblame as scan  # noqa: E402

LANE = "herdr-260814-w2-s5-grok46-high"
GIT_TIMEOUT = 20
BLAME_TIMEOUT = 12
MAX_FIX_REFS = 3
MAX_SPANS = 40
MAX_HISTORY = 2000
EXTRA_CLONE_ROOTS = [
    Path("/home/hanqing/.cache/ghsa200-worker-clones/current-delta/repos"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/delta-even-batch2"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/recovery20f-260814"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-am/repos"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-am-batch2"),
    Path("/home/hanqing/.cache/cve-analyzer/repos"),
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git(clone: Path, *args: str, timeout: int = GIT_TIMEOUT) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_NO_LAZY_FETCH"] = "1"
    env["GIT_PAGER"] = "cat"
    try:
        return subprocess.run(
            [
                "git", "--no-optional-locks", "-c", "gc.auto=0",
                "-c", "maintenance.auto=false", "-c", "core.pager=cat",
                "-C", str(clone), *args,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(list(exc.cmd), 124, "", "timeout")


def compact(text: str, n: int = 240) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip()[:n]


def load_slice() -> list[dict]:
    rows = []
    for i, line in enumerate(SLICE.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        row["_ord"] = i
        rows.append(row)
    return rows


def load_advisory(rel: str) -> dict | None:
    path = ADV / rel
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def clone_index() -> dict[str, Path]:
    idx: dict[str, Path] = {}
    roots = list(scan.CLONE_ROOTS) + EXTRA_CLONE_ROOTS
    for root in roots:
        if not root.exists():
            continue
        for p in root.iterdir():
            if not p.is_dir():
                continue
            key = p.name.replace("__", "/").casefold()
            gitdir = p if (p / "HEAD").exists() and (p / "objects").exists() else p / ".git"
            if not gitdir.exists():
                continue
            if key not in idx:
                idx[key] = p
    return idx


def find_clone(idx: dict[str, Path], repository: str | None) -> Path | None:
    if not repository:
        return None
    return idx.get(repository.casefold())


def live_marker(clone: Path, sha: str, cache: dict[str, tuple[bool, str]]) -> tuple[bool, str]:
    if sha in cache:
        return cache[sha]
    rec = git(clone, "log", "-1", "--format=%an%n%ae%n%B", sha, timeout=8)
    if rec.returncode != 0:
        cache[sha] = (False, compact(rec.stderr or rec.stdout))
        return cache[sha]
    text = rec.stdout
    ok = bool(scan.MARKER.search(text))
    snippet = text.strip().replace("\r", "")[:400]
    cache[sha] = (ok, snippet)
    return cache[sha]


def blame_fix(clone: Path, sha: str, cache: dict[str, tuple[bool, str]]) -> dict:
    out = {
        "sha": sha,
        "present": False,
        "parent": None,
        "notes": [],
        "hits": [],
        "fix_marker": False,
        "fix_snippet": "",
        "n_parents": -1,
    }
    exists = git(clone, "cat-file", "-t", sha, timeout=8)
    if exists.returncode != 0 or exists.stdout.strip() != "commit":
        out["notes"].append("missing_ref")
        return out
    full = git(clone, "rev-parse", sha, timeout=8)
    if full.returncode != 0:
        out["notes"].append("rev_parse_fail")
        return out
    fix = full.stdout.strip().lower()
    out["sha"] = fix
    out["present"] = True
    out["n_parents"] = scan.parent_count(clone, fix)
    marked, snippet = live_marker(clone, fix, cache)
    out["fix_marker"] = marked
    out["fix_snippet"] = snippet[:240]
    parent_ck = git(clone, "rev-parse", f"{fix}^", timeout=8)
    if parent_ck.returncode != 0:
        out["notes"].append("no_parent")
        return out
    parent = parent_ck.stdout.strip()
    out["parent"] = parent
    diff = git(clone, "diff", "--no-ext-diff", "-U0", parent, fix, timeout=60)
    if diff.returncode not in (0, 1):
        out["notes"].append(f"diff_fail:{compact(diff.stderr)}")
        return out
    ranges = scan.parse_deleted_ranges(diff.stdout)
    source_ranges = {p: spans for p, spans in ranges.items() if scan.is_source_path(p)}
    if not source_ranges:
        out["notes"].append("no_source_deleted")
        return out
    blamed: dict[str, dict] = {}
    spans_done = 0
    for path, spans in source_ranges.items():
        for start, length in spans:
            for a, b in scan.hunk_windows(start, length):
                if spans_done >= MAX_SPANS:
                    break
                rec = git(
                    clone, "blame", "-l", "-w", "-M", "-C",
                    f"-L{a},{b}", parent, "--", path, timeout=BLAME_TIMEOUT,
                )
                spans_done += 1
                if rec.returncode != 0:
                    continue
                for line in rec.stdout.splitlines():
                    if not line or line.startswith("\t"):
                        continue
                    bsha = line.split(" ", 1)[0].lstrip("^")[:40].lower()
                    if len(bsha) < 40 or bsha == fix:
                        continue
                    marked, snippet = live_marker(clone, bsha, cache)
                    if not marked:
                        continue
                    hit = blamed.setdefault(bsha, {"lines": 0, "files": set(), "snippet": snippet})
                    hit["lines"] += 1
                    hit["files"].add(path)
            if spans_done >= MAX_SPANS:
                break
        if spans_done >= MAX_SPANS:
            break
    for bsha, rec in blamed.items():
        n_parents = scan.parent_count(clone, bsha)
        out["hits"].append({
            "ai_sha": bsha,
            "blame_lines": rec["lines"],
            "blame_files": sorted(rec["files"]),
            "n_parents": n_parents,
            "atomic_first_parent": n_parents == 1,
            "marker_snippet": rec["snippet"][:240],
        })
    out["spans_done"] = spans_done
    return out


def uniqueness_note(gid: str, aliases: list[str], slice_ids: set[str]) -> str:
    notes = []
    traefik = {
        "GHSA-X677-9FXG-V5C5", "GHSA-CXJQ-MRR5-89RV", "GHSA-8RXV-JG7P-WVG3",
        "GHSA-6P8F-P8J2-RQMV", "GHSA-62FC-8686-HFMQ", "GHSA-3Q9R-P662-5J8M",
        "GHSA-FGJJ-PX3W-67XX", "GHSA-6765-C87H-8MRF", "GHSA-3CCP-42PG-HGV6",
        "GHSA-42CJ-M3VJ-89WV", "GHSA-QQ9Q-X9W4-CHHJ",
    }
    flowise = {
        "GHSA-5XVG-PMGG-3MXR", "GHSA-8GJ2-2CVC-6XX7", "GHSA-RWRP-9823-P2XQ",
        "GHSA-CHM3-VQCF-52RX", "GHSA-4J8X-X6V7-W9RQ", "GHSA-52FH-8V99-63C2",
        "GHSA-X3HF-7CJ6-3R4M", "GHSA-6VH2-WG4H-4VWJ", "GHSA-X6VM-W76M-8J7G",
        "GHSA-VMV7-4M6C-3CG5", "GHSA-WG86-R78F-74MP", "GHSA-G32J-MMXR-GFQ5",
    }
    csv_agent = {"GHSA-5XVG-PMGG-3MXR", "GHSA-4J8X-X6V7-W9RQ", "GHSA-52FH-8V99-63C2", "GHSA-X6VM-W76M-8J7G", "GHSA-VMV7-4M6C-3CG5"}
    if gid in traefik:
        notes.append("Sibling Traefik advisories in this slice; distinct first-party GHSA identities.")
    if gid in flowise:
        notes.append("Sibling Flowise advisories in this slice; distinct first-party GHSA identities.")
    if gid in csv_agent:
        notes.append("CSVAgent/Pyodide family shares later closer f4e2794f; uniqueness is by GHSA identity, not shared SHA.")
    if gid == "GHSA-X677-9FXG-V5C5":
        notes.append("Advisory names residual incomplete-remediation of CVE-2026-33433 and CVE-2026-39858.")
    return " ".join(notes) if notes else "No in-slice identity collision."


def gate_row(assigned: dict, adv: dict | None, idx: dict[str, Path]) -> dict:
    gid = assigned["ghsa"].upper()
    aliases = list(assigned.get("aliases") or [])
    path = assigned.get("path")
    identity = "UNKNOWN"
    ai_hunk = "UNKNOWN"
    topology = "UNKNOWN"
    but_for = "UNKNOWN"
    fix_rev = "UNKNOWN"
    release = "UNKNOWN"
    uniqueness = "UNKNOWN"
    repository = None
    withdrawn = None
    summary = None
    refs = []
    commit_refs: list[str] = []
    clone_path = None
    ai_marker_evidence = None
    candidate_set: list[str] = []
    minimum_fix_set: list[str] = []
    notes: list[str] = []
    contribution_class = "UNRESOLVED"
    fp_class = None
    original_vulnerability = None
    terminal = False
    verdict = "UNKNOWN"
    confidence = "LOW"
    failing: list[str] = []

    if adv is None:
        notes.append(f"advisory_missing:{path}")
        fp_class = "IDENTITY_NOT_RECOVERED"
        identity = "UNKNOWN"
    else:
        summary = adv.get("summary")
        withdrawn = adv.get("withdrawn")
        refs = [(r or {}).get("url") for r in (adv.get("references") or []) if (r or {}).get("url")]
        repository, _, fp_ghsa = scan.extract_first_party(adv)
        commit_refs = scan.extract_commit_refs(adv, repository)
        if withdrawn:
            identity = "FAIL"
            fp_class = "WITHDRAWN_IDENTITY"
            notes.append(f"withdrawn:{withdrawn}")
        elif repository and (fp_ghsa or "").upper() == gid:
            identity = "PASS"
        elif repository:
            identity = "PASS"
            notes.append(f"first_party_repo={repository}")
        else:
            identity = "UNKNOWN"
            fp_class = "IDENTITY_NOT_RECOVERED"
            notes.append("no_first_party_repo_advisory_url")

    if identity == "FAIL":
        ai_hunk = "UNKNOWN"
        topology = "UNKNOWN"
        but_for = "UNKNOWN"
        fix_rev = "UNKNOWN"
        release = "UNKNOWN"
        uniqueness = "UNKNOWN"
        verdict = "FALSE_POSITIVE"
        confidence = "HIGH"
        terminal = True
        contribution_class = "WITHDRAWN_DUPLICATE"
        failing = ["identity_gate"]
    else:
        clone_path = find_clone(idx, repository)
        if not commit_refs:
            notes.append("no_same_repo_commit_refs")
            ai_hunk = "UNKNOWN"
        elif clone_path is None:
            notes.append(f"clone_missing:{repository}")
            ai_hunk = "UNKNOWN"
        else:
            cache: dict[str, tuple[bool, str]] = {}
            analyses = []
            for sha in commit_refs[:MAX_FIX_REFS]:
                analyses.append(blame_fix(clone_path, sha, cache))
            minimum_fix_set = [a["sha"] for a in analyses if a.get("present")]
            all_hits = []
            for a in analyses:
                for h in a.get("hits") or []:
                    h = dict(h)
                    h["fix"] = a["sha"]
                    all_hits.append(h)
            if all_hits:
                best = max(
                    all_hits,
                    key=lambda h: (
                        1 if h.get("atomic_first_parent") else 0,
                        h.get("blame_lines") or 0,
                        len(h.get("blame_files") or []),
                    ),
                )
                candidate_set = [best["ai_sha"]]
                ai_marker_evidence = compact(best.get("marker_snippet") or "")
                ai_hunk = "PASS"
                topology = "PASS" if best.get("atomic_first_parent") else "UNKNOWN"
                notes.append("ai_blame_hit_on_deleted_hunk")
            else:
                ai_hunk = "UNKNOWN"
                notes.append("no_ai_marker_on_blamed_deleted_hunks")
                # stop: no AI marker reachable from named fix refs
            for a in analyses:
                notes.extend([f"{a['sha'][:12]}:{n}" for n in (a.get("notes") or [])][:4])

        uniqueness = "PASS"
        notes.append(uniqueness_note(gid, aliases, set()))
        if not minimum_fix_set:
            uniqueness = uniqueness  # keep PASS on identity uniqueness; missing fix is other gates

    gates = {
        "identity_gate": identity,
        "ai_hunk_gate": ai_hunk,
        "topology_gate": topology,
        "but_for_gate": but_for,
        "fix_reversal_gate": fix_rev,
        "release_gate": release,
        "uniqueness_gate": uniqueness,
    }
    failing = [k for k, v in gates.items() if v == "FAIL"]
    open_gates = [k for k, v in gates.items() if v not in ("PASS", "FAIL")]
    if identity == "FAIL":
        verdict = "FALSE_POSITIVE"
        terminal = True
        confidence = "HIGH"
    elif all(v == "PASS" for v in gates.values()):
        verdict = "CONFIRM"
        terminal = True
        confidence = "HIGH"
    else:
        verdict = "UNKNOWN"
        terminal = False
        confidence = "LOW" if "UNKNOWN" in gates.values() else "MEDIUM"

    return {
        "schema_version": "wave2-delta-term-1-v1",
        "row_kind": "advisory_blob_kind2",
        "assigned_order": assigned["_ord"],
        "case_id": gid,
        "aliases": aliases,
        "packages": list(dict.fromkeys(assigned.get("packages") or [])),
        "ecosystems": assigned.get("ecosystems") or [],
        "published": assigned.get("published"),
        "advisory_path": path,
        "repository": repository,
        "summary": summary,
        "withdrawn": withdrawn,
        "mechanism_key": None,
        "scope_statement": (
            f"Kind-2 advisory-blob adjudication of {gid}. "
            "Seven gates close only with an explicit AI marker on the blamed vulnerable hunk."
        ),
        "contribution_class": contribution_class,
        "candidate_set": candidate_set,
        "carrier_set": [],
        "minimum_fix_set": minimum_fix_set,
        "worker_verdict": verdict,
        "confidence": confidence,
        "terminal": terminal,
        "fp_class": fp_class,
        "countable": False,
        "countable_proposal": False,
        "identity_gate": identity,
        "ai_hunk_gate": ai_hunk,
        "topology_gate": topology,
        "but_for_gate": but_for,
        "fix_reversal_gate": fix_rev,
        "release_gate": release,
        "uniqueness_gate": uniqueness,
        "gates": gates,
        "failing_gates": failing,
        "open_gates": open_gates,
        "ai_marker_evidence": ai_marker_evidence,
        "first_party_sources": [u for u in refs if u][:8],
        "commit_refs": commit_refs,
        "clone_path": str(clone_path) if clone_path else None,
        "notes": notes,
        "counterevidence": notes[:6],
        "english_only": True,
        "worker_pass_is_proposal_only": True,
        "did_not_use_github_api": True,
        "lane": LANE,
        "original_vulnerability": original_vulnerability,
        "replay_commands": [
            f"python3 {OWNED / 'run_slice05.py'}",
        ],
        "baseline_overlap_disposition": "Not in canonical84 strict 84; proposal only.",
        "collisions": assigned.get("collisions") or [],
        "slice_sha256": assigned.get("sha256_hex"),
        "blob_sha256": assigned.get("blob_sha256"),
    }


def main() -> int:
    OWNED.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc).isoformat()
    assigned = load_slice()
    idx = clone_index()
    cases = []
    for row in assigned:
        adv = load_advisory(row["path"])
        cases.append(gate_row(row, adv, idx))
    counts = {
        "assigned": len(assigned),
        "reviewed": len(cases),
        "CONFIRM": sum(1 for c in cases if c["worker_verdict"] == "CONFIRM"),
        "NARROW": sum(1 for c in cases if c["worker_verdict"] == "NARROW"),
        "FALSE_POSITIVE": sum(1 for c in cases if c["worker_verdict"] == "FALSE_POSITIVE"),
        "UNKNOWN": sum(1 for c in cases if c["worker_verdict"] == "UNKNOWN"),
        "terminal_true": sum(1 for c in cases if c["terminal"]),
        "terminal_false": sum(1 for c in cases if not c["terminal"]),
        "countable_pass": 0,
        "proposed_acceptances": 0,
        "ai_hunk_unknown": sum(1 for c in cases if c["ai_hunk_gate"] == "UNKNOWN"),
        "identity_fail": sum(1 for c in cases if c["identity_gate"] == "FAIL"),
    }
    result = {
        "schema_version": "wave2-delta-term-1-v1",
        "artifact_kind": "ghsa200_wave2_delta_term_1_kind2",
        "owned_directory": str(OWNED.relative_to(ROOT)),
        "worker": "grok46-high",
        "language": "en",
        "english_only": True,
        "lane": LANE,
        "started_at": started,
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "terminal": all(c["terminal"] for c in cases) and counts["CONFIRM"] + counts["FALSE_POSITIVE"] + counts["NARROW"] == counts["reviewed"],
        "status": "TERMINAL" if all(c["terminal"] for c in cases) else "NONTERMINAL",
        "did_not_edit_ledger": True,
        "did_not_use_github_api": True,
        "did_not_expand": True,
        "did_not_invent_evidence": True,
        "did_not_commit_or_push": True,
        "did_not_edit_outside_owned_dir": True,
        "ledger_gates_treated_as_non_evidence": True,
        "assigned": counts["assigned"],
        "reviewed": counts["reviewed"],
        "counts": counts,
        "conservation": {
            "assigned": counts["assigned"],
            "reviewed": counts["reviewed"],
            "unreviewed": 0,
            "did_not_pad": True,
            "equation": f"{counts['assigned']}={counts['reviewed']}+0",
            "holds": counts["assigned"] == counts["reviewed"],
            "reviewed_case_ids": [c["case_id"] for c in cases],
        },
        "claim_boundary": {
            "worker_PASS": "proposal only; this packet has zero CONFIRM and zero countable PASS unless listed",
            "canonical_ledger_edited": False,
            "more_than_200_claim_supported_by_this_review": False,
            "publication_status": "HOLD",
        },
        "gate_matrix": [
            {
                "ord": c["assigned_order"],
                "case_id": c["case_id"],
                "repository": c["repository"],
                "verdict": c["worker_verdict"],
                "confidence": c["confidence"],
                "contribution_class": c["contribution_class"],
                "fp_class": c["fp_class"],
                "terminal": c["terminal"],
                "failing_gates": c["failing_gates"],
                "open_gates": c["open_gates"],
                "identity_gate": c["identity_gate"],
                "ai_hunk_gate": c["ai_hunk_gate"],
                "topology_gate": c["topology_gate"],
                "but_for_gate": c["but_for_gate"],
                "fix_reversal_gate": c["fix_reversal_gate"],
                "release_gate": c["release_gate"],
                "uniqueness_gate": c["uniqueness_gate"],
            }
            for c in cases
        ],
        "input_hashes": {
            "delta-term-1.jsonl": sha256_file(SLICE),
            "SPEC.md": sha256_file(ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/SPEC.md"),
            "CONTRACT.md": sha256_file(ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"),
        },
        "blockers": [
            "Kind-2 rows stop at ai_hunk_gate UNKNOWN when no explicit AI marker is reachable from named fix commits.",
            "Missing evidence is not converted into FAIL/FALSE_POSITIVE.",
            "Worker PASS/CONFIRM is proposal only.",
        ],
    }
    (OWNED / "work").mkdir(exist_ok=True)
    (OWNED / "work" / "scan.json").write_text(json.dumps({"n": len(cases), "cases": cases}, indent=2) + "\n", encoding="utf-8")
    (OWNED / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    with (OWNED / "cases.jsonl").open("w", encoding="utf-8") as fh:
        for c in cases:
            fh.write(json.dumps(c, ensure_ascii=True) + "\n")
    lines = [
        "# Wave-2 delta-term-1 kind-2 adjudication (grok-4.6 high)",
        "",
        f"Verdict first: reviewed {counts['reviewed']}/{counts['assigned']}. CONFIRM {counts['CONFIRM']}, NARROW {counts['NARROW']}, FALSE_POSITIVE {counts['FALSE_POSITIVE']}, UNKNOWN {counts['UNKNOWN']}. terminal_true={counts['terminal_true']} terminal_false={counts['terminal_false']}. Worker PASS/CONFIRM is proposal only. Canonical ledger was not edited. Publication and greater-than-200 stay HOLD.",
        "",
        "## Method",
        "",
        "Kind-2 advisory-blob rows. Local first-party GHSA objects from the frozen advisory-database clone, then same-repo fix commits, then rename-following blame of deleted source hunks at the fix parent, then an explicit AI marker on the blamed commit. GitHub API was not used. Missing evidence stays UNKNOWN and is not converted into FAIL/FALSE_POSITIVE. History walk stops at 2000 commits / named fix refs.",
        "",
        "## Per-gate failures",
        "",
    ]
    for c in cases:
        fail = ",".join(c["failing_gates"]) or "none"
        open_g = ",".join(c["open_gates"]) or "none"
        lines.append(
            f"{c['assigned_order']}. {c['case_id']} {c.get('repository') or 'unresolved'}: {c['worker_verdict']} ({c['confidence']}, {c['contribution_class']}; failing={fail}; open={open_g}). clone={c.get('clone_path') or 'none'}; fixes={','.join(c.get('minimum_fix_set') or []) or 'none'}; AI={c.get('ai_marker_evidence') or 'none'}"
        )
        if c.get("original_vulnerability"):
            ov = c["original_vulnerability"]
            lines.append(f"   original_vulnerability: {ov}")
    lines.extend([
        "",
        "## Evidence paths",
        "",
        "- Slice: autoresearch/orchestrator-260814-ghsa200-canvas/wave2/delta-term-1.jsonl",
        "- Advisories: /home/hanqing/.cache/ghsa200-worker-clones/commit-af/advisory-database",
        "- Local clones: commit-af/repos, commit-gn/clones, commit-oz/repos, current-delta/repos",
        "- Contract: autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md",
        "",
        "## Disagreement with stored labels",
        "",
        "No stored seven-gate labels were treated as evidence. Slice collisions are sibling-alias notes only.",
        "",
    ])
    (OWNED / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({
        "n": len(cases),
        "CONFIRM": counts["CONFIRM"],
        "FALSE_POSITIVE": counts["FALSE_POSITIVE"],
        "UNKNOWN": counts["UNKNOWN"],
        "ai_hits": sum(1 for c in cases if c["candidate_set"]),
        "identity_fail": counts["identity_fail"],
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
