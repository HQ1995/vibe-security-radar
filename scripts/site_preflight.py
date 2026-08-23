#!/usr/bin/env python3
"""Fail a site publish if public cases are missing dates, diffs, or identity.

A hole is a research task, not a skip. Fill the commit, advisory range, or
product repository, then republish. site_preflight_allowlist.json is only for
residuals that remain after that work, with a first-party reason.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = ROOT / "web/src/generated/research-data.json"
ALLOWLIST = ROOT / "scripts/site_preflight_allowlist.json"
GHSA_RE = re.compile(r"^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$", re.I)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\u3000-\u303f]")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def official_ids(case: dict) -> list[str]:
    values = [case.get("case_id"), *(case.get("aliases") or [])]
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "")
        if (GHSA_RE.match(text) or CVE_RE.match(text)) and text.upper() not in seen:
            seen.add(text.upper())
            out.append(text)
    return out


def has_hunks(case: dict) -> bool:
    evidence = case.get("code_evidence") or {}
    return bool(evidence.get("comparison_hunks") or evidence.get("candidate_hunks"))


def has_release(case: dict) -> bool:
    return bool(case.get("vulnerable_release") or case.get("fixed_release"))


def evaluate(payload: dict, allowlist: dict | None = None) -> tuple[list[str], list[str], dict]:
    allowlist = allowlist or {}
    diff_allow = {
        key.upper(): reason
        for key, reason in (allowlist.get("missing_diff") or {}).items()
    }
    release_allow = {
        key.upper(): reason
        for key, reason in (allowlist.get("missing_release") or {}).items()
    }
    cases = payload.get("cases") or []
    snapshot = payload.get("snapshot") or {}
    errors: list[str] = []
    warnings: list[str] = []
    seen_official: dict[str, str] = {}
    dated = 0
    hunks = 0
    releases = 0
    unused_diff_allow = set(diff_allow)
    unused_release_allow = set(release_allow)

    if snapshot.get("case_count") != len(cases):
        errors.append(
            f"snapshot.case_count={snapshot.get('case_count')} but cases={len(cases)}"
        )

    for case in cases:
        case_id = str(case.get("case_id") or "")
        key = case_id.upper()
        blob = json.dumps(case, ensure_ascii=False)
        if CJK_RE.search(blob):
            errors.append(f"{case_id}: CJK leaked into public fields")
        published = str(case.get("published_at") or "")
        if not DATE_RE.match(published):
            errors.append(f"{case_id}: missing published_at")
        else:
            dated += 1
        if has_hunks(case):
            hunks += 1
        elif key in diff_allow:
            unused_diff_allow.discard(key)
            warnings.append(f"{case_id}: no diff ({diff_allow[key]})")
        else:
            errors.append(
                f"{case_id}: no code comparison; add hunks or allowlist a reason"
            )
        ids = official_ids(case)
        if has_release(case):
            releases += 1
        elif ids:
            if key in release_allow:
                unused_release_allow.discard(key)
                warnings.append(f"{case_id}: no release range ({release_allow[key]})")
            else:
                errors.append(
                    f"{case_id}: official ID has no vulnerable/fixed release; fetch it or allowlist"
                )
        if case.get("contribution_class") == "AI_INCOMPLETE_REMEDIATION" and not case.get("ir_chain"):
            errors.append(f"{case_id}: incomplete remediation without ir_chain")
        if case.get("ir_chain") and case.get("contribution_class") != "AI_INCOMPLETE_REMEDIATION":
            errors.append(
                f"{case_id}: ir_chain present but class is {case.get('contribution_class')}"
            )
        ghsas = [item for item in ids if GHSA_RE.match(item)]
        if len(ghsas) > 1:
            errors.append(f"{case_id}: multiple GHSAs {ghsas}")
        for official in ids:
            owner = seen_official.get(official.upper())
            if owner and owner != case_id:
                errors.append(f"{official}: claimed by both {owner} and {case_id}")
            seen_official[official.upper()] = case_id
        if snapshot.get("unknown_publication_dates"):
            pass

    if unused_diff_allow:
        errors.append(
            "stale missing_diff allowlist: " + ", ".join(sorted(unused_diff_allow)[:12])
        )
    if unused_release_allow:
        errors.append(
            "stale missing_release allowlist: "
            + ", ".join(sorted(unused_release_allow)[:12])
        )
    if snapshot.get("unknown_publication_dates", 0) != len(cases) - dated:
        errors.append("snapshot unknown_publication_dates does not match cases")
    if snapshot.get("unknown_publication_dates", 0) != 0:
        errors.append("snapshot still reports unknown publication dates")

    stats = {
        "cases": len(cases),
        "dated": dated,
        "diffs": hunks,
        "releases": releases,
        "errors": len(errors),
        "warnings": len(warnings),
    }
    return errors, warnings, stats


def main(argv: list[str] | None = None) -> int:
    path = Path(argv[1]) if argv and len(argv) > 1 else DEFAULT_DATA
    payload = load_json(path)
    allowlist = load_json(ALLOWLIST) if ALLOWLIST.exists() else {}
    errors, warnings, stats = evaluate(payload, allowlist)
    print(
        json.dumps(
            {
                "preflight": "FAIL" if errors else "OK",
                "cases": stats["cases"],
                "dated": f"{stats['dated']}/{stats['cases']}",
                "diffs": f"{stats['diffs']}/{stats['cases']}",
                "releases": f"{stats['releases']}/{stats['cases']}",
                "allowlisted": stats["warnings"],
                "errors": stats["errors"],
            },
            sort_keys=True,
        )
    )
    verbose = os.environ.get("SITE_PREFLIGHT_VERBOSE") == "1"
    if verbose:
        for warning in warnings:
            print(f"warn: {warning}")
    if errors:
        print("preflight failed:")
        for error in errors[:40]:
            print(f"  {error}")
        if len(errors) > 40:
            print(f"  ... {len(errors) - 40} more")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
