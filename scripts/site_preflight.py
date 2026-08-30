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
PUBLICATION_STATUSES = ("confirmed", "qualified", "provisional")


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


def is_unpatched(case: dict) -> bool:
    record = case.get("unpatched")
    return isinstance(record, dict) and record.get("confirmed") is True


def unpatched_errors(case_id: str, case: dict) -> list[str]:
    record = case.get("unpatched")
    if record is None:
        return []
    if not isinstance(record, dict) or record.get("confirmed") is not True:
        return [f"{case_id}: unpatched record is present but not confirmed"]
    reason = str(record.get("reason") or "").strip()
    potential = record.get("potential_fix") if isinstance(record.get("potential_fix"), dict) else {}
    approach = str(potential.get("approach") or "").strip()
    rationale = str(potential.get("rationale") or "").strip()
    errors: list[str] = []
    if not reason:
        errors.append(f"{case_id}: unpatched record has no reason")
    if not approach or not rationale:
        errors.append(f"{case_id}: unpatched record has no potential_fix approach/rationale")
    if case.get("minimum_fix_set"):
        errors.append(f"{case_id}: unpatched case still has a fix set")
    return errors


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
    status_counts = {status: 0 for status in PUBLICATION_STATUSES}
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
        status = str(case.get("publication_status") or "")
        if status not in status_counts:
            errors.append(f"{case_id}: invalid publication_status {status!r}")
        else:
            status_counts[status] += 1
        evidence = case.get("code_evidence") or {}
        errors.extend(unpatched_errors(case_id, case))
        unpatched = is_unpatched(case)
        for role in ("candidate_hunks", "fix_hunks", "comparison_hunks"):
            for index, hunk in enumerate(evidence.get(role) or []):
                if not str(hunk.get("file") or "").strip():
                    errors.append(f"{case_id}: {role}[{index}] has no file")
        if status == "confirmed":
            gates = case.get("gates") or {}
            if not gates or set(gates.values()) != {"PASS"}:
                errors.append(f"{case_id}: confirmed case does not have all PASS gates")
            if case.get("publication_issues"):
                errors.append(
                    f"{case_id}: confirmed case has publication issues "
                    f"{case.get('publication_issues')}"
                )
            for field in (
                "candidate_set",
                "minimum_fix_set",
                "vulnerable_release",
                "fixed_release",
                "advisory_url",
            ):
                if field in {"minimum_fix_set", "fixed_release"} and unpatched:
                    continue
                if not case.get(field):
                    errors.append(f"{case_id}: confirmed case has no {field}")
            for role in ("candidate_hunks", "fix_hunks"):
                if role == "fix_hunks" and unpatched:
                    continue
                if not evidence.get(role):
                    errors.append(f"{case_id}: confirmed case has no {role}")
        published = str(case.get("published_at") or "")
        if not DATE_RE.match(published):
            errors.append(f"{case_id}: missing published_at")
        else:
            dated += 1
        language = str(
            ((case.get("repository_metadata") or {}).get("language") or "").strip()
        )
        if not language:
            errors.append(f"{case_id}: missing repository language")
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
        if has_release(case) or (unpatched and case.get("vulnerable_release")):
            releases += 1
        elif ids and not unpatched:
            if key in release_allow:
                unused_release_allow.discard(key)
                warnings.append(f"{case_id}: no release range ({release_allow[key]})")
            else:
                errors.append(
                    f"{case_id}: official ID has no vulnerable/fixed release; fetch it or allowlist"
                )
        elif ids and unpatched and not case.get("vulnerable_release"):
            if key in release_allow:
                unused_release_allow.discard(key)
                warnings.append(f"{case_id}: no release range ({release_allow[key]})")
            else:
                errors.append(
                    f"{case_id}: unpatched official ID has no vulnerable release; fetch it or allowlist"
                )
        if case.get("contribution_class") == "AI_INCOMPLETE_REMEDIATION" and not case.get("ir_chain"):
            errors.append(f"{case_id}: incomplete remediation without ir_chain")
        chain = case.get("ir_chain") or {}
        if chain and not chain.get("original_sha") and not str(
            chain.get("unresolved_reason") or ""
        ).strip():
            errors.append(f"{case_id}: ir_chain without original_sha needs unresolved_reason")
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
    expected_status_counts = {
        "confirmed": snapshot.get("confirmed_cases"),
        "qualified": snapshot.get("qualified_cases"),
        "provisional": snapshot.get("provisional_cases"),
    }
    if expected_status_counts != status_counts:
        errors.append(
            f"snapshot publication counts {expected_status_counts} "
            f"do not match cases {status_counts}"
        )
    census_total = sum(
        int(snapshot.get(field) or 0)
        for field in ("ledger_reviewed", "ledger_in_progress", "ledger_not_started")
    )
    if census_total != snapshot.get("ledger_total"):
        errors.append(
            f"ledger census totals {census_total} but ledger_total="
            f"{snapshot.get('ledger_total')}"
        )

    stats = {
        "cases": len(cases),
        "dated": dated,
        "diffs": hunks,
        "releases": releases,
        "languages": sum(
            1
            for case in cases
            if str(((case.get("repository_metadata") or {}).get("language") or "").strip())
        ),
        "publication_statuses": status_counts,
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
                "languages": f"{stats['languages']}/{stats['cases']}",
                "allowlisted": stats["warnings"],
                "errors": stats["errors"],
                "publication_statuses": stats["publication_statuses"],
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
