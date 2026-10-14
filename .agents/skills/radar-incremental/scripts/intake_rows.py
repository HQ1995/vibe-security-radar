#!/usr/bin/env python3
"""Select admissible new ledger rows from a verified delta; never writes Neon.

Admission policy, unchanged since the October run: a component new since the original
universe, or an explicitly linked off-ledger precursor from an earlier delta, with an
active reviewed GitHub advisory published inside the frozen window, exactly one reviewed
product repository corroborated by a same-repository security advisory, and no ledger
row, identity/source conflict or occupancy. Original-universe identities that would
otherwise qualify are deferred to product-source review. Admission is intake mapping
only, not research acceptance.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path

POLICY = ("New since the original universe, active reviewed advisory published in the frozen incremental "
          "window, one corroborated product repository, no identity/source conflict or foreign occupancy. "
          "Includes explicitly linked earlier off-ledger precursor identities; preserve their existing class_id.")
MAPPING_BASIS = ("GitHub reviewed source_code_location corroborated by a same-repository security advisory; "
                 "intake mapping only.")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def instant(value: str) -> datetime:
    text = value.upper().replace("Z", "+00:00")
    return datetime.fromisoformat(text if "+" in text[10:] else text + "+00:00")


def owner(component: dict) -> str:
    if component["identity"] == "EXISTING_UNIVERSE_NOT_IN_LEDGER":
        return component["prior_universe_class_ids"][0]
    return component["class_id"]


def reviewed_records(component: dict) -> list[dict]:
    return [r for r in component["source_records"] if r["source"] == "github" and not r["retired"]
            and "/ghsa-reviewed-" in r["path"] and r.get("reviewed_product_repository")]


def admissible(component: dict, window: dict) -> bool:
    start, end = instant(window["start"]), instant(window["end"])
    return (component["routing"] == "PRODUCT_SOURCE_REVIEW"
            and component["identity"] in {"NEW_TO_UNIVERSE", "EXISTING_UNIVERSE_NOT_IN_LEDGER"}
            and not component["ledger_class_ids"] and not component["occupancy"]
            and not component["source_capture_conflicts"] and not component["all_sources_retired"]
            and len(component["reviewed_product_repositories"]) == 1
            and (component["identity"] != "EXISTING_UNIVERSE_NOT_IN_LEDGER"
                 or len(component["prior_universe_class_ids"]) == 1)
            and any(start <= instant(r["published"]) <= end for r in reviewed_records(component)))


def row(component: dict, window: dict, delta: Path, coverage: Path) -> dict:
    repository = component["reviewed_product_repositories"][0]
    label = "incremental-reviewed-intake-" + instant(window["end"]).strftime("%Y%m%d")
    return {"advisories": len(component["public_ids"]), "advisory_ids": component["public_ids"],
            "advisory_ids_source": label, "class_id": owner(component),
            "repo": repository.removeprefix("https://github.com/"), "status": "UNANALYZED",
            "source_intake": {
                "admission_policy": POLICY, "delta_path": str(delta.resolve()), "delta_sha256": digest(delta),
                "records": component["source_records"],
                "repository_mapping": {
                    "basis": MAPPING_BASIS, "repository": repository.removeprefix("https://github.com/"),
                    "evidence": [{"reference": r["product_mapping_reference"],
                                  "repository": r["reviewed_product_repository"], "source_id": r["source_id"]}
                                 for r in reviewed_records(component)]},
                "research_acceptance": "NOT_ASSESSED_BY_INTAKE",
                "source_coverage_sha256": digest(coverage),
                "window": {key: window[key] for key in ("end", "inclusive", "start")}}}


def prior_identities(prior: list[Path]) -> dict[str, dict]:
    """Where each off-ledger identity was first recorded, oldest delta first."""
    found = {}
    for path in prior:
        sha = digest(path)
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if line.strip():
                found.setdefault(json.loads(line)["class_id"],
                                 {"line": number, "path": str(path.resolve()), "sha256": sha})
    return found


def select(delta: Path, coverage: Path, universe: Path, prior: list[Path]) -> tuple[list[dict], list[dict]]:
    window = json.loads(coverage.read_text())["window"]
    original = {json.loads(line)["class_id"] for line in universe.read_text().splitlines() if line.strip()}
    earlier = prior_identities(prior)
    admitted, deferred = {}, []
    for line in delta.read_text().splitlines():
        component = json.loads(line)
        if not admissible(component, window):
            continue
        if component["identity"] == "EXISTING_UNIVERSE_NOT_IN_LEDGER" and owner(component) in original:
            deferred.append({"class_id": owner(component), "public_ids": component["public_ids"],
                             "routing": "PRODUCT_SOURCE_REVIEW",
                             "reason": "original-universe identity; admitting it would widen the funnel policy"})
            continue
        if owner(component) in admitted:
            raise ValueError(f"{owner(component)}: two components claim one class ID; resolve the identity conflict")
        admitted[owner(component)] = row(component, window, delta, coverage)
        if component["identity"] == "EXISTING_UNIVERSE_NOT_IN_LEDGER":
            if owner(component) not in earlier:
                raise ValueError(f"{owner(component)}: off-ledger precursor missing from the prior delta chain")
            admitted[owner(component)]["source_intake"]["prior_identity"] = earlier[owner(component)]
    return [admitted[key] for key in sorted(admitted)], deferred


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--delta", type=Path, required=True, help="classification/delta.jsonl from build_delta.py")
    parser.add_argument("--capture", type=Path, required=True, help="the capture directory the delta classified")
    parser.add_argument("--universe", type=Path, required=True, help="the original universe rows")
    parser.add_argument("--prior-delta", type=Path, action="append", default=[],
                        help="earlier delta.jsonl files, oldest first (the same chain build_delta used)")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    rows, deferred = select(args.delta, args.capture / "coverage.json", args.universe, args.prior_delta)
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "new-ledger-rows.jsonl").write_text(
        "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows))
    (args.out / "deferred.jsonl").write_text("".join(json.dumps(d, sort_keys=True) + "\n" for d in deferred))
    (args.out / "manifest.txt").write_text("".join(r["class_id"] + "\n" for r in rows))
    summary = {"admitted": len(rows), "deferred": len(deferred), "delta_sha256": digest(args.delta),
               "rows_sha256": digest(args.out / "new-ledger-rows.jsonl"), "policy": POLICY}
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
