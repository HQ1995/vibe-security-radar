#!/usr/bin/env python3
"""Score blinded root selections after opening the sealed candidate map."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from collections import Counter
from pathlib import Path

from cohort.root_adjudication import canonical_sha256


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-dir", type=Path, required=True)
    parser.add_argument("--execution-dir", type=Path, required=True)
    parser.add_argument("--input-usd-per-million", type=float, default=0.2)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise SystemExit(f"{path}:{line_number}: row is not an object")
                rows.append(row)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _atomic_write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.input_usd_per_million < 0:
        raise SystemExit("input price assumption must be non-negative")
    sealed = _load_json(args.packet_dir / "sealed_candidate_map.json")
    pilot = _load_json(args.packet_dir / "pilot.json")
    execution = _load_json(args.execution_dir / "summary.json")
    if not isinstance(sealed, dict) or not isinstance(pilot, dict) or not isinstance(
        execution, dict
    ):
        raise SystemExit("root-adjudication scoring inputs are malformed")
    sealed_rows = sealed.get("rows")
    selected_specs = pilot.get("selected")
    if not isinstance(sealed_rows, list) or not isinstance(selected_specs, list):
        raise SystemExit("sealed map or pilot rows are malformed")
    sealed_by_packet = {
        str(row["packet_id"]): row for row in sealed_rows if isinstance(row, dict)
    }
    packet_rows = _load_jsonl(args.packet_dir / "packets.jsonl")
    packet_by_id = {str(row.get("packet_id") or ""): row for row in packet_rows}
    responses = _load_jsonl(args.execution_dir / "responses.jsonl")
    response_by_packet = {str(row["packet_id"]): row for row in responses}
    pilot_ids = {str(row["packet_id"]) for row in selected_specs if isinstance(row, dict)}
    if set(response_by_packet) != pilot_ids or not pilot_ids <= set(sealed_by_packet):
        raise SystemExit("responses do not conserve the frozen pilot packets")
    selected_order = [
        str(row["packet_id"]) for row in selected_specs if isinstance(row, dict)
    ]
    if not pilot_ids <= set(packet_by_id):
        raise SystemExit("pilot packets are unavailable")
    if execution.get("packet_input_sha256") != canonical_sha256(
        [packet_by_id[identifier] for identifier in selected_order]
    ):
        raise SystemExit("execution packet input does not match the scoring packet set")
    if execution.get("pilot_spec_sha256") != canonical_sha256(pilot):
        raise SystemExit("execution pilot specification does not match scoring input")

    rows: list[dict[str, object]] = []
    for spec in selected_specs:
        if not isinstance(spec, dict):
            raise SystemExit("pilot row is malformed")
        identifier = str(spec["packet_id"])
        secret = sealed_by_packet[identifier]
        response = response_by_packet[identifier]
        candidates = secret.get("candidates")
        if not isinstance(candidates, list):
            raise SystemExit("sealed candidates are malformed")
        candidate_by_id = {
            str(candidate["candidate_id"]): candidate
            for candidate in candidates
            if isinstance(candidate, dict)
        }
        decision = response.get("decision")
        selected_ids = (
            list(decision.get("selected_ids", []))
            if isinstance(decision, dict)
            else []
        )
        public_ids = set(str(value) for value in secret.get("public_exact_candidate_ids", []))
        control_ids = set(
            str(value)
            for value in secret.get("public_control_candidate_ids", public_ids)
        )
        selected_set = set(str(value) for value in selected_ids)
        source_class = str(secret.get("source_class") or "")
        exact_hit = bool(public_ids & selected_set) if public_ids else None
        control_hit = bool(control_ids & selected_set) if control_ids else None
        selected_candidates = [candidate_by_id[value] for value in selected_ids]
        rows.append(
            {
                "packet_id": identifier,
                "repository_identity": secret["repository_identity"],
                "advisory": secret["advisory"],
                "source_class": source_class,
                "reasoning_effort": spec["reasoning_effort"],
                "execution_status": response["status"],
                "decision": decision,
                "candidate_count": len(candidates),
                "selected_count": len(selected_ids),
                "selected_fraction": (
                    len(selected_ids) / len(candidates) if candidates else 0.0
                ),
                "selected_candidates": selected_candidates,
                "public_exact_candidate_ids": sorted(public_ids),
                "public_control_candidate_ids": sorted(control_ids),
                "public_control_equivalences": secret.get(
                    "public_control_equivalences", []
                ),
                "public_control_eligible": secret.get(
                    "public_control_eligible", bool(control_ids)
                ),
                "public_control_ineligible_reason": secret.get(
                    "public_control_ineligible_reason", ""
                ),
                "public_exact_control_hit": exact_hit,
                "public_control_closure_hit": control_hit,
            }
        )
    rows.sort(key=lambda row: str(row["packet_id"]))
    raw_controls = [
        row for row in rows if row["source_class"] == "public_exact_present"
    ]
    controls = [row for row in raw_controls if row["public_control_eligible"] is True]
    exact_control_hits = sum(
        row["public_exact_control_hit"] is True for row in raw_controls
    )
    control_hits = sum(
        row["public_control_closure_hit"] is True for row in controls
    )
    control_resolved = sum(row["execution_status"] == "RESOLVED" for row in controls)
    selected_total = sum(int(row["selected_count"]) for row in rows)
    candidate_total = sum(int(row["candidate_count"]) for row in rows)
    usage = execution.get("usage") if isinstance(execution.get("usage"), dict) else {}
    prompt_tokens = int(usage.get("prompt_tokens", 0) or 0)
    completion_tokens = int(usage.get("completion_tokens", 0) or 0)
    pilot_continue = (
        control_resolved == len(controls)
        and control_hits == len(controls)
        and selected_total < candidate_total
    )
    result = {
        "schema_version": 1,
        "artifact_kind": "sealed_root_adjudication_score",
        "pilot_id": pilot["pilot_id"],
        "gate_status": "CONTINUE" if pilot_continue else "REVISE_OR_STOP",
        "control_count": len(controls),
        "raw_public_boundary_control_count": len(raw_controls),
        "ineligible_public_boundary_control_count": len(raw_controls) - len(controls),
        "ineligible_public_boundary_reasons": dict(
            sorted(
                Counter(
                    str(row["public_control_ineligible_reason"] or "unspecified")
                    for row in raw_controls
                    if row["public_control_eligible"] is not True
                ).items()
            )
        ),
        "control_resolved_count": control_resolved,
        "public_exact_control_hit_count": exact_control_hits,
        "public_exact_control_recall": (
            exact_control_hits / len(raw_controls) if raw_controls else 0.0
        ),
        "public_control_closure_hit_count": control_hits,
        "public_control_closure_recall": (
            control_hits / len(controls) if controls else 0.0
        ),
        "candidate_count": candidate_total,
        "selected_count": selected_total,
        "candidate_reduction_fraction": (
            1 - selected_total / candidate_total if candidate_total else 0.0
        ),
        "decision_counts": dict(
            sorted(
                Counter(
                    str(row["decision"].get("decision") or "")
                    if isinstance(row["decision"], dict)
                    else "BLOCKED_EXECUTION"
                    for row in rows
                ).items()
            )
        ),
        "usage": usage,
        "input_price_assumption_usd_per_million": args.input_usd_per_million,
        "input_cost_estimate_usd": (
            prompt_tokens * args.input_usd_per_million / 1_000_000
        ),
        "completion_tokens_without_price_contract": completion_tokens,
        "claim_boundary": (
            "Raw OSV range-boundary exact recall is reported separately from an "
            "eligible public-control set. Eligibility requires that the SHA occur "
            "literally in the frozen CVE record; an inferred OSV range boundary is "
            "retained as a candidate but cannot serve as ground truth. The narrow "
            "control closure "
            "closure that also accepts a candidate only when it is a tree-identical "
            "parent of a referenced merge commit. Neither metric is precision, and "
            "association-only selections remain hypotheses. Model output never "
            "removes the all-commit fallback."
        ),
        "rows": rows,
    }
    result["result_sha256"] = canonical_sha256(result)
    _atomic_write(args.output, result)
    print("sealed root-adjudication pilot scored")
    print(f"  gate                  : {result['gate_status']}")
    print(
        "  raw boundary exact    : "
        f"{exact_control_hits}/{len(raw_controls)}"
    )
    print(f"  eligible controls     : {len(controls)}/{len(raw_controls)}")
    print(f"  closure controls      : {control_hits}/{len(controls)}")
    print(f"  candidates selected   : {selected_total}/{candidate_total}")
    print(f"  prompt tokens         : {prompt_tokens:,}")
    print(f"  completion tokens     : {completion_tokens:,}")
    print(f"  input cost assumption : ${result['input_cost_estimate_usd']:.6f}")
    print(f"  output                : {args.output}")
    return 0 if pilot_continue else 2


if __name__ == "__main__":
    raise SystemExit(main())
