#!/usr/bin/env python3
"""Build final mechanism, public-case, ID-conservation, and experience ledgers."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from build_conflicts import DETAIL_FIELDS
from verify import HERE, load_jsonl, verify_row


def compact(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_numbered(directory: str) -> dict[int, dict]:
    rows: dict[int, dict] = {}
    for path in sorted((HERE / directory).glob("*.jsonl")):
        for row in load_jsonl(path):
            assert row["ordinal"] not in rows
            rows[row["ordinal"]] = row
    return rows


def build() -> dict[Path, str]:
    manifest_rows = load_jsonl(HERE / "manifest.jsonl")
    manifest = {row["ordinal"]: row for row in manifest_rows}
    first = load_numbered("shards")
    second = load_numbered("crossreviews")
    adjudicated = load_numbered("adjudications")
    conflict_ordinals = {
        row["ordinal"]
        for path in sorted((HERE / "conflict_inputs").glob("*.jsonl"))
        for row in load_jsonl(path)
    }
    assert set(manifest) == set(first) == set(second) == set(range(1, 212))
    assert len(conflict_ordinals) == 45
    assert set(adjudicated) == conflict_ordinals

    final = []
    for ordinal in range(1, 212):
        if ordinal in conflict_ordinals:
            row = adjudicated[ordinal]
        else:
            assert all(first[ordinal][field] == second[ordinal][field] for field in DETAIL_FIELDS)
            row = second[ordinal]
        verify_row(row, manifest[ordinal])
        final.append(row)

    cases = []
    id_to_cases: dict[str, list[str]] = {}
    for row in final:
        source = manifest[row["ordinal"]]
        ghsas = sorted(value for value in row["public_ids_keep"] if value.startswith("GHSA-"))
        cves = sorted(value for value in row["public_ids_keep"] if value.startswith("CVE-"))
        if len(ghsas) == 2:
            assert row["ordinal"] == 200
            mapping = {
                "GHSA-3J8Q-FWPJ-F8J5": ["CVE-2026-58407"],
                "GHSA-JJCJ-H3CM-P7X7": ["CVE-2026-58410"],
            }
            assert set(ghsas) == set(mapping) and set(cves) == {value for values in mapping.values() for value in values}
        elif len(ghsas) == 1:
            mapping = {ghsas[0]: cves}
        else:
            assert not ghsas and cves
            mapping = {cves[0]: cves[1:]}
        for case_id, aliases in sorted(mapping.items()):
            related = sorted(value for value in mapping if value != case_id)
            case = {
                "schema_version": 1,
                "case_id": case_id,
                "aliases": sorted(aliases),
                "related_case_ids": related,
                "identity_relation": source.get("identity_relation") or "ROW_PUBLIC_ID_ASSOCIATION",
                "ordinal": row["ordinal"],
                "row_key": row["row_key"],
                "repository": source.get("repository"),
                "source_tier": source.get("source_tier"),
                "verdict": row["verdict"],
                "confidence": row["confidence"],
                "causal_class": row["causal_class"],
                "mechanism_key": source.get("mechanism_key"),
                "strict_confirmed": row["verdict"] == "CONFIRM",
                "causal_valid": row["verdict"] in {"CONFIRM", "NARROW"},
            }
            cases.append(case)
            id_to_cases[case_id] = [case_id]
            for alias in aliases:
                assert alias not in id_to_cases
                id_to_cases[alias] = [case_id]

    cases.sort(key=lambda row: row["case_id"])
    assert len(cases) == len({row["case_id"] for row in cases}) == 212

    dispositions = []
    for source in manifest_rows:
        row = final[source["ordinal"] - 1]
        for public_id in sorted(source["public_ids"]):
            kept = public_id in row["public_ids_keep"]
            dispositions.append({
                "schema_version": 1,
                "public_id": public_id,
                "id_type": "GHSA" if public_id.startswith("GHSA-") else "CVE",
                "disposition": "KEPT" if kept else "REMOVED_IDENTITY",
                "case_ids": id_to_cases.get(public_id, []),
                "ordinal": row["ordinal"],
                "row_key": row["row_key"],
                "mechanism_verdict": row["verdict"],
            })
    dispositions.sort(key=lambda row: row["public_id"])
    assert len(dispositions) == len({row["public_id"] for row in dispositions}) == 381

    tags: dict[str, list[int]] = defaultdict(list)
    false_classes: dict[str, list[int]] = defaultdict(list)
    for row in final:
        for tag in row["experience_tags"]:
            tags[tag].append(row["ordinal"])
        if row["verdict"] == "FALSE_POSITIVE":
            false_classes[row["false_positive_class"].lower()].append(row["ordinal"])
    experience = {
        "schema_version": 1,
        "experience_tags": [
            {"tag": tag, "count": len(ordinals), "ordinals": ordinals}
            for tag, ordinals in sorted(tags.items(), key=lambda item: (-len(item[1]), item[0]))
        ],
        "false_positive_classes": [
            {"class": label, "count": len(ordinals), "ordinals": ordinals}
            for label, ordinals in sorted(false_classes.items(), key=lambda item: (-len(item[1]), item[0]))
        ],
    }

    mechanism_counts = Counter(row["verdict"] for row in final)
    case_counts = Counter(row["verdict"] for row in cases)
    disposition_counts = Counter(row["disposition"] for row in dispositions)
    summary = {
        "schema_version": 1,
        "status": "FINAL_AUDIT_COMPLETE",
        "mechanism_rows": len(final),
        "mechanism_verdicts": dict(sorted(mechanism_counts.items())),
        "causal_valid_mechanisms": mechanism_counts["CONFIRM"] + mechanism_counts["NARROW"],
        "public_cases": len(cases),
        "public_case_verdicts": dict(sorted(case_counts.items())),
        "strict_confirmed_cases": case_counts["CONFIRM"],
        "causal_valid_cases": case_counts["CONFIRM"] + case_counts["NARROW"],
        "unresolved_cases": case_counts["UNKNOWN"],
        "public_200_claim_supported": False,
        "public_ids": len(dispositions),
        "public_id_dispositions": dict(sorted(disposition_counts.items())),
        "kept_ghsa_ids": sum(row["id_type"] == "GHSA" and row["disposition"] == "KEPT" for row in dispositions),
        "kept_cve_ids": sum(row["id_type"] == "CVE" and row["disposition"] == "KEPT" for row in dispositions),
        "input_sha256": {
            "manifest.jsonl": sha256(HERE / "manifest.jsonl"),
            "first_pass_commit": "e0491f7e1b6773fe3f6126bcf1364df7a19f2373",
            "second_pass_commit": "48853c0031625ad6c203f31d3f834cc17d4d46cf",
        },
        "claim_boundary": "CONFIRM is strict; NARROW is causal-valid only at its narrowed scope; UNKNOWN is not counted as valid.",
    }

    return {
        HERE / "final_mechanisms.jsonl": "".join(compact(row) + "\n" for row in final),
        HERE / "public_cases.jsonl": "".join(compact(row) + "\n" for row in cases),
        HERE / "public_id_dispositions.jsonl": "".join(compact(row) + "\n" for row in dispositions),
        HERE / "experience.json": json.dumps(experience, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        HERE / "summary.json": json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = build()
    if args.check:
        for path, text in outputs.items():
            assert path.is_file() and path.read_text() == text, f"stale: {path}"
        print("PASS: final mechanism/case/ID/experience ledgers are byte-identical")
        return
    for path, text in outputs.items():
        path.write_text(text)
    print("WROTE:", " ".join(path.name for path in outputs))


if __name__ == "__main__":
    main()
