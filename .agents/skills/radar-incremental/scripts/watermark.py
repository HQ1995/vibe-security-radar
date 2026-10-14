#!/usr/bin/env python3
"""Advance the source-capture watermark after a complete, classified increment.

The watermark says every advisory captured through its instant has a recorded
disposition. It never implies research completion, ledger landing or publication.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil

from intake_rows import instant

ROOT = Path(__file__).resolve().parents[4]
WATERMARK = ROOT / "artifacts" / "source-watermark.json"
SOURCES = ROOT / ".ai-slop" / "sources"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def advance(run: Path, watermark: Path = WATERMARK, sources: Path = SOURCES) -> dict:
    current = json.loads(watermark.read_text())
    coverage = json.loads((run / "capture" / "coverage.json").read_text())
    delta, summary = run / "classification" / "delta.jsonl", run / "classification" / "summary.json"
    recorded = json.loads(summary.read_text())
    if coverage.get("status") != "COMPLETE":
        raise ValueError("capture is incomplete; its coverage gaps stay open and the watermark stays")
    if recorded.get("delta_sha256") != digest(delta):
        raise ValueError("delta does not match its summary")
    chain = current["delta_chain"]
    if [p["sha256"] for p in recorded.get("prior_deltas", [])] != [c["sha256"] for c in chain]:
        raise ValueError("the increment was not classified against the complete recorded chain")
    window = {key: coverage["window"][key] for key in ("start", "end", "inclusive")}
    if instant(window["end"]) <= instant(current["source_capture_watermark"]):
        raise ValueError("the increment does not extend the watermark")
    target = sources / "deltas" / f"{len(chain) + 1:03d}-{window['end'].replace('-', '').replace(':', '')}"
    target.mkdir(parents=True)
    shutil.copyfile(delta, target / "delta.jsonl")
    shutil.copyfile(summary, target / "summary.json")
    copied = target / "delta.jsonl"
    chain.append({"path": str(copied.relative_to(ROOT) if ROOT in copied.parents else copied), "sha256": digest(copied),
                  "summary_sha256": digest(target / "summary.json"), "window": window,
                  "components": recorded.get("components")})
    current.update(source_capture_watermark=window["end"], next_window_start=window["end"][:10] + "T00:00:00Z",
                   verified_by={"run": run.name, "coverage_sha256": digest(run / "capture" / "coverage.json"),
                                "classified_components": recorded.get("components")})
    watermark.write_text(json.dumps(current, indent=2) + "\n")
    return {"source_capture_watermark": window["end"], "chain_length": len(chain)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path, help="increment directory holding capture/ and classification/")
    print(json.dumps(advance(parser.parse_args().run), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
