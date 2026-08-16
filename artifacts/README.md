# Artifact ledger

Append-only system of record for every advisory evidence row and every model
verdict. Nothing in here is deleted; re-scans append verdicts to existing rows.

## Files

- ledger.jsonl — one JSON per line, one row per advisory x candidate-edge.
- manifests.jsonl — sha256/size/row manifests of local-only raw pools that are
  too large for git (the pools themselves stay on disk, not committed).

## Derivation

- foundation.jsonl is derived from ledger.jsonl via
  scripts/build_foundation_from_ledger.py; re-run it before every publish.
- publish_research_ledger.py consumes the derived foundation unchanged.
- The site data, foundation snapshot, and census are derived artifacts, not
  sources of truth.

## Ledger row schema (v1)

{
  "v": 1,
  "row_key": "<CASE_ID>|<cand_sha12>|<fix_sha12>",   // unique; 'none' when missing
  "case_id": "GHSA-...",
  "public_ids": ["CVE-...", ...],
  "repo": "owner/name",
  "candidate_sha": "...",
  "fix_sha": "...",
  "mechanism": "...",
  "contribution_class": "...",      // only when adjudicated
  "tier": "...",                    // only when adjudicated
  "gates": {...},                   // current adjudicated gates, if any
  "evidence_refs": {"ai_refs": [], "fix_refs": []},
  "verdicts": [
    {
      "kind": "pilot|review|prefilter|audit|second_opinion|final_verify",
      "model": "deepseek-v4-pro|deepseek-v4-flash|glm-5.3|gemini-3.7-flash",
      "ts": "ISO date",
      "verdict": "B1_AI_FAULT|B2_NOT_AI|B3_BLOCKED|REVIEW|SKIP|FLAG|OK|...",
      "refs": {"ai_refs": [], "fix_refs": []},
      "reasoning": "..."
    }
  ],
  "source": {"file": "...", "note": "..."}
}

## Invariants

- row_key is unique across the file; new evidence merges into the existing row
  by row_key and only appends verdicts.
- No verdict is ever removed; bucket (B1/B2/B3) is derived downstream from
  verdict history, latest non-audit review wins.
- The site data, foundation snapshot, and census are derived artifacts, not
  sources of truth.
