import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  ADMISSION_GATES,
  CONTRIBUTION_CLASSES,
  RESEARCH_SNAPSHOT,
  WORKFLOW_STEPS,
} from "../research-status";

describe("research snapshot", () => {
  it("keeps the strict ledger separate from publication readiness", () => {
    const summaryBytes = readFileSync(
      resolve(
        import.meta.dirname,
        "../../../../autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json",
      ),
    );
    const summary = JSON.parse(summaryBytes.toString("utf8"));

    expect(createHash("sha256").update(summaryBytes).digest("hex")).toBe(
      RESEARCH_SNAPSHOT.summarySha256,
    );
    expect(RESEARCH_SNAPSHOT.strictReleasedGhsa).toBe(
      summary.canonical_strict_count,
    );
    expect(RESEARCH_SNAPSHOT.status).toBe(summary.status);
    expect(RESEARCH_SNAPSHOT.publicationReady).toBe(summary.publication_ready);
    expect(RESEARCH_SNAPSHOT.ledgerSha256).toBe(summary.ledger_sha256);
    expect(RESEARCH_SNAPSHOT.strictReleasedGhsa).toBe(94);
    expect(RESEARCH_SNAPSHOT.status).toBe("HOLD");
    expect(RESEARCH_SNAPSHOT.publicationReady).toBe(false);
    expect(RESEARCH_SNAPSHOT.ledgerSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("pins the seven-gate admission contract", () => {
    expect(ADMISSION_GATES).toHaveLength(7);
    expect(new Set(ADMISSION_GATES.map(([number]) => number)).size).toBe(7);
    expect(CONTRIBUTION_CLASSES).toHaveLength(3);
    expect(WORKFLOW_STEPS).toHaveLength(5);
  });
});
