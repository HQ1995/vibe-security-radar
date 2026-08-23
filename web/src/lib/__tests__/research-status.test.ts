import { describe, expect, it } from "vitest";

import {
  ADMISSION_GATES,
  CONTRIBUTION_CLASSES,
  RESEARCH_SNAPSHOT,
  WORKFLOW_STEPS,
} from "../research-status";
import { getResearchSnapshot } from "../research-data";

describe("research snapshot", () => {
  it("publishes the confirmed true-positive ledger", () => {
    const snapshot = getResearchSnapshot().snapshot;

    expect(RESEARCH_SNAPSHOT.ledger).toBe("tp-funnel");
    expect(RESEARCH_SNAPSHOT.status).toBe("PUBLISHED");
    expect(RESEARCH_SNAPSHOT.publicationReady).toBe(true);
    expect(snapshot.status).toBe("PUBLISHED");
    expect(snapshot.case_set).toBe("TP_FUNNEL");
    expect(snapshot.case_count).toBeGreaterThanOrEqual(190);
    expect((snapshot.ai_root_cause ?? 0) + (snapshot.ai_code_flawed ?? 0)).toBe(
      snapshot.case_count,
    );
  });

  it("pins the seven-gate admission contract", () => {
    expect(ADMISSION_GATES).toHaveLength(7);
    expect(new Set(ADMISSION_GATES.map(([number]) => number)).size).toBe(7);
    expect(CONTRIBUTION_CLASSES).toHaveLength(4);
    expect(WORKFLOW_STEPS).toHaveLength(5);
  });
});
