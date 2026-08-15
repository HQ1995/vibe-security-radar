import { describe, expect, it } from "vitest";

import {
  buildResearchTimeline,
  getAiToolDistribution,
  getCauseDistribution,
  getLanguageDistribution,
  getRepositoryDistribution,
  getResearchCaseById,
  getResearchSnapshot,
  getResearchTimeline,
} from "@/lib/research-data";

describe("canonical research data", () => {
  it("resolves aliases and derives a timeline from the case array", () => {
    const snapshot = getResearchSnapshot();
    const timeline = getResearchTimeline();

    expect(snapshot.cases).toHaveLength(168);
    expect(getResearchCaseById("CVE-2026-34218")?.case_id).toBe(
      "GHSA-FPMV-5WGW-QHHR",
    );
    expect(timeline.at(-1)?.month).toBe("2026-08");
    expect(getCauseDistribution().map(({ label, count }) => [label, count])).toEqual([
      ["Authentication & access control", 38],
      ["Injection & unsafe execution", 37],
      ["Validation & fail-open logic", 20],
      ["Path & link handling", 19],
      ["SSRF & network boundaries", 13],
      ["Resource abuse & availability", 10],
      ["Other / insufficient public mechanism detail", 31],
    ]);
    expect(getAiToolDistribution()).toMatchObject({
      coverage: { complete: 163, generic: 4, partial: 0, unresolved: 1 },
      total: 168,
      items: [
        { label: "Claude", count: 122 },
        { label: "OpenAI GPT/Codex", count: 18 },
        { label: "GitHub Copilot", count: 15 },
        { label: "Cursor", count: 7 },
        { label: "claude-flow", count: 1 },
      ],
    });
    expect(getLanguageDistribution()[0]).toMatchObject({
      label: "TypeScript",
      count: 46,
    });
    expect(getRepositoryDistribution()[0]).toMatchObject({
      label: "openclaw/openclaw",
      count: 45,
    });
    expect(snapshot.cases.every((item) => item.case_id)).toBe(true);
    expect(
      snapshot.cases.every(
        (item) => item.gates && Object.keys(item.gates).length > 0,
      ),
    ).toBe(true);

    const extended = buildResearchTimeline([
      ...snapshot.cases,
      { published_at: "2026-09-03" },
    ]);
    expect(extended.at(-1)).toEqual({ month: "2026-09", count: 1 });
  });
});
