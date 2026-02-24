import { describe, it, expect } from "vitest";
import { buildToolData } from "../tool-utils";

describe("buildToolData", () => {
  it("builds tool data with severity breakdown", () => {
    const byTool = { cursor: 2, copilot: 1 };
    const cves = [
      { ai_tools: ["cursor"], severity: "HIGH" },
      { ai_tools: ["cursor", "copilot"], severity: "CRITICAL" },
    ];

    const result = buildToolData(byTool, cves);

    expect(result).toHaveLength(2);
    expect(result[0].tool).toBe("cursor");
    expect(result[0].count).toBe(2);
    expect(result[0].severities).toEqual({ HIGH: 1, CRITICAL: 1 });
    expect(result[1].tool).toBe("copilot");
    expect(result[1].count).toBe(1);
    expect(result[1].severities).toEqual({ CRITICAL: 1 });
  });

  it("sorts by count descending", () => {
    const byTool = { a: 1, b: 3, c: 2 };
    const cves = [
      { ai_tools: ["a"], severity: "LOW" },
      { ai_tools: ["b"], severity: "HIGH" },
      { ai_tools: ["b"], severity: "HIGH" },
      { ai_tools: ["b"], severity: "MEDIUM" },
      { ai_tools: ["c"], severity: "LOW" },
      { ai_tools: ["c"], severity: "LOW" },
    ];

    const result = buildToolData(byTool, cves);

    expect(result.map((r) => r.tool)).toEqual(["b", "c", "a"]);
  });

  it("returns empty array for empty input", () => {
    expect(buildToolData({}, [])).toEqual([]);
  });

  it("handles tool with zero matching cves", () => {
    const byTool = { ghost: 1 };
    const cves: { ai_tools: string[]; severity: string }[] = [];

    const result = buildToolData(byTool, cves);

    expect(result).toHaveLength(1);
    expect(result[0].severities).toEqual({});
  });
});
