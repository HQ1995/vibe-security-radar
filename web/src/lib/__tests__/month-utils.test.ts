import { describe, it, expect } from "vitest";
import {
  formatMonthLabel,
  computeSeverityBreakdown,
  computeToolBreakdown,
  sortCvesByPriority,
} from "../month-utils";
import type { CveEntry } from "../types";

function makeCve(overrides: Partial<CveEntry> = {}): CveEntry {
  return {
    id: "CVE-2026-0001",
    description: "Test vulnerability",
    severity: "HIGH",
    cvss: 7.5,
    cwes: [],
    ecosystem: "",
    published: "2026-01-15",
    ai_tools: ["cursor"],
    languages: [],
    confidence: 0.85,
    verified_by: "",
    how_introduced: "",
    bug_commits: [],
    fix_commits: [],
    references: [],
    ...overrides,
  };
}

// --- formatMonthLabel ---

describe("formatMonthLabel", () => {
  it("formats YYYY-MM to full month name and year", () => {
    expect(formatMonthLabel("2025-05")).toBe("May 2025");
    expect(formatMonthLabel("2026-01")).toBe("January 2026");
    expect(formatMonthLabel("2025-12")).toBe("December 2025");
  });

  it("handles all 12 months", () => {
    const expected = [
      "January", "February", "March", "April", "May", "June",
      "July", "August", "September", "October", "November", "December",
    ];
    for (let i = 1; i <= 12; i++) {
      const mm = String(i).padStart(2, "0");
      expect(formatMonthLabel(`2025-${mm}`)).toBe(`${expected[i - 1]} 2025`);
    }
  });

  it("falls back to raw month number for invalid month", () => {
    expect(formatMonthLabel("2025-00")).toBe("00 2025");
    expect(formatMonthLabel("2025-13")).toBe("13 2025");
  });
});

// --- computeSeverityBreakdown ---

describe("computeSeverityBreakdown", () => {
  it("returns empty for no CVEs", () => {
    expect(computeSeverityBreakdown([])).toEqual([]);
  });

  it("counts single severity", () => {
    const cves = [makeCve({ severity: "HIGH" }), makeCve({ severity: "HIGH" })];
    expect(computeSeverityBreakdown(cves)).toEqual([
      { severity: "HIGH", count: 2 },
    ]);
  });

  it("counts multiple severities sorted by severity order", () => {
    const cves = [
      makeCve({ severity: "LOW" }),
      makeCve({ severity: "CRITICAL" }),
      makeCve({ severity: "HIGH" }),
      makeCve({ severity: "CRITICAL" }),
    ];
    const result = computeSeverityBreakdown(cves);
    expect(result).toEqual([
      { severity: "CRITICAL", count: 2 },
      { severity: "HIGH", count: 1 },
      { severity: "LOW", count: 1 },
    ]);
  });

  it("puts unknown severity last", () => {
    const cves = [
      makeCve({ severity: "UNKNOWN" }),
      makeCve({ severity: "MEDIUM" }),
    ];
    const result = computeSeverityBreakdown(cves);
    expect(result[0].severity).toBe("MEDIUM");
    expect(result[1].severity).toBe("UNKNOWN");
  });
});

// --- computeToolBreakdown ---

describe("computeToolBreakdown", () => {
  it("returns empty for no CVEs", () => {
    expect(computeToolBreakdown([])).toEqual([]);
  });

  it("counts tools across CVEs", () => {
    const cves = [
      makeCve({ ai_tools: ["cursor", "github_copilot"] }),
      makeCve({ ai_tools: ["cursor"] }),
    ];
    const result = computeToolBreakdown(cves);
    expect(result).toEqual([
      { tool: "cursor", count: 2 },
      { tool: "github_copilot", count: 1 },
    ]);
  });

  it("sorts by count descending", () => {
    const cves = [
      makeCve({ ai_tools: ["aider"] }),
      makeCve({ ai_tools: ["cursor"] }),
      makeCve({ ai_tools: ["cursor"] }),
      makeCve({ ai_tools: ["cursor"] }),
    ];
    const result = computeToolBreakdown(cves);
    expect(result[0]).toEqual({ tool: "cursor", count: 3 });
    expect(result[1]).toEqual({ tool: "aider", count: 1 });
  });
});

// --- sortCvesByPriority ---

describe("sortCvesByPriority", () => {
  it("sorts CRITICAL before HIGH before LOW", () => {
    const cves = [
      makeCve({ id: "CVE-2026-0003", severity: "LOW", published: "2026-01-01" }),
      makeCve({ id: "CVE-2026-0001", severity: "CRITICAL", published: "2026-01-01" }),
      makeCve({ id: "CVE-2026-0002", severity: "HIGH", published: "2026-01-01" }),
    ];
    const sorted = sortCvesByPriority(cves);
    expect(sorted.map((c) => c.severity)).toEqual(["CRITICAL", "HIGH", "LOW"]);
  });

  it("within same severity, sorts by published date descending", () => {
    const cves = [
      makeCve({ id: "CVE-2026-0001", severity: "HIGH", published: "2026-01-01" }),
      makeCve({ id: "CVE-2026-0002", severity: "HIGH", published: "2026-01-15" }),
      makeCve({ id: "CVE-2026-0003", severity: "HIGH", published: "2026-01-10" }),
    ];
    const sorted = sortCvesByPriority(cves);
    expect(sorted.map((c) => c.id)).toEqual([
      "CVE-2026-0002",
      "CVE-2026-0003",
      "CVE-2026-0001",
    ]);
  });

  it("does not mutate original array", () => {
    const cves = [
      makeCve({ severity: "LOW" }),
      makeCve({ severity: "CRITICAL" }),
    ];
    const original = [...cves];
    sortCvesByPriority(cves);
    expect(cves).toEqual(original);
  });

  it("returns empty for empty input", () => {
    expect(sortCvesByPriority([])).toEqual([]);
  });
});
