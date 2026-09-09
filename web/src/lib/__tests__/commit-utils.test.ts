import { describe, it, expect } from "vitest";
import { formatPublished } from "../commit-utils";

describe("formatPublished", () => {
  it("formats ISO datetime string", () => {
    const result = formatPublished("2026-01-12T23:15:53.063");
    expect(result).toContain("Jan");
    expect(result).toContain("2026");
  });

  it("returns year-only string as-is", () => {
    expect(formatPublished("2025")).toBe("2025");
  });

  it("returns empty string for empty input", () => {
    expect(formatPublished("")).toBe("");
  });

  it("formats ISO date with timezone", () => {
    const result = formatPublished("2025-10-03T19:15:43.490");
    expect(result).toContain("Oct");
    expect(result).toContain("2025");
  });

  it("formats ISO datetime with UTC offset", () => {
    const result = formatPublished("2026-03-04T02:38:37.627213+00:00");
    expect(result).toContain("Mar");
    expect(result).toContain("2026");
  });

  it("keeps date-only strings on their local day", () => {
    expect(formatPublished("2025-05-01")).toBe("May 1, 2025");
  });

  it("returns original string for unparseable input", () => {
    expect(formatPublished("not-a-date")).toBe("not-a-date");
  });
});

