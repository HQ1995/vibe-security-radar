import { describe, it, expect } from "vitest";
import {
  buildCommitUrl,
  formatDate,
  formatBlameConfidence,
  firstLine,
} from "../commit-utils";

describe("buildCommitUrl", () => {
  it("builds url from repo url and sha", () => {
    expect(buildCommitUrl("https://github.com/owner/repo", "abc1234")).toBe(
      "https://github.com/owner/repo/commit/abc1234",
    );
  });

  it("strips trailing slashes from repo url", () => {
    expect(buildCommitUrl("https://github.com/owner/repo///", "abc1234")).toBe(
      "https://github.com/owner/repo/commit/abc1234",
    );
  });
});

describe("formatDate", () => {
  it("formats ISO date string", () => {
    const result = formatDate("2026-01-15T12:00:00Z");
    expect(result).toContain("Jan");
    expect(result).toContain("2026");
  });

  it("returns original string for invalid date", () => {
    expect(formatDate("not-a-date")).toBe("not-a-date");
  });

  it("handles date-only string", () => {
    const result = formatDate("2025-12-01");
    expect(result).toContain("2025");
  });
});

describe("formatBlameConfidence", () => {
  it("formats as percentage", () => {
    expect(formatBlameConfidence(0.85)).toBe("85%");
  });

  it("rounds to nearest integer", () => {
    expect(formatBlameConfidence(0.856)).toBe("86%");
  });

  it("handles zero", () => {
    expect(formatBlameConfidence(0)).toBe("0%");
  });

  it("handles one", () => {
    expect(formatBlameConfidence(1)).toBe("100%");
  });
});

describe("firstLine", () => {
  it("returns full string when no newline", () => {
    expect(firstLine("single line message")).toBe("single line message");
  });

  it("returns first line of multi-line string", () => {
    expect(firstLine("first line\nsecond line\nthird")).toBe("first line");
  });

  it("handles empty string", () => {
    expect(firstLine("")).toBe("");
  });

  it("handles string starting with newline", () => {
    expect(firstLine("\nsecond line")).toBe("");
  });
});
