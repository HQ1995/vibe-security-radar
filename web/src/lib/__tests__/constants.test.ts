import { describe, it, expect } from "vitest";
import {
  severityBadgeClass,
  getToolDisplayName,
  getSignalTypeLabel,
  formatConfidence,
  formatVerifiedBy,
  verifiedByTooltip,
  verifiedBadgeColor,
  truncate,
  getLanguageColor,
  SEVERITY_COLORS,
  LANGUAGE_COLORS,
  LANGUAGE_FALLBACK_COLOR,
} from "../constants";

describe("severityBadgeClass", () => {
  it("returns correct class for known severities", () => {
    expect(severityBadgeClass("CRITICAL")).toBe(SEVERITY_COLORS["CRITICAL"]);
    expect(severityBadgeClass("HIGH")).toBe(SEVERITY_COLORS["HIGH"]);
    expect(severityBadgeClass("MEDIUM")).toBe(SEVERITY_COLORS["MEDIUM"]);
    expect(severityBadgeClass("LOW")).toBe(SEVERITY_COLORS["LOW"]);
  });

  it("returns UNKNOWN class for unrecognized severity", () => {
    expect(severityBadgeClass("BOGUS")).toBe(SEVERITY_COLORS["UNKNOWN"]);
    expect(severityBadgeClass("")).toBe(SEVERITY_COLORS["UNKNOWN"]);
  });
});

describe("getToolDisplayName", () => {
  it("returns display name for known tools", () => {
    expect(getToolDisplayName("claude_code")).toBe("Claude Code");
    expect(getToolDisplayName("cursor")).toBe("Cursor");
    expect(getToolDisplayName("github_copilot")).toBe("GitHub Copilot");
  });

  it("returns raw key for unknown tools", () => {
    expect(getToolDisplayName("some_new_tool")).toBe("some_new_tool");
  });
});

describe("getSignalTypeLabel", () => {
  it("returns label for known signal types", () => {
    expect(getSignalTypeLabel("co_author_trailer")).toBe("Co-author trailer");
    expect(getSignalTypeLabel("author_email")).toBe("Author email");
    expect(getSignalTypeLabel("author_name")).toBe("Author name");
    expect(getSignalTypeLabel("committer_email")).toBe("Committer email");
    expect(getSignalTypeLabel("message_keyword")).toBe("Commit message keyword");
    expect(getSignalTypeLabel("pr_body_keyword")).toBe("PR body keyword");
    expect(getSignalTypeLabel("squash_decomposed_co_author_trailer")).toBe("Squash PR co-author");
    expect(getSignalTypeLabel("squash_decomposed_author_email")).toBe("Squash PR author email");
  });

  it("replaces underscores for unknown types", () => {
    expect(getSignalTypeLabel("some_new_type")).toBe("some new type");
  });
});

describe("formatConfidence", () => {
  it("formats as percentage", () => {
    expect(formatConfidence(0.85)).toBe("85%");
    expect(formatConfidence(1.0)).toBe("100%");
    expect(formatConfidence(0)).toBe("0%");
  });

  it("rounds to nearest integer", () => {
    expect(formatConfidence(0.856)).toBe("86%");
    expect(formatConfidence(0.854)).toBe("85%");
  });
});

describe("truncate", () => {
  it("returns text as-is when under limit", () => {
    expect(truncate("short", 10)).toBe("short");
  });

  it("truncates with ellipsis when over limit", () => {
    expect(truncate("this is a long string", 10)).toBe("this is a ...");
  });

  it("handles exact length", () => {
    expect(truncate("exact", 5)).toBe("exact");
  });

  it("handles empty string", () => {
    expect(truncate("", 10)).toBe("");
  });
});

describe("formatVerifiedBy", () => {
  it("returns Unverified for empty string", () => {
    expect(formatVerifiedBy("")).toBe("Unverified");
  });

  it("returns the value as-is for non-empty string", () => {
    expect(formatVerifiedBy("claude-opus-4-6")).toBe("claude-opus-4-6");
  });
});

describe("verifiedByTooltip", () => {
  it("returns not verified for empty string", () => {
    expect(verifiedByTooltip("")).toBe("Not yet verified");
  });

  it("returns OSV tooltip for osv", () => {
    expect(verifiedByTooltip("osv")).toBe("Verified via OSV advisory data");
  });

  it("returns model name for other values", () => {
    expect(verifiedByTooltip("claude-opus-4-6")).toBe("Verified by claude-opus-4-6");
  });
});

describe("verifiedBadgeColor", () => {
  it("returns blue for osv", () => {
    expect(verifiedBadgeColor("osv")).toContain("bg-blue-500");
  });

  it("returns orange for claude models", () => {
    expect(verifiedBadgeColor("claude-opus-4-6")).toContain("bg-orange-500");
    expect(verifiedBadgeColor("claude-sonnet-4-6")).toContain("bg-orange-500");
  });

  it("returns emerald for gpt models", () => {
    expect(verifiedBadgeColor("gpt-5.4")).toContain("bg-emerald-500");
  });

  it("returns sky for flash-lite models", () => {
    expect(verifiedBadgeColor("gemini-2.5-flash-lite")).toContain("bg-sky-500");
  });

  it("returns violet for flash models", () => {
    expect(verifiedBadgeColor("gemini-2.0-flash")).toContain("bg-violet-500");
  });

  it("returns indigo for gemini pro models", () => {
    expect(verifiedBadgeColor("gemini-3.1-pro-preview")).toContain("bg-indigo-500");
  });

  it("returns zinc fallback for unknown models", () => {
    expect(verifiedBadgeColor("unknown-model")).toContain("bg-zinc-500");
  });
});

describe("getLanguageColor", () => {
  it("returns distinct colors for known languages", () => {
    const langs = ["Python", "JavaScript", "TypeScript", "Go", "Rust", "PHP"];
    const colors = langs.map(getLanguageColor);
    // All should be unique
    expect(new Set(colors).size).toBe(langs.length);
  });

  it("returns the mapped color for a known language", () => {
    expect(getLanguageColor("Python")).toBe(LANGUAGE_COLORS["Python"]);
    expect(getLanguageColor("TypeScript")).toBe(LANGUAGE_COLORS["TypeScript"]);
  });

  it("returns fallback color for unknown language", () => {
    expect(getLanguageColor("Brainfuck")).toBe(LANGUAGE_FALLBACK_COLOR);
  });
});
