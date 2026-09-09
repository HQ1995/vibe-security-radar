import { describe, it, expect } from "vitest";
import {
  severityBadgeClass,
  getToolDisplayName,
  getLanguageColor,
  SEVERITY_COLORS,
  LANGUAGE_COLORS,
  LANGUAGE_FALLBACK_COLOR,
  TOOL_DISPLAY_NAMES,
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
  it("keeps the monitored-tool catalog complete", () => {
    const monitored = Object.keys(TOOL_DISPLAY_NAMES)
      .filter((tool) => tool !== "unknown_ai")
      .sort();

    expect(monitored).toHaveLength(62);
  });

  it("returns display name for known tools", () => {
    expect(getToolDisplayName("claude_code")).toBe("Claude Code");
    expect(getToolDisplayName("cursor")).toBe("Cursor");
    expect(getToolDisplayName("github_copilot")).toBe("GitHub Copilot");
  });

  it("publishes the complete Qwen Code catalog entry", () => {
    expect(TOOL_DISPLAY_NAMES.qwen_code).toBe("Qwen Code");
  });

  it("returns raw key for unknown tools", () => {
    expect(getToolDisplayName("some_new_tool")).toBe("some_new_tool");
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

