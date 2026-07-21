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
  getModelDisplayName,
  getModelDetailName,
  deduplicateModels,
  SEVERITY_COLORS,
  LANGUAGE_COLORS,
  LANGUAGE_FALLBACK_COLOR,
  TOOL_BRAND_COLORS,
  TOOL_DISPLAY_NAMES,
  TOOL_URLS,
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
    expect(Object.keys(TOOL_URLS).sort()).toEqual(monitored);
    expect(
      Object.keys(TOOL_BRAND_COLORS)
        .filter((tool) => tool !== "unknown_ai")
        .sort(),
    ).toEqual(monitored);
  });

  it("returns display name for known tools", () => {
    expect(getToolDisplayName("claude_code")).toBe("Claude Code");
    expect(getToolDisplayName("cursor")).toBe("Cursor");
    expect(getToolDisplayName("github_copilot")).toBe("GitHub Copilot");
  });

  it("publishes the complete Qwen Code catalog entry", () => {
    expect(TOOL_DISPLAY_NAMES.qwen_code).toBe("Qwen Code");
    expect(TOOL_BRAND_COLORS.qwen_code).toMatch(/^#[0-9A-F]{6}$/i);
    expect(TOOL_URLS.qwen_code).toBe("https://github.com/QwenLM/qwen-code");
  });

  it.each([
    ["qoder", "Qoder", "https://qoder.com"],
    ["coderabbit", "CodeRabbit", "https://www.coderabbit.ai"],
    ["ellipsis", "Ellipsis", "https://www.ellipsis.dev"],
    ["pi", "Pi Coding Agent", "https://pi.dev"],
    [
      "mistral_vibe",
      "Mistral Vibe",
      "https://github.com/mistralai/mistral-vibe",
    ],
    ["kimi_code", "Kimi Code", "https://moonshotai.github.io/kimi-code/en/"],
    ["openwork", "OpenWork", "https://github.com/modelstudioai/openwork"],
    [
      "google_antigravity",
      "Google Antigravity",
      "https://antigravity.google/docs/cli-overview",
    ],
    ["roomote", "Roomote", "https://roomote.dev"],
    ["grok_build", "Grok Build", "https://docs.x.ai/build/overview"],
    ["same_dev", "Same", "https://same.new"],
  ])("publishes the complete %s catalog entry", (tool, name, url) => {
    expect(TOOL_DISPLAY_NAMES[tool]).toBe(name);
    expect(TOOL_BRAND_COLORS[tool]).toMatch(/^#[0-9A-F]{6}$/i);
    expect(TOOL_URLS[tool]).toBe(url);
  });

  it.each([
    ["claude_code", "https://code.claude.com/docs"],
    ["openai_codex", "https://openai.com/codex/"],
    ["windsurf", "https://devin.ai/desktop"],
    ["codeium", "https://devin.ai/desktop"],
    ["google_gemini", "https://codeassist.google"],
    ["roo_code", "https://github.com/RooCodeInc/Roo-Code"],
    ["openhands", "https://openhands.dev"],
    ["kilo_code", "https://kilo.ai"],
    ["v0", "https://v0.app"],
    ["aether", "https://tryaether.ai"],
    ["plandex", "https://github.com/plandex-ai/plandex"],
    [
      "mentat",
      "https://marketplace.visualstudio.com/items?itemName=AbanteAI.mentat",
    ],
    ["mux", "https://coder.com/solutions/agents"],
  ])("uses the current %s destination", (tool, url) => {
    expect(TOOL_URLS[tool]).toBe(url);
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
    expect(getSignalTypeLabel("message_keyword")).toBe(
      "Commit message keyword",
    );
    expect(getSignalTypeLabel("pr_body_keyword")).toBe("PR body keyword");
    expect(getSignalTypeLabel("squash_decomposed_co_author_trailer")).toBe(
      "Squash PR co-author",
    );
    expect(getSignalTypeLabel("squash_decomposed_author_email")).toBe(
      "Squash PR author email",
    );
    expect(getSignalTypeLabel("agent_logs_url_trailer")).toBe(
      "Agent logs URL trailer",
    );
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
    expect(verifiedByTooltip("claude-opus-4-6")).toBe(
      "Verified by claude-opus-4-6",
    );
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
    expect(verifiedBadgeColor("gemini-3.1-pro-preview")).toContain(
      "bg-indigo-500",
    );
  });

  it("returns zinc fallback for unknown models", () => {
    expect(verifiedBadgeColor("unknown-model")).toContain("bg-zinc-500");
  });
});

describe("getModelDisplayName", () => {
  it("returns detailed name for known models", () => {
    expect(getModelDisplayName("claude-opus-4-6")).toBe("Claude Opus 4.6");
    expect(getModelDisplayName("gemini-3.1-pro-preview")).toBe(
      "Gemini 3.1 Pro",
    );
    expect(getModelDisplayName("gpt-5.4")).toBe("GPT-5.4");
    expect(getModelDisplayName("gpt-5.6-luna-max")).toBe("GPT-5.6 Luna Max");
  });

  it("keeps short suffixes and trims long table labels", () => {
    expect(getModelDisplayName("gpt-5.4-high")).toBe("GPT-5.4 High");
    expect(getModelDisplayName("claude-opus-4-6-thinking")).toBe(
      "Claude Opus 4.6",
    );
  });

  it("keeps reasoning suffixes in detail labels", () => {
    expect(getModelDetailName("claude-opus-4-6-thinking")).toBe(
      "Claude Opus 4.6 Thinking",
    );
    expect(getModelDetailName("gpt-5.4-high")).toBe("GPT-5.4 High");
    expect(getModelDetailName("gpt-5.6-luna-max")).toBe("GPT-5.6 Luna Max");
  });

  it("returns raw string for unknown models", () => {
    expect(getModelDisplayName("some-future-model")).toBe("some-future-model");
  });
});

describe("deduplicateModels", () => {
  it("keeps strongest model per provider", () => {
    const models = [
      "claude-opus-4-6",
      "gemini-3.1-pro-preview",
      "gemini-3.1-flash-lite-preview",
      "gemini-3-flash-preview",
      "gpt-5.4",
      "gpt-5.6-luna-max",
    ];
    const result = deduplicateModels(models);
    expect(result).toContain("claude-opus-4-6");
    expect(result).toContain("gemini-3.1-pro-preview");
    expect(result).toContain("gpt-5.6-luna-max");
    expect(result).not.toContain("gpt-5.4");
    expect(result).not.toContain("gemini-3.1-flash-lite-preview");
    expect(result).not.toContain("gemini-3-flash-preview");
    expect(result).toHaveLength(3);
  });

  it("preserves unknown models as their own provider", () => {
    const result = deduplicateModels(["unknown-model", "gpt-5.4"]);
    expect(result).toContain("unknown-model");
    expect(result).toContain("gpt-5.4");
    expect(result).toHaveLength(2);
  });

  it("handles empty array", () => {
    expect(deduplicateModels([])).toEqual([]);
  });

  it("handles single model", () => {
    expect(deduplicateModels(["gpt-5.4"])).toEqual(["gpt-5.4"]);
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
