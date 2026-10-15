export const TOOL_DISPLAY_NAMES: Readonly<Record<string, string>> = {
  claude_code: "Claude Code",
  cursor: "Cursor",
  github_copilot: "GitHub Copilot",
  openai_codex: "ChatGPT/Codex",
  unknown_ai: "Unknown AI",
};

export const SEVERITY_COLORS: Readonly<Record<string, string>> = {
  CRITICAL: "bg-red-600 text-white hover:bg-red-600",
  HIGH: "bg-orange-500 text-white hover:bg-orange-500",
  MEDIUM: "bg-yellow-500 text-black hover:bg-yellow-500",
  LOW: "bg-green-600 text-white hover:bg-green-600",
  UNKNOWN: "bg-zinc-500 text-white hover:bg-zinc-500",
};

export function severityBadgeClass(severity: string): string {
  return SEVERITY_COLORS[severity] ?? SEVERITY_COLORS["UNKNOWN"];
}

export function getToolDisplayName(tool: string): string {
  return TOOL_DISPLAY_NAMES[tool] ?? tool;
}

export const LANGUAGE_COLORS: Readonly<Record<string, string>> = {
  Python: "#3572A5",
  JavaScript: "#F7DF1E",
  TypeScript: "#3178C6",
  Go: "#00ADD8",
  Rust: "#DEA584",
  Ruby: "#CC342D",
  Java: "#B07219",
  Kotlin: "#A97BFF",
  PHP: "#4F5D95",
  "C/C++": "#555555",
  "C#": "#178600",
  Swift: "#F05138",
  Vue: "#41B883",
  Dart: "#00B4AB",
  Scala: "#DC322F",
  R: "#198CE7",
  Lua: "#000080",
  Elixir: "#6E4A7E",
  Erlang: "#B83998",
  Zig: "#F7A41D",
  Nim: "#FFE953",
  Perl: "#0298C3",
  Shell: "#89E051",
  "GitHub Actions": "#2088FF",
};

export const LANGUAGE_FALLBACK_COLOR = "#71717A";

export function getLanguageColor(language: string): string {
  return LANGUAGE_COLORS[language] ?? LANGUAGE_FALLBACK_COLOR;
}

