/** Display names for each AI tool (keyed by internal tool id). */
export const TOOL_DISPLAY_NAMES: Readonly<Record<string, string>> = {
  claude_code: "Claude Code",
  cursor: "Cursor",
  aider: "Aider",
  github_copilot: "GitHub Copilot",
  devin: "Devin",
  windsurf: "Windsurf",
  codeium: "Codeium",
  amazon_q: "Amazon Q",
  sweep: "Sweep",
  openai_codex: "ChatGPT/Codex",
  google_gemini: "Google Gemini",
  google_jules: "Google Jules",
  tabnine: "Tabnine",
  sourcegraph_cody: "Sourcegraph Cody",
  opencode: "OpenCode",
  kiro: "Kiro",
  jetbrains_junie: "JetBrains Junie",
  roo_code: "Roo Code",
  roomote: "Roomote",
  cline: "Cline",
  openhands: "OpenHands",
  lovable: "Lovable",
  fine_dev: "Fine Dev",
  replit_agent: "Replit Agent",
  qodo: "Qodo",
  continue_dev: "Continue",
  augment_code: "Augment Code",
  trae: "Trae",
  gitlab_duo: "GitLab Duo",
  kimi_code: "Kimi Code",
  mistral_vibe: "Mistral Vibe",
  qwen_code: "Qwen Code",
  openwork: "OpenWork",
  qoder: "Qoder",
  coderabbit: "CodeRabbit",
  ellipsis: "Ellipsis",
  pi: "Pi Coding Agent",
  google_antigravity: "Google Antigravity",
  kilo_code: "Kilo Code",
  codegeex: "CodeGeeX",
  bolt_new: "Bolt.new",
  zencoder: "Zencoder",
  codegpt: "CodeGPT",
  amp: "Amp Code",
  v0: "v0",
  same_dev: "Same",
  leap_new: "Leap.new",
  traycer: "Traycer",
  atlassian_rovo: "Atlassian Rovo",
  aether: "Aether",
  factory_droid: "Factory Droid",
  goose: "Goose",
  cosine_genie: "Cosine Genie",
  grok_build: "Grok Build",
  blackbox_ai: "Blackbox AI",
  plandex: "Plandex",
  mentat: "Mentat",
  forgecode: "ForgeCode",
  mux: "Mux",
  letta_code: "Letta Code",
  warp: "Warp",
  abacus_ai: "Abacus AI",
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

/** Brand colors for programming languages. */
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

