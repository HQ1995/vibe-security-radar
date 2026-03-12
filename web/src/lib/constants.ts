/** Brand colors for each AI tool (keyed by internal tool id). */
export const TOOL_BRAND_COLORS: Readonly<Record<string, string>> = {
  claude_code: "#E87322",
  cursor: "#00B4D8",
  aider: "#14B8A6",
  github_copilot: "#6E40C9",
  devin: "#2563EB",
  windsurf: "#22D3EE",
  codeium: "#09B6A2",
  amazon_q: "#FF9900",
  sweep: "#8B5CF6",
  openai_codex: "#10A37F",
  google_gemini: "#4285F4",
  google_jules: "#EA4335",
  tabnine: "#6C63FF",
  sourcegraph_cody: "#A112FF",
  opencode: "#3B82F6",
  kiro: "#FF6B2B",
  jetbrains_junie: "#FE315D",
  roo_code: "#FFA500",
  cline: "#5A67D8",
  openhands: "#EF4444",
  lovable: "#E11D48",
  fine_dev: "#06B6D4",
  replit_agent: "#F26522",
  qodo: "#7C3AED",
  continue_dev: "#F59E0B",
  augment_code: "#2DD4BF",
  trae: "#6366F1",
  gitlab_duo: "#FC6D26",
  kimi_code: "#5046E5",
  bolt_new: "#F97316",
  zencoder: "#0EA5E9",
  codegpt: "#10A37F",
  google_antigravity: "#34A853",
  kilo_code: "#F97316",
  codegeex: "#3B82F6",
  amp: "#FF5543",
  v0: "#18181B",
  same_dev: "#EC4899",
  leap_new: "#10B981",
  traycer: "#A855F7",
  unknown_ai: "#71717A",
};

export const TOOL_BRAND_FALLBACK_COLOR = "#71717A";

export function getToolColor(tool: string): string {
  return TOOL_BRAND_COLORS[tool] ?? TOOL_BRAND_FALLBACK_COLOR;
}

export const SEVERITY_COLORS: Readonly<Record<string, string>> = {
  CRITICAL: "bg-red-600 text-white hover:bg-red-600",
  HIGH: "bg-orange-500 text-white hover:bg-orange-500",
  MEDIUM: "bg-yellow-500 text-black hover:bg-yellow-500",
  LOW: "bg-green-600 text-white hover:bg-green-600",
  UNKNOWN: "bg-zinc-500 text-white hover:bg-zinc-500",
};

export const SEVERITY_ORDER: Readonly<Record<string, number>> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  UNKNOWN: 4,
};

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
  openai_codex: "OpenAI Codex",
  google_gemini: "Google Gemini",
  google_jules: "Google Jules",
  tabnine: "Tabnine",
  sourcegraph_cody: "Sourcegraph Cody",
  opencode: "OpenCode",
  kiro: "Kiro",
  jetbrains_junie: "JetBrains Junie",
  roo_code: "Roo Code",
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
  google_antigravity: "Google Antigravity",
  kilo_code: "Kilo Code",
  codegeex: "CodeGeeX",
  bolt_new: "Bolt.new",
  zencoder: "Zencoder",
  codegpt: "CodeGPT",
  amp: "Amp",
  v0: "v0",
  same_dev: "Same.dev",
  leap_new: "Leap.new",
  traycer: "Traycer",
  unknown_ai: "Unknown AI",
};

export const SIGNAL_TYPE_LABELS: Readonly<Record<string, string>> = {
  co_author_trailer: "Co-author trailer",
  author_email: "Author email",
  author_name: "Author name",
  committer_email: "Committer email",
  commit_message: "Commit message",
  message_keyword: "Commit message keyword",
  branch_name: "Branch name",
  co_author_trailer_generic: "Co-author trailer (generic)",
  pr_body_keyword: "PR body keyword",
  squash_decomposed_co_author_trailer: "Squash PR co-author",
  squash_decomposed_co_author_trailer_generic: "Squash PR co-author (generic)",
  squash_decomposed_author_email: "Squash PR author email",
  squash_decomposed_author_name: "Squash PR author name",
  squash_decomposed_committer_email: "Squash PR committer email",
  squash_decomposed_commit_message: "Squash PR commit message",
  squash_decomposed_message_keyword: "Squash PR message keyword",
  squash_decomposed_branch_name: "Squash PR branch name",
};

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
};

export const LANGUAGE_FALLBACK_COLOR = "#71717A";

export function getLanguageColor(language: string): string {
  return LANGUAGE_COLORS[language] ?? LANGUAGE_FALLBACK_COLOR;
}

export function severityBadgeClass(severity: string): string {
  return SEVERITY_COLORS[severity] ?? SEVERITY_COLORS["UNKNOWN"];
}

export function getToolDisplayName(tool: string): string {
  return TOOL_DISPLAY_NAMES[tool] ?? tool;
}

export function getSignalTypeLabel(signalType: string): string {
  return SIGNAL_TYPE_LABELS[signalType] ?? signalType.replaceAll("_", " ");
}

export function formatConfidence(confidence: number): string {
  return `${Math.round(confidence * 100)}%`;
}

/** Model metadata: display name, provider, and strength rank (lower = stronger). */
const MODEL_METADATA: Readonly<
  Record<string, { displayName: string; detailName: string; provider: string; rank: number }>
> = {
  "claude-opus-4-6": { displayName: "Claude", detailName: "Claude Opus 4.6", provider: "anthropic", rank: 0 },
  "gemini-3.1-pro-preview": { displayName: "Gemini", detailName: "Gemini 3.1 Pro", provider: "google", rank: 0 },
  "gemini-3.1-flash-lite-preview": { displayName: "Gemini", detailName: "Gemini 3.1 Flash Lite", provider: "google", rank: 2 },
  "gemini-3-flash-preview": { displayName: "Gemini", detailName: "Gemini 3 Flash", provider: "google", rank: 1 },
  "gpt-5.4": { displayName: "GPT", detailName: "GPT-5.4", provider: "openai", rank: 0 },
};

/** Get short display name for a verification model (used in table badges). */
export function getModelDisplayName(model: string): string {
  return MODEL_METADATA[model]?.displayName ?? model;
}

/** Get full display name for a verification model (used in detail pages). */
export function getModelDetailName(model: string): string {
  return MODEL_METADATA[model]?.detailName ?? model;
}

/** Model strength rank (lower = stronger). Unknown models default to 99. */
export function getModelRank(model: string): number {
  return MODEL_METADATA[model]?.rank ?? 99;
}

/** Keep only the strongest (lowest rank) model per provider. */
export function deduplicateModels(models: string[]): string[] {
  const bestPerProvider = new Map<string, { model: string; rank: number }>();
  for (const model of models) {
    const info = MODEL_METADATA[model];
    if (!info) {
      // Unknown model — treat as its own unique provider
      bestPerProvider.set(model, { model, rank: 0 });
      continue;
    }
    const existing = bestPerProvider.get(info.provider);
    if (!existing || info.rank < existing.rank) {
      bestPerProvider.set(info.provider, { model, rank: info.rank });
    }
  }
  return Array.from(bestPerProvider.values()).map((v) => v.model);
}

export function formatVerifiedBy(verifiedBy: string): string {
  if (!verifiedBy) return "Unverified";
  return verifiedBy;
}

/** Tooltip text for the verified-by badge. */
export function verifiedByTooltip(verifiedBy: string): string {
  if (!verifiedBy) return "Not yet verified";
  if (verifiedBy === "osv") return "Verified via OSV advisory data";
  return `Verified by ${verifiedBy}`;
}

/** Badge color classes for a verification source. Most-specific patterns first. */
export function verifiedBadgeColor(verifiedBy: string): string {
  if (verifiedBy === "osv")
    return "bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/25";
  const v = verifiedBy.toLowerCase();
  if (v.includes("claude"))
    return "bg-orange-500/15 text-orange-600 dark:text-orange-400 border-orange-500/25";
  if (v.includes("gpt"))
    return "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/25";
  if (v.includes("flash-lite") || v.includes("flash_lite"))
    return "bg-sky-500/15 text-sky-600 dark:text-sky-400 border-sky-500/25";
  if (v.includes("flash"))
    return "bg-violet-500/15 text-violet-600 dark:text-violet-400 border-violet-500/25";
  if (v.includes("gemini") || v.includes("pro"))
    return "bg-indigo-500/15 text-indigo-600 dark:text-indigo-400 border-indigo-500/25";
  return "bg-zinc-500/15 text-zinc-600 dark:text-zinc-400 border-zinc-500/25";
}

export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}...`;
}
