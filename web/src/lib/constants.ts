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
  atlassian_rovo: "#0052CC",
  aether: "#6366F1",
  factory_droid: "#1E40AF",
  goose: "#F59E0B",
  cosine_genie: "#8B5CF6",
  grok_build: "#1D9BF0",
  blackbox_ai: "#111827",
  plandex: "#22C55E",
  mentat: "#6366F1",
  forgecode: "#0D9488",
  mux: "#3B82F6",
  letta_code: "#7C3AED",
  warp: "#01A4FF",
  abacus_ai: "#2563EB",
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
  amp: "Amp Code",
  v0: "v0",
  same_dev: "Same.dev",
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

export const TOOL_URLS: Readonly<Record<string, string>> = {
  claude_code: "https://docs.anthropic.com/en/docs/claude-code",
  cursor: "https://www.cursor.com",
  aider: "https://aider.chat",
  github_copilot: "https://github.com/features/copilot",
  devin: "https://devin.ai",
  windsurf: "https://windsurf.com",
  codeium: "https://codeium.com",
  amazon_q: "https://aws.amazon.com/q/developer",
  sweep: "https://sweep.dev",
  openai_codex: "https://openai.com/index/openai-codex",
  google_gemini: "https://gemini.google.com",
  google_jules: "https://jules.google",
  tabnine: "https://www.tabnine.com",
  sourcegraph_cody: "https://sourcegraph.com/cody",
  opencode: "https://opencode.ai",
  kiro: "https://kiro.dev",
  jetbrains_junie: "https://www.jetbrains.com/junie",
  roo_code: "https://roocode.com",
  cline: "https://cline.bot",
  openhands: "https://www.all-hands.dev",
  lovable: "https://lovable.dev",
  fine_dev: "https://fine.dev",
  replit_agent: "https://replit.com",
  qodo: "https://www.qodo.ai",
  continue_dev: "https://continue.dev",
  augment_code: "https://www.augmentcode.com",
  trae: "https://trae.ai",
  gitlab_duo: "https://about.gitlab.com/gitlab-duo",
  kimi_code: "https://kimi.ai",
  google_antigravity: "https://antigravity.dev",
  kilo_code: "https://kilocode.ai",
  codegeex: "https://codegeex.cn",
  bolt_new: "https://bolt.new",
  zencoder: "https://zencoder.ai",
  codegpt: "https://codegpt.co",
  amp: "https://ampcode.com",
  v0: "https://v0.dev",
  same_dev: "https://same.dev",
  leap_new: "https://leap.new",
  traycer: "https://traycer.ai",
  atlassian_rovo: "https://www.atlassian.com/rovo",
  aether: "https://aether.engineer",
  factory_droid: "https://factory.ai",
  goose: "https://block.github.io/goose",
  cosine_genie: "https://cosine.sh",
  grok_build: "https://grokai.build",
  blackbox_ai: "https://www.blackbox.ai",
  plandex: "https://plandex.ai",
  mentat: "https://mentat.ai",
  forgecode: "https://forgecode.dev",
  mux: "https://coder.com/products/mux",
  letta_code: "https://www.letta.com",
  warp: "https://www.warp.dev",
  abacus_ai: "https://abacus.ai",
};

export function getToolUrl(tool: string): string | undefined {
  return TOOL_URLS[tool];
}

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
  "GitHub Actions": "#2088FF",
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
  "claude-code": { displayName: "Claude Code", detailName: "Claude Code", provider: "anthropic-sdk", rank: 0 },
  "claude-opus-4-6": { displayName: "Claude", detailName: "Claude Opus 4.6", provider: "anthropic", rank: 0 },
  "gemini-3.1-pro-preview": { displayName: "Gemini", detailName: "Gemini 3.1 Pro", provider: "google", rank: 0 },
  "gemini-3.1-flash-lite-preview": { displayName: "Gemini", detailName: "Gemini 3.1 Flash Lite", provider: "google", rank: 2 },
  "gemini-3-flash-preview": { displayName: "Gemini", detailName: "Gemini 3 Flash", provider: "google", rank: 1 },
  "gpt-5.4": { displayName: "GPT", detailName: "GPT-5.4", provider: "openai", rank: 0 },
};

/** Reasoning mode suffixes appended to model names in verified_by fields. */
const REASONING_SUFFIXES = ["-high", "-thinking"] as const;

/** Strip reasoning suffix (e.g. "-high", "-thinking") to get the base model name. */
function stripReasoningSuffix(model: string): string {
  for (const suffix of REASONING_SUFFIXES) {
    if (model.endsWith(suffix)) return model.slice(0, -suffix.length);
  }
  return model;
}

/** Get short display name for a verification model (used in table badges). */
export function getModelDisplayName(model: string): string {
  return MODEL_METADATA[stripReasoningSuffix(model)]?.displayName ?? model;
}

/** Get full display name for a verification model (used in detail pages). */
export function getModelDetailName(model: string): string {
  return MODEL_METADATA[stripReasoningSuffix(model)]?.detailName ?? model;
}

/** Model strength rank (lower = stronger). Unknown models default to 99. */
export function getModelRank(model: string): number {
  return MODEL_METADATA[stripReasoningSuffix(model)]?.rank ?? 99;
}

/** Keep only the strongest (lowest rank) model per provider. */
export function deduplicateModels(models: string[]): string[] {
  const bestPerProvider = new Map<string, { model: string; rank: number }>();
  for (const model of models) {
    const info = MODEL_METADATA[stripReasoningSuffix(model)];
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

const FIX_SOURCE_LABELS: Readonly<Record<string, string>> = {
  osv: "OSV",
  nvd: "NVD",
  github_advisory: "GitHub Advisory",
  advisory_version: "Advisory Version",
  gemnasium: "Gemnasium",
  gemnasium_version: "Gemnasium Version",
  ghsa_ref_version: "GHSA Ref",
  ai_tag_search: "AI Tag Search",
  ai_inferred: "AI Inferred",
  github_advisory_pr: "GitHub Advisory PR",
  nvd_pr_merge: "NVD PR Merge",
  nvd_compare: "NVD Compare",
};

export function getFixSourceLabel(source: string): string {
  return FIX_SOURCE_LABELS[source] ?? source.replaceAll("_", " ");
}

export function fixSourceBadgeClass(source: string): string {
  if (source === "ai_inferred" || source === "ai_tag_search")
    return "bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/30";
  if (["osv", "nvd", "github_advisory"].includes(source))
    return "bg-blue-500/15 text-blue-700 dark:text-blue-400 border-blue-500/30";
  return "";
}

export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}...`;
}
