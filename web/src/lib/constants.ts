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
  unknown_ai: "Unknown AI",
};

export const SIGNAL_TYPE_LABELS: Readonly<Record<string, string>> = {
  co_author_trailer: "Co-author trailer",
  author_email: "Author email",
  commit_message: "Commit message",
  branch_name: "Branch name",
};

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

export function formatVerifiedBy(verifiedBy: string): string {
  if (!verifiedBy) return "Unverified";
  return verifiedBy;
}

/** Short label for the verified-by badge shown in table columns. */
export function verifiedByLabel(verifiedBy: string): string {
  if (!verifiedBy) return "";
  if (verifiedBy === "osv") return "OSV";
  return "LLM";
}

/** Tooltip text for the verified-by badge. */
export function verifiedByTooltip(verifiedBy: string): string {
  if (!verifiedBy) return "Not yet verified";
  if (verifiedBy === "osv") return "Verified via OSV advisory data";
  return `Verified by ${verifiedBy}`;
}

export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}...`;
}
