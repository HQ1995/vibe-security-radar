import { getToolDisplayName } from "@/lib/constants";

/** Monochrome SVGs from Simple Icons — need dark:invert for dark mode. */
const MONOCHROME_ICONS = new Set([
  "claude_code",
  "github_copilot",
  "cursor",
  "google_gemini",
  "google_jules",
  "windsurf",
  "jetbrains_junie",
  "gitlab_duo",
  "qodo",
  "replit_agent",
  "gemini_cli",
  "google_antigravity",
]);

/** Map of tool keys that have dedicated SVG icon files in /icons/tools/. */
const TOOLS_WITH_ICONS = new Set([
  "claude_code",
  "github_copilot",
  "cursor",
  "google_gemini",
  "google_jules",
  "windsurf",
  "aider",
  "amazon_q",
  "codeium",
  "openai_codex",
  "devin",
  "sweep",
  "tabnine",
  "sourcegraph_cody",
  "opencode",
  "kiro",
  "jetbrains_junie",
  "roo_code",
  "cline",
  "openhands",
  "lovable",
  "fine_dev",
  "replit_agent",
  "qodo",
  "continue_dev",
  "augment_code",
  "trae",
  "gitlab_duo",
  "gemini_cli",
  "kimi_code",
  "google_antigravity",
  "kilo_code",
  "codegeex",
  "bolt_new",
  "zencoder",
  "codegpt",
  "unknown_ai",
]);

interface ToolIconProps {
  readonly tool: string;
  readonly size?: number;
}

export function ToolIcon({ tool, size = 20 }: ToolIconProps) {
  const displayName = getToolDisplayName(tool);

  if (!TOOLS_WITH_ICONS.has(tool)) {
    return (
      <span
        className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground"
        title={displayName}
      >
        {displayName}
      </span>
    );
  }

  const darkClass = MONOCHROME_ICONS.has(tool) ? " dark:invert" : "";

  return (
    <img
      src={`/icons/tools/${tool}.svg`}
      alt={displayName}
      title={displayName}
      width={size}
      height={size}
      className={`inline-block shrink-0${darkClass}`}
    />
  );
}
