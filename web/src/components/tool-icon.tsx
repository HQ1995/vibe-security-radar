import { getToolDisplayName } from "@/lib/constants";

/** Tools that have separate light/dark SVGs (e.g. foo.svg + foo_dark.svg). */
const THEMED_ICONS = new Set(["github_copilot", "cursor", "unknown_ai"]);

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
  "kimi_code",
  "google_antigravity",
  "kilo_code",
  "codegeex",
  "bolt_new",
  "zencoder",
  "codegpt",
  "amp",
  "v0",
  "same_dev",
  "leap_new",
  "traycer",
  "atlassian_rovo",
  "aether",
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

  if (THEMED_ICONS.has(tool)) {
    return (
      <>
        <img
          src={`/icons/tools/${tool}.svg`}
          alt={displayName}
          title={displayName}
          width={size}
          height={size}
          className="inline-block shrink-0 dark:hidden"
        />
        <img
          src={`/icons/tools/${tool}_dark.svg`}
          alt={displayName}
          title={displayName}
          width={size}
          height={size}
          className="hidden shrink-0 dark:inline-block"
        />
      </>
    );
  }

  return (
    <img
      src={`/icons/tools/${tool}.svg`}
      alt={displayName}
      title={displayName}
      width={size}
      height={size}
      className="inline-block shrink-0"
    />
  );
}
