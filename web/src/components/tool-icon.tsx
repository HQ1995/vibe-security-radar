import { getToolDisplayName } from "@/lib/constants";

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
