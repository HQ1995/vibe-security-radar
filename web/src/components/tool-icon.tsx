import Image from "next/image";
import { getToolDisplayName } from "@/lib/constants";

/** Tools that have separate light/dark SVGs (e.g. foo.svg + foo_dark.svg). */
export const THEMED_ICONS = new Set(["github_copilot", "cursor", "unknown_ai"]);

/** Intrinsic SVG width/height ratios for the non-square tool marks. */
const ICON_ASPECT_RATIOS: Readonly<Record<string, number>> = {
  cursor: 466.73 / 532.09,
  github_copilot: 256 / 208,
  replit_agent: 20 / 24,
};

export function getIconDimensions(iconKey: string, width: number) {
  const ratio = ICON_ASPECT_RATIOS[iconKey] ?? 1;
  return { width, height: Math.round(width / ratio) };
}

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
  const dimensions = getIconDimensions(tool, size);

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
        <Image
          src={`/icons/tools/${tool}.svg`}
          alt={displayName}
          title={displayName}
          {...dimensions}
          className="inline-block shrink-0 dark:hidden"
        />
        <Image
          src={`/icons/tools/${tool}_dark.svg`}
          alt={displayName}
          title={displayName}
          {...dimensions}
          className="hidden shrink-0 dark:inline-block"
        />
      </>
    );
  }

  return (
    <Image
      src={`/icons/tools/${tool}.svg`}
      alt={displayName}
      title={displayName}
      {...dimensions}
      className="inline-block shrink-0"
    />
  );
}
