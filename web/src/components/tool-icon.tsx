import Image from "next/image";
import { getToolDisplayName } from "@/lib/constants";

export const THEMED_ICONS = new Set([
  "github_copilot",
  "cursor",
  "unknown_ai",
]);

const ICON_ASPECT_RATIOS: Readonly<Record<string, number>> = {
  cursor: 466.73 / 532.09,
  github_copilot: 256 / 208,
};

export function getIconDimensions(iconKey: string, width: number) {
  const ratio = ICON_ASPECT_RATIOS[iconKey] ?? 1;
  return { width, height: Math.round(width / ratio) };
}

const TOOLS_WITH_ICONS = new Set([
  "claude_code",
  "github_copilot",
  "cursor",
  "openai_codex",
  "unknown_ai",
]);

interface ToolIconProps {
  readonly tool: string;
  readonly size?: number;
}

export function ToolIcon({ tool, size = 20 }: ToolIconProps) {
  const displayName = getToolDisplayName(tool);
  const dimensions = getIconDimensions(tool, size);
  const source =
    tool === "openai_codex"
      ? "/icons/tools/chatgpt-64.png"
      : `/icons/tools/${tool}.svg`;

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
          src={source}
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
      src={source}
      alt={displayName}
      title={displayName}
      {...dimensions}
      className="inline-block shrink-0"
    />
  );
}
