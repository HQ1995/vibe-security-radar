import Link from "next/link";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const TOOL_DISPLAY_NAMES: Readonly<Record<string, string>> = {
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
  unknown_ai: "Unknown AI",
};

const SEVERITY_COLORS: Readonly<Record<string, string>> = {
  CRITICAL: "bg-red-600 text-white hover:bg-red-600",
  HIGH: "bg-orange-500 text-white hover:bg-orange-500",
  MEDIUM: "bg-yellow-500 text-black hover:bg-yellow-500",
  LOW: "bg-green-600 text-white hover:bg-green-600",
  UNKNOWN: "bg-zinc-500 text-white hover:bg-zinc-500",
};

function getDisplayName(tool: string): string {
  return TOOL_DISPLAY_NAMES[tool] ?? tool;
}

function severityBadgeClass(severity: string): string {
  return SEVERITY_COLORS[severity] ?? SEVERITY_COLORS["UNKNOWN"];
}

interface ToolCardProps {
  readonly tool: string;
  readonly count: number;
  readonly severities: Readonly<Record<string, number>>;
}

export function ToolCard({ tool, count, severities }: ToolCardProps) {
  const displayName = getDisplayName(tool);

  return (
    <Link href={`/cves?tool=${encodeURIComponent(tool)}`}>
      <Card className="transition-colors hover:border-primary/50">
        <CardHeader className="pb-2">
          <CardTitle className="text-lg">{displayName}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-3xl font-bold tabular-nums">
            {count}
            <span className="ml-2 text-sm font-normal text-muted-foreground">
              {count === 1 ? "CVE" : "CVEs"}
            </span>
          </p>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(severities).map(([severity, severityCount]) => (
              <Badge key={severity} className={severityBadgeClass(severity)}>
                {severity} {severityCount}
              </Badge>
            ))}
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}
