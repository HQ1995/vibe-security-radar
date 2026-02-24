import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { AiSignalEntry } from "@/lib/types";

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

const SIGNAL_TYPE_LABELS: Readonly<Record<string, string>> = {
  co_author_trailer: "Co-author trailer",
  author_email: "Author email",
  commit_message: "Commit message",
  branch_name: "Branch name",
};

function getToolDisplayName(tool: string): string {
  return TOOL_DISPLAY_NAMES[tool] ?? tool;
}

function getSignalTypeLabel(signalType: string): string {
  return SIGNAL_TYPE_LABELS[signalType] ?? signalType.replaceAll("_", " ");
}

function formatConfidencePercent(confidence: number): string {
  return `${Math.round(confidence * 100)}%`;
}

interface AiSignalsDisplayProps {
  readonly signals: readonly AiSignalEntry[];
  readonly commitSha: string;
}

export function AiSignalsDisplay({ signals, commitSha }: AiSignalsDisplayProps) {
  if (signals.length === 0) {
    return null;
  }

  return (
    <Card className="border-primary/30 bg-primary/5">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          AI Signals in {commitSha.slice(0, 7)}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-2">
          {signals.map((signal, index) => (
            <SignalPill key={`${commitSha}-${signal.tool}-${signal.signal_type}-${index}`} signal={signal} />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function SignalPill({ signal }: { readonly signal: AiSignalEntry }) {
  return (
    <div className="flex items-center gap-1.5 rounded-lg border border-border bg-muted/50 px-3 py-1.5">
      <Badge className="bg-primary/20 text-primary hover:bg-primary/20">
        {getToolDisplayName(signal.tool)}
      </Badge>
      <span className="text-xs text-muted-foreground">
        {getSignalTypeLabel(signal.signal_type)}
      </span>
      <Badge variant="outline" className="ml-1 font-mono text-xs">
        {formatConfidencePercent(signal.confidence)}
      </Badge>
    </div>
  );
}
