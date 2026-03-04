import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  getToolDisplayName,
  getSignalTypeLabel,
  formatConfidence,
} from "@/lib/constants";
import { buildCommitUrl } from "@/lib/commit-utils";
import type { AiSignalEntry } from "@/lib/types";

interface AiSignalsDisplayProps {
  readonly signals: readonly AiSignalEntry[];
  readonly commitSha: string;
  readonly repoUrl?: string;
}

export function AiSignalsDisplay({
  signals,
  commitSha,
  repoUrl,
}: AiSignalsDisplayProps) {
  if (signals.length === 0) {
    return null;
  }

  const shaFragment = commitSha.slice(0, 7);

  return (
    <Card className="border-primary/30 bg-primary/5">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          AI Signals in{" "}
          {repoUrl ? (
            <a
              href={buildCommitUrl(repoUrl, commitSha)}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-primary underline-offset-4 hover:underline"
            >
              {shaFragment}
            </a>
          ) : (
            <span className="font-mono">{shaFragment}</span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-2">
          {signals.map((signal, index) => (
            <SignalPill
              key={`${commitSha}-${signal.tool}-${signal.signal_type}-${index}`}
              signal={signal}
            />
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
      {signal.matched_text && (
        <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
          {signal.matched_text}
        </code>
      )}
      <Badge variant="outline" className="ml-1 font-mono text-xs">
        {formatConfidence(signal.confidence)}
      </Badge>
    </div>
  );
}
