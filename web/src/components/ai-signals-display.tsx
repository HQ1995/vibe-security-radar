import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  getToolDisplayName,
  getSignalTypeLabel,
  formatConfidence,
} from "@/lib/constants";
import type { AiSignalEntry } from "@/lib/types";

interface AiSignalsDisplayProps {
  readonly signals: readonly AiSignalEntry[];
  readonly commitSha: string;
}

export function AiSignalsDisplay({
  signals,
  commitSha,
}: AiSignalsDisplayProps) {
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
      <Badge variant="outline" className="ml-1 font-mono text-xs">
        {formatConfidence(signal.confidence)}
      </Badge>
    </div>
  );
}
