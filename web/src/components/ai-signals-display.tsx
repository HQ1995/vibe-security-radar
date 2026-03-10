import { Badge } from "@/components/ui/badge";
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
  readonly prUrl?: string;
  readonly prTitle?: string;
}

export function AiSignalsDisplay({
  signals,
  commitSha,
  repoUrl,
  prUrl,
  prTitle,
}: AiSignalsDisplayProps) {
  if (signals.length === 0) {
    return null;
  }

  const shaFragment = commitSha.slice(0, 7);

  return (
    <div className="rounded-lg border overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-2 px-4 py-2 bg-muted/50 border-b text-sm">
        <span className="text-muted-foreground">Commit</span>
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
        {prUrl && /^https:\/\/github\.com\//.test(prUrl) && (
          <>
            <span className="text-muted-foreground/40">|</span>
            <a
              href={prUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary underline-offset-4 hover:underline truncate max-w-[300px]"
            >
              PR #{prUrl.match(/\/pull\/(\d+)/)?.[1] ?? prUrl.split("/").pop()}
              {prTitle && <span className="text-muted-foreground ml-1">{prTitle}</span>}
            </a>
          </>
        )}
      </div>
      {/* Signal rows */}
      <table className="w-full text-sm">
        <tbody className="divide-y divide-border">
          {signals.map((signal, index) => (
            <tr key={`${commitSha}-${signal.tool}-${signal.signal_type}-${index}`} className="hover:bg-muted/30">
              <td className="px-4 py-2 whitespace-nowrap">
                <Badge className="bg-primary/20 text-primary hover:bg-primary/20 text-xs">
                  {getToolDisplayName(signal.tool)}
                </Badge>
              </td>
              <td className="px-4 py-2 text-muted-foreground whitespace-nowrap">
                {getSignalTypeLabel(signal.signal_type)}
              </td>
              <td className="px-4 py-2 max-w-[200px]">
                {signal.matched_text && (
                  <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs truncate block">
                    {signal.matched_text}
                  </code>
                )}
              </td>
              <td className="px-4 py-2 text-right whitespace-nowrap">
                <span className="font-mono text-xs text-muted-foreground">
                  {formatConfidence(signal.confidence)}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
