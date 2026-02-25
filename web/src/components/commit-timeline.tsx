import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  buildCommitUrl,
  formatDate,
  formatBlameConfidence,
  firstLine,
} from "@/lib/commit-utils";
import type { BugCommit, FixCommit } from "@/lib/types";

// --- Bug commits timeline ---

interface BugCommitTimelineProps {
  readonly commits: readonly BugCommit[];
  readonly repoUrl?: string;
}

function hasAiSignals(commit: BugCommit): boolean {
  return commit.ai_signals.length > 0;
}

export function BugCommitTimeline({
  commits,
  repoUrl,
}: BugCommitTimelineProps) {
  if (commits.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        No bug-introducing commits identified.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      {commits.map((commit) => (
        <Card
          key={commit.sha}
          className={hasAiSignals(commit) ? "border-primary/40" : ""}
        >
          <CardContent className="pt-4">
            <div className="flex flex-wrap items-start gap-x-4 gap-y-2">
              <div className="flex items-center gap-2">
                {repoUrl ? (
                  <a
                    href={buildCommitUrl(repoUrl, commit.sha)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="rounded bg-muted px-2 py-0.5 font-mono text-sm text-primary underline-offset-4 hover:underline"
                  >
                    {commit.sha.slice(0, 7)}
                  </a>
                ) : (
                  <code className="rounded bg-muted px-2 py-0.5 font-mono text-sm">
                    {commit.sha.slice(0, 7)}
                  </code>
                )}
                {hasAiSignals(commit) && (
                  <Badge className="bg-purple-600 text-white hover:bg-purple-600">
                    AI
                  </Badge>
                )}
              </div>
              <div className="flex-1 min-w-0">
                <p className="truncate text-sm font-medium">
                  {firstLine(commit.message)}
                </p>
                <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                  <span>{commit.author}</span>
                  <span>{formatDate(commit.date)}</span>
                  <span className="font-mono" title="Blamed file">
                    {commit.blamed_file}
                  </span>
                  <span title="Blame confidence">
                    Blame: {formatBlameConfidence(commit.blame_confidence)}
                  </span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// --- Fix commits timeline ---

interface FixCommitTimelineProps {
  readonly commits: readonly FixCommit[];
}

export function FixCommitTimeline({ commits }: FixCommitTimelineProps) {
  if (commits.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">No fix commits recorded.</p>
    );
  }

  return (
    <div className="space-y-3">
      {commits.map((commit) => (
        <Card key={commit.sha}>
          <CardContent className="pt-4">
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
              {commit.repo_url ? (
                <a
                  href={buildCommitUrl(commit.repo_url, commit.sha)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="rounded bg-muted px-2 py-0.5 font-mono text-sm text-primary underline-offset-4 hover:underline"
                >
                  {commit.sha.slice(0, 7)}
                </a>
              ) : (
                <code className="rounded bg-muted px-2 py-0.5 font-mono text-sm">
                  {commit.sha.slice(0, 7)}
                </code>
              )}
              {commit.repo_url ? (
                <a
                  href={buildCommitUrl(commit.repo_url, commit.sha)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="truncate text-sm text-primary underline-offset-4 hover:underline"
                >
                  {commit.repo_url.replace(/^https?:\/\//, "")}
                </a>
              ) : (
                <span className="text-sm text-muted-foreground">
                  No repo URL
                </span>
              )}
              <Badge variant="outline" className="ml-auto text-xs">
                {commit.source}
              </Badge>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
