import { Badge } from "@/components/ui/badge";
import { Section } from "@/components/ui/section";
import {
  buildCommitUrl,
  extractRepoName,
  formatDate,
  firstLine,
} from "@/lib/commit-utils";
import {
  formatConfidence,
  getToolDisplayName,
  getSignalTypeLabel,
  getFixSourceLabel,
  fixSourceBadgeClass,
  truncate,
} from "@/lib/constants";
import { CollapsibleNonAiCommits } from "@/components/collapsible-commits";
import { cn } from "@/lib/utils";
import type { BugCommit, DecomposedCommit, FixCommit } from "@/lib/types";

// --- Bug commits timeline ---

interface BugCommitTimelineProps {
  readonly commits: readonly BugCommit[];
  readonly repoUrl?: string;
}

export function bugCommitSubjectKey(
  commit: Pick<BugCommit, "fix_commit_sha" | "sha" | "blamed_file">,
): string {
  return `${commit.fix_commit_sha ?? ""}:${commit.sha}:${commit.blamed_file}`;
}

function hasAiSignals(commit: BugCommit): boolean {
  return commit.ai_signals.length > 0;
}

function isCulprit(dc: DecomposedCommit): boolean {
  return dc.ai_signals.length > 0 && dc.touched_blamed_file === true;
}

function SubCommitRow({
  dc,
  repoUrl,
}: {
  readonly dc: DecomposedCommit;
  readonly repoUrl?: string;
}) {
  const culprit = isCulprit(dc);
  return (
    <div
      className={cn(
        "rounded-md px-3 py-2 text-sm",
        culprit && "bg-primary/5",
      )}
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        {repoUrl ? (
          <a
            href={buildCommitUrl(repoUrl, dc.sha)}
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-xs text-primary underline-offset-4 hover:underline shrink-0"
          >
            {dc.sha.slice(0, 7)}
          </a>
        ) : (
          <code className="font-mono text-xs shrink-0">{dc.sha.slice(0, 7)}</code>
        )}
        <span className="text-xs text-muted-foreground shrink-0">{dc.author_name}</span>
        {culprit && (
          <Badge className="bg-red-600/20 text-red-700 dark:text-red-300 hover:bg-red-600/20 text-[10px] px-1.5 py-0 shrink-0">
            Culprit
          </Badge>
        )}
      </div>
      <p className="mt-1 text-xs text-muted-foreground truncate">
        {truncate(firstLine(dc.message), 120)}
      </p>
      {dc.ai_signals.length > 0 && (
        <div className="mt-1.5 flex flex-wrap gap-1.5">
          {dc.ai_signals.map((sig, i) => (
            <span
              key={`${dc.sha}-${sig.tool}-${i}`}
              className="inline-flex items-center gap-1 rounded bg-purple-600/10 px-1.5 py-0.5 text-[10px] text-purple-700 dark:text-purple-300"
            >
              {getToolDisplayName(sig.tool)}
              <span className="text-purple-500/60">&middot;</span>
              {getSignalTypeLabel(sig.signal_type)}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function DecomposedCommitsSection({
  commits,
  repoUrl,
}: {
  readonly commits: readonly DecomposedCommit[];
  readonly repoUrl?: string;
}) {
  return (
    <Section
      size="sm"
      title={`${commits.length} sub-commit${commits.length > 1 ? "s" : ""} in this PR`}
      className="mt-2"
    >
      <div className="space-y-1.5 border-l-2 border-muted pl-3">
        {commits.map((dc) => (
          <SubCommitRow key={dc.sha} dc={dc} repoUrl={repoUrl} />
        ))}
      </div>
    </Section>
  );
}

function BugCommitRow({
  commit,
  repoUrl,
}: {
  readonly commit: BugCommit;
  readonly repoUrl?: string;
}) {
  return (
    <div className="py-3">
      <div className="flex items-center gap-2">
        {repoUrl ? (
          <a
            href={buildCommitUrl(repoUrl, commit.sha)}
            target="_blank"
            rel="noopener noreferrer"
            className="rounded bg-muted px-2 py-0.5 font-mono text-sm text-primary underline-offset-4 hover:underline shrink-0"
          >
            {commit.sha.slice(0, 7)}
          </a>
        ) : (
          <code className="rounded bg-muted px-2 py-0.5 font-mono text-sm shrink-0">
            {commit.sha.slice(0, 7)}
          </code>
        )}
        {hasAiSignals(commit) && (
          <Badge className="bg-purple-600 text-white hover:bg-purple-600">
            AI
          </Badge>
        )}
        <p className="min-w-0 flex-1 truncate text-sm font-medium">
          {firstLine(commit.message)}
        </p>
      </div>
      <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span>{commit.author}</span>
        <span>{formatDate(commit.date)}</span>
        <span className="font-mono" title="Blamed file">
          {commit.blamed_file}
        </span>
        {commit.fix_commit_sha && (
          <span className="font-mono" title="Fix commit">
            Fix: {commit.fix_commit_sha.slice(0, 7)}
          </span>
        )}
        <span title="Blame confidence">
          Blame: {formatConfidence(commit.blame_confidence)}
        </span>
        {(commit.fix_commit_source === "ai_inferred" || commit.fix_commit_source === "ai_tag_search") && (
          <Badge
            variant="outline"
            className={fixSourceBadgeClass(commit.fix_commit_source)}
            title="Fix commit was discovered by AI inference, not from an advisory database"
          >
            {getFixSourceLabel(commit.fix_commit_source)}
          </Badge>
        )}
      </div>
      {commit.squash_merge_sha && (
        <p className="mt-1 text-xs text-muted-foreground/70">
          Extracted from squash merge{" "}
          {repoUrl ? (
            <a
              href={buildCommitUrl(repoUrl, commit.squash_merge_sha)}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono underline-offset-4 hover:underline"
            >
              {commit.squash_merge_sha.slice(0, 7)}
            </a>
          ) : (
            <code className="font-mono">{commit.squash_merge_sha.slice(0, 7)}</code>
          )}
        </p>
      )}
      {commit.decomposed_commits && commit.decomposed_commits.length > 0 && (
        <DecomposedCommitsSection
          commits={commit.decomposed_commits}
          repoUrl={repoUrl}
        />
      )}
    </div>
  );
}

const COLLAPSE_THRESHOLD = 5;

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

  const aiCommits = commits.filter(hasAiSignals);
  const nonAiCommits = commits.filter((c) => !hasAiSignals(c));
  const shouldCollapse = commits.length > COLLAPSE_THRESHOLD && nonAiCommits.length > 0;

  const visibleCommits = shouldCollapse ? aiCommits : commits;

  return (
    <div>
      <div className="divide-y divide-border">
        {visibleCommits.map((commit) => (
          <BugCommitRow
            key={bugCommitSubjectKey(commit)}
            commit={commit}
            repoUrl={repoUrl}
          />
        ))}
      </div>
      {shouldCollapse && (
        <CollapsibleNonAiCommits count={nonAiCommits.length}>
          <div className="divide-y divide-border">
            {nonAiCommits.map((commit) => (
              <BugCommitRow
                key={bugCommitSubjectKey(commit)}
                commit={commit}
                repoUrl={repoUrl}
              />
            ))}
          </div>
        </CollapsibleNonAiCommits>
      )}
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
    <div className="rounded-lg border overflow-hidden divide-y divide-border">
      {commits.map((commit) => (
        <div key={commit.sha} className="flex items-center gap-3 px-4 py-2.5 hover:bg-muted/30 transition-colors">
          {commit.repo_url ? (
            <a
              href={buildCommitUrl(commit.repo_url, commit.sha)}
              target="_blank"
              rel="noopener noreferrer"
              className="rounded bg-muted px-2 py-0.5 font-mono text-sm text-primary underline-offset-4 hover:underline shrink-0"
            >
              {commit.sha.slice(0, 7)}
            </a>
          ) : (
            <code className="rounded bg-muted px-2 py-0.5 font-mono text-sm shrink-0">
              {commit.sha.slice(0, 7)}
            </code>
          )}
          {commit.repo_url && (
            <a
              href={commit.repo_url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-muted-foreground hover:text-primary underline-offset-4 hover:underline truncate min-w-0"
            >
              {extractRepoName(commit.repo_url)}
            </a>
          )}
          <Badge
            variant="outline"
            className={`ml-auto text-xs shrink-0 ${fixSourceBadgeClass(commit.source)}`}
          >
            {getFixSourceLabel(commit.source)}
          </Badge>
        </div>
      ))}
    </div>
  );
}
