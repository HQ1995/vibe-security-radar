import type { BugCommit, FixCommit } from "@/lib/types";
import { getFixSourceLabel } from "@/lib/constants";
import { buildCommitUrl, extractRepoName } from "@/lib/commit-utils";

interface ChainStep {
  readonly label: string;
  readonly sha?: string;
  readonly context?: string;
  readonly variant: "source" | "commit" | "process" | "result";
}

interface AttributionChainProps {
  readonly bugCommits: readonly BugCommit[];
  readonly fixCommits: readonly FixCommit[];
  readonly repoUrl?: string;
}

function deriveChain(
  bugCommit: BugCommit,
  fixCommits: readonly FixCommit[],
): readonly ChainStep[] {
  const fixCommit =
    fixCommits.find((fc) => fc.sha === bugCommit.fix_commit_sha) ??
    fixCommits[0];

  const steps: ChainStep[] = [];

  // 1. Advisory source
  steps.push({
    label: "Advisory",
    context: fixCommit ? getFixSourceLabel(fixCommit.source) : undefined,
    variant: "source",
  });

  // 2. Fix commit
  if (fixCommit) {
    steps.push({
      label: "Fix Commit",
      sha: fixCommit.sha,
      context: extractRepoName(fixCommit.repo_url),
      variant: "commit",
    });
  }

  // 3. Blame step — branch on strategy
  if (bugCommit.blame_strategy === "verifier_discovered") {
    steps.push({
      label: "git blame",
      context: "No direct match",
      variant: "process",
    });
    steps.push({
      label: "LLM Investigator",
      context: "Discovered during deep verification",
      variant: "process",
    });
  } else {
    steps.push({
      label: "git blame",
      context: bugCommit.blamed_file,
      variant: "process",
    });
  }

  // 4. Squash decomposition (if applicable)
  if (bugCommit.squash_merge_sha) {
    const subCount = bugCommit.decomposed_commits?.length ?? "?";
    steps.push({
      label: "Squash Merge",
      sha: bugCommit.squash_merge_sha,
      context: `${subCount} sub-commits`,
      variant: "commit",
    });
    steps.push({
      label: "PR Decomposition",
      context: "File overlap + AI signal analysis",
      variant: "process",
    });
  }

  // 5. Bug-introducing commit (final)
  steps.push({
    label: "Bug-Introducing Commit",
    sha: bugCommit.sha,
    variant: "result",
  });

  return steps;
}

function StepDot({ isResult }: { readonly isResult: boolean }) {
  return (
    <div
      className={`absolute -left-[5px] top-[3px] h-2 w-2 rounded-full ${
        isResult ? "bg-foreground" : "bg-muted-foreground"
      }`}
    />
  );
}

function ShaLink({
  sha,
  repoUrl,
  isResult,
}: {
  readonly sha: string;
  readonly repoUrl?: string;
  readonly isResult: boolean;
}) {
  const display = sha.slice(0, 7);
  const textClass = isResult
    ? "font-mono text-sm text-foreground"
    : "font-mono text-sm text-primary";

  if (repoUrl) {
    const href = buildCommitUrl(repoUrl, sha);
    return (
      <a
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        className={`${textClass} hover:underline`}
      >
        {display}
      </a>
    );
  }

  return <span className={textClass}>{display}</span>;
}

function ChainStepRow({
  step,
  repoUrl,
  isLast,
}: {
  readonly step: ChainStep;
  readonly repoUrl?: string;
  readonly isLast: boolean;
}) {
  const isResult = step.variant === "result";

  return (
    <div
      className={`relative border-l border-border pl-4 ${
        isLast ? "border-transparent pb-0" : "pb-4"
      }`}
    >
      <StepDot isResult={isResult} />
      <div className="flex flex-col gap-0.5">
        <span
          className={`text-xs uppercase tracking-wider font-medium ${
            isResult ? "text-foreground" : "text-muted-foreground"
          }`}
        >
          {step.label}
        </span>
        <div className="flex items-center gap-2">
          {step.sha && (
            <ShaLink sha={step.sha} repoUrl={repoUrl} isResult={isResult} />
          )}
          {step.context && (
            <span className="text-xs text-muted-foreground">
              {step.sha ? `\u2014 ${step.context}` : step.context}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

function SingleChain({
  bugCommit,
  fixCommits,
  repoUrl,
}: {
  readonly bugCommit: BugCommit;
  readonly fixCommits: readonly FixCommit[];
  readonly repoUrl?: string;
}) {
  const steps = deriveChain(bugCommit, fixCommits);

  return (
    <div className="relative">
      {steps.map((step, i) => (
        <ChainStepRow
          key={`${step.label}-${step.sha ?? i}`}
          step={step}
          repoUrl={repoUrl}
          isLast={i === steps.length - 1}
        />
      ))}
    </div>
  );
}

export function AttributionChain({
  bugCommits,
  fixCommits,
  repoUrl,
}: AttributionChainProps) {
  if (bugCommits.length === 0) {
    return null;
  }

  const visibleCommits = bugCommits.slice(0, 2);
  const hiddenCommits = bugCommits.slice(2);

  return (
    <div className="space-y-6">
      {visibleCommits.map((bc) => (
        <SingleChain
          key={bc.sha}
          bugCommit={bc}
          fixCommits={fixCommits}
          repoUrl={repoUrl}
        />
      ))}
      {hiddenCommits.length > 0 && (
        <details className="group">
          <summary className="cursor-pointer text-sm text-muted-foreground hover:text-foreground transition-colors">
            +{hiddenCommits.length} more attribution{" "}
            {hiddenCommits.length === 1 ? "chain" : "chains"}
          </summary>
          <div className="mt-4 space-y-6">
            {hiddenCommits.map((bc) => (
              <SingleChain
                key={bc.sha}
                bugCommit={bc}
                fixCommits={fixCommits}
                repoUrl={repoUrl}
              />
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
