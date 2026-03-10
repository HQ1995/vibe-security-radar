import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getCves, getCveById } from "@/lib/data";
import { Badge } from "@/components/ui/badge";
import { AiSignalsDisplay } from "@/components/ai-signals-display";
import {
  BugCommitTimeline,
  FixCommitTimeline,
} from "@/components/commit-timeline";
import { ToolIcon } from "@/components/tool-icon";
import {
  severityBadgeClass,
  getToolDisplayName,
  getSignalTypeLabel,
  formatVerifiedBy,
  formatConfidence,
  getModelDisplayName,
} from "@/lib/constants";
import { formatPublished, buildCommitUrl } from "@/lib/commit-utils";
import type { CveEntry, BugCommit, FixCommit } from "@/lib/types";

// --- Static generation ---

export function generateStaticParams() {
  const data = getCves();
  return data.cves.map((cve) => ({ id: cve.id }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ id: string }>;
}): Promise<Metadata> {
  const { id } = await params;
  const cve = getCveById(id);
  if (!cve) {
    return { title: "Vulnerability Not Found - Vibe Security Radar" };
  }
  return {
    title: `${cve.id} - Vibe Security Radar`,
    description: cve.description,
  };
}

// --- Helpers ---

function collectUniqueSignalTypes(
  commits: readonly BugCommit[],
): readonly string[] {
  const types = new Set<string>();
  for (const commit of commits) {
    for (const signal of commit.ai_signals) {
      types.add(getSignalTypeLabel(signal.signal_type));
    }
  }
  return Array.from(types);
}

function commitsWithAiSignals(
  commits: readonly BugCommit[],
): readonly BugCommit[] {
  return commits.filter((c) => c.ai_signals.length > 0);
}

function countTotalSignals(commits: readonly BugCommit[]): number {
  return commits.reduce((sum, c) => sum + c.ai_signals.length, 0);
}

// --- Verdict helpers ---

function verdictBadgeClass(verdict: string): string {
  if (verdict === "CONFIRMED") return "bg-green-600/20 text-green-700 dark:text-green-300 border-green-600/30";
  if (verdict === "UNLIKELY") return "bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/30";
  return "bg-red-500/20 text-red-700 dark:text-red-300 border-red-500/30";
}

function verdictAccentBorder(verdict: string): string {
  if (verdict === "CONFIRMED") return "border-l-green-500";
  if (verdict === "UNLIKELY") return "border-l-amber-500";
  return "border-l-red-400";
}

function verdictBarColor(verdict: string): string {
  if (verdict === "CONFIRMED") return "bg-green-500";
  if (verdict === "UNLIKELY") return "bg-amber-500";
  return "bg-red-400";
}

// --- Section components ---

function PageHeader({ cve }: { readonly cve: CveEntry }) {
  return (
    <div className="space-y-3">
      <Link
        href="/cves"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
      >
        &larr; Back
      </Link>

      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-bold tracking-tight sm:text-3xl font-mono">
          {cve.id}
        </h1>
        <Badge className={severityBadgeClass(cve.severity)}>
          {cve.severity}
        </Badge>
        {cve.cvss !== null && cve.cvss > 0 && (
          <span className="rounded bg-muted px-2 py-0.5 font-mono text-sm font-medium">
            CVSS {cve.cvss.toFixed(1)}
          </span>
        )}
        {cve.ai_tools.map((tool) => (
          <Badge
            key={tool}
            variant="secondary"
            className="inline-flex items-center gap-1"
          >
            <ToolIcon tool={tool} size={14} />
            {getToolDisplayName(tool)}
          </Badge>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted-foreground">
        {cve.published && <span>{formatPublished(cve.published)}</span>}
        {cve.ecosystem && (
          <span className="rounded bg-muted px-1.5 py-0.5 text-xs">{cve.ecosystem}</span>
        )}
        {cve.cwes.map((cwe) => {
          const cweNum = cwe.replace(/^CWE-/, "");
          return (
            <a
              key={cwe}
              href={`https://cwe.mitre.org/data/definitions/${cweNum}.html`}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-xs text-primary hover:underline underline-offset-4"
            >
              {cwe}
            </a>
          );
        })}
        <span>Verified by: {formatVerifiedBy(cve.verified_by)}</span>
      </div>
    </div>
  );
}

function VerdictSection({ cve, repoUrl }: { readonly cve: CveEntry; readonly repoUrl?: string }) {
  const hasExplanation = cve.how_introduced.length > 0;
  const signalTypes = collectUniqueSignalTypes(cve.bug_commits);

  // Find the best tribunal verdict across all commits
  const tribunalCommits = cve.bug_commits.filter((c) => c.tribunal_verdict?.agent_verdicts?.length);
  const bestTribunal = tribunalCommits.length > 0 ? tribunalCommits[0].tribunal_verdict! : null;

  // Find LLM causality verdicts
  const causalityCommits = cve.bug_commits.filter((c) => c.llm_verdict !== null);
  const bestCausality = causalityCommits.length > 0 ? causalityCommits[0].llm_verdict! : null;

  // Pick the primary verdict to show
  const primaryVerdict = bestTribunal?.verdict ?? bestCausality?.verdict;
  const primaryConfidence = bestTribunal?.confidence ?? null;

  if (!primaryVerdict && !hasExplanation) return null;

  return (
    <div className={`rounded-lg border border-l-4 p-5 space-y-4 ${primaryVerdict ? verdictAccentBorder(primaryVerdict) : "border-l-muted-foreground"}`}>
      {/* Verdict headline */}
      {primaryVerdict && (
        <div className="flex items-center gap-3">
          <span className={`inline-flex items-center rounded-md border px-2.5 py-1 text-sm font-bold ${verdictBadgeClass(primaryVerdict)}`}>
            {primaryVerdict}
          </span>
          {primaryConfidence && (
            <span className="text-sm text-muted-foreground">Confidence: {primaryConfidence}</span>
          )}
        </div>
      )}

      {/* Explanation */}
      {hasExplanation ? (
        <p className="text-sm leading-relaxed text-muted-foreground">{cve.how_introduced}</p>
      ) : signalTypes.length > 0 ? (
        <p className="text-sm leading-relaxed text-muted-foreground">
          Detected AI tool involvement via {signalTypes.join(", ")}.
        </p>
      ) : null}

      {/* Best causality reasoning (if no tribunal, or as supplementary) */}
      {bestCausality && !bestTribunal && (
        <div className="space-y-2">
          {bestCausality.vuln_type && (
            <div className="flex gap-2 text-sm">
              <span className="font-medium text-muted-foreground shrink-0">Vulnerability:</span>
              <span className="capitalize">{bestCausality.vuln_type}</span>
            </div>
          )}
          {bestCausality.vuln_description && (
            <div className="flex gap-2 text-sm">
              <span className="font-medium text-muted-foreground shrink-0">Root Cause:</span>
              <span className="text-muted-foreground">{bestCausality.vuln_description}</span>
            </div>
          )}
          {bestCausality.vulnerable_pattern && (
            <div className="flex gap-2 text-sm">
              <span className="font-medium text-muted-foreground shrink-0">Pattern:</span>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{bestCausality.vulnerable_pattern}</code>
            </div>
          )}
          {bestCausality.causal_chain && (
            <div className="flex gap-2 text-sm">
              <span className="font-medium text-muted-foreground shrink-0">Causal Chain:</span>
              <span className="text-muted-foreground">{bestCausality.causal_chain}</span>
            </div>
          )}
          {bestCausality.reasoning && !bestCausality.vuln_description && (
            <p className="text-sm text-muted-foreground">{bestCausality.reasoning}</p>
          )}
        </div>
      )}

      {/* Tribunal agent verdicts (collapsible) */}
      {bestTribunal && (
        <details className="group">
          <summary className="text-sm font-medium cursor-pointer hover:text-foreground text-muted-foreground transition-colors">
            Tribunal Details ({bestTribunal.agent_verdicts!.length} agents)
          </summary>
          <div className="mt-3 rounded-lg border overflow-hidden divide-y divide-border">
            {bestTribunal.agent_verdicts!.map((av) => (
              <details key={av.model} className="group/agent">
                <summary className="flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-muted/50 transition-colors">
                  <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold shrink-0 ${verdictBadgeClass(av.verdict)}`}>
                    {av.verdict}
                  </span>
                  <span className="text-sm font-medium shrink-0">
                    {getModelDisplayName(av.model)}
                  </span>
                  <div className="flex items-center gap-2 ml-auto shrink-0">
                    <div className="h-1.5 w-16 rounded-full bg-muted">
                      <div
                        className={`h-1.5 rounded-full ${verdictBarColor(av.verdict)}`}
                        style={{ width: `${Math.round(av.confidence * 100)}%` }}
                      />
                    </div>
                    <span className="text-xs text-muted-foreground tabular-nums w-8 text-right">
                      {formatConfidence(av.confidence)}
                    </span>
                  </div>
                </summary>
                <div className="px-4 py-3 bg-muted/30 text-sm space-y-2">
                  <p className="text-muted-foreground leading-relaxed">{av.reasoning}</p>
                  {av.evidence.length > 0 && (
                    <ul className="list-disc list-inside space-y-0.5 text-xs text-muted-foreground">
                      {av.evidence.map((e, i) => (
                        <li key={`${i}-${e.slice(0, 32)}`}>{e}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </details>
            ))}
          </div>
        </details>
      )}

      {/* Additional causality commits beyond the first (rare, collapsible) */}
      {causalityCommits.length > 1 && (
        <details>
          <summary className="text-sm font-medium cursor-pointer hover:text-foreground text-muted-foreground transition-colors">
            {causalityCommits.length - 1} more causality analysis{causalityCommits.length > 2 ? "es" : ""}
          </summary>
          <div className="mt-2 space-y-2">
            {causalityCommits.slice(1).map((commit) => {
              const v = commit.llm_verdict!;
              return (
                <div key={commit.sha} className="text-sm pl-3 border-l-2 border-muted space-y-1">
                  <div className="flex items-center gap-2">
                    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold ${verdictBadgeClass(v.verdict)}`}>
                      {v.verdict}
                    </span>
                    {repoUrl ? (
                      <a
                        href={buildCommitUrl(repoUrl, commit.sha)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono text-xs text-primary hover:underline"
                      >
                        {commit.sha.slice(0, 7)}
                      </a>
                    ) : (
                      <span className="font-mono text-xs">{commit.sha.slice(0, 7)}</span>
                    )}
                  </div>
                  <p className="text-muted-foreground">{v.reasoning}</p>
                </div>
              );
            })}
          </div>
        </details>
      )}
    </div>
  );
}

function CollapsibleSection({
  title,
  count,
  defaultOpen,
  children,
}: {
  readonly title: string;
  readonly count?: number;
  readonly defaultOpen?: boolean;
  readonly children: React.ReactNode;
}) {
  return (
    <details open={defaultOpen} className="group">
      <summary className="flex items-center gap-2 cursor-pointer text-lg font-semibold tracking-tight hover:text-foreground transition-colors">
        <span className="text-muted-foreground group-open:rotate-90 transition-transform text-sm">&#9654;</span>
        {title}
        {count !== undefined && (
          <span className="text-sm font-normal text-muted-foreground">({count})</span>
        )}
      </summary>
      <div className="mt-3">
        {children}
      </div>
    </details>
  );
}

// --- Page component ---

export default async function CveDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const cve = getCveById(id);

  if (!cve) {
    notFound();
  }

  const repoUrl = cve.fix_commits[0]?.repo_url;
  const aiCommits = commitsWithAiSignals(cve.bug_commits);
  const totalSignals = countTotalSignals(cve.bug_commits);

  return (
    <main className="mx-auto max-w-4xl space-y-6 px-4 py-10 sm:px-6">
      <PageHeader cve={cve} />

      {/* Description — no card wrapper */}
      <p className="leading-relaxed text-muted-foreground">{cve.description}</p>

      {/* Verdict — the star of the page */}
      <VerdictSection cve={cve} repoUrl={repoUrl} />

      {/* Evidence sections — all collapsible */}
      {aiCommits.length > 0 && (
        <CollapsibleSection title="AI Signals" count={totalSignals} defaultOpen={totalSignals <= 6}>
          <div className="space-y-3">
            {aiCommits.map((commit) => (
              <AiSignalsDisplay
                key={commit.sha}
                signals={commit.ai_signals}
                commitSha={commit.sha}
                repoUrl={repoUrl}
                prUrl={commit.pr_url}
                prTitle={commit.pr_title}
              />
            ))}
          </div>
        </CollapsibleSection>
      )}

      <CollapsibleSection title="Bug-Introducing Commits" count={cve.bug_commits.length}>
        <BugCommitTimeline commits={cve.bug_commits} repoUrl={repoUrl} />
      </CollapsibleSection>

      <CollapsibleSection title="Fix Commits" count={cve.fix_commits.length}>
        <FixCommitTimeline commits={cve.fix_commits} />
      </CollapsibleSection>

      {cve.references.length > 0 && (
        <CollapsibleSection title="References" count={cve.references.length}>
          <ul className="space-y-1.5">
            {cve.references.map((ref) => (
              <li key={ref}>
                <a
                  href={/^https?:\/\//i.test(ref) ? ref : "#"}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-primary underline-offset-4 hover:underline break-all"
                >
                  {ref}
                </a>
              </li>
            ))}
          </ul>
        </CollapsibleSection>
      )}
    </main>
  );
}
