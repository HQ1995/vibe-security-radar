import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getCves, getCveById } from "@/lib/data";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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

// --- Section components ---

function PageHeader({ cve }: { readonly cve: CveEntry }) {
  return (
    <div className="space-y-4">
      <Link
        href="/cves"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
      >
        &larr; Back to Vulnerability Database
      </Link>

      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">
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
      </div>

      {cve.cwes.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {cve.cwes.map((cwe) => {
            const cweNum = cwe.replace(/^CWE-/, "");
            return (
              <a
                key={cwe}
                href={`https://cwe.mitre.org/data/definitions/${cweNum}.html`}
                target="_blank"
                rel="noopener noreferrer"
              >
                <Badge
                  variant="outline"
                  className="font-mono text-xs hover:bg-muted"
                >
                  {cwe}
                </Badge>
              </a>
            );
          })}
        </div>
      )}

      <div className="flex flex-wrap gap-x-6 gap-y-1 text-sm text-muted-foreground">
        {cve.published && <span>Published: {formatPublished(cve.published)}</span>}
        {cve.ecosystem && <span>Ecosystem: {cve.ecosystem}</span>}
        <span>Verified by: {formatVerifiedBy(cve.verified_by)}</span>
      </div>
    </div>
  );
}

function DescriptionSection({ description }: { readonly description: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-xl">Description</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="leading-relaxed text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  );
}

function VerdictIcon({ verdict }: { readonly verdict: string }) {
  if (verdict === "CONFIRMED") return <span className="text-green-600">&#10003;</span>;
  if (verdict === "UNLIKELY") return <span className="text-amber-600">?</span>;
  return <span className="text-red-400">&#10007;</span>;
}

function verdictBorderClass(verdict: string): string {
  if (verdict === "CONFIRMED") return "border-green-500/40 bg-green-500/5";
  if (verdict === "UNLIKELY") return "border-amber-500/40 bg-amber-500/5";
  return "border-red-500/30 bg-red-500/5";
}

function formatVerificationSource(models: readonly string[]): string {
  const sources: string[] = [];
  const llmModels = models.filter((m) => m !== "osv");
  if (models.includes("osv")) sources.push("OSV vulnerability database");
  if (llmModels.length > 0) sources.push(llmModels[0]);
  return sources.join(" + ");
}

function LlmCausalitySection({ commits, repoUrl }: { readonly commits: readonly BugCommit[]; readonly repoUrl?: string }) {
  const withVerdict = commits.filter((c) => c.llm_verdict !== null);
  if (withVerdict.length === 0) return null;

  const models = Array.from(new Set(withVerdict.map((c) => c.llm_verdict!.model)));

  return (
    <div className="mt-4 space-y-2">
      <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">
        Causality Analysis
      </h3>
      <div className="space-y-2">
        {withVerdict.map((commit) => {
          const v = commit.llm_verdict!;
          const shaText = commit.sha.slice(0, 12);
          const hasRichData = v.verdict === "CONFIRMED" && (v.vuln_type || v.causal_chain || v.vuln_description || v.vulnerable_pattern);
          return (
            <div
              key={commit.sha}
              className={`rounded-md border p-3 text-sm ${verdictBorderClass(v.verdict)}`}
            >
              <div className="flex items-start gap-2">
                <VerdictIcon verdict={v.verdict} />
                <div className="flex-1 space-y-2">
                  <div>
                    <span className="font-semibold">{v.verdict}</span>
                    {" — "}
                    {repoUrl ? (
                      <a
                        href={buildCommitUrl(repoUrl, commit.sha)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono text-xs text-primary underline-offset-4 hover:underline"
                      >
                        {shaText}
                      </a>
                    ) : (
                      <span className="font-mono text-xs">{shaText}</span>
                    )}
                  </div>
                  {hasRichData ? (
                    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
                      {v.vuln_type && (
                        <>
                          <dt className="font-medium text-muted-foreground">Vulnerability</dt>
                          <dd className="capitalize">{v.vuln_type}</dd>
                        </>
                      )}
                      {v.vuln_description && (
                        <>
                          <dt className="font-medium text-muted-foreground">Root Cause</dt>
                          <dd className="text-muted-foreground">{v.vuln_description}</dd>
                        </>
                      )}
                      {v.vulnerable_pattern && (
                        <>
                          <dt className="font-medium text-muted-foreground">Pattern</dt>
                          <dd>
                            <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                              {v.vulnerable_pattern}
                            </code>
                          </dd>
                        </>
                      )}
                      {v.causal_chain && (
                        <>
                          <dt className="font-medium text-muted-foreground">Causal Chain</dt>
                          <dd className="text-muted-foreground">{v.causal_chain}</dd>
                        </>
                      )}
                      {v.reasoning && (
                        <>
                          <dt className="font-medium text-muted-foreground">Reasoning</dt>
                          <dd className="text-muted-foreground">{v.reasoning}</dd>
                        </>
                      )}
                    </dl>
                  ) : (
                    <p className="text-muted-foreground">{v.reasoning}</p>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
      <p className="text-xs text-muted-foreground text-right">
        Verified by {formatVerificationSource(models)}
      </p>
    </div>
  );
}

function verdictBadgeClass(verdict: string): string {
  if (verdict === "CONFIRMED") return "bg-green-600/20 text-green-700 dark:text-green-300 border-green-600/30";
  if (verdict === "UNLIKELY") return "bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/30";
  return "bg-red-500/20 text-red-700 dark:text-red-300 border-red-500/30";
}

function verdictAccentClass(verdict: string): string {
  if (verdict === "CONFIRMED") return "border border-l-4 border-l-green-500";
  if (verdict === "UNLIKELY") return "border border-l-4 border-l-amber-500";
  return "border border-l-4 border-l-red-400";
}

function verdictBarColor(verdict: string): string {
  if (verdict === "CONFIRMED") return "bg-green-500";
  if (verdict === "UNLIKELY") return "bg-amber-500";
  return "bg-red-400";
}

function reasoningPreview(reasoning: string, maxLen = 60): string {
  if (reasoning.length <= maxLen) return reasoning;
  return `${reasoning.slice(0, maxLen)}...`;
}

function TribunalSection({ commits, repoUrl }: { readonly commits: readonly BugCommit[]; readonly repoUrl?: string }) {
  const withTribunal = commits.filter((c) => c.tribunal_verdict?.agent_verdicts?.length);
  if (withTribunal.length === 0) return null;

  return (
    <div className="mt-4 space-y-3">
      <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">
        Tribunal Verdict
      </h3>
      {withTribunal.map((commit) => {
        const tv = commit.tribunal_verdict!;
        return (
          <div key={commit.sha} className="space-y-2">
            {/* Overall verdict */}
            <div className={`flex items-center gap-3 rounded-lg px-4 py-2.5 ${verdictAccentClass(tv.verdict)}`}>
              <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-bold ${verdictBadgeClass(tv.verdict)}`}>
                {tv.verdict}
              </span>
              <span className="text-sm font-medium">Confidence: {tv.confidence}</span>
              {repoUrl ? (
                <a
                  href={buildCommitUrl(repoUrl, commit.sha)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-xs text-primary underline-offset-4 hover:underline"
                >
                  {commit.sha.slice(0, 7)}
                </a>
              ) : (
                <span className="text-muted-foreground font-mono text-xs">{commit.sha.slice(0, 7)}</span>
              )}
            </div>
            {/* Agent verdicts — full-width rows */}
            <div className="rounded-lg border overflow-hidden divide-y divide-border">
              {(tv.agent_verdicts ?? []).map((av) => (
                <details key={av.model} className="group">
                  <summary className="flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-muted/50 transition-colors">
                    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold shrink-0 ${verdictBadgeClass(av.verdict)}`}>
                      {av.verdict}
                    </span>
                    <span className="text-sm font-medium shrink-0">
                      {getModelDisplayName(av.model)}
                    </span>
                    {/* Reasoning preview — hints the row is expandable */}
                    <span className="text-xs text-muted-foreground truncate min-w-0 hidden sm:inline group-open:hidden">
                      {reasoningPreview(av.reasoning)}
                    </span>
                    {/* Inline confidence bar */}
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
                    {av.tool_calls_made > 0 && (
                      <p className="text-xs text-muted-foreground/60">
                        {av.tool_calls_made} tool call{av.tool_calls_made !== 1 ? "s" : ""}
                      </p>
                    )}
                  </div>
                </details>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function HowIntroducedSection({ cve, repoUrl }: { readonly cve: CveEntry; readonly repoUrl?: string }) {
  const hasExplicitExplanation = cve.how_introduced.length > 0;
  const signalTypes = collectUniqueSignalTypes(cve.bug_commits);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-xl">How AI Introduced This</CardTitle>
      </CardHeader>
      <CardContent>
        {hasExplicitExplanation ? (
          <p className="leading-relaxed text-muted-foreground">
            {cve.how_introduced}
          </p>
        ) : (
          <div className="space-y-2">
            <p className="leading-relaxed text-muted-foreground">
              Detected AI tool involvement via{" "}
              {signalTypes.length > 0
                ? signalTypes.join(", ")
                : "analysis pipeline"}
              .
            </p>
            {cve.ai_tools.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {cve.ai_tools.map((tool) => (
                  <Badge
                    key={tool}
                    variant="secondary"
                    className="inline-flex items-center gap-1.5"
                  >
                    <ToolIcon tool={tool} size={14} />
                    {getToolDisplayName(tool)}
                  </Badge>
                ))}
              </div>
            )}
          </div>
        )}
        <LlmCausalitySection commits={cve.bug_commits} repoUrl={repoUrl} />
        <TribunalSection commits={cve.bug_commits} repoUrl={repoUrl} />
      </CardContent>
    </Card>
  );
}

function AiSignalsSection({
  commits,
  repoUrl,
}: {
  readonly commits: readonly BugCommit[];
  readonly repoUrl?: string;
}) {
  const aiCommits = commitsWithAiSignals(commits);

  if (aiCommits.length === 0) {
    return null;
  }

  return (
    <section className="space-y-4">
      <h2 className="text-xl font-semibold tracking-tight">
        AI Signal Details
      </h2>
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
    </section>
  );
}

function BugCommitsSection({
  commits,
  repoUrl,
}: {
  readonly commits: readonly BugCommit[];
  readonly repoUrl?: string;
}) {
  return (
    <section className="space-y-4">
      <h2 className="text-xl font-semibold tracking-tight">
        Bug-Introducing Commits
        <span className="ml-2 text-sm font-normal text-muted-foreground">
          ({commits.length})
        </span>
      </h2>
      <BugCommitTimeline commits={commits} repoUrl={repoUrl} />
    </section>
  );
}

function FixCommitsSection({
  commits,
}: {
  readonly commits: readonly FixCommit[];
}) {
  return (
    <section className="space-y-4">
      <h2 className="text-xl font-semibold tracking-tight">
        Fix Commits
        <span className="ml-2 text-sm font-normal text-muted-foreground">
          ({commits.length})
        </span>
      </h2>
      <FixCommitTimeline commits={commits} />
    </section>
  );
}

function ReferencesSection({
  references,
}: {
  readonly references: readonly string[];
}) {
  if (references.length === 0) {
    return null;
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-xl">References</CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="space-y-2">
          {references.map((ref) => (
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
      </CardContent>
    </Card>
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

  return (
    <main className="mx-auto max-w-4xl space-y-8 px-4 py-10 sm:px-6">
      <PageHeader cve={cve} />
      <DescriptionSection description={cve.description} />
      <HowIntroducedSection cve={cve} repoUrl={cve.fix_commits[0]?.repo_url} />
      <AiSignalsSection commits={cve.bug_commits} repoUrl={cve.fix_commits[0]?.repo_url} />
      <BugCommitsSection
        commits={cve.bug_commits}
        repoUrl={cve.fix_commits[0]?.repo_url}
      />
      <FixCommitsSection commits={cve.fix_commits} />
      <ReferencesSection references={cve.references} />
    </main>
  );
}
