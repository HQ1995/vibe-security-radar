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
  if (verdict === "UNLIKELY") return <span className="text-yellow-600">?</span>;
  return <span className="text-muted-foreground">&#10007;</span>;
}

function verdictBorderClass(verdict: string): string {
  if (verdict === "CONFIRMED") return "border-green-500/40 bg-green-500/5";
  if (verdict === "UNLIKELY") return "border-yellow-500/40 bg-yellow-500/5";
  return "border-muted bg-muted/30";
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
          return (
            <div
              key={commit.sha}
              className={`rounded-md border p-3 text-sm ${verdictBorderClass(v.verdict)}`}
            >
              <div className="flex items-start gap-2">
                <VerdictIcon verdict={v.verdict} />
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
                  {" "}
                  <span className="text-muted-foreground">{v.reasoning}</span>
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
                href={ref}
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
