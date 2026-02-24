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
import {
  severityBadgeClass,
  getToolDisplayName,
  getSignalTypeLabel,
  formatConfidence,
} from "@/lib/constants";
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
    return { title: "CVE Not Found - Vibe Security Radar" };
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
        &larr; Back to CVE Database
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
        {cve.published && <span>Published: {cve.published}</span>}
        {cve.ecosystem && <span>Ecosystem: {cve.ecosystem}</span>}
        <span>AI Confidence: {formatConfidence(cve.confidence)}</span>
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

function HowIntroducedSection({ cve }: { readonly cve: CveEntry }) {
  const hasExplicitExplanation = cve.how_introduced.length > 0;
  const signalTypes = collectUniqueSignalTypes(cve.bug_commits);
  const toolNames = cve.ai_tools.map(getToolDisplayName);

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
            {toolNames.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {toolNames.map((name) => (
                  <Badge key={name} variant="secondary">
                    {name}
                  </Badge>
                ))}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function AiSignalsSection({
  commits,
}: {
  readonly commits: readonly BugCommit[];
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
      <HowIntroducedSection cve={cve} />
      <AiSignalsSection commits={cve.bug_commits} />
      <BugCommitsSection
        commits={cve.bug_commits}
        repoUrl={cve.fix_commits[0]?.repo_url}
      />
      <FixCommitsSection commits={cve.fix_commits} />
      <ReferencesSection references={cve.references} />
    </main>
  );
}
