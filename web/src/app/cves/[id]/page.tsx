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
  getModelDetailName,
  getModelRank,
} from "@/lib/constants";
import { LanguageBadge } from "@/components/language-badge";
import { formatPublished, buildCommitUrl } from "@/lib/commit-utils";
import type { CveEntry, BugCommit, TribunalVerdict } from "@/lib/types";
import {
  ShieldAlert,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Bot,
  GitCommit,
  Wrench,
  ExternalLink,
  Fingerprint,
  Scale,
  Code2,
  MessageSquareWarning,
  ArrowLeft,
} from "lucide-react";

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

/** Single pass over bug_commits to extract all needed subsets, counts, and signal types. */
function analyzeBugCommits(commits: readonly BugCommit[]) {
  const aiCommits: BugCommit[] = [];
  const tribunalCommits: BugCommit[] = [];
  const causalityCommits: BugCommit[] = [];
  const signalTypeSet = new Set<string>();
  let totalSignals = 0;

  for (const c of commits) {
    if (c.ai_signals.length > 0) {
      aiCommits.push(c);
      totalSignals += c.ai_signals.length;
      for (const s of c.ai_signals) {
        signalTypeSet.add(getSignalTypeLabel(s.signal_type));
      }
    }
    if (c.tribunal_verdict?.agent_verdicts?.length) {
      tribunalCommits.push(c);
    }
    if (c.llm_verdict !== null) {
      causalityCommits.push(c);
    }
  }

  return { aiCommits, tribunalCommits, causalityCommits, totalSignals, signalTypes: Array.from(signalTypeSet) };
}

// --- Verdict visual helpers ---

function verdictBadgeClass(verdict: string): string {
  if (verdict === "CONFIRMED") return "bg-green-600/20 text-green-700 dark:text-green-300 border-green-600/30";
  if (verdict === "UNLIKELY") return "bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/30";
  return "bg-red-500/20 text-red-700 dark:text-red-300 border-red-500/30";
}

function verdictBarColor(verdict: string): string {
  if (verdict === "CONFIRMED") return "bg-green-500";
  if (verdict === "UNLIKELY") return "bg-amber-500";
  return "bg-red-400";
}

function VerdictIcon({ verdict, className }: { readonly verdict: string; readonly className?: string }) {
  const cls = className ?? "h-5 w-5";
  if (verdict === "CONFIRMED") return <CheckCircle2 className={`${cls} text-green-500`} />;
  if (verdict === "UNLIKELY") return <AlertTriangle className={`${cls} text-amber-500`} />;
  return <XCircle className={`${cls} text-red-400`} />;
}

function SmallVerdictBadge({ verdict }: { readonly verdict: string }) {
  return (
    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold shrink-0 ${verdictBadgeClass(verdict)}`}>
      {verdict}
    </span>
  );
}

function severityCardBg(severity: string): string {
  if (severity === "CRITICAL") return "bg-red-500/10 border-red-500/30";
  if (severity === "HIGH") return "bg-orange-500/10 border-orange-500/30";
  if (severity === "MEDIUM") return "bg-yellow-500/10 border-yellow-500/30";
  return "bg-green-500/10 border-green-500/30";
}

function verdictCardBg(verdict: string): string {
  if (verdict === "CONFIRMED") return "bg-green-500/10 border-green-500/30";
  if (verdict === "UNLIKELY") return "bg-amber-500/10 border-amber-500/30";
  return "bg-red-500/10 border-red-500/30";
}

// --- Section components ---

function PageHeader({ cve }: { readonly cve: CveEntry }) {
  return (
    <div className="space-y-3">
      <Link
        href="/cves"
        className="inline-flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        Back to Vulnerabilities
      </Link>

      <h1 className="text-2xl font-bold tracking-tight sm:text-3xl font-mono">
        {cve.id}
      </h1>

      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-sm text-muted-foreground">
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
        {cve.languages.length > 0 && (
          <div className="flex items-center gap-1">
            {cve.languages.map((lang) => (
              <LanguageBadge key={lang} language={lang} />
            ))}
          </div>
        )}
        <span className="text-xs">Verified by {formatVerifiedBy(cve.verified_by)}</span>
      </div>
    </div>
  );
}

function SummaryCards({
  cve,
  primaryVerdict,
  primaryConfidence,
}: {
  readonly cve: CveEntry;
  readonly primaryVerdict?: string;
  readonly primaryConfidence?: string | null;
}) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      {/* Severity + CVSS */}
      <div className={`rounded-xl border p-4 ${severityCardBg(cve.severity)}`}>
        <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground mb-2">
          <ShieldAlert className="h-3.5 w-3.5" />
          Severity
        </div>
        <div className="flex items-baseline gap-2">
          <Badge className={severityBadgeClass(cve.severity)}>
            {cve.severity}
          </Badge>
          {cve.cvss !== null && cve.cvss > 0 && (
            <span className="font-mono text-xl font-bold tabular-nums">{cve.cvss.toFixed(1)}</span>
          )}
        </div>
      </div>

      {/* Verdict */}
      <div className={`rounded-xl border p-4 ${primaryVerdict ? verdictCardBg(primaryVerdict) : "bg-card"}`}>
        <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground mb-2">
          <Scale className="h-3.5 w-3.5" />
          Verdict
        </div>
        {primaryVerdict ? (
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <VerdictIcon verdict={primaryVerdict} className="h-4.5 w-4.5" />
              <span className="font-semibold text-sm">{primaryVerdict}</span>
            </div>
            {primaryConfidence && (
              <span className="text-xs text-muted-foreground">{primaryConfidence} confidence</span>
            )}
          </div>
        ) : (
          <span className="text-sm text-muted-foreground">Pending</span>
        )}
      </div>

      {/* AI Tool */}
      <div className="rounded-xl border bg-card p-4">
        <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground mb-2">
          <Bot className="h-3.5 w-3.5" />
          AI Tool
        </div>
        <div className="space-y-1.5">
          {cve.ai_tools.map((tool) => (
            <div key={tool} className="flex items-center gap-1.5">
              <ToolIcon tool={tool} size={16} />
              <span className="font-semibold text-sm">{getToolDisplayName(tool)}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Confidence */}
      <div className="rounded-xl border bg-card p-4">
        <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground mb-2">
          <Fingerprint className="h-3.5 w-3.5" />
          Confidence
        </div>
        <div className="space-y-1.5">
          <span className="font-mono text-xl font-bold tabular-nums">
            {formatConfidence(cve.confidence)}
          </span>
          <div className="h-1.5 w-full rounded-full bg-muted">
            <div
              className="h-1.5 rounded-full bg-primary transition-all"
              style={{ width: `${Math.round(cve.confidence * 100)}%` }}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

function HowIntroducedCallout({
  cve,
  signalTypes,
}: {
  readonly cve: CveEntry;
  readonly signalTypes: readonly string[];
}) {
  const hasSummary = cve.how_introduced.length > 0;
  const hasRootCause = (cve.root_cause ?? "").length > 0;
  if (!hasSummary && !hasRootCause && signalTypes.length === 0) return null;

  return (
    <div className="rounded-xl border border-l-4 border-l-primary bg-primary/5 p-5">
      <div className="flex items-center gap-2 mb-3">
        <MessageSquareWarning className="h-4.5 w-4.5 text-primary shrink-0" />
        <h2 className="text-sm font-semibold uppercase tracking-wide text-primary">
          How AI Introduced This
        </h2>
        {cve.vuln_type && (
          <Badge variant="outline" className="ml-auto text-xs font-normal">
            {cve.vuln_type}
          </Badge>
        )}
      </div>
      {hasSummary ? (
        <p className="text-sm leading-relaxed">{cve.how_introduced}</p>
      ) : (
        <p className="text-sm leading-relaxed text-muted-foreground">
          Detected AI tool involvement via {signalTypes.join(", ")}.
        </p>
      )}
      {hasRootCause && hasSummary && (
        <div className="mt-3 pt-3 border-t border-primary/10">
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">Root Cause</p>
          <p className="text-sm leading-relaxed text-muted-foreground">{cve.root_cause}</p>
        </div>
      )}
    </div>
  );
}

function CausalityDetails({
  commit,
  repoUrl,
}: {
  readonly commit: BugCommit;
  readonly repoUrl?: string;
}) {
  const v = commit.llm_verdict!;
  return (
    <div className="rounded-lg border overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2.5 bg-muted/50 border-b">
        <Code2 className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
          Causality Analysis
        </span>
        <span className="text-xs text-muted-foreground ml-auto">
          by {getModelDetailName(v.model)}
        </span>
      </div>
      <div className="grid gap-px bg-border">
        {v.vuln_type && (
          <div className="grid grid-cols-[120px_1fr] bg-card">
            <span className="px-4 py-2.5 text-xs font-medium text-muted-foreground bg-muted/30">Vulnerability</span>
            <span className="px-4 py-2.5 text-sm capitalize">{v.vuln_type}</span>
          </div>
        )}
        {v.vuln_description && (
          <div className="grid grid-cols-[120px_1fr] bg-card">
            <span className="px-4 py-2.5 text-xs font-medium text-muted-foreground bg-muted/30">Root Cause</span>
            <span className="px-4 py-2.5 text-sm text-muted-foreground">{v.vuln_description}</span>
          </div>
        )}
        {v.vulnerable_pattern && (
          <div className="grid grid-cols-[120px_1fr] bg-card">
            <span className="px-4 py-2.5 text-xs font-medium text-muted-foreground bg-muted/30">Pattern</span>
            <div className="px-4 py-2.5">
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{v.vulnerable_pattern}</code>
            </div>
          </div>
        )}
        {v.causal_chain && (
          <div className="grid grid-cols-[120px_1fr] bg-card">
            <span className="px-4 py-2.5 text-xs font-medium text-muted-foreground bg-muted/30">Causal Chain</span>
            <span className="px-4 py-2.5 text-sm text-muted-foreground">{v.causal_chain}</span>
          </div>
        )}
        {v.reasoning && !v.vuln_description && (
          <div className="grid grid-cols-[120px_1fr] bg-card">
            <span className="px-4 py-2.5 text-xs font-medium text-muted-foreground bg-muted/30">Reasoning</span>
            <span className="px-4 py-2.5 text-sm text-muted-foreground">{v.reasoning}</span>
          </div>
        )}
      </div>
    </div>
  );
}

function TribunalSection({
  bestTribunal,
  bestCausality,
  causalityCommits,
  repoUrl,
}: {
  readonly bestTribunal: TribunalVerdict | null;
  readonly bestCausality: BugCommit | null;
  readonly causalityCommits: readonly BugCommit[];
  readonly repoUrl?: string;
}) {
  if (!bestTribunal && !bestCausality) return null;

  return (
    <div className="space-y-4">
      {/* Tribunal Agents */}
      {bestTribunal && (
        <div className="rounded-xl border overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 bg-muted/50 border-b">
            <Scale className="h-4 w-4 text-muted-foreground" />
            <h2 className="text-sm font-semibold">Tribunal Analysis</h2>
            <span className="text-xs text-muted-foreground ml-1">
              {bestTribunal.agent_verdicts!.length} agents
            </span>
            <div className="ml-auto flex items-center gap-2">
              <SmallVerdictBadge verdict={bestTribunal.verdict} />
              <span className="text-xs text-muted-foreground">{bestTribunal.confidence}</span>
            </div>
          </div>
          <div className="divide-y divide-border">
            {[...bestTribunal.agent_verdicts!].sort((a, b) => getModelRank(a.model) - getModelRank(b.model)).map((av) => (
              <details key={av.model} className="group/agent">
                <summary className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-muted/30 transition-colors">
                  <span className="text-muted-foreground group-open/agent:rotate-90 transition-transform text-xs">&#9654;</span>
                  <SmallVerdictBadge verdict={av.verdict} />
                  <span className="text-sm font-medium">
                    {getModelDetailName(av.model)}
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
                <div className="px-4 py-3 bg-muted/20 border-t border-border/50">
                  <p className="text-sm text-muted-foreground leading-relaxed">{av.reasoning}</p>
                  {av.evidence.length > 0 && (
                    <ul className="mt-2 space-y-1">
                      {av.evidence.map((e, i) => (
                        <li key={`${i}-${e.slice(0, 32)}`} className="flex gap-2 text-xs text-muted-foreground">
                          <span className="text-primary/60 shrink-0">&#x2022;</span>
                          <span>{e}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </details>
            ))}
          </div>
        </div>
      )}

      {/* Causality analysis */}
      {bestCausality && (
        <CausalityDetails commit={bestCausality} repoUrl={repoUrl} />
      )}

      {/* Additional causality commits beyond the first */}
      {causalityCommits.length > 1 && (
        <details className="group">
          <summary className="flex items-center gap-2 text-sm font-medium cursor-pointer hover:text-foreground text-muted-foreground transition-colors">
            <span className="text-muted-foreground group-open:rotate-90 transition-transform text-xs">&#9654;</span>
            {causalityCommits.length - 1} more causality analysis{causalityCommits.length > 2 ? "es" : ""}
          </summary>
          <div className="mt-3 space-y-3">
            {causalityCommits.slice(1).map((commit) => (
              <CausalityDetails key={commit.sha} commit={commit} repoUrl={repoUrl} />
            ))}
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
  icon,
  children,
}: {
  readonly title: string;
  readonly count?: number;
  readonly defaultOpen?: boolean;
  readonly icon?: React.ReactNode;
  readonly children: React.ReactNode;
}) {
  return (
    <details open={defaultOpen} className="group">
      <summary className="flex items-center gap-2 cursor-pointer text-base font-semibold tracking-tight hover:text-foreground transition-colors">
        <span className="text-muted-foreground group-open:rotate-90 transition-transform text-xs">&#9654;</span>
        {icon}
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
  const { aiCommits, tribunalCommits, causalityCommits, totalSignals, signalTypes } =
    analyzeBugCommits(cve.bug_commits);

  // Sort causality commits by model strength (strongest first) so the best analysis is expanded
  const sortedCausalityCommits = [...causalityCommits].sort(
    (a, b) => getModelRank(a.llm_verdict!.model) - getModelRank(b.llm_verdict!.model),
  );

  const bestTribunal = tribunalCommits.length > 0 ? tribunalCommits[0].tribunal_verdict! : null;
  const bestCausalityCommit = sortedCausalityCommits.length > 0 ? sortedCausalityCommits[0] : null;
  const primaryVerdict = bestTribunal?.verdict ?? bestCausalityCommit?.llm_verdict?.verdict;
  const primaryConfidence = bestTribunal?.confidence ?? null;

  return (
    <main className="mx-auto max-w-4xl space-y-8 px-4 py-10 sm:px-6">
      {/* Header */}
      <PageHeader cve={cve} />

      {/* Summary Cards — at-a-glance metrics */}
      <SummaryCards
        cve={cve}
        primaryVerdict={primaryVerdict}
        primaryConfidence={primaryConfidence}
      />

      {/* Description */}
      <p className="text-sm leading-relaxed text-muted-foreground">{cve.description}</p>

      {/* How AI Introduced This — the star of the page */}
      <HowIntroducedCallout cve={cve} signalTypes={signalTypes} />

      {/* Bug-Introducing Commits — between intro and tribunal */}
      <CollapsibleSection
        title="Bug-Introducing Commits"
        count={cve.bug_commits.length}
        icon={<GitCommit className="h-4 w-4 text-muted-foreground" />}
        defaultOpen
      >
        <BugCommitTimeline commits={cve.bug_commits} repoUrl={repoUrl} />
      </CollapsibleSection>

      {/* Tribunal + Causality Analysis */}
      <TribunalSection
        bestTribunal={bestTribunal}
        bestCausality={bestCausalityCommit}
        causalityCommits={sortedCausalityCommits}
        repoUrl={repoUrl}
      />

      {/* AI Signals */}
      {aiCommits.length > 0 && (
        <CollapsibleSection
          title="AI Signals"
          count={totalSignals}
          icon={<Fingerprint className="h-4 w-4 text-muted-foreground" />}
        >
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

      <CollapsibleSection
        title="Fix Commits"
        count={cve.fix_commits.length}
        icon={<Wrench className="h-4 w-4 text-muted-foreground" />}
      >
        <FixCommitTimeline commits={cve.fix_commits} />
      </CollapsibleSection>

      {cve.references.length > 0 && (
        <CollapsibleSection
          title="References"
          count={cve.references.length}
          icon={<ExternalLink className="h-4 w-4 text-muted-foreground" />}
        >
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
