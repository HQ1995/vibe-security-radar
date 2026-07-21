import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getCves, getCveById } from "@/lib/data";
import { Badge } from "@/components/ui/badge";
import { Section } from "@/components/ui/section";
import { AiSignalsDisplay } from "@/components/ai-signals-display";
import {
  BugCommitTimeline,
  FixCommitTimeline,
  bugCommitSubjectKey,
} from "@/components/commit-timeline";
import { AttributionChain } from "@/components/attribution-chain";
import { SectionNav, type SectionNavItem } from "@/components/section-nav";
import { ToolIcon } from "@/components/tool-icon";
import {
  severityBadgeClass,
  getToolDisplayName,
  formatVerifiedBy,
  formatConfidence,
  getModelDetailName,
  getModelRank,
} from "@/lib/constants";
import { LanguageBadge } from "@/components/language-badge";
import { formatPublished, buildCommitUrl, extractRepoName } from "@/lib/commit-utils";
import type { AiSignalEntry, CveEntry, BugCommit } from "@/lib/types";
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  GitCommit,
  Wrench,
  ExternalLink,
  Fingerprint,
  Scale,
  Code2,
  MessageSquareWarning,
  ArrowLeft,
  SearchCheck,
} from "lucide-react";

// --- Static generation ---

export const dynamicParams = false;

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

interface CommitSignalAccumulator {
  readonly commit: BugCommit;
  readonly signals: AiSignalEntry[];
  readonly signalKeys: Set<string>;
}

function commitSignalKey(signal: AiSignalEntry): string {
  return JSON.stringify([
    signal.tool,
    signal.signal_type,
    signal.matched_text,
    signal.confidence,
  ]);
}

/**
 * Preserve verification subjects while projecting commit-level signals by SHA.
 * A BIC can be independently assessed for multiple fix/file subjects, but its
 * commit metadata and signal count should appear only once.
 */
function analyzeBugCommits(commits: readonly BugCommit[]) {
  const signalCommitsBySha = new Map<string, CommitSignalAccumulator>();
  const deepVerifiedCommits: BugCommit[] = [];
  const causalityCommits: BugCommit[] = [];

  for (const c of commits) {
    if (c.ai_signals.length > 0) {
      let accumulator = signalCommitsBySha.get(c.sha);
      if (!accumulator) {
        accumulator = {
          commit: c,
          signals: [],
          signalKeys: new Set<string>(),
        };
        signalCommitsBySha.set(c.sha, accumulator);
      }
      for (const s of c.ai_signals) {
        const key = commitSignalKey(s);
        if (!accumulator.signalKeys.has(key)) {
          accumulator.signalKeys.add(key);
          accumulator.signals.push(s);
        }
      }
    }
    if (c.verification?.agent_verdicts?.length) {
      deepVerifiedCommits.push(c);
    }
    if (c.screening_verification != null) {
      causalityCommits.push(c);
    }
  }

  const aiCommits = Array.from(signalCommitsBySha.values(), (entry) => ({
    ...entry.commit,
    ai_signals: entry.signals,
  }));
  const totalSignals = aiCommits.reduce(
    (total, commit) => total + commit.ai_signals.length,
    0,
  );

  return {
    aiCommits,
    deepVerifiedCommits,
    causalityCommits,
    totalSignals,
  };
}

/**
 * Best deep-verified commit: strongest model (lowest rank) wins, confidence
 * breaks ties — the same model-rank logic used for causality commits.
 */
function pickBestDeepVerified(
  commits: readonly BugCommit[],
): BugCommit | null {
  let best: BugCommit | null = null;
  let bestRank = Infinity;
  let bestConfidence = -1;
  for (const commit of commits) {
    const agent = commit.verification?.agent_verdicts?.[0];
    if (!agent) continue;
    const rank = getModelRank(agent.model);
    if (
      rank < bestRank ||
      (rank === bestRank && agent.confidence > bestConfidence)
    ) {
      best = commit;
      bestRank = rank;
      bestConfidence = agent.confidence;
    }
  }
  return best;
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

// --- Section components ---

function PageHeader({ cve }: { readonly cve: CveEntry }) {
  const repoUrl = cve.fix_commits[0]?.repo_url;
  const repoName = repoUrl ? extractRepoName(repoUrl) : "";

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

      {repoName && (
        <a
          href={repoUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 text-sm font-medium text-foreground hover:text-primary transition-colors"
        >
          <Code2 className="h-3.5 w-3.5" />
          {repoName}
          <ExternalLink className="h-3 w-3 text-muted-foreground" />
        </a>
      )}

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

function MetaSeparator() {
  return (
    <span aria-hidden="true" className="select-none text-muted-foreground/40">
      &middot;
    </span>
  );
}

/** Borderless at-a-glance strip replacing the old tinted summary cards. */
function MetaStrip({
  cve,
  primaryVerdict,
  primaryConfidence,
}: {
  readonly cve: CveEntry;
  readonly primaryVerdict?: string;
  readonly primaryConfidence?: number | null;
}) {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-sm">
      {/* Severity + CVSS */}
      <span className="flex items-center gap-2">
        <Badge className={severityBadgeClass(cve.severity)}>
          {cve.severity}
        </Badge>
        {cve.cvss !== null && cve.cvss > 0 && (
          <span className="font-mono font-semibold tabular-nums">{cve.cvss.toFixed(1)}</span>
        )}
      </span>

      <MetaSeparator />

      {/* Verdict */}
      {primaryVerdict ? (
        <span className="flex items-center gap-1.5">
          <VerdictIcon verdict={primaryVerdict} className="h-4 w-4" />
          <span className="font-medium">{primaryVerdict}</span>
          {primaryConfidence != null && (
            <span className="text-xs text-muted-foreground">
              {formatConfidence(primaryConfidence)} confidence
            </span>
          )}
        </span>
      ) : (
        <span className="text-muted-foreground">Pending</span>
      )}

      {/* AI tools */}
      {cve.ai_tools.length > 0 && (
        <>
          <MetaSeparator />
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            {cve.ai_tools.map((tool) => (
              <span key={tool} className="flex items-center gap-1.5">
                <ToolIcon tool={tool} size={14} />
                <span>{getToolDisplayName(tool)}</span>
              </span>
            ))}
            {cve.signal_source === "pr_body" && (
              <span className="text-xs text-muted-foreground">
                Signal from PR description only — not from commit metadata
              </span>
            )}
          </span>
        </>
      )}

      {/* Languages */}
      {cve.languages.length > 0 && (
        <>
          <MetaSeparator />
          <span className="flex items-center gap-1">
            {cve.languages.map((lang) => (
              <LanguageBadge key={lang} language={lang} />
            ))}
          </span>
        </>
      )}
    </div>
  );
}

function HowIntroducedCallout({ cve }: { readonly cve: CveEntry }) {
  const hasSummary = cve.how_introduced.length > 0;
  const hasRootCause = (cve.root_cause ?? "").length > 0;
  const hasPattern = (cve.vulnerable_pattern ?? "").length > 0;
  if (!hasSummary && !hasRootCause && !hasPattern) return null;

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
      {hasPattern && (
        <code className="block rounded-md bg-muted/60 px-3 py-2 font-mono text-xs leading-relaxed mb-3">
          {cve.vulnerable_pattern}
        </code>
      )}
      {hasSummary && (
        <p className="text-sm leading-relaxed">{cve.how_introduced}</p>
      )}
      {hasRootCause && (
        <div className={hasSummary || hasPattern ? "mt-3 pt-3 border-t border-primary/10" : ""}>
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">Root Cause</p>
          <p className="text-sm leading-relaxed text-muted-foreground">{cve.root_cause}</p>
        </div>
      )}
    </div>
  );
}

function SubjectLabel({
  commit,
  repoUrl,
}: {
  readonly commit: BugCommit;
  readonly repoUrl?: string;
}) {
  return (
    <>
      {commit.fix_commit_sha && <>Fix {commit.fix_commit_sha.slice(0, 7)} &rarr; </>}
      {repoUrl ? (
        <a
          href={buildCommitUrl(repoUrl, commit.sha)}
          target="_blank"
          rel="noopener noreferrer"
          className="text-primary underline-offset-4 hover:underline"
        >
          BIC {commit.sha.slice(0, 7)}
        </a>
      ) : (
        <>BIC {commit.sha.slice(0, 7)}</>
      )}
      <> &middot; {commit.blamed_file}</>
    </>
  );
}

function CausalityDetails({
  commit,
  repoUrl,
}: {
  readonly commit: BugCommit;
  readonly repoUrl?: string;
}) {
  const v = commit.screening_verification!;
  return (
    <div>
      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
        Causality Analysis
        <span className="normal-case tracking-normal">
          {" "}&middot; by {getModelDetailName(v.model)}
        </span>
      </p>
      <div className="mt-2 divide-y divide-border border-y border-border">
        <div className="grid grid-cols-[120px_1fr] gap-x-4 py-2">
          <span className="text-xs font-medium text-muted-foreground">
            Subject
          </span>
          <span className="font-mono text-xs text-muted-foreground">
            <SubjectLabel commit={commit} repoUrl={repoUrl} />
          </span>
        </div>
        {v.vuln_type && (
          <div className="grid grid-cols-[120px_1fr] gap-x-4 py-2">
            <span className="text-xs font-medium text-muted-foreground">Vulnerability</span>
            <span className="text-sm capitalize">{v.vuln_type}</span>
          </div>
        )}
        {v.vuln_description && (
          <div className="grid grid-cols-[120px_1fr] gap-x-4 py-2">
            <span className="text-xs font-medium text-muted-foreground">Root Cause</span>
            <span className="text-sm text-muted-foreground">{v.vuln_description}</span>
          </div>
        )}
        {v.vulnerable_pattern && (
          <div className="grid grid-cols-[120px_1fr] gap-x-4 py-2">
            <span className="text-xs font-medium text-muted-foreground">Pattern</span>
            <div>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{v.vulnerable_pattern}</code>
            </div>
          </div>
        )}
        {v.causal_chain && (
          <div className="grid grid-cols-[120px_1fr] gap-x-4 py-2">
            <span className="text-xs font-medium text-muted-foreground">Causal Chain</span>
            <span className="text-sm text-muted-foreground">{v.causal_chain}</span>
          </div>
        )}
        {v.reasoning && !v.vuln_description && (
          <div className="grid grid-cols-[120px_1fr] gap-x-4 py-2">
            <span className="text-xs font-medium text-muted-foreground">Reasoning</span>
            <span className="text-sm text-muted-foreground">{v.reasoning}</span>
          </div>
        )}
      </div>
    </div>
  );
}

function DeepVerificationEntry({
  commit,
  repoUrl,
  defaultOpen,
}: {
  readonly commit: BugCommit;
  readonly repoUrl?: string;
  readonly defaultOpen: boolean;
}) {
  const verification = commit.verification!;
  const agent = verification.agent_verdicts?.[0];
  if (!agent) return null;

  return (
    <Section
      size="sm"
      title={`${commit.sha.slice(0, 7)} · ${verification.verdict} · ${getModelDetailName(agent.model)}`}
      defaultOpen={defaultOpen}
    >
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <SmallVerdictBadge verdict={verification.verdict} />
          {verification.confidence !== null && (
            <span className="text-xs text-muted-foreground tabular-nums">
              {formatConfidence(verification.confidence)}
            </span>
          )}
          <span className="font-mono text-xs text-muted-foreground">
            <SubjectLabel commit={commit} repoUrl={repoUrl} />
          </span>
        </div>
        {/* Investigation stats */}
        <div className="flex items-center gap-4 text-xs text-muted-foreground">
          <span className="inline-flex items-center gap-1.5">
            <span className="font-medium tabular-nums">{agent.tool_calls_made}</span> tool calls
          </span>
          <div className="flex items-center gap-2">
            <div className="h-1.5 w-20 rounded-full bg-muted">
              <div
                className={`h-1.5 rounded-full ${verdictBarColor(agent.verdict)}`}
                style={{ width: `${Math.round(agent.confidence * 100)}%` }}
              />
            </div>
            <span className="tabular-nums">{formatConfidence(agent.confidence)}</span>
          </div>
        </div>
        {/* Reasoning */}
        <p className="text-sm leading-relaxed text-muted-foreground">{agent.reasoning}</p>
        {/* Evidence */}
        {agent.evidence.length > 0 && (
          <div className="rounded-lg bg-muted/30 px-4 py-3">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">Evidence</p>
            <ul className="space-y-1.5">
              {agent.evidence.map((e, i) => (
                <li key={`${i}-${e.slice(0, 32)}`} className="flex gap-2 text-sm text-muted-foreground">
                  <span className="text-primary/60 shrink-0 mt-1">&#x2022;</span>
                  <span className="leading-relaxed">{e}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {commit.screening_verification && (
          <CausalityDetails commit={commit} repoUrl={repoUrl} />
        )}
      </div>
    </Section>
  );
}

function DeepVerificationSection({
  deepVerifiedCommits,
  causalityCommits,
  repoUrl,
}: {
  readonly deepVerifiedCommits: readonly BugCommit[];
  readonly causalityCommits: readonly BugCommit[];
  readonly repoUrl?: string;
}) {
  if (deepVerifiedCommits.length === 0 && causalityCommits.length === 0) {
    return null;
  }

  const bestDeepVerified = pickBestDeepVerified(deepVerifiedCommits);
  // Commits covered by a deep-verification entry render their causality
  // analysis inside it; the rest get their own nested section.
  const deepKeys = new Set(deepVerifiedCommits.map(bugCommitSubjectKey));
  const causalityOnlyCommits = causalityCommits.filter(
    (commit) => !deepKeys.has(bugCommitSubjectKey(commit)),
  );
  // With no deep-verified commits, the best causality analysis (already sorted
  // first by model rank) is the expanded entry instead.
  const openCausalityKey =
    deepVerifiedCommits.length === 0 && causalityOnlyCommits.length > 0
      ? bugCommitSubjectKey(causalityOnlyCommits[0])
      : null;

  return (
    <Section
      id="verification"
      title="Deep Verification"
      icon={<SearchCheck />}
      aside={`(${deepVerifiedCommits.length + causalityOnlyCommits.length})`}
      defaultOpen
    >
      <div className="space-y-2">
        {deepVerifiedCommits.map((commit) => (
          <DeepVerificationEntry
            key={bugCommitSubjectKey(commit)}
            commit={commit}
            repoUrl={repoUrl}
            defaultOpen={commit === bestDeepVerified}
          />
        ))}
        {causalityOnlyCommits.map((commit) => {
          const v = commit.screening_verification!;
          const key = bugCommitSubjectKey(commit);
          return (
            <Section
              key={key}
              size="sm"
              title={`${commit.sha.slice(0, 7)} · ${v.verdict} · ${getModelDetailName(v.model)}`}
              defaultOpen={key === openCausalityKey}
            >
              <CausalityDetails commit={commit} repoUrl={repoUrl} />
            </Section>
          );
        })}
      </div>
    </Section>
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
  const { aiCommits, deepVerifiedCommits, causalityCommits, totalSignals } =
    analyzeBugCommits(cve.bug_commits);

  // Sort causality commits by model strength (strongest first) so the best analysis is expanded
  const sortedCausalityCommits = [...causalityCommits].sort(
    (a, b) => getModelRank(a.screening_verification!.model) - getModelRank(b.screening_verification!.model),
  );

  const bestVerification = deepVerifiedCommits.length > 0 ? deepVerifiedCommits[0].verification! : null;
  const bestCausalityCommit = sortedCausalityCommits.length > 0 ? sortedCausalityCommits[0] : null;
  const primaryVerdict =
    cve.verdict ||
    bestVerification?.verdict ||
    bestCausalityCommit?.screening_verification?.verdict;
  const primaryConfidence =
    deepVerifiedCommits.length === 1 ? (bestVerification?.confidence ?? null) : null;

  const hasVerification =
    deepVerifiedCommits.length > 0 || sortedCausalityCommits.length > 0;

  const navItems: SectionNavItem[] = [
    { id: "attribution", label: "Attribution" },
    { id: "commits", label: "Commits" },
    ...(hasVerification
      ? [{ id: "verification", label: "Verification" }]
      : []),
    ...(aiCommits.length > 0 ? [{ id: "signals", label: "Signals" }] : []),
    { id: "fixes", label: "Fixes" },
    ...(cve.references.length > 0
      ? [{ id: "references", label: "References" }]
      : []),
  ];

  return (
    <main className="mx-auto max-w-4xl space-y-6 px-4 py-10 sm:px-6">
      {/* Header */}
      <PageHeader cve={cve} />

      {/* At-a-glance meta strip */}
      <MetaStrip
        cve={cve}
        primaryVerdict={primaryVerdict}
        primaryConfidence={primaryConfidence}
      />

      {/* In-page navigation */}
      <SectionNav items={navItems} />

      {/* Description */}
      <p className="text-sm leading-relaxed text-muted-foreground">{cve.description}</p>

      {/* How AI Introduced This — the star of the page */}
      <HowIntroducedCallout cve={cve} />

      {/* Attribution Chain — how we traced the vulnerability */}
      <Section
        id="attribution"
        title="Attribution Chain"
        icon={<Scale />}
      >
        <AttributionChain
          bugCommits={cve.bug_commits}
          fixCommits={cve.fix_commits}
          repoUrl={repoUrl}
        />
      </Section>

      {/* Bug-Introducing Commits */}
      <Section
        id="commits"
        title="Bug-Introducing Commits"
        icon={<GitCommit />}
        aside={`(${cve.bug_commits.length})`}
        defaultOpen
      >
        <BugCommitTimeline commits={cve.bug_commits} repoUrl={repoUrl} />
      </Section>

      {/* Deep Verification + Causality Analysis */}
      {hasVerification && (
        <DeepVerificationSection
          deepVerifiedCommits={deepVerifiedCommits}
          causalityCommits={sortedCausalityCommits}
          repoUrl={repoUrl}
        />
      )}

      {/* AI Signals */}
      {aiCommits.length > 0 && (
        <Section
          id="signals"
          title="AI Signals"
          icon={<Fingerprint />}
          aside={`(${totalSignals})`}
        >
          <div className="space-y-3">
            {aiCommits.map((commit) => (
              <AiSignalsDisplay
                // analyzeBugCommits coalesces this commit-level view by SHA.
                key={commit.sha}
                signals={commit.ai_signals}
                commitSha={commit.sha}
                repoUrl={repoUrl}
                prUrl={commit.pr_url}
                prTitle={commit.pr_title}
              />
            ))}
          </div>
        </Section>
      )}

      <Section
        id="fixes"
        title="Fix Commits"
        icon={<Wrench />}
        aside={`(${cve.fix_commits.length})`}
      >
        <FixCommitTimeline commits={cve.fix_commits} />
      </Section>

      {cve.references.length > 0 && (
        <Section
          id="references"
          title="References"
          icon={<ExternalLink />}
          aside={`(${cve.references.length})`}
        >
          <ul className="space-y-1.5">
            {cve.references.map((ref) => (
              <li key={ref}>
                {/^https?:\/\//i.test(ref) ? (
                  <a
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-primary underline-offset-4 hover:underline break-all"
                  >
                    {ref}
                  </a>
                ) : (
                  <span className="text-sm text-muted-foreground break-all">
                    {ref}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </Section>
      )}
    </main>
  );
}
