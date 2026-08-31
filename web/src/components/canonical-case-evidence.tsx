import type { ReactNode } from "react";
import { ArrowRight, ChevronDown, ExternalLink } from "lucide-react";

import { isPublicProse, stripMarkdown } from "@/lib/markdown-utils";
import { formatPublished } from "@/lib/commit-utils";
import { severityBadgeClass } from "@/lib/constants";
import { Badge } from "@/components/ui/badge";
import {
  formatCaseLabel,
  formatContributionClass,
  getAiToolLabel,
  getCauseCategoryLabel,
  preferredCaseId,
  type ResearchCase,
  type ResearchCodeHunk,
  type ResearchRelease,
} from "@/lib/research-data";

function shortSha(value: string): string {
  return value.slice(0, 10);
}

function commitUrl(repository: string | null, sha: string): string | null {
  return repository ? `https://github.com/${repository}/commit/${sha}` : null;
}

function commitSource(
  value: string | null | undefined,
  fallbackRepository: string | null,
  fallbackSha: string,
) {
  const match = value?.match(
    /^https?:\/\/github\.com\/([^/]+\/[^/]+)\/commit\/([0-9a-f]{7,40})(?:$|[/?#])/i,
  );
  return {
    repository: match?.[1] ?? fallbackRepository,
    sha: match?.[2] ?? fallbackSha,
  };
}

function releaseLabel(release: ResearchRelease | null): string {
  if (!release) return "Not recorded";
  return (
    release.tag ??
    release.version ??
    release.sha?.slice(0, 10) ??
    release.kind ??
    "Recorded in the evidence bundle"
  );
}

function contributionHeadline(value: string): string {
  return (
    {
      AI_DIRECT_ROOT:
        "AI introduced the vulnerable behavior.",
      AI_CAUSAL_CONTRIBUTOR:
        "AI made the vulnerable path reachable.",
      AI_INCOMPLETE_REMEDIATION:
        "AI tried to fix the flaw, but the patch was incomplete.",
      AI_NEW_SURFACE_CONTRIBUTOR:
        "AI added the surface that made the flaw reachable.",
      AI_CODE_FLAWED:
        "AI-written code contained the vulnerability.",
    }[value] ?? "AI contributed to this vulnerability."
  );
}

type DiffRole = "AI change" | "Fix" | "Comparison";

function compactPublicProse(
  ...values: (string | null | undefined)[]
): string | null {
  for (const value of values) {
    const text = stripMarkdown(value).trim();
    if (text.length <= 360 && isPublicProse(text)) return text;
  }
  return null;
}

function usefulHunkAnnotation(value: string): string | null {
  const text = compactPublicProse(value);
  if (
    !text ||
    /^(?:AI introduced this behavior|AI removed a constraint|The fix adds):/i.test(
      text,
    )
  ) {
    return null;
  }
  return text;
}

function advisoryBlurb(item: ResearchCase): string | null {
  const blurb = advisoryDescription(item);
  if (!blurb) return null;
  return blurb;
}

/** Full advisory text, not the 500-char teaser — rendered with a manual expand. */
function advisoryDescription(item: ResearchCase): string | null {
  const full = stripMarkdown(item.description);
  if (!full || !isPublicProse(full)) return null;
  return full;
}

/** Plain-language explanation of the AI-caused mechanism, when fit for visitors. */
function publicMechanism(item: ResearchCase): string | null {
  const text = (item.mechanism ?? "").trim();
  if (!text || !isPublicProse(text)) return null;
  return text;
}

function findingSummary(item: ResearchCase): string | null {
  const summary = item.code_evidence?.summary;
  if (summary && isPublicProse(summary)) return summary;
  const blurb = advisoryBlurb(item);
  if (blurb) return blurb;
  return null;
}


function missingCheck(item: ResearchCase): string | null {
  return (
    item.ir_chain?.attempted_remediation?.missed?.replace(/\.$/, "") ||
    item.ir_chain?.residual_bypass?.replace(/\.$/, "") ||
    null
  );
}

function whatWentWrong(item: ResearchCase): string {
  return (
    findingSummary(item) ?? contributionHeadline(item.contribution_class)
  );
}

/**
 * Prefer the audited step title, but drop the generic "AI change"/"Fix" labels —
 * those say nothing a visitor doesn't already know from the kicker.
 */
function cardStepTitle(
  step: { readonly title: string } | undefined,
  fallback: string,
): string {
  const generic = new Set(["AI change", "AI fix", "Fix", "Root cause"]);
  if (step?.title && !generic.has(step.title.trim())) return step.title;
  return fallback;
}

function whatClosedIt(item: ResearchCase): string | null {
  return item.ir_chain?.final_closure?.closed?.replace(/\.$/, "") || null;
}

function rootCauseTitle(item: ResearchCase): string {
  const category = getCauseCategoryLabel(item.cause_category);
  return (
    {
      AI_DIRECT_ROOT: `${category} introduced`,
      AI_CAUSAL_CONTRIBUTOR: `${category} path exposed`,
      AI_INCOMPLETE_REMEDIATION: `${category} bypass remained`,
    }[item.contribution_class] ?? category
  );
}


function fixAuthorship(item: ResearchCase): string {
  const record = item.fix_authorship;
  if (!record) return "Fix authorship not yet analyzed";
  const authors = [...new Set(record.fixes.map((fix) => fix.author.name))].join(", ");
  const families = record.families
    .map(
      (family) =>
        ({
          aether: "Aether AI",
          claude: "Claude Code",
          claude_code: "Claude Code",
          cursor: "Cursor",
          github_copilot: "GitHub Copilot",
          copilot: "GitHub Copilot",
          openai_codex: "ChatGPT/Codex",
          openai_gpt_codex: "ChatGPT/Codex",
        })[family] ?? family,
    )
    .join(" + ");
  if (record.classification === "ai_assisted") {
    return `AI-assisted fix: ${families} · ${authors}`;
  }
  if (record.classification === "mixed") {
    return `Mixed fix set: ${families} + unmarked commit · ${authors}`;
  }
  return `Fix by ${authors} · no AI marker found`;
}

function CommitLink({
  repository,
  sha,
}: {
  readonly repository: string | null;
  readonly sha: string;
}) {
  const href = commitUrl(repository, sha);
  if (!href) return <span className="font-mono">{shortSha(sha)}</span>;
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex min-w-0 items-center gap-1 font-mono text-primary hover:underline"
    >
      {shortSha(sha)}
      <ExternalLink className="h-3 w-3" />
    </a>
  );
}

function FileLink({
  repository,
  sha,
  file,
}: {
  readonly repository: string | null;
  readonly sha: string;
  readonly file: string;
}) {
  if (!file) return <span className="font-mono">File path unavailable</span>;
  if (!repository || !sha) return <span className="font-mono">{file}</span>;
  return (
    <a
      href={`https://github.com/${repository}/blob/${sha}/${file}`}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex min-w-0 max-w-full items-center gap-1 break-all font-mono text-primary hover:underline"
    >
      {file}
      <ExternalLink className="h-3 w-3" />
    </a>
  );
}

function SourceLink({
  repository,
  sha,
}: {
  readonly repository: string | null;
  readonly sha: string;
}) {
  const href = commitUrl(repository, sha);
  const label = repository && sha ? `${repository}@${shortSha(sha)}` : "unresolved";
  if (!href) {
    return <span className="font-mono text-muted-foreground">source {label}</span>;
  }
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      aria-label={`Source commit ${repository} ${sha}`}
      className="inline-flex shrink-0 items-center gap-1 font-mono text-muted-foreground hover:text-primary hover:underline"
    >
      source {label}
      <ExternalLink className="h-3 w-3" />
    </a>
  );
}

function CauseFixCard({
  tone,
  kicker,
  title,
  detail,
  missed,
  repository,
  shas,
  sources,
  files,
  authorship,
  badge,
  muted,
}: {
  readonly tone: "bad" | "warn" | "good";
  readonly kicker: string;
  readonly title: string;
  readonly detail: string;
  readonly missed?: string | null;
  readonly repository: string | null;
  readonly shas: readonly string[];
  readonly sources?: ResearchCase["candidate_sources"];
  readonly files: readonly string[];
  readonly authorship: string;
  readonly badge?: string;
  readonly muted?: boolean;
}) {
  const toneClass = {
    bad: {
      border: "border-l-destructive bg-red-50/55",
      kicker: "text-destructive",
    },
    warn: {
      border: "border-l-amber-600 bg-amber-50/55",
      kicker: "text-amber-800",
    },
    good: {
      border: "border-l-emerald-600 bg-emerald-50/55",
      kicker: "text-emerald-700",
    },
  }[tone];
  return (
    <article
      className={`min-w-0 border border-border border-l-4 p-5 ${toneClass.border} ${
        muted ? "opacity-75" : ""
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p
          className={`font-mono text-[10px] font-semibold uppercase tracking-wider ${toneClass.kicker}`}
        >
          {kicker}
        </p>
        {badge ? (
          <span
            className={`font-mono text-[10px] font-semibold uppercase tracking-wider ${
              muted
                ? "text-muted-foreground"
                : "bg-primary px-1.5 py-0.5 text-primary-foreground"
            }`}
          >
            {badge}
          </span>
        ) : null}
      </div>
      <h3 className="mt-3 text-lg font-semibold">{title}</h3>
      <p className="mt-2 text-sm leading-6 text-muted-foreground">{detail}</p>
      {missed ? (
        <p className="mt-3 text-sm font-medium leading-6 text-amber-900">
          Missed: {missed}
        </p>
      ) : null}
      <div className="mt-5 space-y-2 border-t border-border pt-4 text-xs">
        <p className="text-muted-foreground">{authorship}</p>
        <div className="flex flex-wrap gap-x-3 gap-y-1">
          {shas.map((sha) => (
            <CommitLink
              key={sha}
              repository={
                sources?.find((source) => source.sha === sha)?.repository ??
                repository
              }
              sha={sha}
            />
          ))}
        </div>
        {files.length ? (
          <div className="flex flex-wrap gap-x-3 gap-y-1">
            {[...new Set(files)].map((file) => (
              <FileLink
                key={file}
                repository={
                  sources?.find((source) => source.sha === shas[0])?.repository ??
                  repository
                }
                sha={shas[0]}
                file={file}
              />
            ))}
          </div>
        ) : null}
      </div>
    </article>
  );
}

/**
 * Advisory description: fixed-height preview (no ellipsis cut), manual expand.
 * line-clamp trims visually; <details> supplies the explicit toggle.
 */
function AdvisoryDisclosure({
  text,
  className,
}: {
  readonly text: string;
  readonly className?: string;
}) {
  return (
    <details className={`group/advisory ${className ?? ""}`}>
      <summary className="-mx-1 inline-flex cursor-pointer select-none items-center gap-1 rounded px-1 text-sm font-medium text-primary transition-colors hover:bg-primary/5 [&::-webkit-details-marker]:hidden">
        <span className="group-open/advisory:hidden">Show full advisory description</span>
        <span className="hidden group-open/advisory:inline">Hide advisory description</span>
        <ChevronDown className="h-3.5 w-3.5 transition-transform group-open/advisory:rotate-180" />
      </summary>
      <p className="mt-2 max-w-3xl whitespace-pre-line text-sm leading-6 text-muted-foreground group-open/advisory:mt-3">
        {text}
      </p>
    </details>
  );
}

/**
 * Plain-language mechanism note: clamped preview, manual expand. Only rendered
 * when the text passes the public-prose filter.
 */
function MechanismDisclosure({
  item,
  className,
}: {
  readonly item: ResearchCase;
  readonly className?: string;
}) {
  const text = publicMechanism(item);
  const blurb = advisoryBlurb(item);
  if (!text || (blurb && stripMarkdown(text).trim() === blurb.trim())) return null;
  return (
    <details className={`group/mech ${className ?? ""}`}>
      <summary className="-mx-1 inline-flex cursor-pointer select-none items-center gap-1 rounded px-1 text-sm font-medium text-primary transition-colors hover:bg-primary/5 [&::-webkit-details-marker]:hidden">
        <span className="group-open/mech:hidden">What actually happened</span>
        <span className="hidden group-open/mech:inline">Hide details</span>
        <ChevronDown className="h-3.5 w-3.5 transition-transform group-open/mech:rotate-180" />
      </summary>
      <p className="mt-2 max-w-3xl whitespace-pre-line text-sm leading-6 text-muted-foreground">
        {text}
      </p>
    </details>
  );
}

/** Right-hand facts card: dates, severity, releases. */
function CaseFactsCard({ item }: { readonly item: ResearchCase }) {
  const facts: { label: string; value: ReactNode }[] = [
    {
      label: "Published",
      value: item.published_at ? formatPublished(item.published_at) : "Unavailable",
    },
    {
      label: "Severity",
      value: item.severity ? (
        <Badge className={severityBadgeClass(item.severity)}>{item.severity}</Badge>
      ) : (
        "Not scored"
      ),
    },
    {
      label: "Language",
      value: item.repository_metadata.language || "Unknown",
    },
    {
      label: "AI role",
      value: formatContributionClass(item.contribution_class),
    },
    ...(item.vulnerable_release
      ? [
          {
            label: "Vulnerable release",
            value: (
              <span className="font-mono">
                {releaseLabel(item.vulnerable_release)}
              </span>
            ),
          },
        ]
      : []),
    ...(item.fixed_release
      ? [
          {
            label: "Fixed release",
            value: (
              <span className="font-mono">{releaseLabel(item.fixed_release)}</span>
            ),
          },
        ]
      : []),
  ];
  return (
    <aside className="h-fit rounded-lg border border-border bg-card p-5 text-sm shadow-sm xl:sticky xl:top-6">
      <p className="section-kicker">Case facts</p>
      <dl className="mt-4 space-y-3.5">
        {facts.map(({ label, value }) => (
          <div key={label} className="flex min-w-0 items-baseline justify-between gap-4">
            <dt className="shrink-0 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              {label}
            </dt>
            <dd className="min-w-0 break-words text-right">{value}</dd>
          </div>
        ))}
      </dl>
      {item.cwes.length ? (
        <div className="mt-4 flex flex-wrap gap-1.5 border-t border-border pt-4">
          {item.cwes.map((cwe) => (
            <a
              key={cwe}
              href={`https://cwe.mitre.org/data/definitions/${cwe.replace(/^CWE-/, "")}.html`}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-xs text-primary hover:underline"
            >
              {cwe}
            </a>
          ))}
        </div>
      ) : null}
      {item.advisory_url ? (
        <a
          href={item.advisory_url}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-4 inline-flex items-center gap-1 border-t border-border pt-4 text-primary hover:underline"
        >
          Advisory source <ExternalLink className="h-3 w-3" />
        </a>
      ) : null}
    </aside>
  );
}

function ChainArrow() {
  return (
    <div className="flex items-center justify-center" aria-hidden="true">
      <ArrowRight className="h-5 w-5 rotate-90 text-muted-foreground sm:rotate-0" />
    </div>
  );
}

function introducedBy(chain: NonNullable<ResearchCase["ir_chain"]>): string {
  if (chain.original_author_kind === "AI") {
    return `Originally written by AI${chain.original_author_name ? ` (${chain.original_author_name})` : ""}`;
  }
  if (chain.original_author_kind === "HUMAN") {
    return `Originally written by ${chain.original_author_name ?? "a human commit"}`;
  }
  return "Original authorship unresolved";
}

function caseIdentities(item: ResearchCase): Set<string> {
  return new Set(
    [item.case_id, item.class_id, ...item.aliases]
      .filter((value): value is string => Boolean(value))
      .map((value) => value.toUpperCase()),
  );
}

function earlierAdvisoryId(item: ResearchCase): string | null {
  const current = caseIdentities(item);
  const original = item.ir_chain?.original_advisory_ids ?? [];
  return (
    original.find((id) => !current.has(id.toUpperCase())) ?? null
  );
}

function ThisAdvisoryFrame({
  label,
  children,
}: {
  readonly label: string;
  readonly children: ReactNode;
}) {
  return (
    <div className="border-2 border-primary bg-primary/[0.04] p-3 sm:p-4">
      <p className="mb-3 flex flex-wrap items-center gap-2 font-mono text-[10px] font-semibold uppercase tracking-wider text-primary">
        <span className="bg-primary px-1.5 py-0.5 text-primary-foreground">
          This advisory
        </span>
        <span className="normal-case tracking-normal">{label}</span>
      </p>
      {children}
    </div>
  );
}

function IncompleteRemediationFlow({
  item,
  displayId,
}: {
  readonly item: ResearchCase;
  readonly displayId: string;
}) {
  const chain = item.ir_chain;
  if (!chain) return null;
  const attempt = chain.attempted_remediation;
  const closure = chain.final_closure;
  const attemptShas = attempt?.candidate_shas?.length
    ? attempt.candidate_shas
    : item.candidate_set;
  const closureShas = closure?.minimum_fix_shas?.length
    ? closure.minimum_fix_shas
    : item.minimum_fix_set;
  const hasClosure = closureShas.length > 0;
  const attemptCoversOriginal = Boolean(
    chain.original_sha &&
      attemptShas.some(
        (sha) =>
          sha.startsWith(chain.original_sha!.slice(0, 12)) ||
          chain.original_sha!.startsWith(sha.slice(0, 12)),
      ),
  );
  const originalDistinct = Boolean(
    (chain.original_mechanism || chain.original_sha || chain.unresolved_reason) &&
      !attemptCoversOriginal,
  );
  const earlierId = originalDistinct ? earlierAdvisoryId(item) : null;

  const attemptCard = (
    <CauseFixCard
      tone="warn"
      kicker="AI tried to fix this"
      title={attempt?.changed ?? "An AI patch touched the vulnerable path."}
      detail="The AI change was a real security patch, but it left the same advisory reachable."
      missed={attempt?.missed ?? chain.residual_bypass}
      repository={item.repository}
      shas={attemptShas}
      files={item.code_evidence?.candidate_hunks.map((hunk) => hunk.file) ?? []}
      authorship={`Incomplete AI fix · ${getAiToolLabel(item)}`}
    />
  );
  const closureCard = (
    <CauseFixCard
      tone={hasClosure ? "good" : "warn"}
      kicker={hasClosure ? "Fixed again" : "Fix status"}
      title={
        hasClosure
          ? (closure?.closed ?? "A later commit closed the remaining case.")
          : "No public closure identified"
      }
      detail={
        hasClosure
          ? "This is the patch that actually stops the same attack path."
          : "No minimum fix commit has been established for the remaining path."
      }
      repository={item.repository}
      shas={closureShas}
      files={item.code_evidence?.fix_hunks.map((hunk) => hunk.file) ?? []}
      authorship={hasClosure ? fixAuthorship(item) : "Fix status unresolved"}
    />
  );
  const thisAdvisoryPair = (
    <ThisAdvisoryFrame label={formatCaseLabel(item, displayId)}>
      <div className="grid items-stretch gap-3 sm:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
        {attemptCard}
        <ChainArrow />
        {closureCard}
      </div>
    </ThisAdvisoryFrame>
  );

  if (!originalDistinct) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-muted-foreground">
          The highlighted steps are this advisory: the incomplete AI patch and
          the later commit that closed it.
        </p>
        {thisAdvisoryPair}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">
        Only the highlighted steps are this advisory. The first card is the
        earlier flaw the AI tried, and failed, to close.
      </p>
      <div className="grid items-stretch gap-3 xl:grid-cols-[minmax(0,0.9fr)_auto_minmax(0,1.4fr)]">
        <CauseFixCard
          tone="bad"
          kicker="Original flaw"
          title={
            chain.original_mechanism ??
            "The vulnerable behavior already existed."
          }
          detail={
            `${
              chain.original_sink
                ? `Sink: ${chain.original_sink}`
                : "Prior context, not this advisory."
            }${
              !chain.original_sha && chain.unresolved_reason
                ? ` Unresolved origin: ${chain.unresolved_reason}`
                : ""
            }`
          }
          repository={item.repository}
          shas={chain.original_sha ? [chain.original_sha] : []}
          files={[]}
          authorship={introducedBy(chain)}
          badge={earlierId ? `Earlier advisory · ${earlierId}` : "Earlier flaw"}
          muted
        />
        <ChainArrow />
        {thisAdvisoryPair}
      </div>
    </div>
  );
}
function DiffHunk({
  hunk,
  repository,
  sha,
  label,
  annotation,
  readerContext,
  open,
}: {
  readonly hunk: ResearchCodeHunk;
  readonly repository: string | null;
  readonly sha: string;
  readonly label: DiffRole;
  readonly annotation: string | null;
  readonly readerContext: string;
  readonly open: boolean;
}) {
  const lines = hunk.code.replace(/\n$/, "").split("\n");
  const added = lines.filter(
    (line) => line.startsWith("+") && !line.startsWith("+++"),
  ).length;
  const removed = lines.filter(
    (line) => line.startsWith("-") && !line.startsWith("---"),
  ).length;
  // Curated, hunk-specific explanations open with their code; unannotated long
  // patches stay collapsed. Expanded diffs are never clipped.
  const collapsible = lines.length > 24;
  const openDefault = Boolean(annotation) || (!collapsible && open);
  return (
    <details
      open={openDefault}
      className="group overflow-hidden border border-border bg-card"
    >
      <summary className="flex cursor-pointer select-none items-center justify-between gap-3 px-4 py-2.5 [&::-webkit-details-marker]:hidden">
        <span className="flex min-w-0 flex-wrap items-center gap-2 text-[11px]">
          <span className="shrink-0 border border-border bg-muted/50 px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-wide text-muted-foreground">
            {label}
          </span>
          <FileLink repository={repository} sha={sha} file={hunk.file} />
          <SourceLink repository={repository} sha={sha} />
        </span>
        <span className="flex shrink-0 items-center gap-2 font-mono text-[10px] tabular-nums">
          <span className="text-emerald-700">+{added}</span>
          <span className="text-red-700">−{removed}</span>
        </span>
      </summary>
      <pre className="overflow-x-auto border-t border-border py-3 text-[12px] leading-5 [contain:paint]">
        <code>
          {lines.map((line, index) => (
            <span
              key={`${index}-${line}`}
              className={`block min-w-max px-4 ${
                line.startsWith("+")
                  ? "bg-emerald-50 text-emerald-900"
                  : line.startsWith("-")
                    ? "bg-red-50 text-red-900"
                    : line.startsWith("@@")
                      ? "text-primary"
                      : ""
              }`}
            >
              {line || " "}
            </span>
          ))}
        </code>
      </pre>
      <p
        className={`border-t px-4 py-3 text-xs leading-5 ${
          annotation
            ? "border-amber-200 bg-amber-50/70 text-amber-950"
            : "border-border bg-muted/30 text-muted-foreground"
        }`}
      >
        <span className="font-semibold text-foreground">
          Why this change is shown
          {annotation
            ? ":"
            : ` (case-level ${label.toLowerCase()} context; not a hunk-specific annotation):`}
        </span>{" "}
        {annotation ?? readerContext}
      </p>
    </details>
  );
}

export function CanonicalCaseEvidence({
  item,
  displayId,
}: {
  readonly item: ResearchCase;
  readonly displayId?: string;
}) {
  const visibleId = displayId ?? preferredCaseId(item);
  const evidence = item.code_evidence;
  const candidateHunks = evidence?.candidate_hunks ?? [];
  const fixHunks = evidence?.fix_hunks ?? [];
  const comparisonHunks = evidence?.comparison_hunks ?? [];
  const candidateFiles = candidateHunks.map((hunk) => hunk.file);
  const fixFiles = fixHunks.map((hunk) => hunk.file);
  const hasFix = item.minimum_fix_set.length > 0;
  const incomplete =
    item.contribution_class === "AI_INCOMPLETE_REMEDIATION" &&
    Boolean(item.ir_chain);
  const steps = evidence?.steps ?? [];
  const rightStep =
    [...steps].reverse().find((step) => /\bfix\b/i.test(step.title)) ??
    (steps.length >= 3 ? steps[2] : steps[1]);
  const leftStep =
    steps.length >= 3
      ? steps[1]
      : steps.find((step) => !/\bfix\b/i.test(step.title));
  const introStep = steps.length >= 3 ? steps[0] : null;
  const summary = findingSummary(item);
  const blurb = advisoryBlurb(item);
  const attempt = item.ir_chain?.attempted_remediation;
  const candidateExplanation =
    incomplete && attempt
      ? `What the AI patch changed: ${attempt.changed} What it still missed: ${attempt.missed}`
      : (compactPublicProse(
          evidence?.summary,
          item.mechanism,
          item.description,
        ) ?? contributionHeadline(item.contribution_class));
  const fixExplanation =
    compactPublicProse(whatClosedIt(item), rightStep?.detail) ??
    "This later patch closes the vulnerable path described above.";
  const hunkAnnotation = (hunk: ResearchCodeHunk) => {
    const annotation = usefulHunkAnnotation(hunk.annotation);
    const repeated = [evidence?.summary, item.mechanism].some(
      (value) => annotation && stripMarkdown(value).trim() === annotation,
    );
    return annotation && !repeated ? annotation : null;
  };
  const markerMatch = evidence?.ai_marker?.match(
    /(?:Co-Authored-By|Assisted-by):\s*([^<]+)/i,
  );
  const candidateModel = markerMatch?.[1].trim() ?? getAiToolLabel(item);
  const candidateSource = commitSource(
    evidence?.candidate_url,
    item.repository,
    item.candidate_set[0] ?? "",
  );
  const fixSource = commitSource(
    evidence?.fix_url,
    item.repository,
    item.minimum_fix_set[0] ?? candidateSource.sha,
  );
  const sameHunk = (left: ResearchCodeHunk, right: ResearchCodeHunk) =>
    left.file === right.file && left.code === right.code;
  const hunkRole = (hunk: ResearchCodeHunk): DiffRole =>
    hunk.role === "candidate" ||
    candidateHunks.some((item) => sameHunk(item, hunk))
      ? "AI change"
      : hunk.role === "fix" || fixHunks.some((item) => sameHunk(item, hunk))
        ? "Fix"
        : "Comparison";
  const selectedHunks = comparisonHunks.length
    ? [...comparisonHunks]
    : [...candidateHunks, ...fixHunks];
  if (comparisonHunks.length) {
    for (const [role, hunks] of [
      ["AI change", candidateHunks],
      ["Fix", fixHunks],
    ] as const) {
      if (selectedHunks.some((hunk) => hunkRole(hunk) === role)) continue;
      for (const hunk of hunks) {
        if (!selectedHunks.some((selected) => sameHunk(selected, hunk))) {
          selectedHunks.push(hunk);
        }
      }
    }
  }
  const codeHunks = selectedHunks.map((hunk) => {
    const label = hunkRole(hunk);
    return {
      hunk,
      label,
      ...(label === "AI change" ? candidateSource : fixSource),
      annotation: hunkAnnotation(hunk),
      readerContext:
        label === "AI change"
          ? candidateExplanation
          : label === "Fix"
            ? fixExplanation
            : `${candidateExplanation} ${fixExplanation}`,
    };
  });
  const hasCode = codeHunks.length > 0;
  const codeTitle =
    candidateHunks.length && fixHunks.length
      ? "Vulnerable code and fix"
      : candidateHunks.length
        ? "Candidate change"
        : "Security fix";
  return (
    <section className="space-y-12 border-t border-border pt-8">
      <div className="grid items-start gap-8 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="min-w-0 space-y-8">
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <p className="section-kicker">How AI contributed</p>
              <span className="border border-primary/25 bg-primary/[0.05] px-2 py-1 font-mono text-[10px] font-semibold text-primary">
                {formatContributionClass(item.contribution_class)}
              </span>
            </div>
            <h2 className="mt-3 text-xl font-semibold tracking-[-0.025em] sm:text-2xl">
              {summary ?? contributionHeadline(item.contribution_class)}
            </h2>
            {blurb && blurb !== summary ? (
              <AdvisoryDisclosure text={blurb} className="mt-3" />
            ) : null}
            <MechanismDisclosure item={item} className="mt-5" />
          </div>

          {introStep && !incomplete ? (
            <div className="grid gap-2 border-y border-border py-4 sm:grid-cols-[8rem_1fr]">
              <p className="font-mono text-[10px] font-semibold uppercase tracking-wider text-primary">
                AI change
              </p>
              <p className="text-sm leading-6 text-muted-foreground">
                {introStep.detail}
              </p>
            </div>
          ) : null}

          {incomplete ? (
            <IncompleteRemediationFlow item={item} displayId={visibleId} />
          ) : (
            <div className="grid min-w-0 items-stretch gap-3 sm:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
              <CauseFixCard
                tone="bad"
                kicker="Root cause"
                title={cardStepTitle(leftStep, rootCauseTitle(item))}
                detail={
                  leftStep?.detail ??
                  "The candidate commit below is where the vulnerable behavior appears."
                }
                repository={candidateSource.repository}
                shas={item.candidate_set}
                sources={item.candidate_sources}
                files={candidateFiles}
                authorship={`AI candidate: ${candidateModel}`}
              />
              <ChainArrow />
              <CauseFixCard
                tone={hasFix ? "good" : "warn"}
                kicker={hasFix ? "Fix" : "Fix status"}
                title={hasFix ? cardStepTitle(rightStep, "Security fix") : "No public fix identified"}
                detail={
                  hasFix
                    ? (rightStep?.detail ??
                      "The minimum fix commit below closes the same vulnerable path.")
                    : "No minimum fix commit has been established for this finding."
                }
                repository={fixSource.repository}
                shas={item.minimum_fix_set}
                files={fixFiles}
                authorship={hasFix ? fixAuthorship(item) : "Fix status unresolved"}
              />
            </div>
          )}
        </div>
        <CaseFactsCard item={item} />
      </div>

      {evidence && hasCode ? (
        <div className="space-y-4" aria-labelledby="code-comparison">
          <div>
            <p className="section-kicker">Code comparison</p>
            <h3 id="code-comparison" className="mt-2 text-lg font-semibold">
              {codeTitle}
            </h3>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
              Lines beginning with − were removed; lines beginning with + were
              added. The badge shows whether a hunk belongs to the AI-linked
              change, the later fix, or a curated comparison of the two.
            </p>
          </div>
          {codeHunks.map(
            (
              { hunk, label, repository, sha, annotation, readerContext },
              index,
            ) => (
              <DiffHunk
                key={`${label}-${index}-${hunk.file}`}
                hunk={hunk}
                repository={repository}
                sha={sha}
                label={label}
                annotation={annotation}
                readerContext={readerContext}
                open={
                  index === 0 ||
                  (label === "Fix" && codeHunks[index - 1]?.label !== "Fix")
                }
              />
            ),
          )}
          {evidence.candidate_patch_sha256 && evidence.fix_patch_sha256 ? (
            <details className="text-xs text-muted-foreground">
              <summary className="cursor-pointer">Patch fingerprints</summary>
              <p className="mt-2 break-all font-mono text-[10px] leading-5">
                Candidate {evidence.candidate_patch_sha256}
                {" · "}Fix {evidence.fix_patch_sha256}
              </p>
            </details>
          ) : null}
        </div>
      ) : (
        <div className="space-y-4 border-y border-border py-5">
          <div>
            <p className="section-kicker">What went wrong</p>
            <h3 className="mt-2 text-lg font-semibold">
              {rootCauseTitle(item)}
            </h3>
          </div>
          {blurb ? (
            <p className="max-w-3xl text-sm leading-6 text-muted-foreground">
              {blurb}
            </p>
          ) : null}
          {evidence?.unavailable_reason ? (
            <p className="max-w-3xl border-l-2 border-amber-400 pl-3 text-sm leading-6 text-muted-foreground">
              <span className="font-semibold text-foreground">
                Why no code diff is shown:
              </span>{" "}
              {evidence.unavailable_reason}
            </p>
          ) : null}
          <dl className="max-w-3xl space-y-4 text-sm">
            <div>
              <dt className="font-medium">The problem</dt>
              <dd className="mt-1 leading-6 text-muted-foreground">
                {whatWentWrong(item)}
              </dd>
            </div>
            {missingCheck(item) ? (
              <div>
                <dt className="font-medium">Missing check</dt>
                <dd className="mt-1 leading-6 text-muted-foreground">
                  {missingCheck(item)}
                </dd>
              </div>
            ) : null}
            {whatClosedIt(item) ? (
              <div>
                <dt className="font-medium">What closed it</dt>
                <dd className="mt-1 leading-6 text-muted-foreground">
                  {whatClosedIt(item)}
                </dd>
              </div>
            ) : null}
          </dl>
        </div>
      )}

    </section>
  );
}
