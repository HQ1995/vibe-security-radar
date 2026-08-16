import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, ExternalLink } from "lucide-react";
import { stripMarkdown } from "@/lib/markdown-utils";
import { getProseSummary } from "@/lib/markdown-utils";

import { CanonicalCaseEvidence } from "@/components/canonical-case-evidence";
import { LanguageBadge } from "@/components/language-badge";
import { Badge } from "@/components/ui/badge";
import { formatPublished } from "@/lib/commit-utils";
import { severityBadgeClass } from "@/lib/constants";
import {
  formatContributionClass,
  getResearchCaseById,
  getResearchCases,
  type ResearchCase,
} from "@/lib/research-data";

export const dynamicParams = false;

export function generateStaticParams() {
  const ids = new Set<string>();
  for (const item of getResearchCases()) {
    ids.add(item.case_id);
    item.aliases.forEach((alias) => ids.add(alias));
  }
  return [...ids].sort().map((id) => ({ id }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ id: string }>;
}): Promise<Metadata> {
  const { id } = await params;
  const item = getResearchCaseById(id);
  if (!item) return { title: "Case not found" };

  const description = stripMarkdown(
     "Mechanism-level evidence for " + id + ".",
    item.description ?? "Mechanism-level evidence for " + id + ".",
  ).slice(0, 200);
  return {
    title: `${id} — AI contribution evidence`,
    description,
  };
}

function PageHeader({
  id,
  item,
  summary,
}: {
  readonly id: string;
  readonly item: ResearchCase;
  readonly summary: string | null;
}) {
  const repository = item.repository;
  const owner = repository?.split("/")[0];
  const repoUrl = repository ? `https://github.com/${repository}` : undefined;
  const avatarUrl = owner ? `https://github.com/${owner}.png?size=32` : undefined;
  const languages = item.repository_metadata.language
    ? [item.repository_metadata.language]
    : [];

  return (
    <header className="space-y-4">
      <Link
        href="/#cases"
        className="inline-flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        Back to case files
      </Link>

      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
        <div>
          <p className="section-kicker">Case evidence</p>
          <h1 className="mt-2 font-mono text-2xl font-bold tracking-tight sm:text-3xl">
            {id}
          </h1>
          {id.toUpperCase() !== item.case_id.toUpperCase() ? (
            <p className="mt-2 font-mono text-xs text-muted-foreground">
              First-party advisory: {item.case_id}
            </p>
          ) : null}
          {summary ? (
            <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
              {summary}
            </p>
          ) : null}
          {repoUrl ? (
            <a
              href={repoUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-3 inline-flex items-center gap-1.5 text-sm font-medium text-foreground transition-colors hover:text-primary"
            >
              {avatarUrl ? (
                // eslint-disable-next-line @next/next/no-img-element -- remote avatar, not an asset
                <img
                  src={avatarUrl}
                  alt=""
                  width={16}
                  height={16}
                  loading="lazy"
                  className="h-4 w-4 rounded-full border border-border"
                />
              ) : null}
              {repository}
              <ExternalLink className="h-3 w-3 text-muted-foreground" />
            </a>
          ) : null}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 border-y border-border py-3 text-xs text-muted-foreground">
        {item.published_at ? (
          <span>
            First-party advisory: {formatPublished(item.published_at)}
          </span>
        ) : (
          <span>First-party advisory date unavailable</span>
        )}
        {item.severity ? (
          <Badge className={severityBadgeClass(item.severity)}>
            {item.severity}
          </Badge>
        ) : null}
        {item.cwes.map((cwe) => (
          <a
            key={cwe}
            href={`https://cwe.mitre.org/data/definitions/${cwe.replace(/^CWE-/, "")}.html`}
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-primary hover:underline"
          >
            {cwe}
          </a>
        ))}
        {languages.map((language) => (
          <LanguageBadge key={language} language={language} />
        ))}
        <span>{formatContributionClass(item.contribution_class)}</span>
      </div>
    </header>
  );
}

function IrChain({
  chain,
}: {
  readonly chain: NonNullable<ResearchCase["ir_chain"]>;
}) {
  const steps = [
    {
      title: "1. Original vulnerability",
      body: [
        chain.original_mechanism,
        chain.original_sink ? `Sink: ${chain.original_sink}` : null,
        chain.original_sha
          ? `Introduced by ${chain.original_author_kind === "AI" ? "AI" : "a human"} (${chain.original_author_name ?? "unknown"}) in ${chain.original_sha.slice(0, 12)}`
          : null,
        chain.original_advisory_ids.length
          ? `Advisories: ${chain.original_advisory_ids.join(", ")}`
          : null,
      ].filter(Boolean),
    },
    {
      title: "2. AI attempted fix",
      body: [
        chain.attempted_remediation?.changed,
        chain.attempted_remediation?.candidate_shas.length
          ? `Commit: ${chain.attempted_remediation.candidate_shas.join(", ")}`
          : null,
      ].filter(Boolean),
    },
    {
      title: "3. What it missed (this advisory)",
      body: [chain.attempted_remediation?.missed, chain.residual_bypass].filter(
        Boolean,
      ),
    },
    {
      title: "4. Final closure",
      body: [
        chain.final_closure?.closed,
        chain.final_closure?.minimum_fix_shas.length
          ? `Fix: ${chain.final_closure.minimum_fix_shas.join(", ")}`
          : null,
      ].filter(Boolean),
    },
  ];
  return (
    <section className="border-t border-border pt-7" aria-labelledby="ir-chain">
      <p className="section-kicker">Incomplete remediation chain</p>
      <h2 id="ir-chain" className="sr-only">
        Incomplete remediation chain
      </h2>
      <ol className="mt-4 space-y-4">
        {steps.map((step) => (
          <li key={step.title} className="text-sm">
            <p className="font-semibold text-foreground">{step.title}</p>
            {step.body.map((line, i) => (
              <p key={i} className="mt-1 leading-6 text-muted-foreground">
                {line}
              </p>
            ))}
          </li>
        ))}
      </ol>
    </section>
  );
}

export default async function CveDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const item = getResearchCaseById(id);
  if (!item) notFound();

  const references = item.references ?? [];
  const summary = getProseSummary(item.description);

  return (
    <main className="mx-auto w-full max-w-[96rem] space-y-8 px-4 py-10 sm:px-6 2xl:px-8 min-[1920px]:max-w-[112rem] min-[2400px]:max-w-[128rem]">
      <PageHeader id={id} item={item} summary={summary} />

      <CanonicalCaseEvidence item={item} />

      {item.ir_chain ? <IrChain chain={item.ir_chain} /> : null}

      {references.length > 0 ? (
        <section
          className="border-t border-border pt-7"
          aria-labelledby="sources"
        >
          <p className="section-kicker">Advisory references</p>
          <h2 id="sources" className="sr-only">
            Advisory references
          </h2>
          <ul className="mt-4 space-y-2">
            {references.map((reference) => (
              <li key={reference}>
                {/^https?:\/\//i.test(reference) ? (
                  <a
                    href={reference}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="break-all text-sm text-primary hover:underline"
                  >
                    {reference}
                  </a>
                ) : (
                  <span className="break-all text-sm text-muted-foreground">
                    {reference}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </main>
  );
}
