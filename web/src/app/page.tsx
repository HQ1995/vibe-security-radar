import type { Metadata } from "next";
import Link from "next/link";
import { Search } from "lucide-react";

import { AiToolComparison } from "@/components/ai-tool-comparison";
import { DistributionBars } from "@/components/distribution-bars";
import { OverviewPanel } from "@/components/overview-panel";
import { SeverityLabel } from "@/components/severity-label";
import { ToolIcon } from "@/components/tool-icon";
import { TrendChart } from "@/components/trend-chart";
import { SITE_URL } from "@/lib/constants";
import { formatDay, formatMonthShort } from "@/lib/month-utils";
import {
  formatContributionClass,
  getAiFamilyIconKey,
  getAiToolDistribution,
  getAiToolLabel,
  getCauseDistribution,
  getCauseCategoryLabel,
  formatCount,
  getCaseHeadline,
  preferredCaseId,
  getLanguageDistribution,
  getRepositoryDistribution,
  getResearchCases,
  getResearchSnapshot,
  getResearchTimeline,
  type ResearchCase,
} from "@/lib/research-data";

export const metadata: Metadata = {
  alternates: {
    canonical: "/",
    types: { "application/atom+xml": "/feed.xml" },
  },
};

const MEDIA_COVERAGE = [
  {
    source: "Infosecurity Magazine",
    date: "Mar 26, 2026",
    title:
      "Researchers sound the alarm on vulnerabilities in AI-generated code",
    href: "https://www.infosecurity-magazine.com/news/ai-generated-code-vulnerabilities/",
  },
  {
    source: "Georgia Tech Research News",
    date: "Apr 13, 2026",
    title: "Bad vibes: AI-generated code is vulnerable, researchers warn",
    href: "https://news.research.gatech.edu/2026/04/13/bad-vibes-ai-generated-code-vulnerable-researchers-warn",
  },
  {
    source: "Def Method",
    date: "Apr 13, 2026",
    title: "Detection won't save you",
    href: "https://www.defmethod.com/essential-complexity/detection-wont-save-you",
  },
] as const;

function faqs(caseCount: number) {
  return [
    {
      question: "What counts as an AI-contributed vulnerability?",
      answer:
        "The vulnerable behavior must depend on an AI-authored code change and be reversed by a real security fix.",
    },
    {
      question: "Is every AI-related commit shown?",
      answer:
        "No. Each finding shows the contributing change and minimum fix, not unrelated search candidates.",
    },
    {
      question: "Is this the total number of AI security bugs?",
      answer: `No. The index contains ${caseCount} findings, an observed public set rather than a census of every AI bug.`,
    },
    {
      question: "Can a finding be corrected?",
      answer:
        "Yes. Open a GitHub issue with the advisory, commit, or release evidence that changes the conclusion.",
    },
  ] as const;
}

function findingsHref(key: string, value: string): string {
  return `/cves?${new URLSearchParams({ [key]: value })}`;
}

function HeadlineStat({
  label,
  value,
  detail,
}: {
  readonly label: string;
  readonly value: string;
  readonly detail: string;
}) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 text-2xl font-semibold tracking-[-0.02em]">
        {value}
      </dd>
      <dd className="mt-0.5 line-clamp-2 text-xs text-muted-foreground [overflow-wrap:anywhere]">
        {detail}
      </dd>
    </div>
  );
}

function FindingRow({ item }: { readonly item: ResearchCase }) {
  const id = preferredCaseId(item);
  return (
    <li className="py-4">
      <Link
        href={`/cves/${id}`}
        className="line-clamp-2 font-medium leading-6 [overflow-wrap:anywhere] hover:text-primary hover:underline"
      >
        {getCaseHeadline(item)}
      </Link>
      <p className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
        <SeverityLabel severity={item.severity} />
        <span className="font-mono">{id}</span>
        <span aria-hidden="true">·</span>
        <span>{item.repository ?? "Repository not recorded"}</span>
        <span aria-hidden="true">·</span>
        <span className="inline-flex items-center gap-1">
          <ToolIcon
            tool={getAiFamilyIconKey(item.ai_provenance.family)}
            size={13}
          />
          {getAiToolLabel(item)}
        </span>
        <span aria-hidden="true">·</span>
        <span>{formatContributionClass(item.contribution_class)}</span>
        <span aria-hidden="true">·</span>
        <span>{getCauseCategoryLabel(item.cause_category)}</span>
        <span aria-hidden="true">·</span>
        <span className="whitespace-nowrap">
          {item.published_at
            ? formatDay(item.published_at)
            : "Date unavailable"}
        </span>
      </p>
    </li>
  );
}

export default function HomePage() {
  const research = getResearchSnapshot();
  const caseCount = research.snapshot.case_count;
  const faqItems = faqs(caseCount);
  const timeline = getResearchTimeline();
  const aiTools = getAiToolDistribution();
  const causes = getCauseDistribution();
  const languages = getLanguageDistribution();
  const repositories = getRepositoryDistribution();
  const featuredCases = (() => {
    const pool = [...getResearchCases()].sort((a, b) =>
      (b.published_at ?? "").localeCompare(a.published_at ?? ""),
    );
    const picked: typeof pool = [];
    const classOrder = [
      "AI_INCOMPLETE_REMEDIATION",
      "AI_DIRECT_ROOT",
      "AI_CODE_FLAWED",
      "AI_NEW_SURFACE_CONTRIBUTOR",
      "AI_ROOT_NEW_COMPONENT",
    ];
    for (const cls of classOrder) {
      const hit = pool.find((item) => item.contribution_class === cls);
      if (hit) picked.push(hit);
    }
    for (const item of pool) {
      if (picked.length >= 6) break;
      if (!picked.includes(item)) picked.push(item);
    }
    return picked;
  })();
  const topRepository = repositories[0];
  const coveredFrom = (research.snapshot.coverage_from ?? "2025-05-01").slice(
    0,
    7,
  );
  const coveredTo = (research.snapshot.coverage_to ?? "2026-08-16").slice(0, 7);

  return (
    <main>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify({
            "@context": "https://schema.org",
            "@type": "Dataset",
            name: "Vibe Security Radar",
            description: `${caseCount} publicly disclosed vulnerabilities where an AI-assisted code change introduced the flaw, exposed the vulnerable path, or left a security fix incomplete, each linked to first-party evidence.`,
            url: SITE_URL,
            creator: { "@type": "Organization", name: "Georgia Tech SSLab" },
            license: "https://opensource.org/licenses/MIT",
            temporalCoverage: `${research.snapshot.coverage_from ?? ""}/${research.snapshot.coverage_to ?? ""}`,
            dateModified: research.snapshot.source_cutoff.slice(0, 10),
            keywords: [
              "AI-generated code",
              "vulnerabilities",
              "CVE",
              "GHSA",
              "software security",
            ],
            distribution: [
              {
                "@type": "DataDownload",
                encodingFormat: "text/csv",
                contentUrl: `${SITE_URL}/data/findings.csv`,
              },
            ],
          }).replace(/</g, "\\u003c"),
        }}
      />
      <header className="border-b border-border">
        <div className="page-container grid gap-8 py-8 sm:py-10 lg:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)] lg:items-center lg:gap-12">
          <div>
            <p className="text-sm text-muted-foreground">
              Georgia Tech SSLab · Security research · Data through{" "}
              {formatMonthShort(
                research.snapshot.source_cutoff.slice(0, 7),
              ).slice(0, 3)}{" "}
              {Number(research.snapshot.source_cutoff.slice(8, 10))},{" "}
              {research.snapshot.source_cutoff.slice(0, 4)}
            </p>
            <h1 className="mt-3 text-[2.5rem] font-semibold leading-[1.05] tracking-[-0.04em] sm:text-5xl">
              Vibe Security Radar
            </h1>
            <p className="mt-4 max-w-xl text-lg leading-7 text-muted-foreground">
              {caseCount} AI-contributed vulnerabilities cataloged and
              evidence-linked across their full causal chain.
            </p>
            <form
              action="/cves/"
              method="get"
              className="mt-6 flex max-w-xl gap-2"
            >
              <label className="relative min-w-0 flex-1">
                <span className="sr-only">Search findings</span>
                <Search
                  aria-hidden="true"
                  className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
                />
                <input
                  type="search"
                  name="q"
                  placeholder="CVE, GHSA, repository or keyword"
                  className="h-10 w-full rounded-md border border-input bg-card pl-9 pr-3 text-sm text-foreground outline-none focus:border-primary focus:ring-2 focus:ring-primary/15"
                />
              </label>
              <button
                type="submit"
                className="h-10 shrink-0 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90"
              >
                Search
              </button>
            </form>
            <p className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
              <Link
                href="/cves"
                className="font-medium text-primary hover:underline"
              >
                Browse all {caseCount} findings →
              </Link>
              <a
                href="https://github.com/HQ1995/vibe-security-radar"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-foreground"
              >
                Star on GitHub ↗
              </a>
              <Link
                href="/about"
                className="text-muted-foreground hover:text-foreground"
              >
                How we verify
              </Link>
            </p>
            <dl className="mt-8 grid grid-cols-2 gap-x-8 gap-y-5 border-t border-border pt-6">
              <HeadlineStat
                label="Findings"
                value={formatCount(caseCount)}
                detail="AI-contributed vulnerabilities"
              />
              <HeadlineStat
                label="Covered advisories"
                value={formatCount(research.snapshot.ledger_total ?? 0)}
                detail={`${formatMonthShort(coveredFrom)} – ${formatMonthShort(coveredTo)}`}
              />
              <HeadlineStat
                label="Fully researched"
                value={formatCount(research.snapshot.ledger_reviewed ?? 0)}
                detail={`${Math.round(((research.snapshot.ledger_reviewed ?? 0) / Math.max(1, research.snapshot.ledger_total ?? 0)) * 100)}% of covered advisories so far`}
              />
              <HeadlineStat
                label="Projects"
                value={formatCount(repositories.length)}
                detail={`Most represented project: ${topRepository?.label ?? "—"}`}
              />
            </dl>
          </div>
          <OverviewPanel
            timeline={timeline}
            tools={aiTools.items}
            causes={causes}
            sourceCutoff={research.snapshot.source_cutoff}
          />
        </div>
      </header>

      <div className="page-container">
        <div className="py-10 sm:py-14">
          <TrendChart
            data={timeline}
            caseCount={caseCount}
            datedCount={research.snapshot.exact_publication_dates}
            unknownDateCount={research.snapshot.unknown_publication_dates}
            sourceCutoff={research.snapshot.source_cutoff}
          />
        </div>

        <section
          id="patterns"
          className="scroll-mt-20 border-t border-border py-10 sm:py-14"
        >
          <h2 className="text-xl font-semibold tracking-[-0.02em]">Patterns</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Who, where, and why: the AI tools involved, what went wrong, and
            where the vulnerable code lives.
          </p>
          <div className="mt-8 grid gap-x-14 gap-y-12 md:grid-cols-2">
            <AiToolComparison />
            <DistributionBars
              title="Root causes"
              description="One root-cause category per finding."
              items={causes.map((item) => ({
                ...item,
                muted: item.key === "other_ambiguous",
                href: findingsHref("cause", item.key),
                hint: item.definition,
              }))}
            />
            <DistributionBars
              title="Languages"
              description="Where the vulnerable code lives, including findings whose language is not yet recorded."
              iconMode="language"
              items={languages.slice(0, 6).map((item) => ({
                ...item,
                href:
                  item.label === "Unknown"
                    ? undefined
                    : findingsHref("language", item.label),
              }))}
            />
            <DistributionBars
              title="Repositories"
              description="Repositories with the most findings. Filter the full index by repository in Findings."
              items={repositories.slice(0, 6).map((item) => ({
                ...item,
                href: findingsHref("repository", item.label),
              }))}
            />
          </div>
        </section>

        <section
          id="cases"
          className="scroll-mt-20 border-t border-border py-10 sm:py-14"
        >
          <div className="flex flex-wrap items-baseline justify-between gap-3">
            <div>
              <h2 className="text-xl font-semibold tracking-[-0.02em]">
                Featured findings
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                See the vulnerable code and fix: one recent example of each kind
                of AI contribution.
              </p>
            </div>
            <Link
              href="/cves"
              className="text-sm font-medium text-primary hover:underline"
            >
              Browse all {caseCount} findings →
            </Link>
          </div>
          <ol className="mt-4 divide-y divide-border border-y border-border">
            {featuredCases.map((item) => (
              <FindingRow key={item.case_id} item={item} />
            ))}
          </ol>
        </section>

        <section className="border-t border-border py-10 sm:py-14">
          <div className="grid gap-12 lg:grid-cols-2 lg:gap-16">
            <div>
              <h2 className="text-lg font-semibold">Media coverage</h2>
              <div className="mt-4 divide-y divide-border border-y border-border">
                {MEDIA_COVERAGE.map((item) => (
                  <a
                    key={item.href}
                    href={item.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="group block py-4"
                  >
                    <p className="text-xs text-muted-foreground">
                      {item.source} · {item.date}
                    </p>
                    <p className="mt-1 font-medium leading-6 group-hover:text-primary">
                      {item.title} ↗
                    </p>
                  </a>
                ))}
              </div>
            </div>

            <div>
              <h2 className="text-lg font-semibold">Q&amp;A</h2>
              <dl className="mt-4 divide-y divide-border border-y border-border">
                {faqItems.map((item) => (
                  <div key={item.question} className="py-4">
                    <dt className="font-medium">{item.question}</dt>
                    <dd className="mt-1 text-sm leading-6 text-muted-foreground">
                      {item.answer}
                    </dd>
                  </div>
                ))}
              </dl>
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
