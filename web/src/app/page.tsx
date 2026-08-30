import Image from "next/image";
import Link from "next/link";
import { CalendarDays } from "lucide-react";

import { AiToolBaseRate } from "@/components/ai-tool-base-rate";
import { DistributionBars } from "@/components/distribution-bars";
import { ToolIcon } from "@/components/tool-icon";
import { TrendChart } from "@/components/trend-chart";
import { formatMonthShort } from "@/lib/month-utils";
import {
  formatContributionClass,
  getAiFamilyIconKey,
  getAiToolDistribution,
  getCauseDistribution,
  getCauseCategoryLabel,
  formatCaseLabel,
  formatCount,
  getCaseSummary,
  preferredCaseId,
  getLanguageDistribution,
  getRepositoryDistribution,
  getResearchCases,
  getResearchSnapshot,
  getResearchTimeline,
} from "@/lib/research-data";

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
    const pool = [...getResearchCases()].sort(
      (a, b) => (b.published_at ?? "").localeCompare(a.published_at ?? ""),
    );
    const picked: typeof pool = [];
    const classOrder = [
      "AI_INCOMPLETE_REMEDIATION",
      "AI_DIRECT_ROOT",
      "AI_CAUSAL_CONTRIBUTOR",
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
  const peak = timeline.reduce(
    (best, item) => (item.count > best.count ? item : best),
    timeline[0] ?? { month: "", count: 0 },
  );
  const topTool = aiTools.items[0];
  const topRepository = repositories[0];
  const coveredFrom = (research.snapshot.coverage_from ?? "2025-05-01").slice(
    0,
    7,
  );
  const coveredTo = (research.snapshot.coverage_to ?? "2026-08-16").slice(0, 7);

  return (
    <main>
      <header className="border-b border-border">
        <div className="mx-auto w-full max-w-[96rem] px-4 py-5 sm:px-6 sm:py-7 2xl:px-8 min-[1920px]:max-w-[112rem] min-[2400px]:max-w-[128rem]">
          <div className="grid gap-7 xl:grid-cols-[minmax(24rem,0.72fr)_minmax(0,1.28fr)] xl:items-start xl:gap-10 2xl:grid-cols-[minmax(27rem,0.68fr)_minmax(0,1.32fr)] 2xl:gap-14">
            <div className="md:grid md:grid-cols-[minmax(0,1.25fr)_minmax(15rem,0.75fr)] md:gap-8 xl:block xl:py-5">
              <div>
                <p className="section-kicker">
                  Georgia Tech SSLab · security research
                </p>
                <h1 className="mt-3 text-balance text-[clamp(2rem,1.6rem_+_1.8vw,3rem)] font-semibold leading-[1.08] tracking-[-0.04em]">
                  Vibe Security Radar
                </h1>
                <p className="mt-3 max-w-xl text-lg font-medium leading-7 tracking-[-0.02em] sm:text-xl sm:leading-8">
                  {caseCount} AI-contributed vulnerabilities cataloged and
                  evidence-linked across their full causal chain.
                </p>
              </div>
              <div className="mt-6 md:mt-0 xl:mt-6">
                <div className="flex flex-wrap items-center gap-3 border-t border-border pt-4 text-sm">
                  <Link
                    href="/cves"
                    className="inline-flex min-h-10 w-full items-center justify-center bg-primary px-4 font-semibold text-primary-foreground hover:opacity-90 sm:w-auto"
                  >
                    Browse all {caseCount} findings →
                  </Link>
                  <a
                    href="https://github.com/HQ1995/vibe-security-radar"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex min-h-10 w-full items-center justify-center border border-foreground px-4 font-semibold text-foreground hover:bg-foreground hover:text-background sm:w-auto"
                  >
                    Star on GitHub ↗
                  </a>
                  <Link
                    href="/about"
                    className="px-1 text-muted-foreground hover:text-foreground"
                  >
                    How we verify
                  </Link>
                </div>
                <dl className="mt-6 divide-y divide-border border-y border-border text-sm">
                  <div className="flex items-start justify-between gap-4 py-2.5">
                    <dt className="flex items-center gap-2 text-muted-foreground">
                      Cataloged findings
                    </dt>
                    <dd className="text-right font-semibold">
                      {formatCount(caseCount)} findings
                    </dd>
                  </div>
                  <div className="flex items-start justify-between gap-4 py-2.5">
                    <dt className="text-muted-foreground">
                      Covered advisories
                      <span className="block text-xs font-normal">
                        {coveredFrom} – {coveredTo}
                      </span>
                    </dt>
                    <dd className="text-right font-semibold">
                      {formatCount(research.snapshot.ledger_total ?? 0)}{" "}
                      advisories
                      <span className="block text-xs font-normal text-muted-foreground">
                        {formatCount(research.snapshot.ledger_reviewed ?? 0)}{" "}
                        completed ·{" "}
                        {formatCount(research.snapshot.ledger_not_started ?? 0)}{" "}
                        not started
                      </span>
                    </dd>
                  </div>
                  <div className="flex items-start justify-between gap-4 py-2.5">
                    <dt className="flex items-center gap-2 text-muted-foreground">
                      <CalendarDays
                        className="h-4 w-4 shrink-0 text-primary"
                        aria-hidden
                      />
                      Peak advisory month
                    </dt>
                    <dd className="text-right font-semibold">
                      {peak.month
                        ? formatMonthShort(peak.month)
                        : "Unavailable"}
                      {" · "}
                      {peak.count} cases
                    </dd>
                  </div>
                  <div className="flex items-start justify-between gap-4 py-2.5">
                    <dt className="flex items-center gap-2 text-muted-foreground">
                      {topTool ? (
                        <ToolIcon
                          tool={getAiFamilyIconKey(topTool.key)}
                          size={16}
                        />
                      ) : null}
                      Most common AI tool
                    </dt>
                    <dd className="text-right font-semibold">
                      {topTool?.label ?? "Unavailable"}
                      {" · "}
                      {topTool?.count ?? 0} of {research.snapshot.case_count}
                    </dd>
                  </div>
                  <div className="flex items-start justify-between gap-4 py-2.5">
                    <dt className="flex items-center gap-2 text-muted-foreground">
                      {topRepository ? (
                        <Image
                          src={`https://github.com/${topRepository.label.split("/")[0]}.png?size=40`}
                          alt=""
                          width={18}
                          height={18}
                          className="shrink-0 rounded-full"
                        />
                      ) : null}
                      Most represented project
                    </dt>
                    <dd className="text-right font-semibold">
                      {topRepository?.label ?? "Unavailable"}
                      <span className="block whitespace-nowrap 2xl:inline">
                        <span className="hidden 2xl:inline"> · </span>
                        {topRepository?.count ?? 0} of{" "}
                        {research.snapshot.case_count}
                      </span>
                    </dd>
                  </div>
                </dl>
              </div>
            </div>
            <TrendChart
              data={timeline}
              caseCount={research.snapshot.case_count}
              datedCount={research.snapshot.exact_publication_dates}
              unknownDateCount={research.snapshot.unknown_publication_dates}
              sourceCutoff={research.snapshot.source_cutoff}
            />
          </div>
        </div>
      </header>

      <div className="mx-auto w-full max-w-[96rem] px-4 sm:px-6 2xl:px-8 min-[1920px]:max-w-[112rem] min-[2400px]:max-w-[128rem]">
        <section className="py-9 sm:py-11">
          <p className="section-kicker">Patterns</p>
          <h2 className="mt-2 text-2xl font-semibold tracking-[-0.025em]">
            Who, where, and why
          </h2>
          <div className="mt-7 grid gap-8 sm:grid-cols-2 2xl:grid-cols-6">
            <div className="grid min-w-0 gap-8 sm:col-span-2 sm:grid-cols-2 2xl:col-span-3">
              <DistributionBars
                eyebrow="AI tooling"
                title="Who appears on the candidate change"
                description={`${aiTools.coverage.complete} of ${aiTools.total} findings name a tool on every candidate commit.`}
                items={aiTools.items.map((item) => ({
                  ...item,
                  iconKey: getAiFamilyIconKey(item.key),
                }))}
              />
              <AiToolBaseRate />
            </div>
            <DistributionBars
              eyebrow="Root causes"
              title="What went wrong"
              description="One root-cause category per finding."
              items={causes.map((item) => ({
                ...item,
                muted: item.key === "other_ambiguous",
              }))}
            />
            <DistributionBars
              eyebrow="Languages"
              title="Where the vulnerable code lives"
              description="Top languages, including findings whose language is not yet recorded."
              iconMode="language"
              items={languages.slice(0, 6)}
            />
            <DistributionBars
              eyebrow="Projects"
              title="Repositories with the most findings"
              description="Top repositories; filter the full index in Findings."
              items={repositories.slice(0, 6)}
            />
          </div>
        </section>

        <section
          id="cases"
          className="scroll-mt-20 border-t border-border py-9 sm:py-11"
        >
          <div className="mb-7 flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
            <div>
              <p className="section-kicker">Featured findings</p>
              <h2 className="mt-3 text-3xl font-semibold tracking-[-0.035em]">
                See the vulnerable code and fix
              </h2>
            </div>
            <Link href="/cves" className="text-sm text-primary hover:underline">
              Browse all {research.snapshot.case_count} findings →
            </Link>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            {featuredCases.map((item) => {
              const id = preferredCaseId(item);
              return (
                <article
                  key={item.case_id}
                  className="border border-border bg-card p-5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="font-mono text-xs text-primary">
                      {formatCaseLabel(item, id)}
                    </p>
                    <p className="font-mono text-[10px] text-muted-foreground">
                      {item.published_at?.slice(0, 10) ?? "Date unavailable"}
                    </p>
                  </div>
                  <p className="mt-3 text-xs text-muted-foreground">
                    {item.repository ?? "Repository not recorded"}
                  </p>
                  <h3 className="mt-3 text-lg font-semibold leading-7">
                    {getCaseSummary(item)}
                  </h3>
                  <p className="mt-3 text-xs leading-5 text-muted-foreground">
                    {getCauseCategoryLabel(item.cause_category)} ·{" "}
                    {formatContributionClass(item.contribution_class)}
                  </p>
                  <Link
                    href={`/cves/${id}`}
                    className="mt-5 inline-block text-sm font-medium text-primary hover:underline"
                  >
                    See root cause and fix →
                  </Link>
                </article>
              );
            })}
          </div>
        </section>

        <section className="border-t border-border py-9 sm:py-11">
          <div className="grid gap-12 lg:grid-cols-2 lg:gap-16">
            <div>
              <p className="section-kicker">Media coverage</p>
              <div className="mt-5 divide-y divide-border border-y border-border">
                {MEDIA_COVERAGE.map((item) => (
                  <a
                    key={item.href}
                    href={item.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block py-4 hover:text-primary"
                  >
                    <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                      {item.source} · {item.date}
                    </p>
                    <p className="mt-1.5 text-sm font-medium leading-6">
                      {item.title} ↗
                    </p>
                  </a>
                ))}
              </div>
            </div>

            <div>
              <p className="section-kicker">Q&amp;A</p>
              <dl className="mt-5 divide-y divide-border border-y border-border">
                {faqItems.map((item) => (
                  <div key={item.question} className="py-4">
                    <dt className="text-sm font-medium">{item.question}</dt>
                    <dd className="mt-1.5 text-sm leading-6 text-muted-foreground">
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
