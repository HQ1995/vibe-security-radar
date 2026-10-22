import Link from "next/link";

import { DistributionBars } from "@/components/distribution-bars";
import { HeadlineStat } from "@/components/headline-stat";
import { BreadcrumbJsonLd } from "@/components/json-ld";
import { MonthlyBars } from "@/components/monthly-bars";
import { ResearchCaseTable } from "@/components/research-case-table";
import { ToolIcon } from "@/components/tool-icon";
import { formatDay } from "@/lib/month-utils";
import {
  formatContributionClass,
  getAiFamilyIconKey,
  getAiToolLabel,
  getCauseCategoryLabel,
  getResearchLabels,
  getResearchSnapshot,
  type ResearchCase,
} from "@/lib/research-data";
import { severityLevel, toFindingRow } from "@/lib/research-format";
import { topicPath, topicTimeline, type Topic } from "@/lib/topics";

const KIND_LABEL = { tool: "AI tool", cause: "Root cause" } as const;
const LIST_LIMIT = 50;

export function topicHeading(topic: Topic): string {
  return topic.kind === "tool"
    ? `Vulnerabilities in code written with ${topic.label}`
    : `${topic.label} in AI-generated code`;
}

function tally(
  cases: readonly ResearchCase[],
  keyOf: (item: ResearchCase) => string,
): { key: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const item of cases) {
    const key = keyOf(item);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}

function projectsOf(cases: readonly ResearchCase[]) {
  return tally(
    cases.filter((item) => item.repository),
    (item) => item.repository!,
  );
}

function topCause(topic: Topic): string | null {
  const top = tally(
    topic.cases,
    (item) => item.cause_category ?? "other_ambiguous",
  ).find((entry) => entry.key !== "other_ambiguous");
  return top ? getCauseCategoryLabel(top.key).toLowerCase() : null;
}

export function topicSummary(topic: Topic): string {
  const n = topic.cases.length;
  const projects = projectsOf(topic.cases).length;
  if (topic.kind === "tool") {
    const cause = topCause(topic);
    return `${n} published CVEs and GitHub advisories where a change made with ${topic.label} introduced the flaw, exposed the vulnerable path, or left a security fix incomplete, across ${projects} projects.${cause ? ` Most common root cause: ${cause}.` : ""}`;
  }
  return `${topic.definition ?? topic.label} ${n} published CVEs and GitHub advisories in this category trace back to an AI-assisted code change, across ${projects} projects.`;
}

export function topicDescription(topic: Topic): string {
  const n = topic.cases.length;
  const projects = projectsOf(topic.cases).length;
  if (topic.kind === "tool") {
    const cause = topCause(topic);
    return `${n} published CVEs and GitHub advisories traced to code written with ${topic.label}, across ${projects} projects.${cause ? ` Most common root cause: ${cause}.` : ""}`;
  }
  return `${n} published CVEs and GitHub advisories where AI-generated code caused ${topic.label.toLowerCase()} flaws, across ${projects} projects. ${topic.definition ?? ""}`.trim();
}

function filterHref(topic: Topic, extra: Record<string, string> = {}): string {
  const base: Record<string, string> =
    topic.kind === "tool" ? { tool: topic.label } : { cause: topic.key };
  return `/cves?${new URLSearchParams({ ...base, ...extra })}`;
}

export function TopicPage({ topic }: { readonly topic: Topic }) {
  const research = getResearchSnapshot();
  const total = research.snapshot.case_count;
  const cases = topic.cases;
  const projects = projectsOf(cases);
  const scored = cases.filter((item) => severityLevel(item.severity));
  const severe = scored.filter((item) =>
    ["CRITICAL", "HIGH"].includes(severityLevel(item.severity) ?? ""),
  ).length;
  const latest = cases.find((item) => item.published_at);
  const heading = topicHeading(topic);
  const breakdown =
    topic.kind === "tool"
      ? {
          title: "Root causes",
          description: `What went wrong in findings that involve ${topic.label}.`,
          items: tally(
            cases,
            (item) => item.cause_category ?? "other_ambiguous",
          )
            .sort(
              (a, b) =>
                Number(a.key === "other_ambiguous") -
                  Number(b.key === "other_ambiguous") || b.count - a.count,
            )
            .map((entry) => ({
              label: getCauseCategoryLabel(entry.key),
              count: entry.count,
              muted: entry.key === "other_ambiguous",
              href: filterHref(topic, { cause: entry.key }),
            })),
          iconMode: "tool" as const,
        }
      : {
          title: "AI tools",
          description: "Which AI tool made the contributing change.",
          items: tally(cases, (item) => getAiToolLabel(item)).map((entry) => {
            const sample = cases.find(
              (item) => getAiToolLabel(item) === entry.key,
            );
            return {
              label: entry.key,
              count: entry.count,
              iconKey: getAiFamilyIconKey(
                sample?.ai_provenance.coverage === "complete"
                  ? sample.ai_provenance.family
                  : null,
              ),
              href: filterHref(topic, { tool: entry.key }),
            };
          }),
          iconMode: "tool" as const,
        };
  const contributions = tally(cases, (item) => item.contribution_class).map(
    (entry) => ({
      label: formatContributionClass(entry.key),
      count: entry.count,
      href: filterHref(topic, { contribution: entry.key }),
    }),
  );
  const languages = tally(
    cases,
    (item) => item.repository_metadata.language || "Unknown",
  )
    .slice(0, 6)
    .map((entry) => ({
      label: entry.key,
      count: entry.count,
      href:
        entry.key === "Unknown"
          ? undefined
          : filterHref(topic, { language: entry.key }),
    }));

  return (
    <main className="page-container py-8 sm:py-12">
      <BreadcrumbJsonLd
        items={[
          { name: "Findings", path: "/cves/" },
          { name: topic.label, path: `${topicPath(topic)}/` },
        ]}
      />
      <nav
        aria-label="Breadcrumb"
        className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm"
      >
        <Link href="/cves" className="text-primary hover:underline">
          Findings
        </Link>
        <span aria-hidden="true" className="text-muted-foreground">
          /
        </span>
        <span className="text-muted-foreground">{KIND_LABEL[topic.kind]}</span>
        <span aria-hidden="true" className="text-muted-foreground">
          /
        </span>
        <span className="text-foreground">{topic.label}</span>
      </nav>

      <div className="mt-6 grid gap-10 lg:grid-cols-[minmax(0,1fr)_minmax(0,24rem)] lg:gap-14">
        <header className="min-w-0">
          <h1 className="flex items-center gap-3 text-3xl font-semibold tracking-[-0.03em] text-balance">
            {topic.kind === "tool" ? (
              <span aria-hidden="true" className="shrink-0">
                <ToolIcon tool={getAiFamilyIconKey(topic.key)} size={28} />
              </span>
            ) : null}
            <span>{heading}</span>
          </h1>
          <p className="mt-3 max-w-3xl text-base leading-7 text-muted-foreground">
            {topicSummary(topic)}
          </p>
          <dl className="mt-6 grid grid-cols-2 gap-x-8 gap-y-5 border-t border-border pt-6 sm:grid-cols-4">
            <HeadlineStat
              label="Findings"
              value={String(cases.length)}
              detail={`${Math.round((cases.length / Math.max(1, total)) * 100)}% of all ${total}`}
            />
            <HeadlineStat
              label="Projects"
              value={String(projects.length)}
              detail={
                projects[0] && projects[0].count > 1
                  ? `Most: ${projects[0].key} (${projects[0].count})`
                  : "One finding per project"
              }
            />
            <HeadlineStat
              label="Critical or high"
              value={String(severe)}
              detail={`of ${scored.length} with a severity score`}
            />
            <HeadlineStat
              label="Latest advisory"
              value={
                latest?.published_at ? formatDay(latest.published_at) : "—"
              }
              detail={`Data through ${formatDay(research.snapshot.source_cutoff)}`}
            />
          </dl>
          <p className="mt-6 text-sm">
            <Link
              href={filterHref(topic)}
              className="font-medium text-primary hover:underline"
            >
              Search and filter these findings →
            </Link>
          </p>
        </header>

        <section
          aria-labelledby="topic-monthly"
          className="min-w-0 border-t border-border pt-5 lg:border-l lg:border-t-0 lg:pl-10 lg:pt-0"
        >
          <h2 id="topic-monthly" className="text-sm font-semibold">
            Findings per month
          </h2>
          <MonthlyBars
            timeline={topicTimeline(cases)}
            sourceCutoff={research.snapshot.source_cutoff}
          />
          <p className="mt-3 text-[11px] leading-4 text-muted-foreground">
            By advisory publication month. The latest month is partial.
          </p>
        </section>
      </div>

      <div className="mt-12 grid gap-x-14 gap-y-10 border-t border-border pt-10 md:grid-cols-2 lg:grid-cols-3">
        <DistributionBars
          title={breakdown.title}
          description={breakdown.description}
          items={breakdown.items}
          iconMode={breakdown.iconMode}
        />
        <DistributionBars
          title="How AI contributed"
          description="Whether the AI-assisted change introduced the flaw, widened exposure, or left a fix incomplete."
          items={contributions}
        />
        <DistributionBars
          title="Languages"
          description="Primary language of the affected repository."
          iconMode="language"
          items={languages}
        />
      </div>

      <section aria-labelledby="topic-findings" className="mt-12">
        <div className="flex flex-wrap items-baseline justify-between gap-3 border-b border-border pb-3">
          <h2
            id="topic-findings"
            className="text-xl font-semibold tracking-[-0.02em]"
          >
            {cases.length > LIST_LIMIT
              ? `Latest ${LIST_LIMIT} of ${cases.length} findings`
              : `All ${cases.length} findings`}
          </h2>
          {cases.length > LIST_LIMIT ? (
            <Link
              href={filterHref(topic)}
              className="text-sm text-primary hover:underline"
            >
              View all {cases.length} →
            </Link>
          ) : (
            <span className="text-sm text-muted-foreground">Newest first</span>
          )}
        </div>
        <ResearchCaseTable
          cases={cases.slice(0, LIST_LIMIT).map(toFindingRow)}
          labels={getResearchLabels()}
        />
        {cases.length > LIST_LIMIT ? (
          <p className="mt-4 text-sm">
            <Link
              href={filterHref(topic)}
              className="font-medium text-primary hover:underline"
            >
              Search all {cases.length} findings in the index →
            </Link>
          </p>
        ) : null}
      </section>
    </main>
  );
}
