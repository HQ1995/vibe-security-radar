import {
  buildResearchTimeline,
  getAiToolDistribution,
  getCauseDistribution,
  getResearchCases,
  getResearchTimeline,
  type ResearchCase,
  type ResearchMonth,
} from "@/lib/research-data";

export type TopicKind = "tool" | "cause";

export interface Topic {
  readonly kind: TopicKind;
  readonly key: string;
  readonly slug: string;
  readonly label: string;
  readonly definition?: string;
  readonly cases: readonly ResearchCase[];
}

const MIN_FINDINGS = 5;
const UNPAGED_CAUSES = new Set(["other_ambiguous"]);
const BASE_PATH: Record<TopicKind, string> = {
  tool: "/tools",
  cause: "/causes",
};

let cache: Record<TopicKind, readonly Topic[]> | null = null;

function byNewest(a: ResearchCase, b: ResearchCase): number {
  return (
    (b.published_at ?? "").localeCompare(a.published_at ?? "") ||
    a.case_id.localeCompare(b.case_id)
  );
}

function build(): Record<TopicKind, readonly Topic[]> {
  const cases = getResearchCases();
  const tools = getAiToolDistribution()
    .items.filter((item) => item.count >= MIN_FINDINGS)
    .map((item) => ({
      kind: "tool" as const,
      key: item.key,
      slug: item.key.replaceAll("_", "-"),
      label: item.label,
      cases: cases
        .filter(
          (other) =>
            other.ai_provenance.coverage === "complete" &&
            other.ai_provenance.family === item.key,
        )
        .sort(byNewest),
    }));
  const causes = getCauseDistribution()
    .filter(
      (item) => item.count >= MIN_FINDINGS && !UNPAGED_CAUSES.has(item.key),
    )
    .map((item) => ({
      kind: "cause" as const,
      key: item.key,
      slug: item.key.replaceAll("_", "-"),
      label: item.label,
      definition: item.definition,
      cases: cases
        .filter(
          (other) => (other.cause_category ?? "other_ambiguous") === item.key,
        )
        .sort(byNewest),
    }));
  return { tool: tools, cause: causes };
}

export function getTopics(kind: TopicKind): readonly Topic[] {
  cache ??= build();
  return cache[kind];
}

export function getTopic(kind: TopicKind, slug: string): Topic | null {
  return getTopics(kind).find((topic) => topic.slug === slug) ?? null;
}

export function topicPath(topic: Pick<Topic, "kind" | "slug">): string {
  return `${BASE_PATH[topic.kind]}/${topic.slug}`;
}

export function topicHref(kind: TopicKind, key: string | null): string | null {
  const topic = getTopics(kind).find((item) => item.key === key);
  return topic ? topicPath(topic) : null;
}

export function topicTimeline(cases: readonly ResearchCase[]): ResearchMonth[] {
  const counts = new Map(
    buildResearchTimeline(cases).map((entry) => [entry.month, entry.count]),
  );
  return getResearchTimeline().map((entry) => ({
    month: entry.month,
    count: counts.get(entry.month) ?? 0,
  }));
}
