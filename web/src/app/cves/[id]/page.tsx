import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ExternalLink } from "lucide-react";

import { BackToFindings } from "@/components/back-to-findings";
import { ResearchCaseTable } from "@/components/research-case-table";
import { toFindingRow } from "@/lib/research-format";
import { SeverityLabel } from "@/components/severity-label";
import { formatPublished } from "@/lib/commit-utils";
import { CanonicalCaseEvidence } from "@/components/canonical-case-evidence";
import {
  formatCaseLabel,
  getCaseHeadline,
  getResearchCaseById,
  preferredCaseId,
  getResearchCases,
  getCauseCategoryLabel,
  getResearchLabels,
  type ResearchCase,
} from "@/lib/research-data";

export const dynamicParams = false;

const SHARE_IMAGE = {
  url: "/opengraph-image",
  width: 1200,
  height: 630,
  alt: "Vibe Security Radar",
};
export function generateStaticParams() {
  const ids = new Set<string>();
  for (const item of getResearchCases()) {
    for (const id of [item.case_id, ...item.aliases]) {
      if (/^(?:GHSA-[A-Z0-9-]+|CVE-\d{4}-\d{4,7})$/i.test(id)) {
        ids.add(id);
      }
    }
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
  if (!item) return { title: "Finding not found" };
  const canonicalId = preferredCaseId(item);
  const headline = getCaseHeadline(item);
  const description =
    headline.length > 200
      ? `${headline.slice(0, 197).replace(/\s+\S*$/, "")}…`
      : headline;
  const title = item.repository
    ? `${canonicalId} in ${item.repository}`
    : canonicalId;
  return {
    title,
    description,
    alternates: { canonical: `/cves/${canonicalId}` },
    openGraph: {
      title,
      description,
      url: `/cves/${canonicalId}`,
      type: "article",
      images: [SHARE_IMAGE],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: [SHARE_IMAGE],
    },
  };
}

function Breadcrumb({
  id,
  item,
}: {
  readonly id: string;
  readonly item: ResearchCase;
}) {
  return (
    <nav
      aria-label="Breadcrumb"
      className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm"
    >
      <BackToFindings />
      <span aria-hidden="true" className="text-muted-foreground">
        /
      </span>
      <span className="break-all font-mono text-foreground">
        {formatCaseLabel(item, id)}
      </span>
    </nav>
  );
}

function FindingMeta({ item }: { readonly item: ResearchCase }) {
  const repository = item.repository;
  const siblings = repository
    ? getResearchCases().filter((other) => other.repository === repository)
        .length
    : 0;
  return (
    <>
      {item.severity ? (
        <>
          <span aria-hidden="true">·</span>
          <SeverityLabel severity={item.severity} />
        </>
      ) : null}
      <span aria-hidden="true">·</span>
      <span>
        {item.published_at
          ? `Published ${formatPublished(item.published_at)}`
          : "Publication date unavailable"}
        {repository ? (
          <>
            {" in "}
            <a
              href={`https://github.com/${repository}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 break-all font-medium text-foreground hover:text-primary hover:underline"
            >
              {repository}
              <ExternalLink className="h-3 w-3 text-muted-foreground" />
            </a>
          </>
        ) : null}
      </span>
      {repository && siblings > 1 ? (
        <>
          <span aria-hidden="true">·</span>
          <Link
            href={`/cves?${new URLSearchParams({ repository })}`}
            className="whitespace-nowrap text-primary hover:underline"
          >
            All {siblings} findings in this repository
          </Link>
        </>
      ) : null}
    </>
  );
}

function hasRelated(item: ResearchCase): boolean {
  return getResearchCases().some(
    (other) =>
      other.case_id !== item.case_id &&
      (item.repository
        ? other.repository === item.repository ||
          other.cause_category === item.cause_category
        : other.cause_category === item.cause_category),
  );
}

function RelatedFindings({ item }: { readonly item: ResearchCase }) {
  const others = getResearchCases().filter(
    (other) => other.case_id !== item.case_id,
  );
  const sameRepository = item.repository
    ? others.filter((other) => other.repository === item.repository)
    : [];
  const pool = sameRepository.length
    ? sameRepository
    : others.filter((other) => other.cause_category === item.cause_category);
  if (!pool.length) return null;
  const related = [...pool]
    .sort((a, b) => (b.published_at ?? "").localeCompare(a.published_at ?? ""))
    .slice(0, 5)
    .map(toFindingRow);
  const [title, href] = sameRepository.length
    ? [
        `More findings in ${item.repository}`,
        `/cves?${new URLSearchParams({ repository: item.repository! })}`,
      ]
    : [
        `More ${getCauseCategoryLabel(item.cause_category)} findings`,
        `/cves?${new URLSearchParams({ cause: item.cause_category ?? "" })}`,
      ];
  return (
    <section
      className="scroll-mt-20 border-t border-border pt-8"
      aria-labelledby="related"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-3 border-b border-border pb-3">
        <h2 id="related" className="scroll-mt-20 text-base font-semibold">
          {title}
        </h2>
        {pool.length > related.length ? (
          <Link href={href} className="text-sm text-primary hover:underline">
            All {pool.length} →
          </Link>
        ) : null}
      </div>
      <ResearchCaseTable cases={related} labels={getResearchLabels()} />
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

  return (
    <main className="page-container space-y-6 py-8 sm:py-10">
      <Breadcrumb id={id} item={item} />

      <CanonicalCaseEvidence
        item={item}
        displayId={id}
        meta={<FindingMeta item={item} />}
        extraLinks={[
          ...(hasRelated(item)
            ? [{ id: "related", label: "Related findings" }]
            : []),
          ...(references.length
            ? [{ id: "sources", label: "Advisory references" }]
            : []),
        ]}
      />

      <RelatedFindings item={item} />

      {references.length > 0 ? (
        <section
          className="border-t border-border pt-8"
          aria-labelledby="sources"
        >
          <h2 id="sources" className="scroll-mt-20 text-base font-semibold">
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
