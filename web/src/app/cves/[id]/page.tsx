import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ExternalLink } from "lucide-react";

import { BackToFindings } from "@/components/back-to-findings";
import { formatPublished } from "@/lib/commit-utils";
import { CanonicalCaseEvidence } from "@/components/canonical-case-evidence";
import {
  formatCaseLabel,
  getCaseHeadline,
  getResearchCaseById,
  preferredCaseId,
  getResearchCases,
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
  const owner = repository?.split("/")[0];
  const siblings = repository
    ? getResearchCases().filter((other) => other.repository === repository)
        .length
    : 0;
  return (
    <>
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
              {owner ? (
                // eslint-disable-next-line @next/next/no-img-element
                <img
                  src={`https://github.com/${owner}.png?size=32`}
                  alt=""
                  width={14}
                  height={14}
                  loading="lazy"
                  className="h-3.5 w-3.5 rounded-full"
                />
              ) : null}
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
      />

      {references.length > 0 ? (
        <section
          className="border-t border-border pt-8"
          aria-labelledby="sources"
        >
          <h2 id="sources" className="text-base font-semibold">
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
