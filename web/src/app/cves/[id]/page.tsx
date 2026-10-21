import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ExternalLink } from "lucide-react";

import { BackToFindings } from "@/components/back-to-findings";
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

function PageHeader({
  id,
  item,
}: {
  readonly id: string;
  readonly item: ResearchCase;
}) {
  const repository = item.repository;
  const owner = repository?.split("/")[0];
  const repoUrl = repository ? `https://github.com/${repository}` : undefined;
  const avatarUrl = owner
    ? `https://github.com/${owner}.png?size=32`
    : undefined;
  const siblings = repository
    ? getResearchCases().filter((other) => other.repository === repository)
        .length
    : 0;

  return (
    <header>
      <BackToFindings />
      <h1 className="mt-4 break-words font-mono text-xl font-semibold tracking-tight sm:text-2xl">
        {formatCaseLabel(item, id)}
      </h1>
      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
        {repoUrl ? (
          <a
            href={repoUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex min-w-0 items-center gap-1.5 break-all font-medium text-foreground transition-colors hover:text-primary"
          >
            {avatarUrl ? (
              // eslint-disable-next-line @next/next/no-img-element
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
        {repository && siblings > 1 ? (
          <Link
            href={`/cves?${new URLSearchParams({ repository })}`}
            className="whitespace-nowrap text-primary hover:underline"
          >
            All {siblings} findings in this repository →
          </Link>
        ) : null}
      </div>
    </header>
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
    <main className="page-container space-y-10 py-8 sm:py-10">
      <PageHeader id={id} item={item} />

      <CanonicalCaseEvidence item={item} displayId={id} />

      {references.length > 0 ? (
        <section
          className="border-t border-border pt-8"
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
