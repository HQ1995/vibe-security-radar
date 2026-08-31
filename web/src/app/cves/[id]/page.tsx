import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, ExternalLink } from "lucide-react";
import { stripMarkdown } from "@/lib/markdown-utils";

import { CanonicalCaseEvidence } from "@/components/canonical-case-evidence";
import {
  formatCaseLabel,
  getResearchCaseById,
  preferredCaseId,
  getResearchCases,
  type ResearchCase,
} from "@/lib/research-data";

export const dynamicParams = false;
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
  const description = stripMarkdown(
    item.description ?? "Mechanism-level evidence for " + id + ".",
  ).slice(0, 200);
  const canonicalId = preferredCaseId(item);
  const title = `${canonicalId} — AI contribution evidence`;
  return {
    title,
    description,
    alternates: { canonical: `/cves/${canonicalId}` },
    openGraph: { title, description, url: `/cves/${canonicalId}` },
    twitter: { title, description },
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
  const avatarUrl = owner ? `https://github.com/${owner}.png?size=32` : undefined;
  const verificationStatus =
    item.publication_status === "confirmed"
      ? "AI contribution confirmed"
      : item.publication_status === "qualified"
        ? "AI contribution supported, with limits"
        : "AI contribution still under review";
  const verificationCopy =
    item.publication_status === "confirmed"
      ? "The evidence below connects a change attributed to an AI coding tool to the vulnerable behavior; no required evidence is missing."
      : item.publication_status === "qualified"
        ? "The evidence supports an AI contribution, but one or more checks are too limited for full confirmation."
        : "At least one link in the causal chain is unresolved, so the attribution is not final.";

  return (
    <header className="space-y-4">
      <Link
        href="/cves"
        className="inline-flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        Back to findings
      </Link>

      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
        <div>
          <p className="section-kicker">Evidence</p>
          <h1 className="mt-2 font-mono text-2xl font-bold tracking-tight sm:text-3xl">
            {formatCaseLabel(item, id)}
          </h1>
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

      <div className="border-l-2 border-primary bg-primary/[0.04] px-4 py-3 text-sm">
        <p className="font-semibold">{verificationStatus}</p>
        <p className="mt-1 max-w-4xl leading-6 text-muted-foreground">
          {verificationCopy}
        </p>
        <Link
          href="/about"
          className="mt-2 inline-block text-xs font-medium text-primary hover:underline"
        >
          How we verify evidence →
        </Link>
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
    <main className="mx-auto w-full max-w-[96rem] space-y-12 px-4 py-10 sm:px-6 2xl:px-8 min-[1920px]:max-w-[112rem] min-[2400px]:max-w-[128rem]">
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
