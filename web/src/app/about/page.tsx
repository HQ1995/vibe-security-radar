import type { Metadata } from "next";

import Link from "next/link";

import { pageMetadata } from "@/lib/page-metadata";
import { getCauseDistribution, getResearchSnapshot } from "@/lib/research-data";
import { topicHref } from "@/lib/topics";

export const metadata: Metadata = pageMetadata({
  title: "How we verify",
  description:
    "How Vibe Security Radar traces a published CVE to the AI-assisted change behind it: match the advisory, locate the AI-assisted commit, prove cause and fix, and confirm the release.",
  path: "/about",
});

const STEPS = [
  {
    number: "01",
    title: "Match the advisory",
    detail: "Confirm the advisory, repository, package, and vulnerability.",
  },
  {
    number: "02",
    title: "Locate the AI-assisted change",
    detail: "Bind AI evidence to the exact commit and relevant code hunk.",
  },
  {
    number: "03",
    title: "Prove cause and fix",
    detail:
      "Compare the parent, AI-assisted change, and minimum fix on the same attack path.",
  },
  {
    number: "04",
    title: "Confirm the release",
    detail:
      "Verify the vulnerable and fixed releases, then remove true duplicates.",
  },
] as const;

const BOUNDARIES = [
  {
    title: "What counts",
    body: "AI introduced the flaw, exposed the vulnerable path, or left a security fix incomplete.",
  },
  {
    title: "What does not count",
    body: "An AI marker, Git blame, or model verdict alone. The code change must affect the same mechanism.",
  },
  {
    title: "What we do not claim",
    body: "This is not a census of every AI bug and does not compare AI and human defect rates.",
  },
] as const;

const SECTIONS = [
  { id: "method-steps", label: "Verification steps" },
  { id: "claim-boundary", label: "What the dataset means" },
  { id: "root-causes", label: "Root cause categories" },
  { id: "sources", label: "Sources" },
  { id: "cite", label: "Cite and download" },
  { id: "corrections", label: "Corrections" },
] as const;

const LINK =
  "text-primary underline decoration-primary/40 underline-offset-2 hover:decoration-primary";

const SOURCES = [
  ["GitHub advisories", "https://github.com/advisories"],
  ["CVEList V5", "https://github.com/CVEProject/cvelistV5"],
  ["Git history", "https://github.com"],
  ["OSV routing", "https://osv.dev"],
] as const;

export default function AboutPage() {
  const snapshot = getResearchSnapshot().snapshot;
  const caseCount = snapshot.case_count;
  const causes = getCauseDistribution();
  return (
    <main className="page-container py-10 sm:py-14 xl:grid xl:grid-cols-[minmax(0,48rem)_13rem] xl:justify-between xl:gap-12">
      <article className="max-w-3xl">
        <p className="text-sm text-muted-foreground">How we verify</p>
        <h1 className="mt-2 text-balance text-4xl font-semibold tracking-[-0.04em] sm:text-5xl">
          Evidence before attribution.
        </h1>
        <p className="mt-4 text-lg leading-8 text-muted-foreground">
          This public index covers {caseCount} findings. Each case links its
          vulnerability, contributing change, AI signal, and closing fix back to
          first-party evidence.
        </p>
        <p className="mt-3 text-sm text-muted-foreground">
          Real disclosed vulnerabilities from{" "}
          <a
            href="https://gts3.org"
            target="_blank"
            rel="noopener noreferrer"
            className={LINK}
          >
            Georgia Tech SSLab
          </a>
          , not synthetic benchmarks.
        </p>

        <section className="mt-12" aria-labelledby="method-steps">
          <h2 id="method-steps" className="scroll-mt-20 text-xl font-semibold">
            From disclosure to a verified finding
          </h2>
          <p className="mt-2 leading-7 text-muted-foreground">
            Every finding passes four checks before it is published.
          </p>
          <ol className="mt-4 list-decimal space-y-3 pl-5 leading-7 marker:font-medium marker:text-muted-foreground">
            {STEPS.map((step) => (
              <li key={step.number} className="pl-1">
                <span className="font-semibold">{step.title}.</span>{" "}
                <span className="text-muted-foreground">{step.detail}</span>
              </li>
            ))}
          </ol>
        </section>

        <section className="mt-12" aria-labelledby="claim-boundary">
          <h2
            id="claim-boundary"
            className="scroll-mt-20 text-xl font-semibold"
          >
            What the dataset means
          </h2>
          <dl className="mt-4 divide-y divide-border border-y border-border">
            {BOUNDARIES.map((boundary) => (
              <div
                key={boundary.title}
                className="grid gap-1 py-4 sm:grid-cols-[11rem_minmax(0,1fr)] sm:gap-6"
              >
                <dt className="font-semibold">{boundary.title}</dt>
                <dd className="leading-7 text-muted-foreground">
                  {boundary.body}
                </dd>
              </div>
            ))}
          </dl>
        </section>

        <section className="mt-12" aria-labelledby="root-causes">
          <h2 id="root-causes" className="scroll-mt-20 text-xl font-semibold">
            Root cause categories
          </h2>
          <p className="mt-2 leading-7 text-muted-foreground">
            Each finding gets one category, taken from the advisory&apos;s CWE
            when it names one and from the verified mechanism otherwise.
          </p>
          <dl className="mt-4 divide-y divide-border border-y border-border">
            {causes.map((cause) => {
              const href = topicHref("cause", cause.key);
              return (
                <div
                  key={cause.key}
                  className="grid gap-1 py-4 sm:grid-cols-[11rem_minmax(0,1fr)] sm:gap-6"
                >
                  <dt className="font-semibold">
                    {href ? (
                      <Link
                        href={href}
                        className="hover:text-primary hover:underline"
                      >
                        {cause.label}
                      </Link>
                    ) : (
                      cause.label
                    )}
                    <span className="ml-2 font-normal tabular-nums text-muted-foreground">
                      {cause.count}
                    </span>
                  </dt>
                  <dd className="leading-7 text-muted-foreground">
                    {cause.definition}
                  </dd>
                </div>
              );
            })}
          </dl>
        </section>

        <section className="mt-12" aria-labelledby="sources">
          <h2 id="sources" className="scroll-mt-20 text-xl font-semibold">
            Sources
          </h2>
          <p className="mt-2 leading-7 text-muted-foreground">
            Public and repository advisories identify disclosed vulnerabilities.
            Git history and released artifacts determine the AI contribution and
            each finding&apos;s verification status.
          </p>
          <ul className="mt-3 flex flex-wrap gap-x-6 gap-y-2">
            {SOURCES.map(([label, href]) => (
              <li key={label}>
                <a
                  href={href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={LINK}
                >
                  {label}
                </a>
              </li>
            ))}
          </ul>
        </section>

        <section className="mt-12" aria-labelledby="cite">
          <h2 id="cite" className="scroll-mt-20 text-xl font-semibold">
            Cite and download
          </h2>
          <p className="mt-2 leading-7 text-muted-foreground">
            Every published finding is available as{" "}
            <a href="/data/findings.csv" download className={LINK}>
              one CSV file
            </a>{" "}
            with its identifiers, repository, AI tool, AI role, root cause and
            summary. To cite the dataset:
          </p>
          <pre
            tabIndex={0}
            className="mt-3 overflow-x-auto rounded-md border border-border bg-card p-4 font-mono text-xs leading-5"
          >
            {`@misc{vibesecradar,
  title        = {Vibe Security Radar},
  author       = {{Georgia Tech SSLab}},
  howpublished = {\\url{https://vibesecradar.com}},
  note         = {${caseCount} findings, data through ${snapshot.source_cutoff.slice(0, 10)}}
}`}
          </pre>
        </section>

        <section className="mt-12" aria-labelledby="corrections">
          <h2 id="corrections" className="scroll-mt-20 text-xl font-semibold">
            Corrections
          </h2>
          <p className="mt-2 leading-7 text-muted-foreground">
            Found a false positive?{" "}
            <a
              href="https://github.com/HQ1995/vibe-security-radar/issues/new"
              target="_blank"
              rel="noopener noreferrer"
              className={LINK}
            >
              Open a GitHub issue
            </a>{" "}
            or email{" "}
            <a href="mailto:hanqing@gatech.edu" className={LINK}>
              hanqing@gatech.edu
            </a>{" "}
            with the advisory, commit, or release evidence that changes the
            conclusion. Each finding page also has a &ldquo;Suggest a
            correction&rdquo; link that fills in the finding for you.
          </p>
        </section>
      </article>
      <nav aria-label="On this page" className="hidden xl:block">
        <div className="sticky top-24">
          <p className="text-sm font-semibold">On this page</p>
          <ul className="mt-3 space-y-2 border-l border-border text-sm">
            {SECTIONS.map((section) => (
              <li key={section.id}>
                <a
                  href={`#${section.id}`}
                  className="-ml-px block border-l border-transparent pl-3 text-muted-foreground hover:border-foreground hover:text-foreground"
                >
                  {section.label}
                </a>
              </li>
            ))}
          </ul>
        </div>
      </nav>
    </main>
  );
}
