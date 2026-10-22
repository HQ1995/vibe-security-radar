import type { Metadata } from "next";

import { getResearchSnapshot } from "@/lib/research-data";

export const metadata: Metadata = {
  title: "How we verify",
  description:
    "How Vibe Security Radar verifies AI-contributed vulnerabilities.",
  alternates: { canonical: "/about" },
};

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

const SOURCES = [
  ["GitHub advisories", "https://github.com/advisories"],
  ["CVEList V5", "https://github.com/CVEProject/cvelistV5"],
  ["Git history", "https://github.com"],
  ["OSV routing", "https://osv.dev"],
] as const;

export default function AboutPage() {
  const snapshot = getResearchSnapshot().snapshot;
  const caseCount = snapshot.case_count;
  return (
    <main className="page-container py-10 sm:py-14">
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
            className="text-primary underline decoration-primary/40 underline-offset-2 hover:decoration-primary"
          >
            Georgia Tech SSLab
          </a>
          , not synthetic benchmarks.
        </p>

        <section className="mt-12" aria-labelledby="method-steps">
          <h2 id="method-steps" className="text-xl font-semibold">
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
          <h2 id="claim-boundary" className="text-xl font-semibold">
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

        <section className="mt-12" aria-labelledby="sources">
          <h2 id="sources" className="text-xl font-semibold">
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
                  className="text-primary underline decoration-primary/40 underline-offset-2 hover:decoration-primary"
                >
                  {label}
                </a>
              </li>
            ))}
          </ul>
        </section>

        <section className="mt-12" aria-labelledby="cite">
          <h2 id="cite" className="text-xl font-semibold">
            Cite and download
          </h2>
          <p className="mt-2 leading-7 text-muted-foreground">
            Every published finding is available as{" "}
            <a
              href="/data/findings.csv"
              download
              className="text-primary underline decoration-primary/40 underline-offset-2 hover:decoration-primary"
            >
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
          <h2 id="corrections" className="text-xl font-semibold">
            Corrections
          </h2>
          <p className="mt-2 leading-7 text-muted-foreground">
            Found a false positive? Email{" "}
            <a
              href="mailto:hanqing@gatech.edu"
              className="text-primary underline decoration-primary/40 underline-offset-2 hover:decoration-primary"
            >
              hanqing@gatech.edu
            </a>{" "}
            with the advisory, commit, or release evidence that changes the
            conclusion.
          </p>
        </section>
      </article>
    </main>
  );
}
