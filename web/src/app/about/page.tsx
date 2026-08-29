import type { Metadata } from "next";

import { getResearchSnapshot } from "@/lib/research-data";

export const metadata: Metadata = {
  title: "How we verify — Vibe Security Radar",
  description:
    "How Vibe Security Radar verifies AI-contributed vulnerabilities.",
};

const STEPS = [
  {
    number: "01",
    title: "Match the advisory",
    detail: "Confirm the advisory, repository, package, and vulnerability.",
  },
  {
    number: "02",
    title: "Locate the AI change",
    detail: "Bind AI evidence to the exact commit and relevant code hunk.",
  },
  {
    number: "03",
    title: "Prove cause and fix",
    detail:
      "Compare the parent, AI change, and minimum fix on the same attack path.",
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
    <main className="mx-auto w-full max-w-[96rem] px-4 py-10 sm:px-6 sm:py-14 2xl:px-8 min-[1920px]:max-w-[112rem] min-[2400px]:max-w-[128rem]">
      <header className="border-b border-border pb-8">
        <p className="section-kicker">How we verify</p>
        <h1 className="mt-3 text-balance text-4xl font-semibold tracking-[-0.045em] sm:text-5xl">
          Evidence before attribution.
        </h1>
        <p className="mt-4 max-w-3xl text-lg leading-7 text-muted-foreground">
          This public index covers {caseCount} findings. Each case links its
          vulnerability, contributing change, AI signal, and closing fix back
          to first-party evidence.
        </p>
        <p className="mt-3 text-sm text-muted-foreground">
          Real disclosed vulnerabilities from{" "}
          <a
            href="https://gts3.org"
            target="_blank"
            rel="noopener noreferrer"
            className="text-primary hover:underline"
          >
            Georgia Tech SSLab
          </a>
          —not synthetic benchmarks.
        </p>
      </header>

      <section className="py-10 sm:py-12" aria-labelledby="method-steps">
        <p className="section-kicker">Four steps</p>
        <h2 id="method-steps" className="mt-3 text-2xl font-semibold">
          From disclosure to a verified finding
        </h2>
        <ol className="mt-7 grid border-y border-border lg:grid-cols-4">
          {STEPS.map((step) => (
            <li
              key={step.number}
              className="border-b border-border py-5 last:border-b-0 lg:border-r lg:border-b-0 lg:px-5 lg:first:pl-0 lg:last:border-r-0 lg:last:pr-0"
            >
              <span className="font-mono text-xs text-primary">
                {step.number}
              </span>
              <h3 className="mt-3 font-semibold">{step.title}</h3>
              <p className="mt-2 text-sm leading-6 text-muted-foreground">
                {step.detail}
              </p>
            </li>
          ))}
        </ol>
      </section>

      <section
        className="border-t border-border py-10 sm:py-12"
        aria-labelledby="claim-boundary"
      >
        <p className="section-kicker">Claim boundary</p>
        <h2 id="claim-boundary" className="mt-3 text-2xl font-semibold">
          What the dataset means
        </h2>
        <div className="mt-7 grid gap-7 sm:grid-cols-3">
          {BOUNDARIES.map((boundary) => (
            <div
              key={boundary.title}
              className="border-l-2 border-primary pl-4"
            >
              <h3 className="font-semibold">{boundary.title}</h3>
              <p className="mt-2 text-sm leading-6 text-muted-foreground">
                {boundary.body}
              </p>
            </div>
          ))}
        </div>
      </section>

      <section
        className="border-y border-border py-6"
        aria-labelledby="sources"
      >
        <h2 id="sources" className="font-semibold">
          Sources
        </h2>
        <div className="mt-3 flex flex-wrap gap-x-6 gap-y-2 text-sm">
          {SOURCES.map(([label, href]) => (
            <a
              key={label}
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              {label} →
            </a>
          ))}
        </div>
        <p className="mt-4 max-w-3xl text-xs leading-5 text-muted-foreground">
          Public and repository advisories identify disclosed vulnerabilities.
          Git history and released artifacts determine the AI contribution and
          each finding&apos;s verification status.
        </p>
      </section>

      <p className="py-8 text-sm text-muted-foreground">
        Found a false positive? Email{" "}
        <a
          href="mailto:hanqing@gatech.edu"
          className="text-primary hover:underline"
        >
          hanqing@gatech.edu
        </a>
        .
      </p>
    </main>
  );
}
