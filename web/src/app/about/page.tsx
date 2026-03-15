import type { Metadata } from "next";
import { getStats } from "@/lib/data";
import { DataFreshness } from "@/components/data-freshness";
import { TOOL_DISPLAY_NAMES } from "@/lib/constants";

export const metadata: Metadata = {
  title: "About - Vibe Security Radar",
  description:
    "How Vibe Security Radar finds and verifies vulnerabilities introduced by AI coding tools.",
};

/** Derive the tool list from the single source of truth, excluding the catch-all. */
const AI_TOOLS = Object.entries(TOOL_DISPLAY_NAMES)
  .filter(([key]) => key !== "unknown_ai")
  .map(([, name]) => name);

const DATA_SOURCES = [
  {
    name: "OSV.dev (bulk + API)",
    url: "https://osv.dev",
    description:
      "Open Source Vulnerability database. Bulk data dumps are used for batch scans; the REST API fills in any gaps.",
  },
  {
    name: "GitHub Advisory Database (local clone)",
    url: "https://github.com/github/advisory-database",
    description:
      "Full git clone of GitHub-reviewed and community-unreviewed advisories. We query this locally instead of hitting the API.",
  },
  {
    name: "NVD",
    url: "https://nvd.nist.gov",
    description:
      "National Vulnerability Database (NIST). Reference URLs are parsed to extract commit and pull-request links.",
  },
] as const;

const LIMITATIONS = [
  "We can only see AI involvement when the tool leaves a signature (co-author trailers, bot emails, commit message markers). If a developer pastes AI-generated code manually, we won't know.",
  "Git blame sometimes points to the wrong commit. The investigator catches most of these and can discover commits that blame missed, but it is not infallible.",
  "The investigator is a single LLM with tool access. Borderline cases where causality is ambiguous can still go either way.",
  "We only cover publicly disclosed vulnerabilities with available fix commits. Closed-source bugs and unpatched vulnerabilities are out of scope.",
] as const;

const PIPELINE_STEPS = [
  {
    tier: "Tier 1",
    title: "Bulk advisory ingestion",
    description:
      "Load all advisories from the OSV bulk data dump and the local GitHub Advisory Database clone (reviewed + unreviewed). No API calls needed for this tier.",
  },
  {
    tier: "Tier 2",
    title: "NVD references",
    description:
      "Parse NVD reference URLs to extract GitHub commit and pull-request links for each CVE.",
  },
  {
    tier: "Tier 3",
    title: "Git log search (fallback)",
    description:
      "Search the cloned repository's git log for CVE/GHSA ID mentions when earlier tiers lack fix-commit SHAs. Only searches repos already identified by advisory sources, avoiding false matches from scanner or PoC repositories.",
  },
  {
    tier: "Tier 4",
    title: "Git blame analysis",
    description:
      "Clone the repo, diff the fix commit, and run SZZ-style git blame to trace bug-introducing commits. An LLM first identifies which files are actually security-relevant, so we only blame those instead of everything the fix touched.",
  },
  {
    tier: "Tier 5",
    title: "AI signature detection",
    description:
      "Check each bug-introducing commit for AI coding tool signatures: co-author trailers, bot email addresses, commit message markers, and tool-specific metadata. Known CI/CD bots (Dependabot, Renovate, GitHub Actions, etc.) are explicitly filtered out.",
  },
  {
    tier: "Tier 6",
    title: "Deep investigation",
    description:
      "An LLM investigator receives the full vulnerability context (all fix commits, all blame candidates) and runs an agentic investigation with tool access (git log, file read, blame, diff, pickaxe search). It can trace chains of related commits and discover bug-introducing commits that blame missed. One investigation per vulnerability, not per commit. Details below.",
  },
] as const;

export default function AboutPage() {
  const stats = getStats();

  return (
    <main className="mx-auto max-w-3xl space-y-14 px-4 py-10 sm:px-6">
      {/* Hero */}
      <section className="space-y-4">
        <h1 className="text-4xl font-bold tracking-tight">
          About Vibe Security Radar
        </h1>
        <p className="text-lg leading-relaxed text-muted-foreground">
          AI coding tools write a lot of code now. Some of that code has
          security vulnerabilities. We track the ones that made it into
          public advisories (CVEs, GHSAs, RustSec, and others) where
          the vulnerable code was authored by an AI tool.
        </p>
        <p className="leading-relaxed text-muted-foreground">
          This is a research project from{" "}
          <a
            href="https://gts3.org"
            target="_blank"
            rel="noopener noreferrer"
            className="font-medium text-primary underline underline-offset-4 transition-colors hover:text-primary/80"
          >
            Georgia Tech SSLab
          </a>{" "}
          (Systems Software &amp; Security Lab, School of Cybersecurity and
          Privacy).
          We want to understand how AI-assisted development affects software
          security in practice. Not in benchmarks or synthetic tasks, but in
          real vulnerabilities that got reported and fixed.
        </p>
        <div className="flex flex-wrap gap-x-6 gap-y-1 text-sm text-muted-foreground">
          <span>{stats.total_cves} AI-linked vulnerabilities tracked</span>
          <span>{stats.total_analyzed.toLocaleString()} advisories analyzed</span>
          <DataFreshness generatedAt={stats.generated_at} coverageFrom={stats.coverage_from} coverageTo={stats.coverage_to} />
        </div>
      </section>

      {/* Methodology */}
      <section className="space-y-6">
        <h2 className="text-2xl font-semibold tracking-tight">How it works</h2>
        <p className="leading-relaxed text-muted-foreground">
          Each vulnerability goes through a six-tier pipeline. We pull advisory
          data in bulk where possible and fall back to APIs when needed.
          Fix commits get traced back to bug-introducing commits via git blame,
          then we check those commits for AI tool signatures. Finally, an LLM
          investigator looks at the whole vulnerability at once, not each
          blamed commit in isolation, so it can trace chains of commits and
          catch things that line-level blame misses.
        </p>
        <ol className="space-y-4">
          {PIPELINE_STEPS.map((step) => (
            <li key={step.tier} className="flex gap-4">
              <span className="mt-0.5 shrink-0 rounded bg-muted px-2 py-0.5 font-mono text-xs font-medium text-muted-foreground">
                {step.tier}
              </span>
              <div>
                <h3 className="font-medium">{step.title}</h3>
                <p className="text-sm leading-relaxed text-muted-foreground">
                  {step.description}
                </p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      {/* Investigation Details */}
      <section className="space-y-4">
        <h2 className="text-2xl font-semibold tracking-tight">
          Deep investigation
        </h2>
        <p className="leading-relaxed text-muted-foreground">
          Finding an AI signature in a bug-introducing commit is not enough.
          The commit might have touched the file without causing the actual
          vulnerability. And git blame can miss the real introducer entirely:
          it tracks line authorship, not causal responsibility. A commit
          that made a security credential optional might not show up in
          blame at all, even though it is the root cause.
        </p>
        <p className="leading-relaxed text-muted-foreground">
          So we run one investigation per vulnerability, not per commit. An
          LLM receives the full context (vulnerability description, all fix
          commits, every blame candidate) and investigates the vulnerability
          as a whole. It has tool access to git log, file read, blame, diff,
          and pickaxe search. It uses them to trace code changes across the
          repository, follow chains of related commits, and when blame missed
          something, discover it on its own.
        </p>
        <p className="leading-relaxed text-muted-foreground">
          This replaced an earlier per-commit approach where each blame
          candidate was verified in isolation. The difference matters for
          multi-commit vulnerabilities. For example: one commit designs a
          credential as optional, a later commit enables the feature without
          requiring it. Both contribute to the vulnerability, but checking
          each in isolation, the first one looks harmless ("not yet
          exploitable"). Seeing them together makes the chain obvious. If the
          investigator determines a commit is unrelated, we drop it.
        </p>
      </section>

      {/* AI Tools Monitored */}
      <section className="space-y-4">
        <h2 className="text-2xl font-semibold tracking-tight">
          AI tools monitored
        </h2>
        <p className="leading-relaxed text-muted-foreground">
          We detect signatures from {AI_TOOLS.length} AI coding tools via
          co-author trailers, bot email addresses, and commit message markers.
          CI/CD bots (Dependabot, Renovate, etc.) are filtered out.
        </p>
        <ul className="flex flex-wrap gap-2">
          {AI_TOOLS.map((tool) => (
            <li
              key={tool}
              className="rounded-md border border-border bg-muted/50 px-3 py-1 text-sm"
            >
              {tool}
            </li>
          ))}
        </ul>
      </section>

      {/* Data Sources */}
      <section className="space-y-4">
        <h2 className="text-2xl font-semibold tracking-tight">Data sources</h2>
        <ul className="space-y-3">
          {DATA_SOURCES.map((source) => (
            <li key={source.name} className="flex items-baseline gap-2">
              <a
                href={source.url}
                target="_blank"
                rel="noopener noreferrer"
                className="shrink-0 font-medium text-primary underline underline-offset-4 transition-colors hover:text-primary/80"
              >
                {source.name}
              </a>
              <span className="text-sm text-muted-foreground">
                — {source.description}
              </span>
            </li>
          ))}
        </ul>
      </section>

      {/* Limitations */}
      <section className="space-y-4">
        <h2 className="text-2xl font-semibold tracking-tight">What we can't detect</h2>
        <ul className="list-inside list-disc space-y-2 text-muted-foreground">
          {LIMITATIONS.map((limitation) => (
            <li key={limitation} className="leading-relaxed">
              {limitation}
            </li>
          ))}
        </ul>
      </section>

      {/* Contact */}
      <section className="space-y-4">
        <h2 className="text-2xl font-semibold tracking-tight">Contact</h2>
        <p className="leading-relaxed text-muted-foreground">
          Found a false positive? Think we missed something? Email{" "}
          <a
            href="mailto:hanqing@gatech.edu"
            className="font-medium text-primary underline underline-offset-4 transition-colors hover:text-primary/80"
          >
            hanqing@gatech.edu
          </a>
          .
        </p>
      </section>
    </main>
  );
}
