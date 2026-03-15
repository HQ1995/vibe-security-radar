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
  "Git blame sometimes points to the wrong commit. The deep verifier catches most of these, but not all.",
  "The deep verifier is a single LLM with tool access. Borderline cases where causality is ambiguous can still go either way.",
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
    title: "Deep verification",
    description:
      "An LLM first analyzes the fix commit to understand the vulnerability type and root cause. Then a deep verifier — a single LLM with tool access (git log, file read, blame, diff) — runs an agentic investigation loop on the blamed commit to determine causality. Details below.",
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
          public advisories — CVEs, GHSAs, RustSec, and others — where
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
          security in practice — not in benchmarks or synthetic tasks, but in
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
          then we check those commits for AI tool signatures. A deep verifier
          — a single LLM with tool access — investigates each candidate to
          determine whether the AI-authored commit actually caused the
          vulnerability.
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

      {/* Verification Details */}
      <section className="space-y-4">
        <h2 className="text-2xl font-semibold tracking-tight">
          Deep verification
        </h2>
        <p className="leading-relaxed text-muted-foreground">
          Finding an AI signature in a bug-introducing commit is not enough.
          The commit might have touched the file without causing the actual
          vulnerability. So every candidate goes through a two-phase check.
        </p>
        <p className="leading-relaxed text-muted-foreground">
          First, an LLM reads the fix commit to understand what the
          vulnerability is: its type (command injection, XSS, etc.), root
          cause, and the code pattern that was vulnerable. Then a deep
          verifier — a single LLM with tool access to git log, file read,
          blame, and diff — runs an agentic investigation loop. It
          autonomously explores the repository, traces code changes, and
          builds a causal chain before submitting a verdict.
        </p>
        <p className="leading-relaxed text-muted-foreground">
          This replaced an earlier three-model tribunal (GPT, Claude, Gemini
          majority vote). The deep verifier is more accurate because it can
          actually read the code and trace the history, rather than relying
          on context-limited single-pass analysis. If the verifier determines
          the commit is unrelated, we drop it.
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
