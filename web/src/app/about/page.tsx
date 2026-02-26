import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "About - Vibe Security Radar",
  description:
    "Methodology and data sources behind Vibe Security Radar — a public tracker for security vulnerabilities introduced by AI coding tools.",
};

const AI_TOOLS = [
  "Claude Code",
  "Cursor",
  "Aider",
  "GitHub Copilot",
  "Sweep",
  "Devin",
  "Windsurf",
  "Codeium",
  "Amazon Q",
  "Tabnine",
  "Sourcegraph Cody",
  "OpenAI Codex",
  "Google Gemini",
  "Google Jules",
  "Google Antigravity",
  "OpenCode",
  "Kiro",
  "JetBrains Junie",
  "Roo Code",
  "Cline",
  "OpenHands",
  "Lovable",
  "Fine Dev",
  "Replit Agent",
  "Qodo",
  "Continue",
  "Augment Code",
  "Trae",
  "GitLab Duo",
  "Kimi Code",
  "Kilo Code",
  "CodeGeeX",
  "Bolt.new",
  "Zencoder",
  "CodeGPT",
] as const;

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
      "Full git clone of GitHub-reviewed and community-unreviewed advisories, enabling offline batch analysis without API rate limits.",
  },
  {
    name: "NVD",
    url: "https://nvd.nist.gov",
    description:
      "National Vulnerability Database (NIST). Reference URLs are parsed to extract commit and pull-request links.",
  },
  {
    name: "GitHub Search API",
    url: "https://docs.github.com/en/rest/search",
    description:
      "Fallback commit and code search when advisory databases lack fix-commit SHAs.",
  },
] as const;

const LIMITATIONS = [
  "Only detects AI involvement when explicit signatures exist (co-author trailers, bot emails, commit message markers).",
  "AI tools that do not leave signatures in commits cannot be detected.",
  "Git blame may attribute lines to the wrong commit in some edge cases; LLM verification reduces but does not eliminate this.",
  "LLM verification uses a small model (Gemini 2.5 Flash Lite) and may occasionally misclassify borderline cases.",
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
    title: "GitHub search (fallback)",
    description:
      "Search GitHub commits for CVE/GHSA mentions when earlier tiers lack fix-commit SHAs.",
  },
  {
    tier: "Tier 4",
    title: "Git blame analysis",
    description:
      "Clone the affected repository, diff the fix commit, and run SZZ-style git blame to trace bug-introducing commits.",
  },
  {
    tier: "Tier 5",
    title: "AI signature detection",
    description:
      "Check each bug-introducing commit for AI coding tool signatures: co-author trailers, bot email addresses, commit message markers, and tool-specific metadata.",
  },
  {
    tier: "Tier 6",
    title: "LLM causality verification",
    description:
      "For commits with AI signals, an LLM (Gemini 2.5 Flash Lite) reviews the fix diff and blamed diff side-by-side to confirm the blamed commit actually introduced the vulnerability, filtering out git-blame false positives.",
  },
] as const;

export default function AboutPage() {
  return (
    <main className="mx-auto max-w-3xl space-y-14 px-4 py-10 sm:px-6">
      {/* Hero */}
      <section className="space-y-4">
        <h1 className="text-4xl font-bold tracking-tight">
          About Vibe Security Radar
        </h1>
        <p className="text-lg leading-relaxed text-muted-foreground">
          Vibe Security Radar is a public tracker that monitors vulnerabilities
          (CVEs, GHSAs, RustSec, and other advisories) where AI coding tools
          introduced the vulnerable code.
          The goal is to bring transparency to the security implications of
          AI-assisted development so that developers, maintainers, and security
          teams can make informed decisions.
        </p>
      </section>

      {/* Methodology */}
      <section className="space-y-6">
        <h2 className="text-2xl font-semibold tracking-tight">Methodology</h2>
        <p className="leading-relaxed text-muted-foreground">
          Every vulnerability is processed through a multi-tier pipeline. Bulk
          local data is preferred for throughput; API calls serve as fallbacks.
          Fix commits are traced back to bug-introducing commits via git blame,
          then each commit is checked for AI tool signatures and verified by an
          LLM to confirm causality.
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

      {/* AI Tools Monitored */}
      <section className="space-y-4">
        <h2 className="text-2xl font-semibold tracking-tight">
          AI Tools Monitored
        </h2>
        <p className="leading-relaxed text-muted-foreground">
          We detect signatures from {AI_TOOLS.length} AI coding tools. Detection
          relies on co-author trailers, bot email addresses, commit message
          keywords, and other metadata that these tools embed in git commits.
          Known CI/CD bots (Dependabot, Renovate, GitHub Actions, etc.) are
          explicitly filtered out to prevent false positives.
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
        <h2 className="text-2xl font-semibold tracking-tight">Data Sources</h2>
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
        <h2 className="text-2xl font-semibold tracking-tight">Limitations</h2>
        <ul className="list-inside list-disc space-y-2 text-muted-foreground">
          {LIMITATIONS.map((limitation) => (
            <li key={limitation} className="leading-relaxed">
              {limitation}
            </li>
          ))}
        </ul>
      </section>
    </main>
  );
}
