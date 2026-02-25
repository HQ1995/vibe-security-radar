import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "About - Vibe Security Radar",
  description:
    "Methodology and data sources behind Vibe Security Radar, a public tracker for vulnerabilities introduced by AI coding tools.",
};

const AI_TOOLS = [
  "Claude Code",
  "Cursor",
  "Aider",
  "GitHub Copilot",
  "Devin",
  "Windsurf",
  "Codeium",
  "Amazon Q",
  "Tabnine",
  "Sourcegraph Cody",
  "OpenAI Codex",
  "Google Gemini",
  "Google Jules",
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
  "Continue Dev",
  "Augment Code",
  "Trae",
  "GitLab Duo",
] as const;

const DATA_SOURCES = [
  {
    name: "OSV.dev",
    url: "https://osv.dev",
    description: "Open Source Vulnerability database",
  },
  {
    name: "NVD",
    url: "https://nvd.nist.gov",
    description: "National Vulnerability Database (NIST)",
  },
  {
    name: "GitHub Advisory Database",
    url: "https://github.com/advisories",
    description: "GitHub's curated security advisory database",
  },
  {
    name: "GitHub Search API",
    url: "https://docs.github.com/en/rest/search",
    description: "GitHub commit and code search",
  },
] as const;

const LIMITATIONS = [
  "Only detects AI involvement when explicit signatures exist (co-author trailers, bot emails).",
  "AI tools that do not leave signatures in commits cannot be detected.",
  "Confidence scores are estimates, not certainties.",
  "Git blame may attribute lines to the wrong commit in some cases.",
] as const;

const PIPELINE_STEPS = [
  {
    tier: "Tier 1",
    title: "Advisory databases",
    description:
      "Query OSV.dev and GitHub Advisory DB for CVE fix commit SHAs.",
  },
  {
    tier: "Tier 2",
    title: "NVD references",
    description: "Parse NVD references for commit and pull request URLs.",
  },
  {
    tier: "Tier 3",
    title: "GitHub search",
    description:
      "Search GitHub commits for CVE mentions when advisory data is incomplete.",
  },
  {
    tier: "Tier 4",
    title: "Git blame analysis",
    description:
      "Trace bug-introducing commits using SZZ-style git blame on fix diffs.",
  },
  {
    tier: "Detection",
    title: "AI signature check",
    description:
      "Check each bug-introducing commit for AI coding tool signatures, including co-author trailers, bot email addresses, and tool-specific metadata.",
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
          (CVEs and GHSAs) where AI coding tools — such as GitHub Copilot,
          Cursor, and Claude Code — introduced the vulnerability. The goal is to
          bring transparency to the security implications of AI-assisted
          development so that developers, maintainers, and security teams can
          make informed decisions.
        </p>
      </section>

      {/* Methodology */}
      <section className="space-y-6">
        <h2 className="text-2xl font-semibold tracking-tight">Methodology</h2>
        <p className="leading-relaxed text-muted-foreground">
          Every vulnerability is processed through a multi-tier analysis
          pipeline that traces fixes back to the commits that introduced the
          bug, then checks those commits for AI tool signatures.
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
          relies on co-author trailers, bot email addresses, and other metadata
          that these tools embed in git commits.
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
                className="font-medium text-primary underline underline-offset-4 transition-colors hover:text-primary/80"
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
