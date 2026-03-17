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
      "Open Source Vulnerability database. Bulk data dumps for batch scans; the REST API fills gaps.",
  },
  {
    name: "GitHub Advisory Database (local clone)",
    url: "https://github.com/github/advisory-database",
    description:
      "Full git clone of reviewed and unreviewed advisories. Queried locally, no API needed.",
  },
  {
    name: "Gemnasium DB",
    url: "https://gitlab.com/gitlab-org/security-products/gemnasium-db",
    description:
      "GitLab's vulnerability database. Provides fix commit URLs and fixed versions for additional coverage.",
  },
  {
    name: "NVD",
    url: "https://nvd.nist.gov",
    description:
      "National Vulnerability Database (NIST). Reference URLs are parsed to extract commit and PR links.",
  },
] as const;

const LIMITATIONS = [
  "We can only see AI involvement when the tool leaves a trace (co-author trailers, bot emails, commit message markers). If a developer pastes AI-generated code by hand, there is nothing to detect.",
  "Git blame tracks line authorship, not causal responsibility. The investigator catches most misattributions and can discover commits that blame missed entirely, but it is not perfect.",
  "The investigator is a single LLM with tool access. Borderline cases where causality is genuinely ambiguous can go either way.",
  "We only cover publicly disclosed vulnerabilities with available fix commits. Closed-source bugs and unpatched issues are out of scope.",
] as const;

const PIPELINE_STEPS = [
  {
    tier: "Phase A",
    title: "Fix commit discovery",
    summary:
      "Pull fix commit SHAs from advisory databases and reference URLs, with LLM-assisted search as a last resort.",
    details:
      "Advisory sources are checked in order: OSV bulk data and the local GitHub Advisory Database clone first (no API calls), then Gemnasium DB commit URLs and fixed-version tag resolution, then NVD reference URL parsing for GitHub commits and PRs. If none of those produce a fix commit, and LLM mode is enabled, the pipeline tries two more strategies: a multi-version tag search that uses an LLM to rank candidate commits between version tags, and a description-based search that extracts search terms from the CVE description and scores git log results. Earlier tiers short-circuit later ones.",
  },
  {
    tier: "Phase B",
    title: "Bug-introducing commit discovery",
    summary:
      "Clone the repo, diff each fix commit, and run SZZ-style git blame to trace who introduced the vulnerable code.",
    details:
      "Four blame strategies run in parallel on each fix commit. (1) Blame deleted lines: when a fix removes or modifies code, blame those lines to find who wrote them (strongest causal signal). (2) Context blame: for add-only fixes, blame the surrounding lines in the parent commit. (3) Function history: when context blame finds nothing, trace function-level history with git log -L. (4) Pickaxe search: when a vulnerability analysis identifies a dangerous pattern (e.g., a specific function call), search git history with git log -S to find who first introduced it. An LLM first identifies which files in the fix are actually security-relevant, so blame focuses there instead of diffing everything the fix touched.",
  },
  {
    tier: "Phase B+",
    title: "Squash-merge decomposition",
    summary:
      "Large squash-merge commits get broken apart via the GitHub API to find which specific sub-commit introduced the vulnerable code.",
    details:
      "When a fix commit or bug-introducing commit is a squash-merge (detected by the (#NNN) PR pattern in the commit message) with more than 30 changed files, the pipeline fetches the original PR sub-commits from the GitHub API. Each sub-commit is scored by file relevance to the CVE. For fix commits, only the CVE-relevant files are blamed instead of all 1000+ files. For bug-introducing commits, the pipeline checks which sub-commit actually touched the blamed file and stores it as the culprit. This matters for AI attribution: if a PR has 17 commits and only one has a Copilot co-author trailer, but that commit did not touch the vulnerable file, the AI signal is dropped.",
  },
  {
    tier: "Phase C",
    title: "AI signal detection",
    summary:
      "Check each bug-introducing commit for AI coding tool signatures. CI/CD bots are filtered out.",
    details:
      "The pipeline scans commit metadata for co-author trailers (e.g., Co-Authored-By: Copilot), author and committer email domains, commit message keywords, and tool-specific patterns. It also looks up the associated PR body for attribution text. For squash-merged BICs, individual PR sub-commits are checked separately, and confidence is scaled by the ratio of AI-authored commits in the PR (a single Copilot commit in a 20-commit PR gets lower confidence than a PR where every commit has it). Known CI/CD bots (Dependabot, Renovate, GitHub Actions, etc.) are explicitly excluded, and an anachronism filter rejects signals where the commit predates the tool's release.",
  },
  {
    tier: "Phase D",
    title: "Screening verification",
    summary:
      "A quick LLM check compares the fix commit diff against the bug-introducing commit diff to verify the causal link.",
    details:
      "For each bug-introducing commit with AI signals, an LLM receives both diffs plus the vulnerability description and assesses whether the blamed commit actually introduced the security issue. This is a lightweight single-pass check. Verdicts are CONFIRMED, UNLIKELY, or UNRELATED. When a squash-merge has a culprit sub-commit identified, the LLM analyzes that sub-commit's diff instead of the full squash merge. Results are cached per (BIC SHA, fix SHA, blamed file) tuple.",
  },
  {
    tier: "Phase E",
    title: "Deep investigation",
    summary:
      "A single LLM investigator sees the entire vulnerability at once and runs a multi-step investigation with tool access.",
    details:
      "This replaced an earlier per-commit tribunal. The investigator receives all fix commits, all blame candidates, and the CVE description. It has access to git log, file read, blame, diff, and pickaxe search, and runs up to 50 tool calls per investigation. It can trace chains of related commits, follow code across renames, and discover bug-introducing commits that blame missed entirely. The verdict is authoritative: if the investigator says UNRELATED, the commit is dropped regardless of what earlier stages said. If it discovers a new bug-introducing commit with AI signals, that gets added to the results.",
  },
] as const;

function ExpandableStep({
  step,
}: {
  step: (typeof PIPELINE_STEPS)[number];
}) {
  return (
    <li className="flex gap-4">
      <span className="mt-0.5 shrink-0 rounded bg-muted px-2 py-0.5 font-mono text-xs font-medium text-muted-foreground">
        {step.tier}
      </span>
      <details className="group w-full">
        <summary className="cursor-pointer list-none [&::-webkit-details-marker]:hidden">
          <h3 className="inline font-medium">{step.title}</h3>
          <span className="ml-2 text-xs text-muted-foreground group-open:hidden">
            ▸ details
          </span>
          <span className="ml-2 text-xs text-muted-foreground hidden group-open:inline">
            ▾ less
          </span>
          <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
            {step.summary}
          </p>
        </summary>
        <div className="mt-3 rounded-lg border border-border/50 bg-muted/30 px-4 py-3">
          <p className="text-sm leading-relaxed text-muted-foreground">
            {step.details}
          </p>
        </div>
      </details>
    </li>
  );
}

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

      {/* How it works */}
      <section className="space-y-6">
        <h2 className="text-2xl font-semibold tracking-tight">How it works</h2>
        <p className="leading-relaxed text-muted-foreground">
          Each vulnerability goes through a multi-phase pipeline. We pull
          advisory data in bulk where possible (no API calls for 95%+ of
          lookups) and fall back to APIs and LLM-assisted search for the rest.
          Fix commits get traced back to bug-introducing commits via git blame,
          then those commits are checked for AI tool signatures. For
          squash-merged PRs, we decompose to the specific sub-commit that
          introduced the vulnerable code, so a Copilot trailer on an unrelated
          commit in the same PR does not count. Finally, an LLM investigator
          looks at the whole vulnerability, not each blame candidate in
          isolation, and can trace commit chains and discover things that
          line-level blame misses.
        </p>
        <p className="text-sm leading-relaxed text-muted-foreground">
          Click any phase to see how the algorithm works.
        </p>
        <ol className="space-y-4">
          {PIPELINE_STEPS.map((step) => (
            <ExpandableStep key={step.tier} step={step} />
          ))}
        </ol>
      </section>

      {/* Attribution principle */}
      <section className="space-y-4">
        <h2 className="text-2xl font-semibold tracking-tight">
          How we attribute vulnerabilities to AI
        </h2>
        <p className="leading-relaxed text-muted-foreground">
          An AI signature in a bug-introducing commit is not enough. The
          question we ask: strip out the AI-written code from the change. Does
          the vulnerability still exist? If it does, the AI tool did not cause
          it and we drop the attribution.
        </p>
        <p className="leading-relaxed text-muted-foreground">
          This comes up a lot with squash-merged PRs. Say a PR has 20 commits
          and one of them has a Copilot co-author trailer. But that commit
          changed a README, and a different (human-written) commit in the same
          PR introduced the actual vulnerability. We check file-level overlap
          between each sub-commit and the blamed file, and remove the AI signal
          when it does not match.
        </p>
      </section>

      {/* AI tools monitored */}
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

      {/* Data sources */}
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
                {source.description}
              </span>
            </li>
          ))}
        </ul>
      </section>

      {/* Limitations */}
      <section className="space-y-4">
        <h2 className="text-2xl font-semibold tracking-tight">What we miss</h2>
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
