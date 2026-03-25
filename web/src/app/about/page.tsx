import type { Metadata } from "next";
import { getStats } from "@/lib/data";
import { DataFreshness } from "@/components/data-freshness";
import { TOOL_DISPLAY_NAMES, TOOL_URLS } from "@/lib/constants";

export const metadata: Metadata = {
  title: "About - Vibe Security Radar",
  description:
    "How Vibe Security Radar finds and verifies vulnerabilities introduced by AI coding tools.",
};

/** Derive the tool list from the single source of truth, excluding the catch-all. */
const AI_TOOLS = Object.entries(TOOL_DISPLAY_NAMES)
  .filter(([key]) => key !== "unknown_ai")
  .map(([key, name]) => ({ key, name, url: TOOL_URLS[key] }));

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

const LIMITATION_CATEGORIES = [
  {
    title: "Detection blind spots",
    items: [
      "Our detection relies entirely on metadata signals: co-author trailers, bot emails, commit message markers. Code written with AI assistance but committed without any of these markers is invisible to us. This is the single biggest limitation — many developers use AI tools in ways that leave no trace (copy-pasting from ChatGPT, using tools that don't stamp commits, or stripping co-author trailers before pushing). Our numbers are a strict lower bound on AI-linked vulnerabilities.",
      "Different AI tools leave different amounts of metadata. Claude Code and GitHub Copilot have strong co-author conventions; others are harder to detect. This creates uneven coverage across tools.",
      "We are developing LLM-based code fingerprinting to detect AI-generated code by its stylistic and structural patterns, independent of commit metadata. This would catch cases where AI involvement is obvious from the code itself but invisible in the git history.",
    ],
  },
  {
    title: "Attribution accuracy",
    items: [
      "Git blame tracks line authorship, not semantic causality. A line can be blamed on commit X even if the real root cause is a design decision in commit Y. The deep investigator's CVE-level analysis catches most of these, but not all.",
      "Squash-merge decomposition depends on the GitHub API returning sub-commits. Force-pushed PRs or rebased branches may lose the original commit history, making per-commit attribution impossible.",
      "The investigator is a single LLM with tool access. Borderline cases where causality is genuinely ambiguous can go either way. We do not claim 100% accuracy on any individual case.",
    ],
  },
  {
    title: "Coverage scope",
    items: [
      "We cover publicly disclosed vulnerabilities (CVEs, GHSAs, RustSec, etc.) in public repositories — including CI/CD configuration vulnerabilities such as GitHub Actions composite action injection. When advisory databases don't provide a fix commit, the pipeline uses LLM-assisted search (version-tag ranking and description-based git log search) to discover it. About 10% of our confirmed cases rely on these AI-inferred fix commits. Closed-source bugs and unpatched issues are still out of scope.",
      "Our analysis starts from May 2025. Vulnerabilities disclosed or fixed before that date are not covered, even if AI tools were involved.",
      "We do not analyze whether AI tools are more or less likely to introduce vulnerabilities compared to human developers. This project measures incidence, not relative risk.",
    ],
  },
  {
    title: "Methodological constraints",
    items: [
      "Our approach is inherently retrospective. We find AI-authored vulnerabilities after they are reported and fixed. We cannot predict which AI-generated code will become vulnerable.",
      "The pipeline is conservative by design: we would rather miss a true positive than report a false positive. This means our count underestimates the real number of AI-linked vulnerabilities.",
      "We use LLMs to judge whether AI-authored code caused a vulnerability. This creates a circularity: the investigator may have systematic blind spots or biases when evaluating AI-generated code patterns. We mitigate this with multi-model verification and conflict resolution, but cannot fully eliminate it.",
      "We can audit for false positives (cases we flagged incorrectly), but we have no systematic way to measure our false negative rate — the number of AI-caused vulnerabilities we miss entirely. The true count is unknowable with metadata-only detection.",
    ],
  },
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
      "A per-CVE LLM triage decides whether the AI-signaled commits are plausibly related to the vulnerability, gating the expensive deep investigation.",
    details:
      "Instead of sending every AI-signaled CVE to the deep investigator, a lightweight LLM screen runs first at the CVE level. It receives the vulnerability description, the fix commit diff, and a summary of all AI-signaled bug-introducing commits (including their decomposed sub-commits and blamed files). The screener asks one question: could any of these AI commits have contributed to this vulnerability? If the answer is no — for example, the AI commits touched frontend auth code but the vulnerability is a backend SSRF — the CVE is excluded without incurring the cost of a full investigation. CVEs that pass screening proceed to Phase E. This filter has ~80% precision (validated by independent audit of rejected cases) and catches cases where blame cast a wide net across a large repo and happened to land on unrelated AI-authored code.",
  },
  {
    tier: "Phase E",
    title: "Deep investigation",
    summary:
      "A single LLM investigator sees the entire vulnerability at once, runs a multi-step investigation with tool access, and answers a CVE-level question: did AI-authored code contribute to introducing this vulnerability?",
    details:
      "The investigator receives all fix commits, all blame candidates, and the CVE description. It has access to git log, file read, blame, diff, and pickaxe search, and runs up to 50 tool calls per investigation. It can trace chains of related commits, follow code across renames, and discover bug-introducing commits that blame missed entirely. Instead of just rating each commit, it answers a vulnerability-level question: was AI part of the causal chain? This is the verdict that decides what appears on the site. Per-commit assessments are kept as supporting evidence, but they no longer drive the final call.",
  },
  {
    tier: "Phase F",
    title: "Conflict resolution",
    summary:
      "When screening and deep investigation disagree on a BIC, a Claude Agent SDK resolver with git MCP tools adjudicates.",
    details:
      "For each bug-introducing commit, screening (Phase D) and deep investigation (Phase E) produce independent verdicts. When these disagree — for example, screening says CONFIRMED but the deep investigator says UNLIKELY — the conflict resolver steps in for that individual BIC. It runs as a Claude Agent SDK subprocess with MCP-based git tools (log, blame, diff, file read) so it can independently inspect the repository. It sees both verdicts and their evidence, then makes the final call. Conflicts are batched per-CVE to minimize subprocess overhead. The resolver's verdict is final and overwrites earlier decisions.",
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

      {/* Core methodology */}
      <section className="space-y-6">
        <h2 className="text-2xl font-semibold tracking-tight">Core methodology</h2>
        <p className="leading-relaxed text-muted-foreground">
          Our approach has three steps: <strong>find the fix</strong>,{" "}
          <strong>trace the blame</strong>, and{" "}
          <strong>verify the cause</strong>.
        </p>
        <div className="space-y-4 rounded-lg border border-border bg-muted/20 px-5 py-4">
          <div className="space-y-1">
            <h3 className="font-medium">1. Find the fix commit</h3>
            <p className="text-sm leading-relaxed text-muted-foreground">
              We aggregate vulnerability data from four advisory databases
              (OSV, GitHub Advisory Database, Gemnasium, NVD) and extract
              the commit that fixed each vulnerability. 95%+ of lookups use
              local bulk data with no API calls.
            </p>
          </div>
          <div className="space-y-1">
            <h3 className="font-medium">2. Trace who introduced the bug</h3>
            <p className="text-sm leading-relaxed text-muted-foreground">
              Using SZZ-style git blame on the fix commit, we trace backward
              to the commit that introduced the vulnerable code. For
              squash-merged PRs, we decompose to individual sub-commits so
              attribution is per-commit, not per-PR. We then scan the
              bug-introducing commit for AI tool signatures: co-author
              trailers, bot emails, and commit message markers from{" "}
              {AI_TOOLS.length}+ tools.
            </p>
          </div>
          <div className="space-y-1">
            <h3 className="font-medium">3. Verify causality</h3>
            <p className="text-sm leading-relaxed text-muted-foreground">
              An AI signature in a commit is not enough. A screening pass
              checks whether the blamed commit actually introduced the
              security issue. Then a deep investigator with git tool access
              examines the entire vulnerability — all fix commits, all blame
              candidates — running up to 50 tool calls per case. Instead of
              rating each commit separately, it answers one question: did
              AI-authored code help cause this vulnerability? This catches
              things that per-commit analysis misses — an AI commit that
              changed how a function gets called, making old code newly
              exploitable, or a squash-merge where the AI sub-commit never
              touched the vulnerable file. When screening and deep investigation disagree
              on a blame candidate, a conflict resolver with independent
              repository access adjudicates. The result is conservative: we
              drop attribution when causality is uncertain.
            </p>
          </div>
        </div>
      </section>

      {/* Pipeline details */}
      <section className="space-y-6">
        <h2 className="text-2xl font-semibold tracking-tight">Pipeline details</h2>
        <p className="text-sm leading-relaxed text-muted-foreground">
          Click any phase to see the algorithm in detail.
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
          An AI signature in a bug-introducing commit is not enough. We ask
          the question at the vulnerability level: did AI-authored code help
          cause this? That could mean the AI wrote the vulnerable lines, or
          changed how a function gets called so that old code became
          exploitable, or added a feature without the security checks it
          needed. If the AI commits were not part of the causal chain, we
          drop the attribution.
        </p>
        <p className="leading-relaxed text-muted-foreground">
          This matters for squash-merged PRs especially. Say a PR has 20
          commits and one has a Copilot co-author trailer. But that commit
          changed a README, and a different (human-written) commit in the same
          PR introduced the actual vulnerability. We check file-level overlap
          between each sub-commit and the blamed file, and the deep
          investigator independently verifies whether AI code was actually part
          of the causal chain.
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
            <li key={tool.key}>
              {tool.url ? (
                <a
                  href={tool.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-block rounded-md border border-border bg-muted/50 px-3 py-1 text-sm transition-colors hover:bg-muted hover:text-primary"
                >
                  {tool.name}
                </a>
              ) : (
                <span className="inline-block rounded-md border border-border bg-muted/50 px-3 py-1 text-sm">
                  {tool.name}
                </span>
              )}
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
      <section className="space-y-6">
        <h2 className="text-2xl font-semibold tracking-tight">
          Limitations &amp; what we miss
        </h2>
        <p className="leading-relaxed text-muted-foreground">
          This is an observational study with inherent blind spots. We are
          transparent about what we can and cannot measure.
        </p>
        {LIMITATION_CATEGORIES.map((category) => (
          <div key={category.title} className="space-y-2">
            <h3 className="font-medium">{category.title}</h3>
            <ul className="list-inside list-disc space-y-2 text-muted-foreground">
              {category.items.map((item) => (
                <li key={item} className="leading-relaxed">
                  {item}
                </li>
              ))}
            </ul>
          </div>
        ))}
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
