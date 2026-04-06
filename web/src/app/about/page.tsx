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
      "Open-source vulnerability database. Bulk data dumps power batch scans; the REST API fills in gaps for individual lookups.",
  },
  {
    name: "GitHub Advisory Database (local clone)",
    url: "https://github.com/github/advisory-database",
    description:
      "Full git clone of reviewed and unreviewed advisories, queried locally with no API calls required.",
  },
  {
    name: "Gemnasium DB",
    url: "https://gitlab.com/gitlab-org/security-products/gemnasium-db",
    description:
      "GitLab's vulnerability database. Supplies fix commit URLs and fixed-version data that other sources often lack.",
  },
  {
    name: "NVD",
    url: "https://nvd.nist.gov",
    description:
      "NIST's National Vulnerability Database. Reference URLs are parsed to extract commit and pull request links.",
  },
] as const;

const LIMITATION_CATEGORIES = [
  {
    title: "Detection blind spots",
    items: [
      "Our detection relies entirely on metadata signals: co-author trailers, bot emails, commit message markers. Code written with AI assistance but committed without these markers is invisible to us. This is the single biggest limitation: many developers use AI tools in ways that leave no trace (copy-pasting from ChatGPT, using tools that don't add co-author trailers, or stripping markers before pushing). Our numbers represent a strict lower bound on AI-linked vulnerabilities.",
      "Different AI tools leave varying amounts of metadata. Claude Code and GitHub Copilot have well-established co-author conventions; others are harder to detect. This creates uneven coverage across tools.",
      "We are developing LLM-based code fingerprinting to identify AI-generated code from its stylistic and structural patterns, independent of commit metadata. This would catch cases where AI involvement is evident from the code itself but leaves no trace in the git history.",
    ],
  },
  {
    title: "Attribution accuracy",
    items: [
      "Git blame tracks line authorship, not semantic causality. A line may be blamed on commit X even when the real root cause is a design decision in commit Y. The deep investigator's CVE-level analysis catches most of these cases, but not all.",
      "Squash-merge decomposition depends on the GitHub API returning sub-commits. Force-pushed PRs or rebased branches may lose the original commit history, making per-commit attribution impossible.",
      "The investigator is a single LLM with tool access. Borderline cases where causality is genuinely ambiguous can go either way. We do not claim 100% accuracy on any individual case.",
    ],
  },
  {
    title: "Coverage scope",
    items: [
      "We cover publicly disclosed vulnerabilities (CVEs, GHSAs, RustSec, etc.) in public repositories, including CI/CD configuration issues like GitHub Actions injection. When advisory databases lack a fix commit, the pipeline uses LLM-assisted search (version-tag ranking and description-based git log matching) to discover one. Roughly 10% of our confirmed cases rely on these LLM-inferred fix commits. Closed-source bugs and unpatched vulnerabilities remain out of scope.",
      "Our analysis starts from May 2025. Vulnerabilities disclosed or fixed before that date are not covered, even if AI tools were involved.",
      "We do not analyze whether AI tools are more or less likely to introduce vulnerabilities than human developers. This project measures incidence, not relative risk.",
    ],
  },
  {
    title: "Methodological constraints",
    items: [
      "Our approach is inherently retrospective: we find AI-authored vulnerabilities after they are reported and fixed. We cannot predict which AI-generated code will become vulnerable.",
      "The pipeline is conservative by design: we would rather miss a true positive than report a false positive. This means our count underestimates the real number of AI-linked vulnerabilities.",
      "We use LLMs to judge whether AI-authored code caused a vulnerability, which creates an inherent circularity. The investigator may have systematic blind spots when evaluating AI-generated code patterns. We mitigate this with multi-model verification and conflict resolution, but cannot fully eliminate the risk.",
      "We can audit for false positives (cases we flagged incorrectly), but have no systematic way to measure our false negative rate: how many AI-caused vulnerabilities we miss entirely. The true count is unknowable with metadata-only detection.",
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
      "Advisory sources are queried in priority order: OSV bulk data and the local GitHub Advisory Database clone first (no API calls), then Gemnasium DB commit URLs and fixed-version tag resolution, followed by NVD reference URL parsing for GitHub commits and PRs. If none yield a fix commit and LLM mode is enabled, two additional strategies are attempted: a multi-version tag search that uses an LLM to rank candidate commits between version tags, and a description-based search that extracts terms from the CVE description and scores git log matches. Earlier tiers short-circuit later ones.",
  },
  {
    tier: "Phase B",
    title: "Bug-introducing commit discovery",
    summary:
      "Clone the repo, diff each fix commit, and run SZZ-style git blame to trace who introduced the vulnerable code.",
    details:
      "Four blame strategies run in parallel on each fix commit: (1) Deleted-line blame: when a fix removes or modifies code, blame those lines to find who wrote them (strongest causal signal). (2) Context blame: for add-only fixes, blame the surrounding lines in the parent commit. (3) Function history: when context blame finds nothing, trace function-level history via git log -L. (4) Pickaxe search: when vulnerability analysis identifies a dangerous pattern (e.g., a specific function call), search git history with git log -S to find who first introduced it. Before blaming, an LLM identifies which files in the fix are security-relevant, so blame runs only on those rather than every file the fix touched.",
  },
  {
    tier: "Phase B+",
    title: "Squash-merge decomposition",
    summary:
      "Large squash-merge commits get broken apart via the GitHub API to find which specific sub-commit introduced the vulnerable code.",
    details:
      "When a fix or bug-introducing commit is a squash-merge (detected by the (#NNN) pattern in the commit message) with over 30 changed files, the pipeline fetches the original PR sub-commits via the GitHub API. Each sub-commit is scored by file relevance to the CVE. For fix commits, only CVE-relevant files are blamed instead of all 1000+ files. For bug-introducing commits, the pipeline identifies which sub-commit actually touched the blamed file and records it as the culprit. This matters for AI attribution: if a PR has 17 commits and only one carries a Copilot co-author trailer, but that commit never touched the vulnerable file, the AI signal is dropped.",
  },
  {
    tier: "Phase C",
    title: "AI signal detection",
    summary:
      "Check each bug-introducing commit for AI coding tool signatures. CI/CD bots are filtered out.",
    details:
      "The pipeline scans commit metadata for co-author trailers (e.g., Co-Authored-By: Copilot), author and committer email domains, commit message keywords, and tool-specific patterns. Associated PR bodies are also checked for attribution text. For squash-merged BICs, individual sub-commits are inspected separately and confidence is scaled by the proportion of AI-authored commits in the PR. A lone Copilot commit in a 20-commit PR yields lower confidence than one where every commit carries AI signatures. Known CI/CD bots (Dependabot, Renovate, GitHub Actions, etc.) are excluded, and an anachronism filter rejects signals where the commit predates the tool's public release.",
  },
  {
    tier: "Phase D",
    title: "Screening verification",
    summary:
      "A lightweight LLM screen decides whether AI-signaled commits are plausibly related to the vulnerability, gating the expensive deep investigation.",
    details:
      "Rather than sending every AI-signaled CVE to the deep investigator, a lightweight LLM screen runs first. It receives the vulnerability description, the fix diff, and a summary of all AI-signaled bug-introducing commits (including decomposed sub-commits and blamed files). The screener asks one question: could any of these AI commits have contributed to this vulnerability? If not (say the AI commits touched frontend auth code but the vulnerability is a backend SSRF), the CVE is filtered out without incurring a full investigation. CVEs that pass proceed to Phase E. This filter achieves ~80% precision (validated by independent audit of rejected cases) and catches cases where blame cast a wide net and happened to land on unrelated AI-authored code.",
  },
  {
    tier: "Phase E",
    title: "Deep investigation",
    summary:
      "A single LLM investigator sees the entire vulnerability at once, runs a multi-step investigation with tool access, and answers a CVE-level question: did AI-authored code contribute to introducing this vulnerability?",
    details:
      "The investigator receives all fix commits, all blame candidates, and the CVE description. It has access to git log, file read, blame, diff, and pickaxe search, running up to 50 tool calls per investigation. It can trace chains of related commits, follow code across renames, and discover bug-introducing commits that blame missed entirely. Rather than rating individual commits, it answers a vulnerability-level question: was AI-authored code part of the causal chain? This verdict determines what appears on the site. Per-commit assessments are retained as supporting evidence but do not drive the final call.",
  },
  {
    tier: "Phase F",
    title: "Fallback verification",
    summary:
      "When the primary deep investigator fails (timeout, model error), a Claude Agent SDK subprocess with git MCP tools retries the investigation independently.",
    details:
      "The deep investigator (Phase E) uses a model fallback chain. When the primary model exhausts its tool-call budget or errors out, the pipeline falls back to a Claude Agent SDK subprocess with its own git tools (log, blame, diff, file read) via MCP. This is a fundamentally different execution path (a full CLI subprocess rather than API calls), so it often succeeds where the primary model failed. If the SDK fallback also fails, remaining models in the chain are tried. The fallback verdict replaces the failed investigation.",
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
          AI coding tools are writing a growing share of production code.
          Some of it ships with security vulnerabilities. We track the
          cases where vulnerable code in public advisories (CVEs, GHSAs,
          RustSec, and others) was authored by an AI tool.
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
          Our goal is to understand how AI-assisted development affects
          software security, not through benchmarks or synthetic tasks,
          but by studying real vulnerabilities that were reported and
          fixed in the wild.
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
              the commit that fixed each vulnerability. Over 95% of lookups
              use local bulk data, with no API calls required.
            </p>
          </div>
          <div className="space-y-1">
            <h3 className="font-medium">2. Trace who introduced the bug</h3>
            <p className="text-sm leading-relaxed text-muted-foreground">
              Using SZZ-style git blame on the fix commit, we trace backward
              to the commit that introduced the vulnerable code.
              Squash-merged PRs are decomposed into individual sub-commits
              so attribution is per-commit, not per-PR. Each
              bug-introducing commit is then scanned for AI tool
              signatures: co-author trailers, bot emails, and commit
              message markers from{" "}
              {AI_TOOLS.length}+ tools.
            </p>
          </div>
          <div className="space-y-1">
            <h3 className="font-medium">3. Verify causality</h3>
            <p className="text-sm leading-relaxed text-muted-foreground">
              An AI signature in a commit is not enough. First, a
              screening pass checks whether the blamed commit is plausibly
              related to the security issue. Then a deep investigator with
              full git tool access examines the entire vulnerability (all
              fix commits, all blame candidates), running up to 50 tool
              calls per case. Rather than rating each commit in isolation,
              it answers one question: did AI-authored code contribute to
              causing this vulnerability? This catches patterns that
              per-commit analysis misses: an AI commit that altered a
              calling convention, making previously safe code exploitable,
              or a squash-merge where the AI-tagged sub-commit never
              touched the vulnerable file. If the primary model fails, a
              Claude Agent SDK fallback with independent repository access
              retries the investigation. The pipeline is conservative:
              attribution is dropped when causality is uncertain.
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
          cause this? That could mean the AI wrote the vulnerable lines
          directly, altered a calling convention that made existing code
          exploitable, or added a feature without the security checks it
          needed. If the AI commits were not part of the causal chain, we
          drop the attribution.
        </p>
        <p className="leading-relaxed text-muted-foreground">
          This matters especially for squash-merged PRs. Suppose a PR has
          20 commits and one carries a Copilot co-author trailer, but that
          commit only updated a README, while a different human-written
          commit in the same PR introduced the vulnerability. We check
          file-level overlap between each sub-commit and the blamed file,
          and the deep investigator independently verifies whether
          AI-authored code was actually part of the causal chain.
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
          Found a false positive? Think we missed something? Have a
          question about our methodology? Email{" "}
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
