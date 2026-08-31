import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import ErrorPage from "@/app/error";
import Loading from "@/app/loading";
import AboutPage from "@/app/about/page";
import CveDetailPage from "@/app/cves/[id]/page";
import HomePage from "@/app/page";
import { CanonicalCaseEvidence } from "@/components/canonical-case-evidence";
import { getLangIconKey } from "@/components/language-distribution-chart";
import { getIconDimensions } from "@/components/tool-icon";
import { ReviewPathBadge } from "@/components/review-path-badge";
import {
  filterResearchCases,
  ResearchCaseExplorer,
} from "@/components/research-case-explorer";
import { ResearchCaseTable } from "@/components/research-case-table";
import { DataFreshness } from "@/components/data-freshness";
import { TrendChart } from "@/components/trend-chart";
import { ToolDistributionChart } from "@/components/tool-distribution-chart";
import {
  formatContributionClass,
  getAiToolLabel,
  getResearchCaseById,
  getResearchSnapshot,
  getResearchCases,
} from "@/lib/research-data";

describe("ReviewPathBadge", () => {
  it("keeps model provenance without presenting the model as an authority", () => {
    const html = renderToStaticMarkup(
      <ReviewPathBadge verifiedBy="claude-opus-4-6-thinking,gpt-5.4-high" />,
    );

    expect(html).toContain("block truncate");
    expect(html).toContain("GPT-5.4 High trace");
    expect(html).toContain("Investigation provenance:");
    expect(html).toContain("not publication authority");
    expect(html).not.toContain("Verified by");
  });
});

describe("DataFreshness", () => {
  it("shows the generation timestamp and advisory cutoff together", () => {
    const html = renderToStaticMarkup(
      <DataFreshness
        generatedAt="2026-08-09T09:41:55+00:00"
        coverageFrom="2025-05-01"
        coverageTo="2026-03-31"
      />,
    );

    expect(html).toContain("Aug 9, 2026");
    expect(html).toContain("09:41 UTC");
    expect(html).toContain("advisory coverage");
    expect(html).toContain("Mar 31, 2026");
  });
});

describe("server-rendered charts", () => {
  it("renders trend and distribution data without a client chart runtime", () => {
    const trend = renderToStaticMarkup(
      <TrendChart
        data={[
          { month: "2026-02", count: 5 },
          { month: "2026-03", count: 23 },
        ]}
        caseCount={28}
        datedCount={28}
        unknownDateCount={0}
        sourceCutoff="2026-08-10T04:01:13.999999+00:00"
      />,
    );
    const distribution = renderToStaticMarkup(
      <ToolDistributionChart
        data={{ claude_code: 3, github_copilot: 1, openai_codex: 1 }}
        totalCves={5}
      />,
    );

    expect(trend).toContain("Feb 2026: 5 cases");
    expect(trend).toContain("Mar 2026: 23 cases");
    expect(trend).toContain("Disclosures over time");
    expect(trend).not.toContain("Exact GHSA dates");
    expect(trend).not.toContain("Unavailable");
    expect(distribution).toContain("3 · 60%");
    expect(distribution).toContain("chatgpt.png");
    expect(trend + distribution).not.toContain("recharts");
    expect(trend).not.toContain("min-w-[760px]");
  });
});

describe("homepage hierarchy", () => {
  it("keeps the full table on the case index", () => {
    const html = renderToStaticMarkup(<HomePage />);
    const snapshot = getResearchSnapshot().snapshot;

    expect(html).toContain("Vibe Security Radar");
    expect(html).toContain("See the vulnerable code and fix");
    expect(html).toContain(
      `${snapshot.case_count} AI-contributed vulnerabilities cataloged`,
    );
    expect(html).toContain(
      `Browse all ${getResearchCases().length} findings`,
    );
    expect(html).toContain("Star on GitHub");
    expect(html).toContain("Covered advisories");
    expect(html).toContain("2025-05 – 2026-08");
    expect(html).not.toContain("Covered Advisories (2025-05-01");
    expect(html).not.toContain("Research ledger");
    expect(html).toContain("completed");
    expect(html).toContain("not started");
    expect(html).not.toContain("under analysis");
    expect(html).not.toContain("flawed AI code");
    expect(html).not.toContain(" · PUBLISHED");
    expect(html).toContain("Peak advisory month");
    expect(html).toContain("Most common AI tool");
    expect(html).toContain("Most represented project");
    expect(html).toContain("Media coverage");
    expect(html).toContain("Where the vulnerable code lives");
    expect(html).toContain("Repositories with the most findings");
    expect(html).toContain("How we verify");
    expect(html).toContain("Featured findings");
    expect(html).toContain("/icons/tools/claude_code.svg");
    expect(html).toContain("/icons/tools/github_copilot.svg");
    expect(html).toContain("chatgpt.png");
    expect(html).not.toContain("/icons/tools/openai_codex_dark.svg");
    expect(html).toContain("What counts as an AI-contributed vulnerability?");
    expect(html).not.toContain(
      `All ${getResearchCases().length} research cases`,
    );
    expect(html).not.toContain(`All ${getResearchCases().length} findings`);
  });
});

describe("how we verify page", () => {
  it("keeps the public verification page short and scannable", () => {
    const html = renderToStaticMarkup(<AboutPage />);

    expect(html).toContain("How we verify");
    expect(html).toContain("Evidence before attribution");
    expect(html).toContain("Match the advisory");
    expect(html).toContain("Locate the AI change");
    expect(html).toContain("Prove cause and fix");
    expect(html).toContain("Confirm the release");
    expect(html).toContain(
      `This public index covers ${getResearchCases().length} findings.`,
    );
    expect(html).not.toContain("AI provenance signals");
    expect(html).not.toContain("Stage 6");
    expect(html).not.toContain("details");
  });
});

describe("canonical case evidence", () => {
  it("keeps internal publication status off reader-facing case pages", async () => {
    const cases = [
      "GHSA-X98J-GH4V-7P7G",
      "GHSA-WFX9-6H8H-F3GM",
      "GHSA-Q8HH-M6V5-4F3X",
    ];

    for (const id of cases) {
      const page = await CveDetailPage({ params: Promise.resolve({ id }) });
      const html = renderToStaticMarkup(page);

      expect(html).not.toContain("AI contribution confirmed");
      expect(html).not.toContain("AI contribution supported, with limits");
      expect(html).not.toContain("AI contribution still under review");
      expect(html).not.toContain("AI-contributed vulnerability");
      expect(html).not.toContain("all seven evidence gates");
    }
  });

  it("searches and filters the full case index", () => {
    const cases = getResearchCases();
    const html = renderToStaticMarkup(<ResearchCaseExplorer cases={cases} />);
    const filtered = filterResearchCases(cases, {
      query: "go-git",
      cause: "path_link",
      contribution: "AI_INCOMPLETE_REMEDIATION",
      tool: "Claude",
      language: "Go",
      repository: "go-git/go-git",
      month: "2026-08",
    });

    expect(html).toContain("CVE, GHSA, or repository");
    expect(html).toContain("All root causes");
    expect(html).toContain("All contribution types");
    expect(html).toContain("All tools");
    expect(html).toContain("All languages");
    expect(html).toContain("All repositories");
    expect(html).toContain("All months");
    expect(html).toContain(
      `Page 1 of ${Math.ceil(getResearchCases().length / 20)}`,
    );
    expect(filtered.map((item) => item.case_id)).toEqual([
      "GHSA-HC8V-WWC9-VGXM",
    ]);
  });

  it("renders the complete case table", () => {
    const html = renderToStaticMarkup(
      <ResearchCaseTable cases={getResearchCases()} />,
    );

    expect(
      html.match(/class="border-t border-border align-top"/g),
    ).toHaveLength(getResearchCases().length);
    expect(html).toContain("sm:grid-cols-2 xl:hidden");
    expect(html).toContain(
      "hidden overflow-x-auto border-y border-border xl:block",
    );
    expect(html).toContain(`All ${getResearchCases().length} findings`);
    expect(html).toContain("CVE-2026-71556");
    expect(html).toContain("/icons/languages/go.svg");
    expect(html).toContain("/icons/tools/claude_code.svg");
  });

  it("keeps every case reachable through identities, facets, and evidence", () => {
    const cases = getResearchCases();
    const search = (query: string) =>
      filterResearchCases(cases, {
        query,
        cause: "",
        contribution: "",
        tool: "",
        language: "",
        repository: "",
        month: "",
      });

    for (const item of cases) {
      expect(search(item.case_id).map(({ case_id }) => case_id)).toContain(
        item.case_id,
      );
      for (const value of item.aliases) {
        expect(search(value).map(({ case_id }) => case_id)).toContain(
          item.case_id,
        );
      }
      for (const value of [
        ...item.candidate_set,
        ...item.carrier_set,
        ...item.minimum_fix_set,
      ]) {
        expect(search(value)).toContain(item);
      }
      expect(
        filterResearchCases(cases, {
          query: item.repository ?? item.case_id,
          cause: item.cause_category ?? "",
          contribution: item.contribution_class,
          tool: getAiToolLabel(item),
          language: item.repository_metadata.language,
          repository: item.repository!,
          month: item.published_at?.slice(0, 7) ?? "undated",
        }),
      ).toContain(item);
    }

    expect(search("kind")).toHaveLength(0);
    expect(search("2026-08-07").length).toBeGreaterThan(0);
    expect(
      filterResearchCases(cases, {
        query: "",
        cause: "",
        contribution: "",
        tool: "",
        language: "",
        repository: "",
        month: "undated",
      }).length,
    ).toBe(0);
    expect(formatContributionClass("AI_NEW_SURFACE_CONTRIBUTOR")).toBe(
      "New attack surface",
    );
    expect(formatContributionClass("AI_ROOT_NEW_COMPONENT")).toBe(
      "New vulnerable component",
    );
  });

  it("assigns a non-empty case_id and gates object to every case", () => {
    for (const item of getResearchCases()) {
      expect(item.case_id).toBeTruthy();
      expect(item.gates).toBeTruthy();
      expect(Object.keys(item.gates).length).toBeGreaterThan(0);
    }
  });

  it("shows only the admitted candidate and exact fix for CVE-2026-34218", () => {
    const item = getResearchCaseById("CVE-2026-34218");
    expect(item).not.toBeNull();

    const html = renderToStaticMarkup(<CanonicalCaseEvidence item={item!} />);

    expect(html).toContain("How AI contributed");
    expect(html).toContain("Startup ordering drops the merged rules");
    expect(html).toContain("56d617b778");
    expect(html).toContain("-server.applyPolicyToFilter()");
    expect(html).toContain("+server.applyPolicyToFilter()");
    expect(html).not.toContain("AI-assisted vulnerable code");
    expect(html).toContain("Root cause");
    expect(html).toContain("AI-assisted fix: Claude Code");
    expect(html).not.toContain("ddfdacb263");
    expect(html).not.toContain("Verified by");
    expect(html).not.toContain("cand=");
  });

  it("shows the real AI contribution summary, not the generic headline", () => {
    const dump = getResearchCaseById("GHSA-8JQH-598V-RFXC");
    expect(dump).not.toBeNull();
    const html = renderToStaticMarkup(<CanonicalCaseEvidence item={dump!} />);
    expect(html).toContain("How AI contributed");
    expect(html).not.toContain("cand=b7b362");
    expect(html).not.toContain("AI introduced the vulnerable behavior.");
    expect(html).toContain((dump!.code_evidence?.summary ?? "").slice(0, 60));
  });

  it("keeps the summary and causal chain together without viewport-sized gaps", async () => {
    const item = getResearchCaseById("CVE-2026-34218");
    expect(item).not.toBeNull();

    const page = await CveDetailPage({
      params: Promise.resolve({ id: "CVE-2026-34218" }),
    });
    const html = renderToStaticMarkup(page);
    const classes = [...html.matchAll(/class="([^"]*)"/g)]
      .map((match) => match[1])
      .join(" ");

    expect(html).toContain(
      "grid items-start gap-8 xl:grid-cols-[minmax(0,1fr)_22rem]",
    );
    expect(html.indexOf("How AI contributed")).toBeLessThan(
      html.indexOf("Root cause"),
    );
    expect(html.indexOf("Root cause")).toBeLessThan(
      html.indexOf("Case facts"),
    );
    expect(classes).not.toMatch(
      /(?:^|\s)(?:[^\s:]+:)*(?:min-h-screen|h-screen|(?:min-)?h-\[(?:[6-9]\d|100)vh\])(?=\s|$)/,
    );
  });

  it("shows audited fix authorship without unknown labels", () => {
    const humanMarked = getResearchCaseById("GHSA-7P8R-X3MC-P8W7");
    const aiMarked = getResearchCaseById("GHSA-5XXX-QHH7-9287");

    expect(humanMarked).not.toBeNull();
    expect(aiMarked).not.toBeNull();
    expect(
      renderToStaticMarkup(<CanonicalCaseEvidence item={humanMarked!} />),
    ).toContain("Fix by Matteo Collina · no AI marker found");
    expect(
      renderToStaticMarkup(<CanonicalCaseEvidence item={aiMarked!} />),
    ).toContain("AI-assisted fix: ChatGPT/Codex · Byron");
  });

  it("explains incomplete remediation without exposing an internal mechanism key", () => {
    const item = getResearchCaseById("CVE-2026-71556");
    expect(item).not.toBeNull();

    const html = renderToStaticMarkup(<CanonicalCaseEvidence item={item!} />);

    expect(html).toContain("This advisory");
    expect(html).toContain("AI tried to fix this");
    expect(html).toContain("Missed:");
    expect(html).toContain("leading symlink");
    expect(html).toContain("Fixed again");
    expect(html).toContain("validWritePath");
    expect(html).toContain("AI-assisted fix: Claude Code");
    expect(html).toContain("worktree_fs.go");
    expect(html).not.toContain(
      "go-git.worktreeFilesystem.validPath.symlink-follow",
    );
  });

  it("renders the GitPython incomplete-fix chain as original, AI attempt, and later fix", () => {
    const item = getResearchCaseById("GHSA-3WXW-XV34-2FRG");
    expect(item).not.toBeNull();

    const html = renderToStaticMarkup(<CanonicalCaseEvidence item={item!} />);

    expect(html).toContain("Original flaw");
    expect(html).toContain("Earlier advisory");
    expect(html).toContain("GHSA-3F7W-8RR8-F37F");
    expect(html).toContain("This advisory");
    expect(html).toContain("AI tried to fix this");
    expect(html).toContain("positional");
    expect(html).toContain("Fixed again");
    expect(html).toContain("3af0c2516c");
    expect(html).toContain("1b0d2d9b91");
  });

  it("never presents unresolved original authorship as human", () => {
    const base = getResearchCaseById("GHSA-3WXW-XV34-2FRG");
    expect(base?.ir_chain).toBeTruthy();

    for (const originalAuthorKind of [null, "UNKNOWN"] as const) {
      const item = {
        ...base!,
        ir_chain: {
          ...base!.ir_chain!,
          original_author_kind: originalAuthorKind,
          original_author_name: "Unverified name",
          original_sha: null,
          unresolved_reason: "History does not include the introducing commit.",
        },
      };
      const html = renderToStaticMarkup(<CanonicalCaseEvidence item={item} />);

      expect(html).toContain("Original authorship unresolved");
      expect(html).toContain(
        "Unresolved origin: History does not include the introducing commit.",
      );
      expect(html).not.toContain("Originally written by Unverified name");
      expect(html).not.toContain("Originally written by a human commit");
    }
  });

  it("keeps the route loading state compact and content-shaped", () => {
    const html = renderToStaticMarkup(<Loading />);
    const classes = [...html.matchAll(/class="([^"]*)"/g)]
      .map((match) => match[1])
      .join(" ");

    expect(html).toContain('aria-busy="true"');
    expect(html).toContain("Loading case details");
    expect(html).toContain("xl:grid-cols-[minmax(0,1fr)_22rem]");
    expect(classes).not.toMatch(
      /(?:^|\s)(?:[^\s:]+:)*(?:fixed|inset-0|min-h-screen|h-screen|(?:min-)?h-\[(?:[6-9]\d|100)vh\])(?=\s|$)/,
    );
  });

  it("keeps diff code collapsed with curated notes beside key hunks", () => {
    const item = structuredClone(
      getResearchCaseById("GHSA-9J5F-PJWJ-62R3")!,
    );
    Object.assign(item.code_evidence!.comparison_hunks[0], {
      annotation:
        "The newly added PluginImportGuard and both causal mechanisms are visible in this hunk.",
    });
    expect(item?.code_evidence?.comparison_hunks.length).toBeGreaterThan(0);

    const html = renderToStaticMarkup(<CanonicalCaseEvidence item={item!} />);
    const roleBadges = html.match(/>(?:AI change|Fix|Comparison)<\/span>/g) ?? [];

    expect(roleBadges).toHaveLength(
      item!.code_evidence!.comparison_hunks.length,
    );
    expect(html).toContain(
      "newly added PluginImportGuard and both causal mechanisms",
    );
    expect(html).toContain('aria-label="Key code note"');
    expect(html).not.toContain('<details open=""');
    expect(html).not.toContain("Lines beginning with");
    expect(html).not.toContain("Why this change is shown");
  });

  it("supplements a fix-only comparison with the missing candidate hunk", () => {
    const item = structuredClone(
      getResearchCaseById("GHSA-49MQ-FC6Q-3H46")!,
    );
    const candidateHunk = item.code_evidence?.candidate_hunks[0];
    const fixHunk = item.code_evidence?.fix_hunks[0];
    expect(candidateHunk).toBeTruthy();
    expect(fixHunk).toBeTruthy();
    Object.assign(item.code_evidence!, {
      candidate_hunks: [candidateHunk!],
      fix_hunks: [fixHunk!],
      comparison_hunks: [fixHunk!],
    });

    const html = renderToStaticMarkup(<CanonicalCaseEvidence item={item} />);

    expect(html.match(/>AI change<\/span>/g)).toHaveLength(1);
    expect(html.match(/>Fix<\/span>/g)).toHaveLength(1);
    expect(html).toContain(">AI change</h3>");
    expect(html).toContain(">Security fix</h3>");
  });

  it("links fix hunks to the verified canonical fix commit", () => {
    const item = getResearchCaseById("GHSA-QF5V-M7P4-95RP");
    const canonicalFix = "2569b42bfadbcb7d78b55a00a60f77937e522699";
    expect(item?.code_evidence?.fix_url).toContain(canonicalFix);
    expect(item?.minimum_fix_set).toContain(canonicalFix);

    const html = renderToStaticMarkup(<CanonicalCaseEvidence item={item!} />);

    expect(html).toContain(
      `href="https://github.com/fission/fission/blob/${canonicalFix}/pkg/executor/util/merge.go"`,
    );
    expect(html).toContain("source fission/fission@2569b42bfa");
    expect(html).toContain(
      `href="https://github.com/fission/fission/commit/${canonicalFix}"`,
    );
  });

  it("links diff hunks to the repository named by the evidence URLs", () => {
    const item = getResearchCaseById("CVE-2026-42278");
    expect(item?.repository).toBe("UltraDAGcom/core");

    const html = renderToStaticMarkup(<CanonicalCaseEvidence item={item!} />);

    expect(html).toContain(
      'href="https://github.com/sumitshahorg/core/blob/8f000e9403a33c693eeb630771bc3d4846473991/crates/ultradag-coin/src/tx/smart_account.rs"',
    );
    expect(html).toContain("source sumitshahorg/core@8f000e9403");
    expect(html).toContain(
      'href="https://github.com/sumitshahorg/core/blob/fb6ef59d6c1385400e7acea7ae31fc6a473c3051/crates/ultradag-coin/src/state/engine.rs"',
    );
    expect(html).toContain("source sumitshahorg/core@fb6ef59d6c");
  });

  it("uses role-specific repositories in the cause and fix cards", () => {
    const item = getResearchCaseById("GHSA-VJ3G-5PX3-GR46");
    const candidate = "a604df8c83d179a6e9fc07987ebef610faaf4991";
    const fix = "c821099157a9767d4df208c6b12f214946507871";
    expect(item?.repository).toBe("openclaw/openclaw");

    const html = renderToStaticMarkup(<CanonicalCaseEvidence item={item!} />);

    expect(html).toContain(
      `href="https://github.com/m1heng/clawdbot-feishu/blob/${candidate}/src/media.ts"`,
    );
    expect(html).toContain(
      `href="https://github.com/openclaw/openclaw/blob/${fix}/extensions/feishu/src/media.ts"`,
    );

    const fetchedContext = getResearchCaseById("GHSA-877V-W3F5-3PCQ");
    const fetchedContextHtml = renderToStaticMarkup(
      <CanonicalCaseEvidence item={fetchedContext!} />,
    );
    expect(fetchedContextHtml).toContain(
      'href="https://github.com/m1heng/clawdbot-feishu/commit/4286755f26bcfdd5c704cc4eb0cabfdc1b314e68"',
    );
    expect(fetchedContextHtml).toContain(
      'href="https://github.com/openclaw/openclaw/commit/8a607d7553339fffa97870668c482734db1b2d68"',
    );
  });

  it("shows release facts in the case facts card without not-recorded rows", () => {
    const withRelease = getResearchCaseById("GHSA-5XXX-QHH7-9287");
    const withoutRelease = getResearchCaseById("GHSA-C7RR-QHWX-6Q49");
    expect(withRelease?.vulnerable_release).toBeTruthy();
    expect(withoutRelease?.vulnerable_release).toBeNull();

    expect(
      renderToStaticMarkup(<CanonicalCaseEvidence item={withRelease!} />),
    ).toContain("Vulnerable release");
    expect(
      renderToStaticMarkup(<CanonicalCaseEvidence item={withoutRelease!} />),
    ).not.toContain("Not recorded");
  });
});

describe("chart icon contracts", () => {
  it("uses the official ChatGPT app icon", () => {
    const icon = readFileSync("public/icons/tools/chatgpt.png");
    expect(createHash("sha256").update(icon).digest("hex")).toBe(
      "e799e2fa0d4149a2ec28fc595c8bfb4990bcbb478649791b42acff7cde6e805e",
    );
  });

  it("skips unavailable language assets", () => {
    expect(getLangIconKey("TypeScript")).toBe("typescript");
    expect(getLangIconKey("GitHub Actions")).toBeNull();
  });

  it("preserves non-square tool icon aspect ratios", () => {
    expect(getIconDimensions("github_copilot", 18)).toEqual({
      width: 18,
      height: 15,
    });
    expect(getIconDimensions("cursor", 18)).toEqual({
      width: 18,
      height: 21,
    });
  });
});

describe("global error page", () => {
  it("uses a stable user-safe message", () => {
    const html = renderToStaticMarkup(
      <ErrorPage
        error={new Error("database credential: secret")}
        reset={() => undefined}
      />,
    );

    expect(html).toContain(
      "An unexpected error occurred while rendering this page.",
    );
    expect(html).not.toContain("database credential");
  });
});
