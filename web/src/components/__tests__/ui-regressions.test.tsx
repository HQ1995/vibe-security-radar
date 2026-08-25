import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import ErrorPage from "@/app/error";
import AboutPage from "@/app/about/page";
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

    expect(html).toContain("Vibe Security Radar");
    expect(html).toContain("See the vulnerable code and fix");
    expect(html).toContain(
      `${getResearchCases().length} confirmed vulnerabilities`,
    );
    expect(html).toContain(
      `Browse all ${getResearchCases().length} true positives`,
    );
    expect(html).toContain("Star on GitHub");
    expect(html).toContain("Confirmed true positives");
    expect(html).toContain("Covered advisories");
    expect(html).toContain("2025-05 – 2026-08");
    expect(html).not.toContain("Covered Advisories (2025-05-01");
    expect(html).not.toContain("Research ledger");
    expect(html).toContain("reviewed");
    expect(html).toContain("under analysis");
    expect(html).not.toContain("not started");
    expect(html).not.toContain("analysed");
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
      `This public index covers ${getResearchCases().length} confirmed true positives`,
    );
    expect(html).not.toContain("AI provenance signals");
    expect(html).not.toContain("Stage 6");
    expect(html).not.toContain("details");
  });
});

describe("canonical case evidence", () => {
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

  it("does not put internal research notes in the contribution headline", () => {
    const dump = getResearchCaseById("GHSA-8JQH-598V-RFXC");
    expect(dump).not.toBeNull();
    const html = renderToStaticMarkup(<CanonicalCaseEvidence item={dump!} />);
    expect(html).toContain("How AI contributed");
    expect(html).not.toContain("cand=b7b362");
    expect(html).toContain("AI introduced the vulnerable behavior.");
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
    expect(html).not.toContain("Security fix");
  });

  it("shows researched hunks and an annotation for previously empty comparisons", () => {
    const item = getResearchCaseById("GHSA-WVPP-8HX9-P66J");
    expect(item).not.toBeNull();
    expect(item?.code_evidence?.comparison_hunks.length).toBeGreaterThan(0);

    const html = renderToStaticMarkup(<CanonicalCaseEvidence item={item!} />);

    expect(html).toContain("Vulnerable code and fix");
    expect(html).not.toContain(
      "A line-by-line code comparison has not been prepared",
    );
    expect(html).toMatch(/AI introduced this behavior:|The fix adds:|Unsafe git option/);
  });

  it("never ships the empty comparison placeholder", () => {
    // Mirrors scripts/site_preflight_allowlist.json: GHSA-VCV2's commits
    // were force-pushed upstream, so no comparison patch exists (verified
    // fact, not a filter).
    const noHunks: Record<string, true> = { "GHSA-VCV2-R9JH-99M5": true };
    for (const item of getResearchCases()) {
      const html = renderToStaticMarkup(<CanonicalCaseEvidence item={item} />);
      expect(html, item.case_id).not.toContain(
        "A line-by-line code comparison has not been prepared",
      );
      if (item.case_id.toUpperCase() in noHunks) {
        continue;
      }
      expect(
        item.code_evidence?.comparison_hunks?.length ||
          item.code_evidence?.candidate_hunks?.length,
        item.case_id,
      ).toBeGreaterThan(0);
    }
  });

  it("omits empty release rows instead of showing not recorded", () => {
    const withRelease = getResearchCaseById("GHSA-5XXX-QHH7-9287");
    const withoutRelease = getResearchCaseById("GHSA-C7RR-QHWX-6Q49");
    expect(withRelease?.vulnerable_release).toBeTruthy();
    expect(withoutRelease?.vulnerable_release).toBeNull();

    expect(
      renderToStaticMarkup(<CanonicalCaseEvidence item={withRelease!} />),
    ).toContain("Releases");
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
